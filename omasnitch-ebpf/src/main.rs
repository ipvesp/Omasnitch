#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_sock_addr,
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
    },
    macros::{
        cgroup_sock_addr,
        cgroup_skb,
        map,
    },
    maps::{
        HashMap,
        LruHashMap,
        PerCpuHashMap,
        RingBuf,
    },
    programs::{SockAddrContext, SkBuffContext},
    EbpfContext,
};

use omasnitch_common::{
    ConnectEvent,
    TrafficCounter,
    VERDICT_ALLOW,
    VERDICT_ASK,
    VERDICT_BLOCK,
};

//
// Policy artık process/thread adına göre değil,
// Linux TGID yani uygulama process ID'sine göre tutuluyor.
//
#[map]
static POLICIES: HashMap<u32, u8> =
    HashMap::<u32, u8>::with_max_entries(16384, 0);

#[map]
static PROMPT_UID: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[map]
static ONCE: HashMap<u32, u8> = HashMap::with_max_entries(16384, 0);

#[map]
static EVENTS: RingBuf =
    RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static SOCKET_OWNERS: LruHashMap<u64, u32> = LruHashMap::with_max_entries(65536, 0);

#[map]
static TRAFFIC: PerCpuHashMap<u32, TrafficCounter> = PerCpuHashMap::with_max_entries(16384, 0);

#[cgroup_skb(ingress)]
pub fn count_ingress(ctx: SkBuffContext) -> i32 {
    count_packet(ctx, false);
    1
}

#[cgroup_skb(egress)]
pub fn count_egress(ctx: SkBuffContext) -> i32 {
    count_packet(ctx, true);
    1
}

fn count_packet(ctx: SkBuffContext, upload: bool) {
    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie == 0 { return; }
    let Some(pid) = (unsafe { SOCKET_OWNERS.get(&cookie).copied() }) else { return; };
    let len = ctx.len() as u64;
    if let Some(counter) = TRAFFIC.get_ptr_mut(&pid) {
        unsafe {
            if upload { (*counter).uploaded += len; }
            else { (*counter).downloaded += len; }
        }
    } else {
        let mut initial = TrafficCounter::default();
        if upload { initial.uploaded = len; }
        else { initial.downloaded = len; }
        let _ = TRAFFIC.insert(&pid, &initial, 0);
    }
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(
    ctx: SockAddrContext,
) -> i32 {
    match handle_connect(
        ctx,
        false,
    ) {
        Ok(value) => value,
        Err(_) => 1,
    }
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(
    ctx: SockAddrContext,
) -> i32 {
    match handle_connect(
        ctx,
        true,
    ) {
        Ok(value) => value,
        Err(_) => 1,
    }
}

fn handle_connect(
    ctx: SockAddrContext,
    ipv6: bool,
) -> Result<i32, i32> {
    let pid_tgid =
        bpf_get_current_pid_tgid();

    //
    // bpf_get_current_pid_tgid():
    //
    // upper 32 bits = TGID
    // lower 32 bits = thread PID
    //
    // Biz uygulama seviyesinde çalışmak istediğimiz
    // için TGID kullanıyoruz.
    //
    let tgid =
        (pid_tgid >> 32) as u32;

    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie != 0 { let _ = SOCKET_OWNERS.insert(&cookie, &tgid, 0); }

    let explicit_policy = unsafe { POLICIES.get(&tgid).copied() };
    let mut policy = explicit_policy.unwrap_or(VERDICT_ALLOW);

    let uid_gid =
        bpf_get_current_uid_gid();

    let comm =
        bpf_get_current_comm()
            .unwrap_or([0u8; 16]);

    let mut event =
        ConnectEvent::empty();

    event.pid =
        tgid;

    event.uid =
        uid_gid as u32;

    event.comm =
        comm;

    event.verdict =
        policy;

    unsafe {
        let raw =
            &*(ctx.as_ptr()
                as *const bpf_sock_addr);

        event.protocol =
            raw.protocol as u8;

        event.port =
            u16::from_be(
                raw.user_port as u16,
            );

        if ipv6 {
            event.family = 10;

            let words =
                raw.user_ip6;

            let mut i = 0;

            while i < 4 {
                let bytes =
                    words[i]
                        .to_ne_bytes();

                let base =
                    i * 4;

                event.addr[base] =
                    bytes[0];

                event.addr[base + 1] =
                    bytes[1];

                event.addr[base + 2] =
                    bytes[2];

                event.addr[base + 3] =
                    bytes[3];

                i += 1;
            }
        } else {
            event.family = 2;

            let bytes =
                raw.user_ip4
                    .to_ne_bytes();

            event.addr[0] =
                bytes[0];

            event.addr[1] =
                bytes[1];

            event.addr[2] =
                bytes[2];

            event.addr[3] =
                bytes[3];
        }
    }

    if explicit_policy.is_none() && !is_local_destination(&event) {
        if let Some(target_uid) = unsafe { PROMPT_UID.get(&0).copied() } {
            if target_uid == event.uid { policy = VERDICT_ASK; }
        }
    }
    if !is_local_destination(&event) && unsafe { ONCE.get(&tgid).is_some() } {
        policy = VERDICT_ALLOW;
        let _ = ONCE.remove(&tgid);
    }
    event.verdict = policy;

    let _ =
        EVENTS.output::<ConnectEvent>(
            &event,
            0,
        );

    match policy {
        VERDICT_BLOCK =>
            Ok(0),

        VERDICT_ASK =>
            Ok(0),

        _ =>
            Ok(1),
    }
}

fn is_local_destination(event: &ConnectEvent) -> bool {
    if event.family == 2 {
        let a = event.addr[0];
        let b = event.addr[1];
        return is_local_v4(a, b);
    }
    if event.addr[0] == 0 && event.addr[1] == 0 && event.addr[2] == 0
        && event.addr[3] == 0 && event.addr[4] == 0 && event.addr[5] == 0
        && event.addr[6] == 0 && event.addr[7] == 0 && event.addr[8] == 0
        && event.addr[9] == 0 && event.addr[10] == 255 && event.addr[11] == 255
    {
        return is_local_v4(event.addr[12], event.addr[13]);
    }
    event.addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        || (event.addr[0] & 0xfe) == 0xfc
        || (event.addr[0] == 0xfe && (event.addr[1] & 0xc0) == 0x80)
}

fn is_local_v4(a: u8, b: u8) -> bool {
    a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31)
        || (a == 192 && b == 168) || (a == 169 && b == 254)
}

#[panic_handler]
fn panic(
    _info: &core::panic::PanicInfo,
) -> ! {
    loop {}
}
