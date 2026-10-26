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
        cgroup_sock,
        cgroup_skb,
        map,
        sk_msg,
        sock_ops,
    },
    maps::{
        HashMap,
        PerCpuHashMap,
        RingBuf,
        SockHash,
    },
    programs::{SkMsgContext, SockAddrContext, SockContext, SockOpsContext, SkBuffContext},
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
static RULE_GENERATION: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf =
    RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static SOCKET_OWNERS: HashMap<u64, u32> = HashMap::with_max_entries(131072, 0);

// High bits are the current rule generation. Low byte: 1 = connection,
// 2 = one UDP datagram. Any rule change invalidates old exceptions.
#[map]
static SOCKET_EXCEPTIONS: HashMap<u64, u64> = HashMap::with_max_entries(16384, 0);

#[map]
static TCP_SOCKETS: SockHash<u64> = SockHash::with_max_entries(131072, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpKey {
    pid: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6_0: u32,
    remote_ip6_1: u32,
    remote_ip6_2: u32,
    remote_ip6_3: u32,
    local_ip6_0: u32,
    local_ip6_1: u32,
    local_ip6_2: u32,
    local_ip6_3: u32,
    remote_port: u32,
    local_port: u32,
}

#[map]
static TCP_EXCEPTIONS: HashMap<TcpKey, u32> = HashMap::with_max_entries(16384, 0);

#[map]
static TRAFFIC: PerCpuHashMap<u32, TrafficCounter> = PerCpuHashMap::with_max_entries(16384, 0);

#[cgroup_skb(ingress)]
pub fn count_ingress(ctx: SkBuffContext) -> i32 {
    count_packet(ctx, false);
    1
}

#[cgroup_skb(egress)]
pub fn count_egress(ctx: SkBuffContext) -> i32 {
    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    let current = (bpf_get_current_pid_tgid() >> 32) as u32;
    let mut blocked = false;
    if let Some(policy) = unsafe { POLICIES.get(&current).copied() } {
        if policy == VERDICT_BLOCK || policy == VERDICT_ASK { blocked = true; }
    }
    if cookie != 0 {
        if let Some(pid) = unsafe { SOCKET_OWNERS.get(&cookie).copied() } {
            if let Some(policy) = unsafe { POLICIES.get(&pid).copied() } {
                if policy == VERDICT_BLOCK || policy == VERDICT_ASK { blocked = true; }
            }
        }
        if blocked {
            let generation = unsafe { RULE_GENERATION.get(&0).copied() }.unwrap_or(0);
            if let Some(value) = unsafe { SOCKET_EXCEPTIONS.get(&cookie).copied() } {
                if (value >> 8) == generation as u64 {
                    if (value & 0xff) == 1 {
                        count_packet(ctx, true);
                        return 1;
                    }
                    if (value & 0xff) == 2 {
                        let _ = SOCKET_EXCEPTIONS.remove(&cookie);
                        count_packet(ctx, true);
                        return 1;
                    }
                }
            }
        }
    }
    if blocked { return 0; }
    count_packet(ctx, true);
    1
}

#[cgroup_sock(sock_create)]
pub fn track_socket(ctx: SockContext) -> i32 {
    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie == 0 { return 1; }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if SOCKET_OWNERS.insert(&cookie, &pid, 0).is_err() { 0 } else { 1 }
}

#[cgroup_sock(sock_release)]
pub fn release_socket(ctx: SockContext) -> i32 {
    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie != 0 {
        let _ = SOCKET_OWNERS.remove(&cookie);
        let _ = SOCKET_EXCEPTIONS.remove(&cookie);
    }
    1
}

#[sock_ops]
pub fn track_tcp(ctx: SockOpsContext) -> u32 {
    if ctx.op() == 4 {
        let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
        if cookie != 0 {
            let _ = TCP_SOCKETS.update(cookie, unsafe { &mut *ctx.ops }, 0);
            if let Some(exception) = unsafe { SOCKET_EXCEPTIONS.get(&cookie).copied() } {
                if (exception & 0xff) == 1 {
                    if let Some(pid) = unsafe { SOCKET_OWNERS.get(&cookie).copied() } {
                        let key = TcpKey {
                            pid,
                            family: ctx.family(),
                            remote_ip4: ctx.remote_ip4(),
                            local_ip4: ctx.local_ip4(),
                            remote_ip6_0: unsafe { (*ctx.ops).remote_ip6[0] },
                            remote_ip6_1: unsafe { (*ctx.ops).remote_ip6[1] },
                            remote_ip6_2: unsafe { (*ctx.ops).remote_ip6[2] },
                            remote_ip6_3: unsafe { (*ctx.ops).remote_ip6[3] },
                            local_ip6_0: unsafe { (*ctx.ops).local_ip6[0] },
                            local_ip6_1: unsafe { (*ctx.ops).local_ip6[1] },
                            local_ip6_2: unsafe { (*ctx.ops).local_ip6[2] },
                            local_ip6_3: unsafe { (*ctx.ops).local_ip6[3] },
                            remote_port: ctx.remote_port(),
                            local_port: ctx.local_port(),
                        };
                        let _ = TCP_EXCEPTIONS.insert(&key, &((exception >> 8) as u32), 0);
                    }
                }
            }
        }
    }
    1
}

#[sk_msg]
pub fn check_tcp_message(ctx: SkMsgContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(policy) = unsafe { POLICIES.get(&pid).copied() } {
        if policy == VERDICT_BLOCK || policy == VERDICT_ASK {
            let raw = unsafe { &*ctx.msg };
            let key = TcpKey {
                pid,
                family: raw.family,
                remote_ip4: raw.remote_ip4,
                local_ip4: raw.local_ip4,
                remote_ip6_0: raw.remote_ip6[0],
                remote_ip6_1: raw.remote_ip6[1],
                remote_ip6_2: raw.remote_ip6[2],
                remote_ip6_3: raw.remote_ip6[3],
                local_ip6_0: raw.local_ip6[0],
                local_ip6_1: raw.local_ip6[1],
                local_ip6_2: raw.local_ip6[2],
                local_ip6_3: raw.local_ip6[3],
                remote_port: raw.remote_port,
                local_port: raw.local_port,
            };
            let generation = unsafe { RULE_GENERATION.get(&0).copied() }.unwrap_or(0);
            if let Some(allowed_generation) = unsafe { TCP_EXCEPTIONS.get(&key).copied() } {
                if allowed_generation == generation { return 1; }
            }
            return 0;
        }
    }
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
    match handle_destination(
        ctx,
        false,
        false,
    ) {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(
    ctx: SockAddrContext,
) -> i32 {
    match handle_destination(
        ctx,
        true,
        false,
    ) {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    handle_destination(ctx, false, true).unwrap_or(0)
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    handle_destination(ctx, true, true).unwrap_or(0)
}

fn handle_destination(
    ctx: SockAddrContext,
    ipv6: bool,
    datagram: bool,
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
    if cookie != 0 && SOCKET_OWNERS.insert(&cookie, &tgid, 0).is_err() {
        return Ok(0);
    }

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
    if unsafe { ONCE.get(&tgid).is_some() } {
        if cookie != 0 {
            let generation = unsafe { RULE_GENERATION.get(&0).copied() }.unwrap_or(0);
            let exception = ((generation as u64) << 8) | if datagram { 2 } else { 1 };
            if SOCKET_EXCEPTIONS.insert(&cookie, &exception, 0).is_ok() {
                policy = VERDICT_ALLOW;
                let _ = ONCE.remove(&tgid);
            }
        }
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
