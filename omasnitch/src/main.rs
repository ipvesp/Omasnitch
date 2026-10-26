mod dns;
mod api;
mod model;
mod process;
mod rules;

use std::{
    collections::{
        HashMap,
        HashSet,
        VecDeque,
    },
    fs::File,
    os::unix::fs::PermissionsExt,
    mem::size_of,
    path::{
        Path,
        PathBuf,
    },
    sync::{
        mpsc,
        Arc,
        Mutex,
        RwLock,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{
    Context,
    Result,
};

use aya::{
    maps::{
        HashMap as BpfHashMap,
        PerCpuHashMap as BpfPerCpuHashMap,
        RingBuf,
        SockHash,
    },
    programs::{
        CgroupAttachMode,
        CgroupSock,
        CgroupSockAddr,
        CgroupSkb,
        CgroupSkbAttachType,
        SkMsg,
        SockOps,
    },
    Ebpf,
};

use tokio::{
    io::{
        AsyncBufReadExt,
        AsyncReadExt,
        AsyncWriteExt,
        BufReader,
    },
    net::{
        UnixListener,
        UnixStream,
    },
    sync::Semaphore,
    time::timeout,
};

use omasnitch_common::ConnectEvent;

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelTrafficCounter {
    uploaded: u64,
    downloaded: u64,
}

unsafe impl aya::Pod for KernelTrafficCounter {}

use crate::{
    api::{
        Request,
        Response,
        Status,
        ProfileStatus,
        IpPreview,
        TrafficUsage,
        TemporaryRule,
        PendingConnection,
        PromptStatus,
    },
    model::Connection,
    process::{
        pids_for_application,
        process_start_time,
        resolve_process,
    },
    rules::RuleStore,
};

const SOCKET_PATH: &str =
    "/run/omasnitch/omasnitch.sock";

const RULES_PATH: &str =
    "/var/lib/omasnitch/rules.json";

const MAX_EVENTS: usize =
    1000;
const MAX_PENDING: usize = 1024;
const MAX_RETIRED_APPS: usize = 4096;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

//
// Artık key process adı değil,
// TGID/PID.
//
type KernelPolicies =
    BpfHashMap<
        aya::maps::MapData,
        u32,
        u8,
    >;

#[derive(Clone, PartialEq, Eq)]
struct TrafficIdentity {
    application: String,
    uid: u32,
    start_time: u64,
}

struct AppState {
    policies:
        Mutex<KernelPolicies>,

    traffic: Mutex<BpfPerCpuHashMap<aya::maps::MapData, u32, KernelTrafficCounter>>,

    prompt_uid: Mutex<BpfHashMap<aya::maps::MapData, u32, u32>>,

    once: Mutex<BpfHashMap<aya::maps::MapData, u32, u8>>,

    rule_generation: Mutex<(BpfHashMap<aya::maps::MapData, u32, u32>, u32)>,

    pending: RwLock<HashMap<String, PendingConnection>>,

    pid_applications: RwLock<HashMap<u32, TrafficIdentity>>,

    retired_traffic: RwLock<HashMap<(String, u32), (u64, u64)>>,

    rules:
        RwLock<RuleStore>,

    temporary_allows: RwLock<HashMap<String, Option<Instant>>>,

    events:
        RwLock<
            VecDeque<Connection>,
        >,

    hostnames: RwLock<HashMap<String, Option<String>>>,
    dns_sender: mpsc::SyncSender<String>,

    //
    // Hangi uygulamaya hangi PID'leri
    // policy olarak eklediğimizi takip ediyoruz.
    //
    application_pids:
        RwLock<
            HashMap<
                String,
                HashSet<u32>,
            >,
        >,
}

fn bump_memlock() {
    let rlim =
        libc::rlimit {
            rlim_cur:
                libc::RLIM_INFINITY,

            rlim_max:
                libc::RLIM_INFINITY,
        };

    unsafe {
        libc::setrlimit(
            libc::RLIMIT_MEMLOCK,
            &rlim,
        );
    }
}

fn event_from_bytes(
    bytes: &[u8],
) -> Option<ConnectEvent> {
    if bytes.len()
        < size_of::<ConnectEvent>()
    {
        return None;
    }

    let ptr =
        bytes.as_ptr()
            as *const ConnectEvent;

    Some(
        unsafe {
            ptr.read_unaligned()
        },
    )
}

fn event_comm(
    event: &ConnectEvent,
) -> String {
    let end =
        event
            .comm
            .iter()
            .position(
                |byte| {
                    *byte == 0
                },
            )
            .unwrap_or(
                event.comm.len(),
            );

    String::from_utf8_lossy(
        &event.comm[..end],
    )
    .to_string()
}

fn retire_pid_traffic(state: &Arc<AppState>, pid: u32, identity: TrafficIdentity) {
    let totals = {
        let mut traffic = state.traffic.lock().unwrap();
        let mut totals = (0u64, 0u64);
        if let Ok(counters) = traffic.get(&pid, 0) {
            for counter in counters.iter() {
                totals.0 = totals.0.saturating_add(counter.uploaded);
                totals.1 = totals.1.saturating_add(counter.downloaded);
            }
        }
        let _ = traffic.remove(&pid);
        totals
    };
    let mut retired = state.retired_traffic.write().unwrap();
    if retired.len() >= MAX_RETIRED_APPS
        && !retired.contains_key(&(identity.application.clone(), identity.uid)) {
        retired.clear();
    }
    let total = retired.entry((identity.application, identity.uid)).or_default();
    total.0 = total.0.saturating_add(totals.0);
    total.1 = total.1.saturating_add(totals.1);
}

fn spawn_traffic_cleanup(state: Arc<AppState>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        let snapshot = state.pid_applications.read().unwrap().clone();
        for (pid, identity) in snapshot {
            if Path::new(&format!("/proc/{pid}")).exists()
                && process_start_time(pid).unwrap_or(0) == identity.start_time { continue; }
            let removed = {
                let mut identities = state.pid_applications.write().unwrap();
                if identities.get(&pid) == Some(&identity) { identities.remove(&pid) }
                else { None }
            };
            if let Some(old) = removed { retire_pid_traffic(&state, pid, old); }
        }
    });
}

//
// Tek uygulamanın PID listesini
// kernel map ile eşitle.
//
fn sync_application_policy(
    state: &Arc<AppState>,
    application: &str,
    action: u8,
) -> Result<()> {
    let current_pids:
        HashSet<u32> =
        pids_for_application(
            application,
        )
        .into_iter()
        .collect();

    let previous_pids = {
        state
            .application_pids
            .read()
            .unwrap()
            .get(
                application,
            )
            .cloned()
            .unwrap_or_default()
    };

    {
        let mut policies =
            state
                .policies
                .lock()
                .unwrap();

        //
        // Yeni/current process'lere
        // policy uygula.
        //
        for pid in
            &current_pids
        {
            policies.insert(
                *pid,
                action,
                0,
            )?;
        }

        //
        // Artık bu uygulamaya ait olmayan/eski
        // PID'leri kernel map'ten çıkar.
        //
        for pid in
            previous_pids
                .difference(
                    &current_pids,
                )
        {
            let _ =
                policies.remove(
                    pid,
                );
        }
    }

    {
        let mut tracked =
            state
                .application_pids
                .write()
                .unwrap();

        tracked.insert(
            application
                .to_string(),
            current_pids,
        );
    }

    Ok(())
}

fn remove_application_policy(
    state: &Arc<AppState>,
    application: &str,
) {
    let mut pids =
        HashSet::new();

    //
    // Daha önce takip ettiğimiz PID'ler.
    //
    if let Some(tracked) =
        state
            .application_pids
            .read()
            .unwrap()
            .get(
                application,
            )
    {
        pids.extend(
            tracked
                .iter()
                .copied(),
        );
    }

    //
    // Şu an çalışan PID'ler.
    //
    pids.extend(
        pids_for_application(
            application,
        ),
    );

    {
        let mut policies =
            state
                .policies
                .lock()
                .unwrap();

        for pid in pids {
            let _ =
                policies.remove(
                    &pid,
                );
        }
    }

    state
        .application_pids
        .write()
        .unwrap()
        .remove(
            application,
        );
}

fn sync_all_rules(
    state: &Arc<AppState>,
) -> Result<()> {
    let mut rules =
        state
            .rules
            .read()
            .unwrap()
            .rules
            .clone();

    let has_expired = state.temporary_allows.read().unwrap().values()
        .any(|deadline| deadline.is_some_and(|end| end <= Instant::now()));
    if has_expired && let Err(error) = invalidate_socket_exceptions(state) {
        return Err(error).context("could not expire temporary rules");
    }
    let expired = {
        let mut temporary = state.temporary_allows.write().unwrap();
        let expired: Vec<String> = temporary.iter()
            .filter_map(|(app, deadline)| deadline.and_then(|end| (end <= Instant::now()).then(|| app.clone())))
            .collect();
        for app in &expired { temporary.remove(app); }
        for app in temporary.keys() { rules.insert(app.clone(), crate::model::RuleAction::Allow); }
        expired
    };
    for app in expired {
        if !rules.contains_key(&app) {
            remove_application_policy(state, &app);
        }
    }

    for (
        application,
        action,
    ) in rules
    {
        sync_application_policy(
                state,
                &application,
                action.to_kernel(),
            ).with_context(|| format!("policy sync error for {application}"))?;
    }
    Ok(())
}

fn invalidate_socket_exceptions(state: &Arc<AppState>) -> Result<()> {
    let mut generation = state.rule_generation.lock().unwrap();
    let next = generation.1.wrapping_add(1);
    generation.0.insert(0, next, 0)?;
    generation.1 = next;
    Ok(())
}

fn clear_once_for_application(state: &Arc<AppState>, application: &str) {
    let mut once = state.once.lock().unwrap();
    for pid in pids_for_application(application) {
        let _ = once.remove(&pid);
    }
}

fn clear_all_once(state: &Arc<AppState>) {
    let mut once = state.once.lock().unwrap();
    let pids: Vec<u32> = once.iter().flatten().map(|(pid, _)| pid).collect();
    for pid in pids { let _ = once.remove(&pid); }
}

//
// Kalıcı rule varsa yeni açılan process'leri de
// otomatik kernel map'e ekler.
//
// Örneğin:
//
// block chromium
// chromium kapalı
// chromium 10 dakika sonra açıldı
//
// -> yeni PID otomatik BLOCK.
//
fn spawn_policy_sync(
    state: Arc<AppState>,
) {
    thread::spawn(
        move || loop {
            if let Err(error) = sync_all_rules(&state) {
                eprintln!("policy sync error: {error:#}");
            }

            thread::sleep(
                Duration::from_millis(
                    250,
                ),
            );
        },
    );
}

fn spawn_ring_reader(
    mut ring:
        RingBuf<
            aya::maps::MapData,
        >,

    state:
        Arc<AppState>,
) {
    thread::spawn(
        move || loop {
            let mut found =
                false;

            while let Some(item) =
                ring.next()
            {
                found = true;

                let Some(raw) =
                    event_from_bytes(
                        &item,
                    )
                else {
                    continue;
                };

                let comm =
                    event_comm(
                        &raw,
                    );

                let identity =
                    resolve_process(
                        raw.pid,
                        &comm,
                    );

                let application =
                    identity
                        .application
                        .clone();

                let traffic_identity = TrafficIdentity {
                    application: application.clone(),
                    uid: raw.uid,
                    start_time: process_start_time(raw.pid).unwrap_or(0),
                };
                let previous = state.pid_applications.write().unwrap()
                    .insert(raw.pid, traffic_identity.clone());
                if let Some(old) = previous.filter(|old| old != &traffic_identity) {
                    retire_pid_traffic(&state, raw.pid, old);
                }

                //
                // Bu process'in ait olduğu uygulama için
                // rule varsa PID'yi hemen kernel map'e ekle.
                //
                let active_rule = {
                    if state.temporary_allows.read().unwrap().contains_key(&application) {
                        Some(crate::model::RuleAction::Allow)
                    } else {
                        let rules = state.rules.read().unwrap();
                        rules.rules.get(&application).cloned()
                    }
                };

                if let Some(action) =
                    active_rule.clone()
                {
                    {
                        let mut policies =
                            state
                                .policies
                                .lock()
                                .unwrap();

                        let _ =
                            policies.insert(
                                raw.pid,
                                action
                                    .to_kernel(),
                                0,
                            );
                    }

                    {
                        let mut tracked =
                            state
                                .application_pids
                                .write()
                                .unwrap();

                        tracked
                            .entry(
                                application
                                    .clone(),
                            )
                            .or_default()
                            .insert(
                                raw.pid,
                            );
                    }
                }

                let event =
                    Connection::from_event(
                        &raw,
                        identity,
                    );

                if raw.verdict == omasnitch_common::VERDICT_ASK
                    && active_rule.as_ref().is_none_or(|action| matches!(action, crate::model::RuleAction::Ask))
                {
                    let mut pending = state.pending.write().unwrap();
                    if pending.len() < MAX_PENDING || pending.contains_key(&application) {
                        pending.entry(application.clone()).or_insert_with(|| PendingConnection {
                            application: application.clone(),
                            pid: raw.pid,
                            destination: event.destination.clone(),
                            uid: raw.uid,
                            timestamp: event.timestamp,
                        });
                    }
                }

                {
                    let mut hostnames = state.hostnames.write().unwrap();
                    if !hostnames.contains_key(&event.destination) {
                        if hostnames.len() >= 4096 {
                            hostnames.clear();
                        }
                        hostnames.insert(event.destination.clone(), None);
                        let _ = state.dns_sender.try_send(event.destination.clone());
                    }
                }

                {
                    let mut events =
                        state
                            .events
                            .write()
                            .unwrap();

                    if events.len()
                        >= MAX_EVENTS
                    {
                        events.pop_front();
                    }

                    events.push_back(
                        event,
                    );
                }
            }

            if !found {
                thread::sleep(
                    Duration::from_millis(
                        30,
                    ),
                );
            }
        },
    );
}

fn spawn_dns_resolver(
    receiver: mpsc::Receiver<String>,
    state: Arc<AppState>,
) {
    thread::spawn(move || {
        while let Ok(address) = receiver.recv() {
            let hostname = dns::reverse_hostname(&address);
            if let Some(cached) = state.hostnames.write().unwrap().get_mut(&address) {
                *cached = hostname;
            }
        }
    });
}

fn load_rules_into_kernel(
    state: &Arc<AppState>,
) -> Result<()> {
    sync_all_rules(
        state,
    )
}

async fn respond(
    stream: UnixStream,
    state: Arc<AppState>,
) -> Result<()> {
    let (
        reader,
        mut writer,
    ) =
        stream.into_split();

    let reader =
        BufReader::new(
            reader,
        );

    let mut bytes = Vec::new();
    let mut limited = reader.take(MAX_REQUEST_BYTES + 1);
    timeout(Duration::from_secs(5), limited.read_until(b'\n', &mut bytes)).await??;
    if bytes.len() as u64 > MAX_REQUEST_BYTES || bytes.last() != Some(&b'\n') {
        return send(&mut writer, Response::Error("request too large or incomplete".to_string())).await;
    }

    let request:
        Result<Request, _> =
        serde_json::from_slice(
            &bytes,
        );

    let response =
        match request {
            Err(error) =>
                Response::Error(
                    error.to_string(),
                ),

            Ok(
                Request::Status,
            ) => {
                let rules =
                    state
                        .rules
                        .read()
                        .unwrap()
                        .rules
                        .len();

                let events =
                    state
                        .events
                        .read()
                        .unwrap()
                        .len();

                Response::Status(
                    Status {
                        running: true,
                        ebpf: true,
                        rules,
                        events,
                    },
                )
            }

            Ok(
                Request::Rules,
            ) => {
                let rules =
                    state
                        .rules
                        .read()
                        .unwrap()
                        .list();

                Response::Rules(
                    rules,
                )
            }

            Ok(Request::Profiles) => {
                let rules = state.rules.read().unwrap();
                Response::Profiles(ProfileStatus {
                    active: rules.active_profile.clone(),
                    names: rules.profiles(),
                })
            }

            Ok(Request::Pending) => {
                let mut pending: Vec<PendingConnection> = state.pending.read().unwrap().values().cloned().collect();
                pending.sort_by_key(|item| item.timestamp);
                Response::Pending(pending)
            }

            Ok(Request::PromptStatus) => {
                let uid = state.rules.read().unwrap().prompt_uid;
                Response::PromptStatus(PromptStatus { enabled: uid.is_some(), uid })
            }

            Ok(Request::SetPrompt { enabled, uid }) => {
                if uid == 0 || uid == u32::MAX {
                    Response::Error("invalid user ID".to_string())
                } else {
                    let kernel_result: Result<(), aya::maps::MapError> = {
                        let mut map = state.prompt_uid.lock().unwrap();
                        if enabled { map.insert(0, uid, 0) }
                        else { let _ = map.remove(&0); Ok(()) }
                    };
                    match kernel_result {
                        Err(error) => Response::Error(error.to_string()),
                        Ok(()) => {
                            if !enabled { state.pending.write().unwrap().clear(); }
                            let save_result = {
                                let mut rules = state.rules.write().unwrap();
                                rules.prompt_uid = enabled.then_some(uid);
                                rules.save(RULES_PATH)
                            };
                            match save_result {
                                Ok(()) => Response::Ok,
                                Err(error) => Response::Error(error.to_string()),
                            }
                        }
                    }
                }
            }

            Ok(Request::SwitchProfile { name }) => {
                clear_all_once(&state);
                let switched = invalidate_socket_exceptions(&state).and_then(|_| {
                    let mut rules = state.rules.write().unwrap();
                    let previous = rules.clone();
                    let result = rules.switch_profile(name).and_then(|_| rules.save(RULES_PATH));
                    if result.is_err() { *rules = previous; }
                    result
                });
                match switched {
                    Ok(()) => {
                        let tracked: Vec<String> = state.application_pids.read().unwrap().keys().cloned().collect();
                        for app in tracked { remove_application_policy(&state, &app); }
                        match sync_all_rules(&state) {
                            Ok(()) => Response::Ok,
                            Err(error) => Response::Error(error.to_string()),
                        }
                    }
                    Err(error) => Response::Error(error.to_string()),
                }
            }

            Ok(Request::TemporaryAllow { application, seconds, once }) => {
                if application.is_empty() || seconds == Some(0) || seconds.is_some_and(|s| s > 86400) {
                    Response::Error("invalid application or duration".to_string())
                } else if once {
                    let pending_pid = state.pending.read().unwrap().get(&application).map(|item| item.pid);
                    let running = pids_for_application(&application);
                    let pid = match pending_pid {
                        Some(pid) if running.contains(&pid) => Some(pid),
                        Some(_) => None,
                        None => running.into_iter().next(),
                    };
                    match pid {
                        Some(pid) => match state.once.lock().unwrap().insert(pid, 1, 0) {
                            Ok(()) => {
                            state.pending.write().unwrap().remove(&application);
                            Response::Ok
                            }
                            Err(error) => Response::Error(error.to_string()),
                        },
                        None => Response::Error("pending process is no longer running".to_string()),
                    }
                } else if let Err(error) = invalidate_socket_exceptions(&state) {
                    Response::Error(error.to_string())
                } else {
                    let deadline = seconds.map(|s| Instant::now() + Duration::from_secs(s));
                    let previous = state.temporary_allows.write().unwrap().insert(application.clone(), deadline);
                    match sync_application_policy(&state, &application, omasnitch_common::VERDICT_ALLOW) {
                        Ok(()) => {
                            state.pending.write().unwrap().remove(&application);
                            Response::Ok
                        },
                        Err(error) => {
                            let mut temporary = state.temporary_allows.write().unwrap();
                            if let Some(old) = previous { temporary.insert(application.clone(), old); }
                            else { temporary.remove(&application); }
                            drop(temporary);
                            remove_application_policy(&state, &application);
                            let _ = sync_all_rules(&state);
                            Response::Error(error.to_string())
                        },
                    }
                }
            }

            Ok(Request::RevokeTemporary { application }) => {
                clear_once_for_application(&state, &application);
                match invalidate_socket_exceptions(&state) {
                    Err(error) => Response::Error(error.to_string()),
                    Ok(()) => {
                        state.temporary_allows.write().unwrap().remove(&application);
                        if !state.rules.read().unwrap().rules.contains_key(&application) {
                            remove_application_policy(&state, &application);
                        }
                        match sync_all_rules(&state) {
                            Ok(()) => Response::Ok,
                            Err(error) => Response::Error(error.to_string()),
                        }
                    }
                }
            }

            Ok(Request::PreviewIp { address }) => {
                match address.parse::<std::net::IpAddr>() {
                    Ok(ip) => {
                        let events = state.events.read().unwrap();
                        let mut apps: Vec<String> = events.iter()
                            .filter(|event| event.destination == ip.to_string())
                            .map(|event| event.application.clone())
                            .collect();
                        let attempts = apps.len();
                        apps.sort();
                        apps.dedup();
                        Response::IpPreview(IpPreview { address: ip.to_string(), applications: apps, recorded_attempts: attempts })
                    }
                    Err(_) => Response::Error("invalid IP address".to_string()),
                }
            }

            Ok(
                Request::Events,
            ) => {
                let mut events: Vec<Connection> =
                    state
                        .events
                        .read()
                        .unwrap()
                        .iter()
                        .cloned()
                        .collect();

                let hostnames = state.hostnames.read().unwrap();
                for event in &mut events {
                    event.hostname = hostnames
                        .get(&event.destination)
                        .cloned()
                        .flatten();
                }

                Response::Events(
                    events,
                )
            }

            Ok(Request::Traffic) => {
                let mut usage = state.retired_traffic.read().unwrap().clone();
                let identities = state.pid_applications.read().unwrap().clone();
                let traffic = state.traffic.lock().unwrap();
                for entry in traffic.iter().flatten() {
                    let (pid, counters) = entry;
                    let Some(identity) = identities.get(&pid) else { continue; };
                    let total = usage.entry((identity.application.clone(), identity.uid)).or_default();
                    for value in counters.iter() {
                        total.0 = total.0.saturating_add(value.uploaded);
                        total.1 = total.1.saturating_add(value.downloaded);
                    }
                }
                let mut result: Vec<TrafficUsage> = usage.into_iter().map(|((application, uid), (uploaded, downloaded))|
                    TrafficUsage { application, uid, uploaded, downloaded }).collect();
                result.sort_by(|a, b| a.application.cmp(&b.application));
                Response::Traffic(result)
            }

            Ok(Request::Temporary) => {
                let rules = state.temporary_allows.read().unwrap();
                let mut result: Vec<TemporaryRule> = rules.iter().map(|(application, deadline)| {
                    TemporaryRule {
                        application: application.clone(),
                        remaining_seconds: deadline.map(|end| end.saturating_duration_since(Instant::now()).as_secs()),
                    }
                }).collect();
                result.sort_by(|a, b| a.application.cmp(&b.application));
                Response::Temporary(result)
            }

            Ok(
                Request::ClearEvents,
            ) => {
                state
                    .events
                    .write()
                    .unwrap()
                    .clear();

                Response::Ok
            }

            Ok(
                Request::SetRule {
                    application,
                    action,
                },
            ) => {
                clear_once_for_application(&state, &application);
                let kernel_result =
                    invalidate_socket_exceptions(&state).and_then(|_| sync_application_policy(
                        &state,
                        &application,
                        action.to_kernel(),
                    ));

                match kernel_result {
                    Err(error) =>
                        Response::Error(
                            error.to_string(),
                        ),

                    Ok(_) => {
                        state.pending.write().unwrap().remove(&application);
                        let (save_result, previous_action) = {
                            let mut rules =
                                state
                                    .rules
                                    .write()
                                    .unwrap();
                            let previous = rules.rules.get(&application).cloned();
                            rules.set(application.clone(), action);
                            let result = rules.save(RULES_PATH);
                            if result.is_err() {
                                if let Some(old) = previous.clone() { rules.set(application.clone(), old); }
                                else { rules.remove(&application); }
                            }
                            (result, previous)
                        };

                        match save_result {
                            Ok(_) =>
                                Response::Ok,

                            Err(error) => {
                                if let Some(old) = previous_action {
                                    let _ = sync_application_policy(&state, &application, old.to_kernel());
                                } else {
                                    remove_application_policy(&state, &application);
                                }
                                Response::Error(error.to_string())
                            },
                        }
                    }
                }
            }

            Ok(
                Request::RemoveRule {
                    application,
                },
            ) => {
                clear_once_for_application(&state, &application);
                let save_result = invalidate_socket_exceptions(&state).and_then(|_| {
                    let mut rules =
                        state
                            .rules
                            .write()
                            .unwrap();
                    let previous = rules.rules.get(&application).cloned();
                    rules.remove(
                        &application,
                    );
                    let result = rules.save(
                        RULES_PATH,
                    );
                    if result.is_err() && let Some(old) = previous {
                        rules.set(application.clone(), old);
                    }
                    result
                });

                match save_result {
                    Ok(_) => {
                        state.pending.write().unwrap().remove(&application);
                        remove_application_policy(&state, &application);
                        Response::Ok
                    },

                    Err(error) =>
                        Response::Error(
                            error.to_string(),
                        ),
                }
            }
        };

    send(
        &mut writer,
        response,
    )
    .await
}

async fn send(
    writer:
        &mut tokio::net::unix::OwnedWriteHalf,

    response:
        Response,
) -> Result<()> {
    let mut data =
        serde_json::to_vec(
            &response,
        )?;

    data.push(
        b'\n',
    );

    timeout(Duration::from_secs(5), writer.write_all(&data)).await??;

    Ok(())
}

fn prepare_socket()
    -> Result<()>
{
    let path =
        Path::new(
            SOCKET_PATH,
        );

    if let Some(parent) =
        path.parent()
    {
        std::fs::create_dir_all(
            parent,
        )?;
    }

    if path.exists() {
        std::fs::remove_file(
            path,
        )?;
    }

    Ok(())
}

#[tokio::main]
async fn main()
    -> Result<()>
{
    bump_memlock();

    std::fs::create_dir_all(
        "/var/lib/omasnitch",
    )?;
    std::fs::set_permissions("/var/lib/omasnitch", std::fs::Permissions::from_mode(0o700))?;
    if Path::new(RULES_PATH).exists() {
        std::fs::set_permissions(RULES_PATH, std::fs::Permissions::from_mode(0o600))?;
    }

    prepare_socket()?;

    let mut ebpf =
        Ebpf::load(
            aya::include_bytes_aligned!(
                concat!(
                    env!("OUT_DIR"),
                    "/omasnitch-ebpf-program"
                )
            ),
        )
        .context(
            "failed to load eBPF object",
        )?;

    let cgroup =
        File::open(
            "/sys/fs/cgroup",
        )
        .context(
            "cannot open /sys/fs/cgroup",
        )?;

    for name in ["track_socket", "release_socket"] {
        let program: &mut CgroupSock = ebpf.program_mut(name)
            .with_context(|| format!("{name} program missing"))?.try_into()?;
        program.load()?;
        program.attach(&cgroup, CgroupAttachMode::Single)?;
    }

    {
        let program: &mut SockOps = ebpf.program_mut("track_tcp")
            .context("track_tcp program missing")?.try_into()?;
        program.load()?;
        program.attach(&cgroup, CgroupAttachMode::Single)?;
    }

    {
        let sockets: SockHash<_, u64> = ebpf.map("TCP_SOCKETS")
            .context("TCP_SOCKETS map missing")?.try_into()?;
        let map_fd = sockets.fd().try_clone()?;
        let program: &mut SkMsg = ebpf.program_mut("check_tcp_message")
            .context("check_tcp_message program missing")?.try_into()?;
        program.load()?;
        program.attach(&map_fd)?;
    }

    {
        let program:
            &mut CgroupSockAddr =
            ebpf
                .program_mut(
                    "connect4",
                )
                .context(
                    "connect4 program missing",
                )?
                .try_into()?;

        program.load()?;

        program.attach(
            &cgroup,
            CgroupAttachMode::Single,
        )?;
    }

    for name in ["sendmsg4", "sendmsg6"] {
        let program: &mut CgroupSockAddr = ebpf.program_mut(name)
            .with_context(|| format!("{name} program missing"))?.try_into()?;
        program.load()?;
        program.attach(&cgroup, CgroupAttachMode::Single)?;
    }

    for (name, direction) in [
        ("count_ingress", CgroupSkbAttachType::Ingress),
        ("count_egress", CgroupSkbAttachType::Egress),
    ] {
        let program: &mut CgroupSkb = ebpf.program_mut(name)
            .with_context(|| format!("{name} program missing"))?.try_into()?;
        program.load()?;
        program.attach(&cgroup, direction, CgroupAttachMode::Single)?;
    }

    {
        let program:
            &mut CgroupSockAddr =
            ebpf
                .program_mut(
                    "connect6",
                )
                .context(
                    "connect6 program missing",
                )?
                .try_into()?;

        program.load()?;

        program.attach(
            &cgroup,
            CgroupAttachMode::Single,
        )?;
    }

    let policies =
        BpfHashMap::try_from(
            ebpf
                .take_map(
                    "POLICIES",
                )
                .context(
                    "POLICIES map missing",
                )?,
        )?;

    let mut prompt_uid: BpfHashMap<aya::maps::MapData, u32, u32> = BpfHashMap::try_from(
        ebpf.take_map("PROMPT_UID").context("PROMPT_UID map missing")?
    )?;

    let once: BpfHashMap<aya::maps::MapData, u32, u8> = BpfHashMap::try_from(
        ebpf.take_map("ONCE").context("ONCE map missing")?
    )?;

    let rule_generation: BpfHashMap<aya::maps::MapData, u32, u32> = BpfHashMap::try_from(
        ebpf.take_map("RULE_GENERATION").context("RULE_GENERATION map missing")?
    )?;

    let ring =
        RingBuf::try_from(
            ebpf
                .take_map(
                    "EVENTS",
                )
                .context(
                    "EVENTS map missing",
                )?,
        )?;

    let traffic = BpfPerCpuHashMap::try_from(
        ebpf.take_map("TRAFFIC").context("TRAFFIC map missing")?
    )?;

    let rules =
        RuleStore::load(
            PathBuf::from(
                RULES_PATH,
            ),
        )?;

    if let Some(uid) = rules.prompt_uid { prompt_uid.insert(0, uid, 0)?; }

    let (dns_sender, dns_receiver) = mpsc::sync_channel(256);

    let state =
        Arc::new(
            AppState {
                policies:
                    Mutex::new(
                        policies,
                    ),

                traffic: Mutex::new(traffic),

                prompt_uid: Mutex::new(prompt_uid),

                once: Mutex::new(once),

                rule_generation: Mutex::new((rule_generation, 0)),

                pending: RwLock::new(HashMap::new()),

                pid_applications: RwLock::new(HashMap::new()),

                retired_traffic: RwLock::new(HashMap::new()),

                rules:
                    RwLock::new(
                        rules,
                    ),

                temporary_allows: RwLock::new(HashMap::new()),

                events:
                    RwLock::new(
                        VecDeque::new(),
                    ),

                hostnames: RwLock::new(HashMap::new()),
                dns_sender,

                application_pids:
                    RwLock::new(
                        HashMap::new(),
                    ),
            },
        );

    load_rules_into_kernel(
        &state,
    )?;

    spawn_ring_reader(
        ring,
        state.clone(),
    );

    spawn_dns_resolver(dns_receiver, state.clone());

    spawn_policy_sync(
        state.clone(),
    );

    spawn_traffic_cleanup(state.clone());

    let listener =
        UnixListener::bind(
            SOCKET_PATH,
        )?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660))?;

    println!(
        "OmaSnitch daemon running",
    );

    let client_slots = Arc::new(Semaphore::new(64));

    loop {
        tokio::select! {
            result =
                listener.accept() =>
            {
                let (
                    stream,
                    _,
                ) = result?;

                let Ok(permit) = client_slots.clone().try_acquire_owned() else {
                    continue;
                };

                let state =
                    state.clone();

                tokio::spawn(
                    async move {
                        let _permit = permit;
                        if let Err(error) =
                            respond(
                                stream,
                                state,
                            )
                            .await
                        {
                            eprintln!(
                                "client error: {error}",
                            );
                        }
                    },
                );
            }

            _ =
                tokio::signal::ctrl_c() =>
            {
                break;
            }
        }
    }

    let _ =
        std::fs::remove_file(
            SOCKET_PATH,
        );

    Ok(())
}
