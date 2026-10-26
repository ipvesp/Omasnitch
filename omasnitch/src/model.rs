use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        Ipv6Addr,
    },
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

use omasnitch_common::{
    ConnectEvent,
    VERDICT_ALLOW,
    VERDICT_ASK,
    VERDICT_BLOCK,
};

use serde::{
    Deserialize,
    Serialize,
};

use crate::process::ProcessIdentity;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Block,
    Ask,
}

impl RuleAction {
    pub fn to_kernel(&self) -> u8 {
        match self {
            Self::Allow =>
                VERDICT_ALLOW,

            Self::Block =>
                VERDICT_BLOCK,

            Self::Ask =>
                VERDICT_ASK,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
pub struct Rule {
    pub application: String,
    pub action: RuleAction,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
pub struct Connection {
    pub timestamp: u64,

    pub pid: u32,

    pub uid: u32,

    pub application: String,

    pub process_name: String,

    pub executable: String,

    pub destination: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    pub port: u16,

    pub protocol: String,

    pub verdict: RuleAction,
}

impl Connection {
    pub fn from_event(
        event: &ConnectEvent,
        identity: ProcessIdentity,
    ) -> Self {
        let destination =
            if event.family == 2 {
                IpAddr::V4(
                    Ipv4Addr::new(
                        event.addr[0],
                        event.addr[1],
                        event.addr[2],
                        event.addr[3],
                    ),
                )
            } else {
                IpAddr::V6(
                    Ipv6Addr::from(
                        event.addr,
                    ),
                )
            };

        let verdict =
            match event.verdict {
                VERDICT_BLOCK =>
                    RuleAction::Block,

                VERDICT_ASK =>
                    RuleAction::Ask,

                _ =>
                    RuleAction::Allow,
            };

        let protocol =
            match event.protocol {
                6 => "TCP",
                17 => "UDP",
                _ => "OTHER",
            }
            .to_string();

        let timestamp =
            SystemTime::now()
                .duration_since(
                    UNIX_EPOCH,
                )
                .unwrap_or_default()
                .as_secs();

        Self {
            timestamp,

            pid:
                event.pid,

            uid:
                event.uid,

            application:
                identity.application,

            process_name:
                identity.comm,

            executable:
                identity.executable,

            destination:
                destination.to_string(),

            hostname: None,

            port:
                event.port,

            protocol,

            verdict,
        }
    }
}
