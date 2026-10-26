use serde::{
    Deserialize,
    Serialize,
};

use crate::model::{
    Connection,
    Rule,
    RuleAction,
};

#[derive(
    Debug,
    Deserialize,
)]
#[serde(
    tag = "cmd",
    rename_all = "snake_case"
)]
pub enum Request {
    Status,

    Rules,

    Events,

    Traffic,

    Temporary,

    Pending,

    PromptStatus,

    SetPrompt { enabled: bool, uid: u32 },

    Profiles,

    SwitchProfile { name: String },

    TemporaryAllow { application: String, seconds: Option<u64>, #[serde(default)] once: bool },

    RevokeTemporary { application: String },

    PreviewIp { address: String },

    SetRule {
        application: String,
        action: RuleAction,
    },

    RemoveRule {
        application: String,
    },

    ClearEvents,
}

#[derive(
    Debug,
    Serialize,
)]
pub struct Status {
    pub running: bool,
    pub ebpf: bool,
    pub rules: usize,
    pub events: usize,
}

#[derive(Debug, Serialize)]
pub struct ProfileStatus {
    pub active: String,
    pub names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IpPreview {
    pub address: String,
    pub applications: Vec<String>,
    pub recorded_attempts: usize,
}

#[derive(Debug, Serialize)]
pub struct TrafficUsage {
    pub application: String,
    pub uid: u32,
    pub uploaded: u64,
    pub downloaded: u64,
}

#[derive(Debug, Serialize)]
pub struct TemporaryRule {
    pub application: String,
    pub remaining_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PendingConnection {
    pub application: String,
    pub pid: u32,
    pub destination: String,
    pub uid: u32,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct PromptStatus {
    pub enabled: bool,
    pub uid: Option<u32>,
}

#[derive(
    Debug,
    Serialize,
)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case"
)]
pub enum Response {
    Status(Status),

    Rules(Vec<Rule>),

    Events(Vec<Connection>),

    Traffic(Vec<TrafficUsage>),

    Temporary(Vec<TemporaryRule>),

    Pending(Vec<PendingConnection>),

    PromptStatus(PromptStatus),

    Profiles(ProfileStatus),

    IpPreview(IpPreview),

    Ok,

    Error(String),
}
