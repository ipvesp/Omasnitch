use anyhow::Result;

use clap::{
    Parser,
    Subcommand,
    ValueEnum,
};

use serde_json::{
    json,
    Value,
};

use tokio::{
    io::{
        AsyncBufReadExt,
        AsyncWriteExt,
        BufReader,
    },
    net::UnixStream,
};

const SOCKET_PATH: &str =
    "/run/omasnitch/omasnitch.sock";

#[derive(Parser)]
#[command(name = "omasnitchctl", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status,

    Rules,

    Events,

    Traffic,

    Temporary,

    Pending,

    PromptStatus,

    PromptOn { uid: u32 },

    PromptOff { uid: u32 },

    Profiles,

    Profile { name: String },

    AllowOnce { application: String },

    AllowSession { application: String },

    Revoke { application: String },

    AllowFor { application: String, seconds: u64 },

    PreviewIp { address: String },

    Clear,

    Allow {
        application: String,
    },

    Block {
        application: String,
    },

    Ask {
        application: String,
    },

    Remove {
        application: String,
    },
}

#[derive(
    Clone,
    ValueEnum,
)]
enum Format {
    Json,
}

async fn request(
    value: Value,
) -> Result<Value> {
    let stream =
        UnixStream::connect(
            SOCKET_PATH,
        )
        .await?;

    let (
        reader,
        mut writer,
    ) =
        stream.into_split();

    let mut payload =
        serde_json::to_vec(
            &value,
        )?;

    payload.push(b'\n');

    writer
        .write_all(
            &payload,
        )
        .await?;

    let mut reader =
        BufReader::new(
            reader,
        );

    let mut line =
        String::new();

    reader
        .read_line(
            &mut line,
        )
        .await?;

    Ok(
        serde_json::from_str(
            line.trim(),
        )?,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli =
        Cli::parse();

    let command =
        match cli.command {
            Command::Status =>
                json!({
                    "cmd": "status"
                }),

            Command::Rules =>
                json!({
                    "cmd": "rules"
                }),

            Command::Events =>
                json!({
                    "cmd": "events"
                }),

            Command::Traffic => json!({ "cmd": "traffic" }),

            Command::Temporary => json!({ "cmd": "temporary" }),

            Command::Pending => json!({ "cmd": "pending" }),

            Command::PromptStatus => json!({ "cmd": "prompt_status" }),

            Command::PromptOn { uid } => json!({ "cmd": "set_prompt", "enabled": true, "uid": uid }),

            Command::PromptOff { uid } => json!({ "cmd": "set_prompt", "enabled": false, "uid": uid }),

            Command::Profiles => json!({ "cmd": "profiles" }),

            Command::Profile { name } => json!({ "cmd": "switch_profile", "name": name }),

            Command::AllowOnce { application } => json!({ "cmd": "temporary_allow", "application": application, "seconds": null, "once": true }),

            Command::AllowSession { application } => json!({ "cmd": "temporary_allow", "application": application, "seconds": null }),

            Command::Revoke { application } => json!({ "cmd": "revoke_temporary", "application": application }),

            Command::AllowFor { application, seconds } => json!({ "cmd": "temporary_allow", "application": application, "seconds": seconds }),

            Command::PreviewIp { address } => json!({ "cmd": "preview_ip", "address": address }),

            Command::Clear =>
                json!({
                    "cmd":
                        "clear_events"
                }),

            Command::Allow {
                application
            } =>
                json!({
                    "cmd": "set_rule",
                    "application":
                        application,
                    "action": "allow"
                }),

            Command::Block {
                application
            } =>
                json!({
                    "cmd": "set_rule",
                    "application":
                        application,
                    "action": "block"
                }),

            Command::Ask {
                application
            } =>
                json!({
                    "cmd": "set_rule",
                    "application":
                        application,
                    "action": "ask"
                }),

            Command::Remove {
                application
            } =>
                json!({
                    "cmd":
                        "remove_rule",
                    "application":
                        application
                }),
        };

    let response =
        request(
            command,
        )
        .await?;

    println!(
        "{}",
        serde_json::to_string_pretty(
            &response,
        )?
    );

    Ok(())
}
