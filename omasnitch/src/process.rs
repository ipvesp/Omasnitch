use std::{
    fs,
    path::{
        Path,
        PathBuf,
    },
};

#[derive(
    Debug,
    Clone,
)]
pub struct ProcessIdentity {
    pub application: String,
    pub executable: String,
    pub comm: String,
}

pub fn resolve_process(
    pid: u32,
    fallback_comm: &str,
) -> ProcessIdentity {
    let executable =
        resolve_executable(
            pid,
        );

    let application =
        executable
            .as_deref()
            .and_then(
                application_from_executable,
            )
            .or_else(|| {
                resolve_cmdline_application(
                    pid,
                )
            })
            .unwrap_or_else(|| {
                normalize_application_name(
                    fallback_comm,
                )
            });

    ProcessIdentity {
        application,

        executable:
            executable
                .unwrap_or_default(),

        comm:
            fallback_comm
                .to_string(),
    }
}

pub fn resolve_executable(
    pid: u32,
) -> Option<String> {
    let path =
        PathBuf::from(
            format!(
                "/proc/{pid}/exe"
            ),
        );

    fs::read_link(
        path,
    )
    .ok()
    .map(|path| {
        path
            .to_string_lossy()
            .trim_end_matches(
                " (deleted)",
            )
            .to_string()
    })
}

pub fn process_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    stat[end + 1..].split_whitespace().nth(19)?.parse().ok()
}

fn resolve_cmdline_application(
    pid: u32,
) -> Option<String> {
    let path =
        format!(
            "/proc/{pid}/cmdline"
        );

    let bytes =
        fs::read(
            path,
        )
        .ok()?;

    if bytes.is_empty() {
        return None;
    }

    let end =
        bytes
            .iter()
            .position(
                |byte| {
                    *byte == 0
                },
            )
            .unwrap_or(
                bytes.len(),
            );

    if end == 0 {
        return None;
    }

    let command =
        String::from_utf8_lossy(
            &bytes[..end],
        )
        .to_string();

    let filename =
        Path::new(
            &command,
        )
        .file_name()?
        .to_string_lossy()
        .to_string();

    Some(
        normalize_application_name(
            &filename,
        ),
    )
}

fn application_from_executable(
    executable: &str,
) -> Option<String> {
    if executable.is_empty() {
        return None;
    }

    let filename =
        Path::new(
            executable,
        )
        .file_name()?
        .to_string_lossy()
        .to_string();

    Some(
        normalize_application_name(
            &filename,
        ),
    )
}

pub fn normalize_application_name(
    name: &str,
) -> String {
    let lower =
        name
            .trim()
            .to_lowercase();

    match lower.as_str() {
        "chromium"
        | "chromium-browser" =>
            "chromium"
                .to_string(),

        "google-chrome"
        | "google-chrome-stable" =>
            "google-chrome"
                .to_string(),

        "brave"
        | "brave-browser"
        | "brave-bin" =>
            "brave"
                .to_string(),

        "firefox"
        | "firefox-bin" =>
            "firefox"
                .to_string(),

        "discord"
        | "discordcanary"
        | "discord-canary" =>
            "discord"
                .to_string(),

        "steam"
        | "steamwebhelper" =>
            "steam"
                .to_string(),

        "code"
        | "code-oss"
        | "visual-studio-code" =>
            "vscode"
                .to_string(),

        "zed"
        | "zed-editor" =>
            "zed"
                .to_string(),

        _ =>
            lower,
    }
}

pub fn application_for_pid(
    pid: u32,
) -> Option<String> {
    let executable =
        resolve_executable(
            pid,
        );

    executable
        .as_deref()
        .and_then(
            application_from_executable,
        )
        .or_else(|| {
            resolve_cmdline_application(
                pid,
            )
        })
}

//
// Sistemde şu anda belirli uygulamaya ait
// çalışan bütün TGID/PID'leri bul.
//
pub fn pids_for_application(
    application: &str,
) -> Vec<u32> {
    let wanted =
        normalize_application_name(
            application,
        );

    let Ok(entries) =
        fs::read_dir(
            "/proc",
        )
    else {
        return Vec::new();
    };

    let mut result =
        Vec::new();

    for entry in entries.flatten() {
        let filename =
            entry.file_name();

        let Some(pid_string) =
            filename.to_str()
        else {
            continue;
        };

        let Ok(pid) =
            pid_string.parse::<u32>()
        else {
            continue;
        };

        let Some(found_app) =
            application_for_pid(
                pid,
            )
        else {
            continue;
        };

        if found_app == wanted {
            result.push(
                pid,
            );
        }
    }

    result
}
