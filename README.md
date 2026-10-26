# OmaSnitch

Application-level outgoing network firewall for Omarchy.

The panel lists installed desktop applications followed by processes observed
in connection events. Select an item to see its rule, connection counts, and
recent destinations. Rules are available for
desktop entries with a distinct executable; launchers that share a browser or
another process cannot be controlled independently by the current PID-based
firewall.

The Name tab shows all items; Recent shows the ten latest active items;
Connections shows items with recorded connections; Blocked shows items with a
block rule or blocked traffic. Each tab sorts its results accordingly.
Pinned items and collapsed sections persist in
`~/.config/omasnitch/panel.json`. Details show the last connection time,
local versus internet totals, TCP versus UDP totals, and copy actions for
addresses, PTR names, and executable paths. The panel can hide local traffic.
Services can be tagged and grouped, annotated with notes, and acknowledged
when their yellow **NEW** badge appears. These display preferences are saved
in `panel.json`.

The detail view displays uploaded and downloaded packet bytes for outgoing
sockets. The counters include network headers and may not match an app's own
payload totals. They start over when the daemon restarts. Connection counts
cover the daemon's current in-memory event window and also reset on restart.

Rules have three manually selected profiles: Home, Work, and Public Wi-Fi.
They are stored in `/var/lib/omasnitch/rules.json`. A temporary allow can
last ten minutes or until the daemon restarts. **Allow once** permits the
next connection attempt from the selected running process.

In Settings, **Ask on first internet attempt** is off by default. When
enabled, a new app's first internet `connect()` attempt is denied and queued
for review. The bar shows pending requests and sends a desktop notification;
the panel offers one-time, timed, session, permanent allow, and block actions.
The app may have to retry its connection after a decision. Known permanent
rules are applied to new processes by the daemon, but the first attempt can
still be denied before process identification completes.

The IP preview shows applications with matching connection attempts in the
recent event window. It does not create an IP rule or predict unseen traffic.

The firewall checks IPv4 and IPv6 TCP connects and UDP sends, and drops
outgoing packets from sockets it has associated with a blocked process. This
also stops traffic on a connection that was open before a Block rule was
applied. The rules are process based: a newly started process can make a
connection during the daemon's process discovery interval (up to roughly
250 ms), and sockets opened before the daemon attached its hooks may not be
associated with their process. Raw sockets and traffic outside the daemon's
cgroup are outside this firewall's scope. Do not rely on OmaSnitch as the
only network isolation boundary for untrusted processes.

Recent destinations include a reverse DNS (PTR) hostname when one exists.
This name is not necessarily the domain the application requested. Exact
domain blocking requires DNS request tracking in addition to the current
IP-based connection hook and is not implemented.

## Install

```bash
omarchy plugin add https://github.com/ipvesp/Omasnitch.git --enable
```

This installs the Omarchy bar widget. Once enabled, it starts a local setup
process for the native firewall service. Omarchy, Quickshell, Git, Bash, jq,
Polkit, systemd, and an Arch-compatible `pacman` are required. Setup installs
`rustup`, `clang`, and `llvm` with pacman if they are missing. It installs the
stable Rust toolchain, nightly Rust with `rust-src`, and `bpf-linker` 0.12.0;
Cargo downloads locked Rust dependencies when they are not cached. Building
requires a Linux kernel with the eBPF and cgroup hooks used by the daemon.
Plugin release v0.3.1 keeps the native service at v0.3.0. Updating an already
running v0.3.0 service only refreshes the panel; it does not rebuild the daemon.
The panel's copy button uses `wl-copy`, and desktop notifications use
`notify-send` when available.

The plugin checks whether the matching OmaSnitch service is running. On a new
installation it verifies that the cloned checkout is clean and that its HEAD
matches the `v0.3.1` release tag, then builds the daemon from that checkout
with `cargo --locked`. It does not clone or download another application
revision. Omarchy's polkit agent will ask for permission to install build
packages, the daemon and CLI binaries in `/usr/local/bin`, and the systemd
service in `/etc/systemd/system`. The service runs as root with BPF and network
capabilities, stores rules in `/var/lib/omasnitch`, and exposes its local
control socket to members of `wheel`. The bar shows setup
progress; if it fails, open the panel to retry and check
`~/.cache/omasnitch/install.log`.

`omarchy plugin add` itself clones the current default branch. For an exact
reviewed-commit checkout, use the manual route below.

## Install from the reviewed commit manually

Use the full 40-character commit SHA named in the marketplace review. The
checkout, native build, systemd service, and QML files must all come from that
same commit. The installer does not clone, pull, update, or run remote scripts.

```bash
read -r -p "Reviewed commit SHA: " reviewed_commit
[[ "$reviewed_commit" =~ ^[0-9a-f]{40}$ ]] || exit 1
git clone --no-checkout https://github.com/ipvesp/Omasnitch.git
git -C Omasnitch checkout --detach "$reviewed_commit"
cd Omasnitch
./scripts/bootstrap.sh --check
./scripts/install-deps.sh
OMASNITCH_REVIEWED_COMMIT="$reviewed_commit" ./scripts/install.sh
```

The installer verifies `HEAD` and a clean checkout before building with
`cargo --locked`. It validates the repository-root plugin, installs the daemon
and CLI, starts the systemd service, and copies the QML files from that same
checkout into Omarchy. `sudo` is used only for system files and the service.
The dependency script installs Arch build tools and bpf-linker 0.12.0.

The panel's preferences and notes are kept in a private directory under
`~/.config/omasnitch`. The daemon keeps rules in `/var/lib/omasnitch` with
owner-only access. Existing files are restricted when the updated panel or
daemon starts. The install log in `~/.cache/omasnitch` is private as well.

The manual installer verifies the selected commit, builds the daemon, and
copies the QML plugin from that checkout. It needs a terminal for sudo. It
refuses to replace an existing plugin directory unless you explicitly set
`OMASNITCH_REPLACE_EXISTING=1`.

## Validate before submitting

```bash
omarchy plugin validate .
/usr/lib/qt6/bin/qmllint -I "$OMARCHY_PATH/shell" BarWidget.qml Panel.qml
cargo build --locked --release --package omasnitch
# Against an installed 0.3.0 daemon; uses a temporary test-only Block rule:
python3 tests/firewall_regression.py
python3 tests/allow_once_regression.py
```

Publish only after the code is committed and the SHA in the marketplace
submission identifies that exact commit. The repository must be public and
contain the root `manifest.json`, `BarWidget.qml`, `Panel.qml`, README, and
LICENSE.

## Remove

```bash
./scripts/uninstall.sh                         # from a manual checkout
# or, after `omarchy plugin add`:
~/.config/omarchy/plugins/vesp.omasnitch/scripts/uninstall.sh
```

Removal leaves saved rules in `/var/lib/omasnitch/rules.json` for recovery.
Use the uninstall script to remove the widget and service together. Running
`omarchy plugin remove` alone leaves the system service installed.

## CLI examples

```bash
omasnitchctl status
omasnitchctl profiles
omasnitchctl profile Work
omasnitchctl traffic
omasnitchctl pending
omasnitchctl allow-once firefox
omasnitchctl allow-for firefox 600
omasnitchctl allow-session firefox
omasnitchctl revoke firefox
omasnitchctl preview-ip 1.1.1.1
```
