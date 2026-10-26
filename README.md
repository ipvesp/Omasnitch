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
next internet connection attempt from the selected running process.

In Settings, **Ask on first internet attempt** is off by default. When
enabled, a new app's first internet `connect()` attempt is denied and queued
for review. The bar shows pending requests and sends a desktop notification;
the panel offers one-time, timed, session, permanent allow, and block actions.
The app may have to retry its connection after a decision. Known permanent
rules are applied to new processes by the daemon, but the first attempt can
still be denied before process identification completes.

The IP preview shows applications with matching connection attempts in the
recent event window. It does not create an IP rule or predict unseen traffic.

Recent destinations include a reverse DNS (PTR) hostname when one exists.
This name is not necessarily the domain the application requested. Exact
domain blocking requires DNS request tracking in addition to the current
IP-based connection hook and is not implemented.

## Install from the reviewed commit

Use the full 40-character commit SHA named in the marketplace review. The
checkout, native build, systemd service, and QML files must all come from that
same commit. The installer does not clone, pull, update, or run remote scripts.

```bash
read -r -p "Reviewed commit SHA: " reviewed_commit
[[ "$reviewed_commit" =~ ^[0-9a-f]{40}$ ]] || exit 1
git clone --no-checkout https://github.com/ipvesp/Omasnitch.git
git -C Omasnitch checkout --detach "$reviewed_commit"
cd Omasnitch
./scripts/install-deps.sh
OMASNITCH_REVIEWED_COMMIT="$reviewed_commit" ./scripts/install.sh
```

The installer verifies `HEAD` and a clean checkout before building with
`cargo --locked`. It validates the repository-root plugin, installs the daemon
and CLI, starts the systemd service, and copies the QML files from that same
checkout into Omarchy. `sudo` is used only for system files and the service.
The dependency script installs Arch build tools and bpf-linker 0.12.0.

Omarchy's `plugin add` command clones the current default branch and does not
install the native daemon. Use the commit-pinned checkout above for the full
installation.

## Validate before submitting

```bash
omarchy plugin validate .
/usr/lib/qt6/bin/qmllint -I "$OMARCHY_PATH/shell" BarWidget.qml Panel.qml
cargo build --locked --release --package omasnitch
```

Publish only after the code is committed and the SHA in the marketplace
submission identifies that exact commit. The repository must be public and
contain the root `manifest.json`, `BarWidget.qml`, `Panel.qml`, README, and
LICENSE.

## Remove

```bash
./scripts/uninstall.sh
```

Removal leaves saved rules in `/var/lib/omasnitch/rules.json` for recovery.

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
