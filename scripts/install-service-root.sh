#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 2 ]] || exit 2
build_dir="$1"
source_dir="$2"

install -Dm755 "$build_dir/omasnitchd" /usr/local/bin/omasnitchd
install -Dm755 "$build_dir/omasnitchctl" /usr/local/bin/omasnitchctl
install -Dm644 "$source_dir/systemd/omasnitch.service" /etc/systemd/system/omasnitch.service
install -d -m700 /var/lib/omasnitch
if [[ -f /var/lib/omasnitch/rules.json ]]; then
  chmod 600 /var/lib/omasnitch/rules.json
fi
systemctl daemon-reload
systemctl enable omasnitch.service
systemctl restart omasnitch.service
systemctl is-active --quiet omasnitch.service
