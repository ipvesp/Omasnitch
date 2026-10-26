#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 2 ]] || exit 2
build_dir="$1"
source_dir="$2"

backup_dir="$(mktemp -d /tmp/omasnitch-install.XXXXXXXX)"
chmod 700 "$backup_dir"
for file in /usr/local/bin/omasnitchd /usr/local/bin/omasnitchctl /etc/systemd/system/omasnitch.service; do
  if [[ -f "$file" ]]; then
    cp -a -- "$file" "$backup_dir/$(basename "$file")"
  fi
done
rollback() {
  status=$?
  if (( status != 0 )); then
    for file in /usr/local/bin/omasnitchd /usr/local/bin/omasnitchctl /etc/systemd/system/omasnitch.service; do
      previous="$backup_dir/$(basename "$file")"
      if [[ -f "$previous" ]]; then
        cp -a -- "$previous" "$file"
      else
        rm -f -- "$file"
      fi
    done
    systemctl daemon-reload || true
    systemctl restart omasnitch.service || true
    echo "OmaSnitch install failed; restored the previous service" >&2
  fi
  rm -rf -- "$backup_dir"
  exit "$status"
}
trap rollback EXIT

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
for (( attempt = 0; attempt < 20; attempt++ )); do
  if systemctl is-active --quiet omasnitch.service \
    && /usr/local/bin/omasnitchctl status >/dev/null 2>&1; then
    exit 0
  fi
  sleep 0.25
done
systemctl status omasnitch.service --no-pager >&2 || true
exit 1
