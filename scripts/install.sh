#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
"$ROOT/scripts/bootstrap.sh" --check

# A release install may pass the full commit reviewed by the marketplace.
# This script never fetches or changes revisions: build and QML use this checkout.
if [[ -n ${OMASNITCH_REVIEWED_COMMIT:-} ]]; then
  [[ ${OMASNITCH_REVIEWED_COMMIT} =~ ^[0-9a-f]{40}$ ]] || {
    echo "OMASNITCH_REVIEWED_COMMIT must be a full 40-character SHA" >&2
    exit 1
  }
  actual_commit="$(git rev-parse --verify 'HEAD^{commit}')"
  [[ "$actual_commit" == "$OMASNITCH_REVIEWED_COMMIT" ]] || {
    echo "Checkout is $actual_commit, expected $OMASNITCH_REVIEWED_COMMIT" >&2
    exit 1
  }
  [[ -z $(git status --porcelain --untracked-files=all) ]] || {
    echo "Checkout has local changes; use the exact reviewed commit" >&2
    exit 1
  }
fi

omarchy plugin validate "$ROOT"
plugin_dir="$HOME/.config/omarchy/plugins/vesp.omasnitch"
[[ ! -L "$plugin_dir" ]] || {
  echo "Refusing to overwrite a symlink: $plugin_dir" >&2
  exit 1
}
if [[ -e "$plugin_dir/manifest.json" ]]; then
  existing_id="$(jq -r '.id // empty' "$plugin_dir/manifest.json")"
  [[ "$existing_id" == "vesp.omasnitch" ]] || {
    echo "Refusing to overwrite another plugin: $plugin_dir" >&2
    exit 1
  }
fi
[[ ! -e "$plugin_dir" || -d "$plugin_dir" ]] || {
  echo "Refusing to overwrite a non-directory: $plugin_dir" >&2
  exit 1
}

build_dir="$(mktemp -d "${TMPDIR:-/tmp}/omasnitch-build.XXXXXXXX")"
trap 'rm -rf -- "$build_dir"' EXIT
CARGO_TARGET_DIR="$build_dir" cargo build --locked --release --package omasnitch

sudo install -Dm755 "$build_dir/release/omasnitchd" /usr/local/bin/omasnitchd
sudo install -Dm755 "$build_dir/release/omasnitchctl" /usr/local/bin/omasnitchctl
sudo install -Dm644 systemd/omasnitch.service /etc/systemd/system/omasnitch.service
sudo install -d -m755 /var/lib/omasnitch
sudo systemctl daemon-reload
sudo systemctl enable omasnitch.service
sudo systemctl restart omasnitch.service

mkdir -p "$plugin_dir"
install -m644 BarWidget.qml Panel.qml manifest.json "$plugin_dir/"
omarchy plugin validate "$plugin_dir"
omarchy-shell shell rescanPlugins
omarchy plugin enable vesp.omasnitch

echo "OmaSnitch installed from $ROOT"
