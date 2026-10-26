#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$HOME/.config/omarchy/plugins/vesp.omasnitch"
if [[ -e "$plugin_dir" || -L "$plugin_dir" ]]; then
  omarchy plugin remove vesp.omasnitch --yes
fi

sudo systemctl disable \
  --now \
  omasnitch.service || true

sudo rm -f \
  /etc/systemd/system/omasnitch.service

sudo rm -f \
  /usr/local/bin/omasnitchd

sudo rm -f \
  /usr/local/bin/omasnitchctl

sudo systemctl daemon-reload
