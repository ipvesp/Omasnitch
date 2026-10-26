#!/usr/bin/env bash
set -euo pipefail

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

if [[ -e "$HOME/.config/omarchy/plugins/vesp.omasnitch" ]]; then
  omarchy plugin remove vesp.omasnitch --yes
fi
