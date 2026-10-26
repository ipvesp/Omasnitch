#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"

version="$(jq -er '.version' manifest.json)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "Invalid manifest version" >&2
  exit 1
}
service_version="$(sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' Cargo.toml | head -n 1)"
[[ "$service_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "Invalid service version" >&2
  exit 1
}
head="$(git rev-parse --verify 'HEAD^{commit}')"
tag="$(git rev-parse --verify "v${version}^{commit}")"
[[ "$head" == "$tag" ]] || {
  echo "The installed checkout is not the reviewed v${version} release" >&2
  exit 1
}
[[ -z $(git status --porcelain --untracked-files=all) ]] || {
  echo "The installed checkout has local changes" >&2
  exit 1
}

if [[ ${1:-} == --check ]]; then
  echo "Reviewed source: $head (v$version)"
  exit 0
fi

log_dir="${XDG_CACHE_HOME:-$HOME/.cache}/omasnitch"
install -d -m700 "$log_dir"
touch "$log_dir/install.log"
chmod 600 "$log_dir/install.log"

if command -v omasnitchctl >/dev/null 2>&1 \
  && [[ $(omasnitchctl --version 2>/dev/null || true) == "omasnitchctl $service_version" ]] \
  && omasnitchctl status >/dev/null 2>&1; then
  echo "OmaSnitch service v$service_version is already running"
  exit 0
fi

exec >"$log_dir/install.log" 2>&1
echo "Installing OmaSnitch service v$service_version from plugin v$version ($head)"

packages=()
command -v rustup >/dev/null 2>&1 || packages+=(rustup)
command -v clang >/dev/null 2>&1 || packages+=(clang)
command -v llvm-config >/dev/null 2>&1 || packages+=(llvm)
if (( ${#packages[@]} > 0 )); then
  pkexec /usr/bin/pacman -S --needed --noconfirm "${packages[@]}"
fi
rustup toolchain install stable
rustup toolchain install nightly --component rust-src

if ! command -v bpf-linker >/dev/null 2>&1; then
  rustup run stable cargo install bpf-linker --version 0.12.0 --locked
fi
[[ $(bpf-linker --version) == "bpf-linker 0.12.0" ]] || {
  echo "bpf-linker 0.12.0 is required" >&2
  exit 1
}

build_dir="$(mktemp -d "${TMPDIR:-/tmp}/omasnitch-build.XXXXXXXX")"
trap 'rm -rf -- "$build_dir"' EXIT
CARGO_TARGET_DIR="$build_dir" rustup run stable cargo build --locked --release --package omasnitch
pkexec /usr/bin/bash "$ROOT/scripts/install-service-root.sh" "$build_dir/release" "$ROOT"

for (( attempt = 0; attempt < 20; attempt++ )); do
  if omasnitchctl status >/dev/null 2>&1; then
    echo "OmaSnitch service v$service_version installed"
    exit 0
  fi
  sleep 0.5
done
omasnitchctl status
echo "OmaSnitch service v$service_version installed"
