#!/usr/bin/env bash
set -euo pipefail

sudo pacman -S --needed \
  rustup \
  clang \
  llvm \
  bpftool

rustup toolchain install stable

rustup toolchain install \
  nightly \
  --component rust-src

if command -v bpf-linker >/dev/null 2>&1; then
  [[ $(bpf-linker --version) == "bpf-linker 0.12.0" ]] || {
    echo "bpf-linker 0.12.0 is required" >&2
    exit 1
  }
else
  cargo install bpf-linker --version 0.12.0 --locked
fi
