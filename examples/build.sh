#!/usr/bin/env bash
# Build the example guard crates into WebAssembly Components and copy them to
# tests/fixtures/, where the WASM-runner tests `include_bytes!` them.
#
# The committed fixtures let `cargo test --features wasm` run without the WASM
# toolchain (CI has no wasm32 target or wasm-tools); rerun this only when an
# example guard's source changes.
#
# Requires: rustup target add wasm32-unknown-unknown; cargo install wasm-tools.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../tests/fixtures"
mkdir -p "$fixtures"

build_guard() {
  local crate="$1" out="$2"
  echo "building $crate -> $out"
  (cd "$here/$crate" && cargo build --release --target wasm32-unknown-unknown)
  local module="$here/$crate/target/wasm32-unknown-unknown/release/${crate//-/_}.wasm"
  wasm-tools component new "$module" -o "$fixtures/$out"
  wasm-tools validate --features component-model "$fixtures/$out"
}

build_guard redact-foo-guard redact-foo-guard.wasm
build_guard egress-guard egress-guard.wasm

echo "fixtures written to $fixtures"
