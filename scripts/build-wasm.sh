#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo build --locked --release -p axiom-gateway-protocol --features browser --target wasm32-unknown-unknown --lib
wasm-bindgen --target web --out-dir sdk/wasm --out-name axiom_gateway_protocol target/wasm32-unknown-unknown/release/axiom_gateway_protocol.wasm
