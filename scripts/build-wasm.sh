#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p sdk/wasm out
cd verifier
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o ../out/axiom-gateway-verify ./cmd/native
GOOS=js GOARCH=wasm go build -trimpath -ldflags='-s -w' -o ../sdk/wasm/axiom_gateway_verifier.wasm ./cmd/browser
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ../sdk/wasm/wasm_exec.js
