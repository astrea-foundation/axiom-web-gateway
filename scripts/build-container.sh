#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
engine=${CONTAINER_ENGINE:-podman}
mkdir -p out
cargo vendor --locked --versioned-dirs out/vendor > out/vendor-config.toml
# Container paths are independent of this machine and neighboring checkouts.
sed -i 's|directory = "[^"]*"|directory = "/vendor"|' out/vendor-config.toml
"$engine" build --target runtime -t axiom-web-gateway:dev .
"$engine" build --target verifier -t axiom-gateway-verifier:dev .
"$engine" build --target appliance-tools -t axiom-gateway-appliance-tools:dev .
