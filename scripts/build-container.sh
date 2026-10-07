#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
engine=${CONTAINER_ENGINE:-podman}
mkdir -p out
revision=$(git rev-parse HEAD)
cargo vendor --locked --versioned-dirs out/vendor > out/vendor-config.toml
# Container paths are independent of this machine and neighboring checkouts.
sed -i 's|directory = "[^"]*"|directory = "/vendor"|' out/vendor-config.toml
"$engine" build --label "org.opencontainers.image.revision=$revision" --label "org.opencontainers.image.source=https://github.com/astrea-foundation/axiom-web-gateway" --label "org.opencontainers.image.licenses=Apache-2.0" --target runtime -t axiom-web-gateway:dev .
"$engine" build --label "org.opencontainers.image.revision=$revision" --label "org.opencontainers.image.source=https://github.com/astrea-foundation/axiom-web-gateway" --label "org.opencontainers.image.licenses=Apache-2.0" --target verifier -t axiom-gateway-verifier:dev .
python3 scripts/record-build.py --engine "$engine" --revision "$revision" --output out/build-record.json
