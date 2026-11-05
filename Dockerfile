# syntax=docker/dockerfile:1
# CPU-only linux/amd64 Tinfoil Container. No Azure SDK or guest appliance.
FROM docker.io/library/golang@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS verifier-build
WORKDIR /build
COPY verifier/go.mod verifier/go.sum ./
RUN go mod download
COPY verifier ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /axiom-gateway-verify ./cmd/native

FROM docker.io/library/rust@sha256:618466f4caae45cd6b7b6adfa98764ad462aacf67e7149c6d277c625da9f1282 AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake make perl pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Locked dependencies are vendored on the build host. No GitHub token
# or neighboring checkout is sent as a build argument or included in the image.
COPY out/vendor /vendor
COPY out/vendor-config.toml /build/.cargo/config.toml
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --offline --locked --release -p axiom-web-gateway --bin axiom-web-gateway

FROM scratch AS verifier
COPY --from=verifier-build /axiom-gateway-verify /axiom-gateway-verify
ENTRYPOINT ["/axiom-gateway-verify"]

FROM python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217 AS direct-verifier
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
COPY out/direct-verifier /build/direct-verifier
RUN python -m venv /opt/axiom-direct \
    && /opt/axiom-direct/bin/pip install --require-hashes -r /build/direct-verifier/deploy/direct/requirements.lock \
    && /opt/axiom-direct/bin/python /build/direct-verifier/scripts/build_direct_tools.py --python /opt/axiom-direct/bin/python --output /usr/local/bin
COPY deploy/astreaai-staging.json /etc/axiom/astreaai-staging.json
COPY deploy/astreaai-production.json /etc/axiom/astreaai-production.json
COPY scripts/pin-direct-configs.py /build/pin-direct-configs.py
RUN python /build/pin-direct-configs.py \
    && chown 10001:10001 /etc/axiom/astreaai-*.json \
    && chmod 0400 /etc/axiom/astreaai-*.json

FROM python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl3t64 && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=direct-verifier /opt/axiom-direct /opt/axiom-direct
COPY --from=direct-verifier /usr/local/bin/axiom-direct-verify /usr/local/bin/axiom-direct-verify
COPY --from=direct-verifier --chown=10001:10001 /etc/axiom/astreaai-staging.json /etc/axiom/astreaai-staging.json
COPY --from=direct-verifier --chown=10001:10001 /etc/axiom/astreaai-production.json /etc/axiom/astreaai-production.json
COPY --from=build /build/target/release/axiom-web-gateway /usr/local/bin/axiom-web-gateway
COPY --from=verifier-build /axiom-gateway-verify /usr/local/bin/axiom-gateway-verify
COPY --chmod=0555 scripts/check-gateway-health.py /usr/local/bin/axiom-gateway-health
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/axiom-web-gateway"]
