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

FROM docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl3t64 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/axiom-web-gateway /usr/local/bin/axiom-web-gateway
COPY --from=verifier-build /axiom-gateway-verify /usr/local/bin/axiom-gateway-verify
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/axiom-web-gateway"]
