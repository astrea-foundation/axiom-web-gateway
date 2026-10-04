# syntax=docker/dockerfile:1
# AMD64 is deliberate: the qualified target is Azure Intel TDX.
FROM docker.io/library/rust@sha256:618466f4caae45cd6b7b6adfa98764ad462aacf67e7149c6d277c625da9f1282 AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake make perl pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Vendor from Cargo.lock on the authenticated developer/build host; credentials
# and private source checkouts never enter the image or Docker build arguments.
COPY out/vendor /vendor
COPY out/vendor-config.toml /build/.cargo/config.toml
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --offline --locked --release -p axiom-web-gateway -p axiom-gateway-protocol --bin axiom-web-gateway --bin axiom-gateway-verify

FROM build AS verifier-build
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --offline --locked --release --target x86_64-unknown-linux-musl -p axiom-gateway-protocol --bin axiom-gateway-verify

FROM scratch AS verifier
COPY --from=verifier-build /build/target/x86_64-unknown-linux-musl/release/axiom-gateway-verify /axiom-gateway-verify
ENTRYPOINT ["/axiom-gateway-verify"]

FROM docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3t64 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/axiom-web-gateway /usr/local/bin/axiom-web-gateway
COPY --from=verifier-build /build/target/x86_64-unknown-linux-musl/release/axiom-gateway-verify /usr/local/bin/axiom-gateway-verify
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/axiom-web-gateway"]

FROM runtime AS appliance-tools
USER root
RUN apt-get update && apt-get install -y --no-install-recommends busybox-static util-linux linux-image-amd64 systemd systemd-ukify systemd-boot-efi sbsigntool pesign dosfstools mtools gdisk qemu-utils python3 cpio kmod && rm -rf /var/lib/apt/lists/*
COPY deploy/appliance /build-tools
ENTRYPOINT ["python3", "/build-tools/build.py"]
