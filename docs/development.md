# Development

Use `~/sync2/work/axiom-web-gateway`. A clone builds independently from pinned
public Cargo dependencies; no Desktop checkout or submodule is required. Rust
1.90 or newer, Node 24 or newer, pnpm 11.22 and the matching wasm-bindgen CLI are
required. Cargo.lock and pnpm-lock.yaml record dependencies. Azure SDK and all
three shared Axiom crates are pinned by full Git revision.

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.127 --locked
pnpm install --frozen-lockfile
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p axiom-web-gateway --locked -- --ignored
pnpm build
pnpm typecheck
pnpm test
```

The explicit ignored Rust test requires installed JavaScript dependencies and
runs the published EHBP browser implementation against the Rust server
composition. No network inference or plaintext listener is started by tests.
The browser and native evidence verifiers use the same Rust source and Intel
DCAP verification library. WASM is packaged with the SDK, never fetched from the
attester. SDK integration is described in [protocol](protocol.md).

## Containers

```sh
sh scripts/build-container.sh
```

This uses Podman by default; set `CONTAINER_ENGINE=docker` for Docker. It vendors
only Cargo.lock sources on the authenticated build host and rewrites vendor
paths for the container. No GitHub credentials or neighboring checkout enter
build arguments/layers. Outputs are local development images:
`axiom-web-gateway:dev`, `axiom-gateway-verifier:dev` (static offline verifier),
and `axiom-gateway-appliance-tools:dev`. OCI runtime bases are digest-pinned.
The signed appliance includes the exact installed runtime libraries and kernel;
APT package metadata must be retained for release provenance/qualification.
This is not yet a claim of byte-for-byte reproducible package installation.

On an ordinary host the runtime fails before opening its listener: it requires
Azure hardware/HCL/vTPM evidence, signed workload metadata, strict local
verification and backend admission. Container configuration mounts are only for
qualification diagnostics. Production uses baked configuration in the UKI;
a host-mounted mutable config or a general-purpose Docker host is insufficient.

## Shared code and branches

Make shared inference changes in `axiom-desktop` first, qualify them, then update
all three shared Cargo revisions together. Do not commit machine-specific path
patches. Production builds resolve the pinned remote revision.

Push development to `dev`; feature PRs target `dev`. CI performs required checks
only, with concurrency cancellation. It never deploys or publishes installers.
Production `main`, release artifacts and public repository visibility require
explicit authorization. Gateway testing never bumps Desktop versions.

## Backend integration

The separate platform feature implements database-backed grants, attested
admission and limited relay credentials. See
[the platform contract](https://github.com/astrea-foundation/axiom-platform/blob/dev/docs/api/web-gateway.md).
Install the static verifier artifact into the platform image using its optional
`backend/Dockerfile.web-gateway` variant. Gateway and backend remain independently
buildable; the integration boundary is a versioned executable/OCI artifact and
HTTP contracts, never sibling source imports.
