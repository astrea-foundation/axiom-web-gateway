# Axiom Web Gateway

A Rust gateway for **Tinfoil Containers on Intel TDX**. Browsers verify the
measured gateway and its keys, encrypt to it, and receive authenticated streams.
The gateway reuses Axiom's attested provider-E2EE client for upstream inference.
The ordinary platform backend handles ciphertext, admission and account billing.

Includes the Rust service, the same pinned Tinfoil verifier in native and browser
WASM builds, a TypeScript SDK, Docker images and a config-only deployment generator.
Azure dependencies and appliance tooling have been removed. Local checks and
container builds pass; hosted Tinfoil qualification is still required. No
production gateway has been deployed.

```sh
pnpm install --frozen-lockfile
cargo test --workspace --locked
pnpm build && pnpm test
sh scripts/build-container.sh
```

See [deployment](docs/tinfoil.md), [development](docs/development.md) and the
[documentation index](docs/README.md). Provider crates are pinned Cargo Git
dependencies; no Desktop submodule or neighboring checkout is required.
Development targets `dev`. Source and images remain private during development;
public config publication and production promotion require explicit authorization.

Licensed under [Apache-2.0](LICENSE).
