# Axiom Web Gateway

A private development implementation of an encrypted browser gateway for an
**Azure Intel TDX confidential VM**. The browser verifies the gateway workload
and key; the gateway reuses Axiom's attested provider-E2EE client to verify,
encrypt to and authenticate upstream model workers.

Includes the Rust service, shared native/WebAssembly evidence verifier,
TypeScript browser/extension SDK, Docker images and a measured UKI appliance
builder. Backend account delegation lives in `axiom-platform`. No production
gateway is deployed. **Azure firmware qualification and a live TDX test remain
required before enabling this for users.** An ordinary machine cannot open the
inference listener.

```sh
cargo test --workspace --locked
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

Provider implementation comes from commit-pinned `axiom-desktop` Cargo crates;
there is no Desktop submodule or required neighboring checkout. See the
[documentation index](docs/README.md) for setup, protocol and Azure qualification.
Development targets `dev`. The repository remains private; production promotion,
publication and deployment require explicit authorization.

Licensed under [Apache-2.0](LICENSE).
