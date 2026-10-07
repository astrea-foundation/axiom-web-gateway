# Development

Use `~/sync2/work/axiom-web-gateway`. Required tools: Rust 1.90+, Go 1.27.1,
Node 24+, pnpm 11.22, OpenSSL and Podman or Docker for packaging. `Cargo.lock`,
`verifier/go.mod`, `verifier/go.sum` and `pnpm-lock.yaml` pin dependencies.
No Desktop checkout is required. The official Tinfoil verifier is pinned to
`ef79d8ed92a4b5e669c71328caa2b4a9f7931d25`; both upstream replacements in
`go.mod` are required for its portable dependency graph.

```sh
pnpm install --frozen-lockfile
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
(cd verifier && go test ./... && go vet ./...)
python3 -m unittest discover -s scripts/tests
pnpm build && pnpm typecheck && pnpm test
cargo test -p axiom-web-gateway --locked -- --ignored
sh scripts/build-container.sh
```

The ignored interop test uses the published EHBP JavaScript implementation and
our SDK transport against the Rust server composition. All fixtures are public
synthetic data; tests introduce no plaintext inference listener. Policy tests
inject hardware facts only into an unexported test helper. Production verifiers
always use the official embedded trust roots and never conformance trust overrides.

`pnpm build` creates `out/axiom-gateway-verify`, the packaged WASM and its matching
Go runtime, then SDK ESM/types. Browser verification runs in a module worker to
avoid blocking chat rendering. Bundle the worker, `sdk/wasm` and SDK together;
serve WASM compressed and cache immutable assets. The uncompressed module is
about 36 MiB; this is a material initial-download cost, not a prompt transfer.
Extensions may supply packaged WASM bytes and need normal module-worker/WASM CSP
support. No remote executable imports or eval are required.

Container builds vendor locked private Cargo dependencies on the authenticated
host, then build offline. Go public dependencies use their lockfile. No GitHub
credential is passed through build arguments or layers. Outputs:
`axiom-web-gateway:dev`, `axiom-gateway-verifier:dev` and `out/build-record.json`. The latter contains a
CGO-disabled static executable for independently built backend images.
Runtime bases are digest-pinned. Package installation is not claimed to be
byte-for-byte reproducible; the measured immutable image covers installed bytes.

An ordinary host cannot open the gateway listener: it lacks fresh valid Tinfoil
TDX evidence, granted keys, signed provenance and backend admission. There is no
debug/plaintext fallback. Measured Tinfoil config supplies
`AXIOM_GATEWAY_CONFIG_JSON`; a CLI JSON path is also accepted for diagnostics,
with identical mandatory attestation checks.

Development PRs target `dev`. CI runs required checks only and never deploys,
bumps Desktop versions, or publishes installers. A separately dispatched
`container-artifacts.yml` builds private images, a build record and browser SDK;
it does not deploy or run on pushes. Production `main`, public source
publication and production deployment require explicit authorization. The public
config-only project uses Tinfoil's pinned, manually dispatched release workflows;
that is separate from private application CI.
