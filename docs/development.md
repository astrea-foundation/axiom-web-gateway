# Development

Use `~/sync2/work/axiom-web-gateway`. Required tools: Rust 1.90+, Go 1.27.2,
Node 24+, pnpm 11.22, OpenSSL and Podman or Docker for packaging. `Cargo.lock`,
`verifier/go.mod`, `verifier/go.sum` and `pnpm-lock.yaml` pin dependencies.
No Desktop checkout is required. The official Tinfoil verifier is pinned to
`31c57af7d7b4fedf1724cb3552924dc6ecebf109`; both upstream replacements in
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
Go runtime, then SDK ESM/types. The browser starts the module worker and its
verifier alongside the evidence and trust-policy reads. Verification runs off
the UI thread and must finish before session admission. Bundle the worker,
`sdk/wasm` and SDK together;
serve WASM compressed and cache immutable assets. The uncompressed module is
about 36 MiB; this is a material initial-download cost, not a prompt transfer.
Extensions may supply packaged WASM bytes and need normal module-worker/WASM CSP
support. No remote executable imports or eval are required.

Container builds vendor locked Cargo dependencies on the build
host, then build offline. Go public dependencies use their lockfile. No GitHub
credential is passed through build arguments or layers. Outputs:
`axiom-web-gateway:dev`, `axiom-gateway-verifier:dev` and `out/build-record.json`. The latter contains a
CGO-disabled static executable for independently built backend images.
Runtime bases are digest-pinned. Package installation is not claimed to be
byte-for-byte reproducible; the measured immutable image covers installed bytes.

The shared client pin also supplies its owned SNP/NVIDIA verifier source bundle.
Keep all three shared crate revisions synchronized. The current stack uses
AstreaAI for image generation and selects its image adapter from the selected
chat model's curated `uncensored` tag. Updating the source pin takes effect in
the running gateway only after a separately qualified measured release.
`scripts/prepare-direct-verifier.py` resolves that bundle from Cargo's locked
remote dependency and checks every file against its provenance manifest.
No neighboring checkout or private inference repository is a build input.
The build host vendors both locked Rust dependency graphs, and the container
compiles the native `axiom-direct-verify` binary offline. No Python or OpenSSL
runtime is needed for AstreaAI verification. The image binds its actual executable digest into the image's public AstreaAI staging
configuration. The file is private to runtime UID 10001 and contains public pins,
prices and a spending ceiling; account authority always comes from each browser
session's delegated credential.

Only generated configuration with `--astreaai-staging` enables this provider.
It requires the existing staging browser, API and gateway origins and permits
the selected worker's provider DNS name and NVIDIA appraisal endpoint.
Production configuration has no provider activation environment variable.

Both Git and the container context exclude `.env`, `.env.*`, private PEM files
and key files. Keep credentials outside the checkout and build context; an
untracked file is not automatically excluded from a container build. The
recursive environment-file rules also cover nested directories; see Docker's
[ignore matching rules](https://docs.docker.com/build/concepts/context/#matching).

An ordinary host cannot open the gateway listener: it lacks fresh valid Tinfoil
supported CPU evidence, granted keys, signed provenance and backend admission. There is no
debug/plaintext fallback. Measured Tinfoil config supplies
`AXIOM_GATEWAY_CONFIG_JSON`; a CLI JSON path is also accepted for diagnostics,
with identical mandatory attestation checks.

Development PRs target `dev`. CI runs required checks only and never deploys,
bumps Desktop versions, or publishes installers. A separately dispatched
`container-artifacts.yml` builds images, a build record and browser SDK; it does
not deploy or run on pushes. This public repository also owns the root measured
`tinfoil-config.yml` and Tinfoil's pinned, manually dispatched release workflows.
Staging uses `dev` and distinct prerelease tags. Production `main` promotion and
production deployment require explicit authorization.

The shared NEAR client also supports exact client-authenticated request bytes
and raw streaming wire version 1. The enclave receives and decrypts bounded raw
provider chunks provisionally, then verifies the selected worker receipt against
the complete ordered bytes, model and request before emitting authenticated
gateway completion. Account authorization and backend billing admission remain
independent. The gateway's shared inference/openai-compat/secure-client revisions
must advance together to the tested remotely published Desktop commit.

The current pin also prepares lossy WebP vision copies with a useful quality
floor, bounds account-local variant caches, and budgets NEAR's encrypted provider
request at 10 MiB. When the relay lease advertises `relay_request_wire_versions:
[2]`, the client sends the exact encrypted request once using the versioned
binary NEAR route. Otherwise it selects the legacy JSON route before dispatch;
an inference failure never authorizes replay through another format. Request
hashing, local TEE verification, worker/session ownership and authenticated stream
completion are unchanged. Deploy the compatible platform relay first, then
qualify a new measured gateway build before browser rollout. Updating this source
pin alone does not change a running enclave or the browser's history planner.

The shared client also accepts authenticated AstreaAI image-progress frames. The
ordinary image API drains updates when its caller has no progress consumer, so
workers that report progress remain compatible with gateway image requests.
Progress never replaces request binding or authenticated stream completion.

The 2048² development image profile accepts 20 MiB image uploads/outputs and a
128 MiB per-account upload pool so five full-size RGBA references fit. Ordinary
files retain their 10 MiB bound. The SDK accepts the matching image area/byte
bounds and a bounded 64 MiB reply stream.
The server separately bounds image responses to the base64 expansion of 20 MiB
plus 1 MiB of framing, progress and metadata; other responses retain 16 MiB.
Shared inference dependencies must
advance together to the Desktop commit that contains the separate reference
normalizer and larger signed image grants; coordinate with the worker and API
rollout and the encrypted-file size migration before enabling 2K clients.

## Chutes image overflow

The gateway reuses the encrypted `image` operation for the local overflow
pilot. It can consider Qwen Image 2512 for text-only image requests when the
account controller reports backpressure. Requests need queue negotiation and
explicit dimensions on the existing 32-pixel grid, within 2048 pixels per
side and the normal 1536² area budget. The account controller authorizes and
settles these jobs at the configured AstreaAI image price. Existing Desktop
builds connect to AstreaAI directly.

Keep `chutes_images` omitted while qualifying a Chutes deployment. Activation
requires a measured gateway configuration with this optional block:

```json
{
  "chutes_images": {
    "api_key_file": "/run/secrets/chutes-api-key",
    "verifier": "/usr/local/bin/axiom-chutes-image-verify",
    "verifier_sha256": "<hex SHA-256 of the installed verifier>",
    "workload_sha256": "<hex SHA-256 of the approved raw workload manifest>"
  }
}
```

Install the credential as a runtime secret. The companion Platform pool
configuration enables `chutes_image_overflow` for explicit pilot accounts
using the same workload digest. The gateway keeps one overflow attempt active
at a time. Its provider HTTP client targets `https://api.chutes.ai` and invokes
only the E2EE path for the qualified image deployment.

The verifier is an independently reviewed executable pinned in the measured
gateway configuration. It receives a JSON object on stdin with `protocol`
(`axiom-chutes-image-verification-v1`), `nonce`, `chute_id`, `instance_id`,
`e2e_pubkey`, `workload_sha256`, and `evidence` (the exact Chutes evidence
response as a JSON string). It must verify hardware status, freshness, the
recipient key, and a cryptographic link from that key to the exact running
image deployment and verified model inventory. On acceptance it returns a
JSON object with `nonce`, `chute_id`, `instance_id`, `e2e_pubkey`, an
`expires_at` Unix timestamp, and `workload_manifest` as an exact JSON string.
The manifest contains `chute_id`, `source_uri`, `source_sha256`,
`container_digest`, `model`, `model_revision`, and `weights_manifest_sha256`.
The gateway checks identity, freshness and the manifest digest again before
encrypting to that recipient.

The public [Chutes evidence guide](https://github.com/chutesai/chutes-api/blob/main/docs/tee-verification.md)
covers hardware and the recipient key. A verifier that establishes the full
serving-build and weights binding for the public image route still needs
qualification. Local tests use synthetic evidence and encrypted replies in
the test harness. Keep live routing disabled until qualification succeeds.

The adapter authenticates the complete encrypted response and checks the
exact requested dimensions before converting the JPEG to PNG in the gateway.
Customer completion requires account settlement. A repeated settlement
acknowledgement can recover an idempotent debit. An uncertain provider dispatch
ends the attempt.
