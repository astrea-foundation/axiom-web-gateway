# Tinfoil deployment

The implemented target is a non-debug, CPU-only AMD SEV-SNP or Intel TDX Tinfoil Container using
CVM 0.14.13 or a subsequently qualified version with nonce-bound v3 local
attestation and boot key grants. The public `astrea-foundation/axiom-web-gateway`
repository owns source, root `tinfoil-config.yml` and both measured release
workflows. No second configuration repository is needed. Credentials and
publisher private keys remain outside Git.

## Build and prepare

Build from a clean committed revision locally or in an authorized development runner:

```sh
sh scripts/build-container.sh
podman tag axiom-web-gateway:dev ghcr.io/astrea-foundation/axiom-web-gateway:dev
# Authenticate to the registry, then push the immutable build.
podman push ghcr.io/astrea-foundation/axiom-web-gateway:dev
```

Alternatively, manually dispatch `container-artifacts.yml` on `dev` to build
GHCR runtime/verifier images, immutable pushed digests, a build record and browser
SDK. It has no push/schedule trigger and deploys nothing. Set the two packages
to Public in their GitHub package settings once, then confirm an anonymous digest
pull before releasing configuration; public repository visibility does not make
GHCR packages public automatically. Production artifacts must use an explicitly
promoted `main` revision. Axiom's offline release authority signs the trusted
build record; the same repository's Tinfoil workflow provides independently
verified Sigstore measurement evidence.

Use the pushed manifest digest, independently pinned publisher key and staging
origins. Generate the measured config into this checkout. The two pinned release
workflows already live in `.github/workflows`; generation publishes nothing and
creates no cloud resources:

```sh
python3 scripts/prepare-tinfoil.py \
  --image ghcr.io/astrea-foundation/axiom-web-gateway@sha256:ACTUAL_DIGEST \
  --cvm-version 0.14.13 \
  --gateway-origin https://gateway-staging.example \
  --backend-origin https://api-staging.example \
  --browser-origin https://app-staging.example \
  --publisher-key PINNED_PUBLIC_KEY_HEX \
  --output .
```

`deploy/tinfoil/tinfoil-config.example.yml` has dummy image/key values
for schema tests and must not be deployed. The generator rejects mutable image
tags, invalid keys and noncanonical origins. The measured release action is
pinned to v0.13.2, which supports both boot key grants and container attestation
access in the reviewed v0.1.14 configuration schema. Earlier v0.11.0 rejects
this configuration and must not be used. Validate the generated file with
Tinfoil's canonical parser, pinned to the reviewed schema revision:

```sh
go run github.com/tinfoilsh/tinfoil-config/cmd/tinfoil-config@70d5811ce0f931e4c9a0605a0c479eba94001c74 \
  tinfoil-config.yml
```

The single container runs as 10001:10001 with a read-only filesystem, no public
application port, no GPU/admin/SSH/persistent volume or billable API secret.
Only it receives `/tinfoil/attestation.sock` and its two read-only key mounts.
Runtime configuration is a measured environment value. Egress is allowlisted to
the configured platform and public provenance/collateral endpoints. Reassess the
list on upstream dependency changes; never switch it to open to mask failures.
The pinned Tinfoil Rust verifier uses `github-proxy.tinfoil.sh` for public release
evidence and `kds-proxy.tinfoil.sh` for AMD certificates. Both must be reachable;
direct GitHub/AMD hosts do not replace these configured proxy destinations.
Inference ciphertext continues through the account-scoped platform relay.
The shim forwards only readiness, evidence, session and RPC paths and configured
browser origins. The Rust listener is opened only after self-verification and
backend admission, not merely when the container starts.

## Release and staged startup

Before creating anything, install the current Tinfoil CLI, run `tinfoil login`
with the organization admin key interactively and confirm `tinfoil whoami`.
Google OAuth signs into the dashboard; CLI management needs a separately created
organization admin key. Keep that key in the protected CLI credential file. The
organization must have the Containers product enabled before creating instances.
Connect the Tinfoil GitHub App to this repository. Commit the generated root
configuration through a `dev` PR and dispatch its measured release workflow.
Staging tags keep the `-staging.N` suffix and staging-only runtime settings.
They must be eligible for GitHub latest in this dedicated gateway repository
so Tinfoil can publish freshness witnesses. They are unrelated to Desktop
releases or platform production promotion:

```sh
tinfoil repo build run astrea-foundation/axiom-web-gateway --version v0.0.1-staging.1
tinfoil repo build status astrea-foundation/axiom-web-gateway --version v0.0.1-staging.1
```

Wait for both release workflows and the published `tinfoil-deployment.json`/
`tinfoil.hash` assets, not just a queued build or tag. Download the artifact:

```sh
gh release download v0.0.1-staging.1 --repo astrea-foundation/axiom-web-gateway \
  --pattern tinfoil-deployment.json --dir out/tinfoil-release
```

Check out the exact clean source revision in the build record before signing,
even if a later config-only commit in this same repository selected the image.
From that source revision, sign Axiom's mapping and
short-lived policy using the separately managed offline Ed25519 authority. The offline publisher is a trusted release authority; keep its key separate from
the builder and runtime. `out/build-record.json` records immutable image content
IDs, clean source revision and lock/recipe hashes. Never accept a record from an
untrusted builder. Dirty development builds are useful for testing but cannot be
signed. The workload command checks the published image against that record and
first verifies the GitHub/Sigstore release workflow identity:

```sh
python3 scripts/publish-documents.py workload --key /protected/publisher.pem \
  --config-repository astrea-foundation/axiom-web-gateway --generation 1 \
  --deployment out/tinfoil-release/tinfoil-deployment.json \
  --build-record out/build-record.json --output out/documents
python3 scripts/publish-documents.py policy --key /protected/publisher.pem \
  --config-repository astrea-foundation/axiom-web-gateway --generation 1 \
  --sequence 1 --output out/documents
```

Use the platform v2 admission implementation. Build its optional backend variant
from independently published immutable backend and gateway-verifier OCI images.
Set its canonical gateway origin, pinned publisher key, static verifier executable,
read-only signed documents directory and approved chat origins. The API serves
`trust-policy.json` and `manifests/<config_digest>.json`. Publish these before
starting the gateway to avoid a bootstrap loop. Renew policy before its 24-hour
expiry, increasing sequence; supported releases get signed build provenance
without end-user commit approval. Development artifacts never authorize prod.
For an unchanged qualified build, publish a new policy sequence with the same
minimum generation; renewal requires no image rebuild or measured release.

List available hosts or use the organization default. Both AMD SEV-SNP and
Intel TDX use the complete pinned offline verifier and the same measured
boot-key/provenance contract. An empty host list can still permit automatic
placement; inspect the created instance and qualify its actual platform.
Unsupported platforms, debug mode and provisional SNP firmware are rejected.
Use the stable gateway domain signed in the configuration. The generated
Tinfoil domain can be used directly for staging; a custom domain needs separate
organization/DNS verification. Create an
explicitly non-debug staging instance using its published release:

```sh
tinfoil container hosts
tinfoil container create axiom-gateway-staging \
  --repo astrea-foundation/axiom-web-gateway --tag v0.0.1-staging.1 --mark-latest=true \
  --custom-domain gateway-staging.example
tinfoil container get axiom-gateway-staging
```

Use a stable configured gateway domain and route it to that instance. Its hostname
must match the signed origin and backend setting before browsers connect.
A Running instance or `/healthz` response is connectivity/readiness, not proof.
The browser SDK and backend must independently accept fresh nonce-bound evidence.

See [2026-10-07 staging qualification](qa-2026-10-07.md) for the actual AMD
deployment and tested browser/inference scope. Those results do not qualify an
Intel deployment or production promotion.

## Live acceptance

Exercise two distinct accounts with the packaged SDK and real platform sessions:
models, attested NEAR/Tinfoil encrypted inference, cancellation, disconnect and
stream backpressure. The upstream client must preserve strict production TCB and
protocol-specific completion checks; no native outdated-TEE consent is enabled.
Verify DPoP replay/grant expiry, logout, account isolation and billing attribution.

Tamper quote, nonce, origin, key inventory, measurements, release digest,
policy sequence/signature/expiry, source mapping and response frames. Each must
fail without exposing input or admitting credentials. Verify browser refresh,
120-second service renewal, 240-second epoch expiry, failed refresh cancellation
and boot-key rotation/reconnect. Inspect host/edge/container/backend logs and
storage for absence of plaintext messages/credentials. Load-test the bounded
concurrency/tenant budgets and measure initial WASM load before public service.

Keep staging failure closed. Do not enable debug mode, custom test roots, open
egress, ordinary-TLS-only inference, Azure fallback, or claim qualification from
synthetic fixtures. Production promotion/deployment remains a separate explicitly
authorized action.

Sources: [Tinfoil quickstart](https://docs.tinfoil.sh/containers/quickstart),
[boot-key configuration](https://github.com/tinfoilsh/tinfoil-config),
[offline verifier](https://github.com/tinfoilsh/tinfoil-go/tree/31c57af7d7b4fedf1724cb3552924dc6ecebf109/verify),
[release template](https://github.com/tinfoilsh/tinfoil-containers-template/tree/0eddc320b8f328d7a3c057152596934444ac2d75).


### Freshness witness publication

Tinfoil's control plane discovers active configuration repositories and witnesses
GitHub latest, refreshing it automatically. Non-latest releases are not renewed.
A new repository containing only GitHub prereleases has no latest and can boot
while its v3 endpoint returns `attestation_unavailable`: there is no code freshness
witness. Publish the staging-suffixed gateway tag as a normal release and select
it as latest when deploying this dedicated gateway staging repository. This does
not promote platform/desktop `main` or select a Desktop update.
Select the tag as latest before starting its new instance, after authenticating
and publishing the signed deployment mapping and policy.

Wait for the exact `tinfoil-deployment.json` digest to have a Sigstore freshness
witness from `tinfoilsh/freshness-witness` and for v3 proof to verify. Do not bypass
freshness, supply a replacement signer or fall back to the unversioned v2 document.
A successful VM boot or legacy quote alone cannot qualify the application.

### Application health and verification failures

Tinfoil's instance state describes the confidential VM. A Running VM can have
an unavailable gateway process; check `/healthz` and fresh `/v1/attestation`
evidence as well. Generated configurations declare a loopback HTTP healthcheck
using the image's `curl`, with a two-minute startup grace period. The listener
opens only after mandatory self-verification and backend admission.

Every two minutes the application renews and verifies its attestation epoch.
A failed or timed-out renewal cancels the service and returns an error, producing
a nonzero process exit for the measured `restart: on-failure` policy. A later
startup must verify fresh evidence and admission again before opening a listener.
Operator termination remains a successful exit. Rejected evidence is never
accepted, and failures do not expose verifier input or credentials in logs.

On October 9, 2026, live evidence rejected by the previous verifier pinned to
`v0.17.0-rc.1` identified Tinfoil's new platform publisher:
`tinfoilsh/cvmimage/.github/workflows/platform-release.yml`, tag
`platform-v0.1.0`. The pinned official verifier now includes upstream
[publisher migration 224](https://github.com/tinfoilsh/tinfoil-go/pull/224), with
the exact workflow, immutable repository/organization identity, artifact schemas,
hardware checks and freshness authentication retained. Update the native
verifier, backend verifier image and packaged browser WASM together. Restarting
an old verifier against a new publisher cannot restore service; it must continue
to reject the unsupported signing identity.

See the [official witness control-plane contract](https://github.com/tinfoilsh/freshness-witness).

The gateway closes the verifier stdin descriptor before awaiting output. A
process-framing regression checks EOF delivery; it does not mock live hardware
qualification. Backend runtime roles also need the documented gateway table
grants before admission can succeed.

## Shared-chat staging workload

The staging configuration selects the immutable upload-capable runtime from
source `23ca69e60604f8cc9d7976d4c261580817b2a9a5`, built by
[container artifacts 37641794831](https://github.com/astrea-foundation/axiom-web-gateway/actions/runs/37641794831).
This update adds bounded original-file uploads and authenticated acceptance events.
It requires a newly measured staging release and publisher-signed source mapping;
the prior staging qualification does not cover this workload. Hardware, key,
freshness, stream-completion and upstream provider checks remain required.
