# Tinfoil deployment

The implemented target is a non-debug, CPU-only Intel TDX Tinfoil Container using
CVM 0.14.13 or a subsequently qualified version with nonce-bound v3 local
attestation and boot key grants. Source and image can stay private. Tinfoil needs
a public config-only GitHub project with its measured release evidence; do not
publish the private application repository. Private registry pulls may require
your organization's Containers/enterprise entitlement.

## Build and prepare

Build from a clean committed revision locally or in an authorized development runner:

```sh
sh scripts/build-container.sh
podman tag axiom-web-gateway:dev ghcr.io/astrea-foundation/axiom-web-gateway:dev
# Authenticate to the private registry, then push the immutable build.
podman push ghcr.io/astrea-foundation/axiom-web-gateway:dev
```

Alternatively, manually dispatch `container-artifacts.yml` on `dev` to build
private GHCR runtime/verifier images and a downloadable build record/browser SDK.
It has no push/schedule trigger and deploys nothing. Keep both GHCR packages
private and grant the Tinfoil organization registry access. Production artifacts
must use an explicitly promoted `main` revision. This workflow avoids requiring
GitHub Enterprise private-repository attestations: Axiom's offline release
authority signs the trusted build record, while Tinfoil's public config workflow
provides its independently verified Sigstore measurement evidence.

Use the pushed manifest digest, independently pinned publisher key and staging
origins. Generation creates a complete config-only directory and two pinned
Tinfoil release workflows, without publishing or creating cloud resources:

```sh
python3 scripts/prepare-tinfoil.py \
  --image ghcr.io/astrea-foundation/axiom-web-gateway@sha256:ACTUAL_DIGEST \
  --cvm-version 0.14.13 \
  --gateway-origin https://gateway-staging.example \
  --backend-origin https://api-staging.example \
  --browser-origin https://app-staging.example \
  --publisher-key PINNED_PUBLIC_KEY_HEX \
  --output out/tinfoil-config
```

`deploy/tinfoil/config-repo/tinfoil-config.example.yml` has dummy image/key values
for schema tests and must not be deployed. The generator rejects mutable image
tags, invalid keys and noncanonical origins. Validate the generated file with
Tinfoil's canonical parser, pinned to the reviewed schema revision:

```sh
go run github.com/tinfoilsh/tinfoil-config/cmd/tinfoil-config@70d5811ce0f931e4c9a0605a0c479eba94001c74 \
  out/tinfoil-config/tinfoil-config.yml
```

The single container runs as 10001:10001 with a read-only filesystem, no public
application port, no GPU/admin/SSH/persistent volume or billable API secret.
Only it receives `/tinfoil/attestation.sock` and its two read-only key mounts.
Runtime configuration is a measured environment value. Egress is allowlisted to
the configured platform and public provenance/collateral endpoints. Reassess the
list on upstream dependency changes; never switch it to open to mask failures.
The shim forwards only readiness, evidence, session and RPC paths and configured
browser origins. The Rust listener is opened only after self-verification and
backend admission, not merely when the container starts.

## Release and staged startup

Before creating anything, install the current Tinfoil CLI, run `tinfoil login`
with the organization admin key interactively and confirm `tinfoil whoami`.
Configure private-registry credentials in that organization. After authorized
public config publication, connect the Tinfoil GitHub App to the config repository.
Commit the generated files there and dispatch its release workflow:

```sh
tinfoil repo build run OWNER/axiom-web-gateway-config --version v0.0.1
tinfoil repo build status OWNER/axiom-web-gateway-config --version v0.0.1
```

Wait for both release workflows and the published `tinfoil-deployment.json`/
`tinfoil.hash` assets, not just a queued build or tag. Download the artifact:

```sh
gh release download v0.0.1 --repo OWNER/axiom-web-gateway-config \
  --pattern tinfoil-deployment.json --dir out/tinfoil-release
```

From the clean source revision used to build the image, sign Axiom's mapping and
short-lived policy using the separately managed offline Ed25519 authority. The offline publisher is a trusted release authority; keep its key separate from
the builder and runtime. `out/build-record.json` records immutable image content
IDs, clean source revision and lock/recipe hashes. Never accept a record from an
untrusted builder. Dirty development builds are useful for testing but cannot be
signed. The workload command checks the published image against that record and
first verifies the GitHub/Sigstore release workflow identity:

```sh
python3 scripts/publish-documents.py workload --key /protected/publisher.pem \
  --config-repository OWNER/axiom-web-gateway-config --generation 1 \
  --deployment out/tinfoil-release/tinfoil-deployment.json \
  --build-record out/build-record.json --output out/documents
python3 scripts/publish-documents.py policy --key /protected/publisher.pem \
  --config-repository OWNER/axiom-web-gateway-config --generation 1 \
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

List available hosts and select an Intel TDX host; this implementation explicitly
rejects SNP/unsupported platforms. Use the stable gateway domain that was signed
in the config, verified for use with your Tinfoil organization. Create an
explicitly non-debug staging instance using its published release:

```sh
tinfoil container hosts
tinfoil container create axiom-gateway-staging \
  --repo OWNER/axiom-web-gateway-config --tag v0.0.1 --mark-latest=false \
  --host INTEL_TDX_HOST --custom-domain gateway-staging.example
tinfoil container get axiom-gateway-staging
```

Use a stable configured gateway domain and route it to that instance. Its hostname
must match the signed origin and backend setting before browsers connect.
A Running instance or `/healthz` response is connectivity/readiness, not proof.
The browser SDK and backend must independently accept fresh nonce-bound evidence.

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
[offline verifier](https://github.com/tinfoilsh/tinfoil-go/tree/ef79d8ed92a4b5e669c71328caa2b4a9f7931d25/verify),
[release template](https://github.com/tinfoilsh/tinfoil-containers-template/tree/0eddc320b8f328d7a3c057152596934444ac2d75).
