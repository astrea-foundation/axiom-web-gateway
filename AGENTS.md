# Agent Instructions

## Workspace and branches

Use `~/sync2/work/axiom-web-gateway` for this checkout. Ongoing development and
feature pull requests target `dev`. The user authorized public source and
Tinfoil deployment configuration in this same repository on 2026-10-06. Keep
credentials and signing private keys outside Git. Staging measured releases may
use `dev`; do not promote to `main` or deploy production without explicit user
authorization. Do not bump
Desktop versions or trigger Desktop release builds to test gateway work.

## Ownership and reuse

This repository owns the gateway enclave application, its browser encryption
protocol/client library, and gateway-specific attestation/build provenance.
Hosted chat UI, account services and billing remain in `axiom-platform`.
Desktop, TUI and local proxy applications remain in `axiom-desktop`.

Use the pinned `axiom-inference`, `axiom-openai-compat` and `axiom-secure-client`
dependencies declared in the root Cargo workspace. Do not copy their provider
implementations here, use a neighboring checkout as a required build input, or
add a Desktop Git submodule. Make shared fixes in the owning repository's `dev`
branch, then update all shared dependency revisions together in this repository.
Commit `Cargo.lock`. See [development instructions](docs/development.md).

## Gateway security boundary

The full gateway is an explicitly intended additional confidential endpoint.
Message plaintext may exist only in the browser, the attested gateway's protected
memory and the authenticated provider enclave. The ordinary backend, edge,
storage and host must remain ciphertext-only for inference content.

Before accepting inference, the browser must verify fresh gateway attestation,
the gateway key binding and provenance of the measured build. Gateway source,
dependencies and security-sensitive configuration must be covered by verified
build provenance and measurement. A GitHub repository or a health/status response
alone is not evidence of the running code. Do not require users to approve every
gateway revision or introduce repository/commit allowlists for gateway updates.

Within the enclave, preserve all upstream provider-E2EE authentication checks:
fresh attestation, accepted hardware status, verified recipient keys, model and
worker identity, request binding and each protocol's response authentication.
Never add plaintext inference, ordinary-TLS-only or unverified-key fallbacks.
Keep strict production trust policy; do not automatically enable the Desktop
runtime's local-user outdated-TEE exception in a shared gateway.

Browser transport must authenticate request/session identity, stream ordering
and completion. Upstream authenticated deltas may remain provisional until
authenticated completion. Missing or invalid completion must fail closed.
Verification claims must be authenticated and bound to the actual request and
response. Never report successful verification using an unbound boolean.

Do not log, persist or export plaintext prompts, histories, model output, tool
payloads, account credentials or gateway private keys. Do not repurpose account
credentials as encryption keys. Enforce account isolation and delegated billing
authority; a shared service credential must not authorize every user's runs.

Until the browser transport and enclave attestation are implemented and tested,
keep the foundation without an inference listener. Do not add a plaintext
development listener that could be mistaken for the production gateway.

## Documentation and validation

Keep authored guides, architecture, plans, QA and runbooks in `docs/`, linked
from its index. Update documentation with changes to behavior or security.
Validate dependency changes through Cargo using the pinned remote source and
lockfile. CI should be limited to required checks and explicitly authorized
release artifacts; avoid schedules, automatic deployment and redundant jobs.
