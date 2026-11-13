# Encrypted GPU pool routing

The pool routes preserve a second encryption layer from browser to GPU worker.
The gateway authenticates the browser session and relays opaque worker bytes
through the platform. It never constructs an inference request for this path.
The [owning runbook](https://github.com/astrea-foundation/axiom-inference/blob/dev/docs/implementation.md)
describes the worker, controller, release format and qualification status.

The outer protocol is `axiom-gateway-pool-v1`. Routes under `/v1/pool/` are
`reserve`, `grants`, `attestation`, `control` and `exchange`. Each request uses
the browser session, a fresh proof bound to its exact method, route, gateway
key and payload, and an outer request ID. The gateway sends only that session's
delegated token to the fixed platform origin. It cannot select arbitrary
worker URLs. Durable claims and account quotas span gateway replicas.

The outer stream authenticates ordering, request ID, transcript completion and
EOF. Inner worker ciphertext stays opaque. Image bodies have explicit bounded
transport limits; legacy RPC limits remain unchanged. Active requests,
backpressure, cancellation, session expiry and gateway evidence expiry are
bounded. Closing the SDK session aborts outstanding requests.

The SDK exposes `gateway.pool({ issuerKey, minimumWorkerPolicySequence,
rememberWorkerPolicySequence }).run(modelManifest, input, limits, callback)`.
The issuer key is trusted installed application configuration, independent of
model discovery. Callbacks are provisional; a returned result follows inner
worker transcript, receipt and EOF verification and includes text, reasoning,
optional image Blob, usage and the signed receipt. Call `gateway.close()` on
logout or account switches. Tools and image inputs are unsupported.

Worker CPU/GPU, provenance, model and endorsed-key verification runs locally
through the pinned Go/WASM verifier. NVIDIA JWKS and public verdicts come from
fixed vendor endpoints. Unknown hardware, vendor failure, stale policy, changed
boot/key or invalid completion fails closed. A backend boolean or ordinary TLS
cannot replace worker attestation. `scripts/build-wasm.sh` builds both native
verifiers and browser WASM from the committed Go locks. The native worker
verifier is `out/axiom-pool-verify`.

NVIDIA's overall and detached device JWTs are both verified, including their
digest link. Device policy requires secure boot, disabled debug, successful
measurements, verified signatures and good certificate/OCSP status. A standalone
overall pass or missing detailed claims cannot qualify the GPU.

The routes are included in staging/example Tinfoil shim configurations. A new
measured gateway release and real confidential GPU browser run still require
qualification. Rust/browser vector, malformed stream, isolation and composed
CPU/key/model/NVIDIA unit tests pass; public production verification rejects
synthetic CPU evidence. The Vast run validates runtime/E2EE only.
