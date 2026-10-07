# Shared chat staging qualification, 2026-10-07

The existing staging container was updated to `v0.0.1-staging.8` and qualified
with the new shared Desktop/web UI and encrypted browser vault. No production
promotion or Desktop installer release occurred.

## Measured identity

| Item | Tested value |
| --- | --- |
| Runtime/SDK source | `23ca69e60604f8cc9d7976d4c261580817b2a9a5` |
| Selected config revision | `7110dca511875998eec23a5e7ed89c7e3245c813` |
| Runtime OCI | `sha256:f3eac8b6bcbaf498b6fe1e456518fc0af590abc576cd23be6fd430e6b73cc900` |
| Deployment artifact | `ea07e71759d0f953c40d397a08be80b7d74684c5a5c38e829e576bb05f749e70` |
| Admission generation / policy sequence | `7` / `6` |
| Policy expiry | `2026-10-08 15:25:33 UTC` |
| Hosted browser | `https://auth-staging.axiom.stream/chat/` |

[Container build 37641794831](https://github.com/astrea-foundation/axiom-web-gateway/actions/runs/37641794831)
and [measured publication 37643490903](https://github.com/astrea-foundation/axiom-web-gateway/actions/runs/37643490903)
passed. The offline publisher verified the exact clean build record, immutable
image and GitHub build attestation before signing source/admission documents.
Archive the build-record and SDK artifacts before their retention expires.

Actual placement remains AMD SEV-SNP, CVM 0.14.13, two CPUs, 4096 MiB RAM and zero
GPUs. Debug mode, disabled confidential computing, SSH keys, application secrets
and writable volumes are absent. Both application keys remain boot-only grants.
The control-plane blue/green update completed successfully for this revision.

## Live results and security scope

The packaged SDK and deployed browser locally verified fresh hardware, measured
source, publisher policy and boot encryption keys. Eleven offerings loaded:
seven Tinfoil, four NEAR, no Phala. Real DeepSeek V4.1 Flash inference reached the
upstream authenticated result and ordered encrypted gateway terminal plus EOF.
A wrong-browser-key grant was rejected. Account-owned cancellation was idempotent;
a stream stopped after provisional output was rejected as incomplete.

An original text-file canary was delivered and read by the provider without local
extraction. An original PNG also reached authenticated completion. Reusing a
consumed upload handle was rejected. Upload tests used the encrypted chunked
protocol with account/session/model/future-request bindings. Files existed only
in protected gateway memory and their browser-owned encrypted vault.

The deployed actual Desktop UI passed immediate composer placement, highlighting,
stop/queue/resend, message revision, consented live search, original-file upload,
reload and password decryption of cloud chats from a fresh browser context.
Search sent only the bounded query through its explicit non-E2EE exception;
inference and file contents used encrypted transport. No plaintext model-message
fallback, test attestation roots, screenshots or desktop mouse control were used.
Private canary credentials, prompts and replies are not checked into QA records.

Gateway Rust service/core, SDK, Go verifier, interoperability, clippy and CI checks
passed. The detailed browser-vault tests, backend deployment bridge and limits are
recorded in [Platform qualification](https://github.com/astrea-foundation/axiom-platform/blob/dev/docs/testing/shared-chat-2026-10-07.md).
Historical nonce/key/origin/policy tamper and 250-second renewal results for the
unchanged verification protocol remain scoped to the
[initial staging qualification](qa-2026-10-07.md), rather than claimed as reruns.

Renew signed policy with a higher sequence before expiry, retaining minimum
generation at least seven; no image rebuild is needed. Fail closed after expiry.
NEAR live inference, sustained load, Intel TDX placement and production rollout
remain separate qualifications.
