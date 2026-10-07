# Browser protocol and SDK

The implemented contract is `axiom-gateway-v2` for Tinfoil AMD SEV-SNP and Intel TDX.
Azure v1 proofs and signature domains are rejected. Only nonce-bound v3
documents with the complete supported vendor verification chain are accepted.

## Proof and admission

`POST /v1/attestation` accepts only a random 32-byte lowercase-hex `challenge`.
The gateway asks `/tinfoil/attestation.sock` for
`GET /.well-known/tinfoil-attestation/v3?nonce=<challenge>` and returns the public
v3 document plus signed Axiom workload manifest and policy. Only the random nonce
reaches the attestation service, never user identity, prompts, files or credentials.

Policy schema 2 has sequence, issued/expiry (at most 24 hours), minimum generation
and authenticated config-release publisher `owner/repo`. The workload manifest
binds the immutable Tinfoil deployment artifact digest and measured register set
to image digest, source revision, build recipe, Cargo/Go locks and canonical HTTPS
origin. Manifest lookup uses `manifests/<config_digest>.json`. Values are derived
from a Sigstore-authenticated build artifact, never observed quote measurements.

The browser pins the Axiom publisher independently, fetches current policy from
the platform and locally runs the packaged native-equivalent verifier. Its own
nonce, origin, clock and remembered policy sequence are verifier context. The
verifier checks Tinfoil's nonce/report-data binding, CPU signature, strict vendor
policy/debug rejection, vendor revocation, measured code/platform, release
provenance/freshness, and exact endorsed SPKI boot keys `axiom-encryption`
(X25519) and `axiom-authorization` (Ed25519). Evidence cannot choose trust roots. SNP requires the endorsed launch/firmware
floors, VMPL 0, disabled debug and migration, and fully committed firmware
TCB/build/API versions. TDX additionally requires a non-debug guest and
UpToDate Intel collateral status.

The backend invokes the separately packaged static verifier with the current
first-party policy and a single-use, 60-second admission challenge. Possession
signatures use `axiom-gateway-register-v2\0 || challenge`. Admission expires at
the earliest of 240 seconds, witness expiry and policy expiry. Exchange signatures
use `axiom-gateway-exchange-v2\0 || exact_body`. Grant and relay scopes remain
account-specific; see [platform delegation](https://github.com/astrea-foundation/axiom-platform/blob/dev/docs/api/web-gateway.md).

## Encrypted requests and completion

| Route | Body |
| --- | --- |
| `GET /healthz` | Public readiness only, available after admission |
| `POST /v1/attestation` | Public nonce-bound evidence |
| `POST /v1/session` | One complete EHBP frame containing grant and P-256 DPoP |
| `POST /v1/rpc` | One complete EHBP frame containing `models`, strict `infer`, or owned `cancel` |

EHBP uses its published X25519/HKDF-SHA256/AES-256-GCM suite and response exporter.
`Axiom-Encapsulated-Key` and `Axiom-Response-Nonce` carry the normal EHBP values.
The custom header names keep Tinfoil's shim from decrypting the application body
or stripping its response nonce. The shim's private hop forwards ciphertext;
Rust alone decrypts it with the attested application key. SDK uses the upstream
Identity encryption/decryption functions and maps headers, without global fetch
patches or a second cipher design. Ordinary HTTP bodies, incomplete/multiple
request frames, Authorization/Cookie headers and failed AEAD are rejected.

The inner envelope binds protocol, session, DPoP and exact serialized payload.
DPoP binds POST URI, token hash, accepted encryption key, payload hash, timestamp
and one-use replay ID. Grants last 120 seconds; sessions at most 15 minutes.
Absolute delegation expiries allow the verifier's 60-second clock tolerance,
but are capped at the local 240-second admission or 900-second session deadline.
Expired or excessively future claims are rejected; admission also ends at the
locally verified policy expiry. Cryptographic freshness checks are unchanged.
Fresh proof is required every 240 seconds; SDK refreshes it before new RPCs and
requires reconnect after boot-key rotation. Gateway policy refresh failure
cancels active work. Account/session quotas, body limits, cancellation and stream
backpressure remain enforced.

Response frames bind protocol, request ID, ordered sequence, kind and data. Each
frame is AEAD-authenticated. Deltas are provisional until encrypted terminal
completion authenticates the transcript digest and upstream verified completion,
then EOF confirms no suffix/truncated AEAD frame. A missing terminal, provider
failure, cancellation, reordered frames, digest substitution or AEAD failure
cannot produce success or a persisted verified response.

## SDK use

```ts
import { GatewayClient, browserGrant } from '@axiom/web-gateway';
const gateway = await GatewayClient.connect({
  publisherKey: installedPublisherKey,
  gatewayOrigin: 'https://gateway.example',
  backendOrigin: 'https://api.example',
  minimumPolicySequence: storedSequence,
  rememberPolicySequence: saveSequence,
  grant: browserGrant('https://api.example'),
});
const result = await gateway.rpc({
  op: 'infer', request: { model: selectedModel, messages, stream: true },
}, renderProvisional, { signal: abortController.signal });
saveVerifiedCompletion(result);
```

Serve the SDK, module worker, matching Go runtime and WASM as one reviewed bundle.
No attester-supplied executable is loaded. Extensions can provide packaged bytes
through `verifierWasm` and their own authenticated grant callback. Website code
integrity, search-query privacy and original-file capability checks remain
separate responsibilities.
