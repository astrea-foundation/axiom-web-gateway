# Browser and gateway protocol

## Trust and proof

The installed client pins an Ed25519 build-publisher key and first-party HTTPS
origins. Discovery is configuration metadata, not a trust root. The SDK asks the
gateway for evidence using a fresh 32-byte challenge and a 30-second deadline.
It fetches the current policy from the relying application's backend, then
verifies the bundle locally using packaged WebAssembly. Native admission uses
the same Rust verifier. Neither browser nor extension contacts Microsoft/Intel
with account credentials or prompts to verify evidence.

Verification checks Intel production-root DCAP signatures, endorsement validity
and strictly UpToDate TCB status; a qualified Azure firmware/RTMR profile; the
exact hardware-bound HCL runtime bytes and RSA attestation key; an RSA-signed
TPM quote over PCRs 4, 7, 11 and 12; challenge, origin and both gateway keys;
boot-log replay; and signed build provenance matching every quoted PCR.
Publisher policy expires within 24 hours and carries a monotonic sequence and
minimum workload generation. Clients should persist the accepted sequence.
Updated signed builds do not require per-commit approvals or source allowlists.

Only the minimal verified result reaches application state: gateway origin,
keys, source/revision, image digest, generation and policy sequence/expiry. Raw
HCL claims may contain unavoidable VM identifiers; do not store them with users
or send them to analytics. No account identifier or message digest enters a
TPM/Azure challenge. Public provenance is metadata; while this repository is
private, source inspection requires authorized GitHub access.

## Account authorization

Generate a nonextractable WebCrypto P-256 signing key separately from EHBP's
X25519 encryption. With the existing HttpOnly login session and CSRF token, ask
the platform for a 120-second, one-use grant bound to the public P-256 key. Send
the grant to the gateway **inside EHBP**, with an ES256 DPoP proof of the logical
POST URI, grant hash, timestamp, random replay ID, accepted gateway encryption
key and SHA256 of the exact inner payload string. The backend sees only the
minimal grant exchange, never an inference envelope.

The gateway first obtains a short admission lease by proving its own hardware,
workload and authorization key to the backend. It signs the exact exchange body
with that separate attested Ed25519 key. The backend verifies both signatures,
atomically consumes the grant, rechecks account/login state and returns a
15-minute relay credential for that account. No general-purpose/shared user API
key is used. Account credentials are not encryption key material.

The browser receives only an encrypted random session ID. The grant helper
uses the existing authenticated API session endpoint to obtain CSRF even when
the chat page cannot read the API host cookie; it forwards no profile data. Every RPC requires a
new sender-constrained proof bound to the session ID, RPC URI and exact payload.
The gateway stores at most four sessions per account, a bounded replay set per
session, and five active inference requests per account. Backend credentials
remain in gateway memory. Logout/revocation prevents subsequent authenticated
backend calls; already accepted upstream streams may finish unless cancelled.

## Encrypted endpoints and streams

| Gateway route | Behavior |
| --- | --- |
| `GET /healthz` | Process readiness only; never evidence |
| `POST /v1/attestation` | Fresh public challenge-bound hardware/workload proof |
| `POST /v1/session` | One complete EHBP request frame containing grant and proof |
| `POST /v1/rpc` | EHBP `models`, strict OpenAI-shaped `infer`, or account-owned `cancel` |

Outer Cookie and Authorization headers are rejected. Bodies use the published
EHBP HPKE suite X25519/HKDF-SHA256/AES-256-GCM, exporter and response derivation.
No unauthenticated `/keys` endpoint is used. There is no plaintext inference or
TLS-only fallback. Request bodies are capped at 4 MiB; SDK payloads at 3 MiB;
response frames at 1 MiB and total plaintext response at 16 MiB. Runs have a
600-second gateway deadline and a 30-second write/backpressure deadline. A disconnected browser cancels its upstream run.

Decrypted responses contain newline-delimited JSON frames with protocol,
request ID, sequential frame number, kind and data. Deltas are provisional.
The terminal frame authenticates success and a SHA256 digest of all exact
preceding plaintext frame bytes, including newlines. The SDK requires the right
request ID, sequence, digest, successful terminal and clean authenticated EOF.
Missing, reordered, modified, truncated or appended frames fail completion.
Callback output must not be persisted or labelled verified before `rpc` resolves.

The gateway refreshes hardware/collateral every 120 seconds and rejects requests
if the 240-second epoch or publisher policy has expired. Refresh failure cancels
all runs and stops admission.

Inside the enclave, `axiom-secure-client` fetches the signed upstream trust
policy, pre-verifies the selected worker/key chain, constructs the provider-E2EE
exchange and authenticates completion. A successful result requires both a
successful native result and its ResponseVerified event. Cancellation or missing
upstream authentication emits failure or an interrupted stream, never success.
Upstream proof and final result are carried in the same authenticated request
stream. Browser-owned tools and conversation storage remain outside this
stateless gateway; it does not launch local MCP processes.

## SDK example

```ts
import { GatewayClient, browserGrant } from '@axiom/web-gateway';

const client = await GatewayClient.connect({
  publisherKey: PINNED_RELEASE_PUBLISHER_KEY,
  gatewayOrigin: 'https://gateway.example.com',
  backendOrigin: 'https://api.example.com',
  minimumPolicySequence: savedPolicySequence,
  rememberPolicySequence: savePolicySequence,
  grant: browserGrant('https://api.example.com'),
});
const result = await client.rpc({
  op: 'infer',
  request: { model: selectedModelId, messages: localMessages, stream: true },
}, frame => renderProvisional(frame), { signal: abortController.signal });
saveVerifiedCompletion(result);
```

An extension packages the WASM and SDK with its reviewed bundle and can supply
WASM bytes through `verifierWasm` and its own authenticated `grant` callback.
No remote executable code or eval is needed; Chromium WASM CSP uses the normal
`wasm-unsafe-eval` allowance. A website still trusts delivered JavaScript: a
compromised website can read text before encryption. Gateway attestation does
not attest browser code or make external search/tools confidential.
