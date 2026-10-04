# Axiom Web Gateway implementation plan

## Decision and current state

Updated 2026-10-04. Target **Microsoft Azure with an Intel TDX confidential VM**.
The proof must establish that the accepted encryption key belongs to the Axiom
gateway workload running in that VM. Google Confidential Space and Phala dstack
are not deployment targets for this implementation.

Implementation resumed on 2026-10-04. The Rust service, native/WASM verifier,
TypeScript SDK, backend delegation, container build, measured UKI appliance
builder and Azure deployment template are implemented. See
[development](development.md), [protocol](protocol.md) and [Azure operations](azure.md).

Local component tests and builds do not qualify Azure hardware. Still open:
access to a development TDX VM, independent Azure firmware/boot-profile
qualification, live boot/evidence validation, and complete browser → gateway →
upstream provider qualification. These steps remain admission requirements; no
hardware/workload verification bypass is available.

## 1. Qualify the Azure evidence chain first

Use the Azure guest-attestation SDK to collect the hardware report, HCL runtime
claims, vTPM attestation key, challenge-bound TPM quote, quoted PCR values,
measured-boot event log and required endorsements. Pin reviewed dependency
revisions. Prove the following chain on the exact intended Azure VM family:

1. Valid Intel TDX hardware evidence and acceptable current TCB status.
2. The vTPM attestation key is bound to that hardware evidence through the
   authenticated HCL runtime claims; never trust a separately supplied key.
3. A TPM quote signed by that key binds a fresh browser challenge and the
   gateway encryption key to the selected PCR values.
4. The boot log reproduces those PCR values, and the measured guest enforces
   the exact gateway workload and security-sensitive launch configuration.
5. Signed build provenance identifies the source, build procedure, dependency
   lockfiles, guest image and gateway image that produced those measurements.

Use a domain-separated digest of the browser challenge, protocol version,
canonical gateway origin and encryption key for the fresh binding. Bind any
separate gateway authorization public key too. Challenges contain random bytes,
never account identifiers, login credentials or prompt hashes.

Azure's TDX-only platform attestation is insufficient for this requirement: it
omits the TPM/PCR guest evidence. A runtime-data field containing a Docker digest
also does not establish that the corresponding application was launched or that
it cannot be replaced. The measured guest must enforce that relationship.

Qualification must establish actual evidence formats, firmware endorsements,
PCR selection, TPM quote freshness and VM-image compatibility. Do not infer
support from a VM marketing name, a decoded JWT or a generic Secure Boot claim.
No inference listener is enabled until this chain is implemented and tested.

## 2. Package an immutable gateway appliance

Build the gateway as a minimal Docker/OCI image using the shared Axiom crates.
Build a minimal Azure-compatible guest appliance that includes the container
runtime, exact gateway image and enforced launch configuration. Prefer a signed
unified kernel image with the kernel, initramfs, fixed command line and integrity
root covered by measured boot. Use a read-only root with verified integrity.

Disable SSH, interactive consoles, guest-agent command execution, Docker exec,
mutable startup scripts, unmeasured host mounts, debugging, swap and core dumps.
Keep plaintext and private keys in protected volatile memory. Runtime options
that change the trust boundary must be measured and checked. Network routing
and discovery may remain outside the appliance; they carry ciphertext only.

The guest must launch and supervise the gateway with the enforced image and
configuration. Only the intended gateway can generate/use its channel key.
Attestation plus proof of possession establishes that key in the enforced guest
environment; it is not a continuous scanner of arbitrary runtime processes.

Updates replace the measured appliance through a new boot. Publish signed
provenance and a fresh trust policy covering supported software/security
generations and revocations. Clients verify new builds automatically through
the trusted build authority; do not introduce per-commit allowlists or manual
user approval for every update. Keep source and build details inspectable while
the repository remains private to its authorized development reviewers.

## 3. Implement browser verification and encrypted transport

Provide a TypeScript SDK suitable for the hosted UI and an eventual extension.
Verify the Azure evidence chain locally using reviewed verification libraries
and trusted Intel/Azure roots. Public endorsements may be cached and served by
first-party infrastructure, with their signatures, expiry and freshness checked
locally. A relay-supplied trust root is never sufficient. Do not replace this
verification with a backend-provided `verified` boolean.

Use EHBP/HPKE with the verified gateway key for browser requests and responses.
Carry credentials, model requests, cancellation and request-specific proofs
inside encrypted bodies. Bind protocol, request identity, provider and model.
Authenticate stream sequence and a terminal record; missing or invalid terminal
authentication must never become success. Provider-authenticated deltas remain
provisional until upstream response authentication completes.

Serve generic challenge/key/measurement evidence separately from authenticated,
owner-scoped request proofs. Never send browser credentials or message content
to Intel, Azure or other attestation services. Explain that website-delivered
JavaScript integrity and network metadata remain separate trust considerations.

## 4. Add account-scoped delegation in axiom-platform

Keep account login, billing and hosted web UI in `axiom-platform`. Mint short
lived, limited grants after the existing authenticated login and CSRF checks.
Bind grants to a separate browser authorization key. Deliver them to the
verified gateway inside the encrypted channel.

Authenticate the gateway instance cryptographically and exchange the browser
grant for separate account-scoped relay authority. Reuse the existing
ciphertext relay, attestation and accounting APIs. Never create a shared user
API key to bill all gateway traffic, or treat an asserted gateway header as
authority to bypass limits.

Keep account quotas and concurrent-run limits. Give authenticated gateway
instances an explicit aggregate capacity budget so a shared egress IP does not
incorrectly consume one ordinary client's IP allowance. Retain bounded
unauthenticated/IP abuse limits, expiry, revocation and replay protection.

## 5. Compose bounded inference service

Use `axiom-secure-client` for fresh upstream TEE verification, signed trust
policy, provider E2EE and response authentication. Keep NEAR and Tinfoil
implementations in the shared source. Never enable ordinary TLS inference or
the Desktop local-user exception for outdated hardware.

Isolate credentials, provider sessions and prompt-cache secrets by account.
Bound body sizes, response sizes, queue length, per-account/global concurrency,
session lifetimes and deadlines. Propagate cancellation and disconnects.
Respect upstream quota/cooldown responses; do not automatically replay a
possibly dispatched billable inference request.

Persist conversations only browser-side or as ciphertext encrypted with
browser-held storage keys. No plaintext prompts, tool content, replies,
credentials or channel private keys enter application logs or diagnostics.

## 6. Acceptance and delivery

Run Rust checks, browser SDK checks, encrypted provider-fixture integration and
Docker/Podman builds without Desktop release/version changes. Test invalid TDX
evidence, a substituted vTPM key, stale challenges, a valid TDX VM running
another image, modified launch configuration, gateway-key substitution,
untrusted provenance, rollback/revocation, replay and cross-account access.

Also test tampering, reordering/truncation, missing upstream completion,
disconnect/cancellation, bounded overload and plaintext/credential canaries in
logs, URLs, proof bundles and attestation requests. A Docker build on an
ordinary host is packaging validation, not evidence of confidential execution.

Qualify the full chain on an Azure TDX VM before claiming a working attested
deployment. Cloud deployment/access details remain to be supplied when that
stage is authorized. Keep development on `dev` and the repo private; production
promotion, deployment and public publication require explicit authorization.

## References

- [Azure confidential VM guest-attestation design](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design)
- [Azure guest-attestation SDK](https://github.com/Azure/azure-guest-attestation-sdk)
- [Microsoft Azure Attestation TDX API](https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-tdx-vm?view=rest-attestation-2025-06-01)
- [Azure confidential VM availability and attestation caveats](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-faq)
- [Encrypted HTTP Body Protocol](https://github.com/tinfoilsh/encrypted-http-body-protocol)
