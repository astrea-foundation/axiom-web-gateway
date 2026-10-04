# Azure appliance build and qualification

## Current qualification boundary

Local tests establish protocol behavior, encrypted browser/Rust interoperability,
backend delegation and Docker/UKI buildability. They do **not** establish a live
Azure deployment. A qualified firmware/boot profile is intentionally not shipped
with fabricated measurements. Access to an Azure Intel TDX VM, actual boot and
evidence qualification, upstream live inference and load tests remain required.
The listener opens only after fresh local verification and backend admission.

The selected VM families use Intel TDX, not AMD SNP or ordinary Trusted Launch.
See [Azure confidential VM overview](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview)
and [guest attestation design](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design).
The collector uses the pinned Azure guest-attestation SDK, its HCL attestation
key and explicit nonce-bearing TPM Quote command. The SDK convenience quote
method uses an empty qualifying nonce and is deliberately not used here.

## Build an immutable guest

Build the local images as described in [development](development.md). Prepare
the gateway's fixed `deploy/config.example.json` replacement, an external Secure
Boot signing key/certificate, and an empty output directory. The Ed25519 build
publisher key is a separate release authority, never included in the guest.

```sh
mkdir -p out/appliance
podman run --rm \
  -v "$PWD/out/appliance:/output" \
  -v /secure/build-inputs:/inputs:ro \
  axiom-gateway-appliance-tools:dev \
  --config /inputs/config.json \
  --secure-boot-key /inputs/uefi.key \
  --secure-boot-certificate /inputs/uefi.pem \
  --epoch "$(git log -1 --format=%ct)"
```

The output includes a signed `gateway.efi` UKI, fixed-size Gen2 `gateway.vhd`,
PCR11 calculation and unsigned build candidate metadata. The complete root,
gateway binary, dynamic libraries, CA roots, minimal kernel modules and fixed
configuration live in the embedded initramfs. Its init mounts the root read-only,
disables core dumps, runs no SSH/login/cloud agent/container daemon, mounts no
data disk/swap and drops privileges before launching the sole application.
DHCP only supplies network routing; DNS configuration and launch code are baked.
Private keys/sessions exist only in protected process memory and rotate on boot.

PCR4 identifies the actual PE boot image in the qualified firmware boot chain;
PCR7 identifies its Secure Boot policy; PCR11 covers the exact UKI sections,
including automatically added uname/SBAT; PCR12 must remain zero, preventing
external command-line/credential/add-on changes. Boot events are replayed locally.
A general-purpose VM that later downloads a container is not an accepted image.
Updates replace the measured appliance and publish a signed manifest; they do
not hot-swap code inside an already accepted measured guest.

## Azure image and VM

Upload the VHD to a private build storage account. Create a **Specialized Gen2**
Compute Gallery image definition supporting `TrustedLaunchAndConfidentialVmSupported`.
When creating its version, append the gateway's Secure Boot DER certificate to
UEFI DB using the REST security profile in
`deploy/azure/gallery-uefi.example.json`. This is Azure's supported
[custom UEFI key mechanism](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-secure-boot-custom-uefi),
subject to region and image compatibility qualification. Never disable Secure
Boot to make an unsigned image start.

`deploy/azure/main.bicep` creates an Intel DCesv5 confidential VM with Secure
Boot/vTPM enabled, private networking, no boot diagnostics and no mutable guest
provisioning. Supply the existing subnet, qualified gallery image version and
first-party edge CIDR. No public IP or SSH access is created. No Azure resources
are created by local builds or CI.

The external HTTPS edge forwards only encrypted session/RPC bodies and public
evidence. Disable request/response-body and sensitive-header logging, caching
and buffering; preserve streamed bytes and expose EHBP-Response-Nonce. It must
never add credentials or terminate EHBP. Gate inbound 8080 to that edge. Permit
guest outbound HTTPS to the Axiom backend, required provider attestation
endpoints and Intel public collateral, plus Azure IMDS locally. Do not install
debug agents/extensions in the serving appliance.

## Qualify firmware once, publish builds automatically

Independent vendor evidence and a reviewed boot chain establish a profile with:
`schema_version: 1`, `qualified: true`, archived `qualification_evidence_sha256`,
the TDX `firmware` tuple, `pcr4_before_uki` and `pcr4_after_uki` SHA256 event lists,
the expected `pcr7`, and `secure_boot_certificate_sha256`. Do not create this
profile by trusting measurements reported by an arbitrary VM. Establish the
firmware endorsement and expected secure boot variables/event sequence
independently, then reproduce them on the intended Azure family.

Release-authority automation runs `scripts/publish-documents.py` with that
qualified profile. `policy` signs a current 24-hour policy, monotonic sequence
and minimum generation; `workload` requires a clean committed checkout, the
actual appliance and immutable OCI digest, and signs the calculated PCR11 and
PE-bound PCR4 with source, lockfile, recipe and artifact provenance. Workload
values are never copied blindly from an attester's quote. Store policy at
`trust-policy.json`, manifests at `manifests/<pcr11>.json` on the backend. Renew
the short-lived policy using protected release-authority automation before
expiry. No per-commit allowlist or user update approval is required.

Before user traffic, test all of the following on a development TDX VM:

1. Exact HCL runtime encoding/TDX binding, hardware endorsements, firmware tuple,
   AK type/TPM signature, PCRs and replayed event log pass the native and WASM
   verifiers. Report freshness derives from nonce binding, not decoded JWT text.
2. Altered UKI/config, extra boot arguments, expired/revoked policy, outdated TCB,
   wrong gateway keys, nonce replay and changed Secure Boot state are rejected.
3. Account grants and upstream inference use only the existing encrypted relay;
   both supported providers complete with authenticated responses. Disconnect,
   stop, timeout and truncated streams never emit successful completion.
4. Concurrent accounts have isolated credentials, sessions, prompt-cache state,
   quotas, cancellations and billing; rotated instances require new proofs.
5. Edge, backend, Azure diagnostics, disk and crash paths retain no message text,
   credentials, raw provider deltas or gateway private keys.

Publish the dated evidence and limitations under docs. Local candidate signing
keys and synthetic unit proofs are development fixtures, never release trust
roots. Production publication/deployment still requires explicit authorization.
