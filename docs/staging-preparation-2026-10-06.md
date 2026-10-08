# Tinfoil staging preparation, 2026-10-06

This is a preparation snapshot. See [2026-10-07 qualification](qa-2026-10-07.md)
for the deployed instance, resolved gates and current testing scope.

The gateway repository is public with the user's authorization. Source, the
root measured configuration and Tinfoil release workflows all live in
`astrea-foundation/axiom-web-gateway`. No separate configuration repository,
production promotion or Desktop release is involved.

## Published build

[Artifact run 37582746771](https://github.com/astrea-foundation/axiom-web-gateway/actions/runs/37582746771)
completed successfully from clean source
`4f6ab52e8117bd6823c73feecd692eb73c24bcff`.

| Artifact | Immutable reference |
| --- | --- |
| Runtime | `ghcr.io/astrea-foundation/axiom-web-gateway@sha256:2d26893a14d4b0a0eca0eefd013a9af465a8cedbfaa9593c2d2d88700c377667` |
| Independent verifier | `ghcr.io/astrea-foundation/axiom-web-gateway-verifier@sha256:76f654f7a3adccb09c95c0faf06cab9f23a333a1d604172e18da6df8c7622ec3` |

The run's `gateway-source-record-and-sdk` artifact contains the clean-source
build record, both pushed digest records and the packaged browser SDK. Archive
that artifact before the run's 14-day retention ends. Build records must remain
associated with this exact source revision; the later config-only commit does
not require rebuilding the runtime.

[PR #2](https://github.com/astrea-foundation/axiom-web-gateway/pull/2)
consolidated the workflows and passed CI. [PR #3](https://github.com/astrea-foundation/axiom-web-gateway/pull/3)
added the actual staging configuration and passed CI. Both are merged into
`dev`; the config merge is `52322f6`.

## Staging configuration

The root configuration selects the runtime digest above, CVM 0.14.13, two CPUs,
4096 MiB RAM and exclusive boot-generated encryption and authorization keys.
It contains no application credentials. Its signed-origin targets are:

- Gateway: `https://gateway-staging.axiom.stream`
- Backend: `https://api-staging.axiom.stream`
- Browser: `https://app-staging.axiom.stream`
- Account app: `https://auth-staging.axiom.stream`

A dedicated staging publisher key was generated outside Git. Its public key is
in the measured configuration; the private key must stay outside the source,
builder and running gateway. No workload mapping or admission policy has been
signed yet: those require the real published measured deployment artifact.

Google OAuth and a separate scoped CLI credential were verified for the AxiomAI
organization. That credential is restricted to this repository and the exact
`axiom-gateway-staging` name. It grants container lifecycle, validation, metrics
and host listing, without billing, account-key or unrelated-container access.

## Outstanding deployment gates

At the time of this record:

- Containers was not enabled for the organization. CLI host listing returned no
  available hosts and container listing returned no containers. The subscription
  checkout still required the user's payment verification.
- Both GHCR packages were private despite the public repository. Anonymous pull
  failed. Set both packages to Public and confirm anonymous digest pulls before
  publishing measured configuration.
- Backend staging SSH access was unavailable. Install the independent verifier
  and signed documents only after confirming access and the live revision;
  preserve any newer staging backend work.
- No measured staging release, cloud instance, gateway DNS setup or hosted
  attestation/inference qualification has been completed.

Follow [the deployment runbook](tinfoil.md) after resolving these gates. Use
`v0.0.1-staging.1` on `dev` for the first measured prerelease. Confirm an Intel
TDX host is actually available before creating an instance. The gateway remains
fail-closed until independently verified backend admission succeeds.

The local hosted-chat preview is still a simulated UI. Its availability does
not establish a working gateway or real encrypted web inference.
