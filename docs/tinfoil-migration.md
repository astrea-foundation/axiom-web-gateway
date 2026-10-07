# Tinfoil migration decision

Implemented on 2026-10-06 on a development branch. Tinfoil Intel TDX replaces the
unqualified Azure appliance. Rust inference composition, pinned provider clients,
account-scoped relay and authenticated browser completion are retained.

Implemented: local v3 attestation collection, exclusive boot X25519/Ed25519 keys,
shared native/browser Tinfoil verification, schema/domain v2, backend admission,
proof refresh, Docker runtime/static verifier artifacts, measured config generator,
pinned public-config release workflows, and signed source/image publication.
Azure TPM/HCL collector, dependencies, verifier, UKI builder and deployment
templates have been removed. Historical local Azure evidence remains dated.

Two changes from the original plan are deliberate:

- The inspected official JavaScript verifier only handles older SNP evidence.
  The official Go verifier supports v3 TDX, all boot keys and offline collateral;
  it is compiled for both the native executable and browser WASM worker. Neither
  client nor backend falls back to legacy verification.
- Application EHBP terminates in Rust. A separate attested boot X25519 key and
  distinct headers avoid the shim terminating or stripping that channel.
  This preserves the existing tested ordered/terminal transport without relying
  on a plaintext-accepting shim as the application authorization boundary.

Local tests/builds do not qualify hosted hardware. Remaining work: organization
admin login, an authorized public config-only repository, private-registry access,
a published measured release, staging platform v2 configuration/documents, then
fresh browser/backend acceptance, encrypted provider runs, isolation, refresh,
restart and log/load qualification. No production promotion or Desktop release
is part of this migration. See the executable commands in [deployment](tinfoil.md).
