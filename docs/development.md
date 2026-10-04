# Development

## Build the foundation

Use `~/sync2/work/axiom-web-gateway`. A normal clone does not require Git
submodules, pnpm, Electron or another Axiom checkout. Install a compatible Rust
toolchain; the workspace declares a minimum Rust version of 1.88. The committed
lockfile records the dependency set used for validation.

```sh
cargo check --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

There is no executable or inference endpoint yet. The core library exposes the
shared inference contracts, optional compatibility translator and secure client
through `inference`, `openai_compat` and `secure_client` modules. This is a
dependency integration boundary, not a second implementation of those crates.

## Update shared code once

1. Change the owning shared crate in `axiom-desktop`, test its relevant provider
   and integration behavior and merge into that repository's `dev` branch.
2. Update all three root Cargo Git revisions to the same reviewed commit. Use a
   full commit hash; do not track a moving branch for a measured gateway build.
3. Refresh the lockfile with `cargo check --workspace`, inspect the source and
   dependency changes, then run the locked checks above.
4. Once gateway/browser integration exists, qualify upstream changes against the
   browser channel, platform delegation and failure tests before deployment.

During development, Cargo's local patch mechanism may temporarily substitute
shared crates from a local Desktop checkout. Keep such machine-specific paths
out of commits and perform final qualification using the pinned remote source.

## Branches and releases

The initial/default branch is `dev`. Feature branches and pull requests target
`dev`. The repository stays private during development. No production branch,
automatic deployment, scheduled workflow or release tag is created by this
foundation.

Promotion to `main` and gateway deployments require explicit authorization.
Future CI should run only required Rust and protocol checks, with caching and
concurrency cancellation. Measured images and provenance belong in an explicitly
authorized gateway release pipeline. Building this gateway never requires a
Desktop version bump or all-platform installer run.

## Evidence for this foundation

Validate Cargo resolution from the pinned public repository rather than a path
override. Confirm that the dependency graph has one instance of each shared
Axiom crate, no test-fixture feature and no Desktop, CLI, proxy or installer
application packages. Successful dependency compilation establishes reuse; it
does not establish an attested deployment or a working web chat service.
