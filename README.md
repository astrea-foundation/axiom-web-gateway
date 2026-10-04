# Axiom Web Gateway

A foundation for a gateway that runs inside a trusted execution
environment (TEE), verifies upstream model providers and bridges their encrypted
inference protocols to a single encrypted browser protocol. The repository is
private during development, with open-source publication planned later.

The browser will verify the gateway before sending messages. Messages will be
decrypted only inside the gateway enclave and the verified provider enclave.
The ordinary Axiom backend continues to handle accounts, billing and ciphertext
relay without receiving message plaintext.

**Status:** repository and Rust dependency foundation only. There is no running
gateway, HTTP inference endpoint, browser SDK or TEE deployment yet.

Provider security and inference types are reused directly from commit-pinned
Cargo dependencies in `axiom-desktop`; they are not copied into this repository.

```sh
git clone --branch dev https://github.com/astrea-foundation/axiom-web-gateway.git
cd axiom-web-gateway
cargo check --workspace --locked
```

See the [documentation index](docs/README.md) for architecture, implementation
stages and development instructions. Development uses `dev`; production releases
require explicit promotion to `main`.

Licensed under [Apache-2.0](LICENSE).
