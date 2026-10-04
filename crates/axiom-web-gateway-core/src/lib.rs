//! Dependency foundation for the Axiom web gateway.
//!
//! Provider attestation, provider E2EE, response authentication and wire
//! translation remain implemented by the shared Axiom crates. This library
//! exposes those dependencies for the future enclave composition root; it
//! contains no HTTP listener, browser transport or deployment implementation.

pub use axiom_inference as inference;
pub use axiom_openai_compat as openai_compat;
pub use axiom_secure_client as secure_client;
