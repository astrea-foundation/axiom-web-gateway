//! Axiom gateway wire schemas and request authorization. Hardware verification
//! uses the pinned Tinfoil verifier artifact in native and browser WASM builds.
pub mod authorization;
#[cfg(test)]
mod tests;
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
pub const PROTOCOL: &str = "axiom-gateway-v2";
pub const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDocument {
    /// Exact signed bytes, not reserialized JSON. Signatures are domain separated.
    pub payload: String,
    pub signature: String,
}

pub fn verify_document<T: DeserializeOwned>(
    doc: &SignedDocument,
    key: &str,
    domain: &str,
) -> Result<T> {
    ensure!(
        doc.payload.len() <= 128 * 1024,
        "signed document exceeds limit"
    );
    let raw = URL_SAFE_NO_PAD
        .decode(&doc.payload)
        .context("invalid signed document")?;
    let key: [u8; 32] = hex::decode(key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid publisher key"))?;
    let signature = Signature::from_slice(&hex::decode(&doc.signature)?)?;
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&raw);
    VerifyingKey::from_bytes(&key)?.verify_strict(&bytes, &signature)?;
    serde_json::from_slice(&raw).context("invalid signed document schema")
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub schema_version: u16,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub minimum_generation: u64,
    pub config_repository: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationEvidence {
    pub protocol: String,
    pub challenge: String,
    pub origin: String,
    pub encryption_key: String,
    pub authorization_key: String,
    pub document: serde_json::Value,
    pub manifest: SignedDocument,
    pub policy: SignedDocument,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationContext {
    pub challenge: String,
    pub origin: String,
    pub publisher_key: String,
    pub now: u64,
    pub minimum_policy_sequence: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedGateway {
    pub encryption_key: String,
    pub authorization_key: String,
    pub origin: String,
    pub image_digest: String,
    pub source_repository: String,
    pub source_revision: String,
    pub config_repository: String,
    pub config_digest: String,
    pub generation: u64,
    pub policy_sequence: u64,
    pub policy_expires_at: u64,
    pub evidence_expires_at: u64,
}
