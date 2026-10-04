//! Portable, offline verification of the Azure TDX -> HCL AK -> vTPM -> workload chain.
//! Public endorsements are transportable; trust roots and publisher keys are supplied by
//! the installed client, never accepted from the attester's evidence bundle.

pub mod authorization;
#[cfg(test)]
mod tests;
mod tpm;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use rsa::{BigUint, RsaPublicKey, pkcs1v15, signature::Verifier as _};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub const PROTOCOL: &str = "axiom-gateway-v1";
pub const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
pub const PCR_SELECTION: [u8; 4] = [4, 7, 11, 12];

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
pub struct FirmwareIdentity {
    pub mr_td: String,
    pub mr_config_id: String,
    pub mr_owner: String,
    pub mr_owner_config: String,
    pub rt_mrs: [String; 4],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub schema_version: u16,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub minimum_generation: u64,
    /// Azure paravisor/firmware profiles qualified against vendor endorsements.
    /// This is hardware policy, not a repository or commit allowlist.
    pub azure_firmware: Vec<FirmwareIdentity>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadManifest {
    pub schema_version: u16,
    pub generation: u64,
    pub source_repository: String,
    pub source_revision: String,
    pub build_recipe_sha256: String,
    pub cargo_lock_sha256: String,
    pub gateway_image_digest: String,
    pub appliance_sha256: String,
    pub pcrs: BTreeMap<u8, String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationEvidence {
    pub protocol: String,
    pub challenge: String,
    pub origin: String,
    pub encryption_key: String,
    pub authorization_key: String,
    pub tdx_quote: String,
    /// Exact bytes hashed by the Azure HCL hardware report; must not be redacted.
    pub hcl_runtime_data: String,
    pub tpm_quote: String,
    pub tpm_signature: String,
    pub pcrs: BTreeMap<u8, String>,
    pub event_log: String,
    pub collateral: dcap_qvl::QuoteCollateralV3,
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
pub struct VerifiedGateway {
    pub encryption_key: String,
    pub authorization_key: String,
    pub origin: String,
    pub image_digest: String,
    pub source_repository: String,
    pub source_revision: String,
    pub generation: u64,
    pub policy_sequence: u64,
    pub policy_expires_at: u64,
}

/// The challenge is generated/stored by the relying client, with a local deadline.
/// `now` is the relying client's clock, not an attester-supplied timestamp.
pub fn binding(
    challenge: &str,
    origin: &str,
    encryption_key: &str,
    authorization_key: &str,
) -> Result<[u8; 32]> {
    let challenge = hex::decode(challenge)?;
    let encryption_key = hex::decode(encryption_key)?;
    let authorization_key = hex::decode(authorization_key)?;
    ensure!(
        challenge.len() == 32 && encryption_key.len() == 32 && authorization_key.len() == 32,
        "invalid binding lengths"
    );
    let parsed = url::Url::parse(origin)?;
    ensure!(
        origin.len() <= 512
            && parsed.scheme() == "https"
            && parsed.origin().ascii_serialization() == origin
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "invalid gateway origin"
    );
    let mut digest = Sha256::new();
    for part in [
        PROTOCOL.as_bytes(),
        origin.as_bytes(),
        &challenge,
        &encryption_key,
        &authorization_key,
    ] {
        digest.update(u32::try_from(part.len())?.to_be_bytes());
        digest.update(part);
    }
    Ok(digest.finalize().into())
}

#[allow(clippy::too_many_lines)] // Keep the complete ordered chain visible in one verifier.
pub fn verify(
    evidence: &AttestationEvidence,
    context: &VerificationContext,
) -> Result<VerifiedGateway> {
    ensure!(
        evidence.protocol == PROTOCOL
            && evidence.challenge == context.challenge
            && evidence.origin == context.origin,
        "evidence context mismatch"
    );
    let policy: TrustPolicy = verify_document(
        &evidence.policy,
        &context.publisher_key,
        "axiom-gateway-policy-v1",
    )?;
    ensure!(
        policy.schema_version == 1
            && policy.sequence >= context.minimum_policy_sequence
            && policy.issued_at <= context.now
            && policy.expires_at > context.now
            && policy.expires_at.saturating_sub(policy.issued_at) <= 86400
            && !policy.azure_firmware.is_empty(),
        "invalid, expired or rolled-back trust policy"
    );
    let manifest: WorkloadManifest = verify_document(
        &evidence.manifest,
        &context.publisher_key,
        "axiom-gateway-workload-v1",
    )?;
    ensure!(
        manifest.schema_version == 1 && manifest.generation >= policy.minimum_generation,
        "unsupported or revoked workload"
    );
    ensure!(
        manifest.source_repository.starts_with("https://")
            && manifest.source_revision.len() == 40
            && hex::decode(&manifest.source_revision)?.len() == 20,
        "invalid source provenance"
    );
    for digest in [
        &manifest.build_recipe_sha256,
        &manifest.cargo_lock_sha256,
        &manifest.appliance_sha256,
    ] {
        ensure!(
            hex::decode(digest)?.len() == 32,
            "invalid provenance digest"
        );
    }
    ensure!(
        manifest.gateway_image_digest.starts_with("sha256:")
            && hex::decode(&manifest.gateway_image_digest[7..])?.len() == 32,
        "invalid image digest"
    );
    ensure!(
        manifest.pcrs.keys().copied().collect::<Vec<_>>() == PCR_SELECTION
            && evidence.pcrs == manifest.pcrs,
        "workload measurements mismatch"
    );

    let raw_quote = decode_bounded(&evidence.tdx_quote, 128 * 1024)?;
    let hardware = dcap_qvl::verify::QuoteVerifier::new_prod().verify(
        &raw_quote,
        &evidence.collateral,
        context.now,
    )?;
    ensure!(
        hardware.status == "UpToDate"
            && hardware.qe_status.status == dcap_qvl::tcb_info::TcbStatus::UpToDate
            && hardware.platform_status.status == dcap_qvl::tcb_info::TcbStatus::UpToDate,
        "unacceptable TDX TCB status"
    );
    let td = hardware
        .report
        .as_td10()
        .context("evidence is not Intel TDX")?;
    let identity = FirmwareIdentity {
        mr_td: hex::encode(td.mr_td),
        mr_config_id: hex::encode(td.mr_config_id),
        mr_owner: hex::encode(td.mr_owner),
        mr_owner_config: hex::encode(td.mr_owner_config),
        rt_mrs: [
            hex::encode(td.rt_mr0),
            hex::encode(td.rt_mr1),
            hex::encode(td.rt_mr2),
            hex::encode(td.rt_mr3),
        ],
    };
    ensure!(
        policy
            .azure_firmware
            .iter()
            .any(|v| v.mr_td == identity.mr_td
                && v.mr_config_id == identity.mr_config_id
                && v.mr_owner == identity.mr_owner
                && v.mr_owner_config == identity.mr_owner_config
                && v.rt_mrs == identity.rt_mrs),
        "unqualified Azure firmware"
    );
    let runtime = decode_bounded(&evidence.hcl_runtime_data, 64 * 1024)?;
    // Azure HCL uses SHA-256 of the exact JSON runtime claims in report_data.
    ensure!(
        td.report_data[..32] == Sha256::digest(&runtime)[..] && td.report_data[32..] == [0; 32],
        "HCL runtime claims are not hardware-bound"
    );
    verify_guest(evidence, &runtime)?;
    Ok(VerifiedGateway {
        encryption_key: evidence.encryption_key.clone(),
        authorization_key: evidence.authorization_key.clone(),
        origin: evidence.origin.clone(),
        image_digest: manifest.gateway_image_digest,
        source_repository: manifest.source_repository,
        source_revision: manifest.source_revision,
        generation: manifest.generation,
        policy_sequence: policy.sequence,
        policy_expires_at: policy.expires_at,
    })
}

fn decode_bounded(input: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(input.len() <= max * 2, "evidence component exceeds limit");
    hex::decode(input).context("invalid evidence encoding")
}

fn verify_guest(evidence: &AttestationEvidence, runtime: &[u8]) -> Result<()> {
    let claims: serde_json::Value = serde_json::from_slice(runtime)?;
    ensure!(
        claims["vm-configuration"]["secure-boot"] == true
            && claims["vm-configuration"]["tpm-enabled"] == true,
        "guest security configuration mismatch"
    );
    let keys = claims["keys"]
        .as_array()
        .context("missing hardware-bound AK")?;
    let matches: Vec<_> = keys.iter().filter(|k| k["kid"] == "HCLAkPub").collect();
    ensure!(matches.len() == 1, "ambiguous or missing HCL AK");
    let jwk = matches[0];
    ensure!(jwk["kty"] == "RSA", "unsupported AK type");
    let modulus = URL_SAFE_NO_PAD.decode(jwk["n"].as_str().context("invalid AK")?)?;
    let exponent = URL_SAFE_NO_PAD.decode(jwk["e"].as_str().context("invalid AK")?)?;
    ensure!(
        (256..=512).contains(&modulus.len()) && exponent.len() <= 4,
        "invalid AK size"
    );
    let key = RsaPublicKey::new(
        BigUint::from_bytes_be(&modulus),
        BigUint::from_bytes_be(&exponent),
    )?;
    let quote = decode_bounded(&evidence.tpm_quote, 4096)?;
    let signature = decode_bounded(&evidence.tpm_signature, 1024)?;
    pkcs1v15::VerifyingKey::<Sha256>::new(key).verify(
        &quote,
        &pkcs1v15::Signature::try_from(signature.as_slice())?,
    )?;
    tpm::verify_quote(
        &quote,
        &binding(
            &evidence.challenge,
            &evidence.origin,
            &evidence.encryption_key,
            &evidence.authorization_key,
        )?,
        &evidence.pcrs,
    )?;
    tpm::verify_event_log(
        &decode_bounded(&evidence.event_log, 2 * 1024 * 1024)?,
        &evidence.pcrs,
    )
}

#[cfg(feature = "browser")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn verify_gateway(
    evidence_json: &str,
    context_json: &str,
) -> Result<String, wasm_bindgen::JsValue> {
    let result = (|| {
        ensure!(
            evidence_json.len() <= MAX_EVIDENCE_BYTES,
            "evidence exceeds limit"
        );
        let evidence = serde_json::from_str(evidence_json)?;
        let context = serde_json::from_str(context_json)?;
        serde_json::to_string(&verify(&evidence, &context)?).map_err(Into::into)
    })();
    result.map_err(|_: anyhow::Error| wasm_bindgen::JsValue::from_str("gateway attestation failed"))
}
