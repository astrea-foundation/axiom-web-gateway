mod nvidia;

use super::{CHUTE_ID, CHUTES_ORIGIN, DiscoveredWorker, MODEL_ID, bounded};
use anyhow::{Context, Result, anyhow, ensure};
use axiom_web_gateway_core::secure_client::{
    EvidenceCheck, EvidenceClaim, SecurityEvidence, SecurityState,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dcap_qvl::{
    collateral::{CollateralClient, INTEL_PCS_URL},
    configs::DefaultConfig,
    http::{HttpClient, HttpResponse},
    quote::TDReport10,
};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use x509_parser::parse_x509_certificate;

const POLICY: &str = "axiom-chutes-image-tee-v1";
const MAX_COLLATERAL: usize = 512 * 1024;
const MAX_QUOTE: usize = 64 * 1024;
const PROOF_SECONDS: u64 = 180;

#[derive(Deserialize)]
struct Evidence {
    tee_type: String,
    instance_id: Option<String>,
    quote: String,
    certificate: String,
    attested_body: String,
    signature: String,
    #[serde(rename = "gpu_evidence")]
    gpus: Vec<GpuEvidence>,
}

#[derive(Deserialize, PartialEq, Eq)]
struct GpuEvidence {
    arch: String,
    evidence: String,
    certificate: String,
}

#[derive(Deserialize)]
struct AttestedBody {
    nonce: String,
    evidence: SignedEvidence,
}

#[derive(Deserialize)]
struct SignedEvidence {
    quote: String,
    nvtrust_evidence: SignedGpus,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SignedGpus {
    Encoded(String),
    List(Vec<GpuEvidence>),
}

#[derive(Deserialize)]
struct GuestBaseline {
    version: String,
    mrtd: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
}

impl GuestBaseline {
    fn matches(&self, report: &TDReport10) -> bool {
        [
            (&self.mrtd, report.mr_td),
            (&self.rtmr0, report.rt_mr0),
            (&self.rtmr1, report.rt_mr1),
            (&self.rtmr2, report.rt_mr2),
            (&self.rtmr3, report.rt_mr3),
        ]
        .iter()
        .all(|(expected, measured)| expected.eq_ignore_ascii_case(&hex::encode(measured)))
    }
}

struct IntelHttp<'a>(&'a reqwest::Client);

impl HttpClient for IntelHttp<'_> {
    async fn get(&self, url: &str) -> Result<HttpResponse> {
        let url = url::Url::parse(url)?;
        ensure!(
            url.scheme() == "https"
                && url.port().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && matches!(
                    url.host_str(),
                    Some(
                        "api.trustedservices.intel.com" | "certificates.trustedservices.intel.com"
                    )
                ),
            "unapproved Intel collateral URL"
        );
        let response = self.0.get(url).send().await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(key, value)| Ok((key.to_string(), value.to_str()?.to_owned())))
            .collect::<Result<_>>()?;
        Ok(HttpResponse {
            status,
            headers,
            body: bounded(response, MAX_COLLATERAL).await?,
        })
    }
}

async fn verify_intel(http: &reqwest::Client, quote: &[u8]) -> Result<(TDReport10, u64)> {
    let collateral = CollateralClient::<DefaultConfig, _>::new(IntelHttp(http), INTEL_PCS_URL)
        .fetch(quote)
        .await?;
    let now = crate::now();
    let expires = now + PROOF_SECONDS;
    let verified = dcap_qvl::verify::verify(quote, &collateral, now)?;
    let report = verified
        .report
        .as_td10()
        .context("Intel quote is not a supported TDX report")?;
    ensure!(
        verified.status == "UpToDate" && report.td_attributes[0] & 1 == 0,
        "Chutes Intel TCB status or debug state rejected"
    );
    // Require Intel's collateral to remain valid through the invocation window.
    dcap_qvl::verify::verify(quote, &collateral, expires)?;
    Ok((*report, expires))
}

pub(super) async fn verify(
    http: &reqwest::Client,
    worker: &DiscoveredWorker,
    nonce: &str,
    raw: &[u8],
) -> Result<SecurityEvidence> {
    let evidence: Evidence = serde_json::from_slice(raw)?;
    ensure!(
        evidence.tee_type == "tdx"
            && evidence
                .instance_id
                .as_deref()
                .is_none_or(|instance| instance == worker.instance_id),
        "Chutes evidence describes a different worker or TEE type"
    );
    let recipient = STANDARD.decode(&worker.e2e_pubkey)?;
    ensure!(
        recipient.len() == 1184,
        "invalid Chutes recipient key length"
    );
    let quote = STANDARD.decode(&evidence.quote)?;
    ensure!(
        !quote.is_empty() && quote.len() <= MAX_QUOTE,
        "invalid Chutes TDX quote size"
    );
    let ((report, intel_expires), baselines) =
        tokio::try_join!(verify_intel(http, &quote), async {
            let response = http
                .get(format!("{CHUTES_ORIGIN}/servers/tdx/measurements"))
                .send()
                .await?;
            Ok::<Vec<GuestBaseline>, anyhow::Error>(serde_json::from_slice(
                &bounded(response, MAX_COLLATERAL).await?,
            )?)
        })?;
    let baseline = baselines
        .iter()
        .find(|baseline| baseline.matches(&report))
        .context("Chutes TDX quote does not match a published guest baseline")?;
    ensure!(
        !baseline.version.is_empty()
            && baseline.version.len() <= 48
            && baseline
                .version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)),
        "invalid Chutes guest version"
    );
    let (challenge, certificate_expires) =
        evidence.verify_signature(&report.report_data, nonce, &worker.e2e_pubkey, crate::now())?;
    let gpu_expires = nvidia::verify(http, &evidence.gpus, &hex::encode(challenge)).await?;
    let expires = intel_expires.min(certificate_expires).min(gpu_expires);
    let now = crate::now();
    ensure!(expires > now, "Chutes attestation expired");
    Ok(SecurityEvidence {
        state: SecurityState::Verified,
        provider_id: "chutes".into(),
        model_id: MODEL_ID.into(),
        attestation_protocol: "chutes-intel-tdx-nvidia-v1".into(),
        e2ee_protocol: "chutes-mlkem768-v1".into(),
        e2ee_encryption_version: 1,
        trust_policy_version: POLICY.into(),
        verified_at_unix_seconds: now,
        attestation_generation: None,
        hard_expires_at_unix_seconds: Some(expires),
        model_key_fingerprint: hex::encode(Sha256::digest(recipient)),
        tls_spki_fingerprint: None,
        checks: [
            ("intel-tdx", "Intel TDX", "UpToDate"),
            ("chutes-guest", "Chutes guest measurements", "matched"),
            ("recipient-key", "Fresh ML-KEM recipient key", "verified"),
            ("nvidia-gpu", "NVIDIA GPU evidence", "verified"),
        ]
        .into_iter()
        .map(|(id, label, status)| EvidenceCheck {
            id: id.into(),
            label: label.into(),
            status: status.into(),
            passed: true,
        })
        .collect(),
        provider_claims: vec![
            EvidenceClaim {
                name: "Chutes route".into(),
                value: CHUTE_ID.into(),
            },
            EvidenceClaim {
                name: "Worker instance".into(),
                value: worker.instance_id.clone(),
            },
            EvidenceClaim {
                name: "Chutes guest version".into(),
                value: baseline.version.clone(),
            },
            EvidenceClaim {
                name: "Image build and weights".into(),
                value: "Managed by Chutes".into(),
            },
        ],
        workload_manifest: None,
    })
}

impl Evidence {
    fn verify_signature(
        &self,
        report_data: &[u8; 64],
        nonce: &str,
        recipient: &str,
        now: u64,
    ) -> Result<([u8; 32], u64)> {
        let der = STANDARD.decode(&self.certificate)?;
        let (remaining, cert) = parse_x509_certificate(&der)
            .map_err(|_| anyhow!("invalid Chutes evidence signing certificate"))?;
        let expires = u64::try_from(cert.validity().not_after.timestamp())?;
        ensure!(
            remaining.is_empty()
                && cert.validity().not_before.timestamp() <= i64::try_from(now)?
                && expires > now,
            "Chutes evidence signing certificate is outside its validity period"
        );
        let spki = cert.public_key();
        let challenge = report_binding(report_data, nonce, recipient, spki.raw)?;
        self.verify_body(spki.subject_public_key.data.as_ref(), nonce)?;
        Ok((challenge, expires))
    }

    fn verify_body(&self, signing_key: &[u8], nonce: &str) -> Result<()> {
        let body = STANDARD.decode(&self.attested_body)?;
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, signing_key)
            .verify(&body, &STANDARD.decode(&self.signature)?)
            .map_err(|_| anyhow!("invalid Chutes evidence signature"))?;
        let signed: AttestedBody = serde_json::from_slice(&body)?;
        let gpus = match signed.evidence.nvtrust_evidence {
            SignedGpus::Encoded(raw) => serde_json::from_str(&raw)?,
            SignedGpus::List(gpus) => gpus,
        };
        ensure!(
            signed.nonce == nonce && signed.evidence.quote == self.quote && gpus == self.gpus,
            "Chutes signature covers different evidence or nonce"
        );
        Ok(())
    }
}

fn report_binding(
    report_data: &[u8; 64],
    nonce: &str,
    recipient: &str,
    spki: &[u8],
) -> Result<[u8; 32]> {
    // Chutes hashes the hex nonce and base64 public key as transmitted.
    let mut hash = Sha256::new();
    hash.update(nonce.as_bytes());
    hash.update(recipient.as_bytes());
    let challenge: [u8; 32] = hash.finalize().into();
    let signer: [u8; 32] = Sha256::digest(spki).into();
    ensure!(
        report_data[..32] == challenge && report_data[32..] == signer,
        "TDX report does not bind the Chutes nonce, recipient and evidence signer"
    );
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tdx_binding_rejects_a_different_recipient_nonce_or_signer() {
        let nonce = "a1".repeat(32);
        let recipient = STANDARD.encode([3; 1184]);
        let spki = b"signing key";
        let challenge = Sha256::digest(format!("{nonce}{recipient}"));
        let mut report_data = [0; 64];
        report_data[..32].copy_from_slice(&challenge);
        report_data[32..].copy_from_slice(&Sha256::digest(spki));
        assert!(report_binding(&report_data, &nonce, &recipient, spki).is_ok());
        assert!(report_binding(&report_data, &nonce, &STANDARD.encode([4; 1184]), spki).is_err());
        assert!(report_binding(&report_data, &"b2".repeat(32), &recipient, spki).is_err());
        assert!(report_binding(&report_data, &nonce, &recipient, b"different signer").is_err());
    }
}
