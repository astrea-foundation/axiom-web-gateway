mod wire;

use anyhow::{Context, Result, ensure};
use axiom_web_gateway_core::inference::{
    ImageDimensions, ImageGenerationRequest, InvocationState, RequestUsage, UsageCompleteness,
};
use axiom_web_gateway_core::secure_client::{
    EvidenceClaim, GeneratedImage, SecurityEvidence, SecurityState,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use image::{ImageEncoder as _, ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{io::Cursor, path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{Semaphore, SemaphorePermit},
};
use zeroize::Zeroizing;

const CHUTES_ORIGIN: &str = "https://api.chutes.ai";
const CHUTE_ID: &str = "c5cbd4df-7460-502b-a9f1-01071c670692";
const MODEL_ID: &str = "chutes:qwen-image-2512";
const MAX_EVIDENCE: usize = 8 * 1024 * 1024;
const MAX_MANIFEST: usize = 64 * 1024;
const INVOCATION_TIMEOUT: u64 = 120;
const REQUIRED_PROOF_SECONDS: u64 = INVOCATION_TIMEOUT + 20;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    api_key_file: PathBuf,
    verifier: PathBuf,
    verifier_sha256: String,
    workload_sha256: String,
}

pub struct Client {
    http: reqwest::Client,
    api_key: Zeroizing<String>,
    config: Config,
    // One concurrent overflow attempt in the initial pilot, including preflight.
    slot: Semaphore,
}

#[derive(Deserialize)]
struct Discovery {
    instances: Vec<DiscoveredWorker>,
    nonce_expires_at: u64,
}

#[derive(Deserialize)]
struct DiscoveredWorker {
    instance_id: String,
    e2e_pubkey: String,
    nonces: Vec<String>,
}

#[derive(Serialize)]
struct Verification<'a> {
    protocol: &'static str,
    nonce: &'a str,
    chute_id: &'static str,
    instance_id: &'a str,
    e2e_pubkey: &'a str,
    workload_sha256: &'a str,
    evidence: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verified {
    nonce: String,
    chute_id: String,
    instance_id: String,
    e2e_pubkey: String,
    expires_at: u64,
    workload_manifest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadManifest<'a> {
    chute_id: &'a str,
    source_uri: &'a str,
    source_sha256: &'a str,
    container_digest: &'a str,
    model: &'a str,
    model_revision: &'a str,
    weights_manifest_sha256: &'a str,
}

pub struct Prepared<'a> {
    _slot: SemaphorePermit<'a>,
    instance: String,
    invocation_nonce: String,
    invoke_by: u64,
    pub wire_sha256: String,
    pub workload_sha256: &'a str,
    proof: SecurityEvidence,
    sealed: wire::SealedImage,
}

fn lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn supports_dimensions(size: ImageDimensions) -> bool {
    size.validate().is_ok()
        && size.width <= 2048
        && size.height <= 2048
        && u64::from(size.width) * u64::from(size.height) <= 1536 * 1536
}

pub fn eligible_size(request: &ImageGenerationRequest<'_>) -> Option<ImageDimensions> {
    let size = request
        .dimensions
        .filter(|size| supports_dimensions(*size))?;
    (request.allow_long_queue
        && request.references.is_empty()
        && !request.chat_model_id.trim().is_empty()
        && request.chat_model_id.len() <= 256
        && !request.chat_model_id.chars().any(char::is_control))
    .then_some(size)
}

pub fn verified_image(
    request_id: &str,
    chat_model_id: &str,
    size: ImageDimensions,
    png: &[u8],
    evidence: SecurityEvidence,
    charge: u64,
    started: u64,
) -> GeneratedImage {
    GeneratedImage {
        request_id: request_id.into(),
        data: STANDARD.encode(png),
        mime_type: "image/png".into(),
        width: size.width,
        height: size.height,
        sha256: hex::encode(Sha256::digest(png)),
        source_image_ids: Vec::new(),
        chat_model_id: Some(chat_model_id.into()),
        evidence,
        usage: RequestUsage {
            request_id: request_id.into(),
            model_id: MODEL_ID.into(),
            provider_id: "chutes".into(),
            state: InvocationState::Completed,
            completeness: UsageCompleteness::Final,
            image_pixels: Some((u64::from(size.width) * u64::from(size.height)).to_string()),
            input_image_pixels: Some("0".into()),
            cost_microusd: Some(charge.to_string()),
            settled: true,
            response_verified: true,
            started_at_ms: (started * 1000).to_string(),
            finished_at_ms: Some((crate::now() * 1000).to_string()),
            ..Default::default()
        },
    }
}

impl Client {
    pub fn new(config: Config) -> Result<Self> {
        ensure!(
            config.api_key_file.is_absolute()
                && config.verifier.is_absolute()
                && config.verifier.is_file()
                && lowercase_hex(&config.verifier_sha256, 64)
                && lowercase_hex(&config.workload_sha256, 64)
                && config.api_key_file.metadata()?.len() <= 4096
                && config.verifier.metadata()?.len() <= 128 * 1024 * 1024,
            "invalid Chutes image configuration",
        );
        ensure!(
            hex::encode(Sha256::digest(std::fs::read(&config.verifier)?)) == config.verifier_sha256,
            "Chutes workload verifier digest differs",
        );
        let key = Zeroizing::new(std::fs::read_to_string(&config.api_key_file)?);
        let key = key.trim();
        ensure!(
            (32..=4096).contains(&key.len())
                && key.starts_with("cpk_")
                && reqwest::header::HeaderValue::from_str(key).is_ok(),
            "invalid Chutes credential"
        );
        Ok(Self {
            http: reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .build()?,
            api_key: Zeroizing::new(key.to_owned()),
            config,
            slot: Semaphore::new(1),
        })
    }

    pub async fn prepare(&self, prompt: &str, size: ImageDimensions) -> Result<Prepared<'_>> {
        let slot = self.slot.try_acquire().context("Chutes overflow is busy")?;
        ensure!(
            supports_dimensions(size)
                && (1..=8192).contains(&prompt.len())
                && !prompt.trim().is_empty(),
            "unsupported Chutes image request"
        );
        let discovery: Discovery = serde_json::from_slice(
            &self
                .get(&format!("/e2e/instances/{CHUTE_ID}"), 128 * 1024)
                .await?,
        )?;
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        let instance = discovery
            .instances
            .into_iter()
            .find(|instance| !instance.nonces.is_empty())
            .context("no active Chutes image instance")?;
        ensure!(
            instance.instance_id.len() == 36
                && instance
                    .instance_id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b'-')
                && instance.e2e_pubkey.len() == 1580,
            "invalid Chutes instance identity",
        );
        let invocation_nonce = instance
            .nonces
            .first()
            .cloned()
            .context("missing Chutes nonce")?;
        ensure!(
            (1..=1024).contains(&invocation_nonce.len())
                && invocation_nonce.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid Chutes invocation nonce"
        );
        let evidence = self
            .get(
                &format!("/instances/{}/evidence?nonce={nonce}", instance.instance_id),
                MAX_EVIDENCE,
            )
            .await?;
        let verification = Verification {
            protocol: "axiom-chutes-image-verification-v1",
            nonce: &nonce,
            chute_id: CHUTE_ID,
            instance_id: &instance.instance_id,
            e2e_pubkey: &instance.e2e_pubkey,
            workload_sha256: &self.config.workload_sha256,
            evidence: std::str::from_utf8(&evidence)?,
        };
        let verified = self.verify(&verification).await?;
        let proof = verified.proof(&verification, crate::now())?;
        let invoke_by = discovery
            .nonce_expires_at
            .min(verified.expires_at - REQUIRED_PROOF_SECONDS);
        ensure!(
            invoke_by > crate::now() + 10,
            "Chutes invocation nonce expired"
        );
        let sealed = wire::seal(&verified.e2e_pubkey, prompt, size.width, size.height)?;
        Ok(Prepared {
            _slot: slot,
            instance: instance.instance_id,
            invocation_nonce,
            invoke_by,
            wire_sha256: hex::encode(Sha256::digest(&sealed.body)),
            workload_sha256: &self.config.workload_sha256,
            proof,
            sealed,
        })
    }

    async fn get(&self, path: &str, limit: usize) -> Result<Vec<u8>> {
        bounded(
            self.http
                .get(format!("{CHUTES_ORIGIN}{path}"))
                .bearer_auth(self.api_key.as_str())
                .send()
                .await?,
            limit,
        )
        .await
    }

    async fn verify(&self, verification: &Verification<'_>) -> Result<Verified> {
        let raw = serde_json::to_vec(verification)?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut child = tokio::process::Command::new(&self.config.verifier)
                .env_clear()
                .kill_on_drop(true)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            let mut stdin = child
                .stdin
                .take()
                .context("missing Chutes verifier input")?;
            let stdout = child
                .stdout
                .take()
                .context("missing Chutes verifier output")?;
            let mut stdout = stdout.take(128 * 1024 + 1);
            let mut out = Vec::new();
            tokio::try_join!(
                async move { stdin.write_all(&raw).await },
                stdout.read_to_end(&mut out),
            )?;
            ensure!(
                out.len() <= 128 * 1024 && child.wait().await?.success(),
                "Chutes workload verification rejected"
            );
            serde_json::from_slice(&out).context("invalid Chutes verification result")
        })
        .await?
    }

    pub async fn invoke(
        &self,
        prepared: Prepared<'_>,
        size: ImageDimensions,
    ) -> Result<(Zeroizing<Vec<u8>>, SecurityEvidence)> {
        ensure!(
            prepared.invoke_by > crate::now(),
            "Chutes invocation nonce expired"
        );
        let Prepared {
            mut sealed,
            instance,
            invocation_nonce,
            proof,
            _slot,
            ..
        } = prepared;
        let response = self
            .http
            .post(format!("{CHUTES_ORIGIN}/e2e/invoke"))
            .bearer_auth(self.api_key.as_str())
            .header("x-chute-id", CHUTE_ID)
            .header("x-instance-id", instance)
            .header("x-e2e-nonce", invocation_nonce)
            .header("x-e2e-stream", "false")
            .header("x-e2e-path", "/generate")
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .timeout(Duration::from_secs(INVOCATION_TIMEOUT))
            .body(std::mem::take(&mut sealed.body))
            .send()
            .await?;
        let raw = bounded(response, wire::MAX_IMAGE_RESPONSE + 4096).await?;
        let png =
            tokio::task::spawn_blocking(move || png_from_jpeg(&sealed.open(&raw)?, size)).await??;
        ensure!(
            proof
                .hard_expires_at_unix_seconds
                .is_some_and(|expires| expires > crate::now()),
            "Chutes worker proof expired"
        );
        Ok((png, proof))
    }
}

impl Verified {
    fn proof(&self, request: &Verification<'_>, now: u64) -> Result<SecurityEvidence> {
        ensure!(
            self.nonce == request.nonce
                && self.chute_id == request.chute_id
                && self.instance_id == request.instance_id
                && self.e2e_pubkey == request.e2e_pubkey
                && self.expires_at > now + REQUIRED_PROOF_SECONDS
                && self.expires_at <= now + 600
                && self.workload_manifest.len() <= MAX_MANIFEST
                && hex::encode(Sha256::digest(self.workload_manifest.as_bytes()))
                    == request.workload_sha256,
            "Chutes workload, key or freshness differs",
        );
        let manifest: WorkloadManifest<'_> = serde_json::from_str(&self.workload_manifest)?;
        ensure!(
            manifest.chute_id == CHUTE_ID
                && manifest.model == "Qwen/Qwen-Image-2512"
                && lowercase_hex(manifest.model_revision, 40)
                && lowercase_hex(manifest.source_sha256, 64)
                && lowercase_hex(manifest.weights_manifest_sha256, 64)
                && manifest
                    .container_digest
                    .strip_prefix("sha256:")
                    .is_some_and(|digest| lowercase_hex(digest, 64))
                && url::Url::parse(manifest.source_uri).is_ok_and(|uri| {
                    uri.scheme() == "https"
                        && uri.host_str().is_some()
                        && uri.username().is_empty()
                        && uri.password().is_none()
                }),
            "Chutes workload manifest does not describe the approved image deployment",
        );
        Ok(SecurityEvidence {
            state: SecurityState::Verified,
            provider_id: "chutes".into(),
            model_id: MODEL_ID.into(),
            attestation_protocol: "axiom-chutes-image-verification-v1".into(),
            e2ee_protocol: "chutes-mlkem768-v1".into(),
            e2ee_encryption_version: 1,
            trust_policy_version: request.workload_sha256.into(),
            verified_at_unix_seconds: now,
            attestation_generation: None,
            hard_expires_at_unix_seconds: Some(self.expires_at),
            model_key_fingerprint: hex::encode(Sha256::digest(STANDARD.decode(&self.e2e_pubkey)?)),
            tls_spki_fingerprint: None,
            checks: Vec::new(),
            provider_claims: vec![EvidenceClaim {
                name: "Chutes deployment".into(),
                value: CHUTE_ID.into(),
            }],
            workload_manifest: Some(self.workload_manifest.clone()),
        })
    }
}

pub async fn bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(response.status().is_success(), "upstream request rejected");
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit - bytes.len(),
            "upstream response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn png_from_jpeg(jpeg: &[u8], size: ImageDimensions) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(supports_dimensions(size), "unsupported output dimensions");
    let reader = || ImageReader::with_format(Cursor::new(jpeg), ImageFormat::Jpeg);
    ensure!(
        reader().into_dimensions()? == (size.width, size.height),
        "Chutes image size differs"
    );
    let pixels = Zeroizing::new(reader().decode()?.into_rgb8().into_raw());
    let mut png = Zeroizing::new(Vec::new());
    image::codecs::png::PngEncoder::new(&mut *png).write_image(
        &pixels,
        size.width,
        size.height,
        image::ExtendedColorType::Rgb8,
    )?;
    ensure!(
        png.len() <= axiom_web_gateway_core::inference::MAX_GENERATED_IMAGE_BYTES,
        "normalized Chutes image exceeds limit"
    );
    Ok(png)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_exact_request_size_and_normalizes_authenticated_jpeg() {
        let size = ImageDimensions {
            width: 256,
            height: 256,
        };
        let mut jpg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpg)
            .write_image(
                &vec![37; 256 * 256 * 3],
                256,
                256,
                image::ExtendedColorType::Rgb8,
            )
            .unwrap();
        let png = png_from_jpeg(&jpg, size).unwrap();
        assert_eq!(
            image::load_from_memory_with_format(&png, ImageFormat::Png)
                .unwrap()
                .width(),
            256
        );
        assert!(
            png_from_jpeg(
                &jpg,
                ImageDimensions {
                    width: 256,
                    height: 288
                }
            )
            .is_err()
        );
        assert!(!supports_dimensions(ImageDimensions {
            width: 2240,
            height: 960
        }));
    }

    #[test]
    fn edits_and_legacy_short_waits_stay_on_primary() {
        use axiom_web_gateway_core::inference::ImageContent;
        let mut request = ImageGenerationRequest {
            chat_model_id: "fixture-chat-model",
            prompt: "One red kite",
            references: &[],
            dimensions: Some(ImageDimensions {
                width: 1536,
                height: 1536,
            }),
            allow_long_queue: true,
        };
        assert_eq!(eligible_size(&request), request.dimensions);
        let image = ImageContent {
            mime_type: "image/png".into(),
            data: "fixture".into(),
        };
        let references = [
            ("a", &image),
            ("b", &image),
            ("c", &image),
            ("d", &image),
            ("e", &image),
        ];
        for count in 1..=references.len() {
            request.references = &references[..count];
            assert_eq!(eligible_size(&request), None);
        }
        request.references = &[];
        request.allow_long_queue = false;
        assert_eq!(eligible_size(&request), None);
    }

    #[test]
    fn rejects_hardware_only_or_rebound_verifier_results() {
        let manifest = serde_json::json!({
            "chute_id": CHUTE_ID, "model": "Qwen/Qwen-Image-2512",
            "source_uri": "https://fixture.example/source", "source_sha256": "a".repeat(64),
            "container_digest": format!("sha256:{}", "b".repeat(64)),
            "model_revision": "c".repeat(40), "weights_manifest_sha256": "d".repeat(64),
        })
        .to_string();
        let hash = hex::encode(Sha256::digest(manifest.as_bytes()));
        let recipient = STANDARD.encode([5; 1184]);
        let request = Verification {
            protocol: "axiom-chutes-image-verification-v1",
            nonce: "fresh",
            chute_id: CHUTE_ID,
            instance_id: "instance",
            e2e_pubkey: &recipient,
            workload_sha256: &hash,
            evidence: "{}",
        };
        let mut verified = Verified {
            nonce: request.nonce.into(),
            chute_id: request.chute_id.into(),
            instance_id: request.instance_id.into(),
            e2e_pubkey: recipient.clone(),
            expires_at: 300,
            workload_manifest: String::new(),
        };
        assert!(verified.proof(&request, 1).is_err());
        verified.workload_manifest = manifest;
        assert!(verified.proof(&request, 1).is_ok());
        verified.nonce = "stale".into();
        assert!(verified.proof(&request, 1).is_err());
        verified.nonce = request.nonce.into();
        verified.e2e_pubkey = STANDARD.encode([7; 1184]);
        assert!(verified.proof(&request, 1).is_err());
    }
}
