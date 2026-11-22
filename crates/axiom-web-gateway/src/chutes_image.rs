mod attestation;
mod wire;

use anyhow::{Context, Result, ensure};
use axiom_web_gateway_core::inference::{
    ImageDimensions, ImageGenerationRequest, InvocationState, RequestUsage, UsageCompleteness,
};
use axiom_web_gateway_core::secure_client::{GeneratedImage, SecurityEvidence};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use image::{ImageEncoder as _, ImageFormat, ImageReader};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{io::Cursor, path::PathBuf, time::Duration};
use tokio::sync::{Semaphore, SemaphorePermit};
use zeroize::Zeroizing;

const CHUTES_ORIGIN: &str = "https://api.chutes.ai";
pub const CHUTE_ID: &str = "c5cbd4df-7460-502b-a9f1-01071c670692";
const MODEL_ID: &str = "chutes:qwen-image-2512";
const MAX_EVIDENCE: usize = 8 * 1024 * 1024;
const INVOCATION_TIMEOUT: u64 = 120;
const REQUIRED_PROOF_SECONDS: u64 = INVOCATION_TIMEOUT + 20;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    api_key_file: PathBuf,
}

pub struct Client {
    http: reqwest::Client,
    api_key: Zeroizing<String>,
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

pub struct Prepared<'a> {
    _slot: SemaphorePermit<'a>,
    instance: String,
    invocation_nonce: String,
    invoke_by: u64,
    pub wire_sha256: String,
    proof: SecurityEvidence,
    sealed: wire::SealedImage,
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
    pub fn new(config: &Config) -> Result<Self> {
        ensure!(
            config.api_key_file.is_absolute() && config.api_key_file.metadata()?.len() <= 4096,
            "invalid Chutes image configuration",
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
        let proof = tokio::time::timeout(
            Duration::from_secs(30),
            attestation::verify(&self.http, &instance, &nonce, &evidence),
        )
        .await??;
        let proof_expires = proof
            .hard_expires_at_unix_seconds
            .context("missing Chutes proof expiry")?;
        let invoke_by = discovery
            .nonce_expires_at
            .min(proof_expires.saturating_sub(REQUIRED_PROOF_SECONDS));
        ensure!(
            invoke_by > crate::now() + 10,
            "Chutes invocation nonce expired"
        );
        let sealed = wire::seal(&instance.e2e_pubkey, prompt, size.width, size.height)?;
        Ok(Prepared {
            _slot: slot,
            instance: instance.instance_id,
            invocation_nonce,
            invoke_by,
            wire_sha256: hex::encode(Sha256::digest(&sealed.body)),
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
}
