mod attestation;
mod service;
mod transport;

use anyhow::{Context, Result, ensure};
use axiom_gateway_protocol::{SignedDocument, TrustPolicy, verify_document};
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_origin: String,
    pub backend_origin: String,
    pub publisher_key: String,
    pub browser_origins: Vec<String>,
    pub max_concurrency: usize,
    pub max_sessions: usize,
    pub attestation_socket: String,
    pub encryption_key_path: String,
    pub authorization_key_path: String,
    pub verifier: String,
}

#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |v| v.as_secs())
}

pub fn origin(value: &str) -> Result<()> {
    let url = url::Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.origin().ascii_serialization() == value
            && !url.host_str().unwrap_or_default().is_empty(),
        "invalid HTTPS origin"
    );
    Ok(())
}

async fn document<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: String,
) -> Result<T> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 128 * 1024,
            "document exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("invalid public verification document")
}

async fn collect(
    config: &Config,
    client: &reqwest::Client,
    identity: &transport::Identity,
    authorization_key: &ed25519_dalek::SigningKey,
    minimum_sequence: u64,
) -> Result<Arc<attestation::Collector>> {
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let local = tokio::time::timeout(
        Duration::from_secs(20),
        attestation::local_document(&config.attestation_socket, &nonce),
    )
    .await??;
    // A lookup hint only. The verifier authenticates this digest and measurement
    // against the signed release and running TDX quote before opening a listener.
    let entries = local["collateral"]
        .as_array()
        .context("missing collateral")?;
    let code = entries
        .iter()
        .find(|v| v["format"] == "https://tinfoil.sh/collateral/sigstore-code/v1")
        .context("missing code provenance")?;
    let digest = code["data"]["digest"]
        .as_str()
        .context("missing config digest")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid config digest"
    );
    let manifest = document::<SignedDocument>(
        client,
        format!(
            "{}/api/v1/web-gateway/manifests/{digest}",
            config.backend_origin
        ),
    )
    .await?;
    let policy = document::<SignedDocument>(
        client,
        format!("{}/api/v1/web-gateway/trust-policy", config.backend_origin),
    )
    .await?;
    let trusted: TrustPolicy =
        verify_document(&policy, &config.publisher_key, "axiom-gateway-policy-v2")?;
    ensure!(
        trusted.sequence >= minimum_sequence,
        "gateway trust policy rollback"
    );
    attestation::Collector::new(
        config,
        identity.public_hex.clone(),
        hex::encode(authorization_key.verifying_key().as_bytes()),
        manifest,
        policy,
        minimum_sequence,
    )
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("gateway startup or runtime verification failed");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)] // Startup must show the ordering before the listener is opened.
async fn run() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/axiom-gateway/config.json".into());
    let raw = match std::env::var("AXIOM_GATEWAY_CONFIG_JSON") {
        Ok(value) => value.into_bytes(),
        Err(std::env::VarError::NotPresent) => std::fs::read(Path::new(&path))?,
        Err(_) => anyhow::bail!("invalid measured runtime configuration"),
    };
    ensure!(raw.len() <= 16384, "configuration exceeds limit");
    let config: Config = serde_json::from_slice(&raw)?;
    origin(&config.public_origin)?;
    origin(&config.backend_origin)?;
    ensure!(
        (1..=128).contains(&config.max_concurrency)
            && (1..=1024).contains(&config.max_sessions)
            && config.browser_origins.len() <= 16,
        "invalid capacity configuration"
    );
    for value in &config.browser_origins {
        origin(value)?;
    }
    ensure!(
        hex::decode(&config.publisher_key)?.len() == 32,
        "invalid publisher key"
    );
    // No tracing subscriber: failures expose only the constant above.
    let identity = Arc::new(transport::Identity::load(Path::new(
        &config.encryption_key_path,
    ))?);
    let signing_pem =
        zeroize::Zeroizing::new(std::fs::read_to_string(&config.authorization_key_path)?);
    ensure!(signing_pem.len() <= 4096, "private key exceeds limit");
    let authorization_key = ed25519_dalek::SigningKey::from_pkcs8_pem(&signing_pem)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let collector = tokio::time::timeout(
        Duration::from_secs(60),
        collect(&config, &http, &identity, &authorization_key, 0),
    )
    .await??;
    let initial = collector
        .proof(hex::encode(rand::random::<[u8; 32]>()))
        .await?;
    let policy: TrustPolicy = verify_document(
        &initial.policy,
        &config.publisher_key,
        "axiom-gateway-policy-v2",
    )?;
    let shutdown = CancellationToken::new();
    let state = Arc::new(service::State {
        slots: Arc::new(Semaphore::new(config.max_concurrency)),
        proof_slots: Arc::new(Semaphore::new(2)),
        config: config.clone(),
        identity: Arc::clone(&identity),
        authorization_key,
        http,
        collector: RwLock::new(collector),
        sessions: Mutex::new(BTreeMap::new()),
        active: Mutex::new(BTreeMap::new()),
        lease: Mutex::new(None),
        shutdown: shutdown.clone(),
    });
    // No listener until hardware/workload self-verification and attested backend admission pass.
    state.lease().await?;
    let refresh_state = Arc::clone(&state);
    let refresh = tokio::spawn(async move {
        let mut sequence = policy.sequence;
        loop {
            tokio::select! { () = refresh_state.shutdown.cancelled() => break, () = tokio::time::sleep(Duration::from_secs(120)) => {} }
            let result = tokio::time::timeout(Duration::from_secs(60), async {
                let candidate = collect(
                    &refresh_state.config,
                    &refresh_state.http,
                    &refresh_state.identity,
                    &refresh_state.authorization_key,
                    sequence,
                )
                .await?;
                let proof = candidate
                    .proof(hex::encode(rand::random::<[u8; 32]>()))
                    .await?;
                let policy: TrustPolicy = verify_document(
                    &proof.policy,
                    &refresh_state.config.publisher_key,
                    "axiom-gateway-policy-v2",
                )?;
                sequence = policy.sequence;
                *refresh_state.collector.write().await = candidate;
                Ok::<_, anyhow::Error>(())
            })
            .await;
            if !matches!(result, Ok(Ok(()))) {
                refresh_state.shutdown.cancel();
                break;
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let signal = shutdown.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut terminate) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        signal.cancel();
    });
    axum::serve(listener, service::router(Arc::clone(&state))?)
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .await?;
    shutdown.cancel();
    refresh.await?;
    Ok(())
}
