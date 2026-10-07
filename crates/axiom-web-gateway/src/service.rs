use crate::{
    Config,
    attestation::Collector,
    now,
    transport::{Identity, Reply},
};
use anyhow::{Context, Result, ensure};
use axiom_gateway_protocol::{
    PROTOCOL,
    authorization::{self, BrowserKey},
};
use axiom_web_gateway_core::{
    inference::{InferenceRequest, ProviderEvent},
    openai_compat::{ChatCompletionRequest, CompatMode},
    secure_client::{ApiCredential, SecureClient, SecureClientConfig, SecurityState},
};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State as ExtractState},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};
use ed25519_dalek::Signer as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub struct State {
    pub config: Config,
    pub identity: Arc<Identity>,
    pub authorization_key: ed25519_dalek::SigningKey,
    pub http: reqwest::Client,
    pub collector: RwLock<Arc<Collector>>,
    pub sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    pub active: Mutex<BTreeMap<(String, String), ActiveRequest>>,
    pub lease: Mutex<Option<Lease>>,
    pub slots: Arc<Semaphore>,
    pub proof_slots: Arc<Semaphore>,
    pub shutdown: CancellationToken,
}
pub struct ActiveRequest {
    owner: [u8; 16],
    cancellation: CancellationToken,
}
pub struct Lease {
    token: Zeroizing<String>,
    expires_at: u64,
}
pub struct Session {
    account: String,
    key: BrowserKey,
    client: Arc<SecureClient>,
    expires_at: u64,
    replays: Mutex<BTreeMap<String, u64>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    protocol: String,
    session_id: Option<String>,
    proof: String,
    payload: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionPayload {
    grant: String,
}
#[derive(Deserialize)]
struct RpcPayload {
    request_id: String,
    #[serde(flatten)]
    operation: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Models,
    Infer { request: Box<ChatCompletionRequest> },
    Cancel { target_request_id: String },
}

impl State {
    pub async fn lease(&self) -> Result<Zeroizing<String>> {
        let mut lease = self.lease.lock().await;
        if let Some(current) = lease.as_ref()
            && current.expires_at > now() + 30
        {
            return Ok(current.token.clone());
        }
        let challenge: Value = self.backend("challenges", json!({}), None).await?;
        let challenge = challenge["challenge"]
            .as_str()
            .context("invalid admission challenge")?
            .to_owned();
        let collector = Arc::clone(&*self.collector.read().await);
        let evidence = collector.proof(challenge.clone()).await?;
        let signature = self.sign(b"axiom-gateway-register-v2", challenge.as_bytes());
        let value = self
            .backend(
                "register",
                json!({"evidence":evidence,"signature":signature}),
                None,
            )
            .await?;
        let token = value["lease"]
            .as_str()
            .context("invalid gateway lease")?
            .to_owned();
        let expires_at = value["expires_at"]
            .as_u64()
            .context("invalid lease expiry")?;
        ensure!(
            token.starts_with("axl_") && expires_at > now() && expires_at <= now() + 240,
            "invalid gateway admission"
        );
        *lease = Some(Lease {
            token: Zeroizing::new(token.clone()),
            expires_at,
        });
        Ok(Zeroizing::new(token))
    }
    fn sign(&self, domain: &[u8], body: &[u8]) -> String {
        hex::encode(
            self.authorization_key
                .sign(&[domain, &[0], body].concat())
                .to_bytes(),
        )
    }
    async fn backend(&self, endpoint: &str, payload: Value, lease: Option<&str>) -> Result<Value> {
        let raw = Zeroizing::new(serde_json::to_vec(&payload)?);
        let mut request = self
            .http
            .post(format!(
                "{}/api/v1/web-gateway/{endpoint}",
                self.config.backend_origin
            ))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(lease) = lease {
            request = request.header("x-gateway-lease", lease).header(
                "x-gateway-signature",
                self.sign(b"axiom-gateway-exchange-v2", &raw),
            );
        }
        let mut response = request
            .body(raw.to_vec())
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 16384,
                "backend delegation response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).context("invalid backend delegation response")
    }
}

pub fn router(state: Arc<State>) -> Result<Router> {
    let origins = state
        .config
        .browser_origins
        .iter()
        .map(|v| v.parse::<HeaderValue>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
        .allow_headers([
            header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("axiom-encapsulated-key"),
        ])
        .expose_headers([axum::http::HeaderName::from_static("axiom-response-nonce")]);
    Ok(Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/attestation", post(proof))
        .route("/v1/session", post(session))
        .route("/v1/rpc", post(rpc))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(tower::limit::ConcurrencyLimitLayer::new(128))
        .layer(cors)
        .with_state(state))
}
fn rejected(status: StatusCode) -> Response {
    (status, "gateway request rejected").into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    challenge: String,
}
async fn proof(
    ExtractState(state): ExtractState<Arc<State>>,
    Json(challenge): Json<Challenge>,
) -> Response {
    let Ok(_permit) = state.proof_slots.clone().try_acquire_owned() else {
        return rejected(StatusCode::TOO_MANY_REQUESTS);
    };
    if challenge.challenge.len() != 64
        || hex::decode(&challenge.challenge).map_or(true, |v| v.len() != 32)
    {
        return rejected(StatusCode::BAD_REQUEST);
    }
    let collector = Arc::clone(&*state.collector.read().await);
    match tokio::time::timeout(
        Duration::from_secs(30),
        collector.proof(challenge.challenge),
    )
    .await
    {
        Ok(Ok(value)) => {
            let mut response = Json(value).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        _ => rejected(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn open(state: &State, headers: &HeaderMap, body: &[u8]) -> Result<(Envelope, Reply)> {
    ensure!(!state.shutdown.is_cancelled(), "gateway unavailable");
    ensure!(
        state
            .collector
            .try_read()
            .is_ok_and(|collector| collector.is_fresh()),
        "gateway attestation expired"
    );
    ensure!(
        !headers.contains_key(header::AUTHORIZATION) && !headers.contains_key(header::COOKIE),
        "outer credentials forbidden"
    );
    let encapsulated = headers
        .get("axiom-encapsulated-key")
        .context("encrypted request required")?
        .to_str()?;
    let (plaintext, reply) = state.identity.open(encapsulated, body)?;
    let envelope: Envelope = serde_json::from_slice(&plaintext)?;
    ensure!(
        envelope.protocol == PROTOCOL
            && envelope.proof.len() <= 8192
            && envelope.payload.len() <= 4 * 1024 * 1024,
        "invalid encrypted envelope"
    );
    Ok((envelope, reply))
}

async fn session(
    ExtractState(state): ExtractState<Arc<State>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok((envelope, mut reply)) = open(&state, &headers, &body) else {
        return rejected(StatusCode::BAD_REQUEST);
    };
    let result = async {
        ensure!(envelope.session_id.is_none(), "invalid session request");
        let payload: SessionPayload = serde_json::from_str(&envelope.payload)?;
        ensure!(
            payload.grant.len() == 47 && payload.grant.starts_with("axw_"),
            "invalid grant"
        );
        let lease = state.lease().await?;
        let authority = state
            .backend(
                "exchange",
                json!({"grant":payload.grant,"proof":envelope.proof,"payload":envelope.payload}),
                Some(&lease),
            )
            .await?;
        let account = authority["account_key"]
            .as_str()
            .context("missing tenant authority")?
            .to_owned();
        let key: BrowserKey = serde_json::from_value(authority["browser_key"].clone())?;
        let expires_at = authority["expires_at"]
            .as_u64()
            .context("invalid delegation expiry")?;
        let token = authority["relay_token"]
            .as_str()
            .context("missing relay authority")?;
        ensure!(
            expires_at > now()
                && expires_at <= now() + 900
                && token.starts_with("axg_")
                && account.len() == 64,
            "invalid relay authority"
        );
        authorization::verify(
            &envelope.proof,
            &key,
            &payload.grant,
            &format!("{}/v1/session", state.config.public_origin),
            &state.identity.public_hex,
            &envelope.payload,
            now(),
        )?;
        let client = Arc::new(SecureClient::new(
            SecureClientConfig::new(&state.config.backend_origin)?,
            ApiCredential::new(token),
        )?);
        let id = hex::encode(rand::random::<[u8; 32]>());
        let mut sessions = state.sessions.lock().await;
        sessions.retain(|_, value| value.expires_at > now());
        ensure!(
            sessions.len() < state.config.max_sessions
                && sessions.values().filter(|s| s.account == account).count() < 4,
            "session capacity reached"
        );
        sessions.insert(
            id.clone(),
            Arc::new(Session {
                account,
                key,
                client,
                expires_at,
                replays: Mutex::new(BTreeMap::new()),
            }),
        );
        Ok::<_, anyhow::Error>(json!({"protocol":PROTOCOL,"session_id":id,"expires_at":expires_at}))
    }
    .await;
    let payload = match result {
        Ok(value) => json!({"success":true,"data":value}),
        Err(_) => json!({"success":false,"code":"authorization_failed"}),
    };
    match reply.frame(&payload) {
        Ok(bytes) => encrypted_response(&reply.nonce_hex, Body::from(bytes)),
        Err(_) => rejected(StatusCode::BAD_REQUEST),
    }
}

fn encrypted_response(nonce: &str, body: Body) -> Response {
    // Accept ownership so callers can move the nonce out of their reply state.
    let nonce = HeaderValue::from_str(nonce).expect("nonce is hex");
    let mut response = Response::new(body);
    response.headers_mut().insert("axiom-response-nonce", nonce);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn rpc(
    ExtractState(state): ExtractState<Arc<State>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok((envelope, reply)) = open(&state, &headers, &body) else {
        return rejected(StatusCode::BAD_REQUEST);
    };
    let result = async {
        let id = envelope.session_id.as_ref().context("missing session")?;
        let session = state
            .sessions
            .lock()
            .await
            .get(id)
            .cloned()
            .context("unknown session")?;
        ensure!(session.expires_at > now(), "session expired");
        let proof = authorization::verify(
            &envelope.proof,
            &session.key,
            id,
            &format!("{}/v1/rpc", state.config.public_origin),
            &state.identity.public_hex,
            &envelope.payload,
            now(),
        )?;
        let mut replays = session.replays.lock().await;
        replays.retain(|_, expiry| *expiry > now());
        ensure!(
            replays.len() < 4096 && !replays.contains_key(&proof.jti),
            "request replay or capacity limit"
        );
        replays.insert(proof.jti, proof.iat + 91);
        drop(replays);
        let payload: RpcPayload = serde_json::from_str(&envelope.payload)?;
        ensure!(
            payload.request_id.len() == 32 && hex::decode(&payload.request_id)?.len() == 16,
            "invalid request identity"
        );
        Ok::<_, anyhow::Error>((session, payload))
    }
    .await;
    let Ok((session, payload)) = result else {
        let mut reply = reply;
        return match reply.frame(&json!({"success":false,"code":"authorization_failed"})) {
            Ok(bytes) => encrypted_response(&reply.nonce_hex, Body::from(bytes)),
            Err(_) => rejected(StatusCode::BAD_REQUEST),
        };
    };
    let nonce = reply.nonce_hex.clone();
    let (sender, receiver) = mpsc::channel(16);
    let cancellation = state.shutdown.child_token();
    let stream_cancel = cancellation.clone();
    tokio::spawn(async move {
        let active_key = (session.account.clone(), payload.request_id.clone());
        let owner = rand::random::<[u8; 16]>();
        let mut output = Output {
            reply,
            sender,
            digest: Sha256::new(),
            request_id: payload.request_id.clone(),
            sequence: 0,
        };
        let result = tokio::time::timeout(
            Duration::from_secs(600),
            execute(&state, &session, payload, &cancellation, owner, &mut output),
        )
        .await;
        let mut active = state.active.lock().await;
        if active
            .get(&active_key)
            .is_some_and(|entry| entry.owner == owner)
        {
            active.remove(&active_key);
        }
        drop(active);
        match result {
            Ok(Ok(value)) if !cancellation.is_cancelled() => {
                let _ = output.terminal(true, value).await;
            }
            _ => {
                cancellation.cancel();
                let _ = output
                    .terminal(false, json!({"code":"request_failed"}))
                    .await;
            }
        }
    });
    encrypted_response(
        &nonce,
        Body::from_stream(CancelStream {
            inner: tokio_stream::wrappers::ReceiverStream::new(receiver),
            cancellation: stream_cancel,
        }),
    )
}

struct CancelStream {
    inner: tokio_stream::wrappers::ReceiverStream<std::result::Result<Bytes, std::io::Error>>,
    cancellation: CancellationToken,
}
impl futures_util::Stream for CancelStream {
    type Item = std::result::Result<Bytes, std::io::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(context)
    }
}
impl Drop for CancelStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct Output {
    reply: Reply,
    sender: mpsc::Sender<std::result::Result<Bytes, std::io::Error>>,
    digest: Sha256,
    request_id: String,
    sequence: u64,
}
impl Output {
    async fn send(&mut self, kind: &str, data: Value) -> Result<()> {
        let frame = json!({"protocol":PROTOCOL,"request_id":self.request_id,"sequence":self.sequence,"kind":kind,"data":data});
        let mut plaintext = Zeroizing::new(serde_json::to_vec(&frame)?);
        plaintext.push(b'\n');
        self.digest.update(&plaintext);
        let bytes = self.reply.frame(&frame)?;
        self.sequence += 1;
        tokio::time::timeout(
            Duration::from_secs(30),
            self.sender.send(Ok(Bytes::from(bytes))),
        )
        .await
        .context("browser backpressure deadline")?
        .map_err(|_| anyhow::anyhow!("browser disconnected"))
    }
    async fn terminal(&mut self, success: bool, result: Value) -> Result<()> {
        let digest = hex::encode(self.digest.clone().finalize());
        self.send(
            "terminal",
            json!({"success":success,"transcript_sha256":digest,"result":result}),
        )
        .await
    }
}

async fn execute(
    state: &Arc<State>,
    session: &Arc<Session>,
    payload: RpcPayload,
    cancellation: &CancellationToken,
    owner: [u8; 16],
    output: &mut Output,
) -> Result<Value> {
    match payload.operation {
        Operation::Models => {
            let models = session.client.models(cancellation.clone()).await?;
            output.send("models", serde_json::to_value(models)?).await?;
            Ok(json!({}))
        }
        Operation::Cancel { target_request_id } => {
            ensure!(target_request_id.len() == 32, "invalid cancellation target");
            let active = state.active.lock().await;
            let target = active
                .get(&(session.account.clone(), target_request_id))
                .context("request not owned by account")?;
            target.cancellation.cancel();
            Ok(json!({"cancelled":true}))
        }
        Operation::Infer { request } => {
            let mut request = (*request).into_domain(CompatMode::Strict)?.request;
            let _permit = state
                .slots
                .clone()
                .try_acquire_owned()
                .context("gateway capacity reached")?;
            let active_key = (session.account.clone(), payload.request_id.clone());
            {
                let mut active = state.active.lock().await;
                ensure!(
                    active
                        .keys()
                        .filter(|(account, _)| account == &session.account)
                        .count()
                        < 5
                        && !active.contains_key(&active_key),
                    "account concurrency reached"
                );
                active.insert(
                    active_key,
                    ActiveRequest {
                        owner,
                        cancellation: cancellation.clone(),
                    },
                );
            }
            infer(
                session,
                &mut request,
                &payload.request_id,
                cancellation,
                output,
            )
            .await
        }
    }
}

async fn infer(
    session: &Session,
    request: &mut InferenceRequest,
    id: &str,
    cancellation: &CancellationToken,
    output: &mut Output,
) -> Result<Value> {
    request.request_id = Some(id.into());
    request.stream = true;
    request.validate()?;
    let models = session.client.models(cancellation.clone()).await?;
    let model = models
        .iter()
        .find(|m| m.id == request.model)
        .context("unsupported model")?;
    let policy = session.client.trust_policy(cancellation.clone()).await?;
    ensure!(
        policy.accepted_intel_statuses == ["UpToDate"],
        "weak upstream trust policy"
    );
    let mut upstream = session
        .client
        .establish(model, &policy, cancellation.clone())
        .await?;
    ensure!(
        upstream.evidence().state == SecurityState::Verified,
        "upstream attestation rejected"
    );
    output
        .send("upstream_proof", serde_json::to_value(upstream.evidence())?)
        .await?;
    let (sender, mut receiver) = mpsc::channel(16);
    let result = bridge(
        async {
            upstream
                .stream(request.clone(), sender, cancellation.clone())
                .await
                .map_err(Into::into)
        },
        &mut receiver,
        cancellation,
        output,
    )
    .await?;
    Ok(
        json!({"response":{"assistant":{"text":result.assistant.text,"reasoning":result.assistant.reasoning,"tool_calls":result.assistant.tool_calls},"refusal":result.refusal,"usage":result.usage,"finish_reason":result.finish_reason},"upstream_response_verified":true}),
    )
}

async fn bridge<T>(
    future: impl std::future::Future<Output = Result<T>>,
    receiver: &mut mpsc::Receiver<ProviderEvent>,
    cancellation: &CancellationToken,
    output: &mut Output,
) -> Result<T> {
    let mut verified = false;
    let mut ended = false;
    let result = {
        tokio::pin!(future);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => anyhow::bail!("request cancelled"),
                result = &mut future => break result,
                event = receiver.recv(), if !ended => {
                    if let Some(event) = event { forward(event, output, &mut verified).await?; } else { ended = true; }
                },
            }
        }
    }?;
    while let Some(event) = receiver.recv().await {
        forward(event, output, &mut verified).await?;
    }
    ensure!(
        verified && !cancellation.is_cancelled(),
        "upstream terminal authentication missing"
    );
    Ok(result)
}

async fn forward(event: ProviderEvent, output: &mut Output, verified: &mut bool) -> Result<()> {
    match event {
        ProviderEvent::ResponseVerified => { *verified = true; },
        ProviderEvent::TextDelta(value) => output.send("text_delta", json!({"text":value,"provisional":true})).await?,
        ProviderEvent::ReasoningDelta(value) => output.send("reasoning_delta", json!({"text":value,"provisional":true})).await?,
        ProviderEvent::RefusalDelta(value) => output.send("refusal_delta", json!({"text":value,"provisional":true})).await?,
        ProviderEvent::ToolCallDelta(value) => output.send("tool_call_delta", json!({"index":value.index,"id":value.id,"name":value.name,"arguments":value.arguments})).await?,
        ProviderEvent::Usage { input_tokens, output_tokens } => output.send("usage", json!({"input_tokens":input_tokens,"output_tokens":output_tokens})).await?,
        ProviderEvent::Accounting(value) => output.send("accounting", serde_json::to_value(value)?).await?,
        ProviderEvent::Finished(_) | ProviderEvent::SecurityState(_) | ProviderEvent::Status { .. } => {},
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{Deserializable as _, Serializable as _, kem::X25519HkdfSha256};
    use rand::{SeedableRng as _, rngs::StdRng};

    fn output() -> (
        Output,
        mpsc::Receiver<std::result::Result<Bytes, std::io::Error>>,
    ) {
        let identity = Identity::generate();
        let public = <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(
            &hex::decode(&identity.public_hex).unwrap(),
        )
        .unwrap();
        let (enc, mut context) = hpke::setup_sender::<
            hpke::aead::AesGcm256,
            hpke::kdf::HkdfSha256,
            X25519HkdfSha256,
            _,
        >(
            &hpke::OpModeS::Base,
            &public,
            ehbp::HPKE_REQUEST_INFO,
            &mut StdRng::from_os_rng(),
        )
        .unwrap();
        let ciphertext = context.seal(b"{}", &[]).unwrap();
        let mut body = u32::try_from(ciphertext.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        body.extend(ciphertext);
        let (_, reply) = identity.open(&hex::encode(enc.to_bytes()), &body).unwrap();
        let (sender, receiver) = mpsc::channel(16);
        (
            Output {
                reply,
                sender,
                digest: Sha256::new(),
                request_id: "ab".repeat(16),
                sequence: 0,
            },
            receiver,
        )
    }

    #[tokio::test]
    async fn upstream_success_requires_authenticated_completion() {
        for verified in [false, true] {
            let (sender, mut events) = mpsc::channel(4);
            let future = async move {
                sender
                    .send(ProviderEvent::TextDelta("provisional fixture".into()))
                    .await
                    .unwrap();
                if verified {
                    sender.send(ProviderEvent::ResponseVerified).await.unwrap();
                }
                Ok::<_, anyhow::Error>(())
            };
            let (mut output, _receiver) = output();
            let result = bridge(future, &mut events, &CancellationToken::new(), &mut output).await;
            assert_eq!(result.is_ok(), verified);
            assert_eq!(output.sequence, 1);
        }
    }

    #[tokio::test]
    async fn authenticated_delta_cannot_turn_provider_failure_or_cancel_into_success() {
        let (sender, mut events) = mpsc::channel(4);
        let future = async move {
            sender.send(ProviderEvent::ResponseVerified).await.unwrap();
            Err::<(), _>(anyhow::anyhow!("provider completion failed"))
        };
        let (mut output, _receiver) = output();
        assert!(
            bridge(future, &mut events, &CancellationToken::new(), &mut output)
                .await
                .is_err()
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let (_, mut events) = mpsc::channel(4);
        assert!(
            bridge(
                std::future::pending::<Result<()>>(),
                &mut events,
                &cancellation,
                &mut output
            )
            .await
            .is_err()
        );
    }
}
