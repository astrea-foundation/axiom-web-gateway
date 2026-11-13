//! Opaque inner-worker relay. This module never imports an inference request.
use super::*;
use axiom_pool_protocol::{OUTER_PROTOCOL, strict};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    request_id: String,
    payload: Value,
}
#[derive(Clone, Copy)]
enum Operation {
    Reserve,
    Grants,
    Attestation,
    Control,
    Exchange,
}
impl Operation {
    fn route(self) -> &'static str {
        match self {
            Self::Reserve => "reserve",
            Self::Grants => "grants",
            Self::Attestation => "attestation",
            Self::Control => "control",
            Self::Exchange => "exchange",
        }
    }
}

pub(super) fn router() -> Router<Arc<State>> {
    async fn reserve(s: ExtractState<Arc<State>>, h: HeaderMap, b: Bytes) -> Response {
        handle(s.0, h, b, Operation::Reserve).await
    }
    async fn grants(s: ExtractState<Arc<State>>, h: HeaderMap, b: Bytes) -> Response {
        handle(s.0, h, b, Operation::Grants).await
    }
    async fn attestation(s: ExtractState<Arc<State>>, h: HeaderMap, b: Bytes) -> Response {
        handle(s.0, h, b, Operation::Attestation).await
    }
    async fn control(s: ExtractState<Arc<State>>, h: HeaderMap, b: Bytes) -> Response {
        handle(s.0, h, b, Operation::Control).await
    }
    async fn exchange(s: ExtractState<Arc<State>>, h: HeaderMap, b: Bytes) -> Response {
        handle(s.0, h, b, Operation::Exchange).await
    }
    Router::new()
        .route("/v1/pool/reserve", post(reserve))
        .route("/v1/pool/grants", post(grants))
        .route("/v1/pool/attestation", post(attestation))
        .route("/v1/pool/control", post(control))
        .route("/v1/pool/exchange", post(exchange))
        .layer(DefaultBodyLimit::max(24 * 1024 * 1024))
}
async fn authorize(state: &State, envelope: &Envelope, op: Operation) -> Result<Arc<Session>> {
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
        &format!("{}/v1/pool/{}", state.config.public_origin, op.route()),
        &state.identity.public_hex,
        &envelope.payload,
        now(),
    )?;
    let mut replays = session.replays.lock().await;
    replays.retain(|_, expiry| *expiry > now());
    ensure!(
        replays.len() < 4096 && !replays.contains_key(&proof.jti),
        "proof replay/capacity"
    );
    replays.insert(proof.jti, proof.iat + 91);
    drop(replays);
    Ok(session)
}
async fn handle(state: Arc<State>, headers: HeaderMap, body: Bytes, op: Operation) -> Response {
    let (envelope, reply) = match open_protocol(
        &state,
        &headers,
        &body,
        OUTER_PROTOCOL,
        24 * 1024 * 1024,
        160 * 1024 * 1024,
    ) {
        Ok(v) => v,
        Err(_) => return rejected(StatusCode::BAD_REQUEST),
    };
    let session = match authorize(&state, &envelope, op).await {
        Ok(v) => v,
        Err(_) => return rejected(StatusCode::FORBIDDEN),
    };
    let call: Call = match strict::decode(envelope.payload.as_bytes()) {
        Ok(v) => v,
        Err(_) => return rejected(StatusCode::BAD_REQUEST),
    };
    if axiom_pool_protocol::hex_bytes(&call.request_id, 16).is_err() {
        return rejected(StatusCode::BAD_REQUEST);
    }
    let permit = match state.slots.clone().try_acquire_owned() {
        Ok(v) => v,
        Err(_) => return rejected(StatusCode::TOO_MANY_REQUESTS),
    };
    let active_key = (session.account.clone(), call.request_id.clone());
    let owner = rand::random::<[u8; 16]>();
    let cancellation = state.shutdown.child_token();
    let mut active = state.active.lock().await;
    if active.contains_key(&active_key)
        || active
            .keys()
            .filter(|(account, _)| account == &session.account)
            .count()
            >= 5
    {
        return rejected(StatusCode::TOO_MANY_REQUESTS);
    }
    active.insert(
        active_key.clone(),
        ActiveRequest {
            owner,
            cancellation: cancellation.clone(),
        },
    );
    drop(active);
    let nonce = reply.nonce_hex.clone();
    let (sender, receiver) = mpsc::channel(16);
    let stream_cancel = cancellation.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let mut output = RelayOutput {
            reply,
            sender,
            request_id: call.request_id,
            sequence: 0,
            digest: Sha256::new(),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(600),
            relay(
                &state,
                &session,
                call.payload,
                op,
                &cancellation,
                &mut output,
            ),
        )
        .await;
        let success = matches!(result, Ok(Ok(()))) && !cancellation.is_cancelled();
        let _ = output.terminal(success).await;
        let mut active = state.active.lock().await;
        if active
            .get(&active_key)
            .is_some_and(|entry| entry.owner == owner)
        {
            active.remove(&active_key);
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
struct RelayOutput {
    reply: Reply,
    sender: mpsc::Sender<std::result::Result<Bytes, std::io::Error>>,
    request_id: String,
    sequence: u64,
    digest: Sha256,
}
impl RelayOutput {
    async fn frame(&mut self, kind: &str, data: Value) -> Result<()> {
        let value = json!({"protocol":OUTER_PROTOCOL,"request_id":self.request_id,"sequence":self.sequence,"kind":kind,"data":data});
        self.sequence = self.sequence.checked_add(1).context("sequence exhausted")?;
        if kind != "terminal" {
            let mut raw = serde_json::to_vec(&value)?;
            raw.push(b'\n');
            self.digest.update(raw);
        }
        let wire = self.reply.frame(&value)?;
        tokio::time::timeout(
            Duration::from_secs(30),
            self.sender.send(Ok(Bytes::from(wire))),
        )
        .await?
        .map_err(|_| anyhow::anyhow!("subscriber closed"))?;
        Ok(())
    }
    async fn terminal(&mut self, success: bool) -> Result<()> {
        self.frame("terminal",json!({"success":success,"transcript_sha256":hex::encode(self.digest.clone().finalize())})).await
    }
}
async fn relay(
    state: &State,
    session: &Session,
    payload: Value,
    op: Operation,
    cancel: &CancellationToken,
    output: &mut RelayOutput,
) -> Result<()> {
    // Account identity comes exclusively from this session's delegated token.
    // The platform maps a signed reservation to a configured worker route.
    let request = state
        .http
        .post(format!(
            "{}/api/v1/pool/{}",
            state.config.backend_origin,
            op.route()
        ))
        .bearer_auth(session.pool_token.as_str())
        .timeout(Duration::from_secs(610))
        .json(&payload);
    let mut response = tokio::select! {_=cancel.cancelled()=>anyhow::bail!("cancelled"),r=request.send()=>r?.error_for_status()?};
    if matches!(op, Operation::Exchange) {
        let nonce = response
            .headers()
            .get("axiom-pool-response-nonce")
            .context("worker nonce missing")?
            .to_str()?
            .to_owned();
        axiom_pool_protocol::hex_bytes(&nonce, 32)?;
        output
            .frame("worker_meta", json!({"response_nonce":nonce}))
            .await?;
        let mut stream = response.bytes_stream();
        let mut total = 0usize;
        loop {
            let chunk = tokio::select! {_=cancel.cancelled()=>anyhow::bail!("cancelled"),chunk=stream.next()=>chunk};
            let Some(chunk) = chunk else { break };
            let chunk = chunk?;
            ensure!(
                session.expires_at > now()
                    && state.collector.try_read().is_ok_and(|c| c.is_fresh()),
                "gateway/session expired"
            );
            total += chunk.len();
            ensure!(total <= 100 * 1024 * 1024, "worker ciphertext limit");
            for chunk in chunk.chunks(192 * 1024) {
                output
                    .frame(
                        "worker_bytes",
                        json!({"bytes_base64":STANDARD.encode(chunk)}),
                    )
                    .await?;
            }
        }
    } else {
        let mut raw = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(raw.len() + chunk.len() <= 8 * 1024 * 1024, "metadata limit");
            raw.extend_from_slice(&chunk);
        }
        // Large public quotes are split without exposing inference plaintext.
        for chunk in raw.chunks(192 * 1024) {
            output
                .frame(
                    "metadata_bytes",
                    json!({"bytes_base64":STANDARD.encode(chunk)}),
                )
                .await?;
        }
    }
    Ok(())
}
