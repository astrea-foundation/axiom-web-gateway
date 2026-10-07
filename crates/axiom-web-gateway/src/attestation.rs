use anyhow::{Context, Result, ensure};
use axiom_gateway_protocol::{
    AttestationEvidence, MAX_EVIDENCE_BYTES, PROTOCOL, SignedDocument, VerificationContext,
    VerifiedGateway,
};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    process::Command,
};

/// No TPM, IMDS, account or message input. Only a random caller nonce is sent
/// over Tinfoil's explicitly granted local HTTP attestation socket.
pub struct Collector {
    socket: String,
    verifier: String,
    manifest: SignedDocument,
    policy: SignedDocument,
    origin: String,
    encryption_key: String,
    authorization_key: String,
    publisher_key: String,
    collected_at: Instant,
    expires_at: u64,
    minimum_sequence: u64,
    work_slots: Arc<tokio::sync::Semaphore>,
}

pub async fn local_document(socket: &str, challenge: &str) -> Result<serde_json::Value> {
    ensure!(
        challenge.len() == 64
            && challenge
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid attestation nonce"
    );
    let mut stream = UnixStream::connect(Path::new(socket)).await?;
    let request = format!(
        "GET /.well-known/tinfoil-attestation/v3?nonce={challenge} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut bytes = Vec::new();
    stream
        .take(u64::try_from(MAX_EVIDENCE_BYTES + 16385)?)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() <= MAX_EVIDENCE_BYTES + 16384,
        "attestation exceeds limit"
    );
    let split = bytes
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .context("invalid attestation response")?;
    ensure!(split <= 16384, "attestation headers exceed limit");
    let headers = std::str::from_utf8(&bytes[..split])?;
    ensure!(
        headers.starts_with("HTTP/1.0 200 ") || headers.starts_with("HTTP/1.1 200 "),
        "local attestation unavailable"
    );
    // HTTP/1.0 deliberately avoids chunked transfer decoding and redirects.
    ensure!(
        !headers.to_ascii_lowercase().contains("transfer-encoding:"),
        "unsupported attestation encoding"
    );
    serde_json::from_slice(&bytes[split + 4..]).context("invalid local attestation")
}

impl Collector {
    pub fn new(
        config: &crate::Config,
        encryption_key: String,
        authorization_key: String,
        manifest: SignedDocument,
        policy: SignedDocument,
        minimum_sequence: u64,
    ) -> Result<Arc<Self>> {
        let trusted: axiom_gateway_protocol::TrustPolicy = axiom_gateway_protocol::verify_document(
            &policy,
            &config.publisher_key,
            "axiom-gateway-policy-v2",
        )?;
        ensure!(
            trusted.schema_version == 2
                && trusted.sequence >= minimum_sequence
                && trusted.expires_at > crate::now(),
            "invalid gateway policy"
        );
        Ok(Arc::new(Self {
            socket: config.attestation_socket.clone(),
            verifier: config.verifier.clone(),
            manifest,
            policy,
            origin: config.public_origin.clone(),
            encryption_key,
            authorization_key,
            publisher_key: config.publisher_key.clone(),
            collected_at: Instant::now(),
            expires_at: trusted.expires_at,
            minimum_sequence,
            work_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        }))
    }
    pub fn is_fresh(&self) -> bool {
        self.collected_at.elapsed().as_secs() < 240 && crate::now() < self.expires_at
    }
    pub async fn proof(self: &Arc<Self>, challenge: String) -> Result<AttestationEvidence> {
        let _permit = self
            .work_slots
            .clone()
            .try_acquire_owned()
            .context("attestation capacity reached")?;
        ensure!(self.is_fresh(), "attestation epoch expired");
        let document = tokio::time::timeout(
            Duration::from_secs(20),
            local_document(&self.socket, &challenge),
        )
        .await??;
        let evidence = AttestationEvidence {
            protocol: PROTOCOL.into(),
            challenge,
            origin: self.origin.clone(),
            encryption_key: self.encryption_key.clone(),
            authorization_key: self.authorization_key.clone(),
            document,
            manifest: self.manifest.clone(),
            policy: self.policy.clone(),
        };
        let context = VerificationContext {
            challenge: evidence.challenge.clone(),
            origin: self.origin.clone(),
            publisher_key: self.publisher_key.clone(),
            now: crate::now(),
            minimum_policy_sequence: self.minimum_sequence,
        };
        let raw = serde_json::to_vec(&serde_json::json!({"evidence":evidence,"context":context}))?;
        ensure!(raw.len() <= MAX_EVIDENCE_BYTES, "attestation exceeds limit");
        let mut child = Command::new(&self.verifier)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let mut stdin = child.stdin.take().context("verifier input unavailable")?;
        let mut stdout = child.stdout.take().context("verifier output unavailable")?;
        let verified = tokio::time::timeout(Duration::from_secs(20), async {
            let writer = async {
                stdin.write_all(&raw).await?;
                stdin.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            };
            let reader = async {
                let mut out = Vec::new();
                (&mut stdout).take(16385).read_to_end(&mut out).await?;
                ensure!(out.len() <= 16384, "verifier output exceeds limit");
                Ok::<_, anyhow::Error>(out)
            };
            let ((), out) = tokio::try_join!(writer, reader)?;
            ensure!(child.wait().await?.success(), "gateway evidence rejected");
            serde_json::from_slice::<VerifiedGateway>(&out).context("invalid verifier output")
        })
        .await??;
        ensure!(
            self.is_fresh()
                && verified.encryption_key == self.encryption_key
                && verified.authorization_key == self.authorization_key
                && verified.origin == self.origin
                && verified.evidence_expires_at > crate::now(),
            "gateway attestation expired"
        );
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    async fn response(raw: &'static [u8]) -> Result<serde_json::Value> {
        let path = std::env::temp_dir().join(format!(
            "axiom-attestation-{}.sock",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        let listener = UnixListener::bind(&path)?;
        let nonce = "ab".repeat(32);
        let expected = nonce.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let byte = stream.read_u8().await.unwrap();
                request.push(byte);
                assert!(request.len() <= 1024);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert_eq!(
                String::from_utf8(request).unwrap(),
                format!(
                    "GET /.well-known/tinfoil-attestation/v3?nonce={expected} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
            );
            stream.write_all(raw).await.unwrap();
        });
        let result = local_document(path.to_str().unwrap(), &nonce).await;
        server.await.unwrap();
        std::fs::remove_file(path)?;
        result
    }
    #[tokio::test]
    async fn local_socket_receives_only_nonce_and_rejects_http_failures() {
        assert_eq!(
            response(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"public\":true}")
                .await
                .unwrap()["public"],
            true
        );
        for raw in [
            b"HTTP/1.0 302 Found\r\nLocation: https://attacker.example\r\n\r\n{}".as_slice(),
            b"HTTP/1.0 500 Error\r\n\r\n{}",
            b"HTTP/1.0 200 OK\r\n\r\n{",
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ] {
            assert!(response(raw).await.is_err());
        }
        assert!(local_document("/missing.sock", "bad").await.is_err());
    }
}
