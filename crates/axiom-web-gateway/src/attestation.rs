use anyhow::{Context, Result, ensure};
use axiom_gateway_protocol::{
    AttestationEvidence, MAX_EVIDENCE_BYTES, PROTOCOL, SignedDocument, VerificationContext,
    VerifiedGateway,
};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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
    evidence_expires_at: AtomicU64,
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
            evidence_expires_at: AtomicU64::new(0),
            minimum_sequence,
            work_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        }))
    }
    pub fn is_fresh(&self) -> bool {
        self.is_fresh_at(crate::now())
    }
    fn epoch_is_fresh_at(&self, now: u64) -> bool {
        self.collected_at.elapsed().as_secs() < 240 && now < self.expires_at
    }
    fn is_fresh_at(&self, now: u64) -> bool {
        self.epoch_is_fresh_at(now) && now < self.evidence_expires_at.load(Ordering::Acquire)
    }
    pub fn evidence_expires_at(&self) -> u64 {
        self.expires_at
            .min(self.evidence_expires_at.load(Ordering::Acquire))
    }
    fn accept_verified(&self, verified: &VerifiedGateway) -> Result<()> {
        let now = crate::now();
        ensure!(
            self.epoch_is_fresh_at(now)
                && verified.encryption_key == self.encryption_key
                && verified.authorization_key == self.authorization_key
                && verified.origin == self.origin
                && verified.evidence_expires_at > now,
            "gateway attestation expired"
        );
        // Never extend this epoch past any evidence deadline it accepted.
        let _ = self.evidence_expires_at.compare_exchange(
            0,
            verified.evidence_expires_at,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.evidence_expires_at
            .fetch_min(verified.evidence_expires_at, Ordering::AcqRel);
        ensure!(self.is_fresh(), "gateway attestation expired");
        Ok(())
    }
    pub async fn proof(self: &Arc<Self>, challenge: String) -> Result<AttestationEvidence> {
        let _permit = self
            .work_slots
            .clone()
            .try_acquire_owned()
            .context("attestation capacity reached")?;
        ensure!(
            self.epoch_is_fresh_at(crate::now()),
            "attestation epoch expired"
        );
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
        let verified = verify_process(&self.verifier, &raw).await?;
        self.accept_verified(&verified)?;
        Ok(evidence)
    }
}

async fn verify_process(verifier: &str, raw: &[u8]) -> Result<VerifiedGateway> {
    let mut child = Command::new(verifier)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().context("verifier input unavailable")?;
    let mut stdout = child.stdout.take().context("verifier output unavailable")?;
    tokio::time::timeout(Duration::from_secs(20), async {
        let writer = async {
            stdin.write_all(raw).await?;
            stdin.shutdown().await?;
            // ChildStdin shutdown does not close the Unix pipe. The verifier
            // reads through EOF; release the descriptor before awaiting it.
            drop(stdin);
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
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    // Projection fixtures exercise deadline enforcement, not hardware acceptance.
    fn collector() -> Collector {
        Collector {
            socket: String::new(),
            verifier: String::new(),
            manifest: SignedDocument {
                payload: String::new(),
                signature: String::new(),
            },
            policy: SignedDocument {
                payload: String::new(),
                signature: String::new(),
            },
            origin: "https://fixture.example".into(),
            encryption_key: "encryption-fixture".into(),
            authorization_key: "authorization-fixture".into(),
            publisher_key: String::new(),
            collected_at: Instant::now(),
            expires_at: crate::now() + 86400,
            evidence_expires_at: AtomicU64::new(0),
            minimum_sequence: 1,
            work_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
    fn projection(collector: &Collector, evidence_expires_at: u64) -> VerifiedGateway {
        VerifiedGateway {
            encryption_key: collector.encryption_key.clone(),
            authorization_key: collector.authorization_key.clone(),
            origin: collector.origin.clone(),
            image_digest: String::new(),
            source_repository: String::new(),
            source_revision: String::new(),
            config_repository: String::new(),
            config_digest: String::new(),
            generation: 2,
            policy_sequence: 1,
            policy_expires_at: collector.expires_at,
            evidence_expires_at,
        }
    }
    #[test]
    fn witness_deadline_closes_admission_before_policy_or_local_epoch_expiry() {
        let collector = collector();
        let deadline = crate::now() + 30;
        assert!(!collector.is_fresh());
        assert_eq!(collector.evidence_expires_at(), 0);
        collector
            .accept_verified(&projection(&collector, deadline))
            .unwrap();
        assert!(collector.is_fresh_at(deadline - 1));
        assert!(!collector.is_fresh_at(deadline));
        assert_eq!(collector.evidence_expires_at(), deadline);
    }
    #[test]
    fn concurrent_proofs_cannot_extend_the_earliest_verified_deadline() {
        let collector = Arc::new(collector());
        let deadline = crate::now() + 30;
        std::thread::scope(|scope| {
            for expiry in [deadline + 60, deadline, deadline + 30] {
                let collector = Arc::clone(&collector);
                scope.spawn(move || {
                    collector
                        .accept_verified(&projection(&collector, expiry))
                        .unwrap();
                });
            }
        });
        assert_eq!(collector.evidence_expires_at(), deadline);
        assert!(!collector.is_fresh_at(deadline));
    }
    #[test]
    fn rejected_projections_never_make_a_collector_fresh() {
        let collector = collector();
        let mut verified = projection(&collector, crate::now() + 30);
        verified.authorization_key = "wrong-key".into();
        assert!(collector.accept_verified(&verified).is_err());
        assert!(!collector.is_fresh());
        assert!(
            collector
                .accept_verified(&projection(&collector, crate::now()))
                .is_err()
        );
        assert_eq!(collector.evidence_expires_at(), 0);
    }
    #[test]
    fn verified_evidence_never_extends_the_policy_or_local_epoch() {
        let mut collector = collector();
        collector.expires_at = crate::now() + 20;
        collector
            .accept_verified(&projection(&collector, crate::now() + 30))
            .unwrap();
        assert_eq!(collector.evidence_expires_at(), collector.expires_at);
        assert!(!collector.is_fresh_at(collector.expires_at));
        collector.collected_at = Instant::now()
            .checked_sub(Duration::from_secs(240))
            .unwrap();
        assert!(!collector.is_fresh());
        assert!(
            collector
                .accept_verified(&projection(&collector, crate::now() + 30))
                .is_err()
        );
    }

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
    async fn verifier_receives_eof_before_waiting_for_its_output() {
        // cat exercises process framing only; this is not hardware acceptance.
        let raw = serde_json::to_vec(&serde_json::json!({
            "encryption_key":"public-fixture", "authorization_key":"public-fixture",
            "origin":"https://fixture.example", "image_digest":"fixture",
            "source_repository":"fixture", "source_revision":"fixture",
            "config_repository":"fixture", "config_digest":"fixture",
            "generation":2, "policy_sequence":1,
            "policy_expires_at":1, "evidence_expires_at":1
        }))
        .unwrap();
        let verified =
            tokio::time::timeout(Duration::from_secs(2), verify_process("/bin/cat", &raw))
                .await
                .expect("verifier input remained open")
                .unwrap();
        assert_eq!(verified.policy_sequence, 1);
        assert!(verify_process("/bin/false", &raw).await.is_err());
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
