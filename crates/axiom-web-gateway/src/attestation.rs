use anyhow::{Context, Result, ensure};
use axiom_gateway_protocol::{
    AttestationEvidence, PCR_SELECTION, PROTOCOL, SignedDocument, VerificationContext, binding,
};
use azure_guest_attestation_sdk::{AttestationClient, CvmEvidenceOptions};
use azure_tpm::{
    TpmCommandExt as _,
    helpers::build_command_pw_sessions,
    types::{
        ALG_SHA256, PcrSelectionList, QuoteCommandParameters, QuoteResponse, Tpm2bBytes,
        TpmCommandCode, TpmMarshal as _, TpmtSigScheme, TpmtSignature,
    },
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// Hardware/collateral is cached for a short epoch; each proof obtains a fresh
/// challenge-bound quote. No caller identity or message input reaches Azure IMDS.
pub struct Collector {
    client: Mutex<AttestationClient>,
    tdx_quote: String,
    runtime_data: String,
    event_log: String,
    collateral: dcap_qvl::QuoteCollateralV3,
    manifest: SignedDocument,
    policy: SignedDocument,
    origin: String,
    encryption_key: String,
    authorization_key: String,
    publisher_key: String,
    collected_at: std::time::Instant,
    expires_at: u64,
    work_slots: Arc<tokio::sync::Semaphore>,
}

impl Collector {
    pub async fn new(
        origin: String,
        encryption_key: String,
        authorization_key: String,
        publisher_key: String,
        manifest: SignedDocument,
        policy: SignedDocument,
    ) -> Result<Arc<Self>> {
        let (client, cvm, event_log) = tokio::task::spawn_blocking(|| -> Result<_> {
            let client = AttestationClient::new()?;
            let cvm = client.get_cvm_evidence(Some(&CvmEvidenceOptions {
                user_data: None,
                fetch_platform_quote: true,
            }))?;
            ensure!(
                !cvm.platform_quote.is_empty(),
                "Azure TDX quote unavailable"
            );
            let event_log = std::fs::read("/sys/kernel/security/tpm0/binary_bios_measurements")?;
            ensure!(event_log.len() <= 2 * 1024 * 1024, "boot log exceeds limit");
            Ok((client, cvm, event_log))
        })
        .await??;
        // Intel PCS roots are fixed by QVL. This HTTPS source is only a collateral
        // transport and cannot replace cryptographic roots or status checks.
        let collateral = dcap_qvl::collateral::CollateralClient::with_default_http(
            "https://api.trustedservices.intel.com",
        )?
        .fetch(&cvm.platform_quote)
        .await?;
        let trusted: axiom_gateway_protocol::TrustPolicy = axiom_gateway_protocol::verify_document(
            &policy,
            &publisher_key,
            "axiom-gateway-policy-v1",
        )?;
        Ok(Arc::new(Self {
            client: Mutex::new(client),
            tdx_quote: hex::encode(cvm.platform_quote),
            runtime_data: hex::encode(cvm.runtime_data),
            event_log: hex::encode(event_log),
            collateral,
            manifest,
            policy,
            origin,
            encryption_key,
            authorization_key,
            publisher_key,
            collected_at: std::time::Instant::now(),
            expires_at: trusted.expires_at,
            work_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        }))
    }

    pub fn is_fresh(&self) -> bool {
        self.collected_at.elapsed().as_secs() < 240 && crate::now() < self.expires_at
    }

    pub async fn proof(self: &Arc<Self>, challenge: String) -> Result<AttestationEvidence> {
        ensure!(self.is_fresh(), "attestation epoch expired");
        let permit = Arc::clone(&self.work_slots)
            .try_acquire_owned()
            .context("TPM proof capacity reached")?;
        let this = Arc::clone(self);
        let evidence = tokio::task::spawn_blocking(move || -> Result<_> {
            // A timed-out caller cannot release the worker slot while a TPM
            // operation is still blocked and grow an unbounded blocking queue.
            let _permit = permit;
            let nonce = binding(
                &challenge,
                &this.origin,
                &this.encryption_key,
                &this.authorization_key,
            )?;
            let client = this
                .client
                .lock()
                .map_err(|_| anyhow::anyhow!("TPM lock unavailable"))?;
            let indices: Vec<_> = PCR_SELECTION.iter().map(|v| u32::from(*v)).collect();
            // SDK's quote_with_key uses empty qualifying_data. Explicitly provide
            // our challenge/key binding through its typed TPM command interface.
            let params = QuoteCommandParameters {
                qualifying_data: Tpm2bBytes(nonce.to_vec()),
                scheme: TpmtSigScheme::Rsassa(ALG_SHA256),
                pcr_selection: PcrSelectionList::from_pcrs(&indices),
            };
            let command =
                build_command_pw_sessions(TpmCommandCode::Quote, &[0x8100_0003], &[&[]], |out| {
                    params.marshal(out);
                });
            let raw = client.tpm().transmit(&command)?;
            let quote = QuoteResponse::from_bytes(&raw)?.parameters;
            let TpmtSignature::Rsassa { hash_alg, sig } = quote.signature else {
                anyhow::bail!("unsupported TPM signature");
            };
            ensure!(hash_alg == ALG_SHA256, "unsupported TPM hash");
            let pcrs: BTreeMap<_, _> = client
                .tpm()
                .read_pcrs_sha256(&indices)?
                .into_iter()
                .map(|(pcr, digest)| Ok((u8::try_from(pcr)?, hex::encode(digest))))
                .collect::<Result<_>>()?;
            Ok(AttestationEvidence {
                protocol: PROTOCOL.into(),
                challenge,
                origin: this.origin.clone(),
                encryption_key: this.encryption_key.clone(),
                authorization_key: this.authorization_key.clone(),
                tdx_quote: this.tdx_quote.clone(),
                hcl_runtime_data: this.runtime_data.clone(),
                tpm_quote: hex::encode(quote.attest),
                tpm_signature: hex::encode(sig),
                pcrs,
                event_log: this.event_log.clone(),
                collateral: this.collateral.clone(),
                manifest: this.manifest.clone(),
                policy: this.policy.clone(),
            })
        })
        .await??;
        ensure!(self.is_fresh(), "attestation epoch expired");
        // Self-verification is necessary for admission, but clients still verify independently.
        axiom_gateway_protocol::verify(
            &evidence,
            &VerificationContext {
                challenge: evidence.challenge.clone(),
                origin: self.origin.clone(),
                publisher_key: self.publisher_key.clone(),
                now: crate::now(),
                minimum_policy_sequence: 0,
            },
        )
        .context("gateway evidence rejected")?;
        Ok(evidence)
    }
}
