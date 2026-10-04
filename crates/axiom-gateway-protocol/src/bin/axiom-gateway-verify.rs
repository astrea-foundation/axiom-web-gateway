//! Public-evidence verifier for platform registration. No inference input.
use serde::Deserialize;
use std::io::{Read as _, Write as _};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    evidence: axiom_gateway_protocol::AttestationEvidence,
    context: axiom_gateway_protocol::VerificationContext,
}
fn main() {
    let result = (|| -> anyhow::Result<_> {
        let mut input = Vec::new();
        std::io::stdin()
            .take(u64::try_from(axiom_gateway_protocol::MAX_EVIDENCE_BYTES)? + 1)
            .read_to_end(&mut input)?;
        anyhow::ensure!(
            input.len() <= axiom_gateway_protocol::MAX_EVIDENCE_BYTES,
            "oversized evidence"
        );
        let request: Input = serde_json::from_slice(&input)?;
        let verified = axiom_gateway_protocol::verify(&request.evidence, &request.context)?;
        let output = serde_json::to_vec(&verified)?;
        std::io::stdout().write_all(&output)?;
        Ok(())
    })();
    if result.is_err() {
        eprintln!("gateway attestation rejected");
        std::process::exit(1);
    }
}
