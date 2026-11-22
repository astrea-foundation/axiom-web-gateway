use super::{GpuEvidence, bounded};
use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

const NRAS: &str = "https://nras.attestation.nvidia.com";
const MAX_VENDOR_BODY: usize = 2 * 1024 * 1024;

type Bundle = ((String, String), BTreeMap<String, String>);

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    #[serde(rename = "typ")]
    _typ: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    eat_nonce: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    #[serde(flatten)]
    verdict: Map<String, Value>,
}

pub(super) async fn verify(
    http: &reqwest::Client,
    gpus: &[GpuEvidence],
    nonce: &str,
) -> Result<u64> {
    let first = gpus.first().context("Chutes returned no GPU evidence")?;
    ensure!(
        gpus.len() <= 8
            && !first.arch.is_empty()
            && gpus.iter().all(|gpu| {
                gpu.arch == first.arch && !gpu.evidence.is_empty() && !gpu.certificate.is_empty()
            }),
        "invalid Chutes GPU evidence"
    );
    let bundle = async {
        let response = http
            .post(format!("{NRAS}/v3/attest/gpu"))
            .json(&json!({
                "nonce": nonce, "arch": first.arch, "claims_version": "2.0",
                "evidence_list": gpus.iter().map(|gpu| json!({
                    "evidence": gpu.evidence, "certificate": gpu.certificate,
                })).collect::<Vec<_>>(),
            }))
            .send()
            .await?;
        Ok::<Bundle, anyhow::Error>(serde_json::from_slice(
            &bounded(response, MAX_VENDOR_BODY).await?,
        )?)
    };
    let jwks = async {
        let response = http
            .get(format!("{NRAS}/.well-known/jwks.json"))
            .send()
            .await?;
        Ok::<Jwks, anyhow::Error>(serde_json::from_slice(
            &bounded(response, MAX_VENDOR_BODY).await?,
        )?)
    };
    let (bundle, jwks) = tokio::try_join!(bundle, jwks)?;
    verify_bundle(&bundle, &jwks, nonce, gpus.len(), crate::now())
}

fn verify_bundle(
    bundle: &Bundle,
    jwks: &Jwks,
    nonce: &str,
    gpu_count: usize,
    now: u64,
) -> Result<u64> {
    let ((label, token), devices) = bundle;
    ensure!(
        label == "JWT" && devices.len() == gpu_count && gpu_count > 0,
        "NVIDIA device count or token type differs"
    );
    let (overall, mut expires) = verify_token(token, jwks, nonce, now)?;
    let submods = overall["submods"]
        .as_object()
        .context("NVIDIA device bindings omitted")?;
    ensure!(
        overall["x-nvidia-overall-att-result"] == true
            && overall["x-nvidia-ver"] == "2.0"
            && submods.len() == gpu_count,
        "NVIDIA overall attestation rejected"
    );
    for (name, token) in devices {
        let digest = hex::encode(Sha256::digest(token.as_bytes()));
        ensure!(
            submods.get(name) == Some(&json!(["DIGEST", ["SHA-256", digest]])),
            "NVIDIA device token digest differs"
        );
        let (gpu, device_expires) = verify_token(token, jwks, nonce, now)?;
        ensure!(
            gpu["dbgstat"] == "disabled"
                && gpu["secboot"] == true
                && gpu["measres"] == "success"
                && gpu["x-nvidia-attestation-warning"].is_null()
                && gpu["x-nvidia-error-details"].is_null()
                && [
                    "x-nvidia-gpu-attestation-report-parsed",
                    "x-nvidia-gpu-attestation-report-signature-verified",
                    "x-nvidia-gpu-attestation-report-cert-chain-validated",
                    "x-nvidia-gpu-attestation-report-nonce-match",
                    "x-nvidia-gpu-driver-rim-signature-verified",
                    "x-nvidia-gpu-vbios-rim-signature-verified",
                ]
                .iter()
                .all(|name| gpu[*name] == true),
            "NVIDIA GPU attestation rejected"
        );
        expires = expires.min(device_expires);
    }
    Ok(expires)
}

fn verify_token(token: &str, jwks: &Jwks, nonce: &str, now: u64) -> Result<(Value, u64)> {
    let (signed, signature) = token.rsplit_once('.').context("invalid NVIDIA JWT")?;
    let (header, claims) = signed.split_once('.').context("invalid NVIDIA JWT")?;
    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header)?)?;
    ensure!(
        header.alg == "ES384" && !header.kid.is_empty(),
        "unsupported NVIDIA JWT algorithm or key"
    );
    let mut matching = jwks.keys.iter().filter(|key| key.kid == header.kid);
    let key = matching.next().context("unrecognized NVIDIA signing key")?;
    ensure!(
        matching.next().is_none() && key.kty == "EC" && key.crv == "P-384",
        "invalid or ambiguous NVIDIA signing key"
    );
    let x = URL_SAFE_NO_PAD.decode(&key.x)?;
    let y = URL_SAFE_NO_PAD.decode(&key.y)?;
    ensure!(x.len() == 48 && y.len() == 48, "invalid NVIDIA key size");
    let mut public_key = [0_u8; 97];
    public_key[0] = 4;
    public_key[1..49].copy_from_slice(&x);
    public_key[49..].copy_from_slice(&y);
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, public_key)
        .verify(signed.as_bytes(), &URL_SAFE_NO_PAD.decode(signature)?)
        .map_err(|_| anyhow!("invalid NVIDIA JWT signature"))?;
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims)?)?;
    ensure!(
        claims.iss == NRAS
            && claims.eat_nonce == nonce
            && claims.iat >= now.saturating_sub(120)
            && claims.iat <= now
            && claims.nbf <= now
            && claims.exp > now,
        "NVIDIA issuer, nonce or freshness differs"
    );
    Ok((Value::Object(claims.verdict), claims.exp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
    };

    #[test]
    fn authenticates_the_nvidia_nonce_and_detached_device_token() {
        let now = 1000;
        let nonce = "aa".repeat(32);
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let jwks = Jwks {
            keys: vec![Jwk {
                kid: "fixture".into(),
                kty: "EC".into(),
                crv: "P-384".into(),
                x: URL_SAFE_NO_PAD.encode(&key.public_key().as_ref()[1..49]),
                y: URL_SAFE_NO_PAD.encode(&key.public_key().as_ref()[49..]),
            }],
        };
        let sign = |claims: Value| {
            let mut claims = claims.as_object().unwrap().clone();
            claims.extend([
                ("iss".into(), json!(NRAS)),
                ("eat_nonce".into(), json!(nonce)),
                ("iat".into(), json!(now)),
                ("nbf".into(), json!(now)),
                ("exp".into(), json!(now + 180)),
            ]);
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(br#"{"kid":"fixture","alg":"ES384"}"#),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            );
            let signature = key.sign(&rng, signed.as_bytes()).unwrap();
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
        };
        let device = sign(json!({
            "dbgstat": "disabled", "secboot": true, "measres": "success",
            "x-nvidia-gpu-attestation-report-parsed": true,
            "x-nvidia-gpu-attestation-report-signature-verified": true,
            "x-nvidia-gpu-attestation-report-cert-chain-validated": true,
            "x-nvidia-gpu-attestation-report-nonce-match": true,
            "x-nvidia-gpu-driver-rim-signature-verified": true,
            "x-nvidia-gpu-vbios-rim-signature-verified": true,
        }));
        let overall = sign(json!({
            "x-nvidia-ver": "2.0", "x-nvidia-overall-att-result": true,
            "submods": {"GPU-0": ["DIGEST", ["SHA-256", hex::encode(Sha256::digest(&device))]]},
        }));
        let mut bundle = (
            ("JWT".into(), overall),
            BTreeMap::from([("GPU-0".into(), device)]),
        );
        assert_eq!(
            verify_bundle(&bundle, &jwks, &nonce, 1, now).unwrap(),
            now + 180
        );
        assert!(verify_bundle(&bundle, &jwks, &"bb".repeat(32), 1, now).is_err());
        assert!(verify_bundle(&bundle, &jwks, &nonce, 1, now + 180).is_err());
        bundle.1.insert("GPU-0".into(), sign(json!({})));
        assert!(verify_bundle(&bundle, &jwks, &nonce, 1, now).is_err());
    }
}
