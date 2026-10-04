//! RFC 9449 `DPoP` validation for the logical HTTP request inside EHBP.
//! Additional claims bind the accepted gateway key and exact encrypted payload.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl BrowserKey {
    pub fn thumbprint(&self) -> Result<String> {
        ensure!(
            self.kty == "EC" && self.crv == "P-256",
            "unsupported browser authorization key"
        );
        let x = URL_SAFE_NO_PAD.decode(&self.x)?;
        let y = URL_SAFE_NO_PAD.decode(&self.y)?;
        ensure!(x.len() == 32 && y.len() == 32, "invalid browser key");
        VerifyingKey::from_sec1_bytes(&[&[4], x.as_slice(), y.as_slice()].concat())?;
        // RFC 7638 canonical member order.
        let canonical = serde_json::json!({"crv":self.crv,"kty":self.kty,"x":self.x,"y":self.y});
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&canonical)?)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    typ: String,
    alg: String,
    jwk: BrowserKey,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub htm: String,
    pub htu: String,
    pub iat: u64,
    pub jti: String,
    pub ath: String,
    pub gateway_key: String,
    pub request_digest: String,
}

#[must_use]
pub fn token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

pub fn verify(
    proof: &str,
    key: &BrowserKey,
    token: &str,
    uri: &str,
    gateway_key: &str,
    payload: &str,
    now: u64,
) -> Result<Claims> {
    ensure!(proof.len() <= 8192, "oversized authorization proof");
    let parts: Vec<_> = proof.split('.').collect();
    ensure!(parts.len() == 3, "invalid authorization proof");
    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    ensure!(
        header.typ == "dpop+jwt" && header.alg == "ES256" && header.jwk == *key,
        "authorization key mismatch"
    );
    key.thumbprint()?;
    let x = URL_SAFE_NO_PAD.decode(&key.x)?;
    let y = URL_SAFE_NO_PAD.decode(&key.y)?;
    let public = VerifyingKey::from_sec1_bytes(&[&[4], x.as_slice(), y.as_slice()].concat())?;
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?;
    let signed = proof.rsplit_once('.').context("invalid proof")?.0;
    public.verify(signed.as_bytes(), &signature)?;
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    ensure!(
        claims.htm == "POST"
            && claims.htu == uri
            && claims.iat <= now.saturating_add(30)
            && claims.iat.saturating_add(60) >= now
            && claims.jti.len() == 32
            && hex::decode(&claims.jti)?.len() == 16
            && claims.ath == token_hash(token)
            && claims.gateway_key == gateway_key
            && claims.request_digest == hex::encode(Sha256::digest(payload.as_bytes())),
        "authorization request binding mismatch"
    );
    Ok(claims)
}
