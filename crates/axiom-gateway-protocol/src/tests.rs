use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use p256::ecdsa::SigningKey as BrowserSigningKey;
use sha2::{Digest as _, Sha256};

#[test]
fn signed_provenance_is_domain_separated_and_exact() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let raw = br#"{"build":"first"}"#;
    let document = SignedDocument {
        payload: URL_SAFE_NO_PAD.encode(raw),
        signature: hex::encode(
            key.sign(&[b"axiom-gateway-workload-v2\0".as_slice(), raw].concat())
                .to_bytes(),
        ),
    };
    let public = hex::encode(key.verifying_key().as_bytes());
    assert!(
        verify_document::<serde_json::Value>(&document, &public, "axiom-gateway-workload-v2")
            .is_ok()
    );
    assert!(
        verify_document::<serde_json::Value>(&document, &public, "axiom-gateway-policy-v2")
            .is_err()
    );
    let modified = SignedDocument {
        payload: URL_SAFE_NO_PAD.encode(br#"{"build":"other"}"#),
        ..document
    };
    assert!(
        verify_document::<serde_json::Value>(&modified, &public, "axiom-gateway-workload-v2")
            .is_err()
    );
}

#[test]
fn browser_authority_cannot_move_to_another_request_or_gateway() {
    let signer = BrowserSigningKey::from_slice(&[9; 32]).unwrap();
    let point = signer.verifying_key().to_encoded_point(false);
    let key = authorization::BrowserKey {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    };
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":key})).unwrap(),
    );
    let payload = "encrypted logical payload";
    let claims = serde_json::json!({"htm":"POST","htu":"https://gateway.example/v1/rpc","iat":1000,"jti":"aa".repeat(16),"ath":authorization::token_hash("session"),"gateway_key":"bb".repeat(32),"request_digest":hex::encode(Sha256::digest(payload))});
    let encoded = format!(
        "{header}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = signer.sign(encoded.as_bytes());
    let proof = format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    let verify = |token: &str, uri: &str, gateway: &str, body: &str, now: u64| {
        authorization::verify(&proof, &key, token, uri, gateway, body, now)
    };
    assert!(
        verify(
            "session",
            "https://gateway.example/v1/rpc",
            &"bb".repeat(32),
            payload,
            1000
        )
        .is_ok()
    );
    assert!(
        verify(
            "other",
            "https://gateway.example/v1/rpc",
            &"bb".repeat(32),
            payload,
            1000
        )
        .is_err()
    );
    assert!(
        verify(
            "session",
            "https://gateway.example/v1/session",
            &"bb".repeat(32),
            payload,
            1000
        )
        .is_err()
    );
    assert!(
        verify(
            "session",
            "https://gateway.example/v1/rpc",
            &"cc".repeat(32),
            payload,
            1000
        )
        .is_err()
    );
    assert!(
        verify(
            "session",
            "https://gateway.example/v1/rpc",
            &"bb".repeat(32),
            "substitution",
            1000
        )
        .is_err()
    );
    assert!(
        verify(
            "session",
            "https://gateway.example/v1/rpc",
            &"bb".repeat(32),
            payload,
            1061
        )
        .is_err()
    );
}
