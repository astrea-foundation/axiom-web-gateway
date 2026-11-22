//! Chutes' non-streaming ML-KEM-768 / HKDF / ChaCha20-Poly1305 envelope.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit as _, Nonce,
    aead::{Aead as _, AeadInPlace as _},
};
use flate2::{Compression, bufread::GzDecoder, write::GzEncoder};
use hkdf::Hkdf;
use ml_kem::{
    Ciphertext, Encoded, EncodedSizeUser as _, KemCore, MlKem768,
    kem::{Decapsulate as _, Encapsulate as _},
};
use rand_core::OsRng;
use serde::Serialize;
use sha2::Sha256;
use std::io::{Read as _, Write as _};
use zeroize::{Zeroize as _, Zeroizing};

pub const MAX_IMAGE_RESPONSE: usize = 10 * 1024 * 1024;
const KEM_BYTES: usize = 1088;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

type DecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;
type EncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;

pub struct SealedImage {
    pub body: Vec<u8>,
    response_key: Box<DecapsulationKey>,
}

#[derive(Serialize)]
struct Input<'a> {
    prompt: &'a str,
    width: u32,
    height: u32,
    seed: u32,
    e2e_response_pk: String,
}

fn cipher(shared: &[u8], encapsulated: &[u8], domain: &[u8]) -> Result<ChaCha20Poly1305> {
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(&encapsulated[..16]), shared)
        .expand(domain, key.as_mut())
        .map_err(|_| anyhow::anyhow!("invalid Chutes key derivation"))?;
    Ok(ChaCha20Poly1305::new((&*key).into()))
}

fn compress(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(raw)?;
    Ok(Zeroizing::new(encoder.finish()?))
}

pub fn seal(recipient: &str, prompt: &str, width: u32, height: u32) -> Result<SealedImage> {
    let raw = STANDARD.decode(recipient)?;
    let encoded = Encoded::<EncapsulationKey>::try_from(raw.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid Chutes recipient key length"))?;
    let remote_key = EncapsulationKey::from_bytes(&encoded);
    ensure!(
        remote_key.as_bytes() == encoded,
        "noncanonical Chutes recipient"
    );
    let (response_key, response_public) = MlKem768::generate(&mut OsRng);
    // The one-use reply public key travels only inside the verified recipient's
    // envelope. Its confidentiality binds the authenticated response to this job.
    let input = Input {
        prompt,
        width,
        height,
        seed: rand::random(),
        e2e_response_pk: STANDARD.encode(response_public.as_bytes()),
    };
    let raw = Zeroizing::new(serde_json::to_vec(&input)?);
    let compressed = compress(&raw)?;
    let (encapsulated, mut shared) = remote_key
        .encapsulate(&mut OsRng)
        .map_err(|()| anyhow::anyhow!("Chutes encapsulation failed"))?;
    let request_cipher = cipher(shared.as_slice(), &encapsulated, b"e2e-req-v1");
    shared.as_mut_slice().zeroize();
    let nonce = rand::random::<[u8; NONCE_BYTES]>();
    let encrypted = request_cipher?
        .encrypt(Nonce::from_slice(&nonce), compressed.as_slice())
        .map_err(|_| anyhow::anyhow!("Chutes request encryption failed"))?;
    Ok(SealedImage {
        body: [encapsulated.as_slice(), &nonce, &encrypted].concat(),
        response_key: Box::new(response_key),
    })
}

impl SealedImage {
    pub fn open(self, raw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            (KEM_BYTES + NONCE_BYTES + TAG_BYTES..=MAX_IMAGE_RESPONSE + 4096).contains(&raw.len()),
            "invalid encrypted Chutes response size",
        );
        let (encapsulated, body) = raw.split_at(KEM_BYTES);
        let (nonce, body) = body.split_at(NONCE_BYTES);
        let ciphertext = Ciphertext::<MlKem768>::try_from(encapsulated)
            .map_err(|_| anyhow::anyhow!("invalid Chutes response encapsulation"))?;
        let mut shared = self
            .response_key
            .decapsulate(&ciphertext)
            .map_err(|()| anyhow::anyhow!("Chutes response decapsulation failed"))?;
        let response_cipher = cipher(shared.as_slice(), encapsulated, b"e2e-resp-v1");
        shared.as_mut_slice().zeroize();
        let (encrypted, tag) = body.split_at(body.len() - TAG_BYTES);
        let mut compressed = Zeroizing::new(encrypted.to_vec());
        response_cipher?
            .decrypt_in_place_detached(Nonce::from_slice(nonce), b"", &mut compressed, tag.into())
            .map_err(|_| anyhow::anyhow!("Chutes response authentication failed"))?;
        let mut image_bytes = Zeroizing::new(Vec::new());
        let mut decoder = GzDecoder::new(compressed.as_slice());
        decoder
            .by_ref()
            .take(MAX_IMAGE_RESPONSE as u64 + 1)
            .read_to_end(&mut image_bytes)
            .context("invalid Chutes response compression")?;
        ensure!(
            image_bytes.len() <= MAX_IMAGE_RESPONSE && decoder.get_ref().is_empty(),
            "invalid Chutes response body length"
        );
        Ok(image_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn response(recipient: &EncapsulationKey, plaintext: &[u8]) -> Vec<u8> {
        let (encapsulated, shared) = recipient.encapsulate(&mut OsRng).unwrap();
        let nonce = [9_u8; NONCE_BYTES];
        let body = compress(plaintext).unwrap();
        let encrypted = cipher(&shared, &encapsulated, b"e2e-resp-v1")
            .unwrap()
            .encrypt(Nonce::from_slice(&nonce), &**body)
            .unwrap();
        [encapsulated.as_slice(), &nonce, &encrypted].concat()
    }

    #[test]
    fn encrypted_request_and_binary_reply_use_a_single_request_key() {
        let (secret, public) = MlKem768::generate(&mut OsRng);
        let key = STANDARD.encode(public.as_bytes());
        let request = seal(&key, "A red cup", 1536, 1536).unwrap();
        let (encapsulated, body) = request.body.split_at(KEM_BYTES);
        let shared = secret
            .decapsulate(&Ciphertext::<MlKem768>::try_from(encapsulated).unwrap())
            .unwrap();
        let (nonce, encrypted) = body.split_at(NONCE_BYTES);
        let compressed = cipher(&shared, encapsulated, b"e2e-req-v1")
            .unwrap()
            .decrypt(Nonce::from_slice(nonce), encrypted)
            .unwrap();
        let input: Value = serde_json::from_reader(GzDecoder::new(compressed.as_slice())).unwrap();
        assert_eq!(input["prompt"], "A red cup");
        assert_eq!(input["height"], 1536);
        let recipient = STANDARD
            .decode(input["e2e_response_pk"].as_str().unwrap())
            .unwrap();
        let recipient = EncapsulationKey::from_bytes(
            &Encoded::<EncapsulationKey>::try_from(recipient.as_slice()).unwrap(),
        );
        let reply = response(&recipient, b"\xff\xd8 fixture");
        let unrelated_request = seal(&key, "A blue cup", 1536, 1536).unwrap();
        assert!(unrelated_request.open(&reply).is_err());
        let mut truncated = reply.clone();
        truncated.pop();
        let second_unrelated = seal(&key, "A cup", 1536, 1536).unwrap();
        assert!(second_unrelated.open(&truncated).is_err());
        assert_eq!(&**request.open(&reply).unwrap(), b"\xff\xd8 fixture");
        assert!(seal("invalid-key", "A cup", 1536, 1536).is_err());
    }
}
