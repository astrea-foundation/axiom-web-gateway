//! EHBP server composition using the upstream protocol's HPKE suite/exporter
//! labels and response key derivation; no alternate cryptographic protocol.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _},
};
use anyhow::{Result, ensure};
#[cfg(test)]
use hpke::kem::Kem as _;
use hpke::{
    Deserializable as _, Serializable as _, aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256,
};
#[cfg(test)]
use rand::{SeedableRng as _, rngs::StdRng};
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;

pub struct Identity {
    private: <Kem as hpke::kem::Kem>::PrivateKey,
    pub public_hex: String,
}
pub struct Reply {
    material: ehbp::ResponseKeyMaterial,
    pub nonce_hex: String,
    sequence: u64,
    sent_bytes: usize,
}

impl Identity {
    #[cfg(test)]
    pub fn generate() -> Self {
        let (private, public) = Kem::gen_keypair(&mut StdRng::from_os_rng());
        Self {
            private,
            public_hex: hex::encode(public.to_bytes()),
        }
    }
    /// Read only the boot-generated, attested X25519 key; never generate a
    /// substitute if its mount is unavailable.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let pem = Zeroizing::new(std::fs::read_to_string(path)?);
        ensure!(pem.len() <= 4096, "private key exceeds limit");
        let (label, document) = pkcs8::SecretDocument::from_pem(&pem)?;
        let info = pkcs8::PrivateKeyInfo::try_from(document.as_bytes())?;
        ensure!(
            label == "PRIVATE KEY"
                && info.algorithm.oid == pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110")
                && info.algorithm.parameters.is_none()
                && info.private_key.len() == 34
                && info.private_key[..2] == [4, 32],
            "invalid boot encryption key"
        );
        let key = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(&info.private_key[2..])?);
        let public = x25519_dalek::PublicKey::from(&key);
        let raw = Zeroizing::new(key.to_bytes());
        let private = <Kem as hpke::kem::Kem>::PrivateKey::from_bytes(raw.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid boot encryption key"))?;
        Ok(Self {
            private,
            public_hex: hex::encode(public.as_bytes()),
        })
    }
    /// Each RPC request is exactly one authenticated HPKE frame. Multiple or
    /// incomplete frames are rejected, preventing request truncation ambiguity.
    pub fn open(&self, encapsulated_key: &str, body: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Reply)> {
        ensure!(
            body.len() >= 20 && body.len() <= 4 * 1024 * 1024,
            "invalid encrypted body size"
        );
        let length = usize::try_from(u32::from_be_bytes(body[..4].try_into()?))?;
        ensure!(
            length == body.len() - 4,
            "incomplete or multiple request frames"
        );
        let enc = <Kem as hpke::kem::Kem>::EncappedKey::from_bytes(&hex::decode(encapsulated_key)?)
            .map_err(|_| anyhow::anyhow!("invalid encapsulated key"))?;
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(
            &hpke::OpModeR::Base,
            &self.private,
            &enc,
            ehbp::HPKE_REQUEST_INFO,
        )
        .map_err(|_| anyhow::anyhow!("invalid HPKE request"))?;
        let plaintext = Zeroizing::new(
            receiver
                .open(&body[4..], &[])
                .map_err(|_| anyhow::anyhow!("request authentication failed"))?,
        );
        let mut secret = Zeroizing::new([0_u8; 32]);
        receiver
            .export(ehbp::EXPORT_LABEL, secret.as_mut())
            .map_err(|_| anyhow::anyhow!("response exporter failed"))?;
        let nonce: [u8; 32] = rand::random();
        let material = ehbp::derive_response_keys(secret.as_ref(), &enc.to_bytes(), &nonce)?;
        Ok((
            plaintext,
            Reply {
                material,
                nonce_hex: hex::encode(nonce),
                sequence: 0,
                sent_bytes: 0,
            },
        ))
    }
}

impl Reply {
    pub fn frame(&mut self, payload: &serde_json::Value) -> Result<Vec<u8>> {
        let mut plaintext = Zeroizing::new(serde_json::to_vec(payload)?);
        plaintext.push(b'\n');
        self.sent_bytes = self
            .sent_bytes
            .checked_add(plaintext.len())
            .ok_or_else(|| anyhow::anyhow!("response limit"))?;
        ensure!(
            self.sent_bytes <= 16 * 1024 * 1024
                && plaintext.len() <= 1024 * 1024
                && self.sequence < u64::MAX,
            "response limit"
        );
        let nonce = ehbp::compute_nonce(&self.material.nonce_base, self.sequence);
        let cipher = Aes256Gcm::new_from_slice(&self.material.key)
            .map_err(|_| anyhow::anyhow!("invalid response key"))?;
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| anyhow::anyhow!("response encryption failed"))?;
        self.sequence += 1;
        let mut out = u32::try_from(sealed.len())?.to_be_bytes().to_vec();
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead as _, Write as _},
        process::{Command, Stdio},
    };

    #[test]
    #[ignore = "requires pnpm install; run cargo test -p axiom-web-gateway -- --ignored"]
    fn published_browser_ehbp_interoperability() {
        let identity = Identity::generate();
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/test/ehbp-peer.mjs");
        let mut child = Command::new("node")
            .arg(script)
            .arg(&identity.public_hex)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        let (plaintext, mut reply) = identity
            .open(
                request["encapsulated"].as_str().unwrap(),
                &hex::decode(request["body"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        assert_eq!(plaintext.as_slice(), b"public interoperability fixture");
        let frame = reply
            .frame(&serde_json::json!({"interoperable":true}))
            .unwrap();
        writeln!(
            child.stdin.as_mut().unwrap(),
            "{}",
            serde_json::json!({"nonce":reply.nonce_hex,"body":hex::encode(frame)})
        )
        .unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn boot_pkcs8_key_matches_external_spki_and_rejects_wrong_algorithm() {
        let path = std::env::temp_dir().join(format!(
            "axiom-boot-key-{}.pem",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        for algorithm in ["X25519", "ED25519"] {
            let output = Command::new("openssl")
                .args(["genpkey", "-algorithm", algorithm])
                .output()
                .unwrap();
            assert!(output.status.success());
            std::fs::write(&path, &output.stdout).unwrap();
            if algorithm == "X25519" {
                let identity = Identity::load(&path).unwrap();
                let public = Command::new("openssl")
                    .args(["pkey", "-pubout", "-outform", "DER", "-in"])
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(public.status.success());
                assert_eq!(public.stdout.len(), 44);
                assert_eq!(identity.public_hex, hex::encode(&public.stdout[12..]));
            } else {
                assert!(Identity::load(&path).is_err());
            }
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn ehbp_round_trip_tamper_and_ordering() {
        let identity = Identity::generate();
        let public = <Kem as hpke::kem::Kem>::PublicKey::from_bytes(
            &hex::decode(&identity.public_hex).unwrap(),
        )
        .unwrap();
        let (enc, mut sender) = hpke::setup_sender::<AesGcm256, HkdfSha256, Kem, _>(
            &hpke::OpModeS::Base,
            &public,
            ehbp::HPKE_REQUEST_INFO,
            &mut StdRng::from_os_rng(),
        )
        .unwrap();
        let sealed = sender.seal(b"private prompt", &[]).unwrap();
        let mut request = u32::try_from(sealed.len()).unwrap().to_be_bytes().to_vec();
        request.extend_from_slice(&sealed);
        let (plaintext, mut reply) = identity
            .open(&hex::encode(enc.to_bytes()), &request)
            .unwrap();
        assert_eq!(plaintext.as_slice(), b"private prompt");
        let mut secret = [0_u8; 32];
        sender.export(ehbp::EXPORT_LABEL, &mut secret).unwrap();
        let material = ehbp::derive_response_keys(
            &secret,
            &enc.to_bytes(),
            &hex::decode(&reply.nonce_hex).unwrap(),
        )
        .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&material.key).unwrap();
        let first = reply.frame(&serde_json::json!({"text":"secret"})).unwrap();
        let second = reply.frame(&serde_json::json!({"terminal":true})).unwrap();
        let nonce = ehbp::compute_nonce(&material.nonce_base, 0);
        assert_eq!(
            cipher
                .decrypt(Nonce::from_slice(&nonce), &first[4..])
                .unwrap(),
            b"{\"text\":\"secret\"}\n"
        );
        assert!(
            cipher
                .decrypt(Nonce::from_slice(&nonce), &second[4..])
                .is_err()
        );
        let mut corrupt = request.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            identity
                .open(&hex::encode(enc.to_bytes()), &corrupt)
                .is_err()
        );
        request.pop();
        assert!(
            identity
                .open(&hex::encode(enc.to_bytes()), &request)
                .is_err()
        );
    }
}
