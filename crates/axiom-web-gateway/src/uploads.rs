//! Original file bytes live only in bounded, expiring enclave memory.
use anyhow::{Context, Result, ensure};
use axiom_web_gateway_core::inference::{ChatRole, FileContent, ImageContent, InferenceRequest};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

const CHUNK: usize = 256 * 1024;
const ACCOUNT_BYTES: usize = 64 * 1024 * 1024;
const TOTAL_BYTES: usize = 256 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Begin {
    pub target_request_id: String,
    pub model: String,
    pub kind: String,
    pub name: String,
    pub mime_type: String,
    pub length: usize,
    pub sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub upload_id: String,
    pub message_index: usize,
}
struct Upload {
    account: String,
    session: String,
    request: Begin,
    expires: u64,
    bytes: Zeroizing<Vec<u8>>,
    sealed: bool,
    capacity: OwnedSemaphorePermit,
}
pub struct Uploads(BTreeMap<String, Upload>, Arc<Semaphore>);
impl Default for Uploads {
    fn default() -> Self {
        Self(BTreeMap::new(), Arc::new(Semaphore::new(TOTAL_BYTES)))
    }
}
impl Uploads {
    pub fn prune(&mut self, now: u64) {
        self.0.retain(|_, u| u.expires > now);
    }
    pub fn begin(
        &mut self,
        account: &str,
        session: &str,
        request: Begin,
        now: u64,
        session_expiry: u64,
    ) -> Result<String> {
        self.prune(now);
        ensure!(
            request.target_request_id.len() == 32
                && hex::decode(&request.target_request_id)?.len() == 16,
            "invalid upload target"
        );
        ensure!(
            !request.model.is_empty()
                && request.model.len() <= 256
                && !request.model.chars().any(char::is_control),
            "invalid upload model"
        );
        ensure!(
            request.sha256.len() == 64 && hex::decode(&request.sha256)?.len() == 32,
            "invalid upload digest"
        );
        let max = match request.kind.as_str() {
            "image" => {
                ensure!(
                    ["image/png", "image/jpeg", "image/gif", "image/webp"]
                        .contains(&request.mime_type.as_str()),
                    "invalid image type"
                );
                5 * 1024 * 1024
            }
            "file" => {
                ensure!(
                    axiom_web_gateway_core::inference::FILE_MIME_TYPES
                        .contains(&request.mime_type.as_str()),
                    "invalid file type"
                );
                10 * 1024 * 1024
            }
            _ => anyhow::bail!("invalid upload kind"),
        };
        ensure!(
            !request.name.is_empty()
                && request.name.len() <= 512
                && !request.name.chars().any(char::is_control),
            "invalid file name"
        );
        ensure!(
            request.length > 0 && request.length <= max,
            "invalid upload length"
        );
        let account_uploads = self.0.values().filter(|u| u.account == account);
        ensure!(
            account_uploads.clone().count() < 64
                && account_uploads.map(|u| u.request.length).sum::<usize>() + request.length
                    <= ACCOUNT_BYTES,
            "upload account capacity reached"
        );
        ensure!(
            self.0.values().map(|u| u.request.length).sum::<usize>() + request.length
                <= TOTAL_BYTES
                && self.0.len() < 1024,
            "upload capacity reached"
        );
        let id = hex::encode(rand::random::<[u8; 16]>());
        let capacity = self
            .1
            .clone()
            .try_acquire_many_owned(u32::try_from(request.length)?)
            .context("upload memory capacity reached")?;
        self.0.insert(
            id.clone(),
            Upload {
                account: account.into(),
                session: session.into(),
                request,
                expires: (now + 300).min(session_expiry),
                bytes: Zeroizing::new(Vec::new()),
                sealed: false,
                capacity,
            },
        );
        Ok(id)
    }
    #[allow(clippy::too_many_arguments)] // Explicit account/session binding on every chunk.
    pub fn chunk(
        &mut self,
        account: &str,
        session: &str,
        id: &str,
        offset: usize,
        data: &str,
        final_chunk: bool,
        now: u64,
    ) -> Result<()> {
        self.prune(now);
        let upload = self.0.get_mut(id).context("unknown upload")?;
        ensure!(
            upload.account == account && upload.session == session,
            "upload not owned by session"
        );
        ensure!(
            !upload.sealed && offset == upload.bytes.len() && data.len() <= CHUNK.div_ceil(3) * 4,
            "invalid chunk order or size"
        );
        let bytes = Zeroizing::new(STANDARD.decode(data)?);
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= CHUNK
                && STANDARD.encode(&*bytes) == data
                && offset + bytes.len() <= upload.request.length,
            "invalid upload chunk"
        );
        upload.bytes.extend_from_slice(&bytes);
        if final_chunk {
            if upload.bytes.len() != upload.request.length
                || hex::encode(Sha256::digest(&*upload.bytes)) != upload.request.sha256
            {
                self.0.remove(id);
                anyhow::bail!("upload digest or length mismatch");
            }
            upload.sealed = true;
        }
        Ok(())
    }
    pub fn discard(&mut self, account: &str, session: &str, target: &str) -> bool {
        let before = self.0.len();
        self.0.retain(|_, u| {
            !(u.account == account && u.session == session && u.request.target_request_id == target)
        });
        before != self.0.len()
    }
    pub fn attach(
        &mut self,
        account: &str,
        session: &str,
        target: &str,
        bindings: &[Binding],
        request: &mut InferenceRequest,
        now: u64,
    ) -> Result<Vec<OwnedSemaphorePermit>> {
        self.prune(now);
        ensure!(bindings.len() <= 64, "too many upload bindings");
        let mut seen = std::collections::BTreeSet::new();
        for binding in bindings {
            ensure!(seen.insert(&binding.upload_id), "duplicate upload binding");
            let upload = self.0.get(&binding.upload_id).context("unknown upload")?;
            ensure!(
                upload.account == account
                    && upload.session == session
                    && upload.request.target_request_id == target
                    && upload.request.model == request.model
                    && upload.sealed,
                "upload binding rejected"
            );
            ensure!(
                request
                    .messages
                    .get(binding.message_index)
                    .is_some_and(|m| m.role == ChatRole::User),
                "invalid upload message"
            );
        }
        let mut capacity = Vec::new();
        for binding in bindings {
            let upload = self
                .0
                .remove(&binding.upload_id)
                .context("unknown upload")?;
            capacity.push(upload.capacity);
            let message = &mut request.messages[binding.message_index];
            let data = STANDARD.encode(&*upload.bytes);
            if upload.request.kind == "image" {
                message.images.push(ImageContent {
                    mime_type: upload.request.mime_type,
                    data,
                });
            } else {
                message.files.push(FileContent {
                    name: upload.request.name,
                    mime_type: upload.request.mime_type,
                    data,
                });
            }
        }
        request.validate()?;
        Ok(capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_web_gateway_core::inference::{ChatMessage, ChatRole};
    fn begin(bytes: &[u8]) -> Begin {
        Begin {
            target_request_id: "ab".repeat(16),
            model: "model".into(),
            kind: "file".into(),
            name: "file.txt".into(),
            mime_type: "text/plain".into(),
            length: bytes.len(),
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }
    #[test]
    fn chunks_are_ordered_owned_bounded_and_digest_checked() {
        let mut uploads = Uploads::default();
        let id = uploads
            .begin("a", "s", begin(b"original"), 100, 900)
            .unwrap();
        assert!(uploads.chunk("b", "s", &id, 0, "b3Jp", false, 100).is_err());
        assert!(
            uploads
                .chunk("a", "other", &id, 0, "b3Jp", false, 100)
                .is_err()
        );
        assert!(uploads.chunk("a", "s", &id, 3, "b3Jp", false, 100).is_err());
        uploads.chunk("a", "s", &id, 0, "b3Jp", false, 100).unwrap();
        assert!(uploads.chunk("a", "s", &id, 0, "b3Jp", false, 100).is_err());
        uploads
            .chunk("a", "s", &id, 3, "Z2luYWw=", true, 100)
            .unwrap();
        assert!(uploads.chunk("a", "s", &id, 8, "eA==", true, 100).is_err());
        assert!(!uploads.discard("b", "s", &"ab".repeat(16)));
        assert!(uploads.discard("a", "s", &"ab".repeat(16)));
        let bad = uploads.begin("a", "s", begin(b"good"), 100, 900).unwrap();
        assert!(
            uploads
                .chunk("a", "s", &bad, 0, "YmFkIQ==", true, 100)
                .is_err()
        );
        assert!(!uploads.0.contains_key(&bad));
        let expired = uploads.begin("a", "s", begin(b"x"), 100, 900).unwrap();
        assert!(
            uploads
                .chunk("a", "s", &expired, 0, "eA==", true, 401)
                .is_err()
        );
        let mut oversized = begin(b"x");
        oversized.length = 10 * 1024 * 1024 + 1;
        assert!(uploads.begin("a", "s", oversized, 100, 900).is_err());
    }
    #[test]
    fn attaching_requires_exact_request_model_user_and_one_use() {
        let mut uploads = Uploads::default();
        let id = uploads
            .begin("a", "s", begin(b"original"), 100, 900)
            .unwrap();
        let mut request =
            serde_json::from_value::<axiom_web_gateway_core::openai_compat::ChatCompletionRequest>(
                serde_json::json!({"model":"model","messages":[{"role":"user","content":"hello"}]}),
            )
            .unwrap()
            .into_domain(axiom_web_gateway_core::openai_compat::CompatMode::Strict)
            .unwrap()
            .request;
        let binding = vec![Binding {
            upload_id: id.clone(),
            message_index: 0,
        }];
        assert!(
            uploads
                .attach("a", "s", &"ab".repeat(16), &binding, &mut request, 100)
                .is_err()
        );
        uploads
            .chunk("a", "s", &id, 0, "b3JpZ2luYWw=", true, 100)
            .unwrap();
        assert!(
            uploads
                .attach("a", "s", &"cd".repeat(16), &binding, &mut request, 100)
                .is_err()
        );
        request.model = "other".into();
        assert!(
            uploads
                .attach("a", "s", &"ab".repeat(16), &binding, &mut request, 100)
                .is_err()
        );
        request.model = "model".into();
        request.messages = vec![ChatMessage::text(ChatRole::Assistant, "hello")];
        assert!(
            uploads
                .attach("a", "s", &"ab".repeat(16), &binding, &mut request, 100)
                .is_err()
        );
        request.messages = vec![ChatMessage::text(ChatRole::User, "hello")];
        uploads
            .attach("a", "s", &"ab".repeat(16), &binding, &mut request, 100)
            .unwrap();
        assert_eq!(request.messages[0].files[0].data, "b3JpZ2luYWw=");
        assert!(
            uploads
                .attach("a", "s", &"ab".repeat(16), &binding, &mut request, 100)
                .is_err()
        );
    }
}
