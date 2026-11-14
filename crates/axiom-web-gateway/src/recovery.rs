//! Short-lived replay inside the attested process. A reconnect subscribes to
//! the same execution; it never resubmits inference or weakens its terminal.
use anyhow::{Result, ensure};
use serde_json::Value;
use std::sync::{
    Arc, Mutex as SyncMutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

const MAX_BYTES: usize = 4 * 1024 * 1024;
const GRACE: std::time::Duration = std::time::Duration::from_secs(30);
static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Default)]
struct Frames {
    values: Vec<Zeroizing<Vec<u8>>>,
    bytes: usize,
    finished: bool,
    unavailable: bool,
}

pub struct Replay {
    frames: Mutex<Frames>,
    pub changed: Notify,
    subscribers: SyncMutex<(usize, Option<tokio::time::Instant>)>,
    expires: AtomicU64,
    _capacity: OwnedSemaphorePermit,
}

impl Replay {
    pub fn new() -> Option<Arc<Self>> {
        let capacity = SLOTS
            .get_or_init(|| Arc::new(Semaphore::new(16)))
            .clone()
            .try_acquire_owned()
            .ok()?;
        Some(Arc::new(Self {
            frames: Mutex::new(Frames::default()),
            changed: Notify::new(),
            subscribers: SyncMutex::new((1, None)),
            expires: AtomicU64::new(crate::now() + 660),
            _capacity: capacity,
        }))
    }
    pub fn expired(&self) -> bool {
        self.expires.load(Ordering::SeqCst) <= crate::now()
    }
    pub fn attach(self: &Arc<Self>) -> Subscriber {
        {
            let mut state = self.subscribers.lock().expect("subscriber lock");
            state.0 += 1;
            state.1 = None;
        }
        self.changed.notify_waiters();
        Subscriber(Arc::clone(self))
    }
    pub fn detach(&self) {
        {
            let mut state = self.subscribers.lock().expect("subscriber lock");
            state.0 -= 1;
            if state.0 == 0 {
                state.1 = Some(tokio::time::Instant::now() + GRACE);
            }
        }
        self.changed.notify_waiters();
    }
    pub async fn append(&self, frame: &Value) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(frame)?);
        let mut state = self.frames.lock().await;
        if state.bytes.saturating_add(bytes.len()) > MAX_BYTES {
            // Large replies continue normally without a replay buffer.
            state.unavailable = true;
            state.values.clear();
            state.bytes = 0;
        }
        if !state.unavailable {
            state.bytes += bytes.len();
            state.values.push(bytes);
        }
        if frame["kind"] == "terminal" {
            state.finished = true;
            self.expires.store(crate::now() + 60, Ordering::SeqCst);
        }
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
    pub async fn frame(&self, index: usize) -> Result<(Option<Value>, bool)> {
        ensure!(!self.expired(), "response recovery expired");
        let state = self.frames.lock().await;
        ensure!(!state.unavailable, "response exceeds replay limit");
        Ok((
            state
                .values
                .get(index)
                .map(|bytes| serde_json::from_slice(bytes))
                .transpose()?,
            state.finished,
        ))
    }
    pub async fn abandoned(&self) {
        loop {
            let changed = self.changed.notified();
            let deadline = self.subscribers.lock().expect("subscriber lock").1;
            if let Some(deadline) = deadline {
                tokio::select! {
                    () = tokio::time::sleep_until(deadline) => {
                        let current = self.subscribers.lock().expect("subscriber lock");
                        if current.0 == 0 && current.1.is_some_and(|at| at <= tokio::time::Instant::now()) { return; }
                    }
                    () = changed => {}
                }
            } else {
                changed.await;
            }
        }
    }
}

pub struct Subscriber(Arc<Replay>);
impl Drop for Subscriber {
    fn drop(&mut self) {
        self.0.detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn replays_the_same_bound_frames_and_terminal() {
        let log = Replay::new().unwrap();
        let frame = serde_json::json!({"kind":"text_delta","request_id":"owned","sequence":0,"data":{"text":"private"}});
        log.append(&frame).await.unwrap();
        log.detach();
        let reader = log.attach();
        assert_eq!(log.frame(0).await.unwrap(), (Some(frame), false));
        log.append(&serde_json::json!({"kind":"terminal","sequence":1}))
            .await
            .unwrap();
        assert!(log.frame(2).await.unwrap().1);
        drop(reader);
    }
    #[tokio::test(start_paused = true)]
    async fn output_during_disconnect_does_not_extend_the_subscriber_grace() {
        let log = Replay::new().unwrap();
        log.detach();
        let waiting = log.clone();
        let task = tokio::spawn(async move {
            waiting.abandoned().await;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(29)).await;
        log.append(&serde_json::json!({"kind":"text_delta","data":{"text":"still running"}}))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        task.await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn a_new_subscriber_cancels_the_old_grace_and_gets_a_fresh_detach_deadline() {
        let log = Replay::new().unwrap();
        log.detach();
        let waiting = log.clone();
        let task = tokio::spawn(async move {
            waiting.abandoned().await;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(29)).await;
        let subscriber = log.attach();
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        assert!(!task.is_finished());
        drop(subscriber);
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(29)).await;
        assert!(!task.is_finished());
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        task.await.unwrap();
    }
    #[tokio::test]
    async fn oversized_buffers_are_erased_and_cannot_be_resumed() {
        let log = Replay::new().unwrap();
        log.append(&serde_json::json!({"kind":"text_delta","data":"x".repeat(MAX_BYTES)}))
            .await
            .unwrap();
        assert!(log.frame(0).await.is_err());
        assert!(log.frames.lock().await.values.is_empty());
    }
}
