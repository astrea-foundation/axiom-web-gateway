//! Session activity never extends the account delegation or attestation lifetime.
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

pub const IDLE_SECONDS: u64 = 180;
pub const HEARTBEAT_SECONDS: u64 = 60;

pub struct Activity {
    last_used: AtomicU64,
    in_flight: AtomicUsize,
    closing: AtomicBool,
    heartbeat: AtomicBool,
}

impl Activity {
    pub fn new(current: u64) -> Arc<Self> {
        Arc::new(Self {
            last_used: AtomicU64::new(current),
            in_flight: AtomicUsize::new(0),
            closing: AtomicBool::new(false),
            heartbeat: AtomicBool::new(false),
        })
    }

    /// Call while holding the session map lock, so admission cannot race a pin.
    pub fn pin(self: &Arc<Self>) -> Use {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Use(Arc::clone(self))
    }

    pub fn touch(&self, current: u64) {
        self.last_used.fetch_max(current, Ordering::SeqCst);
    }

    pub fn heartbeat(&self, current: u64) {
        self.heartbeat.store(true, Ordering::SeqCst);
        self.touch(current);
    }

    pub fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
    }

    pub fn closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    pub fn busy(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst) != 0
    }

    pub fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::SeqCst)
    }

    pub fn expired(&self, current: u64, delegation_expiry: u64) -> bool {
        delegation_expiry <= current
            || (self.heartbeat.load(Ordering::SeqCst)
                && self.last_used().saturating_add(IDLE_SECONDS) <= current)
    }

    pub fn removable(&self, current: u64, delegation_expiry: u64, has_uploads: bool) -> bool {
        !self.busy()
            && (self.closing() || (!has_uploads && self.expired(current, delegation_expiry)))
    }
}

/// Owned by the response producer until its terminal frame has been sent.
pub struct Use(Arc<Activity>);
impl Drop for Use {
    fn drop(&mut self) {
        self.0.touch(crate::now());
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_heartbeats_reclaim_idle_sessions_but_never_extend_delegation() {
        let activity = Activity::new(100);
        // Older clients retain their existing absolute lifetime.
        assert!(!activity.expired(500, 1_000));
        activity.heartbeat(500);
        assert!(!activity.expired(679, 1_000));
        assert!(activity.removable(680, 1_000, false));
        activity.heartbeat(999);
        assert!(activity.expired(1_000, 1_000));
    }

    #[test]
    fn cleanup_and_release_preserve_active_replies_and_pending_uploads() {
        let activity = Activity::new(100);
        activity.heartbeat(100);
        let first = activity.pin();
        let second = activity.pin();
        assert!(!activity.removable(1_000, 900, false));
        activity.close();
        drop(first);
        assert!(!activity.removable(1_000, 900, true));
        drop(second);
        assert!(activity.removable(1_000, 900, true));
        let upload = Activity::new(100);
        upload.heartbeat(100);
        assert!(!upload.removable(400, 900, true));
        assert!(upload.removable(400, 900, false));
    }
}
