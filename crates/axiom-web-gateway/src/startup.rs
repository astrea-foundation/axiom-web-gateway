//! Bounded startup metadata. Never record errors, credentials or inference data.
use std::sync::atomic::{AtomicBool, Ordering};

static READY: AtomicBool = AtomicBool::new(false);
const STATUS: &str = "/dev/shm/axiom-gateway-startup";

pub fn phase(value: &'static str) {
    if !READY.load(Ordering::Acquire) {
        // Docker's private shared-memory mount remains writable with a read-only
        // root. This file contains only the static phase names below.
        let _ = std::fs::write(STATUS, value);
    }
}

pub fn ready() {
    phase("ready");
    READY.store(true, Ordering::Release);
}

pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}
