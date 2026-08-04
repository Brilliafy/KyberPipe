//! APP-LEVEL UTILITIES (audit #21 — structural decomposition). Extracted from
//! the former `crypto/mod.rs` re-export soup: clipboard deduplication, cover
//! traffic and clipboard text normalization are APPLICATION helpers, not
//! cryptographic primitives. `crypto/mod.rs` is now a pure re-export of the
//! primitive submodules; this module owns the app-level helpers so import
//! hygiene and static analysis are clean.

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Normalize text to prevent OS line-ending and whitespace hash mismatches (\r\n -> \n, trim end)
pub fn normalize_clipboard_text(text: &str) -> String {
    text.replace("\r\n", "\n").trim_end().to_string()
}

/// Compute SHA-256 hash of normalized text
pub fn hash_clipboard_text(text: &str) -> String {
    let normalized = normalize_clipboard_text(text);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate jittered dummy cover traffic heartbeat payload
pub fn generate_cover_traffic_packet() -> Vec<u8> {
    let mut dummy = vec![0u8; 256];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut dummy);
    dummy
}

/// Thread-safe clipboard deduplicator ring buffer with AtomicBool state flag
/// Uses RAII Drop guard to prevent permanent lock on panic
#[derive(Clone)]
pub struct ClipboardDeduplicator {
    history: Arc<Mutex<VecDeque<String>>>,
    is_processing_remote_update: Arc<AtomicBool>,
    max_history: usize,
}

/// RAII guard that releases the remote update lock on Drop
pub struct RemoteUpdateGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for RemoteUpdateGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

impl ClipboardDeduplicator {
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(5))),
            is_processing_remote_update: Arc::new(AtomicBool::new(false)),
            max_history: 5,
        }
    }

    /// Execute a closure within a remote update scope.
    /// The AtomicBool flag is set before the closure and released after (even on panic via Drop).
    pub fn with_remote_update<F, T>(&self, f: F) -> Option<T>
    where
        F: FnOnce() -> T,
    {
        let acquired = self
            .is_processing_remote_update
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if !acquired {
            return None;
        }
        let _guard = RemoteUpdateGuard {
            flag: self.is_processing_remote_update.clone(),
        };
        Some(f())
    }

    pub fn is_suppressed(&self, text: &str) -> bool {
        if self.is_processing_remote_update.load(Ordering::SeqCst) {
            return true;
        }
        let hash = hash_clipboard_text(text);
        let guard = self.history.lock().unwrap_or_else(|e| e.into_inner());
        // Use constant-time comparison to prevent timing oracle on hash lookup
        guard
            .iter()
            .any(|h| subtle::ConstantTimeEq::ct_eq(h.as_bytes(), hash.as_bytes()).into())
    }

    pub fn record_text(&self, text: &str) {
        let hash = hash_clipboard_text(text);
        let mut guard = self.history.lock().unwrap_or_else(|e| e.into_inner());
        if guard.contains(&hash) {
            return;
        }
        if guard.len() >= self.max_history {
            guard.pop_front();
        }
        guard.push_back(hash);
    }
    /// Atomic check-and-record: holds the Mutex for both operations.
    /// Returns true if the text was newly recorded (was not a duplicate).
    pub fn check_and_record(&self, text: &str) -> bool {
        let hash = hash_clipboard_text(text);
        let mut guard = self.history.lock().unwrap_or_else(|e| e.into_inner());
        // Use constant-time comparison to prevent timing oracle on hash lookup
        if guard
            .iter()
            .any(|h| subtle::ConstantTimeEq::ct_eq(h.as_bytes(), hash.as_bytes()).into())
        {
            return false;
        }
        if guard.len() >= self.max_history {
            guard.pop_front();
        }
        guard.push_back(hash);
        true
    }
}

impl Default for ClipboardDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}
