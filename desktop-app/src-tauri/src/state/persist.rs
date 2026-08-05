//! Coalescing persistence channel (audit F7/F20 split): the bounded
//! latest-value slot + Condvar writer, promoted out of `services.rs` into
//! its own module with its documented boundedness contract.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Durably write `data` to `path` via temp-file → fsync → rename (audit P4-2).
///
/// This is the SHARED atomic-write discipline the ratchet store already
/// applied to the secret-bearing store (`persist_all_ratchet_sessions`): the
/// bytes go to a sibling `.tmp` file, are fsynced to disk, then renamed over
/// the real path. A crash mid-write leaves only the `.tmp` sibling — the
/// previous good file at `path` is never truncated, so a power loss cannot
/// produce a zero-length/partial `settings.json` that a restart would parse
/// as defaults (silently dropping the persisted pairing identity that F1's
/// restart-rebuild depends on). Returns true only when the rename landed.
pub(crate) fn atomic_write(path: &std::path::Path, data: &[u8]) -> bool {
    let mut tmp_path = path.as_os_str().to_owned();
    tmp_path.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp_path);
    let mut write_ok = false;
    if std::fs::write(&tmp, data).is_ok() {
        // fsync BEFORE rename: a power loss must not leave an empty temp file
        // that then gets renamed over the good target.
        write_ok = std::fs::File::open(&tmp).and_then(|f| f.sync_all()).is_ok();
    }
    if write_ok && std::fs::rename(&tmp, path).is_ok() {
        // fsync the containing directory so the rename itself is durable
        // (best-effort; not supported on every platform/filesystem).
        if let Some(dir) = path.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        return true;
    }
    let _ = std::fs::remove_file(&tmp);
    false
}

/// Shared latest-value persistence state (audit F7): a `Mutex<VecDeque<(path,
/// data)>>` slot + Condvar replaced the previous UNBOUNDED `mpsc` channel. The
/// previous design enqueued every write into an unbounded channel and only
/// coalesced at DRAIN time — a stalled filesystem (NFS/FUSE/full disk) let
/// producers enqueue without bound, growing memory without limit. The slot
/// keeps AT MOST ONE entry per path (the newest value, replaced atomically),
/// so memory is bounded by the number of distinct paths (a fixed, small set)
/// and `persist()` can never block — it is a mutex-protected insert + condvar
/// signal.
type PersistState = (
    std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(String, String)>>>,
    std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
);

/// Condvar paired with the persist slot: the writer waits on it, `persist`
/// signals it, teardown signals it to wake-and-exit.
static PERSIST_CONDVAR: OnceLock<std::sync::Condvar> = OnceLock::new();
/// Shutdown flag: set by `shutdown_persist_for_tests` so the writer exits its
/// wait loop (the old design closed the channel instead — the slot has no
/// channel to close).
static PERSIST_SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Hard cap on distinct pending paths in the persist slot (audit F7). The set
/// of real paths is tiny (settings, notifications, ratchet store); the cap
/// guards against a buggy caller creating unbounded distinct paths. When the
/// cap is hit the OLDEST entry is dropped (drop-oldest semantics).
const MAX_PENDING_PATHS: usize = 32;

static PERSIST_STATE: OnceLock<PersistState> = OnceLock::new();

/// Non-blocking, COALESCING persistence (audit finding #22 + F7). The writer
/// thread wakes on signal, drains the slot (taking every pending path), and
/// writes each path's LATEST value, so a slow filesystem never blocks a Tauri
/// command on the main thread and an intermediate stale write is dropped
/// without loss (the newest value for each path always lands).
fn persist_channel() -> &'static PersistState {
    PERSIST_STATE.get_or_init(|| {
        let slot: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        let writer_slot = slot.clone();
        let handle = std::thread::spawn(move || {
            let cv = PERSIST_CONDVAR.get_or_init(std::sync::Condvar::new);
            let mut latest: HashMap<String, String> = HashMap::new();
            loop {
                // Block until work is available or shutdown is requested.
                let mut guard = writer_slot.lock().unwrap_or_else(|e| e.into_inner());
                while guard.is_empty()
                    && !PERSIST_SHUTDOWN.load(std::sync::atomic::Ordering::Acquire)
                {
                    guard = cv.wait(guard).unwrap_or_else(|e| e.into_inner());
                }
                if guard.is_empty() && PERSIST_SHUTDOWN.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                // Drain the slot into the coalesced map (latest value per path
                // wins — later entries overwrite earlier ones).
                latest.clear();
                for (path, data) in guard.drain(..) {
                    latest.insert(path, data);
                }
                drop(guard);
                for (path, data) in latest.drain() {
                    // AUDIT P4-2 (LOW): settings.json (which holds the
                    // persisted pairing identity F1's restart-rebuild depends
                    // on) was written with `File::create` + `write_all` and NO
                    // fsync — a crash mid-write left a truncated/zero-length
                    // file that the next boot parsed as defaults, silently
                    // losing `is_paired` while the keyring and ratchet store
                    // still held the session material. Route every persist
                    // through the same temp-fsync-rename discipline the
                    // ratchet store uses.
                    let path = std::path::PathBuf::from(&path);
                    if !atomic_write(&path, data.as_bytes()) {
                        tracing::warn!(
                            "[Persist] Atomic write failed for {} — previous file left untouched",
                            path.display()
                        );
                    }
                }
            }
        });
        (slot, std::sync::Mutex::new(Some(handle)))
    })
}

/// Enqueue a persistence job WITHOUT blocking the caller (audit F7). The slot
/// is bounded (one entry per path, capped at MAX_PENDING_PATHS with
/// drop-oldest), so a slow FS or a busy persistence thread can never stall a
/// Tauri command NOR grow memory without limit.
pub(crate) fn persist(path: String, data: String) {
    let (slot, _handle) = persist_channel();
    let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
    // Replace any pending entry for the same path (latest value wins) — this
    // keeps at most one entry per path in flight.
    if let Some(pos) = guard.iter().position(|(p, _)| *p == path) {
        guard[pos] = (path, data);
    } else {
        guard.push_back((path, data));
        while guard.len() > MAX_PENDING_PATHS {
            guard.pop_front(); // drop-oldest
        }
    }
    drop(guard);
    if let Some(cv) = PERSIST_CONDVAR.get() {
        cv.notify_all();
    }
}

/// TEST/TEARDOWN ONLY: stop the writer thread and join it. After this call
/// `persist()` is a no-op. Without this, the writer thread blocks on the
/// condvar forever and keeps the test process alive (the e2e's save_settings
/// creates it via the first persist call).
#[allow(dead_code)] // e2e teardown helper; not referenced by lib code
pub fn shutdown_persist_for_tests() {
    // Set the shutdown flag UNDER the slot lock so the writer's
    // check-flag-then-`cv.wait` cannot lose the wakeup: the writer evaluates the
    // flag while holding the slot lock and `cv.wait` atomically releases it
    // while parking, so a store performed here under the same lock is either
    // visible before the writer parks (it breaks) or the notify lands after it
    // parks (it wakes). Without the lock, a store+notify issued in the window
    // between the writer's flag check and its `cv.wait` park was missed and the
    // writer slept forever (a latent CI hang).
    if let Some((slot, handle)) = PERSIST_STATE.get() {
        {
            let _guard = slot.lock().unwrap_or_else(|e| e.into_inner());
            PERSIST_SHUTDOWN.store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(cv) = PERSIST_CONDVAR.get() {
            cv.notify_all();
        }
        if let Ok(mut h) = handle.lock() {
            if let Some(handle) = h.take() {
                let _ = handle.join();
            }
        }
    } else {
        // The writer was never created — nothing to stop, but record the
        // shutdown so a LATER-created writer exits immediately.
        PERSIST_SHUTDOWN.store(true, std::sync::atomic::Ordering::Release);
    }
}
