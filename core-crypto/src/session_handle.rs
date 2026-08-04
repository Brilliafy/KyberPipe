use crate::error::KyberError;
use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};

pub(crate) struct SessionKey {
    key: [u8; 32],
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

/// Maximum active session key handles — prevents unbounded growth from
/// malicious or buggy callers creating handles in a loop.
const MAX_SESSION_KEYS: usize = 256;

/// Single registry guarded by ONE mutex.
///
/// Audit finding #10: the previous implementation used three independent
/// statics (SESSION_KEYS, KEY_FINGERPRINTS, LRU_ORDER) acquired in DIFFERENT
/// orders in `session_key_create` (SESSIONS → LRU → FINGERPRINTS) vs
/// `session_key_destroy` (SESSIONS → FINGERPRINTS → LRU) — a classic ABBA
/// deadlock under concurrent create+destroy. Collapsing all three into one
/// struct behind a single mutex eliminates the ordering problem entirely.
struct SessionRegistry {
    keys: HashMap<u64, std::sync::Arc<SessionKey>>,
    /// handle -> fingerprint, kept in sync with `keys`.
    fingerprints: HashMap<u64, [u8; 16]>,
    /// LRU eviction order — least recently used at the front.
    lru: VecDeque<u64>,
    /// Handles that must NEVER be evicted by the LRU cap (audit finding #23).
    /// A long-idle but still-referenced key (e.g. the persisted master session
    /// key used only at restore time) must not silently vanish when 256 churny
    /// transient handles are created; evicting it turns a later decrypt into
    /// "Invalid handle" and silently destroys undecryptable material. Pinned
    /// handles are skipped by the eviction sweep. The cap still bounds the
    /// total set; if every handle is pinned, creation fails with a clear error
    /// instead of evicting a pinned key.
    pinned: std::collections::HashSet<u64>,
}

impl SessionRegistry {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            fingerprints: HashMap::new(),
            lru: VecDeque::new(),
            pinned: std::collections::HashSet::new(),
        }
    }

    fn evict_lru(&mut self) {
        // Skip pinned handles — only churny TRANSIENT handles are evictable
        // (audit finding #23).
        while let Some(oldest) = self.lru.pop_front() {
            if !self.pinned.contains(&oldest) {
                self.keys.remove(&oldest);
                self.fingerprints.remove(&oldest);
                return;
            }
        }
    }

    fn touch(&mut self, handle: u64) {
        if let Some(pos) = self.lru.iter().position(|&h| h == handle) {
            self.lru.remove(pos);
            self.lru.push_back(handle);
        }
    }
}

static SESSION_REGISTRY: LazyLock<Mutex<SessionRegistry>> =
    LazyLock::new(|| Mutex::new(SessionRegistry::new()));

static NEXT_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn key_fingerprint(key: &[u8; 32]) -> [u8; 16] {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(key);
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&digest[..16]);
    fp
}

/// Create a new session key handle from raw key bytes.
/// Returns an opaque handle ID (u64) that Kotlin stores instead of the key.
pub fn session_key_create(key_bytes: Vec<u8>) -> Result<u64, KyberError> {
    if key_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len() as u64,
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);

    let mut key = std::sync::Arc::new(SessionKey { key: arr });
    let fp = key_fingerprint(&key.key);

    let mut reg = SESSION_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());

    // Enforce cap first: evict the least-recently-used EVICTABLE handle so its
    // key bytes become reusable (a replaced handle is genuinely destroyed).
    // Pinned handles are never evicted (audit finding #23). If every handle is
    // pinned and the registry is full, fail loudly instead of silently
    // destroying a pinned key the caller still references.
    if reg.keys.len() >= MAX_SESSION_KEYS {
        let evictable = reg.lru.iter().any(|h| !reg.pinned.contains(h));
        if !evictable {
            return Err(KyberError::CryptoError(
                "Session key registry full and every handle is pinned — destroy an unused handle first (audit finding #23)"
                    .into(),
            ));
        }
        reg.evict_lru();
    }
    // Reject duplicate key material among LIVE handles: two concurrent handles
    // with identical key bytes would otherwise encrypt with the same key.
    if reg.fingerprints.values().any(|f| *f == fp) {
        // Zeroize our local copy before rejecting.
        if let Some(sk) = std::sync::Arc::get_mut(&mut key) {
            zeroize::Zeroize::zeroize(&mut sk.key);
        }
        // Also drop the Arc-local copy of the key bytes.
        drop(key);
        return Err(KyberError::CryptoError(
            "A session key handle for identical key bytes already exists".into(),
        ));
    }
    let id = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    reg.keys.insert(id, key);
    reg.fingerprints.insert(id, fp);
    reg.lru.push_back(id);
    Ok(id)
}

/// Get a reference to the session key by handle ID.
/// Returns None if the handle is invalid or has been dropped.
pub(crate) fn session_key_get(handle: u64) -> Option<std::sync::Arc<SessionKey>> {
    let mut reg = SESSION_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let result = reg.keys.get(&handle).cloned();
    // Update LRU order on access
    if result.is_some() {
        reg.touch(handle);
    }
    result
}

/// Destroy a session key handle, zeroizing the key material.
pub fn session_key_destroy(handle: u64) {
    let mut reg = SESSION_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    reg.keys.remove(&handle);
    reg.fingerprints.remove(&handle);
    reg.pinned.remove(&handle);
    if let Some(pos) = reg.lru.iter().position(|&h| h == handle) {
        reg.lru.remove(pos);
    }
    // Arc drop triggers SessionKey drop, which triggers zeroization
}

/// Pin a session key handle so the LRU cap can never evict it (audit finding
/// #23). Pinned handles are still destroyed explicitly via `session_key_destroy`
/// (unpair / self-destruct). Returns true when the handle is live and was
/// pinned (or was already pinned); false for an unknown handle.
pub fn session_key_pin(handle: u64) -> bool {
    let mut reg = SESSION_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if reg.keys.contains_key(&handle) {
        reg.pinned.insert(handle);
        true
    } else {
        false
    }
}

/// Unpin a session key handle, returning it to the pool of evictable handles.
/// No-op for unknown handles.
pub fn session_key_unpin(handle: u64) {
    let mut reg = SESSION_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    reg.pinned.remove(&handle);
}

/// Destroy ALL session key handles, zeroizing every key. Used by the panic
/// self-destruct path.
pub fn session_key_destroy_all() {
    let mut reg = SESSION_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    reg.keys.clear();
    reg.fingerprints.clear();
    reg.lru.clear();
    reg.pinned.clear();
}

/// Encrypt data using a session key handle.
/// Uses a FRESH random 96-bit nonce per message. The previous scheme derived a
/// deterministic 32-bit sid from the key bytes and reset the sequence counter
/// per handle, so re-creating a handle from the same key bytes after an eviction
/// or restart reproduced identical (key, nonce) pairs → ChaCha20-Poly1305
/// keystream reuse. Random nonces remove that entire class of bug.
pub fn session_key_encrypt(handle: u64, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KyberError> {
    if !crate::check_generation() {
        return Err(KyberError::CryptoError(
            "Session invalidated by self-destruct".into(),
        ));
    }
    let key = session_key_get(handle)
        .ok_or_else(|| KyberError::CryptoError(format!("Invalid session key handle {handle}")))?;

    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let ciphertext = crate::crypto::encrypt_chacha20(&key.key, &nonce, data, &[])?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt data using a session key handle.
pub fn session_key_decrypt(
    handle: u64,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KyberError> {
    if !crate::check_generation() {
        return Err(KyberError::CryptoError(
            "Session invalidated by self-destruct".into(),
        ));
    }
    let key = session_key_get(handle)
        .ok_or_else(|| KyberError::CryptoError(format!("Invalid session key handle {handle}")))?;

    if nonce.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    crate::crypto::decrypt_chacha20(&key.key, &nonce_arr, ciphertext, &[])
}

/// Get a truncated, salted HMAC fingerprint for a session key handle (for logging/identification).
/// Uses HMAC-SHA256 with a domain-specific salt to prevent fingerprint exposure via raw SHA-256.
pub fn session_key_hash(handle: u64) -> Result<String, KyberError> {
    let key = session_key_get(handle)
        .ok_or_else(|| KyberError::CryptoError(format!("Invalid session key handle {handle}")))?;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(b"kyberpipe-session-id").unwrap();
    mac.update(&key.key);
    let result = mac.finalize().into_bytes();
    // Truncate to 8 bytes (16 hex chars) — enough for identification, not enough for attacks
    Ok(hex::encode(&result[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u16) -> Vec<u8> {
        // Spread the seed across the first two bytes so every seed maps to a
        // UNIQUE 32-byte key — parallel tests in this shared registry cannot
        // collide even when seed values exceed 255.
        let mut k = [0u8; 32];
        k[0] = (seed % 256) as u8;
        k[1] = (seed / 256) as u8;
        k.to_vec()
    }

    /// Regression: unbounded handle creation must be capped by LRU eviction.
    #[test]
    fn test_handle_cap_lru_eviction() {
        // Create more handles than the cap permits
        let mut handles = Vec::new();
        for i in 0..(MAX_SESSION_KEYS + 50) {
            handles.push(session_key_create(test_key(i as u16)).unwrap());
        }
        // Map must never exceed the cap
        let reg = SESSION_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        assert!(reg.keys.len() <= MAX_SESSION_KEYS);
        drop(reg);
        // The oldest handle must have been evicted (handles[0] created first)
        assert!(session_key_get(handles[0]).is_none());
        // A recent handle must still be alive
        assert!(session_key_get(*handles.last().unwrap()).is_some());
        // Cleanup
        for h in handles.iter().skip(1) {
            session_key_destroy(*h);
        }
    }

    /// Regression: destroy must also remove the handle from LRU tracking.
    #[test]
    fn test_destroy_clears_lru() {
        // Seed 400 is disjoint from every other session_handle test's range so
        // parallel tests cannot collide in the shared process-wide registry.
        let h = session_key_create(test_key(400)).unwrap();
        assert!(session_key_get(h).is_some());
        session_key_destroy(h);
        assert!(session_key_get(h).is_none());
        let reg = SESSION_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!reg.lru.iter().any(|&x| x == h));
        drop(reg);
    }

    /// Audit #10 regression: concurrent create+destroy on many handles must
    /// complete without deadlock (the old three-static ABBA ordering hung).
    #[test]
    fn test_concurrent_create_destroy_no_deadlock() {
        // Disjoint seed ranges (500..563, 600..649) — see test_destroy_clears_lru.
        let handles: Vec<u64> = (500..563u16)
            .map(|i| session_key_create(test_key(i)).unwrap())
            .collect();
        let handles_clone = handles.clone();
        let t = std::thread::spawn(move || {
            for h in handles_clone {
                session_key_destroy(h);
            }
        });
        // Concurrently create fresh handles with unique key bytes.
        let mut extra = Vec::new();
        for i in 600..649u16 {
            extra.push(session_key_create(test_key(i)).unwrap());
        }
        t.join()
            .expect("destroy thread must finish without deadlock");
        // Cleanup remaining.
        for h in handles {
            session_key_destroy(h);
        }
        for h in extra {
            session_key_destroy(h);
        }
    }
}
