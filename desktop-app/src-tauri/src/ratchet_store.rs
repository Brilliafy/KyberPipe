//! Encrypted ratchet-session persistence.
//!
//! The ratchet registry in core-crypto is in-memory; without persistence a
//! desktop/phone restart wipes every chain state and forces a full re-pair.
//! This module stores each peer's exported ratchet snapshot to disk wrapped by
//! a key derived from the session key (which itself lives in the OS keyring),
//! using a fresh random 96-bit nonce per write (no nonce reuse).

use std::collections::BTreeMap;
use std::path::PathBuf;

const KEYRING_SESSION_KEY: &str = "session_key";
/// Independent snapshot-wrap key. Audit finding #15b: the ratchet snapshots
/// must NOT be wrapped with a key derived from the session key, because the
/// session key is stored in the same keyring — anyone who could read the
/// keyring could unwrap every snapshot. A separate random key makes the wrap
/// genuinely independent defense-in-depth.
const KEYRING_SNAPSHOT_KEY: &str = "snapshot_key";

/// The OS keyring is the persistent home of the session key (hex-encoded).
pub fn store_session_key_to_keyring(session_key_hex: &str) {
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_SESSION_KEY) {
        let _ = entry.set_password(session_key_hex);
    }
}

/// Load the session key from the OS keyring (hex-encoded), if present.
pub fn session_key_from_keyring() -> Option<String> {
    keyring::Entry::new("kyberpipe", KEYRING_SESSION_KEY)
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|s| !s.is_empty())
}

/// Ensure an independent snapshot-wrap key exists in the keyring (generated
/// once per install) and return it as hex.
pub fn snapshot_key_from_keyring() -> Option<String> {
    let existing = keyring::Entry::new("kyberpipe", KEYRING_SNAPSHOT_KEY)
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|s| !s.is_empty());
    if let Some(key) = existing {
        return Some(key);
    }
    // Generate a fresh 32-byte key on first use.
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    let hex_key = hex::encode(&bytes);
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_SNAPSHOT_KEY) {
        let _ = entry.set_password(&hex_key);
    }
    Some(hex_key)
}

/// Derive the snapshot wrap key from the INDEPENDENT snapshot key bytes.
fn wrap_key(snapshot_key_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(snapshot_key_hex).ok()?;
    core_crypto::crypto::derive_session_key(
        &bytes,
        b"kyberpipe-ratchet-persist-salt",
        b"kyberpipe-ratchet-snapshot-v1",
    )
    .ok()
}

/// Domain-separated wrap-key context for the notification/SMS history store
/// (audit finding #21): the same independent snapshot key derives a DIFFERENT
/// key here than for ratchet snapshots, so the two stores never share a
/// (key, purpose) derivation context.
fn notif_wrap_key(snapshot_key_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(snapshot_key_hex).ok()?;
    core_crypto::crypto::derive_session_key(
        &bytes,
        b"kyberpipe-notif-persist-salt",
        b"kyberpipe-notif-store-v1",
    )
    .ok()
}

/// AEAD-wrap the notification/SMS history JSON with the independent snapshot
/// key (audit finding #21): forwarded Signal/WhatsApp content must not sit on
/// disk in plaintext. Returns "{nonce_hex}:{ciphertext_hex}".
pub fn encrypt_notifications_data(snapshot_key_hex: &str, data: &[u8]) -> Option<String> {
    let wk = notif_wrap_key(snapshot_key_hex)?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let ct = core_crypto::crypto::encrypt_chacha20(&wk, &nonce, data, &[]).ok()?;
    Some(format!("{}:{}", hex::encode(nonce), hex::encode(ct)))
}

/// Decrypt a notification history blob written by `encrypt_notifications_data`.
pub fn decrypt_notifications_data(snapshot_key_hex: &str, blob: &str) -> Option<Vec<u8>> {
    let (nonce_hex, ct_hex) = blob.split_once(':')?;
    let (nonce, ct) = (hex::decode(nonce_hex).ok()?, hex::decode(ct_hex).ok()?);
    let nonce_arr = <[u8; 12]>::try_from(nonce.as_slice()).ok()?;
    let wk = notif_wrap_key(snapshot_key_hex)?;
    core_crypto::crypto::decrypt_chacha20(&wk, &nonce_arr, &ct, &[]).ok()
}

fn store_path() -> PathBuf {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| std::env::temp_dir());
    let _ = std::fs::create_dir_all(&dir);
    dir.join("ratchet_sessions.json")
}

/// Save every ratchet session's snapshot, encrypted with the independent
/// snapshot key (NOT the session key — audit finding #15b).
pub fn persist_all_ratchet_sessions(snapshot_key_hex: &str) {
    let Some(wk) = wrap_key(snapshot_key_hex) else {
        tracing::warn!("[RatchetStore] Cannot derive wrap key — skipping persistence");
        return;
    };
    let peer_ids = core_crypto::ratchet_peer_ids();
    if peer_ids.is_empty() {
        return;
    }
    let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for peer in peer_ids {
        if let Ok(Some(snap)) = core_crypto::ratchet_export_session(peer.clone()) {
            // Fresh random 96-bit nonce per write — never reuse.
            let mut nonce = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
            if let Ok(ct) = core_crypto::crypto::encrypt_chacha20(&wk, &nonce, &snap, &[]) {
                map.insert(
                    peer,
                    serde_json::json!({
                        "nonce_hex": hex::encode(nonce),
                        "ciphertext_hex": hex::encode(ct),
                    }),
                );
            }
        }
    }
    if map.is_empty() {
        return;
    }
    if let Ok(json) = serde_json::to_string_pretty(&map) {
        let _ = std::fs::write(store_path(), json);
    }
}

/// Remove the persisted ratchet store (used on unpair/self-destruct so no
/// ciphertext of old chain state survives).
pub fn clear_ratchet_store() {
    let _ = std::fs::remove_file(store_path());
}

/// Restore every persisted ratchet session, decrypting with the independent
/// snapshot key (audit finding #15b).
pub fn restore_all_ratchet_sessions(snapshot_key_hex: &str) -> usize {
    let Some(wk) = wrap_key(snapshot_key_hex) else {
        return 0;
    };
    let Ok(data) = std::fs::read_to_string(store_path()) else {
        return 0;
    };
    let Ok(map) = serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&data) else {
        return 0;
    };
    let mut restored = 0usize;
    for (peer, entry) in map {
        let (Some(nonce_hex), Some(ct_hex)) = (
            entry.get("nonce_hex").and_then(|v| v.as_str()),
            entry.get("ciphertext_hex").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let (Ok(nonce), Ok(ct)) = (hex::decode(nonce_hex), hex::decode(ct_hex)) else {
            continue;
        };
        let Ok(nonce_arr) = <[u8; 12]>::try_from(nonce.as_slice()) else {
            continue;
        };
        if let Ok(snap) = core_crypto::crypto::decrypt_chacha20(&wk, &nonce_arr, &ct, &[]) {
            if core_crypto::ratchet_import_session(peer.clone(), snap).is_ok() {
                restored += 1;
            }
        }
    }
    restored
}
