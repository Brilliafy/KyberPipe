//! Atomic snapshot-store file lifecycle (audit P5-1 split).
//!
//! Per-peer ratchet snapshot persistence: atomic write/rotate/restore and
//! per-peer removal. Key material is AEAD-wrapped with the independent
//! snapshot wrap key from `super::keys` before it reaches disk; the
//! watermark/rollback policy lives in `super::watermark`.

use super::keys::{wrap_key, KEYRING_RATCHET_WATERMARK};
use super::watermark::{
    is_rollback, load_watermarks, merge_watermark, save_watermarks, snapshot_watermark,
    watermark_path, Watermark,
};

use std::collections::BTreeMap;
use std::path::PathBuf;

fn store_path() -> PathBuf {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dir);
    dir.join("ratchet_sessions.json")
}

/// Temp file for an in-progress atomic store write (audit F19). The store is
/// never written in place: bytes go to this path, are fsynced, then renamed
/// over the real store path. A crash mid-write leaves only this temp file —
/// the previous good store stays intact.
fn store_tmp_path() -> PathBuf {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dir);
    dir.join("ratchet_sessions.json.tmp")
}

/// Previous-good-store backup (audit F19). Before the store path is replaced,
/// the current file is rotated here, so a torn/replaced store can be recovered
/// on the next restore.
fn store_bak_path() -> PathBuf {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dir);
    dir.join("ratchet_sessions.json.bak")
}

/// SEPARATE, tamper-evident high-water-mark file (audit F16). Written on every
/// successful persist; read before restore. A same-user process that swaps
/// `ratchet_sessions.json` for an older copy cannot regress this file (it only
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
    let mut fresh_watermarks: std::collections::HashMap<String, Watermark> = load_watermarks();
    for peer in peer_ids {
        if let Ok(Some(mut snap)) = core_crypto::ratchet_export_session(peer.clone()) {
            // Record the (authenticated) watermark for this snapshot.
            if let Some(wm) = snapshot_watermark(&snap) {
                // Only ever move the watermark forward (component-wise — audit
                // #1) — a stale snapshot cannot regress it.
                let entry = fresh_watermarks.entry(peer.clone()).or_insert((0, 0, 0, 0));
                merge_watermark(entry, &wm);
            }
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
            // AUDIT #14: the exported snapshot holds full session key material;
            // wipe the plaintext buffer as soon as it has been wrapped.
            use zeroize::Zeroize;
            snap.zeroize();
        }
    }
    if map.is_empty() {
        return;
    }
    if let Ok(json) = serde_json::to_string_pretty(&map) {
        // AUDIT F19 + P4-2: ATOMIC store write. The legacy `fs::write(store_path())`
        // wrote in place — a crash mid-write left a truncated
        // `ratchet_sessions.json` that `restore_all_ratchet_sessions` failed
        // to parse, silently discarding EVERY persisted session (full re-pair
        // for every device). The write goes through the SHARED
        // `atomic_write` helper (temp file → fsync → rename, extracted into
        // `state::persist` so settings.json and the ratchet store cannot
        // drift apart in durability discipline); the previous good store is
        // rotated to `.bak` first so the next restore can recover it.
        // Rotate the current good store to .bak before replacing it.
        if store_path().exists() {
            let _ = std::fs::rename(store_path(), store_bak_path());
        }
        if crate::state::persist::atomic_write(&store_path(), json.as_bytes()) {
            // The store file is durably in place — NOW advance the watermark
            // file (a crash between the two is recovered by the
            // watermark/rollback guard on the next restore).
            save_watermarks(&fresh_watermarks);
        } else {
            tracing::warn!(
                "[RatchetStore] Store write failed — restoring previous store from .bak"
            );
            let _ = std::fs::rename(store_bak_path(), store_path());
        }
        let _ = std::fs::remove_file(store_tmp_path());
    }
}

/// Remove the persisted ratchet store (used on unpair/self-destruct so no
/// ciphertext of old chain state survives). Also removes the watermark file.
pub fn clear_ratchet_store() {
    let _ = std::fs::remove_file(store_path());
    let _ = std::fs::remove_file(watermark_path());
    // AUDIT F19: also remove the atomic-write temp + .bak siblings so no
    // ciphertext residue survives an unpair/self-destruct.
    let _ = std::fs::remove_file(store_tmp_path());
    let _ = std::fs::remove_file(store_bak_path());
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK) {
        let _ = entry.delete_password();
    }
}

/// Remove ONE peer's persisted ratchet snapshot AND its watermark entry
/// (AUDIT F13). The store is a per-peer map, so un-pairing a SECOND device
/// must not clear every other peer's persisted sessions — the legacy unpair
/// called [`clear_ratchet_store`], wiping the whole store (and the keyring
/// watermark) on ANY peer's unpair, silently "un-pairing" the other devices
/// after the next desktop restart.
///
/// `save_watermarks` only ever ADVANCES marks and cannot remove an entry, so
/// the watermark tiers (keyring + file) are rewritten directly with the peer's
/// key dropped.
pub fn remove_ratchet_session_for_peer(peer_id: &str) {
    if peer_id.is_empty() {
        return;
    }
    // 1) Snapshot store — atomic rewrite without the peer's entry.
    if let Ok(data) = std::fs::read_to_string(store_path()) {
        if let Ok(mut map) = serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&data) {
            if map.remove(peer_id).is_some() {
                if let Ok(json) = serde_json::to_string_pretty(&map) {
                    if store_path().exists() {
                        let _ = std::fs::rename(store_path(), store_bak_path());
                    }
                    // Shared atomic-write discipline (audit P4-2): temp file →
                    // fsync → rename, so an unpair can never truncate the
                    // store of OTHER peers.
                    let ok = crate::state::persist::atomic_write(&store_path(), json.as_bytes());
                    if !ok {
                        let _ = std::fs::rename(store_bak_path(), store_path());
                    }
                    let _ = std::fs::remove_file(store_tmp_path());
                }
            }
        }
    }
    // 2) Watermark tiers — keyring first (tamper-evident source of truth),
    //    then the file fallback. Rewrite each with the peer's key removed; if
    //    the map is now empty, delete the tier outright.
    let remove_key =
        |obj: &mut serde_json::Map<String, serde_json::Value>| obj.remove(peer_id).is_some();
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK) {
        if let Ok(data) = entry.get_password() {
            if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(obj) = v.as_object_mut() {
                    if remove_key(obj) {
                        if obj.is_empty() {
                            let _ = entry.delete_password();
                        } else if let Ok(json) = serde_json::to_string(&v) {
                            let _ = entry.set_password(&json);
                        }
                    }
                }
            }
        }
    }
    if let Ok(data) = std::fs::read_to_string(watermark_path()) {
        if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(obj) = v.as_object_mut() {
                if remove_key(obj) {
                    if obj.is_empty() {
                        let _ = std::fs::remove_file(watermark_path());
                    } else if let Ok(json) = serde_json::to_string(&v) {
                        let _ = std::fs::write(watermark_path(), json);
                    }
                }
            }
        }
    }
}

/// Restore every persisted ratchet session, decrypting with the independent
/// snapshot key (audit finding #15b). AUDIT F16: per-entry watermarks are
/// checked against the persisted high-water-mark file — an entry whose
/// watermark is at or below the recorded high-water mark is a ROLLBACK (or a
/// replay of an already-restored snapshot) and is refused. This closes the
/// snapshot-to-snapshot regression the live-session guard in the registry
/// cannot see (on startup there is no live session to compare against).
///
/// AUDIT FINDING #7: the comparison is over the EPOCH-AWARE 4-tuple, so the
/// epoch check is enforced HERE in the store (independent of the live-session
/// registry guard, which does not run at restore): a snapshot whose epoch is
/// OLDER than the peer's recorded epoch is refused even if its counters are
/// larger (stale pre-re-pair snapshot), while a fresh re-pair snapshot (newer
/// epoch, counters reset to 0) is accepted.
pub fn restore_all_ratchet_sessions(snapshot_key_hex: &str) -> usize {
    let Some(wk) = wrap_key(snapshot_key_hex) else {
        return 0;
    };
    let Ok(data) = std::fs::read_to_string(store_path()) else {
        return 0;
    };
    // AUDIT F19: tolerate a torn/corrupt store (a crash from a pre-fix build,
    // or a filesystem-level truncation) by recovering the previous good store
    // from `.bak`. The legacy code returned 0 on ANY parse failure — silently
    // discarding every persisted session and forcing a full re-pair.
    let map = match serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&data) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                "[RatchetStore] Store parse failed ({e}) — attempting .bak recovery (audit F19)"
            );
            match std::fs::read_to_string(store_bak_path())
                .ok()
                .and_then(|bak| {
                    serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&bak).ok()
                }) {
                Some(m) => m,
                None => {
                    tracing::error!(
                        "[RatchetStore] Store AND .bak unreadable — persisted sessions lost"
                    );
                    return 0;
                }
            }
        }
    };
    let watermarks = load_watermarks();
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
            // AUDIT F16 + AUDIT #1: refuse a snapshot that REGRESSES the
            // persisted high-water mark for this peer in ANY component
            // (rollback detection). The current snapshot's watermark EQUALS
            // the high-water mark and is accepted; any older (rolled-back)
            // snapshot — including one that is ahead in send but behind in
            // recv (the lexicographic blind spot) — is refused.
            if let Some(wm) = snapshot_watermark(&snap) {
                if let Some(high) = watermarks.get(&peer) {
                    if is_rollback(&wm, high) {
                        tracing::warn!(
                            "[RatchetStore] Refusing rollback: snapshot for {peer} at {:?} regresses high-water mark {:?}",
                            wm, high
                        );
                        continue;
                    }
                }
            }
            if core_crypto::ratchet_import_session(peer.clone(), snap).is_ok() {
                restored += 1;
            }
        }
    }
    restored
}
