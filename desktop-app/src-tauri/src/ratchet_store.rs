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
/// The pairing keypair (private halves) persisted across restarts (audit
/// KYP-2026-02 #6). Previously the keypair was regenerated on EVERY app mount,
/// rotating the identity the phone pins and invalidating any in-flight pairing
/// QR. The OS keyring is the at-rest store; the private halves live in Rust
/// state (never the renderer).
const KEYRING_PAIRING_KEYPAIR: &str = "pairing_keypair";
/// KEYRING-backed rollback watermark (audit F16 follow-up). The watermark is
/// stored in the OS keyring — a same-user attacker who can rewrite
/// `ratchet_sessions.json` (and its sibling watermark FILE) cannot rewrite the
/// keyring entry without OS credential-store approval. The file is kept as a
/// fallback for keyring-less environments; on restore the HIGHER of the two is
/// the effective high-water mark.
const KEYRING_RATCHET_WATERMARK: &str = "ratchet_watermark";
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

/// Load the session key from the OS keyring (hex-encoded), if present. Used on
/// startup (audit F11) to re-create the desktop session-key handle so
/// session-key material survives restarts — the handle is otherwise only set
/// during a live SAS confirmation.
pub fn session_key_from_keyring() -> Option<String> {
    keyring::Entry::new("kyberpipe", KEYRING_SESSION_KEY)
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|s| !s.is_empty())
}

/// Persist the pairing keypair (hex-encoded JSON) in the OS keyring so the
/// identity survives restarts (audit KYP-2026-02 #6). Called by the
/// `generate_keypair` command after generating/regenerating a keypair.
///
/// Audit KYP-2026-02 #7 follow-up: the transient hex encoding of the private
/// halves (and the serialized JSON that embeds them) is zeroized before the
/// buffers are dropped, so the at-rest keyring copy is the only survivor.
pub fn store_pairing_keypair_to_keyring(pair: &core_crypto::PqKeyPair) {
    use zeroize::Zeroize;
    let mut x25519_sk_hex = hex::encode(&pair.x25519_sk);
    let mut mlkem_sk_hex = hex::encode(&pair.mlkem_sk);
    let mut json = serde_json::json!({
        "x25519_pk": hex::encode(&pair.x25519_pk),
        "x25519_sk": &x25519_sk_hex,
        "mlkem_pk": hex::encode(&pair.mlkem_pk),
        "mlkem_sk": &mlkem_sk_hex,
    })
    .to_string();
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_PAIRING_KEYPAIR) {
        let _ = entry.set_password(&json);
    }
    // Zeroize the transient secret-bearing buffers (hex strings + the JSON
    // string that serialized them) before they are dropped.
    x25519_sk_hex.zeroize();
    mlkem_sk_hex.zeroize();
    unsafe {
        for b in json.as_bytes_mut() {
            *b = 0;
        }
    }
}

/// Load the persisted pairing keypair from the OS keyring, if present.
pub fn load_pairing_keypair_from_keyring() -> Option<core_crypto::PqKeyPair> {
    let stored = keyring::Entry::new("kyberpipe", KEYRING_PAIRING_KEYPAIR)
        .ok()?
        .get_password()
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&stored).ok()?;
    let pk = hex::decode(v.get("x25519_pk")?.as_str()?).ok()?;
    let sk = hex::decode(v.get("x25519_sk")?.as_str()?).ok()?;
    let mpk = hex::decode(v.get("mlkem_pk")?.as_str()?).ok()?;
    let msk = hex::decode(v.get("mlkem_sk")?.as_str()?).ok()?;
    if pk.is_empty() || sk.is_empty() || mpk.is_empty() || msk.is_empty() {
        return None;
    }
    Some(core_crypto::PqKeyPair {
        x25519_pk: pk,
        x25519_sk: sk,
        mlkem_pk: mpk,
        mlkem_sk: msk,
    })
}

/// Remove the persisted pairing keypair (unpair / self-destruct path).
pub fn clear_pairing_keypair_from_keyring() {
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_PAIRING_KEYPAIR) {
        let _ = entry.delete_password();
    }
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
    let hex_key = hex::encode(bytes);
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
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dir);
    dir.join("ratchet_sessions.json")
}

/// SEPARATE, tamper-evident high-water-mark file (audit F16). Written on every
/// successful persist; read before restore. A same-user process that swaps
/// `ratchet_sessions.json` for an older copy cannot regress this file (it only
/// ever moves forward), so per-entry watermarks below it are refused.
fn watermark_path() -> PathBuf {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dir);
    dir.join("ratchet_watermarks.json")
}

/// Per-peer monotonic watermark: `(pairing_epoch, ratchet_generation,
/// send_message_count, recv_message_count)`. An older watermark means an older
/// (potentially rolled-back) snapshot.
///
/// AUDIT FINDING #7: the watermark is EPOCH-AWARE. The legacy 3-tuple dropped
/// `pairing_epoch`, so after a re-pair the fresh session (epoch 1, counters
/// reset to 0) was compared against the OLD epoch-0 high-water (large
/// counters) and REFUSED as a "rollback" — every re-pair followed by a restart
/// lost the session. A newer epoch always outranks an older one regardless of
/// counters (re-pair is accepted), while a stale pre-re-pair snapshot (old
/// epoch, even with large counters) is still refused against the recorded
/// higher-epoch watermark.
///
/// AUDIT #1 (HIGH, one-sided rollback): WITHIN one epoch the ordering is
/// COMPONENT-WISE, never lexicographic. The legacy lexicographic 4-tuple let
/// the send chain's lead mask a recv-chain regression: a snapshot with
/// send=50/recv=0 was judged "not below" a high-water of send=0/recv=100 and
/// restored, rolling the receiving chain back (silent desync + authenticated
/// replay window). The helpers below (`dominates`, `merge_watermark`,
/// `is_rollback`) encode the same partial order the Rust registry guard and
/// the Kotlin store enforce, so the three cannot drift.
type Watermark = (u64, u32, u64, u64);

/// Merge a fresh watermark into a high-water mark (audit #1). A NEWER pairing
/// epoch supersedes an older one wholesale (re-pair resets counters); within
/// one epoch the mark is the component-wise MAX so a send-chain lead can never
/// mask a recv-chain regression (or vice versa). Only ever moves forward.
fn merge_watermark(high: &mut Watermark, fresh: &Watermark) {
    if fresh.0 > high.0 {
        *high = *fresh;
        return;
    }
    if fresh.0 < high.0 {
        return;
    }
    high.1 = high.1.max(fresh.1);
    high.2 = high.2.max(fresh.2);
    high.3 = high.3.max(fresh.3);
}

/// True when a snapshot watermark is a ROLLBACK relative to the recorded
/// high-water mark (audit #1 + finding #7). A snapshot from an OLDER pairing
/// epoch is stale (refuse); a SAME-epoch snapshot that is behind in ANY of
/// generation/send/recv is a rollback (refuse). A snapshot from a NEWER epoch
/// (re-pair, counters reset) is accepted. Equal = the current snapshot.
fn is_rollback(snap: &Watermark, high: &Watermark) -> bool {
    if snap.0 < high.0 {
        return true;
    }
    if snap.0 > high.0 {
        return false;
    }
    snap.1 < high.1 || snap.2 < high.2 || snap.3 < high.3
}

/// True when `fresh` ADVANCES the recorded high-water mark `high` (component-
/// wise, audit #1): a newer pairing epoch, or a same-epoch component that
/// moved forward. Used by the persist path's early-out so a keyring write only
/// happens when something actually moved.
fn advances(high: &Watermark, fresh: &Watermark) -> bool {
    if fresh.0 > high.0 {
        return true;
    }
    if fresh.0 < high.0 {
        return false;
    }
    fresh.1 > high.1 || fresh.2 > high.2 || fresh.3 > high.3
}

/// Extract the watermark from a DECRYPTED ratchet snapshot JSON. The snapshot
/// is AEAD-authenticated, so a watermark extracted from a validly-decrypted
/// blob is authentic — an attacker cannot craft a snapshot with a forged
/// watermark without the wrap key.
///
/// AUDIT #2 (follow-up): the field mapping is centralized in the core-crypto
/// registry (`ratchet_snapshot_watermark`), so the desktop store and the
/// UniFFI import guard read the same fields and cannot drift. The store keeps
/// the FULL 4-tuple high-water format INCLUDING `pairing_epoch` (audit finding
/// #7); legacy 3-element persisted entries parse with epoch 0.
fn snapshot_watermark(snap: &[u8]) -> Option<Watermark> {
    core_crypto::ratchet_snapshot_watermark(snap.to_vec())
        .ok()?
        .map(|wm| {
            (
                wm.pairing_epoch,
                wm.ratchet_generation,
                wm.send_message_count,
                wm.recv_message_count,
            )
        })
}

/// Read the persisted per-peer watermarks (default empty).
/// Parse a watermark JSON map (both the file and the keyring entry use the
/// same shape: `{ peer: [epoch, gen, send, recv] }`). Legacy 3-element entries
/// `[gen, send, recv]` parse with epoch 0 (audit finding #7 — the store
/// upgraded the persisted format in place).
fn parse_watermark_map(v: &serde_json::Value) -> std::collections::HashMap<String, Watermark> {
    let mut out = std::collections::HashMap::new();
    let Some(obj) = v.as_object() else {
        return out;
    };
    for (peer, wm) in obj {
        let Some(arr) = wm.as_array() else { continue };
        match arr.as_slice() {
            // 4-tuple: [epoch, gen, send, recv]
            [e, g, s, r] => {
                if let (Some(e), Some(g), Some(s), Some(r)) =
                    (e.as_u64(), g.as_u64(), s.as_u64(), r.as_u64())
                {
                    out.insert(peer.clone(), (e, g as u32, s, r));
                }
            }
            // Legacy 3-tuple: [gen, send, recv] → epoch 0.
            [g, s, r] => {
                if let (Some(g), Some(s), Some(r)) = (g.as_u64(), s.as_u64(), r.as_u64()) {
                    out.insert(peer.clone(), (0, g as u32, s, r));
                }
            }
            _ => continue,
        }
    }
    out
}

/// Read the persisted per-peer watermarks (audit F16). The KEYRING tier is the
/// tamper-evident source of truth (a same-user attacker who can rewrite
/// `ratchet_sessions.json` AND its sibling file cannot rewrite the keyring
/// entry without OS credential-store approval). The sibling file is a fallback
/// for keyring-less environments. The effective watermark per peer is the HIGHER
/// of the two tiers — the rollback guard is monotonic and can only move forward.
fn load_watermarks() -> std::collections::HashMap<String, Watermark> {
    let mut out: std::collections::HashMap<String, Watermark> = std::collections::HashMap::new();
    // Keyring tier (tamper-evident).
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK) {
        if let Ok(data) = entry.get_password() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                for (peer, wm) in parse_watermark_map(&v) {
                    let e = out.entry(peer).or_insert((0, 0, 0, 0));
                    merge_watermark(e, &wm);
                }
            }
        }
    }
    // File tier (fallback for keyring-less environments).
    if let Ok(data) = std::fs::read_to_string(watermark_path()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            for (peer, wm) in parse_watermark_map(&v) {
                let e = out.entry(peer).or_insert((0, 0, 0, 0));
                merge_watermark(e, &wm);
            }
        }
    }
    out
}

/// Persist the per-peer watermarks (audit F16). Only ever moves forward.
fn save_watermarks(wms: &std::collections::HashMap<String, Watermark>) {
    if wms.is_empty() {
        return;
    }
    // AUDIT F16 follow-up (perf): early-out when NOTHING advanced. This is
    // called on every poll (2.5 s cadence from the phone via
    // `persist_all_ratchet_sessions`), and a Secret-Service keyring write is an
    // OS RPC — doing it when every watermark is unchanged would add per-poll
    // keyring overhead (and zbus/D-Bus connection churn). Compare against the
    // CURRENTLY persisted high-water mark (keyring + file tiers merged) and
    // only write when at least one peer moved forward.
    let current = load_watermarks();
    if wms
        .iter()
        .all(|(peer, wm)| current.get(peer).is_some_and(|c| !advances(c, wm)))
    {
        return;
    }
    let mut obj = serde_json::Map::new();
    for (peer, (e, g, s, r)) in wms {
        obj.insert(peer.clone(), serde_json::json!([e, g, s, r]));
    }
    if let Ok(json) = serde_json::to_string(&serde_json::Value::Object(obj)) {
        // Keyring tier FIRST — a same-user attacker cannot rewrite it. When it
        // succeeds it is the source of truth; the file is written too, as a
        // best-effort fallback for keyring-less environments so the two stay in
        // lockstep.
        let keyring_ok = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK)
            .and_then(|e| e.set_password(&json))
            .is_ok();
        let _ = std::fs::write(watermark_path(), json);
        if keyring_ok {
            tracing::debug!("[RatchetStore] watermark advanced in keyring + file");
        }
    }
}

/// Save every ratchet session's snapshot, encrypted with the independent
/// snapshot key (NOT the session key — audit finding #15b). AUDIT F16: each
/// entry's AEAD-authenticated watermark is recorded in the separate watermark
/// file AFTER a successful write, so a full-file rollback is detected on the
/// next restore.
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
        let _ = std::fs::write(store_path(), json);
        // The store file is fully written — NOW advance the watermark file.
        save_watermarks(&fresh_watermarks);
    }
}

/// Remove the persisted ratchet store (used on unpair/self-destruct so no
/// ciphertext of old chain state survives). Also removes the watermark file.
pub fn clear_ratchet_store() {
    let _ = std::fs::remove_file(store_path());
    let _ = std::fs::remove_file(watermark_path());
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK) {
        let _ = entry.delete_password();
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
    let Ok(map) = serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&data) else {
        return 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// AUDIT F16 + FINDING #7 + AUDIT #1: the watermark is extracted from the
    /// AEAD-authenticated snapshot and the rollback-refusal predicate is
    /// COMPONENT-WISE — it rejects a snapshot that regresses the high-water
    /// mark in ANY of generation/send/recv (equal = the current snapshot,
    /// accepted). The tuple is EPOCH-AWARE: a fresh re-pair snapshot (newer
    /// epoch, counters reset) outranks an old epoch's large counters.
    #[test]
    fn watermark_is_monotonic_and_rollback_is_refused() {
        let newer =
            br#"{"ratchet_generation":2,"send_message_count":105,"recv_message_count":102}"#;
        let older = br#"{"ratchet_generation":2,"send_message_count":100,"recv_message_count":99}"#;
        let current =
            br#"{"ratchet_generation":2,"send_message_count":105,"recv_message_count":102}"#;
        // AUDIT #1: ahead in send but BEHIND in recv — the lexicographic blind
        // spot that must now be refused.
        let one_sided =
            br#"{"ratchet_generation":2,"send_message_count":150,"recv_message_count":0}"#;

        let w_newer = snapshot_watermark(newer).expect("newer watermark");
        let w_older = snapshot_watermark(older).expect("older watermark");
        let w_current = snapshot_watermark(current).expect("current watermark");
        let w_one_sided = snapshot_watermark(one_sided).expect("one-sided watermark");

        // Legacy JSON (no pairing_epoch) parses with epoch 0.
        assert_eq!(w_newer, (0, 2, 105, 102));
        assert_eq!(w_newer, w_current);

        // The restore predicate: refuse any snapshot that regresses the mark in
        // ANY component, accept equal (the current snapshot after a normal
        // restart) and accept strictly-forward snapshots.
        let high = w_newer;
        assert!(is_rollback(&w_older, &high), "older snapshot refused");
        assert!(
            is_rollback(&w_one_sided, &high),
            "one-sided snapshot (send ahead, recv behind) must be refused — audit #1"
        );
        assert!(
            !is_rollback(&w_current, &high),
            "current snapshot equals the high-water mark and is accepted"
        );
        assert!(!is_rollback(&w_newer, &high));

        // AUDIT FINDING #7: a stale pre-re-pair snapshot (epoch 0, even with
        // LARGER counters) must be refused against a re-paired epoch-1
        // high-water; a fresh epoch-1 snapshot (counters reset) must be
        // accepted.
        let re_paired_high = (1u64, 0u32, 0u64, 0u64);
        let stale_epoch0 = (0u64, 2u32, 999u64, 999u64);
        assert!(
            is_rollback(&stale_epoch0, &re_paired_high),
            "a stale epoch-0 snapshot with larger counters must still be refused after a re-pair"
        );
        let fresh_epoch1 = (1u64, 0u32, 0u64, 0u64);
        assert!(
            !is_rollback(&fresh_epoch1, &re_paired_high),
            "a fresh re-pair snapshot (epoch 1, counters reset) must be accepted"
        );

        // merge_watermark: a one-sided fresh watermark must NOT clobber the
        // recv lead — the merged envelope keeps BOTH chains' maxima.
        let mut merged = high;
        merge_watermark(&mut merged, &w_one_sided);
        assert_eq!(merged, (0, 2, 150, 102));
        // advances() correctly reports both directions.
        assert!(advances(&high, &merged));
        assert!(!advances(&high, &w_current));
    }

    /// AUDIT F16: a malformed snapshot (missing watermark fields) yields no
    /// watermark — restore treats it as uncheckable and still attempts import
    /// (the AEAD tag already authenticated the bytes; missing counters only
    /// weaken the rollback check, never widen the import surface).
    #[test]
    fn watermark_requires_all_three_fields() {
        let missing_send = br#"{"ratchet_generation":1,"recv_message_count":5}"#;
        assert!(snapshot_watermark(missing_send).is_none());
        let empty = b"{}";
        assert!(snapshot_watermark(empty).is_none());
        let garbage = b"not json";
        assert!(snapshot_watermark(garbage).is_none());
    }
}

#[cfg(test)]
mod keyring_watermark_tests {
    use super::*;

    /// AUDIT F16 (follow-up): the KEYRING tier of the rollback watermark must
    /// actually be WRITTEN and READ — the earlier "fix" only declared the
    /// constant and never populated it, leaving a same-user file-swap attacker
    /// able to defeat rollback detection. This test drives the real
    /// `save_watermarks`/`load_watermarks` path and asserts the keyring entry
    /// round-trips. Gracefully skips when no keyring backend is available
    /// (headless CI).
    #[test]
    fn keyring_watermark_is_written_and_read() {
        // Graceful skip when the keyring backend is absent or stuck.
        let probe = {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(
                    keyring::Entry::new("kyberpipe", "watermark_probe")
                        .and_then(|e| e.set_password("probe"))
                        .is_ok(),
                );
            });
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .unwrap_or(false)
        };
        if !probe {
            eprintln!("Skipping keyring watermark test: no keyring backend available");
            return;
        }
        let _ =
            keyring::Entry::new("kyberpipe", "watermark_probe").and_then(|e| e.delete_password());

        // Write a watermark via the real persistence path.
        let mut wms = std::collections::HashMap::new();
        // Epoch-aware 4-tuple (audit finding #7).
        wms.insert("peer-a".to_string(), (3u64, 2u32, 200u64, 150u64));
        save_watermarks(&wms);

        // The keyring entry must exist and contain the watermark.
        let stored = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK)
            .and_then(|e| e.get_password())
            .expect("keyring watermark must be written");
        let parsed: serde_json::Value =
            serde_json::from_str(&stored).expect("keyring watermark must be valid JSON");
        assert_eq!(
            parsed["peer-a"],
            serde_json::json!([3, 2, 200, 150]),
            "keyring watermark must contain the saved watermark"
        );

        // load_watermarks must merge the keyring tier back.
        let loaded = load_watermarks();
        assert_eq!(
            loaded.get("peer-a"),
            Some(&(3u64, 2u32, 200u64, 150u64)),
            "load_watermarks must read the keyring tier"
        );

        // Cleanup.
        let _ = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK)
            .and_then(|e| e.delete_password());
        let _ = std::fs::remove_file(watermark_path());
    }
}
