//! Ratchet-store watermark policy (audit P5-1 split).
//!
//! The per-peer (epoch, generation, send, recv) high-water mark is the
//! tamper-evidence layer for the snapshot store: it only ever moves
//! forward (keyring tier + sibling file), and a restored snapshot whose
//! watermark is at or below the recorded high-water mark is a rollback.

use std::path::PathBuf;

use super::keys::KEYRING_RATCHET_WATERMARK;

pub(crate) fn watermark_path() -> PathBuf {
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
pub(crate) type Watermark = (u64, u32, u64, u64);

/// Merge a fresh watermark into a high-water mark (audit #1). A NEWER pairing
/// epoch supersedes an older one wholesale (re-pair resets counters); within
/// one epoch the mark is the component-wise MAX so a send-chain lead can never
/// mask a recv-chain regression (or vice versa). Only ever moves forward.
pub(crate) fn merge_watermark(high: &mut Watermark, fresh: &Watermark) {
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
pub(crate) fn is_rollback(snap: &Watermark, high: &Watermark) -> bool {
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
pub(crate) fn advances(high: &Watermark, fresh: &Watermark) -> bool {
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
pub(crate) fn snapshot_watermark(snap: &[u8]) -> Option<Watermark> {
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
pub(crate) fn parse_watermark_map(
    v: &serde_json::Value,
) -> std::collections::HashMap<String, Watermark> {
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
pub(crate) fn load_watermarks() -> std::collections::HashMap<String, Watermark> {
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
pub(crate) fn save_watermarks(wms: &std::collections::HashMap<String, Watermark>) {
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
