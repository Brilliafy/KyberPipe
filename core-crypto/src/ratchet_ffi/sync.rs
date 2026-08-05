//! Synchronize recovery protocol (audit KYP-2026-02 #22 — extracted from the
//! former `ratchet_ffi.rs` monolith): authenticated resync, per-peer rate
//! limiting, and the send/recv counter accessors.

use super::registry::with_ratchet_session;
use crate::crypto;
use crate::error::KyberError;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// AUDIT #4 (self-inflicted recovery DoS): the legacy budget was a HARD 15s
/// lockout stamped on every successful sync — a device that reconnects within
/// the window (or suffers a second gap burst) could not resync. It is now a
/// per-peer BURST budget: up to [`SYNC_RATE_BURST`] AUTHENTICATED syncs per
/// window are allowed (a reconnect storm needs several recovery round-trips),
/// while an unauthenticated attacker still cannot consume the budget (only
/// AEAD-verified syncs stamp it). Idempotent re-processing of an already-
/// applied sync costs nothing and does not stamp.
const SYNC_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(15);
const SYNC_RATE_BURST: usize = 3;

static LAST_SYNC_AT: std::sync::LazyLock<Mutex<HashMap<String, VecDeque<std::time::Instant>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

// ── Authenticated already-applied cache (audit F4 fix) ────────────────────
// The legacy already-applied fast-path consulted the live ratchet's replay
// state (`seen` set / recv counter) BEFORE the AEAD gate, so ANY packet — a
// garbage frame from an unauthenticated peer included — with a plausible
// (gen,seq) short-circuited to `Ok(0)` without consuming the rate budget and
// without being authenticated. This cache records the exact bytes of every
// packet that was AEAD-authenticated AND applied; a byte-identical re-send
// (the poll layer legitimately retries the same in-band carrier) hits the
// cache and is a no-op success, while a modified or never-authenticated
// packet falls through to the rate limiter and the AEAD gate.

/// Max applied-sync entries remembered per peer (bounded — the cache is a
/// same-peer idempotency hint, not a ledger).
const APPLIED_SYNC_CACHE_MAX: usize = 16;
/// How long an applied sync stays recognized. The desktop's poll retry window
/// is ~2.5s and the sync rate window is 15s; 120s covers any in-band retry
/// chain while staying bounded.
const APPLIED_SYNC_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(120);

struct AppliedSyncEntry {
    /// 64-bit FNV-1a digest of the exact packet bytes. Not cryptographic by
    /// design: authenticity is established by the AEAD on first application,
    /// and a collision only causes a spurious no-op of a packet that is
    /// byte-identical to one already applied.
    digest: u64,
    at: std::time::Instant,
}

static APPLIED_SYNC_CACHE: std::sync::LazyLock<Mutex<HashMap<String, VecDeque<AppliedSyncEntry>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn sync_digest(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Whether `data` was previously AUTHENTICATED and APPLIED for this peer.
fn already_applied_authenticated(peer: &str, data: &[u8]) -> bool {
    let digest = sync_digest(data);
    let mut map = APPLIED_SYNC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let queue = map.entry(peer.to_string()).or_default();
    let now = std::time::Instant::now();
    queue.retain(|e| now.duration_since(e.at) < APPLIED_SYNC_CACHE_TTL);
    queue.iter().any(|e| e.digest == digest)
}

/// Record that `data` was AEAD-verified AND applied for `peer`.
fn record_applied_sync(peer: &str, data: &[u8]) {
    let digest = sync_digest(data);
    let mut map = APPLIED_SYNC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let queue = map.entry(peer.to_string()).or_default();
    let now = std::time::Instant::now();
    queue.retain(|e| now.duration_since(e.at) < APPLIED_SYNC_CACHE_TTL);
    queue.push_back(AppliedSyncEntry { digest, at: now });
    while queue.len() > APPLIED_SYNC_CACHE_MAX {
        queue.pop_front();
    }
}

/// True when `peer` has consumed the whole authenticated-sync burst within the
/// current window. The queue is pruned of entries older than the window first,
/// so a window that has fully elapsed always permits a fresh sync.
fn sync_rate_limited(peer: &str) -> bool {
    let mut map = LAST_SYNC_AT.lock().unwrap_or_else(|e| e.into_inner());
    let queue = map.entry(peer.to_string()).or_default();
    let now = std::time::Instant::now();
    queue.retain(|t| now.duration_since(*t) < SYNC_RATE_WINDOW);
    queue.len() >= SYNC_RATE_BURST
}

/// Record a successfully AUTHENTICATED sync (audit KYP-2026-02 #20 — only
/// AEAD-verified syncs consume the budget).
fn stamp_sync(peer: &str) {
    let mut map = LAST_SYNC_AT.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(peer.to_string())
        .or_default()
        .push_back(std::time::Instant::now());
}

// NOTE (audit F2): the raw-number `ratchet_synchronize_session_impl` entry was
// DELETED. Every resync must go through `ratchet_process_synchronize_impl`,
// which authenticates the Synchronize packet (AEAD) before advancing the
// receive chain. A raw `target_seq` export bypassed the generation gate and
// let an unauthenticated caller jump the receive chain by up to SYNC_MAX_GAP,
// permanently discarding skip keys for in-flight messages.

pub fn ratchet_synchronize_packet_impl(
    peer_identity: &str,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| {
        let msg = crate::packets::KyberMessage::Synchronize {
            send_count: ratchet.send.message_count,
        };
        ratchet.ratchet_encrypt(msg.to_json()?.as_bytes())
    })
}

pub fn ratchet_synchronize_packet_binary_impl(peer_identity: &str) -> Result<Vec<u8>, KyberError> {
    ratchet_synchronize_packet_impl(peer_identity)?.to_binary()
}

pub fn ratchet_process_synchronize_impl(
    peer_identity: &str,
    data: &[u8],
) -> Result<u64, KyberError> {
    let msg = crate::crypto::RatchetEncryptedMessage::from_binary(data)?;
    if msg.nonce.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&msg.nonce);
    // The sync message's chain position (the sender's send-space seq) is
    // encoded in the nonce — this is the authenticated resync target.
    let sync_gen = u32::from_be_bytes([nonce_arr[0], nonce_arr[1], nonce_arr[2], nonce_arr[3]]);
    let sync_seq = u64::from_be_bytes([
        nonce_arr[4],
        nonce_arr[5],
        nonce_arr[6],
        nonce_arr[7],
        nonce_arr[8],
        nonce_arr[9],
        nonce_arr[10],
        nonce_arr[11],
    ]);

    // AUDIT #4 (idempotent consumer): an ALREADY-APPLIED sync is a no-op
    // SUCCESS, not an error. The same authenticated packet legitimately arrives
    // twice when a poll retried it in-band and the manifest loop reaches it
    // again, or when a lost poll response caused the desktop to re-send the
    // same carrier. Returning an error here made the poll layer log noise and
    // the (legacy) hard rate limiter rejected the legitimate duplicate.
    // Replays of an already-applied sync advance nothing, so treating them as
    // no-ops cannot weaken replay protection. This check runs BEFORE the rate
    // limiter so a duplicate never consumes the burst budget.
    //
    // AUDIT F4 FIX: the fast-path is now AUTHENTICATED. The legacy position-
    // based check (replay seen-set / below-recv-counter) fired for ANY packet
    // before the AEAD gate and before the rate limiter, so a garbage frame
    // from an unauthenticated peer with a plausible (gen,seq) short-circuited
    // to Ok(0) — bypassing the per-peer burst budget and leaking a receive-
    // position oracle. Only packets whose exact bytes were previously
    // AEAD-authenticated AND applied are cached; a byte-identical re-send is a
    // no-op, anything else falls through to the rate limiter + AEAD gate.
    let already_applied = already_applied_authenticated(peer_identity, data);
    if already_applied {
        return Ok(0);
    }

    // AUDIT #4: rate-limit CHECK per peer BEFORE touching the session, but the
    // budget is STAMPED only after the Synchronize is AUTHENTICATED (audit
    // KYP-2026-02 #20): the AEAD verification below is the only proof this is
    // a legitimate peer, so a garbage/injected payload must not consume the
    // resync budget for the real peer. The budget is a small BURST (3/window)
    // so a reconnect storm is not self-DoSed, unlike the legacy hard 15s
    // lockout.
    if sync_rate_limited(peer_identity) {
        return Err(KyberError::CryptoError(format!(
            "Synchronize rate-limited for peer {peer_identity} — burst ({SYNC_RATE_BURST}/{}) exhausted; retry in {}s",
            SYNC_RATE_WINDOW.as_secs(),
            SYNC_RATE_WINDOW.as_secs()
        )));
    }

    let result = with_ratchet_session(peer_identity, |ratchet| {
        // Shared rekey-aware decrypt for the live state or the trial clone.
        let do_decrypt =
            |r: &mut crate::crypto::DoubleRatchetState| -> Result<Vec<u8>, KyberError> {
                if msg.rekey_x25519_pk.is_some()
                    || msg.rekey_mlkem_pk.is_some()
                    || msg.rekey_ciphertext.is_some()
                {
                    let rekey_x = msg
                        .rekey_x25519_pk
                        .as_deref()
                        .map(|s| {
                            <[u8; 32]>::try_from(s).map_err(|_| KyberError::InvalidKeyLength {
                                expected: 32,
                                got: s.len() as u64,
                            })
                        })
                        .transpose()?;
                    r.ratchet_decrypt_with_rekey(
                        &nonce_arr,
                        &msg.ciphertext,
                        msg.rekey_ciphertext.as_deref(),
                        rekey_x.as_ref(),
                        msg.rekey_mlkem_pk.as_deref(),
                    )
                } else {
                    r.ratchet_decrypt(&nonce_arr, &msg.ciphertext)
                }
            };
        // Verify the decrypted payload is a Synchronize packet whose send_count
        // matches the nonce position (a mismatched packet is a protocol error).
        let verify = |plaintext: &[u8]| -> Result<(), KyberError> {
            let packet =
                crate::packets::KyberMessage::from_json(&String::from_utf8_lossy(plaintext))
                    .map_err(|_| {
                        KyberError::CryptoError(
                            "Decrypted Synchronize payload is not a valid packet".into(),
                        )
                    })?;
            let crate::packets::KyberMessage::Synchronize { send_count } = packet else {
                return Err(KyberError::CryptoError(
                    "Decrypted payload is not a Synchronize packet".into(),
                ));
            };
            if send_count != sync_seq {
                return Err(KyberError::CryptoError(format!(
                    "Synchronize send_count {send_count} does not match nonce position {sync_seq}"
                )));
            }
            Ok(())
        };

        let cur = ratchet.recv.message_count;
        let gap = seq_gap(cur, sync_seq);
        if sync_gen == ratchet.ratchet_generation && gap > ratchet.max_skip as u64 {
            // Real handoff gap beyond max_skip: position the chain at the sync
            // message's seq on a CLONE (bounded by SYNC_MAX_GAP + cumulative
            // budget + pending-rekey refusal inside resync_receiving_chain),
            // then decrypt. Only an AEAD-verified Synchronize commits the
            // clone — the recovery path is gated entirely on authentication.
            let mut trial = ratchet.clone();
            let skipped = trial.resync_receiving_chain(sync_seq)?;
            let plaintext = do_decrypt(&mut trial)?;
            verify(&plaintext)?;
            *ratchet = trial;
            Ok(skipped)
        } else if sync_gen >= ratchet.ratchet_generation.saturating_add(1) {
            // AUDIT #3 (cross-generation Synchronize): the sync packet is from
            // a HIGHER ratchet generation — the handoff dropped messages across
            // a rekey boundary. Recovery is possible ONLY if the rekey carrier
            // was received and the pending proposal derived (or the sync packet
            // itself carries the rekey payload at a boundary — the shared
            // rekey-aware decrypt below handles both). When it cannot
            // authenticate, this is NOT a benign no-op: the legacy else-branch
            // silently swallowed the failure (the poll layer retried into the
            // 15s rate limiter forever). Surface a DISTINCT typed error the
            // poll layer can escalate to a re-pair hint.
            //
            // AUDIT F3 (LOW/MEDIUM): the decrypt runs on a TRIAL CLONE, not
            // the live state. The rekey-aware decrypt internally COMMITS a
            // pending incoming rekey (generation bump, counter reset, seen-set
            // clear) as a side effect of authenticating on the pending chain —
            // running it against the live state meant an AEAD-valid-but-
            // malformed sync (payload that is not a Synchronize, or a
            // send_count mismatch) left the session at the new generation with
            // no rollback while the caller was told `Ok(0)`. On the trial,
            // decrypt + verify BOTH pass before the clone is committed to the
            // live session — the same trial-then-commit discipline as the
            // same-generation gap path above.
            let mut trial = ratchet.clone();
            match do_decrypt(&mut trial) {
                Ok(plaintext) => {
                    verify(&plaintext)?;
                    *ratchet = trial;
                    Ok(0)
                }
                Err(e) => Err(KyberError::CrossGenerationResyncRequired(format!(
                    "Synchronize from generation {sync_gen} (current {}) cannot be applied without the rekey carrier: {e} — a re-pair (or a fresh rekey exchange) is required",
                    ratchet.ratchet_generation
                ))),
            }
        } else {
            // Within max_skip: the normal decrypt path positions the chain; no
            // additional resync is needed. A stale target (already aligned) is
            // simply a no-op.
            let plaintext = do_decrypt(ratchet)?;
            verify(&plaintext)?;
            Ok(0)
        }
    });
    // Audit KYP-2026-02 #20 + AUDIT #4: stamp the burst budget ONLY after the
    // Synchronize authenticated (AEAD verified + packet type verified) AND
    // actually applied (the already-applied fast path returns before this). An
    // unauthenticated payload must not consume the per-peer resync budget.
    if result.is_ok() {
        stamp_sync(peer_identity);
        // AUDIT F4 FIX: remember the EXACT authenticated bytes so a legitimate
        // byte-identical re-send (poll retry / lost response) is recognized by
        // the authenticated fast-path instead of the removed position-based
        // check. Every `Ok` here means the packet authenticated AND applied.
        record_applied_sync(peer_identity, data);
    }
    result
}

pub fn ratchet_recv_count_impl(peer_identity: &str) -> Result<u64, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| Ok(ratchet.recv.message_count))
}

pub fn ratchet_send_count_impl(peer_identity: &str) -> Result<u64, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| Ok(ratchet.send.message_count))
}

fn seq_gap(cur: u64, target: u64) -> u64 {
    target.saturating_sub(cur)
}
