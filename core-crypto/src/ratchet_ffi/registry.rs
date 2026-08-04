//! Ratchet session REGISTRY + lock discipline (audit KYP-2026-02 #22 — extracted
//! from the former `ratchet_ffi.rs` monolith so the registry, the sync protocol
//! and the rekey-ack channel each live in their own module).

use crate::crypto::DoubleRatchetState;
use crate::error::KyberError;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use zeroize::Zeroizing;

/// Ratchet session registry keyed by peer identity fingerprint.
/// Each peer gets its own independent mutex (wrapped in Arc), preventing one
/// session's cryptographic operations from blocking another session.
/// The outer map lock is only held during lookup/clone — never during crypto ops.
///
/// LOCK ORDERING (audit KYP-2026-02 #23): the STRICT order across the four
/// process-global registries is `map → session` — the registry map lock is
/// acquired, the session `Arc` is cloned, and the map lock is dropped BEFORE
/// the per-session lock is acquired. `ratchet_import_session` follows the same
/// order (it drops the map lock before locking the live session). NEVER lock a
/// per-session mutex while holding a registry map lock. The other registries
/// (PAIRING_KEYPAIR, QUIC_CONNECTIONS/RECONNECT_STATES, SESSION_REGISTRY) are
/// single-lock structures with no cross-registry nesting, so this map→session
/// order is the only ordering invariant that must be preserved.
/// The session-registry map type: peer identity → per-session mutex.
/// Alias keeps the (complex) registry type readable (clippy::type_complexity).
pub(crate) type RatchetSessionMap = HashMap<String, Arc<Mutex<DoubleRatchetState>>>;
/// (x25519_pk, x25519_sk, mlkem_pk, mlkem_sk) caller-owned pairing keypair.
/// The private halves are `Zeroizing<Vec<u8>>` (audit #2 follow-up): passing
/// them through plain `Vec<u8>` let the raw secret bytes survive in freed heap
/// after the init consumed them into the (ZeroizeOnDrop) session keypair. As
/// `Zeroizing<Vec<u8>>` the buffers are wiped on drop — even on the error path
/// — so no raw private half ever lingers after this boundary.
pub(crate) type CallerKeypair = (Vec<u8>, Zeroizing<Vec<u8>>, Vec<u8>, Zeroizing<Vec<u8>>);

pub(crate) static RATCHET_SESSIONS: LazyLock<Mutex<RatchetSessionMap>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn ratchet_init_session_impl(
    peer_identity: &str,
    master_shared_secret: &[u8],
    is_initiator: bool,
    peer_x25519_pk: Option<&[u8]>,
    peer_mlkem_pk: Option<&[u8]>,
) -> Result<(), KyberError> {
    ratchet_init_session_with_keypair_impl(
        peer_identity,
        master_shared_secret,
        is_initiator,
        None,
        peer_x25519_pk,
        peer_mlkem_pk,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn ratchet_init_session_with_keypair_impl(
    peer_identity: &str,
    master_shared_secret: &[u8],
    is_initiator: bool,
    our_keypair: Option<CallerKeypair>,
    peer_x25519_pk: Option<&[u8]>,
    peer_mlkem_pk: Option<&[u8]>,
) -> Result<(), KyberError> {
    // AUDIT FINDING #6: the peer X25519 public key is validated to exactly 32
    // bytes BEFORE any `copy_from_slice` — the legacy code panicked (an
    // unwinding panic through the registry that poisoned the per-session Mutex)
    // when a malformed pairing body carried a 31/33-byte key. The ML-KEM-768
    // public key is validated to exactly 1184 bytes too (it is only caught
    // later, at encapsulation time, by `kyber768::PublicKey::from_bytes` — a
    // typed error, but better to reject at the boundary where the caller can
    // see it). Both now return a typed `KyberError::InvalidKeyLength` instead
    // of panicking or deferring.
    const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
    let x25519_arr = match peer_x25519_pk {
        Some(pk) => {
            if pk.len() != 32 {
                return Err(KyberError::InvalidKeyLength {
                    expected: 32,
                    got: pk.len() as u64,
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(pk);
            Some(arr)
        }
        None => None,
    };
    let peer_mlkem = match peer_mlkem_pk {
        Some(v) => {
            if v.len() != MLKEM768_PUBLIC_KEY_BYTES {
                return Err(KyberError::InvalidKeyLength {
                    expected: MLKEM768_PUBLIC_KEY_BYTES as u64,
                    got: v.len() as u64,
                });
            }
            Some(v.to_vec())
        }
        None => None,
    };
    let our_pair = match our_keypair {
        Some((xpk, xsk, mpk, msk)) => {
            let mut x25519_pk = [0u8; 32];
            let mut x25519_sk = [0u8; 32];
            if xpk.len() != 32 || xsk.len() != 32 {
                return Err(KyberError::InvalidKeyLength {
                    expected: 32,
                    got: xpk.len() as u64,
                });
            }
            x25519_pk.copy_from_slice(&xpk);
            x25519_sk.copy_from_slice(&xsk); // &xsk derefs the Zeroizing buffer
            crate::crypto::HybridKeyPair {
                x25519_pk,
                x25519_sk,
                mlkem_pk: mpk,
                // `msk` is Zeroizing — a transient plain Vec copy is moved
                // straight into the (ZeroizeOnDrop) session keypair, and the
                // source Zeroizing buffer itself is wiped when it drops.
                mlkem_sk: msk.to_vec(),
            }
        }
        None => crate::crypto::generate_hybrid_keypair(),
    };
    let ratchet = DoubleRatchetState::new_with_keypair(
        master_shared_secret,
        is_initiator,
        our_pair,
        x25519_arr,
        peer_mlkem,
    )?;
    let mut map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => {
            // Previous thread panicked while holding the map lock. Clear the
            // corrupted sessions and continue with a fresh map.
            let mut recovered = poisoned.into_inner();
            recovered.clear();
            recovered
        }
    };
    if map.contains_key(peer_identity) {
        return Err(KyberError::CryptoError(
            "Session already exists for this peer. Remove it first.".into(),
        ));
    }
    map.insert(peer_identity.to_string(), Arc::new(Mutex::new(ratchet)));
    Ok(())
}

pub fn ratchet_remove_session_impl(peer_identity: &str) -> bool {
    let mut map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.remove(peer_identity).is_some()
}

/// Bump the pairing epoch of the live session for `peer_identity` (audit
/// finding #2). Called by the Android app immediately after a RE-PAIR
/// (`ratchetRemoveSession` + fresh `ratchet_init_session_from_kem_handle`): the
/// fresh session starts at epoch 0, but the OLD pairing's snapshot on disk is
/// also epoch 0 (legacy format) — so the caller must bump the epoch so any
/// stale pre-re-pair snapshot can be recognized as cross-epoch and refused by
/// `ratchet_import_session_impl`. Returns the new epoch, or None when no live
/// session exists (nothing to bump).
pub fn ratchet_bump_pairing_epoch_impl(peer_identity: &str) -> Option<u64> {
    let session_arc = {
        let map = RATCHET_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        map.get(peer_identity).cloned()?
    }; // map lock dropped before the session lock
    let mut guard = session_arc.lock().ok()?;
    guard.pairing_epoch = guard.pairing_epoch.saturating_add(1);
    Some(guard.pairing_epoch)
}

pub fn ratchet_clear_all_sessions_impl() {
    let mut map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.clear();
}

pub fn ratchet_peer_ids_impl() -> Vec<String> {
    let map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.keys().cloned().collect()
}

pub(crate) fn with_ratchet_session<F, T>(peer_identity: &str, f: F) -> Result<T, KyberError>
where
    F: FnOnce(&mut DoubleRatchetState) -> Result<T, KyberError>,
{
    // Clone Arc while holding map lock, then drop map lock before crypto.
    // This prevents the outer lock from serializing operations across peers.
    let session_arc = {
        let map = RATCHET_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        map.get(peer_identity)
            .ok_or_else(|| {
                KyberError::CryptoError(format!(
                    "No ratchet session for peer '{}'. Call ratchet_init_session first.",
                    peer_identity
                ))
            })?
            .clone()
    }; // Map lock dropped here — crypto ops run without holding it
       // Detect poisoned mutex — if a previous thread panicked while holding the lock,
       // the ratchet state may be corrupted. Remove the session and return an error
       // rather than silently operating on potentially invalid key material.
    let result = match session_arc.lock() {
        Ok(mut session) => f(&mut session),
        Err(_poisoned) => Err(KyberError::CryptoError(format!(
            "Ratchet session for peer '{}' was corrupted (mutex poisoned). \
                 Session is marked for re-initialization — do not use until re-paired.",
            peer_identity
        ))),
    };
    result
}

pub fn ratchet_export_session_impl(peer_identity: &str) -> Result<Option<Vec<u8>>, KyberError> {
    let session_arc = {
        let map = RATCHET_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(peer_identity) {
            Some(s) => s.clone(),
            None => return Ok(None),
        }
    };
    let guard = session_arc
        .lock()
        .map_err(|_| KyberError::CryptoError("Ratchet session mutex poisoned".into()))?;
    let snap = guard.to_snapshot();
    // AUDIT #14: serialize into a Zeroizing buffer so the serde scratch
    // allocation (full session key material) is wiped on drop instead of
    // surviving in freed heap. The returned Vec is the caller's to zeroize.
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, &snap)
        .map_err(|e| KyberError::SerializationError(e.to_string()))?;
    Ok(Some(bytes.to_vec()))
}

/// Export a ratchet session and AEAD-wrap the serialized snapshot INSIDE Rust
/// (audit finding #5). Returns `(nonce, ciphertext)` — the raw serialized
/// state (chain keys, root key, our ML-KEM/X25519 secret halves, previous
/// keypairs, skip keys) NEVER crosses the UniFFI boundary as plaintext. The
/// Android app previously exported the full snapshot to the JVM heap, Base64'd
/// it, and re-entered Rust for wrapping — every 2.5s the complete session key
/// material sat in unzeroized, GC-promoted heap memory on a mobile device. With
/// this entry point the wrap key is the only secret that travels (the at-rest
/// wrap key, which is caller-owned by design); the snapshot itself stays in
/// Rust zeroizing memory throughout.
#[allow(clippy::type_complexity)] // (nonce, ciphertext) tuple; the UniFFI layer maps it to EncryptedPayload
pub fn ratchet_export_session_wrapped_impl(
    peer_identity: &str,
    wrap_key: &[u8],
) -> Result<Option<(Vec<u8>, Vec<u8>)>, KyberError> {
    if wrap_key.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: wrap_key.len() as u64,
        });
    }
    let Some(mut snap_bytes) = ratchet_export_session_impl(peer_identity)? else {
        return Ok(None);
    };
    // Fresh random 96-bit nonce per export — never reused.
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(wrap_key);
    let ct = crate::crypto::encrypt_chacha20(&key_arr, &nonce, &snap_bytes, &[])?;
    use zeroize::Zeroize;
    key_arr.zeroize();
    // AUDIT #14: wipe the plaintext snapshot buffer now that it has been
    // wrapped — the full session key material must not linger in heap memory.
    snap_bytes.zeroize();
    Ok(Some((nonce.to_vec(), ct)))
}

/// Full rollback watermark of a ratchet session (audit finding #2 follow-up).
/// `(pairing_epoch, ratchet_generation, send_message_count,
/// recv_message_count)`. The send chain is exactly as stateful as the recv
/// chain (chain key + counter advance on every `ratchet_encrypt`), so a live
/// session that has sent MORE than a snapshot contains must never be replaced
/// by it: the send chain would roll back and the derived message keys +
/// (generation, seq) nonces would be reused for NEW plaintext — the exact
/// IV-reuse class the nonce-generation redesign eliminates elsewhere. This
/// record is the SINGLE watermark representation shared by the UniFFI import
/// guard, the UniFFI export surface and the store restore paths, so the
/// comparisons cannot drift.
///
/// AUDIT #1 (HIGH, one-sided rollback): ordering is COMPONENT-WISE, never
/// lexicographic. A lexicographic order lets ONE chain's lead mask the other
/// chain's regression (send dominates recv, so a snapshot with send=50/recv=0
/// is judged "not a rollback" against a live session with send=0/recv=100 —
/// and the live receiving chain, positioned at seq 100, is replaced by the
/// snapshot's chain at seq 0: silent desync + an authenticated replay window
/// for messages 0..=99). `is_ahead_of` is therefore the monotonic partial
/// order (dominance), and the import guard refuses any snapshot that is not
/// at least as advanced as the live session in EVERY component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RatchetWatermark {
    pub pairing_epoch: u64,
    pub ratchet_generation: u32,
    pub send_message_count: u64,
    pub recv_message_count: u64,
}

impl RatchetWatermark {
    pub(crate) fn from_snapshot(snap: &crate::crypto::ratchet::RatchetSnapshot) -> Self {
        Self {
            pairing_epoch: snap.pairing_epoch,
            ratchet_generation: snap.ratchet_generation,
            send_message_count: snap.send_message_count,
            recv_message_count: snap.recv_message_count,
        }
    }

    pub(crate) fn from_live(state: &DoubleRatchetState) -> Self {
        Self {
            pairing_epoch: state.pairing_epoch,
            ratchet_generation: state.ratchet_generation,
            send_message_count: state.send.message_count,
            recv_message_count: state.recv.message_count,
        }
    }

    /// True when `self` strictly DOMINATES `other` component-wise: at least as
    /// advanced in every component (epoch, generation, send, recv) and
    /// strictly more advanced in at least one. This is a PARTIAL order — a
    /// watermark that is ahead in send but behind in recv is INCOMPARABLE
    /// with one that is ahead in recv but behind in send (neither dominates),
    /// and the import guard refuses that situation too: importing either one
    /// would roll back the chain the other leads. No caller can re-derive a
    /// lexicographic "one chain masks the other" interpretation (audit #1).
    pub fn is_ahead_of(&self, other: &Self) -> bool {
        self.pairing_epoch >= other.pairing_epoch
            && self.ratchet_generation >= other.ratchet_generation
            && self.send_message_count >= other.send_message_count
            && self.recv_message_count >= other.recv_message_count
            && *self != *other
    }

    /// True when `self` is at least as advanced as `other` in EVERY component
    /// (dominance or equality). The monotonic guard's acceptance predicate
    /// (audit #1): a snapshot import may proceed only when it satisfies this
    /// against the live session — any component regression refuses the import.
    pub(crate) fn dominates_or_equals(&self, other: &Self) -> bool {
        self.pairing_epoch >= other.pairing_epoch
            && self.ratchet_generation >= other.ratchet_generation
            && self.send_message_count >= other.send_message_count
            && self.recv_message_count >= other.recv_message_count
    }
}

/// Live-session watermark export (audit finding #2 follow-up). Lets callers
/// (Android snapshot persistence) record the monotonic high-water mark of the
/// LIVE session without importing anything, so a later restore can enforce the
/// same rollback bound the desktop's store enforces. Returns None when no
/// session exists for the peer.
pub fn ratchet_session_watermark_impl(
    peer_identity: &str,
) -> Result<Option<RatchetWatermark>, KyberError> {
    let session_arc = {
        let map = RATCHET_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(peer_identity) {
            Some(s) => s.clone(),
            None => return Ok(None),
        }
    };
    let guard = session_arc
        .lock()
        .map_err(|_| KyberError::CryptoError("Ratchet session mutex poisoned".into()))?;
    Ok(Some(RatchetWatermark::from_live(&guard)))
}

/// Parse the full 4-tuple watermark out of a serialized ratchet snapshot
/// (audit finding #2 follow-up). Centralizes the snapshot field mapping in ONE
/// place so the registry import guard, the desktop store's restore check and
/// the Android restore check all read the same fields. Parses tolerantly via
/// `serde_json::Value` — only the four watermark fields are required, so both
/// a full `RatchetSnapshot` JSON (as persisted/exported) and a minimal
/// watermark-only JSON (as used by the store restore test) yield a watermark.
/// `pairing_epoch` defaults to 0 when absent (legacy snapshots). Returns None
/// when the blob is not valid JSON or lacks the send/recv/generation fields.
pub fn ratchet_snapshot_watermark_impl(
    data: &[u8],
) -> Result<Option<RatchetWatermark>, KyberError> {
    let v: serde_json::Value =
        serde_json::from_slice(data).map_err(|e| KyberError::SerializationError(e.to_string()))?;
    let Some(gen) = v.get("ratchet_generation").and_then(|g| g.as_u64()) else {
        return Ok(None);
    };
    let Some(send) = v.get("send_message_count").and_then(|g| g.as_u64()) else {
        return Ok(None);
    };
    let Some(recv) = v.get("recv_message_count").and_then(|g| g.as_u64()) else {
        return Ok(None);
    };
    let epoch = v.get("pairing_epoch").and_then(|g| g.as_u64()).unwrap_or(0);
    Ok(Some(RatchetWatermark {
        pairing_epoch: epoch,
        ratchet_generation: gen as u32,
        send_message_count: send,
        recv_message_count: recv,
    }))
}

/// THE single rollback guard for snapshot import (audit finding #2
/// follow-up + AUDIT #1). A snapshot may be imported only when no live session
/// exists OR the snapshot is at least as advanced as the live session in
/// EVERY component. Returns `Ok(true)` when the import must be REFUSED. This
/// is the only comparison the import surface performs — the store layers
/// either call this (via `ratchet_import_session`) or mirror the same
/// `RatchetWatermark` ordering, so the guard and the watermark checks cannot
/// drift.
fn import_watermark_guard(
    peer_identity: &str,
    snap_wm: &RatchetWatermark,
) -> Result<bool, KyberError> {
    // AUDIT #2 (HIGH, pairing-epoch watermark): a snapshot from a DIFFERENT
    // pairing epoch must never be imported over a live session. After a re-pair
    // the live session is fresh (gen 0, new master secret) while the persisted
    // snapshot is from the OLD pairing (gen > 0, old key material). An epoch
    // mismatch is a hard refusal REGARDLESS of relative advancement: the
    // snapshot belongs to a different (now-dead) pairing and must never overlay
    // this session.
    let live_wm = {
        let map = RATCHET_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(peer_identity).cloned() {
            None => return Ok(false), // no live session — nothing to protect
            Some(session_arc) => {
                drop(map);
                match session_arc.lock() {
                    Ok(live) => RatchetWatermark::from_live(&live),
                    Err(_) => return Ok(false), // corrupted live session — allow re-import
                }
            }
        }
    };
    if live_wm.pairing_epoch != snap_wm.pairing_epoch {
        tracing::warn!(
            "[Import] Refusing snapshot for {peer_identity}: pairing epoch mismatch (snapshot epoch {}) — stale pre-re-pair snapshot refused (audit finding #2)",
            snap_wm.pairing_epoch,
        );
        return Ok(true);
    }
    // AUDIT #1 (HIGH): component-wise monotonic guard. The import is refused
    // unless the snapshot is at least as advanced as the live session in
    // EVERY component — `snap.send >= live.send AND snap.recv >= live.recv`
    // (and generation). The legacy lexicographic guard let the send chain's
    // lead mask a recv-chain regression (live send=0/recv=100, snapshot
    // send=50/recv=0 was judged "not a rollback" and imported, replacing the
    // live receiving chain positioned at seq 100 with the snapshot's at
    // seq 0 — silent desync + an authenticated replay window for the old
    // messages). `is_ahead_of`/`dominates_or_equals` encode the SAME partial
    // order, so no caller can re-derive a divergent interpretation.
    if !snap_wm.dominates_or_equals(&live_wm) {
        tracing::warn!(
            "[Import] Refusing snapshot for {peer_identity}: live watermark {:?} is not dominated by snapshot watermark {:?} — component-wise rollback guard refuses the import (audit finding #1)",
            live_wm, snap_wm,
        );
        return Ok(true);
    }
    Ok(false)
}

pub fn ratchet_import_session_impl(peer_identity: &str, data: &[u8]) -> Result<(), KyberError> {
    let snap: crate::crypto::ratchet::RatchetSnapshot =
        serde_json::from_slice(data).map_err(|e| KyberError::SerializationError(e.to_string()))?;
    let snap_wm = RatchetWatermark::from_snapshot(&snap);

    // Centralized COMPONENT-WISE monotonic watermark guard (epoch, generation,
    // SEND count, recv count). The legacy guard compared only (generation,
    // recv count) and was send-chain-blind; the first lexicographic 4-tuple
    // fix added send but let send MASK recv (one-sided chain rollback — audit
    // #1). This guard refuses unless the snapshot dominates the live session
    // in every component. The store-level watermark mirrors the same partial
    // order; this guard is the single source of truth for the FFI surface.
    if import_watermark_guard(peer_identity, &snap_wm)? {
        return Ok(());
    }

    let ratchet = DoubleRatchetState::from_snapshot(&snap)?;
    let mut map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.insert(peer_identity.to_string(), Arc::new(Mutex::new(ratchet)));
    Ok(())
}
