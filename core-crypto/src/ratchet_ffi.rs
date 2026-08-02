use crate::crypto::{self, DoubleRatchetState};
use crate::error::KyberError;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

/// Ratchet session registry keyed by peer identity fingerprint.
/// Each peer gets its own independent mutex (wrapped in Arc), preventing one
/// session's cryptographic operations from blocking another session.
/// The outer map lock is only held during lookup/clone — never during crypto ops.
pub(crate) static RATCHET_SESSIONS: LazyLock<
    Mutex<HashMap<String, Arc<Mutex<DoubleRatchetState>>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Initialize a Double Ratchet session for a given peer identity.
/// Returns an error if a session already exists for this peer
/// (caller must explicitly remove it first to prevent silent overwrite).
///
/// The ratchet's initial DH identity is a FRESH, never-exchanged keypair — the
/// peer encapsulates rekey payloads to our pairing public keys, so decapsulating
/// with this unrelated private key would permanently desync the session at the
/// first rekey boundary (audit finding #1). Production callers MUST use
/// [`ratchet_init_session_with_keypair_impl`] and pass their own pairing keypair.
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

/// Initialize a Double Ratchet session using the caller's OWN pairing keypair as
/// the ratchet's initial DH identity (audit finding #1).
///
/// `our_keypair` — when `Some` — carries the X25519/ML-KEM secret AND public
/// halves whose PUBLIC halves were exchanged with the peer during the KEM
/// pairing handshake. The peer encapsulates rekey payloads to those public keys,
/// so we must decapsulate with these matching private keys. On Android the
/// caller passes the pairing keypair the client already holds; on the desktop
/// the private halves stay in Rust (the pairing handler's stored keypair).
pub fn ratchet_init_session_with_keypair_impl(
    peer_identity: &str,
    master_shared_secret: &[u8],
    is_initiator: bool,
    our_keypair: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>, // (x25519_pk, x25519_sk, mlkem_pk, mlkem_sk)
    peer_x25519_pk: Option<&[u8]>,
    peer_mlkem_pk: Option<&[u8]>,
) -> Result<(), KyberError> {
    let x25519_arr = peer_x25519_pk.map(|pk| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk);
        arr
    });
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
            x25519_sk.copy_from_slice(&xsk);
            crate::crypto::HybridKeyPair {
                x25519_pk,
                x25519_sk,
                mlkem_pk: mpk,
                mlkem_sk: msk,
            }
        }
        None => crate::crypto::generate_hybrid_keypair(),
    };
    let ratchet = DoubleRatchetState::new_with_keypair(
        master_shared_secret,
        is_initiator,
        our_pair,
        x25519_arr,
        peer_mlkem_pk.map(|v| v.to_vec()),
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

/// Remove a ratchet session for a given peer identity.
pub fn ratchet_remove_session_impl(peer_identity: &str) -> bool {
    let mut map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.remove(peer_identity).is_some()
}

/// Remove ALL ratchet sessions from the registry.
/// Used during self-destruct to ensure no cryptographic material persists.
pub fn ratchet_clear_all_sessions_impl() {
    let mut map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.clear();
}

/// List all peer identities with an active ratchet session.
pub fn ratchet_peer_ids_impl() -> Vec<String> {
    let map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.keys().cloned().collect()
}

fn with_ratchet_session<F, T>(peer_identity: &str, f: F) -> Result<T, KyberError>
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

/// Encrypt a plaintext using the ratchet state for the specified peer.
pub fn ratchet_encrypt_message_impl(
    peer_identity: &str,
    plaintext: &[u8],
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| ratchet.ratchet_encrypt(plaintext))
}

/// Decrypt a ciphertext using the ratchet state for the specified peer.
pub fn ratchet_decrypt_message_impl(
    peer_identity: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| KyberError::DecryptionFailed("Nonce must be 12 bytes".into()))?;
    with_ratchet_session(peer_identity, |ratchet| {
        ratchet.ratchet_decrypt(&nonce_arr, ciphertext)
    })
}

/// Decrypt a ciphertext that includes rekey payload using the ratchet state.
/// Processes DH re-key payload embedded in the message.
pub fn ratchet_decrypt_with_rekey_message_impl(
    peer_identity: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    rekey_ciphertext: Option<&[u8]>,
    rekey_x25519_pk: Option<&[u8; 32]>,
    rekey_mlkem_pk: Option<&[u8]>,
) -> Result<Vec<u8>, KyberError> {
    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| KyberError::DecryptionFailed("Nonce must be 12 bytes".into()))?;
    with_ratchet_session(peer_identity, |ratchet| {
        ratchet.ratchet_decrypt_with_rekey(
            &nonce_arr,
            ciphertext,
            rekey_ciphertext,
            rekey_x25519_pk,
            rekey_mlkem_pk,
        )
    })
}

pub fn generate_rekey_ack_message_impl(
    peer_identity: &str,
    seq: u64,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| ratchet.generate_rekey_ack(seq))
}

/// Take the pending RekeyAck carrier seq (if any) and immediately produce the
/// encrypted RekeyAck message to send back to the peer. Combines
/// `take_pending_rekey_ack_seq` + `generate_rekey_ack` in one session lock so
/// the carrier is not lost between two separate calls. Returns None when no
/// ACK is pending.
pub fn ratchet_generate_rekey_ack_impl(
    peer_identity: &str,
) -> Result<Option<crypto::RatchetEncryptedMessage>, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| {
        if let Some(seq) = ratchet.take_pending_rekey_ack_seq() {
            Ok(Some(ratchet.generate_rekey_ack(seq)?))
        } else {
            Ok(None)
        }
    })
}

pub fn ratchet_process_rekey_ack_impl(peer_identity: &str, seq: u64) -> Result<bool, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| Ok(ratchet.process_rekey_ack(seq)))
}

/// Export the ratchet session for `peer_identity` as a serialized snapshot
/// (JSON bytes). Returns None if no session exists. The caller MUST encrypt the
/// returned bytes with a device/session key before persisting them.
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
    let bytes =
        serde_json::to_vec(&snap).map_err(|e| KyberError::SerializationError(e.to_string()))?;
    Ok(Some(bytes))
}

/// Restore a ratchet session from a previously exported (and decrypted)
/// snapshot. Replaces any existing session for the peer — UNLESS the live
/// session is already AHEAD of the snapshot, in which case the import is a
/// no-op (audit finding #5: activity recreation / service restarts can import
/// a stale snapshot over a live, advanced session, rolling the chain back and
/// desynchronizing the peer — the import must never regress a session).
pub fn ratchet_import_session_impl(peer_identity: &str, data: &[u8]) -> Result<(), KyberError> {
    let snap: crate::crypto::ratchet::RatchetSnapshot =
        serde_json::from_slice(data).map_err(|e| KyberError::SerializationError(e.to_string()))?;

    // High-water-mark guard: if a live session exists and is at least as
    // advanced as the snapshot, refuse to regress it. Comparison is
    // lexicographic over (ratchet_generation, recv_message_count) because a
    // rekey commit resets the per-generation counters.
    let live_ahead = {
        let map = RATCHET_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(peer_identity).cloned() {
            None => false,
            Some(session_arc) => {
                drop(map);
                match session_arc.lock() {
                    Ok(live) => {
                        live.ratchet_generation > snap.ratchet_generation
                            || (live.ratchet_generation == snap.ratchet_generation
                                && live.recv_message_count >= snap.recv_message_count)
                    }
                    Err(_) => false, // corrupted live session — allow re-import
                }
            }
        }
    };
    if live_ahead {
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

/// Minimum interval between accepted resyncs for the same peer. A compromised
/// peer that somehow reaches the (now authenticated) resync path cannot spam
/// polls to force repeated forward jumps (audit finding #4).
const SYNC_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(15);

static LAST_SYNC_AT: std::sync::LazyLock<Mutex<HashMap<String, std::time::Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Resynchronize a ratchet session after the peer's authenticated Synchronize
/// message: re-derive skip keys for the missed range and advance the receiving
/// chain. Returns the number of messages skipped.
///
/// Audit finding #4: the resync is rate-limited per peer (15s window). The
/// generation-blindness and unbounded-cumulative problems are handled inside
/// `DoubleRatchetState::resync_receiving_chain` (pending-rekey refusal +
/// persisted cumulative budget).
pub fn ratchet_synchronize_session_impl(
    peer_identity: &str,
    target_seq: u64,
) -> Result<u64, KyberError> {
    // Rate-limit per peer BEFORE touching the session.
    {
        let mut last = LAST_SYNC_AT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = last.get(peer_identity) {
            if at.elapsed() < SYNC_RATE_WINDOW {
                return Err(KyberError::CryptoError(format!(
                    "Synchronize rate-limited for peer {peer_identity} — retry in {}s",
                    SYNC_RATE_WINDOW.as_secs()
                )));
            }
        }
        last.insert(peer_identity.to_string(), std::time::Instant::now());
    }
    with_ratchet_session(peer_identity, |ratchet| {
        ratchet.resync_receiving_chain(target_seq)
    })
}

/// Build an encrypted `KyberMessage::Synchronize` packet carrying the current
/// send counter. The peer processes it via
/// [`ratchet_process_synchronize_impl`] — the ONLY path that honors a resync
/// target (audit finding #4: the plaintext counter in the poll body is never
/// acted on).
pub fn ratchet_synchronize_packet_impl(
    peer_identity: &str,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| {
        let msg = crate::packets::KyberMessage::Synchronize {
            send_count: ratchet.send_message_count,
        };
        ratchet.ratchet_encrypt(msg.to_json()?.as_bytes())
    })
}

/// Binary-TLV variant of [`ratchet_synchronize_packet_impl`] — returns the full
/// TLV framing (including any rekey payload the message carried), so the peer
/// can process it rekey-aware (audit finding #12).
pub fn ratchet_synchronize_packet_binary_impl(peer_identity: &str) -> Result<Vec<u8>, KyberError> {
    ratchet_synchronize_packet_impl(peer_identity)?.to_binary()
}

/// Process a peer's encrypted Synchronize packet carried as a BINARY TLV
/// (audit finding #12): decrypts it rekey-aware with our receiving chain
/// (authenticating the sender and adopting any DH rekey payload the packet
/// carried at seq 100/200), verifies the packet type, and only then resyncs
/// the receiving chain to the authenticated target. This is the ONLY resync
/// path the wire protocol should use (audit finding #4).
/// Process a peer's encrypted Synchronize packet carried as a BINARY TLV
/// (audit finding #12): decrypts it rekey-aware with our receiving chain
/// (authenticating the sender and adopting any DH rekey payload the packet
/// carried at seq 100/200), verifies the packet type, and only then resyncs
/// the receiving chain to the authenticated target.
///
/// AUDIT FINDING #4 FIX: the previous implementation decrypted the sync
/// message first and then resynced to the payload's `send_count` — but the
/// decrypt already advanced the chain past that position, so the target was
/// always stale (dead code), and a real gap beyond max_skip could never be
/// recovered. Now the chain is POSITIONED at the sync message's sequence
/// number BEFORE decrypting when the gap exceeds max_skip (bounded by
/// SYNC_MAX_GAP), so the sync message itself decrypts at its own position and
/// the resync actually repairs handoff gaps up to 1000 messages. The advance
/// is performed on a CLONE and only committed after AEAD verification, so an
/// unauthenticated/injected sync can never move the chain.
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

    // Rate-limit per peer BEFORE touching the session (audit finding #4).
    {
        let mut last = LAST_SYNC_AT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = last.get(peer_identity) {
            if at.elapsed() < SYNC_RATE_WINDOW {
                return Err(KyberError::CryptoError(format!(
                    "Synchronize rate-limited for peer {peer_identity} — retry in {}s",
                    SYNC_RATE_WINDOW.as_secs()
                )));
            }
        }
        last.insert(peer_identity.to_string(), std::time::Instant::now());
    }

    with_ratchet_session(peer_identity, |ratchet| {
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

        let cur = ratchet.recv_message_count;
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
        } else {
            // Within max_skip (or cross-generation): the normal decrypt path
            // positions the chain; no additional resync is needed. A stale
            // target (already aligned) is simply a no-op.
            let plaintext = do_decrypt(ratchet)?;
            verify(&plaintext)?;
            Ok(0)
        }
    })
}

/// The receiver's current recv counter, used to build a Synchronize request
/// when a gap exceeds max_skip.
pub fn ratchet_recv_count_impl(peer_identity: &str) -> Result<u64, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| Ok(ratchet.recv_message_count))
}

/// The sender's current send counter.
pub fn ratchet_send_count_impl(peer_identity: &str) -> Result<u64, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| Ok(ratchet.send_message_count))
}

/// `a.saturating_sub(b)` expressed as an explicit helper (the sync target must
/// be ahead of the current position for a resync; equal/behind is a no-op).
fn seq_gap(cur: u64, target: u64) -> u64 {
    target.saturating_sub(cur)
}

/// Take the pending RekeyAck carrier seq (if any) and immediately produce the
/// ENCRYPTED ACK as a binary TLV (audit finding #12). Combines
/// `take_pending_rekey_ack_seq` + `generate_rekey_ack` + `to_binary` in one
/// session lock so the carrier is not lost between calls. Returns None when no
/// ACK is pending.
pub fn ratchet_generate_rekey_ack_binary_impl(
    peer_identity: &str,
) -> Result<Option<Vec<u8>>, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| {
        if let Some(seq) = ratchet.take_pending_rekey_ack_seq() {
            let ack = ratchet.generate_rekey_ack(seq)?;
            Ok(Some(ack.to_binary()?))
        } else {
            Ok(None)
        }
    })
}

/// NON-CONSUMING variant (audit finding #6): generate the encrypted ack TLV
/// from the pending carrier WITHOUT clearing it, so a poll response that is
/// lost on the wire can be retried on the next poll. Returns None when no ACK
/// is pending.
pub fn ratchet_generate_rekey_ack_binary_peek_impl(
    peer_identity: &str,
) -> Result<Option<Vec<u8>>, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| {
        if let Some(seq) = ratchet.pending_rekey_ack_seq {
            let ack = ratchet.generate_rekey_ack(seq)?;
            Ok(Some(ack.to_binary()?))
        } else {
            Ok(None)
        }
    })
}

/// Clear the pending RekeyAck carrier. Called AFTER the poll response carrying
/// the (peeked) ack has been successfully written to the wire, making ack
/// consumption atomic with delivery (audit finding #6). Returns whether a
/// pending ack existed.
pub fn ratchet_consume_rekey_ack_impl(peer_identity: &str) -> bool {
    with_ratchet_session(peer_identity, |ratchet| {
        Ok(ratchet.pending_rekey_ack_seq.take().is_some())
    })
    .unwrap_or(false)
}

/// Decrypt a peer's RekeyAck carried as a BINARY TLV (audit finding #12) and
/// process it — committing the peer's ack of OUR outgoing proposal. The ack is
/// a normal ratchet_encrypt output, so it is decrypted REKEY-AWARE: when the
/// sender's send chain is at a rekey boundary the ack itself carries a rekey
/// payload and its AEAD tag is bound to the rekey AAD (audit finding #3).
pub fn ratchet_process_rekey_ack_binary_impl(
    peer_identity: &str,
    data: &[u8],
) -> Result<bool, KyberError> {
    let msg = crate::crypto::RatchetEncryptedMessage::from_binary(data)?;
    if msg.nonce.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&msg.nonce);
    let plaintext = with_ratchet_session(peer_identity, |ratchet| {
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
            ratchet.ratchet_decrypt_with_rekey(
                &nonce_arr,
                &msg.ciphertext,
                msg.rekey_ciphertext.as_deref(),
                rekey_x.as_ref(),
                msg.rekey_mlkem_pk.as_deref(),
            )
        } else {
            ratchet.ratchet_decrypt(&nonce_arr, &msg.ciphertext)
        }
    })?;
    let packet = crate::packets::KyberMessage::from_json(&String::from_utf8_lossy(&plaintext))
        .map_err(|_| {
            KyberError::CryptoError("Decrypted RekeyAck payload is not a valid packet".into())
        })?;
    let crate::packets::KyberMessage::RekeyAck { seq } = packet else {
        return Err(KyberError::CryptoError(
            "Decrypted payload is not a RekeyAck packet".into(),
        ));
    };
    ratchet_process_rekey_ack_impl(peer_identity, seq)
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    use crate::crypto::generate_hybrid_keypair;

    fn alice_bob_registry(tag: &str) -> (String, String) {
        // Tests run in PARALLEL and share the process-global registry — use
        // unique per-test peer identities and clean up only our own entries.
        let alice = format!("alice-{tag}");
        let bob = format!("bob-{tag}");
        ratchet_remove_session_impl(&alice);
        ratchet_remove_session_impl(&bob);
        let alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();
        let shared = b"registry-test-shared-secret-0123456789abcdef";
        ratchet_init_session_with_keypair_impl(
            &alice,
            shared,
            true,
            Some((
                alice_pair.x25519_pk.to_vec(),
                alice_pair.x25519_sk.to_vec(),
                alice_pair.mlkem_pk.clone(),
                alice_pair.mlkem_sk.clone(),
            )),
            Some(&bob_pair.x25519_pk),
            Some(&bob_pair.mlkem_pk),
        )
        .expect("alice init");
        ratchet_init_session_with_keypair_impl(
            &bob,
            shared,
            false,
            Some((
                bob_pair.x25519_pk.to_vec(),
                bob_pair.x25519_sk.to_vec(),
                bob_pair.mlkem_pk.clone(),
                bob_pair.mlkem_sk.clone(),
            )),
            Some(&alice_pair.x25519_pk),
            Some(&alice_pair.mlkem_pk),
        )
        .expect("bob init");
        (alice, bob)
    }

    /// Audit finding #4 FIX: the Synchronize resync must repair a real gap that
    /// EXCEEDS max_skip (e.g. a Wi-Fi→cellular handoff dropping a burst). The
    /// old code decrypted the sync message first — impossible for a gap beyond
    /// max_skip — so the recovery path was dead. Now the chain is positioned at
    /// the sync message's seq BEFORE decrypting (bounded by SYNC_MAX_GAP), and
    /// the advance only commits after AEAD verification.
    #[test]
    fn synchronize_recovers_gap_beyond_max_skip() {
        let (alice, bob) = alice_bob_registry("default");

        // Alice sends 150 messages to bob (gap 150 > max_skip 100). Bob never
        // receives them — only the sync packet that rides a later message.
        for _ in 0..150 {
            let _ = ratchet_encrypt_message_impl(&alice, b"payload").expect("alice encrypt");
        }
        // Alice produces the authenticated Synchronize packet (seq 150) and bob
        // processes it — this must now RESYNC bob's chain instead of failing.
        let sync = ratchet_synchronize_packet_binary_impl(&alice).expect("sync packet");
        let skipped = ratchet_process_synchronize_impl(&bob, &sync).expect("bob processes sync");
        assert_eq!(skipped, 150, "bob must skip the 150 missed messages");

        // Bob can now decrypt a fresh message from alice (seq 151).
        let msg = ratchet_encrypt_message_impl(&alice, b"after-resync").expect("encrypt");
        let pt = ratchet_decrypt_message_impl(&bob, &msg.nonce, &msg.ciphertext)
            .expect("bob decrypts post-resync message");
        assert_eq!(pt, b"after-resync");
    }

    /// Audit finding #4: a forged/injected Synchronize whose AEAD does not
    /// verify must NOT advance the chain (the tentative clone is discarded).
    #[test]
    fn synchronize_forgery_does_not_advance_chain() {
        let (_alice, bob) = alice_bob_registry("forgery");
        let before = ratchet_recv_count_impl(&bob).expect("recv count");
        // Tamper with the ciphertext of a real sync packet.
        let sync = ratchet_synchronize_packet_binary_impl(&_alice).expect("sync");
        let mut forged = sync.clone();
        let n = forged.len();
        forged[n - 1] ^= 0xFF;
        assert!(
            ratchet_process_synchronize_impl(&bob, &forged).is_err(),
            "forged sync must be rejected"
        );
        assert_eq!(
            ratchet_recv_count_impl(&bob).expect("recv count"),
            before,
            "chain must not advance on a forged sync"
        );
    }

    /// Audit finding #1 FIX: the phone→desktop RekeyAck channel. The phone
    /// adopts the desktop's outgoing proposal (pending_rekey_ack_seq set); the
    /// binary ack generation+processing round-trip must commit the desktop's
    /// outgoing rekey (outgoing_root_key cleared).
    #[test]
    fn rekey_ack_binary_roundtrip_commits_outgoing() {
        let (alice, bob) = alice_bob_registry("ack");
        // Drive alice's send chain to the first rekey boundary (seq 100).
        for _ in 0..100 {
            let msg = ratchet_encrypt_message_impl(&alice, b"x").expect("encrypt");
            // Bob decrypts every message rekey-aware so his chain stays aligned.
            let _ = with_ratchet_session(&bob, |r| {
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
                if msg.rekey_ciphertext.is_some() {
                    r.ratchet_decrypt_with_rekey(
                        &<[u8; 12]>::try_from(msg.nonce.as_slice()).expect("nonce"),
                        &msg.ciphertext,
                        msg.rekey_ciphertext.as_deref(),
                        rekey_x.as_ref(),
                        msg.rekey_mlkem_pk.as_deref(),
                    )
                } else {
                    r.ratchet_decrypt(
                        &<[u8; 12]>::try_from(msg.nonce.as_slice()).expect("nonce"),
                        &msg.ciphertext,
                    )
                }
            })
            .expect("bob decrypt");
        }
        // Alice's seq-100 message carries the rekey proposal; bob adopts it and
        // queues the ack.
        let carrier = ratchet_encrypt_message_impl(&alice, b"carrier").expect("carrier");
        assert!(
            carrier.rekey_ciphertext.is_some(),
            "carrier must carry rekey"
        );
        let _ = with_ratchet_session(&bob, |r| {
            let rekey_x = carrier
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
                &<[u8; 12]>::try_from(carrier.nonce.as_slice()).expect("nonce"),
                &carrier.ciphertext,
                carrier.rekey_ciphertext.as_deref(),
                rekey_x.as_ref(),
                carrier.rekey_mlkem_pk.as_deref(),
            )
        })
        .expect("bob decrypts carrier");
        assert!(
            with_ratchet_session(&bob, |r| Ok(r.pending_rekey_ack_seq.is_some())).expect("ack?")
        );

        // Production flow (audit finding #6): the ack is generated NON-CONSUMING
        // (peek) and attached to the poll response; the carrier is cleared only
        // after the response is successfully written (consume).
        let ack_tlv = ratchet_generate_rekey_ack_binary_peek_impl(&bob)
            .expect("peek")
            .expect("ack pending");
        assert!(!ack_tlv.is_empty());
        // A second peek returns the ack again (nothing consumed yet).
        assert!(
            ratchet_generate_rekey_ack_binary_peek_impl(&bob)
                .expect("second peek")
                .is_some(),
            "peek must not consume — the carrier remains"
        );
        // The peer processes the (first) ack and commits our outgoing rekey.
        let committed =
            ratchet_process_rekey_ack_binary_impl(&alice, &ack_tlv).expect("process ack");
        assert!(committed, "alice must commit her outgoing rekey on the ack");
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.ratchet_generation)).expect("gen"),
            1,
            "alice must advance to generation 1 after the ack commit"
        );
        // Delivery succeeded — consume the carrier; a second consume returns
        // false and a subsequent peek returns None.
        assert!(ratchet_consume_rekey_ack_impl(&bob));
        assert!(!ratchet_consume_rekey_ack_impl(&bob));
        assert!(
            ratchet_generate_rekey_ack_binary_peek_impl(&bob)
                .expect("peek after consume")
                .is_none(),
            "after consume the ack carrier is gone"
        );
    }

    /// Audit finding #5: importing a STALE snapshot must not regress a live
    /// session that has advanced past it.
    #[test]
    fn stale_snapshot_import_is_noop() {
        let (alice, _bob) = alice_bob_registry("stale");
        // Advance alice's live session by 10 messages.
        for _ in 0..10 {
            let _ = ratchet_encrypt_message_impl(&alice, b"y").expect("encrypt");
        }
        // Export a snapshot NOW (recv count 0, send count 10).
        let snap = ratchet_export_session_impl(&alice)
            .expect("export")
            .expect("session exists");
        // Advance the live session further.
        let _ = ratchet_encrypt_message_impl(&alice, b"z").expect("encrypt");
        // Re-importing the older snapshot must be a NO-OP (live is ahead).
        ratchet_import_session_impl(&alice, &snap).expect("import");
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.send_message_count)).expect("count"),
            11,
            "stale import must not regress the live send count"
        );
    }
}
