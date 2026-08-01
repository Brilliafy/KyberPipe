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
pub fn ratchet_init_session_impl(
    peer_identity: &str,
    master_shared_secret: &[u8],
    is_initiator: bool,
    peer_x25519_pk: Option<&[u8]>,
    peer_mlkem_pk: Option<&[u8]>,
) -> Result<(), KyberError> {
    let x25519_arr = peer_x25519_pk.map(|pk| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk);
        arr
    });
    let ratchet = DoubleRatchetState::new(
        master_shared_secret,
        is_initiator,
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
        Err(_poisoned) => {
            Err(KyberError::CryptoError(format!(
                "Ratchet session for peer '{}' was corrupted (mutex poisoned). \
                 Session is marked for re-initialization — do not use until re-paired.",
                peer_identity
            )))
        }
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
pub fn ratchet_export_session_impl(
    peer_identity: &str,
) -> Result<Option<Vec<u8>>, KyberError> {
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
    let bytes = serde_json::to_vec(&snap)
        .map_err(|e| KyberError::SerializationError(e.to_string()))?;
    Ok(Some(bytes))
}

/// Restore a ratchet session from a previously exported (and decrypted)
/// snapshot. Replaces any existing session for the peer.
pub fn ratchet_import_session_impl(
    peer_identity: &str,
    data: &[u8],
) -> Result<(), KyberError> {
    let snap: crate::crypto::ratchet::RatchetSnapshot = serde_json::from_slice(data)
        .map_err(|e| KyberError::SerializationError(e.to_string()))?;
    let ratchet = DoubleRatchetState::from_snapshot(&snap)?;
    let mut map = match RATCHET_SESSIONS.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.insert(peer_identity.to_string(), Arc::new(Mutex::new(ratchet)));
    Ok(())
}

/// Resynchronize a ratchet session after the peer's authenticated Synchronize
/// message: re-derive skip keys for the missed range and advance the receiving
/// chain. Returns the number of messages skipped.
pub fn ratchet_synchronize_session_impl(
    peer_identity: &str,
    target_seq: u64,
) -> Result<u64, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| ratchet.resync_receiving_chain(target_seq))
}

/// The receiver's current recv counter, used to build a Synchronize request
/// when a gap exceeds max_skip.
pub fn ratchet_recv_count_impl(peer_identity: &str) -> Result<u64, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| Ok(ratchet.recv_message_count))
}

/// The sender's current send counter — included in every poll response so the
/// peer can detect a receive-chain gap exceeding max_skip and resync (the
/// Synchronize recovery path, audit finding #4).
pub fn ratchet_send_count_impl(peer_identity: &str) -> Result<u64, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| Ok(ratchet.send_message_count))
}
