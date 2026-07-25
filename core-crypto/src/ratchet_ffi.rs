use crate::crypto::{self, DoubleRatchetState};
use crate::error::KyberError;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Ratchet session registry keyed by peer identity fingerprint.
/// Each peer gets its own independent ratchet state, preventing
/// session corruption on reconnect / re-pairing.
pub(crate) static RATCHET_SESSIONS: OnceLock<Mutex<HashMap<String, Box<DoubleRatchetState>>>> =
    OnceLock::new();

pub(crate) fn get_ratchet_map() -> &'static Mutex<HashMap<String, Box<DoubleRatchetState>>> {
    RATCHET_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Initialize a Double Ratchet session for a given peer identity.
/// Returns an error if a session already exists for this peer
/// (caller must explicitly remove it first to prevent silent overwrite).
pub fn ratchet_init_session_impl(
    peer_identity: &str,
    master_shared_secret: &[u8],
    is_initiator: bool,
) -> Result<(), KyberError> {
    let mut map = get_ratchet_map().lock().unwrap_or_else(|e| e.into_inner());
    if map.contains_key(peer_identity) {
        return Err(KyberError::CryptoError(
            "Session already exists for this peer. Remove it first.".into(),
        ));
    }
    let ratchet = DoubleRatchetState::new(master_shared_secret, is_initiator)?;
    map.insert(peer_identity.to_string(), Box::new(ratchet));
    Ok(())
}

/// Remove a ratchet session for a given peer identity.
pub fn ratchet_remove_session_impl(peer_identity: &str) -> bool {
    get_ratchet_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(peer_identity)
        .is_some()
}

/// Encrypt a plaintext using the ratchet state for the specified peer.
pub fn ratchet_encrypt_message_impl(
    peer_identity: &str,
    plaintext: &[u8],
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    let mut map = get_ratchet_map().lock().unwrap_or_else(|e| e.into_inner());
    match map.get_mut(peer_identity) {
        Some(ref mut ratchet) => ratchet.ratchet_encrypt(plaintext),
        None => Err(KyberError::CryptoError(format!(
            "No ratchet session for peer '{}'. Call ratchet_init_session first.",
            peer_identity
        ))),
    }
}

/// Decrypt a ciphertext using the ratchet state for the specified peer.
pub fn ratchet_decrypt_message_impl(
    peer_identity: &str,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let mut map = get_ratchet_map().lock().unwrap_or_else(|e| e.into_inner());
    match map.get_mut(peer_identity) {
        Some(ref mut ratchet) => ratchet.ratchet_decrypt(nonce, ciphertext),
        None => Err(KyberError::CryptoError(format!(
            "No ratchet session for peer '{}'. Call ratchet_init_session first.",
            peer_identity
        ))),
    }
}
