pub mod crypto;
pub mod error;
pub mod network;
pub mod packets;
pub mod qr_scanner;
pub mod quic_app;
pub mod telemetry;

pub mod crypto_api;
pub mod ffi;
pub mod kem_handle;
pub mod network_api;
pub mod p2p_group;
pub mod pairing_api;
pub mod quic_bridge;
pub mod ratchet_ffi;
pub mod session_handle;
pub mod system_net;

// Re-export domain API modules so callers can use `crate::function_name`
// and UniFFI bindings see a flat namespace.
pub use crypto_api::*;
pub use network_api::*;
pub use pairing_api::*;

pub mod destruct;
pub mod records;
pub mod runtime;

pub use destruct::*;
pub use records::*;
pub use runtime::*;

use error::KyberError;

uniffi::setup_scaffolding!();

/// Post-quantum hybrid keypair crossing the UniFFI boundary. Audit finding
/// #16: the private halves must not persist in freed heap after unpairing or
/// self-destruct. UniFFI's Record derive cannot coexist with a Drop impl
/// (its field move-out is incompatible with Drop), so zeroization is done
/// explicitly: every disposal path (desktop `CryptoState::set_keypair(None)`,
/// `clear_all_pairing`, self-destruct, the process-global registry) calls
/// `zeroize()` on the pair before dropping it.
/// Process-global pairing keypair registry. `generate_pq_pairing_public` stores
/// the FULL keypair (including private halves) here so a pairing handler can
/// decapsulate the peer's KEM ciphertext. Previously the private half was built
/// into a temporary and dropped — a latent API trap (audit finding #14).
/// Initialize a Double Ratchet session using the caller's OWN pairing keypair
/// as the ratchet's initial DH identity. This is the correct production entry
/// point (audit finding #1): the peer encapsulates rekey payloads to our
/// pairing public keys, so decapsulation must use the matching pairing private
/// keys — never a fresh, unexchanged keypair.
///
/// `our_x25519_pk`, `our_x25519_sk`, `our_mlkem_pk`, `our_mlkem_sk` are the
/// caller's own hybrid keypair (the public halves exchanged during pairing).
///
/// AUDIT KYP-2026-02 #25: this raw-secrets FFI variant is gated behind
/// `#[cfg(test)]` — it accepts secret key bytes as plain `Vec<u8>` arguments,
/// a surface future callers could misuse. Production callers use
/// `ratchet_init_session_with_keypair_handle` (opaque handle) on Android and
/// the Rust-internal `ratchet_ffi::ratchet_init_session_with_keypair_impl` on
/// the desktop (same-process crate call, never an FFI marshalling boundary).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn ratchet_init_session_with_keypair(
    peer_identity: String,
    master_shared_secret: Vec<u8>,
    is_initiator: bool,
    our_x25519_pk: Vec<u8>,
    our_x25519_sk: Vec<u8>,
    our_mlkem_pk: Vec<u8>,
    our_mlkem_sk: Vec<u8>,
    peer_x25519_pk: Vec<u8>,
    peer_mlkem_pk: Vec<u8>,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    let x25519 = if peer_x25519_pk.is_empty() {
        None
    } else {
        Some(peer_x25519_pk.as_slice())
    };
    let mlkem = if peer_mlkem_pk.is_empty() {
        None
    } else {
        Some(peer_mlkem_pk.as_slice())
    };
    ratchet_ffi::ratchet_init_session_with_keypair_impl(
        &peer_identity,
        &master_shared_secret,
        is_initiator,
        Some((our_x25519_pk, our_x25519_sk, our_mlkem_pk, our_mlkem_sk)),
        x25519,
        mlkem,
    )?;
    Ok("Session initialized".to_string())
}

#[uniffi::export]
pub fn ratchet_remove_session(peer_identity: String) -> bool {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_remove_session_impl(&peer_identity)
}
#[uniffi::export]
pub fn ratchet_clear_all_sessions() {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_clear_all_sessions_impl();
}
/// Bump the pairing epoch of the live session for a peer (audit finding #2).
/// Called by the Android app immediately after a RE-PAIR so a stale
/// pre-re-pair snapshot on disk can be recognized as cross-epoch and refused
/// by `ratchet_import_session`. Returns the new epoch, or None when no live
/// session exists.
#[uniffi::export]
pub fn ratchet_bump_pairing_epoch(peer_identity: String) -> Option<u64> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_bump_pairing_epoch_impl(&peer_identity)
}
#[uniffi::export]
pub fn ratchet_peer_ids() -> Vec<String> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_peer_ids_impl()
}
#[uniffi::export]
pub fn ratchet_encrypt_message(
    peer_identity: String,
    plaintext: Vec<u8>,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_encrypt_message_impl(&peer_identity, &plaintext)
}

/// Encrypt a plaintext and return the ratchet message as a BINARY TLV frame
/// (audit finding #12). The binary framing is the single cross-platform
/// serialization contract — no hex-in-JSON drift surface and ~2x smaller than
/// hex-encoded fields.
#[uniffi::export]
pub fn ratchet_encrypt_message_binary(
    peer_identity: String,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    let msg = ratchet_ffi::ratchet_encrypt_message_impl(&peer_identity, &plaintext)?;
    msg.to_binary()
}

/// Decrypt a ratchet message from a BINARY TLV frame, rekey-aware (audit
/// finding #12). Handles the same rekey payloads as the hex path.
#[uniffi::export]
pub fn ratchet_decrypt_message_binary(
    peer_identity: String,
    data: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    let msg = crypto::RatchetEncryptedMessage::from_binary(&data)?;
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
        ratchet_ffi::ratchet_decrypt_with_rekey_message_impl(
            &peer_identity,
            &msg.nonce,
            &msg.ciphertext,
            msg.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            msg.rekey_mlkem_pk.as_deref(),
        )
    } else {
        ratchet_ffi::ratchet_decrypt_message_impl(&peer_identity, &msg.nonce, &msg.ciphertext)
    }
}

#[uniffi::export]
pub fn ratchet_decrypt_message(
    peer_identity: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    if nonce.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    ratchet_ffi::ratchet_decrypt_message_impl(&peer_identity, &nonce, &ciphertext)
}

#[uniffi::export]
pub fn ratchet_decrypt_with_rekey_message(
    peer_identity: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    rekey_ciphertext: Option<Vec<u8>>,
    rekey_x25519_pk: Option<Vec<u8>>,
    rekey_mlkem_pk: Option<Vec<u8>>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    if nonce.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    let rekey_x25519 = match rekey_x25519_pk.as_deref() {
        Some(s) => Some(s.try_into().map_err(|_| KyberError::InvalidKeyLength {
            expected: 32,
            got: s.len() as u64,
        })?),
        None => None,
    };
    ratchet_ffi::ratchet_decrypt_with_rekey_message_impl(
        &peer_identity,
        &nonce,
        &ciphertext,
        rekey_ciphertext.as_deref(),
        rekey_x25519,
        rekey_mlkem_pk.as_deref(),
    )
}

#[uniffi::export]
pub fn generate_rekey_ack_message(
    peer_identity: String,
    seq: u64,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::generate_rekey_ack_message_impl(&peer_identity, seq)
}

#[uniffi::export]
pub fn ratchet_process_rekey_ack(peer_identity: String, seq: u64) -> Result<bool, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_process_rekey_ack_impl(&peer_identity, seq)
}

/// Take the pending RekeyAck carrier seq (if any) and produce the encrypted
/// ACK message to send back to the peer. Returns None when no ACK is pending.
#[uniffi::export]
pub fn ratchet_generate_rekey_ack(
    peer_identity: String,
) -> Result<Option<crypto::RatchetEncryptedMessage>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_generate_rekey_ack_impl(&peer_identity)
}

/// Take the pending RekeyAck carrier seq and produce the encrypted ACK as a
/// BINARY TLV (audit finding #12), consuming the carrier in the same session
/// lock. This is the phone's outbound RekeyAck channel: the phone attaches the
/// returned TLV to its next poll request so the desktop can commit its
/// outgoing proposal (audit finding #1 — the missing phone→desktop ack).
#[uniffi::export]
pub fn ratchet_generate_rekey_ack_binary(
    peer_identity: String,
) -> Result<Option<Vec<u8>>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_generate_rekey_ack_binary_impl(&peer_identity)
}

/// NON-CONSUMING variant of `ratchet_generate_rekey_ack_binary`: produces the
/// ack TLV without clearing the pending carrier, so a poll response lost on
/// the wire can be retried (audit finding #6). Callers MUST clear the carrier
/// with `ratchet_consume_rekey_ack` only after the response is written.
#[uniffi::export]
pub fn ratchet_generate_rekey_ack_binary_peek(
    peer_identity: String,
) -> Result<Option<Vec<u8>>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_generate_rekey_ack_binary_peek_impl(&peer_identity)
}

/// Clear the pending RekeyAck carrier — called after a poll response carrying
/// the peeked ack has been successfully written (audit finding #6).
#[uniffi::export]
pub fn ratchet_consume_rekey_ack(peer_identity: String) -> bool {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_consume_rekey_ack_impl(&peer_identity)
}

/// Decrypt (rekey-aware) and process a peer's RekeyAck carried as a BINARY TLV
/// (audit finding #12): commits the peer's ack of OUR outgoing proposal. The
/// ack is decrypted rekey-aware because a ratchet message at a rekey boundary
/// carries a rekey payload whose AEAD tag binds those fields (audit finding
/// #3 — the non-rekey decrypt would drop it).
#[uniffi::export]
pub fn ratchet_process_rekey_ack_binary(
    peer_identity: String,
    data: Vec<u8>,
) -> Result<bool, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_process_rekey_ack_binary_impl(&peer_identity, &data)
}

/// Export a ratchet session as a serialized snapshot (JSON bytes) for
/// encrypted persistence. Returns None if no session exists for the peer.
#[uniffi::export]
pub fn ratchet_export_session(peer_identity: String) -> Result<Option<Vec<u8>>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_export_session_impl(&peer_identity)
}

/// Export a ratchet session and AEAD-wrap the serialized snapshot INSIDE Rust
/// (audit finding #5). Returns an `EncryptedPayload` — the raw serialized
/// state NEVER crosses the UniFFI boundary as plaintext, so no complete
/// session key material ever sits on the JVM heap. `wrap_key` is the caller's
/// at-rest wrap key (32 bytes, caller-owned by design). The Android app uses
/// this for its per-poll snapshot persistence instead of the raw export + JVM
/// Base64 + re-entry dance.
#[uniffi::export]
pub fn ratchet_export_session_wrapped(
    peer_identity: String,
    wrap_key: Vec<u8>,
) -> Result<Option<EncryptedPayload>, KyberError> {
    ensure_panic_hook_installed();
    Ok(ratchet_ffi::ratchet_export_session_wrapped_impl(&peer_identity, &wrap_key)?.map(
        |(nonce, ciphertext)| EncryptedPayload {
            nonce,
            ciphertext,
        },
    ))
}

/// Restore a ratchet session from a previously exported (and decrypted)
/// snapshot. Replaces any existing session for the peer.
#[uniffi::export]
pub fn ratchet_import_session(peer_identity: String, data: Vec<u8>) -> Result<(), KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_import_session_impl(&peer_identity, &data)
}

/// Build an encrypted `Synchronize` packet carrying our current send counter.
/// The peer processes it via `ratchet_process_synchronize` — the ONLY path that
/// honors a resync target (audit finding #4: the plaintext counter in the poll
/// body is never acted on).
#[uniffi::export]
pub fn ratchet_synchronize_packet(
    peer_identity: String,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_synchronize_packet_impl(&peer_identity)
}

/// Binary-TLV variant of `ratchet_synchronize_packet` (audit finding #12):
/// returns the full TLV framing including any rekey payload the packet carried,
/// so the peer can process it rekey-aware via `ratchet_process_synchronize`.
#[uniffi::export]
pub fn ratchet_synchronize_packet_binary(peer_identity: String) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_synchronize_packet_binary_impl(&peer_identity)
}

/// Process a peer's encrypted Synchronize packet carried as a BINARY TLV:
/// decrypts it rekey-aware (authenticating the sender and adopting any rekey
/// payload the packet carried), verifies it is a `Synchronize`, and only then
/// resyncs our receiving chain to the authenticated target. Returns the number
/// of skipped messages. Refuses (rate-limited / pending rekey / budget
/// exhausted) per the audit finding #4 hardening.
#[uniffi::export]
pub fn ratchet_process_synchronize(
    peer_identity: String,
    data: Vec<u8>,
) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_process_synchronize_impl(&peer_identity, &data)
}

/// The receiver's current recv counter — used to build a Synchronize request
/// when a gap exceeds max_skip.
#[uniffi::export]
pub fn ratchet_recv_count(peer_identity: String) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_recv_count_impl(&peer_identity)
}

/// The sender's current send counter — carried in every poll response so the
/// peer can detect a receive-chain gap exceeding max_skip and resync (the
/// Synchronize recovery path, audit finding #4).
#[uniffi::export]
pub fn ratchet_send_count(peer_identity: String) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_send_count_impl(&peer_identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_handshake_flow() {
        let _alice = generate_pq_keypair().unwrap();
        let bob = generate_pq_keypair().unwrap();

        let kem_res = encapsulate_pq_secret(bob.x25519_pk.clone(), bob.mlkem_pk.clone()).unwrap();
        let decapsulated = decapsulate_pq_secret(
            kem_res.ciphertext.clone(),
            bob.x25519_sk.clone(),
            bob.mlkem_sk.clone(),
        )
        .unwrap();

        assert_eq!(kem_res.shared_secret, decapsulated);
    }

    /// Audit #14: `generate_pq_pairing_public` must retain the PRIVATE half of
    /// the pairing keypair in the registry so a pairing handler can later
    /// decapsulate the peer's KEM ciphertext. Regression: the private half used
    /// to be built into a temporary and dropped at the end of the call.
    #[test]
    fn test_pairing_public_retains_private_key() {
        // Clear any prior registry state.
        if let Some(cell) = PAIRING_KEYPAIR.get() {
            if let Ok(mut g) = cell.lock() {
                *g = None;
            }
        }
        let public = generate_pq_pairing_public().expect("pairing public");
        let stored = get_pq_pairing_keypair().expect("private half must survive");
        assert_eq!(stored.mlkem_pk, hex::decode(&public.mlkem_pk_hex).unwrap());
        assert_eq!(
            stored.x25519_pk,
            hex::decode(&public.x25519_pk_hex).unwrap()
        );
        assert!(
            !stored.mlkem_sk.is_empty(),
            "mlkem private key must be retained"
        );
        assert!(
            !stored.x25519_sk.is_empty(),
            "x25519 private key must be retained"
        );
    }
}
