//! RekeyAck channel (audit KYP-2026-02 #22 — extracted from the former
//! `ratchet_ffi.rs` monolith): generate / peek / consume / process the peer's
//! rekey acknowledgement, including the idempotent-peek cache (audit #11).

use super::registry::with_ratchet_session;
use crate::crypto;
use crate::error::KyberError;

pub fn generate_rekey_ack_message_impl(
    peer_identity: &str,
    seq: u64,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| ratchet.generate_rekey_ack(seq))
}

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

pub fn ratchet_generate_rekey_ack_binary_peek_impl(
    peer_identity: &str,
) -> Result<Option<Vec<u8>>, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| {
        if let Some(seq) = ratchet.pending_rekey_ack_seq {
            // Audit KYP-2026-02 #11: the peek MUST be idempotent. Each call to
            // `generate_rekey_ack` → `ratchet_encrypt` advances the SENDER's
            // send chain and produces a fresh message at a new seq. If poll
            // responses are lost N times, N peeks previously burned N chain
            // positions — the peer derives N skip keys, and beyond max_skip the
            // chain gap makes every subsequent payload undecryptable (chain
            // burn / KDF-work DoS). Re-serve the cached TLV while the carrier
            // is unchanged: no re-encryption, no chain advancement.
            if let Some((cached_seq, cached_tlv)) = &ratchet.peeked_ack_cache {
                if *cached_seq == seq {
                    return Ok(Some(cached_tlv.clone()));
                }
            }
            let ack = ratchet.generate_rekey_ack(seq)?;
            let bin = ack.to_binary()?;
            ratchet.peeked_ack_cache = Some((seq, bin.clone()));
            Ok(Some(bin))
        } else {
            // No pending carrier — drop the stale cache so a later carrier
            // regenerates from scratch.
            ratchet.peeked_ack_cache = None;
            Ok(None)
        }
    })
}

pub fn ratchet_consume_rekey_ack_impl(peer_identity: &str) -> bool {
    with_ratchet_session(peer_identity, |ratchet| {
        let existed = ratchet.pending_rekey_ack_seq.take().is_some();
        // Clear the idempotent-peek cache: the ack was delivered, so the next
        // peek must not re-serve a consumed carrier (audit KYP-2026-02 #11).
        ratchet.peeked_ack_cache = None;
        Ok(existed)
    })
    .unwrap_or(false)
}

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
