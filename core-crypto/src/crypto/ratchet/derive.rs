use super::super::{encapsulate_hybrid, generate_hybrid_keypair, HybridKemResult, KyberError};
use super::state::DoubleRatchetState;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive sending and receiving chain keys from the root key with domain separation.
pub(crate) fn derive_chain_keys_from_root(
    root_key: &[u8; 32],
    send_label: &[u8],
    recv_label: &[u8],
) -> Result<([u8; 32], [u8; 32]), KyberError> {
    let mut send_ck = [0u8; 32];
    let mut recv_ck = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"kyberpipe-chain-salt"), root_key)
        .expand(send_label, &mut send_ck)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
    Hkdf::<Sha256>::new(Some(b"kyberpipe-chain-salt"), root_key)
        .expand(recv_label, &mut recv_ck)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
    Ok((send_ck, recv_ck))
}

/// Derive a message key from a receiving chain key at a given sequence offset.
/// Non-mutating helper used by the pending chain AEAD verification fallback.
pub(crate) fn derive_tentative_msg_key(
    recv_chain_key: &[u8; 32],
    recv_message_count: u64,
    target_seq: u64,
    max_skip: usize,
) -> Result<[u8; 32], KyberError> {
    if target_seq > recv_message_count {
        let diff = (target_seq - recv_message_count) as usize;
        if diff > max_skip {
            return Err(KyberError::CryptoError(format!(
                "Tentative derivation gap {} exceeds max_skip {}",
                diff, max_skip
            )));
        }
    }
    let mut ck = *recv_chain_key;
    for _ in recv_message_count..target_seq {
        let hk = Hkdf::<Sha256>::new(Some(&ck), b"step");
        let mut next_ck = [0u8; 32];
        hk.expand(b"kyberpipe-next-chain", &mut next_ck)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        ck = next_ck;
    }
    let hk = Hkdf::<Sha256>::new(Some(&ck), b"step");
    let mut msg_key = [0u8; 32];
    hk.expand(b"kyberpipe-msg-key", &mut msg_key)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
    Ok(msg_key)
}

impl DoubleRatchetState {
    /// Perform a Post-Quantum Ephemeral DH/KEM Ratchet re-key step.
    /// Derives new keys into the OUTGOING proposal fields — does NOT overwrite
    /// active state until the peer acknowledges via process_rekey_ack().
    /// Refuses to run while an outgoing proposal is still pending so two
    /// overlapping proposals cannot overwrite each other (single-slot
    /// serialization).
    pub fn dh_ratchet_rekey(
        &mut self,
        peer_x25519_pk: [u8; 32],
        peer_mlkem_pk: &[u8],
    ) -> Result<HybridKemResult, KyberError> {
        if self.outgoing_root_key.is_some() {
            return Err(KyberError::CryptoError(
                "Outgoing rekey already pending — wait for the peer ACK before proposing again"
                    .into(),
            ));
        }
        let kem_res = encapsulate_hybrid(&peer_x25519_pk, peer_mlkem_pk)?;

        let hk = Hkdf::<Sha256>::new(
            Some(&self.root_key),
            &kem_res.combined_shared_secret.clone(),
        );
        let mut new_root = [0u8; 32];
        let mut new_send = [0u8; 32];
        let mut new_recv = [0u8; 32];
        hk.expand(b"kyberpipe-next-root-key", &mut new_root)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-send-chain-from-rekey", &mut new_send)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-recv-chain-from-rekey", &mut new_recv)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        // Store as an OUTGOING proposal — we are the initiator of this rekey,
        // so our send chain is new_send and our recv chain is new_recv.
        self.outgoing_root_key = Some(new_root);
        self.outgoing_sending_chain_key = Some(new_send);
        self.outgoing_receiving_chain_key = Some(new_recv);
        self.peer_x25519_pk = Some(peer_x25519_pk);
        self.peer_mlkem_pk = Some(peer_mlkem_pk.to_vec());
        let new_pair = generate_hybrid_keypair();
        let _ = self.outgoing_hybrid_pair.replace(new_pair);

        Ok(kem_res)
    }
}
