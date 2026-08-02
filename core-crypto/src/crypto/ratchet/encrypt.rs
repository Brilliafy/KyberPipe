use super::super::{
    encapsulate_hybrid, encrypt_chacha20, generate_hybrid_keypair, generate_nonce_from_seq,
    KyberError,
};
use super::state::{build_rekey_aad, DoubleRatchetState, RekeyCarrier};
use super::tlv::RatchetEncryptedMessage;
use hkdf::Hkdf;
use sha2::Sha256;

/// How long an unacknowledged outgoing rekey proposal may sit before the
/// carrier is RE-SENT (attached to a later message). An unacknowledged
/// proposal is never committed — committing key material the peer has not
/// confirmed permanently desyncs the session (audit finding #1).
const REKEY_RETRY_TTL: std::time::Duration = std::time::Duration::from_secs(30);

impl DoubleRatchetState {
    /// Advance sending symmetric chain key and encrypt plaintext payload.
    /// Every `rekey_interval` messages, generates a DH re-key payload attached to the message.
    /// The re-key does NOT take effect until the peer ACKs the carrier message — the current
    /// message is encrypted with the old chain, and the outgoing proposal is committed by
    /// `commit_outgoing_rekey()` when `process_rekey_ack()` matches (or TTL fallback).
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
    ) -> Result<RatchetEncryptedMessage, KyberError> {
        let seq = self.send_message_count;
        self.send_message_count += 1;

        // Guard: generation must fit in u32 for nonce domain separation.
        // If this fires, the session has been rekeyed 4+ billion times —
        // re-pair instead of risking nonce reuse.
        if self.ratchet_generation == u32::MAX {
            return Err(KyberError::CryptoError(format!(
                "Ratchet generation {} reaches u32::MAX — nonce reuse risk. Re-pair required.",
                self.ratchet_generation
            )));
        }
        let nonce = generate_nonce_from_seq(seq, self.ratchet_generation);

        // Retry eviction: an outgoing proposal whose ACK never arrived after
        // REKEY_RETRY_TTL is RE-SENT on this message (the stored payload is
        // re-attached below). The proposal is NEVER committed unacknowledged —
        // that is what permanently desynchronized sessions in the field.
        let now = std::time::Instant::now();
        let mut resend: Option<RekeyCarrier> = None;
        self.rekey_pending_confirm_queue.retain(|carrier| {
            if carrier.attached_at.elapsed() >= REKEY_RETRY_TTL && resend.is_none() {
                resend = Some(carrier.clone());
                false
            } else {
                true
            }
        });

        // Serialization: never overwrite a still-pending proposal — either our
        // own outgoing one OR the peer's incoming one. A single pending slot +
        // explicit ACK-before-next-proposal prevents two racing one-sided rekeys
        // from clobbering each other and diverging generations.
        let proposal_pending = self.outgoing_root_key.is_some() || self.pending_root_key.is_some();
        let should_rekey = seq > 0
            && seq.is_multiple_of(self.rekey_interval)
            && self.rekey_pending_confirm_queue.len() < 2
            && !proposal_pending;
        let (rekey_x25519_pk, rekey_mlkem_pk, rekey_ciphertext) = if let Some(carrier) = resend {
            // Re-send the pending proposal — same payload, updated carrier seq,
            // fresh timestamp. The peer re-derives the same pending proposal
            // (or updates its pending_rekey_ack_seq to this carrier).
            self.rekey_pending_confirm_queue.push_back(RekeyCarrier {
                carrier_seq: seq,
                attached_at: now,
                rekey_x25519_pk: carrier.rekey_x25519_pk.clone(),
                rekey_mlkem_pk: carrier.rekey_mlkem_pk.clone(),
                rekey_ciphertext: carrier.rekey_ciphertext.clone(),
            });
            (
                Some(carrier.rekey_x25519_pk),
                Some(carrier.rekey_mlkem_pk),
                Some(carrier.rekey_ciphertext),
            )
        } else if should_rekey {
            if let (Some(peer_xpk), Some(ref peer_mpk)) =
                (self.peer_x25519_pk, self.peer_mlkem_pk.clone())
            {
                let our_new = generate_hybrid_keypair();
                let new_x25519_pk = our_new.x25519_pk;
                let new_mlkem_pk = our_new.mlkem_pk.clone();
                let kem_res = encapsulate_hybrid(&peer_xpk, peer_mpk)?;

                // Derive new root + chains but store as an OUTGOING proposal.
                let hk2 = Hkdf::<Sha256>::new(
                    Some(&self.root_key),
                    &kem_res.combined_shared_secret.clone(),
                );
                let mut new_root: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
                let mut new_send: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
                let mut new_recv: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
                hk2.expand(b"kyberpipe-next-root-key", &mut *new_root)
                    .map_err(|e| KyberError::CryptoError(e.to_string()))?;
                hk2.expand(b"kyberpipe-next-send-chain-from-rekey", &mut *new_send)
                    .map_err(|e| KyberError::CryptoError(e.to_string()))?;
                hk2.expand(b"kyberpipe-next-recv-chain-from-rekey", &mut *new_recv)
                    .map_err(|e| KyberError::CryptoError(e.to_string()))?;

                // Do NOT switch chains or swap our_hybrid_pair here — that only
                // happens on commit_outgoing_rekey() after the peer's ACK, avoiding
                // a lockout window where the sender can't decapsulate peer rekeys.
                self.outgoing_root_key = Some(*new_root);
                self.outgoing_sending_chain_key = Some(*new_send);
                self.outgoing_receiving_chain_key = Some(*new_recv);
                self.outgoing_hybrid_pair = Some(our_new);
                self.outgoing_rekey_payload = Some((
                    new_x25519_pk.to_vec(),
                    new_mlkem_pk.clone(),
                    kem_res.ciphertext_bytes.clone(),
                ));
                self.rekey_pending_confirm_queue.push_back(RekeyCarrier {
                    carrier_seq: seq,
                    attached_at: now,
                    rekey_x25519_pk: new_x25519_pk.to_vec(),
                    rekey_mlkem_pk: new_mlkem_pk.clone(),
                    rekey_ciphertext: kem_res.ciphertext_bytes.clone(),
                });

                (
                    Some(new_x25519_pk.to_vec()),
                    Some(new_mlkem_pk),
                    Some(kem_res.ciphertext_bytes.clone()),
                )
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };
        // Build AAD from rekey parameters to bind them into the AEAD tag
        let aad = build_rekey_aad(
            rekey_ciphertext.as_deref(),
            rekey_x25519_pk.as_deref(),
            rekey_mlkem_pk.as_deref(),
        );

        // Derive message key and next chain key from the current (or newly committed) chain.
        // The next-chain label is direction-agnostic: the sender's next chain key must
        // equal the receiver's next chain key, so both sides derive it with the SAME
        // label. Direction separation happens only at the root/chain split above.
        let hk = Hkdf::<Sha256>::new(Some(&self.sending_chain_key), b"step");
        let mut msg_key: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
        hk.expand(b"kyberpipe-msg-key", &mut *msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-chain", &mut self.sending_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        let ciphertext = encrypt_chacha20(&msg_key, &nonce, plaintext, &aad)?;

        Ok(RatchetEncryptedMessage {
            nonce: nonce.to_vec(),
            ciphertext,
            rekey_x25519_pk,
            rekey_mlkem_pk,
            rekey_ciphertext,
        })
    }
}
