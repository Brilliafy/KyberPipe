//! PREVIOUS-GENERATION receive path (audit F19 split): in-flight messages that
//! straddle a rekey commit are decrypted with the retained previous receiving
//! chain + replay watermark. Extracted from the former `decrypt.rs` monolith so
//! the previous-generation path, the dispatch table and the resync module each
//! live in their own file.

use super::super::{decrypt_chacha20, KyberError};
use super::resync::{advance_receiving_chain, prune_skip_keys, try_decrypt_with_cached_key};
use crate::crypto::ratchet::state::DoubleRatchetState;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

impl DoubleRatchetState {
    /// Try to decrypt a message belonging to the PREVIOUS ratchet generation
    /// using the retained previous receiving chain (audit finding #3). Returns
    /// Ok(Some(plaintext)) on success, Ok(None) when this message is not from
    /// the previous generation (or no previous chain is retained).
    pub(crate) fn try_decrypt_previous_generation(
        &mut self,
        nonce_gen: u32,
        seq: u64,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Option<(Vec<u8>, bool)>, KyberError> {
        // The `bool` reports whether delivery came from the retained skip cache
        // (audit KYP-2026-02 #22) so the caller can classify the decision as
        // `Skipped` vs `Committed` for the explicit `DecryptOutcome` machine.
        let (prev_ck, prev_anchor, prev_gen) = match (
            self.previous_recv_chain_key,
            self.previous_recv_anchor,
            self.previous_recv_gen,
        ) {
            (Some(ck), Some(anchor), Some(gen)) => (ck, anchor, gen),
            _ => return Ok(None),
        };
        if nonce_gen != prev_gen {
            return Ok(None);
        }
        // Audit KYP-2026-02 #4: CACHED-BUT-UNDELIVERED previous-generation
        // messages must be delivered from the retained skip cache FIRST. A key
        // derived during a gap skip but not yet received survives the rekey
        // commit in the cache (`reset_generation_counters` no longer clears
        // it); the retained chain cannot step backwards below its anchor and
        // the watermark below would misclassify these as "already delivered" —
        // the cache is the ONLY path that can deliver them. A key present here
        // means the message was never delivered (keys are removed at delivery),
        // so this cannot re-accept a replay.
        if let Some(plaintext) = {
            let store = self
                .skip_message_keys
                .as_mut()
                .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;
            // AUDIT #5 (VERIFY-THEN-REMOVE): the shared helper consumes the
            // cached key ONLY after AEAD verification. The legacy code removed
            // the key BEFORE decrypting, so an on-path attacker who flipped one
            // ciphertext bit of a captured legitimate frame and replayed it
            // permanently burned the key — the genuine frame arriving later
            // found no key and the retained chain cannot step below its anchor,
            // a deterministic message-loss DoS on out-of-order deliveries
            // straddling a rekey commit.
            try_decrypt_with_cached_key(store, nonce_gen, seq, nonce, ciphertext, aad)?
        } {
            self.replay_window.record_delivered(nonce_gen, seq);
            // Keep the delivery watermark in sync so a genuine duplicate that
            // somehow re-enters the cache can still be rejected downstream.
            self.replay_window.prev_gen_highest_delivered = Some(
                self.replay_window
                    .prev_gen_highest_delivered
                    .map_or(seq, |w| w.max(seq)),
            );
            return Ok(Some((plaintext, true)));
        }
        // Replays / already-processed messages must not be re-accepted.
        if self.replay_window.seen.contains(&(prev_gen, seq)) {
            return Err(KyberError::CryptoError(format!(
                "Duplicate sequence number {} detected (replay attack)",
                seq
            )));
        }
        // A message older than the abandoned anchor cannot be positioned on the
        // retained chain — the keys for it were already consumed.
        if seq < prev_anchor {
            return Err(KyberError::SessionDesynchronized(format!(
                "Previous-generation message seq {} predates retained anchor {}",
                seq, prev_anchor
            )));
        }
        // Audit finding #7: the watermark freezes the highest DELIVERED
        // previous-generation sequence number at commit time. A message at or
        // below it was already delivered (possibly via a skip key that the
        // commit then cleared) — accepting it again would be a replay window.
        if let Some(watermark) = self.replay_window.prev_gen_highest_delivered {
            if seq <= watermark {
                return Err(KyberError::CryptoError(format!(
                    "Previous-generation message seq {} already delivered (watermark {}) — replay",
                    seq, watermark
                )));
            }
        }
        let (next_ck, skip_map) =
            advance_receiving_chain(&prev_ck, prev_anchor, seq, prev_gen, self.max_skip)?;
        // Derive the message key for `seq` from the advanced chain position.
        let mut ck: Zeroizing<[u8; 32]> = Zeroizing::new(prev_ck);
        for _ in prev_anchor..seq {
            let hk = Hkdf::<Sha256>::new(Some(&*ck), b"step");
            let mut next: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
            hk.expand(b"kyberpipe-next-chain", &mut *next)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            ck = next;
        }
        let hk = Hkdf::<Sha256>::new(Some(&*ck), b"step");
        let mut msg_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        hk.expand(b"kyberpipe-msg-key", &mut *msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        let plaintext = decrypt_chacha20(&msg_key, nonce, ciphertext, aad)?;
        // AEAD verified — commit the advance on the retained previous chain.
        self.previous_recv_chain_key = Some(next_ck);
        self.previous_recv_anchor = Some(seq + 1);
        self.replay_window.prev_gen_highest_delivered = Some(
            self.replay_window
                .prev_gen_highest_delivered
                .map_or(seq, |w| w.max(seq)),
        );
        let store = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;
        for (k, v) in skip_map {
            store.insert(k, v);
        }
        prune_skip_keys(store, self.ratchet_generation, self.max_skip * 2);
        self.replay_window.record_delivered(prev_gen, seq);
        Ok(Some((plaintext, false)))
    }
}
