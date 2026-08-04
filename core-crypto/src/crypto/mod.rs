// KyberPipe crypto module — domain-specific submodules
pub mod aead;
pub mod crdt;
pub mod kem;
pub mod misc;
pub mod padding;
pub mod ratchet;
pub mod sas;
pub mod shamir;
pub mod signing;

// Re-export everything at crate::crypto::* for backward compatibility
#[allow(unused_imports)]
pub use aead::*;
#[allow(unused_imports)]
pub use crdt::*;
#[allow(unused_imports)]
pub use kem::*;
#[allow(unused_imports)]
pub use misc::*;
#[allow(unused_imports)]
pub use padding::*;
#[allow(unused_imports)]
pub use ratchet::*;
#[allow(unused_imports)]
pub use sas::*;
#[allow(unused_imports)]
pub use shamir::*;
#[allow(unused_imports)]
pub use signing::*;

use crate::error::KyberError;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const CHUNKS_SIZE: usize = 64 * 1024;
pub const RATCHET_REKEY_INTERVAL: u64 = 100;

/// Canonical domain-separation salt for session-key derivation. BOTH the
/// desktop (Rust, `handlers/pairing.rs`) and Android (Kotlin via UniFFI) MUST
/// consume these exact bytes — never hex-encode/re-encode the salt at a call
/// site (audit finding #2: Android passed the hex-encoding as ASCII, producing
/// a byte-different salt and making every session-key payload undecryptable).
pub const SESSION_KEY_DERIVATION_SALT: &[u8] = b"kyberpipe-sync-v1";

/// Derive a 256-bit (32-byte) symmetric key using HKDF-SHA256 from combined shared secret.
pub fn derive_session_key(
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], KyberError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| KyberError::CryptoError(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}

/// Normalize text to prevent OS line-ending and whitespace hash mismatches (\r\n -> \n, trim end)
pub fn normalize_clipboard_text(text: &str) -> String {
    text.replace("\r\n", "\n").trim_end().to_string()
}

/// Compute SHA-256 hash of normalized text
pub fn hash_clipboard_text(text: &str) -> String {
    let normalized = normalize_clipboard_text(text);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate jittered dummy cover traffic heartbeat payload
pub fn generate_cover_traffic_packet() -> Vec<u8> {
    let mut dummy = vec![0u8; 256];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut dummy);
    dummy
}

/// Thread-safe clipboard deduplicator ring buffer with AtomicBool state flag
/// Uses RAII Drop guard to prevent permanent lock on panic
#[derive(Clone)]
pub struct ClipboardDeduplicator {
    history: Arc<Mutex<VecDeque<String>>>,
    is_processing_remote_update: Arc<AtomicBool>,
    max_history: usize,
}

/// RAII guard that releases the remote update lock on Drop
pub struct RemoteUpdateGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for RemoteUpdateGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

impl ClipboardDeduplicator {
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(5))),
            is_processing_remote_update: Arc::new(AtomicBool::new(false)),
            max_history: 5,
        }
    }

    /// Execute a closure within a remote update scope.
    /// The AtomicBool flag is set before the closure and released after (even on panic via Drop).
    pub fn with_remote_update<F, T>(&self, f: F) -> Option<T>
    where
        F: FnOnce() -> T,
    {
        let acquired = self
            .is_processing_remote_update
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if !acquired {
            return None;
        }
        let _guard = RemoteUpdateGuard {
            flag: self.is_processing_remote_update.clone(),
        };
        Some(f())
    }

    pub fn is_suppressed(&self, text: &str) -> bool {
        if self.is_processing_remote_update.load(Ordering::SeqCst) {
            return true;
        }
        let hash = hash_clipboard_text(text);
        let guard = self.history.lock().unwrap_or_else(|e| e.into_inner());
        // Use constant-time comparison to prevent timing oracle on hash lookup
        guard
            .iter()
            .any(|h| subtle::ConstantTimeEq::ct_eq(h.as_bytes(), hash.as_bytes()).into())
    }

    pub fn record_text(&self, text: &str) {
        let hash = hash_clipboard_text(text);
        let mut guard = self.history.lock().unwrap_or_else(|e| e.into_inner());
        if guard.contains(&hash) {
            return;
        }
        if guard.len() >= self.max_history {
            guard.pop_front();
        }
        guard.push_back(hash);
    }
    /// Atomic check-and-record: holds the Mutex for both operations.
    /// Returns true if the text was newly recorded (was not a duplicate).
    pub fn check_and_record(&self, text: &str) -> bool {
        let hash = hash_clipboard_text(text);
        let mut guard = self.history.lock().unwrap_or_else(|e| e.into_inner());
        // Use constant-time comparison to prevent timing oracle on hash lookup
        if guard
            .iter()
            .any(|h| subtle::ConstantTimeEq::ct_eq(h.as_bytes(), hash.as_bytes()).into())
        {
            return false;
        }
        if guard.len() >= self.max_history {
            guard.pop_front();
        }
        guard.push_back(hash);
        true
    }
}

impl Default for ClipboardDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        let _alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();

        let kem_res = encapsulate_hybrid(&bob_pair.x25519_pk, &bob_pair.mlkem_pk).unwrap();

        let alice_decapsulated_ss = decapsulate_hybrid(
            &kem_res.ciphertext_bytes.clone(),
            &bob_pair.x25519_sk,
            &bob_pair.mlkem_sk,
        )
        .unwrap();

        assert_eq!(
            kem_res.combined_shared_secret.clone(),
            alice_decapsulated_ss
        );
    }

    #[test]
    fn test_double_ratchet_flow() {
        let _alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&bob_pair.x25519_pk, &bob_pair.mlkem_pk).unwrap();

        let mut alice_ratchet =
            DoubleRatchetState::new(&kem_res.combined_shared_secret.clone(), true, None, None)
                .unwrap();
        let mut bob_ratchet =
            DoubleRatchetState::new(&kem_res.combined_shared_secret.clone(), false, None, None)
                .unwrap();

        let msg = alice_ratchet
            .ratchet_encrypt(b"Post-Quantum Double Ratchet Test")
            .unwrap();
        let nonce_arr: [u8; 12] = msg.nonce.try_into().expect("nonce must be 12 bytes");
        let decrypted = bob_ratchet
            .ratchet_decrypt(&nonce_arr, &msg.ciphertext)
            .unwrap();

        assert_eq!(b"Post-Quantum Double Ratchet Test".to_vec(), decrypted);
    }

    /// Synchronize resync: after a gap that exceeds max_skip, the receiver uses
    /// the peer's authenticated Synchronize counter to re-derive the chain and
    /// continues decrypting — the Wi-Fi→cellular handoff recovery path.
    #[test]
    fn test_ratchet_synchronize_resync() {
        let probe = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&probe.x25519_pk, &probe.mlkem_pk).unwrap();
        let mut alice =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, true, None, None).unwrap();
        let mut bob =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, false, None, None).unwrap();
        alice.peer_x25519_pk = Some(bob.our_hybrid_pair.x25519_pk);
        alice.peer_mlkem_pk = Some(bob.our_hybrid_pair.mlkem_pk.clone());
        bob.peer_x25519_pk = Some(alice.our_hybrid_pair.x25519_pk);
        bob.peer_mlkem_pk = Some(alice.our_hybrid_pair.mlkem_pk.clone());

        // Alice sends 0..=200; Bob decrypts only the first 100 (a "lost" burst).
        let mut msgs = Vec::new();
        for i in 0..=200u64 {
            msgs.push(alice.ratchet_encrypt(format!("m{i}").as_bytes()).unwrap());
        }
        for (i, msg) in msgs.iter().take(100).enumerate() {
            let nonce: [u8; 12] = msg.nonce.clone().try_into().unwrap();
            let pt = bob.ratchet_decrypt(&nonce, &msg.ciphertext).unwrap();
            assert_eq!(String::from_utf8(pt).unwrap(), format!("m{i}"));
        }
        // The gap to message 200 exceeds max_skip — the Synchronize path repairs it.
        let skipped = bob.resync_receiving_chain(200).unwrap();
        assert_eq!(skipped, 100);

        // Now message 200 (and beyond) decrypts.
        let nonce: [u8; 12] = msgs[200].nonce.clone().try_into().unwrap();
        let pt = bob.ratchet_decrypt(&nonce, &msgs[200].ciphertext).unwrap();
        assert_eq!(String::from_utf8(pt).unwrap(), "m200");

        // Stale and unbounded resyncs are rejected.
        assert!(bob.resync_receiving_chain(100).is_err());
        assert!(bob.resync_receiving_chain(100_000).is_err());
    }

    /// Snapshot/restore round-trip: the restored state must be able to continue
    /// decrypting new messages exactly where the original left off (the restart
    /// scenario that previously forced a full re-pair).
    #[test]
    fn test_ratchet_snapshot_restore_resumes() {
        let probe = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&probe.x25519_pk, &probe.mlkem_pk).unwrap();
        let mut alice =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, true, None, None).unwrap();
        let mut bob =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, false, None, None).unwrap();
        alice.peer_x25519_pk = Some(bob.our_hybrid_pair.x25519_pk);
        alice.peer_mlkem_pk = Some(bob.our_hybrid_pair.mlkem_pk.clone());
        bob.peer_x25519_pk = Some(alice.our_hybrid_pair.x25519_pk);
        bob.peer_mlkem_pk = Some(alice.our_hybrid_pair.mlkem_pk.clone());

        // Advance the session a bit, then "restart" Bob.
        for i in 0..5u64 {
            let msg = alice.ratchet_encrypt(format!("m{i}").as_bytes()).unwrap();
            let nonce: [u8; 12] = msg.nonce.clone().try_into().unwrap();
            bob.ratchet_decrypt(&nonce, &msg.ciphertext).unwrap();
        }
        let snap = bob.to_snapshot();
        let ser = serde_json::to_vec(&snap).unwrap();
        let restored: crate::crypto::ratchet::RatchetSnapshot =
            serde_json::from_slice(&ser).unwrap();
        let mut bob2 = DoubleRatchetState::from_snapshot(&restored).unwrap();
        assert_eq!(bob2.recv.message_count, 5);
        assert_eq!(bob2.send.message_count, 0);

        // Alice sends more; restored Bob must decrypt them.
        for i in 5..8u64 {
            let msg = alice.ratchet_encrypt(format!("m{i}").as_bytes()).unwrap();
            let nonce: [u8; 12] = msg.nonce.clone().try_into().unwrap();
            let pt = bob2.ratchet_decrypt(&nonce, &msg.ciphertext).unwrap();
            assert_eq!(String::from_utf8(pt).unwrap(), format!("m{i}"));
        }
        // And Bob's own sends (from the restored state) decrypt on Alice.
        let bm = bob2.ratchet_encrypt(b"bob-after-restart").unwrap();
        let nonce: [u8; 12] = bm.nonce.clone().try_into().unwrap();
        let pt = alice.ratchet_decrypt(&nonce, &bm.ciphertext).unwrap();
        assert_eq!(pt, b"bob-after-restart");
    }

    /// Full rekey lifecycle regression: sender rekeys at seq 100, receiver
    /// derives the incoming proposal, sends a RekeyAck carrying the CARRIER
    /// seq (receiver's recv space == sender's send space), sender commits its
    /// outgoing proposal, both sides continue bidirectionally on generation 1.
    #[test]
    fn test_double_ratchet_rekey_ack_roundtrip() {
        let probe = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&probe.x25519_pk, &probe.mlkem_pk).unwrap();

        let mut alice =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, true, None, None).unwrap();
        let mut bob =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, false, None, None).unwrap();
        // Align peer public keys with each side's REAL internal keypair (as the
        // pairing handshake would: each side learns the peer's actual pubkeys).
        alice.peer_x25519_pk = Some(bob.our_hybrid_pair.x25519_pk);
        alice.peer_mlkem_pk = Some(bob.our_hybrid_pair.mlkem_pk.clone());
        bob.peer_x25519_pk = Some(alice.our_hybrid_pair.x25519_pk);
        bob.peer_mlkem_pk = Some(alice.our_hybrid_pair.mlkem_pk.clone());

        // Alice sends seq 0..=100 — a rekey payload is attached at seq 100.
        let mut alice_msgs = Vec::new();
        for i in 0..=100u64 {
            let msg = alice
                .ratchet_encrypt(format!("alice-msg-{i}").as_bytes())
                .unwrap();
            alice_msgs.push(msg);
        }
        assert!(
            alice_msgs[100].rekey_x25519_pk.is_some(),
            "rekey should attach at seq 100"
        );
        assert!(
            alice.outgoing_proposal.root_key.is_some(),
            "outgoing proposal must be pending"
        );

        // Bob decrypts every message, using the rekey path when a payload is present.
        for (i, msg) in alice_msgs.iter().enumerate() {
            let nonce: [u8; 12] = msg.nonce.clone().try_into().unwrap();
            let pt = if msg.rekey_ciphertext.is_some() {
                let xpk: [u8; 32] = msg
                    .rekey_x25519_pk
                    .as_ref()
                    .unwrap()
                    .clone()
                    .try_into()
                    .unwrap();
                bob.ratchet_decrypt_with_rekey(
                    &nonce,
                    &msg.ciphertext,
                    msg.rekey_ciphertext.as_deref(),
                    Some(&xpk),
                    msg.rekey_mlkem_pk.as_deref(),
                )
                .unwrap()
            } else {
                bob.ratchet_decrypt(&nonce, &msg.ciphertext).unwrap()
            };
            assert_eq!(String::from_utf8(pt).unwrap(), format!("alice-msg-{i}"));
        }

        // Bob's pending ACK must carry the CARRIER seq (100) — the seq of the
        // message that carried the rekey in the SENDER's space, not Bob's send count.
        let ack_seq = bob.take_pending_rekey_ack_seq();
        assert_eq!(ack_seq, Some(100), "ACK must carry the rekey carrier seq");
        assert_eq!(
            bob.ratchet_generation, 0,
            "receiver must not bump gen before commit"
        );

        // Bob sends the encrypted RekeyAck back; Alice decrypts it and processes it.
        let ack_msg = bob.generate_rekey_ack(ack_seq.unwrap()).unwrap();
        let nonce: [u8; 12] = ack_msg.nonce.clone().try_into().unwrap();
        let ack_pt = alice.ratchet_decrypt(&nonce, &ack_msg.ciphertext).unwrap();
        let parsed =
            crate::packets::KyberMessage::from_json(&String::from_utf8_lossy(&ack_pt)).unwrap();
        match parsed {
            crate::packets::KyberMessage::RekeyAck { seq } => assert_eq!(seq, 100),
            other => panic!("expected RekeyAck, got {other:?}"),
        }
        assert!(
            alice.process_rekey_ack(100),
            "carrier seq must match the confirm queue"
        );
        assert!(
            alice.outgoing_proposal.root_key.is_none(),
            "outgoing proposal must be committed"
        );
        assert_eq!(
            alice.ratchet_generation, 1,
            "sender bumps gen on ACK commit"
        );

        // Alice sends the first new-generation message; Bob's fallback commits the
        // incoming proposal and both sides converge on generation 1.
        let new_msg = alice.ratchet_encrypt(b"alice-after-rekey").unwrap();
        let nonce: [u8; 12] = new_msg.nonce.clone().try_into().unwrap();
        let pt = if new_msg.rekey_ciphertext.is_some() {
            let xpk: [u8; 32] = new_msg
                .rekey_x25519_pk
                .as_ref()
                .unwrap()
                .clone()
                .try_into()
                .unwrap();
            bob.ratchet_decrypt_with_rekey(
                &nonce,
                &new_msg.ciphertext,
                new_msg.rekey_ciphertext.as_deref(),
                Some(&xpk),
                new_msg.rekey_mlkem_pk.as_deref(),
            )
            .unwrap()
        } else {
            bob.ratchet_decrypt(&nonce, &new_msg.ciphertext).unwrap()
        };
        assert_eq!(pt, b"alice-after-rekey");
        assert_eq!(
            bob.ratchet_generation, 1,
            "receiver converges to generation 1"
        );
        assert!(
            bob.incoming_proposal.root_key.is_none(),
            "incoming proposal must be committed"
        );

        // Reverse direction must still work after the rekey.
        let bob_msg = bob.ratchet_encrypt(b"bob-response").unwrap();
        let nonce: [u8; 12] = bob_msg.nonce.clone().try_into().unwrap();
        let pt = if bob_msg.rekey_ciphertext.is_some() {
            let xpk: [u8; 32] = bob_msg
                .rekey_x25519_pk
                .as_ref()
                .unwrap()
                .clone()
                .try_into()
                .unwrap();
            alice
                .ratchet_decrypt_with_rekey(
                    &nonce,
                    &bob_msg.ciphertext,
                    bob_msg.rekey_ciphertext.as_deref(),
                    Some(&xpk),
                    bob_msg.rekey_mlkem_pk.as_deref(),
                )
                .unwrap()
        } else {
            alice.ratchet_decrypt(&nonce, &bob_msg.ciphertext).unwrap()
        };
        assert_eq!(pt, b"bob-response");
    }

    /// Audit #5: two-sided rekey race. Both peers propose simultaneously; the
    /// deterministic tie-break (initiator wins) must make both sides converge
    /// on the initiator's new generation — no double-bump, no divergence.
    #[test]
    fn test_double_ratchet_two_sided_rekey_race() {
        let probe = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&probe.x25519_pk, &probe.mlkem_pk).unwrap();
        // Alice = initiator, Bob = responder.
        let mut alice =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, true, None, None).unwrap();
        let mut bob =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, false, None, None).unwrap();
        alice.peer_x25519_pk = Some(bob.our_hybrid_pair.x25519_pk);
        alice.peer_mlkem_pk = Some(bob.our_hybrid_pair.mlkem_pk.clone());
        bob.peer_x25519_pk = Some(alice.our_hybrid_pair.x25519_pk);
        bob.peer_mlkem_pk = Some(alice.our_hybrid_pair.mlkem_pk.clone());

        // BOTH sides encrypt through seq 100 so each attaches a rekey payload.
        let mut alice_msgs = Vec::new();
        let mut bob_msgs = Vec::new();
        for i in 0..=100u64 {
            alice_msgs.push(alice.ratchet_encrypt(format!("a{i}").as_bytes()).unwrap());
            bob_msgs.push(bob.ratchet_encrypt(format!("b{i}").as_bytes()).unwrap());
        }
        assert!(alice.outgoing_proposal.root_key.is_some());
        assert!(bob.outgoing_proposal.root_key.is_some());

        // Deliver Bob's rekey-carrying message to Alice FIRST (Alice sees Bob's
        // proposal while her own is still unacked → initiator discards Bob's).
        let bob_rekey = &bob_msgs[100];
        let nonce: [u8; 12] = bob_rekey.nonce.clone().try_into().unwrap();
        let xpk: [u8; 32] = bob_rekey
            .rekey_x25519_pk
            .as_ref()
            .unwrap()
            .clone()
            .try_into()
            .unwrap();
        let pt = alice
            .ratchet_decrypt_with_rekey(
                &nonce,
                &bob_rekey.ciphertext,
                bob_rekey.rekey_ciphertext.as_deref(),
                Some(&xpk),
                bob_rekey.rekey_mlkem_pk.as_deref(),
            )
            .unwrap();
        assert_eq!(String::from_utf8(pt).unwrap(), "b100");
        // Alice keeps her own proposal; Bob's tentative proposal is discarded,
        // and NO RekeyAck for Bob's proposal is recorded.
        assert!(
            alice.outgoing_proposal.root_key.is_some(),
            "initiator keeps its own proposal"
        );
        assert!(
            alice.incoming_proposal.root_key.is_none(),
            "initiator discards responder proposal"
        );
        assert!(
            alice.take_pending_rekey_ack_seq().is_none(),
            "initiator must not ACK the loser"
        );

        // Deliver Alice's rekey-carrying message to Bob (responder): Bob must
        // CANCEL its own outgoing proposal and adopt Alice's, then ACK it.
        let alice_rekey = &alice_msgs[100];
        let nonce: [u8; 12] = alice_rekey.nonce.clone().try_into().unwrap();
        let xpk: [u8; 32] = alice_rekey
            .rekey_x25519_pk
            .as_ref()
            .unwrap()
            .clone()
            .try_into()
            .unwrap();
        let pt = bob
            .ratchet_decrypt_with_rekey(
                &nonce,
                &alice_rekey.ciphertext,
                alice_rekey.rekey_ciphertext.as_deref(),
                Some(&xpk),
                alice_rekey.rekey_mlkem_pk.as_deref(),
            )
            .unwrap();
        assert_eq!(String::from_utf8(pt).unwrap(), "a100");
        assert!(
            bob.outgoing_proposal.root_key.is_none(),
            "responder must cancel its own proposal"
        );
        assert!(
            bob.incoming_proposal.root_key.is_some(),
            "responder adopts the initiator's proposal"
        );
        let ack_seq = bob.take_pending_rekey_ack_seq();
        assert_eq!(ack_seq, Some(100), "responder ACKs the initiator's carrier");

        // Alice processes Bob's RekeyAck → commits her outgoing proposal.
        assert!(alice.process_rekey_ack(ack_seq.unwrap()));
        assert_eq!(alice.ratchet_generation, 1);

        // Alice sends the first new-generation message; Bob's fallback commits
        // the adopted proposal. Both converge on generation 1 with matching chains.
        let new_msg = alice.ratchet_encrypt(b"post-race").unwrap();
        let nonce: [u8; 12] = new_msg.nonce.clone().try_into().unwrap();
        let pt = bob.ratchet_decrypt(&nonce, &new_msg.ciphertext).unwrap();
        assert_eq!(pt, b"post-race");
        assert_eq!(
            bob.ratchet_generation, 1,
            "receiver must land on generation 1"
        );
        assert_eq!(alice.ratchet_generation, 1);

        // Bidirectional continuity after the race.
        let bm = bob.ratchet_encrypt(b"bob-live").unwrap();
        let nonce: [u8; 12] = bm.nonce.clone().try_into().unwrap();
        let pt = alice.ratchet_decrypt(&nonce, &bm.ciphertext).unwrap();
        assert_eq!(pt, b"bob-live");
    }

    /// Audit #1: an unacknowledged outgoing rekey proposal must be RE-SENT
    /// (re-attached to a later message), never TTL-committed. The peer that
    /// ignores the first carrier must still be able to adopt the proposal from
    /// the re-sent carrier and ACK it.
    #[test]
    fn test_double_ratchet_rekey_resend_not_commit() {
        let probe = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&probe.x25519_pk, &probe.mlkem_pk).unwrap();
        let mut alice =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, true, None, None).unwrap();
        let mut bob =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, false, None, None).unwrap();
        alice.peer_x25519_pk = Some(bob.our_hybrid_pair.x25519_pk);
        alice.peer_mlkem_pk = Some(bob.our_hybrid_pair.mlkem_pk.clone());
        bob.peer_x25519_pk = Some(alice.our_hybrid_pair.x25519_pk);
        bob.peer_mlkem_pk = Some(alice.our_hybrid_pair.mlkem_pk.clone());

        // Alice sends 0..=101; a rekey attaches at seq 100. Bob decrypts only
        // 0..=99 — the rekey carrier (seq 100) is bound by AAD to the rekey
        // payload, so a client that never calls the rekey-aware decrypt path
        // (the legacy Android behavior — audit #1) simply cannot decrypt it and
        // the message is lost for Bob.
        let mut alice_msgs = Vec::new();
        for i in 0..=101u64 {
            alice_msgs.push(alice.ratchet_encrypt(format!("m{i}").as_bytes()).unwrap());
        }
        assert!(
            alice_msgs[100].rekey_x25519_pk.is_some(),
            "rekey attaches at seq 100"
        );
        for msg in &alice_msgs[..100] {
            let nonce: [u8; 12] = msg.nonce.clone().try_into().unwrap();
            bob.ratchet_decrypt(&nonce, &msg.ciphertext).unwrap();
        }
        assert!(
            alice.outgoing_proposal.root_key.is_some(),
            "proposal must stay pending (no TTL commit)"
        );
        assert_eq!(
            alice.ratchet_generation, 0,
            "no TTL auto-commit: gen must not bump"
        );

        // Simulate the retry TTL expiring by aging the confirm-queue entry.
        if let Some(carrier) = alice.rekey_pending_confirm_queue.back_mut() {
            carrier.attached_at = std::time::Instant::now() - std::time::Duration::from_secs(31);
        }
        // Next message re-attaches the SAME proposal (re-send) with a fresh carrier.
        let resent = alice.ratchet_encrypt(b"resent-carrier").unwrap();
        assert!(
            resent.rekey_x25519_pk.is_some(),
            "re-send must re-attach the rekey payload"
        );
        assert_eq!(
            alice.ratchet_generation, 0,
            "re-send must not commit either"
        );
        assert!(alice.outgoing_proposal.root_key.is_some());

        // Bob decrypts the re-sent carrier via the rekey-aware path, adopts the
        // proposal and ACKs with the NEW carrier seq (101 = message index 101).
        let nonce: [u8; 12] = resent.nonce.clone().try_into().unwrap();
        let xpk: [u8; 32] = resent
            .rekey_x25519_pk
            .as_ref()
            .unwrap()
            .clone()
            .try_into()
            .unwrap();
        let pt = bob
            .ratchet_decrypt_with_rekey(
                &nonce,
                &resent.ciphertext,
                resent.rekey_ciphertext.as_deref(),
                Some(&xpk),
                resent.rekey_mlkem_pk.as_deref(),
            )
            .unwrap();
        assert_eq!(pt, b"resent-carrier");
        let ack_seq = bob
            .take_pending_rekey_ack_seq()
            .expect("Bob must ACK the re-sent carrier");
        assert!(
            alice.process_rekey_ack(ack_seq),
            "re-sent carrier seq must match the queue"
        );
        assert_eq!(
            alice.ratchet_generation, 1,
            "ACK commit bumps generation exactly once"
        );
        assert!(alice.outgoing_proposal.root_key.is_none());
    }

    /// Audit #2 known-answer test: the canonical session-key derivation salt
    /// must be the exact bytes `b"kyberpipe-sync-v1"`, and the UniFFI export
    /// must return those SAME bytes the desktop uses in its pairing handler.
    /// Android consumes `sessionDerivationSalt()` — any divergence here breaks
    /// every session-key payload between the platforms.
    #[test]
    fn test_session_derivation_salt_kat() {
        let canonical: &[u8] = b"kyberpipe-sync-v1";
        assert_eq!(SESSION_KEY_DERIVATION_SALT, canonical);
        // The UniFFI-exported accessor must return the identical bytes.
        let exported = crate::crypto_api::session_derivation_salt();
        assert_eq!(exported, canonical.to_vec());
        // Deriving with the exported salt must match deriving with the literal.
        let ss = [7u8; 32];
        let a = derive_session_key(&ss, canonical, b"kyberpipe-hybrid-session").unwrap();
        let b = derive_session_key(&ss, &exported, b"kyberpipe-hybrid-session").unwrap();
        assert_eq!(a, b);
        // The Android bug (hex-encoding as ASCII) must produce DIFFERENT bytes
        // — proving the fix matters and the old call site was wrong.
        let wrong_salt = b"6b79626572706970652d73796e632d7631".to_vec();
        assert_ne!(wrong_salt, canonical);
    }

    #[test]
    fn test_sas_code_generation() {
        let sas1 =
            generate_sas_code(b"host_pk_123", b"client_pk_456", b"shared_secret_789").unwrap();
        let sas2 =
            generate_sas_code(b"host_pk_123", b"client_pk_456", b"shared_secret_789").unwrap();
        assert_eq!(sas1.len(), 7);
        assert_eq!(sas1, sas2);
    }

    #[test]
    fn test_padding_and_unpadding() {
        let original = b"Kyberpipe Cover Traffic Padding Test Payload";
        let padded = pad_payload(original).unwrap();
        assert_eq!(padded.len(), 256);

        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(original.to_vec(), unpadded);
    }

    #[test]
    #[allow(deprecated)] // split_secret_shamir is superseded by *_with_meta; retained for legacy recovery
    fn test_shamir_secret_sharing() {
        let master_key = b"Kyberpipe Master Identity Secret Key Recovery Test";
        let shares = split_secret_shamir(master_key, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // AUDIT #5 (follow-up): the recovered bytes must EQUAL the secret, not
        // just match in length. The legacy assertion only checked length, which
        // masked a broken GF(2^8) LOG table that produced garbage shares.
        let recovered = reconstruct_secret_shamir(&shares[0..2], 2).unwrap();
        assert_eq!(recovered.len(), master_key.len());
        assert_eq!(recovered.as_slice(), master_key, "recovered secret must equal the original");
    }

    #[test]
    fn test_mldsa_signature_verification() {
        let (pk, sk) = generate_mldsa_keypair();
        let payload = b"NIST ML-DSA-65 WASM Script Signing Payload";
        let sig = sign_mldsa_payload(payload, &sk).unwrap();
        assert!(verify_mldsa_signature(payload, &sig, &pk));
    }
}

#[cfg(test)]
proptest::proptest! {
    #[test]
    fn test_packet_padding_roundtrip_proptest(ref data in "\\PC*") {
        let original = data.as_bytes();
        if original.len() < 60000 {
            let padded = pad_payload(original).unwrap();
            let unpadded = unpad_payload(&padded).unwrap();
            assert_eq!(original, unpadded.as_slice());
        }
    }

    #[test]
    fn test_quic_frame_decode_fuzz(ref bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..2048)) {
        // Ensure QuicFrame::decode never panics on arbitrary malformed bytes
        let _ = crate::quic_app::QuicFrame::decode(bytes);
    }
}
