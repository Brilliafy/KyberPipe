//! Ratchet FFI bridge (audit KYP-2026-02 #22): thin per-peer encrypt/decrypt
//! shims over the session registry. The registry, the Synchronize protocol and
//! the RekeyAck channel live in their own submodules.

use crate::crypto;
use crate::error::KyberError;
use registry::with_ratchet_session;

pub mod registry;
pub mod rekey_ack;
pub mod sync;

pub use registry::*;
pub use rekey_ack::*;
pub use sync::*;

pub fn ratchet_encrypt_message_impl(
    peer_identity: &str,
    plaintext: &[u8],
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    with_ratchet_session(peer_identity, |ratchet| ratchet.ratchet_encrypt(plaintext))
}

pub fn ratchet_decrypt_message_impl(
    peer_identity: &str,
    msg: &crypto::RatchetEncryptedMessage,
) -> Result<Vec<u8>, KyberError> {
    // AUDIT F4: this entry point is the NON-rekey-aware path. A message whose
    // TLV carries rekey fields is AEAD-bound to those fields — decrypting it
    // here (empty AAD) would fail with a misleading "decryption failed" while
    // silently dropping the peer's rekey proposal (no Phase-1 derivation, no
    // race resolution, no ACK bookkeeping). Surface a DISTINCT
    // `CarrierMisrouted` error instead so no internal caller can silently
    // lose a carrier; the rekey-aware dispatch
    // (`ratchet_decrypt_with_rekey_message_impl` / the UniFFI binary
    // dispatcher) is the ONLY path that may consume rekey payloads.
    if msg.rekey_x25519_pk.is_some()
        || msg.rekey_mlkem_pk.is_some()
        || msg.rekey_ciphertext.is_some()
    {
        return Err(KyberError::CarrierMisrouted(
            "decrypt called on a message carrying a rekey payload — route through the rekey-aware dispatch".into(),
        ));
    }
    let nonce_arr: [u8; 12] = msg
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| KyberError::DecryptionFailed("Nonce must be 12 bytes".into()))?;
    with_ratchet_session(peer_identity, |ratchet| {
        ratchet.ratchet_decrypt(&nonce_arr, &msg.ciphertext)
    })
}

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
                zeroize::Zeroizing::new(alice_pair.x25519_sk.to_vec()),
                alice_pair.mlkem_pk.clone(),
                zeroize::Zeroizing::new(alice_pair.mlkem_sk.clone()),
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
                zeroize::Zeroizing::new(bob_pair.x25519_sk.to_vec()),
                bob_pair.mlkem_pk.clone(),
                zeroize::Zeroizing::new(bob_pair.mlkem_sk.clone()),
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
        let pt =
            ratchet_decrypt_message_impl(&bob, &msg).expect("bob decrypts post-resync message");
        assert_eq!(pt, b"after-resync");
    }

    /// AUDIT #4 (idempotent consumer): applying the SAME authenticated sync
    /// packet twice must be a no-op SUCCESS on the second application (the
    /// poll layer legitimately re-processes a sync whose first application
    /// realigned the chain). The legacy consumer returned a replay/rate-limit
    /// error that wasted the per-peer budget and logged noise.
    #[test]
    fn duplicate_sync_is_idempotent_noop() {
        let (alice, bob) = alice_bob_registry("dup-sync");
        // Alice sends 150 messages; bob misses them all.
        for _ in 0..150 {
            let _ = ratchet_encrypt_message_impl(&alice, b"p").expect("encrypt");
        }
        let sync = ratchet_synchronize_packet_binary_impl(&alice).expect("sync");
        let skipped = ratchet_process_synchronize_impl(&bob, &sync).expect("first apply");
        assert_eq!(skipped, 150);
        // Second application of the same packet: already aligned → Ok(0), no error.
        let again = ratchet_process_synchronize_impl(&bob, &sync).expect("second apply");
        assert_eq!(again, 0, "already-aligned sync must be a no-op success");
        assert_eq!(ratchet_recv_count_impl(&bob).expect("recv"), 151);
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

    /// Audit KYP-2026-02 #23: the registry lock ordering must be `map →
    /// session` (never session → map). This test hammers concurrent
    /// init/encrypt/import/remove against the SHARED process-global registry
    /// to prove the documented order holds — the class of ABBA deadlock that
    /// previously hung the session-key registry (cf. the session_handle ABBA
    /// regression test).
    #[test]
    fn registry_lock_order_no_deadlock_under_concurrency() {
        let pair = generate_hybrid_keypair();
        let our_keypair = Some((
            pair.x25519_pk.to_vec(),
            zeroize::Zeroizing::new(pair.x25519_sk.to_vec()),
            pair.mlkem_pk.clone(),
            zeroize::Zeroizing::new(pair.mlkem_sk.clone()),
        ));
        let tag = format!("lock{}", std::process::id());

        let our_keypair_a = our_keypair.clone();
        let our_keypair_b = our_keypair.clone();
        let tag_a = tag.clone();
        let tag_b = tag.clone();
        let t1 = std::thread::spawn(move || {
            for i in 0..150u32 {
                let id = format!("{tag_a}-a-{i}");
                ratchet_remove_session_impl(&id);
                ratchet_init_session_with_keypair_impl(
                    &id,
                    b"concurrent-secret-0123456789abcdef",
                    true,
                    our_keypair_a.clone(),
                    None,
                    None,
                )
                .expect("init a");
                let _ = ratchet_encrypt_message_impl(&id, b"x");
                let snap = ratchet_export_session_impl(&id)
                    .expect("export")
                    .expect("some");
                let _ = ratchet_import_session_impl(&id, &snap);
                assert!(ratchet_remove_session_impl(&id));
            }
        });
        let t2 = std::thread::spawn(move || {
            for i in 0..150u32 {
                let id = format!("{tag_b}-b-{i}");
                ratchet_remove_session_impl(&id);
                ratchet_init_session_with_keypair_impl(
                    &id,
                    b"concurrent-secret-0123456789abcdef",
                    false,
                    our_keypair_b.clone(),
                    None,
                    None,
                )
                .expect("init b");
                let _ = ratchet_encrypt_message_impl(&id, b"y");
                assert!(ratchet_remove_session_impl(&id));
            }
        });
        t1.join().expect("thread 1 must finish without deadlock");
        t2.join().expect("thread 2 must finish without deadlock");
        // No leaked sessions remain from this test.
        let peer_ids = ratchet_peer_ids_impl();
        for id in peer_ids {
            if id.contains(&tag) {
                ratchet_remove_session_impl(&id);
            }
        }
    }

    /// Audit KYP-2026-02 #11: repeated peeks of the RekeyAck must be
    /// IDEMPOTENT — the same TLV is re-served WITHOUT advancing the send chain.
    /// Previously each peek re-encrypted a fresh ack at a new seq, so N lost
    /// poll responses burned N chain positions (chain burn / skip-cache
    /// pressure / max_skip exhaustion).
    #[test]
    fn rekey_ack_peek_is_idempotent_and_does_not_burn_chain() {
        let (alice, bob) = alice_bob_registry("peek");
        // Drive alice to the rekey boundary; bob stays aligned rekey-aware.
        for _ in 0..100 {
            let msg = ratchet_encrypt_message_impl(&alice, b"x").expect("encrypt");
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
        // Alice's seq-100 carrier carries the proposal; bob adopts it.
        let carrier = ratchet_encrypt_message_impl(&alice, b"carrier").expect("carrier");
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
        .expect("bob adopts proposal");
        assert!(
            with_ratchet_session(&bob, |r| Ok(r.pending_rekey_ack_seq.is_some())).expect("ack?"),
            "bob must have a pending ack"
        );

        // The FIRST peek generates + caches the ack (one legitimate chain
        // advance: the ack is a real ratchet message). Every SUBSEQUENT peek
        // must re-serve the cached TLV without advancing the chain.
        let send_before = ratchet_send_count_impl(&bob).expect("send count");
        let ack1 = ratchet_generate_rekey_ack_binary_peek_impl(&bob)
            .expect("peek1")
            .expect("ack pending");
        let send_after_first = ratchet_send_count_impl(&bob).expect("send count");
        assert_eq!(
            send_after_first,
            send_before + 1,
            "the first peek generates exactly one ack message"
        );
        let ack2 = ratchet_generate_rekey_ack_binary_peek_impl(&bob)
            .expect("peek2")
            .expect("ack pending");
        assert_eq!(ack1, ack2, "peek must be idempotent — identical TLV");
        let send_after_second = ratchet_send_count_impl(&bob).expect("send count");
        assert_eq!(
            send_after_second, send_after_first,
            "a second peek must NOT advance the send chain"
        );
        // 100 further peeks (a long stretch of lost poll responses) must still
        // burn nothing.
        for _ in 0..100 {
            let tlv = ratchet_generate_rekey_ack_binary_peek_impl(&bob)
                .expect("peek")
                .expect("ack pending");
            assert_eq!(tlv, ack1);
        }
        assert_eq!(
            ratchet_send_count_impl(&bob).expect("send count"),
            send_after_second,
            "repeated peeks must never advance the send chain"
        );

        // The peer still commits on the (cached) ack, and after consume the
        // cache is cleared (a later peek returns None).
        assert!(
            ratchet_process_rekey_ack_binary_impl(&alice, &ack1).expect("process ack"),
            "alice commits on the cached ack"
        );
        assert!(ratchet_consume_rekey_ack_impl(&bob));
        assert!(
            ratchet_generate_rekey_ack_binary_peek_impl(&bob)
                .expect("peek after consume")
                .is_none(),
            "after consume the peek must return None"
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
            with_ratchet_session(&alice, |r| Ok(r.send.message_count)).expect("count"),
            11,
            "stale import must not regress the live send count"
        );
    }

    /// AUDIT FINDING #2 (HIGH, pairing-epoch watermark): a snapshot from a
    /// DIFFERENT pairing epoch must never be imported over a live session.
    /// The failure scenario: pair → polls advance the session to gen>0; user
    /// re-pairs (ratchetRemoveSession + fresh init, gen 0, NEW master secret);
    /// a MainActivity recreation then re-imports the OLD pre-re-pair snapshot
    /// (gen>0, OLD key material). The legacy high-water guard evaluates
    /// live.gen(0) > snap.gen(G) → false, so the import would proceed and
    /// REVERT the fresh session — a silent state rollback that presents as
    /// "paired but nothing syncs". The epoch watermark refuses it.
    #[test]
    fn cross_epoch_snapshot_import_is_refused() {
        let (alice, bob) = alice_bob_registry("epoch");
        // Advance alice's live session past a rekey boundary by running a full
        // round-trip against bob (alice encrypts, bob decrypts rekey-aware,
        // bob ACKs, alice commits) — mirroring the production ACK channel.
        for _ in 0..100 {
            let msg = ratchet_encrypt_message_impl(&alice, b"old-pairing").expect("encrypt");
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
        // The seq-100 carrier staged alice's proposal on bob; bob ACKs it and
        // alice commits → gen 1. (This mirrors the wire RekeyAck round-trip.)
        let carrier = ratchet_encrypt_message_impl(&alice, b"carrier").expect("carrier");
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
        .expect("bob adopts proposal");
        let ack_seq = with_ratchet_session(&bob, |r| Ok(r.pending_rekey_ack_seq)).expect("ack");
        if let Some(seq) = ack_seq {
            assert!(
                ratchet_process_rekey_ack_impl(&alice, seq).expect("process ack"),
                "alice must commit her outgoing rekey on bob's ack"
            );
        }
        assert!(
            with_ratchet_session(&alice, |r| Ok(r.ratchet_generation)).expect("gen") > 0,
            "precondition: the old-pairing session advanced past a rekey boundary"
        );
        let old_snap = ratchet_export_session_impl(&alice)
            .expect("export")
            .expect("session exists");

        // Simulate a RE-PAIR: remove the old session and init a FRESH one (gen
        // 0, new master secret), then bump its pairing epoch — exactly what the
        // Android flow does after `ratchetRemoveSession` + fresh init.
        ratchet_remove_session_impl(&alice);
        let pair = generate_hybrid_keypair();
        ratchet_init_session_with_keypair_impl(
            &alice,
            b"fresh-repair-master-secret-0123456789abcdef",
            true,
            Some((
                pair.x25519_pk.to_vec(),
                zeroize::Zeroizing::new(pair.x25519_sk.to_vec()),
                pair.mlkem_pk.clone(),
                zeroize::Zeroizing::new(pair.mlkem_sk.clone()),
            )),
            None,
            None,
        )
        .expect("fresh re-pair init");
        ratchet_bump_pairing_epoch_impl(&alice).expect("bump: live session exists");
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.pairing_epoch)).expect("epoch"),
            1,
            "the re-paired session must carry epoch 1"
        );
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.ratchet_generation)).expect("gen"),
            0,
            "the re-paired session must be fresh (gen 0)"
        );

        // The OLD snapshot (epoch 0, gen>0) is STRICTLY AHEAD of the fresh live
        // session (epoch 1, gen 0) — the legacy high-water guard would import
        // it. The epoch watermark must refuse it.
        ratchet_import_session_impl(&alice, &old_snap).expect("import call");
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.pairing_epoch)).expect("epoch"),
            1,
            "cross-epoch snapshot must NOT overwrite the re-paired session"
        );
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.ratchet_generation)).expect("gen"),
            0,
            "the re-paired session must remain fresh after the refused import"
        );
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.root_key)).expect("root"),
            {
                let shared = b"fresh-repair-master-secret-0123456789abcdef";
                let p = generate_hybrid_keypair();
                let probe = crate::crypto::DoubleRatchetState::new_with_keypair(
                    shared, true, p, None, None,
                )
                .expect("probe init");
                probe.root_key
            },
            "the re-paired session's root key must NOT revert to the old pairing's key material"
        );
    }

    /// AUDIT #2 (follow-up, HIGH): the import guard must be SEND-CHAIN-AWARE.
    /// The legacy guard compared only (ratchet_generation, recv_message_count),
    /// so a live session that had sent MORE than the snapshot contained was
    /// judged "not ahead" and the import rolled the SEND chain back — the
    /// derived message keys and (generation, seq) nonces would then be reused
    /// for NEW plaintext (the exact IV-reuse class the nonce redesign
    /// eliminates elsewhere). This test drives the failure scenario: identical
    /// epoch, generation and recv count, but live send > snapshot send.
    #[test]
    fn send_chain_rollback_import_is_refused() {
        let (alice, _bob) = alice_bob_registry("sendwm");
        // Alice sends 2 messages, then the snapshot is taken (send = 2, recv = 0).
        for _ in 0..2 {
            let _ = ratchet_encrypt_message_impl(&alice, b"a").expect("encrypt");
        }
        let snap = ratchet_export_session_impl(&alice)
            .expect("export")
            .expect("session exists");
        // The live session keeps SENDING (3 more messages — the phone sent
        // seq 0..=4 while the snapshot on disk is from seq 2).
        for _ in 0..3 {
            let _ = ratchet_encrypt_message_impl(&alice, b"b").expect("encrypt");
        }

        // Preconditions: identical epoch/gen/recv, live send strictly ahead.
        let wm_live = ratchet_session_watermark_impl(&alice)
            .expect("live wm")
            .expect("some");
        let wm_snap = ratchet_snapshot_watermark_impl(&snap)
            .expect("snap wm")
            .expect("some");
        assert_eq!(wm_live.pairing_epoch, wm_snap.pairing_epoch);
        assert_eq!(wm_live.ratchet_generation, wm_snap.ratchet_generation);
        assert_eq!(wm_live.recv_message_count, wm_snap.recv_message_count);
        assert!(
            wm_live.send_message_count > wm_snap.send_message_count,
            "precondition: the live send chain is ahead of the snapshot"
        );
        assert!(
            wm_live.is_ahead_of(&wm_snap),
            "the 4-tuple watermark must capture the send-chain lead"
        );

        // The old guard (gen, recv) would have allowed this import. It must be
        // REFUSED now — the live send chain must not roll back to 2.
        ratchet_import_session_impl(&alice, &snap).expect("import call");
        assert_eq!(
            ratchet_send_count_impl(&alice).expect("send count"),
            wm_live.send_message_count,
            "send-chain rollback must be refused: the live send count must stay ahead"
        );
    }

    /// AUDIT #1 (HIGH, one-sided rollback): the watermark guard must be
    /// COMPONENT-WISE, not lexicographic. The legacy lexicographic order let
    /// the send chain's lead mask a recv-chain regression: live send=0/recv=100
    /// with snapshot send=50/recv=0 was judged "not a rollback" (send 0 < 50
    /// ⇒ live not ahead) and imported — replacing the live receiving chain at
    /// seq 100 with the snapshot's at seq 0 (silent desync + an authenticated
    /// replay window for messages 0..=99). The component-wise guard refuses
    /// because the snapshot regresses the recv chain, even though it leads the
    /// send chain.
    #[test]
    fn mixed_send_recv_snapshot_is_refused_componentwise() {
        let (alice, bob) = alice_bob_registry("mixedwm");
        // Bob sends 100 messages; Alice receives all of them → live (0,0,0,100).
        for _ in 0..100 {
            let m = ratchet_encrypt_message_impl(&bob, b"p").expect("bob encrypt");
            ratchet_decrypt_message_impl(&alice, &m).expect("alice decrypt");
        }
        let live_wm = ratchet_session_watermark_impl(&alice)
            .expect("live wm")
            .expect("some");
        assert_eq!(live_wm.send_message_count, 0, "precondition: nothing sent");
        assert_eq!(
            live_wm.recv_message_count, 100,
            "precondition: all received"
        );

        // A same-user snapshot from a device with the OPPOSITE traffic pattern:
        // ahead in send (50) but behind in recv (0). Patch the exported JSON's
        // two counters to build the hostile watermark.
        let snap = ratchet_export_session_impl(&alice)
            .expect("export")
            .expect("session exists");
        let mut v: serde_json::Value = serde_json::from_slice(&snap).expect("snap json");
        v["send_message_count"] = serde_json::json!(50u64);
        v["recv_message_count"] = serde_json::json!(0u64);
        let hostile = serde_json::to_vec(&v).expect("hostile snap");
        let snap_wm = ratchet_snapshot_watermark_impl(&hostile)
            .expect("snap wm")
            .expect("some");
        assert!(snap_wm.send_message_count > live_wm.send_message_count);
        assert!(snap_wm.recv_message_count < live_wm.recv_message_count);
        // Under the OLD lexicographic guard this import would have been ALLOWED
        // (live send 0 < snapshot send 50 ⇒ live not ahead).
        assert!(
            !live_wm.is_ahead_of(&snap_wm),
            "precondition: incomparable watermarks — the exact case lexicographic order got wrong"
        );

        // The component-wise guard must REFUSE: the snapshot regresses recv.
        ratchet_import_session_impl(&alice, &hostile).expect("import call");
        let after = ratchet_session_watermark_impl(&alice)
            .expect("after wm")
            .expect("some");
        assert_eq!(
            after, live_wm,
            "the recv-chain rollback must be refused — live session untouched"
        );
        assert_eq!(
            ratchet_recv_count_impl(&alice).expect("recv count"),
            100,
            "live receiving chain must stay positioned at seq 100"
        );
    }

    /// AUDIT F3 (LOW/MEDIUM): an AEAD-valid but MALFORMED cross-generation
    /// Synchronize must NOT advance the live session. The legacy code ran the
    /// rekey-aware decrypt against the LIVE state — a gen+1 packet that
    /// authenticates on the pending chain COMMITTED the incoming rekey
    /// (generation bump, counter reset, seen-set clear) BEFORE the payload was
    /// verified, so a compromised/buggy paired peer could leave the session at
    /// a new generation on an error path (the caller sees an error, the state
    /// has already advanced, and watermark accounting no longer reflects the
    /// jump). The decrypt now runs on a TRIAL CLONE and commits to the live
    /// session only after decrypt AND verify both pass.
    #[test]
    fn cross_gen_sync_with_malformed_payload_does_not_commit() {
        let (alice, bob) = alice_bob_registry("f3-malformed");

        // Alice sends 100 messages; bob receives them so the chains align.
        for _ in 0..100 {
            let m = ratchet_encrypt_message_impl(&alice, b"p").expect("encrypt");
            ratchet_decrypt_message_impl(&bob, &m).expect("decrypt");
        }
        // Alice stages the rekey carrier at seq 100; bob derives the pending
        // incoming proposal (gen 1) WITHOUT committing — bob stays at gen 0.
        let carrier = ratchet_encrypt_message_impl(&alice, b"carrier").expect("carrier");
        assert!(
            carrier.rekey_ciphertext.is_some(),
            "carrier carries the rekey"
        );
        let rekey_x = <[u8; 32]>::try_from(carrier.rekey_x25519_pk.as_deref().unwrap()).unwrap();
        with_ratchet_session(&bob, |r| {
            r.ratchet_decrypt_with_rekey(
                &<[u8; 12]>::try_from(carrier.nonce.as_slice()).expect("nonce"),
                &carrier.ciphertext,
                carrier.rekey_ciphertext.as_deref(),
                Some(&rekey_x),
                carrier.rekey_mlkem_pk.as_deref(),
            )
        })
        .expect("bob derives the pending proposal");
        assert_eq!(
            with_ratchet_session(&bob, |r| Ok(r.ratchet_generation)).expect("gen"),
            0,
            "bob must still be at gen 0 — proposal pending, not committed"
        );
        assert!(
            with_ratchet_session(&bob, |r| Ok(r.incoming_proposal.root_key.is_some()
                || r.incoming_proposal.receiving_chain_key.is_some()))
            .expect("pending"),
            "bob holds a pending incoming proposal"
        );

        // Alice commits her outgoing proposal (the peer's ACK) → gen 1.
        assert!(
            ratchet_process_rekey_ack_impl(&alice, 100).expect("ack"),
            "alice commits her outgoing rekey"
        );
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.ratchet_generation)).expect("gen"),
            1,
            "alice is at gen 1"
        );

        // The compromised/buggy paired peer produces an AEAD-VALID gen-1
        // message whose payload is NOT a Synchronize. It authenticates on
        // bob's pending chain (both sides derived the same rekey keys) but
        // must NOT commit bob's session — the live state stays untouched.
        let malformed =
            ratchet_encrypt_message_impl(&alice, b"{\"type\":\"clipboard\",\"text\":\"pwn\"}")
                .expect("alice (gen 1) encrypts a non-sync payload")
                .to_binary()
                .expect("binary");
        assert!(
            ratchet_process_synchronize_impl(&bob, &malformed).is_err(),
            "malformed cross-gen sync must be rejected"
        );
        assert_eq!(
            with_ratchet_session(&bob, |r| Ok(r.ratchet_generation)).expect("gen"),
            0,
            "the session must NOT advance on an AEAD-valid-but-malformed sync (AUDIT F3)"
        );
        assert!(
            with_ratchet_session(&bob, |r| Ok(r.incoming_proposal.root_key.is_some()
                || r.incoming_proposal.receiving_chain_key.is_some()))
            .expect("pending"),
            "the pending incoming proposal must survive the rejected sync"
        );
    }

    /// AUDIT F3 (control): a WELL-FORMED cross-generation Synchronize still
    /// applies — the trial clone's decrypt + verify both pass, and the session
    /// advances to gen 1 exactly as before.
    #[test]
    fn cross_gen_sync_with_valid_payload_commits() {
        let (alice, bob) = alice_bob_registry("f3-valid");
        for _ in 0..100 {
            let m = ratchet_encrypt_message_impl(&alice, b"p").expect("encrypt");
            ratchet_decrypt_message_impl(&bob, &m).expect("decrypt");
        }
        let carrier = ratchet_encrypt_message_impl(&alice, b"carrier").expect("carrier");
        let rekey_x = <[u8; 32]>::try_from(carrier.rekey_x25519_pk.as_deref().unwrap()).unwrap();
        with_ratchet_session(&bob, |r| {
            r.ratchet_decrypt_with_rekey(
                &<[u8; 12]>::try_from(carrier.nonce.as_slice()).expect("nonce"),
                &carrier.ciphertext,
                carrier.rekey_ciphertext.as_deref(),
                Some(&rekey_x),
                carrier.rekey_mlkem_pk.as_deref(),
            )
        })
        .expect("bob derives the pending proposal");
        assert!(
            ratchet_process_rekey_ack_impl(&alice, 100).expect("ack"),
            "alice commits her outgoing rekey"
        );
        assert_eq!(
            with_ratchet_session(&alice, |r| Ok(r.ratchet_generation)).expect("gen"),
            1
        );

        // A REAL Synchronize from gen 1 applies and advances bob.
        let sync = ratchet_synchronize_packet_binary_impl(&alice).expect("gen-1 sync");
        let res = ratchet_process_synchronize_impl(&bob, &sync).expect("apply cross-gen sync");
        assert_eq!(res, 0);
        assert_eq!(
            with_ratchet_session(&bob, |r| Ok(r.ratchet_generation)).expect("gen"),
            1,
            "a valid cross-generation sync must commit the pending proposal"
        );
    }

    /// AUDIT F4 (LOW): the internal non-rekey-aware decrypt entry point must
    /// surface a DISTINCT `CarrierMisrouted` error when handed a message that
    /// carries rekey fields, instead of failing AEAD with a misleading
    /// "decryption failed" and silently dropping the peer's rekey proposal.
    #[test]
    fn plain_decrypt_rejects_carrier_with_distinct_error() {
        let (alice, bob) = alice_bob_registry("f4-misroute");
        // Alice sends 100 messages; bob receives them so the chains align.
        for _ in 0..100 {
            let m = ratchet_encrypt_message_impl(&alice, b"p").expect("encrypt");
            ratchet_decrypt_message_impl(&bob, &m).expect("decrypt");
        }
        // The rekey carrier at seq 100 carries rekey fields.
        let carrier = ratchet_encrypt_message_impl(&alice, b"carrier").expect("carrier");
        assert!(
            carrier.rekey_ciphertext.is_some(),
            "carrier must carry the rekey payload"
        );

        // Routing the carrier through the PLAIN path must fail with the
        // distinct CarrierMisrouted error — and must NOT have advanced bob's
        // session or derived/committed anything.
        let before = ratchet_recv_count_impl(&bob).expect("recv before");
        let err = ratchet_decrypt_message_impl(&bob, &carrier)
            .expect_err("plain path must reject a carrier");
        assert!(
            matches!(err, KyberError::CarrierMisrouted(_)),
            "expected CarrierMisrouted, got: {err:?}"
        );
        assert_eq!(err.error_code(), "CARRIER_MISROUTED");
        assert_eq!(
            ratchet_recv_count_impl(&bob).expect("recv after"),
            before,
            "the misrouted carrier must not advance the chain"
        );
        assert!(
            with_ratchet_session(&bob, |r| Ok(r.incoming_proposal.root_key.is_none()))
                .expect("no proposal"),
            "no proposal may be derived on the misrouted plain path"
        );

        // Control: the SAME carrier decrypts fine through the rekey-aware
        // dispatch (the production path), proving only the plain entry point
        // is blocked.
        let rekey_x = <[u8; 32]>::try_from(carrier.rekey_x25519_pk.as_deref().unwrap()).unwrap();
        let pt = with_ratchet_session(&bob, |r| {
            r.ratchet_decrypt_with_rekey(
                &<[u8; 12]>::try_from(carrier.nonce.as_slice()).expect("nonce"),
                &carrier.ciphertext,
                carrier.rekey_ciphertext.as_deref(),
                Some(&rekey_x),
                carrier.rekey_mlkem_pk.as_deref(),
            )
        })
        .expect("rekey-aware decrypt of the carrier");
        assert_eq!(pt, b"carrier");
    }
}
