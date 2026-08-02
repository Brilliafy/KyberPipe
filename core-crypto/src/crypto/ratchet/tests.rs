//! Regression tests for the ratchet rekey machinery (audit findings #1/#2/#3).
//!
//! The critical property: a long-lived session MUST survive crossing a rekey
//! boundary (seq 100, 200, ...) in BOTH directions, including under out-of-order
//! delivery of the messages straddling the boundary. The legacy implementation
//! guaranteed a permanent desync at the first rekey because the sender
//! encapsulated to the peer's PAIRING public keys while the receiver
//! decapsulated with a fresh, never-exchanged ratchet keypair.

use super::state::DoubleRatchetState;
use crate::crypto::{generate_hybrid_keypair, HybridKeyPair};

/// Build two interoperating ratchets. Each side uses its OWN pairing keypair as
/// the initial DH identity and the peer's public halves as `peer_*` keys — the
/// exact contract production callers now follow (audit finding #1).
fn alice_bob() -> (DoubleRatchetState, DoubleRatchetState) {
    let alice_pair = generate_hybrid_keypair();
    let bob_pair = generate_hybrid_keypair();
    let shared = b"test-master-shared-secret-0123456789abcdef";

    let alice = DoubleRatchetState::new_with_keypair(
        shared,
        true, // initiator
        alice_pair.clone(),
        Some(bob_pair.x25519_pk),
        Some(bob_pair.mlkem_pk.clone()),
    )
    .expect("alice init");
    let bob = DoubleRatchetState::new_with_keypair(
        shared,
        false, // responder
        bob_pair,
        Some(alice_pair.x25519_pk),
        Some(alice_pair.mlkem_pk.clone()),
    )
    .expect("bob init");
    (alice, bob)
}

/// Encrypt a message with alice's ratchet (rekey payloads auto-attached at the
/// interval) and decrypt it with bob's rekey-aware path.
fn a2b(alice: &mut DoubleRatchetState, bob: &mut DoubleRatchetState, i: u64) {
    let msg = alice
        .ratchet_encrypt(format!("alice-{i}").as_bytes())
        .expect("alice encrypt");
    let rekey_x = msg
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("rekey x25519 pk must be 32 bytes"));
    let plaintext = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(msg.nonce.as_slice()).expect("nonce 12 bytes"),
            &msg.ciphertext,
            msg.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            msg.rekey_mlkem_pk.as_deref(),
        )
        .unwrap_or_else(|e| panic!("bob decrypt of alice-{i} failed: {e}"));
    assert_eq!(plaintext, format!("alice-{i}").as_bytes());
}

/// Encrypt a message with bob's ratchet and decrypt with alice's rekey-aware path.
fn b2a(alice: &mut DoubleRatchetState, bob: &mut DoubleRatchetState, i: u64) {
    let msg = bob
        .ratchet_encrypt(format!("bob-{i}").as_bytes())
        .expect("bob encrypt");
    let rekey_x = msg
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("rekey x25519 pk must be 32 bytes"));
    let plaintext = alice
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(msg.nonce.as_slice()).expect("nonce 12 bytes"),
            &msg.ciphertext,
            msg.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            msg.rekey_mlkem_pk.as_deref(),
        )
        .unwrap_or_else(|e| panic!("alice decrypt of bob-{i} failed: {e}"));
    assert_eq!(plaintext, format!("bob-{i}").as_bytes());
}

#[test]
fn rekey_survives_100_message_boundary_both_directions() {
    let (mut alice, mut bob) = alice_bob();

    // Drive 250 messages per direction — crosses rekey boundaries at seq 100 and
    // 200. Every message must decrypt, proving the rekey KEM keypairs match and
    // the pending-chain fallback works.
    for i in 0..250 {
        a2b(&mut alice, &mut bob, i);
        b2a(&mut alice, &mut bob, i);
        // Interleave: bob sends its RekeyAck when it has one pending so alice can
        // commit her outgoing proposal.
        if let Some(ack_seq) = bob.take_pending_rekey_ack_seq() {
            let ack = bob.generate_rekey_ack(ack_seq).expect("ack");
            let pt = alice
                .ratchet_decrypt(
                    &<[u8; 12]>::try_from(ack.nonce.as_slice()).unwrap(),
                    &ack.ciphertext,
                )
                .expect("alice processes rekey ack");
            let decoded = crate::packets::safe_decode_packet(&pt).unwrap();
            if let crate::packets::KyberMessage::RekeyAck { seq } = decoded {
                // The ACK for an already-committed carrier may legitimately arrive
                // twice (bob re-derives it while catching up) — ignore those.
                if !alice.rekey_pending_confirm_queue.is_empty() {
                    assert!(alice.process_rekey_ack(seq), "alice must commit on ack");
                }
            }
        }
    }

    assert!(
        alice.ratchet_generation >= 2,
        "alice must have crossed rekey boundaries, generation={}",
        alice.ratchet_generation
    );
    assert!(
        bob.ratchet_generation >= 2,
        "bob must have crossed rekey boundaries, generation={}",
        bob.ratchet_generation
    );
    assert_eq!(alice.send_message_count, bob.recv_message_count);
    assert_eq!(bob.send_message_count, alice.recv_message_count);
}

#[test]
fn rekey_survives_out_of_order_delivery_at_boundary() {
    let (mut alice, mut bob) = alice_bob();

    // Drive exactly to the first rekey boundary: 100 messages → send count 100.
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }

    // Alice sends the carrier (seq 100, carries the rekey payload).
    let carrier = alice.ratchet_encrypt(b"carrier".as_ref()).expect("carrier");
    assert!(
        carrier.rekey_ciphertext.is_some(),
        "carrier at seq 100 must carry a rekey payload"
    );
    // Bob processes the carrier: pending proposal derived, ack queued.
    let rekey_x_carrier = carrier
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    bob.ratchet_decrypt_with_rekey(
        &<[u8; 12]>::try_from(carrier.nonce.as_slice()).unwrap(),
        &carrier.ciphertext,
        carrier.rekey_ciphertext.as_deref(),
        rekey_x_carrier.as_ref(),
        carrier.rekey_mlkem_pk.as_deref(),
    )
    .expect("bob decrypts carrier");

    // Bob ACKs; alice commits her outgoing rekey (generation 1, counters reset).
    while let Some(ack_seq) = bob.take_pending_rekey_ack_seq() {
        let ack = bob.generate_rekey_ack(ack_seq).expect("ack");
        let pt = alice
            .ratchet_decrypt(
                &<[u8; 12]>::try_from(ack.nonce.as_slice()).unwrap(),
                &ack.ciphertext,
            )
            .expect("alice decrypts ack");
        let decoded = crate::packets::safe_decode_packet(&pt).unwrap();
        if let crate::packets::KyberMessage::RekeyAck { seq } = decoded {
            assert!(alice.process_rekey_ack(seq));
        }
    }
    assert_eq!(alice.ratchet_generation, 1);
    assert_eq!(alice.send_message_count, 0);

    // Now the boundary-straddling messages: alice sends two new-generation
    // messages (seq 0 and seq 1) and two OLD-generation messages are still in
    // flight (seq 101, 102 — sent before alice committed, delivered late).
    let post0 = alice.ratchet_encrypt(b"post0".as_ref()).expect("post0"); // gen 1, seq 0
    let post1 = alice.ratchet_encrypt(b"post1".as_ref()).expect("post1"); // gen 1, seq 1
                                                                          // Old-generation in-flight messages (encrypted by bob's perspective is
                                                                          // alice's gen 0 — but alice is now gen 1; the "old" messages are the ones
                                                                          // bob would send, which is a different chain. To exercise audit #2 we must
                                                                          // deliver the NEW-gen messages out of order, so deliver post1 first.)

    // BOB receives the FIRST new-generation message as seq 1 (seq 0 lost/delayed):
    // the pending-chain fallback must anchor at position 0, not at bob's
    // recv_message_count (101).
    let rekey_x1 = post1
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(post1.nonce.as_slice()).unwrap(),
            &post1.ciphertext,
            post1.rekey_ciphertext.as_deref(),
            rekey_x1.as_ref(),
            post1.rekey_mlkem_pk.as_deref(),
        )
        .expect("bob must decrypt the out-of-order first new-gen message");
    assert_eq!(pt, b"post1");
    // Bob has now committed the pending proposal.
    assert_eq!(bob.ratchet_generation, 1);
    // The delayed seq 0 arrives — recovered from the skip key cached during the
    // pending-chain advance.
    let rekey_x0 = post0
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(post0.nonce.as_slice()).unwrap(),
            &post0.ciphertext,
            post0.rekey_ciphertext.as_deref(),
            rekey_x0.as_ref(),
            post0.rekey_mlkem_pk.as_deref(),
        )
        .expect("delayed new-gen seq 0 must decrypt via cached skip key");
    assert_eq!(pt, b"post0");

    // The session must keep working bidirectionally past the boundary.
    for i in 0..60 {
        a2b(&mut alice, &mut bob, i);
        b2a(&mut alice, &mut bob, i);
    }
}

#[test]
fn previous_generation_messages_decrypt_after_commit() {
    // Audit finding #3: after alice commits her outgoing rekey, bob's messages
    // that were in flight on the OLD generation must still decrypt.
    let (mut alice, mut bob) = alice_bob();

    // Drive exactly to the boundary: 100 messages → send count 100.
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }
    let carrier = alice.ratchet_encrypt(b"carrier".as_ref()).expect("carrier");
    assert!(
        carrier.rekey_ciphertext.is_some(),
        "carrier at seq 100 must carry a rekey payload"
    );

    // Bob processes the carrier and ACKs it; alice commits her outgoing rekey.
    let rekey_x_carrier = carrier
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    bob.ratchet_decrypt_with_rekey(
        &<[u8; 12]>::try_from(carrier.nonce.as_slice()).unwrap(),
        &carrier.ciphertext,
        carrier.rekey_ciphertext.as_deref(),
        rekey_x_carrier.as_ref(),
        carrier.rekey_mlkem_pk.as_deref(),
    )
    .expect("bob decrypts carrier");
    while let Some(ack_seq) = bob.take_pending_rekey_ack_seq() {
        let ack = bob.generate_rekey_ack(ack_seq).expect("ack");
        let pt = alice
            .ratchet_decrypt(
                &<[u8; 12]>::try_from(ack.nonce.as_slice()).unwrap(),
                &ack.ciphertext,
            )
            .expect("alice decrypts ack");
        let decoded = crate::packets::safe_decode_packet(&pt).unwrap();
        if let crate::packets::KyberMessage::RekeyAck { seq } = decoded {
            assert!(alice.process_rekey_ack(seq));
        }
    }
    // Alice is now on generation 1.
    assert_eq!(alice.ratchet_generation, 1);
    assert!(alice.previous_recv_chain_key.is_some());

    // Bob still has in-flight OLD-generation messages (he has not yet committed).
    let msg = bob
        .ratchet_encrypt(b"late-old-gen".as_ref())
        .expect("old gen msg");
    // This message is (gen 0, seq 0) — bob's sending chain was never reset, so
    // it is bob's first message and still on the old generation.
    let rekey_x = msg
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = alice
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(msg.nonce.as_slice()).unwrap(),
            &msg.ciphertext,
            msg.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            msg.rekey_mlkem_pk.as_deref(),
        )
        .unwrap_or_else(|e| panic!("late old-gen message must decrypt: {e}"));
    assert_eq!(pt, b"late-old-gen");
}

#[test]
fn resync_refuses_pending_rekey_and_bounds_gap() {
    let (mut alice, _bob) = alice_bob();
    // A pending incoming proposal blocks resync (audit finding #4).
    let mut pending = alice.clone();
    // Fake an unconsumed pending proposal.
    pending.pending_root_key = Some([7u8; 32]);
    pending.pending_receiving_chain_key = Some([8u8; 32]);
    assert!(
        pending.resync_receiving_chain(50).is_err(),
        "resync must refuse across a pending rekey"
    );
    // Gap beyond SYNC_MAX_GAP is rejected.
    assert!(alice.resync_receiving_chain(2000).is_err());
    // A sane in-budget resync succeeds.
    assert!(alice.resync_receiving_chain(50).is_ok());
    // Cumulative budget eventually exhausts.
    let mut alice2 = alice_bob().0;
    let mut advanced: u64 = 0;
    while advanced < super::decrypt::SYNC_MAX_CUMULATIVE + 100 {
        match alice2.resync_receiving_chain(alice2.recv_message_count + 999) {
            Ok(gap) => advanced += gap,
            Err(_) => break,
        }
    }
    assert!(
        advanced <= super::decrypt::SYNC_MAX_CUMULATIVE,
        "cumulative resync advancement must be capped, got {advanced}"
    );
}

#[test]
fn ratchet_message_binary_tlv_roundtrip() {
    // Audit finding #12: the binary TLV framing must round-trip every field,
    // including the optional rekey payload, so both platforms can exchange the
    // typed record without hex-in-JSON drift.
    let with_rekey = super::tlv::RatchetEncryptedMessage {
        nonce: vec![1u8; 12],
        ciphertext: vec![2u8; 64],
        rekey_x25519_pk: Some(vec![3u8; 32]),
        rekey_mlkem_pk: Some(vec![4u8; 1184]),
        rekey_ciphertext: Some(vec![5u8; 1088]),
    };
    let bytes = with_rekey.to_binary().unwrap();
    let decoded = super::tlv::RatchetEncryptedMessage::from_binary(&bytes).unwrap();
    assert_eq!(decoded.nonce, with_rekey.nonce);
    assert_eq!(decoded.ciphertext, with_rekey.ciphertext);
    assert_eq!(decoded.rekey_x25519_pk, with_rekey.rekey_x25519_pk);
    assert_eq!(decoded.rekey_mlkem_pk, with_rekey.rekey_mlkem_pk);
    assert_eq!(decoded.rekey_ciphertext, with_rekey.rekey_ciphertext);

    let no_rekey = super::tlv::RatchetEncryptedMessage {
        nonce: vec![9u8; 12],
        ciphertext: vec![8u8; 32],
        rekey_x25519_pk: None,
        rekey_mlkem_pk: None,
        rekey_ciphertext: None,
    };
    let decoded =
        super::tlv::RatchetEncryptedMessage::from_binary(&no_rekey.to_binary().unwrap()).unwrap();
    assert_eq!(decoded.nonce, no_rekey.nonce);
    assert_eq!(decoded.ciphertext, no_rekey.ciphertext);
    assert!(decoded.rekey_x25519_pk.is_none());
    assert!(decoded.rekey_mlkem_pk.is_none());
    assert!(decoded.rekey_ciphertext.is_none());
}

#[test]
fn snapshot_roundtrip_preserves_previous_chain_and_budget() {
    let (_alice, _bob) = alice_bob();
    // Simulate a completed rekey so the previous chain is retained.
    let mut snap_holder = DoubleRatchetState::new_with_keypair(
        b"snap-secret",
        true,
        HybridKeyPair {
            x25519_pk: [1u8; 32],
            x25519_sk: [2u8; 32],
            mlkem_pk: vec![3u8; 1184],
            mlkem_sk: vec![4u8; 2400],
        },
        Some([5u8; 32]),
        Some(vec![6u8; 1184]),
    )
    .unwrap();
    snap_holder.previous_recv_chain_key = Some([9u8; 32]);
    snap_holder.previous_recv_anchor = Some(42);
    snap_holder.previous_recv_gen = Some(0);
    snap_holder.resync_forward_total = 1234;
    let bytes = serde_json::to_vec(&snap_holder.to_snapshot()).unwrap();
    let restored =
        DoubleRatchetState::from_snapshot(&serde_json::from_slice(&bytes).unwrap()).unwrap();
    assert_eq!(restored.previous_recv_chain_key, Some([9u8; 32]));
    assert_eq!(restored.previous_recv_anchor, Some(42));
    assert_eq!(restored.previous_recv_gen, Some(0));
    assert_eq!(restored.resync_forward_total, 1234);
}
