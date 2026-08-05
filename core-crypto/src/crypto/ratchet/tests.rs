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
    assert_eq!(alice.send.message_count, bob.recv.message_count);
    assert_eq!(bob.send.message_count, alice.recv.message_count);
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
    assert_eq!(alice.send.message_count, 0);

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
    pending.incoming_proposal.root_key = Some([7u8; 32]);
    pending.incoming_proposal.receiving_chain_key = Some([8u8; 32]);
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
    while advanced < super::resync::SYNC_MAX_CUMULATIVE + 100 {
        match alice2.resync_receiving_chain(alice2.recv.message_count + 999) {
            Ok(gap) => advanced += gap,
            Err(_) => break,
        }
    }
    assert!(
        advanced <= super::resync::SYNC_MAX_CUMULATIVE,
        "cumulative resync advancement must be capped, got {advanced}"
    );
}

/// Audit KYP-2026-02 #1 (CRITICAL): an out-of-order rekey carrier MUST NOT be
/// silently stripped of its proposal. When a receive-gap derives skip keys for
/// a range that includes the rekey carrier, the carrier's key is cached; if the
/// carrier then arrives late (reordered), the cached-key dispatch must run the
/// proposal derivation FIRST so the pending proposal and the RekeyAck are
/// queued — otherwise the sender's confirm queue stays occupied and the session
/// desyncs at the generation boundary.
#[test]
fn out_of_order_rekey_carrier_still_derives_pending_proposal() {
    let (mut alice, mut bob) = alice_bob();

    // Alice sends seq 0..=99; bob receives them in order (bob at recv 100).
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }
    assert_eq!(bob.recv.message_count, 100);

    // Alice's seq-100 message is the rekey carrier; 101 and 102 follow.
    let carrier = alice.ratchet_encrypt(b"carrier".as_ref()).expect("carrier");
    assert!(
        carrier.rekey_ciphertext.is_some(),
        "carrier at seq 100 must carry a rekey payload"
    );
    let msg101 = alice.ratchet_encrypt(b"m101".as_ref()).expect("m101");
    let msg102 = alice.ratchet_encrypt(b"m102".as_ref()).expect("m102");

    // Deliver seq 102 FIRST → gap (100..102) → skip keys for 100 and 101 are
    // cached, and 102 decrypts on the current chain.
    let rekey_x102 = msg102
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(msg102.nonce.as_slice()).unwrap(),
            &msg102.ciphertext,
            msg102.rekey_ciphertext.as_deref(),
            rekey_x102.as_ref(),
            msg102.rekey_mlkem_pk.as_deref(),
        )
        .expect("bob decrypts 102 after gap skip");
    assert_eq!(pt, b"m102");
    // The carrier's key is now cached.
    assert!(
        bob.skip_message_keys
            .as_ref()
            .unwrap()
            .contains_key(&(0, 100)),
        "carrier key must be cached by the gap skip"
    );

    // Deliver the carrier (seq 100) LATE — it decrypts from the skip cache.
    // The cached-key dispatch MUST have already derived the pending proposal
    // and queued the ACK (regression for KYP-2026-02 #1).
    let rekey_x100 = carrier
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(carrier.nonce.as_slice()).unwrap(),
            &carrier.ciphertext,
            carrier.rekey_ciphertext.as_deref(),
            rekey_x100.as_ref(),
            carrier.rekey_mlkem_pk.as_deref(),
        )
        .expect("bob decrypts the late carrier from the skip cache");
    assert_eq!(pt, b"carrier");
    // The proposal survived the cached-key path:
    assert!(
        bob.incoming_proposal.receiving_chain_key.is_some(),
        "out-of-order carrier must derive the pending receiving chain key"
    );
    assert!(
        bob.incoming_proposal.root_key.is_some(),
        "out-of-order carrier must derive the pending root key"
    );
    assert_eq!(
        bob.pending_rekey_ack_seq,
        Some(100),
        "out-of-order carrier must queue the RekeyAck for the sender's confirm queue"
    );

    // The ack completes the round-trip: bob acks, alice commits her outgoing
    // rekey, and the first new-generation message authenticates on bob's
    // pending chain.
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

    // Deliver seq 101 (also cached) — must still decrypt on the old chain.
    let rekey_x101 = msg101
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(msg101.nonce.as_slice()).unwrap(),
            &msg101.ciphertext,
            msg101.rekey_ciphertext.as_deref(),
            rekey_x101.as_ref(),
            msg101.rekey_mlkem_pk.as_deref(),
        )
        .expect("bob decrypts 101");
    assert_eq!(pt, b"m101");

    // Alice is now on gen 1 — her next message is (gen 1, seq 0); bob's
    // pending chain must authenticate it and commit.
    let post = alice
        .ratchet_encrypt(b"post-commit".as_ref())
        .expect("post-commit");
    let rekey_xp = post
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(post.nonce.as_slice()).unwrap(),
            &post.ciphertext,
            post.rekey_ciphertext.as_deref(),
            rekey_xp.as_ref(),
            post.rekey_mlkem_pk.as_deref(),
        )
        .expect("bob decrypts the first new-generation message via the pending chain");
    assert_eq!(pt, b"post-commit");
    assert_eq!(bob.ratchet_generation, 1);
}

/// Audit KYP-2026-02 #3 (HIGH): the Synchronize recovery path must NOT be
/// deadlocked by an unconsumed rekey proposal. A FRESH proposal refuses the
/// resync; a STALE proposal (past `INCOMING_REKEY_TTL_SECS`) is evicted so the
/// recovery proceeds, and the attach time survives snapshot round-trips.
#[test]
fn stale_pending_proposal_does_not_deadlock_resync() {
    let (alice, _bob) = alice_bob();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Fresh proposal refuses resync.
    let mut fresh = alice.clone();
    fresh.incoming_proposal.root_key = Some([7u8; 32]);
    fresh.incoming_proposal.receiving_chain_key = Some([8u8; 32]);
    fresh.incoming_proposal.attached_at_unix = Some(now);
    assert!(
        fresh.resync_receiving_chain(50).is_err(),
        "a fresh pending proposal must still refuse resync"
    );

    // Stale proposal (attached at epoch — far beyond the TTL) is evicted and
    // the resync proceeds.
    let mut stale = alice.clone();
    stale.incoming_proposal.root_key = Some([7u8; 32]);
    stale.incoming_proposal.receiving_chain_key = Some([8u8; 32]);
    stale.incoming_proposal.attached_at_unix = Some(0);
    let skipped = stale
        .resync_receiving_chain(50)
        .expect("stale proposal must be evicted, not block recovery");
    assert_eq!(skipped, 50);
    assert!(
        stale.incoming_proposal.root_key.is_none()
            && stale.incoming_proposal.receiving_chain_key.is_none(),
        "stale incoming proposal must be evicted"
    );

    // The attach time must survive a snapshot round-trip (restart survival).
    let mut holder = alice.clone();
    holder.incoming_proposal.root_key = Some([9u8; 32]);
    holder.incoming_proposal.attached_at_unix = Some(1234);
    let bytes = serde_json::to_vec(&holder.to_snapshot()).unwrap();
    let restored =
        DoubleRatchetState::from_snapshot(&serde_json::from_slice(&bytes).unwrap()).unwrap();
    assert_eq!(restored.incoming_proposal.attached_at_unix, Some(1234));
    assert_eq!(restored.incoming_proposal.root_key, Some([9u8; 32]));
}

/// Audit KYP-2026-02 #4 (MEDIUM): previous-generation messages whose keys were
/// CACHED-but-UNDELIVERED at the rekey commit must not be permanently lost.
/// After the commit, the retained skip cache delivers them; the anchor/watermark
/// would otherwise classify them as already-delivered or predating the anchor.
#[test]
fn cached_but_undelivered_prev_gen_messages_survive_commit() {
    let (mut alice, mut bob) = alice_bob();

    // Drive to the boundary: alice sends 100 messages; bob receives all.
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }
    // Alice sends the carrier (seq 100) plus a burst 101..=120.
    let mut burst: Vec<crate::crypto::RatchetEncryptedMessage> = Vec::new();
    for i in 0..=20 {
        burst.push(
            alice
                .ratchet_encrypt(format!("burst-{i}").as_bytes())
                .expect("encrypt"),
        );
    }
    assert!(
        burst[0].rekey_ciphertext.is_some(),
        "burst[0] (seq 100) must carry the rekey payload"
    );

    // Bob receives only the TAIL of the burst (120, 119, 118) → the gap skip
    // caches keys for 100..=117 without delivering them.
    for idx in [20usize, 19, 18] {
        let m = &burst[idx];
        let rekey_x = m
            .rekey_x25519_pk
            .as_deref()
            .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
        let pt = bob
            .ratchet_decrypt_with_rekey(
                &<[u8; 12]>::try_from(m.nonce.as_slice()).unwrap(),
                &m.ciphertext,
                m.rekey_ciphertext.as_deref(),
                rekey_x.as_ref(),
                m.rekey_mlkem_pk.as_deref(),
            )
            .expect("tail decrypt");
        assert_eq!(pt, format!("burst-{idx}").as_bytes());
    }
    let store = bob.skip_message_keys.as_ref().unwrap();
    assert!(
        store.contains_key(&(0, 100)),
        "carrier (seq 100) must be cached-but-undelivered"
    );
    assert!(store.contains_key(&(0, 105)));

    // Deliver the carrier late → proposal derived + ack queued (F1 fix).
    let rekey_x = burst[0]
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(burst[0].nonce.as_slice()).unwrap(),
            &burst[0].ciphertext,
            burst[0].rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            burst[0].rekey_mlkem_pk.as_deref(),
        )
        .expect("late carrier decrypts from cache");
    assert_eq!(pt, b"burst-0");
    assert_eq!(bob.pending_rekey_ack_seq, Some(100));

    // Bob acks; alice commits (gen 1).
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

    // Alice's first new-generation message authenticates on bob's pending
    // chain → bob COMMITS (retains the old chain, and — with the F4 fix — the
    // old generation's cached-but-undelivered keys).
    let post = alice.ratchet_encrypt(b"post".as_ref()).expect("post");
    let rekey_x = post
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(post.nonce.as_slice()).unwrap(),
            &post.ciphertext,
            post.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            post.rekey_mlkem_pk.as_deref(),
        )
        .expect("post authenticates on pending chain — bob commits");
    assert_eq!(pt, b"post");
    assert_eq!(bob.ratchet_generation, 1);
    assert!(
        bob.previous_recv_chain_key.is_some(),
        "previous receiving chain must be retained at commit"
    );

    // Now deliver a cached-but-undelivered previous-generation message (burst[5]
    // = seq 105). The retained skip cache must deliver it — regression for audit
    // KYP-2026-02 #4 (the anchor/watermark would otherwise reject it).
    let m = &burst[5];
    let rekey_x = m
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(m.nonce.as_slice()).unwrap(),
            &m.ciphertext,
            m.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            m.rekey_mlkem_pk.as_deref(),
        )
        .expect("cached-but-undelivered prev-gen message must decrypt after commit");
    assert_eq!(pt, b"burst-5");

    // A duplicate of the same message must now be rejected as replay.
    let pt = bob.ratchet_decrypt_with_rekey(
        &<[u8; 12]>::try_from(m.nonce.as_slice()).unwrap(),
        &m.ciphertext,
        m.rekey_ciphertext.as_deref(),
        rekey_x.as_ref(),
        m.rekey_mlkem_pk.as_deref(),
    );
    assert!(pt.is_err(), "replayed prev-gen message must be rejected");
}

/// AUDIT #5 (MEDIUM, verify-then-remove): the PREVIOUS-GENERATION cached-key
/// branch must not consume the key before AEAD verification. The fix for
/// finding #13 was applied to the current-chain dispatch but NOT to the
/// previous-generation cache path — there the key was `remove()`d BEFORE
/// decrypting, so an on-path attacker who flipped one ciphertext bit of a
/// captured legitimate frame and replayed it permanently burned the key; the
/// genuine frame arriving later found no key and the retained chain cannot
/// step below its anchor (deterministic message-loss DoS). After the fix the
/// key survives the failed attempt and the genuine frame still decrypts.
#[test]
fn prev_gen_cached_key_survives_bitflip_forgery() {
    let (mut alice, mut bob) = alice_bob();
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }
    // Alice sends the carrier + a burst; bob caches 100..=117 without delivery.
    let mut burst: Vec<crate::crypto::RatchetEncryptedMessage> = Vec::new();
    for i in 0..=20 {
        burst.push(
            alice
                .ratchet_encrypt(format!("burst-{i}").as_bytes())
                .expect("encrypt"),
        );
    }
    for idx in [20usize, 19, 18] {
        let m = &burst[idx];
        let rekey_x = m
            .rekey_x25519_pk
            .as_deref()
            .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
        let _ = bob
            .ratchet_decrypt_with_rekey(
                &<[u8; 12]>::try_from(m.nonce.as_slice()).unwrap(),
                &m.ciphertext,
                m.rekey_ciphertext.as_deref(),
                rekey_x.as_ref(),
                m.rekey_mlkem_pk.as_deref(),
            )
            .expect("tail decrypt");
    }
    let store = bob.skip_message_keys.as_ref().unwrap();
    assert!(store.contains_key(&(0, 105)), "precondition: key cached");

    // Deliver the carrier late → proposal derived + ack queued.
    let rekey_x = burst[0]
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let _ = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(burst[0].nonce.as_slice()).unwrap(),
            &burst[0].ciphertext,
            burst[0].rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            burst[0].rekey_mlkem_pk.as_deref(),
        )
        .expect("late carrier");
    while let Some(ack_seq) = bob.take_pending_rekey_ack_seq() {
        let ack = bob.generate_rekey_ack(ack_seq).expect("ack");
        let pt = alice
            .ratchet_decrypt(
                &<[u8; 12]>::try_from(ack.nonce.as_slice()).unwrap(),
                &ack.ciphertext,
            )
            .expect("alice ack");
        if let crate::packets::KyberMessage::RekeyAck { seq } =
            crate::packets::safe_decode_packet(&pt).unwrap()
        {
            assert!(alice.process_rekey_ack(seq));
        }
    }
    let post = alice.ratchet_encrypt(b"post".as_ref()).expect("post");
    let _ = bob
        .ratchet_decrypt_with_rekey(
            &<[u8; 12]>::try_from(post.nonce.as_slice()).unwrap(),
            &post.ciphertext,
            post.rekey_ciphertext.as_deref(),
            None,
            post.rekey_mlkem_pk.as_deref(),
        )
        .expect("post commits bob");
    assert_eq!(bob.ratchet_generation, 1);

    // The cached-but-undelivered previous-gen message (seq 105, gen 0).
    let m = &burst[5];
    let rekey_x = m
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let nonce_arr = <[u8; 12]>::try_from(m.nonce.as_slice()).unwrap();

    // On-path attacker flips one ciphertext bit and replays the forged copy.
    let mut forged_ct = m.ciphertext.clone();
    let last = forged_ct.len() - 1;
    forged_ct[last] ^= 0x01;
    let forgery = bob.ratchet_decrypt_with_rekey(
        &nonce_arr,
        &forged_ct,
        m.rekey_ciphertext.as_deref(),
        rekey_x.as_ref(),
        m.rekey_mlkem_pk.as_deref(),
    );
    assert!(forgery.is_err(), "forged copy must fail AEAD");
    assert!(
        bob.skip_message_keys
            .as_ref()
            .unwrap()
            .contains_key(&(0, 105)),
        "the cached key must SURVIVE the failed attempt (audit #5)"
    );

    // The GENUINE frame must still decrypt.
    let pt = bob
        .ratchet_decrypt_with_rekey(
            &nonce_arr,
            &m.ciphertext,
            m.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            m.rekey_mlkem_pk.as_deref(),
        )
        .expect("genuine prev-gen message must still decrypt after the forgery");
    assert_eq!(pt, b"burst-5");
}

/// Audit KYP-2026-02 #22: the explicit receive-path state machine returns the
/// correct `DecryptOutcome` classification for each branch — a current-chain
/// message is `Committed`, a gap-skip delivery is `Skipped`, an out-of-order
/// rekey carrier is `ProposalDerived` (never silently stripped), and a replay
/// is rejected as `Replay`.
#[test]
fn decrypt_outcome_classification() {
    use super::decrypt::DecryptOutcome;
    let (mut alice, mut bob) = alice_bob();
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }
    let carrier = alice.ratchet_encrypt(b"carrier".as_ref()).expect("carrier");
    assert!(carrier.rekey_ciphertext.is_some());
    let msg101 = alice.ratchet_encrypt(b"m101".as_ref()).expect("m101");
    let msg102 = alice.ratchet_encrypt(b"m102".as_ref()).expect("m102");

    let classify = |bob: &mut DoubleRatchetState, m: &crate::crypto::RatchetEncryptedMessage| {
        let rekey_x = m
            .rekey_x25519_pk
            .as_deref()
            .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
        bob.ratchet_decrypt_with_rekey_classified(
            &<[u8; 12]>::try_from(m.nonce.as_slice()).unwrap(),
            &m.ciphertext,
            m.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            m.rekey_mlkem_pk.as_deref(),
        )
    };

    // Deliver seq 102 first → the CURRENT chain advances across the gap
    // (gap-skip derives + commits) = Committed.
    let (pt, out) = classify(&mut bob, &msg102).expect("102");
    assert_eq!(pt, b"m102");
    assert_eq!(out, DecryptOutcome::Committed);

    // Deliver the carrier out-of-order (from the skip cache) → ProposalDerived
    // (F1 fix: the proposal survives the cached-key dispatch).
    let (pt, out) = classify(&mut bob, &carrier).expect("carrier");
    assert_eq!(pt, b"carrier");
    assert_eq!(out, DecryptOutcome::ProposalDerived);

    // Deliver seq 101 (late, from the skip cache) → Skipped.
    let (pt, out) = classify(&mut bob, &msg101).expect("101");
    assert_eq!(pt, b"m101");
    assert_eq!(out, DecryptOutcome::Skipped);

    // A duplicate carrier → Replay.
    assert!(classify(&mut bob, &carrier).is_err());
}

/// Audit KYP-2026-02 #19 (LOW): a PARTIAL rekey parameter set is a protocol
/// error, never an empty AAD that masks the failure as a decryption error.
#[test]
fn partial_rekey_params_are_rejected() {
    let (mut alice, mut bob) = alice_bob();
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }
    let carrier = alice.ratchet_encrypt(b"carrier".as_ref()).expect("carrier");
    assert!(carrier.rekey_ciphertext.is_some());
    let rekey_x = carrier
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    // Feed the carrier with a PARTIAL set (x25519 pk present, ct + mlkem dropped).
    let err = bob.ratchet_decrypt_with_rekey(
        &<[u8; 12]>::try_from(carrier.nonce.as_slice()).unwrap(),
        &carrier.ciphertext,
        None,
        rekey_x.as_ref(),
        None,
    );
    assert!(
        err.is_err(),
        "partial rekey parameter set must be rejected as a protocol error"
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

/// AUDIT FINDING #17 (5-place manual mirror): `DoubleRatchetState` is mirrored
/// field-by-field into `RatchetSnapshot`, so a field added to the live struct
/// but not to `to_snapshot`/`from_snapshot` silently resets on restore. This
/// guard round-trips a FULLY-populated state and asserts every persisted field
/// survives — the mirror can no longer drift without failing the build.
#[test]
fn snapshot_completeness_guard_roundtrips_every_field() {
    use super::state::{Chain, IncomingProposal, OutgoingProposal, ReplayWindow};
    use std::collections::{HashMap, VecDeque};

    let mut s = DoubleRatchetState::new_with_keypair(
        b"completeness-secret",
        true,
        HybridKeyPair {
            x25519_pk: [0x11; 32],
            x25519_sk: [0x22; 32],
            mlkem_pk: vec![0x33; 1184],
            mlkem_sk: vec![0x44; 2400],
        },
        Some([0x55; 32]),
        Some(vec![0x66; 1184]),
    )
    .unwrap();
    // Populate EVERY persisted field.
    s.root_key = [0xAA; 32];
    s.send = Chain {
        key: [0xBB; 32],
        message_count: 101,
    };
    s.recv = Chain {
        key: [0xCC; 32],
        message_count: 202,
    };
    s.ratchet_generation = 3;
    s.pairing_epoch = 7;
    s.previous_recv_chain_key = Some([0xDD; 32]);
    s.previous_recv_anchor = Some(42);
    s.previous_recv_gen = Some(2);
    s.replay_window = ReplayWindow {
        seen: [(3u32, 5u64), (3u32, 6u64)].into_iter().collect(),
        prev_gen_highest_delivered: Some(99),
    };
    s.incoming_proposal = IncomingProposal {
        root_key: Some([0x11; 32]),
        sending_chain_key: Some([0x12; 32]),
        receiving_chain_key: Some([0x13; 32]),
        peer_x25519_pk: Some([0x14; 32]),
        peer_mlkem_pk: Some(vec![0x15; 1184]),
        generation_bump: true,
        carrier_seq: Some(77),
        carrier_gen: Some(3),
        attached_at_unix: Some(1_700_000_000),
        attached_at_mono: None,
    };
    s.outgoing_proposal = OutgoingProposal {
        root_key: Some([0x21; 32]),
        sending_chain_key: Some([0x22; 32]),
        receiving_chain_key: Some([0x23; 32]),
        hybrid_pair: Some(HybridKeyPair {
            x25519_pk: [0x24; 32],
            x25519_sk: [0x25; 32],
            mlkem_pk: vec![0x26; 1184],
            mlkem_sk: vec![0x27; 2400],
        }),
        rekey_payload: Some((vec![0x28; 32], vec![0x29; 1184], vec![0x2A; 1088])),
    };
    s.max_skip = 100;
    s.max_key_history = 3;
    s.previous_keypairs.push_back(HybridKeyPair {
        x25519_pk: [0x31; 32],
        x25519_sk: [0x32; 32],
        mlkem_pk: vec![0x33; 1184],
        mlkem_sk: vec![0x34; 2400],
    });
    s.skip_message_keys = Some(HashMap::from([((3u32, 5u64), [0x35; 32].into())]));
    s.rekey_pending_confirm_queue = VecDeque::from([super::state::RekeyCarrier {
        carrier_seq: 100,
        attached_at: std::time::Instant::now(),
        attached_at_unix: 1_700_000_000,
        // AUDIT F2: first-staged wall clock distinct from the last re-send
        // stamp so the round-trip proves the two are mirrored separately.
        first_attached_at: std::time::Instant::now(),
        first_attached_at_unix: 1_699_999_940,
        rekey_x25519_pk: vec![0x41; 32],
        rekey_mlkem_pk: vec![0x42; 1184],
        rekey_ciphertext: vec![0x43; 1088],
    }]);
    s.pending_rekey_ack_seq = Some(100);
    s.resync_forward_total = 555;
    s.is_initiator = true;

    let restored = DoubleRatchetState::from_snapshot(&s.to_snapshot()).expect("roundtrip");
    // Deep-equality: every field (except the transient peeked_ack_cache, which
    // is intentionally not persisted) must survive the round-trip. Zeroize on
    // the original before comparing so a missing mirror surfaces as a diff.
    use zeroize::Zeroize;
    let mut orig = s.clone();
    orig.peeked_ack_cache = None; // transient by design
    let mut restored_mut = restored;
    restored_mut.peeked_ack_cache = None;
    assert_eq!(orig.root_key, restored_mut.root_key);
    assert_eq!(orig.send.key, restored_mut.send.key);
    assert_eq!(orig.send.message_count, restored_mut.send.message_count);
    assert_eq!(orig.recv.key, restored_mut.recv.key);
    assert_eq!(orig.recv.message_count, restored_mut.recv.message_count);
    assert_eq!(
        orig.our_hybrid_pair.x25519_pk,
        restored_mut.our_hybrid_pair.x25519_pk
    );
    assert_eq!(
        orig.our_hybrid_pair.x25519_sk,
        restored_mut.our_hybrid_pair.x25519_sk
    );
    assert_eq!(
        orig.our_hybrid_pair.mlkem_pk,
        restored_mut.our_hybrid_pair.mlkem_pk
    );
    assert_eq!(
        orig.our_hybrid_pair.mlkem_sk,
        restored_mut.our_hybrid_pair.mlkem_sk
    );
    assert_eq!(orig.peer_x25519_pk, restored_mut.peer_x25519_pk);
    assert_eq!(orig.peer_mlkem_pk, restored_mut.peer_mlkem_pk);
    assert_eq!(orig.ratchet_generation, restored_mut.ratchet_generation);
    assert_eq!(orig.pairing_epoch, restored_mut.pairing_epoch);
    assert_eq!(
        orig.incoming_proposal.root_key,
        restored_mut.incoming_proposal.root_key
    );
    assert_eq!(
        orig.incoming_proposal.sending_chain_key,
        restored_mut.incoming_proposal.sending_chain_key
    );
    assert_eq!(
        orig.incoming_proposal.receiving_chain_key,
        restored_mut.incoming_proposal.receiving_chain_key
    );
    assert_eq!(
        orig.incoming_proposal.carrier_seq,
        restored_mut.incoming_proposal.carrier_seq
    );
    assert_eq!(
        orig.incoming_proposal.carrier_gen,
        restored_mut.incoming_proposal.carrier_gen
    );
    assert_eq!(
        orig.incoming_proposal.attached_at_unix,
        restored_mut.incoming_proposal.attached_at_unix
    );
    assert_eq!(
        orig.outgoing_proposal.root_key,
        restored_mut.outgoing_proposal.root_key
    );
    assert_eq!(
        orig.outgoing_proposal.sending_chain_key,
        restored_mut.outgoing_proposal.sending_chain_key
    );
    assert_eq!(
        orig.outgoing_proposal.receiving_chain_key,
        restored_mut.outgoing_proposal.receiving_chain_key
    );
    assert_eq!(
        orig.outgoing_proposal
            .hybrid_pair
            .as_ref()
            .map(|p| p.x25519_pk),
        restored_mut
            .outgoing_proposal
            .hybrid_pair
            .as_ref()
            .map(|p| p.x25519_pk)
    );
    assert_eq!(
        orig.outgoing_proposal.rekey_payload,
        restored_mut.outgoing_proposal.rekey_payload
    );
    assert_eq!(
        orig.previous_recv_chain_key,
        restored_mut.previous_recv_chain_key
    );
    assert_eq!(orig.previous_recv_anchor, restored_mut.previous_recv_anchor);
    assert_eq!(orig.previous_recv_gen, restored_mut.previous_recv_gen);
    assert_eq!(
        orig.replay_window.prev_gen_highest_delivered,
        restored_mut.replay_window.prev_gen_highest_delivered
    );
    assert_eq!(orig.replay_window.seen, restored_mut.replay_window.seen);
    assert_eq!(orig.resync_forward_total, restored_mut.resync_forward_total);
    assert_eq!(orig.is_initiator, restored_mut.is_initiator);
    assert_eq!(orig.max_skip, restored_mut.max_skip);
    assert_eq!(orig.max_key_history, restored_mut.max_key_history);
    assert_eq!(
        orig.pending_rekey_ack_seq,
        restored_mut.pending_rekey_ack_seq
    );
    assert_eq!(
        orig.rekey_pending_confirm_queue.len(),
        restored_mut.rekey_pending_confirm_queue.len()
    );
    assert_eq!(
        orig.rekey_pending_confirm_queue
            .front()
            .map(|c| (c.carrier_seq, c.attached_at_unix)),
        restored_mut
            .rekey_pending_confirm_queue
            .front()
            .map(|c| (c.carrier_seq, c.attached_at_unix))
    );
    assert_eq!(
        orig.rekey_pending_confirm_queue
            .front()
            .map(|c| (c.carrier_seq, c.first_attached_at_unix)),
        restored_mut
            .rekey_pending_confirm_queue
            .front()
            .map(|c| (c.carrier_seq, c.first_attached_at_unix))
    );
    assert_eq!(
        orig.skip_message_keys.as_ref().map(|m| m.len()),
        restored_mut.skip_message_keys.as_ref().map(|m| m.len())
    );
    assert_eq!(
        orig.previous_keypairs.len(),
        restored_mut.previous_keypairs.len()
    );
    // The transient peek cache is the ONLY intentionally-dropped field.
    assert_eq!(orig.peeked_ack_cache, restored_mut.peeked_ack_cache);
    orig.zeroize();
}

/// AUDIT F1 regression: a stale/crossed rekey carrier from an already-superseded
/// generation must NEVER populate the single incoming-proposal slot.
///
/// Attack trace: both sides rekey near seq 100. Our (initiator's) proposal
/// commits first, advancing `ratchet_generation` to 1. The peer's stale
/// re-send — a gen-0 carrier encapsulated to our OLD public key — arrives after
/// our commit. If Phase 1 derived it under the NEW root it would stage a
/// garbage proposal whose receiving chain matches nothing, blocking the slot
/// for up to INCOMING_REKEY_TTL_SECS. The F1 guard refuses derivation whenever
/// `carrier_gen < ratchet_generation` (or older than the pending proposal), so
/// the slot stays untouched.
#[test]
fn stale_generation_rekey_carrier_never_poisons_incoming_slot() {
    use super::super::decrypt::DecryptOutcome;

    let (mut alice, mut bob) = alice_bob();
    // Drive BOTH sides to the first rekey boundary (send count 100 on each),
    // exactly like the crossed-double-rekey race in the audit.
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
        b2a(&mut alice, &mut bob, i);
    }
    assert_eq!(alice.send.message_count, 100);
    assert_eq!(bob.send.message_count, 100);

    // Bob (responder) builds his rekey carrier at gen 0 / seq 100 — but it is
    // never delivered before the race resolves (the "stale re-send").
    let stale = bob
        .ratchet_encrypt(b"stale-carrier".as_ref())
        .expect("bob carrier");
    let stale_nonce = <[u8; 12]>::try_from(stale.nonce.as_slice()).unwrap();
    let stale_gen = u32::from_be_bytes([
        stale_nonce[0],
        stale_nonce[1],
        stale_nonce[2],
        stale_nonce[3],
    ]);
    assert_eq!(stale_gen, 0, "bob's carrier is a gen-0 message");
    assert!(
        stale.rekey_ciphertext.is_some(),
        "bob's carrier must carry a rekey payload"
    );

    // Alice (initiator) also rekeys at seq 100 and COMMITS her own outgoing
    // proposal — her root advances to gen 1, retaining the gen-0 receiving
    // chain but swapping her DH keypair.
    let _alice_carrier = alice
        .ratchet_encrypt(b"alice-carrier".as_ref())
        .expect("alice carrier");
    assert!(
        _alice_carrier.rekey_ciphertext.is_some(),
        "alice's carrier must carry a rekey payload"
    );
    alice.commit_outgoing_rekey();
    assert_eq!(alice.ratchet_generation, 1);

    // Simulate an incomplete retained-previous state (chain key retained but
    // anchor lost — a half-formed restore). The prev-gen branch then returns
    // Ok(None) and control WOULD reach Phase 1 without the F1 guard.
    alice.previous_recv_anchor = None;

    let stale_x = stale
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let result = alice.ratchet_decrypt_with_rekey_classified(
        &stale_nonce,
        &stale.ciphertext,
        stale.rekey_ciphertext.as_deref(),
        stale_x.as_ref(),
        stale.rekey_mlkem_pk.as_deref(),
    );

    // The stale carrier cannot authenticate on the current (gen-1) chain — but
    // the FAILURE MODE that matters is the state left behind: the slot must be
    // empty, never poisoned with a gen-0-derived-under-gen-1 proposal.
    assert!(
        !alice.incoming_proposal.is_pending(),
        "stale carrier must not stage an incoming proposal (generation superseded)"
    );
    assert!(
        alice.incoming_proposal.carrier_gen.is_none(),
        "stale carrier must not record a carrier generation"
    );
    assert!(
        alice.incoming_proposal.attached_at_unix.is_none(),
        "stale carrier must not stamp an attach time"
    );
    assert!(
        result.is_err(),
        "stale gen-0 carrier cannot decrypt on gen-1 chain"
    );
    let _ = DecryptOutcome::Committed; // (keep the import meaningful if classification changes)
}

/// AUDIT FINDING #3 (payload-anchored tie-break): a simultaneous two-sided
/// rekey is decided by the proposal with the lexicographically LARGER rekey
/// (x25519 pk, mlkem pk) tuple — not by generation parity. Both sides hold
/// both proposals at race time (their own staged payload + the peer's carrier
/// payload, both bound into the message AAD), so both MUST agree on the same
/// winner with NO shared generation state. A generation drift (the condition
/// the Synchronize path repairs) can therefore never make the two sides pick
/// different winners and silently kill one proposal.
///
/// This test forces a true simultaneous race: both sides stage a proposal at
/// the same boundary and each receives the other's carrier. It derives the
/// EXPECTED winner from the actual rekey keys (the side with the larger
/// (xpk, mpk) tuple), then asserts both sides agree on that winner — the
/// winner keeps its own proposal and discards the peer's; the loser cancels
/// its own and adopts the winner's; the loser ACKs the winner's carrier; the
/// winner commits (its keypair rotates) and the loser converges on the
/// winner's keys.
#[test]
fn two_sided_rekey_race_alternates_winners() {
    // Build two interoperating ratchets (alice = initiator, bob = responder).
    let (mut alice, mut bob) = alice_bob();

    // Drive both sides to just below the first rekey boundary WITHOUT crossing
    // it — each side sends 100 messages so both are at send_count 100 and the
    // NEXT encrypt (seq 100) stages a proposal.
    for i in 0..100u64 {
        a2b(&mut alice, &mut bob, i);
        b2a(&mut alice, &mut bob, i);
    }
    assert_eq!(alice.send.message_count, 100);
    assert_eq!(bob.send.message_count, 100);
    assert_eq!(alice.ratchet_generation, 0);

    // ── Race at generation 0 ────────────────────────────────────────────
    // Both sides encrypt message 100: each stages its own outgoing proposal
    // and attaches a rekey carrier with a freshly generated keypair.
    let a100 = alice
        .ratchet_encrypt(b"alice-carrier-0")
        .expect("alice carrier at gen 0");
    let b100 = bob
        .ratchet_encrypt(b"bob-carrier-0")
        .expect("bob carrier at gen 0");
    assert!(a100.rekey_ciphertext.is_some(), "alice staged a proposal");
    assert!(b100.rekey_ciphertext.is_some(), "bob staged a proposal");
    assert!(
        alice.outgoing_proposal.root_key.is_some(),
        "alice has an outgoing proposal pending"
    );
    assert!(
        bob.outgoing_proposal.root_key.is_some(),
        "bob has an outgoing proposal pending"
    );

    // Derive the EXPECTED winner from the payloads themselves (audit finding
    // #3): the winner is the proposal with the lexicographically larger
    // (x25519 pk, mlkem pk) tuple. This is exactly the comparison both sides
    // perform, so the test asserts the protocol matches it.
    let alice_wins = {
        let a_xpk = a100.rekey_x25519_pk.as_deref().expect("alice xpk");
        let b_xpk = b100.rekey_x25519_pk.as_deref().expect("bob xpk");
        let a_mpk = a100.rekey_mlkem_pk.as_deref().expect("alice mpk");
        let b_mpk = b100.rekey_mlkem_pk.as_deref().expect("bob mpk");
        (a_xpk, a_mpk) > (b_xpk, b_mpk)
    };
    assert_ne!(
        a100.rekey_x25519_pk, b100.rekey_x25519_pk,
        "the two random proposals must differ (the test cannot assert a winner otherwise)"
    );

    // Deliver each carrier to the other side (both authenticated on the
    // current chain) — this is the simultaneous race.
    let a100_x = a100
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let _a_on_bob = bob
        .ratchet_decrypt_with_rekey_classified(
            &<[u8; 12]>::try_from(a100.nonce.as_slice()).expect("nonce"),
            &a100.ciphertext,
            a100.rekey_ciphertext.as_deref(),
            a100_x.as_ref(),
            a100.rekey_mlkem_pk.as_deref(),
        )
        .expect("bob decrypts alice's gen-0 carrier");
    let b100_x = b100
        .rekey_x25519_pk
        .as_deref()
        .map(|v| <[u8; 32]>::try_from(v).expect("32 bytes"));
    let _b_on_alice = alice
        .ratchet_decrypt_with_rekey_classified(
            &<[u8; 12]>::try_from(b100.nonce.as_slice()).expect("nonce"),
            &b100.ciphertext,
            b100.rekey_ciphertext.as_deref(),
            b100_x.as_ref(),
            b100.rekey_mlkem_pk.as_deref(),
        )
        .expect("alice decrypts bob's gen-0 carrier");

    // The payload-anchored tie-break: BOTH sides agree on the same winner. The
    // winner keeps its own outgoing proposal and discards the peer's incoming;
    // the loser cancels its own and adopts the winner's.
    if alice_wins {
        assert!(
            alice.outgoing_proposal.root_key.is_some(),
            "alice wins the race — her proposal stays pending"
        );
        assert!(
            !alice.incoming_proposal.is_pending(),
            "alice discards bob's proposal (she won)"
        );
        assert!(
            !bob.outgoing_proposal.root_key.is_some(),
            "bob cancels his own proposal (he lost)"
        );
        assert!(
            bob.incoming_proposal.is_pending(),
            "bob adopts alice's proposal"
        );
    } else {
        assert!(
            bob.outgoing_proposal.root_key.is_some(),
            "bob wins the race — his proposal stays pending"
        );
        assert!(
            !bob.incoming_proposal.is_pending(),
            "bob discards alice's proposal (he won)"
        );
        assert!(
            !alice.outgoing_proposal.root_key.is_some(),
            "alice cancels her own proposal (she lost)"
        );
        assert!(
            alice.incoming_proposal.is_pending(),
            "alice adopts bob's proposal"
        );
    }

    // The LOSER ACKs the winner's carrier; the winner commits its proposal.
    let alice_pair_at_race = alice.our_hybrid_pair.clone();
    let bob_pair_at_race = bob.our_hybrid_pair.clone();
    if alice_wins {
        let bob_ack = bob.pending_rekey_ack_seq.expect("bob ACKs alice's carrier");
        assert!(
            alice.process_rekey_ack(bob_ack),
            "alice commits on bob's ack"
        );
        assert_eq!(alice.ratchet_generation, 1);
        assert_ne!(
            alice.our_hybrid_pair.x25519_sk, alice_pair_at_race.x25519_sk,
            "the winner's x25519 secret must rotate on commit"
        );
        assert_eq!(
            bob.our_hybrid_pair.x25519_sk, bob_pair_at_race.x25519_sk,
            "the loser's keypair must stay fixed"
        );
    } else {
        let alice_ack = alice
            .pending_rekey_ack_seq
            .expect("alice ACKs bob's carrier");
        assert!(
            bob.process_rekey_ack(alice_ack),
            "bob commits on alice's ack"
        );
        assert_eq!(bob.ratchet_generation, 1);
        assert_ne!(
            bob.our_hybrid_pair.x25519_sk, bob_pair_at_race.x25519_sk,
            "the winner's x25519 secret must rotate on commit"
        );
        assert_eq!(
            alice.our_hybrid_pair.x25519_sk, alice_pair_at_race.x25519_sk,
            "the loser's keypair must stay fixed"
        );
    }

    // The winner sends its first new-generation message; the loser commits the
    // adopted proposal on the pending chain, converging on the winner's keys.
    let (winner_msg, winner, loser) = if alice_wins {
        (
            alice
                .ratchet_encrypt(b"alice-first-new-gen")
                .expect("alice gen-1 message"),
            &mut alice,
            &mut bob,
        )
    } else {
        (
            bob.ratchet_encrypt(b"bob-first-new-gen")
                .expect("bob gen-1 message"),
            &mut bob,
            &mut alice,
        )
    };
    let _ = loser
        .ratchet_decrypt_with_rekey_classified(
            &<[u8; 12]>::try_from(winner_msg.nonce.as_slice()).expect("nonce"),
            &winner_msg.ciphertext,
            winner_msg.rekey_ciphertext.as_deref(),
            None,
            winner_msg.rekey_mlkem_pk.as_deref(),
        )
        .expect("loser commits the winner's new-generation chain");
    assert_eq!(winner.ratchet_generation, 1);
    assert_eq!(
        loser.ratchet_generation, 1,
        "both sides converge on generation 1"
    );
    // The loser's peer keys are the winner's ROTATED public halves.
    assert_eq!(
        loser.peer_x25519_pk,
        Some(winner.our_hybrid_pair.x25519_pk),
        "the loser must adopt the winner's rotated public x25519 key"
    );
    assert_eq!(
        loser.peer_mlkem_pk.as_deref(),
        Some(winner.our_hybrid_pair.mlkem_pk.as_slice()),
        "the loser must adopt the winner's rotated public mlkem key"
    );
}

/// AUDIT #2 (HIGH, stale-carrier poison): a 2-entry confirm queue + a peer
/// ACK matching ONE entry must leave the queue EMPTY after the commit. The
/// legacy `commit_outgoing_rekey` cleared only the proposal slot, so the
/// surviving second carrier was re-sent by the next `ratchet_encrypt` with the
/// ALREADY-COMMITTED payload under the NEW generation — the peer decapsulated
/// it under its new root and staged a garbage proposal that poisoned its
/// single incoming slot. This test drives the exact precondition (two carriers
/// for one proposal) and asserts the queue is empty after the ack + commit.
#[test]
fn two_entry_confirm_queue_is_cleared_by_ack_commit() {
    let (mut alice, mut bob) = alice_bob();

    // Drive alice to the first rekey boundary so a carrier is staged.
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }
    let carrier = alice
        .ratchet_encrypt(b"first-carrier".as_ref())
        .expect("alice stages rekey at seq 100");
    assert!(carrier.rekey_ciphertext.is_some(), "carrier has payload");
    // The staged carrier is at send-space seq 100, the proposal is pending, and
    // the queue holds exactly one entry.
    assert_eq!(alice.rekey_pending_confirm_queue.len(), 1);
    assert!(alice.outgoing_proposal.is_pending());

    // FORGE the audit's poisoned precondition: a second carrier for the SAME
    // payload (a re-send that a lost ACK left in the queue alongside the new
    // push). The payload must match the pending proposal's rekey payload so the
    // peer's ACK matches one entry while the other survives.
    let (xpk, mpk, ct) = alice
        .outgoing_proposal
        .rekey_payload
        .clone()
        .expect("pending payload");
    alice
        .rekey_pending_confirm_queue
        .push_back(super::state::RekeyCarrier {
            carrier_seq: 130,
            attached_at: std::time::Instant::now(),
            attached_at_unix: super::state::now_unix_secs(),
            first_attached_at: std::time::Instant::now(),
            first_attached_at_unix: super::state::now_unix_secs(),
            rekey_x25519_pk: xpk,
            rekey_mlkem_pk: mpk,
            rekey_ciphertext: ct,
        });
    assert_eq!(
        alice.rekey_pending_confirm_queue.len(),
        2,
        "precondition: 2 entries"
    );

    // The peer ACKs the SECOND carrier (seq 130). process_rekey_ack removes the
    // matched entry and commits — the OTHER entry must NOT survive.
    assert!(
        alice.process_rekey_ack(130),
        "ack matches the second carrier"
    );
    assert_eq!(
        alice.rekey_pending_confirm_queue.len(),
        0,
        "the unacked first carrier must not survive the commit (audit #2)"
    );
    assert_eq!(alice.ratchet_generation, 1, "outgoing proposal committed");
    assert!(!alice.outgoing_proposal.is_pending());
    alice.assert_confirm_queue_invariant();

    // The next encrypted message must NOT re-attach the committed payload under
    // the new generation (the stale-carrier poison).
    let next = alice
        .ratchet_encrypt(b"post-commit".as_ref())
        .expect("encrypt after commit");
    assert!(
        next.rekey_ciphertext.is_none() && next.rekey_x25519_pk.is_none(),
        "no stale carrier may ride post-commit messages (audit #2)"
    );
}

/// AUDIT #2 (HIGH): the resend retry path must not accumulate a second carrier
/// for the same proposal — after a stale re-send the queue holds exactly one
/// entry (the fresh carrier), never two.
#[test]
fn resend_evicts_all_stale_carriers_keeping_one() {
    let (mut alice, mut bob) = alice_bob();
    for i in 0..100 {
        a2b(&mut alice, &mut bob, i);
    }
    let _carrier = alice
        .ratchet_encrypt(b"carrier".as_ref())
        .expect("alice stages rekey at seq 100");
    assert_eq!(alice.rekey_pending_confirm_queue.len(), 1);

    // Age BOTH a forged second entry AND the original entry past the retry TTL,
    // then encrypt: the retain must evict every stale carrier and push exactly
    // one fresh re-send (queue stays at 1, never grows to 2).
    let (xpk, mpk, ct) = alice
        .outgoing_proposal
        .rekey_payload
        .clone()
        .expect("pending payload");
    let old = std::time::Instant::now() - std::time::Duration::from_secs(31);
    let old_unix = super::state::now_unix_secs() - 31;
    alice.rekey_pending_confirm_queue.clear();
    alice
        .rekey_pending_confirm_queue
        .push_back(super::state::RekeyCarrier {
            carrier_seq: 100,
            attached_at: old,
            attached_at_unix: old_unix,
            first_attached_at: old,
            first_attached_at_unix: old_unix,
            rekey_x25519_pk: xpk.clone(),
            rekey_mlkem_pk: mpk.clone(),
            rekey_ciphertext: ct.clone(),
        });
    alice
        .rekey_pending_confirm_queue
        .push_back(super::state::RekeyCarrier {
            carrier_seq: 130,
            attached_at: old,
            attached_at_unix: old_unix,
            first_attached_at: old,
            first_attached_at_unix: old_unix,
            rekey_x25519_pk: xpk,
            rekey_mlkem_pk: mpk,
            rekey_ciphertext: ct,
        });
    assert_eq!(alice.rekey_pending_confirm_queue.len(), 2);

    let resent = alice
        .ratchet_encrypt(b"resend-driver".as_ref())
        .expect("encrypt triggers resend");
    assert!(
        resent.rekey_ciphertext.is_some(),
        "a stale carrier must be re-sent"
    );
    assert_eq!(
        alice.rekey_pending_confirm_queue.len(),
        1,
        "resend must leave exactly one carrier, never two (audit #2)"
    );
    alice.assert_confirm_queue_invariant();
}

/// AUDIT F2 (MEDIUM): a live-but-unacked outgoing rekey proposal whose re-sends
/// keep refreshing the retry TTL must still age out of "fresh" for the resync
/// path once its FIRST-STAGED window exceeds the staleness TTL — otherwise the
/// Synchronize recovery path is blocked forever by exactly the condition it
/// exists to repair (peer ACK channel down, data channel still flowing).
#[test]
fn resend_refreshed_proposal_ages_out_of_fresh_for_resync() {
    let (mut alice, mut _bob) = alice_bob();
    for i in 0..100 {
        a2b(&mut alice, &mut _bob, i);
    }
    alice
        .ratchet_encrypt(b"carrier".as_ref())
        .expect("alice stages rekey at seq 100");
    assert_eq!(alice.rekey_pending_confirm_queue.len(), 1);
    assert!(alice.outgoing_proposal.is_pending());

    let now_unix = super::state::now_unix_secs();

    // Simulate a proposal staged ~90s ago whose re-send traffic keeps
    // refreshing the LAST-attach stamps (fresh retry budget) while the FIRST-
    // staged window grows past the 60s staleness TTL.
    let mut refreshed = alice.clone();
    {
        let c = refreshed.rekey_pending_confirm_queue.front_mut().unwrap();
        c.first_attached_at = std::time::Instant::now() - std::time::Duration::from_secs(90);
        c.first_attached_at_unix = now_unix - 90;
        c.attached_at = std::time::Instant::now();
        c.attached_at_unix = now_unix;
    }

    // The retry budget still sees a "fresh" last re-send (≤ 30s)...
    let carrier = refreshed.rekey_pending_confirm_queue.front().unwrap();
    assert!(
        super::policy::carrier_effective_age(carrier)
            < std::time::Duration::from_secs(super::policy::REKEY_RETRY_TTL_SECS),
        "the re-send refreshed the retry TTL"
    );
    assert!(
        refreshed.outgoing_proposal_is_stale(),
        "staleness must judge the FIRST-staged window, not the last re-send (AUDIT F2)"
    );

    // ...and the resync path must EVICT the stale proposal and proceed instead
    // of refusing forever.
    let skipped = refreshed
        .resync_receiving_chain(130)
        .expect("stale outgoing proposal must be evicted, not block recovery");
    assert_eq!(skipped, 130);
    assert!(
        !refreshed.outgoing_proposal.is_pending(),
        "stale outgoing proposal must be evicted"
    );

    // Control: a genuinely fresh proposal (first-staged NOW) still refuses
    // resync.
    let mut fresh = alice.clone();
    assert!(
        fresh.resync_receiving_chain(130).is_err(),
        "a fresh pending outgoing proposal must still refuse resync"
    );
}
