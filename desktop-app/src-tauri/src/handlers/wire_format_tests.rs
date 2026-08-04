//! Cross-boundary wire-format integration tests (audit F8).
//!
//! The Android senders produce `{"encrypted_ratchet": {"tlv_b64": ...}}`
//! (binary ratchet TLV via `ratchetEncryptMessageBinary`). These tests drive
//! the REAL desktop handlers with exactly that payload shape and assert the
//! SMS/media data lands — the regression that previously dropped every
//! forwarded SMS/media because the handlers still parsed the removed legacy
//! session-key hex format.

use crate::state::AppState;
use std::future::Future;
use std::sync::Arc;

/// Run the handler on a HERMETIC current-thread runtime (audit follow-up): the
/// wire-format tests must not create the process-global FFI runtime — the e2e
/// teardown shuts that runtime down, and a cross-test ordering race between a
/// late-starting wire test and the e2e's shutdown would leave either a panic
/// or a live runtime keeping the test binary open. Each test builds, uses and
/// drops its own runtime, so the suites are fully independent.
fn block_on_hermetic<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("hermetic test runtime")
        .block_on(fut)
}

/// Build a phone-side ratchet message the desktop's registered session can
/// decrypt: init the phone (responder) session, encrypt, then replace it with
/// the desktop (initiator) session whose receive chain mirrors the phone's
/// send chain. Returns the binary TLV.
fn android_produced_ratchet_tlv(peer_id: &str, plaintext: &[u8]) -> Vec<u8> {
    let server_pair = core_crypto::generate_pq_keypair().expect("server pair");
    let client_pair = core_crypto::generate_pq_keypair().expect("client pair");
    let secret = b"test-master-secret-for-wire-format-0123456789";

    let caller_keypair = |p: &core_crypto::PqKeyPair| {
        (
            p.x25519_pk.clone(),
            zeroize::Zeroizing::new(p.x25519_sk.clone()),
            p.mlkem_pk.clone(),
            zeroize::Zeroizing::new(p.mlkem_sk.clone()),
        )
    };

    // Phone (responder): encrypts the payload.
    core_crypto::ratchet_ffi::ratchet_init_session_with_keypair_impl(
        peer_id,
        secret,
        false,
        Some(caller_keypair(&client_pair)),
        Some(server_pair.x25519_pk.as_slice()),
        Some(server_pair.mlkem_pk.as_slice()),
    )
    .expect("phone session init");
    let tlv = core_crypto::ratchet_ffi::ratchet_encrypt_message_impl(peer_id, plaintext)
        .expect("phone encrypt")
        .to_binary()
        .expect("phone TLV");

    // Replace with the desktop (initiator) session under the SAME peer id so
    // `handle_sms`/`handle_media` can decrypt through the registry.
    core_crypto::ratchet_remove_session(peer_id.to_string());
    core_crypto::ratchet_ffi::ratchet_init_session_with_keypair_impl(
        peer_id,
        secret,
        true,
        Some(caller_keypair(&server_pair)),
        Some(client_pair.x25519_pk.as_slice()),
        Some(client_pair.mlkem_pk.as_slice()),
    )
    .expect("desktop session init");
    tlv
}

fn android_json_body(tlv: &[u8]) -> Vec<u8> {
    let tlv_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, tlv);
    serde_json::json!({
        "encrypted_ratchet": { "tlv_b64": tlv_b64 }
    })
    .to_string()
    .into_bytes()
}

/// AUDIT F8 (CRITICAL): `handle_sms` must decrypt the Android-produced ratchet
/// TLV body and record the packet — not parse the removed legacy hex format.
#[test]
fn handle_sms_accepts_android_ratchet_tlv() {
    let state = Arc::new(AppState::default());
    let client_pair = core_crypto::generate_pq_keypair().expect("client pair");
    let peer_id = hex::encode(&client_pair.mlkem_pk);
    state.set_pairing_initiator_pk(peer_id.clone());

    let sms_json = serde_json::json!({
        "sender": "+15551234567",
        "body": "hello from the ratchet wire",
        "timestamp": 1234567890u64,
    })
    .to_string();
    let tlv = android_produced_ratchet_tlv(&peer_id, sms_json.as_bytes());
    let body = android_json_body(&tlv);

    let resp = block_on_hermetic(crate::handlers::handle_sms(
        body,
        peer_id.clone(),
        state.clone(),
    ));
    let resp_json: serde_json::Value = serde_json::from_slice(&resp).expect("resp json");
    assert_eq!(
        resp_json["status"].as_str(),
        Some("synced"),
        "SMS must be accepted: {resp_json}"
    );
    let history = state.get_sms_history();
    assert_eq!(history.len(), 1, "exactly one SMS must be recorded");
    assert_eq!(history[0].sender, "+15551234567");
    assert_eq!(history[0].body, "hello from the ratchet wire");
    assert_eq!(history[0].timestamp, 1234567890);

    // Scope cleanup to THIS test's peer only — the global registry is shared
    // with the e2e test running in parallel.
    core_crypto::ratchet_remove_session(peer_id.clone());
}

/// AUDIT F8: a legacy session-key hex body (the removed wire format) is a
/// protocol violation — it must NOT silently decrypt to nothing and must not
/// record anything.
#[test]
fn handle_sms_rejects_legacy_session_key_hex_body() {
    let state = Arc::new(AppState::default());
    let client_pair = core_crypto::generate_pq_keypair().expect("client pair");
    let peer_id = hex::encode(&client_pair.mlkem_pk);
    state.set_pairing_initiator_pk(peer_id.clone());
    // (No ratchet session needed — the legacy body should be refused on shape.)
    let legacy_body = serde_json::json!({
        "encrypted": {
            "nonce_hex": "00112233445566778899aabb",
            "ciphertext_hex": "deadbeef"
        }
    })
    .to_string()
    .into_bytes();
    let resp = block_on_hermetic(crate::handlers::handle_sms(
        legacy_body,
        peer_id.clone(),
        state.clone(),
    ));
    let resp_json: serde_json::Value = serde_json::from_slice(&resp).expect("resp json");
    assert_ne!(
        resp_json["status"].as_str(),
        Some("synced"),
        "legacy hex body must NOT be accepted"
    );
    assert_eq!(state.get_sms_history().len(), 0);
    core_crypto::ratchet_remove_session(peer_id.clone());
}

/// AUDIT F8: `handle_media` must decrypt the Android-produced ratchet TLV body
/// and update the media state.
#[test]
fn handle_media_accepts_android_ratchet_tlv() {
    let state = Arc::new(AppState::default());
    let client_pair = core_crypto::generate_pq_keypair().expect("client pair");
    let peer_id = hex::encode(&client_pair.mlkem_pk);
    state.set_pairing_initiator_pk(peer_id.clone());

    let media_json = serde_json::json!({
        "title": "Bohemian Rhapsody",
        "artist": "Queen",
        "album_art": "",
        "is_playing": true,
        "actions": [
            { "title": "Play", "index": 0 },
            { "title": "Pause", "index": 1 },
        ],
    })
    .to_string();
    let tlv = android_produced_ratchet_tlv(&peer_id, media_json.as_bytes());
    let body = android_json_body(&tlv);

    let resp = block_on_hermetic(crate::handlers::handle_media(
        body,
        peer_id.clone(),
        state.clone(),
    ));
    let resp_json: serde_json::Value = serde_json::from_slice(&resp).expect("resp json");
    assert_eq!(
        resp_json["status"].as_str(),
        Some("synced"),
        "media must be accepted: {resp_json}"
    );
    let media = state.get_media_state();
    assert_eq!(media.title, "Bohemian Rhapsody");
    assert_eq!(media.artist, "Queen");
    assert!(media.is_playing);
    assert_eq!(media.actions.len(), 2);
    assert_eq!(media.actions[0].title, "Play");

    core_crypto::ratchet_remove_session(peer_id.clone());
}

/// AUDIT FINDING #12 (binary pairing frame unreachable): the nonce check used
/// to parse the body as JSON BEFORE the binary-frame branch, so a binary body
/// could never satisfy it (empty supplied nonce → rejected) — the binary
/// transport was dead code, and reordering the checks naively would have let
/// the binary path skip the nonce entirely. The decoder now carries the nonce
/// per-format and BOTH formats validate against the same QR-bound nonce.
/// This test pins the decoder contract: a frame WITH the correct nonce
/// round-trips; a frame WITHOUT a nonce decodes with an empty nonce (which the
/// handler then rejects identically to a nonce-less JSON body).
#[test]
fn binary_pairing_frame_nonce_roundtrip() {
    // Build a minimal frame: ct, mlkem pk, x25519 pk, cert hash, nonce.
    let mut frame: Vec<u8> = Vec::new();
    let ct = vec![1u8, 2, 3, 4];
    let pk = vec![5u8, 6, 7];
    let xpk = vec![8u8, 9];
    let cert = "aabbccdd".to_string();
    let nonce = "deadbeef".to_string();

    for field in [&ct, &pk, &xpk] {
        frame.extend_from_slice(&(field.len() as u32).to_be_bytes());
        frame.extend_from_slice(field);
    }
    frame.extend_from_slice(&(cert.len() as u32).to_be_bytes());
    frame.extend_from_slice(cert.as_bytes());
    frame.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    frame.extend_from_slice(nonce.as_bytes());

    let decoded = crate::handlers::pairing::decode_binary_pairing_frame(&frame)
        .expect("valid binary frame decodes");
    assert_eq!(decoded.0, ct);
    assert_eq!(decoded.1, pk);
    assert_eq!(decoded.2, xpk);
    assert_eq!(decoded.3, cert);
    assert_eq!(
        decoded.4, nonce,
        "the nonce must round-trip through the binary frame (audit finding #12)"
    );
    assert!(
        decoded.5.is_empty(),
        "a frame without an embedded SAS echo must surface an empty sas_hex (audit finding #10)"
    );

    // A frame WITHOUT the trailing nonce still decodes (legacy shape) but with
    // an EMPTY nonce — which the handler rejects identically to a nonce-less
    // JSON body, so there is no nonce bypass for the binary path.
    let mut legacy = Vec::new();
    for field in [&ct, &pk, &xpk] {
        legacy.extend_from_slice(&(field.len() as u32).to_be_bytes());
        legacy.extend_from_slice(field);
    }
    legacy.extend_from_slice(&(cert.len() as u32).to_be_bytes());
    legacy.extend_from_slice(cert.as_bytes());
    let decoded_legacy = crate::handlers::pairing::decode_binary_pairing_frame(&legacy)
        .expect("legacy frame without nonce still decodes");
    assert!(
        decoded_legacy.4.is_empty(),
        "a frame without an embedded nonce must surface an empty nonce"
    );
    assert!(
        decoded_legacy.5.is_empty(),
        "a legacy frame surfaces an empty sas_hex, rejected by the mandatory SAS-echo check"
    );
}

/// AUDIT FINDING #18 (implicit cross-repo ordering contract): the poll
/// response's ratchet-encrypted fields have a strict processing order on the
/// Android side (clip → rekey_ack → sync). The response now carries an
/// explicit `manifest` listing that insertion order. This test builds a real
/// response through `build_poll_response` and pins the manifest so any future
/// reordering fails here rather than silently desyncing the phone.
#[test]
fn poll_response_manifest_prescribes_field_order() {
    let peer_id = "manifest-peer-test";
    let server_pair = core_crypto::generate_pq_keypair().expect("server pair");
    let client_pair = core_crypto::generate_pq_keypair().expect("client pair");
    let secret = b"test-master-secret-for-manifest-012345678";

    let caller_keypair = |p: &core_crypto::PqKeyPair| {
        (
            p.x25519_pk.clone(),
            zeroize::Zeroizing::new(p.x25519_sk.clone()),
            p.mlkem_pk.clone(),
            zeroize::Zeroizing::new(p.mlkem_sk.clone()),
        )
    };
    // Server (initiator) — the poll responder.
    core_crypto::ratchet_ffi::ratchet_init_session_with_keypair_impl(
        peer_id,
        secret,
        true,
        Some(caller_keypair(&server_pair)),
        Some(client_pair.x25519_pk.as_slice()),
        Some(client_pair.mlkem_pk.as_slice()),
    )
    .expect("server session init");

    let state = Arc::new(AppState::default());
    let body = serde_json::json!({ "need_sync": true }).to_string();
    let resp_bytes = block_on_hermetic(crate::handlers::handle_poll(
        body.into_bytes(),
        peer_id.to_string(),
        state,
    ));
    let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).expect("resp json");

    // The manifest must exist and prescribe the exact processing order of the
    // ratchet-encrypted fields that ARE present: `latest_clip_encrypted` first,
    // `rekey_ack_encrypted` (when the responder holds a pending ack) second,
    // `sync` (when a sync was requested) last. Every manifest entry must
    // correspond to a real field, and every ratchet field in the response must
    // be in the manifest — so a producer that reorders its inserts (or omits
    // the manifest) fails this contract.
    let manifest: Vec<String> = resp["manifest"]
        .as_array()
        .expect("response must carry a manifest")
        .iter()
        .map(|v| v.as_str().expect("manifest entry").to_string())
        .collect();
    // Ordering property: clip before sync, and ack (if present) between them.
    assert!(
        manifest.first().map(|s| s.as_str()) == Some("latest_clip_encrypted"),
        "clip must be first, got {manifest:?}"
    );
    if let Some(pos) = manifest.iter().position(|s| s == "sync") {
        assert!(
            manifest[pos - 1] == "latest_clip_encrypted"
                || manifest[pos - 1] == "rekey_ack_encrypted",
            "sync must follow clip (and ack, when present), got {manifest:?}"
        );
    }
    if let Some(pos) = manifest.iter().position(|s| s == "rekey_ack_encrypted") {
        assert!(
            pos == 1,
            "ack must be second when present, got {manifest:?}"
        );
    }
    // Every manifest entry maps to a real response field, and vice versa.
    for entry in &manifest {
        assert!(
            resp.get(entry).is_some(),
            "manifest entry '{entry}' must exist in the response"
        );
    }
    for key in ["latest_clip_encrypted", "rekey_ack_encrypted", "sync"] {
        if resp.get(key).is_some() {
            assert!(
                manifest.contains(&key.to_string()),
                "present field '{key}' must be listed in the manifest"
            );
        }
    }

    core_crypto::ratchet_remove_session(peer_id.to_string());
}

/// AUDIT #12 (wire-format conformance): the ratchet wire fields must round-trip
/// through the SAME codecs both platforms use — the Android side builds
/// `tlv_b64` (Base64 of the binary ratchet TLV) and the pairing KEM ciphertext
/// via the shared `core_crypto::hex_encode`; the desktop decodes both. A
/// hand-rolled encoder on one side (the pre-#12 `joinToString { "%02x" }`) is
/// a drift surface — this test pins the exact codec round-trips so any future
/// encoding divergence fails here rather than silently corrupting the wire.
#[test]
fn shared_codec_roundtrips_ratchet_wire_fields() {
    // 1. The Android-produced ratchet TLV (binary) must round-trip through
    //    Base64 (the poll wire shape) and decode to the same bytes the desktop
    //    then hands to `ratchet_process_synchronize` / the decrypt dispatcher.
    let tlv = android_produced_ratchet_tlv("codec-peer", b"codec-conformance");
    assert!(!tlv.is_empty());
    let tlv_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tlv);
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64).expect("b64");
    assert_eq!(decoded, tlv, "base64 round-trip must be lossless");

    // 2. The pairing KEM ciphertext travels as hex produced by the SHARED
    //    UniFFI codec (`core_crypto::hex_encode`) and is decoded on the desktop
    //    with the same `hex` implementation that codec wraps. Round-trip it
    //    through both entry points and assert byte equality.
    let raw: Vec<u8> = (0u8..=255u8).collect();
    let via_uniffi = core_crypto::hex_encode(raw.clone());
    let decoded_via_hex_crate = hex::decode(&via_uniffi).expect("hex::decode");
    assert_eq!(decoded_via_hex_crate, raw, "shared hex codec must round-trip");
    // The shared codec output must be canonical lowercase hex — the exact shape
    // the desktop's `hex::decode` (and the QR-bound fields) expect.
    assert_eq!(
        via_uniffi,
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "hex_encode must produce canonical lowercase hex"
    );

    // 3. The Android phone's decoded ciphertext bytes are what the KEM handler
    //    consumes — verify the full chain: raw bytes → hexEncode (Android) →
    //    hex::decode (desktop) → identical bytes.
    let kem_ct: Vec<u8> = (0u8..16u8).chain(250..=255u8).collect();
    let android_hex = core_crypto::hex_encode(kem_ct.clone());
    let desktop_bytes = hex::decode(android_hex).expect("desktop decode");
    assert_eq!(desktop_bytes, kem_ct, "cross-platform hex chain must be lossless");

    core_crypto::ratchet_remove_session("codec-peer".to_string());
}
