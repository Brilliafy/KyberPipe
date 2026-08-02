//! End-to-end integration test: a QUIC client (simulating the Android app)
//! performs the FULL pairing round-trip against the real desktop handler
//! pipeline — KEM → pairing stream → SAS confirmation → mTLS-adjacent state
//! promotion → poll → ratchet-encrypted clipboard sync.
//!
//! This is the only test that proves the layers work as a WHOLE: transport
//! dispatch, per-stream authorization, pairing state machine, ratchet
//! initialization, and encrypted payload exchange over a real QUIC socket.

use crate::state::AppState;
use core_crypto::quic_app::{QuicAppManager, STREAM_CLIPBOARD, STREAM_PAIRING, STREAM_POLL};
use std::future::Future;
use std::sync::Arc;

/// Block a future on the shared core-crypto IO runtime.
fn block_on_io_pub<F: Future>(fut: F) -> F::Output {
    core_crypto::block_on_io(fut)
}

fn hex_encode(b: &[u8]) -> String {
    hex::encode(b)
}

#[test]
fn pairing_poll_clipboard_roundtrip() {
    // Hermetic clipboard: the wire-level rekey crossing below must be
    // deterministic. If the real OS clipboard has content, the desktop's own
    // send chain crosses seq 100 during the test and, as the initiator,
    // suppresses the client's rekey proposal (race outcome). Forcing an empty
    // clipboard keeps the client's rekey the one that wins.
    crate::handlers::FORCE_EMPTY_CLIPBOARD.store(true, std::sync::atomic::Ordering::Release);

    // ── Server side ─────────────────────────────────────────────────────────
    let state = Arc::new(AppState::default());
    // Mandatory QR pairing nonce (audit finding #20): the server rejects every
    // pairing request that does not echo the nonce it issued.
    state.issue_fresh_pairing_nonce();
    let pairing_nonce = state.get_pending_pairing_nonce();
    let server_pair = core_crypto::generate_pq_keypair().expect("server keypair");
    state.set_keypair(Some(server_pair.clone()));

    // Bind a real QUIC server endpoint on an ephemeral port.
    let endpoint = block_on_io_pub(core_crypto::quic_app::QuicAppManager::bind_server(0))
        .expect("server bind");
    let server_port = endpoint.local_addr().expect("local addr").port();
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();

    // Run the REAL dispatch loop (same code the production sync server uses)
    // on a dedicated thread; a oneshot lets the test stop it cleanly.
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let dispatch_state = state.clone();
    let dispatch = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("dispatch runtime");
        rt.block_on(crate::sync_server::run_server_dispatch(
            endpoint,
            dispatch_state,
            Some(stop_rx),
        ));
    });
    // Give the accept loop a moment to start.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // ── Client side (simulating the Android app) ────────────────────────────
    let client_pair = core_crypto::generate_pq_keypair().expect("client keypair");

    // Per-install client identity certificate (audit finding #8): the server
    // pins its hash during pairing and authorizes every post-pairing stream by
    // certificate — never by IP.
    let client_identity =
        core_crypto::generate_client_identity_cert().expect("client identity cert");
    // Build rustls client-cert material (constructed per-connect; PrivateKeyDer
    // is not Clone).
    let client_certs = || -> Option<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> {
        Some((
            vec![rustls::pki_types::CertificateDer::from(client_identity.cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(client_identity.key_der.clone().into()),
        ))
    };

    // 1) KEM: encapsulate to the server's public keys.
    let kem = core_crypto::encapsulate_pq_secret(
        server_pair.x25519_pk.clone(),
        server_pair.mlkem_pk.clone(),
    )
    .expect("client KEM");

    // 2) Connect over QUIC, PRESENTING the client identity certificate.
    let conn = block_on_io_pub(QuicAppManager::connect(server_addr, None, client_certs()))
        .expect("client QUIC connect");

    // 3) STREAM_PAIRING with the pairing payload (mirrors Android's JSON,
    // including the client cert hash so the server pins OUR identity).
    let pairing_body = serde_json::json!({
        "name": "E2E Phone",
        "ciphertext_hex": hex_encode(&kem.ciphertext),
        "client_pk_hex": hex_encode(&client_pair.mlkem_pk),
        "client_x25519_pk_hex": hex_encode(&client_pair.x25519_pk),
        "cert_hash_hex": client_identity.sha256_hex,
        "pairing_nonce_hex": pairing_nonce,
    })
    .to_string()
    .into_bytes();
    let resp = send_recv(&conn, STREAM_PAIRING, &pairing_body);
    let resp_json: serde_json::Value = serde_json::from_slice(&resp).expect("pairing response");
    assert_eq!(
        resp_json["status"].as_str(),
        Some("pairing_pending_sas"),
        "server must accept the KEM and move to SAS-pending, got: {resp_json}"
    );

    // 4) SAS: both sides compute it independently from the same inputs.
    let sas = core_crypto::generate_sas_code(
        server_pair.mlkem_pk.clone(),
        client_pair.mlkem_pk.clone(),
        kem.shared_secret.clone(),
    )
    .expect("sas");
    let stored_sas = state.get_sas_code();
    assert_eq!(
        sas, stored_sas,
        "client-computed SAS must equal the server's"
    );

    // 5) Confirm the SAS (server-side promotion, driven without the Tauri
    // layer). This pins the client cert and REBINDS the server with mTLS on
    // the same port.
    block_on_io_pub(crate::commands::pairing::perform_sas_confirmation(
        &state,
        sas,
        "E2E Phone".to_string(),
    ))
    .expect("SAS confirmation");
    assert!(
        state.settings.lock().is_paired,
        "settings.is_paired must be promoted by the pairing handler"
    );
    assert_eq!(
        state.get_paired_client_cert_hash(),
        client_identity.sha256_hex,
        "the client cert hash must be pinned during pairing"
    );

    // 6) Client initializes its ratchet (mirrors Android's handshake path).
    // Audit finding #1: the ratchet's initial DH identity must be the client's
    // OWN pairing keypair — the peer encapsulates rekey payloads to these public
    // keys, so decapsulation must use the matching private keys. Passing a fresh
    // unexchanged keypair (the legacy `ratchet_init_session` behaviour) would
    // permanently desync the session at the first rekey boundary.
    core_crypto::ratchet_init_session_with_keypair(
        hex_encode(&server_pair.mlkem_pk),
        kem.shared_secret.clone(),
        false, // client is the responder
        client_pair.x25519_pk.clone(),
        client_pair.x25519_sk.clone(),
        client_pair.mlkem_pk.clone(),
        client_pair.mlkem_sk.clone(),
        server_pair.x25519_pk.clone(),
        server_pair.mlkem_pk.clone(),
    )
    .expect("client ratchet init");

    // 7) The mTLS rebind dropped the old connection — reconnect WITH the
    // client cert to the same address (the rebind preserved the port).
    std::thread::sleep(std::time::Duration::from_millis(300));
    let conn = block_on_io_pub(QuicAppManager::connect(server_addr, None, client_certs()))
        .expect("client re-connect after mTLS rebind");

    // 8) STREAM_POLL: the paired peer may poll and receives pairing state.
    let poll = send_recv(&conn, STREAM_POLL, b"");
    let poll_json: serde_json::Value = serde_json::from_slice(&poll).expect("poll response");
    assert_eq!(
        poll_json["is_paired"].as_bool(),
        Some(true),
        "poll must report is_paired=true, got: {poll_json}"
    );

    // 8) Ratchet-encrypt a clipboard payload and send it over STREAM_CLIPBOARD.
    // Audit finding #12: the wire payload is a single base64-wrapped BINARY TLV.
    let plaintext = "e2e-clipboard-content-42";
    let bin = core_crypto::ratchet_encrypt_message_binary(
        hex_encode(&server_pair.mlkem_pk),
        plaintext.as_bytes().to_vec(),
    )
    .expect("client ratchet encrypt binary");
    let clip_body = serde_json::json!({
        "encrypted_ratchet": {
            "tlv_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin),
        }
    })
    .to_string()
    .into_bytes();
    let clip_resp = send_recv(&conn, STREAM_CLIPBOARD, &clip_body);
    let clip_json: serde_json::Value =
        serde_json::from_slice(&clip_resp).expect("clipboard response");
    assert_eq!(
        clip_json["status"].as_str(),
        Some("synced"),
        "server must decrypt and accept the ratchet payload, got: {clip_json}"
    );

    // 9) The server's clipboard deduplicator must now hold the decrypted text's
    // hash — proof the plaintext was actually recovered, not merely acknowledged.
    assert!(
        state.is_suppressed_duplicate(plaintext),
        "server must have recorded the decrypted clipboard text"
    );

    // ── 10) WIRE-LEVEL REKEY CROSSING (audit finding #1 regression) ──────────
    // The unit tests drive 250 messages per direction against in-memory
    // ratchets, but the e2e must prove the SAME property through the real
    // transport: the client sends ratchet-encrypted clipboard payloads over
    // STREAM_CLIPBOARD; at seq 100/200 the client's message carries a rekey
    // payload, the server derives the pending proposal, and the client commits
    // its outgoing rekey only after processing the server's RekeyAck (delivered
    // in the STREAM_POLL response). Each poll response also carries the
    // server's authenticated Synchronize packet, which the client must decrypt
    // to keep its receiving chain aligned with the server's send chain.
    let client_peer = hex_encode(&server_pair.mlkem_pk);
    let mut crossed_rekeys: u64 = 0;
    for i in 0..250 {
        let payload = format!("e2e-rekey-clipboard-{i}");
        let bin = core_crypto::ratchet_encrypt_message_binary(
            client_peer.clone(),
            payload.as_bytes().to_vec(),
        )
        .unwrap_or_else(|e| panic!("client encrypt {i} failed: {e}"));
        let clip_body = serde_json::json!({
            "encrypted_ratchet": {
                "tlv_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin),
            }
        })
        .to_string()
        .into_bytes();
        let resp = send_recv(&conn, STREAM_CLIPBOARD, &clip_body);
        let resp_json: serde_json::Value =
            serde_json::from_slice(&resp).expect("clipboard response");
        assert_eq!(
            resp_json["status"].as_str(),
            Some("synced"),
            "clipboard msg {i} must decrypt on the wire, got: {resp_json}"
        );
        assert!(
            state.is_suppressed_duplicate(&payload),
            "server must have recovered plaintext of msg {i}"
        );

        // Poll for the server's RekeyAck + Synchronize (in server send order:
        // rekey_ack first, then sync).
        let poll = send_recv(&conn, STREAM_POLL, b"");
        let poll_json: serde_json::Value = serde_json::from_slice(&poll).expect("poll response");
        if let Some(ack) = poll_json.get("rekey_ack_encrypted") {
            let tlv_b64 = ack["tlv_b64"].as_str().expect("ack tlv_b64");
            let tlv = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64)
                .expect("ack tlv decode");
            let pt = core_crypto::ratchet_decrypt_message_binary(client_peer.clone(), tlv)
                .unwrap_or_else(|e| panic!("client decrypt of rekey ack failed: {e}"));
            let msg = core_crypto::packets::KyberMessage::from_json(&String::from_utf8_lossy(&pt))
                .expect("ack packet");
            if let core_crypto::packets::KyberMessage::RekeyAck { seq } = msg {
                if core_crypto::ratchet_process_rekey_ack(client_peer.clone(), seq).unwrap_or(false)
                {
                    crossed_rekeys += 1;
                }
            }
        }
        // Keep the client's receive chain aligned with the server's send chain
        // by processing the server's authenticated Synchronize packet (binary
        // TLV; rekey-aware inside ratchet_process_synchronize). A stale target
        // (chain already aligned) is ignored by the core.
        if let Some(sync) = poll_json.get("sync") {
            let tlv_b64 = sync["tlv_b64"].as_str().expect("sync tlv_b64");
            let tlv = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64)
                .expect("sync tlv decode");
            let _ = core_crypto::ratchet_process_synchronize(client_peer.clone(), tlv);
        }
    }
    // The client must have committed its outgoing rekey at least once via the
    // wire RekeyAck (gen 0 seq 100; gen 1 seq 100 if it ran far enough). This
    // proves the full rekey round-trip — KEM keypairs matching end-to-end, the
    // pending-chain fallback, and the ACK-driven commit — over the real
    // transport, not just in-memory.
    assert!(
        crossed_rekeys >= 1,
        "the client must have committed an outgoing rekey via the wire RekeyAck, crossed={crossed_rekeys}"
    );

    // ── Teardown ────────────────────────────────────────────────────────────
    // Signal the dispatch loop to stop and join the thread so the test process
    // exits cleanly (no lingering runtime holding the binary open).
    let _ = stop_tx.send(());
    let _ = dispatch.join_timeout(std::time::Duration::from_secs(10));
    // Stop the shared IO runtime so its worker threads do not keep the test
    // process alive after the assertions complete.
    core_crypto::shutdown_io_runtime();
}

/// Block on a join handle with a timeout (std has no timed join).
trait JoinTimeout {
    fn join_timeout(
        self,
        _d: std::time::Duration,
    ) -> Result<(), Box<dyn std::any::Any + Send + 'static>>;
}
impl JoinTimeout for std::thread::JoinHandle<()> {
    fn join_timeout(
        self,
        d: std::time::Duration,
    ) -> Result<(), Box<dyn std::any::Any + Send + 'static>> {
        for _ in 0..(d.as_millis() / 100).max(1) {
            if self.is_finished() {
                return self.join();
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // Timed out — detach rather than hang the process.
        let _ = self;
        Ok(())
    }
}

/// Send one frame and read the matching response on a connected QUIC stream.
fn send_recv(conn: &quinn::Connection, stream_type: u8, body: &[u8]) -> Vec<u8> {
    block_on_io_pub(core_crypto::quic_bridge::quic_send_and_recv_impl(
        conn,
        stream_type,
        &String::from_utf8_lossy(body),
    ))
    .expect("quic send/recv")
    .into_bytes()
}
