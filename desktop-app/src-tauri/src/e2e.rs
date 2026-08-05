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

/// Make the server TLS identity hermetic for the test. `load_or_generate_cert`
/// (audit #4 follow-up) REFUSES to serve when a persisted `server_cert.der`
/// exists but its private key is unaccounted for (no keyring entry, no legacy
/// key file) — the correct security posture. Across test runs the keyring is
/// process-local (not persisted) while the cert FILE survives, so a stale
/// keyless cert can linger and trip the refusal. Remove that stale state so the
/// test always takes the clean first-run generate path.
fn reset_server_tls_identity() {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::remove_file(dir.join("server_cert.der"));
    let _ = std::fs::remove_file(dir.join("server_key.der"));
    if let Ok(entry) = keyring::Entry::new("kyberpipe", "server_tls_key") {
        let _ = entry.delete_password();
    }
    // The OS keyring is not durable on every machine (headless/CI backends can
    // accept `set_password` without persisting across Entry instances). The
    // mTLS rebind loads the server identity a SECOND time; force the 0600 key
    // file to be the durable store so the post-pairing cert-less-rejection
    // assertion is deterministic (audit finding #2).
    core_crypto::quic_app::FORCE_LEGACY_KEY_FILE.store(true, std::sync::atomic::Ordering::Release);
}

#[test]
fn pairing_poll_clipboard_roundtrip() {
    // A stale keyless server cert from a previous run would make the audit-#4
    // identity guard refuse to serve REGARDLESS of THIS test's own setup — make
    // the server identity hermetic so the assertion below is meaningful.
    reset_server_tls_identity();
    // AUDIT F1: SettingsService now LOADS settings.json at startup, so a stale
    // real-user settings file (is_paired, identity fields) would leak into
    // this test and break the fresh-state assertions. Wipe the persisted
    // app-data state so the test is hermetic.
    if let Some(dirs) = directories::ProjectDirs::from("io", "github", "KyberPipe") {
        for name in [
            "settings.json",
            "ratchet_sessions.json",
            "ratchet_watermarks.json",
        ] {
            let _ = std::fs::remove_file(dirs.data_dir().join(name));
        }
    }
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
    // AUDIT F9: the QR payload the renderer builds must ALWAYS carry a 32-hex
    // pairing nonce and a 64-hex server cert hash — assert both shapes here so
    // a token-gate regression (or a dropped field) is caught at the wire level.
    assert_eq!(
        pairing_nonce.len(),
        32,
        "pairing nonce must be 32 hex chars (16 random bytes), got {pairing_nonce:?}"
    );
    let server_cert_hash = core_crypto::quic_server_cert_hash().unwrap_or_default();
    assert_eq!(
        server_cert_hash.len(),
        64,
        "server cert hash must be 64 hex chars (SHA-256), got {server_cert_hash:?}"
    );
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

    // AUDIT FINDING #1 (CRITICAL, regression): the bootstrap pairing
    // connection MUST present the client identity certificate. The defect was
    // that the Android app connected cert-less at pairing time, so the desktop
    // recorded an EMPTY TLS-observed peer cert hash, the pin/map/mTLS-rebind
    // block in perform_sas_confirmation was skipped, and every post-pairing
    // stream was rejected against an empty pinned set ("paired but nothing
    // syncs"). Drive the exact defective path here: a cert-less connection
    // submitting a valid KEM handshake must be REJECTED loudly (before the
    // rate limiter, so it does not consume the legitimate peer's budget), not
    // silently admitted to a SAS-pending state that can never sync.
    {
        let cert_less_conn = block_on_io_pub(QuicAppManager::connect(server_addr, None, None))
            .expect("cert-less QUIC connect");
        let cert_less_body = serde_json::json!({
            "name": "E2E Cert-Less Phone",
            "ciphertext_hex": hex_encode(&kem.ciphertext),
            "client_pk_hex": hex_encode(&client_pair.mlkem_pk),
            "client_x25519_pk_hex": hex_encode(&client_pair.x25519_pk),
            "pairing_nonce_hex": pairing_nonce,
        })
        .to_string()
        .into_bytes();
        let cert_less_resp = send_recv(&cert_less_conn, STREAM_PAIRING, &cert_less_body);
        let cert_less_json: serde_json::Value =
            serde_json::from_slice(&cert_less_resp).expect("cert-less pairing response");
        assert_eq!(
            cert_less_json["reason"].as_str(),
            Some("Client certificate required for pairing"),
            "cert-less pairing must be rejected loudly, got: {cert_less_json}"
        );
        assert!(
            !state.settings.lock().is_paired,
            "cert-less pairing must never reach the paired state"
        );
        drop(cert_less_conn);
    }

    // 2) Connect over QUIC, PRESENTING the client identity certificate.
    let conn = block_on_io_pub(QuicAppManager::connect(server_addr, None, client_certs()))
        .expect("client QUIC connect");

    // 3) STREAM_PAIRING with the pairing payload (mirrors Android's JSON,
    // including the client cert hash so the server pins OUR identity).
    // AUDIT FINDING #10: the phone-side SAS echo is MANDATORY — the desktop
    // rejects a pairing request whose `sas_hex` does not equal the SAS it
    // computed from the same KEM shared secret. Compute the SAS up front and
    // embed it, exactly like the Android pairing flow does.
    let sas = core_crypto::generate_sas_code(
        server_pair.mlkem_pk.clone(),
        client_pair.mlkem_pk.clone(),
        kem.shared_secret.clone(),
    )
    .expect("sas");
    let pairing_body = serde_json::json!({
        "name": "E2E Phone",
        "ciphertext_hex": hex_encode(&kem.ciphertext),
        "client_pk_hex": hex_encode(&client_pair.mlkem_pk),
        "client_x25519_pk_hex": hex_encode(&client_pair.x25519_pk),
        "cert_hash_hex": client_identity.sha256_hex,
        "pairing_nonce_hex": pairing_nonce,
        "sas_hex": sas,
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
    // (Computed above for the phone-side echo; verify it matches the server's.)
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

    // AUDIT FINDING #2 (regression): the post-pairing mTLS rebind must take
    // effect IMMEDIATELY — not "on next restart". The defect was that
    // rebind_server re-bound the same 0.0.0.0:port while the old endpoint was
    // still referenced, the second bind failed with EADDRINUSE, and the
    // running endpoint kept serving with the pre-pairing accept-any verifier.
    // In this quinn/rustls stack the TLS handshake's client-auth rejection is
    // ASYNCHRONOUS (the server-side handshake stalls at the empty/foreign
    // certificate while the client's `connect()` may already have returned) —
    // so the observable post-pairing guarantee is at the data plane: a
    // cert-less or wrong-cert reconnect must NOT complete a stream round-trip
    // through the dispatch loop, while a paired-cert reconnect MUST.
    {
        // Give the dispatch loop a beat to re-acquire the rebound endpoint.
        std::thread::sleep(std::time::Duration::from_millis(300));
        // 1) Cert-less reconnect — must not complete a poll round-trip.
        if let Ok(cert_less) = block_on_io_pub(QuicAppManager::connect(server_addr, None, None)) {
            let poll = send_recv_timeout(&cert_less, STREAM_POLL, b"", 2_000);
            assert!(
                poll.is_none(),
                "a cert-less reconnect MUST be rejected post-pairing: got a poll response {poll:?}"
            );
            drop(cert_less);
        }
        // 2) Unrelated-cert reconnect — must not complete a poll round-trip.
        let stranger_cert =
            core_crypto::generate_client_identity_cert().expect("stranger identity cert");
        let stranger_certs = || -> Option<(
            Vec<rustls::pki_types::CertificateDer<'static>>,
            rustls::pki_types::PrivateKeyDer<'static>,
        )> {
            Some((
                vec![rustls::pki_types::CertificateDer::from(stranger_cert.cert_der.clone())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(stranger_cert.key_der.clone().into()),
            ))
        };
        if let Ok(stranger) =
            block_on_io_pub(QuicAppManager::connect(server_addr, None, stranger_certs()))
        {
            let poll = send_recv_timeout(&stranger, STREAM_POLL, b"", 2_000);
            assert!(
                poll.is_none(),
                "a stranger-cert reconnect MUST be rejected post-pairing: got a poll response {poll:?}"
            );
            drop(stranger);
        }
        // 3) The PAIRED cert must still complete a poll round-trip.
        if let Ok(paired_conn) =
            block_on_io_pub(QuicAppManager::connect(server_addr, None, client_certs()))
        {
            let poll = send_recv_timeout(&paired_conn, STREAM_POLL, b"", 2_000);
            assert!(
                poll.is_some(),
                "the paired cert must still complete a poll round-trip after the rebind"
            );
            drop(paired_conn);
        }
    }

    // 6) Client initializes its ratchet (mirrors Android's handshake path).
    // Audit finding #1: the ratchet's initial DH identity must be the client's
    // OWN pairing keypair — the peer encapsulates rekey payloads to these public
    // keys, so decapsulation must use the matching private keys. Passing a fresh
    // unexchanged keypair (the legacy `ratchet_init_session` behaviour) would
    // permanently desync the session at the first rekey boundary.
    // The raw-secrets UniFFI export is cfg(test)-gated (audit KYP-2026-02 #25);
    // this e2e calls the Rust-internal impl directly with the same semantics.
    core_crypto::ratchet_ffi::ratchet_init_session_with_keypair_impl(
        &hex_encode(&server_pair.mlkem_pk),
        &kem.shared_secret,
        false, // client is the responder
        Some((
            client_pair.x25519_pk.clone(),
            zeroize::Zeroizing::new(client_pair.x25519_sk.clone()),
            client_pair.mlkem_pk.clone(),
            zeroize::Zeroizing::new(client_pair.mlkem_sk.clone()),
        )),
        Some(&server_pair.x25519_pk),
        Some(&server_pair.mlkem_pk),
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
    // (AUDIT F14: `is_suppressed_duplicate` was removed with the ungated
    // `sync_clipboard` command; re-checking via `check_and_record` proves the
    // hash was already recorded — a second check reports it as a duplicate.)
    assert!(
        !state.check_and_record_clipboard(plaintext),
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
            !state.check_and_record_clipboard(&payload),
            "server must have recovered plaintext of msg {i}"
        );

        // Poll for the server's RekeyAck + Synchronize (in server send order:
        // rekey_ack first, then sync). AUDIT FINDING #16: the Synchronize
        // carrier is now CONDITIONAL — the client must request it via
        // `need_sync` (mirroring the Android loop's heartbeat/decrypt-gap
        // logic) for the desktop to attach its carrier. The e2e requests a
        // sync on every poll so the wire-level alignment path is still fully
        // exercised.
        let poll_body = serde_json::json!({ "need_sync": true }).to_string();
        let poll = send_recv(&conn, STREAM_POLL, poll_body.as_bytes());
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
    // Drop the client connection so its quinn driver task finishes; the server
    // endpoint is held by the process-global static, so release it too.
    drop(conn);
    let _ = core_crypto::quic_app::release_server_endpoint_for_tests();
    // Join with a generous bound — the dispatch loop breaks on the oneshot and
    // the per-connection tasks abort when the thread's runtime drops.
    // HARD join (audit follow-up): the previous `join_timeout(20s)` silently
    // gave up if the dispatch thread ran long, letting its non-daemon runtime
    // workers keep the test binary open forever (the CI hang). The dispatch is
    // designed to exit on `stop` — the accept loop breaks on the oneshot and
    // dropping the runtime aborts the per-connection tasks — so a blocking
    // join is correct and makes any linger a visible teardown failure instead
    // of an invisible post-assertions hang.
    let _ = dispatch.join();
    // Stop the shared IO runtime (bounded blocking) so its worker threads do
    // not keep the test process alive after the assertions complete.
    core_crypto::shutdown_io_runtime();
    // Also shut down the FFI runtime (if any test path created it) and the
    // background persistence writer (created by the first save_settings call)
    // — both keep non-daemon threads alive and would otherwise hang the
    // process after the tests pass.
    core_crypto::shutdown_ffi_runtime();
    crate::state::shutdown_persist_for_tests();
}

/// Send one frame and read the matching response on a connected QUIC stream.
fn send_recv(conn: &quinn::Connection, stream_type: u8, body: &[u8]) -> Vec<u8> {
    block_on_io_pub(core_crypto::quic_bridge::quic_send_and_recv_impl(
        conn.clone(),
        stream_type,
        String::from_utf8_lossy(body).to_string(),
    ))
    .expect("quic send/recv")
    .into_bytes()
}

/// Send one frame and wait up to `timeout_ms` for the response. Returns None
/// when no response arrives in time — the connection was dropped or the peer
/// never admitted the stream (the mTLS post-pairing rejection is asynchronous
/// at the TLS layer in this quinn/rustls stack, so this is the observable
/// data-plane signal).
fn send_recv_timeout(
    conn: &quinn::Connection,
    stream_type: u8,
    body: &[u8],
    timeout_ms: u64,
) -> Option<Vec<u8>> {
    block_on_io_pub(async {
        tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            core_crypto::quic_bridge::quic_send_and_recv_impl(
                conn.clone(),
                stream_type,
                String::from_utf8_lossy(body).to_string(),
            ),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|r| r.into_bytes())
    })
}
