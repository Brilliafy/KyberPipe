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
    // ── Server side ─────────────────────────────────────────────────────────
    let state = Arc::new(AppState::default());
    let server_pair = core_crypto::generate_pq_keypair().expect("server keypair");
    state.set_keypair(Some(server_pair.clone()));

    // Bind a real QUIC server endpoint on an ephemeral port.
    let endpoint = block_on_io_pub(core_crypto::quic_app::QuicAppManager::bind_server(0))
        .expect("server bind");
    let server_port = endpoint.local_addr().expect("local addr").port();
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
        .parse()
        .unwrap();

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
    assert_eq!(sas, stored_sas, "client-computed SAS must equal the server's");

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
    core_crypto::ratchet_init_session(
        hex_encode(&server_pair.mlkem_pk),
        kem.shared_secret.clone(),
        false, // client is the responder
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
    let plaintext = "e2e-clipboard-content-42";
    let msg = core_crypto::ratchet_encrypt_message(
        hex_encode(&server_pair.mlkem_pk),
        plaintext.as_bytes().to_vec(),
    )
    .expect("client ratchet encrypt");
    let clip_body = serde_json::json!({
        "encrypted_ratchet": {
            "nonce_hex": hex_encode(&msg.nonce),
            "ciphertext_hex": hex_encode(&msg.ciphertext),
            "rekey_x25519_pk_hex": msg.rekey_x25519_pk.as_ref().map(|v| hex_encode(v)),
            "rekey_mlkem_pk_hex": msg.rekey_mlkem_pk.as_ref().map(|v| hex_encode(v)),
            "rekey_ciphertext_hex": msg.rekey_ciphertext.as_ref().map(|v| hex_encode(v)),
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
    fn join_timeout(self, _d: std::time::Duration) -> Result<(), Box<dyn std::any::Any + Send + 'static>>;
}
impl JoinTimeout for std::thread::JoinHandle<()> {
    fn join_timeout(self, d: std::time::Duration) -> Result<(), Box<dyn std::any::Any + Send + 'static>> {
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

