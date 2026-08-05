//! End-to-end integration test: a QUIC client (simulating the Android app)
//! performs the FULL pairing round-trip against the real desktop handler
//! pipeline — KEM → pairing stream → SAS confirmation → mTLS-adjacent state
//! promotion → poll → ratchet-encrypted clipboard sync.
//!
//! This is the only test that proves the layers work as a WHOLE: transport
//! dispatch, per-stream authorization, pairing state machine, ratchet
//! initialization, and encrypted payload exchange over a real QUIC socket.

use std::future::Future;

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

mod pairing_poll_roundtrip;

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
