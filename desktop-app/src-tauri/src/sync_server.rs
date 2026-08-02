//! QUIC-backed sync server.
//!
//! Binds a quinn QUIC endpoint and dispatches incoming streams
//! to the handler functions defined in the `handlers` module.
//!
//! # Security model
//! Every accepted connection is bound to the peer's client-certificate hash and
//! IP at handshake time. Stream dispatch is then authorized per stream:
//! - `STREAM_PAIRING` is only allowed while unpaired (and is per-IP rate limited).
//! - All other streams (clipboard, media, poll, rekey-ack, unpair) require an
//!   active pairing AND a peer that matches the identity recorded during
//!   pairing (certificate hash preferred, IP as fallback). This closes the
//!   unauthenticated poll/unpair hole.

use crate::handlers::{
    handle_clipboard, handle_media, handle_pairing, handle_poll, handle_rekey_ack, handle_sms,
    handle_unpair,
};
use crate::state::AppState;
use core_crypto::quic_app::{
    BoxFuture, QuicFrame, STREAM_CLIPBOARD, STREAM_MEDIA, STREAM_PAIRING, STREAM_POLL,
    STREAM_REKEY_ACK, STREAM_SMS, STREAM_UNPAIR,
};
use sha2::Digest;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

/// Maximum concurrent QUIC connections accepted at once. Bounds the number of
/// per-connection accept-loop tasks and connection buffers an attacker on the
/// LAN can force the server to hold before any authorization happens (audit
/// finding #8 — pre-pairing LAN DoS).
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
/// Maximum concurrent streams per connection. Bounds the N×M task explosion
/// from a single hostile connection.
const MAX_STREAMS_PER_CONNECTION: usize = 16;
/// Maximum concurrent streams across ALL connections.
const MAX_GLOBAL_STREAMS: usize = 256;

/// Authorize a stream from a given peer against the pairing state.
/// Post-pairing identity is the CLIENT CERTIFICATE hash captured at pairing
/// time — never the IP address (audit finding #8: IP binding breaks on network
/// handoff and is forgeable on a LAN).
fn authorize_stream(
    state: &AppState,
    peer_cert_hash: &str,
    _peer_ip: &str,
    stream_type: u8,
) -> Result<(), &'static str> {
    let is_paired = state.settings.lock().is_paired;
    match stream_type {
        STREAM_PAIRING => {
            if is_paired {
                return Err("Already paired — unpair first");
            }
            Ok(())
        }
        _ => {
            if !is_paired {
                return Err("Not paired");
            }
            // Every non-pairing stream REQUIRES a client certificate matching
            // the one pinned during pairing. The IP fallback is removed: it
            // broke on Wi-Fi→cellular handoff and was trivially spoofable.
            let paired_cert = state.get_paired_client_cert_hash();
            if paired_cert.is_empty() {
                return Err("No paired client certificate recorded — re-pair");
            }
            if peer_cert_hash.is_empty() || peer_cert_hash != paired_cert {
                return Err("Peer certificate not authorized");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState::default())
    }

    /// Audit finding #8: the stream authorization matrix must be enforced —
    /// pairing streams only while unpaired, everything else only when paired
    /// AND the peer's TLS-observed cert hash matches the pinned one.
    #[test]
    fn authorize_stream_matrix() {
        let state = test_state();
        // Pre-pairing: pairing streams allowed, everything else rejected.
        assert!(authorize_stream(&state, "", "", STREAM_PAIRING).is_ok());
        assert!(authorize_stream(&state, "", "", STREAM_POLL).is_err());
        assert!(authorize_stream(&state, "", "", STREAM_CLIPBOARD).is_err());
        assert!(authorize_stream(&state, "", "", STREAM_UNPAIR).is_err());

        // Paired: non-pairing streams require the pinned cert hash.
        {
            let mut settings = state.settings.lock();
            settings.is_paired = true;
        }
        state.set_paired_client_cert_hash("deadbeef".to_string());
        assert!(authorize_stream(&state, "deadbeef", "", STREAM_POLL).is_ok());
        assert!(authorize_stream(&state, "deadbeef", "", STREAM_CLIPBOARD).is_ok());
        assert!(authorize_stream(&state, "wronghash", "", STREAM_POLL).is_err());
        assert!(authorize_stream(&state, "", "", STREAM_POLL).is_err());
        // Pairing streams are refused once paired.
        assert!(authorize_stream(&state, "deadbeef", "", STREAM_PAIRING).is_err());
    }
}

pub fn start_local_sync_server(state: Arc<AppState>) {
    core_crypto::p2p_group::try_start_p2p_group();

    std::thread::spawn(move || {
        // Use the dedicated IO_RUNTIME from core-crypto for the accept loop.
        // Separate from FFI_RUNTIME to prevent long-lived QUIC connections
        // from starving UniFFI bridge calls.
        core_crypto::block_on_io(async move {
            // Initial bind — stores endpoint in SERVER_ENDPOINT static
            let endpoint = match core_crypto::quic_app::QuicAppManager::bind_server(
                core_crypto::network::DEFAULT_KYBERPIPE_PORT,
            )
            .await
            {
                Ok(ep) => {
                    eprintln!(
                        "[QUIC Sync] Listening on port {}",
                        core_crypto::network::DEFAULT_KYBERPIPE_PORT
                    );
                    ep
                }
                Err(e) => {
                    eprintln!("[QUIC Sync] Failed to bind: {e}");
                    return;
                }
            };

            // Beacon broadcast loop — OPT-IN (audit finding #20): the 30s
            // cleartext UDP beacon previously disclosed device name + LAN IP +
            // truncated key hash to every LAN host unconditionally. Now it only
            // runs when the user explicitly enables discovery, and the payload
            // never carries the device name (identity disclosure removed); it
            // is multicast-scoped by the p2p_group layer.
            let beacon_state = state.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    let enabled = { beacon_state.settings.lock().beacon_discovery_enabled };
                    if !enabled {
                        continue;
                    }
                    let host_pk = {
                        beacon_state
                            .get_keypair()
                            .map(|p| p.mlkem_pk.clone())
                            .unwrap_or_default()
                    };
                    let local_ip = core_crypto::system_net::get_system_local_ip();
                    if !host_pk.is_empty() && !local_ip.is_empty() {
                        let hash = sha2::Sha256::digest(&host_pk);
                        let pk_hash = hex::encode(&hash[..16]);
                        // Identity-minimal payload: truncated pk hash + LAN IP
                        // only — no device name on an unauthenticated channel.
                        let payload = format!("{pk_hash}:{local_ip}");
                        let _ = core_crypto::p2p_group::send_beacon_payload(payload).await;
                    }
                }
            });

            // Run the (extractable, testable) dispatch loop against the bound endpoint.
            run_server_dispatch(endpoint, state, None).await;
        });
    });
}

/// Run the stream-dispatch accept loop against a concrete QUIC endpoint.
/// Extracted from `start_local_sync_server` so integration tests can drive the
/// REAL handler pipeline (pairing → SAS confirm → poll → clipboard) end-to-end
/// against an in-process server without the Tauri runtime.
/// `stop` (optional) lets callers terminate the dispatch loop cleanly — used
/// by the integration test so the test process exits; production passes None.
pub async fn run_server_dispatch(
    mut endpoint: quinn::Endpoint,
    state: Arc<AppState>,
    stop: Option<tokio::sync::oneshot::Receiver<()>>,
) {
    let mut stop_rx = stop;
    let pairing_state = state.clone();
    let on_pairing = move |body: Vec<u8>,
                           peer_ip: IpAddr,
                           peer_cert_hash: String|
          -> BoxFuture<Vec<u8>> {
        let state = pairing_state.clone();
        Box::pin(async move { handle_pairing(body, Some(peer_ip), peer_cert_hash, state).await })
    };

    let s = state.clone();
    let on_clipboard = move |body: Vec<u8>| -> BoxFuture<Vec<u8>> {
        let s = s.clone();
        Box::pin(handle_clipboard(body, s))
    };

    let s = state.clone();
    let on_media = move |body: Vec<u8>| -> BoxFuture<Vec<u8>> {
        let s = s.clone();
        Box::pin(handle_media(body, s))
    };

    let s = state.clone();
    let on_sms = move |body: Vec<u8>| -> BoxFuture<Vec<u8>> {
        let s = s.clone();
        Box::pin(handle_sms(body, s))
    };

    let s = state.clone();
    let on_poll = move |body: Vec<u8>| -> BoxFuture<Vec<u8>> {
        let s = s.clone();
        Box::pin(handle_poll(body, s))
    };

    let s = state.clone();
    let on_unpair = move |peer_cert_hash: String, peer_ip: IpAddr| -> BoxFuture<()> {
        let s = s.clone();
        Box::pin(async move { handle_unpair(s, peer_cert_hash, peer_ip.to_string()).await })
    };

    let s = state.clone();
    let on_rekey_ack = move |body: Vec<u8>| -> BoxFuture<Vec<u8>> {
        let s = s.clone();
        Box::pin(handle_rekey_ack(body, s))
    };

    let pairing_cb = std::sync::Arc::new(on_pairing);
    let clipboard_cb = std::sync::Arc::new(on_clipboard);
    let media_cb = std::sync::Arc::new(on_media);
    let poll_cb = std::sync::Arc::new(on_poll);
    let unpair_cb = std::sync::Arc::new(on_unpair);
    let rekey_ack_cb = std::sync::Arc::new(on_rekey_ack);
    let sms_cb = std::sync::Arc::new(on_sms);

    // ── Resource budgets (audit finding #8) ──────────────────────────────────
    // A pre-pairing desktop is a public pairing server on 0.0.0.0:9876. Without
    // caps, an attacker on the LAN could open N connections × M streams and
    // force the server to buffer up to 1 MiB per stream before authorization.
    let connection_semaphore =
        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let global_stream_semaphore =
        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_GLOBAL_STREAMS));

    loop {
        let incoming = match stop_rx.as_mut() {
            Some(rx) => {
                tokio::select! {
                    inc = endpoint.accept() => inc,
                    _ = rx => break,
                }
            }
            None => endpoint.accept().await,
        };
        match incoming {
            Some(connecting) => {
                let state = state.clone();
                let pairing_cb = pairing_cb.clone();
                let clipboard_cb = clipboard_cb.clone();
                let media_cb = media_cb.clone();
                let poll_cb = poll_cb.clone();
                let unpair_cb = unpair_cb.clone();
                let rekey_ack_cb = rekey_ack_cb.clone();
                let sms_cb = sms_cb.clone();
                // Refuse connections beyond the budget immediately: the
                // connecting peer sees a dropped handshake instead of being
                // queued, so the accept loop and the pairing path cannot be
                // starved by a flood of connections.
                let conn_permit = match connection_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        info!("[QUIC] Refusing connection: budget exhausted (max {MAX_CONCURRENT_CONNECTIONS})");
                        continue;
                    }
                };
                let global_stream = global_stream_semaphore.clone();
                tokio::spawn(async move {
                    let _conn_guard = conn_permit;
                    match connecting.await {
                        Ok(connection) => {
                            info!("QUIC connection: {}", connection.remote_address());
                            let peer_cert_hash =
                                core_crypto::quic_app::connection_peer_cert_hash(&connection)
                                    .unwrap_or_default();
                            let peer_ip = connection.remote_address().ip();
                            // Per-connection stream budget.
                            let per_conn_streams = std::sync::Arc::new(
                                tokio::sync::Semaphore::new(MAX_STREAMS_PER_CONNECTION),
                            );
                            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                                let state = state.clone();
                                let pairing_cb = pairing_cb.clone();
                                let clipboard_cb = clipboard_cb.clone();
                                let media_cb = media_cb.clone();
                                let poll_cb = poll_cb.clone();
                                let unpair_cb = unpair_cb.clone();
                                let rekey_ack_cb = rekey_ack_cb.clone();
                                let sms_cb = sms_cb.clone();
                                let peer_cert_hash = peer_cert_hash.clone();
                                let per_conn = per_conn_streams.clone();
                                let global_stream = global_stream.clone();
                                tokio::spawn(async move {
                                    // Both the per-connection and the global stream
                                    // budget must be available; otherwise the stream
                                    // is dropped without reading its body.
                                    let _local_guard = match per_conn.try_acquire_owned() {
                                        Ok(g) => g,
                                        Err(_) => {
                                            info!("[QUIC] Dropping stream: per-connection budget exhausted");
                                            return;
                                        }
                                    };
                                    let _global_guard = match global_stream.try_acquire_owned() {
                                        Ok(g) => g,
                                        Err(_) => {
                                            info!("[QUIC] Dropping stream: global stream budget exhausted");
                                            return;
                                        }
                                    };
                                    // Authorize from the HEADER before reading the
                                    // body: an unauthenticated peer cannot force the
                                    // server to buffer a 1 MiB body.
                                    let (stream_type, _body_len) = match core_crypto::quic_app::QuicAppManager::recv_frame_header(&mut recv).await {
                                        Ok(h) => h,
                                        Err(e) => {
                                            info!("[QUIC] Stream header read failed: {e}");
                                            return;
                                        }
                                    };
                                    if let Err(reason) = authorize_stream(
                                        &state,
                                        &peer_cert_hash,
                                        &peer_ip.to_string(),
                                        stream_type,
                                    ) {
                                        info!(
                                            "[QUIC Auth] Rejected stream 0x{:02x} from {}: {}",
                                            stream_type, peer_ip, reason
                                        );
                                        let _ = core_crypto::quic_app::QuicAppManager::send_frame(
                                            &mut send,
                                            &QuicFrame {
                                                stream_type,
                                                body: format!(
                                                    r#"{{"status":"error","reason":"{reason}"}}"#
                                                )
                                                .into_bytes(),
                                            },
                                        )
                                        .await;
                                        return;
                                    }
                                    // Authorized: now read the (bounded) body and
                                    // dispatch to the handler.
                                    let body = match core_crypto::quic_app::QuicAppManager::recv_frame_body(&mut recv, _body_len).await {
                                        Ok(b) => b,
                                        Err(e) => {
                                            info!("[QUIC] Stream body read failed: {e}");
                                            return;
                                        }
                                    };
                                    let response = match stream_type {
                                        STREAM_PAIRING => QuicFrame {
                                            stream_type: STREAM_PAIRING,
                                            body: pairing_cb(body, peer_ip, peer_cert_hash.clone())
                                                .await,
                                        },
                                        STREAM_CLIPBOARD => QuicFrame {
                                            stream_type: STREAM_CLIPBOARD,
                                            body: clipboard_cb(body).await,
                                        },
                                        STREAM_MEDIA => QuicFrame {
                                            stream_type: STREAM_MEDIA,
                                            body: media_cb(body).await,
                                        },
                                        STREAM_POLL => QuicFrame {
                                            stream_type: STREAM_POLL,
                                            body: poll_cb(body).await,
                                        },
                                        STREAM_UNPAIR => {
                                            unpair_cb(peer_cert_hash.clone(), peer_ip).await;
                                            QuicFrame {
                                                stream_type: STREAM_UNPAIR,
                                                body: vec![],
                                            }
                                        }
                                        STREAM_REKEY_ACK => QuicFrame {
                                            stream_type: STREAM_REKEY_ACK,
                                            body: rekey_ack_cb(body).await,
                                        },
                                        STREAM_SMS => QuicFrame {
                                            stream_type: STREAM_SMS,
                                            body: sms_cb(body).await,
                                        },
                                        _ => QuicFrame {
                                            stream_type,
                                            body: vec![],
                                        },
                                    };
                                    // Audit finding #6: the poll response carries a
                                    // PEEKED RekeyAck (generated non-destructively).
                                    // Only after the response is successfully written
                                    // do we clear the pending carrier — a lost
                                    // response retains the ack so the next poll
                                    // re-derives it instead of dropping it silently.
                                    let poll_stream = stream_type == STREAM_POLL;
                                    let sent = core_crypto::quic_app::QuicAppManager::send_frame(
                                        &mut send, &response,
                                    )
                                    .await;
                                    if poll_stream && sent.is_ok() {
                                        let peer = state.get_pairing_initiator_pk();
                                        if !peer.is_empty() {
                                            let _ = core_crypto::ratchet_consume_rekey_ack(peer);
                                        }
                                    }
                                });
                            }
                        }
                        Err(e) => info!("QUIC connection failed: {e}"),
                    }
                });
            }
            None => {
                // The bound endpoint was dropped — this is how the mTLS rebind
                // after pairing signals the accept loop (audit finding #8b).
                // Re-acquire the current endpoint and continue dispatching on
                // the SAME port instead of tearing the server down.
                match core_crypto::quic_app::get_server_endpoint() {
                    Some(new_ep) => {
                        info!("[QUIC Sync] Accept loop re-acquired rebound endpoint");
                        endpoint = new_ep;
                    }
                    None => {
                        info!("Server endpoint dropped");
                        break;
                    }
                }
            }
        }
    }
}
