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

use crate::handlers::{handle_clipboard, handle_media, handle_pairing, handle_poll, handle_sms, handle_unpair, handle_rekey_ack};
use crate::state::AppState;
use core_crypto::quic_app::{BoxFuture, QuicFrame, STREAM_PAIRING, STREAM_CLIPBOARD, STREAM_MEDIA, STREAM_POLL, STREAM_UNPAIR, STREAM_REKEY_ACK, STREAM_SMS};
use sha2::Digest;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

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

            // Beacon broadcast loop — rate limited to 30s to reduce the
            // continuous presence/IP disclosure on the LAN (was 3s).
            let beacon_state = state.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    let host_pk = {
                        beacon_state
                            .get_keypair()
                            .map(|p| p.mlkem_pk.clone())
                            .unwrap_or_default()
                    };
                    let device_name = {
                        let s = beacon_state.settings.lock();
                        s.device_name
                            .clone()
                            .unwrap_or_else(|| "Desktop".to_string())
                    };
                    let local_ip = core_crypto::system_net::get_system_local_ip();
                    if !host_pk.is_empty() && !local_ip.is_empty() {
                        let hash = sha2::Sha256::digest(&host_pk);
                        let pk_hash = hex::encode(&hash[..16]);
                        let payload = format!("{}:{}:{}", pk_hash, local_ip, device_name);
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
    let on_pairing = move |body: Vec<u8>, peer_ip: IpAddr, peer_cert_hash: String| -> BoxFuture<Vec<u8>> {
        let state = pairing_state.clone();
        Box::pin(async move {
            handle_pairing(body, Some(peer_ip), peer_cert_hash, state).await
        })
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
        Box::pin(async move {
            handle_unpair(s, peer_cert_hash, peer_ip.to_string()).await
        })
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
                tokio::spawn(async move {
                    match connecting.await {
                        Ok(connection) => {
                            info!("QUIC connection: {}", connection.remote_address());
                            let peer_cert_hash =
                                core_crypto::quic_app::connection_peer_cert_hash(&connection)
                                    .unwrap_or_default();
                            let peer_ip = connection.remote_address().ip();
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
                                tokio::spawn(async move {
                                    if let Ok(frame) = core_crypto::quic_app::QuicAppManager::recv_frame(&mut recv).await {
                                        if let Err(reason) = authorize_stream(
                                            &state,
                                            &peer_cert_hash,
                                            &peer_ip.to_string(),
                                            frame.stream_type,
                                        ) {
                                            info!(
                                                "[QUIC Auth] Rejected stream 0x{:02x} from {}: {}",
                                                frame.stream_type, peer_ip, reason
                                            );
                                            let _ = core_crypto::quic_app::QuicAppManager::send_frame(
                                                &mut send,
                                                &QuicFrame {
                                                    stream_type: frame.stream_type,
                                                    body: format!(r#"{{"status":"error","reason":"{reason}"}}"#).into_bytes(),
                                                },
                                            )
                                            .await;
                                            return;
                                        }
                                        let response = match frame.stream_type {
                                            STREAM_PAIRING => QuicFrame { stream_type: STREAM_PAIRING, body: pairing_cb(frame.body, peer_ip, peer_cert_hash.clone()).await },
                                            STREAM_CLIPBOARD => QuicFrame { stream_type: STREAM_CLIPBOARD, body: clipboard_cb(frame.body).await },
                                            STREAM_MEDIA => QuicFrame { stream_type: STREAM_MEDIA, body: media_cb(frame.body).await },
                                            STREAM_POLL => QuicFrame { stream_type: STREAM_POLL, body: poll_cb(frame.body).await },
                                            STREAM_UNPAIR => { unpair_cb(peer_cert_hash.clone(), peer_ip).await; QuicFrame { stream_type: STREAM_UNPAIR, body: vec![] } },
                                            STREAM_REKEY_ACK => QuicFrame { stream_type: STREAM_REKEY_ACK, body: rekey_ack_cb(frame.body).await },
                                            STREAM_SMS => QuicFrame { stream_type: STREAM_SMS, body: sms_cb(frame.body).await },
                                            _ => QuicFrame { stream_type: frame.stream_type, body: vec![] },
                                        };
                                        let _ = core_crypto::quic_app::QuicAppManager::send_frame(&mut send, &response).await;
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
