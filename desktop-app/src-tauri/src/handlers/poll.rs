use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use super::DESKTOP_SESSION_KEY_HANDLE;
use super::IS_SESSION_KEY_AUTHENTICATED;

/// Cap on the receive-chain forward gap before this side issues a resync.
/// Mirrors the ratchet's default max_skip (100).
const RESYNC_GAP_THRESHOLD: u64 = 100;

/// Clipboard read cache TTL — poll requests arrive every 2.5s from the phone;
/// re-reading the OS clipboard (arboard / wl-paste / xclip, each up to 3s) on
/// EVERY poll would stall the accept-loop runtime. Cache for 1s instead
/// (audit finding #9).
const CLIPBOARD_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// Cached clipboard bytes + wall-clock timestamp.
static CLIPBOARD_CACHE: LazyLock<Mutex<Option<(Instant, Vec<u8>)>>> =
    LazyLock::new(|| Mutex::new(None));

/// Read the real clipboard through a 1s cache so the (potentially
/// multi-second) OS clipboard read never runs on the accept-loop workers more
/// than once per second, regardless of poll frequency.
fn cached_clipboard_read() -> Vec<u8> {
    let now = Instant::now();
    if let Ok(cache) = CLIPBOARD_CACHE.lock() {
        if let Some((at, bytes)) = cache.as_ref() {
            if now.duration_since(*at) < CLIPBOARD_CACHE_TTL {
                return bytes.clone();
            }
        }
    }
    // Cache miss — perform the blocking read (caller should be on a
    // spawn_blocking thread; see handle_poll).
    let content = crate::commands::read_real_clipboard_internal()
        .unwrap_or_default()
        .into_bytes();
    if let Ok(mut cache) = CLIPBOARD_CACHE.lock() {
        *cache = Some((Instant::now(), content.clone()));
    }
    content
}

/// Encapsulates which encryption method to use for a payload.
/// Encapsulation decision is made once at the start, then dispatched cleanly.
enum EncryptionMethod {
    Ratchet { peer_id: String },
    SessionKey { handle: u64 },
    None,
}

/// Select the best encryption method for a peer. Ratchet preferred over session key.
fn select_encryption_method(
    peer_id: &str,
    session_key_auth: bool,
    sk_handle: u64,
) -> EncryptionMethod {
    if !peer_id.is_empty() {
        EncryptionMethod::Ratchet {
            peer_id: peer_id.to_string(),
        }
    } else if session_key_auth && sk_handle != 0 {
        EncryptionMethod::SessionKey {
            handle: sk_handle,
        }
    } else {
        EncryptionMethod::None
    }
}

/// Encrypt clipboard data using the selected method. Returns a JSON Value
/// or Null if encryption fails or is unavailable.
fn encrypt_clipboard_data(method: &EncryptionMethod, latest_clip: &[u8]) -> serde_json::Value {
    match method {
        EncryptionMethod::Ratchet { peer_id } => {
            match core_crypto::ratchet_encrypt_message(
                peer_id.clone(),
                latest_clip.to_vec(),
            ) {
                Ok(msg) => {
                    let ratchet_val = serde_json::json!({
                        "nonce_hex": hex::encode(&msg.nonce),
                        "ciphertext_hex": hex::encode(&msg.ciphertext),
                        "rekey_x25519_pk_hex": msg.rekey_x25519_pk.as_ref().map(hex::encode),
                        "rekey_mlkem_pk_hex": msg.rekey_mlkem_pk.as_ref().map(hex::encode),
                        "rekey_ciphertext_hex": msg.rekey_ciphertext.as_ref().map(hex::encode),
                    });
                    serde_json::json!({"encrypted_ratchet": ratchet_val})
                }
                Err(e) => {
                    tracing::warn!("[Poll] Ratchet encrypt failed for {peer_id}: {e}");
                    serde_json::Value::Null
                }
            }
        }
        EncryptionMethod::SessionKey { handle } => {
            match core_crypto::session_key_encrypt(*handle, latest_clip.to_vec()) {
                Ok(payload) => serde_json::json!({
                    "nonce_hex": hex::encode(&payload.nonce),
                    "ciphertext_hex": hex::encode(&payload.ciphertext),
                }),
                Err(e) => {
                    tracing::warn!("[Poll] Session key encrypt failed: {e}");
                    serde_json::Value::Null
                }
            }
        }
        EncryptionMethod::None => serde_json::Value::Null,
    }
}

/// Sync QUIC connection state with AppState.
/// Called on every poll to ensure the UI reflects the actual connection status.
fn sync_connection_state(s: &AppState) {
    core_crypto::quic_bridge::touch_connection();
    if !core_crypto::quic_bridge::is_quic_connected() {
        s.set_connection_status("DISCONNECTED".to_string());
        s.set_connection_color("red".to_string());
    }
}

/// Split of `handle_poll`: read the pairing/session state that drives the
/// response. Pure in-memory reads — no filesystem, keyring, or clipboard I/O
/// (audit finding #18).
fn read_local_state(s: &AppState) -> (String, bool, u64, bool, serde_json::Value, serde_json::Value) {
    let peer_id = s.get_pairing_initiator_pk();
    let session_key_auth = IS_SESSION_KEY_AUTHENTICATED.load(Ordering::Acquire);
    let sk_handle = DESKTOP_SESSION_KEY_HANDLE.load(Ordering::Acquire);
    let is_paired = s.settings.lock().is_paired;
    let connection = s.get_connection();
    let pending_act = s.get_pending_media_action();
    let base = serde_json::json!({
        "is_paired": is_paired,
        "connection_status": connection.status,
        "connection_method": connection.method,
        "connection_color": connection.color,
        "pending_media_action": pending_act,
    });
    (peer_id, session_key_auth, sk_handle, is_paired, base, connection.status.clone().into())
}

/// Parse the peer's poll REQUEST body. The Android poll loop now sends its own
/// ratchet send counter (`sync_send_count`) so the desktop can detect and
/// repair receive-chain gaps (audit finding #4 — Synchronize recovery).
fn peer_sync_send_count(body: &[u8]) -> Option<u64> {
    if body.is_empty() {
        return None;
    }
    let v = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    v.get("sync_send_count").and_then(|x| x.as_u64())
}

/// Split of `handle_poll`: encrypt the clipboard and attach the rekey-ack and
/// synchronize payloads. Runs the blocking clipboard read + ratchet persistence
/// on a spawn_blocking thread so the accept-loop workers are never wedged
/// (audit finding #9).
async fn build_poll_response(
    peer_id: &str,
    session_key_auth: bool,
    sk_handle: u64,
    base: serde_json::Value,
) -> serde_json::Value {
    let peer = peer_id.to_string();
    let sk_auth = session_key_auth;
    let skh = sk_handle;

    // Blocking I/O (OS clipboard read + keyring + full-file persistence) is
    // delegated to the tokio blocking pool, sized independently of the
    // 2-worker IO accept-loop runtime.
    let latest_clip_encrypted = tokio::task::spawn_blocking(move || {
        let latest_clip = cached_clipboard_read();
        let latest_clip_encrypted = if latest_clip.is_empty() {
            serde_json::Value::Null
        } else {
            let enc_method = select_encryption_method(&peer, sk_auth, skh);
            encrypt_clipboard_data(&enc_method, &latest_clip)
        };
        // Persist ratchet state after any mutation this poll may have caused.
        // Keyring + full-file serde_json are blocking — keep them here on the
        // blocking pool, not on the accept-loop task. Wrapped with the
        // independent snapshot key (audit finding #15b).
        if !peer.is_empty() {
            if let Some(sk) = crate::ratchet_store::snapshot_key_from_keyring() {
                crate::ratchet_store::persist_all_ratchet_sessions(&sk);
            }
        }
        latest_clip_encrypted
    })
    .await
    .unwrap_or(serde_json::Value::Null);

    let mut resp = base;
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("latest_clip_encrypted".to_string(), latest_clip_encrypted);
    }

    // If this side received a rekey from the peer, build the encrypted RekeyAck
    // (carrying the rekey carrier's seq in the SENDER's space) and attach it to
    // the poll response so the peer can commit its outgoing proposal.
    if !peer_id.is_empty() {
        if let Ok(Some(ack)) = core_crypto::ratchet_generate_rekey_ack(peer_id.to_string()) {
            if let Some(obj) = resp.as_object_mut() {
                obj.insert("rekey_ack_encrypted".to_string(), serde_json::json!({
                    "nonce_hex": hex::encode(ack.nonce),
                    "ciphertext_hex": hex::encode(ack.ciphertext),
                }));
            }
        }
        // Producer for the Synchronize recovery path (audit finding #4): the
        // peer uses this plaintext counter to detect a receive-chain gap and
        // resync locally.
        if let Ok(send_count) = core_crypto::ratchet_send_count(peer_id.to_string()) {
            if let Some(obj) = resp.as_object_mut() {
                obj.insert("ratchet_send_count".to_string(), serde_json::json!(send_count));
            }
        }
    }

    resp
}

pub(crate) async fn handle_poll(body: Vec<u8>, s: Arc<AppState>) -> Vec<u8> {
    sync_connection_state(&s);
    let (peer_id, session_key_auth, sk_handle, _is_paired, base, _conn) =
        read_local_state(&s);

    // Consumer for the Synchronize recovery path: if the peer's send counter
    // is ahead of our receive counter by more than max_skip, resync our
    // receiving chain so we can follow the peer across a network handoff.
    if !peer_id.is_empty() {
        if let Some(peer_send) = peer_sync_send_count(&body) {
            if let Ok(recv) = core_crypto::ratchet_recv_count(peer_id.clone()) {
                if peer_send > recv && peer_send - recv > RESYNC_GAP_THRESHOLD {
                    tracing::info!(
                        "[Sync] Peer send count {peer_send} ahead of recv {recv} — resynchronizing receiving chain"
                    );
                    let _ = core_crypto::ratchet_synchronize_session(peer_id.clone(), peer_send);
                }
            }
        }
    }

    let resp = build_poll_response(&peer_id, session_key_auth, sk_handle, base).await;
    serde_json::to_string(&resp)
        .unwrap_or_default()
        .into_bytes()
}
