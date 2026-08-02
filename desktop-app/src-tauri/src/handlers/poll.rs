use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use super::DESKTOP_SESSION_KEY_HANDLE;
use super::IS_SESSION_KEY_AUTHENTICATED;

/// Clipboard read cache TTL — poll requests arrive every 2.5s from the phone;
/// re-reading the OS clipboard (arboard / wl-paste / xclip, each up to 3s) on
/// EVERY poll would stall the accept-loop runtime. Cache for 1s instead
/// (audit finding #9).
const CLIPBOARD_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// Cached clipboard bytes + wall-clock timestamp.
static CLIPBOARD_CACHE: LazyLock<Mutex<Option<(Instant, Vec<u8>)>>> =
    LazyLock::new(|| Mutex::new(None));

/// TEST-ONLY hermetic override: when set, the poll handler treats the OS
/// clipboard as empty. The wire-level rekey e2e sets this so the desktop never
/// encrypts real clipboard content during the test — otherwise the desktop's
/// own send chain can cross seq 100 and, as the initiator, suppress the
/// client's rekey proposal (deterministic race outcome required by the test).
#[cfg(test)]
pub(crate) static FORCE_EMPTY_CLIPBOARD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Read the real clipboard through a 1s cache so the (potentially
/// multi-second) OS clipboard read never runs on the accept-loop workers more
/// than once per second, regardless of poll frequency.
fn cached_clipboard_read() -> Vec<u8> {
    #[cfg(test)]
    if FORCE_EMPTY_CLIPBOARD.load(std::sync::atomic::Ordering::Acquire) {
        return Vec::new();
    }
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
        EncryptionMethod::SessionKey { handle: sk_handle }
    } else {
        EncryptionMethod::None
    }
}

/// Encrypt clipboard data using the selected method. Returns a JSON Value
/// or Null if encryption fails or is unavailable.
fn encrypt_clipboard_data(method: &EncryptionMethod, latest_clip: &[u8]) -> serde_json::Value {
    match method {
        EncryptionMethod::Ratchet { peer_id } => {
            // Audit finding #12: the ratchet payload is serialized as a single
            // base64-wrapped BINARY TLV (the UniFFI Record's `to_binary` framing)
            // instead of five independent hex fields — one serialization
            // contract shared by both platforms, no per-field drift surface.
            match core_crypto::ratchet_encrypt_message_binary(peer_id.clone(), latest_clip.to_vec())
            {
                Ok(bin) => serde_json::json!({
                    "encrypted_ratchet": {
                        "tlv_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin)
                    }
                }),
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
fn read_local_state(
    s: &AppState,
) -> (
    String,
    bool,
    u64,
    bool,
    serde_json::Value,
    serde_json::Value,
) {
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
    (
        peer_id,
        session_key_auth,
        sk_handle,
        is_paired,
        base,
        connection.status.clone().into(),
    )
}

/// Parse the peer's poll REQUEST body for an ENCRYPTED `Synchronize` packet.
/// The Android poll loop sends its current send counter as a ratchet-encrypted
/// `KyberMessage::Synchronize` (`{ "sync": { nonce_hex, ciphertext_hex } }`);
/// the desktop processes it via `ratchet_process_synchronize`, which decrypts
/// (authenticating the sender), verifies the packet type, and only then resyncs
/// the receiving chain (audit finding #4 — the plaintext counter is NEVER
/// acted on, and resync is rate-limited / budget-bounded / generation-aware).
fn peer_sync_packet(body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    let v = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let sync = v.get("sync")?;
    let tlv_b64 = sync.get("tlv_b64")?.as_str()?;
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64).ok()
}

/// Parse the peer's poll REQUEST body for an ENCRYPTED `RekeyAck` TLV — the
/// phone's outbound RekeyAck channel (audit finding #1). The phone attaches
/// its ack of OUR outgoing proposal to the poll request; we decrypt it
/// rekey-aware and commit the proposal.
fn peer_rekey_ack_packet(body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    let v = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let ack = v.get("rekey_ack_encrypted")?;
    let tlv_b64 = ack.get("tlv_b64")?.as_str()?;
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64).ok()
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
    //
    // AUDIT FINDING #6: the ack is generated NON-CONSUMING (peek). The pending
    // carrier is cleared only after the dispatch loop successfully writes the
    // response — if the response is lost on the wire, the ack is re-derived on
    // the next poll instead of being silently dropped.
    if !peer_id.is_empty() {
        if let Ok(Some(bin)) =
            core_crypto::ratchet_generate_rekey_ack_binary_peek(peer_id.to_string())
        {
            if let Some(obj) = resp.as_object_mut() {
                obj.insert("rekey_ack_encrypted".to_string(), serde_json::json!({
                    "tlv_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin)
                }));
            }
        }
        // Producer for the Synchronize recovery path (audit finding #4): our
        // send counter is sent as a RATCHET-ENCRYPTED Synchronize packet so the
        // peer can authenticate the resync target. The packet is encoded as a
        // full BINARY TLV (audit finding #12): a ratchet message may carry a
        // rekey payload at seq 100/200, and dropping those fields would make the
        // ciphertext undecryptable (AEAD binds the rekey params).
        if let Ok(sync_msg) = core_crypto::ratchet_synchronize_packet(peer_id.to_string()) {
            if let Ok(bin) = sync_msg.to_binary() {
                if let Some(obj) = resp.as_object_mut() {
                    obj.insert("sync".to_string(), serde_json::json!({
                        "tlv_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin),
                    }));
                }
            }
        }
        // AUDIT FINDING #4/#19: the plaintext `ratchet_send_count` field is
        // REMOVED. The only resync trigger is the authenticated Synchronize
        // packet above; a plaintext counter would be an unauthenticated
        // forward-advance oracle (the legacy Android loop acted on it).
    }

    resp
}

pub(crate) async fn handle_poll(body: Vec<u8>, s: Arc<AppState>) -> Vec<u8> {
    sync_connection_state(&s);
    let (peer_id, session_key_auth, sk_handle, _is_paired, base, _conn) = read_local_state(&s);

    // Consumer for the Synchronize recovery path (audit finding #4): the peer
    // sends its send counter as a RATCHET-ENCRYPTED Synchronize packet. Only an
    // authenticated, verified Synchronize can trigger a resync; the plaintext
    // counter is never acted on. The core additionally refuses resync across an
    // unconsumed pending rekey, enforces a persisted cumulative budget, and
    // rate-limits per peer.
    if !peer_id.is_empty() {
        if let Some(data) = peer_sync_packet(&body) {
            match core_crypto::ratchet_process_synchronize(peer_id.clone(), data) {
                Ok(skipped) => {
                    if skipped > 0 {
                        tracing::info!(
                            "[Sync] Authenticated Synchronize from {peer_id} advanced receive chain by {skipped}"
                        );
                    }
                }
                Err(e) => {
                    tracing::info!("[Sync] Synchronize from {peer_id} not applied: {e}");
                }
            }
        }
        // Consumer for the phone's outbound RekeyAck (audit finding #1): the
        // phone attaches its encrypted ack of OUR outgoing proposal to the poll
        // request. Processing it commits our outgoing rekey; without this
        // channel the desktop's rekey_pending_confirm_queue would stay occupied
        // forever (permanent deadlock).
        if let Some(data) = peer_rekey_ack_packet(&body) {
            match core_crypto::ratchet_process_rekey_ack_binary(peer_id.clone(), data) {
                Ok(true) => tracing::info!(
                    "[RekeyAck] Phone acked our outgoing rekey — committed (peer {peer_id})"
                ),
                Ok(false) => {}
                Err(e) => {
                    tracing::info!("[RekeyAck] Phone RekeyAck not applied: {e}");
                }
            }
        }
    }

    let resp = build_poll_response(&peer_id, session_key_auth, sk_handle, base).await;
    serde_json::to_string(&resp)
        .unwrap_or_default()
        .into_bytes()
}
