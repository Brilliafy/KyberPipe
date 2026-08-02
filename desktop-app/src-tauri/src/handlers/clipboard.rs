use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::DESKTOP_SESSION_KEY_HANDLE;
use super::IS_SESSION_KEY_AUTHENTICATED;

/// Decrypt a payload from the JSON+hex wire format. THIS is the single wire
/// format both platforms use (audit finding #15): the previous `KP\x01` binary
/// frame parser was unreachable in production (Android only ever sent
/// JSON+hex), so it has been removed — one encoder/decoder, no drift surface.
fn decrypt_json_payload(
    body: &[u8],
    peer_id: &str,
    sk_handle: u64,
    sk_auth: bool,
) -> Option<String> {
    let body_str = String::from_utf8_lossy(body);
    let json = serde_json::from_str::<serde_json::Value>(&body_str).ok()?;

    // Try ratchet decryption first. Audit finding #12: the ratchet payload is a
    // single base64-wrapped BINARY TLV (`tlv_b64`) — one serialization contract
    // instead of five independent hex fields.
    if !peer_id.is_empty() {
        if let Some(enc) = json.get("encrypted_ratchet") {
            let tlv_b64 = enc.get("tlv_b64").and_then(|v| v.as_str())?;
            let bin =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64).ok()?;
            match core_crypto::ratchet_decrypt_message_binary(peer_id.to_string(), bin) {
                Ok(pt) => return String::from_utf8(pt).ok(),
                Err(e) => {
                    tracing::warn!("[Clipboard] Ratchet binary decrypt failed for {peer_id}: {e}")
                }
            }
        }
    }

    // Fallback to session key decryption
    if sk_auth && sk_handle != 0 {
        if let Some(enc) = json.get("encrypted") {
            let nonce_hex = enc.get("nonce_hex").and_then(|v| v.as_str())?;
            let ct_hex = enc.get("ciphertext_hex").and_then(|v| v.as_str())?;
            if let (Ok(nonce), Ok(ct)) = (hex::decode(nonce_hex), hex::decode(ct_hex)) {
                if let Ok(pt) = core_crypto::session_key_decrypt(sk_handle, nonce, ct) {
                    return String::from_utf8(pt).ok();
                }
            }
        }
    }
    None
}

pub(crate) async fn handle_clipboard(body: Vec<u8>, s: Arc<AppState>) -> Vec<u8> {
    let peer_id = s.get_pairing_initiator_pk();
    let sk_handle = DESKTOP_SESSION_KEY_HANDLE.load(Ordering::Acquire);
    let sk_auth = IS_SESSION_KEY_AUTHENTICATED.load(Ordering::Acquire);

    // Single wire format: JSON+hex (audit finding #15).
    let text = decrypt_json_payload(&body, &peer_id, sk_handle, sk_auth);

    // A non-empty body that cannot be decrypted is a protocol failure, not a
    // no-op — surface it so clients (and integration tests) can distinguish a
    // successful sync from a silently-dropped payload.
    let Some(decrypted) = text else {
        if body.is_empty() {
            return r#"{"status":"synced"}"#.to_string().into_bytes();
        }
        return r#"{"status":"error","reason":"Decryption failed"}"#
            .to_string()
            .into_bytes();
    };

    if !decrypted.is_empty() && s.check_and_record_clipboard(&decrypted) {
        // Audit finding #9: the OS clipboard write (arboard / wl-copy / xclip
        // subprocesses with multi-second waits) must NEVER execute on the
        // accept-loop worker — it would stall every concurrent QUIC stream.
        // Delegate to the tokio blocking pool, which is sized independently of
        // the 2-worker IO accept-loop runtime.
        let text = decrypted.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = crate::portal::sync_clipboard_text(&text);
        })
        .await;
        s.add_log(format!(
            "[Clipboard] Received via QUIC: \"{}\"",
            decrypted.chars().take(30).collect::<String>()
        ));
    }
    r#"{"status":"synced"}"#.to_string().into_bytes()
}
