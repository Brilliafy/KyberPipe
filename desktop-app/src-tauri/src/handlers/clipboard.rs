use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::DESKTOP_SESSION_KEY_HANDLE;
use super::IS_SESSION_KEY_AUTHENTICATED;

/// Decrypt a payload from the JSON+hex wire format. THIS is the single wire
/// format both platforms use (audit finding #15): the previous `KP\x01` binary
/// frame parser was unreachable in production (Android only ever sent
/// JSON+hex), so it has been removed — one encoder/decoder, no drift surface.
fn decrypt_json_payload(body: &[u8], peer_id: &str, sk_handle: u64, sk_auth: bool) -> Option<String> {
    let body_str = String::from_utf8_lossy(body);
    let json = serde_json::from_str::<serde_json::Value>(&body_str).ok()?;

    // Try ratchet decryption first
    if !peer_id.is_empty() {
        if let Some(enc) = json.get("encrypted_ratchet") {
            let nonce_hex = enc.get("nonce_hex").and_then(|v| v.as_str())?;
            let ct_hex = enc.get("ciphertext_hex").and_then(|v| v.as_str())?;
            if let (Ok(nonce), Ok(ct)) = (hex::decode(nonce_hex), hex::decode(ct_hex)) {
                // REKEY-AWARE decrypt (audit finding #1): forward the rekey fields
                // so DH/KEM proposals are adopted and ACKed — the phone's plain
                // decrypt path previously ignored rekey payloads and permanently
                // desynced the session when the desktop committed via TTL.
                let rekey_x = enc
                    .get("rekey_x25519_pk_hex")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok());
                let rekey_m = enc
                    .get("rekey_mlkem_pk_hex")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok());
                let rekey_ct = enc
                    .get("rekey_ciphertext_hex")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok());
                match core_crypto::ratchet_decrypt_with_rekey_message(
                    peer_id.to_string(),
                    nonce,
                    ct,
                    rekey_ct,
                    rekey_x,
                    rekey_m,
                ) {
                    Ok(pt) => return String::from_utf8(pt).ok(),
                    Err(e) => tracing::warn!(
                        "[Clipboard] Ratchet rekey decrypt failed for {peer_id}: {e}"
                    ),
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
        let _ = crate::portal::sync_clipboard_text(&decrypted);
        s.add_log(format!(
            "[Clipboard] Received via QUIC: \"{}\"",
            decrypted.chars().take(30).collect::<String>()
        ));
    }
    r#"{"status":"synced"}"#.to_string().into_bytes()
}
