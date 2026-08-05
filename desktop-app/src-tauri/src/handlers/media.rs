use crate::state::AppState;
use std::sync::Arc;

use super::decrypt_json_payload;

/// Handle a media-state packet forwarded from the Android client over QUIC.
///
/// AUDIT F8 (CRITICAL): the body is the SHARED ratchet-TLV wire format
/// `{"encrypted_ratchet": {"tlv_b64": ...}}` — exactly what the Android
/// `NotificationHook` produces via `ratchetEncryptMessageBinary`. The legacy
/// session-key hex format (`encrypted.nonce_hex` / `encrypted.ciphertext_hex`)
/// is DELETED: no sender produces it, and the drift silently dropped every
/// forwarded media update. Decryption goes through the same
/// [`decrypt_json_payload`] helper as clipboard/SMS.
pub(crate) async fn handle_media(body: Vec<u8>, peer_id: String, s: Arc<AppState>) -> Vec<u8> {
    let decrypted = decrypt_json_payload(&body, &peer_id);
    if let Some(json) = decrypted.and_then(|p| serde_json::from_str::<serde_json::Value>(&p).ok()) {
        let title = json
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let artist = json
            .get("artist")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let album_art = json
            .get("album_art")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let is_playing = json
            .get("is_playing")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut actions = vec![];
        if let Some(act_arr) = json.get("actions").and_then(|v| v.as_array()) {
            for act_val in act_arr {
                let act_title = act_val
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let act_index = act_val
                    .get("index")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_default() as u32;
                actions.push(crate::state::MediaAction {
                    title: act_title,
                    index: act_index,
                });
            }
        }
        s.set_media_state(crate::state::MediaState {
            title,
            artist,
            album_art,
            is_playing,
            actions,
        });
    } else if !body.is_empty() {
        tracing::warn!(
            "[Media] Non-empty body could not be decrypted as a ratchet-TLV media packet"
        );
        return r#"{"status":"error","reason":"Decryption failed"}"#
            .to_string()
            .into_bytes();
    }
    r#"{"status":"synced"}"#.to_string().into_bytes()
}
