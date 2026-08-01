use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::DESKTOP_SESSION_KEY_HANDLE;

pub(crate) async fn handle_media(body: Vec<u8>, s: Arc<AppState>) -> Vec<u8> {
    let body_str = String::from_utf8_lossy(&body);
    let decrypted = serde_json::from_str::<serde_json::Value>(&body_str)
        .ok()
        .and_then(|json| {
            let encrypted = json.get("encrypted").and_then(|e| {
                let nonce = e.get("nonce_hex").and_then(|v| v.as_str())?;
                let ct = e.get("ciphertext_hex").and_then(|v| v.as_str())?;
                Some((nonce.to_string(), ct.to_string()))
            })?;
            if !super::IS_SESSION_KEY_AUTHENTICATED.load(Ordering::Acquire) {
                return None;
            }
            let handle = DESKTOP_SESSION_KEY_HANDLE.load(Ordering::Acquire);
            if handle == 0 {
                return None;
            }
            core_crypto::session_key_decrypt(
                handle,
                hex::decode(&encrypted.0).unwrap_or_default(),
                hex::decode(&encrypted.1).unwrap_or_default(),
            )
            .ok()
        })
        .and_then(|d| serde_json::from_slice::<serde_json::Value>(&d).ok());
    if let Some(json) = decrypted {
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
    }
    r#"{"status":"synced"}"#.to_string().into_bytes()
}
