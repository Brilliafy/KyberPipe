use crate::state::AppState;
use crate::state::NotificationRecord;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::DESKTOP_SESSION_KEY_HANDLE;
use super::IS_SESSION_KEY_AUTHENTICATED;

/// Handle an encrypted SMS packet forwarded from the Android client over QUIC.
/// The body is a JSON object `{"encrypted": {"nonce_hex": ..., "ciphertext_hex": ...}}`
/// wrapping a serialized SmsPacket. Decrypts with the session key and records it.
pub(crate) async fn handle_sms(body: Vec<u8>, s: Arc<AppState>) -> Vec<u8> {
    let body_str = String::from_utf8_lossy(&body);
    let decrypted = serde_json::from_str::<serde_json::Value>(&body_str)
        .ok()
        .and_then(|json| {
            let encrypted = json.get("encrypted").and_then(|e| {
                let nonce = e.get("nonce_hex").and_then(|v| v.as_str())?;
                let ct = e.get("ciphertext_hex").and_then(|v| v.as_str())?;
                Some((nonce.to_string(), ct.to_string()))
            })?;
            if !IS_SESSION_KEY_AUTHENTICATED.load(Ordering::Acquire) {
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
        .and_then(|d| serde_json::from_slice::<core_crypto::packets::SmsPacket>(&d).ok());

    match decrypted {
        Some(pkt) => {
            s.add_log(format!("[SMS] Received from {} via QUIC", pkt.sender));
            s.add_sms_packet(pkt);
            r#"{"status":"synced"}"#.to_string().into_bytes()
        }
        None => r#"{"status":"error","reason":"Decryption failed"}"#
            .to_string()
            .into_bytes(),
    }
}

/// Notification handler — records a forwarded notification (kept for symmetry
/// with the QUIC dispatch; desktop-originated notifications use the IPC command).
#[allow(dead_code)]
pub(crate) async fn handle_notification(body: Vec<u8>, s: Arc<AppState>) -> Vec<u8> {
    let body_str = String::from_utf8_lossy(&body);
    let decrypted = serde_json::from_str::<serde_json::Value>(&body_str)
        .ok()
        .and_then(|json| {
            let encrypted = json.get("encrypted").and_then(|e| {
                let nonce = e.get("nonce_hex").and_then(|v| v.as_str())?;
                let ct = e.get("ciphertext_hex").and_then(|v| v.as_str())?;
                Some((nonce.to_string(), ct.to_string()))
            })?;
            if !IS_SESSION_KEY_AUTHENTICATED.load(Ordering::Acquire) {
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
        let pkt = NotificationRecord {
            id: format!(
                "{}_remote",
                json.get("app_package")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            ),
            title: json
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            text: json
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            app_package: json
                .get("app_package")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            timestamp: json.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0),
            is_dismissed: false,
            updated_at: 0,
            type_field: "remote".to_string(),
        };
        s.add_notification(pkt);
    }
    r#"{"status":"synced"}"#.to_string().into_bytes()
}
