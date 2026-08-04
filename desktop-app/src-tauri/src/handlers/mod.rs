mod clipboard;
mod media;
mod pairing;
/// AUDIT #20 (structural decomposition): the former `handlers/pairing.rs`
/// monolith is split into the wire codec (`pairing_wire`), the rate policy
/// (`pairing_policy`) and the remaining KEM/phase machine (`pairing`) — each
/// changes in isolation and can be tested/reused independently.
mod pairing_policy;
mod pairing_wire;
mod poll;
mod sms;
mod unpair;
#[cfg(test)]
mod wire_format_tests;

pub(crate) use clipboard::handle_clipboard;
pub(crate) use media::handle_media;
pub(crate) use pairing::{handle_pairing, DESKTOP_SESSION_KEY_HANDLE};
pub(crate) use poll::handle_poll;
#[cfg(test)]
pub(crate) use poll::FORCE_EMPTY_CLIPBOARD;
pub(crate) use sms::handle_sms;
pub(crate) use unpair::handle_unpair;

pub(crate) static IS_SESSION_KEY_AUTHENTICATED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// THE single cross-platform wire format for ratchet payloads (audit F8 /
/// KYP-2026-02 #17): a JSON object `{"encrypted_ratchet": {"tlv_b64": ...}}`
/// wrapping a base64-encoded BINARY TLV ratchet message. Every inbound handler
/// (clipboard, SMS, media, rekey-ack) decrypts through this one helper so the
/// contract can never drift per stream. A body that does not carry the ratchet
/// TLV shape decrypts to `None` — the legacy session-key hex format
/// (`encrypted.nonce_hex` / `encrypted.ciphertext_hex`) is a protocol violation
/// and is NOT accepted anywhere.
pub(crate) fn decrypt_json_payload(body: &[u8], peer_id: &str) -> Option<String> {
    let body_str = String::from_utf8_lossy(body);
    let json = serde_json::from_str::<serde_json::Value>(&body_str).ok()?;

    if !peer_id.is_empty() {
        if let Some(enc) = json.get("encrypted_ratchet") {
            let tlv_b64 = enc.get("tlv_b64").and_then(|v| v.as_str())?;
            let bin =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64).ok()?;
            match core_crypto::ratchet_decrypt_message_binary(peer_id.to_string(), bin) {
                Ok(pt) => return String::from_utf8(pt).ok(),
                Err(e) => {
                    tracing::warn!("[Wire] Ratchet binary decrypt failed for {peer_id}: {e}")
                }
            }
        }
    }
    None
}

/// Process-global Tauri AppHandle, set in `run()` setup. Used to push pairing
/// state transitions (sas-ready / complete / timeout) to the webview so the UI
/// can never drift from backend state (audit finding #7 / #13).
pub(crate) static APP_HANDLE: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

/// Emit a Tauri event to every window. Safe no-op if the handle is not yet set.
pub(crate) fn emit_app_event(event: &str, payload: serde_json::Value) {
    use tauri::Emitter;
    if let Some(app) = APP_HANDLE.get() {
        let _ = app.emit(event, payload);
    }
}
