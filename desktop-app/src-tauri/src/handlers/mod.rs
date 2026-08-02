mod clipboard;
mod media;
mod pairing;
mod poll;
mod rekey_ack;
mod sms;
mod unpair;

pub(crate) use clipboard::handle_clipboard;
pub(crate) use media::handle_media;
pub(crate) use pairing::{handle_pairing, DESKTOP_SESSION_KEY_HANDLE};
pub(crate) use poll::handle_poll;
#[cfg(test)]
pub(crate) use poll::FORCE_EMPTY_CLIPBOARD;
pub(crate) use rekey_ack::handle_rekey_ack;
pub(crate) use sms::handle_sms;
pub(crate) use unpair::handle_unpair;

pub(crate) static IS_SESSION_KEY_AUTHENTICATED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
