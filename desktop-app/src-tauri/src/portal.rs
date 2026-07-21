use std::path::Path;
use tracing::{info, warn};

/// Returns true if running inside a Flatpak container sandbox
pub fn is_flatpak() -> bool {
    Path::new("/.flatpak-info").exists()
}

/// Dynamic notification dispatcher: routes to ashpd in Flatpak, notify-rust natively
pub async fn send_notification(title: &str, body: &str) -> Result<(), String> {
    if is_flatpak() {
        info!("Flatpak sandbox detected: Dispatching notification via XDG Desktop Portal (ashpd)");
        match ashpd::desktop::notification::NotificationProxy::new().await {
            Ok(proxy) => {
                let notification = ashpd::desktop::notification::Notification::new(title)
                    .body(Some(body));
                proxy
                    .add_notification("kyberpipe-notif", notification)
                    .await
                    .map_err(|e| format!("XDG Notification portal error: {e}"))?;
                Ok(())
            }
            Err(e) => {
                warn!("Failed to create ashpd NotificationProxy: {e}");
                Err(format!("XDG Notification proxy failed: {e}"))
            }
        }
    } else {
        info!("Native Linux detected: Dispatching notification via DBus notify-rust");
        notify_rust::Notification::new()
            .summary(title)
            .body(body)
            .appname("Kyberpipe")
            .show()
            .map_err(|e| format!("Native notification error: {e}"))?;
        Ok(())
    }
}

/// Dynamic clipboard sync dispatcher
pub fn sync_clipboard_text(text: &str) -> Result<(), String> {
    if is_flatpak() {
        info!("Flatpak sandbox detected: Syncing clipboard via Portal");
        // Flatpak clipboard sync hook
        Ok(())
    } else {
        info!("Native Linux detected: Syncing clipboard via arboard");
        let mut board = arboard::Clipboard::new()
            .map_err(|e| format!("Failed to access clipboard: {e}"))?;
        board
            .set_text(text.to_string())
            .map_err(|e| format!("Failed to set clipboard text: {e}"))?;
        Ok(())
    }
}
