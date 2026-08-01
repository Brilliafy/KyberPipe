use std::path::Path;
use tracing::{info, warn};

/// Returns true if running inside a Flatpak container sandbox
pub fn is_flatpak() -> bool {
    Path::new("/.flatpak-info").exists()
}

/// Strip HTML-like markup from user-controlled notification strings.
/// DBus notification daemons (GNOME/KDE) render HTML-like markup, so
/// attacker-controlled SMS/notification content reaching a notification must
/// never carry <a href=...>, <img src=...>, etc. Sanitizing here covers EVERY
/// call path (send_desktop_notification, push_notification_packet, SMS).
fn sanitize_notification_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Dynamic notification dispatcher: routes to ashpd in Flatpak, notify-rust natively
pub async fn send_notification(title: &str, body: &str) -> Result<(), String> {
    let title = sanitize_notification_text(title);
    let body = sanitize_notification_text(body);
    if is_flatpak() {
        info!("Flatpak sandbox detected: Dispatching notification via XDG Desktop Portal (ashpd)");
        match ashpd::desktop::notification::NotificationProxy::new().await {
            Ok(proxy) => {
                let notification =
                    ashpd::desktop::notification::Notification::new(&title).body(Some(body.as_str()));
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
            .summary(&title)
            .body(&body)
            .appname("Kyberpipe")
            .show()
            .map_err(|e| format!("Native notification error: {e}"))?;
        Ok(())
    }
}

/// Dynamic clipboard sync dispatcher
pub fn sync_clipboard_text(text: &str) -> Result<(), String> {
    if is_flatpak() {
        info!("Flatpak sandbox detected: Syncing clipboard via Portal/fallbacks");
        let _ = crate::commands::write_clipboard_fallback(text);
        Ok(())
    } else {
        info!("Native Linux detected: Syncing clipboard via arboard/fallbacks");
        // Bounded native write — arboard blocks forever on headless sessions.
        let owned = text.to_string();
        let native_ok = crate::commands::with_timeout(std::time::Duration::from_secs(3), move || {
            arboard::Clipboard::new()
                .and_then(|mut b| b.set_text(owned))
                .is_ok()
        })
        .unwrap_or(false);
        if native_ok {
            let _ = crate::commands::write_clipboard_fallback(text);
            return Ok(());
        }
        crate::commands::write_clipboard_fallback(text)
    }
}
