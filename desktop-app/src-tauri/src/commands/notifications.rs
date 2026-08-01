use crate::state::{AppState, NotificationRecord};
use core_crypto::packets::SmsPacket;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

/// Strip HTML tags and common markup from user-controlled notification strings
/// to prevent DBus content injection attacks via org.freedesktop.Notifications.
/// GNOME/KDE notification daemons support HTML-like markup (<a href>, <img>, etc.)
/// which can be abused for URI-based attacks if attacker-controlled content is rendered.
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

#[tauri::command]
pub async fn send_desktop_notification(
    title: String,
    body: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<(), String> {
    state.add_log(format!("[Notification] Sending: {title}"));
    crate::portal::send_notification(&title, &body).await
}

#[tauri::command]
pub fn push_sms_packet(
    sender: String,
    body: String,
    timestamp: u64,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Vec<SmsPacket> {
    let pkt = SmsPacket {
        sender: sender.clone(),
        body,
        timestamp,
    };
    state.add_log(format!("[SMS] Received from {sender}"));
    state.add_sms_packet(pkt);
    state.get_sms_history()
}

#[tauri::command]
pub async fn push_notification_packet(
    title: String,
    text: String,
    app_package: String,
    timestamp: u64,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<Vec<NotificationRecord>, String> {
    let pkt = NotificationRecord {
        id: format!("{app_package}_{timestamp}"),
        title: title.clone(),
        text: text.clone(),
        app_package: app_package.clone(),
        timestamp,
        is_dismissed: false,
        updated_at: timestamp,
        type_field: "remote".to_string(),
    };
    let notif_title = sanitize_notification_text(&title);
    let notif_text = sanitize_notification_text(&text);
    tokio::task::spawn_blocking(move || {
        let _ = notify_rust::Notification::new()
            .summary(&notif_title)
            .body(&notif_text)
            .icon("dialog-information")
            .show();
    });

    state.add_log(format!(
        "[Notification Sync] {app_package}: {title} - {text}"
    ));
    state.add_notification(pkt);
    Ok(state.get_notifications())
}

#[tauri::command]
pub fn send_outbound_sms(
    recipient: String,
    body: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    state.add_log(format!("[Outbound SMS] Dispatching to {recipient}: {body}"));
    core_crypto::create_outbound_sms_packet(
        recipient,
        body,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn trigger_notification_action(
    sbn_key: String,
    action_index: u32,
    action_title: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    state.add_log(format!(
        "[Notification Action] Triggered action '{action_title}' on {sbn_key}"
    ));
    core_crypto::create_notification_action_packet(
        sbn_key,
        action_index,
        action_title,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn send_hardware_command(
    command_type: String,
    payload_json: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    state.add_log(format!("[Hardware Command] Dispatching: {command_type}"));
    core_crypto::create_hardware_command_packet(
        command_type,
        payload_json,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn trigger_desktop_media_action(action_index: u32, state: State<'_, std::sync::Arc<AppState>>) {
    state.set_pending_media_action(Some(action_index));
    state.add_log(format!(
        "[Media] Desktop triggered action index: {action_index}"
    ));
}

#[tauri::command]
pub fn get_media_state(state: State<'_, std::sync::Arc<AppState>>) -> crate::state::MediaState {
    state.get_media_state()
}
