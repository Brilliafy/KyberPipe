use tauri::State;
use crate::executor::{run_boa_sandboxed_script, run_fallback_subprocess, ScriptExecutionResult};
use crate::portal::{is_flatpak, send_notification, sync_clipboard_text};
use crate::state::AppState;
use core_crypto::packets::{NotificationPacket, SensorPacket, SmsPacket};
use core_crypto::generate_pq_keypair;
use serde::Serialize;

#[derive(Serialize)]
pub struct SystemInfo {
    pub is_flatpak: bool,
    pub platform: String,
    pub app_version: String,
    pub pqc_algorithm: String,
}

#[derive(Serialize)]
pub struct KeyPairDTO {
    pub x25519_pk_hex: String,
    pub x25519_sk_hex: String,
    pub mlkem_pk_hex: String,
    pub mlkem_sk_hex: String,
}

#[tauri::command]
pub fn get_system_info() -> SystemInfo {
    SystemInfo {
        is_flatpak: is_flatpak(),
        platform: std::env::consts::OS.to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        pqc_algorithm: "Hybrid X25519 + NIST ML-KEM-768 & ChaCha20-Poly1305".to_string(),
    }
}

#[tauri::command]
pub fn generate_keypair(state: State<'_, AppState>) -> Result<KeyPairDTO, String> {
    let pair = generate_pq_keypair().map_err(|e| e.to_string())?;
    let dto = KeyPairDTO {
        x25519_pk_hex: pair.x25519_pk_hex.clone(),
        x25519_sk_hex: pair.x25519_sk_hex.clone(),
        mlkem_pk_hex: pair.mlkem_pk_hex.clone(),
        mlkem_sk_hex: pair.mlkem_sk_hex.clone(),
    };
    if let Ok(mut lock) = state.keypair.lock() {
        *lock = Some(pair);
    }
    state.add_log("[PQC] Generated Hybrid Keypair (X25519 + ML-KEM-768)".to_string());
    Ok(dto)
}

#[tauri::command]
pub fn execute_boa_script(
    script_code: String,
    lux: f64,
    state: State<'_, AppState>,
) -> ScriptExecutionResult {
    state.add_log(format!("[Sandbox] Running Boa script (lux = {lux})"));
    let res = run_boa_sandboxed_script(&script_code, lux);
    state.add_log(format!("[Sandbox] Result: success={}, output={}", res.success, res.output));
    res
}

#[tauri::command]
pub fn execute_fallback_script(
    script_path: String,
    lux: f64,
    state: State<'_, AppState>,
) -> ScriptExecutionResult {
    state.add_log(format!("[Subprocess] Executing fallback script: {script_path} (lux = {lux})"));
    let res = run_fallback_subprocess(&script_path, lux);
    state.add_log(format!("[Subprocess] Result: success={}, output={}", res.success, res.output));
    res
}

#[tauri::command]
pub fn sync_clipboard(text: String, state: State<'_, AppState>) -> Result<bool, String> {
    if state.dedup.is_suppressed(&text) {
        state.add_log("[Clipboard] Suppressed duplicate or loop-back clipboard sync".to_string());
        return Ok(false);
    }
    state.dedup.record_text(&text);
    sync_clipboard_text(&text)?;
    state.add_log(format!("[Clipboard] Synced: \"{}\"", &text.chars().take(30).collect::<String>()));
    Ok(true)
}

#[tauri::command]
pub async fn send_desktop_notification(
    title: String,
    body: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.add_log(format!("[Notification] Sending: {title}"));
    send_notification(&title, &body).await
}

#[tauri::command]
pub fn push_sensor_reading(
    lux: f64,
    timestamp: u64,
    state: State<'_, AppState>,
) -> Vec<SensorPacket> {
    let pkt = SensorPacket { lux, timestamp };
    if let Ok(mut hist) = state.sensor_history.lock() {
        if hist.len() >= 50 {
            hist.remove(0);
        }
        hist.push(pkt);
        hist.clone()
    } else {
        vec![]
    }
}

#[tauri::command]
pub fn push_sms_packet(
    sender: String,
    body: String,
    timestamp: u64,
    state: State<'_, AppState>,
) -> Vec<SmsPacket> {
    let pkt = SmsPacket {
        sender: sender.clone(),
        body,
        timestamp,
    };
    state.add_log(format!("[SMS] Received from {sender}"));
    if let Ok(mut hist) = state.sms_history.lock() {
        if hist.len() >= 50 {
            hist.remove(0);
        }
        hist.push(pkt);
        hist.clone()
    } else {
        vec![]
    }
}

#[tauri::command]
pub fn push_notification_packet(
    title: String,
    text: String,
    app_package: String,
    timestamp: u64,
    state: State<'_, AppState>,
) -> Vec<NotificationPacket> {
    let pkt = NotificationPacket {
        title: title.clone(),
        text,
        app_package: app_package.clone(),
        icon_base64: None,
        timestamp,
    };
    state.add_log(format!("[Mirror] Notification from {app_package}: {title}"));
    if let Ok(mut hist) = state.notification_history.lock() {
        if hist.len() >= 50 {
            hist.remove(0);
        }
        hist.push(pkt);
        hist.clone()
    } else {
        vec![]
    }
}

#[tauri::command]
pub fn get_connection_status(state: State<'_, AppState>) -> String {
    state.connection_status.lock().map(|s| s.clone()).unwrap_or_else(|_| "Disconnected".to_string())
}

#[tauri::command]
pub fn get_app_logs(state: State<'_, AppState>) -> Vec<String> {
    state.logs.lock().map(|l| l.clone()).unwrap_or_default()
}
