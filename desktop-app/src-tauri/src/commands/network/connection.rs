//! Connection status queries and management.
//!
//! Read-only state queries and connection lifecycle management.

use crate::state::AppState;
use serde::Serialize;
use tauri::State;

#[tauri::command]
pub fn get_connection_status(state: State<'_, std::sync::Arc<AppState>>) -> String {
    state.get_connection_status()
}

#[tauri::command]
pub fn perform_stun_hole_punch(
    stun_host: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    state.add_log(format!(
        "[STUN] Initiating UDP hole punch via STUN: {stun_host}"
    ));
    let addr = core_crypto::perform_stun_hole_punch(stun_host).map_err(|e| e.to_string())?;
    state.add_log(format!("[STUN] Mapped public reflexive address: {addr}"));

    state.set_connection_status(format!("Connected (WAN STUN: {addr})"));

    Ok(addr)
}

/// Evaluate the connection path. The Wi-Fi Direct (P2P) argument was removed
/// from the product (audit finding #1 — the group was never actually secured
/// and the Android join path was dead), so `wifi_direct_active` is always
/// false; the parameter is kept only for the UniFFI signature and is ignored.
#[tauri::command]
pub fn evaluate_connection_status(
    _wifi_direct_active: bool,
    lan_active: bool,
    public_endpoint: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::ConnectionInfo, String> {
    let info = core_crypto::evaluate_connection_hierarchy(false, lan_active, public_endpoint);
    state.add_log(format!(
        "[Connection Manager] Active path: {} (Tier {}, Latency {}ms)",
        info.active_path_description, info.active_tier, info.latency_ms
    ));

    state.set_connection_status(format!("Connected ({})", info.active_path_description));

    Ok(info)
}

#[derive(Serialize)]
pub struct ConnectionStatusFull {
    pub status: String,
    pub method: String,
    pub color: String,
}

#[tauri::command]
pub fn get_connection_status_full(
    state: State<'_, std::sync::Arc<AppState>>,
) -> ConnectionStatusFull {
    let conn = state.get_connection();
    ConnectionStatusFull {
        status: conn.status,
        method: conn.method,
        color: conn.color,
    }
}

#[tauri::command]
pub fn set_connection_status_full(
    status: String,
    method: String,
    color: String,
    state: State<'_, std::sync::Arc<AppState>>,
) {
    let current_status = state.get_connection_status();
    state.set_connection(status.clone(), method.clone(), color.clone());

    if current_status != status {
        state.add_log(format!(
            "[Connection State] Changed to {status} via method {method}"
        ));
    }
}
