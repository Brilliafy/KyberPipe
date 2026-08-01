use crate::portal::is_flatpak;
use crate::state::AppState;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct SystemInfo {
    pub is_flatpak: bool,
    pub platform: String,
    pub app_version: String,
    pub pqc_algorithm: String,
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
pub fn get_latest_crash_log() -> Option<String> {
    let data_dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    std::fs::read_to_string(data_dir.join("crash_log.txt")).ok()
}

#[tauri::command]
pub fn get_app_logs(state: State<'_, std::sync::Arc<AppState>>) -> Vec<String> {
    state.get_logs()
}
