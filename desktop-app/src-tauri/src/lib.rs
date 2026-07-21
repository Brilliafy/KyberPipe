mod commands;
mod executor;
mod portal;
mod state;

use commands::*;
use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            generate_keypair,
            execute_boa_script,
            execute_fallback_script,
            sync_clipboard,
            send_desktop_notification,
            push_sensor_reading,
            push_sms_packet,
            push_notification_packet,
            get_connection_status,
            get_app_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
