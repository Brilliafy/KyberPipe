mod commands;
mod executor;
mod portal;
mod browser_bridge;
mod state;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
            send_outbound_sms,
            trigger_notification_action,
            send_hardware_command,
            get_telemetry_metrics,
            generate_sas_pairing_code,
            store_key_in_secure_enclave,
            check_stepup_authorization,
            merge_mesh_crdt_state,
            stream_binary_file,
            toggle_neural_anomaly_engine,
            bind_pkcs11_yubikey_hardware_token,
            execute_enclave_confidential_wasm,
            generate_shamir_recovery_shares,
            reconstruct_key_from_shamir_shares,
            trigger_panic_self_destruct,
            get_connection_status,
            get_app_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
