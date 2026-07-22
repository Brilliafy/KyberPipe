mod commands;
mod executor;
mod portal;
mod browser_bridge;
mod state;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use commands::*;
use state::AppState;
use std::panic;
use std::fs;

fn setup_panic_hook() {
    panic::set_hook(Box::new(|panic_info| {
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            *s
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            &**s
        } else {
            "Unknown panic payload"
        };

        let location = if let Some(loc) = panic_info.location() {
            format!("{}:{}:{}", loc.file(), loc.line(), loc.column())
        } else {
            "unknown location".to_string()
        };

        let backtrace = std::backtrace::Backtrace::force_capture();
        let raw_report = format!(
            "KyberPipe Engine Panic Crash Log\n\
             ===============================\n\
             Panic message: {}\n\
             Location: {}\n\
             Backtrace:\n{:#?}\n",
            message, location, backtrace
        );

        let anonymized_report = anonymize_report(&raw_report);
        let _ = fs::write("crash_log.txt", anonymized_report);
    }));
}

fn anonymize_report(report: &str) -> String {
    let mut scrubbed = String::new();
    for line in report.lines() {
        let mut line_str = line.to_string();
        
        if let Some(home_idx) = line_str.find("/home/") {
            let rest = &line_str[home_idx + 6..];
            let user_end = rest.find('/').unwrap_or(rest.len());
            let username = &rest[..user_end];
            line_str = line_str.replace(&format!("/home/{}", username), "/home/[USER]");
        }
        if let Some(users_idx) = line_str.find("Users\\") {
            let rest = &line_str[users_idx + 6..];
            let user_end = rest.find('\\').unwrap_or(rest.len());
            let username = &rest[..user_end];
            line_str = line_str.replace(&format!("Users\\{}", username), "Users\\[USER]");
        }
        
        line_str = scrub_ips(&line_str);
        scrubbed.push_str(&line_str);
        scrubbed.push('\n');
    }
    scrubbed
}

fn scrub_ips(input: &str) -> String {
    let mut output = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let mut dot_count = 0;
            let mut j = i;
            let mut current_segment_len = 0;
            let mut valid_ip = true;
            while j < chars.len() {
                if chars[j].is_ascii_digit() {
                    current_segment_len += 1;
                    if current_segment_len > 3 {
                        valid_ip = false;
                        break;
                    }
                } else if chars[j] == '.' {
                    if current_segment_len == 0 {
                        valid_ip = false;
                        break;
                    }
                    dot_count += 1;
                    current_segment_len = 0;
                    if dot_count > 3 {
                        break;
                    }
                } else {
                    break;
                }
                j += 1;
            }
            if valid_ip && dot_count == 3 && current_segment_len > 0 {
                output.push_str("[MASKED_IP]");
                i = j;
                continue;
            }
        }
        output.push(chars[i]);
        i += 1;
    }
    output
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    setup_panic_hook();
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
            toggle_flight_recorder,
            dump_flight_recorder_events,
            init_sentry_desktop_telemetry,
            bind_pkcs11_yubikey_hardware_token,
            execute_enclave_confidential_wasm,
            generate_shamir_recovery_shares,
            reconstruct_key_from_shamir_shares,
            trigger_panic_self_destruct,
            get_connection_status,
            get_app_logs,
            get_latest_crash_log,
            perform_stun_hole_punch,
            evaluate_connection_status,
            get_pairing_config,
            get_settings,
            save_settings,
            get_connection_status_full,
            set_connection_status_full,
            grant_file_access,
            read_real_clipboard,
            write_real_clipboard,
            list_mock_files,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
