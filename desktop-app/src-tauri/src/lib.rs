mod commands;
mod executor;
mod portal;
mod ratchet_store;
mod state;
mod handlers;
mod sync_server;

#[cfg(test)]
mod e2e;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use commands::*;
use state::AppState;
use std::fs;
use std::panic;

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
        // Write to app data directory, not CWD (symlink attack vector)
        let data_dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(std::env::temp_dir);
        let crash_path = data_dir.join("crash_log.txt");
        let _ = fs::write(&crash_path, anonymized_report);
        eprintln!("{raw_report}");
        // Never unwind across the FFI/Tauri boundary — abort after logging.
        std::process::abort();
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
    // Check for sandbox/worker mode before starting the full Tauri app.
    // These flags are used when the app re-spawns itself as a subprocess
    // for isolated Boa JS execution.
    let args: Vec<String> = std::env::args().collect();
    if args.contains(&"--boa-worker".to_string()) {
        // Persistent Boa worker mode: read JSON commands from stdin,
        // execute scripts, write JSON results to stdout.
        executor::run_boa_worker_loop();
        return;
    }
    if args.contains(&"--boa-sandbox".to_string()) {
        // Legacy one-shot sandbox mode: read JSON from stdin, execute, write result.
        executor::apply_worker_rlimits();
        use std::io::Read;
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).ok();
        let req: serde_json::Value = serde_json::from_str(&input).unwrap_or_default();
        let script = req["script"].as_str().unwrap_or("");
        let lux = req["lux"].as_f64().unwrap_or(0.0);
        let feed = req["feed"].as_str().unwrap_or("");
        let result = executor::run_boa_sandboxed_script(script, lux, feed);
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
        return;
    }

    setup_panic_hook();
    let state = std::sync::Arc::new(AppState::default());

    // Restore persisted ratchet sessions (encrypted with an INDEPENDENT
    // snapshot key — audit finding #15b, not derived from the session key) so
    // a restart does not force a full re-pair.
    if let Some(snapshot_key_hex) = ratchet_store::snapshot_key_from_keyring() {
        let restored = ratchet_store::restore_all_ratchet_sessions(&snapshot_key_hex);
        if restored > 0 {
            state.add_log(format!(
                "[Ratchet] Restored {restored} persisted session(s) from encrypted store"
            ));
        }
    }
    
    // SD8: PCKS#11 YubiKey warning check
    {
        let mut settings = state.settings.lock();
        if settings.yubikey_bound {
            state.add_log("WARNING: Your previous hardware-backed keys were not actually backed by hardware due to a missing PKCS#11 integration. YubiKey binding has been reset.".to_string());
            settings.yubikey_bound = false;
        }
    }
    state.save_settings();

    let state_clone = state.clone();

    tauri::Builder::default()
        .manage(state)
        .setup(move |app| {
            // Expose the AppHandle to the pairing handler so SAS/complete/timeout
            // transitions can be pushed to the webview (audit finding #7).
            let _ = crate::handlers::APP_HANDLE.set(app.handle().clone());
            crate::sync_server::start_local_sync_server(state_clone);
            Ok(())
        })
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
            request_privilege_token,
            check_stepup_authorization,
            merge_mesh_crdt_state,
            toggle_neural_anomaly_engine,
            toggle_flight_recorder,
            dump_flight_recorder_events,
            init_sentry_desktop_telemetry,
            bind_pkcs11_yubikey_hardware_token,
            generate_shamir_recovery_shares,
            reconstruct_key_from_shamir_shares,
            trigger_panic_self_destruct,
            get_connection_status,
            get_app_logs,
            get_latest_crash_log,
            perform_stun_hole_punch,
            evaluate_connection_status,
            get_pairing_config,
            confirm_pairing_sas,
            get_pairing_status,
            get_settings,
            save_settings,
            delete_connection,
            get_connection_status_full,
            set_connection_status_full,
            grant_file_access,
            read_real_clipboard,
            write_real_clipboard,
            list_mock_files,
            open_local_file,
            check_flatpak_permissions,
            trigger_desktop_media_action,
            get_media_state,
            check_firewall,
            request_firewall_open,
            create_p2p_group,
            register_mdns_service,
            create_tor_onion,
            generate_wormhole_code,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
