mod commands;
mod executor;
mod handlers;
mod portal;
mod ratchet_store;
mod state;
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
        // Do NOT abort the whole process. UniFFI's scaffolding catch_unwind
        // contains panics inside exported FFI functions and returns them as
        // structured errors, so a single panicking call must not kill the app
        // (and its in-memory key material). The crash report above is still
        // written so the failure is observable (audit finding #13).
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

    // Audit KYP-2026-02 #6: restore the persisted pairing keypair (if any) so
    // the identity the phone pins is STABLE across restarts — regenerating it
    // on every mount rotated the identity and silently invalidated in-flight
    // pairing QRs. Only when no keypair is persisted (first run) does the
    // renderer generate a fresh one via generate_keypair.
    if state.get_keypair().is_none() {
        if let Some(pair) = ratchet_store::load_pairing_keypair_from_keyring() {
            state.set_keypair(Some(pair));
            state.add_log(
                "[PQC] Restored persisted pairing keypair from OS keyring (stable identity)"
                    .to_string(),
            );
        }
    }

    // Issue the mandatory QR pairing nonce at app start (audit finding #20):
    // every pairing request must echo a nonce this desktop issued, so a LAN
    // peer that never scanned a QR cannot occupy the pairing slot.
    state.issue_fresh_pairing_nonce();

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

    // AUDIT F1 FIX: rebuild the pairing identity + TLS client-cert allowlist
    // from persisted settings. `SettingsService::new` now LOADS settings.json
    // (the legacy constructor discarded every persisted value on boot), and
    // this call restores `paired_client_cert_hash`, the peer public keys and
    // the per-peer cert→ratchet map into the pairing service, and re-seeds
    // core-crypto's `ALLOWED_CLIENT_CERTS`. It MUST run before the QUIC server
    // binds (`start_local_sync_server` in `.setup`) so `bind_server` builds
    // its verifier with the restored allowlist (`required=true`) instead of an
    // empty set that both accepts any client cert at TLS and rejects every
    // stream at the authorization layer.
    state.restore_pairing_identity();

    // AUDIT F11: re-create the DESKTOP session-key handle from the persisted
    // keyring entry after a restart. The handle is a process-global AtomicU64
    // that starts at 0 — previously it was only ever set during a live
    // `perform_sas_confirmation`, so after ANY restart it silently dropped to
    // 0 and every session-key decrypt path returned None (a write-only keyring
    // entry, dead weight, and a trap for any future session_key_* user).
    if crate::handlers::DESKTOP_SESSION_KEY_HANDLE.load(std::sync::atomic::Ordering::Acquire) == 0 {
        if let Some(session_key_hex) = ratchet_store::session_key_from_keyring() {
            if let Ok(sk) = hex::decode(&session_key_hex) {
                if !sk.is_empty() {
                    match core_crypto::session_key_create(sk) {
                        Ok(h) if h != 0 => {
                            crate::handlers::DESKTOP_SESSION_KEY_HANDLE
                                .store(h, std::sync::atomic::Ordering::Release);
                            state.add_log(
                                "[Session] Restored desktop session-key handle from keyring"
                                    .to_string(),
                            );
                        }
                        Ok(_) => {
                            state.add_log(
                                "[Session] Keyring session key produced reserved handle 0 — ignoring"
                                    .to_string(),
                            );
                        }
                        Err(e) => {
                            state.add_log(format!(
                                "[Session] Failed to restore session-key handle from keyring: {e}"
                            ));
                        }
                    }
                }
            }
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
        // ── Command surface, registered per-TIER (audit finding #20) ────────
        // Tier 0: read-only queries — no token required.
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            get_connection_status,
            get_connection_status_full,
            get_app_logs,
            get_latest_crash_log,
            get_pairing_status,
            get_pairing_nonce,
            get_server_cert_hash,
            get_settings,
            get_media_state,
            get_telemetry_metrics,
            check_flatpak_permissions,
            check_firewall,
            dump_flight_recorder_events,
            get_pairing_config,
            read_real_clipboard,
            list_mock_files,
        ])
        // Tier 1: state mutation — driven by a real user gesture in the UI;
        // no extra token (the renderer is the trusted local frontend).
        .invoke_handler(tauri::generate_handler![
            generate_keypair,
            save_settings,
            push_sensor_reading,
            push_sms_packet,
            push_notification_packet,
            send_outbound_sms,
            trigger_notification_action,
            trigger_desktop_media_action,
            send_desktop_notification,
            send_hardware_command,
            set_connection_status_full,
            toggle_flight_recorder,
            init_sentry_desktop_telemetry,
            merge_mesh_crdt_state,
            perform_stun_hole_punch,
            evaluate_connection_status,
            generate_sas_pairing_code,
            write_real_clipboard,
            register_mdns_service,
            get_beacon_signing_key,
            confirm_pairing_sas,
            toggle_neural_anomaly_engine,
        ])
        // Tier 2: privileged/destructive — EVERY command first calls
        // `gate_tier2(action, token)` (or consumes a user-gesture token
        // internally via `consume_privilege_token`), consuming the single-use
        // token issued by `request_privilege_token`. Enforcement is per-TIER
        // (uniform), not ad-hoc per command. `generate_shamir_recovery_shares`
        // and `reconstruct_key_from_shamir_shares` are classified here — they
        // consume tokens internally (they handle the master identity key), so
        // listing them in Tier 1 would disagree with their internal gate
        // (audit finding #10).
        .invoke_handler(tauri::generate_handler![
            request_privilege_token,
            check_stepup_authorization,
            delete_connection,
            trigger_panic_self_destruct,
            store_key_in_secure_enclave,
            bind_pkcs11_yubikey_hardware_token,
            grant_file_access,
            open_local_file,
            // AUDIT F17: external URL opening is token-gated + scheme
            // allowlisted (opener:default was dropped from the capability).
            open_external_url,
            request_firewall_open,
            create_tor_onion,
            execute_boa_script,
            execute_fallback_script,
            generate_shamir_recovery_shares,
            reconstruct_key_from_shamir_shares,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
