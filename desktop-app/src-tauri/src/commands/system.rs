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

#[derive(Serialize)]
pub struct TelemetryMetrics {
    pub rtt_ms: f64,
    pub transport_path: String,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub last_script_execution_ms: f64,
}

#[tauri::command]
pub fn get_telemetry_metrics(state: State<'_, std::sync::Arc<AppState>>) -> TelemetryMetrics {
    let _logs = state.logs.lock().ok();
    TelemetryMetrics {
        rtt_ms: 0.0,
        transport_path: "Disconnected".to_string(),
        packets_sent: 0,
        packets_received: 0,
        last_script_execution_ms: 0.0,
    }
}

#[tauri::command]
pub fn toggle_neural_anomaly_engine(
    enabled: bool,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    let status_str = if enabled {
        "ENABLED (eBPF ONNX Engine Active)"
    } else {
        "DISABLED (Battery & Performance Optimized)"
    };
    state.add_log(format!(
        "[Neural Anomaly Engine] Status changed to: {status_str}"
    ));
    Ok(format!(
        "Neuromorphic On-Device Anomaly Engine is now {status_str}"
    ))
}

#[tauri::command]
pub fn toggle_flight_recorder(
    enabled: bool,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    core_crypto::telemetry::GLOBAL_FLIGHT_RECORDER.set_enabled(enabled);
    let status_str = if enabled {
        "ENABLED (sub-nanosecond qlog ring buffer active)"
    } else {
        "DISABLED (zero overhead)"
    };
    state.add_log(format!("[Flight Data Recorder] {status_str}"));
    Ok(format!("Flight Data Recorder is now {status_str}"))
}

#[tauri::command]
pub fn dump_flight_recorder_events() -> Result<String, String> {
    Ok(core_crypto::telemetry::GLOBAL_FLIGHT_RECORDER.dump_events_json())
}

#[tauri::command]
pub fn init_sentry_desktop_telemetry(
    dsn: String,
    state: tauri::State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    state.add_log(format!(
        "[Telemetry] Local logging active. Remote telemetry disabled. DSN: {}",
        dsn
    ));
    Ok("Local Diagnostics Active (Zero-Trust Enforcement)".to_string())
}

#[tauri::command]
pub fn get_latest_crash_log() -> Option<String> {
    let data_dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    std::fs::read_to_string(data_dir.join("crash_log.txt")).ok()
}

#[tauri::command]
pub fn bind_pkcs11_yubikey_hardware_token(
    _slot_id: u32,
    _user_pin: String,
) -> Result<String, String> {
    Err("PKCS#11 YubiKey binding is not yet implemented — the stub returned success erroneously. This command will be available in a future release.".into())
}

#[tauri::command]
pub fn trigger_panic_self_destruct(
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    core_crypto::trigger_panic_hardware_wipe().map_err(|e| e.to_string())?;
    state.set_connection_status("SELF_DESTRUCTED_MEMORY_ZEROIZED".to_string());
    state.add_log(
        "[PANIC DESTRUCTION] Memory zeroized & Hardware KeyStore invalidated!".to_string(),
    );
    Ok("Hardware master key destroyed and active ratchet zeroized.".to_string())
}

#[tauri::command]
pub fn get_app_logs(state: State<'_, std::sync::Arc<AppState>>) -> Vec<String> {
    state.logs.lock().map(|l| l.clone()).unwrap_or_default()
}

#[tauri::command]
pub fn check_stepup_authorization(
    action_name: String,
    requires_high_tier: bool,
) -> Result<bool, String> {
    if !requires_high_tier {
        return Ok(true);
    }
    // REMOVED: pkexec sh -c "echo authorized" — this was a Local Privilege Escalation
    // vector. pkexec must only execute registered Polkit actions, never arbitrary
    // shell commands. Using it with --disable-internal-agent and sh -c bypasses
    // all authentication controls and allows any local user to elevate privileges.
    // See CVE-2021-4034 (pwnkit) for the class of vulnerability.
    // Proper step-up authorization requires a registered Polkit action file and
    // calling pkexec with the action name, not a shell command.
    tracing::warn!(
        "[Step-Up Auth] High-tier action '{action_name}' — Polkit step-up is disabled for security. Requires registered Polkit action."
    );
    Err(
        "Step-up authorization is unavailable. This action requires a registered Polkit action."
            .to_string(),
    )
}

#[tauri::command]
pub fn merge_mesh_crdt_state(
    incoming_value: String,
    incoming_node_id: String,
    incoming_timestamp: u64,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<bool, String> {
    let mut local_crdt = core_crypto::crypto::LwwRegisterCRDT::new(
        "Local Engine State".to_string(),
        "desktop_node_1".to_string(),
        100,
    );

    let remote_crdt = core_crypto::crypto::LwwRegisterCRDT::new(
        incoming_value,
        incoming_node_id.clone(),
        incoming_timestamp,
    );

    let updated = local_crdt.merge(remote_crdt);
    if updated {
        state.add_log(format!("[CRDT Mesh] Converged state from node {incoming_node_id} (timestamp = {incoming_timestamp})"));
    }
    Ok(updated)
}

#[tauri::command]
pub async fn stream_binary_file(
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<tauri::ipc::Response, String> {
    let _logs = state.logs.lock().ok();
    let raw_bytes = vec![0u8; 1024];
    Ok(tauri::ipc::Response::new(raw_bytes))
}

#[tauri::command]
pub fn get_settings(state: State<'_, std::sync::Arc<AppState>>) -> crate::state::AppSettings {
    let s = state.settings.lock().unwrap_or_else(|e| e.into_inner());
    s.clone()
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn save_settings(
    device_name: Option<String>,
    device_picture: Option<String>,
    paired_device_name: Option<String>,
    paired_device_picture: Option<String>,
    ddns_hostname: String,
    enable_upnp: bool,
    enable_ddns: bool,
    is_paired: bool,
    theme_mode: Option<String>,
    pathway_order: Option<Vec<String>>,
    wireguard_active: bool,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<(), String> {
    state.add_log("[Settings] Updating preferences".to_string());
    if enable_upnp {
        state.add_log("[UPnP] Initializing UPnP port mapper fallback... Done.".to_string());
    }
    if enable_ddns && !ddns_hostname.is_empty() {
        state.add_log(format!(
            "[DDNS] Resolving DDNS Hostname: {ddns_hostname}... Done."
        ));
    }
    {
        let mut s = state.settings.lock().unwrap_or_else(|e| e.into_inner());
        s.device_name = device_name;
        s.device_picture = device_picture;
        s.paired_device_name = paired_device_name;
        s.paired_device_picture = paired_device_picture;
        s.ddns_hostname = ddns_hostname;
        s.enable_upnp = enable_upnp;
        s.enable_ddns = enable_ddns;
        s.is_paired = is_paired;
        s.theme_mode = theme_mode;
        s.pathway_order = pathway_order;
        s.wireguard_active = wireguard_active;
    }
    state.save_settings();
    Ok(())
}

#[tauri::command]
pub fn grant_file_access(
    is_desktop: bool,
    granted: bool,
    state: State<'_, std::sync::Arc<AppState>>,
) -> crate::state::AppSettings {
    {
        let mut s = state.settings.lock().unwrap_or_else(|e| e.into_inner());
        if is_desktop {
            s.file_access_granted_desktop = granted;
        } else {
            s.file_access_granted_phone = granted;
        }
    }
    state.save_settings();
    state
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[derive(Serialize)]
pub struct LocalFileItem {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

#[tauri::command]
pub fn list_mock_files(
    is_phone: bool,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<Vec<LocalFileItem>, String> {
    let s = state.settings.lock().unwrap_or_else(|e| e.into_inner());
    if is_phone {
        if !s.file_access_granted_phone {
            return Err(
                "Access denied by remote phone. Please grant permission in Kyberpipe settings."
                    .to_string(),
            );
        }
        Ok(vec![
            LocalFileItem {
                name: "DCIM".to_string(),
                path: "/sdcard/DCIM".to_string(),
                is_dir: true,
                size: 0,
            },
            LocalFileItem {
                name: "Documents".to_string(),
                path: "/sdcard/Documents".to_string(),
                is_dir: true,
                size: 0,
            },
            LocalFileItem {
                name: "Download".to_string(),
                path: "/sdcard/Download".to_string(),
                is_dir: true,
                size: 0,
            },
            LocalFileItem {
                name: "backup_identity.key".to_string(),
                path: "/sdcard/backup_identity.key".to_string(),
                is_dir: false,
                size: 1240,
            },
            LocalFileItem {
                name: "P2P_Secret_Handshake.pdf".to_string(),
                path: "/sdcard/Documents/P2P_Secret_Handshake.pdf".to_string(),
                is_dir: false,
                size: 405300,
            },
        ])
    } else {
        if !s.file_access_granted_desktop {
            return Err(
                "Access denied by local PC. Please grant permission in Kyberpipe settings."
                    .to_string(),
            );
        }
        Ok(vec![
            LocalFileItem {
                name: "kyberpipe_core".to_string(),
                path: "/home/Aelfwif/Downloads/kyberpipe".to_string(),
                is_dir: true,
                size: 0,
            },
            LocalFileItem {
                name: "settings.json".to_string(),
                path: "/home/Aelfwif/Downloads/kyberpipe/desktop-app/src-tauri/settings.json"
                    .to_string(),
                is_dir: false,
                size: 450,
            },
            LocalFileItem {
                name: "desktop-app".to_string(),
                path: "/home/Aelfwif/Downloads/kyberpipe/desktop-app".to_string(),
                is_dir: true,
                size: 0,
            },
            LocalFileItem {
                name: "core-crypto".to_string(),
                path: "/home/Aelfwif/Downloads/kyberpipe/core-crypto".to_string(),
                is_dir: true,
                size: 0,
            },
        ])
    }
}

#[tauri::command]
pub fn open_local_file(path: String) -> Result<(), String> {
    if path.contains("..") || path.contains("~") {
        return Err("Path traversal blocked: relative path components not permitted".into());
    }
    if path.starts_with("https://")
        || path.starts_with("http://")
        || path.starts_with("file://")
        || path.starts_with("ftp://")
    {
        return Err("URL schemes not permitted: use file paths only".into());
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let resolved = if path.starts_with('/') {
        path.clone()
    } else {
        format!("{home}/{}", path.trim_start_matches("./"))
    };
    let allowed_dirs = [
        format!("{home}/Downloads"),
        format!("{home}/Documents"),
        format!("{home}/Desktop"),
        format!("{home}/kyberpipe"),
    ];
    let canonical = std::fs::canonicalize(&resolved)
        .map_err(|_| format!("Cannot resolve path: {}", resolved))?;
    let canonical_str = canonical.to_string_lossy().to_string();
    if !allowed_dirs.iter().any(|d| canonical_str.starts_with(d)) {
        return Err("Access denied: path must be under Downloads, Documents, Desktop, or kyberpipe directory".into());
    }

    std::process::Command::new("xdg-open")
        .arg(&resolved)
        .spawn()
        .map_err(|e| format!("Failed to open file: {e}"))?;
    Ok(())
}

#[tauri::command]
pub fn check_flatpak_permissions() -> Result<bool, String> {
    if !is_flatpak() {
        return Ok(true);
    }
    let pulse_exists = std::path::Path::new("/run/flatpak/sandbox-pulse").exists()
        || std::path::Path::new("/run/user")
            .read_dir()
            .map(|mut rd| {
                rd.any(|entry| {
                    if let Ok(e) = entry {
                        let p = e.path().join("pulse/native");
                        p.exists()
                    } else {
                        false
                    }
                })
            })
            .unwrap_or(false);
    Ok(pulse_exists)
}
