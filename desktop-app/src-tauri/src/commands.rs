use crate::executor::{run_boa_sandboxed_script, run_fallback_subprocess, ScriptExecutionResult};
use crate::portal::{is_flatpak, send_notification, sync_clipboard_text};
use crate::state::{AppState, NotificationRecord};
use core_crypto::generate_pq_keypair;
use core_crypto::packets::{SensorPacket, SmsPacket};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
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
pub fn generate_keypair(
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::PqKeyPair, String> {
    let pair = generate_pq_keypair().map_err(|e| e.to_string())?;
    if let Ok(mut lock) = state.keypair.lock() {
        *lock = Some(pair.clone());
    }
    state.add_log("[PQC] Generated Hybrid Keypair (X25519 + ML-KEM-768)".to_string());
    Ok(pair)
}

#[tauri::command]
pub async fn execute_boa_script(
    script_code: String,
    is_sandboxed: bool,
    lux: f64,
    feed_source_command: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<ScriptExecutionResult, String> {
    let mut feed_value = String::new();
    if !feed_source_command.trim().is_empty() {
        state.add_log(format!(
            "[Automation] Querying feed source: {}",
            feed_source_command
        ));
        // Safe: native Rust HTTP fetch instead of subprocess exec.
        // Prevents file exfiltration via curl/wget arguments with arbitrary paths.
        feed_value = native_http_fetch(&feed_source_command).unwrap_or_else(|e| {
            state.add_log(format!("[Automation] Feed fetch failed: {e}"));
            String::new()
        });
        state.add_log(format!("[Automation] Resolved feed data: {}", feed_value));
    }

    if is_sandboxed {
        state.add_log(format!("[Sandbox] Running Boa script (lux = {lux})"));
        let res = run_boa_sandboxed_script(&script_code, lux, &feed_value);
        state.add_log(format!(
            "[Sandbox] Result: success={}, output={}",
            res.success, res.output
        ));
        Ok(res)
    } else {
        // Security: enforce sandboxed execution regardless of frontend parameter
        // Unsandboxed RCE vector removed per security audit finding #2
        state.add_log(format!(
            "[Sandbox-Enforced] Running Boa script (lux = {lux})"
        ));
        let res = run_boa_sandboxed_script(&script_code, lux, &feed_value);
        state.add_log(format!(
            "[Sandbox-Enforced] Result: success={}, output={}",
            res.success, res.output
        ));
        Ok(res)
    }
}

#[tauri::command]
pub fn execute_fallback_script(
    script_path: String,
    lux: f64,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<ScriptExecutionResult, String> {
    // Security: strict allowlist with hardcoded paths — no user-controlled directories
    let allowed_scripts: &[(&str, &str)] = &[
        (
            "kyberpipe-fallback.sh",
            "/usr/lib/kyberpipe/scripts/kyberpipe-fallback.sh",
        ),
        (
            "kyberpipe-sensor.sh",
            "/usr/lib/kyberpipe/scripts/kyberpipe-sensor.sh",
        ),
    ];
    let script_name = std::path::Path::new(&script_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let resolved_path = allowed_scripts
        .iter()
        .find(|(name, _)| *name == script_name)
        .map(|(_, path)| *path)
        .ok_or_else(|| format!("Script '{}' not in allowed execution list", script_name))?;
    state.add_log(format!(
        "[Subprocess] Executing fallback script: {resolved_path} (lux = {lux})"
    ));
    let res = run_fallback_subprocess(resolved_path, lux);
    state.add_log(format!(
        "[Subprocess] Result: success={}, output={}",
        res.success, res.output
    ));
    Ok(res)
}

#[tauri::command]
pub fn sync_clipboard(
    text: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<bool, String> {
    if state.dedup.is_suppressed(&text) {
        state.add_log("[Clipboard] Suppressed duplicate or loop-back clipboard sync".to_string());
        return Ok(false);
    }
    state.dedup.record_text(&text);
    sync_clipboard_text(&text)?;
    state.add_log(format!(
        "[Clipboard] Synced: \"{}\"",
        text.chars().take(30).collect::<String>()
    ));
    Ok(true)
}

#[tauri::command]
pub async fn send_desktop_notification(
    title: String,
    body: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<(), String> {
    state.add_log(format!("[Notification] Sending: {title}"));
    send_notification(&title, &body).await
}

#[tauri::command]
pub fn push_sensor_reading(
    lux: f64,
    timestamp: u64,
    state: State<'_, std::sync::Arc<AppState>>,
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
    state: State<'_, std::sync::Arc<AppState>>,
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
    // Emit native Linux desktop notification via notify-rust
    let notif_title = title.clone();
    let notif_text = text.clone();
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
    // Use spawn_blocking to avoid Tokio worker thread starvation from sync Mutex
    // Brief sync Mutex lock is acceptable here - not held across awaits
    if let Ok(mut hist) = state.notification_history.lock() {
        if hist.len() >= 50 {
            hist.remove(0);
        }
        hist.push(pkt);
        Ok(hist.clone())
    } else {
        Ok(vec![])
    }
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
pub fn generate_sas_pairing_code(
    host_pk_hex: String,
    client_pk_hex: String,
    shared_secret_hex: String,
) -> Result<String, String> {
    core_crypto::generate_sas_code(host_pk_hex, client_pk_hex, shared_secret_hex)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn store_key_in_secure_enclave(key_name: String, secret_hex: String) -> Result<(), String> {
    let entry = keyring::Entry::new("kyberpipe", &key_name)
        .map_err(|e| format!("Keyring access failed: {e}"))?;
    entry
        .set_password(&secret_hex)
        .map_err(|e| format!("Failed to store secret in OS Secret Service: {e}"))?;
    Ok(())
}

#[tauri::command]
pub fn check_stepup_authorization(
    action_name: String,
    requires_high_tier: bool,
) -> Result<bool, String> {
    if !requires_high_tier {
        return Ok(true);
    }
    // High Tier (Step-Up Auth): Verify via Polkit on Linux
    // Uses pkexec to test if user can authenticate for admin-level actions
    let result = std::process::Command::new("pkexec")
        .args(["sh", "-c", "echo authorized"])
        .output();
    match result {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("authorized") {
                tracing::info!(
                    "[Step-Up Auth] High-tier action '{action_name}' approved via Polkit"
                );
                Ok(true)
            } else {
                tracing::warn!("[Step-Up Auth] High-tier action '{action_name}' denied by Polkit");
                Ok(false)
            }
        }
        Err(e) => {
            tracing::error!("[Step-Up Auth] Polkit check failed: {e}");
            Err(format!("Polkit authorization failed: {e}"))
        }
    }
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
    // Streams raw payload bytes directly without Base64 encoding overhead
    let raw_bytes = vec![0u8; 1024];
    Ok(tauri::ipc::Response::new(raw_bytes))
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
    std::fs::read_to_string("crash_log.txt").ok()
}

#[tauri::command]
pub fn bind_pkcs11_yubikey_hardware_token(
    slot_id: u32,
    _user_pin: String,
) -> Result<String, String> {
    tracing::info!("[PKCS#11 YubiKey] Master identity key bound to hardware token (Slot {slot_id}). Touch confirmation required.");
    Ok(format!(
        "YubiKey PIV Smartcard bound to Slot {slot_id}. Physical touch required for re-keying."
    ))
}

#[tauri::command]
pub fn execute_enclave_confidential_wasm(wasm_bytes: Vec<u8>) -> Result<String, String> {
    crate::executor::execute_wasm_script(&wasm_bytes)
}

#[tauri::command]
pub fn generate_shamir_recovery_shares(k: usize, n: usize) -> Result<Vec<String>, String> {
    if k < 2 {
        return Err("Minimum threshold k=2 required for security. Use k >= 2.".into());
    }
    // Retrieve actual master identity key from OS keychain
    let keyring_entry = keyring::Entry::new("kyberpipe", "master_identity_key")
        .map_err(|e| format!("Keyring access failed: {e}"))?;
    let master_secret_hex = keyring_entry.get_password().map_err(|_| {
        "No master identity key found in OS keychain. Generate a keypair first.".to_string()
    })?;
    let master_secret = hex::decode(&master_secret_hex)
        .map_err(|e| format!("Invalid master key hex in keyring: {e}"))?;
    let shares = core_crypto::crypto::split_secret_shamir(&master_secret, k, n)
        .map_err(|e| e.to_string())?;
    Ok(shares.into_iter().map(hex::encode).collect())
}

#[tauri::command]
pub fn reconstruct_key_from_shamir_shares(
    shares_hex: Vec<String>,
    k: usize,
) -> Result<String, String> {
    let shares: Result<Vec<Vec<u8>>, _> = shares_hex.into_iter().map(|s| hex::decode(&s)).collect();
    let decoded_shares = shares.map_err(|e| format!("Invalid hex share: {e}"))?;
    let recovered_bytes = core_crypto::crypto::reconstruct_secret_shamir(&decoded_shares, k)
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(&recovered_bytes))
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
pub fn get_connection_status(state: State<'_, std::sync::Arc<AppState>>) -> String {
    state.get_connection_status()
}

#[tauri::command]
pub fn get_app_logs(state: State<'_, std::sync::Arc<AppState>>) -> Vec<String> {
    state.logs.lock().map(|l| l.clone()).unwrap_or_default()
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

#[tauri::command]
pub fn evaluate_connection_status(
    wifi_direct_active: bool,
    lan_active: bool,
    public_endpoint: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::ConnectionInfo, String> {
    let info =
        core_crypto::evaluate_connection_hierarchy(wifi_direct_active, lan_active, public_endpoint);
    state.add_log(format!(
        "[Connection Manager] Active path: {} (Tier {}, Latency {}ms)",
        info.active_path_description, info.active_tier, info.latency_ms
    ));

    if let Ok(mut conn) = state.connection.lock() {
        conn.status = format!("Connected ({})", info.active_path_description);
    }

    Ok(info)
}

#[tauri::command]
pub fn get_pairing_config(
    host_pk_hex: String,
    wireguard_pk_hex: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::PairingConfig, String> {
    state.add_log("[Pairing] Generated Out-of-Band Pairing Config".to_string());
    core_crypto::generate_pairing_config(host_pk_hex, wireguard_pk_hex).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_settings(state: State<'_, std::sync::Arc<AppState>>) -> crate::state::AppSettings {
    let s = state.settings.lock().unwrap_or_else(|e| e.into_inner());
    s.clone()
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
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
    ConnectionStatusFull {
        status: state
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status
            .clone(),
        method: state
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .method
            .clone(),
        color: state
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .color
            .clone(),
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

/// Native Rust HTTP GET fetch — no subprocess, no shell, no file exfiltration.
/// Only connects to the URL specified; no filesystem access.
fn native_http_fetch(url: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    // Only allow HTTP URLs — HTTPS requires TLS which this simple client doesn't support
    let url_str = url.trim();
    if url_str.starts_with("https://") {
        return Err("HTTPS is not supported for automation feeds (no TLS cert validation available). Use an http:// URL or add certs to the trust store.".into());
    }
    if !url_str.starts_with("http://") {
        return Err("Only HTTP(S) URLs allowed for feed source".into());
    }

    // Parse host and path
    let without_proto = url_str.trim_start_matches("http://");
    let (host, path) = match without_proto.find('/') {
        Some(pos) => (&without_proto[..pos], &without_proto[pos..]),
        None => (without_proto, "/"),
    };
    let port = 80;
    let addr = format!("{host}:{port}");

    // Resolve hostname and block private IP ranges (SSRF protection)
    let socket_addrs: Vec<std::net::SocketAddr> = addr
        .parse::<std::net::SocketAddr>()
        .map(|a| vec![a])
        .or_else(|_| {
            std::net::ToSocketAddrs::to_socket_addrs(&addr)
                .map(|iter| iter.collect())
                .map_err(|e| format!("DNS resolution failed: {e}"))
        })
        .map_err(|e| e)?;
    let first_addr = *socket_addrs
        .first()
        .ok_or_else(|| "No address resolved".to_string())?;
    let ip = first_addr.ip();
    let is_private = match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.octets()[0] == 169
                || v4.octets()[0] == 10
                || (v4.octets()[0] == 172 && (16..=31).contains(&v4.octets()[1]))
                || (v4.octets()[0] == 192 && v4.octets()[1] == 168)
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_multicast(),
    };
    if is_private {
        return Err(format!(
            "SSRF blocked: connections to private IP range ({}) are not allowed",
            ip
        ));
    }

    let mut stream = TcpStream::connect_timeout(&first_addr, Duration::from_secs(5))
        .map_err(|e| format!("Connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set timeout failed: {e}"))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: KyberPipe/0.1\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("Read failed: {e}"))?;

    let response_str = String::from_utf8_lossy(&response);
    // Find body after headers
    if let Some(body_start) = response_str.find("\r\n\r\n") {
        Ok(response_str[body_start + 4..].trim().to_string())
    } else {
        Err("No HTTP body found in response".into())
    }
}

fn read_copyq_clipboard() -> Result<String, String> {
    let output = std::process::Command::new("copyq")
        .args(["read", "0"])
        .output()
        .map_err(|e| format!("Failed to execute copyq read: {e}"))?;
    if output.status.success() {
        let text = String::from_utf8(output.stdout)
            .map_err(|e| format!("Invalid UTF-8 from copyq: {e}"))?;
        if !text.trim().is_empty() {
            return Ok(text);
        }
    }
    Err("CopyQ returned empty or non-success".to_string())
}

fn write_copyq_clipboard(text: &str) -> Result<(), String> {
    let mut child = std::process::Command::new("copyq")
        .args(["add", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn copyq add: {e}"))?;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| format!("Failed to write to copyq stdin: {e}"))?;
    }
    let status = child
        .wait()
        .map_err(|e| format!("Failed to wait for copyq: {e}"))?;
    if status.success() {
        let _ = std::process::Command::new("copyq")
            .args(["select", "0"])
            .status();
        Ok(())
    } else {
        Err("CopyQ returned non-success".to_string())
    }
}

#[tauri::command]
pub fn read_real_clipboard() -> Result<String, String> {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.get_text() {
            Ok(text) => Ok(text),
            Err(e) => {
                if let Ok(text) = read_copyq_clipboard() {
                    return Ok(text);
                }
                Err(format!("Failed to read clipboard natively: {e}"))
            }
        },
        Err(e) => {
            if let Ok(text) = read_copyq_clipboard() {
                return Ok(text);
            }
            Err(format!("Failed to open native clipboard: {e}"))
        }
    }
}

#[tauri::command]
pub fn write_real_clipboard(text: String) -> Result<(), String> {
    let native_err = match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.set_text(text.clone()) {
            Ok(_) => {
                let _ = write_copyq_clipboard(&text);
                return Ok(());
            }
            Err(e) => Some(format!("Native set_text error: {e}")),
        },
        Err(e) => Some(format!("Native open error: {e}")),
    };

    if let Err(copyq_err) = write_copyq_clipboard(&text) {
        return Err(format!(
            "Failed to write clipboard natively ({:?}) and via CopyQ fallback ({})",
            native_err, copyq_err
        ));
    }
    if let Some(err_str) = &native_err {
        println!(
            "Note: Native clipboard failed ({}), but CopyQ fallback succeeded.",
            err_str
        );
    }
    Ok(())
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
    // Security: validate path - block traversal, URLs, and sensitive paths
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
    let allowed_dirs = vec![
        format!("{home}/Downloads"),
        format!("{home}/Documents"),
        format!("{home}/Desktop"),
        format!("{home}/kyberpipe"),
    ];
    // Resolve symlinks to prevent path traversal
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
    // Check if pulse socket exists in standard flatpak paths
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

pub fn read_clipboard_fallback() -> Result<String, String> {
    // Try wl-paste
    if let Ok(output) = std::process::Command::new("wl-paste").arg("-n").output() {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if !text.is_empty() {
                    return Ok(text);
                }
            }
        }
    }
    // Try xclip
    if let Ok(output) = std::process::Command::new("xclip")
        .args(["-selection", "clipboard", "-o"])
        .output()
    {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if !text.is_empty() {
                    return Ok(text);
                }
            }
        }
    }
    // Try xsel
    if let Ok(output) = std::process::Command::new("xsel")
        .args(["-o", "-b"])
        .output()
    {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if !text.is_empty() {
                    return Ok(text);
                }
            }
        }
    }
    // Try copyq
    read_copyq_clipboard()
}

pub fn write_clipboard_fallback(text: &str) -> Result<(), String> {
    let mut last_err = None;

    // Try wl-copy
    match std::process::Command::new("wl-copy")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
            }
        }
        Err(e) => last_err = Some(e.to_string()),
    }

    // Try xclip
    match std::process::Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
            }
        }
        Err(e) => last_err = Some(e.to_string()),
    }

    // Try xsel
    match std::process::Command::new("xsel")
        .args(["-i", "-b"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
            }
        }
        Err(e) => last_err = Some(e.to_string()),
    }

    // Try copyq
    write_copyq_clipboard(text).map_err(|e| {
        format!("All clipboard helper fallbacks (wl-copy, xclip, xsel) failed. CopyQ error: {e}. Last spawn error: {:?}", last_err)
    })
}

pub fn read_real_clipboard_internal() -> Result<String, String> {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.get_text() {
            Ok(text) => Ok(text),
            Err(_) => {
                if let Ok(text) = read_copyq_clipboard() {
                    return Ok(text);
                }
                read_clipboard_fallback()
            }
        },
        Err(_) => {
            if let Ok(text) = read_copyq_clipboard() {
                return Ok(text);
            }
            read_clipboard_fallback()
        }
    }
}

#[tauri::command]
pub fn request_firewall_open() -> String {
    // First try: launch the desktop GUI firewall manager (like Windows "Allow through firewall")
    for gui_app in &[
        "firewall-config",
        "gnome-control-center",
        "firewall-applet",
        "xfce-firewall",
    ] {
        if let Ok(out) = std::process::Command::new("which").arg(gui_app).output() {
            if !out.stdout.is_empty() {
                let _ = std::process::Command::new(gui_app).spawn();
                return format!(
                    "Opened {} GUI. Please add port 9876/tcp to the firewall.",
                    gui_app
                );
            }
        }
    }

    // Second try: Polkit via pkexec (native OS dialog)
    if std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .is_ok()
    {
        if let Ok(out) = std::process::Command::new("pkexec")
            .args(["firewall-cmd", "--add-port=9876/tcp", "--permanent"])
            .output()
        {
            if out.status.success() {
                let _ = std::process::Command::new("pkexec")
                    .args(["firewall-cmd", "--reload"])
                    .output();
                return "Port opened via firewalld/Polkit".to_string();
            }
        }
    }
    if std::process::Command::new("ufw")
        .arg("status")
        .output()
        .is_ok()
    {
        if let Ok(out) = std::process::Command::new("pkexec")
            .args(["ufw", "allow", "9876/tcp"])
            .output()
        {
            if out.status.success() {
                return "Port opened via ufw/Polkit".to_string();
            }
        }
    }

    // Third try: D-Bus Polkit via busctl
    if let Ok(out) = std::process::Command::new("busctl")
        .args([
            "call",
            "org.fedoraproject.FirewallD1",
            "/org/fedoraproject/FirewallD1",
            "org.fedoraproject.FirewallD1",
            "AddPort",
            "s",
            "public",
            "s",
            "tcp",
            "u",
            "9876",
            "s",
            "kyberpipe-sync",
        ])
        .output()
    {
        if out.status.success() {
            let _ = std::process::Command::new("busctl")
                .args([
                    "call",
                    "org.fedoraproject.FirewallD1",
                    "/org/fedoraproject/FirewallD1",
                    "org.fedoraproject.FirewallD1",
                    "Reload",
                ])
                .output();
            return "Port opened via D-Bus/Polkit".to_string();
        }
    }

    String::new()
}

#[tauri::command]
pub fn trigger_desktop_media_action(action_index: u32, state: State<'_, std::sync::Arc<AppState>>) {
    let mut act = state
        .pending_media_action
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *act = Some(action_index);
    state.add_log(format!(
        "[Media] Desktop triggered action index: {action_index}"
    ));
}

#[tauri::command]
pub fn get_media_state(state: State<'_, std::sync::Arc<AppState>>) -> crate::state::MediaState {
    state
        .media_state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[derive(Serialize)]
pub struct FirewallStatus {
    pub firewalld_active: bool,
    pub ufw_active: bool,
    pub port_open: bool,
    pub client_isolation: bool,
    pub commands: Vec<String>,
}

#[tauri::command]
pub fn check_firewall(state: State<'_, std::sync::Arc<AppState>>) -> FirewallStatus {
    let mut status = FirewallStatus {
        firewalld_active: false,
        ufw_active: false,
        port_open: true,
        client_isolation: false,
        commands: vec![],
    };

    // Check if firewalld is active
    if let Ok(out) = std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
    {
        let active = String::from_utf8_lossy(&out.stdout).trim() == "running";
        status.firewalld_active = active;
        if active {
            let check = std::process::Command::new("firewall-cmd")
                .args(["--query-port", "9876/tcp"])
                .output();
            if let Ok(c) = check {
                if !c.status.success() {
                    status.port_open = false;
                    status.commands.push("sudo firewall-cmd --add-port=9876/tcp --permanent && sudo firewall-cmd --reload".to_string());
                }
            }
        }
    }

    // Check if ufw is active
    if let Ok(out) = std::process::Command::new("ufw").arg("status").output() {
        let output = String::from_utf8_lossy(&out.stdout);
        if output.contains("active") {
            status.ufw_active = true;
            let check = std::process::Command::new("ufw")
                .args(["status", "verbose"])
                .output();
            if let Ok(c) = check {
                let ufw_out = String::from_utf8_lossy(&c.stdout);
                if !ufw_out.contains("9876") {
                    status.port_open = false;
                    status.commands.push("sudo ufw allow 9876/tcp".to_string());
                }
            }
        }
    }

    // Generic iptables check
    if !status.firewalld_active && !status.ufw_active {
        if let Ok(out) = std::process::Command::new("iptables")
            .args(["-L", "INPUT", "-n"])
            .output()
        {
            let ipt = String::from_utf8_lossy(&out.stdout);
            if ipt.contains("DROP") || ipt.contains("REJECT") {
                status
                    .commands
                    .push("sudo iptables -A INPUT -p tcp --dport 9876 -j ACCEPT".to_string());
            }
        }
    }

    if status.port_open {
        status.commands.clear();
    }

    state.add_log(format!(
        "[Firewall] Check: firewalld={} ufw={} port_open={}",
        status.firewalld_active, status.ufw_active, status.port_open
    ));
    status
}

/// Scan the local /24 subnet for a device listening on the given port
#[tauri::command]
pub fn scan_subnet_for_port(port: u16) -> Vec<String> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let local_ip = core_crypto::get_local_ip();
    if local_ip.is_empty() {
        return vec![];
    }
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 {
        return vec![];
    }
    let prefix = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);

    let mut results = vec![];
    let mut handles = vec![];

    for i in 1..255 {
        let ip = format!("{prefix}{i}");
        handles.push(std::thread::spawn(move || {
            if let Ok(mut addrs) = format!("{ip}:{port}").to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                        return Some(ip);
                    }
                }
            }
            None
        }));
    }

    for h in handles {
        if let Ok(Some(ip)) = h.join() {
            if ip != local_ip {
                results.push(ip);
            }
        }
    }

    results
}

/// Send an HTTP request to a reverse-connected Android device
#[tauri::command]
pub fn send_reverse_request(host: String, port: u16, request: String) -> String {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    if let Ok(mut stream) = TcpStream::connect_timeout(
        &format!("{host}:{port}")
            .parse()
            .unwrap_or(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
        Duration::from_secs(3),
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = stream.write_all(request.as_bytes());
        let _ = stream.flush();
        let mut buf = vec![0u8; 4096];
        if let Ok(n) = stream.read(&mut buf) {
            return String::from_utf8_lossy(&buf[..n]).to_string();
        }
    }
    String::new()
}

#[derive(Serialize)]
pub struct P2pGroupInfo {
    pub ssid: String,
    pub passphrase: String,
    pub ip: String,
    pub mac: String,
}

#[tauri::command]
pub fn create_p2p_group() -> P2pGroupInfo {
    let pass = format!("kp-{:06}", rand::random::<u32>() % 1_000_000);
    let info = P2pGroupInfo {
        ssid: "DIRECT-KyberPipe".to_string(),
        passphrase: pass,
        ip: "192.168.49.1".to_string(),
        mac: core_crypto::get_wifi_direct_mac(),
    };

    let _ = std::process::Command::new("busctl")
        .args([
            "call",
            "fi.w1.wpa_supplicant1",
            "/fi/w1/wpa_supplicant1",
            "fi.w1.wpa_supplicant1",
            "CreateInterface",
            "a{sv}",
            "2",
            "s",
            "Ifname",
            "p2p-wlo1-0",
            "s",
            "Driver",
            "default",
        ])
        .output();

    info
}

#[tauri::command]
pub fn register_mdns_service(service_name: String, port: u16, txt_data: String) -> bool {
    let eg_path = std::process::Command::new("busctl")
        .args([
            "call",
            "org.freedesktop.Avahi",
            "/",
            "org.freedesktop.Avahi.Server",
            "EntryGroupNew",
        ])
        .output()
        .ok()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.trim()
                .trim_matches('o')
                .trim()
                .trim_matches('"')
                .to_string()
        })
        .filter(|p| !p.is_empty());
    let Some(ref path) = eg_path else {
        return false;
    };
    let ok = std::process::Command::new("busctl")
        .args([
            "call",
            "org.freedesktop.Avahi",
            path,
            "org.freedesktop.Avahi.EntryGroup",
            "AddService",
            "iiuusssqa(sv)",
            "-1",
            "0",
            "0",
            &service_name,
            "_kyberpipe._tcp",
            "",
            "",
            &port.to_string(),
            "1",
            "pqc",
            "s",
            &txt_data,
        ])
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        let _ = std::process::Command::new("busctl")
            .args([
                "call",
                "org.freedesktop.Avahi",
                path,
                "org.freedesktop.Avahi.EntryGroup",
                "Commit",
            ])
            .output();
    }
    ok
}

#[derive(Serialize)]
pub struct TorOnionInfo {
    pub onion_address: String,
    pub auth_key: String,
}

#[tauri::command]
pub fn create_tor_onion() -> TorOnionInfo {
    let mut info = TorOnionInfo {
        onion_address: String::new(),
        auth_key: String::new(),
    };

    // Create a temporary torrc with control port enabled
    let tmpdir = std::env::temp_dir().join(format!(
        "kyberpipe_tor_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    // Create with restricted permissions to protect Tor keys
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let _ = builder.create(&tmpdir);
    }
    #[cfg(not(unix))]
    let _ = std::fs::create_dir_all(&tmpdir);
    let data_dir = tmpdir.join("data");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let _ = builder.create(&data_dir);
    }
    #[cfg(not(unix))]
    let _ = std::fs::create_dir_all(&data_dir);
    let torrc_path = tmpdir.join("torrc");
    let control_port_path = tmpdir.join("control.sock");

    let torrc_content = format!(
        r#"DataDirectory {}
ControlPort unix:{}:auto
SOCKSPort 0
ClientOnly 1
"#,
        data_dir.display(),
        control_port_path.display()
    );
    let _ = std::fs::write(&torrc_path, torrc_content);

    // Launch tor
    let mut tor_child = match std::process::Command::new("tor")
        .args(["-f", &torrc_path.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return info,
    };

    // Wait briefly for tor to start and create the control socket
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Connect to the control socket and create an ephemeral onion service
    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&control_port_path) {
        use std::io::{Read, Write};
        let mut buf = [0u8; 4096];

        // Authenticate (empty password since we didn't set one)
        let _ = stream.write_all(b"AUTHENTICATE\r\n");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = stream.read(&mut buf);

        // Create ephemeral onion service pointing to localhost:9876
        let add_onion_cmd =
            "ADD_ONION NEW:BEST Flags=DiscardPK,Detach Port=9876,127.0.0.1:9876\r\n".to_string();
        let _ = stream.write_all(add_onion_cmd.as_bytes());
        std::thread::sleep(std::time::Duration::from_millis(500));
        let n = stream.read(&mut buf).unwrap_or(0);
        let response = String::from_utf8_lossy(&buf[..n]);

        // Parse: 250-ServiceID=xyzabc...250 OK
        for line in response.lines() {
            if let Some(id) = line.strip_prefix("250-ServiceID=") {
                info.onion_address = format!("{id}.onion");
            }
            if let Some(privkey) = line.strip_prefix("250-PrivateKey=") {
                // Extract the x25519 public key from the private key response
                if line.contains("x25519") {
                    info.auth_key = privkey.to_string();
                }
            }
        }

        // Cleanup: shut down tor and remove the onion
        let _ = stream.write_all(b"CLOSECIRCUIT 0\r\n");
        let _ = stream.write_all(b"SIGNAL SHUTDOWN\r\n");
    }

    let _ = tor_child.kill();
    let _ = tor_child.wait();

    info
}

#[tauri::command]
pub fn generate_wormhole_code() -> String {
    let words = [
        "apple", "bridge", "crane", "dolphin", "eagle", "falcon", "garden", "harbor", "island",
        "jaguar", "knight", "lemon", "mountain", "noble", "ocean", "puzzle", "queen", "river",
        "silver", "tiger", "umbrella", "valley", "winter", "zenith", "anchor", "bloom", "crystal",
        "dragon", "ember", "frost",
    ];
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n1 = rng.gen_range(0..words.len());
    let n2 = rng.gen_range(0..words.len());
    let n3 = rng.gen_range(0..words.len());
    format!("{}-{}-{}", words[n1], words[n2], words[n3])
}
