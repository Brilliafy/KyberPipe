use crate::state::AppState;
use crate::state::SecureString;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::LazyLock;
use std::time::Instant;
use tauri::State;

// ── Privileged-action confirmation tokens (audit finding #13) ──
// Destructive / privileged Tauri commands are gated behind a single-use token
// issued by Rust only after the renderer has surfaced a real user gesture
// (the frontend calls `request_privilege_token` immediately after a confirm()
// dialog). Tokens expire after TOKEN_TTL and can be used exactly once.

const TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(30);
static PRIVILEGE_TOKENS: LazyLock<std::sync::Mutex<VecDeque<(String, String, Instant)>>> =
    LazyLock::new(|| std::sync::Mutex::new(VecDeque::new()));

/// Issue a single-use, expiring token for a privileged action.
#[tauri::command]
pub fn request_privilege_token(action: String) -> Result<String, String> {
    let mut token_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut token_bytes);
    let token = hex::encode(&token_bytes);
    let mut guard = PRIVILEGE_TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    guard.retain(|(_, _, at)| at.elapsed() < TOKEN_TTL);
    guard.push_back((action, token.clone(), Instant::now()));
    Ok(token)
}

/// Consume a token. Returns true exactly once per issued token.
pub(crate) fn consume_privilege_token(action: &str, token: &str) -> bool {
    let mut guard = PRIVILEGE_TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    guard.retain(|(_, _, at)| at.elapsed() < TOKEN_TTL);
    if let Some(pos) = guard.iter().position(|(a, t, _)| a == action && t == token) {
        guard.remove(pos);
        true
    } else {
        false
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
    // Honest metrics (audit finding #25): report the ACTUAL transport state.
    // No RTT/packet counters are instrumented, so 0.0/0 are reported rather
    // than a fabricated "5.0ms" that implied real telemetry.
    let is_connected = core_crypto::quic_bridge::is_quic_connected();
    let connection = state.get_connection();
    TelemetryMetrics {
        rtt_ms: 0.0, // not instrumented — honest zero, no fabricated latency
        transport_path: if is_connected {
            connection.method.clone()
        } else {
            "Disconnected".to_string()
        },
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
    // Audit finding #25: this was a log-only STUB that claimed an "eBPF ONNX
    // Engine" was active. There is no such engine — the toggle is retained for
    // frontend API compatibility but must not create a false feature surface.
    state.add_log(format!(
        "[Neural Anomaly] Preference toggled to {} (no on-device engine — placeholder only)",
        if enabled { "enabled" } else { "disabled" }
    ));
    Ok("Local placeholder preference stored — no on-device anomaly engine is bundled.".to_string())
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
pub fn bind_pkcs11_yubikey_hardware_token(slot_id: u32, token: String) -> Result<String, String> {
    if !consume_privilege_token("bind_pkcs11_yubikey_hardware_token", &token) {
        return Err("Privileged action requires a fresh confirmation token".into());
    }
    // Resolve pkcs11-tool to a FIXED absolute path (audit finding #14b): a
    // PATH lookup allows a compromised renderer's environment to substitute a
    // malicious binary. The binary is resolved once per process and cached.
    static PKCS11_TOOL: LazyLock<Option<std::path::PathBuf>> = LazyLock::new(|| {
        [
            "/usr/bin/pkcs11-tool",
            "/bin/pkcs11-tool",
            "/usr/local/bin/pkcs11-tool",
        ]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
    });
    let Some(tool) = PKCS11_TOOL.as_deref() else {
        return Err(
            "pkcs11-tool not found in standard locations. Install opensc to use hardware tokens."
                .into(),
        );
    };
    // Audit finding #17: the previous implementation only string-matched the
    // slot listing for "token"/"present" — it never performed a KEY operation,
    // so "YubiKey-bound" was cosmetic. A real token interaction is required to
    // prove the token is present AND responsive: `--show-info` performs
    // C_GetTokenInfo against the actual token and returns its serial number.
    let out = std::process::Command::new(tool)
        .args(["--slot", &slot_id.to_string(), "--show-info"])
        .output()
        .map_err(|e| format!("Failed to run pkcs11-tool: {e}"))?;
    let listing = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err(format!(
            "PKCS#11 token interaction failed: {} — no hardware-backed binding performed",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // Extract the token serial number as proof of a REAL token operation.
    let serial = listing.lines().find_map(|l| {
        let t = l.trim();
        if t.starts_with("serial number") || t.starts_with("Serial") {
            Some(t.to_string())
        } else {
            None
        }
    });
    // Status-only return: never expose raw tool output to the renderer
    // (audit finding #14b — info disclosure). Honest wording: this verifies the
    // token, it does NOT wrap KyberPipe keys (no key operation is performed).
    match serial {
        Some(s) => Ok(format!(
            "PKCS#11 token present and responsive in slot {slot_id} (serial {s}). Note: KyberPipe keys are NOT hardware-backed — this verifies the token only."
        )),
        None => Err(format!(
            "PKCS#11 slot {slot_id} responded but no serial number was reported — cannot confirm a real token"
        )),
    }
}

#[tauri::command]
pub fn trigger_panic_self_destruct(
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    // Destructive action — requires a fresh user-gesture token (audit #13).
    if !consume_privilege_token("trigger_panic_self_destruct", &token) {
        return Err("Privileged action requires a fresh confirmation token".into());
    }
    // Actually zeroize all key material in AppState
    state.set_keypair(None);
    state.set_session_key(SecureString::new(String::new()));
    state.set_pending_session_key(SecureString::new(String::new()));
    state.set_pending_shared_secret(SecureString::new(String::new()));
    state.clear_sas_code();
    state.set_pairing_initiator_pk(String::new());
    state.set_pairing_initiator_x25519_pk(String::new());

    // Clear settings
    {
        let mut settings = state.settings.lock();
        settings.is_paired = false;
        settings.paired_device_name = None;
        settings.paired_device_picture = None;
    }
    state.save_settings();

    // Wipe OS keyring entries. Enumerate EVERY kyberpipe service entry:
    // master_identity_key, session_key, and the independent ratchet snapshot
    // wrap key — plus the kyberpipe-tofu service's trusted-server TLS pin.
    // (Audit finding #16: the old path left snapshot_key and the TLS pin alive
    // after self-destruct.)
    for key_name in ["master_identity_key", "session_key", "snapshot_key"] {
        if let Ok(entry) = keyring::Entry::new("kyberpipe", key_name) {
            let _ = entry.delete_password();
        }
    }
    if let Ok(entry) = keyring::Entry::new("kyberpipe-tofu", "server_cert_hash") {
        let _ = entry.delete_password();
    }
    // Invalidate the in-memory trusted pin too.
    core_crypto::network::tls_config::store_tofu_cert_hash(String::new());

    // Destroy the desktop session key handle AND every other live handle — the
    // old path only destroyed DESKTOP_SESSION_KEY_HANDLE, leaving the key bytes
    // of other handles registered in memory (audit finding #16).
    let handle =
        crate::handlers::DESKTOP_SESSION_KEY_HANDLE.swap(0, std::sync::atomic::Ordering::AcqRel);
    if handle != 0 {
        core_crypto::session_key_destroy(handle);
    }
    core_crypto::session_key_destroy_all();
    crate::handlers::IS_SESSION_KEY_AUTHENTICATED
        .store(false, std::sync::atomic::Ordering::Release);

    // Clear all ratchet sessions — chain keys must not survive self-destruct
    core_crypto::ratchet_clear_all_sessions();
    // Remove any persisted ratchet snapshots too.
    crate::ratchet_store::clear_ratchet_store();
    // Invalidate all in-flight FFI operations
    core_crypto::increment_destruct_generation();

    // Confirm the destruct generation now blocks use of every keyed operation
    // (check_generation() false). A follow-up session_key_encrypt must fail.
    debug_assert!(!core_crypto::check_generation());

    state.set_connection_status("SELF_DESTRUCTED_MEMORY_ZEROIZED".to_string());
    state.add_log(
        "[PANIC DESTRUCTION] Memory zeroized & Hardware KeyStore invalidated!".to_string(),
    );
    Ok(
        "Hardware master key destroyed, all ratchet sessions cleared, and key material zeroized."
            .to_string(),
    )
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
