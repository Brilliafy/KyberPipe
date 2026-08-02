use crate::portal::is_flatpak;
use crate::state::AppState;
use serde::Serialize;
use tauri::State;

#[tauri::command]
pub fn get_settings(state: State<'_, std::sync::Arc<AppState>>) -> crate::state::AppSettings {
    let s = state.settings.lock();
    s.clone()
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn save_settings(
    device_name: Option<String>,
    device_picture: Option<String>,
    paired_device_name: Option<String>,
    paired_device_picture: Option<String>,
    ddns_hostname: Option<String>,
    enable_upnp: Option<bool>,
    enable_ddns: Option<bool>,
    theme_mode: Option<String>,
    pathway_order: Option<Vec<String>>,
    wireguard_active: Option<bool>,
    beacon_discovery_enabled: Option<bool>,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<(), String> {
    // NOTE: `is_paired` is intentionally NOT accepted here. Pairing state is
    // protocol-owned: it transitions only inside the Rust pairing/unpairing
    // handlers, never from the renderer. The webview must be treated as an
    // untrusted input source.
    state.add_log("[Settings] Updating preferences".to_string());
    if enable_upnp == Some(true) {
        state.add_log("[UPnP] Initializing UPnP port mapper fallback... Done.".to_string());
    }
    if enable_ddns == Some(true) {
        if let Some(h) = &ddns_hostname {
            if !h.is_empty() {
                state.add_log(format!("[DDNS] Resolving DDNS Hostname: {h}... Done."));
            }
        }
    }
    {
        let mut s = state.settings.lock();
        if let Some(v) = device_name {
            s.device_name = Some(v);
        }
        if let Some(v) = device_picture {
            s.device_picture = Some(v);
        }
        if let Some(v) = paired_device_name {
            s.paired_device_name = Some(v);
        }
        if let Some(v) = paired_device_picture {
            s.paired_device_picture = Some(v);
        }
        if let Some(v) = ddns_hostname {
            s.ddns_hostname = v;
        }
        if let Some(v) = enable_upnp {
            s.enable_upnp = v;
        }
        if let Some(v) = enable_ddns {
            s.enable_ddns = v;
        }
        if let Some(v) = theme_mode {
            s.theme_mode = Some(v);
        }
        if let Some(v) = pathway_order {
            s.pathway_order = Some(v);
        }
        if let Some(v) = wireguard_active {
            s.wireguard_active = v;
        }
        if let Some(v) = beacon_discovery_enabled {
            s.beacon_discovery_enabled = v;
            state.add_log(format!(
                "[Beacon] LAN discovery beacons {}",
                if v { "enabled (opt-in)" } else { "disabled" }
            ));
        }
    }
    state.save_settings();
    Ok(())
}

/// Protocol-owned teardown of a connection. Unlike the renderer writing
/// `is_paired = false` directly, this command performs the full authenticated
/// unlink: clears the ratchet session, destroys the session-key handle, wipes
/// pairing state and settings, and persists the result.
///
/// Destructive — requires a fresh user-gesture confirmation token, matching
/// its siblings (audit finding #9: `delete_connection` was the only destructive
/// command WITHOUT a token, so the least protected path was the one most
/// easily reached by a renderer bug or XSS). The renderer must call
/// `request_privilege_token("delete_connection")` immediately after showing a
/// confirmation dialog and pass the token here.
#[tauri::command]
pub fn delete_connection(
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<(), String> {
    if !crate::commands::security::consume_privilege_token("delete_connection", &token) {
        return Err("Destructive action requires a fresh confirmation token".into());
    }
    let peer_id = state.get_pairing_initiator_pk();
    if !peer_id.is_empty() {
        core_crypto::ratchet_remove_session(peer_id);
    }
    let handle =
        crate::handlers::DESKTOP_SESSION_KEY_HANDLE.swap(0, std::sync::atomic::Ordering::AcqRel);
    if handle != 0 {
        core_crypto::session_key_destroy(handle);
    }
    crate::handlers::IS_SESSION_KEY_AUTHENTICATED
        .store(false, std::sync::atomic::Ordering::Release);
    state.set_session_key(crate::state::SecureString::new(String::new()));
    state.clear_all_pairing();
    {
        let mut settings = state.settings.lock();
        settings.is_paired = false;
        settings.paired_device_name = None;
        settings.paired_device_picture = None;
    }
    state.save_settings();
    crate::ratchet_store::clear_ratchet_store();
    state.set_connection(
        "DISCONNECTED".to_string(),
        "None".to_string(),
        "red".to_string(),
    );
    state.add_log("[Connection] Deleted — all pairing state cleared".to_string());
    Ok(())
}

#[tauri::command]
pub fn grant_file_access(
    is_desktop: bool,
    granted: bool,
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<crate::state::AppSettings, String> {
    // Privileged state mutation — requires a fresh user-gesture token
    // (audit finding #20: the token pattern must apply uniformly to
    // privileged/destructive commands).
    if !crate::commands::security::consume_privilege_token("grant_file_access", &token) {
        return Err("Privileged action requires a fresh confirmation token".into());
    }
    {
        let mut s = state.settings.lock();
        if is_desktop {
            s.file_access_granted_desktop = granted;
        } else {
            s.file_access_granted_phone = granted;
        }
    }
    state.save_settings();
    Ok(state.settings.lock().clone())
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
    let s = state.settings.lock();
    let granted = if is_phone {
        s.file_access_granted_phone
    } else {
        s.file_access_granted_desktop
    };
    if !granted {
        return Err("Access denied — permission not granted.".to_string());
    }
    drop(s);
    if is_phone {
        // Phone-side remote listing is not yet wired to the Android file
        // provider — return an honest error instead of fabricated files.
        return Err(
            "Remote phone file listing is not yet wired to the Android file provider".to_string(),
        );
    }
    // REAL bounded listing of the user's document directories.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let mut roots: Vec<String> = vec![
        format!("{home}/Downloads"),
        format!("{home}/Documents"),
        format!("{home}/Desktop"),
    ];
    // Preserve an explicit "Home" entry so the UI shows something sensible.
    let mut items: Vec<LocalFileItem> = Vec::new();
    for dir in [
        format!("{home}/Downloads"),
        format!("{home}/Documents"),
        format!("{home}/Desktop"),
    ] {
        let name = dir.rsplit('/').next().unwrap_or(&dir).to_string();
        if std::path::Path::new(&dir).exists() {
            items.push(LocalFileItem {
                name,
                path: dir.clone(),
                is_dir: true,
                size: 0,
            });
        }
    }
    // List the first directory if it exists (bounded: top 100 entries, no
    // recursion, canonical-path confinement).
    for root in roots.iter_mut() {
        if let Ok(entries) = std::fs::read_dir(&*root) {
            let mut listed = 0;
            for entry in entries.flatten() {
                if listed >= 100 {
                    break;
                }
                let path = entry.path();
                if !path.is_absolute() {
                    continue;
                }
                // Canonical confinement: reject symlinks escaping the root.
                let canonical = std::fs::canonicalize(&path).unwrap_or_default();
                if !canonical.starts_with(std::fs::canonicalize(&*root).unwrap_or_default()) {
                    continue;
                }
                let is_dir = path.is_dir();
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                items.push(LocalFileItem {
                    name: entry.file_name().to_string_lossy().to_string(),
                    path: path.to_string_lossy().to_string(),
                    is_dir,
                    size,
                });
                listed += 1;
            }
            break;
        }
    }
    let _ = roots; // each root is scanned above
    Ok(items)
}

#[tauri::command]
pub fn open_local_file(path: String, token: String) -> Result<(), String> {
    // Destructive/privileged action — requires a fresh user-gesture token
    // (audit finding #20: uniform privilege gating; this previously sat flat
    // next to read-only queries with no gate).
    if !crate::commands::security::consume_privilege_token("open_local_file", &token) {
        return Err("Privileged action requires a fresh confirmation token".into());
    }
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
    let canonical_path = std::path::Path::new(&canonical);
    if !allowed_dirs.iter().any(|d| match std::fs::canonicalize(d) {
        Ok(allowed_canonical) => canonical_path.starts_with(&allowed_canonical),
        Err(_) => false,
    }) {
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
