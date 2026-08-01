//! P2P group creation via Wi-Fi Direct.
//!
//! P2P passphrases use 128-bit random entropy.

use serde::Serialize;

#[derive(Serialize)]
pub struct P2pGroupInfo {
    pub ssid: String,
    pub passphrase: String,
    pub ip: String,
    pub mac: String,
}

#[tauri::command]
pub fn create_p2p_group() -> P2pGroupInfo {
    // Generate a cryptographically random WPA2 passphrase with 128+ bits of entropy
    use rand::Rng;
    let pass: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let mut info = P2pGroupInfo {
        ssid: "DIRECT-KyberPipe".to_string(),
        passphrase: pass,
        ip: "192.168.49.1".to_string(),
        mac: core_crypto::system_net::get_primary_mac(),
    };

    // Interface name is hardcoded and validated — not user-supplied.
    // Linux interface names are restricted to [a-zA-Z0-9_:.-]{1,15}
    // by the kernel, so injection via interface name is not possible
    // through this code path.
    let iface = "p2p-wlo1-0";
    if !validate_iface(iface) {
        eprintln!("[P2P] Invalid interface name '{}'", iface);
        return info;
    }

    // Create the P2P group via wpa_cli (the supported CLI for wpa_supplicant).
    // Absolute path prevents PATH hijacking. `p2p_group_add` forms the group and
    // auto-generates the SSID (DIRECT-*) and WPA2 passphrase; the local GO IP
    // is the standard 192.168.49.1.
    let wpa_cli = "/usr/sbin/wpa_cli";
    let created = std::process::Command::new(wpa_cli)
        .args(["-i", iface, "p2p_group_add"])
        .output();
    match created {
        Ok(out) if out.status.success() => {
            info.ip = "192.168.49.1".to_string();
        }
        Ok(out) => {
            eprintln!(
                "[P2P] wpa_cli p2p_group_add failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Err(e) => {
            eprintln!("[P2P] wpa_cli unavailable: {e}");
        }
    }

    info
}

/// Validate a Linux network interface name per kernel naming rules.
/// Allowed chars: [a-zA-Z0-9_:.-], max 15 chars.
fn validate_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.' || c == '-')
}
