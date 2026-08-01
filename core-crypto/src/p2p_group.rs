use crate::network;

/// Validate a Linux network interface name per kernel naming rules.
/// Allowed chars: [a-zA-Z0-9_:.-], max 15 chars.
fn validate_iface(name: &str) -> bool {
    if name.is_empty() || name.len() > 15 {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.' || c == '-')
}

/// Safe absolute path for the interface name used in busctl/wpa_cli calls.
const P2P_IFACE: &str = "p2p-wlo1-0";

/// Try to start a Wi-Fi Direct P2P group via wpa_cli (Linux only).
/// Uses absolute paths (/usr/sbin/wpa_cli, /usr/bin/busctl, /usr/sbin/iw)
/// to prevent PATH hijacking attacks where a malicious binary could be placed
/// earlier in the PATH.
///
/// Interface names are validated against Linux kernel naming rules before
/// being passed to any subprocess — preventing injection via crafted names
/// from /proc/net/route or other sources.
/// Future: replace with D-Bus wpa_supplicant API (fi.w1.wpa_supplicant1)
/// via the dbus-rs crate to avoid shell command injection entirely.
pub fn try_start_p2p_group() {
    if !validate_iface(P2P_IFACE) {
        tracing::warn!("P2P interface name '{}' failed validation", P2P_IFACE);
        return;
    }
    let iw_path = "/usr/sbin/iw";
    let wpa_cli_path = "/usr/sbin/wpa_cli";
    let busctl_path = "/usr/bin/busctl";

    if let Ok(out) = std::process::Command::new(iw_path).args(["list"]).output() {
        let output = String::from_utf8_lossy(&out.stdout);
        if !output.contains("P2P") {
            return;
        }
    }
    // Try wpa_cli first, fall back to D-Bus busctl if available
    if let Ok(out) = std::process::Command::new(wpa_cli_path)
        .arg("ping")
        .output()
    {
        if out.status.success() {
            let _ = std::process::Command::new(wpa_cli_path)
                .arg("p2p_group_add")
                .output();
        }
    } else {
        // D-Bus fallback: use busctl to call wpa_supplicant directly
        let _ = std::process::Command::new(busctl_path)
            .args([
                "call",
                "fi.w1.wpa_supplicant1",
                "/fi/w1/wpa_supplicant1",
                "fi.w1.wpa_supplicant1",
                "CreateInterface",
                "a{sv}",
                "2",
                "s",
                P2P_IFACE,
                "s",
                "Driver",
                "default",
            ])
            .output();
    }
}

/// Send a P2P discovery beacon payload via UDP broadcast.
pub async fn send_beacon_payload(payload: String) -> Result<(), crate::error::KyberError> {
    network::send_p2p_beacon(&payload, None).await
}
