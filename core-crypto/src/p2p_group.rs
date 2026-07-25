use crate::network;

/// Try to start a Wi-Fi Direct P2P group via wpa_cli (Linux only).
/// Future: replace with D-Bus wpa_supplicant API (fi.w1.wpa_supplicant1)
/// to avoid shell command injection and manage concurrent P2P interfaces.
pub fn try_start_p2p_group() {
    if let Ok(out) = std::process::Command::new("iw").args(["list"]).output() {
        let output = String::from_utf8_lossy(&out.stdout);
        if !output.contains("P2P") {
            return;
        }
    }
    // Try wpa_cli first, fall back to D-Bus busctl if available
    if let Ok(out) = std::process::Command::new("wpa_cli").arg("ping").output() {
        if out.status.success() {
            let _ = std::process::Command::new("wpa_cli")
                .arg("p2p_group_add")
                .output();
        }
    } else {
        // D-Bus fallback: use busctl to call wpa_supplicant directly
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
    }
}

/// Send a P2P discovery beacon payload via UDP broadcast.
pub async fn send_beacon_payload(payload: String) -> Result<(), crate::error::KyberError> {
    network::send_p2p_beacon(&payload, None).await
}
