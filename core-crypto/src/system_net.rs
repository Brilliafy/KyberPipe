/// Get the system's local IP address by connecting to a known external UDP endpoint.
pub fn get_system_local_ip() -> String {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                let ip = addr.ip().to_string();
                if !ip.is_empty() && ip != "0.0.0.0" {
                    return ip;
                }
            }
        }
    }
    String::new()
}

use std::sync::OnceLock;

fn device_id() -> &'static str {
    static DID: OnceLock<String> = OnceLock::new();
    DID.get_or_init(|| {
        // Generate a random device identifier once per install / config reset.
        // Not derived from hardware MAC — which is randomized on Android 10+
        // and can be spoofed on Linux. MAC-based IDs are fingerprintable
        // across networks even when hashed.
        let random_bytes: [u8; 16] = rand::random();
        hex::encode(random_bytes)
    })
}

/// Read the primary MAC address from /sys/class/net/<default_iface>/address.
/// DEPRECATED: Returns a random per-install device ID instead of a hardware-derived
/// identifier. Hardware MAC addresses are randomized on modern OSes and are
/// fingerprintable across networks even when hashed.
pub fn get_primary_mac() -> String {
    let _ = get_default_interface(); // keep side effect for interface discovery
    device_id().to_string()
}

/// Get the default network interface by parsing /proc/net/route.
pub fn get_default_interface() -> String {
    if let Ok(route) = std::fs::read_to_string("/proc/net/route") {
        for line in route.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts.get(1) == Some(&"00000000") {
                let iface = parts[0].to_string();
                // Validate: Linux interface names are [a-zA-Z0-9_:.-]{1,15}
                if !iface.is_empty()
                    && iface.len() <= 15
                    && iface.chars().all(|c| {
                        c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.' || c == '-'
                    })
                {
                    return iface;
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let iface = entry.file_name().to_string_lossy().to_string();
            if iface == "lo" {
                continue;
            }
            // Validate interface name
            if !iface.is_empty()
                && iface.len() <= 15
                && iface.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.' || c == '-'
                })
            {
                return iface;
            }
        }
    }
    String::new()
}
