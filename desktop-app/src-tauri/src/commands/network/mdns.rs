//! mDNS service registration via Avahi/D-Bus.
//!
//! Local service advertisement for peer discovery.

/// The desktop's ML-DSA beacon signing public key (hex). Embedded in the
/// pairing QR (`beacon_signing_pk`) so the phone can, AFTER pairing, reject
/// LAN beacons whose embedded signing key is not the paired desktop's — the
/// exact `listen_for_beacons_with_expected_key` check the Rust side performs
/// (audit finding #5). A plain Tauri command (NOT UniFFI), so it does not
/// disturb the FFI surface.
#[tauri::command]
pub fn get_beacon_signing_key() -> String {
    core_crypto::network::device_signing_public_key_hex()
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
        .and_then(|o| {
            // busctl prints:  o "/org/freedesktop/Avahi/EntryGroup1"
            let s = String::from_utf8_lossy(&o.stdout);
            // Extract the quoted object path robustly (tolerant of whitespace,
            // trailing garbage, and the leading 'o' type tag).
            let first_quote = s.find('"')?;
            let rest = &s[first_quote + 1..];
            let end_quote = rest.find('"')?;
            let path = rest[..end_quote].to_string();
            if path.starts_with("/org/freedesktop/Avahi/") && !path.is_empty() {
                Some(path)
            } else {
                None
            }
        });
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
