//! External URL opening (AUDIT F17).
//!
//! The legacy setup granted the renderer `opener:default` (the Tauri opener
//! plugin capability), letting a compromised renderer trigger arbitrary URL
//! schemes — including `file://` and registered protocol handlers — without a
//! token. All link-opening now flows through [`open_external_url`], which
//! requires the same native-gesture token as every other privileged action and
//! validates the URL scheme (and the pairing deep-link payload) against an
//! allowlist before handing it to the OS.

use std::io::Read;

/// AUDIT F17: token-gated external URL opener with a scheme allowlist.
///
/// Allowed schemes:
///  - `https://…` — normal web links (host required, no embedded credentials).
///  - `mailto:…` — mail links (valid address).
///  - `kyberpipe://pair?data=…` — the pairing deep link, with the Android
///    DeepLinkHandler's origin + payload validation mirrored in Rust.
///
/// Everything else (`file://`, `javascript:`, `data:`, `http://`, custom
/// handlers) is rejected before any OS call.
#[tauri::command]
pub fn open_external_url(url: String, token: String) -> Result<(), String> {
    // Uniform Tier-2 gate (audit finding #20): a fresh user-gesture token is
    // required — a compromised renderer can only trigger the native dialog,
    // never open a URL directly.
    crate::commands::security::consume_privilege_token("open_external_url", &token)
        .then_some(())
        .ok_or_else(|| "Opening external URLs requires a fresh user-gesture token".to_string())?;

    if url.is_empty() || url.chars().count() > 2048 {
        return Err("URL must be non-empty and bounded in length".to_string());
    }
    let scheme = url.split("://").next().unwrap_or("").to_lowercase();
    let allowed = match scheme.as_str() {
        "https" => validate_https_url(&url),
        "mailto" => validate_mailto_url(&url),
        "kyberpipe" => validate_pairing_deep_link(&url),
        _ => false,
    };
    if !allowed {
        return Err(format!(
            "URL scheme/content not permitted (AUDIT F17 allowlist: https, mailto, kyberpipe://pair): {scheme}"
        ));
    }

    // Open with the OS default handler. A missing handler (e.g. nothing
    // registered for kyberpipe://) is surfaced, not silently swallowed.
    std::process::Command::new("xdg-open")
        .arg(&url)
        .spawn()
        .map_err(|e| format!("Failed to open URL: {e}"))?;
    Ok(())
}

/// An https URL must have a non-empty host, no embedded credentials and no
/// whitespace/control characters.
fn validate_https_url(url: &str) -> bool {
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => return false,
    };
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains(char::is_whitespace)
        || rest.chars().any(char::is_control)
    {
        return false;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty()
}

/// A mailto URL must carry a valid-looking address (local part, '@', dot-ful
/// domain).
fn validate_mailto_url(url: &str) -> bool {
    let addr = url
        .strip_prefix("mailto:")
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    match addr.find('@') {
        Some(i) if i > 0 && i < addr.len() - 1 => addr[i + 1..].contains('.'),
        _ => false,
    }
}

/// `kyberpipe://pair?data=…` — mirrors the Android DeepLinkHandler validation:
/// the host MUST be `pair`, the payload MUST arrive as the `data` query
/// parameter, and the decoded base64(zlib) payload MUST carry a 32-hex
/// `pairing_nonce_hex` and a 64-hex `server_cert_hash`. A link missing either
/// (or carrying raw data outside `data=`) is rejected.
fn validate_pairing_deep_link(url: &str) -> bool {
    let rest = match url.strip_prefix("kyberpipe://") {
        Some(r) => r,
        None => return false,
    };
    let (host, query) = match rest.split_once('?') {
        Some((h, q)) => (h, q),
        None => (rest, ""),
    };
    if host != "pair" {
        return false;
    }
    let data = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("data="))
        .unwrap_or("");
    if data.is_empty() {
        return false;
    }
    validate_pairing_payload(data)
}

/// Decode base64(zlib) and verify the embedded pairing token + cert pin.
fn validate_pairing_payload(data: &str) -> bool {
    let decoded = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let mut out = Vec::new();
    let ok = flate2::read::ZlibDecoder::new(decoded.as_slice())
        .read_to_end(&mut out)
        .is_ok();
    if !ok {
        return false;
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out) else {
        return false;
    };
    let nonce = json
        .get("pairing_nonce_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cert_hash = json
        .get("server_cert_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let nonce_ok =
        !nonce.is_empty() && nonce.len() == 32 && nonce.chars().all(|c| c.is_ascii_hexdigit());
    let cert_ok = !cert_hash.is_empty()
        && cert_hash.len() == 64
        && cert_hash.chars().all(|c| c.is_ascii_hexdigit());
    nonce_ok && cert_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_allowlist_validates() {
        assert!(validate_https_url("https://example.com/path?q=1#frag"));
        assert!(validate_https_url("https://192.168.1.50:9876"));
        assert!(!validate_https_url("https://user@example.com"));
        assert!(!validate_https_url("https://"));
        assert!(!validate_https_url("http://example.com"));
        assert!(!validate_https_url("file:///etc/passwd"));
        assert!(!validate_https_url("javascript:alert(1)"));
        assert!(!validate_https_url("data:text/plain;base64,AAAA"));

        assert!(validate_mailto_url("mailto:user@example.com"));
        assert!(!validate_mailto_url("mailto:user@"));
        assert!(!validate_mailto_url("mailto:@example.com"));
        assert!(!validate_mailto_url("mailto:notanemail"));
    }

    #[test]
    fn pairing_deep_link_requires_valid_payload() {
        // Origin + data-param checks.
        assert!(!validate_pairing_deep_link("kyberpipe://evil?data=x"));
        assert!(!validate_pairing_deep_link("kyberpipe://pair")); // no data param
                                                                  // Payload must be base64(zlib) JSON carrying nonce + cert pin.
        let build = |nonce: &str, cert: &str| -> String {
            let json = format!(r#"{{"pairing_nonce_hex":"{nonce}","server_cert_hash":"{cert}"}}"#);
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut encoder, json.as_bytes()).unwrap();
            let z = encoder.finish().unwrap();
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, z)
        };
        let good = build("0123456789abcdef0123456789abcdef", &"0".repeat(64));
        assert!(
            validate_pairing_payload(&good),
            "valid nonce + cert pin accepted"
        );
        assert!(
            validate_pairing_deep_link(&format!("kyberpipe://pair?data={good}")),
            "valid deep link accepted"
        );
        let bad_nonce = build("tooshort", &"0".repeat(64));
        assert!(
            !validate_pairing_payload(&bad_nonce),
            "short nonce rejected"
        );
        let bad_cert = build("0123456789abcdef0123456789abcdef", &"0".repeat(10));
        assert!(
            !validate_pairing_payload(&bad_cert),
            "short cert pin rejected"
        );
        // Garbage that is not base64(zlib) JSON.
        let garbage = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"not zlib json at all",
        );
        assert!(!validate_pairing_payload(&garbage));
    }
}
