use crate::executor::{
    resolve_allowed_fallback_script, run_boa_sandboxed_script, run_fallback_subprocess,
    ScriptExecutionResult,
};
use crate::state::AppState;
use core_crypto::packets::SensorPacket;
use tauri::State;

/// RFC 1918 private networks, link-local, loopback, CGNAT ranges
fn is_private_or_restricted(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (octets[1] & 0xF0) == 16 {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 127.0.0.0/8 (loopback)
            if octets[0] == 127 {
                return true;
            }
            // 169.254.0.0/16 (link-local / metadata)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // 100.64.0.0/10 (CGNAT)
            if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                return true;
            }
            // 0.0.0.0/8
            if octets[0] == 0 {
                return true;
            }
            false
        }
        std::net::IpAddr::V6(v6) => {
            // ::1 (loopback)
            if *v6 == std::net::Ipv6Addr::LOCALHOST {
                return true;
            }
            // fe80::/10 (link-local)
            let segments = v6.segments();
            if segments[0] & 0xFFC0 == 0xFE80 {
                return true;
            }
            // fd00::/8 (unique local)
            if segments[0] & 0xFF00 == 0xFD00 {
                return true;
            }
            // ::ffff:0:0/96 (IPv4-mapped)
            false
        }
    }
}

fn native_http_fetch(url: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let url_str = url.trim();
    if url_str.starts_with("https://") {
        return Err("HTTPS is not supported for automation feeds (no TLS cert validation available). Use an http:// URL or add certs to the trust store.".into());
    }
    if !url_str.starts_with("http://") {
        return Err("Only HTTP(S) URLs allowed for feed source".into());
    }

    let without_proto = url_str.trim_start_matches("http://");
    let (host, path) = match without_proto.find('/') {
        Some(pos) => (&without_proto[..pos], &without_proto[pos..]),
        None => (without_proto, "/"),
    };
    let port = 80;
    let addr = format!("{host}:{port}");

    let socket_addrs: Vec<std::net::SocketAddr> = addr
        .parse::<std::net::SocketAddr>()
        .map(|a| vec![a])
        .or_else(|_| {
            std::net::ToSocketAddrs::to_socket_addrs(&addr)
                .map(|iter| iter.collect())
                .map_err(|e| format!("DNS resolution failed: {e}"))
        })?;
    // SSRF protection: reject private/link-local/loopback addresses
    for addr in &socket_addrs {
        if is_private_or_restricted(&addr.ip()) {
            return Err(format!(
                "SSRF blocked: connection to private/internal address {} is not allowed",
                addr.ip()
            ));
        }
    }
    let first_addr = *socket_addrs
        .first()
        .ok_or_else(|| "No address resolved".to_string())?;
    // AUDIT #18: re-verify the address IMMEDIATELY before connect. The connect
    // targets the validated IP (never a re-resolution of the hostname), so a
    // DNS rebinding after this point cannot redirect the socket to a
    // private/link-local/metadata target.
    if is_private_or_restricted(&first_addr.ip()) {
        return Err(format!(
            "SSRF guard: refusing connect to {} (private/link-local/loopback)",
            first_addr.ip()
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
    if let Some(body_start) = response_str.find("\r\n\r\n") {
        Ok(response_str[body_start + 4..].trim().to_string())
    } else {
        Err("No HTTP body found in response".into())
    }
}

/// AUDIT F22: the `is_sandboxed` flag is GONE — both branches previously ran
/// `run_boa_sandboxed_script` (the flag was ignored), so the command now has a
/// single, always-enforced sandboxed path. The UI toggle that sent it is
/// removed with it (see useAutomation.ts).
#[tauri::command]
pub async fn execute_boa_script(
    script_code: String,
    lux: f64,
    feed_source_command: String,
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<ScriptExecutionResult, String> {
    // Tier-2 destructive command (arbitrary JS execution) — uniform
    // user-gesture token gate (audit finding #20).
    crate::commands::gate_tier2("execute_boa_script", &token)?;
    let mut feed_value = String::new();
    if !feed_source_command.trim().is_empty() {
        state.add_log(format!(
            "[Automation] Querying feed source: {}",
            feed_source_command
        ));
        feed_value = native_http_fetch(&feed_source_command).unwrap_or_else(|e| {
            state.add_log(format!("[Automation] Feed fetch failed: {e}"));
            String::new()
        });
        // AUDIT #18: NEVER log the feed BODY — a user pointing a feed at an
        // authenticated endpoint could leak credentials/tokens into the in-app
        // log pane. Log only the URL host and the body length.
        let feed_host = feed_source_command
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("<unknown>");
        state.add_log(format!(
            "[Automation] Resolved feed data from host {feed_host} ({} bytes)",
            feed_value.len()
        ));
    }

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

#[tauri::command]
pub fn execute_fallback_script(
    script_path: String,
    lux: f64,
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<ScriptExecutionResult, String> {
    // Tier-2 command (subprocess code execution) — uniform user-gesture token
    // gate, matching execute_boa_script (audit finding #20).
    crate::commands::gate_tier2("execute_fallback_script", &token)?;
    // Resolve against the SINGLE shared allowlist (audit finding #19). The
    // resolved value is the same relative key `run_fallback_subprocess` uses,
    // so the command layer and the executor can never disagree.
    let allowed_path = resolve_allowed_fallback_script(&script_path)?;
    state.add_log(format!(
        "[Subprocess] Executing fallback script: {allowed_path} (lux = {lux})"
    ));
    let res = run_fallback_subprocess(&allowed_path, lux);
    state.add_log(format!(
        "[Subprocess] Result: success={}, output={}",
        res.success, res.output
    ));
    Ok(res)
}

#[tauri::command]
pub fn push_sensor_reading(
    lux: f64,
    timestamp: u64,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Vec<SensorPacket> {
    let pkt = SensorPacket { lux, timestamp };
    state.add_sensor_packet(pkt);
    state.get_sensor_history()
}
