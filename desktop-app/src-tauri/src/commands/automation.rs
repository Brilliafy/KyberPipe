use crate::executor::{run_boa_sandboxed_script, run_fallback_subprocess, ScriptExecutionResult};
use crate::state::AppState;
use core_crypto::packets::SensorPacket;
use tauri::State;

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
    for addr in &socket_addrs {
        let ip = addr.ip();
        let ip = match ip {
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    std::net::IpAddr::V4(v4)
                } else {
                    std::net::IpAddr::V6(v6)
                }
            }
            v4 => v4,
        };
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
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || v6.octets()[0..2] == [0xfc, 0x00]
                    || v6.octets()[0..2] == [0xfd, 0x00]
            }
        };
        if is_private {
            return Err(format!(
                "SSRF blocked: connections to private IP range ({}) are not allowed",
                ip
            ));
        }
    }
    let first_addr = *socket_addrs
        .first()
        .ok_or_else(|| "No address resolved".to_string())?;

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
pub fn execute_enclave_confidential_wasm(wasm_bytes: Vec<u8>) -> Result<String, String> {
    crate::executor::execute_wasm_script(&wasm_bytes)
}
