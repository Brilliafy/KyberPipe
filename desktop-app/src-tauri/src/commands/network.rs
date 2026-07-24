use crate::state::AppState;
use serde::Serialize;
use tauri::State;

#[tauri::command]
pub fn get_connection_status(state: State<'_, std::sync::Arc<AppState>>) -> String {
    state.get_connection_status()
}

#[tauri::command]
pub fn perform_stun_hole_punch(
    stun_host: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    state.add_log(format!(
        "[STUN] Initiating UDP hole punch via STUN: {stun_host}"
    ));
    let addr = core_crypto::perform_stun_hole_punch(stun_host).map_err(|e| e.to_string())?;
    state.add_log(format!("[STUN] Mapped public reflexive address: {addr}"));

    state.set_connection_status(format!("Connected (WAN STUN: {addr})"));

    Ok(addr)
}

#[tauri::command]
pub fn evaluate_connection_status(
    wifi_direct_active: bool,
    lan_active: bool,
    public_endpoint: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::ConnectionInfo, String> {
    let info =
        core_crypto::evaluate_connection_hierarchy(wifi_direct_active, lan_active, public_endpoint);
    state.add_log(format!(
        "[Connection Manager] Active path: {} (Tier {}, Latency {}ms)",
        info.active_path_description, info.active_tier, info.latency_ms
    ));

    if let Ok(mut conn) = state.connection.lock() {
        conn.status = format!("Connected ({})", info.active_path_description);
    }

    Ok(info)
}

#[derive(Serialize)]
pub struct ConnectionStatusFull {
    pub status: String,
    pub method: String,
    pub color: String,
}

#[tauri::command]
pub fn get_connection_status_full(
    state: State<'_, std::sync::Arc<AppState>>,
) -> ConnectionStatusFull {
    ConnectionStatusFull {
        status: state
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status
            .clone(),
        method: state
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .method
            .clone(),
        color: state
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .color
            .clone(),
    }
}

#[tauri::command]
pub fn set_connection_status_full(
    status: String,
    method: String,
    color: String,
    state: State<'_, std::sync::Arc<AppState>>,
) {
    let current_status = state.get_connection_status();
    state.set_connection(status.clone(), method.clone(), color.clone());

    if current_status != status {
        state.add_log(format!(
            "[Connection State] Changed to {status} via method {method}"
        ));
    }
}

#[derive(Serialize)]
pub struct FirewallStatus {
    pub firewalld_active: bool,
    pub ufw_active: bool,
    pub port_open: bool,
    pub client_isolation: bool,
    pub commands: Vec<String>,
}

#[tauri::command]
pub fn check_firewall(state: State<'_, std::sync::Arc<AppState>>) -> FirewallStatus {
    let mut status = FirewallStatus {
        firewalld_active: false,
        ufw_active: false,
        port_open: true,
        client_isolation: false,
        commands: vec![],
    };

    if let Ok(out) = std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
    {
        let active = String::from_utf8_lossy(&out.stdout).trim() == "running";
        status.firewalld_active = active;
        if active {
            let check = std::process::Command::new("firewall-cmd")
                .args(["--query-port", "9876/tcp"])
                .output();
            if let Ok(c) = check {
                if !c.status.success() {
                    status.port_open = false;
                    status.commands.push("sudo firewall-cmd --add-port=9876/tcp --permanent && sudo firewall-cmd --reload".to_string());
                }
            }
        }
    }

    if let Ok(out) = std::process::Command::new("ufw").arg("status").output() {
        let output = String::from_utf8_lossy(&out.stdout);
        if output.contains("active") {
            status.ufw_active = true;
            let check = std::process::Command::new("ufw")
                .args(["status", "verbose"])
                .output();
            if let Ok(c) = check {
                let ufw_out = String::from_utf8_lossy(&c.stdout);
                if !ufw_out.contains("9876") {
                    status.port_open = false;
                    status.commands.push("sudo ufw allow 9876/tcp".to_string());
                }
            }
        }
    }

    if !status.firewalld_active && !status.ufw_active {
        if let Ok(out) = std::process::Command::new("iptables")
            .args(["-L", "INPUT", "-n"])
            .output()
        {
            let ipt = String::from_utf8_lossy(&out.stdout);
            if ipt.contains("DROP") || ipt.contains("REJECT") {
                status
                    .commands
                    .push("sudo iptables -A INPUT -p tcp --dport 9876 -j ACCEPT".to_string());
            }
        }
    }

    if status.port_open {
        status.commands.clear();
    }

    state.add_log(format!(
        "[Firewall] Check: firewalld={} ufw={} port_open={}",
        status.firewalld_active, status.ufw_active, status.port_open
    ));
    status
}

#[tauri::command]
pub fn request_firewall_open() -> String {
    for gui_app in &[
        "firewall-config",
        "gnome-control-center",
        "firewall-applet",
        "xfce-firewall",
    ] {
        if let Ok(out) = std::process::Command::new("which").arg(gui_app).output() {
            if !out.stdout.is_empty() {
                let _ = std::process::Command::new(gui_app).spawn();
                return format!(
                    "Opened {} GUI. Please add port 9876/tcp to the firewall.",
                    gui_app
                );
            }
        }
    }

    if std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .is_ok()
    {
        if let Ok(out) = std::process::Command::new("pkexec")
            .args(["firewall-cmd", "--add-port=9876/tcp", "--permanent"])
            .output()
        {
            if out.status.success() {
                let _ = std::process::Command::new("pkexec")
                    .args(["firewall-cmd", "--reload"])
                    .output();
                return "Port opened via firewalld/Polkit".to_string();
            }
        }
    }
    if std::process::Command::new("ufw")
        .arg("status")
        .output()
        .is_ok()
    {
        if let Ok(out) = std::process::Command::new("pkexec")
            .args(["ufw", "allow", "9876/tcp"])
            .output()
        {
            if out.status.success() {
                return "Port opened via ufw/Polkit".to_string();
            }
        }
    }

    if let Ok(out) = std::process::Command::new("busctl")
        .args([
            "call",
            "org.fedoraproject.FirewallD1",
            "/org/fedoraproject/FirewallD1",
            "org.fedoraproject.FirewallD1",
            "AddPort",
            "s",
            "public",
            "s",
            "tcp",
            "u",
            "9876",
            "s",
            "kyberpipe-sync",
        ])
        .output()
    {
        if out.status.success() {
            let _ = std::process::Command::new("busctl")
                .args([
                    "call",
                    "org.fedoraproject.FirewallD1",
                    "/org/fedoraproject/FirewallD1",
                    "org.fedoraproject.FirewallD1",
                    "Reload",
                ])
                .output();
            return "Port opened via D-Bus/Polkit".to_string();
        }
    }

    String::new()
}

#[tauri::command]
pub fn scan_subnet_for_port(port: u16) -> Vec<String> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let local_ip = core_crypto::get_local_ip();
    if local_ip.is_empty() {
        return vec![];
    }
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 {
        return vec![];
    }
    let prefix = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);

    let mut results = vec![];
    let mut handles = vec![];

    for i in 1..255 {
        let ip = format!("{prefix}{i}");
        handles.push(std::thread::spawn(move || {
            if let Ok(mut addrs) = format!("{ip}:{port}").to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                        return Some(ip);
                    }
                }
            }
            None
        }));
    }

    for h in handles {
        if let Ok(Some(ip)) = h.join() {
            if ip != local_ip {
                results.push(ip);
            }
        }
    }

    results
}

#[tauri::command]
pub fn send_reverse_request(host: String, port: u16, request: String) -> String {
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpStream};
    use std::time::Duration;

    let addr: std::net::SocketAddr = match format!("{host}:{port}").parse() {
        Ok(a) => a,
        Err(_) => return String::new(),
    };
    let ip = addr.ip();
    let allowed = match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || (v4.octets()[0] == 192 && v4.octets()[1] == 168)
                || (v4.octets()[0] == 172 && (16..=31).contains(&v4.octets()[1]))
                || v4.octets()[0] == 10
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if !allowed {
        return String::new();
    }

    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = stream.write_all(request.as_bytes());
        let _ = stream.flush();
        let mut buf = vec![0u8; 4096];
        if let Ok(n) = stream.read(&mut buf) {
            return String::from_utf8_lossy(&buf[..n]).to_string();
        }
    }
    String::new()
}

#[derive(Serialize)]
pub struct P2pGroupInfo {
    pub ssid: String,
    pub passphrase: String,
    pub ip: String,
    pub mac: String,
}

#[tauri::command]
pub fn create_p2p_group() -> P2pGroupInfo {
    let pass = format!("kp-{:06}", rand::random::<u32>() % 1_000_000);
    let info = P2pGroupInfo {
        ssid: "DIRECT-KyberPipe".to_string(),
        passphrase: pass,
        ip: "192.168.49.1".to_string(),
        mac: core_crypto::get_wifi_direct_mac(),
    };

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

    info
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
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.trim()
                .trim_matches('o')
                .trim()
                .trim_matches('"')
                .to_string()
        })
        .filter(|p| !p.is_empty());
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

#[derive(Serialize)]
pub struct TorOnionInfo {
    pub onion_address: String,
    pub auth_key: String,
}

#[tauri::command]
pub fn create_tor_onion() -> TorOnionInfo {
    let mut info = TorOnionInfo {
        onion_address: String::new(),
        auth_key: String::new(),
    };

    let tmpdir = std::env::temp_dir().join(format!(
        "kyberpipe_tor_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let _ = builder.create(&tmpdir);
    }
    #[cfg(not(unix))]
    let _ = std::fs::create_dir_all(&tmpdir);
    let data_dir = tmpdir.join("data");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let _ = builder.create(&data_dir);
    }
    #[cfg(not(unix))]
    let _ = std::fs::create_dir_all(&data_dir);
    let torrc_path = tmpdir.join("torrc");
    let control_port_path = tmpdir.join("control.sock");

    let torrc_content = format!(
        r#"DataDirectory {}
ControlPort unix:{}:auto
SOCKSPort 0
ClientOnly 1
"#,
        data_dir.display(),
        control_port_path.display()
    );
    let _ = std::fs::write(&torrc_path, torrc_content);

    let mut tor_child = match std::process::Command::new("tor")
        .args(["-f", &torrc_path.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return info,
    };

    std::thread::sleep(std::time::Duration::from_secs(2));

    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&control_port_path) {
        use std::io::{Read, Write};
        let mut buf = [0u8; 4096];

        let _ = stream.write_all(b"AUTHENTICATE\r\n");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = stream.read(&mut buf);

        let add_onion_cmd =
            "ADD_ONION NEW:BEST Flags=DiscardPK,Detach Port=9876,127.0.0.1:9876\r\n".to_string();
        let _ = stream.write_all(add_onion_cmd.as_bytes());
        std::thread::sleep(std::time::Duration::from_millis(500));
        let n = stream.read(&mut buf).unwrap_or(0);
        let response = String::from_utf8_lossy(&buf[..n]);

        for line in response.lines() {
            if let Some(id) = line.strip_prefix("250-ServiceID=") {
                info.onion_address = format!("{id}.onion");
            }
            if let Some(privkey) = line.strip_prefix("250-PrivateKey=") {
                if line.contains("x25519") {
                    info.auth_key = privkey.to_string();
                }
            }
        }

        let _ = stream.write_all(b"CLOSECIRCUIT 0\r\n");
        let _ = stream.write_all(b"SIGNAL SHUTDOWN\r\n");
    }

    let _ = tor_child.kill();
    let _ = tor_child.wait();

    info
}
