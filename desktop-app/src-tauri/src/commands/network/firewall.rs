//! Firewall check and request to open ports.
//!
//! OS firewall modification (requires privilege).
//! Firewall operations use D-Bus Polkit authentication (not pkexec).

use crate::state::AppState;
use serde::Serialize;
use tauri::State;

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
            // KyberPipe uses QUIC, which runs over UDP — check the UDP port.
            let check = std::process::Command::new("firewall-cmd")
                .args(["--query-port", "9876/udp"])
                .output();
            if let Ok(c) = check {
                if !c.status.success() {
                    status.port_open = false;
                    status.commands.push("sudo firewall-cmd --add-port=9876/udp --permanent && sudo firewall-cmd --reload".to_string());
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
                    status.commands.push("sudo ufw allow 9876/udp".to_string());
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
                    .push("sudo iptables -A INPUT -p udp --dport 9876 -j ACCEPT".to_string());
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
pub fn request_firewall_open(token: String) -> Result<String, String> {
    // Tier-2 destructive command — uniform user-gesture token gate (audit #20).
    crate::commands::gate_tier2("request_firewall_open", &token)?;
    for gui_app in &[
        "firewall-config",
        "gnome-control-center",
        "firewall-applet",
        "xfce-firewall",
    ] {
        if let Ok(out) = std::process::Command::new("which").arg(gui_app).output() {
            if !out.stdout.is_empty() {
                let _ = std::process::Command::new(gui_app).spawn();
                return Ok(format!(
                    "Opened {} GUI. Please add port 9876/udp to the firewall.",
                    gui_app
                ));
            }
        }
    }

    // REMOVED: pkexec with arbitrary args is a privilege escalation vector
    // (CVE-2021-4034 class). The D-Bus path below uses Polkit authentication
    // properly. See security.rs for the same pattern in check_stepup_authorization.

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
            "udp",
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
            return Ok("Port opened via D-Bus/Polkit".to_string());
        }
    }

    Ok(String::new())
}
