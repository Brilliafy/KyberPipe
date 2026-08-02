//! Tor onion service creation.
//!
//! Tor control port uses cookie authentication.

use crate::state::AppState;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct TorOnionInfo {
    pub onion_address: String,
}

#[tauri::command]
pub fn create_tor_onion(
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<TorOnionInfo, String> {
    // Tier-2 destructive command — uniform user-gesture token gate (audit #20).
    crate::commands::gate_tier2("create_tor_onion", &token)?;
    let mut info = TorOnionInfo {
        onion_address: String::new(),
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
    let tor_cookie_path = tmpdir.join("control_auth_cookie");
    // Generate a random 16-byte cookie for Tor control port authentication
    let tor_cookie: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    let _ = std::fs::write(&tor_cookie_path, &tor_cookie);

    let torrc_content = format!(
        r#"DataDirectory {}
ControlPort unix:{}:auto
CookieAuthentication 1
CookieAuthFile {}
SOCKSPort 0
ClientOnly 1
"#,
        data_dir.display(),
        control_port_path.display(),
        tor_cookie_path.display()
    );
    let _ = std::fs::write(&torrc_path, torrc_content);

    let tor_child = match std::process::Command::new("tor")
        .args(["-f", &torrc_path.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(info),
    };

    std::thread::sleep(std::time::Duration::from_secs(2));

    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&control_port_path) {
        use std::io::{Read, Write};
        let mut buf = [0u8; 4096];

        // Authenticate using the cookie we generated
        let auth_cmd = format!(
            "AUTHENTICATE {}\r\n",
            tor_cookie
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        let _ = stream.write_all(auth_cmd.as_bytes());
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
        }

        // Do NOT send SIGNAL SHUTDOWN here — the .onion service would die the
        // moment it was created. Keep the tor daemon running (the child is
        // stored in AppState) so the advertised address stays reachable.
        let _ = stream.write_all(b"CLOSECIRCUIT 0\r\n");
    }

    // Store tor child in AppState so the daemon stays alive as long as the app is running.
    // Previously tor_child was killed immediately, destroying the .onion route.
    state.set_tor_child(tor_child);

    Ok(info)
}
