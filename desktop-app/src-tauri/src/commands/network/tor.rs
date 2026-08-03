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

/// Resolve the `tor` binary to a FIXED absolute path only (audit KYP-2026-02
/// #14): a PATH lookup would let a compromised renderer's environment
/// substitute a malicious binary. Mirrors the pkcs11-tool pattern — resolved
/// once per process and cached. `None` when tor is not installed in any
/// standard location.
static TOR_BINARY: std::sync::LazyLock<Option<std::path::PathBuf>> =
    std::sync::LazyLock::new(|| {
        ["/usr/bin/tor", "/bin/tor", "/usr/local/bin/tor"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.exists())
    });

/// OS keyring entry that persists the onion service's ED25519-V3 private key
/// (audit KYP-2026-02 #14), so the .onion address is STABLE across runs
/// instead of a fresh throwaway address per launch (the old DiscardPK flag).
const TOR_ONION_KEY_KEYRING: (&str, &str) = ("kyberpipe", "tor_onion_key");

/// Read a FULL Tor control-port reply. The control protocol terminates every
/// multi-line reply with a bare "250 OK" line (continuation lines use the
/// "250-" prefix), so a single socket read can silently truncate a reply.
/// Accumulate data until a FINAL reply line — three digits followed by a
/// space ("250 OK", or a "512 ..." error) — arrives, handling partial reads
/// and slow tor startup (audit KYP-2026-02 #14).
fn read_control_reply(stream: &mut std::os::unix::net::UnixStream) -> String {
    use std::io::Read;
    let mut buf = [0u8; 4096];
    let mut acc: Vec<u8> = Vec::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&acc);
                let saw_final = text.lines().any(|line| {
                    let line = line.trim_end_matches('\r');
                    line.len() >= 4
                        && line.as_bytes()[..3].iter().all(u8::is_ascii_digit)
                        && line.as_bytes()[3] == b' '
                });
                if saw_final {
                    break;
                }
            }
            Err(_) => break,
        }
        // Back off briefly between reads — tor assembles multi-line replies
        // across several writes.
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    String::from_utf8_lossy(&acc).into_owned()
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

    // Audit KYP-2026-02 #14: tor must come from a FIXED absolute path — never
    // a PATH lookup (a compromised renderer could substitute a malicious
    // binary via the environment).
    let Some(tor_binary) = TOR_BINARY.as_deref() else {
        return Err(
            "tor not found in standard locations (/usr/bin/tor, /bin/tor, /usr/local/bin/tor). \
             Install Tor to use onion services."
                .into(),
        );
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

    let mut tor_child = match std::process::Command::new(tor_binary)
        .args(["-f", &torrc_path.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to spawn tor: {e}")),
    };

    std::thread::sleep(std::time::Duration::from_secs(2));

    let mut stream = match std::os::unix::net::UnixStream::connect(&control_port_path) {
        Ok(s) => s,
        Err(e) => {
            // No usable daemon — don't leave an orphan tor running.
            let _ = tor_child.kill();
            return Err(format!("Failed to connect to the tor control port: {e}"));
        }
    };
    {
        use std::io::Write;

        // Authenticate using the cookie we generated.
        let auth_cmd = format!(
            "AUTHENTICATE {}\r\n",
            tor_cookie
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        let _ = stream.write_all(auth_cmd.as_bytes());
        let auth_reply = read_control_reply(&mut stream);
        if !auth_reply.contains("250 OK") {
            let _ = tor_child.kill();
            return Err(format!(
                "Tor control-port authentication failed: {}",
                auth_reply.trim()
            ));
        }

        // PERSISTENT onion key (audit KYP-2026-02 #14): reuse the ED25519-V3
        // private key stored in the OS keyring when present (stable .onion
        // across runs); otherwise ask tor to generate a fresh key with
        // NEW:ED25519-V3 and persist the returned PrivateKey line.
        let stored_key = keyring::Entry::new(TOR_ONION_KEY_KEYRING.0, TOR_ONION_KEY_KEYRING.1)
            .ok()
            .and_then(|e| e.get_password().ok())
            .filter(|k| !k.is_empty());
        let add_onion_cmd = match stored_key.as_deref() {
            Some(k) => format!("ADD_ONION ED25519-V3:{k} Port=9876,127.0.0.1:9876\r\n"),
            None => "ADD_ONION NEW:ED25519-V3 Port=9876,127.0.0.1:9876\r\n".to_string(),
        };
        let _ = stream.write_all(add_onion_cmd.as_bytes());
        // Read the FULL reply (line loop until the bare "250 OK" terminator) —
        // a single read would truncate the multi-line ADD_ONION reply.
        let response = read_control_reply(&mut stream);

        for line in response.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(id) = line.strip_prefix("250-ServiceID=") {
                let id = id.trim();
                if !id.is_empty() {
                    info.onion_address = format!("{id}.onion");
                }
            }
            // The PrivateKey line is returned only when tor GENERATED a fresh
            // key — persist it so the next run reuses the same address.
            if stored_key.is_none() {
                if let Some(priv_key) = line.strip_prefix("250-PrivateKey:ED25519-V3:") {
                    let priv_key = priv_key.trim();
                    if !priv_key.is_empty() {
                        if let Ok(entry) =
                            keyring::Entry::new(TOR_ONION_KEY_KEYRING.0, TOR_ONION_KEY_KEYRING.1)
                        {
                            let _ = entry.set_password(priv_key);
                        }
                    }
                }
            }
        }
        if info.onion_address.is_empty() {
            let _ = tor_child.kill();
            return Err(format!(
                "Tor rejected the ADD_ONION request — no ServiceID in reply: {}",
                response.trim()
            ));
        }

        // Verify publication (audit KYP-2026-02 #14): confirm the running
        // onion service actually matches what we requested before reporting
        // success.
        let _ = stream.write_all(b"GETINFO onions/current\r\n");
        let getinfo = read_control_reply(&mut stream);
        let published = getinfo.lines().any(|line| {
            let line = line.trim_end_matches('\r');
            line.strip_prefix("250-onions/current=").is_some_and(|v| {
                v.split(|c: char| c == ',' || c.is_whitespace())
                    .any(|name| name == info.onion_address)
            })
        });
        if !published {
            let _ = tor_child.kill();
            return Err(format!(
                "Tor onion service was not published — GETINFO onions/current does not list {}: {}",
                info.onion_address,
                getinfo.trim()
            ));
        }
    }

    // Do NOT send SIGNAL SHUTDOWN here — the .onion service would die the
    // moment it was created. Keep the tor daemon running (the child is
    // stored in AppState) so the advertised address stays reachable.
    state.set_tor_child(tor_child);

    Ok(info)
}
