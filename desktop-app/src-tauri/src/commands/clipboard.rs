use crate::state::AppState;
use tauri::State;

fn read_copyq_clipboard() -> Result<String, String> {
    let output = std::process::Command::new("copyq")
        .args(["read", "0"])
        .output()
        .map_err(|e| format!("Failed to execute copyq read: {e}"))?;
    if output.status.success() {
        let text = String::from_utf8(output.stdout)
            .map_err(|e| format!("Invalid UTF-8 from copyq: {e}"))?;
        if !text.trim().is_empty() {
            return Ok(text);
        }
    }
    Err("CopyQ returned empty or non-success".to_string())
}

/// Maximum clipboard payload size: 10 MiB
const MAX_CLIPBOARD_SIZE: usize = 10 * 1024 * 1024;

fn write_copyq_clipboard(text: &str) -> Result<(), String> {
    // Validate input: reject oversized or non-UTF-8 content
    if text.len() > MAX_CLIPBOARD_SIZE {
        return Err(format!(
            "Clipboard payload too large: {} bytes (max {})",
            text.len(),
            MAX_CLIPBOARD_SIZE
        ));
    }
    // Verify valid UTF-8 content
    if text.is_empty() {
        return Err("Clipboard payload is empty".to_string());
    }
    if text.chars().any(|c| c == '\0') {
        return Err("Clipboard payload contains null bytes".to_string());
    }

    let mut child = std::process::Command::new("copyq")
        .args(["add", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn copyq add: {e}"))?;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| format!("Failed to write to copyq stdin: {e}"))?;
        // Drop stdin to signal EOF to copyq
        drop(stdin);
    }
    let status = wait_with_timeout(&mut child, std::time::Duration::from_secs(5))
        .ok_or_else(|| "CopyQ timed out".to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("CopyQ returned non-success".to_string())
    }
}

/// AUDIT F14: the renderer-facing `sync_clipboard` command is REMOVED. It was
/// a second ungated OS-clipboard write path alongside `write_real_clipboard`
/// (both wrote the host clipboard via `portal::sync_clipboard_text` /
/// arboard), so a compromised renderer had two paste-jacking vectors instead
/// of one. The trusted phone→desktop QUIC path still writes the clipboard
/// directly via `portal::sync_clipboard_text` (no renderer involvement), and
/// the token-gated `write_real_clipboard` now records the text for loop-back
/// suppression (the behavior `sync_clipboard` provided).
/// Whether an interactive display session is available. arboard's platform
/// backends block indefinitely trying to reach a Wayland/X11 compositor when
/// none exists (headless CI, ssh, tty) — which would hang the QUIC poll loop.
fn has_display_session() -> bool {
    std::env::var("WAYLAND_DISPLAY").is_ok() || std::env::var("DISPLAY").is_ok()
}

/// Run `f` in a thread with a hard timeout, returning None on timeout. The
/// underlying thread is detached (and dies with the process); this guarantees a
/// blocking clipboard backend can never wedge the caller.
pub(crate) fn with_timeout<T: Send + 'static>(
    timeout: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("clipboard-read".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .ok()?;
    rx.recv_timeout(timeout).ok()
}

#[tauri::command]
pub fn read_real_clipboard(token: String) -> Result<String, String> {
    // Audit KYP-2026-02 #6: reading the host clipboard is a Tier-0 command
    // whose confidentiality is otherwise tied to the webview's XSS-resistance.
    // Require a fresh user-gesture token (same mechanism as Tier-2 destructive
    // commands): a renderer compromise can no longer silently harvest the
    // clipboard on a 1.5s timer. The server-side poll loop uses
    // `read_real_clipboard_internal` (trusted Rust, no renderer) and is
    // unaffected.
    if !crate::commands::security::consume_privilege_token("read_real_clipboard", &token) {
        return Err("Reading the host clipboard requires a fresh user-gesture token".to_string());
    }
    read_real_clipboard_internal()
}

/// The trusted Rust-side clipboard read (used by the poll loop and the gated
/// Tauri command). No renderer involvement, so no gesture token is required
/// here.
pub fn read_real_clipboard_internal() -> Result<String, String> {
    if has_display_session() {
        // Bounded native read: never let a wedged compositor connection block
        // the poll handler.
        if let Some(Ok(text)) = with_timeout(std::time::Duration::from_secs(3), || {
            arboard::Clipboard::new().and_then(|mut c| c.get_text())
        }) {
            if !text.is_empty() {
                return Ok(text);
            }
        }
    }
    // Fallbacks (bounded subprocesses).
    if let Ok(text) = read_copyq_clipboard() {
        return Ok(text);
    }
    read_clipboard_fallback()
}

#[tauri::command]
pub fn write_real_clipboard(
    text: String,
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<(), String> {
    // AUDIT F14 (MEDIUM): the clipboard WRITE path now carries the same
    // native-gesture token the READ path already required. The legacy write
    // was renderer-trust-only — under a webview compromise (XSS, supply chain,
    // devtools) a script could plant arbitrary content into the OS clipboard
    // (and CopyQ history) that a subsequent paste into a terminal/editor could
    // execute. With the token, a compromised renderer can only trigger the
    // native dialog; the write happens only when a real user clicks "Yes".
    if !crate::commands::security::consume_privilege_token("write_real_clipboard", &token) {
        return Err("Writing the host clipboard requires a fresh user-gesture token".to_string());
    }
    // AUDIT F14: absorb the (now-removed) ungated `sync_clipboard` renderer
    // command — record the text for loop-back suppression and log it, so the
    // dedup/history behavior the frontend relied on is preserved on the trusted
    // Rust side. The phone→desktop QUIC path writes via
    // `portal::sync_clipboard_text` directly and is untouched.
    state.record_clipboard_text(&text);
    state.add_log(format!(
        "[Clipboard] Synced: \"{}\"",
        text.chars().take(30).collect::<String>()
    ));
    let native_err = match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.set_text(text.clone()) {
            Ok(_) => {
                let _ = write_copyq_clipboard(&text);
                return Ok(());
            }
            Err(e) => Some(format!("Native set_text error: {e}")),
        },
        Err(e) => Some(format!("Native open error: {e}")),
    };

    if let Err(copyq_err) = write_copyq_clipboard(&text) {
        return Err(format!(
            "Failed to write clipboard natively ({:?}) and via CopyQ fallback ({})",
            native_err, copyq_err
        ));
    }
    if let Some(err_str) = &native_err {
        println!(
            "Note: Native clipboard failed ({}), but CopyQ fallback succeeded.",
            err_str
        );
    }
    Ok(())
}

#[allow(dead_code)]
pub fn read_clipboard_fallback() -> Result<String, String> {
    // Run each helper with a hard timeout — `wl-paste`/`xclip`/`xsel` block
    // forever on a headless session and would otherwise hang the poll handler.
    let run = |args: Vec<String>| -> Option<String> {
        with_timeout(std::time::Duration::from_secs(3), move || {
            std::process::Command::new(&args[0])
                .args(&args[1..])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        String::from_utf8(o.stdout).ok()
                    } else {
                        None
                    }
                })
        })
        .flatten()
    };
    for candidate in [
        vec!["wl-paste".to_string(), "-n".to_string()],
        vec![
            "xclip".to_string(),
            "-selection".to_string(),
            "clipboard".to_string(),
            "-o".to_string(),
        ],
        vec!["xsel".to_string(), "-o".to_string(), "-b".to_string()],
    ] {
        if let Some(text) = run(candidate) {
            if !text.trim().is_empty() {
                return Ok(text);
            }
        }
    }
    read_copyq_clipboard()
}

/// Wait for a clipboard helper subprocess with a hard timeout. `wl-copy`,
/// `xclip`, `xsel` and `copyq` can block forever on a headless/foreign
/// session (e.g. trying to connect to a Wayland compositor that is not there),
/// which would otherwise hang the QUIC poll/clipboard handlers indefinitely.
/// On timeout the child is killed and treated as a failure.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}

pub fn write_clipboard_fallback(text: &str) -> Result<(), String> {
    let mut last_err = None;

    match std::process::Command::new("wl-copy")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Some(status) = wait_with_timeout(&mut child, std::time::Duration::from_secs(5)) {
                if status.success() {
                    return Ok(());
                }
            } else {
                last_err = Some("wl-copy timed out (no display session)".to_string());
            }
        }
        Err(e) => last_err = Some(e.to_string()),
    }

    match std::process::Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Some(status) = wait_with_timeout(&mut child, std::time::Duration::from_secs(5)) {
                if status.success() {
                    return Ok(());
                }
            } else {
                last_err = Some("xclip timed out (no display session)".to_string());
            }
        }
        Err(e) => last_err = Some(e.to_string()),
    }

    match std::process::Command::new("xsel")
        .args(["-i", "-b"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Some(status) = wait_with_timeout(&mut child, std::time::Duration::from_secs(5)) {
                if status.success() {
                    return Ok(());
                }
            } else {
                last_err = Some("xsel timed out (no display session)".to_string());
            }
        }
        Err(e) => last_err = Some(e.to_string()),
    }

    write_copyq_clipboard(text).map_err(|e| {
        format!("All clipboard helper fallbacks (wl-copy, xclip, xsel) failed. CopyQ error: {e}. Last spawn error: {:?}", last_err)
    })
}
