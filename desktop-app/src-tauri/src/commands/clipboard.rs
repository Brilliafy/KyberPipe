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

fn write_copyq_clipboard(text: &str) -> Result<(), String> {
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
    }
    let status = child
        .wait()
        .map_err(|e| format!("Failed to wait for copyq: {e}"))?;
    if status.success() {
        let _ = std::process::Command::new("copyq")
            .args(["select", "0"])
            .status();
        Ok(())
    } else {
        Err("CopyQ returned non-success".to_string())
    }
}

#[tauri::command]
pub fn sync_clipboard(
    text: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<bool, String> {
    if state.dedup.is_suppressed(&text) {
        state.add_log("[Clipboard] Suppressed duplicate or loop-back clipboard sync".to_string());
        return Ok(false);
    }
    state.dedup.record_text(&text);
    crate::portal::sync_clipboard_text(&text)?;
    state.add_log(format!(
        "[Clipboard] Synced: \"{}\"",
        text.chars().take(30).collect::<String>()
    ));
    Ok(true)
}

#[tauri::command]
pub fn read_real_clipboard() -> Result<String, String> {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.get_text() {
            Ok(text) => Ok(text),
            Err(e) => {
                if let Ok(text) = read_copyq_clipboard() {
                    return Ok(text);
                }
                Err(format!("Failed to read clipboard natively: {e}"))
            }
        },
        Err(e) => {
            if let Ok(text) = read_copyq_clipboard() {
                return Ok(text);
            }
            Err(format!("Failed to open native clipboard: {e}"))
        }
    }
}

#[tauri::command]
pub fn write_real_clipboard(text: String) -> Result<(), String> {
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

pub fn read_clipboard_fallback() -> Result<String, String> {
    if let Ok(output) = std::process::Command::new("wl-paste").arg("-n").output() {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if !text.is_empty() {
                    return Ok(text);
                }
            }
        }
    }
    if let Ok(output) = std::process::Command::new("xclip")
        .args(["-selection", "clipboard", "-o"])
        .output()
    {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if !text.is_empty() {
                    return Ok(text);
                }
            }
        }
    }
    if let Ok(output) = std::process::Command::new("xsel")
        .args(["-o", "-b"])
        .output()
    {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if !text.is_empty() {
                    return Ok(text);
                }
            }
        }
    }
    read_copyq_clipboard()
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
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
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
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
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
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
            }
        }
        Err(e) => last_err = Some(e.to_string()),
    }

    write_copyq_clipboard(text).map_err(|e| {
        format!("All clipboard helper fallbacks (wl-copy, xclip, xsel) failed. CopyQ error: {e}. Last spawn error: {:?}", last_err)
    })
}

pub fn read_real_clipboard_internal() -> Result<String, String> {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.get_text() {
            Ok(text) => Ok(text),
            Err(_) => {
                if let Ok(text) = read_copyq_clipboard() {
                    return Ok(text);
                }
                read_clipboard_fallback()
            }
        },
        Err(_) => {
            if let Ok(text) = read_copyq_clipboard() {
                return Ok(text);
            }
            read_clipboard_fallback()
        }
    }
}
