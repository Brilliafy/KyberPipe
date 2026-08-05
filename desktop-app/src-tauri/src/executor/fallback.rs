use super::ScriptExecutionResult;
use std::io::Write;
use std::process::{Command, Stdio};

/// THE single allowlist for fallback automation scripts (audit finding #19).
/// `execute_fallback_script` (the Tauri command) and `run_fallback_subprocess`
/// (the executor) BOTH resolve against this list, so a path that passes the
/// command layer can never be rejected by the executor (the old mismatch —
/// the command allowed `/usr/lib/kyberpipe/scripts/*.sh` while the executor
/// only matched `sensors/*.js` — made the feature permanently dead).
pub const FALLBACK_SCRIPT_ALLOWLIST: [&str; 4] = [
    "sensors/ambient_light.js",
    "sensors/temperature.js",
    "sensors/humidity.js",
    "sensors/motion.js",
];

/// Resolve a caller-supplied path to an allowed script (by basename) and
/// return the relative allowlist key. Returns Err for anything outside the
/// allowlist — the ONLY entry point for the Tauri command layer.
pub fn resolve_allowed_fallback_script(script_path: &str) -> Result<String, String> {
    let basename = std::path::Path::new(script_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    FALLBACK_SCRIPT_ALLOWLIST
        .iter()
        .find(|allowed| {
            std::path::Path::new(allowed)
                .file_name()
                .and_then(|n| n.to_str())
                == Some(basename)
        })
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Script '{}' not in allowed execution list", script_path))
}

pub fn run_fallback_subprocess(script_path: &str, lux: f64) -> ScriptExecutionResult {
    // Normalize the caller's path against the shared allowlist by basename so
    // the executor and the command layer can never disagree.
    let allowed_path = match resolve_allowed_fallback_script(script_path) {
        Ok(p) => p,
        Err(e) => {
            return ScriptExecutionResult {
                success: false,
                output: e,
                logs: vec![],
            }
        }
    };
    let scripts_dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf().join("scripts"))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default().join("scripts"));
    let full_path = scripts_dir.join(&allowed_path);
    if !full_path.exists() {
        return ScriptExecutionResult {
            success: false,
            output: format!("Not found: {allowed_path}"),
            logs: vec![],
        };
    }
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return ScriptExecutionResult {
                success: false,
                output: format!("No exe: {e}"),
                logs: vec![],
            }
        }
    };
    let input = serde_json::json!({"script": std::fs::read_to_string(&full_path).unwrap_or_default(), "lux": lux, "feed": ""});
    match Command::new(&exe_path)
        .arg("--boa-sandbox")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("DISPLAY", std::env::var("DISPLAY").unwrap_or_default())
        .env(
            "WAYLAND_DISPLAY",
            std::env::var("WAYLAND_DISPLAY").unwrap_or_default(),
        )
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input.to_string().as_bytes());
                drop(stdin);
            }
            match child.wait_with_output() {
                Ok(output) => {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        serde_json::from_str(&stdout).unwrap_or(ScriptExecutionResult {
                            success: false,
                            output: format!("Parse error: {stdout}"),
                            logs: vec![],
                        })
                    } else {
                        ScriptExecutionResult {
                            success: false,
                            output: format!("Error: {}", String::from_utf8_lossy(&output.stderr)),
                            logs: vec![],
                        }
                    }
                }
                Err(e) => ScriptExecutionResult {
                    success: false,
                    output: format!("I/O error: {e}"),
                    logs: vec![],
                },
            }
        }
        Err(e) => ScriptExecutionResult {
            success: false,
            output: format!("Spawn error: {e}"),
            logs: vec![],
        },
    }
}
