use boa_engine::{js_string, property::Attribute, Context, JsValue, Source};
use std::cell::RefCell;
use std::process::{Command, Stdio};
use tracing::info;

thread_local! {
    static ENGINE_LOGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScriptExecutionResult {
    pub success: bool,
    pub output: String,
    pub logs: Vec<String>,
}

pub fn run_boa_sandboxed_script(
    script_code: &str,
    lux: f64,
    feed_data: &str,
) -> ScriptExecutionResult {
    let script = script_code.to_string();
    let feed = feed_data.to_string();
    // Execute JS in a separate OS process with isolated heap.
    // Thread isolation is insufficient — Rust heap is process-global,
    // so aggressive JS allocations OOM the entire desktop app.
    // We spawn the run_boa_inner function as a subprocess via the same binary
    // with a special flag, communicating via stdin/stdout.
    let exe_path = std::env::current_exe().ok();
    if let Some(exe) = exe_path {
        let input = serde_json::json!({
            "script": script,
            "lux": lux,
            "feed": feed,
        });
        let input_str = input.to_string();
        match std::process::Command::new(&exe)
            .arg("--boa-sandbox")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // Clear the environment to prevent the sandbox from inheriting
            // the parent's session identifiers, D-Bus address, or other secrets.
            // But pass through DISPLAY and WAYLAND_DISPLAY so the sandbox
            // can render if needed (Boa has no display requirement, but
            // environment breakage can cause spurious errors).
            .env_clear()
            .env("DISPLAY", std::env::var("DISPLAY").unwrap_or_default())
            .env(
                "WAYLAND_DISPLAY",
                std::env::var("WAYLAND_DISPLAY").unwrap_or_default(),
            )
            .spawn()
        {
            Ok(mut child) => {
                use std::io::Write;
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(input_str.as_bytes());
                    drop(stdin);
                }
                match child.wait_with_output() {
                    Ok(output) => {
                        if output.status.success() {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            serde_json::from_str(&stdout).unwrap_or(ScriptExecutionResult {
                                success: false,
                                output: format!("Failed to parse sandbox output: {stdout}"),
                                logs: vec![],
                            })
                        } else {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            ScriptExecutionResult {
                                success: false,
                                output: format!("Sandbox process error: {stderr}"),
                                logs: vec![],
                            }
                        }
                    }
                    Err(e) => ScriptExecutionResult {
                        success: false,
                        output: format!("Sandbox process I/O error: {e}"),
                        logs: vec![],
                    },
                }
            }
            Err(e) => ScriptExecutionResult {
                success: false,
                output: format!("Failed to spawn sandbox process: {e}"),
                logs: vec![],
            },
        }
    } else {
        // Fallback: run in-process if we can't determine the binary path.
        // This is safe for testing but not production.
        let handle = std::thread::Builder::new()
            .name("boa-fallback".into())
            .stack_size(1024 * 1024)
            .spawn(move || run_boa_inner(&script, lux, &feed));
        match handle {
            Ok(jh) => jh.join().unwrap_or(ScriptExecutionResult {
                success: false,
                output: "ERROR: Boa sandbox thread panicked (likely OOM)".to_string(),
                logs: vec![],
            }),
            Err(e) => ScriptExecutionResult {
                success: false,
                output: format!("ERROR: Failed to spawn sandbox thread: {e}"),
                logs: vec![],
            },
        }
    }
}

fn run_boa_inner(script_code: &str, lux: f64, feed_data: &str) -> ScriptExecutionResult {
    info!(
        "Executing sandboxed JS code via Boa Engine (lux = {}, feed = {})",
        lux, feed_data
    );

    ENGINE_LOGS.with(|logs| {
        logs.borrow_mut().clear();
    });

    let mut context = Context::default();

    context
        .runtime_limits_mut()
        .set_loop_iteration_limit(100_000);

    let _ = context.register_global_property(
        js_string!("ambientLight"),
        JsValue::from(lux),
        Attribute::all(),
    );

    let _ = context.register_global_property(
        js_string!("feedData"),
        JsValue::from(js_string!(feed_data)),
        Attribute::all(),
    );

    let console_log =
        boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, args, _ctx| {
            let msg = args
                .first()
                .map(|v| v.display().to_string())
                .unwrap_or_default();
            info!("[Boa Engine Log] {msg}");
            ENGINE_LOGS.with(|logs| {
                logs.borrow_mut().push(msg);
            });
            Ok(JsValue::undefined())
        });

    let func_obj =
        boa_engine::object::FunctionObjectBuilder::new(context.realm(), console_log).build();

    let _ = context.register_global_property(js_string!("log"), func_obj, Attribute::all());

    let get_ambient_light =
        boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, _args, ctx| {
            let global_obj = ctx.global_object().clone();
            let val = global_obj
                .get(js_string!("ambientLight"), ctx)
                .unwrap_or(JsValue::from(0.0));
            Ok(val)
        });

    let get_light_obj =
        boa_engine::object::FunctionObjectBuilder::new(context.realm(), get_ambient_light).build();

    let _ = context.register_global_property(
        js_string!("getAmbientLight"),
        get_light_obj,
        Attribute::all(),
    );

    let get_feed_data =
        boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, _args, ctx| {
            let global_obj = ctx.global_object().clone();
            let val = global_obj
                .get(js_string!("feedData"), ctx)
                .unwrap_or(JsValue::from(js_string!("")));
            Ok(val)
        });

    let get_feed_obj =
        boa_engine::object::FunctionObjectBuilder::new(context.realm(), get_feed_data).build();

    let _ =
        context.register_global_property(js_string!("getFeedData"), get_feed_obj, Attribute::all());

    let res = context.eval(Source::from_bytes(script_code.as_bytes()));
    let collected_logs = ENGINE_LOGS.with(|logs| logs.borrow().clone());

    match res {
        Ok(val) => ScriptExecutionResult {
            success: true,
            output: val.display().to_string(),
            logs: collected_logs,
        },
        Err(e) => ScriptExecutionResult {
            success: false,
            output: format!("Execution Error: {e}"),
            logs: collected_logs,
        },
    }
}

pub fn run_fallback_subprocess(script_path: &str, lux: f64) -> ScriptExecutionResult {
    // Security: hardcoded allowlist prevents arbitrary path execution (RCE via XSS).
    // Only specific vetted script files are allowed — NEVER interpreters like python/bash,
    // because passing --light as argv[1] to an interpreter creates a live shell.
    const ALLOWED_PATHS: &[&str] = &[
        "/opt/kyberpipe/scripts/fallback.py",
        "/opt/kyberpipe/scripts/fallback.sh",
    ];
    if !ALLOWED_PATHS.contains(&script_path) {
        return ScriptExecutionResult {
            success: false,
            output: format!(
                "ERROR: Script path '{}' is not in the allowlist",
                script_path
            ),
            logs: vec![],
        };
    }
    info!(
        "Executing fallback native script path: {} (lux = {})",
        script_path, lux
    );

    let output_result = Command::new(script_path)
        .arg("--light")
        .arg(lux.to_string())
        .env("KYBERPIPE_LUX", lux.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let mut logs = Vec::new();
            if !stderr.is_empty() {
                logs.push(format!("STDERR: {stderr}"));
            }
            ScriptExecutionResult {
                success: output.status.success(),
                output: stdout,
                logs,
            }
        }
        Err(e) => ScriptExecutionResult {
            success: false,
            output: format!("Subprocess launch error: {e}"),
            logs: vec![],
        },
    }
}

/// run_unsandboxed_process removed: security vulnerability (RCE via sh -c).
/// All script execution must go through the sandboxed Boa engine.
/// See https://github.com/kyberpipe/security-audit#2 for details.
#[deprecated(note = "Unsafe: use run_boa_sandboxed_script instead")]
#[allow(dead_code)]
pub fn run_unsandboxed_process(
    _script_code: &str,
    _lux: f64,
    _feed_data: &str,
) -> ScriptExecutionResult {
    ScriptExecutionResult {
        success: false,
        output: "ERROR: Unsandboxed script execution is disabled for security. Use sandboxed Boa engine.".to_string(),
        logs: vec![],
    }
}

#[allow(dead_code)]
pub fn execute_wasm_script(wasm_bytes: &[u8]) -> Result<String, String> {
    if wasm_bytes.is_empty() {
        return Err("WASM byte array is empty".into());
    }

    let mut engine_config = wasmtime::Config::new();
    engine_config.consume_fuel(true);
    let engine = wasmtime::Engine::new(&engine_config)
        .map_err(|e| format!("WASM engine creation failed: {e}"))?;
    let module = wasmtime::Module::new(&engine, wasm_bytes)
        .map_err(|e| format!("WASM AOT Validation Failed: {e}"))?;

    let mut store = wasmtime::Store::new(&engine, ());
    store
        .set_fuel(500_000)
        .map_err(|e| format!("Failed to set WASM fuel: {e}"))?;
    let instance = wasmtime::Instance::new(&mut store, &module, &[])
        .map_err(|e| format!("WASM Instance Instantiation Failed: {e}"))?;

    info!("[WASM VM Engine] Validated and executed AOT WebAssembly module safely.");
    Ok(format!(
        "WASM Execution Completed. Engine: wasmtime (Exports: {})",
        instance.exports(&mut store).count()
    ))
}
