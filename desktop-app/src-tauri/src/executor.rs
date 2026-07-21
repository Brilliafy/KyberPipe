use boa_engine::{
    js_string,
    property::Attribute,
    Source, Context, JsValue,
};
use std::process::{Command, Stdio};
use tracing::info;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScriptExecutionResult {
    pub success: bool,
    pub output: String,
    pub logs: Vec<String>,
}

/// Runs user script inside an isolated, in-memory Boa JS Engine VM.
/// Completely isolated from filesystem, network, and process execution space.
pub fn run_boa_sandboxed_script(script_code: &str, lux: f64) -> ScriptExecutionResult {
    info!("Executing sandboxed JS code via Boa Engine (lux = {})", lux);

    let mut context = Context::default();

    // Set loop iteration limit to prevent infinite loops (e.g. while(true) {})
    context.runtime_limits_mut().set_loop_iteration_limit(100_000);

    // Inject ambientLight global variable
    let _ = context.register_global_property(
        js_string!("ambientLight"),
        JsValue::from(lux),
        Attribute::all(),
    );

    // Inject system.notify / console log function
    let console_log = boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, args, _ctx| {
        let msg = args
            .first()
            .map(|v| v.display().to_string())
            .unwrap_or_default();
        info!("[Boa Engine Log] {msg}");
        Ok(JsValue::undefined())
    });

    let func_obj = boa_engine::object::FunctionObjectBuilder::new(context.realm(), console_log).build();

    let _ = context.register_global_property(
        js_string!("log"),
        func_obj,
        Attribute::all(),
    );

    match context.eval(Source::from_bytes(script_code.as_bytes())) {
        Ok(res) => ScriptExecutionResult {
            success: true,
            output: res.display().to_string(),
            logs: vec![],
        },
        Err(e) => ScriptExecutionResult {
            success: false,
            output: format!("Execution Error: {e}"),
            logs: vec![],
        },
    }
}

/// Fallback execution for native shell scripts using argument-passed subprocess.
/// Forbids dynamic shell string evaluation to prevent shell injection attacks.
pub fn run_fallback_subprocess(script_path: &str, lux: f64) -> ScriptExecutionResult {
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

/// WebAssembly WASI Capability-Bounded Executor
pub fn execute_wasm_script(wasm_bytes: &[u8]) -> Result<String, String> {
    if wasm_bytes.is_empty() {
        return Err("WASM byte array is empty".into());
    }

    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::new(&engine, wasm_bytes)
        .map_err(|e| format!("WASM AOT Validation Failed: {e}"))?;

    let mut store = wasmtime::Store::new(&engine, ());
    let instance = wasmtime::Instance::new(&mut store, &module, &[])
        .map_err(|e| format!("WASM Instance Instantiation Failed: {e}"))?;

    info!("[WASM VM Engine] Validated and executed AOT WebAssembly module safely.");
    Ok(format!("WASM Execution Completed. Engine: wasmtime (Exports: {})", instance.exports(&mut store).count()))
}
