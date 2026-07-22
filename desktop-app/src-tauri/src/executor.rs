use boa_engine::{
    js_string,
    property::Attribute,
    Source, Context, JsValue,
};
use std::cell::RefCell;
use std::process::{Command, Stdio};
use tracing::info;

thread_local! {
    static ENGINE_LOGS: RefCell<Vec<String>> = RefCell::new(Vec::new());
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScriptExecutionResult {
    pub success: bool,
    pub output: String,
    pub logs: Vec<String>,
}

/// Runs user script inside an isolated, in-memory Boa JS Engine VM.
/// Completely isolated from filesystem, network, and process execution space.
pub fn run_boa_sandboxed_script(script_code: &str, lux: f64, feed_data: &str) -> ScriptExecutionResult {
    info!("Executing sandboxed JS code via Boa Engine (lux = {}, feed = {})", lux, feed_data);

    // Clear previous logs
    ENGINE_LOGS.with(|logs| {
        logs.borrow_mut().clear();
    });

    let mut context = Context::default();

    // Set loop iteration limit to prevent infinite loops (e.g. while(true) {})
    context.runtime_limits_mut().set_loop_iteration_limit(100_000);

    // Inject ambientLight global variable
    let _ = context.register_global_property(
        js_string!("ambientLight"),
        JsValue::from(lux),
        Attribute::all(),
    );

    // Inject feedData global variable
    let _ = context.register_global_property(
        js_string!("feedData"),
        JsValue::from(js_string!(feed_data)),
        Attribute::all(),
    );

    // Inject system.notify / console log function
    let console_log = boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, args, _ctx| {
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

    let func_obj = boa_engine::object::FunctionObjectBuilder::new(context.realm(), console_log).build();

    let _ = context.register_global_property(
        js_string!("log"),
        func_obj,
        Attribute::all(),
    );

    // Inject getAmbientLight native function
    let get_ambient_light = boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, _args, ctx| {
        let global_obj = ctx.global_object().clone();
        let val = global_obj.get(js_string!("ambientLight"), ctx).unwrap_or(JsValue::from(0.0));
        Ok(val)
    });

    let get_light_obj = boa_engine::object::FunctionObjectBuilder::new(context.realm(), get_ambient_light).build();

    let _ = context.register_global_property(
        js_string!("getAmbientLight"),
        get_light_obj,
        Attribute::all(),
    );

    // Inject getFeedData native function
    let get_feed_data = boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, _args, ctx| {
        let global_obj = ctx.global_object().clone();
        let val = global_obj.get(js_string!("feedData"), ctx).unwrap_or(JsValue::from(js_string!("")));
        Ok(val)
    });

    let get_feed_obj = boa_engine::object::FunctionObjectBuilder::new(context.realm(), get_feed_data).build();

    let _ = context.register_global_property(
        js_string!("getFeedData"),
        get_feed_obj,
        Attribute::all(),
    );

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

/// Run an arbitrary shell/python command on the host directly (Unsandboxed).
pub fn run_unsandboxed_process(script_code: &str, lux: f64, feed_data: &str) -> ScriptExecutionResult {
    info!("Executing unsandboxed code directly on host (lux = {}, feed = {})", lux, feed_data);

    let output_result = Command::new("sh")
        .arg("-c")
        .arg(script_code)
        .env("KYBERPIPE_LUX", lux.to_string())
        .env("KYBERPIPE_FEED_DATA", feed_data)
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
            output: format!("Execution Error: {e}"),
            logs: vec![],
        },
    }
}

/// WebAssembly WASI Capability-Bounded Executor
#[allow(dead_code)]
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
