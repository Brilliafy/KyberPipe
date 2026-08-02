pub mod boa_sandbox;
pub mod fallback;
pub mod worker;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScriptExecutionResult {
    pub success: bool,
    pub output: String,
    pub logs: Vec<String>,
}

pub use fallback::{resolve_allowed_fallback_script, run_fallback_subprocess};
pub use worker::{apply_worker_rlimits, run_boa_sandboxed_script, run_boa_worker_loop};
