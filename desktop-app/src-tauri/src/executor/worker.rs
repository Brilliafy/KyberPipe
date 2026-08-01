use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tracing::info;
use super::ScriptExecutionResult;
use super::boa_sandbox::run_boa_inner;

/// Maximum number of idle worker processes cached in the pool. Bounding the
/// pool prevents unbounded resource growth under concurrent script executions
/// (audit finding #16).
const MAX_POOL_SIZE: usize = 4;

/// Wall-clock budget for a single script execution. CPU-bound scripts that do
/// not hit Boa's loop-iteration limit must still be killed so the automation
/// subsystem can never wedge on a hung worker.
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(15);

/// Apply hard resource limits (RLIMIT_AS / RLIMIT_CPU) to a WORKER child
/// process. Called at the top of `run_boa_worker_loop` and the one-shot
/// `--boa-sandbox` mode — never in the main app process, because RLIMIT_AS is
/// per-process and would cap the entire application (audit finding #16).
pub fn apply_worker_rlimits() {
    #[cfg(unix)]
    unsafe {
        // 1 GiB address-space cap: a memory-bomb script cannot exhaust RAM.
        let as_limit = libc::rlimit {
            rlim_cur: 1 << 30,
            rlim_max: 1 << 30,
        };
        libc::setrlimit(libc::RLIMIT_AS, &as_limit);
        // 15s CPU cap — a busy loop that evades Boa's iteration limit dies.
        let cpu_limit = libc::rlimit {
            rlim_cur: 15,
            rlim_max: 15,
        };
        libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit);
    }
}

/// Persistent Boa worker process. Each worker owns a reader thread that
/// forwards response lines from the child's stdout into a channel, so a caller
/// can wait with `recv_timeout` instead of blocking on `read_line` forever.
struct BoaWorker {
    child: Child,
    response_rx: mpsc::Receiver<String>,
    _reader_thread: std::thread::JoinHandle<()>,
}

impl BoaWorker {
    fn spawn() -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| format!("Cannot find executable: {e}"))?;
        let mut child = Command::new(&exe)
            .arg("--boa-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .env("DISPLAY", std::env::var("DISPLAY").unwrap_or_default())
            .env("WAYLAND_DISPLAY", std::env::var("WAYLAND_DISPLAY").unwrap_or_default())
            .spawn()
            .map_err(|e| format!("Failed to spawn Boa worker: {e}"))?;

        let stdout = child.stdout.take().ok_or("Worker stdout closed")?;
        let (tx, rx) = mpsc::channel::<String>();
        let reader_thread = std::thread::Builder::new()
            .name("boa-stdout-reader".into())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if tx.send(line.clone()).is_err() {
                                break;
                            }
                        }
                    }
                }
            })
            .map_err(|e| format!("Failed to spawn stdout reader: {e}"))?;

        let mut worker = Self {
            child,
            response_rx: rx,
            _reader_thread: reader_thread,
        };
        // Verify worker is alive with a ping (write an empty line, expect "{}").
        worker.write_request("", 0.0, "")?;
        worker
            .response_rx
            .recv_timeout(EXECUTION_TIMEOUT)
            .map_err(|_| "Worker did not respond to startup ping".to_string())?;
        Ok(worker)
    }

    fn write_request(&mut self, script: &str, lux: f64, feed: &str) -> Result<(), String> {
        let request = serde_json::json!({"script": script, "lux": lux, "feed": feed});
        let stdin = self.child.stdin.as_mut().ok_or("Worker stdin closed")?;
        stdin
            .write_all(request.to_string().as_bytes())
            .map_err(|e| format!("Write: {e}"))?;
        stdin.write_all(b"\n").map_err(|e| format!("Write: {e}"))?;
        stdin.flush().map_err(|e| format!("Flush: {e}"))
    }

    /// Execute a script with a hard wall-clock timeout. On timeout the worker
    /// is considered wedged; the caller must kill and respawn it.
    fn execute(&mut self, script: &str, lux: f64, feed: &str) -> Result<ScriptExecutionResult, String> {
        self.write_request(script, lux, feed)?;
        let response = self
            .response_rx
            .recv_timeout(EXECUTION_TIMEOUT)
            .map_err(|_| format!("Boa worker timed out after {EXECUTION_TIMEOUT:?}"))?;
        if response.is_empty() {
            return Err("Worker closed connection".into());
        }
        serde_json::from_str(response.trim()).map_err(|e| format!("Parse: {e}"))
    }

    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for BoaWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Worker pool. The pool lock is ONLY held during checkout/check-in — never
/// across script execution, so a wedged worker cannot deadlock the pool.
static BOA_WORKER_POOL: LazyLock<Mutex<std::collections::VecDeque<BoaWorker>>> =
    LazyLock::new(|| Mutex::new(std::collections::VecDeque::new()));

fn checkout_worker() -> Option<BoaWorker> {
    BOA_WORKER_POOL.lock().unwrap().pop_front()
}

fn checkin_worker(worker: BoaWorker) {
    let mut pool = BOA_WORKER_POOL.lock().unwrap();
    // Bound the pool: never cache more than MAX_POOL_SIZE idle workers.
    if pool.len() >= MAX_POOL_SIZE {
        drop(pool);
        drop(worker); // kills the child
        return;
    }
    pool.push_back(worker);
}

/// Execute a script using the persistent Boa worker pool.
pub fn run_boa_sandboxed_script(script_code: &str, lux: f64, feed_data: &str) -> ScriptExecutionResult {
    // Attempt 1: pooled worker (or a fresh one).
    let mut worker = match checkout_worker() {
        Some(mut w) => {
            if w.is_alive() {
                w
            } else {
                drop(w);
                match BoaWorker::spawn() {
                    Ok(w) => {
                        info!("[Boa Pool] Worker respawned");
                        w
                    }
                    Err(e) => {
                        tracing::error!("[Boa Pool] Failed to spawn worker: {e}");
                        return fallback_in_process(script_code, lux, feed_data);
                    }
                }
            }
        }
        None => match BoaWorker::spawn() {
            Ok(w) => {
                info!("[Boa Pool] Worker spawned");
                w
            }
            Err(e) => {
                tracing::error!("[Boa Pool] Failed to spawn worker: {e}");
                return fallback_in_process(script_code, lux, feed_data);
            }
        },
    };

    match worker.execute(script_code, lux, feed_data) {
        Ok(result) => {
            checkin_worker(worker);
            return result;
        }
        Err(e) => {
            tracing::warn!("[Boa Pool] Worker failed (killing): {e}");
            // Worker is wedged or dead — drop it (kills the child) and retry fresh.
            drop(worker);
        }
    }

    // Attempt 2: fresh worker.
    let mut worker = match BoaWorker::spawn() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("[Boa Pool] Second spawn failed: {e}");
            return fallback_in_process(script_code, lux, feed_data);
        }
    };
    match worker.execute(script_code, lux, feed_data) {
        Ok(result) => {
            checkin_worker(worker);
            result
        }
        Err(e) => {
            tracing::warn!("[Boa Pool] Fresh worker also failed: {e}");
            fallback_in_process(script_code, lux, feed_data)
        }
    }
}

/// Last-resort in-process execution with a bounded stack. The Boa runtime
/// itself enforces a loop-iteration limit; deep recursion / huge allocations
/// are the only unbounded risk, bounded here by the OS thread. 8 MiB stack
/// (audit finding #16 — the old 1 MiB fallback stack could overflow and abort
/// the whole process via the panic hook).
fn fallback_in_process(script_code: &str, lux: f64, feed_data: &str) -> ScriptExecutionResult {
    let script = script_code.to_string();
    let feed = feed_data.to_string();
    let handle = std::thread::Builder::new()
        .name("boa-fallback".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || run_boa_inner(&script, lux, &feed));
    match handle {
        Ok(jh) => jh.join().unwrap_or(ScriptExecutionResult {
            success: false,
            output: "Boa thread panicked".into(),
            logs: vec![],
        }),
        Err(e) => ScriptExecutionResult {
            success: false,
            output: format!("Thread spawn error: {e}"),
            logs: vec![],
        },
    }
}

/// Worker mode: reads JSON commands from stdin, executes scripts, writes results to stdout.
pub fn run_boa_worker_loop() {
    apply_worker_rlimits();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let line = line.trim();
        if line.is_empty() {
            let _ = writer.write_all(b"{}\n");
            writer.flush().ok();
            continue;
        }
        let result = match serde_json::from_str::<serde_json::Value>(line) {
            Ok(req) => {
                let script = req["script"].as_str().unwrap_or("");
                let lux = req["lux"].as_f64().unwrap_or(0.0);
                let feed = req["feed"].as_str().unwrap_or("");
                run_boa_inner(script, lux, feed)
            }
            Err(e) => ScriptExecutionResult { success: false, output: format!("Invalid request: {e}"), logs: vec![] },
        };
        let response = serde_json::to_string(&result).unwrap_or_default();
        let _ = writer.write_all(response.as_bytes());
        let _ = writer.write_all(b"\n");
        writer.flush().ok();
    }
}
