//! Async runtimes + blocking helpers (audit KYP-2026-02 #22 — extracted from
//! the former `lib.rs` monolith so the runtime lifecycle lives apart from the
//! FFI surface and the record types).

use crate::error::KyberError;
use std::future::Future;

/// IO runtime for long-lived tasks (QUIC accept loop, beacon listeners).
/// Dedicated thread pool prevents FFI calls from starving the accept loop.
/// Stored as `Mutex<Option<Arc<Runtime>>>` so `shutdown_io_runtime()` (test
/// teardown) can take ownership and stop the worker threads — a plain
/// `LazyLock<Runtime>` can never be shut down and would keep a test process
/// alive forever. The mutex guards ONLY the Arc slot: every entry point clones
/// the `Arc<Runtime>` out and drops the guard BEFORE calling `block_on`, so
/// concurrent FFI calls never serialize on this mutex (audit F4).
static IO_RUNTIME: std::sync::LazyLock<
    std::sync::Mutex<Option<std::sync::Arc<tokio::runtime::Runtime>>>,
> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new(Some(std::sync::Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("kyberpipe-io")
            .worker_threads(2)
            .build()
            .expect("Failed to create IO runtime"),
    )))
});

/// FFI runtime for short-lived blocking calls from UniFFI (encrypt, decrypt, key ops).
/// Separate from IO_RUNTIME to prevent worker-thread exhaustion under concurrent FFI load.
/// Stored as `Mutex<Option<Arc<Runtime>>>` so `shutdown_ffi_runtime()` (test teardown) can take
/// ownership and stop the worker threads — a plain `LazyLock<Runtime>` can never be shut
/// down and would keep a test process alive forever. The mutex guards ONLY the Arc slot:
/// every entry point clones the Arc out and drops the guard BEFORE `block_on`, so a slow
/// QUIC reconnect can never freeze the rest of the crypto bridge (audit F4 — the previous
/// implementation held the guard across the entire `block_on`, serializing EVERY UniFFI
/// entry point behind whichever call happened to be inside a blocking await).
static FFI_RUNTIME: std::sync::LazyLock<
    std::sync::Mutex<Option<std::sync::Arc<tokio::runtime::Runtime>>>,
> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new(Some(std::sync::Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("kyberpipe-ffi")
            .worker_threads(2)
            .max_blocking_threads(64)
            .build()
            .expect("Failed to create FFI runtime"),
    )))
});

/// Snapshot the current FFI runtime without holding the mutex across `block_on`.
fn ffi_runtime() -> std::sync::Arc<tokio::runtime::Runtime> {
    let guard = FFI_RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .expect("FFI runtime was shut down (shutdown_ffi_runtime)")
        .clone()
}

/// Block on a future using the FFI runtime. Used for short-lived UniFFI bridge calls.
/// The mutex is held only to clone the `Arc<Runtime>` (microseconds) and is dropped
/// BEFORE `block_on`, so concurrent FFI calls run concurrently on the multi-thread
/// runtime instead of serializing behind each other (audit F4).
pub fn block_on_sync<F: Future>(fut: F) -> F::Output {
    ffi_runtime().block_on(fut)
}

/// Block on a future with timeout using the FFI runtime.
/// Returns `None` if the timeout expires. Use from FFI boundaries (e.g.,
/// Android JNI) where blocking indefinitely would exhaust the platform thread pool.
/// Same lock discipline as [`block_on_sync`] — never holds the registry mutex across
/// the `block_on` (audit F4).
pub fn block_on_sync_timeout<F: Future>(fut: F, timeout: std::time::Duration) -> Option<F::Output> {
    ffi_runtime()
        .block_on(tokio::time::timeout(timeout, fut))
        .ok()
}

/// Block on a future with a hard timeout, ABORTING the future when the deadline
/// fires (AUDIT #6). `tokio::time::timeout` alone drops the future but CANNOT
/// stop an in-flight async operation, so a timed-out QUIC round-trip previously
/// leaked a live task (plus any spawned inner tasks) that kept running until it
/// completed on its own — under a blackholed network every poll leaked a task,
/// progressively exhausting the FFI blocking pool and stalling ALL UniFFI
/// crypto. Spawning the future as an abortable task gives real cancellation:
/// on timeout the task is aborted at its next await point and its JoinHandle
/// is dropped, so the leak is bounded to the timeout window.
///
/// Returns `Some(Ok(out))` / `Some(Err(e))` on completion, `None` on timeout
/// (the task has been aborted).
pub fn block_on_sync_timeout_abortable<F, T>(
    fut: F,
    timeout: std::time::Duration,
) -> Option<Result<T, KyberError>>
where
    F: Future<Output = Result<T, KyberError>> + Send + 'static,
    T: Send + 'static,
{
    let rt = ffi_runtime();
    let mut handle = rt.spawn(fut);
    // Poll the JoinHandle by &mut so the handle survives a timeout for abort().
    match rt.block_on(tokio::time::timeout(timeout, &mut handle)) {
        Ok(join_result) => match join_result {
            Ok(out) => Some(out),
            Err(e) => Some(Err(KyberError::NetworkError(format!(
                "FFI task join failed: {e}"
            )))),
        },
        Err(_elapsed) => {
            // Real cancellation: abort the leaked task at its next await point.
            handle.abort();
            None
        }
    }
}

/// Spawn a blocking closure on the FFI runtime's BLOCKING POOL (max 64 threads,
/// sized independently of the 2 crypto worker threads) and return its
/// `JoinHandle`. AUDIT #7: used by the QUIC reconnect path so a handoff
/// reconnect runs on a dedicated blocking thread and NEVER parks one of the two
/// FFI crypto workers — the caller waits on a plain std channel instead of a
/// tokio `block_on`, so concurrent reconnects for different peers cannot
/// starve concurrent UniFFI crypto calls.
pub fn spawn_blocking_on_ffi<F, T>(f: F) -> tokio::task::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    ffi_runtime().spawn_blocking(f)
}

/// Shut down the FFI runtime. TEST/TEARDOWN ONLY: the runtime is a process-wide
/// LazyLock; calling this in production would break every UniFFI bridge call.
/// The e2e test calls it so the worker threads do not keep the test process
/// alive. Bounded blocking shutdown (drain up to 5s, then hard-stop).
pub fn shutdown_ffi_runtime() {
    shutdown_arc_runtime(&FFI_RUNTIME, "FFI");
}

/// Block on a future using the IO runtime. Used for long-lived tasks (accept loop).
/// Same lock discipline as [`block_on_sync`] — clone the Arc out, drop the guard,
/// then `block_on` (audit F4).
pub fn block_on_io<F: Future>(fut: F) -> F::Output {
    let guard = IO_RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .expect("IO runtime was shut down (shutdown_io_runtime)")
        .clone()
        .block_on(fut)
}

/// Shut down the IO runtime. TEST/TEARDOWN ONLY: the runtime is a process-wide
/// LazyLock; calling this in production would break the accept loop. The e2e
/// test calls it after the dispatch loop stops so the test process can exit
/// (the worker threads would otherwise keep the process alive forever). Uses a
/// BOUNDED BLOCKING shutdown (audit finding #4 follow-up): `shutdown_background`
/// could leave worker threads running past the test and keep the harness pipe
/// open; `shutdown_timeout` drains for up to 5s then hard-stops the workers.
pub fn shutdown_io_runtime() {
    shutdown_arc_runtime(&IO_RUNTIME, "IO");
}

/// Stop an Arc-backed runtime at test teardown (audit F4 follow-up — the CI
/// hang). `shutdown_timeout` consumes the Runtime, so the Arc must be unwrapped
/// when we hold the LAST reference. A concurrent `block_on_*` clone (a transient
/// borrow, dropped as soon as the call returns) is waited out with a bounded
/// retry instead of silently skipping the shutdown — skipping left the runtime's
/// non-daemon worker threads alive and kept the test binary open after all
/// assertions passed. Only a genuinely permanent clone (a real leak) falls
/// through, and it is logged loudly instead of passing silently.
fn shutdown_arc_runtime(
    slot: &std::sync::Mutex<Option<std::sync::Arc<tokio::runtime::Runtime>>>,
    name: &str,
) {
    let rt = {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    let Some(rt) = rt else { return };
    // Bounded wait for transient block_on clones (max ~5s).
    for _ in 0..50 {
        if std::sync::Arc::strong_count(&rt) == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    match std::sync::Arc::try_unwrap(rt) {
        Ok(owned) => owned.shutdown_timeout(std::time::Duration::from_secs(5)),
        Err(shared) => {
            eprintln!(
                "[runtime] WARNING: {name} runtime still has {} reference(s) after shutdown wait —                  a caller leaked a block_on clone; the runtime is left running (test process may not exit)",
                std::sync::Arc::strong_count(&shared)
            );
        }
    }
}
