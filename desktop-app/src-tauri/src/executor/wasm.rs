//! WASM sandbox execution for the automation engine.
//!
//! Executes untrusted WebAssembly modules with a hard CPU budget:
//! - No host imports are granted (pure computation only) — the module cannot
//!   touch the network, filesystem, or process.
//! - A fuel limit bounds total computation.
//! - An epoch-deadline bounds wall-clock time (kills runaway modules).

use wasmtime::{Config, Engine, Linker, Module, Store, Val};

/// Maximum fuel a module may consume (~ bounded instructions).
const MAX_FUEL: u64 = 100_000_000;
/// Epoch ticks until the wall-clock deadline fires. With the background ticker
/// below (1ms period) this bounds execution to ~15s even if fuel never runs
/// out (audit finding #20b — the epoch deadline was decorative before because
/// nothing ever incremented the epoch).
const MAX_TICKS: u64 = 15_000;
/// Result value cap — refuse to return absurdly large outputs to the caller.
const MAX_OUTPUT_LEN: usize = 1_048_576;

/// Execute a WASM module with no host imports, bounded fuel and wall-clock.
/// Supports modules that export `_start` (WASI-style) or `main`/`run` returning
/// a string. Returns (success, output, logs).
pub fn execute_wasm_script(wasm_bytes: &[u8]) -> Result<String, String> {
    if wasm_bytes.is_empty() {
        return Err("WASM byte array is empty".into());
    }
    let mut config = Config::new();
    config
        .epoch_interruption(true)
        .consume_fuel(true)
        .wasm_reference_types(true);
    let engine = Engine::new(&config).map_err(|e| format!("WASM engine init failed: {e}"))?;
    engine.increment_epoch();

    let module = Module::new(&engine, wasm_bytes).map_err(|e| format!("WASM compile failed: {e}"))?;

    // Epoch interruption is only enforced if SOMETHING increments the epoch.
    // Spawn a background ticker that advances the engine's epoch every 1ms so
    // set_epoch_deadline genuinely bounds wall-clock time (audit #20b).
    let ticker_engine = engine.clone();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let ticker = std::thread::spawn(move || {
        while stop_rx.try_recv().is_err() {
            std::thread::sleep(std::time::Duration::from_millis(1));
            ticker_engine.increment_epoch();
        }
    });

    let mut store = Store::new(&engine, ());
    store
        .set_fuel(MAX_FUEL)
        .map_err(|e| format!("WASM fuel init failed: {e}"))?;
    store.set_epoch_deadline(MAX_TICKS);

    let linker = Linker::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("WASM instantiate failed: {e}"))?;

    // Entry point resolution: try exports in priority order.
    let entry_names = ["main", "run", "_start"];
    let mut entry = None;
    for name in entry_names {
        if instance.get_func(&mut store, name).is_some() {
            entry = Some(name);
            break;
        }
    }
    let Some(entry_name) = entry else {
        return Err(format!(
            "WASM module has no usable entry point (tried {entry_names:?})"
        ));
    };

    let func = instance
        .get_func(&mut store, entry_name)
        .ok_or_else(|| "Entry point vanished".to_string())?;
    let ty = func.ty(&store);
    let params = ty.params().collect::<Vec<_>>();
    let results = ty.results().collect::<Vec<_>>();

    let mut output = String::new();

    // Only support functions with no params and 0..=1 result for now.
    if !params.is_empty() {
        return Err(format!(
            "WASM entry point '{entry_name}' takes {len} params; only zero-param entries are supported",
            len = params.len()
        ));
    }

    // Trap (deadline / fuel exhausted / host trap) is reported distinctly.
    let call_result: Result<(), String> = if results.is_empty() {
        func.call(&mut store, &[], &mut [])
            .map_err(|e| e.to_string())
    } else if results.len() == 1 {
        let mut out = [Val::I32(0)];
        func.call(&mut store, &[], &mut out).map_err(|e| e.to_string())?;
        // Interpret the single i32 result as a numeric result for pure computations.
        if let Val::I32(v) = out[0] {
            output = format!("{v}");
        }
        Ok(())
    } else {
        return Err(format!(
            "WASM entry point '{entry_name}' returns {len} values; only 0..=1 results are supported",
            len = results.len()
        ));
    };

    let call_result = match call_result {
        Ok(()) => {
            if output.len() > MAX_OUTPUT_LEN {
                Err("WASM output exceeds size cap".into())
            } else {
                Ok(output)
            }
        }
        Err(e) => Err(format!("WASM execution failed: {e}")),
    };
    // Stop the epoch ticker and join it (the module has finished or trapped).
    let _ = stop_tx.send(());
    let _ = ticker.join();
    call_result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wat_bytes(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("valid wat")
    }

    #[test]
    fn test_wasm_executes_and_returns_result() {
        // A pure function module: main() -> i32(42).
        let bytes = wat_bytes("(module (func (export \"main\") (result i32) i32.const 42))");
        let out = execute_wasm_script(&bytes).unwrap();
        assert_eq!(out, "42");
    }

    #[test]
    fn test_wasm_fuel_exhaustion_traps() {
        // An infinite loop must trap (fuel / deadline), not hang the process.
        let bytes = wat_bytes("(module (func (export \"main\") (loop br 0)))");
        let result = execute_wasm_script(&bytes);
        assert!(result.is_err(), "infinite loop must trap: {result:?}");
    }

    #[test]
    fn test_wasm_rejects_empty_and_invalid() {
        assert!(execute_wasm_script(&[]).is_err());
        assert!(execute_wasm_script(b"not wasm").is_err());
    }
}

