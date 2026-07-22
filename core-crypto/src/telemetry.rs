use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlightEvent {
    RatchetStep { seq: u64, path_id: u8 },
    PathMigrated { from_ip: [u8; 4], to_ip: [u8; 4] },
    WasmExecuted { duration_us: u32, fuel_used: u64 },
    ErrorTrace { error_message: String, stacktrace: String },
}

pub struct FlightDataRecorder {
    is_enabled: AtomicBool,
    events: Mutex<Vec<FlightEvent>>,
    max_events: usize,
}

impl FlightDataRecorder {
    pub fn new() -> Self {
        Self {
            is_enabled: AtomicBool::new(false), // Disabled by default for zero overhead
            events: Mutex::new(Vec::with_capacity(1024)),
            max_events: 1024,
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.is_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled.load(Ordering::SeqCst)
    }

    pub fn record_event(&self, event: FlightEvent) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut buffer) = self.events.lock() {
            if buffer.len() >= self.max_events {
                buffer.remove(0); // Evict oldest event
            }
            buffer.push(event);
        }
    }

    pub fn dump_events_json(&self) -> String {
        if let Ok(buffer) = self.events.lock() {
            serde_json::to_string_pretty(&*buffer).unwrap_or_else(|_| "[]".to_string())
        } else {
            "[]".to_string()
        }
    }
}

pub static GLOBAL_FLIGHT_RECORDER: std::sync::LazyLock<FlightDataRecorder> = std::sync::LazyLock::new(FlightDataRecorder::new);

/// Initialize Sentry Desktop Error Tracing SDK (Stub - Zero-Trust Local Logging Active)
pub fn init_sentry_desktop_diagnostics(dsn: &str) {
    if !dsn.is_empty() {
        tracing::info!("[Diagnostics] Local diagnostics active. Sentry telemetry bypassed. DSN: {dsn}");
    }
}
