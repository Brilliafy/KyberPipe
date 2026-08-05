use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlightEvent {
    RatchetStep {
        seq: u64,
        path_id: u8,
    },
    PathMigrated {
        from_ip: [u8; 4],
        to_ip: [u8; 4],
    },
    WasmExecuted {
        duration_us: u32,
        fuel_used: u64,
    },
    ErrorTrace {
        error_message: String,
        stacktrace: String,
    },
}

pub struct FlightDataRecorder {
    is_enabled: AtomicBool,
    events: Mutex<Vec<FlightEvent>>,
    max_events: usize,
}

impl Default for FlightDataRecorder {
    fn default() -> Self {
        Self::new()
    }
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
            // Strip stacktrace from ErrorTrace events before exposing to WebView.
            // Stack traces can leak key material addresses, internal session IDs,
            // and encrypted buffer lengths from cryptographic operations.
            //
            // AUDIT P4-3 (LOW): the dump is served to the renderer, which the
            // token-gating model elsewhere treats as potentially compromised.
            // QUIC qlog metadata — peer addresses, connection IDs — must not
            // cross that boundary. Redact at dump time: zero the peer
            // addresses on PathMigrated events and mask any IPv4 literal that
            // survives inside an error_message string.
            let sanitized: Vec<FlightEvent> = buffer
                .iter()
                .map(|e| match e {
                    FlightEvent::ErrorTrace { error_message, .. } => FlightEvent::ErrorTrace {
                        error_message: error_message.clone(),
                        stacktrace: String::new(),
                    },
                    FlightEvent::PathMigrated { .. } => FlightEvent::PathMigrated {
                        from_ip: [0, 0, 0, 0],
                        to_ip: [0, 0, 0, 0],
                    },
                    other => other.clone(),
                })
                .collect();
            let json =
                serde_json::to_string_pretty(&sanitized).unwrap_or_else(|_| "[]".to_string());
            // Defense-in-depth: mask ANY IPv4 literal (e.g. one embedded in an
            // error_message) so no peer address can leak through the dump even
            // if a future event variant carries one in a string field.
            mask_ipv4_literals(&json)
        } else {
            "[]".to_string()
        }
    }
}

/// Replace every dotted-quad IPv4 literal in `input` with `[MASKED_IP]` (audit
/// P4-3). Mirrors the desktop's crash-log scrubber so peer addresses cannot
/// leak through the renderer-readable flight-recorder dump.
fn mask_ipv4_literals(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let mut dot_count = 0;
            let mut j = i;
            let mut current_segment_len = 0;
            let mut valid_ip = true;
            while j < chars.len() {
                if chars[j].is_ascii_digit() {
                    current_segment_len += 1;
                    if current_segment_len > 3 {
                        valid_ip = false;
                        break;
                    }
                } else if chars[j] == '.' {
                    if current_segment_len == 0 {
                        valid_ip = false;
                        break;
                    }
                    dot_count += 1;
                    current_segment_len = 0;
                    if dot_count > 3 {
                        break;
                    }
                } else {
                    break;
                }
                j += 1;
            }
            if valid_ip && dot_count == 3 && current_segment_len > 0 {
                output.push_str("[MASKED_IP]");
                i = j;
                continue;
            }
        }
        output.push(chars[i]);
        i += 1;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AUDIT P4-3: the dump must redact PathMigrated addresses and any IPv4
    /// literal in an error message.
    #[test]
    fn dump_redacts_peer_addresses() {
        GLOBAL_FLIGHT_RECORDER.set_enabled(true);
        GLOBAL_FLIGHT_RECORDER.record_event(FlightEvent::PathMigrated {
            from_ip: [192, 168, 1, 42],
            to_ip: [10, 0, 0, 7],
        });
        GLOBAL_FLIGHT_RECORDER.record_event(FlightEvent::ErrorTrace {
            error_message: "connect to 203.0.113.9 failed".to_string(),
            stacktrace: "at secret_fn".to_string(),
        });
        let dump = GLOBAL_FLIGHT_RECORDER.dump_events_json();
        assert!(
            !dump.contains("192.168.1.42") && !dump.contains("10.0.0.7"),
            "PathMigrated addresses must be redacted, got: {dump}"
        );
        assert!(
            !dump.contains("203.0.113.9"),
            "IPv4 literals in error messages must be masked, got: {dump}"
        );
        assert!(
            dump.contains("[MASKED_IP]"),
            "the mask marker must be present, got: {dump}"
        );
        assert!(
            !dump.contains("at secret_fn"),
            "stacktraces must remain stripped, got: {dump}"
        );
        // Leave the recorder state clean for other tests.
        GLOBAL_FLIGHT_RECORDER.set_enabled(false);
    }
}

pub static GLOBAL_FLIGHT_RECORDER: std::sync::LazyLock<FlightDataRecorder> =
    std::sync::LazyLock::new(FlightDataRecorder::new);

/// Initialize Sentry Desktop Error Tracing SDK (Stub - Zero-Trust Local Logging Active)
pub fn init_sentry_desktop_diagnostics(dsn: &str) {
    if !dsn.is_empty() {
        tracing::info!(
            "[Diagnostics] Local diagnostics active. Sentry telemetry bypassed. DSN: {dsn}"
        );
    }
}
