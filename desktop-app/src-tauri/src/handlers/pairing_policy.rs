//! PAIRING RATE POLICY (audit #20 — structural decomposition). Extracted from
//! the former `handlers/pairing.rs` monolith so the wire codec
//! (`pairing_wire.rs`), the rate policy (this module) and the phase machine
//! (`state/services/pairing.rs`) each change in isolation — a rate-policy
//! tweak no longer touches the KEM/phase logic or the frame decoder.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Instant;

/// Per-IP attempt budget per sliding window — defeats spoofed-source-IP
/// spraying of pairing requests (audit finding #20).
const PAIRING_PER_IP_MAX: u32 = 10;
const PAIRING_WINDOW_SECS: u64 = 60;
/// Global attempt budget across ALL sources per window.
const PAIRING_GLOBAL_MAX: u32 = 200;

struct RateEntry {
    last_attempt: Instant,
    attempts: u32,
    window_start: Instant,
}

/// (global-floor instant, per-IP entries, global budget, window start).
type RateLimiterState = (Instant, HashMap<IpAddr, RateEntry>, u32, Instant);

static PAIRING_RATE_LIMITER: LazyLock<Mutex<RateLimiterState>> = LazyLock::new(|| {
    Mutex::new((
        Instant::now() - std::time::Duration::from_secs(5),
        HashMap::new(),
        0,
        Instant::now(),
    ))
});

use std::sync::Mutex;

/// Per-IP + global rate limiting with a shared counter. Returns false when the
/// request must be dropped (global throttle, per-IP budget exhausted, or the
/// 2s per-IP cooldown).
pub(crate) fn check_pairing_rate_limit(peer_ip: Option<IpAddr>) -> bool {
    let now = Instant::now();
    let mut guard = PAIRING_RATE_LIMITER
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // Global floor: at most one pairing attempt per 200ms process-wide.
    if now.duration_since(guard.0).as_millis() < 200 {
        return false;
    }
    guard.0 = now;

    // Global budget: reset the window every PAIRING_WINDOW_SECS.
    if now.duration_since(guard.3).as_secs() >= PAIRING_WINDOW_SECS {
        guard.2 = 0;
        guard.3 = now;
        guard.1.clear();
    }
    if guard.2 >= PAIRING_GLOBAL_MAX {
        return false;
    }
    guard.2 += 1;

    if let Some(ip) = peer_ip {
        if guard.1.len() > 1000 {
            guard
                .1
                .retain(|_, e| now.duration_since(e.last_attempt).as_secs() < PAIRING_WINDOW_SECS);
        }
        let is_new = !guard.1.contains_key(&ip);
        let entry = guard.1.entry(ip).or_insert(RateEntry {
            last_attempt: now,
            attempts: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start).as_secs() >= PAIRING_WINDOW_SECS {
            entry.attempts = 0;
            entry.window_start = now;
        }
        // First request from an IP is always allowed; afterwards a 2s cooldown
        // applies between requests.
        if !is_new && now.duration_since(entry.last_attempt).as_secs() < 2 {
            return false;
        }
        if entry.attempts >= PAIRING_PER_IP_MAX {
            return false;
        }
        entry.last_attempt = now;
        entry.attempts += 1;
    }
    true
}
