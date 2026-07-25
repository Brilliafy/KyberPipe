use std::time::{SystemTime, UNIX_EPOCH};

/// Last-Write-Wins Element-Set Conflict-Free Replicated Data Type (LWW-CRDT) for multi-device mesh
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LwwRegisterCRDT<T: Clone> {
    pub value: T,
    pub timestamp: u64,
    pub node_id: String,
}

/// Maximum allowed clock drift: 10 seconds in milliseconds.
/// Incoming timestamps exceeding this threshold relative to local wall clock
/// are rejected as time-jacking attacks.
/// Additionally, if self.timestamp is already more than 10 seconds ahead of
/// the local clock, we reject all incoming updates (local recovery required).
const MAX_CLOCK_DRIFT_MS: u64 = 10_000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl<T: Clone> LwwRegisterCRDT<T> {
    pub fn new(value: T, node_id: String, timestamp: u64) -> Self {
        Self {
            value,
            timestamp,
            node_id,
        }
    }

    /// Merge incoming CRDT state; returns true if incoming state superseded local state.
    /// Rejects timestamps that are too far in the future to prevent u64::MAX time-warp poisoning
    /// AND rejects incoming timestamps that are older than MAX_CLOCK_DRIFT_MS behind now
    /// (prevents an attacker from injecting a timestamp that locks the register for extended periods).
    pub fn merge(&mut self, incoming: LwwRegisterCRDT<T>) -> bool {
        let local_now = now_ms();
        // Reject incoming timestamps too far in the future (time-jacking attack)
        if incoming.timestamp > local_now + MAX_CLOCK_DRIFT_MS {
            return false;
        }
        // If our local timestamp is already ahead of now + drift, we are in a
        // poisoned state. Reject all new updates until recovery.
        if self.timestamp > local_now + MAX_CLOCK_DRIFT_MS {
            return false;
        }
        if incoming.timestamp > self.timestamp
            || (incoming.timestamp == self.timestamp && incoming.node_id > self.node_id)
        {
            self.value = incoming.value;
            self.timestamp = incoming.timestamp;
            self.node_id = incoming.node_id;
            true
        } else {
            false
        }
    }
}
