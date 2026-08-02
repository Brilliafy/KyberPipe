use std::time::{SystemTime, UNIX_EPOCH};

/// Last-Write-Wins Element-Set Conflict-Free Replicated Data Type (LWW-CRDT) for multi-device mesh
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LwwRegisterCRDT<T: Clone> {
    pub value: T,
    pub timestamp: u64,
    pub node_id: String,
}

const MAX_CLOCK_DRIFT_MS: u64 = 60_000;

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
    /// Enforces the wall-clock drift bound BOTH directions: timestamps too far in
    /// the future are rejected (prevents u64::MAX time-warp poisoning that would
    /// permanently lock the register) and timestamps older than MAX_CLOCK_DRIFT_MS
    /// are rejected too (prevents an attacker from injecting a stale value that
    /// blocks convergence). Rejected inputs are silently ignored.
    pub fn merge(&mut self, incoming: LwwRegisterCRDT<T>) -> bool {
        let local_now = now_ms();
        // Reject u64::MAX outright — no legitimate clock will ever produce it,
        // and accepting it would lock the register forever.
        if incoming.timestamp == u64::MAX {
            tracing::warn!("CRDT merge rejected: u64::MAX timestamp (time-warp poisoning)");
            return false;
        }
        let drift = if incoming.timestamp >= local_now {
            incoming.timestamp - local_now
        } else {
            local_now - incoming.timestamp
        };
        if drift > MAX_CLOCK_DRIFT_MS {
            tracing::warn!(
                "CRDT merge rejected: drift {} ms exceeds {} ms",
                drift,
                MAX_CLOCK_DRIFT_MS
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_time_warp_max() {
        let mut crdt = LwwRegisterCRDT::new("local".to_string(), "node_a".to_string(), 100);
        let attacker = LwwRegisterCRDT::new("pwned".to_string(), "node_b".to_string(), u64::MAX);
        assert!(!crdt.merge(attacker), "u64::MAX timestamp must be rejected");
        assert_eq!(crdt.value, "local");
        assert_eq!(crdt.timestamp, 100);
    }

    #[test]
    fn test_rejects_future_poisoning() {
        let mut crdt = LwwRegisterCRDT::new("local".to_string(), "node_a".to_string(), 100);
        let future = now_ms() + MAX_CLOCK_DRIFT_MS + 10_000;
        let attacker = LwwRegisterCRDT::new("pwned".to_string(), "node_b".to_string(), future);
        assert!(
            !crdt.merge(attacker),
            "far-future timestamp must be rejected"
        );
        assert_eq!(crdt.value, "local");
    }

    #[test]
    fn test_rejects_stale_value() {
        let mut crdt = LwwRegisterCRDT::new("local".to_string(), "node_a".to_string(), now_ms());
        let stale = now_ms() - MAX_CLOCK_DRIFT_MS - 10_000;
        let old = LwwRegisterCRDT::new("stale".to_string(), "node_b".to_string(), stale);
        assert!(!crdt.merge(old), "stale timestamp must be rejected");
        assert_eq!(crdt.value, "local");
    }

    #[test]
    fn test_accepts_in_window() {
        let mut crdt = LwwRegisterCRDT::new("local".to_string(), "node_a".to_string(), 100);
        let fresh = now_ms() + 100; // 100ms in the future — within drift bound
        let incoming = LwwRegisterCRDT::new("fresh".to_string(), "node_b".to_string(), fresh);
        assert!(crdt.merge(incoming));
        assert_eq!(crdt.value, "fresh");
    }
}
