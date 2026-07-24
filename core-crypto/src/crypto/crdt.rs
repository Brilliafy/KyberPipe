/// Last-Write-Wins Element-Set Conflict-Free Replicated Data Type (LWW-CRDT) for multi-device mesh
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LwwRegisterCRDT<T: Clone> {
    pub value: T,
    pub timestamp: u64,
    pub node_id: String,
}

impl<T: Clone> LwwRegisterCRDT<T> {
    pub fn new(value: T, node_id: String, timestamp: u64) -> Self {
        Self {
            value,
            timestamp,
            node_id,
        }
    }

    /// Merge incoming CRDT state; returns true if incoming state superseded local state
    pub fn merge(&mut self, incoming: LwwRegisterCRDT<T>) -> bool {
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
