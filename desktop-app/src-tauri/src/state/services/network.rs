use super::super::services::lock_state;
use super::super::types::*;
use std::sync::Mutex;

pub struct NetworkService {
    inner: Mutex<NetworkState>,
}

impl Default for NetworkService {
    fn default() -> Self {
        Self {
            inner: Mutex::new(NetworkState::default()),
        }
    }
}

impl NetworkService {
    pub fn get_connection_status(&self) -> String {
        lock_state(&self.inner).connection.status.clone()
    }
    pub fn set_connection_status(&self, status: String) {
        lock_state(&self.inner).connection.status = status;
    }
    #[allow(dead_code)] // network API surface
    pub fn get_connection_method(&self) -> String {
        lock_state(&self.inner).connection.method.clone()
    }
    pub fn set_connection_method(&self, method: String) {
        lock_state(&self.inner).connection.method = method;
    }
    #[allow(dead_code)] // network API surface
    pub fn get_connection_color(&self) -> String {
        lock_state(&self.inner).connection.color.clone()
    }
    pub fn set_connection_color(&self, color: String) {
        lock_state(&self.inner).connection.color = color;
    }
    pub fn get_connection(&self) -> ConnectionState {
        let is_connected = core_crypto::quic_bridge::is_quic_connected();
        let net = lock_state(&self.inner);
        if !is_connected {
            ConnectionState {
                status: "DISCONNECTED".to_string(),
                method: net.connection.method.clone(),
                color: "red".to_string(),
            }
        } else {
            net.connection.clone()
        }
    }
    pub fn set_connection(&self, status: String, method: String, color: String) {
        let mut n = lock_state(&self.inner);
        n.connection.status = status;
        n.connection.method = method;
        n.connection.color = color;
    }
    #[allow(dead_code)] // network API surface
    pub fn take_tor_child(&self) -> Option<std::process::Child> {
        lock_state(&self.inner).tor_child.take()
    }
    pub fn set_tor_child(&self, child: std::process::Child) {
        lock_state(&self.inner).tor_child = Some(child);
    }
    pub fn merge_mesh_crdt(&self, incoming: core_crypto::crypto::LwwRegisterCRDT<String>) -> bool {
        lock_state(&self.inner).mesh_crdt.merge(incoming)
    }
    #[allow(dead_code)] // service API surface
    pub fn lock(&self) -> std::sync::MutexGuard<'_, NetworkState> {
        lock_state(&self.inner)
    }
}
