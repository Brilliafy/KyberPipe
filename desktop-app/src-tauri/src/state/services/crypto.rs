use super::super::services::lock_state;
use super::super::types::*;
use std::sync::Mutex;

pub struct CryptoService {
    inner: Mutex<CryptoState>,
}

impl Default for CryptoService {
    fn default() -> Self {
        Self {
            inner: Mutex::new(CryptoState::default()),
        }
    }
}

impl CryptoService {
    pub fn get_keypair(&self) -> Option<core_crypto::PqKeyPair> {
        lock_state(&self.inner).keypair.clone()
    }
    /// Replace the held keypair, ZEROIZING the previous one before dropping it
    /// (audit finding #16: unpair/self-destruct must not leave private halves
    /// in freed heap).
    pub fn set_keypair(&self, pair: Option<core_crypto::PqKeyPair>) {
        use zeroize::Zeroize;
        let mut state = lock_state(&self.inner);
        if let Some(prev) = state.keypair.as_mut() {
            prev.zeroize();
        }
        state.keypair = pair;
    }
    pub fn get_session_key_string(&self) -> String {
        lock_state(&self.inner).session_key.to_string()
    }
    pub fn set_session_key(&self, key: SecureString) {
        lock_state(&self.inner).session_key = key;
    }
    #[allow(dead_code)] // service API surface
    pub fn lock(&self) -> std::sync::MutexGuard<'_, CryptoState> {
        lock_state(&self.inner)
    }
}
