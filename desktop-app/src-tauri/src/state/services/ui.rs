use super::super::services::lock_state;
use super::super::types::*;
use std::sync::Mutex;

pub struct UiService {
    inner: Mutex<UiState>,
}

impl Default for UiService {
    fn default() -> Self {
        Self {
            inner: Mutex::new(UiState::default()),
        }
    }
}

impl UiService {
    pub fn add_log(&self, msg: String) {
        let mut ui = lock_state(&self.inner);
        if ui.logs.len() >= 100 {
            ui.logs.remove(0);
        }
        ui.logs.push(msg);
    }
    pub fn get_logs(&self) -> Vec<String> {
        lock_state(&self.inner).logs.clone()
    }
    pub fn get_media_state(&self) -> MediaState {
        lock_state(&self.inner).media_state.clone()
    }
    pub fn set_media_state(&self, state: MediaState) {
        lock_state(&self.inner).media_state = state;
    }
    pub fn get_pending_media_action(&self) -> Option<u32> {
        let mut ui = lock_state(&self.inner);
        let prev = ui.pending_media_action;
        ui.pending_media_action = None;
        prev
    }
    pub fn set_pending_media_action(&self, action: Option<u32>) {
        lock_state(&self.inner).pending_media_action = action;
    }
    #[allow(dead_code)] // service API surface
    pub fn lock(&self) -> std::sync::MutexGuard<'_, UiState> {
        lock_state(&self.inner)
    }
}
