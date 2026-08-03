use super::super::persist::persist;
use super::super::services::lock_state;
use super::super::types::*;
use std::sync::Mutex;

pub struct SettingsService {
    inner: Mutex<AppSettings>,
    settings_path: String,
}

impl SettingsService {
    pub fn new(settings_path: String) -> Self {
        Self {
            inner: Mutex::new(AppSettings::default()),
            settings_path,
        }
    }
    pub fn save_settings(&self) {
        let data = serde_json::to_string_pretty(&*lock_state(&self.inner)).ok();
        if let Some(serialized) = data {
            persist(self.settings_path.clone(), serialized);
        }
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, AppSettings> {
        lock_state(&self.inner)
    }
}
