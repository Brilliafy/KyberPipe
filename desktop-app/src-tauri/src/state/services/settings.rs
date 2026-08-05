use super::super::persist::persist;
use super::super::services::lock_state;
use super::super::types::*;
use std::sync::Mutex;

pub struct SettingsService {
    inner: Mutex<AppSettings>,
    settings_path: String,
}

impl SettingsService {
    /// Parse persisted settings from disk. Public so the load path is
    /// unit-testable directly, even though the constructor (gated to
    /// production) is what exercises it at startup.
    pub fn load_from_disk(settings_path: &str) -> AppSettings {
        std::fs::read_to_string(settings_path)
            .ok()
            .and_then(|data| serde_json::from_str::<AppSettings>(&data).ok())
            .unwrap_or_default()
    }

    pub fn new(settings_path: String) -> Self {
        // AUDIT F1 FIX: LOAD the persisted settings at startup. The legacy
        // constructor always started from `AppSettings::default()`, so every
        // restart discarded ALL persisted settings — including `is_paired` —
        // and the first `save_settings()` call (which `run()` issues during
        // boot) then OVERWROTE the file with defaults. Loading here makes the
        // persisted `is_paired` and the pairing-identity fields survive a
        // restart; a missing or corrupt file falls back to defaults.
        //
        // In unit tests the constructor stays fresh so state-dependent tests
        // (`authorize_stream_matrix`, wire-format tests) are hermetic even
        // when a REAL user `settings.json` exists in the app data dir. The
        // load path itself is covered by the `load_from_disk` tests below.
        #[cfg(not(test))]
        let inner = Self::load_from_disk(&settings_path);
        #[cfg(test)]
        let inner = AppSettings::default();
        Self {
            inner: Mutex::new(inner),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// AUDIT F1 FIX: the startup load path must actually restore persisted
    /// settings (is_paired + the pairing-identity fields) — the constructor's
    /// load is gated out of tests, so this exercises the loader directly with
    /// a temp file.
    #[test]
    fn load_from_disk_restores_persisted_settings() {
        let dir =
            std::env::temp_dir().join(format!("kyberpipe-settings-test-{}", std::process::id()));
        let path = dir.join("settings.json");
        let _ = std::fs::create_dir_all(&dir);
        let cert_hash = "ab".repeat(32);
        std::fs::write(
            &path,
            format!(
                r#"{{"is_paired":true,"paired_device_name":"Test Phone","paired_client_cert_hash":"{cert_hash}","pairing_initiator_pk":"cc","peer_cert_ratchet_map":{{"dd":"ee"}}}}"#
            ),
        )
        .unwrap();
        let loaded = SettingsService::load_from_disk(path.to_str().unwrap());
        assert!(loaded.is_paired, "is_paired must be restored");
        assert_eq!(loaded.paired_device_name.as_deref(), Some("Test Phone"));
        assert_eq!(loaded.paired_client_cert_hash, cert_hash);
        assert_eq!(loaded.pairing_initiator_pk, "cc");
        assert_eq!(
            loaded.peer_cert_ratchet_map.get("dd").map(String::as_str),
            Some("ee")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Missing / corrupt files fall back to defaults (never panic).
    #[test]
    fn load_from_disk_missing_file_falls_back_to_defaults() {
        let loaded = SettingsService::load_from_disk("/nonexistent/kyberpipe/settings.json");
        assert!(!loaded.is_paired);
        assert!(loaded.paired_client_cert_hash.is_empty());
        assert!(loaded.peer_cert_ratchet_map.is_empty());
    }
}
