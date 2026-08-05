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
    ///
    /// AUDIT P3-3: picture fields written at rest with the `kpenc:v1:` marker
    /// (see [`Self::save_settings`]) are AEAD-unwrapped here so the in-memory
    /// value the renderer reads is always the plaintext base64 — the wrap only
    /// ever exists in `settings.json`. Legacy plaintext values (no marker)
    /// pass through untouched.
    pub fn load_from_disk(settings_path: &str) -> AppSettings {
        let mut settings = std::fs::read_to_string(settings_path)
            .ok()
            .and_then(|data| serde_json::from_str::<AppSettings>(&data).ok())
            .unwrap_or_default();
        if let Some(key) = crate::ratchet_store::snapshot_key_from_keyring() {
            for field in [
                &mut settings.device_picture,
                &mut settings.paired_device_picture,
            ] {
                if let Some(value) = field.as_mut() {
                    if value.starts_with(crate::ratchet_store::SETTINGS_MEDIA_WRAP_MARKER) {
                        *value = crate::ratchet_store::decrypt_settings_media_field(&key, value)
                            .unwrap_or_default();
                    }
                }
            }
        }
        settings
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
        // AUDIT P3-3: wrap the picture fields at REST. Avatar/identity images
        // may embed EXIF/location metadata and Android already stores them in
        // EncryptedSharedPreferences; the desktop must not leave them
        // plaintext in settings.json. The wrap happens ONLY on the serialized
        // copy — the in-memory value stays plaintext base64 for the renderer.
        // A keyring-less environment (no snapshot key) degrades to the legacy
        // plaintext write, exactly like the notification store.
        let data = {
            let mut settings = (*lock_state(&self.inner)).clone();
            if let Some(key) = crate::ratchet_store::snapshot_key_from_keyring() {
                for field in [
                    &mut settings.device_picture,
                    &mut settings.paired_device_picture,
                ] {
                    if let Some(value) = field.as_mut() {
                        if !value.is_empty()
                            && !value.starts_with(crate::ratchet_store::SETTINGS_MEDIA_WRAP_MARKER)
                        {
                            *value =
                                crate::ratchet_store::encrypt_settings_media_field(&key, value)
                                    .unwrap_or_else(|| value.clone());
                        }
                    }
                }
            }
            serde_json::to_string_pretty(&settings).ok()
        };
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

    /// AUDIT P3-3: settings media fields are AEAD-wrapped at rest with a
    /// marker prefix, and the round-trip must be lossless while legacy
    /// plaintext values pass through unwrap as None.
    #[test]
    fn settings_media_field_roundtrip_wraps_and_unwraps() {
        let key_hex = "ab".repeat(32);
        let plain = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
        let wrapped =
            crate::ratchet_store::encrypt_settings_media_field(&key_hex, plain).expect("wrap");
        assert!(
            wrapped.starts_with(crate::ratchet_store::SETTINGS_MEDIA_WRAP_MARKER),
            "wrapped value must carry the marker"
        );
        assert_ne!(wrapped, plain, "the field must never sit plaintext at rest");
        let unwrapped =
            crate::ratchet_store::decrypt_settings_media_field(&key_hex, &wrapped).expect("unwrap");
        assert_eq!(unwrapped, plain, "round-trip must be lossless");
        // A legacy plaintext value (no marker) is not wrapped and must be
        // returned as None so the load path leaves it untouched.
        assert!(
            crate::ratchet_store::decrypt_settings_media_field(&key_hex, plain).is_none(),
            "legacy plaintext must not be mistaken for a wrapped field"
        );
        // A wrong key must fail to decrypt (tamper / key-rotation detection).
        let wrong_key = "cd".repeat(32);
        assert!(
            crate::ratchet_store::decrypt_settings_media_field(&wrong_key, &wrapped).is_none(),
            "a wrong wrap key must not decrypt the field"
        );
    }
}
