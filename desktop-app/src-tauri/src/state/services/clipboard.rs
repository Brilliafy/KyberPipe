use super::super::persist::persist;
use super::super::services::lock_state;
use super::super::types::*;
use std::sync::Mutex;

pub struct ClipboardService {
    inner: Mutex<ClipboardState>,
    notifications_path: String,
}

impl ClipboardService {
    pub fn new(notifications_path: String) -> Self {
        Self {
            inner: Mutex::new(ClipboardState::default()),
            notifications_path,
        }
    }
    pub fn record_clipboard_text(&self, text: &str) {
        lock_state(&self.inner).dedup.record_text(text);
    }
    pub fn check_and_record_clipboard(&self, text: &str) -> bool {
        lock_state(&self.inner).dedup.check_and_record(text)
    }
    pub fn get_sensor_history(&self) -> Vec<core_crypto::packets::SensorPacket> {
        lock_state(&self.inner).sync_history.sensor.clone()
    }
    pub fn add_sensor_packet(&self, packet: core_crypto::packets::SensorPacket) {
        lock_state(&self.inner).sync_history.sensor.push(packet);
    }
    pub fn get_sms_history(&self) -> Vec<core_crypto::packets::SmsPacket> {
        lock_state(&self.inner).sync_history.sms.clone()
    }
    pub fn add_sms_packet(&self, pkt: core_crypto::packets::SmsPacket) {
        lock_state(&self.inner).sync_history.sms.push(pkt);
    }
    pub fn get_notifications(&self) -> Vec<NotificationRecord> {
        lock_state(&self.inner).sync_history.notifications.clone()
    }
    pub fn add_notification(&self, pkt: NotificationRecord) {
        lock_state(&self.inner).sync_history.notifications.push(pkt);
    }
    /// Persist the notification/SMS history ENCRYPTED at rest (audit finding
    /// #21): the serialized JSON is AEAD-wrapped with the independent snapshot
    /// key before writing — plaintext privacy data (Signal/WhatsApp content
    /// captured via MessagingStyle) must never sit on disk. On any encryption
    /// failure the write is SKIPPED (never plaintext).
    pub fn save_notifications(&self) {
        let data =
            serde_json::to_string_pretty(&lock_state(&self.inner).sync_history.notifications)
                .unwrap_or_else(|_| "[]".to_string());
        let key = crate::ratchet_store::snapshot_key_from_keyring();
        let Some(blob) =
            key.and_then(|k| crate::ratchet_store::encrypt_notifications_data(&k, data.as_bytes()))
        else {
            tracing::warn!(
                "[NotifyStore] No snapshot key — NOT persisting plaintext notifications"
            );
            return;
        };
        persist(self.notifications_path.clone(), blob);
    }
    /// Load and decrypt the persisted notification history at startup
    /// (audit finding #21: the encrypted blob is the only at-rest format).
    pub fn load_notifications(&self) -> Vec<NotificationRecord> {
        let Ok(blob) = std::fs::read_to_string(&self.notifications_path) else {
            return Vec::new();
        };
        let key = crate::ratchet_store::snapshot_key_from_keyring();
        let Some(key) = key else {
            return Vec::new();
        };
        let Some(bytes) = crate::ratchet_store::decrypt_notifications_data(&key, &blob) else {
            tracing::warn!("[NotifyStore] Notification history failed to decrypt — ignoring");
            return Vec::new();
        };
        serde_json::from_slice(&bytes).unwrap_or_default()
    }
    #[allow(dead_code)] // service API surface
    pub fn lock(&self) -> std::sync::MutexGuard<'_, ClipboardState> {
        lock_state(&self.inner)
    }
}
