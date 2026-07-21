use core_crypto::crypto::ClipboardDeduplicator;
use core_crypto::packets::{NotificationPacket, SensorPacket, SmsPacket};
use core_crypto::PqKeyPair;
use std::sync::Mutex;

pub struct AppState {
    pub keypair: Mutex<Option<PqKeyPair>>,
    pub dedup: ClipboardDeduplicator,
    pub logs: Mutex<Vec<String>>,
    pub sensor_history: Mutex<Vec<SensorPacket>>,
    pub sms_history: Mutex<Vec<SmsPacket>>,
    pub notification_history: Mutex<Vec<NotificationPacket>>,
    pub connection_status: Mutex<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            keypair: Mutex::new(None),
            dedup: ClipboardDeduplicator::new(),
            logs: Mutex::new(vec!["[Kyberpipe] Engine initialized".to_string()]),
            sensor_history: Mutex::new(vec![]),
            sms_history: Mutex::new(vec![]),
            notification_history: Mutex::new(vec![]),
            connection_status: Mutex::new("Disconnected".to_string()),
        }
    }
}

impl AppState {
    pub fn add_log(&self, msg: String) {
        if let Ok(mut l) = self.logs.lock() {
            if l.len() >= 100 {
                l.remove(0);
            }
            l.push(msg);
        }
    }
}
