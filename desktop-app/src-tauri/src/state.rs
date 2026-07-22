use core_crypto::crypto::ClipboardDeduplicator;
use core_crypto::packets::{NotificationPacket, SensorPacket, SmsPacket};
use core_crypto::PqKeyPair;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::{Read, Write};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct AppSettings {
    pub device_name: Option<String>,
    pub device_picture: Option<String>, // Base64 profile pic
    pub paired_device_name: Option<String>,
    pub paired_device_picture: Option<String>,
    pub ddns_hostname: String,
    pub enable_upnp: bool,
    pub enable_ddns: bool,
    pub is_paired: bool,
    pub file_access_granted_desktop: bool,
    pub file_access_granted_phone: bool,
    pub theme_mode: Option<String>,
    pub pathway_order: Option<Vec<String>>,
}

pub struct AppState {
    pub keypair: Mutex<Option<PqKeyPair>>,
    pub dedup: ClipboardDeduplicator,
    pub logs: Mutex<Vec<String>>,
    pub sensor_history: Mutex<Vec<SensorPacket>>,
    pub sms_history: Mutex<Vec<SmsPacket>>,
    pub notification_history: Mutex<Vec<NotificationPacket>>,
    pub connection_status: Mutex<String>,
    pub connection_method: Mutex<String>, // "Wi-Fi Direct", "mDNS LAN", "WireGuard WAN"
    pub connection_color: Mutex<String>,  // "green", "yellow", "red"
    pub settings: Mutex<AppSettings>,
    pub settings_path: String,
}

impl Default for AppState {
    fn default() -> Self {
        let settings_path = "settings.json".to_string();
        let mut settings = AppSettings::default();
        if let Ok(mut file) = File::open(&settings_path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(loaded) = serde_json::from_str::<AppSettings>(&contents) {
                    settings = loaded;
                }
            }
        }

        Self {
            keypair: Mutex::new(None),
            dedup: ClipboardDeduplicator::new(),
            logs: Mutex::new(vec!["[Kyberpipe] Engine initialized".to_string()]),
            sensor_history: Mutex::new(vec![]),
            sms_history: Mutex::new(vec![]),
            notification_history: Mutex::new(vec![]),
            connection_status: Mutex::new("DISCONNECTED".to_string()),
            connection_method: Mutex::new("None".to_string()),
            connection_color: Mutex::new("red".to_string()),
            settings: Mutex::new(settings),
            settings_path,
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

    pub fn save_settings(&self) {
        if let Ok(settings) = self.settings.lock() {
            if let Ok(serialized) = serde_json::to_string_pretty(&*settings) {
                if let Ok(mut file) = File::create(&self.settings_path) {
                    let _ = file.write_all(serialized.as_bytes());
                }
            }
        }
    }
}
