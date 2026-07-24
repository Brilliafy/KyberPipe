use core_crypto::crypto::ClipboardDeduplicator;
use core_crypto::packets::{SensorPacket, SmsPacket};
use core_crypto::PqKeyPair;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Mutex;
use std::sync::MutexGuard;

#[allow(dead_code)]
/// Poison-recovery helper: returns the guard even if the lock is poisoned
pub fn lock_or_recover<T>(mtx: &Mutex<T>) -> MutexGuard<'_, T> {
    mtx.lock().unwrap_or_else(|e| e.into_inner())
}

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
    pub wireguard_active: bool,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct MediaAction {
    pub title: String,
    pub index: u32,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct MediaState {
    pub title: String,
    pub artist: String,
    pub album_art: String,
    pub is_playing: bool,
    pub actions: Vec<MediaAction>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NotificationRecord {
    pub id: String,
    pub title: String,
    pub text: String,
    pub app_package: String,
    pub timestamp: u64,
    pub is_dismissed: bool,
    pub updated_at: u64,
    pub type_field: String, // "local" | "remote"
}

pub struct ConnectionState {
    pub status: String,
    pub method: String,
    pub color: String,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            status: "DISCONNECTED".to_string(),
            method: "None".to_string(),
            color: "red".to_string(),
        }
    }
}

pub struct AppState {
    pub keypair: Mutex<Option<PqKeyPair>>,
    pub session_key: Mutex<zeroize::Zeroizing<String>>,
    pub pending_session_key: Mutex<zeroize::Zeroizing<String>>,
    pub sas_code: Mutex<String>,
    pub dedup: ClipboardDeduplicator,
    pub logs: Mutex<Vec<String>>,
    pub sensor_history: Mutex<Vec<SensorPacket>>,
    pub sms_history: Mutex<Vec<SmsPacket>>,
    pub notification_history: Mutex<Vec<NotificationRecord>>,
    pub connection: Mutex<ConnectionState>,
    pub settings: Mutex<AppSettings>,
    pub settings_path: String,
    #[allow(dead_code)]
    pub notifications_path: String,
    pub media_state: Mutex<MediaState>,
    pub pending_media_action: Mutex<Option<u32>>,
}

impl Default for AppState {
    fn default() -> Self {
        // Use OS-standard app data directory for persistence
        let data_dir =
            if let Some(proj_dirs) = directories::ProjectDirs::from("io", "github", "KyberPipe") {
                let dir = proj_dirs.data_dir().to_path_buf();
                let _ = std::fs::create_dir_all(&dir);
                dir
            } else {
                std::env::current_dir().unwrap_or_default()
            };
        let settings_path = data_dir.join("settings.json").to_string_lossy().to_string();
        let mut settings = AppSettings::default();
        let mut exists = false;
        if let Ok(mut file) = File::open(&settings_path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(loaded) = serde_json::from_str::<AppSettings>(&contents) {
                    settings = loaded;
                    exists = true;
                }
            }
        }
        if !exists {
            settings.wireguard_active = true;
        }

        let notifications_path = data_dir
            .join("notifications.json")
            .to_string_lossy()
            .to_string();
        let mut notifications = vec![];
        if let Ok(mut file) = File::open(&notifications_path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(loaded) = serde_json::from_str::<Vec<NotificationRecord>>(&contents) {
                    notifications = loaded;
                }
            }
        }

        Self {
            keypair: Mutex::new(None),
            session_key: Mutex::new(zeroize::Zeroizing::new(String::new())),
            pending_session_key: Mutex::new(zeroize::Zeroizing::new(String::new())),
            sas_code: Mutex::new(String::new()),
            dedup: ClipboardDeduplicator::new(),
            logs: Mutex::new(vec!["[Kyberpipe] Engine initialized".to_string()]),
            sensor_history: Mutex::new(vec![]),
            sms_history: Mutex::new(vec![]),
            notification_history: Mutex::new(notifications),
            connection: Mutex::new(ConnectionState::default()),
            settings: Mutex::new(settings),
            settings_path,
            notifications_path,
            media_state: Mutex::new(MediaState::default()),
            pending_media_action: Mutex::new(None),
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

    // Backward-compatible accessors for connection state (consolidated under one Mutex)
    pub fn get_connection_status(&self) -> String {
        self.connection
            .lock()
            .map(|c| c.status.clone())
            .unwrap_or_default()
    }
    pub fn set_connection_status(&self, val: String) {
        if let Ok(mut c) = self.connection.lock() {
            c.status = val;
        }
    }
    #[allow(dead_code)]
    pub fn get_connection_method(&self) -> String {
        self.connection
            .lock()
            .map(|c| c.method.clone())
            .unwrap_or_default()
    }
    pub fn set_connection_method(&self, val: String) {
        if let Ok(mut c) = self.connection.lock() {
            c.method = val;
        }
    }
    #[allow(dead_code)]
    pub fn get_connection_color(&self) -> String {
        self.connection
            .lock()
            .map(|c| c.color.clone())
            .unwrap_or_default()
    }
    pub fn set_connection_color(&self, val: String) {
        if let Ok(mut c) = self.connection.lock() {
            c.color = val;
        }
    }
    pub fn get_connection(&self) -> ConnectionState {
        self.connection
            .lock()
            .map(|c| ConnectionState {
                status: c.status.clone(),
                method: c.method.clone(),
                color: c.color.clone(),
            })
            .unwrap_or_default()
    }
    pub fn set_connection(&self, status: String, method: String, color: String) {
        if let Ok(mut c) = self.connection.lock() {
            c.status = status;
            c.method = method;
            c.color = color;
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

    #[allow(dead_code)]
    pub fn save_notifications(&self) {
        if let Ok(notifs) = self.notification_history.lock() {
            if let Ok(serialized) = serde_json::to_string_pretty(&*notifs) {
                if let Ok(mut file) = File::create(&self.notifications_path) {
                    let _ = file.write_all(serialized.as_bytes());
                }
            }
        }
    }
}
