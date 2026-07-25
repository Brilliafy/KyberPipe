use core_crypto::crypto::ClipboardDeduplicator;
use core_crypto::packets::{SensorPacket, SmsPacket};
use core_crypto::PqKeyPair;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::sync::mpsc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Zeroizes the heap buffer of a String by overwriting each byte with zero.
/// Zeroizing<String> only clears stack fields (ptr, len, cap).
/// This reaches into the heap-allocated buffer to wipe the key material.
fn zeroize_string_heap(s: &mut String) {
    // Reserve slack capacity so as_bytes_mut covers the full allocation.
    // Without this, if the string previously held a larger secret that was
    // overwritten with a shorter one, the residual bytes between len and
    // capacity would survive zeroization.
    let cap = s.capacity();
    if cap > s.len() {
        s.reserve(cap - s.len());
    }
    let bytes = unsafe { s.as_bytes_mut() };
    bytes.zeroize();
    s.clear();
}

/// A String wrapper that properly zeroizes the heap-allocated buffer on drop.
/// Unlike bare Zeroizing<String>, this ensures the cryptographic key material
/// is actually overwritten in memory, not just the stack metadata.
#[derive(Clone, Default)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        zeroize_string_heap(&mut self.0);
    }
}

impl std::ops::Deref for SecureString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

type PersistJob = (String, String); // (path, serialized_data)

fn persist_channel() -> &'static mpsc::SyncSender<PersistJob> {
    static CHAN: OnceLock<mpsc::SyncSender<PersistJob>> = OnceLock::new();
    CHAN.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<PersistJob>(16);
        // Single background writer thread — prevents unbounded thread spawning
        // and concurrent writes corrupting the JSON file.
        std::thread::spawn(move || {
            for (path, data) in rx {
                if let Ok(mut file) = File::create(&path) {
                    let _ = file.write_all(data.as_bytes());
                }
            }
        });
        tx
    })
}

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
    pub session_key: Mutex<SecureString>,
    pub pending_session_key: Mutex<SecureString>,
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
    pub pairing_initiator_pk: Mutex<String>,
    pub tor_child: Mutex<Option<std::process::Child>>,
    pub sas_attempt_count: Mutex<u32>,
}

impl Default for AppState {
    fn default() -> Self {
        let data_dir =
            if let Some(proj_dirs) = directories::ProjectDirs::from("io", "github", "KyberPipe") {
                let dir = proj_dirs.data_dir().to_path_buf();
                let _ = std::fs::create_dir_all(&dir);
                dir
            } else {
                std::env::current_dir().unwrap_or_default()
            };
        let settings_path = data_dir.join("settings.json").to_string_lossy().to_string();
        let notifications_path = data_dir
            .join("notifications.json")
            .to_string_lossy()
            .to_string();

        Self {
            keypair: Mutex::new(None),
            session_key: Mutex::new(SecureString::new(String::new())),
            pending_session_key: Mutex::new(SecureString::new(String::new())),
            sas_code: Mutex::new(String::new()),
            dedup: ClipboardDeduplicator::new(),
            logs: Mutex::new(vec!["[Kyberpipe] Engine initialized".to_string()]),
            sensor_history: Mutex::new(vec![]),
            sms_history: Mutex::new(vec![]),
            notification_history: Mutex::new(vec![]),
            connection: Mutex::new(ConnectionState::default()),
            settings: Mutex::new(AppSettings::default()),
            settings_path,
            notifications_path,
            media_state: Mutex::new(MediaState::default()),
            pending_media_action: Mutex::new(None),
            pairing_initiator_pk: Mutex::new(String::new()),
            tor_child: Mutex::new(None),
            sas_attempt_count: Mutex::new(0),
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

    pub fn is_pairing_pending(&self) -> bool {
        let sas = self.sas_code.lock().ok();
        let pending = self.pending_session_key.lock().ok();
        sas.map(|s| !s.is_empty()).unwrap_or(false)
            && pending.map(|p| !p.is_empty()).unwrap_or(false)
    }

    pub fn save_settings(&self) {
        let data = self
            .settings
            .lock()
            .ok()
            .and_then(|settings| serde_json::to_string_pretty(&*settings).ok());
        if let Some(serialized) = data {
            let path = self.settings_path.clone();
            let _ = persist_channel().send((path, serialized));
        }
    }

    #[allow(dead_code)]
    pub fn save_notifications(&self) {
        let data = self
            .notification_history
            .lock()
            .ok()
            .and_then(|notifs| serde_json::to_string_pretty(&*notifs).ok());
        if let Some(serialized) = data {
            let path = self.notifications_path.clone();
            let _ = persist_channel().send((path, serialized));
        }
    }
}
