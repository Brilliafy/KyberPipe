use std::fs::File;
use std::io::Write;
use std::sync::mpsc;
use std::sync::Mutex;
use std::sync::OnceLock;
use super::types::*;

type PersistJob = (String, String);

fn persist_channel() -> &'static mpsc::SyncSender<PersistJob> {
    static CHAN: OnceLock<mpsc::SyncSender<PersistJob>> = OnceLock::new();
    CHAN.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<PersistJob>(16);
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

pub fn lock_state<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| {
        tracing::error!("[CRITICAL STATE ERROR] Mutex poisoned! Recovering inner state: {:?}", e);
        e.into_inner()
    })
}

/// Independent Crypto Service Singleton — isolates keypair & session key state.
pub struct CryptoService {
    inner: Mutex<CryptoState>,
}

impl Default for CryptoService {
    fn default() -> Self {
        Self { inner: Mutex::new(CryptoState::default()) }
    }
}

impl CryptoService {
    pub fn get_keypair(&self) -> Option<core_crypto::PqKeyPair> {
        lock_state(&self.inner).keypair.clone()
    }
    pub fn set_keypair(&self, pair: Option<core_crypto::PqKeyPair>) {
        lock_state(&self.inner).keypair = pair;
    }
    pub fn get_session_key_string(&self) -> String {
        lock_state(&self.inner).session_key.to_string()
    }
    pub fn set_session_key(&self, key: SecureString) {
        lock_state(&self.inner).session_key = key;
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, CryptoState> {
        lock_state(&self.inner)
    }
}

/// Independent Pairing Service Singleton — isolates pairing handshake & SAS code state.
pub struct PairingService {
    inner: Mutex<PairingState>,
}

impl Default for PairingService {
    fn default() -> Self {
        Self { inner: Mutex::new(PairingState::default()) }
    }
}

impl PairingService {
    pub fn get_pairing_read(&self) -> (String, String) {
        let p = lock_state(&self.inner);
        (p.sas_code.clone(), p.pending_session_key.to_string())
    }
    pub fn clear_pairing_stale(&self) {
        let mut p = lock_state(&self.inner);
        p.pending_session_key = SecureString::new(String::new());
        p.pending_client_cert_hash.clear();
        p.sas_code.clear();
        p.pending_pairing_nonce.clear();
    }
    pub fn get_sas_code(&self) -> String {
        lock_state(&self.inner).sas_code.clone()
    }
    pub fn set_sas_code(&self, code: String) {
        lock_state(&self.inner).sas_code = code;
    }
    pub fn clear_sas_code(&self) {
        lock_state(&self.inner).sas_code.clear();
    }
    pub fn is_pairing_pending(&self) -> bool {
        let p = lock_state(&self.inner);
        !p.sas_code.is_empty() && !p.pending_session_key.is_empty()
    }
    pub fn get_pending_session_key(&self) -> String {
        lock_state(&self.inner).pending_session_key.to_string()
    }
    pub fn set_pending_session_key(&self, key: SecureString) {
        lock_state(&self.inner).pending_session_key = key;
    }
    pub fn get_pending_shared_secret(&self) -> String {
        lock_state(&self.inner).pending_shared_secret.to_string()
    }
    pub fn set_pending_shared_secret(&self, secret: SecureString) {
        lock_state(&self.inner).pending_shared_secret = secret;
    }
    pub fn get_pending_client_cert_hash(&self) -> String {
        lock_state(&self.inner).pending_client_cert_hash.clone()
    }
    pub fn set_pending_client_cert_hash(&self, hash: String) {
        lock_state(&self.inner).pending_client_cert_hash = hash;
    }
    pub fn get_pending_pairing_nonce(&self) -> String {
        lock_state(&self.inner).pending_pairing_nonce.clone()
    }
    pub fn set_pending_pairing_nonce(&self, nonce: String) {
        lock_state(&self.inner).pending_pairing_nonce = nonce;
    }
    pub fn get_paired_client_cert_hash(&self) -> String {
        lock_state(&self.inner).paired_client_cert_hash.clone()
    }
    pub fn set_paired_client_cert_hash(&self, hash: String) {
        lock_state(&self.inner).paired_client_cert_hash = hash;
    }
    pub fn get_paired_peer_ip(&self) -> String {
        lock_state(&self.inner).paired_peer_ip.clone()
    }
    pub fn set_paired_peer_ip(&self, ip: String) {
        lock_state(&self.inner).paired_peer_ip = ip;
    }
    pub fn get_pairing_initiator_pk(&self) -> String {
        lock_state(&self.inner).initiator_pk.clone()
    }
    pub fn set_pairing_initiator_pk(&self, pk: String) {
        lock_state(&self.inner).initiator_pk = pk;
    }
    pub fn get_pairing_initiator_x25519_pk(&self) -> String {
        lock_state(&self.inner).initiator_x25519_pk.clone()
    }
    pub fn set_pairing_initiator_x25519_pk(&self, pk: String) {
        lock_state(&self.inner).initiator_x25519_pk = pk;
    }
    pub fn get_sas_attempt_count(&self) -> u32 {
        lock_state(&self.inner).attempt_count
    }
    pub fn increment_sas_attempt_count(&self) {
        lock_state(&self.inner).attempt_count += 1;
    }
    pub fn reset_sas_attempt_count(&self) {
        lock_state(&self.inner).attempt_count = 0;
    }
    pub fn clear_all_pairing(&self) {
        let mut p = lock_state(&self.inner);
        p.sas_code.clear();
        p.pending_session_key = SecureString::new(String::new());
        p.pending_shared_secret = SecureString::new(String::new());
        p.initiator_pk.clear();
        p.attempt_count = 0;
        p.pending_client_cert_hash.clear();
        p.paired_client_cert_hash.clear();
        p.paired_peer_ip.clear();
        p.pending_pairing_nonce.clear();
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, PairingState> {
        lock_state(&self.inner)
    }
}

/// Independent Network Service Singleton — isolates QUIC bridge & Tor connection management.
pub struct NetworkService {
    inner: Mutex<NetworkState>,
}

impl Default for NetworkService {
    fn default() -> Self {
        Self { inner: Mutex::new(NetworkState::default()) }
    }
}

impl NetworkService {
    pub fn get_connection_status(&self) -> String {
        lock_state(&self.inner).connection.status.clone()
    }
    pub fn set_connection_status(&self, status: String) {
        lock_state(&self.inner).connection.status = status;
    }
    pub fn get_connection_method(&self) -> String {
        lock_state(&self.inner).connection.method.clone()
    }
    pub fn set_connection_method(&self, method: String) {
        lock_state(&self.inner).connection.method = method;
    }
    pub fn get_connection_color(&self) -> String {
        lock_state(&self.inner).connection.color.clone()
    }
    pub fn set_connection_color(&self, color: String) {
        lock_state(&self.inner).connection.color = color;
    }
    pub fn get_connection(&self) -> ConnectionState {
        let is_connected = core_crypto::quic_bridge::is_quic_connected();
        let net = lock_state(&self.inner);
        if !is_connected {
            ConnectionState {
                status: "DISCONNECTED".to_string(),
                method: net.connection.method.clone(),
                color: "red".to_string(),
            }
        } else {
            net.connection.clone()
        }
    }
    pub fn set_connection(&self, status: String, method: String, color: String) {
        let mut n = lock_state(&self.inner);
        n.connection.status = status;
        n.connection.method = method;
        n.connection.color = color;
    }
    pub fn take_tor_child(&self) -> Option<std::process::Child> {
        lock_state(&self.inner).tor_child.take()
    }
    pub fn set_tor_child(&self, child: std::process::Child) {
        lock_state(&self.inner).tor_child = Some(child);
    }
    pub fn merge_mesh_crdt(&self, incoming: core_crypto::crypto::LwwRegisterCRDT<String>) -> bool {
        lock_state(&self.inner).mesh_crdt.merge(incoming)
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, NetworkState> {
        lock_state(&self.inner)
    }
}

/// Independent UI Service Singleton — isolates logs & media player state.
pub struct UiService {
    inner: Mutex<UiState>,
}

impl Default for UiService {
    fn default() -> Self {
        Self { inner: Mutex::new(UiState::default()) }
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
    pub fn lock(&self) -> std::sync::MutexGuard<'_, UiState> {
        lock_state(&self.inner)
    }
}

/// Independent Clipboard Service Singleton — isolates deduplication & history.
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
    pub fn is_suppressed_duplicate(&self, text: &str) -> bool {
        lock_state(&self.inner).dedup.is_suppressed(text)
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
    pub fn save_notifications(&self) {
        let data = serde_json::to_string_pretty(&lock_state(&self.inner).sync_history.notifications).ok();
        if let Some(serialized) = data {
            let _ = persist_channel().send((self.notifications_path.clone(), serialized));
        }
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, ClipboardState> {
        lock_state(&self.inner)
    }
}

/// Independent Settings Service Singleton — isolates persistence & app settings.
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
            let _ = persist_channel().send((self.settings_path.clone(), serialized));
        }
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, AppSettings> {
        lock_state(&self.inner)
    }
}
