use super::types::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::mpsc;
use std::sync::Mutex;
use std::sync::OnceLock;

type PersistJob = (String, String);

/// Non-blocking, COALESCING persistence channel (audit finding #22). The
/// consumer drains the queue on every wake and writes only the LATEST value
/// per path, so a slow filesystem never blocks a Tauri command on the main
/// thread and an intermediate stale write is dropped without loss (the newest
/// value for each path always lands). An UNBOUNDED channel is used so
/// `persist()` is a pure enqueue that can never block even under a full
/// buffer; the drain-and-coalesce consumer bounds memory in practice (only one
/// value per path is retained at write time).
fn persist_channel() -> &'static mpsc::Sender<PersistJob> {
    static CHAN: OnceLock<mpsc::Sender<PersistJob>> = OnceLock::new();
    CHAN.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<PersistJob>();
        std::thread::spawn(move || {
            let mut latest: HashMap<String, String> = HashMap::new();
            while let Ok((path, data)) = rx.recv() {
                latest.insert(path, data);
                while let Ok((p2, d2)) = rx.try_recv() {
                    latest.insert(p2, d2);
                }
                for (path, data) in latest.drain() {
                    if let Ok(mut file) = File::create(&path) {
                        let _ = file.write_all(data.as_bytes());
                    }
                }
            }
        });
        tx
    })
}

/// Enqueue a persistence job WITHOUT blocking the caller. `mpsc::Sender::send`
/// on an unbounded channel never blocks, so a slow FS or a busy persistence
/// thread can never stall a Tauri command (audit finding #22).
fn persist(path: String, data: String) {
    let _ = persist_channel().send((path, data));
}

pub fn lock_state<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| {
        tracing::error!(
            "[CRITICAL STATE ERROR] Mutex poisoned! Recovering inner state: {:?}",
            e
        );
        e.into_inner()
    })
}

/// Independent Crypto Service Singleton — isolates keypair & session key state.
pub struct CryptoService {
    inner: Mutex<CryptoState>,
}

impl Default for CryptoService {
    fn default() -> Self {
        Self {
            inner: Mutex::new(CryptoState::default()),
        }
    }
}

impl CryptoService {
    pub fn get_keypair(&self) -> Option<core_crypto::PqKeyPair> {
        lock_state(&self.inner).keypair.clone()
    }
    /// Replace the held keypair, ZEROIZING the previous one before dropping it
    /// (audit finding #16: unpair/self-destruct must not leave private halves
    /// in freed heap).
    pub fn set_keypair(&self, pair: Option<core_crypto::PqKeyPair>) {
        use zeroize::Zeroize;
        let mut state = lock_state(&self.inner);
        if let Some(prev) = state.keypair.as_mut() {
            prev.zeroize();
        }
        state.keypair = pair;
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
        Self {
            inner: Mutex::new(PairingState::default()),
        }
    }
}

impl PairingService {
    pub fn get_pairing_read(&self) -> (String, String) {
        let p = lock_state(&self.inner);
        (p.sas_code.clone(), p.pending_session_key.to_string())
    }
    /// Transition: begin a new KEM pairing attempt. Clears every per-attempt
    /// field (audit finding #24 — ONE transition instead of the old two
    /// divergent "clear" methods) while deliberately PRESERVING the mandatory
    /// QR nonce (audit finding #20) and any confirmed paired identity.
    pub fn begin_pairing_attempt(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        p.phase = PairingPhase::PendingKem;
        p.sas_code.clear();
        p.pending_session_key = SecureString::new(String::new());
        p.pending_shared_secret = SecureString::new(String::new());
        p.initiator_pk.clear();
        p.initiator_x25519_pk.clear();
        p.attempt_count = 0;
        p.pending_client_cert_hash.clear();
        p.phase
    }
    /// Transition: a SAS code has been computed for the pending KEM.
    pub fn promote_to_sas_pending(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        if p.phase == PairingPhase::PendingKem {
            p.phase = PairingPhase::SasPending;
        }
        p.phase
    }
    /// Transition: SAS verified — the session is promoted. Clears the pending
    /// handshake state (the caller persists the session key + ratchet first).
    pub fn confirm_pairing(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        p.phase = PairingPhase::Confirmed;
        p.sas_code.clear();
        p.pending_session_key = SecureString::new(String::new());
        p.pending_shared_secret = SecureString::new(String::new());
        p.attempt_count = 0;
        p.pending_client_cert_hash.clear();
        p.phase
    }
    /// Transition: the SAS window expired without confirmation.
    pub fn timeout_pairing(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        if p.phase == PairingPhase::SasPending {
            p.phase = PairingPhase::TimedOut;
            p.sas_code.clear();
            p.pending_session_key = SecureString::new(String::new());
            p.pending_shared_secret = SecureString::new(String::new());
            p.pending_client_cert_hash.clear();
        }
        p.phase
    }
    /// Transition: the pairing was explicitly rejected (nonce mismatch, rate
    /// limit, bad KEM).
    pub fn fail_pairing(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        p.phase = PairingPhase::Failed;
        p.sas_code.clear();
        p.pending_session_key = SecureString::new(String::new());
        p.pending_shared_secret = SecureString::new(String::new());
        p.pending_client_cert_hash.clear();
        p.phase
    }
    /// Current pairing phase.
    pub fn phase(&self) -> PairingPhase {
        lock_state(&self.inner).phase
    }
    /// Clear STALE per-attempt pairing state — now an alias of the single
    /// `begin_pairing_attempt` transition (audit finding #24). The mandatory QR
    /// nonce (audit finding #20) is preserved.
    pub fn clear_pairing_stale(&self) {
        self.begin_pairing_attempt();
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
    /// Issue a FRESH QR pairing nonce (audit finding #20): the nonce gate is
    /// mandatory — every pairing request must echo a nonce this desktop issued,
    /// so an arbitrary LAN peer that never saw the QR cannot occupy the pairing
    /// slot. Issued at app start (not only at QR build) so a pairing attempt
    /// with no nonce is rejected outright instead of bypassing the gate.
    pub fn issue_fresh_nonce(&self) -> String {
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        let nonce = hex::encode(&bytes);
        self.set_pending_pairing_nonce(nonce.clone());
        nonce
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
        p.phase = PairingPhase::Idle;
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
        Self {
            inner: Mutex::new(NetworkState::default()),
        }
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
            persist(self.settings_path.clone(), serialized);
        }
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, AppSettings> {
        lock_state(&self.inner)
    }
}
