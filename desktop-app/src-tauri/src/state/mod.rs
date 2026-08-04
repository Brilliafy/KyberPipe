pub mod persist;
pub mod services;
pub mod types;

pub use services::{
    ClipboardService, CryptoService, NetworkService, PairingService, SettingsService, UiService,
};
// Compatibility: the persistence writer teardown helper moved to `persist.rs`
// (audit F20); keep the e2e's existing path working.
#[allow(unused_imports)]
pub use persist::shutdown_persist_for_tests;
pub use types::*;

/// Decoupled Application State comprised of isolated, single-responsibility service singletons.
/// Cross-service interactions execute through dedicated service APIs rather than monolithic
/// lock hierarchies.
pub struct AppState {
    pub crypto: CryptoService,
    pub pairing: PairingService,
    pub network: NetworkService,
    pub ui: UiService,
    pub clipboard: ClipboardService,
    pub settings: SettingsService,
    #[allow(dead_code)] // persisted settings file path; retained for observability
    pub settings_path: String,
    #[allow(dead_code)]
    pub notifications_path: String,
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

        let clipboard = ClipboardService::new(notifications_path.clone());
        // Restore encrypted notification/SMS history at startup (audit finding
        // #21): the at-rest blob is AEAD-wrapped; load + decrypt it now.
        for record in clipboard.load_notifications() {
            clipboard.add_notification(record);
        }

        Self {
            crypto: CryptoService::default(),
            pairing: PairingService::default(),
            network: NetworkService::default(),
            ui: UiService::default(),
            clipboard,
            settings: SettingsService::new(settings_path.clone()),
            settings_path,
            notifications_path,
        }
    }
}

impl AppState {
    // ── Crypto Delegates ───────────────────────────────────────────────

    pub fn get_keypair(&self) -> Option<core_crypto::PqKeyPair> {
        self.crypto.get_keypair()
    }
    pub fn set_keypair(&self, pair: Option<core_crypto::PqKeyPair>) {
        self.crypto.set_keypair(pair);
    }
    pub fn get_session_key_string(&self) -> String {
        self.crypto.get_session_key_string()
    }
    pub fn set_session_key(&self, key: SecureString) {
        self.crypto.set_session_key(key);
    }

    // ── UI Delegates ───────────────────────────────────────────────────

    pub fn add_log(&self, msg: String) {
        self.ui.add_log(msg);
    }
    pub fn get_logs(&self) -> Vec<String> {
        self.ui.get_logs()
    }
    pub fn get_media_state(&self) -> MediaState {
        self.ui.get_media_state()
    }
    pub fn set_media_state(&self, state: MediaState) {
        self.ui.set_media_state(state);
    }
    pub fn get_pending_media_action(&self) -> Option<u32> {
        self.ui.get_pending_media_action()
    }
    pub fn set_pending_media_action(&self, action: Option<u32>) {
        self.ui.set_pending_media_action(action);
    }

    // ── Clipboard Delegates ────────────────────────────────────────────

    pub fn is_suppressed_duplicate(&self, text: &str) -> bool {
        self.clipboard.is_suppressed_duplicate(text)
    }
    pub fn record_clipboard_text(&self, text: &str) {
        self.clipboard.record_clipboard_text(text);
    }
    pub fn check_and_record_clipboard(&self, text: &str) -> bool {
        self.clipboard.check_and_record_clipboard(text)
    }
    pub fn get_sensor_history(&self) -> Vec<core_crypto::packets::SensorPacket> {
        self.clipboard.get_sensor_history()
    }
    pub fn add_sensor_packet(&self, packet: core_crypto::packets::SensorPacket) {
        self.clipboard.add_sensor_packet(packet);
    }
    pub fn get_sms_history(&self) -> Vec<core_crypto::packets::SmsPacket> {
        self.clipboard.get_sms_history()
    }
    pub fn add_sms_packet(&self, pkt: core_crypto::packets::SmsPacket) {
        self.clipboard.add_sms_packet(pkt);
    }
    pub fn get_notifications(&self) -> Vec<NotificationRecord> {
        self.clipboard.get_notifications()
    }
    pub fn add_notification(&self, pkt: NotificationRecord) {
        self.clipboard.add_notification(pkt);
        // Persist the (encrypted) history immediately — audit finding #21:
        // forwarded SMS/notification content must survive restarts and must
        // never be written in plaintext. The coalescing persist channel makes
        // per-notification writes cheap.
        self.clipboard.save_notifications();
    }

    // ── Pairing Delegates ──────────────────────────────────────────────

    pub fn get_pairing_read(&self) -> (String, String) {
        self.pairing.get_pairing_read()
    }

    pub fn get_sas_code(&self) -> String {
        self.pairing.get_sas_code()
    }

    pub fn set_sas_code(&self, code: String) {
        self.pairing.set_sas_code(code);
    }

    pub fn clear_sas_code(&self) {
        self.pairing.clear_sas_code();
    }

    pub fn is_pairing_pending(&self) -> bool {
        self.pairing.is_pairing_pending()
    }

    #[allow(dead_code)]
    pub fn get_pending_session_key(&self) -> String {
        self.pairing.get_pending_session_key()
    }

    pub fn set_pending_session_key(&self, key: SecureString) {
        self.pairing.set_pending_session_key(key);
    }

    pub fn get_pending_shared_secret(&self) -> String {
        self.pairing.get_pending_shared_secret()
    }

    pub fn set_pending_shared_secret(&self, secret: SecureString) {
        self.pairing.set_pending_shared_secret(secret);
    }

    pub fn get_pending_client_cert_hash(&self) -> String {
        self.pairing.get_pending_client_cert_hash()
    }

    pub fn set_pending_client_cert_hash(&self, hash: String) {
        self.pairing.set_pending_client_cert_hash(hash);
    }

    pub fn get_pending_pairing_nonce(&self) -> String {
        self.pairing.get_pending_pairing_nonce()
    }

    #[allow(dead_code)] // pairing API surface
    pub fn set_pending_pairing_nonce(&self, nonce: String) {
        self.pairing.set_pending_pairing_nonce(nonce);
    }

    /// Issue a fresh mandatory QR pairing nonce (audit finding #20).
    pub fn issue_fresh_pairing_nonce(&self) -> String {
        self.pairing.issue_fresh_nonce()
    }

    pub fn consume_pairing_nonce(&self) -> String {
        self.pairing.consume_pairing_nonce()
    }

    // ── Pairing phase transitions (audit finding #24) ──
    pub fn begin_pairing_attempt(&self) -> types::PairingPhase {
        self.pairing.begin_pairing_attempt()
    }
    pub fn promote_to_sas_pending(&self) -> types::PairingPhase {
        self.pairing.promote_to_sas_pending()
    }
    pub fn confirm_pairing(&self) -> types::PairingPhase {
        self.pairing.confirm_pairing()
    }
    pub fn timeout_pairing(&self) -> types::PairingPhase {
        self.pairing.timeout_pairing()
    }
    pub fn fail_pairing(&self) -> types::PairingPhase {
        self.pairing.fail_pairing()
    }
    pub fn pairing_phase(&self) -> types::PairingPhase {
        self.pairing.phase()
    }
    /// Per-attempt pairing generation (audit KYP-2026-02 #12) — the SAS-window
    /// timeout task checks it before firing.
    pub fn get_pairing_generation(&self) -> u64 {
        self.pairing.get_pairing_generation()
    }

    pub fn get_paired_client_cert_hash(&self) -> String {
        self.pairing.get_paired_client_cert_hash()
    }

    pub fn set_paired_client_cert_hash(&self, hash: String) {
        self.pairing.set_paired_client_cert_hash(hash);
    }

    pub fn get_paired_peer_ip(&self) -> String {
        self.pairing.get_paired_peer_ip()
    }

    pub fn set_paired_peer_ip(&self, ip: String) {
        self.pairing.set_paired_peer_ip(ip);
    }

    pub fn get_pairing_initiator_pk(&self) -> String {
        self.pairing.get_pairing_initiator_pk()
    }

    pub fn set_pairing_initiator_pk(&self, pk: String) {
        self.pairing.set_pairing_initiator_pk(pk);
    }

    /// AUDIT F12: route an inbound stream's ratchet traffic to the peer whose
    /// TLS-observed client certificate hash matches this connection. Falls back
    /// to the single global pairing id for legacy compatibility.
    pub fn resolve_peer_for_cert_hash(&self, cert_hash: &str) -> String {
        self.pairing.resolve_peer_for_cert_hash(cert_hash)
    }
    pub fn register_peer_cert_mapping(&self, peer_id: &str, cert_hash: &str) {
        self.pairing.register_peer_cert_mapping(peer_id, cert_hash);
    }
    /// AUDIT F12 (admission): is this TLS-observed client cert hash a known
    /// paired peer? Used by the stream authorization gate.
    pub fn is_authorized_peer_cert(&self, cert_hash: &str) -> bool {
        self.pairing.is_authorized_peer_cert(cert_hash)
    }

    pub fn get_pairing_initiator_x25519_pk(&self) -> String {
        self.pairing.get_pairing_initiator_x25519_pk()
    }

    pub fn set_pairing_initiator_x25519_pk(&self, pk: String) {
        self.pairing.set_pairing_initiator_x25519_pk(pk);
    }

    pub fn get_sas_attempt_count(&self) -> u32 {
        self.pairing.get_sas_attempt_count()
    }

    pub fn increment_sas_attempt_count(&self) {
        self.pairing.increment_sas_attempt_count();
    }

    pub fn reset_sas_attempt_count(&self) {
        self.pairing.reset_sas_attempt_count();
    }

    pub fn clear_all_pairing(&self) {
        self.pairing.clear_all_pairing();
    }

    // ── Network Delegates ──────────────────────────────────────────────

    pub fn get_connection_status(&self) -> String {
        self.network.get_connection_status()
    }

    pub fn set_connection_status(&self, status: String) {
        self.network.set_connection_status(status);
    }

    #[allow(dead_code)] // network delegate
    pub fn get_connection_method(&self) -> String {
        self.network.get_connection_method()
    }

    pub fn set_connection_method(&self, method: String) {
        self.network.set_connection_method(method);
    }

    #[allow(dead_code)] // network delegate
    pub fn get_connection_color(&self) -> String {
        self.network.get_connection_color()
    }

    pub fn set_connection_color(&self, color: String) {
        self.network.set_connection_color(color);
    }

    pub fn get_connection(&self) -> ConnectionState {
        self.network.get_connection()
    }

    pub fn set_connection(&self, status: String, method: String, color: String) {
        self.network.set_connection(status, method, color);
    }

    #[allow(dead_code)] // network delegate
    pub fn take_tor_child(&self) -> Option<std::process::Child> {
        self.network.take_tor_child()
    }

    pub fn set_tor_child(&self, child: std::process::Child) {
        self.network.set_tor_child(child);
    }

    pub fn merge_mesh_crdt(&self, incoming: core_crypto::crypto::LwwRegisterCRDT<String>) -> bool {
        self.network.merge_mesh_crdt(incoming)
    }

    // ── Settings Delegates ─────────────────────────────────────────────

    pub fn save_settings(&self) {
        self.settings.save_settings();
    }

    #[allow(dead_code)] // notification API surface
    pub fn save_notifications(&self) {
        self.clipboard.save_notifications();
    }

    #[allow(dead_code)] // generic pairing transition helper
    pub fn transition_pairing<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut PairingState, &mut Option<core_crypto::PqKeyPair>, &mut AppSettings) -> R,
    {
        let mut pairing = self.pairing.lock();
        let mut crypto = self.crypto.lock();
        let mut settings = self.settings.lock();
        f(&mut pairing, &mut crypto.keypair, &mut settings)
    }
}
