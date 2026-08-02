use core_crypto::crypto::ClipboardDeduplicator;
use core_crypto::packets::{SensorPacket, SmsPacket};
use core_crypto::PqKeyPair;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Zeroizes the heap buffer of a String by overwriting each byte with zero.
fn zeroize_string_heap(s: &mut String) {
    let cap = s.capacity();
    if cap > s.len() {
        s.reserve(cap - s.len());
    }
    let bytes = unsafe { s.as_bytes_mut() };
    bytes.zeroize();
    s.clear();
}

/// A String wrapper that properly zeroizes the heap-allocated buffer on drop.
#[derive(Default)]
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

impl std::fmt::Display for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct AppSettings {
    pub device_name: Option<String>,
    pub device_picture: Option<String>,
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
    #[serde(default)]
    pub yubikey_bound: bool,
    /// Opt-in LAN beacon discovery (audit finding #20: the 30s cleartext UDP
    /// beacon disclosed device name + LAN IP + a truncated key hash to every
    /// host on the LAN). Default OFF — the phone can always pair via the QR
    /// (which carries the IP); beacons are only emitted when the user
    /// explicitly enables discovery, and never carry the device name.
    #[serde(default)]
    pub beacon_discovery_enabled: bool,
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
    pub type_field: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Default)]
pub struct CryptoState {
    pub keypair: Option<PqKeyPair>,
    pub session_key: SecureString,
}

/// Explicit pairing-flow phase machine (audit finding #24). Every pairing
/// state change flows through ONE transition method on `PairingService`, so the
/// wire handler, the SAS-confirmation command and the timeout task can never
/// diverge on what the current phase is or which fields are valid in it — the
/// class of bug that previously split pairing policy across four files with two
/// different "clear" semantics.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PairingPhase {
    #[default]
    Idle,
    /// KEM handshake accepted; SAS computed, not yet displayed.
    PendingKem,
    /// SAS displayed — awaiting the user's OOB confirmation.
    SasPending,
    /// SAS verified; session key + ratchet promoted.
    Confirmed,
    /// SAS window expired without confirmation.
    TimedOut,
    /// Explicit rejection (nonce mismatch, rate limit, bad KEM).
    Failed,
}

#[derive(Default)]
pub struct PairingState {
    pub phase: PairingPhase,
    pub sas_code: String,
    pub pending_session_key: SecureString,
    pub pending_shared_secret: SecureString,
    pub initiator_pk: String,
    pub initiator_x25519_pk: String,
    pub attempt_count: u32,
    pub pending_client_cert_hash: String,
    /// Fresh out-of-band QR nonce this desktop issued for the CURRENT pairing
    /// attempt. The phone must echo it back in its pairing payload; arbitrary
    /// LAN peers cannot know it (audit finding #20).
    pub pending_pairing_nonce: String,
    /// Client certificate hash captured from the pairing connection. Promoted
    /// from `pending_client_cert_hash` at SAS confirmation; used to authorize
    /// post-pairing streams so no unauthenticated LAN peer can poll/unpair.
    pub paired_client_cert_hash: String,
    /// IP of the peer that performed pairing. Fallback identity binding when a
    /// client certificate was not presented during pairing.
    pub paired_peer_ip: String,
}

pub struct NetworkState {
    pub connection: ConnectionState,
    pub tor_child: Option<std::process::Child>,
    pub mesh_crdt: core_crypto::crypto::LwwRegisterCRDT<String>,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self {
            connection: ConnectionState::default(),
            tor_child: None,
            mesh_crdt: core_crypto::crypto::LwwRegisterCRDT::new(
                "Local Engine State".to_string(),
                "desktop_node_1".to_string(),
                100, // Initial timestamp
            ),
        }
    }
}

pub struct SyncHistory {
    pub sensor: Vec<SensorPacket>,
    pub sms: Vec<SmsPacket>,
    pub notifications: Vec<NotificationRecord>,
}

impl Default for SyncHistory {
    fn default() -> Self {
        Self {
            sensor: Vec::new(),
            sms: Vec::new(),
            notifications: Vec::new(),
        }
    }
}

#[derive(Default)]
pub struct UiState {
    pub logs: Vec<String>,
    pub media_state: MediaState,
    pub pending_media_action: Option<u32>,
}

pub struct ClipboardState {
    pub dedup: ClipboardDeduplicator,
    pub sync_history: SyncHistory,
}

impl Default for ClipboardState {
    fn default() -> Self {
        Self {
            dedup: ClipboardDeduplicator::new(),
            sync_history: SyncHistory::default(),
        }
    }
}
