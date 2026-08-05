//! UniFFI record types (audit KYP-2026-02 #22 — extracted from the former
//! `lib.rs` monolith so the FFI surface and the runtime lifecycle live apart
//! from the data types crossing the boundary).

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// INTERNAL secret-bearing keypair (audit F14): the PRIVATE halves live in
/// [`Zeroizing`] buffers, so EVERY clone and drop path wipes them from the
/// heap. `PqKeyPair` (the UniFFI record) cannot derive `ZeroizeOnDrop` — UniFFI
///'s Record derive is incompatible with a Drop impl — so any `clone()` of it
/// leaves fresh `Vec<u8>` copies of the private halves in freed heap. The
/// registries (keypair handles, the process-global pairing keypair) therefore
/// store THIS type internally, and accessors hand out zeroizing clones. The
/// UniFFI `PqKeyPair` record remains only at the public boundary.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeypair {
    pub x25519_pk: Vec<u8>,
    pub x25519_sk: Zeroizing<Vec<u8>>,
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Zeroizing<Vec<u8>>,
}

impl From<PqKeyPair> for SecretKeypair {
    fn from(pair: PqKeyPair) -> Self {
        Self {
            x25519_pk: pair.x25519_pk,
            x25519_sk: Zeroizing::new(pair.x25519_sk),
            mlkem_pk: pair.mlkem_pk,
            mlkem_sk: Zeroizing::new(pair.mlkem_sk),
        }
    }
}

impl From<&PqKeyPair> for SecretKeypair {
    fn from(pair: &PqKeyPair) -> Self {
        Self {
            x25519_pk: pair.x25519_pk.clone(),
            x25519_sk: Zeroizing::new(pair.x25519_sk.clone()),
            mlkem_pk: pair.mlkem_pk.clone(),
            mlkem_sk: Zeroizing::new(pair.mlkem_sk.clone()),
        }
    }
}

impl SecretKeypair {
    /// The PUBLIC halves only, as the UniFFI pairing record (private halves
    /// never leave Rust).
    pub fn public(&self) -> PqPairingPublic {
        PqPairingPublic {
            x25519_pk_hex: hex::encode(&self.x25519_pk),
            mlkem_pk_hex: hex::encode(&self.mlkem_pk),
        }
    }
}

#[derive(Clone, serde::Serialize, uniffi::Record, zeroize::Zeroize)]
pub struct PqKeyPair {
    pub x25519_pk: Vec<u8>,
    pub x25519_sk: Vec<u8>,
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

/// PUBLIC-ONLY key material for crossing the Tauri webview boundary. The secret
/// halves of the keypair NEVER leave the Rust process — the renderer receives
/// only the public keys needed to build pairing QR payloads, and the pairing
/// handler reads the private halves from Rust state.
#[derive(uniffi::Record, serde::Serialize, Clone)]
pub struct PqPairingPublic {
    pub x25519_pk_hex: String,
    pub mlkem_pk_hex: String,
}

impl From<&PqKeyPair> for PqPairingPublic {
    fn from(pair: &PqKeyPair) -> Self {
        Self {
            x25519_pk_hex: hex::encode(&pair.x25519_pk),
            mlkem_pk_hex: hex::encode(&pair.mlkem_pk),
        }
    }
}

#[derive(uniffi::Record)]
pub struct PqKemResponse {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Result of a HANDLE-based encapsulation (audit KYP-2026-02 #7): the opaque
/// handle to the KEM shared secret (kept in Rust, zeroized on destroy) plus the
/// PUBLIC ciphertext sent to the peer. The shared secret never crosses the FFI
/// boundary.
#[derive(uniffi::Record)]
pub struct PqKemHandleResponse {
    pub handle: u64,
    pub ciphertext: Vec<u8>,
}

/// A generated per-install client identity certificate (audit finding #8).
/// `cert_der`/`key_der` are DER-encoded; `sha256_hex` is the cert fingerprint
/// the server pins during pairing.
#[derive(uniffi::Record)]
pub struct ClientIdentityCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub sha256_hex: String,
}

#[derive(uniffi::Record)]
pub struct EncryptedPayload {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PathChallengeResult {
    pub challenge_token: String,
    pub expected_response: String,
}

#[derive(uniffi::Record, serde::Serialize, serde::Deserialize, Clone)]
pub struct ConnectionInfo {
    pub active_tier: u32,
    pub active_path_description: String,
    pub latency_ms: f64,
    pub public_endpoint: String,
}

#[derive(uniffi::Record, serde::Serialize, serde::Deserialize, Clone)]
pub struct PairingConfig {
    pub host_identity_pk_hex: String,
    pub local_ip: String,
    pub wifi_direct_mac: String,
    pub p2p_ip: String,
    pub wireguard_pk_hex: String,
    pub stun_endpoint: String,
    pub pairing_nonce_hex: String,
}

// ── Double Ratchet FFI ──
// Double Ratchet FFI — peer-keyed session registry
