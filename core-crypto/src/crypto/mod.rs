// KyberPipe crypto module — domain-specific submodules
pub mod aead;
pub mod crdt;
pub mod kem;
pub mod misc;
pub mod padding;
pub mod ratchet;
pub mod sas;
pub mod shamir;
pub mod signing;

// Re-export everything at crate::crypto::* for backward compatibility
//
// AUDIT #21: this module is now a PURE re-export surface for the primitive
// submodules. The app-level helpers (ClipboardDeduplicator, cover traffic,
// clipboard text normalization) moved to `crate::utils` — they are NOT
// cryptographic primitives and no longer pollute the crypto namespace.
#[allow(unused_imports)]
pub use aead::*;
#[allow(unused_imports)]
pub use crdt::*;
#[allow(unused_imports)]
pub use kem::*;
#[allow(unused_imports)]
pub use misc::*;
#[allow(unused_imports)]
pub use padding::*;
#[allow(unused_imports)]
pub use ratchet::*;
#[allow(unused_imports)]
pub use sas::*;
#[allow(unused_imports)]
pub use shamir::*;
#[allow(unused_imports)]
pub use signing::*;

use crate::error::KyberError;
use hkdf::Hkdf;
use sha2::Sha256;

pub const CHUNKS_SIZE: usize = 64 * 1024;
pub const RATCHET_REKEY_INTERVAL: u64 = 100;

/// Canonical domain-separation salt for session-key derivation. BOTH the
/// desktop (Rust, `handlers/pairing.rs`) and Android (Kotlin via UniFFI) MUST
/// consume these exact bytes — never hex-encode/re-encode the salt at a call
/// site (audit finding #2: Android passed the hex-encoding as ASCII, producing
/// a byte-different salt and making every session-key payload undecryptable).
pub const SESSION_KEY_DERIVATION_SALT: &[u8] = b"kyberpipe-sync-v1";

/// Derive a 256-bit (32-byte) symmetric key using HKDF-SHA256 from combined shared secret.
pub fn derive_session_key(
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], KyberError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| KyberError::CryptoError(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}
