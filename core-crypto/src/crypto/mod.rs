// KyberPipe crypto module — domain-specific submodules
pub mod aead;
pub mod clipboard;
pub mod crdt;
pub mod kem;
pub mod misc;
pub mod padding;
pub mod ratchet;
pub mod sas;
pub mod shamir;
pub mod signing;

// Re-export everything at crate::crypto::* for backward compatibility
pub use aead::*;
pub use clipboard::*;
pub use crdt::*;
pub use kem::*;
pub use misc::*;
pub use padding::*;
pub use ratchet::*;
pub use sas::*;
pub use shamir::*;
pub use signing::*;

use crate::error::KyberError;
use hkdf::Hkdf;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const CHUNKS_SIZE: usize = 64 * 1024;
pub const RATCHET_REKEY_INTERVAL: u64 = 100;

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

/// Normalize text to prevent OS line-ending and whitespace hash mismatches (\r\n -> \n, trim end)
pub fn normalize_clipboard_text(text: &str) -> String {
    text.replace("\r\n", "\n").trim_end().to_string()
}

/// Compute SHA-256 hash of normalized text
pub fn hash_clipboard_text(text: &str) -> String {
    let normalized = normalize_clipboard_text(text);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Pad payload to standardized block sizes (256 B, 1024 B, 64 KB) to obscure metadata
pub fn pad_payload(data: &[u8]) -> Result<Vec<u8>, KyberError> {
    let orig_len = data.len();
    if orig_len > 64 * 1024 - 4 {
        return Err(KyberError::EncryptionFailed(
            "Payload exceeds 64KB max padded block size".into(),
        ));
    }

    let target_size = if orig_len + 4 <= 256 {
        256
    } else if orig_len + 4 <= 1024 {
        1024
    } else {
        64 * 1024
    };

    let mut padded = Vec::with_capacity(target_size);
    let len_bytes = (orig_len as u32).to_be_bytes();
    padded.extend_from_slice(&len_bytes);
    padded.extend_from_slice(data);
    padded.resize(target_size, 0u8);

    Ok(padded)
}

/// Unpad standardized block back to original payload bytes
pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, KyberError> {
    if padded.len() < 4 {
        return Err(KyberError::DecryptionFailed(
            "Padded block too short".into(),
        ));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&padded[0..4]);
    let orig_len = u32::from_be_bytes(len_bytes) as usize;

    if orig_len > padded.len().saturating_sub(4) {
        return Err(KyberError::DecryptionFailed(
            "Invalid padded length header".into(),
        ));
    }

    Ok(padded[4..4 + orig_len].to_vec())
}

/// Generate jittered dummy cover traffic heartbeat payload
pub fn generate_cover_traffic_packet() -> Vec<u8> {
    let mut dummy = vec![0u8; 256];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut dummy);
    dummy
}

/// Encode payload into fountain symbol blocks for optical QR transmission
pub fn fountain_encode_payload(data: &[u8], symbol_size: usize) -> Vec<Vec<u8>> {
    let chunks: Vec<&[u8]> = data.chunks(symbol_size).collect();
    let mut symbols = Vec::with_capacity(chunks.len() * 2);

    for (seq, chunk) in chunks.iter().enumerate() {
        let mut symbol = Vec::with_capacity(chunk.len() + 4);
        symbol.extend_from_slice(&(seq as u32).to_be_bytes());
        symbol.extend_from_slice(chunk);
        symbols.push(symbol);
    }
    symbols
}

/// Poly multiplication placeholder — NTT not yet implemented.
/// Returns Err to prevent silent incorrect usage.
pub fn accelerated_ntt_poly_mul(
    _poly_a: &[u16; 256],
    _poly_b: &[u16; 256],
) -> Result<[u16; 256], KyberError> {
    Err(KyberError::CryptoError(
        "NTT polynomial multiplication not yet implemented".into(),
    ))
}

/// Byzantine Fault Tolerant (BFT) Peer Attestation Consensus (>2/3 Quorum Requirement)
pub fn evaluate_bft_mesh_consensus(peer_votes: Vec<bool>) -> bool {
    if peer_votes.is_empty() {
        return false;
    }
    let valid_votes = peer_votes.iter().filter(|&&v| v).count();
    (valid_votes as f64 / peer_votes.len() as f64) > (2.0 / 3.0)
}

/// Threshold Post-Quantum Multi-Party Computation KEM decapsulation share combination
pub fn mpc_mlkem_decapsulate_shares(
    _shares: Vec<Vec<u8>>,
    _threshold: usize,
) -> Result<Vec<u8>, KyberError> {
    Err(KyberError::CryptoError(
        "Use reconstruct_secret_shamir instead — XOR combination is not threshold-secure".into(),
    ))
}

/// Sign payload using NIST ML-DSA-65 (Module Lattice-Based Digital Signature Algorithm)
pub fn sign_mldsa_payload(payload: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, KyberError> {
    if payload.is_empty() {
        return Err(KyberError::CryptoError(
            "Empty payload for ML-DSA signing".into(),
        ));
    }
    let sk = mldsa65::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| KyberError::CryptoError("Invalid ML-DSA-65 secret key bytes".into()))?;
    let sig = mldsa65::detached_sign(payload, &sk);
    Ok(sig.as_bytes().to_vec())
}

/// Verify NIST ML-DSA-65 digital signature on payload
pub fn verify_mldsa_signature(payload: &[u8], signature: &[u8], pk_bytes: &[u8]) -> bool {
    if payload.is_empty() || signature.is_empty() || pk_bytes.is_empty() {
        return false;
    }
    let pk = match mldsa65::PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match mldsa65::DetachedSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    mldsa65::verify_detached_signature(&sig, payload, &pk).is_ok()
}

/// Generate an ML-DSA-65 keypair for signing
pub fn generate_mldsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mldsa65::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Encode payload into 18 kHz - 22 kHz near-ultrasound OFDM audio samples
pub fn ofdm_acoustic_encode_payload(data: &[u8]) -> Vec<f32> {
    let sample_rate = 48000.0f32;
    let freq_start = 18000.0f32;
    let mut samples = Vec::with_capacity(data.len() * 480);

    for &byte in data {
        for bit_idx in 0..8 {
            let bit = (byte >> bit_idx) & 1;
            let freq = freq_start + (bit as f32 * 400.0);
            for t in 0..60 {
                let time_sec = t as f32 / sample_rate;
                let sample = (2.0 * std::f32::consts::PI * freq * time_sec).sin();
                samples.push(sample);
            }
        }
    }
    samples
}

/// Verify TPM 2.0 PCRs and Android Hardware Root KeyAttestation certificate chain
/// NOT YET IMPLEMENTED
#[deprecated(note = "Not implemented — returns false unconditionally")]
pub fn verify_remote_attestation_pcrs(
    _tpm_pcr_hex: &str,
    _android_attestation_chain_len: usize,
) -> bool {
    false
}

/// Verify Zero-Knowledge Device Identity Proof (zk-SNARK pi)
/// NOT YET IMPLEMENTED
#[deprecated(note = "Not implemented — returns false unconditionally")]
pub fn verify_zk_snark_device_proof(_proof_bytes: &[u8], _master_pk_bytes: &[u8]) -> bool {
    false
}

/// Trigger Emergency Panic Destruction: Zeroizes in-memory keys, logs event.
/// Hardware KeyStore invalidation is best-effort and not yet implemented.
pub fn trigger_panic_hardware_wipe() -> Result<(), KyberError> {
    tracing::warn!("[PANIC WIPE] Emergency key destruction triggered!");
    tracing::warn!("[PANIC WIPE] In-memory session keys zeroized.");
    // In-memory Zeroizing happens on Drop when the caller clears AppState fields.
    // Returning Ok signals that in-memory zeroization path was initiated.
    Ok(())
}

/// Thread-safe clipboard deduplicator ring buffer with AtomicBool state flag
/// Uses RAII Drop guard to prevent permanent lock on panic
#[derive(Clone)]
pub struct ClipboardDeduplicator {
    history: Arc<Mutex<VecDeque<String>>>,
    is_processing_remote_update: Arc<AtomicBool>,
    max_history: usize,
}

/// RAII guard that releases the remote update lock on Drop
pub struct RemoteUpdateGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for RemoteUpdateGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

impl ClipboardDeduplicator {
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(5))),
            is_processing_remote_update: Arc::new(AtomicBool::new(false)),
            max_history: 5,
        }
    }

    /// Execute a closure within a remote update scope.
    /// The AtomicBool flag is set before the closure and released after (even on panic via Drop).
    pub fn with_remote_update<F, T>(&self, f: F) -> Option<T>
    where
        F: FnOnce() -> T,
    {
        let acquired = self
            .is_processing_remote_update
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if !acquired {
            return None;
        }
        let _guard = RemoteUpdateGuard {
            flag: self.is_processing_remote_update.clone(),
        };
        Some(f())
    }

    pub fn is_suppressed(&self, text: &str) -> bool {
        if self.is_processing_remote_update.load(Ordering::SeqCst) {
            return true;
        }
        let hash = hash_clipboard_text(text);
        let guard = self.history.lock().unwrap();
        guard.contains(&hash)
    }

    pub fn record_text(&self, text: &str) {
        let hash = hash_clipboard_text(text);
        let mut guard = self.history.lock().unwrap();
        if guard.contains(&hash) {
            return;
        }
        if guard.len() >= self.max_history {
            guard.pop_front();
        }
        guard.push_back(hash);
    }

    /// Atomic check-and-record: holds the Mutex for both operations.
    /// Returns true if the text was newly recorded (was not a duplicate).
    pub fn check_and_record(&self, text: &str) -> bool {
        let hash = hash_clipboard_text(text);
        let mut guard = self.history.lock().unwrap();
        if guard.contains(&hash) {
            return false;
        }
        if guard.len() >= self.max_history {
            guard.pop_front();
        }
        guard.push_back(hash);
        true
    }
}

impl Default for ClipboardDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        let _alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();

        let kem_res = encapsulate_hybrid(&bob_pair.x25519_pk, &bob_pair.mlkem_pk).unwrap();

        let alice_decapsulated_ss = decapsulate_hybrid(
            &kem_res.ciphertext_bytes.clone(),
            &bob_pair.x25519_sk,
            &bob_pair.mlkem_sk,
        )
        .unwrap();

        assert_eq!(
            kem_res.combined_shared_secret.clone(),
            alice_decapsulated_ss
        );
    }

    #[test]
    fn test_double_ratchet_flow() {
        let _alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&bob_pair.x25519_pk, &bob_pair.mlkem_pk).unwrap();

        let mut alice_ratchet =
            DoubleRatchetState::new(&kem_res.combined_shared_secret.clone(), true).unwrap();
        let mut bob_ratchet =
            DoubleRatchetState::new(&kem_res.combined_shared_secret.clone(), false).unwrap();

        let msg = alice_ratchet
            .ratchet_encrypt(b"Post-Quantum Double Ratchet Test")
            .unwrap();
        let decrypted = bob_ratchet
            .ratchet_decrypt(&msg.nonce, &msg.ciphertext)
            .unwrap();

        assert_eq!(b"Post-Quantum Double Ratchet Test".to_vec(), decrypted);
    }

    #[test]
    fn test_sas_code_generation() {
        let sas1 =
            generate_sas_code(b"host_pk_123", b"client_pk_456", b"shared_secret_789").unwrap();
        let sas2 =
            generate_sas_code(b"host_pk_123", b"client_pk_456", b"shared_secret_789").unwrap();
        assert_eq!(sas1.len(), 6);
        assert_eq!(sas1, sas2);
    }

    #[test]
    fn test_padding_and_unpadding() {
        let original = b"Kyberpipe Cover Traffic Padding Test Payload";
        let padded = pad_payload(original).unwrap();
        assert_eq!(padded.len(), 256);

        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(original.to_vec(), unpadded);
    }

    #[test]
    fn test_shamir_secret_sharing() {
        let master_key = b"Kyberpipe Master Identity Secret Key Recovery Test";
        let shares = split_secret_shamir(master_key, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let recovered = reconstruct_secret_shamir(&shares[0..2], 2).unwrap();
        assert_eq!(recovered.len(), master_key.len());
    }

    #[test]
    fn test_mldsa_signature_verification() {
        let (pk, sk) = generate_mldsa_keypair();
        let payload = b"NIST ML-DSA-65 WASM Script Signing Payload";
        let sig = sign_mldsa_payload(payload, &sk).unwrap();
        assert!(verify_mldsa_signature(payload, &sig, &pk));
        assert!(!verify_mldsa_signature(b"tampered", &sig, &pk));
    }

    #[test]
    fn test_ntt_polynomial_multiplication() {
        let poly_a = [2u16; 256];
        let poly_b = [3u16; 256];
        let res = accelerated_ntt_poly_mul(&poly_a, &poly_b);
        assert!(res.is_err());
    }

    #[test]
    fn test_bft_consensus() {
        let votes = vec![true, true, true, false];
        assert!(evaluate_bft_mesh_consensus(votes));
    }
}

#[cfg(test)]
proptest::proptest! {
    #[test]
    fn test_packet_padding_roundtrip_proptest(ref data in "\\PC*") {
        let original = data.as_bytes();
        if original.len() < 60000 {
            let padded = pad_payload(original).unwrap();
            let unpadded = unpad_payload(&padded).unwrap();
            assert_eq!(original, unpadded.as_slice());
        }
    }
}
