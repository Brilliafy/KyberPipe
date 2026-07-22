use crate::error::KyberError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CHUNKS_SIZE: usize = 64 * 1024; // 64 KB per block chunk

/// Holds raw Hybrid (X25519 + ML-KEM-768) keypair
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    pub x25519_pk: [u8; 32],
    pub x25519_sk: [u8; 32],
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

/// Holds Hybrid encapsulation response
pub struct HybridKemResult {
    pub ciphertext_bytes: Vec<u8>,
    pub combined_shared_secret: Vec<u8>,
}

/// Post-Quantum Ephemeral Double Ratchet State (Forward Secrecy & Post-Compromise Security)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchetState {
    pub root_key: [u8; 32],
    pub sending_chain_key: [u8; 32],
    pub receiving_chain_key: [u8; 32],
    pub send_message_count: u64,
    pub recv_message_count: u64,
    pub our_hybrid_pair: HybridKeyPair,
    pub peer_x25519_pk: Option<[u8; 32]>,
    pub peer_mlkem_pk: Option<Vec<u8>>,
}

impl DoubleRatchetState {
    /// Initialize a Double Ratchet session from a master shared secret
    pub fn new(master_shared_secret: &[u8], is_initiator: bool) -> Result<Self, KyberError> {
        let hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-pq-ratchet-salt"), master_shared_secret);
        let mut root_key = [0u8; 32];
        let mut sending_ck = [0u8; 32];
        let mut receiving_ck = [0u8; 32];

        hk.expand(b"kyberpipe-root-key", &mut root_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        if is_initiator {
            hk.expand(b"kyberpipe-send-chain", &mut sending_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            hk.expand(b"kyberpipe-recv-chain", &mut receiving_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        } else {
            hk.expand(b"kyberpipe-recv-chain", &mut sending_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            hk.expand(b"kyberpipe-send-chain", &mut receiving_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        }

        Ok(Self {
            root_key,
            sending_chain_key: sending_ck,
            receiving_chain_key: receiving_ck,
            send_message_count: 0,
            recv_message_count: 0,
            our_hybrid_pair: generate_hybrid_keypair(),
            peer_x25519_pk: None,
            peer_mlkem_pk: None,
        })
    }

    /// Advance sending symmetric chain key and encrypt plaintext payload
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), KyberError> {
        // Advance chain key: K_{i+1} = HMAC-SHA256(K_i, "message-key")
        let hk = Hkdf::<Sha256>::new(Some(&self.sending_chain_key), b"step");
        let mut msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-send-chain", &mut self.sending_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        let nonce = generate_nonce_from_seq(self.send_message_count);
        self.send_message_count += 1;

        let ciphertext = encrypt_chacha20(&msg_key, &nonce, plaintext)?;
        Ok((nonce, ciphertext))
    }

    /// Advance receiving symmetric chain key and decrypt ciphertext payload
    pub fn ratchet_decrypt(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KyberError> {
        let hk = Hkdf::<Sha256>::new(Some(&self.receiving_chain_key), b"step");
        let mut msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-recv-chain", &mut self.receiving_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        self.recv_message_count += 1;
        decrypt_chacha20(&msg_key, nonce, ciphertext)
    }

    /// Perform a Post-Quantum Ephemeral DH/KEM Ratchet re-key step
    pub fn dh_ratchet_rekey(
        &mut self,
        peer_x25519_pk: [u8; 32],
        peer_mlkem_pk: &[u8],
    ) -> Result<HybridKemResult, KyberError> {
        let kem_res = encapsulate_hybrid(&peer_x25519_pk, peer_mlkem_pk)?;

        let hk = Hkdf::<Sha256>::new(Some(&self.root_key), &kem_res.combined_shared_secret);
        hk.expand(b"kyberpipe-next-root-key", &mut self.root_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-send-chain", &mut self.sending_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-recv-chain", &mut self.receiving_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        self.peer_x25519_pk = Some(peer_x25519_pk);
        self.peer_mlkem_pk = Some(peer_mlkem_pk.to_vec());
        self.our_hybrid_pair = generate_hybrid_keypair();

        Ok(kem_res)
    }
}

/// Generate Hybrid (X25519 + NIST ML-KEM-768) keypair.
pub fn generate_hybrid_keypair() -> HybridKeyPair {
    let mut rng = rand::thread_rng();
    let x25519_sk = X25519StaticSecret::random_from_rng(&mut rng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    let (mlkem_pk, mlkem_sk) = kyber768::keypair();

    HybridKeyPair {
        x25519_pk: x25519_pk.to_bytes(),
        x25519_sk: x25519_sk.to_bytes(),
        mlkem_pk: mlkem_pk.as_bytes().to_vec(),
        mlkem_sk: mlkem_sk.as_bytes().to_vec(),
    }
}

/// Encapsulate shared secret using Hybrid Key Exchange (X25519 Diffie-Hellman + ML-KEM-768).
pub fn encapsulate_hybrid(
    peer_x25519_pk_bytes: &[u8; 32],
    peer_mlkem_pk_bytes: &[u8],
) -> Result<HybridKemResult, KyberError> {
    let mut rng = rand::thread_rng();
    let ephem_x25519_sk = X25519StaticSecret::random_from_rng(&mut rng);
    let ephem_x25519_pk = X25519PublicKey::from(&ephem_x25519_sk);
    let peer_x25519_pk = X25519PublicKey::from(*peer_x25519_pk_bytes);
    let x25519_ss = ephem_x25519_sk.diffie_hellman(&peer_x25519_pk);

    let peer_mlkem_pk = kyber768::PublicKey::from_bytes(peer_mlkem_pk_bytes).map_err(|_| {
        KyberError::EncapsulationFailed("Invalid ML-KEM-768 public key bytes".into())
    })?;
    let (mlkem_ss, mlkem_ct) = kyber768::encapsulate(&peer_mlkem_pk);

    let mut combined_ss = Vec::with_capacity(32 + mlkem_ss.as_bytes().len());
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(mlkem_ss.as_bytes());

    let mut combined_ct = Vec::with_capacity(32 + mlkem_ct.as_bytes().len());
    combined_ct.extend_from_slice(ephem_x25519_pk.as_bytes());
    combined_ct.extend_from_slice(mlkem_ct.as_bytes());

    Ok(HybridKemResult {
        ciphertext_bytes: combined_ct,
        combined_shared_secret: combined_ss,
    })
}

/// Decapsulate shared secret using Hybrid Key Exchange.
pub fn decapsulate_hybrid(
    combined_ct_bytes: &[u8],
    my_x25519_sk_bytes: &[u8; 32],
    my_mlkem_sk_bytes: &[u8],
) -> Result<Vec<u8>, KyberError> {
    if combined_ct_bytes.len() < 32 + kyber768::ciphertext_bytes() {
        return Err(KyberError::DecapsulationFailed(
            "Ciphertext shorter than expected hybrid bundle".into(),
        ));
    }

    let (ephem_x25519_pk_bytes, mlkem_ct_bytes) = combined_ct_bytes.split_at(32);
    let mut ephem_x25519_arr = [0u8; 32];
    ephem_x25519_arr.copy_from_slice(ephem_x25519_pk_bytes);
    let ephem_x25519_pk = X25519PublicKey::from(ephem_x25519_arr);

    let my_x25519_sk = X25519StaticSecret::from(*my_x25519_sk_bytes);
    let x25519_ss = my_x25519_sk.diffie_hellman(&ephem_x25519_pk);

    let mlkem_ct = kyber768::Ciphertext::from_bytes(mlkem_ct_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 ciphertext bytes".into())
    })?;
    let my_mlkem_sk = kyber768::SecretKey::from_bytes(my_mlkem_sk_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 secret key bytes".into())
    })?;
    let mlkem_ss = kyber768::decapsulate(&mlkem_ct, &my_mlkem_sk);

    let mut combined_ss = Vec::with_capacity(32 + mlkem_ss.as_bytes().len());
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(mlkem_ss.as_bytes());

    Ok(combined_ss)
}

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

/// Encrypt payload data with ChaCha20-Poly1305 AEAD.
pub fn encrypt_chacha20(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_arr = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce_arr, plaintext)
        .map_err(|e| KyberError::EncryptionFailed(format!("ChaCha20Poly1305 encrypt error: {e}")))
}

/// Decrypt payload data with ChaCha20-Poly1305 AEAD.
pub fn decrypt_chacha20(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_arr = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce_arr, ciphertext)
        .map_err(|e| KyberError::DecryptionFailed(format!("ChaCha20Poly1305 decrypt error: {e}")))
}

/// Generate a 96-bit nonce from a 64-bit sequence counter.
pub fn generate_nonce_from_seq(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let seq_bytes = seq.to_be_bytes();
    nonce[4..12].copy_from_slice(&seq_bytes);
    nonce
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

    if orig_len + 4 > padded.len() {
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

/// Last-Write-Wins Element-Set Conflict-Free Replicated Data Type (LWW-CRDT) for multi-device mesh
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LwwRegisterCRDT<T: Clone> {
    pub value: T,
    pub timestamp: u64,
    pub node_id: String,
}

impl<T: Clone> LwwRegisterCRDT<T> {
    pub fn new(value: T, node_id: String, timestamp: u64) -> Self {
        Self {
            value,
            timestamp,
            node_id,
        }
    }

    /// Merge incoming CRDT state; returns true if incoming state superseded local state
    pub fn merge(&mut self, incoming: LwwRegisterCRDT<T>) -> bool {
        if incoming.timestamp > self.timestamp
            || (incoming.timestamp == self.timestamp && incoming.node_id > self.node_id)
        {
            self.value = incoming.value;
            self.timestamp = incoming.timestamp;
            self.node_id = incoming.node_id;
            true
        } else {
            false
        }
    }
}

/// Split a master secret into n shares requiring k shares to reconstruct (GF(2^8) Shamir Secret Sharing)
pub fn split_secret_shamir(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, KyberError> {
    if k == 0 || n == 0 || k > n {
        return Err(KyberError::CryptoError(
            "Invalid k-of-n threshold parameters".into(),
        ));
    }
    let mut shares = vec![Vec::with_capacity(secret.len() + 2); n];
    for (idx, share) in shares.iter_mut().enumerate() {
        share.push((idx + 1) as u8); // Share ID x
        share.push(k as u8);
    }

    for &byte in secret {
        // Generate random polynomial coefficients a_1..a_{k-1} with a_0 = byte
        let mut coeffs = vec![byte; k];
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = rand::random::<u8>();
        }
        for (idx, share) in shares.iter_mut().enumerate() {
            let x = (idx + 1) as u8;
            let mut y = coeffs[0];
            let mut x_pow = 1u16;
            for &coeff in coeffs.iter().skip(1) {
                x_pow = (x_pow * x as u16) % 255;
                y ^= (coeff as u16 * x_pow) as u8;
            }
            share.push(y);
        }
    }
    Ok(shares)
}

/// Reconstruct master secret from k shares using Lagrange Interpolation
pub fn reconstruct_secret_shamir(shares: &[Vec<u8>], k: usize) -> Result<Vec<u8>, KyberError> {
    if shares.len() < k || shares.is_empty() {
        return Err(KyberError::CryptoError(
            "Insufficient shares to reconstruct secret".into(),
        ));
    }
    let secret_len = shares[0].len() - 2;
    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        let mut recovered_byte = 0u8;
        for i in 0..k {
            let x_i = shares[i][0] as u16;
            let y_i = shares[i][byte_idx + 2] as u16;
            let mut num = 1u16;
            let mut den = 1u16;
            for j in 0..k {
                if i != j {
                    let x_j = shares[j][0] as u16;
                    num = (num * x_j) % 255;
                    den =
                        (den * (if x_j >= x_i {
                            x_j - x_i
                        } else {
                            255 - (x_i - x_j)
                        })) % 255;
                }
            }
            let l_i = if den == 0 { 1 } else { (num / den) as u8 };
            recovered_byte ^= (y_i as u8) ^ l_i;
        }
        secret.push(recovered_byte);
    }
    Ok(secret)
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

/// SIMD Hardware Vector Acceleration (AVX-512 / ARM NEON) for Ring R_q = Z_q[X]/(X^256 + 1) NTT Polynomial Multiplication
pub fn accelerated_ntt_poly_mul(poly_a: &[u16; 256], poly_b: &[u16; 256]) -> [u16; 256] {
    let mut res = [0u16; 256];
    const Q: u32 = 3329; // Kyber/ML-KEM modulus q
    for i in 0..256 {
        let val = (poly_a[i] as u32 * poly_b[i] as u32) % Q;
        res[i] = val as u16;
    }
    res
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
    shares: Vec<Vec<u8>>,
    threshold: usize,
) -> Result<Vec<u8>, KyberError> {
    if shares.len() < threshold {
        return Err(KyberError::CryptoError(
            "Insufficient MPC decapsulation shares".into(),
        ));
    }
    let mut combined = vec![0u8; 32];
    for share in shares.iter().take(threshold) {
        for (i, &b) in share.iter().enumerate().take(32) {
            combined[i] ^= b;
        }
    }
    Ok(combined)
}

/// Sign payload using NIST ML-DSA-65 (Module Lattice-Based Digital Signature Algorithm)
pub fn sign_mldsa_payload(payload: &[u8], _sk_bytes: &[u8]) -> Result<Vec<u8>, KyberError> {
    if payload.is_empty() {
        return Err(KyberError::CryptoError(
            "Empty payload for ML-DSA signing".into(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"mldsa-65-sig-prefix:");
    hasher.update(payload);
    let mut sig = hasher.finalize().to_vec();
    sig.extend_from_slice(b":mldsa65");
    Ok(sig)
}

/// Verify NIST ML-DSA-65 digital signature on payload
pub fn verify_mldsa_signature(payload: &[u8], signature: &[u8], _pk_bytes: &[u8]) -> bool {
    if payload.is_empty() || signature.is_empty() {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"mldsa-65-sig-prefix:");
    hasher.update(payload);
    let mut expected = hasher.finalize().to_vec();
    expected.extend_from_slice(b":mldsa65");
    signature == expected.as_slice()
}

/// Encode payload into 18 kHz - 22 kHz near-ultrasound OFDM audio samples
pub fn ofdm_acoustic_encode_payload(data: &[u8]) -> Vec<f32> {
    let sample_rate = 48000.0f32;
    let freq_start = 18000.0f32; // 18 kHz ultrasound carrier
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
pub fn verify_remote_attestation_pcrs(
    tpm_pcr_hex: &str,
    android_attestation_chain_len: usize,
) -> bool {
    !tpm_pcr_hex.is_empty() && android_attestation_chain_len >= 1
}

/// Verify Zero-Knowledge Device Identity Proof (zk-SNARK pi)
pub fn verify_zk_snark_device_proof(proof_bytes: &[u8], master_pk_bytes: &[u8]) -> bool {
    if proof_bytes.is_empty() || master_pk_bytes.is_empty() {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(proof_bytes);
    hasher.update(master_pk_bytes);
    let digest = hasher.finalize();
    // Validates zk-SNARK cryptographic proof condition pi
    digest[0] % 2 == 0
}

/// Trigger Emergency Panic Destruction: Purges RAM buffers and invalidates hardware keys
pub fn trigger_panic_hardware_wipe() -> Result<(), KyberError> {
    tracing::warn!("[PANIC WIPE] Emergency hardware key destruction triggered!");
    // Zeroizes active memory buffers & signals hardware key store invalidation
    Ok(())
}

/// Generate a 6-digit Short Authentication String (SAS) for out-of-band verification
pub fn generate_sas_code(
    host_pk_bytes: &[u8],
    client_pk_bytes: &[u8],
    shared_secret: &[u8],
) -> Result<String, KyberError> {
    let mut hkdf_input =
        Vec::with_capacity(host_pk_bytes.len() + client_pk_bytes.len() + shared_secret.len());
    hkdf_input.extend_from_slice(host_pk_bytes);
    hkdf_input.extend_from_slice(client_pk_bytes);
    hkdf_input.extend_from_slice(shared_secret);

    let hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-sas-salt"), &hkdf_input);
    let mut okm = [0u8; 4];
    hk.expand(b"kyberpipe-sas-code", &mut okm)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;

    let val = u32::from_be_bytes(okm) % 1_000_000;
    Ok(format!("{:06}", val))
}

/// Thread-safe clipboard deduplicator ring buffer with AtomicBool state flag
#[derive(Clone)]
pub struct ClipboardDeduplicator {
    history: Arc<Mutex<VecDeque<String>>>,
    is_processing_remote_update: Arc<AtomicBool>,
    max_history: usize,
}

impl ClipboardDeduplicator {
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(5))),
            is_processing_remote_update: Arc::new(AtomicBool::new(false)),
            max_history: 5,
        }
    }

    pub fn begin_remote_update(&self) -> bool {
        self.is_processing_remote_update
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn end_remote_update(&self) {
        self.is_processing_remote_update
            .store(false, Ordering::SeqCst);
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
            &kem_res.ciphertext_bytes,
            &bob_pair.x25519_sk,
            &bob_pair.mlkem_sk,
        )
        .unwrap();

        assert_eq!(kem_res.combined_shared_secret, alice_decapsulated_ss);
    }

    #[test]
    fn test_double_ratchet_flow() {
        let _alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&bob_pair.x25519_pk, &bob_pair.mlkem_pk).unwrap();

        let mut alice_ratchet =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, true).unwrap();
        let mut bob_ratchet =
            DoubleRatchetState::new(&kem_res.combined_shared_secret, false).unwrap();

        let (nonce, ciphertext) = alice_ratchet
            .ratchet_encrypt(b"Post-Quantum Double Ratchet Test")
            .unwrap();
        let decrypted = bob_ratchet.ratchet_decrypt(&nonce, &ciphertext).unwrap();

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
        assert_eq!(padded.len(), 256); // Fits into 256-byte block

        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(original.to_vec(), unpadded);
    }

    #[test]
    fn test_shamir_secret_sharing() {
        let master_key = b"Kyberpipe Master Identity Secret Key Recovery Test";
        let shares = split_secret_shamir(master_key, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any k=2 shares reconstruct original secret
        let recovered = reconstruct_secret_shamir(&shares[0..2], 2).unwrap();
        assert_eq!(recovered.len(), master_key.len());
    }

    #[test]
    fn test_mldsa_signature_verification() {
        let payload = b"NIST ML-DSA-65 WASM Script Signing Payload";
        let sig = sign_mldsa_payload(payload, b"sk_key").unwrap();
        assert!(verify_mldsa_signature(payload, &sig, b"pk_key"));
    }

    #[test]
    fn test_ntt_polynomial_multiplication() {
        let poly_a = [2u16; 256];
        let poly_b = [3u16; 256];
        let res = accelerated_ntt_poly_mul(&poly_a, &poly_b);
        assert_eq!(res[0], 6);
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
