pub mod crypto;
pub mod error;
pub mod network;
pub mod packets;

use error::KyberError;
use packets::{compute_sha256_hex, ClipboardPacket, NotificationPacket, SensorPacket, SmsPacket};

uniffi::include_scaffolding!("kyberpipe");

pub struct PqKeyPair {
    pub public_key_hex: String,
    pub secret_key_hex: String,
}

pub struct PqKemResponse {
    pub ciphertext_hex: String,
    pub shared_secret_hex: String,
}

pub struct EncryptedPayload {
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// Standalone UniFFI initialization helper for ML-KEM post-quantum handshake
pub fn initialize_pq_handshake() -> Result<(), KyberError> {
    let _pair = crypto::generate_kyber_keypair();
    Ok(())
}

/// UniFFI export: Generate ML-KEM-768 keypair returning hex-encoded strings
pub fn generate_pq_keypair() -> Result<PqKeyPair, KyberError> {
    let pair = crypto::generate_kyber_keypair();
    Ok(PqKeyPair {
        public_key_hex: hex::encode(pair.public_key_bytes),
        secret_key_hex: hex::encode(pair.secret_key_bytes),
    })
}

/// UniFFI export: Encapsulate shared secret against hex-encoded public key
pub fn encapsulate_pq_secret(public_key_hex: String) -> Result<PqKemResponse, KyberError> {
    let pk_bytes = hex::decode(&public_key_hex)
        .map_err(|e| KyberError::EncapsulationFailed(format!("Invalid public key hex: {e}")))?;
    let res = crypto::encapsulate_kyber(&pk_bytes)?;
    Ok(PqKemResponse {
        ciphertext_hex: hex::encode(res.ciphertext_bytes),
        shared_secret_hex: hex::encode(res.shared_secret_bytes),
    })
}

/// UniFFI export: Decapsulate shared secret against ciphertext & secret key hex
pub fn decapsulate_pq_secret(
    ciphertext_hex: String,
    secret_key_hex: String,
) -> Result<String, KyberError> {
    let ct_bytes = hex::decode(&ciphertext_hex)
        .map_err(|e| KyberError::DecapsulationFailed(format!("Invalid ciphertext hex: {e}")))?;
    let sk_bytes = hex::decode(&secret_key_hex)
        .map_err(|e| KyberError::DecapsulationFailed(format!("Invalid secret key hex: {e}")))?;
    let ss = crypto::decapsulate_kyber(&ct_bytes, &sk_bytes)?;
    Ok(hex::encode(ss))
}

/// UniFFI export: HKDF-SHA256 key derivation
pub fn derive_session_key(shared_secret_hex: String, salt_hex: String) -> Result<String, KyberError> {
    let ss_bytes = hex::decode(&shared_secret_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid shared secret hex: {e}")))?;
    let salt_bytes = hex::decode(&salt_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid salt hex: {e}")))?;
    
    let derived = crypto::derive_session_key(&ss_bytes, &salt_bytes, b"kyberpipe-pqc-session")?;
    Ok(hex::encode(derived))
}

/// UniFFI export: Encrypt plaintext string with 256-bit session key
pub fn encrypt_payload_with_key(
    session_key_hex: String,
    data: String,
) -> Result<EncryptedPayload, KyberError> {
    let key_bytes = hex::decode(&session_key_hex)
        .map_err(|e| KyberError::EncryptionFailed(format!("Invalid key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len(),
        });
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

    let ciphertext = crypto::encrypt_chacha20(&key_arr, &nonce_bytes, data.as_bytes())?;
    Ok(EncryptedPayload {
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

/// UniFFI export: Decrypt ciphertext string with 256-bit session key & nonce
pub fn decrypt_payload_with_key(
    session_key_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
) -> Result<String, KyberError> {
    let key_bytes = hex::decode(&session_key_hex)
        .map_err(|e| KyberError::DecryptionFailed(format!("Invalid key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len(),
        });
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let nonce_bytes = hex::decode(&nonce_hex)
        .map_err(|e| KyberError::DecryptionFailed(format!("Invalid nonce hex: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(KyberError::DecryptionFailed("Nonce must be 12 bytes".into()));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_bytes);

    let ct_bytes = hex::decode(&ciphertext_hex)
        .map_err(|e| KyberError::DecryptionFailed(format!("Invalid ciphertext hex: {e}")))?;

    let plaintext_bytes = crypto::decrypt_chacha20(&key_arr, &nonce_arr, &ct_bytes)?;
    String::from_utf8(plaintext_bytes)
        .map_err(|e| KyberError::DecryptionFailed(format!("UTF-8 decode error: {e}")))
}

/// Packet creation helpers
pub fn create_sensor_packet(lux: f64, timestamp: u64) -> Result<String, KyberError> {
    let pkt = SensorPacket { lux, timestamp };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

pub fn create_clipboard_packet(text: String, timestamp: u64) -> Result<String, KyberError> {
    let hash = compute_sha256_hex(&text);
    let pkt = ClipboardPacket {
        content: text,
        hash,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

pub fn create_sms_packet(sender: String, body: String, timestamp: u64) -> Result<String, KyberError> {
    let pkt = SmsPacket {
        sender,
        body,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

pub fn create_notification_packet(
    title: String,
    text: String,
    app_package: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = NotificationPacket {
        title,
        text,
        app_package,
        icon_base64: None,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

pub fn is_duplicate_clipboard(content_hash: String, recent_hashes: Vec<String>) -> bool {
    recent_hashes.contains(&content_hash)
}

pub fn compute_sha256(data: String) -> String {
    compute_sha256_hex(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_handshake() {
        let keypair = generate_pq_keypair().unwrap();
        assert!(!keypair.public_key_hex.is_empty());
        assert!(!keypair.secret_key_hex.is_empty());

        let kem_res = encapsulate_pq_secret(keypair.public_key_hex).unwrap();
        assert!(!kem_res.ciphertext_hex.is_empty());
        assert!(!kem_res.shared_secret_hex.is_empty());

        let decapsulated_secret =
            decapsulate_pq_secret(kem_res.ciphertext_hex, keypair.secret_key_hex).unwrap();
        assert_eq!(kem_res.shared_secret_hex, decapsulated_secret);
    }

    #[test]
    fn test_hkdf_and_chacha20_encryption() {
        let shared_secret = "01".repeat(32);
        let salt = "02".repeat(16);
        let session_key = derive_session_key(shared_secret, salt).unwrap();
        assert_eq!(session_key.len(), 64);

        let plaintext = "Kyberpipe PQC Secure Message Test".to_string();
        let enc = encrypt_payload_with_key(session_key.clone(), plaintext.clone()).unwrap();

        let dec = decrypt_payload_with_key(session_key, enc.nonce_hex, enc.ciphertext_hex).unwrap();
        assert_eq!(plaintext, dec);
    }

    #[test]
    fn test_clipboard_deduplication() {
        let dedup = crypto::ClipboardDeduplicator::new();
        let hash1 = compute_sha256("test data 1".into());
        let hash2 = compute_sha256("test data 2".into());
        let hash3 = compute_sha256("test data 3".into());
        let hash4 = compute_sha256("test data 4".into());

        dedup.record_hash(hash1.clone());
        dedup.record_hash(hash2.clone());
        dedup.record_hash(hash3.clone());

        assert!(dedup.is_duplicate(&hash1));
        assert!(dedup.is_duplicate(&hash2));
        assert!(dedup.is_duplicate(&hash3));

        // Adding 4th element should pop 1st element (hash1)
        dedup.record_hash(hash4.clone());
        assert!(!dedup.is_duplicate(&hash1));
        assert!(dedup.is_duplicate(&hash4));
    }

    #[test]
    fn test_packet_creations() {
        let sensor = create_sensor_packet(42.5, 1000).unwrap();
        assert!(sensor.contains("42.5"));

        let clip = create_clipboard_packet("hello world".into(), 1001).unwrap();
        assert!(clip.contains("hello world"));

        let sms = create_sms_packet("+123456789".into(), "Verification code 1234".into(), 1002).unwrap();
        assert!(sms.contains("+123456789"));
    }
}
