pub mod crypto;
pub mod error;
pub mod network;
pub mod packets;

use error::KyberError;
use network::PathMigrationManager;
use packets::{
    compute_sha256_hex, BinaryClipboardPacket, ClipboardPacket, HardwareCommandPacket,
    NotificationActionPacket, NotificationPacket, OutboundSmsPacket, SensorPacket, SmsPacket,
};

uniffi::setup_scaffolding!();

#[derive(uniffi::Record)]
pub struct PqKeyPair {
    pub x25519_pk_hex: String,
    pub x25519_sk_hex: String,
    pub mlkem_pk_hex: String,
    pub mlkem_sk_hex: String,
}

#[derive(uniffi::Record)]
pub struct PqKemResponse {
    pub ciphertext_hex: String,
    pub shared_secret_hex: String,
}

#[derive(uniffi::Record)]
pub struct EncryptedPayload {
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(uniffi::Record)]
pub struct PathChallengeResult {
    pub challenge_token: String,
    pub expected_response: String,
}

/// Standalone UniFFI initialization helper for Hybrid post-quantum handshake
#[uniffi::export]
pub fn initialize_pq_handshake() -> Result<(), KyberError> {
    let _pair = crypto::generate_hybrid_keypair();
    Ok(())
}

/// UniFFI export: Generate Hybrid (X25519 + ML-KEM-768) keypair returning hex-encoded strings
#[uniffi::export]
pub fn generate_pq_keypair() -> Result<PqKeyPair, KyberError> {
    let pair = crypto::generate_hybrid_keypair();
    Ok(PqKeyPair {
        x25519_pk_hex: hex::encode(pair.x25519_pk),
        x25519_sk_hex: hex::encode(pair.x25519_sk),
        mlkem_pk_hex: hex::encode(pair.mlkem_pk),
        mlkem_sk_hex: hex::encode(pair.mlkem_sk),
    })
}

/// UniFFI export: Encapsulate shared secret against peer's Hybrid public keys
#[uniffi::export]
pub fn encapsulate_pq_secret(
    peer_x25519_pk_hex: String,
    peer_mlkem_pk_hex: String,
) -> Result<PqKemResponse, KyberError> {
    let x25519_bytes = hex::decode(&peer_x25519_pk_hex)
        .map_err(|e| KyberError::EncapsulationFailed(format!("Invalid X25519 public key hex: {e}")))?;
    if x25519_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: x25519_bytes.len() as u64,
        });
    }
    let mut x25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(&x25519_bytes);

    let mlkem_bytes = hex::decode(&peer_mlkem_pk_hex)
        .map_err(|e| KyberError::EncapsulationFailed(format!("Invalid ML-KEM public key hex: {e}")))?;

    let res = crypto::encapsulate_hybrid(&x25519_arr, &mlkem_bytes)?;
    Ok(PqKemResponse {
        ciphertext_hex: hex::encode(res.ciphertext_bytes),
        shared_secret_hex: hex::encode(res.combined_shared_secret),
    })
}

/// UniFFI export: Decapsulate shared secret against ciphertext & secret keys
#[uniffi::export]
pub fn decapsulate_pq_secret(
    ciphertext_hex: String,
    my_x25519_sk_hex: String,
    my_mlkem_sk_hex: String,
) -> Result<String, KyberError> {
    let ct_bytes = hex::decode(&ciphertext_hex)
        .map_err(|e| KyberError::DecapsulationFailed(format!("Invalid ciphertext hex: {e}")))?;

    let x25519_sk_bytes = hex::decode(&my_x25519_sk_hex)
        .map_err(|e| KyberError::DecapsulationFailed(format!("Invalid X25519 secret key hex: {e}")))?;
    if x25519_sk_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: x25519_sk_bytes.len() as u64,
        });
    }
    let mut x25519_sk_arr = [0u8; 32];
    x25519_sk_arr.copy_from_slice(&x25519_sk_bytes);

    let mlkem_sk_bytes = hex::decode(&my_mlkem_sk_hex)
        .map_err(|e| KyberError::DecapsulationFailed(format!("Invalid ML-KEM secret key hex: {e}")))?;

    let ss = crypto::decapsulate_hybrid(&ct_bytes, &x25519_sk_arr, &mlkem_sk_bytes)?;
    Ok(hex::encode(ss))
}

/// UniFFI export: HKDF-SHA256 key derivation
#[uniffi::export]
pub fn derive_session_key(shared_secret_hex: String, salt_hex: String) -> Result<String, KyberError> {
    let ss_bytes = hex::decode(&shared_secret_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid shared secret hex: {e}")))?;
    let salt_bytes = hex::decode(&salt_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid salt hex: {e}")))?;

    let derived = crypto::derive_session_key(&ss_bytes, &salt_bytes, b"kyberpipe-hybrid-session")?;
    Ok(hex::encode(derived))
}

/// UniFFI export: Encrypt plaintext string with 256-bit session key
#[uniffi::export]
pub fn encrypt_payload_with_key(
    session_key_hex: String,
    data: String,
) -> Result<EncryptedPayload, KyberError> {
    let key_bytes = hex::decode(&session_key_hex)
        .map_err(|e| KyberError::EncryptionFailed(format!("Invalid key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len() as u64,
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
#[uniffi::export]
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
            got: key_bytes.len() as u64,
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
#[uniffi::export]
pub fn create_sensor_packet(lux: f64, timestamp: u64) -> Result<String, KyberError> {
    let pkt = SensorPacket { lux, timestamp };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_clipboard_packet(text: String, timestamp: u64) -> Result<String, KyberError> {
    let hash = compute_sha256_hex(&text);
    let pkt = ClipboardPacket {
        content: text,
        hash,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_binary_clipboard_packet(
    mime_type: String,
    data_base64: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let hash = compute_sha256_hex(&data_base64);
    let pkt = BinaryClipboardPacket {
        mime_type,
        data_base64,
        hash,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_sms_packet(sender: String, body: String, timestamp: u64) -> Result<String, KyberError> {
    let pkt = SmsPacket {
        sender,
        body,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_outbound_sms_packet(recipient: String, body: String, timestamp: u64) -> Result<String, KyberError> {
    let pkt = OutboundSmsPacket {
        recipient,
        body,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_notification_packet(
    title: String,
    text: String,
    app_package: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = NotificationPacket {
        sbn_key: format!("{app_package}_{timestamp}"),
        title,
        text,
        app_package,
        icon_base64: None,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_notification_action_packet(
    sbn_key: String,
    action_index: u32,
    action_title: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = NotificationActionPacket {
        sbn_key,
        action_index,
        action_title,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_hardware_command_packet(
    command_type: String,
    payload_json: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = HardwareCommandPacket {
        command_type,
        payload_json,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn generate_path_challenge_tokens() -> PathChallengeResult {
    let (challenge_token, expected_response) = PathMigrationManager::create_path_challenge();
    PathChallengeResult {
        challenge_token,
        expected_response,
    }
}

#[uniffi::export]
pub fn verify_path_response_token(challenge_token: String, response_token: String) -> bool {
    PathMigrationManager::verify_path_response(&challenge_token, &response_token)
}

#[uniffi::export]
pub fn generate_sas_code(
    host_pk_hex: String,
    client_pk_hex: String,
    shared_secret_hex: String,
) -> Result<String, KyberError> {
    let host_bytes = hex::decode(&host_pk_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid host PK hex: {e}")))?;
    let client_bytes = hex::decode(&client_pk_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid client PK hex: {e}")))?;
    let ss_bytes = hex::decode(&shared_secret_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid SS hex: {e}")))?;

    crypto::generate_sas_code(&host_bytes, &client_bytes, &ss_bytes)
}

#[uniffi::export]
pub fn is_duplicate_clipboard(content_hash: String, recent_hashes: Vec<String>) -> bool {
    recent_hashes.contains(&content_hash)
}

#[uniffi::export]
pub fn compute_sha256(data: String) -> String {
    compute_sha256_hex(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_handshake_flow() {
        let _alice = generate_pq_keypair().unwrap();
        let bob = generate_pq_keypair().unwrap();

        let kem_res = encapsulate_pq_secret(bob.x25519_pk_hex, bob.mlkem_pk_hex).unwrap();
        let decapsulated = decapsulate_pq_secret(
            kem_res.ciphertext_hex,
            bob.x25519_sk_hex,
            bob.mlkem_sk_hex,
        )
        .unwrap();

        assert_eq!(kem_res.shared_secret_hex, decapsulated);
    }
}
