use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, uniffi::Error)]
pub enum KyberError {
    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: u64, got: u64 },
}
