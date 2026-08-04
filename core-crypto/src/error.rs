use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, uniffi::Error)]
pub enum KyberError {
    #[error("[CRYPTO_ERROR] {0}")]
    CryptoError(String),

    #[error("[KEY_GEN_FAILED] {0}")]
    KeyGenerationFailed(String),

    #[error("[ENCAPSULATION_FAILED] {0}")]
    EncapsulationFailed(String),

    #[error("[DECAPSULATION_FAILED] {0}")]
    DecapsulationFailed(String),

    #[error("[ENCRYPTION_FAILED] {0}")]
    EncryptionFailed(String),

    #[error("[DECRYPTION_FAILED] {0}")]
    DecryptionFailed(String),

    #[error("[SERIALIZATION_ERROR] {0}")]
    SerializationError(String),

    #[error("[NETWORK_ERROR] {0}")]
    NetworkError(String),

    #[error("[SESSION_DESYNC] {0}")]
    SessionDesynchronized(String),

    /// AUDIT #3: a Synchronize packet from a HIGHER ratchet generation could
    /// not be applied because the rekey carrier that would derive the pending
    /// proposal was missed (the handoff dropped it). This is NOT a benign
    /// no-op — the session cannot silently resync across the generation
    /// boundary and the poll layer must escalate to a re-pair hint instead of
    /// retrying forever against the 15s sync rate limit.
    #[error("[CROSS_GENERATION_RESYNC_REQUIRED] {0}")]
    CrossGenerationResyncRequired(String),

    #[error("[INVALID_KEY_LENGTH] expected {expected}, got {got}")]
    InvalidKeyLength { expected: u64, got: u64 },
}

impl KyberError {
    /// Machine-readable error code for UI-level error categorization.
    /// Use this instead of string-matching on error messages.
    pub fn error_code(&self) -> &'static str {
        match self {
            KyberError::CryptoError(_) => "CRYPTO_ERROR",
            KyberError::KeyGenerationFailed(_) => "KEY_GEN_FAILED",
            KyberError::EncapsulationFailed(_) => "ENCAPSULATION_FAILED",
            KyberError::DecapsulationFailed(_) => "DECAPSULATION_FAILED",
            KyberError::EncryptionFailed(_) => "ENCRYPTION_FAILED",
            KyberError::DecryptionFailed(_) => "DECRYPTION_FAILED",
            KyberError::SerializationError(_) => "SERIALIZATION_ERROR",
            KyberError::NetworkError(_) => "NETWORK_ERROR",
            KyberError::SessionDesynchronized(_) => "SESSION_DESYNC",
            KyberError::CrossGenerationResyncRequired(_) => "CROSS_GENERATION_RESYNC_REQUIRED",
            KyberError::InvalidKeyLength { .. } => "INVALID_KEY_LENGTH",
        }
    }
}
