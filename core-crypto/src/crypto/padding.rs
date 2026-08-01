use crate::error::KyberError;

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
