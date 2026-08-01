use crate::error::KyberError;
use hkdf::Hkdf;
use sha2::Sha256;

/// Generate a 7-character alphanumeric Short Authentication String (SAS) for out-of-band verification.
/// Provides ~36 bits of entropy to resist MitM brute-force during pairing.
/// All characters are derived from HKDF output — no LCG fallback.
/// Bound to ephemeral host_pk, client_pk, and shared_secret — replay of the same
/// public keys within a session produces the same SAS, which is safe because
/// each pairing generates fresh ephemeral keys.
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

    let hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-sas-v2-salt"), &hkdf_input);
    // Derive 7 bytes from HKDF — enough for 7 base32 characters (5 bits each = 35 bits)
    let mut okm = [0u8; 7];
    hk.expand(b"kyberpipe-sas-code-v2", &mut okm)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;

    let charset = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 chars (no I, O, 0, 1)
    let mut code = String::with_capacity(7);
    // Extract 5 bits per character using the full HKDF output.
    // Each byte provides one character (upper 5 bits) with carry to the next.
    let mut accum: u64 = 0;
    let mut bits_in_accum = 0;
    for &byte in okm.iter() {
        accum = (accum << 8) | byte as u64;
        bits_in_accum += 8;
        while bits_in_accum >= 5 && code.len() < 7 {
            bits_in_accum -= 5;
            let idx = ((accum >> bits_in_accum) & 0x1F) as usize;
            code.push(charset[idx] as char);
        }
    }
    // Consume any remaining bits
    while bits_in_accum > 0 && code.len() < 7 {
        bits_in_accum -= 5;
        let idx = ((accum >> bits_in_accum) & 0x1F) as usize;
        code.push(charset[idx] as char);
    }

    Ok(code)
}
