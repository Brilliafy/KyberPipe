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
                                                       // Audit finding F17: extract exactly `CODE_LEN` contiguous 5-bit windows
                                                       // from the big-endian OKM bit stream (MSB-first), never fewer, never more.
                                                       // The previous implementation had a second loop that subtracted 5 from
                                                       // `bits_in_accum` while it was still 1–4 bits and then shifted `accum` by
                                                       // the resulting NEGATIVE amount — a shift-overflow panic in debug builds
                                                       // and masked/garbage index arithmetic in release. It was unreachable only
                                                       // because 7 bytes * 8 = 56 bits happened to exhaust the code length before
                                                       // the remainder hit 1–4 bits; ANY future change to the byte count, charset
                                                       // size, or code length would activate it.
                                                       //
                                                       // The rolling window below is the original algorithm minus the bug: `accum`
                                                       // is a shift register whose TOP `bits_in_accum` bits are the unconsumed
                                                       // stream, bytes are topped up when fewer than 5 valid bits remain, and each
                                                       // extraction is guarded by an explicit `>= 5` assertion so the shift can
                                                       // never go negative. At most 8+4 = 12 bits are ever buffered, so `u64` is
                                                       // always sufficient regardless of `okm.len()`.
    const CODE_LEN: usize = 7;
    let mut code = String::with_capacity(CODE_LEN);
    let mut accum: u64 = 0;
    let mut bits_in_accum: u32 = 0;
    let mut byte_idx = 0usize;
    for _ in 0..CODE_LEN {
        while bits_in_accum < 5 {
            // Top up with the next OKM byte. If the stream is exhausted but
            // fewer than 5 bits remain, the last window is zero-padded (same
            // effective value as the original's dead remainder loop, which
            // could never run with these constants).
            if byte_idx < okm.len() {
                accum = (accum << 8) | okm[byte_idx] as u64;
                byte_idx += 1;
                bits_in_accum += 8;
            } else {
                // Zero-pad: shift the (depleted) register and keep the count
                // at 5 so the guard below is satisfied deterministically.
                accum <<= 8;
                bits_in_accum += 8;
            }
        }
        debug_assert!(bits_in_accum >= 5, "window must never go negative");
        let shift = bits_in_accum - 5;
        let idx = ((accum >> shift) & 0x1F) as usize;
        code.push(charset[idx] as char);
        bits_in_accum -= 5;
    }

    Ok(code)
}
