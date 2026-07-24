use crate::error::KyberError;
use hkdf::Hkdf;
use sha2::Sha256;

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
