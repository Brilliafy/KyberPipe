use crate::error::KyberError;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use zeroize::Zeroizing;

/// Sign payload using NIST ML-DSA-65 (Module Lattice-Based Digital Signature Algorithm)
pub fn sign_mldsa_payload(payload: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, KyberError> {
    if payload.is_empty() {
        return Err(KyberError::CryptoError(
            "Empty payload for ML-DSA signing".into(),
        ));
    }
    // Copy the caller's secret key into a zeroizing buffer so our working copy
    // of the private key material is wiped on drop (the caller's own buffer is
    // borrowed and cannot be zeroized from here).
    let owned_sk = Zeroizing::new(sk_bytes.to_vec());
    let sk = mldsa65::SecretKey::from_bytes(&owned_sk)
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
