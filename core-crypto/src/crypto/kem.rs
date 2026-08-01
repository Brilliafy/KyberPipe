use crate::error::KyberError;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Holds raw Hybrid (X25519 + ML-KEM-768) keypair
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    pub x25519_pk: [u8; 32],
    pub x25519_sk: [u8; 32],
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

/// Holds Hybrid encapsulation response
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct HybridKemResult {
    pub ciphertext_bytes: Vec<u8>,
    pub combined_shared_secret: Vec<u8>,
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
    // Contributory behavior check: a low-order X25519 point produces an
    // all-zero shared secret. Reject it so the peer cannot force a known
    // (non-random) DH component into the hybrid secret.
    if x25519_ss.as_bytes().iter().all(|&b| b == 0) {
        return Err(KyberError::EncapsulationFailed(
            "Peer X25519 public key is a low-order point — shared secret is all zero".into(),
        ));
    }
    let peer_mlkem_pk = kyber768::PublicKey::from_bytes(peer_mlkem_pk_bytes).map_err(|_| {
        KyberError::EncapsulationFailed("Invalid ML-KEM-768 public key bytes".into())
    })?;
    let (mlkem_ss, mlkem_ct) = kyber768::encapsulate(&peer_mlkem_pk);
    let mut combined_ss = Vec::with_capacity(32 + mlkem_ss.as_bytes().len() + 40);
    combined_ss.extend_from_slice(b"KyberPipe-X25519");
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(b"KyberPipe-MLKEM");
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
    // Contributory behavior check — reject all-zero shared secrets from
    // low-order ephemeral points.
    if x25519_ss.as_bytes().iter().all(|&b| b == 0) {
        return Err(KyberError::DecapsulationFailed(
            "Ephemeral X25519 public key is a low-order point — shared secret is all zero".into(),
        ));
    }
    let mlkem_ct = kyber768::Ciphertext::from_bytes(mlkem_ct_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 ciphertext bytes".into())
    })?;
    let my_mlkem_sk = kyber768::SecretKey::from_bytes(my_mlkem_sk_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 secret key bytes".into())
    })?;
    let mlkem_ss = kyber768::decapsulate(&mlkem_ct, &my_mlkem_sk);
    let mut combined_ss = Vec::with_capacity(32 + mlkem_ss.as_bytes().len() + 40);
    combined_ss.extend_from_slice(b"KyberPipe-X25519");
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(b"KyberPipe-MLKEM");
    combined_ss.extend_from_slice(mlkem_ss.as_bytes());
    Ok(combined_ss)
}
