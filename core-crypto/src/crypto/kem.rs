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

/// Generate a Tor v3 onion client-authorization x25519 keypair (audit finding
/// #11). The PUBLIC half configures the onion service (`ADD_ONION ...
/// ClientAuth=<base32(pub)>`); the PRIVATE half is the credential a client
/// must hold (appended to the .onion URL as
/// `onion:descriptor:x25519:<base32(priv)>`) to reach the service at all —
/// without it the service is unreachable, so an exposed .onion address leaks
/// nothing. Returns (private_key, public_key), each 32 raw bytes.
pub fn generate_client_auth_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    let secret = X25519StaticSecret::random_from_rng(&mut rng);
    let public = X25519PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// Reject the eight canonical low-order X25519 encodings (audit finding #21).
/// The all-zero shared-secret check below catches the identity point, but
/// order-2/4/8 points produce a NON-zero low-order shared secret and must be
/// rejected at the input: an attacker who can steer the DH component toward a
/// small subgroup forces a biased (partially known) hybrid secret. These are
/// the eight points of small order on the Montgomery curve (RFC 7748 §5, as
/// enumerated in the X25519 draft) in their standard byte encodings.
fn is_low_order_x25519_point(pk: &[u8; 32]) -> bool {
    // The four distinct u-coordinates of small order on the Montgomery curve
    // (RFC 7748 §5 / the original Curve25519 small-order set). Every input in
    // this set forces the clamped X25519 output to the identity; rejecting at
    // the boundary is defense-in-depth on top of the all-zero output check.
    //
    // AUDIT F14 FIX: X25519 ignores the high bit of the FINAL byte, so each
    // small-order u-coordinate has TWO 32-byte encodings (sign bit set and
    // clear) that decode to the SAME point. The legacy table held only the
    // low-sign-bit forms, so the high-bit-set variants bypassed the check
    // while still forcing a known (non-zero) DH output. Mask the sign bit
    // before the table comparison so all 8 encodings are rejected — the
    // all-zero output check below only catches u = 0.
    let mut canonical = *pk;
    canonical[31] &= 0x7F;
    const LOW_ORDER: [&[u8; 32]; 4] = [
        // u = 0 (identity)
        &[0u8; 32],
        // u = 1 (order 2)
        &[
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ],
        // 325606250916557431795983626356110631294008115727848805560023387167927233504
        &[
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823
        &[
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
    ];
    LOW_ORDER.contains(&&canonical)
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
    // Contributory behavior check: reject low-order peer points BEFORE the DH so
    // the peer cannot force a known (small-subgroup) DH component into the
    // hybrid secret. The all-zero check is retained as a belt-and-suspenders
    // backstop for encodings not in the canonical table.
    if is_low_order_x25519_point(peer_x25519_pk_bytes)
        || x25519_ss.as_bytes().iter().all(|&b| b == 0)
    {
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
    // AUDIT FINDING #21: accept EXACTLY one ML-KEM-768 ciphertext — no
    // trailing bytes. The legacy `len >= 32 + ct_bytes` accepted a
    // non-canonical bundle (e.g. 1088-byte ML-KEM ct plus 400 trailing bytes)
    // as valid. A canonical-encoding policy must reject trailing garbage.
    if combined_ct_bytes.len() != 32 + kyber768::ciphertext_bytes() {
        return Err(KyberError::DecapsulationFailed(
            "Ciphertext has unexpected length: expected 32 + ML-KEM-768 ct".into(),
        ));
    }
    let (ephem_x25519_pk_bytes, mlkem_ct_bytes) = combined_ct_bytes.split_at(32);
    let mut ephem_x25519_arr = [0u8; 32];
    ephem_x25519_arr.copy_from_slice(ephem_x25519_pk_bytes);
    // Reject low-order ephemeral points before the DH (audit finding #21): the
    // all-zero output check only catches the identity point; order-2/4/8 points
    // produce a non-zero low-order shared secret and would pass it.
    if is_low_order_x25519_point(&ephem_x25519_arr) {
        return Err(KyberError::DecapsulationFailed(
            "Ephemeral X25519 public key is a low-order point".into(),
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// AUDIT F14: both byte encodings of every small-order X25519 point must be
    /// rejected. The legacy table held only the low-sign-bit forms; the
    /// high-bit-set encodings decode to the same small-order point (X25519
    /// ignores the top bit of the last byte) and previously bypassed the check.
    #[test]
    fn low_order_sign_bit_variants_are_rejected() {
        // The four canonical u-coordinates (low-sign-bit forms) — the SAME
        // byte arrays the LOW_ORDER table matches against.
        let u0 = [0u8; 32];
        let mut u1 = [0u8; 32];
        u1[0] = 1;
        let u_small_a: [u8; 32] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        let u_small_b: [u8; 32] = [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ];

        for base in [u0, u1, u_small_a, u_small_b] {
            assert!(
                is_low_order_x25519_point(&base),
                "low-sign-bit encoding must be rejected"
            );
            let mut sign_set = base;
            sign_set[31] |= 0x80;
            assert!(
                is_low_order_x25519_point(&sign_set),
                "sign-bit-set encoding of the same low-order point must ALSO be rejected (audit F14)"
            );
        }

        // A normal (non-low-order) point must pass the table.
        let mut normal = [0u8; 32];
        normal[0] = 0x09;
        normal[31] = 0x40;
        assert!(!is_low_order_x25519_point(&normal));
    }

    /// AUDIT F14 (end-to-end): encapsulate/decapsulate against a peer public
    /// key whose sign-bit-set encoding is a low-order point must FAIL at the
    /// boundary instead of proceeding with a known DH component.
    #[test]
    fn encapsulate_rejects_sign_bit_low_order_peer_key() {
        let mut low_order = [0u8; 32];
        low_order[0] = 1; // u = 1 (order 2)
        low_order[31] |= 0x80; // the encoding that used to bypass the check
                               // Valid ML-KEM public key so the ONLY rejection path is the X25519
                               // low-order boundary check (a valid keypair makes the test
                               // unambiguous — it cannot pass via an "invalid ML-KEM pk" error).
        let (valid_mpk, _) = kyber768::keypair();
        let err = encapsulate_hybrid(&low_order, valid_mpk.as_bytes()).unwrap_err();
        assert!(
            matches!(err, KyberError::EncapsulationFailed(_)),
            "sign-bit low-order peer key must be rejected: {err:?}"
        );
    }
}
