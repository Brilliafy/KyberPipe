use super::KyberError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Keyed-HMAC type alias.
type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of the master secret, embedded PUBLICLY in every share (audit
/// finding #5 follow-up). It is the tamper-evidence reference that does NOT
/// require the secret at reconstruction time:
///
///  - every share carries it, so any k-subset can compare them for
///    consistency (a mixed-split or substituted share set is rejected);
///  - after interpolation, `SHA-256(recovered)` must equal it — a share that
///    was corrupted or deliberately substituted in a way that changed the
///    polynomial yields a recovered secret whose hash does not match, so
///    silent corruption is impossible.
///
/// Feldman-style commitments are impossible in the small GF(2^8) field (no
/// group with hard DLP), so the public secret-hash + public per-split
/// verification key below are the sound substitutes: forgeability by an
/// attacker who holds fewer than k valid shares is bounded by preimage
/// resistance of the hash reference.
pub(crate) fn compute_secret_hash(master_secret: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(master_secret);
    h.finalize().into()
}

/// Derive the share-integrity MAC key from the PUBLIC per-split verification
/// key (audit finding #5 follow-up). The key is deliberately NOT derived from
/// the master secret: `verify_share_public` must work at RECONSTRUCTION time,
/// when the secret is exactly the thing being recovered. The per-split random
/// `verify_key` (embedded in every share) binds the whole share set together
/// and rejects cross-split substitution — shares from different splits carry
/// different keys.
pub(crate) fn derive_share_mac_key(verify_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-shamir-hmac-v2"), verify_key);
    let mut okm = [0u8; 32];
    let _ = hk.expand(b"share-integrity", &mut okm);
    okm
}

/// Build the canonical MAC input for a share. Binds the share index AND the
/// embedded x-coordinate (data[0] = index + 1) together with all metadata, so
/// an attacker cannot swap share indices or disagree on the coordinate.
fn mac_input(share: &ShamirShare) -> Vec<u8> {
    let mut mac_input = Vec::new();
    mac_input.push(share.index);
    mac_input.push(share.threshold);
    mac_input.push(share.total);
    mac_input.extend_from_slice(&share.timestamp.to_be_bytes());
    mac_input.extend_from_slice(&share.data);
    mac_input
}

/// Keyed HMAC-SHA256 integrity tag for a share, keyed by the per-split PUBLIC
/// verification key.
pub(crate) fn compute_share_mac(verify_key: &[u8; 32], share: &ShamirShare) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&derive_share_mac_key(verify_key))
        .expect("HMAC key is 32 bytes");
    mac.update(&mac_input(share));
    mac.finalize().into_bytes().into()
}

fn default_array_32() -> [u8; 32] {
    [0u8; 32]
}

/// Metadata-enriched Shamir share. Integrity is dual-layer (audit finding #5
/// follow-up):
///
///  1. a per-share keyed HMAC under a FRESH RANDOM per-split `verify_key` that
///     is embedded in EVERY share — public so any k-subset can verify shares
///     WITHOUT the master secret, and split-bound so a share from another
///     split is rejected;
///  2. the PUBLIC `secret_hash` (SHA-256 of the master secret) — the
///     reconstruction backstop that catches even an adaptive forgery (see
///     `reconstruct_shamir_with_meta`).
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ShamirShare {
    pub index: u8,
    pub threshold: u8,
    pub total: u8,
    pub timestamp: u64,
    #[serde(with = "hex_bytes")]
    pub data: Vec<u8>,
    #[serde(with = "hex_bytes_32")]
    pub mac: [u8; 32],
    /// Fresh random per-split verification key (PUBLIC). Identical across all
    /// shares of one split; rejects cross-split substitution.
    #[serde(with = "hex_bytes_32", default = "default_array_32")]
    pub verify_key: [u8; 32],
    /// SHA-256 of the master secret (PUBLIC). Identical across all shares of
    /// one split; the reconstruction-time tamper-evidence reference.
    #[serde(with = "hex_bytes_32", default = "default_array_32")]
    pub secret_hash: [u8; 32],
}

mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte hex string"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

/// GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
struct Gf256;

impl Gf256 {
    fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let idx_a = GF256_LOG[a as usize] as u16;
        let idx_b = GF256_LOG[b as usize] as u16;
        let sum = idx_a + idx_b;
        let mod_sum = if sum >= 255 { sum - 255 } else { sum };
        GF256_EXP[mod_sum as usize]
    }

    fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        let idx = GF256_LOG[a as usize] as u16;
        let neg = 255 - idx;
        GF256_EXP[neg as usize]
    }
}

static GF256_LOG: [u8; 256] = [   0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
   0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
   0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
   0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
   0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
   0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
   0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
   0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
   0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
   0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
   0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
   0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
   0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
   0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
   0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
   0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,];

static GF256_EXP: [u8; 256] = [
    0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
    0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
    0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
    0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
    0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
    0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
    0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
    0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
    0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
    0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
    0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
    0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
    0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
    0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
    0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01,
];

/// Evaluate polynomial at point x using Horner's method in GF(2^8)
fn gf256_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = Gf256::mul(result, x) ^ c;
    }
    result
}

/// Lagrange interpolation in GF(2^8) to recover the secret byte at x=0
fn gf256_lagrange_interpolate(points: &[(u8, u8)], x: u8) -> u8 {
    let mut result = 0u8;
    for i in 0..points.len() {
        let (xi, yi) = points[i];
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                num = Gf256::mul(num, x ^ xj);
                den = Gf256::mul(den, xi ^ xj);
            }
        }
        let li = Gf256::mul(yi, Gf256::mul(num, Gf256::inv(den)));
        result ^= li;
    }
    result
}

#[deprecated(
    note = "Use split_secret_shamir_with_meta for shares with metadata and HMAC verification"
)]
/// Split a master secret into n shares requiring k shares to reconstruct (GF(2^8) Shamir Secret Sharing)
pub fn split_secret_shamir(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, KyberError> {
    if k == 0 || n == 0 || k > n || k > 255 || n > 255 {
        return Err(KyberError::CryptoError(
            "Invalid k-of-n threshold parameters (k,n must be 1..=255, k <= n)".into(),
        ));
    }
    let mut shares = vec![Vec::with_capacity(secret.len() + 2); n];
    for (idx, share) in shares.iter_mut().enumerate() {
        share.push((idx + 1) as u8);
        share.push(k as u8);
    }

    for &byte in secret {
        let mut coeffs = vec![byte; k];
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = rand::random::<u8>();
        }
        for (idx, share) in shares.iter_mut().enumerate() {
            let x = (idx + 1) as u8;
            let y = gf256_eval(&coeffs, x);
            share.push(y);
        }
    }
    Ok(shares)
}

/// Reconstruct master secret from k shares using Lagrange Interpolation in GF(2^8)
pub fn reconstruct_secret_shamir(shares: &[Vec<u8>], k: usize) -> Result<Vec<u8>, KyberError> {
    if shares.len() < k || shares.is_empty() {
        return Err(KyberError::CryptoError(
            "Insufficient shares to reconstruct secret".into(),
        ));
    }
    let secret_len = shares[0].len() - 2;
    if secret_len == 0 {
        return Err(KyberError::CryptoError("Share data too short".into()));
    }
    // Validate all shares have consistent length
    for share in shares {
        if share.len() != shares[0].len() {
            return Err(KyberError::CryptoError(
                "Share length mismatch — shares must be from the same split".into(),
            ));
        }
    }
    // Validate distinct x coordinates — duplicate x causes division-by-zero in GF(256)
    let mut x_coords: Vec<u8> = shares.iter().take(k).map(|s| s[0]).collect();
    x_coords.sort();
    for i in 1..x_coords.len() {
        if x_coords[i] == x_coords[i - 1] {
            return Err(KyberError::CryptoError(
                "Duplicate x coordinate in shares — share set is invalid".into(),
            ));
        }
    }
    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        let mut points = Vec::with_capacity(k);
        for share in shares.iter().take(k) {
            let x = share[0];
            let y = share[byte_idx + 2];
            points.push((x, y));
        }
        let recovered_byte = gf256_lagrange_interpolate(&points, 0);
        secret.push(recovered_byte);
    }
    Ok(secret)
}
/// Split a master secret into n shares with metadata, a fresh per-split PUBLIC
/// verification key and the PUBLIC secret hash (audit finding #5 follow-up).
/// The HMAC is keyed by `verify_key` (not the secret), so verification at
/// reconstruction does not require the recovered secret; the public
/// `secret_hash` provides the tamper-evidence backstop.
#[allow(deprecated)]
pub fn split_secret_shamir_with_meta(
    secret: &[u8],
    k: usize,
    n: usize,
) -> Result<Vec<ShamirShare>, KyberError> {
    let shares = split_secret_shamir(secret, k, n)?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secret_hash = compute_secret_hash(secret);
    // Fresh random per-split verification key. Deliberately PUBLIC and embedded
    // in every share: it lets any k-subset verify shares without the secret and
    // binds the split together (a share from a different split fails the MAC
    // because its key differs).
    let mut verify_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut verify_key);
    let mut result = Vec::with_capacity(n);
    for (i, data) in shares.into_iter().enumerate() {
        let share = ShamirShare {
            index: i as u8,
            threshold: k as u8,
            total: n as u8,
            timestamp,
            data,
            mac: [0u8; 32],
            verify_key,
            secret_hash,
        };
        let mac = compute_share_mac(&verify_key, &share);
        result.push(ShamirShare { mac, ..share });
    }
    Ok(result)
}

/// Verify a share's integrity WITHOUT the master secret (audit finding #5
/// follow-up): x-coordinate consistency, the public-keyed HMAC, and a
/// non-empty public secret-hash reference. Works at reconstruction time — the
/// whole point of the redesign is that verification must not require the
/// secret being recovered. An attacker who knows the public `verify_key` can
/// re-forge a single share's tag; the cross-share consistency checks in
/// [`reconstruct_shamir_with_meta`] and the `secret_hash` backstop catch any
/// forgery that changes the recovered secret.
pub fn verify_share_public(share: &ShamirShare) -> bool {
    // Consistency: the embedded x-coordinate must agree with the share index.
    let x = *share.data.first().unwrap_or(&0);
    if x != share.index.saturating_add(1) {
        return false;
    }
    // A zero secret_hash means a legacy share produced by an old build — it
    // cannot be validated (audit finding #5: the old scheme was secret-keyed
    // and unverifiable at reconstruction). Refuse it loudly.
    if share.secret_hash == [0u8; 32] || share.verify_key == [0u8; 32] {
        return false;
    }
    let computed = compute_share_mac(&share.verify_key, share);
    subtle::ConstantTimeEq::ct_eq(computed.as_slice(), share.mac.as_slice()).into()
}

/// Verify a ShamirShare against the master secret. Available to the SPLITTER
/// (who knows the secret) as a self-check before handing shares out: binds the
/// share to the exact secret by recomputing the public secret hash.
/// (Audit finding #5 follow-up: this is NOT the reconstruction-time verifier —
/// use [`verify_share_public`] + [`reconstruct_shamir_with_meta`] there.)
pub fn verify_share_with_key(share: &ShamirShare, master_secret: &[u8]) -> bool {
    if !verify_share_public(share) {
        return false;
    }
    let expected = compute_secret_hash(master_secret);
    subtle::ConstantTimeEq::ct_eq(expected.as_slice(), share.secret_hash.as_slice()).into()
}

/// Metadata-validated reconstruction (audit finding #5 follow-up): verify every
/// share in the k-subset with the PUBLIC verifier, enforce cross-share
/// consistency (identical secret hash, identical verify key, identical
/// threshold), interpolate, and then require `SHA-256(recovered) == secret_hash`
/// — so a corrupted or substituted share can never silently produce garbage key
/// material. Returns an error on ANY inconsistency instead of silently
/// recovering the wrong secret.
pub fn reconstruct_shamir_with_meta(
    shares: &[ShamirShare],
    k: usize,
) -> Result<Vec<u8>, KyberError> {
    if k == 0 || shares.len() < k {
        return Err(KyberError::CryptoError(
            "Insufficient shares to reconstruct secret".into(),
        ));
    }
    let subset = &shares[..k];
    // Cross-share consistency: all k shares must belong to the same split.
    let secret_hash = subset[0].secret_hash;
    let verify_key = subset[0].verify_key;
    let threshold = subset[0].threshold;
    for share in subset {
        if share.secret_hash != secret_hash || share.verify_key != verify_key {
            return Err(KyberError::CryptoError(
                "Share set is inconsistent — shares come from different splits or were substituted".into(),
            ));
        }
        if share.threshold != threshold || share.total != subset[0].total {
            return Err(KyberError::CryptoError(
                "Share metadata mismatch (threshold/total) — corrupted share".into(),
            ));
        }
        if !verify_share_public(share) {
            return Err(KyberError::CryptoError(format!(
                "Share {} failed integrity verification — corrupted or forged",
                share.index
            )));
        }
    }
    let raw: Vec<Vec<u8>> = subset.iter().map(|s| s.data.clone()).collect();
    let recovered = reconstruct_secret_shamir(&raw, k)?;
    // Tamper-evidence backstop: the reconstructed secret MUST hash to the
    // public reference. An adaptive forgery that changed any y-value produces a
    // different polynomial — hence a different secret — and is caught here even
    // though its public-keyed MAC is forgeable.
    let recovered_hash = compute_secret_hash(&recovered);
    let hash_ok: bool = subtle::ConstantTimeEq::ct_eq(
        recovered_hash.as_slice(),
        secret_hash.as_slice(),
    )
    .into();
    if !hash_ok {
        return Err(KyberError::CryptoError(
            "Reconstructed secret failed hash verification — a share was corrupted or substituted".into(),
        ));
    }
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_verification_and_reconstruction() {
        let secret = b"master-identity-key-bytes";
        let shares = split_secret_shamir_with_meta(secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        // Valid shares verify against the master secret (splitter self-check).
        for share in &shares {
            assert!(verify_share_with_key(share, secret));
        }
        // AUDIT FINDING #5: a share must ALSO verify WITHOUT the secret — the
        // whole point of the public verifier — and a k-subset must reconstruct
        // to the exact secret.
        for share in &shares {
            assert!(verify_share_public(share));
        }
        let recovered = reconstruct_shamir_with_meta(&shares[..2], 2).unwrap();
        assert_eq!(recovered, secret);
        // Tampering with any share byte invalidates the MAC (public verifier).
        let mut tampered = shares[0].clone();
        let last = tampered.data.len() - 1;
        tampered.data[last] ^= 0xFF;
        assert!(!verify_share_public(&tampered));
        assert!(!verify_share_with_key(&tampered, secret));
        // Swapping indices invalidates the tag (index bound into MAC).
        let mut swapped = shares[1].clone();
        swapped.index = shares[0].index;
        assert!(!verify_share_public(&swapped));
    }

    #[test]
    fn test_reconstruction_rejects_corrupted_share() {
        let secret = b"another-master-key";
        let mut shares = split_secret_shamir_with_meta(secret, 2, 3).unwrap();
        // AUDIT FINDING #5: a corrupted share must make reconstruction FAIL
        // LOUDLY — the legacy path silently produced garbage key material.
        shares[1].data[2] ^= 0x01;
        assert!(
            reconstruct_shamir_with_meta(&shares[..2], 2).is_err(),
            "corrupted share must be refused, not silently reconstructed"
        );
    }

    #[test]
    fn test_reconstruction_rejects_cross_split_substitution() {
        let secret = b"real-master-key";
        let split_a = split_secret_shamir_with_meta(secret, 2, 3).unwrap();
        // A DIFFERENT split of the SAME secret carries a different verify key
        // — substituting a share from it must be rejected (mixed-split check).
        let split_b = split_secret_shamir_with_meta(secret, 2, 3).unwrap();
        let mut mixed = vec![split_a[0].clone(), split_b[1].clone()];
        // The two shares may have collided on indices — force a genuine mix.
        mixed[0].verify_key = split_a[0].verify_key;
        mixed[1] = split_b[1].clone();
        assert!(
            reconstruct_shamir_with_meta(&mixed, 2).is_err(),
            "cross-split substitution must be rejected"
        );
    }

    #[test]
    fn test_x_coordinate_consistency_enforced() {
        let secret = b"x-coord-key";
        let mut share = split_secret_shamir_with_meta(secret, 2, 3)
            .unwrap()
            .remove(0);
        // Corrupt the embedded x-coordinate so it disagrees with index.
        share.data[0] = share.data[0].wrapping_add(7);
        assert!(!verify_share_public(&share));
        assert!(!verify_share_with_key(&share, secret));
    }

    #[test]
    fn test_wrong_master_secret_fails() {
        let secret = b"real-master-key";
        let shares = split_secret_shamir_with_meta(secret, 2, 3).unwrap();
        assert!(!verify_share_with_key(&shares[0], b"attacker-key"));
    }

    #[test]
    fn test_adaptive_forgery_caught_by_secret_hash() {
        let secret = b"forge-me-not-0123456789";
        let shares = split_secret_shamir_with_meta(secret, 2, 3).unwrap();
        // An attacker who holds the PUBLIC verify_key can recompute a valid MAC
        // for a forged y-value. The forged share still interpolates to a
        // DIFFERENT secret whose hash does not match — the backstop refuses it.
        let mut forged = shares[0].clone();
        let last = forged.data.len() - 1;
        forged.data[last] ^= 0x40;
        forged.mac = compute_share_mac(&forged.verify_key, &forged);
        assert!(verify_share_public(&forged), "public MAC is forgeable by design");
        let mut set = vec![forged, shares[1].clone()];
        set.sort_by_key(|s| s.data[0]);
        assert!(
            reconstruct_shamir_with_meta(&set, 2).is_err(),
            "adaptive forgery must be caught by the secret-hash backstop"
        );
    }
}
