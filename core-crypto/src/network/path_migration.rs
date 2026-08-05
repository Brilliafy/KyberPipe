use hkdf::hmac::{Hmac, Mac};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Derive a domain-separated HMAC key for path challenges.
/// This prevents the raw session key from being used directly as an HMAC key,
/// providing cryptographic domain separation.
fn derive_path_challenge_key(session_key: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-path-challenge"), session_key);
    let mut okm = [0u8; 32];
    let _ = hk.expand(b"path-challenge-hmac-key", &mut okm);
    okm
}

/// Helper for Seamless Path Migration between LAN and WireGuard interfaces over QUIC CIDs
pub struct PathMigrationManager;

impl PathMigrationManager {
    /// Generate a cryptographically secure PATH_CHALLENGE token and matching PATH_RESPONSE token.
    /// The response is computed as HMAC-SHA256(path_challenge_key, challenge) — binding the path
    /// ownership proof to the authenticated session. Without this binding, any network observer
    /// could compute the response to any challenge via plain SHA256.
    pub fn create_path_challenge(session_key: &[u8]) -> (String, String) {
        let challenge_key = derive_path_challenge_key(session_key);
        let mut challenge_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge_bytes);
        let challenge_token = hex::encode(challenge_bytes);

        let mut mac =
            Hmac::<Sha256>::new_from_slice(&challenge_key).expect("HMAC key should be valid");
        mac.update(b"kyberpipe-path-response:");
        mac.update(challenge_token.as_bytes());
        let response_token = hex::encode(&mac.finalize().into_bytes()[..8]); // truncate to 8 bytes

        (challenge_token, response_token)
    }

    /// Verify PATH_RESPONSE matches expected challenge (constant-time HMAC comparison).
    /// The session key is required to recompute the HMAC — without it, unauthenticated
    /// network observers cannot forge valid responses.
    pub fn verify_path_response(
        session_key: &[u8],
        challenge_token: &str,
        response_token: &str,
    ) -> bool {
        let challenge_key = derive_path_challenge_key(session_key);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&challenge_key).expect("HMAC key should be valid");
        mac.update(b"kyberpipe-path-response:");
        mac.update(challenge_token.as_bytes());
        let expected = hex::encode(&mac.finalize().into_bytes()[..8]);
        let expected_bytes = expected.as_bytes();
        let response_bytes = response_token.as_bytes();
        if expected_bytes.len() != response_bytes.len() {
            return false;
        }
        expected_bytes.ct_eq(response_bytes).into()
    }
}
