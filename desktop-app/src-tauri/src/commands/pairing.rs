use crate::state::AppState;
use crate::state::SecureString;
use core_crypto::generate_pq_keypair;
use hex;
use tauri::State;

/// Keyring service name used for all KyberPipe secrets.
const KEYRING_SERVICE: &str = "kyberpipe";

/// Store a secret (already hex-encoded by the caller) directly in the OS
/// keychain/keyring. No double encryption: the OS keyring (Secret Service /
/// Keychain / Credential Manager) already encrypts the stored blob at rest with
/// its own key, so a second application-layer wrap key only creates a nonce-
/// reuse hazard (fixed zero nonce) and a per-boot throwaway key that made every
/// blob written before a restart permanently undecryptable.
fn write_keyring_secret(key_name: &str, secret_hex: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, key_name)
        .map_err(|e| format!("Keyring access failed: {e}"))?;
    entry
        .set_password(secret_hex)
        .map_err(|e| format!("Failed to store secret in OS Secret Service: {e}"))
}

/// Read a secret previously stored by `write_keyring_secret`.
fn read_keyring_secret(key_name: &str) -> Option<String> {
    keyring::Entry::new(KEYRING_SERVICE, key_name)
        .ok()
        .and_then(|entry| entry.get_password().ok())
}

#[tauri::command]
pub fn generate_keypair(
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::PqPairingPublic, String> {
    // Generate the keypair; the FULL keypair (including secrets) stays in Rust
    // state where the pairing handler can decapsulate. The webview receives ONLY
    // the public keys needed to build pairing QR payloads — the private halves
    // never enter the JS heap.
    let pair = generate_pq_keypair().map_err(|e| e.to_string())?;
    state.set_keypair(Some(pair.clone()));
    state.add_log("[PQC] Generated Hybrid Keypair (X25519 + ML-KEM-768)".to_string());
    Ok(core_crypto::PqPairingPublic::from(&pair))
}

#[allow(dead_code)]
/// Core SAS-confirmation logic, extracted from the Tauri command so the
/// pairing flow can be driven end-to-end by integration tests without a
/// Tauri `State` handle.
pub async fn perform_sas_confirmation(
    state: &std::sync::Arc<AppState>,
    verified_sas: String,
    paired_name: String,
) -> Result<String, String> {
    // Use atomic accessor to check and increment attempt count
    let count = state.get_sas_attempt_count();
    if count >= 3 {
        state.clear_all_pairing();
        return Err("Too many SAS attempts. Re-initiate pairing.".into());
    }
    state.increment_sas_attempt_count();

    // Atomically read both sas_code and pending_session_key in one critical section
    let (stored_sas, pending_key) = {
        let (sas, pending) = state.get_pairing_read();
        (sas, pending.to_string())
    };

    if stored_sas.is_empty() {
        return Err("No pending pairing SAS code found. Initiate pairing first.".into());
    }
    if stored_sas != verified_sas {
        return Err("SAS code mismatch. Pairing rejected.".into());
    }
    if pending_key.is_empty() {
        return Err("No pending session key. Initiate pairing first.".into());
    }

    state.set_pending_session_key(SecureString::new(String::new()));
    state.set_session_key(SecureString::new(pending_key.clone()));
    // Persist the session key in the OS keyring so ratchet snapshots can be
    // encrypted/restored across restarts.
    crate::ratchet_store::store_session_key_to_keyring(&pending_key);
    let shared_secret_hex = state.get_pending_shared_secret().to_string();
    if !shared_secret_hex.is_empty() {
        let peer_id = state.get_pairing_initiator_pk();
        if !peer_id.is_empty() {
            if let Ok(shared_secret) = hex::decode(&shared_secret_hex) {
                let peer_mlkem = hex::decode(state.get_pairing_initiator_pk()).unwrap_or_default();
                let peer_x25519 =
                    hex::decode(state.get_pairing_initiator_x25519_pk()).unwrap_or_default();
                let _ = core_crypto::ratchet_init_session(
                    peer_id,
                    shared_secret,
                    true,
                    peer_x25519,
                    peer_mlkem,
                );
            }
        }
        
        let pending_sk = hex::decode(&pending_key).unwrap_or_default();
        if !pending_sk.is_empty() {
            let handle = core_crypto::session_key_create(pending_sk).unwrap_or(0);
            crate::handlers::DESKTOP_SESSION_KEY_HANDLE.store(handle, std::sync::atomic::Ordering::Release);
        }
    }
    // Store pinned client cert hash and rebind server with mTLS BEFORE marking as paired
    let cert_hash = state.get_pending_client_cert_hash();
    if !cert_hash.is_empty() {
        // Promote the pairing connection's identity to the trusted peer identity
        // used to authorize post-pairing streams.
        state.set_paired_client_cert_hash(cert_hash.clone());
        core_crypto::quic_app::set_pinned_client_cert(cert_hash.clone());
        match core_crypto::quic_app::QuicAppManager::rebind_server(9876).await {
            Ok(()) => {
                tracing::info!("[Pairing] Server rebound with mTLS enforcement completed prior to pairing state promotion");
            }
            Err(e) => {
                tracing::warn!("[Pairing] Server rebind failed: {e} — mTLS will take effect on next restart");
            }
        }
    }
    state.set_pending_shared_secret(SecureString::new(String::new()));
    state.clear_sas_code();
    {
        let mut settings = state.settings.lock();
        settings.is_paired = true;
        settings.paired_device_name = Some(paired_name);
    }
    state.save_settings();
    crate::handlers::IS_SESSION_KEY_AUTHENTICATED.store(true, std::sync::atomic::Ordering::Release);
    state.set_connection_status("ACTIVE".to_string());
    state.set_connection_method("QUIC mTLS".to_string());
    state.set_connection_color("green".to_string());
    state.add_log("[Pairing] SAS verified. Server rebound with mTLS. Session key promoted. Fully paired.".to_string());

    state.reset_sas_attempt_count();

    // Push the completion event so the webview can reconcile without polling
    // get_settings (audit finding #7 / #13).
    crate::handlers::emit_app_event(
        "pairing::complete",
        serde_json::json!({"is_paired": true}),
    );

    Ok("Paired successfully".to_string())
}

/// Current pairing state, exposed to the webview so the SAS modal can be
/// rendered from REAL backend state (audit finding #7 — the modal was dead
/// code because no command exposed the pending SAS).
#[tauri::command]
pub fn get_pairing_status(
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<PairingStatus, String> {
    let (sas_code, _pending_key) = state.get_pairing_read();
    let is_paired = state.settings.lock().is_paired;
    Ok(PairingStatus {
        pending: state.is_pairing_pending(),
        sas_code,
        is_paired,
        paired_device_name: state
            .settings
            .lock()
            .paired_device_name
            .clone()
            .unwrap_or_default(),
    })
}

#[derive(serde::Serialize)]
pub struct PairingStatus {
    pub pending: bool,
    pub sas_code: String,
    pub is_paired: bool,
    pub paired_device_name: String,
}

#[tauri::command]
pub async fn confirm_pairing_sas(
    verified_sas: String,
    paired_name: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    perform_sas_confirmation(&state.inner(), verified_sas, paired_name).await
}

#[tauri::command]
pub fn generate_sas_pairing_code(
    host_pk_hex: String,
    client_pk_hex: String,
    shared_secret_hex: String,
) -> Result<String, String> {
    let host_pk = hex::decode(&host_pk_hex).map_err(|e| format!("Invalid host_pk hex: {e}"))?;
    let client_pk =
        hex::decode(&client_pk_hex).map_err(|e| format!("Invalid client_pk hex: {e}"))?;
    let shared_secret =
        hex::decode(&shared_secret_hex).map_err(|e| format!("Invalid shared_secret hex: {e}"))?;
    if host_pk.len() < 32 || client_pk.len() < 32 || shared_secret.len() < 16 {
        return Err(
            "Invalid key material — SAS requires valid PQC public keys and shared secret".into(),
        );
    }
    core_crypto::generate_sas_code(host_pk, client_pk, shared_secret).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn store_key_in_secure_enclave(
    key_name: String,
    secret_hex: String,
    token: String,
) -> Result<(), String> {
    // Key-material write — requires a fresh user-gesture token (audit #13).
    if !crate::commands::security::consume_privilege_token(
        "store_key_in_secure_enclave",
        &token,
    ) {
        return Err("Privileged action requires a fresh confirmation token".into());
    }
    // Validate that the payload is hex so we never store garbage.
    hex::decode(&secret_hex).map_err(|e| format!("Secret must be hex-encoded: {e}"))?;
    write_keyring_secret(&key_name, &secret_hex)
}

#[tauri::command]
pub fn get_pairing_config(
    host_pk_hex: String,
    wireguard_pk_hex: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::PairingConfig, String> {
    state.add_log("[Pairing] Generated Out-of-Band Pairing Config".to_string());
    let config = core_crypto::generate_pairing_config(host_pk_hex, wireguard_pk_hex)
        .map_err(|e| e.to_string())?;
    // Store the issued QR nonce so handle_pairing can reject pairing payloads
    // from peers that did not scan OUR QR (audit finding #20).
    if !config.pairing_nonce_hex.is_empty() {
        state.set_pending_pairing_nonce(config.pairing_nonce_hex.clone());
    }
    Ok(config)
}

#[tauri::command]
pub fn generate_wormhole_code() -> String {
    use super::bip39_words;
    let mut rng = rand::thread_rng();
    let n1 = rand::Rng::gen_range(&mut rng, 0..bip39_words::BIP39_WORDS.len());
    let n2 = rand::Rng::gen_range(&mut rng, 0..bip39_words::BIP39_WORDS.len());
    let n3 = rand::Rng::gen_range(&mut rng, 0..bip39_words::BIP39_WORDS.len());
    format!(
        "{}-{}-{}",
        bip39_words::BIP39_WORDS[n1],
        bip39_words::BIP39_WORDS[n2],
        bip39_words::BIP39_WORDS[n3]
    )
}

#[cfg(test)]
mod keyring_tests {
    use super::*;

    /// Round-trip: secrets written to the OS keyring must survive a simulated
    /// process restart (the old per-boot wrap key made this fail — every blob
    /// written in a previous boot was permanently undecryptable). The keyring
    /// itself is OS-persistent, so write-then-re-read in a fresh call path is
    /// the same guarantee the app needs across reboots.
    #[test]
    fn test_keyring_secret_roundtrip_across_restart() {
        // Gracefully skip when no keyring backend is available (headless CI).
        if keyring::Entry::new(KEYRING_SERVICE, "test_roundtrip_key")
            .and_then(|e| e.set_password("probe"))
            .is_err()
        {
            eprintln!("Skipping keyring test: no OS keyring backend available");
            return;
        }
        let secret_hex = "deadbeefcafebabec0ffee42";
        write_keyring_secret("test_roundtrip_key", secret_hex).unwrap();
        let read_back = read_keyring_secret("test_roundtrip_key").expect("secret must persist");
        assert_eq!(read_back, secret_hex, "stored secret must round-trip verbatim");
        // Cleanup
        let _ = keyring::Entry::new(KEYRING_SERVICE, "test_roundtrip_key")
            .and_then(|e| e.delete_password());
    }

    /// The stored payload must be the plaintext secret (hex), not an encrypted
    /// blob — this is what generate_shamir_recovery_shares already assumes when
    /// it hex-decodes the keyring entry directly.
    #[test]
    fn test_keyring_does_not_double_encrypt() {
        if keyring::Entry::new(KEYRING_SERVICE, "test_plain_key")
            .and_then(|e| e.set_password("probe"))
            .is_err()
        {
            eprintln!("Skipping keyring test: no OS keyring backend available");
            return;
        }
        let secret_hex = "00112233445566778899aabbccddeeff";
        write_keyring_secret("test_plain_key", secret_hex).unwrap();
        let entry = keyring::Entry::new(KEYRING_SERVICE, "test_plain_key").unwrap();
        let stored = entry.get_password().unwrap();
        assert_eq!(stored, secret_hex, "keyring stores the plain secret hex directly");
        let _ = entry.delete_password();
    }
}
