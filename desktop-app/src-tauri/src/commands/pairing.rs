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
#[allow(dead_code)] // keyring test helper / API surface
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
    // Audit KYP-2026-02 #6: persist the pairing keypair in the OS keyring so it
    // is NOT regenerated on every app mount (which rotated the identity the
    // phone pins and invalidated in-flight pairing QRs on restart).
    crate::ratchet_store::store_pairing_keypair_to_keyring(&pair);
    state.add_log(
        "[PQC] Generated Hybrid Keypair (X25519 + ML-KEM-768) — persisted in OS keyring"
            .to_string(),
    );
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

    // Atomically read both sas_code and pending_session_key in one critical section.
    // AUDIT #2 (follow-up): the pending session key is held in a `Zeroizing`
    // wrapper so the heap String (and the decoded byte vector below) is wiped on
    // drop — the legacy plain String/`Vec<u8>` materialization left session-key
    // bytes lingering in GC/heap memory during every SAS confirmation.
    let (stored_sas, pending_key) = state.get_pairing_read();
    let pending_key = zeroize::Zeroizing::new(pending_key);

    if stored_sas.is_empty() {
        return Err("No pending pairing SAS code found. Initiate pairing first.".into());
    }
    // AUDIT (LOW): constant-time SAS comparison — no early exit on a prefix
    // mismatch, so a future machine-authenticated SAS channel gains no timing
    // oracle. (The human-typed single-shot path is negligible, but this is
    // cheap and removes the class outright.)
    if !constant_time_str_eq(&stored_sas, &verified_sas) {
        return Err("SAS code mismatch. Pairing rejected.".into());
    }
    if pending_key.is_empty() {
        return Err("No pending session key. Initiate pairing first.".into());
    }

    state.set_pending_session_key(SecureString::new(String::new()));
    // `to_string()` on the Zeroizing<String> derefs to a plain String clone
    // which is immediately re-wrapped in a (drop-zeroizing) SecureString — the
    // original Zeroizing buffer is wiped when it drops.
    state.set_session_key(SecureString::new(pending_key.to_string()));
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
                // Audit finding #1: the ratchet's initial DH identity must be OUR
                // OWN pairing keypair (the public halves the phone encapsulated
                // to). The private halves stay in Rust — never cross to the
                // renderer. Using a fresh ratchet keypair here would guarantee a
                // permanent desync at the first rekey boundary (seq 100).
                //
                // Audit KYP-2026-02 #2 (CRITICAL): a RE-PAIR must never silently
                // keep the OLD ratchet session. `ratchet_init_session_with_keypair`
                // rejects when a session already exists for this peer; the old
                // code discarded that error with `let _ =`, leaving the stale
                // session (old master secret, old keypair) live while the phone
                // installed a fresh one — a guaranteed permanent desync that
                // presents as "paired but nothing syncs". Mirror the Android
                // flow: remove the existing session FIRST, then init, and
                // PROPAGATE any error instead of swallowing it. There is no
                // legacy fresh-keypair fallback: init without OUR pairing
                // keypair would permanently desync at the first rekey boundary,
                // so pairing fails loudly instead (audit KYP-2026-02 #18).
                let mut our_pair = state.get_keypair().ok_or_else(|| {
                    "No local pairing keypair registered — cannot initialize the ratchet session. \
                     Generate a pairing keypair first, then re-pair."
                        .to_string()
                })?;
                // Remove any pre-existing session for this peer so the fresh
                // pairing key material is installed atomically. The Rust-INTERNAL
                // impl is called directly (not the raw-secrets UniFFI export,
                // which is cfg(test)-gated — audit KYP-2026-02 #25): this is a
                // same-process crate call, never an FFI boundary, so no secret
                // bytes are marshalled.
                core_crypto::ratchet_remove_session(peer_id.clone());
                core_crypto::ratchet_ffi::ratchet_init_session_with_keypair_impl(
                    &peer_id,
                    &shared_secret,
                    true,
                    Some((
                        our_pair.x25519_pk.clone(),
                        zeroize::Zeroizing::new(our_pair.x25519_sk.clone()),
                        our_pair.mlkem_pk.clone(),
                        zeroize::Zeroizing::new(our_pair.mlkem_sk.clone()),
                    )),
                    if peer_x25519.is_empty() {
                        None
                    } else {
                        Some(peer_x25519.as_slice())
                    },
                    if peer_mlkem.is_empty() {
                        None
                    } else {
                        Some(peer_mlkem.as_slice())
                    },
                )
                .map_err(|e| {
                    format!(
                        "Failed to initialize ratchet session for peer {peer_id}: {e} — re-pair required"
                    )
                })?;
                // AUDIT P1-2 (MEDIUM, one-sided epoch bump): the Android flow
                // explicitly bumps the fresh session to epoch 1 so a stale
                // pre-re-pair snapshot (epoch 0, large counters) is
                // distinguished from the fresh session at restore. The desktop
                // left the fresh session at epoch 0, so its restore guard
                // (`is_rollback`) refused the new epoch-0/0/0/0 snapshot
                // against the old high-water (epoch 0, gen≥1, send≥1, recv≥1)
                // whenever the old watermark survived the unpair — silent
                // session loss after a restart following a re-pair. Bump the
                // epoch HERE, immediately after the fresh init and before the
                // first persist, mirroring the phone exactly. The epoch-aware
                // dirty-gate in the poll handler then persists the fresh
                // (epoch 1) snapshot + watermark on the next poll.
                if let Some(new_epoch) = core_crypto::ratchet_bump_pairing_epoch(peer_id.clone()) {
                    tracing::info!(
                        "[Pairing] Fresh ratchet session for {peer_id} bumped to pairing epoch {new_epoch} (audit P1-2)"
                    );
                }
                // Audit F14: the `get_keypair()` clone (and the transient secret
                // halves it carried) must not linger in freed heap — the
                // ratchet impl has copied what it needs into ZeroizeOnDrop
                // storage; wipe the clone now.
                use zeroize::Zeroize;
                our_pair.zeroize();
            }
        }

        // AUDIT #2 (follow-up): the decoded key bytes are also wrapped in
        // `Zeroizing` so they are wiped after `session_key_create` regardless of
        // whether it succeeds or errors.
        let pending_sk = zeroize::Zeroizing::new(hex::decode(&pending_key).unwrap_or_default());
        if !pending_sk.is_empty() {
            // Audit finding #13: `session_key_create` can fail (duplicate key
            // bytes, registry cap). `unwrap_or(0)` previously turned the failure
            // into a LIVE handle 0 — every later session_key_* call then failed
            // with "Invalid session key handle 0" and the session was silently
            // broken. Handle the error explicitly instead: abort the SAS
            // confirmation (the user can re-pair) rather than commit to a
            // session that cannot encrypt.
            let handle = match core_crypto::session_key_create(pending_sk.to_vec()) {
                Ok(h) if h != 0 => h,
                Ok(_) => {
                    return Err(
                        "Session key handle creation returned the reserved handle 0 — re-pair required"
                            .to_string(),
                    );
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to create session key handle: {e} — re-pair required"
                    ));
                }
            };
            // Audit finding #23: the master session key is used only at
            // restore/startup (long-idle) and must NEVER be silently evicted by
            // the LRU cap — pin it so per-poll churn cannot destroy it.
            core_crypto::session_key_pin(handle);
            crate::handlers::DESKTOP_SESSION_KEY_HANDLE
                .store(handle, std::sync::atomic::Ordering::Release);
        }
    }
    // Store pinned client cert hash and rebind server with mTLS BEFORE marking as paired
    let cert_hash = state.get_pending_client_cert_hash();
    if !cert_hash.is_empty() {
        // Promote the pairing connection's identity to the trusted peer identity
        // used to authorize post-pairing streams.
        state.set_paired_client_cert_hash(cert_hash.clone());
        // AUDIT F12: register the per-peer cert→ratchet-id mapping so this
        // device's poll/clipboard/SMS/media streams route to ITS session, not
        // the global pairing id (which a SECOND paired device would otherwise
        // corrupt).
        let peer_id = state.get_pairing_initiator_pk();
        if !peer_id.is_empty() {
            state.register_peer_cert_mapping(&peer_id, &cert_hash);
        }
        // AUDIT F1 FIX: persist the pairing identity NOW so a desktop restart
        // can rebuild the mTLS allowlist + peer routing map (public data only:
        // cert hashes + peer public keys). Without this, the allowlist and map
        // were process-global/in-memory and every restart severed the data
        // plane while `is_paired` stayed true.
        state.persist_pairing_identity();
        core_crypto::quic_app::set_pinned_client_cert(cert_hash.clone());
        // AUDIT FINDING #4 (multi-device): registering the per-peer mapping
        // must ALSO extend the TLS-layer allowlist so a SECOND paired device's
        // certificate passes the TLS handshake (the single-pin verifier would
        // otherwise reject it before the stream layer ever ran). Both layers
        // now enforce the same set.
        core_crypto::quic_app::register_allowed_client_cert(cert_hash.clone());
        match core_crypto::quic_app::QuicAppManager::rebind_server(9876).await {
            Ok(()) => {
                tracing::info!("[Pairing] Server rebound with mTLS enforcement completed prior to pairing state promotion");
            }
            Err(e) => {
                tracing::warn!(
                    "[Pairing] Server rebind failed: {e} — mTLS will take effect on next restart"
                );
            }
        }
    }
    // Transition: SasPending → Confirmed (audit finding #24 — the single
    // confirmation transition clears the pending handshake fields).
    state.confirm_pairing();
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
    state.add_log(
        "[Pairing] SAS verified. Server rebound with mTLS. Session key promoted. Fully paired."
            .to_string(),
    );

    state.reset_sas_attempt_count();

    // Push the completion event so the webview can reconcile without polling
    // get_settings (audit finding #7 / #13).
    crate::handlers::emit_app_event("pairing::complete", serde_json::json!({"is_paired": true}));

    Ok("Paired successfully".to_string())
}

/// Constant-time string equality for the SAS comparison (audit LOW finding —
/// defensive; the SAS may one day be consumed by a machine channel where a
/// timing oracle matters). No early exit on a prefix mismatch: every byte is
/// folded into the accumulator, so the timing depends only on the (public,
/// fixed-length) SAS length, never on which byte differs.
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    // SAS codes are fixed-size (7 chars) and public — length is not secret.
    if a.len() != b.len() {
        return false;
    }
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut acc: u8 = 0;
    for i in 0..ab.len() {
        acc |= ab[i] ^ bb[i];
    }
    acc == 0
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
    perform_sas_confirmation(state.inner(), verified_sas, paired_name).await
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
    if !crate::commands::security::consume_privilege_token("store_key_in_secure_enclave", &token) {
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
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::PairingConfig, String> {
    // Audit KYP-2026-02 #6: the pairing config discloses host identity
    // metadata (local IP, WireGuard key hash) plus a fresh QR nonce — an
    // enumeration oracle. Gate it behind a fresh user-gesture token so a
    // renderer compromise cannot harvest it silently. (Wi-Fi Direct MAC / P2P
    // IP fields were removed with the P2P feature — audit finding #1.)
    if !crate::commands::security::consume_privilege_token("get_pairing_config", &token) {
        return Err("Building a pairing QR requires a fresh user-gesture token".into());
    }
    state.add_log("[Pairing] Generated Out-of-Band Pairing Config".to_string());
    let mut config = core_crypto::generate_pairing_config(host_pk_hex, wireguard_pk_hex)
        .map_err(|e| e.to_string())?;
    // Audit finding #20: the QR nonce gate is MANDATORY and the nonce is issued
    // by the backend (at app start AND refreshed here on every QR build) — the
    // phone must echo THIS nonce in its pairing payload. Overriding the
    // config's internally-generated nonce with the app-issued one keeps the QR
    // and the server-side gate in lockstep (a stale internally-generated nonce
    // would otherwise desync the check).
    let nonce = state.issue_fresh_pairing_nonce();
    config.pairing_nonce_hex = nonce;
    Ok(config)
}

/// Return the pending QR pairing nonce (issued by `get_pairing_config`). The
/// renderer MUST embed this nonce in every pairing QR payload so the phone can
/// echo it back; without it the server-side nonce check rejects every pairing
/// request (audit finding #5 — QR-nonce contract drift). Returns an empty
/// string when no nonce is pending (keypair not generated / already consumed).
#[tauri::command]
pub fn get_pairing_nonce(
    token: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    // Audit KYP-2026-02 #6: the QR nonce defeats the pairing-slot hijack gate;
    // disclosing it to an unauthenticated renderer would defeat its purpose.
    // Require a fresh user-gesture token.
    if !crate::commands::security::consume_privilege_token("get_pairing_nonce", &token) {
        return Err("Reading the pairing nonce requires a fresh user-gesture token".into());
    }
    Ok(state.get_pending_pairing_nonce())
}

/// SHA-256 (hex) of the desktop server's identity certificate. Embedded in the
/// pairing QR so the phone pins the certificate bound to the QR — never the
/// certificate observed on a possibly MITM'd bootstrap connection (audit
/// finding #15).
#[tauri::command]
pub fn get_server_cert_hash() -> Result<String, String> {
    Ok(core_crypto::quic_server_cert_hash().unwrap_or_default())
}

#[cfg(test)]
mod keyring_tests {
    use super::*;

    /// Probe the keyring backend with a hard timeout so a STUCK Secret Service
    /// daemon (hung D-Bus call) cannot hang the whole test binary after the
    /// assertions pass. Returns None when the backend is unavailable OR does
    /// not answer within the bound — both are treated as a graceful skip.
    fn keyring_available(name: &'static str) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let ok = keyring::Entry::new(KEYRING_SERVICE, name)
                .and_then(|e| e.set_password("probe"))
                .is_ok();
            let _ = tx.send(ok);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ok) => ok,
            Err(_) => {
                eprintln!("Skipping keyring test: keyring probe timed out (stuck backend)");
                false
            }
        }
    }

    /// Round-trip: secrets written to the OS keyring must survive a simulated
    /// process restart (the old per-boot wrap key made this fail — every blob
    /// written in a previous boot was permanently undecryptable). The keyring
    /// itself is OS-persistent, so write-then-re-read in a fresh call path is
    /// the same guarantee the app needs across reboots.
    #[test]
    fn test_keyring_secret_roundtrip_across_restart() {
        // Gracefully skip when no keyring backend is available (headless CI)
        // or a stuck daemon does not answer within the bound (audit follow-up).
        if !keyring_available("test_roundtrip_key") {
            eprintln!("Skipping keyring test: no OS keyring backend available");
            return;
        }
        let secret_hex = "deadbeefcafebabec0ffee42";
        write_keyring_secret("test_roundtrip_key", secret_hex).unwrap();
        let read_back = read_keyring_secret("test_roundtrip_key").expect("secret must persist");
        assert_eq!(
            read_back, secret_hex,
            "stored secret must round-trip verbatim"
        );
        // Cleanup
        let _ = keyring::Entry::new(KEYRING_SERVICE, "test_roundtrip_key")
            .and_then(|e| e.delete_password());
    }

    /// The stored payload must be the plaintext secret (hex), not an encrypted
    /// blob — this is what generate_shamir_recovery_shares already assumes when
    /// it hex-decodes the keyring entry directly.
    #[test]
    fn test_keyring_does_not_double_encrypt() {
        if !keyring_available("test_plain_key") {
            eprintln!("Skipping keyring test: no OS keyring backend available");
            return;
        }
        let secret_hex = "00112233445566778899aabbccddeeff";
        write_keyring_secret("test_plain_key", secret_hex).unwrap();
        let entry = keyring::Entry::new(KEYRING_SERVICE, "test_plain_key").unwrap();
        let stored = entry.get_password().unwrap();
        assert_eq!(
            stored, secret_hex,
            "keyring stores the plain secret hex directly"
        );
        let _ = entry.delete_password();
    }
}
