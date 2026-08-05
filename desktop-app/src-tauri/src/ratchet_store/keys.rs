//! Keyring-backed secrets + wrap-key derivation (audit P5-1 split).
//!
//! The OS keyring is the at-rest home for the session key, the pairing
//! keypair, the independent snapshot-wrap key and the beacon/session
//! metadata. The AEAD wrap keys for the ratchet store, the notification
//! store and the settings media fields are each domain-separated derivations
//! of the independent snapshot key, so no two stores share a (key, purpose)
//! context.

const KEYRING_SESSION_KEY: &str = "session_key";
/// The pairing keypair (private halves) persisted across restarts (audit
/// KYP-2026-02 #6). Previously the keypair was regenerated on EVERY app mount,
/// rotating the identity the phone pins and invalidating any in-flight pairing
/// QR. The OS keyring is the at-rest store; the private halves live in Rust
/// state (never the renderer).
const KEYRING_PAIRING_KEYPAIR: &str = "pairing_keypair";
/// KEYRING-backed rollback watermark (audit F16 follow-up). The watermark is
/// stored in the OS keyring — a same-user attacker who can rewrite
/// `ratchet_sessions.json` (and its sibling watermark FILE) cannot rewrite the
/// keyring entry without OS credential-store approval. The file is kept as a
/// fallback for keyring-less environments; on restore the HIGHER of the two is
/// the effective high-water mark.
pub(crate) const KEYRING_RATCHET_WATERMARK: &str = "ratchet_watermark";
/// Independent snapshot-wrap key. Audit finding #15b: the ratchet snapshots
/// must NOT be wrapped with a key derived from the session key, because the
/// session key is stored in the same keyring — anyone who could read the
/// keyring could unwrap every snapshot. A separate random key makes the wrap
/// genuinely independent defense-in-depth.
const KEYRING_SNAPSHOT_KEY: &str = "snapshot_key";

/// The OS keyring is the persistent home of the session key (hex-encoded).
pub fn store_session_key_to_keyring(session_key_hex: &str) {
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_SESSION_KEY) {
        let _ = entry.set_password(session_key_hex);
    }
}

/// Load the session key from the OS keyring (hex-encoded), if present. Used on
/// startup (audit F11) to re-create the desktop session-key handle so
/// session-key material survives restarts — the handle is otherwise only set
/// during a live SAS confirmation.
pub fn session_key_from_keyring() -> Option<String> {
    keyring::Entry::new("kyberpipe", KEYRING_SESSION_KEY)
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|s| !s.is_empty())
}

/// Persist the pairing keypair (hex-encoded JSON) in the OS keyring so the
/// identity survives restarts (audit KYP-2026-02 #6). Called by the
/// `generate_keypair` command after generating/regenerating a keypair.
///
/// Audit KYP-2026-02 #7 follow-up: the transient hex encoding of the private
/// halves (and the serialized JSON that embeds them) is zeroized before the
/// buffers are dropped, so the at-rest keyring copy is the only survivor.
pub fn store_pairing_keypair_to_keyring(pair: &core_crypto::PqKeyPair) {
    use zeroize::Zeroize;
    let mut x25519_sk_hex = hex::encode(&pair.x25519_sk);
    let mut mlkem_sk_hex = hex::encode(&pair.mlkem_sk);
    let mut json = serde_json::json!({
        "x25519_pk": hex::encode(&pair.x25519_pk),
        "x25519_sk": &x25519_sk_hex,
        "mlkem_pk": hex::encode(&pair.mlkem_pk),
        "mlkem_sk": &mlkem_sk_hex,
    })
    .to_string();
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_PAIRING_KEYPAIR) {
        let _ = entry.set_password(&json);
    }
    // Zeroize the transient secret-bearing buffers (hex strings + the JSON
    // string that serialized them) before they are dropped.
    x25519_sk_hex.zeroize();
    mlkem_sk_hex.zeroize();
    unsafe {
        for b in json.as_bytes_mut() {
            *b = 0;
        }
    }
}

/// Load the persisted pairing keypair from the OS keyring, if present.
pub fn load_pairing_keypair_from_keyring() -> Option<core_crypto::PqKeyPair> {
    let stored = keyring::Entry::new("kyberpipe", KEYRING_PAIRING_KEYPAIR)
        .ok()?
        .get_password()
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&stored).ok()?;
    let pk = hex::decode(v.get("x25519_pk")?.as_str()?).ok()?;
    let sk = hex::decode(v.get("x25519_sk")?.as_str()?).ok()?;
    let mpk = hex::decode(v.get("mlkem_pk")?.as_str()?).ok()?;
    let msk = hex::decode(v.get("mlkem_sk")?.as_str()?).ok()?;
    if pk.is_empty() || sk.is_empty() || mpk.is_empty() || msk.is_empty() {
        return None;
    }
    Some(core_crypto::PqKeyPair {
        x25519_pk: pk,
        x25519_sk: sk,
        mlkem_pk: mpk,
        mlkem_sk: msk,
    })
}

/// Remove the persisted pairing keypair (unpair / self-destruct path).
pub fn clear_pairing_keypair_from_keyring() {
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_PAIRING_KEYPAIR) {
        let _ = entry.delete_password();
    }
}

/// Wipe EVERY OS-keyring entry KyberPipe owns (AUDIT F12). Enumerates the full
/// kyberpipe service set — master_identity_key, session_key, the independent
/// snapshot wrap key, the persisted pairing keypair, the beacon ML-DSA signing
/// keypair, the Tor onion key, the server TLS key and the ratchet watermark —
/// plus the kyberpipe-tofu service's trusted-server TLS pin.
///
/// SHARED by BOTH the unpair path and the panic self-destruct path so the two
/// can never disagree about what survives at rest once the pairing is gone.
/// The legacy unpair path left the master session key and the pairing keypair
/// in the OS keyring indefinitely after the user explicitly unpaired, and the
/// next app start re-imported them even though `is_paired=false` — an attacker
/// with a later filesystem/credential-store snapshot could decrypt historical
/// ratchet snapshots taken before the unpair.
///
/// RE-PAIR SAFETY: every entry here is RECREATED by the next pairing flow
/// (`generate_keypair` → pairing_keypair, SAS confirmation → session_key,
/// `snapshot_key_from_keyring` → snapshot_key; the beacon signing keys, Tor
/// onion key, server TLS key and the tofu pin are likewise regenerated on
/// demand), so wiping the full set after an explicit unpair cannot break a
/// future re-pair — it removes the stale pre-unpair key material that must not
/// survive at rest.
pub fn wipe_keyring_entries() {
    for key_name in [
        "master_identity_key",
        KEYRING_SESSION_KEY,
        KEYRING_SNAPSHOT_KEY,
        KEYRING_PAIRING_KEYPAIR,
        "beacon_signing_sk",
        "beacon_signing_pk",
        "tor_onion_key",
        "server_tls_key",
        KEYRING_RATCHET_WATERMARK,
    ] {
        if let Ok(entry) = keyring::Entry::new("kyberpipe", key_name) {
            let _ = entry.delete_password();
        }
    }
    if let Ok(entry) = keyring::Entry::new("kyberpipe-tofu", "server_cert_hash") {
        let _ = entry.delete_password();
    }
    // AUDIT F16 (follow-up): the legacy PLAINTEXT ML-DSA beacon key files
    // (device_mldsa_*.bin under the app data dir) must not survive an explicit
    // wipe either — deleting the keyring entries alone left the 0600 fallback
    // files behind. Removing them here covers unpair AND panic self-destruct
    // (both call this routine).
    core_crypto::network::beacon::remove_legacy_beacon_key_files();
    clear_pairing_keypair_from_keyring();
}

/// Ensure an independent snapshot-wrap key exists in the keyring (generated
/// once per install) and return it as hex.
pub fn snapshot_key_from_keyring() -> Option<String> {
    let existing = keyring::Entry::new("kyberpipe", KEYRING_SNAPSHOT_KEY)
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|s| !s.is_empty());
    if let Some(key) = existing {
        return Some(key);
    }
    // Generate a fresh 32-byte key on first use.
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    let hex_key = hex::encode(bytes);
    if let Ok(entry) = keyring::Entry::new("kyberpipe", KEYRING_SNAPSHOT_KEY) {
        let _ = entry.set_password(&hex_key);
    }
    Some(hex_key)
}

/// Derive the snapshot wrap key from the INDEPENDENT snapshot key bytes.
pub(crate) fn wrap_key(snapshot_key_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(snapshot_key_hex).ok()?;
    core_crypto::crypto::derive_session_key(
        &bytes,
        b"kyberpipe-ratchet-persist-salt",
        b"kyberpipe-ratchet-snapshot-v1",
    )
    .ok()
}

/// Domain-separated wrap-key context for the notification/SMS history store
/// (audit finding #21): the same independent snapshot key derives a DIFFERENT
/// key here than for ratchet snapshots, so the two stores never share a
/// (key, purpose) derivation context.
fn notif_wrap_key(snapshot_key_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(snapshot_key_hex).ok()?;
    core_crypto::crypto::derive_session_key(
        &bytes,
        b"kyberpipe-notif-persist-salt",
        b"kyberpipe-notif-store-v1",
    )
    .ok()
}

/// Domain-separated wrap-key context for settings media fields (audit P3-3):
/// the same independent snapshot key derives a DIFFERENT key than the ratchet
/// store and the notification store, so no two stores share a
/// (key, purpose) derivation context.
fn settings_media_wrap_key(snapshot_key_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(snapshot_key_hex).ok()?;
    core_crypto::crypto::derive_session_key(
        &bytes,
        b"kyberpipe-settings-media-salt",
        b"kyberpipe-settings-media-v1",
    )
    .ok()
}

/// Prefix marking a settings media field wrapped with the independent snapshot
/// key (audit P3-3). A plaintext legacy value (written by an older build) is
/// detected by the ABSENCE of this marker and re-wrapped on the next save.
pub const SETTINGS_MEDIA_WRAP_MARKER: &str = "kpenc:v1:";

/// AEAD-wrap a settings media field (avatar/identity image base64) with the
/// independent snapshot key (audit P3-3). Avatar/identity images may embed
/// EXIF/location metadata and previously sat plaintext in settings.json while
/// Android stored the same field in EncryptedSharedPreferences. Returns
/// "{marker}{nonce_hex}:{ciphertext_hex}", or None when no wrap key is
/// available (headless/keyring-less environments — the caller keeps the
/// legacy plaintext as the degraded fallback, matching the notification
/// store's behavior).
pub fn encrypt_settings_media_field(snapshot_key_hex: &str, value: &str) -> Option<String> {
    let wk = settings_media_wrap_key(snapshot_key_hex)?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let ct = core_crypto::crypto::encrypt_chacha20(&wk, &nonce, value.as_bytes(), &[]).ok()?;
    Some(format!(
        "{SETTINGS_MEDIA_WRAP_MARKER}{}:{}",
        hex::encode(nonce),
        hex::encode(ct)
    ))
}

/// Decrypt a settings media field written by [`encrypt_settings_media_field`].
/// Returns None when the value is NOT wrapped (legacy plaintext) or cannot be
/// decrypted.
pub fn decrypt_settings_media_field(snapshot_key_hex: &str, blob: &str) -> Option<String> {
    let rest = blob.strip_prefix(SETTINGS_MEDIA_WRAP_MARKER)?;
    let (nonce_hex, ct_hex) = rest.split_once(':')?;
    let (nonce, ct) = (hex::decode(nonce_hex).ok()?, hex::decode(ct_hex).ok()?);
    let nonce_arr = <[u8; 12]>::try_from(nonce.as_slice()).ok()?;
    let wk = settings_media_wrap_key(snapshot_key_hex)?;
    let pt = core_crypto::crypto::decrypt_chacha20(&wk, &nonce_arr, &ct, &[]).ok()?;
    String::from_utf8(pt).ok()
}

/// AEAD-wrap the notification/SMS history JSON with the independent snapshot
/// key (audit finding #21): forwarded Signal/WhatsApp content must not sit on
/// disk in plaintext. Returns "{nonce_hex}:{ciphertext_hex}".
pub fn encrypt_notifications_data(snapshot_key_hex: &str, data: &[u8]) -> Option<String> {
    let wk = notif_wrap_key(snapshot_key_hex)?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let ct = core_crypto::crypto::encrypt_chacha20(&wk, &nonce, data, &[]).ok()?;
    Some(format!("{}:{}", hex::encode(nonce), hex::encode(ct)))
}

/// Decrypt a notification history blob written by `encrypt_notifications_data`.
pub fn decrypt_notifications_data(snapshot_key_hex: &str, blob: &str) -> Option<Vec<u8>> {
    let (nonce_hex, ct_hex) = blob.split_once(':')?;
    let (nonce, ct) = (hex::decode(nonce_hex).ok()?, hex::decode(ct_hex).ok()?);
    let nonce_arr = <[u8; 12]>::try_from(nonce.as_slice()).ok()?;
    let wk = notif_wrap_key(snapshot_key_hex)?;
    core_crypto::crypto::decrypt_chacha20(&wk, &nonce_arr, &ct, &[]).ok()
}
