use crate::error::KyberError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::sync::Mutex;
use tokio::net::UdpSocket;
use tracing::{info, warn};

use super::BEACON_MAGIC;
use super::P2P_BEACON_PORT;

/// AUDIT F15: per-receiver seen-nonce cache for discovery beacons. The ML-DSA
/// signature proves SELF-OWNERSHIP, not freshness: a captured signed beacon
/// can be replayed by any LAN host within the ±60 s timestamp window. The
/// declared-IP check prevents cross-IP replay, but a LAN attacker can simply
/// re-announce the SAME IP — the nonce cache is what closes that window.
/// Every beacon that passes signature verification records its
/// (signing_pk, nonce) pair for the beacon validity window; a duplicate within
/// that window is dropped. Bounded (pruned by TTL and capped), so a
/// discovery-phase flood of unique (pk, nonce) pairs cannot grow it
/// unboundedly.
/// (signing_pk, nonce) → first-seen time for the replay cache (AUDIT F15).
type SeenBeaconKey = (Vec<u8>, Vec<u8>);
static SEEN_BEACON_NONCES: LazyLock<Mutex<HashMap<SeenBeaconKey, std::time::Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Cap on retained (pk, nonce) pairs (AUDIT F15). Generous for real LAN
/// discovery churn while bounding memory.
const BEACON_NONCE_CACHE_MAX: usize = 1024;
/// How long a seen nonce is remembered — the beacon validity window.
const BEACON_NONCE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Returns true when `(pk, nonce)` was already accepted within the TTL
/// (a replay), and records it otherwise.
fn beacon_nonce_is_replay(pk: &[u8], nonce: &[u8]) -> bool {
    let mut map = SEEN_BEACON_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    map.retain(|_, at| now.duration_since(*at) < BEACON_NONCE_TTL);
    if map.len() >= BEACON_NONCE_CACHE_MAX {
        // Bounded: evict the oldest entry rather than growing.
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
    }
    let key = (pk.to_vec(), nonce.to_vec());
    match map.entry(key) {
        std::collections::hash_map::Entry::Occupied(_) => true,
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(now);
            false
        }
    }
}

/// Persist the beacon signing keypair to the OS keyring (service "kyberpipe",
/// hex-encoded). Returns true when both entries were written. The probe write
/// detects headless environments with no keyring backend (matching the keyring
/// round-trip tests in desktop-app); it lands on a key that is immediately
/// overwritten with the real material.
fn persist_beacon_signing_keypair(pk: &[u8], sk: &[u8]) -> bool {
    let pk_hex = hex::encode(pk);
    let sk_hex = hex::encode(sk);
    keyring::Entry::new("kyberpipe", "beacon_signing_sk")
        .and_then(|e| e.set_password("probe"))
        .is_ok()
        && keyring::Entry::new("kyberpipe", "beacon_signing_sk")
            .and_then(|e| e.set_password(&sk_hex))
            .is_ok()
        && keyring::Entry::new("kyberpipe", "beacon_signing_pk")
            .and_then(|e| e.set_password(&pk_hex))
            .is_ok()
}

/// Load (or lazily generate + persist) the device's ML-DSA-65 signing key used
/// to authenticate discovery beacons. Stored in the OS keyring under service
/// "kyberpipe" (keys "beacon_signing_sk"/"beacon_signing_pk"); only when no
/// keyring backend is available (headless CI) is the keypair persisted under
/// the app data dir with 0600 permissions — never weaker.
/// The two legacy plaintext beacon key files under the app data dir
/// (pre-keyring installs / headless fallback). Centralized so the migration
/// path and the teardown path (`remove_legacy_beacon_key_files`) can never
/// disagree about the on-disk location (AUDIT F16 follow-up).
fn beacon_key_files() -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    (
        dir.join("device_mldsa_pk.bin"),
        dir.join("device_mldsa_sk.bin"),
    )
}

/// Migrate a legacy plaintext beacon keypair into the OS keyring and — only
/// after the keyring write is VERIFIED durable by readback — delete the
/// plaintext files. Mirrors the server TLS key migration in `quic_app`: a
/// backend that accepts `set_password` but does not persist must NOT destroy
/// the only copy of the key (AUDIT F16 follow-up — the legacy files were
/// previously left on disk indefinitely after a successful migration).
fn migrate_and_remove_legacy_files(pk: &[u8], sk: &[u8]) {
    if !persist_beacon_signing_keypair(pk, sk) {
        return;
    }
    let sk_hex = hex::encode(sk);
    let durable = keyring::Entry::new("kyberpipe", "beacon_signing_sk")
        .and_then(|e| e.get_password())
        .is_ok_and(|v| v == sk_hex);
    if durable {
        let (pk_path, sk_path) = beacon_key_files();
        let _ = std::fs::remove_file(&pk_path);
        let _ = std::fs::remove_file(&sk_path);
        tracing::info!(
            "[Beacon] Legacy plaintext beacon key files removed after verified keyring migration (AUDIT F16)"
        );
    } else {
        tracing::warn!(
            "[Beacon] Keyring write did not verify durable; KEEPING legacy plaintext beacon key files (never destroy the only copy — AUDIT F16)"
        );
    }
}

/// Remove the legacy plaintext beacon key files (`device_mldsa_*.bin`).
/// Called by the desktop teardown (`ratchet_store::wipe_keyring_entries` →
/// unpair / delete_connection / panic self-destruct) so the plaintext ML-DSA
/// secret never survives an explicit wipe — the keyring entries alone were
/// deleted before, leaving the 0600 files behind (AUDIT F16 follow-up).
pub fn remove_legacy_beacon_key_files() {
    let (pk_path, sk_path) = beacon_key_files();
    let _ = std::fs::remove_file(&pk_path);
    let _ = std::fs::remove_file(&sk_path);
}

fn device_signing_key() -> (Vec<u8>, Vec<u8>) {
    // Preferred: OS keyring. Both entries must decode to the expected sizes.
    let sk_hex = keyring::Entry::new("kyberpipe", "beacon_signing_sk")
        .and_then(|e| e.get_password())
        .ok();
    let pk_hex = keyring::Entry::new("kyberpipe", "beacon_signing_pk")
        .and_then(|e| e.get_password())
        .ok();
    if let (Some(sk_hex), Some(pk_hex)) = (sk_hex, pk_hex) {
        if let (Ok(sk), Ok(pk)) = (hex::decode(&sk_hex), hex::decode(&pk_hex)) {
            if sk.len() == 4032 && pk.len() == 1952 {
                return (pk, sk);
            }
        }
    }

    // Fallback store: the legacy 0600 files under the app data dir, used only
    // when the OS keyring is unavailable (headless CI). If a keypair already
    // lives there (pre-keyring install), keep it — and migrate it into the
    // keyring when a backend is present so the device identity survives. The
    // plaintext files are removed once the keyring write is verified durable
    // (AUDIT F16 follow-up).
    let (pk_path, sk_path) = beacon_key_files();
    if let (Ok(pk), Ok(sk)) = (std::fs::read(&pk_path), std::fs::read(&sk_path)) {
        if pk.len() == 1952 && sk.len() == 4032 {
            migrate_and_remove_legacy_files(&pk, &sk);
            return (pk, sk);
        }
    }

    // Nothing usable anywhere: generate a fresh keypair, preferring the
    // keyring. AUDIT F16 (LOW): the legacy fallback WROTE the ML-DSA secret to
    // a plaintext 0600 file under the app data dir whenever the OS keyring was
    // unavailable — recoverable by any same-user process, one tier below the
    // rest of the key material. Now, when no keyring backend exists, the
    // keypair is kept IN MEMORY ONLY for this process (discovery works while
    // running) and is NEVER persisted in plaintext — the audit's "refuse to
    // persist" option. The device identity is ephemeral on keyring-less hosts,
    // and a paired phone will reject the desktop's beacons after a restart
    // until a keyring backend is available (headless CI only — real desktop
    // sessions have a keyring; the Android side uses Keystore). A pre-existing
    // legacy file is still READ and migrated into the keyring above (identity
    // continuity for pre-keyring installs), but no NEW plaintext secret is
    // ever written.
    let (pk, sk) = crate::crypto::generate_mldsa_keypair();
    if persist_beacon_signing_keypair(&pk, &sk) {
        return (pk, sk);
    }
    tracing::warn!(
        "[Beacon] No OS keyring backend — ML-DSA signing identity is EPHEMERAL for this process (AUDIT F16); the secret is not persisted in plaintext"
    );
    (pk, sk)
}

/// The device's ML-DSA-65 public key (hex), exported for peers to verify
/// signed discovery beacons.
pub fn device_signing_public_key_hex() -> String {
    hex::encode(device_signing_key().0)
}

/// Send UDP P2P discovery beacon with flexible payload format.
///
/// SECURITY NOTE: The beacon is signed with the device's ML-DSA-65 key and
/// carries a per-instance random nonce. The plaintext region (payload:timestamp:
/// nonce) is signature-bound so a peer that holds the device public key (e.g.
/// after pairing) can cryptographically reject forged beacons. The declared IP
/// is also checked against the source socket by receivers.
pub async fn send_p2p_beacon(
    payload_str: &str,
    target_addr: Option<SocketAddr>,
) -> Result<(), KyberError> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to bind UDP socket: {e}")))?;

    socket
        .set_broadcast(true)
        .map_err(|e| KyberError::NetworkError(format!("Failed to set broadcast: {e}")))?;

    // Include Unix timestamp for replay protection (seconds since epoch)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Per-instance nonce prevents replay of a captured beacon across instances.
    let mut nonce = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let nonce_hex = hex::encode(nonce);

    // The payload is a colon-delimited field set (`pk:ip[:...]`) produced by
    // trusted callers (sync_server emits `pk_hash:local_ip`). The payload is
    // SIGNED below, so a tampered or injected delimiter can never slip in
    // undetected — sanitization is neither needed nor safe (replacing ':' with
    // '_' corrupted the field structure and made every receiver unable to
    // parse the beacon).
    let signed_region = format!("{payload_str}:{timestamp}:{nonce_hex}");

    let (pk, sk) = device_signing_key();
    let sig = crate::crypto::sign_mldsa_payload(signed_region.as_bytes(), &sk).unwrap_or_default();
    let pk_hex = hex::encode(&pk);
    let sig_hex = hex::encode(&sig);

    let mut payload = Vec::from(BEACON_MAGIC);
    payload.extend_from_slice(b":");
    payload.extend_from_slice(signed_region.as_bytes());
    payload.extend_from_slice(b":");
    payload.extend_from_slice(pk_hex.as_bytes());
    payload.extend_from_slice(b":");
    payload.extend_from_slice(sig_hex.as_bytes());

    let dest =
        target_addr.unwrap_or_else(|| SocketAddr::from(([255, 255, 255, 255], P2P_BEACON_PORT)));
    socket
        .send_to(&payload, dest)
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to send beacon: {e}")))?;

    info!("P2P Beacon broadcasted to {}", dest);
    Ok(())
}

/// Listen for UDP P2P discovery beacons and return parsed host info.
pub async fn listen_for_beacons(
    bind_port: u16,
    timeout_secs: u64,
) -> Result<Vec<(String, String, String)>, KyberError> {
    listen_for_beacons_with_expected_key(bind_port, timeout_secs, None).await
}

/// Like `listen_for_beacons`, but when `expected_signing_pk_hex` is provided
/// (a device key learned during pairing), beacons whose ML-DSA signature does
/// not verify against that key are dropped. The signed region is
/// `pk:ip:name:timestamp:nonce`.
/// Parse and validate a UDP discovery beacon payload (the portion after
/// `BEACON_MAGIC:`). Returns the discovered host's `(pk_hash, ip, display-name)`
/// or None when the beacon is malformed, stale (older than 60 s), spoofed
/// (declared IP != source socket), or fails ML-DSA signature verification.
///
/// Wire format (signed, REQUIRED):
///   - `pk:ip:ts:nonce:signing_pk:sig`
///
/// Legacy unsigned `pk:ip` beacons are no longer accepted (audit finding F13).
/// The device name is deliberately NOT part of the format — the unauthenticated
/// discovery channel must not disclose identity; receivers show a neutral name.
fn parse_beacon_payload(
    payload: &str,
    source_ip: &std::net::IpAddr,
    expected_signing_pk: Option<&[u8]>,
) -> Option<(String, String, String)> {
    let parts: Vec<&str> = payload.splitn(7, ':').collect();
    if parts.len() < 6 {
        // Signed format is REQUIRED — legacy unsigned `pk:ip` beacons are
        // rejected unconditionally (audit finding F13).
        return None;
    }
    // Signed format: pk:ip:ts:nonce:signing_pk:sig
    let host_pk = parts[0].to_string();
    let local_ip = parts[1].to_string();
    let ts_str = parts[2];
    let nonce_hex = parts[3];
    let signing_pk_hex = parts[4];
    let sig_hex = parts[5];
    // Timestamp replay protection (beacon max age: 60s).
    if let Ok(ts) = ts_str.parse::<u64>() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(ts) > 60 {
            warn!(
                "Stale beacon from {} ({}s old) — discarding",
                source_ip,
                now.saturating_sub(ts)
            );
            return None;
        }
    }
    // Anti-spoofing: declared IP must equal the source socket address
    // (mirrors the Android MdnsBeaconListener check).
    if local_ip != source_ip.to_string() {
        warn!(
            "Beacon IP mismatch: declared={} source={} — dropping",
            local_ip, source_ip
        );
        return None;
    }
    // The signed region is the four fields BEFORE the embedded signing key
    // — reconstruct exactly what the sender signed (audit finding: the
    // sender must NOT colon-sanitize, or the reconstruction drifts).
    let signed_region = format!("{host_pk}:{local_ip}:{ts_str}:{nonce_hex}");
    let sig_ok = match (hex::decode(sig_hex), hex::decode(signing_pk_hex)) {
        (Ok(sig), Ok(pk)) => {
            crate::crypto::verify_mldsa_signature(signed_region.as_bytes(), &sig, &pk)
        }
        _ => false,
    };
    if !sig_ok {
        warn!(
            "Beacon signature verification failed for {} — dropping",
            source_ip
        );
        return None;
    }
    // When a trusted device key is known (learned during pairing), the
    // embedded signing key must MATCH it; an impostor key is dropped.
    if let Some(expected) = expected_signing_pk {
        if expected != hex::decode(signing_pk_hex).unwrap_or_default().as_slice() {
            warn!("Beacon signing key does not match the paired device key — dropping");
            return None;
        }
    } else {
        // Discovery phase: the self-consistent signature is accepted; the
        // signing key is adopted during pairing.
        info!(
            "Beacon from {} (discovery): sign_pk={}",
            source_ip,
            &signing_pk_hex[..16.min(signing_pk_hex.len())]
        );
    }
    // AUDIT F15: a replay within the ±60 s timestamp window (same signing key,
    // same nonce, re-announced from the same IP) must be dropped — the
    // signature authenticates the SENDER's key, not the freshness of the
    // packet. Runs only after signature verification + the expected-key check,
    // so an unauthenticated flood cannot populate the cache.
    if let (Ok(signing_pk), Ok(nonce)) = (hex::decode(signing_pk_hex), hex::decode(nonce_hex)) {
        if beacon_nonce_is_replay(&signing_pk, &nonce) {
            warn!(
                "Replayed beacon (pk+nonce already seen) from {} — dropping",
                source_ip
            );
            return None;
        }
    }
    Some((host_pk, local_ip, "Desktop".to_string()))
}

pub async fn listen_for_beacons_with_expected_key(
    bind_port: u16,
    timeout_secs: u64,
    expected_signing_pk_hex: Option<String>,
) -> Result<Vec<(String, String, String)>, KyberError> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{bind_port}"))
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to bind beacon listener: {e}")))?;

    socket
        .set_broadcast(true)
        .map_err(|e| KyberError::NetworkError(format!("Failed to set broadcast: {e}")))?;

    let expected_pk = expected_signing_pk_hex
        .as_ref()
        .and_then(|h| hex::decode(h).ok());

    let mut results = Vec::new();
    let start = std::time::Instant::now();

    while start.elapsed().as_secs() < timeout_secs {
        let mut buf = [0u8; 2048];
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((len, addr))) => {
                let raw = &buf[..len];
                if raw.starts_with(BEACON_MAGIC) {
                    let payload = &raw[BEACON_MAGIC.len() + 1..];
                    if let Ok(s) = String::from_utf8(payload.to_vec()) {
                        if let Some((host_pk, local_ip, display_name)) =
                            parse_beacon_payload(&s, &addr.ip(), expected_pk.as_deref())
                        {
                            info!(
                                "Beacon received from {}: host={} ip={}",
                                addr,
                                &host_pk[..16.min(host_pk.len())],
                                local_ip
                            );
                            results.push((host_pk, local_ip, display_name));
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                // Transient socket error — keep scanning for the full window.
                warn!("Beacon receive error: {e}");
            }
            Err(_) => {
                // Per-iteration 2s quiet timeout — NOT fatal. The scan must
                // continue until the overall `timeout_secs` window elapses,
                // otherwise listeners exit after the first 2s of silence.
                continue;
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Build a signed beacon payload exactly as `send_p2p_beacon` does
    /// (colon-delimited, NO sanitization). Returns the payload and the signing
    /// keypair so a test can exercise tampering / key-mismatch paths. Each
    /// call uses a FRESH random nonce so two payloads never collide in the
    /// AUDIT F15 seen-nonce cache.
    fn build_signed(payload: &str) -> (String, Vec<u8>, Vec<u8>) {
        let (pk, sk) = crate::crypto::generate_mldsa_keypair();
        let nonce: [u8; 8] = rand::random();
        build_signed_with(payload, &pk, &sk, &nonce)
    }

    fn build_signed_with(
        payload: &str,
        pk: &[u8],
        sk: &[u8],
        nonce: &[u8; 8],
    ) -> (String, Vec<u8>, Vec<u8>) {
        let ts = now_secs();
        let nonce_hex = hex::encode(nonce);
        let signed_region = format!("{payload}:{ts}:{nonce_hex}");
        let sig = crate::crypto::sign_mldsa_payload(signed_region.as_bytes(), sk).unwrap();
        (
            format!(
                "{payload}:{ts}:{nonce_hex}:{}:{}",
                hex::encode(pk),
                hex::encode(&sig)
            ),
            pk.to_vec(),
            sk.to_vec(),
        )
    }

    #[test]
    fn signed_beacon_roundtrip_parses() {
        let src: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        // The payload is `pk_hash:local_ip` — no device name (identity-minimal).
        let (payload, pk, sk) = build_signed("aabbccddeeff0011:192.168.1.50");
        let parsed = parse_beacon_payload(&payload, &src, None).expect("valid beacon");
        assert_eq!(
            parsed,
            (
                "aabbccddeeff0011".to_string(),
                "192.168.1.50".to_string(),
                "Desktop".to_string()
            )
        );
        // The SAME keypair signing a DIFFERENT nonce also parses against the
        // known trusted key (a fresh payload — the AUDIT F15 cache must not
        // reject a legitimate new beacon from the same device).
        let (payload2, _, _) =
            build_signed_with("aabbccddeeff0011:192.168.1.50", &pk, &sk, &[0x22u8; 8]);
        assert!(parse_beacon_payload(&payload2, &src, Some(&pk)).is_some());
    }

    /// AUDIT F15: re-announcing an ALREADY-ACCEPTED signed beacon (same
    /// signing key, same nonce) within the validity window must be dropped —
    /// a LAN attacker that captured a legitimate beacon cannot replay it to
    /// keep a stale/stolen candidate address alive.
    #[test]
    fn signed_beacon_replay_is_dropped() {
        let src: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        let (payload, pk, sk) = build_signed("aabb:192.168.1.50");
        // First delivery is accepted.
        assert!(
            parse_beacon_payload(&payload, &src, Some(&pk)).is_some(),
            "first beacon delivery accepted"
        );
        // An exact replay (same keypair, same nonce, same IP) is dropped.
        assert!(
            parse_beacon_payload(&payload, &src, Some(&pk)).is_none(),
            "replayed beacon must be dropped (AUDIT F15)"
        );
        // A FRESH nonce from the same device is still accepted.
        let (fresh, _, _) = build_signed_with("aabb:192.168.1.50", &pk, &sk, &[0x33u8; 8]);
        assert!(
            parse_beacon_payload(&fresh, &src, Some(&pk)).is_some(),
            "a fresh nonce from the same device must still be accepted"
        );
    }

    #[test]
    fn signed_beacon_rejects_forgery_and_spoofing() {
        let src: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        let (mut payload, _pk, _sk) = build_signed("aabb:192.168.1.50");
        // Tamper one byte of the signature — signature verification must fail.
        let sig_start = payload.rfind(':').unwrap();
        let tampered = payload.clone();
        payload = format!(
            "{}:{}",
            &tampered[..sig_start + 1],
            if tampered.as_bytes()[tampered.len() - 1] == b'0' {
                "1"
            } else {
                "0"
            }
        );
        assert!(
            parse_beacon_payload(&payload, &src, None).is_none(),
            "tampered sig must be rejected"
        );
        // Declared IP that does not match the source socket is spoofed.
        let (payload2, _, _) = build_signed("aabb:10.0.0.99");
        let other: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        assert!(
            parse_beacon_payload(&payload2, &other, None).is_none(),
            "IP mismatch must be rejected"
        );
        // A beacon signed by an UNKNOWN key is rejected when a trusted key is expected.
        let (payload3, _, _) = build_signed("aabb:192.168.1.50");
        let (trusted_pk, _) = crate::crypto::generate_mldsa_keypair();
        assert!(
            parse_beacon_payload(&payload3, &src, Some(&trusted_pk)).is_none(),
            "impostor signing key must be rejected"
        );
    }

    #[test]
    fn stale_and_legacy_beacons() {
        let src: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        // Stale timestamp (> 60 s) is rejected.
        let stale = format!(
            "aabb:192.168.1.50:{}:deadbeef:{}:{}",
            now_secs() - 120,
            "00",
            "00"
        );
        assert!(
            parse_beacon_payload(&stale, &src, None).is_none(),
            "stale beacon must be rejected"
        );
        // Legacy unsigned `pk:ip` is now REJECTED (signed format required).
        assert!(
            parse_beacon_payload("aabb:192.168.1.50", &src, None).is_none(),
            "legacy unsigned beacon must be rejected"
        );
        // Malformed / truncated payloads are rejected.
        assert!(parse_beacon_payload("", &src, None).is_none());
        assert!(parse_beacon_payload("onlyone", &src, None).is_none());
    }
}
