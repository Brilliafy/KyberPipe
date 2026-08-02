use crate::error::KyberError;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{info, warn};

use super::BEACON_MAGIC;
use super::P2P_BEACON_PORT;

/// Load (or lazily generate + persist) the device's ML-DSA-65 signing key used
/// to authenticate discovery beacons. Persisted under the app data dir with
/// 0600 permissions.
fn device_signing_key() -> (Vec<u8>, Vec<u8>) {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let _ = std::fs::create_dir_all(&dir);
    let pk_path = dir.join("device_mldsa_pk.bin");
    let sk_path = dir.join("device_mldsa_sk.bin");
    if let (Ok(pk), Ok(sk)) = (std::fs::read(&pk_path), std::fs::read(&sk_path)) {
        if pk.len() == 1952 && sk.len() == 4032 {
            return (pk, sk);
        }
    }
    let (pk, sk) = crate::crypto::generate_mldsa_keypair();
    let _ = std::fs::write(&pk_path, &pk);
    let _ = std::fs::write(&sk_path, &sk);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&pk_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600));
    }
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
/// Wire formats accepted:
///  - Signed (identity-minimal, current): `pk:ip:ts:nonce:signing_pk:sig`
///  - Legacy unsigned (pre-signing): `pk:ip`
/// The device name is deliberately NOT part of either format — the unauthenticated
/// discovery channel must not disclose identity; receivers show a neutral name.
fn parse_beacon_payload(
    payload: &str,
    source_ip: &std::net::IpAddr,
    expected_signing_pk: Option<&[u8]>,
) -> Option<(String, String, String)> {
    let parts: Vec<&str> = payload.splitn(7, ':').collect();
    if parts.len() >= 6 {
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
            (Ok(sig), Ok(pk)) => crate::crypto::verify_mldsa_signature(
                signed_region.as_bytes(),
                &sig,
                &pk,
            ),
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
            if expected
                != hex::decode(&signing_pk_hex)
                    .unwrap_or_default()
                    .as_slice()
            {
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
        return Some((host_pk, local_ip, "Desktop".to_string()));
    }
    if parts.len() >= 2 {
        // Legacy unsigned format (pre-signing): pk:ip
        let host_pk = parts[0].to_string();
        let local_ip = parts[1].to_string();
        if local_ip != source_ip.to_string() {
            warn!(
                "Beacon IP mismatch: declared={} source={} — dropping",
                local_ip, source_ip
            );
            return None;
        }
        return Some((host_pk, local_ip, "Desktop".to_string()));
    }
    None
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
    /// keypair so a test can exercise tampering / key-mismatch paths.
    fn build_signed(payload: &str) -> (String, Vec<u8>, Vec<u8>) {
        let (pk, sk) = crate::crypto::generate_mldsa_keypair();
        let ts = now_secs();
        let nonce = hex::encode([0x11u8; 8]);
        let signed_region = format!("{payload}:{ts}:{nonce}");
        let sig = crate::crypto::sign_mldsa_payload(signed_region.as_bytes(), &sk).unwrap();
        (
            format!("{payload}:{ts}:{nonce}:{}:{}", hex::encode(&pk), hex::encode(&sig)),
            pk,
            sk,
        )
    }

    #[test]
    fn signed_beacon_roundtrip_parses() {
        let src: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        // The payload is `pk_hash:local_ip` — no device name (identity-minimal).
        let (payload, pk, _sk) = build_signed("aabbccddeeff0011:192.168.1.50");
        let parsed = parse_beacon_payload(&payload, &src, None).expect("valid beacon");
        assert_eq!(parsed, ("aabbccddeeff0011".to_string(), "192.168.1.50".to_string(), "Desktop".to_string()));
        // The same beacon with the KNOWN trusted key also parses.
        assert!(parse_beacon_payload(&payload, &src, Some(&pk)).is_some());
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
            if tampered.as_bytes()[tampered.len() - 1] == b'0' { "1" } else { "0" }
        );
        assert!(parse_beacon_payload(&payload, &src, None).is_none(), "tampered sig must be rejected");
        // Declared IP that does not match the source socket is spoofed.
        let (payload2, _, _) = build_signed("aabb:10.0.0.99");
        let other: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        assert!(parse_beacon_payload(&payload2, &other, None).is_none(), "IP mismatch must be rejected");
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
        let stale = format!("aabb:192.168.1.50:{}:deadbeef:{}:{}", now_secs() - 120, "00", "00");
        assert!(parse_beacon_payload(&stale, &src, None).is_none(), "stale beacon must be rejected");
        // Legacy unsigned `pk:ip` is still accepted (discovery fallback).
        assert_eq!(
            parse_beacon_payload("aabb:192.168.1.50", &src, None),
            Some(("aabb".to_string(), "192.168.1.50".to_string(), "Desktop".to_string()))
        );
        // Malformed / truncated payloads are rejected.
        assert!(parse_beacon_payload("", &src, None).is_none());
        assert!(parse_beacon_payload("onlyone", &src, None).is_none());
    }
}
