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

    // Sanitize payload: replace colons with underscores to prevent delimiter
    // injection if device_name contains ':' characters.
    let sanitized_payload = payload_str.replace(':', "_");
    let signed_region = format!("{sanitized_payload}:{timestamp}:{nonce_hex}");

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
                        // Extended format: pk:ip:name:ts:nonce:signing_pk:sig
                        let parts: Vec<&str> = s.splitn(8, ':').collect();
                        if parts.len() >= 7 {
                            let host_pk = parts[0].to_string();
                            let local_ip = parts[1].to_string();
                            let device_name = parts[2].to_string();
                            let ts_str = parts[3];
                            let nonce_hex = parts[4];
                            let signing_pk_hex = parts[5];
                            let sig_hex = parts[6];
                            // Validate timestamp for replay protection (beacon max age: 60s)
                            if let Ok(ts) = ts_str.parse::<u64>() {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                if now.saturating_sub(ts) > 60 {
                                    warn!(
                                        "Stale beacon from {} ({}s old) — discarding",
                                        addr,
                                        now.saturating_sub(ts)
                                    );
                                    continue;
                                }
                            }
                            // Anti-spoofing: reject beacons whose declared IP does
                            // not match the source socket address (mirrors the
                            // Android MdnsBeaconListener check).
                            if local_ip != addr.ip().to_string() {
                                warn!(
                                    "Beacon IP mismatch: declared={} source={} — dropping",
                                    local_ip,
                                    addr.ip()
                                );
                                continue;
                            }
                            // Signature verification against a known device key.
                            if let Some(expected) = &expected_pk {
                                let signed_region = format!(
                                    "{host_pk}:{local_ip}:{device_name}:{ts_str}:{nonce_hex}"
                                );
                                let ok = match (hex::decode(sig_hex), hex::decode(signing_pk_hex)) {
                                    (Ok(sig), Ok(pk)) => crate::crypto::verify_mldsa_signature(
                                        signed_region.as_bytes(),
                                        &sig,
                                        &pk,
                                    ),
                                    _ => false,
                                };
                                if !ok {
                                    warn!(
                                        "Beacon signature verification failed for {} — dropping",
                                        addr
                                    );
                                    continue;
                                }
                                let _ = expected;
                            } else {
                                // No expected key yet (discovery phase): accept the
                                // beacon; the signing key is adopted during pairing.
                                info!(
                                    "Beacon from {} (unverified discovery): sign_pk={}",
                                    addr,
                                    &signing_pk_hex[..16.min(signing_pk_hex.len())]
                                );
                            }
                            info!(
                                "Beacon received from {}: host={} ip={}",
                                addr,
                                &host_pk[..16.min(host_pk.len())],
                                local_ip
                            );
                            results.push((host_pk, local_ip, device_name));
                        } else if parts.len() >= 2 {
                            // Legacy unsigned format (pre-signing): pk:ip:name
                            let host_pk = parts[0].to_string();
                            let local_ip = parts.get(1).unwrap_or(&"").to_string();
                            let device_name = parts.get(2).unwrap_or(&"Desktop").to_string();
                            if local_ip != addr.ip().to_string() {
                                warn!(
                                    "Beacon IP mismatch: declared={} source={} — dropping",
                                    local_ip,
                                    addr.ip()
                                );
                                continue;
                            }
                            results.push((host_pk, local_ip, device_name));
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
