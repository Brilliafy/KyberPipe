pub mod crypto;
pub mod error;
pub mod network;
pub mod packets;
pub mod qr_scanner;
pub mod quic_app;
pub mod telemetry;

pub mod p2p_group;
pub mod quic_bridge;
pub mod ratchet_ffi;
pub mod system_net;

use error::KyberError;
use network::PathMigrationManager;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

uniffi::setup_scaffolding!();

/// Dedicated Tokio runtime for blocking/synchronous UniFFI bridge calls.
/// NEVER uses block_in_place — always dispatches to this isolated runtime
/// to prevent starvation of the primary network event loop.
static SYNC_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn get_sync_runtime() -> &'static tokio::runtime::Runtime {
    SYNC_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build sync Tokio runtime")
    })
}

/// Helper: block on a future using the dedicated SYNC_RUNTIME.
/// Never uses block_in_place or Handle::try_current to avoid starving
/// the primary network runtime on concurrent UniFFI calls.
fn block_on_sync<F: std::future::Future>(fut: F) -> F::Output {
    get_sync_runtime().block_on(fut)
}

#[derive(Clone, uniffi::Record, serde::Serialize)]
pub struct PqKeyPair {
    pub x25519_pk_hex: String,
    pub x25519_sk_hex: String,
    pub mlkem_pk_hex: String,
    pub mlkem_sk_hex: String,
}

#[derive(uniffi::Record)]
pub struct PqKeyPairRaw {
    pub x25519_pk: Vec<u8>,
    pub x25519_sk: Vec<u8>,
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PqKemResponse {
    pub ciphertext_hex: String,
    pub shared_secret_hex: String,
}

#[derive(uniffi::Record)]
pub struct EncryptedPayload {
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(uniffi::Record)]
pub struct PathChallengeResult {
    pub challenge_token: String,
    pub expected_response: String,
}

#[derive(uniffi::Record, serde::Serialize, serde::Deserialize, Clone)]
pub struct ConnectionInfo {
    pub active_tier: u32,
    pub active_path_description: String,
    pub latency_ms: f64,
    pub public_endpoint: String,
}

#[derive(uniffi::Record, serde::Serialize, serde::Deserialize, Clone)]
pub struct PairingConfig {
    pub host_identity_pk_hex: String,
    pub local_ip: String,
    pub wifi_direct_mac: String,
    pub p2p_ip: String,
    pub wireguard_pk_hex: String,
    pub stun_endpoint: String,
    pub pairing_nonce_hex: String,
}

#[uniffi::export]
pub fn initialize_pq_handshake() -> Result<(), KyberError> {
    let _pair = crypto::generate_hybrid_keypair();
    Ok(())
}

#[uniffi::export]
pub fn generate_pq_keypair() -> Result<PqKeyPair, KyberError> {
    let pair = crypto::generate_hybrid_keypair();
    Ok(PqKeyPair {
        x25519_pk_hex: hex::encode(pair.x25519_pk),
        x25519_sk_hex: hex::encode(pair.x25519_sk),
        mlkem_pk_hex: hex::encode(pair.mlkem_pk.clone()),
        mlkem_sk_hex: hex::encode(pair.mlkem_sk.clone()),
    })
}

#[uniffi::export]
pub fn generate_pq_keypair_raw() -> Result<PqKeyPairRaw, KyberError> {
    let pair = crypto::generate_hybrid_keypair();
    Ok(PqKeyPairRaw {
        x25519_pk: pair.x25519_pk.to_vec(),
        x25519_sk: pair.x25519_sk.to_vec(),
        mlkem_pk: pair.mlkem_pk.clone(),
        mlkem_sk: pair.mlkem_sk.clone(),
    })
}

#[uniffi::export]
pub fn encapsulate_pq_secret(
    peer_x25519_pk_hex: String,
    peer_mlkem_pk_hex: String,
) -> Result<PqKemResponse, KyberError> {
    let x25519_bytes = hex::decode(&peer_x25519_pk_hex).map_err(|e| {
        KyberError::EncapsulationFailed(format!("Invalid X25519 public key hex: {e}"))
    })?;
    if x25519_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: x25519_bytes.len() as u64,
        });
    }
    let mut x25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(&x25519_bytes);

    let mlkem_bytes = hex::decode(&peer_mlkem_pk_hex).map_err(|e| {
        KyberError::EncapsulationFailed(format!("Invalid ML-KEM public key hex: {e}"))
    })?;

    let res = crypto::encapsulate_hybrid(&x25519_arr, &mlkem_bytes)?;
    Ok(PqKemResponse {
        ciphertext_hex: hex::encode(&res.ciphertext_bytes),
        shared_secret_hex: hex::encode(&res.combined_shared_secret),
    })
}

#[uniffi::export]
pub fn decapsulate_pq_secret(
    ciphertext_hex: String,
    my_x25519_sk_hex: String,
    my_mlkem_sk_hex: String,
) -> Result<String, KyberError> {
    let ct_bytes = hex::decode(&ciphertext_hex)
        .map_err(|e| KyberError::DecapsulationFailed(format!("Invalid ciphertext hex: {e}")))?;

    let x25519_sk_bytes = hex::decode(&my_x25519_sk_hex).map_err(|e| {
        KyberError::DecapsulationFailed(format!("Invalid X25519 secret key hex: {e}"))
    })?;
    if x25519_sk_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: x25519_sk_bytes.len() as u64,
        });
    }
    let mut x25519_sk_arr = [0u8; 32];
    x25519_sk_arr.copy_from_slice(&x25519_sk_bytes);

    let mlkem_sk_bytes = hex::decode(&my_mlkem_sk_hex).map_err(|e| {
        KyberError::DecapsulationFailed(format!("Invalid ML-KEM secret key hex: {e}"))
    })?;

    let ss = crypto::decapsulate_hybrid(&ct_bytes, &x25519_sk_arr, &mlkem_sk_bytes)?;
    Ok(hex::encode(ss))
}

#[uniffi::export]
pub fn derive_session_key(
    shared_secret_hex: String,
    salt_hex: String,
) -> Result<String, KyberError> {
    let ss_bytes = hex::decode(&shared_secret_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid shared secret hex: {e}")))?;
    let salt_bytes = hex::decode(&salt_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid salt hex: {e}")))?;

    let derived = crypto::derive_session_key(&ss_bytes, &salt_bytes, b"kyberpipe-hybrid-session")?;
    Ok(hex::encode(derived))
}

static ENCRYPT_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[uniffi::export]
pub fn encrypt_payload_with_key(
    session_key_hex: String,
    data: String,
) -> Result<EncryptedPayload, KyberError> {
    let key_bytes = hex::decode(&session_key_hex)
        .map_err(|e| KyberError::EncryptionFailed(format!("Invalid key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len() as u64,
        });
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let seq = ENCRYPT_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce_bytes = crypto::generate_nonce_from_seq(seq);

    let ciphertext = crypto::encrypt_chacha20(&key_arr, &nonce_bytes, data.as_bytes(), &[])?;
    Ok(EncryptedPayload {
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

#[uniffi::export]
pub fn decrypt_payload_with_key(
    session_key_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
) -> Result<String, KyberError> {
    let key_bytes = hex::decode(&session_key_hex)
        .map_err(|e| KyberError::DecryptionFailed(format!("Invalid key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len() as u64,
        });
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let nonce_bytes = hex::decode(&nonce_hex)
        .map_err(|e| KyberError::DecryptionFailed(format!("Invalid nonce hex: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_bytes);

    let ct_bytes = hex::decode(&ciphertext_hex)
        .map_err(|e| KyberError::DecryptionFailed(format!("Invalid ciphertext hex: {e}")))?;

    let plaintext_bytes = crypto::decrypt_chacha20(&key_arr, &nonce_arr, &ct_bytes, &[])?;
    String::from_utf8(plaintext_bytes)
        .map_err(|e| KyberError::DecryptionFailed(format!("UTF-8 decode error: {e}")))
}

#[uniffi::export]
pub fn create_sensor_packet(lux: f64, timestamp: u64) -> Result<String, KyberError> {
    let pkt = packets::SensorPacket { lux, timestamp };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_clipboard_packet(text: String, timestamp: u64) -> Result<String, KyberError> {
    let hash = packets::compute_sha256_hex(&text);
    let pkt = packets::ClipboardPacket {
        content: text,
        hash,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_binary_clipboard_packet(
    mime_type: String,
    data_base64: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let hash = packets::compute_sha256_hex(&data_base64);
    let pkt = packets::BinaryClipboardPacket {
        mime_type,
        data_base64,
        hash,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_sms_packet(
    sender: String,
    body: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = packets::SmsPacket {
        sender,
        body,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_outbound_sms_packet(
    recipient: String,
    body: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = packets::OutboundSmsPacket {
        recipient,
        body,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_notification_packet(
    title: String,
    text: String,
    app_package: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = packets::NotificationPacket {
        sbn_key: format!("{app_package}_{timestamp}"),
        title,
        text,
        app_package,
        icon_base64: None,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_notification_action_packet(
    sbn_key: String,
    action_index: u32,
    action_title: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = packets::NotificationActionPacket {
        sbn_key,
        action_index,
        action_title,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn create_hardware_command_packet(
    command_type: String,
    payload_json: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = packets::HardwareCommandPacket {
        command_type,
        payload_json,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn generate_path_challenge_tokens(
    session_key_hex: String,
) -> Result<PathChallengeResult, KyberError> {
    let sk = hex::decode(&session_key_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid session key hex: {e}")))?;
    let (challenge_token, expected_response) = PathMigrationManager::create_path_challenge(&sk);
    Ok(PathChallengeResult {
        challenge_token,
        expected_response,
    })
}

#[uniffi::export]
pub fn verify_path_response_token(
    session_key_hex: String,
    challenge_token: String,
    response_token: String,
) -> Result<bool, KyberError> {
    let sk = hex::decode(&session_key_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid session key hex: {e}")))?;
    Ok(PathMigrationManager::verify_path_response(
        &sk,
        &challenge_token,
        &response_token,
    ))
}

#[uniffi::export]
pub fn generate_sas_code(
    host_pk_hex: String,
    client_pk_hex: String,
    shared_secret_hex: String,
) -> Result<String, KyberError> {
    let host_bytes = hex::decode(&host_pk_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid host PK hex: {e}")))?;
    let client_bytes = hex::decode(&client_pk_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid client PK hex: {e}")))?;
    let ss_bytes = hex::decode(&shared_secret_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid SS hex: {e}")))?;

    crypto::generate_sas_code(&host_bytes, &client_bytes, &ss_bytes)
}

#[uniffi::export]
pub fn toggle_flight_data_recorder(enabled: bool) {
    telemetry::GLOBAL_FLIGHT_RECORDER.set_enabled(enabled);
}

#[uniffi::export]
pub fn dump_flight_data_recorder() -> String {
    telemetry::GLOBAL_FLIGHT_RECORDER.dump_events_json()
}

#[uniffi::export]
#[allow(deprecated)]
pub fn trigger_panic_hardware_wipe() -> Result<(), KyberError> {
    crypto::trigger_panic_hardware_wipe()
}

#[uniffi::export]
pub fn is_duplicate_clipboard(content_hash: String, recent_hashes: Vec<String>) -> bool {
    recent_hashes.contains(&content_hash)
}

#[uniffi::export]
pub fn compute_sha256(data: String) -> String {
    packets::compute_sha256_hex(&data)
}

#[uniffi::export]
pub fn perform_stun_hole_punch(stun_host: String) -> Result<String, KyberError> {
    let addr = block_on_sync(network::query_stun_server(&stun_host))?;
    Ok(addr.to_string())
}

// QUIC connection management — thin wrapper around quic_bridge
#[uniffi::export]
pub fn quic_bind_server(port: u16) -> Result<(), KyberError> {
    block_on_sync(quic_app::QuicAppManager::bind_server(port))?;
    Ok(())
}

#[uniffi::export]
pub fn quic_connect(
    host: String,
    port: u16,
    pinned_cert_hash_hex: String,
) -> Result<bool, KyberError> {
    let addr: std::net::SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| KyberError::NetworkError(format!("Invalid address: {e}")))?;
    let pinned = if pinned_cert_hash_hex.is_empty() {
        None
    } else {
        Some(pinned_cert_hash_hex)
    };
    let conn = block_on_sync(quic_app::QuicAppManager::connect(
        addr,
        pinned.clone(),
        None,
    ))?;
    quic_bridge::store_connection(conn, addr, pinned);
    Ok(true)
}

#[uniffi::export]
pub fn quic_send_and_recv(stream_type: u8, body_json: String) -> Result<String, KyberError> {
    let conn = quic_bridge::get_or_reconnect()?;
    block_on_sync(quic_bridge::quic_send_and_recv_impl(
        &conn,
        stream_type,
        &body_json,
    ))
}

#[uniffi::export]
pub fn quic_disconnect() {
    quic_bridge::close_connection();
}

// Double Ratchet FFI — peer-keyed session registry
#[uniffi::export]
pub fn ratchet_init_session(
    peer_identity: String,
    master_shared_secret_hex: String,
    is_initiator: bool,
) -> Result<String, KyberError> {
    let ss = hex::decode(&master_shared_secret_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid shared secret hex: {e}")))?;
    ratchet_ffi::ratchet_init_session_impl(&peer_identity, &ss, is_initiator)?;
    Ok("OK".to_string())
}

#[uniffi::export]
pub fn ratchet_remove_session(peer_identity: String) -> bool {
    ratchet_ffi::ratchet_remove_session_impl(&peer_identity)
}

#[uniffi::export]
pub fn ratchet_encrypt_message(
    peer_identity: String,
    plaintext_hex: String,
) -> Result<String, KyberError> {
    let pt = hex::decode(&plaintext_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid hex: {e}")))?;
    let msg = ratchet_ffi::ratchet_encrypt_message_impl(&peer_identity, &pt)?;
    let mut json = serde_json::json!({
        "nonce_hex": hex::encode(msg.nonce),
        "ciphertext_hex": hex::encode(msg.ciphertext),
    });
    if let Some(ref pk) = msg.rekey_x25519_pk {
        json["rekey_x25519_pk_hex"] = serde_json::Value::String(hex::encode(pk));
    }
    if let Some(ref mpk) = msg.rekey_mlkem_pk {
        json["rekey_mlkem_pk_hex"] = serde_json::Value::String(hex::encode(mpk));
    }
    if let Some(ref ct) = msg.rekey_ciphertext {
        json["rekey_ciphertext_hex"] = serde_json::Value::String(hex::encode(ct));
    }
    serde_json::to_string(&json).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn ratchet_decrypt_message(
    peer_identity: String,
    nonce_hex: String,
    ciphertext_hex: String,
) -> Result<String, KyberError> {
    let nonce_bytes = hex::decode(&nonce_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid nonce hex: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(KyberError::CryptoError("Invalid nonce length".into()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);
    let ct = hex::decode(&ciphertext_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid ciphertext hex: {e}")))?;
    let pt = ratchet_ffi::ratchet_decrypt_message_impl(&peer_identity, &nonce, &ct)?;
    let json = serde_json::json!({"plaintext_hex": hex::encode(pt)});
    serde_json::to_string(&json).map_err(|e| KyberError::SerializationError(e.to_string()))
}

#[uniffi::export]
pub fn listen_for_beacons(timeout_secs: u64) -> Result<Vec<String>, KyberError> {
    let results = block_on_sync(network::listen_for_beacons(
        network::P2P_BEACON_PORT,
        timeout_secs,
    ))?
    .into_iter()
    .map(|(pk, ip, name)| format!("{pk}:{ip}:{name}"))
    .collect();
    Ok(results)
}

#[uniffi::export]
pub fn evaluate_connection_hierarchy(
    wifi_direct_active: bool,
    lan_active: bool,
    public_endpoint: String,
) -> ConnectionInfo {
    if wifi_direct_active {
        ConnectionInfo {
            active_tier: 1,
            active_path_description: "Wi-Fi Direct P2P Link (Multiplexed QUIC)".to_string(),
            latency_ms: 0.0,
            public_endpoint,
        }
    } else if lan_active {
        ConnectionInfo {
            active_tier: 2,
            active_path_description: "Local LAN AP Link (mDNS UDP Discovery)".to_string(),
            latency_ms: 0.0,
            public_endpoint,
        }
    } else {
        ConnectionInfo {
            active_tier: 3,
            active_path_description: "WireGuard WAN Tunnel Overlay (Encrypted QUIC)".to_string(),
            latency_ms: 0.0,
            public_endpoint,
        }
    }
}

pub fn get_local_ip() -> String {
    system_net::get_system_local_ip()
}

pub fn get_wifi_direct_mac() -> String {
    system_net::get_primary_mac()
}

pub async fn send_beacon_payload(payload: String) -> Result<(), KyberError> {
    p2p_group::send_beacon_payload(payload).await
}

pub fn try_start_p2p_group() {
    p2p_group::try_start_p2p_group()
}

#[uniffi::export]
pub fn generate_pairing_config(
    host_pk_hex: String,
    wireguard_pk_hex: String,
) -> Result<PairingConfig, KyberError> {
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

    try_start_p2p_group();

    Ok(PairingConfig {
        host_identity_pk_hex: host_pk_hex,
        local_ip: system_net::get_system_local_ip(),
        wifi_direct_mac: system_net::get_primary_mac(),
        p2p_ip: system_net::get_p2p_ip(),
        wireguard_pk_hex,
        stun_endpoint: "stun.l.google.com:19302".to_string(),
        pairing_nonce_hex: hex::encode(nonce),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_handshake_flow() {
        let _alice = generate_pq_keypair().unwrap();
        let bob = generate_pq_keypair().unwrap();

        let kem_res = encapsulate_pq_secret(bob.x25519_pk_hex, bob.mlkem_pk_hex).unwrap();
        let decapsulated =
            decapsulate_pq_secret(kem_res.ciphertext_hex, bob.x25519_sk_hex, bob.mlkem_sk_hex)
                .unwrap();

        assert_eq!(kem_res.shared_secret_hex, decapsulated);
    }
}
