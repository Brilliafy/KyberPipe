//! Pairing, Authentication, and Path Migration API.
//!
//! Domain module grouping SAS code generation, pairing configuration,
//! path challenge verification, and hardware command packet creation.

use crate::error::KyberError;
use crate::{
    crypto, ensure_panic_hook_installed, ffi, network, system_net, PairingConfig,
    PathChallengeResult,
};

// ── SAS & Pairing ──

#[uniffi::export]
pub fn generate_sas_code(
    host_pk: Vec<u8>,
    client_pk: Vec<u8>,
    shared_secret: Vec<u8>,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    crypto::generate_sas_code(&host_pk, &client_pk, &shared_secret)
}

#[uniffi::export]
pub fn generate_pairing_config(
    host_pk_hex: String,
    wireguard_pk_hex: String,
) -> Result<PairingConfig, KyberError> {
    ensure_panic_hook_installed();
    let host_pk = hex::decode(&host_pk_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid host PK hex: {e}")))?;
    let wg_pk = hex::decode(&wireguard_pk_hex)
        .map_err(|e| KyberError::CryptoError(format!("Invalid WireGuard PK hex: {e}")))?;
    let local_ip = system_net::get_system_local_ip();
    // Fresh out-of-band QR nonce. The phone must echo this in its pairing
    // payload so the server can reject blind races from arbitrary LAN peers
    // (audit finding #20 — pairing-slot hijack/DoS).
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    Ok(PairingConfig {
        host_identity_pk_hex: hex::encode(&host_pk),
        local_ip,
        // Wi-Fi Direct (P2P) was removed from the product (audit finding #1:
        // the group was never actually WPA2-secured and the Android join path
        // was a dead stub). The fields remain in the FFI record only to keep
        // the binding surface stable; they are always empty now and no
        // consumer reads them.
        wifi_direct_mac: String::new(),
        p2p_ip: String::new(),
        wireguard_pk_hex: hex::encode(&wg_pk),
        stun_endpoint: String::new(),
        pairing_nonce_hex: hex::encode(nonce),
    })
}

// ── Path Migration ──

#[uniffi::export]
pub fn generate_path_challenge_tokens(
    session_key: Vec<u8>,
) -> Result<PathChallengeResult, KyberError> {
    ensure_panic_hook_installed();
    if session_key.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: session_key.len() as u64,
        });
    }
    let (challenge, expected) = network::PathMigrationManager::create_path_challenge(&session_key);
    Ok(PathChallengeResult {
        challenge_token: challenge,
        expected_response: expected,
    })
}

#[uniffi::export]
pub fn verify_path_response_token(
    session_key: Vec<u8>,
    challenge_token: String,
    response_token: String,
) -> Result<bool, KyberError> {
    ensure_panic_hook_installed();
    if session_key.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: session_key.len() as u64,
        });
    }
    Ok(network::PathMigrationManager::verify_path_response(
        &session_key,
        &challenge_token,
        &response_token,
    ))
}

// ── Packet Creation ──

#[uniffi::export]
pub fn create_sms_packet(
    sender: String,
    body: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    ffi::packets::create_sms_packet_impl(sender, body, timestamp)
}

#[uniffi::export]
pub fn create_outbound_sms_packet(
    recipient: String,
    body: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    ffi::packets::create_outbound_sms_packet_impl(recipient, body, timestamp)
}

#[uniffi::export]
pub fn create_notification_packet(
    title: String,
    text: String,
    app_package: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    ffi::packets::create_notification_packet_impl(title, text, app_package, timestamp)
}

#[uniffi::export]
pub fn create_notification_action_packet(
    sbn_key: String,
    action_index: u32,
    action_title: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    ffi::packets::create_notification_action_packet_impl(
        sbn_key,
        action_index,
        action_title,
        timestamp,
    )
}

#[uniffi::export]
pub fn create_hardware_command_packet(
    command_type: String,
    payload_json: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    ffi::packets::create_hardware_command_packet_impl(command_type, payload_json, timestamp)
}
