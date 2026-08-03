use crate::state::AppState;
use crate::state::SecureString;
use std::sync::Arc;

/// Verify the connecting peer is the authenticated pairing peer.
/// The client certificate hash captured during pairing is the strong signal;
/// the pairing peer IP is the fallback for clients that did not present a cert.
fn peer_is_authorized(s: &AppState, peer_cert_hash: &str, peer_ip: &str) -> bool {
    let paired_cert = s.get_paired_client_cert_hash();
    if !paired_cert.is_empty() {
        // Strong identity: certificate hash must match the pairing peer.
        return !peer_cert_hash.is_empty() && peer_cert_hash == paired_cert;
    }
    // Fallback: bind to the IP that performed the pairing.
    let paired_ip = s.get_paired_peer_ip();
    if !paired_ip.is_empty() {
        return peer_ip == paired_ip;
    }
    // No identity recorded for this pairing — refuse destructive operations.
    false
}

pub(crate) async fn handle_unpair(s: Arc<AppState>, peer_cert_hash: String, peer_ip: String) {
    // Unpair is a destructive operation — it must only be accepted from the
    // authenticated pairing peer, never from an arbitrary LAN connection.
    if !peer_is_authorized(&s, &peer_cert_hash, &peer_ip) {
        s.add_log(format!(
            "[Pairing] Unpair rejected: unauthenticated peer (cert={}, ip={})",
            if peer_cert_hash.is_empty() {
                "none"
            } else {
                "<hash>"
            },
            peer_ip
        ));
        return;
    }
    // Verify that a session key exists — unauthenticated unpair is not allowed.
    let peer_id = s.get_pairing_initiator_pk();
    let has_session = !s.get_session_key_string().is_empty();
    if !has_session {
        s.add_log("[Pairing] Unpair rejected: no active session".to_string());
        return;
    }
    // Clear the ratchet session for this peer
    if !peer_id.is_empty() {
        core_crypto::ratchet_remove_session(peer_id.clone());
    }
    // Audit KYP-2026-02 #15: unpair must ALSO clear the pairing keypair
    // REGISTRY (not just the in-memory AppState copy) and destroy every
    // opaque keypair/KEM handle so a later re-pair can never observe a stale
    // registered keypair or a secret-bearing handle.
    core_crypto::clear_pq_pairing_registry();
    core_crypto::destroy_all_pq_keypair_handles();
    core_crypto::destroy_all_kem_handles();
    let handle = super::DESKTOP_SESSION_KEY_HANDLE.swap(0, std::sync::atomic::Ordering::AcqRel);
    if handle != 0 {
        core_crypto::session_key_destroy(handle);
    }
    super::IS_SESSION_KEY_AUTHENTICATED.store(false, std::sync::atomic::Ordering::Release);
    // Clear all cryptographic state
    s.set_session_key(SecureString::new(String::new()));
    s.clear_all_pairing();
    {
        let mut settings = s.settings.lock();
        settings.is_paired = false;
        settings.paired_device_name = None;
        settings.paired_device_picture = None;
    }
    s.save_settings();
    crate::ratchet_store::clear_ratchet_store();
    s.set_connection_status("DISCONNECTED".to_string());
    s.set_connection_method("None".to_string());
    s.set_connection_color("red".to_string());
    s.add_log("[Pairing] Unpaired via QUIC — all session state cleared".to_string());
}
