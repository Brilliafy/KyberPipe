use crate::state::AppState;
use crate::state::SecureString;
use std::sync::Arc;

/// Verify the connecting peer is an authenticated paired peer (AUDIT F13).
/// The TLS-observed client certificate hash is the strong signal. The legacy
/// check compared ONLY against the single `get_paired_client_cert_hash()`
/// slot, so a SECOND paired device's unpair stream was silently rejected even
/// though the stream admission layer (`is_authorized_peer_cert`) admitted it.
/// The pairing peer IP remains the fallback for clients that did not present a
/// cert.
fn peer_is_authorized(s: &AppState, peer_cert_hash: &str, peer_ip: &str) -> bool {
    // AUDIT F13: the cert may be the legacy global pairing identity OR an
    // entry in the per-peer cert→ratchet-id map (a second paired device).
    if s.is_authorized_peer_cert(peer_cert_hash) {
        return true;
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
    // Unpair is a destructive operation — it must only be accepted from an
    // authenticated paired peer, never from an arbitrary LAN connection.
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
    // AUDIT F13: unpair is now PER-PEER. Resolve the ratchet peer id this cert
    // belongs to (the cert→ratchet-id map, falling back to the single global
    // pairing identity for the primary device / legacy sessions). The primary
    // device (peer_id == the global pairing id) gets the full global teardown;
    // a SECOND paired device gets ONLY its own session/store/watermark removed
    // so the primary and any other peer keep working.
    let peer_id = s.resolve_peer_for_cert_hash(&peer_cert_hash);
    let is_primary = !peer_id.is_empty() && peer_id == s.get_pairing_initiator_pk();
    // Verify that a session exists — unauthenticated unpair is not allowed.
    let has_session = !s.get_session_key_string().is_empty() || !peer_id.is_empty();
    if !has_session {
        s.add_log("[Pairing] Unpair rejected: no active session".to_string());
        return;
    }

    // ── PER-PEER teardown (runs for primary AND secondary peers) ───────────
    // Remove ONLY this peer's ratchet session, its persisted snapshot and its
    // watermark entry, and its cert→ratchet-id mapping. The legacy code tore
    // down EVERY peer's sessions + the shared ratchet_sessions.json when ANY
    // device unpaired, silently "un-pairing" the other devices after restart.
    if !peer_id.is_empty() {
        core_crypto::ratchet_remove_session(peer_id.clone());
        crate::ratchet_store::remove_ratchet_session_for_peer(&peer_id);
    }
    s.remove_peer_cert_mapping(&peer_cert_hash);

    if is_primary {
        // ── PRIMARY peer: full global teardown ─────────────────────────────
        // Audit KYP-2026-02 #15: unpair must ALSO clear the pairing keypair
        // REGISTRY (not just the in-memory AppState copy) and destroy every
        // opaque keypair/KEM handle so a later re-pair can never observe a
        // stale registered keypair or a secret-bearing handle.
        core_crypto::clear_pq_pairing_registry();
        core_crypto::destroy_all_pq_keypair_handles();
        core_crypto::destroy_all_kem_handles();
        let handle = super::DESKTOP_SESSION_KEY_HANDLE.swap(0, std::sync::atomic::Ordering::AcqRel);
        if handle != 0 {
            core_crypto::session_key_destroy(handle);
        }
        super::IS_SESSION_KEY_AUTHENTICATED.store(false, std::sync::atomic::Ordering::Release);
        // AUDIT F16: tear down any running tor daemon on unpair — its onion
        // service was created for THIS pairing and must not outlive it.
        s.stop_tor();
        // Clear all cryptographic state
        s.set_session_key(SecureString::new(String::new()));
        s.clear_all_pairing();
        {
            let mut settings = s.settings.lock();
            settings.is_paired = false;
            settings.paired_device_name = None;
            settings.paired_device_picture = None;
        }
        // AUDIT F1: clear the persisted pairing identity so a later boot cannot
        // rebuild a stale mTLS allowlist / peer map after an explicit unpair.
        s.clear_persisted_pairing_identity();
        // AUDIT F12 (MEDIUM): wipe the OS keyring. The legacy unpair path left
        // the master session key, the pairing keypair and the snapshot wrap key
        // in the OS keyring indefinitely — the next app start re-imported them
        // even though `is_paired=false`, so an attacker with a later
        // credential-store snapshot could decrypt historical ratchet snapshots
        // taken before the unpair. The SAME routine the panic self-destruct
        // uses now runs here, so unpair and self-destruct share one
        // wipe_keyring contract.
        crate::ratchet_store::wipe_keyring_entries();
        core_crypto::network::tls_config::store_tofu_cert_hash(String::new());
        crate::ratchet_store::clear_ratchet_store();
    } else {
        // ── SECONDARY peer: keep the primary's global pairing + keyring ────
        // intact. Only this peer's session/store/watermark/mapping were removed
        // above. Log the per-peer scope explicitly.
        s.add_log(format!(
            "[Pairing] Unpaired secondary device (ratchet peer {}) via QUIC — primary pairing left intact (audit F13)",
            if peer_id.is_empty() { "<unknown>" } else { &peer_id }
        ));
    }
    s.save_settings();
    s.set_connection_status("DISCONNECTED".to_string());
    s.set_connection_method("None".to_string());
    s.set_connection_color("red".to_string());
    s.add_log("[Pairing] Unpaired via QUIC — session state cleared".to_string());
}
