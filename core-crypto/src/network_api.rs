//! QUIC Transport, STUN, Network Discovery, and Connection Management API.
//!
//! Domain module grouping network-related functions: QUIC connection management,
//! STUN hole punching, beacon listening, and connection hierarchy evaluation.

use crate::error::KyberError;
use crate::{
    ensure_panic_hook_installed, ffi, network, quic_bridge, ClientIdentityCert, ConnectionInfo,
};

// ── QUIC Transport ──

#[uniffi::export]
pub fn quic_bind_server(port: u16) -> Result<(), KyberError> {
    ensure_panic_hook_installed();
    ffi::network::quic_bind_server_impl(port)
}

#[uniffi::export]
pub fn quic_connect(
    host: String,
    port: u16,
    pinned_cert_hash_hex: String,
) -> Result<bool, KyberError> {
    ensure_panic_hook_installed();
    ffi::network::quic_connect_impl(host, port, pinned_cert_hash_hex)
}

/// Bootstrap-pairing connect: permits private (LAN) addresses. Loopback is
/// always blocked. `pinned_cert_hash_hex` is the SHA-256 of the server
/// certificate that was bound into the pairing QR (audit finding #15): when
/// provided, the client verifies the server cert against it BEFORE the KEM
/// handshake, so a bootstrap MITM cannot present its own certificate and later
/// become the pinned identity. Empty (legacy QR without a hash) falls back to
/// accepting any cert for the handshake — content stays protected by the
/// app-layer ratchet, but the pin must then be re-derived from a connection
/// authenticated with the derived session key.
/// ONLY use from the pairing flow (audit finding #6 — the SSRF guard
/// previously made LAN pairing unreachable).
#[uniffi::export]
pub fn quic_connect_pairing_bootstrap(
    host: String,
    port: u16,
    pinned_cert_hash_hex: String,
) -> Result<bool, KyberError> {
    ensure_panic_hook_installed();
    ffi::network::quic_connect_pairing_bootstrap_impl(host, port, pinned_cert_hash_hex)
}

/// SHA-256 hash (hex) of the desktop server's own identity certificate.
/// Embedded in the pairing QR so the phone pins the certificate bound to the
/// QR rather than the certificate observed on a (possibly MITM'd) bootstrap
/// connection (audit finding #15).
#[uniffi::export]
pub fn quic_server_cert_hash() -> Option<String> {
    ensure_panic_hook_installed();
    crate::quic_app::server_cert_sha256()
}

/// Post-pairing connect that presents a per-install client identity certificate
/// (DER cert + DER PKCS#8 key) so the server authorizes the peer by cert hash
/// instead of IP (audit finding #8).
#[uniffi::export]
pub fn quic_connect_with_client_cert(
    host: String,
    port: u16,
    pinned_cert_hash_hex: String,
    client_cert_der: Vec<u8>,
    client_key_der: Vec<u8>,
) -> Result<bool, KyberError> {
    ensure_panic_hook_installed();
    ffi::network::quic_connect_with_client_cert_impl(
        host,
        port,
        pinned_cert_hash_hex,
        client_cert_der,
        client_key_der,
    )
}

#[uniffi::export]
pub fn quic_send_and_recv(stream_type: u8, body_json: String) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    ffi::network::quic_send_and_recv_impl(stream_type, body_json)
}

/// Send/recv on the connection registered for a SPECIFIC peer key. This is the
/// mesh addressing path: each peer connected via `quic_connect` is stored under
/// its own registry entry, so multiple devices can be active simultaneously.
/// The peer key is the pinned cert hash when provided, else "ip:port".
///
/// AUDIT F5: every send/recv is bounded by a hard timeout. On expiry the peer
/// connection is CLOSED so the reconnect state machine re-establishes against
/// the candidate address set (audit F3) — without this, a blackholed network
/// (no ICMP, no TCP reset) would leave the poll/SMS threads blocked for minutes
/// and every subsequent poll would reuse the same dead connection.
#[uniffi::export]
pub fn quic_send_and_recv_to(
    peer_key: String,
    stream_type: u8,
    body_json: String,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    // AUDIT #6 (a): per-peer in-flight gate — at most ONE send/recv round-trip
    // per peer at a time. The SMS forwarder and media pushes are otherwise
    // free to stack concurrent round-trips (each a potential leaked task on
    // timeout) against a blackholed network; a bounded wait serializes them
    // behind the in-flight call instead.
    let _gate = quic_bridge::acquire_in_flight(&peer_key, std::time::Duration::from_secs(10))?;
    let conn = quic_bridge::get_or_reconnect_for(&peer_key)?;
    // AUDIT #6 (b): abortable timeout — the round-trip future is spawned as a
    // task and ABORTED on deadline, so a blackholed path cannot leak a live
    // task that keeps running past the timeout (the legacy `timeout` dropped
    // the future but the in-flight async op survived). The wedged connection is
    // closed so the reconnect state machine re-establishes against the
    // candidate address set (audit F3).
    match crate::block_on_sync_timeout_abortable(
        quic_bridge::quic_send_and_recv_impl(conn.clone(), stream_type, body_json.clone()),
        std::time::Duration::from_secs(QUIC_IO_TIMEOUT_SECS),
    ) {
        Some(Ok(s)) => Ok(s),
        Some(Err(e)) => Err(e),
        None => {
            quic_bridge::close_peer(&peer_key);
            Err(KyberError::NetworkError(format!(
                "QUIC send/recv timed out after {QUIC_IO_TIMEOUT_SECS}s — connection closed for reconnect"
            )))
        }
    }
}

/// Hard cap on a single QUIC send/recv round-trip (audit F5). Bounds how long
/// the Android poll loop / SMS forwarder can block on a blackholed network
/// before the connection is torn down and the reconnect machine re-establishes.
pub(crate) const QUIC_IO_TIMEOUT_SECS: u64 = 10;

/// List the peer keys of every registered QUIC connection.
#[uniffi::export]
pub fn quic_registered_peers() -> Vec<String> {
    ensure_panic_hook_installed();
    quic_bridge::peer_keys()
}

/// Register a LAST-KNOWN-GOOD candidate address for a peer (audit F3 —
/// "Seamless Path Migration"). The reconnect path rotates through the
/// candidate set when the primary address goes stale (DHCP renewal,
/// Wi-Fi→cellular handoff, subnet change), so a desktop whose LAN IP changed is
/// still reachable via an alternate address learned through beacon/mDNS
/// discovery or a prior successful connect. The peer key is the pinned cert
/// hash (or "ip:port" pre-pairing). Returns false when the peer is not
/// registered or the address was already known.
#[uniffi::export]
pub fn quic_note_peer_candidate_address(peer_key: String, host: String, port: u16) -> bool {
    ensure_panic_hook_installed();
    let addr = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => std::net::SocketAddr::new(ip, port),
        Err(_) => return false,
    };
    quic_bridge::note_peer_candidate_address(&peer_key, addr)
}

/// Close the connection to a specific peer (mesh teardown).
#[uniffi::export]
pub fn quic_disconnect_peer(peer_key: String) {
    ensure_panic_hook_installed();
    quic_bridge::close_peer(&peer_key);
}

#[uniffi::export]
pub fn quic_disconnect() {
    ensure_panic_hook_installed();
    quic_bridge::close_connection();
}

/// Touch the active QUIC connection (audit finding #25): pokes the bridge so
/// a Doze-mode keepalive performs a REAL heartbeat instead of a fake sleep. If
/// the connection is down (e.g. Doze dropped it), the reconnect machinery
/// re-establishes it on the next send; the touch itself is non-blocking. Used
/// by the Android foreground service's doze keepalive.
#[uniffi::export]
pub fn quic_bridge_touch() {
    ensure_panic_hook_installed();
    quic_bridge::touch_connection();
}

/// Capture the current server's certificate hash WITHOUT storing it (no silent
/// TOFU). The caller persists this ONLY after out-of-band SAS confirmation so a
/// first-connection MitM can never become the permanently trusted identity.
#[uniffi::export]
pub fn quic_capture_server_cert_hash() -> Option<String> {
    ensure_panic_hook_installed();
    let conn = quic_bridge::active_connection()?;
    network::tls_config::capture_server_cert_hash_no_store(&conn)
}

/// Explicitly persist a server certificate pin after the user confirmed the
/// SAS out-of-band. This is the ONLY path that writes the trusted identity.
#[uniffi::export]
pub fn quic_store_server_pin(cert_hash: String) -> Result<(), KyberError> {
    ensure_panic_hook_installed();
    if cert_hash.len() != 64 || hex::decode(&cert_hash).is_err() {
        return Err(KyberError::NetworkError(
            "Cert pin must be a 64-char hex SHA-256 digest".into(),
        ));
    }
    network::tls_config::store_tofu_cert_hash(cert_hash);
    Ok(())
}

/// Generate a per-install client identity certificate (DER cert + DER PKCS#8
/// key). The Android companion persists these in a secure store and presents
/// them on every post-pairing QUIC connection so the server authorizes by cert
/// hash instead of IP (audit finding #8).
#[uniffi::export]
pub fn generate_client_identity_cert() -> Result<ClientIdentityCert, KyberError> {
    ensure_panic_hook_installed();
    let (cert_der, key_der) = network::tls_config::generate_client_identity_cert()?;
    let sha256_hex = {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&cert_der);
        hex::encode(digest)
    };
    Ok(ClientIdentityCert {
        cert_der,
        key_der,
        sha256_hex,
    })
}

// ── STUN ──

#[uniffi::export]
pub fn perform_stun_hole_punch(stun_host: String) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    ffi::network::perform_stun_hole_punch_impl(stun_host)
}

// ── Network Discovery ──

#[uniffi::export]
pub fn listen_for_beacons(timeout_secs: u64) -> Result<Vec<String>, KyberError> {
    ensure_panic_hook_installed();
    // Run the scan on a dedicated thread with its own current-thread runtime so
    // a long scan never pins one of the shared FFI_RUNTIME worker threads
    // (which would starve concurrent UniFFI crypto calls).
    let handle = std::thread::Builder::new()
        .name("kyberpipe-beacon-scan".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create beacon scan runtime");
            rt.block_on(network::listen_for_beacons(
                network::P2P_BEACON_PORT,
                timeout_secs,
            ))
        })
        .map_err(|e| KyberError::NetworkError(format!("Failed to spawn beacon listener: {e}")))?;
    let results = handle
        .join()
        .map_err(|_| KyberError::NetworkError("Beacon listener panicked".into()))??;
    Ok(results
        .into_iter()
        .map(|(pk, ip, name)| format!("{pk}:{ip}:{name}"))
        .collect())
}

// ── Connection Management ──

#[uniffi::export]
pub fn evaluate_connection_hierarchy(
    _wifi_direct_active: bool,
    lan_active: bool,
    public_endpoint: String,
) -> ConnectionInfo {
    ensure_panic_hook_installed();
    // AUDIT FINDING #1: the Wi-Fi Direct (P2P) transport tier is REMOVED — the
    // group was never actually WPA2-secured, the passphrase was never applied,
    // and the Android join path was a dead stub. The parameter is retained in
    // the FFI signature only for binding/checksum stability and is always
    // ignored; callers pass `false`. The LAN tier (mDNS beacon discovery) is
    // the first-class local transport.
    if lan_active {
        ConnectionInfo {
            active_tier: 2,
            active_path_description: "Local Network (LAN)".to_string(),
            latency_ms: 5.0,
            public_endpoint: public_endpoint.clone(),
        }
    } else if !public_endpoint.is_empty() {
        ConnectionInfo {
            active_tier: 3,
            active_path_description: "Public Internet (STUN)".to_string(),
            latency_ms: 50.0,
            public_endpoint,
        }
    } else {
        ConnectionInfo {
            active_tier: 0,
            active_path_description: "Not Connected".to_string(),
            latency_ms: 0.0,
            public_endpoint: String::new(),
        }
    }
}

// ── Telemetry ──

#[uniffi::export]
pub fn toggle_flight_data_recorder(enabled: bool) {
    ensure_panic_hook_installed();
    crate::telemetry::GLOBAL_FLIGHT_RECORDER.set_enabled(enabled);
}

#[uniffi::export]
pub fn dump_flight_data_recorder() -> String {
    ensure_panic_hook_installed();
    crate::telemetry::GLOBAL_FLIGHT_RECORDER.dump_events_json()
}
