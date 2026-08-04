use crate::error::KyberError;

/// Reject private/internal IP ranges to prevent SSRF.
/// Allows: public IPs, cloudflare/gcloud STUN servers.
/// Blocks: 10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.x.x.x, 0.x.x.x, ::1, fdxx:: (ULA)
fn is_private_or_restricted(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

/// Validate a STUN host. Hostnames are resolved ONCE and every resolved IP is
/// checked — a name that points at 127.0.0.1 (or a rebinding name) is caught
/// instead of slipping past a literal-IP-only check.
pub(crate) fn validate_stun_host(host: &str) -> Result<(), KyberError> {
    // Extract host part (strip port)
    let hostname = host.split(':').next().unwrap_or(host);
    // If it's a raw IP, check for private ranges
    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        if is_private_or_restricted(ip) {
            return Err(KyberError::NetworkError(format!(
                "STUN host {host} is a private/reserved IP — rejected to prevent SSRF"
            )));
        }
        return Ok(());
    }
    // Hostname: resolve once and validate the full resolved set.
    let resolved =
        std::net::ToSocketAddrs::to_socket_addrs(&format!("{hostname}:19302")).map_err(|e| {
            KyberError::NetworkError(format!("STUN host resolution failed for {host}: {e}"))
        })?;
    let ips: Vec<std::net::IpAddr> = resolved.map(|sa| sa.ip()).collect();
    if ips.is_empty() {
        return Err(KyberError::NetworkError(format!(
            "STUN host {host} resolved to no addresses"
        )));
    }
    if let Some(bad) = ips.iter().copied().find(|ip| is_private_or_restricted(*ip)) {
        return Err(KyberError::NetworkError(format!(
            "STUN host {host} resolves to private/internal address {bad} — rejected to prevent SSRF"
        )));
    }
    Ok(())
}

/// Structurally validate a certificate pin: exactly 64 hex chars.
pub(crate) fn validate_cert_pin(pin: &str) -> bool {
    pin.len() == 64 && hex::decode(pin).is_ok()
}

pub fn perform_stun_hole_punch_impl(stun_host: String) -> Result<String, KyberError> {
    validate_stun_host(&stun_host)?;
    let addr = crate::block_on_sync_timeout(
        crate::network::query_stun_server(&stun_host),
        std::time::Duration::from_secs(5),
    )
    .ok_or_else(|| KyberError::NetworkError("STUN query timed out after 5s".into()))??;
    Ok(addr.to_string())
}

pub fn quic_bind_server_impl(port: u16) -> Result<(), KyberError> {
    crate::block_on_sync_timeout(
        crate::quic_app::QuicAppManager::bind_server(port),
        std::time::Duration::from_secs(5),
    )
    .ok_or_else(|| KyberError::NetworkError("QUIC server bind timed out after 5s".into()))??;
    Ok(())
}

pub fn quic_connect_impl(
    host: String,
    port: u16,
    pinned_cert_hash_hex: String,
) -> Result<bool, KyberError> {
    // Post-pairing connects carry a validated pin; private IPs are allowed
    // only when a pin proves this address came from the trusted pairing flow.
    let allow_private = !pinned_cert_hash_hex.is_empty();
    quic_connect_with_mode(&host, port, pinned_cert_hash_hex, allow_private, None)
}

/// Bootstrap-pairing connect: allows private (LAN) addresses, but REQUIRES the
/// QR-bound server certificate pin (audit finding #15). The pin binds the
/// bootstrap TLS to the certificate whose hash was encoded in the pairing QR;
/// without it the verifier would accept ANY server certificate, so a LAN MITM
/// could terminate TLS, forward the KEM handshake unchanged, and hold every
/// session key while the SAS still matches on both ends (the SAS inputs are
/// unchanged by transparent forwarding). Empty-pin bootstrap pairing is
/// therefore FORBIDDEN: the phone fails loudly instead of proceeding with an
/// unverified server identity. Loopback is still rejected in every path.
pub fn quic_connect_pairing_bootstrap_impl(
    host: String,
    port: u16,
    pinned_cert_hash_hex: String,
) -> Result<bool, KyberError> {
    if !validate_cert_pin(&pinned_cert_hash_hex) {
        return Err(KyberError::NetworkError(
            "Bootstrap pairing requires a valid QR-bound server certificate pin — ".to_string()
                + "pairing without one is forbidden (MITM protection, audit finding #15)",
        ));
    }
    quic_connect_with_mode(&host, port, pinned_cert_hash_hex, true, None)
}

/// Post-pairing connect that additionally presents a client identity
/// certificate (mTLS). Used after pairing so the server can authorize the
/// peer by cert hash instead of IP (audit finding #8).
pub fn quic_connect_with_client_cert_impl(
    host: String,
    port: u16,
    pinned_cert_hash_hex: String,
    client_cert_der: Vec<u8>,
    client_key_der: Vec<u8>,
) -> Result<bool, KyberError> {
    let allow_private = !pinned_cert_hash_hex.is_empty();
    let client_certs = Some((client_cert_der, client_key_der));
    quic_connect_with_mode(
        &host,
        port,
        pinned_cert_hash_hex,
        allow_private,
        client_certs,
    )
}

/// Shared connect implementation. `allow_private` permits RFC1918/link-local
/// addresses (bootstrap pairing or a validated pin); loopback is always
/// blocked. `client_certs` (cert DER + key DER) is presented when the caller
/// holds a per-install identity certificate.
fn quic_connect_with_mode(
    host: &str,
    port: u16,
    pinned_cert_hash_hex: String,
    allow_private: bool,
    client_certs: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<bool, KyberError> {
    // Structurally validate the pin: either empty (unpinned — only acceptable
    // during the initial pairing bootstrap) or a 64-char hex SHA-256 digest.
    // A random string must never bypass the SSRF guard.
    if !pinned_cert_hash_hex.is_empty() && !validate_cert_pin(&pinned_cert_hash_hex) {
        return Err(KyberError::NetworkError(
            "Invalid certificate pin: must be a 64-char hex SHA-256 digest".into(),
        ));
    }
    // Audit finding #15: a non-bootstrap connect with an EMPTY pin would also
    // install an accept-any verifier (PinnedCertVerifier::new(None, required =
    // false)). Post-pairing connects must always present the persisted pin;
    // refusing empty pins here closes the residual accept-any path outside the
    // (now mandatory-pin) pairing bootstrap.
    if pinned_cert_hash_hex.is_empty() {
        return Err(KyberError::NetworkError(
            "QUIC connect without a certificate pin is forbidden (MITM protection)".into(),
        ));
    }

    // Resolve ONCE, validate the entire resolved IP set, and connect only to a
    // validated address. Hostnames pointing at loopback/private ranges (or a
    // rebinding name) are caught here.
    let raw = format!("{host}:{port}");
    let socket_addrs: Vec<std::net::SocketAddr> = raw
        .parse::<std::net::SocketAddr>()
        .map(|a| vec![a])
        .or_else(|_| {
            std::net::ToSocketAddrs::to_socket_addrs(&raw)
                .map(|iter| iter.collect())
                .map_err(|e| KyberError::NetworkError(format!("Address resolution failed: {e}")))
        })?;
    if socket_addrs.is_empty() {
        return Err(KyberError::NetworkError(
            "No address resolved for target".into(),
        ));
    }
    // Loopback is ALWAYS forbidden; private IPs require `allow_private` (a
    // validated pin OR the bootstrap-pairing flag).
    for addr in &socket_addrs {
        let ip = addr.ip();
        if ip.is_loopback() {
            return Err(KyberError::NetworkError(format!(
                "Cannot connect to loopback address {ip} (SSRF guard)"
            )));
        }
        if is_private_or_restricted(ip) && !allow_private {
            return Err(KyberError::NetworkError(format!(
                "Cannot connect to private IP {ip} without a valid paired-cert pin"
            )));
        }
    }
    let addr = socket_addrs[0];
    let pinned = if pinned_cert_hash_hex.is_empty() {
        None
    } else {
        Some(pinned_cert_hash_hex)
    };
    // Retain the raw DER bytes for the reconnect registry; convert to rustls
    // types only for the live handshake.
    let client_certs_raw = client_certs;
    let client_certs = client_certs_raw.clone().map(|(cert_der, key_der)| {
        (
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        )
    });
    let conn = crate::block_on_sync_timeout(
        crate::quic_app::QuicAppManager::connect(addr, pinned.clone(), client_certs),
        std::time::Duration::from_secs(5),
    )
    .ok_or_else(|| KyberError::NetworkError("QUIC connect timed out after 5s".into()))??;
    crate::quic_bridge::store_connection(conn, addr, pinned, client_certs_raw);
    Ok(true)
}

pub fn quic_send_and_recv_impl(stream_type: u8, body_json: String) -> Result<String, KyberError> {
    // AUDIT #6 (a): per-peer in-flight gate around the WHOLE round-trip (the
    // legacy path routes through the active peer).
    let peer = crate::quic_bridge::active_peer_key();
    let _gate = match &peer {
        Some(key) => {
            crate::quic_bridge::acquire_in_flight(key, std::time::Duration::from_secs(10))?
        }
        None => crate::quic_bridge::acquire_in_flight(
            "<legacy-active>",
            std::time::Duration::from_secs(10),
        )?,
    };
    let conn = crate::quic_bridge::get_or_reconnect()?;
    // AUDIT F5 + AUDIT #6 (b): bound every send/recv with a hard timeout, and
    // on expiry ABORT the round-trip task (real cancellation, no leaked
    // future) and CLOSE the connection so the reconnect state machine
    // re-establishes against the candidate address set instead of reusing a
    // blackholed socket forever.
    match crate::block_on_sync_timeout_abortable(
        crate::quic_bridge::quic_send_and_recv_impl(conn.clone(), stream_type, body_json.clone()),
        std::time::Duration::from_secs(crate::network_api::QUIC_IO_TIMEOUT_SECS),
    ) {
        Some(Ok(s)) => Ok(s),
        Some(Err(e)) => Err(e),
        None => {
            if let Some(key) = peer {
                crate::quic_bridge::close_peer(&key);
            }
            Err(KyberError::NetworkError(format!(
                "QUIC send/recv timed out after {}s — connection closed for reconnect",
                crate::network_api::QUIC_IO_TIMEOUT_SECS
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: STUN SSRF — private/reserved IPs must be rejected.
    #[test]
    fn test_stun_ssrf_blocklist() {
        for bad in [
            "127.0.0.1:19302",
            "10.0.0.1:19302",
            "192.168.1.1:19302",
            "172.16.0.1:19302",
            "169.254.1.1:19302",
            "0.0.0.0:19302",
        ] {
            assert!(validate_stun_host(bad).is_err(), "{bad} should be rejected");
        }
        // Public STUN servers must pass
        for good in [
            "stun.l.google.com:19302",
            "8.8.8.8:19302",
            "stun.cloudflare.com:3478",
        ] {
            assert!(validate_stun_host(good).is_ok(), "{good} should be allowed");
        }
    }

    /// A hostname that resolves to a private address must be rejected (the
    /// old literal-IP-only check let this through).
    #[test]
    fn test_stun_hostname_resolution_rejected() {
        for host in ["localhost:19302", "ip6-localhost:19302"] {
            assert!(
                validate_stun_host(host).is_err(),
                "{host} should be rejected"
            );
        }
    }

    /// Certificate pins must be structurally valid 64-char hex digests — a
    /// random string must never bypass the SSRF guard.
    #[test]
    fn test_cert_pin_structural_validation() {
        let valid = "a".repeat(64);
        assert!(validate_cert_pin(&valid));
        assert!(!validate_cert_pin(""));
        assert!(!validate_cert_pin(&"a".repeat(63))); // 63 chars
        assert!(!validate_cert_pin(&"a".repeat(65))); // 65 chars
        assert!(!validate_cert_pin(&"zz".repeat(32))); // not hex
    }
}
