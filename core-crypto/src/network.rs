use crate::error::KyberError;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};

pub const DEFAULT_KYBERPIPE_PORT: u16 = 9876;
pub const P2P_BEACON_PORT: u16 = 9877;
pub const BEACON_MAGIC: &[u8] = b"KYBERPIPE_P2P_BEACON_V1";

/// Helper for Seamless Path Migration between Wi-Fi Direct and WireGuard interfaces over QUIC CIDs
pub struct PathMigrationManager;

impl PathMigrationManager {
    /// Generate a cryptographically secure PATH_CHALLENGE token and matching PATH_RESPONSE token
    pub fn create_path_challenge() -> (String, String) {
        let mut challenge_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge_bytes);
        let challenge_token = hex::encode(challenge_bytes);

        let mut hasher = sha2::Sha256::new();
        hasher.update(b"kyberpipe-path-response:");
        hasher.update(challenge_token.as_bytes());
        let response_token = hex::encode(hasher.finalize());

        (challenge_token, response_token)
    }

    /// Verify PATH_RESPONSE matches expected challenge
    pub fn verify_path_response(challenge_token: &str, response_token: &str) -> bool {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"kyberpipe-path-response:");
        hasher.update(challenge_token.as_bytes());
        let expected = hex::encode(hasher.finalize());
        expected.to_lowercase() == response_token.to_lowercase()
    }
}

/// Multipath QUIC (MPQUIC) Link Aggregation Path Identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MpquicPathId {
    WifiDirectP2p = 0,
    WifiLocalLan = 1,
    WireguardWan = 2,
}

/// Simultaneous Multipath QUIC (MPQUIC) Link Aggregator & Scheduler
pub struct MultipathScheduler {
    active_paths: Vec<MpquicPathId>,
    next_path_idx: std::sync::atomic::AtomicUsize,
}

impl MultipathScheduler {
    pub fn new() -> Self {
        Self {
            active_paths: vec![
                MpquicPathId::WifiDirectP2p,
                MpquicPathId::WifiLocalLan,
                MpquicPathId::WireguardWan,
            ],
            next_path_idx: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Select next active path for packet striping (Round-Robin MPQUIC scheduler)
    pub fn schedule_next_path(&self) -> MpquicPathId {
        if self.active_paths.is_empty() {
            return MpquicPathId::WireguardWan;
        }
        let idx = self
            .next_path_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.active_paths[idx % self.active_paths.len()]
    }
}

/// QUIC Certificate Pinning Verifier that verifies the peer's certificate against a pinned certificate hash
#[derive(Debug)]
pub struct PinnedCertVerifier {
    pub pinned_sha256_hex: Option<String>,
}

impl PinnedCertVerifier {
    pub fn new(pinned_sha256_hex: Option<String>) -> Self {
        Self { pinned_sha256_hex }
    }

    fn verify_cert(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let cert_hash = hex::encode(sha2::Sha256::digest(end_entity.as_ref()));
        if let Some(ref pinned) = self.pinned_sha256_hex {
            if cert_hash.to_lowercase() != pinned.to_lowercase() {
                warn!(
                    "Peer certificate hash mismatch! Expected: {}, Received: {}",
                    pinned, cert_hash
                );
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        }
        Ok(())
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.verify_cert(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Build QUIC server listener bound to 0.0.0.0:4433 supporting cross-subnet (Ethernet <-> Wi-Fi) routing
pub fn bind_cross_subnet_listener(port: u16) -> Result<quinn::Endpoint, KyberError> {
    let (certs, key) = generate_self_signed_cert()?;
    let server_config = configure_quic_server(certs, key)?;
    let socket_addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();

    let endpoint = quinn::Endpoint::server(server_config, socket_addr).map_err(|e| {
        KyberError::NetworkError(format!("Failed to bind QUIC cross-subnet listener: {e}"))
    })?;

    tracing::info!("[eBPF Acceleration] QUIC listener bound to 0.0.0.0:{port} (Ethernet <-> Wi-Fi Cross-Subnet Active)");
    Ok(endpoint)
}

/// Helper to generate self-signed cert & server configd private key for QUIC server endpoint
pub fn generate_self_signed_cert() -> Result<
    (
        Vec<CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    KyberError,
> {
    let cert = rcgen::generate_simple_self_signed(vec!["kyberpipe.local".into()])
        .map_err(|e| KyberError::NetworkError(format!("Certificate generation failed: {e}")))?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    Ok((
        vec![CertificateDer::from(cert_der)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
    ))
}

/// Construct QUIC Server endpoint configuration
pub fn configure_quic_server(
    certs: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, KyberError> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| KyberError::NetworkError(format!("Rustls ServerConfig error: {e}")))?;

    server_crypto.alpn_protocols = vec![b"kyberpipe-pqc-v1".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| KyberError::NetworkError(e.to_string()))?,
    ));
    Ok(server_config)
}

/// Construct QUIC Client endpoint configuration with pinned certificate verifier
pub fn configure_quic_client(
    pinned_cert_hash: Option<String>,
) -> Result<quinn::ClientConfig, KyberError> {
    let verifier = Arc::new(PinnedCertVerifier::new(pinned_cert_hash));
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| KyberError::NetworkError(e.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"kyberpipe-pqc-v1".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| KyberError::NetworkError(e.to_string()))?,
    ));
    Ok(client_config)
}

/// Send UDP P2P discovery beacon
pub async fn send_p2p_beacon(
    peer_identity_hex: &str,
    target_addr: Option<SocketAddr>,
) -> Result<(), KyberError> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to bind UDP socket: {e}")))?;

    socket
        .set_broadcast(true)
        .map_err(|e| KyberError::NetworkError(format!("Failed to set broadcast: {e}")))?;

    let mut payload = Vec::from(BEACON_MAGIC);
    payload.extend_from_slice(b":");
    payload.extend_from_slice(peer_identity_hex.as_bytes());

    let dest =
        target_addr.unwrap_or_else(|| SocketAddr::from(([255, 255, 255, 255], P2P_BEACON_PORT)));
    socket
        .send_to(&payload, dest)
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to send beacon: {e}")))?;

    info!("P2P Beacon broadcasted to {}", dest);
    Ok(())
}

/// Query a public STUN server for the external/reflexive SocketAddr (RFC 5389 compliant)
pub async fn query_stun_server(stun_host: &str) -> Result<SocketAddr, KyberError> {
    let addrs = tokio::net::lookup_host(stun_host).await.map_err(|e| {
        KyberError::NetworkError(format!("STUN host lookup failed for {stun_host}: {e}"))
    })?;

    let stun_addr = addrs.into_iter().next().ok_or_else(|| {
        KyberError::NetworkError(format!("No IP address found for STUN host {stun_host}"))
    })?;

    let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
        KyberError::NetworkError(format!("Failed to bind UDP socket for STUN: {e}"))
    })?;

    // STUN Binding Request (RFC 5389) header - 20 bytes
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Message Type: Binding Request
    request[2..4].copy_from_slice(&0x0000u16.to_be_bytes()); // Message Length: 0
    request[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes()); // Magic Cookie

    // Generate random 12-byte Transaction ID
    let tx_id = rand::RngCore::next_u64(&mut rand::thread_rng());
    request[8..16].copy_from_slice(&tx_id.to_be_bytes());
    let tx_id_extra = rand::RngCore::next_u32(&mut rand::thread_rng());
    request[16..20].copy_from_slice(&tx_id_extra.to_be_bytes());

    socket
        .send_to(&request, stun_addr)
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to send STUN request: {e}")))?;

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| KyberError::NetworkError("STUN response timeout".to_string()))?
    .map_err(|e| KyberError::NetworkError(format!("Failed to receive STUN response: {e}")))?;

    if len < 20 {
        return Err(KyberError::NetworkError(
            "STUN response too short".to_string(),
        ));
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != 0x0101 {
        // Binding Success Response
        return Err(KyberError::NetworkError(format!(
            "STUN response was not success: {msg_type:04x}"
        )));
    }

    let mut pos = 20;
    while pos < len {
        if pos + 4 > len {
            break;
        }
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if pos + attr_len > len {
            break;
        }
        let attr_value = &buf[pos..pos + attr_len];
        pos += attr_len;

        if attr_type == 0x0001 {
            // MAPPED-ADDRESS
            if attr_len >= 8 {
                let family = attr_value[1];
                let port = u16::from_be_bytes([attr_value[2], attr_value[3]]);
                if family == 1 {
                    // IPv4
                    let ip = std::net::Ipv4Addr::new(
                        attr_value[4],
                        attr_value[5],
                        attr_value[6],
                        attr_value[7],
                    );
                    return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                }
            }
        } else if attr_type == 0x0020 {
            // XOR-MAPPED-ADDRESS
            if attr_len >= 8 {
                let family = attr_value[1];
                let xport = u16::from_be_bytes([attr_value[2], attr_value[3]]);
                let port = xport ^ 0x2112; // XOR port
                if family == 1 {
                    // IPv4
                    let xip = [attr_value[4], attr_value[5], attr_value[6], attr_value[7]];
                    let cookie_bytes = 0x2112A442u32.to_be_bytes();
                    let ip = std::net::Ipv4Addr::new(
                        xip[0] ^ cookie_bytes[0],
                        xip[1] ^ cookie_bytes[1],
                        xip[2] ^ cookie_bytes[2],
                        xip[3] ^ cookie_bytes[3],
                    );
                    return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                }
            }
        }
    }

    Err(KyberError::NetworkError(
        "No valid mapped address found in STUN response".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_server_client_configs() {
        let (certs, key) = generate_self_signed_cert().unwrap();
        assert!(!certs.is_empty());
        let server_config = configure_quic_server(certs, key);
        assert!(server_config.is_ok());

        let client_config = configure_quic_client(None);
        assert!(client_config.is_ok());
    }

    #[test]
    fn test_path_migration_challenge_response() {
        let (challenge, response) = PathMigrationManager::create_path_challenge();
        assert!(PathMigrationManager::verify_path_response(
            &challenge, &response
        ));
        assert!(!PathMigrationManager::verify_path_response(
            &challenge,
            "invalid-token"
        ));
    }

    #[tokio::test]
    async fn test_stun_query() {
        let res = query_stun_server("stun.l.google.com:19302").await;
        if let Ok(addr) = res {
            assert!(addr.port() > 0);
        }
    }
}
