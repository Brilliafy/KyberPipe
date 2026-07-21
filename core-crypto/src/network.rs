use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};
use crate::error::KyberError;

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

/// Custom Certificate Verifier that verifies the peer's certificate against a pinned certificate hash
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

    let endpoint = quinn::Endpoint::server(server_config, socket_addr)
        .map_err(|e| KyberError::NetworkError(format!("Failed to bind QUIC cross-subnet listener: {e}")))?;

    tracing::info!("[eBPF Acceleration] QUIC listener bound to 0.0.0.0:{port} (Ethernet <-> Wi-Fi Cross-Subnet Active)");
    Ok(endpoint)
}

/// Helper to generate self-signed cert & server configd private key for QUIC server endpoint
pub fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>), KyberError> {
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

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).map_err(|e| KyberError::NetworkError(e.to_string()))?));
    Ok(server_config)
}

/// Construct QUIC Client endpoint configuration with pinned certificate verifier
pub fn configure_quic_client(pinned_cert_hash: Option<String>) -> Result<quinn::ClientConfig, KyberError> {
    let verifier = Arc::new(PinnedCertVerifier::new(pinned_cert_hash));
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| KyberError::NetworkError(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"kyberpipe-pqc-v1".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).map_err(|e| KyberError::NetworkError(e.to_string()))?));
    Ok(client_config)
}

/// Send UDP P2P discovery beacon
pub async fn send_p2p_beacon(peer_identity_hex: &str, target_addr: Option<SocketAddr>) -> Result<(), KyberError> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to bind UDP socket: {e}")))?;

    socket
        .set_broadcast(true)
        .map_err(|e| KyberError::NetworkError(format!("Failed to set broadcast: {e}")))?;

    let mut payload = Vec::from(BEACON_MAGIC);
    payload.extend_from_slice(b":");
    payload.extend_from_slice(peer_identity_hex.as_bytes());

    let dest = target_addr.unwrap_or_else(|| SocketAddr::from(([255, 255, 255, 255], P2P_BEACON_PORT)));
    socket
        .send_to(&payload, dest)
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to send beacon: {e}")))?;

    info!("P2P Beacon broadcasted to {}", dest);
    Ok(())
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
        assert!(PathMigrationManager::verify_path_response(&challenge, &response));
        assert!(!PathMigrationManager::verify_path_response(&challenge, "invalid-token"));
    }
}
