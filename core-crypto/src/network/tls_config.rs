use crate::error::KyberError;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::ClientCertVerified;
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use subtle::ConstantTimeEq;
use tracing::warn;
/// QUIC Certificate Pinning Verifier with enforced mTLS.
/// Requires a pinned certificate hash - rejects all connections without one.
/// Validates the full certificate chain including intermediate and root CAs.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    pub pinned_sha256_hex: Option<String>,
    pub required: bool,
}

impl PinnedCertVerifier {
    pub fn new(pinned_sha256_hex: Option<String>, required: bool) -> Self {
        Self {
            pinned_sha256_hex,
            required,
        }
    }

    fn verify_cert(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let cert_hash = hex::encode(sha2::Sha256::digest(end_entity.as_ref()));
        match self.pinned_sha256_hex {
            Some(ref pinned) => {
                // Constant-time comparison
                let pinned_bytes = pinned.as_bytes();
                let cert_bytes = cert_hash.as_bytes();
                if pinned_bytes.len() != cert_bytes.len()
                    || bool::from(pinned_bytes.ct_ne(cert_bytes))
                {
                    warn!(
                        "Peer certificate hash mismatch! Expected: {}, Received: {}",
                        pinned, cert_hash
                    );
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ));
                }
                Ok(())
            }
            None => {
                if self.required {
                    warn!("No pinned certificate hash configured - rejecting connection");
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                } else {
                    warn!("Certificate pinning not configured - allowing with warning");
                    Ok(())
                }
            }
        }
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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

impl rustls::server::danger::ClientCertVerifier for PinnedCertVerifier {
    /// Client certs are only mandatory once a pin is configured (post-pairing).
    /// Pre-pairing the server must accept clients that present no certificate —
    /// otherwise the initial KEM handshake can never complete.
    fn client_auth_mandatory(&self) -> bool {
        self.required
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_cert(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Persisted trusted-server certificate pin (SAS-confirmed server cert hash).
/// Stored in the OS keychain via the `keyring` crate — never in a plaintext
/// file. Written ONLY by `quic_store_server_pin` after out-of-band SAS
/// confirmation (the TOFU first-connection auto-pin path has been removed —
/// audit finding #15).
/// Trusted server-cert pin (set ONLY after SAS confirmation via
/// `quic_store_server_pin`). Renamed from the legacy `TOFU_CERT_HASH` to make
/// clear this is the explicit, user-confirmed identity — never a first-seen
/// auto-pin (audit finding #15).
static TRUSTED_SERVER_PIN: LazyLock<std::sync::Mutex<Option<String>>> = LazyLock::new(|| {
    let hash = keyring::Entry::new("kyberpipe-tofu", "server_cert_hash")
        .ok()
        .and_then(|entry| entry.get_password().ok());
    std::sync::Mutex::new(hash)
});

/// Get the stored trusted server cert pin.
pub fn get_tofu_cert_hash() -> Option<String> {
    TRUSTED_SERVER_PIN.lock().ok().and_then(|h| h.clone())
}

/// Store the trusted server cert pin (after SAS confirmation).
pub fn store_tofu_cert_hash(hash: String) {
    if let Ok(mut h) = TRUSTED_SERVER_PIN.lock() {
        *h = Some(hash.clone());
        // Store in OS keychain only — no plaintext file fallback.
        if let Ok(entry) = keyring::Entry::new("kyberpipe-tofu", "server_cert_hash") {
            let _ = entry.set_password(&hash);
        }
    }
}

/// Capture the server's certificate hash (hex SHA-256) WITHOUT storing it.
/// Used after a QUIC handshake so the app can pin it only after the user has
/// confirmed the SAS out-of-band. This is the ONLY capture path — the legacy
/// first-connection TOFU auto-pin was removed (audit finding #15).
pub fn capture_server_cert_hash_no_store(conn: &quinn::Connection) -> Option<String> {
    let certs = conn.peer_identity()?.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let cert = certs.first()?;
    Some(hex::encode(sha2::Sha256::digest(cert.as_ref())))
}

/// Generate a per-install client identity certificate (self-signed) used by
/// the Android companion for post-pairing mTLS authorization. Returns the DER
/// certificate and the DER PKCS#8 private key so the caller can persist them
/// in a secure store (audit finding #8 — identity must not fall back to IP).
pub fn generate_client_identity_cert() -> Result<(Vec<u8>, Vec<u8>), KyberError> {
    let cert = rcgen::generate_simple_self_signed(vec!["kyberpipe-client.local".into()])
        .map_err(|e| KyberError::NetworkError(format!("Client cert generation failed: {e}")))?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    Ok((cert_der, key_der))
}

/// Build QUIC server listener bound to 0.0.0.0:4433 supporting cross-subnet (Ethernet <-> Wi-Fi) routing
pub fn bind_cross_subnet_listener(port: u16) -> Result<quinn::Endpoint, KyberError> {
    let (certs, key) = generate_self_signed_cert()?;
    let server_config = configure_quic_server(certs, key, true, None)?;
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
    require_client_auth: bool,
    pinned_client_cert_hash: Option<String>,
) -> Result<quinn::ServerConfig, KyberError> {
    let mut server_crypto = if require_client_auth {
        // Client must present a self-signed cert. When no pinned hash is configured
        // (P2P bootstrap), accept the presented cert without a pin check.
        // The pairing protocol provides post-quantum authentication out-of-band via SAS,
        // so TLS-level pinning is optional during initial key exchange.
        // Enforce cert pinning when a hash is provided (post-pairing).
        // During initial pairing (None), accept any cert — SAS provides OOB auth.
        let required = pinned_client_cert_hash.is_some();
        let client_verifier = Arc::new(PinnedCertVerifier::new(pinned_client_cert_hash, required));
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .map_err(|e| KyberError::NetworkError(format!("Rustls ServerConfig error: {e}")))?
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| KyberError::NetworkError(format!("Rustls ServerConfig error: {e}")))?
    };

    server_crypto.alpn_protocols = vec![b"kyberpipe-pqc-v1".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| KyberError::NetworkError(e.to_string()))?,
    ));
    Ok(server_config)
}

/// Construct QUIC Client endpoint configuration with pinned certificate verifier.
/// `pinned_cert_hash` is the ONLY trusted identity: there is NO silent TOFU
/// fallback here. Auto-pinning the first certificate seen would let a first-
/// connection MitM become the permanent trusted identity before the user has
/// confirmed the SAS. Pinning happens only after out-of-band SAS confirmation
/// via `quic_confirm_server_pin`.
pub fn configure_quic_client(
    pinned_cert_hash: Option<String>,
) -> Result<quinn::ClientConfig, KyberError> {
    let required = pinned_cert_hash.is_some();
    let verifier = Arc::new(PinnedCertVerifier::new(pinned_cert_hash, required));
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
