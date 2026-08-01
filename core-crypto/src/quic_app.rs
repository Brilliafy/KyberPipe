use crate::error::KyberError;
use crate::network;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::io::AsyncReadExt;
use tracing::{info, warn};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Stream type identifiers for multiplexed QUIC application protocol
pub const STREAM_PAIRING: u8 = 0x01;
pub const STREAM_CLIPBOARD: u8 = 0x02;
pub const STREAM_MEDIA: u8 = 0x03;
pub const STREAM_POLL: u8 = 0x04;
pub const STREAM_UNPAIR: u8 = 0x05;
pub const STREAM_REKEY_ACK: u8 = 0x06;
pub const STREAM_SMS: u8 = 0x07;

/// Maximum message body size (1 MB) — clipboard/media payloads
pub const MAX_MESSAGE_SIZE: usize = 1 * 1024 * 1024;

/// Binary frame: [stream_type: 1B][body_len: 4B][body: body_len]
#[derive(Debug)]
pub struct QuicFrame {
    #[allow(dead_code)]
    pub stream_type: u8,
    pub body: Vec<u8>,
}

impl QuicFrame {
    pub fn encode(&self) -> Vec<u8> {
        let len = self.body.len() as u32;
        let mut buf = Vec::with_capacity(5 + self.body.len());
        buf.push(self.stream_type);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, KyberError> {
        if data.len() < 5 {
            return Err(KyberError::NetworkError("Frame too short".into()));
        }
        let stream_type = data[0];
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[1..5]);
        let body_len = u32::from_be_bytes(len_bytes) as usize;
        if body_len > MAX_MESSAGE_SIZE {
            return Err(KyberError::NetworkError(format!(
                "Frame body too large: {body_len} > {MAX_MESSAGE_SIZE}"
            )));
        }
        if data.len() < 5 + body_len {
            return Err(KyberError::NetworkError("Frame truncated".into()));
        }
        Ok(QuicFrame {
            stream_type,
            body: data[5..5 + body_len].to_vec(),
        })
    }
}

/// High-level QUIC application connection manager
pub struct QuicAppManager;

/// Process-global pinned client certificate hash for mTLS enforcement.
/// Set after SAS pairing confirms the client's identity; read by bind_server
/// to configure server-side cert pinning on subsequent QUIC connections.
static PINNED_CLIENT_CERT: OnceLock<std::sync::Mutex<Option<String>>> = OnceLock::new();
/// Process-global QUIC server endpoint. Swappable for mTLS rebind after pairing.
/// The accept loop reads from this; when rebind swaps the endpoint, the old
/// accept() returns an error and the loop restarts with the new endpoint.
static SERVER_ENDPOINT: OnceLock<std::sync::Mutex<Option<Endpoint>>> = OnceLock::new();

/// Get the current server endpoint (if any).
pub fn get_server_endpoint() -> Option<Endpoint> {
    SERVER_ENDPOINT
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|e| e.clone())
}

/// Extract the SHA-256 hash (hex) of the peer's end-entity certificate.
/// Returns None when the peer presented no certificate (e.g. unauthenticated
/// client) or the identity cannot be downcast to a certificate chain.
pub fn connection_peer_cert_hash(conn: &quinn::Connection) -> Option<String> {
    use sha2::Digest;
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let cert = certs.first()?;
    Some(hex::encode(sha2::Sha256::digest(cert.as_ref())))
}

/// Store a new server endpoint, returning the old one (if any) for cleanup.
fn store_server_endpoint(ep: Endpoint) -> Option<Endpoint> {
    let cell = SERVER_ENDPOINT.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = cell.lock().unwrap();
    let old = guard.take();
    *guard = Some(ep);
    old
}


/// Store the pinned client cert hash after successful SAS pairing and rebind
/// the server so mTLS enforcement takes effect IMMEDIATELY — not on the next
/// startup. Rejects empty/malformed hashes (audit findings #8/#8b: an empty
/// pin would reject every client and a deferred rebind leaves an
/// unauthenticated window).
pub fn set_pinned_client_cert(hash: String) {
    // A structurally invalid or empty pin must never be installed — doing so
    // would brick authorization for every future client.
    if hash.is_empty() || hash.len() != 64 || hex::decode(&hash).is_err() {
        warn!(
            "[mTLS] Rejecting invalid client cert pin (len={}): not installing",
            hash.len()
        );
        return;
    }
    *PINNED_CLIENT_CERT
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap() = Some(hash);
}

fn cert_dir() -> PathBuf {
    let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn load_or_generate_cert() -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    KyberError,
> {
    let cert_path = cert_dir().join("server_cert.der");
    let key_path = cert_dir().join("server_key.der");

    if cert_path.exists() && key_path.exists() {
        let cert_der = std::fs::read(&cert_path)
            .map_err(|e| KyberError::NetworkError(format!("Failed to read cert: {e}")))?;
        let key_der = std::fs::read(&key_path)
            .map_err(|e| KyberError::NetworkError(format!("Failed to read key: {e}")))?;

        let cert = rustls::pki_types::CertificateDer::from(cert_der);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());
        return Ok((vec![cert], key));
    }

    // Generate new cert and persist
    let (certs, key) = network::generate_self_signed_cert()?;
    if let Some(cert) = certs.first() {
        let _ = std::fs::write(&cert_path, cert.as_ref());
    }
    if let rustls::pki_types::PrivateKeyDer::Pkcs8(doc) = &key {
        let _ = std::fs::write(&key_path, doc.secret_pkcs8_der().as_ref());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((certs, key))
}

impl QuicAppManager {
    pub async fn bind_server(port: u16) -> Result<Endpoint, KyberError> {
        // Try to load persisted cert; generate new one only on first run
        let (certs, key) = load_or_generate_cert()?;
        let pinned = PINNED_CLIENT_CERT
            .get()
            .and_then(|m| m.lock().ok())
            .and_then(|h| h.clone());
        let server_config = network::configure_quic_server(certs, key, true, pinned)?;
        let socket_addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        let endpoint = Endpoint::server(server_config, socket_addr)
            .map_err(|e| KyberError::NetworkError(format!("QUIC server bind failed: {e}")))?;
        info!("QUIC app server bound to port {port}");
        // Store in shared static for dynamic rebind support
        store_server_endpoint(endpoint.clone());
        Ok(endpoint)
    }

    /// Rebind the server endpoint with updated pinned client certificate.
    /// Call after pairing completes to enforce mTLS on subsequent connections.
    /// Re-binds on the SAME port the server currently uses (the peer
    /// reconnects to the same address) and swaps the endpoint atomically — the
    /// old endpoint's `accept()` returns None, which triggers the dispatch loop
    /// to re-acquire the new endpoint and continue.
    pub async fn rebind_server(port: u16) -> Result<(), KyberError> {
        let pinned = PINNED_CLIENT_CERT
            .get()
            .and_then(|m| m.lock().ok())
            .and_then(|h| h.clone());
        if pinned.is_none() {
            return Err(KyberError::NetworkError(
                "No pinned client cert set — cannot rebind with mTLS".into(),
            ));
        }
        // Preserve the currently-bound port so a rebind never moves the
        // listener (clients reconnect to the same address).
        let port = match get_server_endpoint() {
            Some(ep) => ep.local_addr().map(|a| a.port()).unwrap_or(port),
            None => port,
        };
        info!("Rebinding QUIC server on port {port} with mTLS enforcement");
        let new_endpoint = Self::bind_server(port).await?;
        // bind_server already stored the new endpoint via store_server_endpoint.
        // The old endpoint (if any) was dropped by store_server_endpoint,
        // causing the accept loop to see `accept() → None` and restart with
        // the new endpoint.
        drop(new_endpoint);
        Ok(())
    }



    pub async fn connect(
        server_addr: std::net::SocketAddr,
        pinned_cert_hash: Option<String>,
        client_certs: Option<(
            Vec<rustls::pki_types::CertificateDer<'static>>,
            rustls::pki_types::PrivateKeyDer<'static>,
        )>,
    ) -> Result<Connection, KyberError> {
        let client_config = network::configure_quic_client(pinned_cert_hash.clone())?;
        if let Some((certs, key)) = client_certs {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| KyberError::NetworkError(e.to_string()))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(network::PinnedCertVerifier::new(
                    pinned_cert_hash.clone(),
                    pinned_cert_hash.is_some(),
                )))
                .with_client_auth_cert(certs, key)
                .map_err(|e| KyberError::NetworkError(format!("mTLS client config error: {e}")))?;
            config.alpn_protocols = vec![b"kyberpipe-pqc-v1".to_vec()];
            let quic_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(config)
                    .map_err(|e| KyberError::NetworkError(e.to_string()))?,
            ));
            let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| KyberError::NetworkError(format!("Endpoint create failed: {e}")))?;
            let connect = endpoint
                .connect_with(quic_config, server_addr, "kyberpipe.local")
                .map_err(|e| KyberError::NetworkError(format!("Connect failed: {e}")))?;
            let conn = connect
                .await
                .map_err(|e| KyberError::NetworkError(format!("Handshake failed: {e}")))?;
            Ok(conn)
        } else {
            let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| KyberError::NetworkError(format!("Endpoint create failed: {e}")))?;
            let connect = endpoint
                .connect_with(client_config, server_addr, "kyberpipe.local")
                .map_err(|e| KyberError::NetworkError(format!("Connect failed: {e}")))?;
            let conn = connect
                .await
                .map_err(|e| KyberError::NetworkError(format!("Handshake failed: {e}")))?;
            Ok(conn)
        }
    }

    pub async fn open_stream(
        conn: &Connection,
        _stream_type: u8,
    ) -> Result<(SendStream, RecvStream), KyberError> {
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| KyberError::NetworkError(format!("Open stream failed: {e}")))?;
        Ok((send, recv))
    }

    pub async fn send_frame(send: &mut SendStream, frame: &QuicFrame) -> Result<(), KyberError> {
        let data = frame.encode();
        send.write_all(&data)
            .await
            .map_err(|e| KyberError::NetworkError(format!("Send frame failed: {e}")))?;
        Ok(())
    }

    pub async fn recv_frame(recv: &mut RecvStream) -> Result<QuicFrame, KyberError> {
        let mut header = [0u8; 5];
        recv.read_exact(&mut header)
            .await
            .map_err(|e| KyberError::NetworkError(format!("Read frame header failed: {e}")))?;
        let stream_type = header[0];
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&header[1..5]);
        let body_len = u32::from_be_bytes(len_bytes) as usize;
        if body_len > MAX_MESSAGE_SIZE {
            return Err(KyberError::NetworkError(format!(
                "Frame body too large: {body_len}"
            )));
        }
        let mut body = Vec::with_capacity((body_len).min(8192));
        if body_len > 0 {
            let mut limited = recv.take(body_len as u64);
            limited
                .read_to_end(&mut body)
                .await
                .map_err(|e| KyberError::NetworkError(format!("Read frame body failed: {e}")))?;
            if body.len() != body_len {
                return Err(KyberError::NetworkError(format!(
                    "Frame body truncated: expected {body_len} bytes, got {}",
                    body.len()
                )));
            }
        }
        Ok(QuicFrame { stream_type, body })
    }
}

