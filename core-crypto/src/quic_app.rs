use crate::error::KyberError;
use crate::network;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{info, warn};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Stream type identifiers for multiplexed QUIC application protocol
pub const STREAM_PAIRING: u8 = 0x01;
pub const STREAM_CLIPBOARD: u8 = 0x02;
pub const STREAM_MEDIA: u8 = 0x03;
pub const STREAM_POLL: u8 = 0x04;
pub const STREAM_UNPAIR: u8 = 0x05;

/// Maximum message body size (16 MB)
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

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

impl QuicAppManager {
    pub async fn bind_server(port: u16) -> Result<Endpoint, KyberError> {
        let (certs, key) = network::generate_self_signed_cert()?;
        let server_config = network::configure_quic_server(certs, key, true)?;
        let socket_addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        let endpoint = Endpoint::server(server_config, socket_addr)
            .map_err(|e| KyberError::NetworkError(format!("QUIC server bind failed: {e}")))?;
        info!("QUIC app server bound to port {port}");
        Ok(endpoint)
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
                    pinned_cert_hash,
                    true,
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

    pub async fn accept_loop(
        endpoint: &Endpoint,
        on_pairing: impl Fn(Vec<u8>) -> BoxFuture<Vec<u8>> + Send + Sync + 'static,
        on_clipboard: impl Fn(Vec<u8>) -> BoxFuture<Vec<u8>> + Send + Sync + 'static,
        on_media: impl Fn(Vec<u8>) -> BoxFuture<Vec<u8>> + Send + Sync + 'static,
        on_poll: impl Fn() -> BoxFuture<Vec<u8>> + Send + Sync + 'static,
        on_unpair: impl Fn() -> BoxFuture<()> + Send + Sync + 'static,
    ) -> Result<(), KyberError> {
        let pairing_cb = Arc::new(on_pairing);
        let clipboard_cb = Arc::new(on_clipboard);
        let media_cb = Arc::new(on_media);
        let poll_cb = Arc::new(on_poll);
        let unpair_cb = Arc::new(on_unpair);
        loop {
            let incoming = endpoint.accept().await;
            match incoming {
                Some(connecting) => {
                    let pairing_cb = pairing_cb.clone();
                    let clipboard_cb = clipboard_cb.clone();
                    let media_cb = media_cb.clone();
                    let poll_cb = poll_cb.clone();
                    let unpair_cb = unpair_cb.clone();
                    tokio::spawn(async move {
                        match connecting.await {
                            Ok(connection) => {
                                info!(
                                    "QUIC connection established: {}",
                                    connection.remote_address()
                                );
                                let pairing_cb = pairing_cb.clone();
                                let clipboard_cb = clipboard_cb.clone();
                                let media_cb = media_cb.clone();
                                let poll_cb = poll_cb.clone();
                                let unpair_cb = unpair_cb.clone();
                                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                                    let pairing_cb = pairing_cb.clone();
                                    let clipboard_cb = clipboard_cb.clone();
                                    let media_cb = media_cb.clone();
                                    let poll_cb = poll_cb.clone();
                                    let unpair_cb = unpair_cb.clone();
                                    tokio::spawn(async move {
                                        match Self::recv_frame(&mut recv).await {
                                            Ok(frame) => {
                                                let response = match frame.stream_type {
                                                    STREAM_PAIRING => {
                                                        let result = pairing_cb(frame.body).await;
                                                        QuicFrame {
                                                            stream_type: STREAM_PAIRING,
                                                            body: result,
                                                        }
                                                    }
                                                    STREAM_CLIPBOARD => {
                                                        let result = clipboard_cb(frame.body).await;
                                                        QuicFrame {
                                                            stream_type: STREAM_CLIPBOARD,
                                                            body: result,
                                                        }
                                                    }
                                                    STREAM_MEDIA => {
                                                        let result = media_cb(frame.body).await;
                                                        QuicFrame {
                                                            stream_type: STREAM_MEDIA,
                                                            body: result,
                                                        }
                                                    }
                                                    STREAM_POLL => {
                                                        let result = poll_cb().await;
                                                        QuicFrame {
                                                            stream_type: STREAM_POLL,
                                                            body: result,
                                                        }
                                                    }
                                                    STREAM_UNPAIR => {
                                                        unpair_cb().await;
                                                        QuicFrame {
                                                            stream_type: STREAM_UNPAIR,
                                                            body: vec![],
                                                        }
                                                    }
                                                    _ => QuicFrame {
                                                        stream_type: 0xFF,
                                                        body: b"Unknown stream type".to_vec(),
                                                    },
                                                };
                                                let _ =
                                                    Self::send_frame(&mut send, &response).await;
                                            }
                                            Err(e) => {
                                                warn!("QUIC recv frame error: {e}")
                                            }
                                        }
                                    });
                                }
                            }
                            Err(e) => warn!("QUIC connection handshake failed: {e}"),
                        }
                    });
                }
                None => break,
            }
        }
        Ok(())
    }
}
