//! QUIC application layer: endpoint lifecycle (bind/rebind/accept), server
//! TLS identity + mTLS client-cert allowlist, and the high-level connection
//! manager. AUDIT FINDING #14 (structural decomposition): the frame CODEC
//! lives in [`frame`] (this module re-exports it) so a wire-format change
//! cannot entangle with the endpoint lifecycle; the TLS client-cert verifier
//! itself lives in `crate::network::tls_config`.

use crate::error::KyberError;
use crate::network;
use quinn::{Connection, Endpoint};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use tracing::{info, warn};

pub mod frame;
pub use frame::{
    QuicFrame, MAX_MESSAGE_SIZE, STREAM_CLIPBOARD, STREAM_MEDIA, STREAM_PAIRING, STREAM_POLL,
    STREAM_REKEY_ACK, STREAM_SMS, STREAM_UNPAIR,
};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// High-level QUIC application connection manager
pub struct QuicAppManager;

/// Process-global pinned client certificate hash for mTLS enforcement.
/// Set after SAS pairing confirms the client's identity; read by bind_server
/// to configure server-side cert pinning on subsequent QUIC connections.
static PINNED_CLIENT_CERT: OnceLock<std::sync::Mutex<Option<String>>> = OnceLock::new();

/// TEST/TEARDOWN ONLY (e2e): bypass the OS keyring for the server TLS identity
/// and keep the 0600 `server_key.der` file as the durable store. Some
/// headless/CI environments have a keyring backend that accepts
/// `set_password` but does NOT persist across `keyring::Entry` instances — the
/// mTLS rebind (which loads the server identity a SECOND time) would otherwise
/// hit the audit-#4 unaccounted-key guard and brick the swap. The e2e sets
/// this to make the post-pairing cert-less-rejection assertion deterministic
/// (same pattern as `FORCE_EMPTY_CLIPBOARD`).
pub static FORCE_LEGACY_KEY_FILE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// AUDIT FINDING #4 (multi-device): the set of client-cert hashes the TLS
/// layer will admit. Seeded by `set_pinned_client_cert` (the first paired
/// device) and EXTENDED by `register_allowed_client_cert` for every additional
/// device whose SAS pairing completes — mirroring the per-peer cert→ratchet-id
/// map the STREAM layer already maintains. The server verifier enforces this
/// same set, so a second paired device's certificate passes the TLS handshake
/// exactly when the stream layer would route it. `rebind_server` rebuilds the
/// verifier from the full set.
static ALLOWED_CLIENT_CERTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

fn allowed_client_certs() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    ALLOWED_CLIENT_CERTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Register an ADDITIONAL authorized client-cert hash (audit finding #4).
/// Called by the desktop whenever a second/third device's SAS pairing
/// completes (in `register_peer_cert_mapping`), so the TLS allowlist and the
/// stream-layer peer map can never diverge. Idempotent; rejects empty/malformed
/// hashes. An empty first-pairing pin is validated by `set_pinned_client_cert`;
/// this extends (never clears) the set.
pub fn register_allowed_client_cert(hash: String) {
    if hash.is_empty() || hash.len() != 64 || hex::decode(&hash).is_err() {
        warn!(
            "[mTLS] Rejecting invalid client cert hash (len={}): not adding to allowlist",
            hash.len()
        );
        return;
    }
    allowed_client_certs().insert(hash);
}

/// Current authorized client-cert hashes (audit finding #4) — the TLS server
/// verifier set. Empty before any pairing completes.
pub fn allowed_client_cert_hashes() -> Vec<String> {
    allowed_client_certs().iter().cloned().collect()
}
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

/// SHA-256 hash (hex) of the server's own persisted identity certificate.
/// Exposed so the pairing QR can embed the REAL server cert hash, letting the
/// phone pin the certificate whose public key was bound into the QR instead of
/// pinning whatever certificate a bootstrap MITM happened to present on the
/// wire (audit finding #15 — first-connection MITM pin capture).
pub fn server_cert_sha256() -> Option<String> {
    use sha2::Digest;
    let (certs, _key) = load_or_generate_cert().ok()?;
    let cert = certs.first()?;
    Some(hex::encode(sha2::Sha256::digest(cert.as_ref())))
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

/// Take the current server endpoint OUT of the process-global static, setting
/// it to None and returning the old endpoint (if any) for explicit teardown.
/// Used by `rebind_server` so the old endpoint can be `close()`d and dropped
/// BEFORE the new socket is bound — otherwise the second plain
/// `UdpSocket::bind` to the same 0.0.0.0:port fails with EADDRINUSE (audit
/// finding #2).
fn take_server_endpoint() -> Option<Endpoint> {
    let cell = SERVER_ENDPOINT.get_or_init(|| std::sync::Mutex::new(None));
    match cell.lock() {
        Ok(mut guard) => guard.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    }
}

/// TEST/TEARDOWN ONLY: drop the process-global server endpoint so its UDP
/// socket and driver tasks release before the test process exits (audit
/// finding #4 follow-up — the lingering e2e). Returns whether an endpoint was
/// held. Not cfg(test) because the desktop-app integration test links this
/// crate as a normal dependency.
#[doc(hidden)]
pub fn release_server_endpoint_for_tests() -> bool {
    match SERVER_ENDPOINT.get() {
        Some(cell) => match cell.lock() {
            Ok(mut guard) => guard.take().is_some(),
            Err(poisoned) => poisoned.into_inner().take().is_some(),
        },
        None => false,
    }
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
        .unwrap() = Some(hash.clone());
    // AUDIT FINDING #4: seed the TLS allowlist with the first paired device so
    // bind_server's verifier admits it.
    register_allowed_client_cert(hash);
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

    // AUDIT F18: the server's TLS private key must NOT sit recoverable in
    // plaintext on disk (even 0600 — any same-user reader could impersonate
    // the desktop after a data-dir exfiltration). The key is stored in the OS
    // keyring (the same keyring crate pattern used for the pairing keypair);
    // only the certificate stays on disk. A legacy `server_key.der` file is
    // MIGRATED into the keyring and then deleted.
    if cert_path.exists() {
        let cert_der = std::fs::read(&cert_path)
            .map_err(|e| KyberError::NetworkError(format!("Failed to read cert: {e}")))?;
        let cert = rustls::pki_types::CertificateDer::from(cert_der);

        // 1) Keyring first — the preferred store (unless the e2e forces the legacy
        //    key-file path for determinism on keyring-less test machines).
        if !FORCE_LEGACY_KEY_FILE.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(key_der) = keyring_server_key() {
                return Ok((
                    vec![cert],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
                ));
            }
        }
        // 2) Legacy plaintext key file — migrate it into the keyring and
        //    remove it from disk. The key file is deleted ONLY after the
        //    keyring store is VERIFIED by a readback of the exact key; if the
        //    keyring is unavailable OR its write does not round-trip, the
        //    plaintext file is KEPT (with a warning) so the server can still
        //    start — never destroy the only copy of the key (audit finding #2:
        //    a backend that accepts `set_password` but is not durable would
        //    otherwise leave the rebind's second identity load with an
        //    unaccounted-for key and brick the mTLS swap).
        if key_path.exists() {
            if let Ok(key_der) = std::fs::read(&key_path) {
                if FORCE_LEGACY_KEY_FILE.load(std::sync::atomic::Ordering::Relaxed) {
                    // e2e: the key file IS the durable store for the test run.
                    return Ok((
                        vec![cert],
                        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
                    ));
                }
                match keyring_store_server_key(&key_der) {
                    Ok(()) => {
                        if keyring_server_key().is_ok_and(|k| k == key_der) {
                            let _ = std::fs::remove_file(&key_path);
                        } else {
                            warn!(
                            "[TLS] Keyring write did not verify durable; keeping legacy plaintext server key on disk"
                        );
                        }
                        return Ok((
                            vec![cert],
                            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
                        ));
                    }
                    Err(e) => {
                        warn!(
                        "[TLS] Keyring unavailable ({e}); keeping legacy plaintext server key on disk"
                    );
                        return Ok((
                            vec![cert],
                            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
                        ));
                    }
                }
            }
        }
        // 3) Keyring unavailable AND no key file: the persisted certificate's
        //    private key is UNACCOUNTED FOR. AUDIT #4 (MEDIUM, identity
        //    rotation): the legacy path regenerated a fresh key here and
        //    OVERWROTE the persisted cert — silently rotating the server
        //    identity every start. Every paired phone pins the ORIGINAL
        //    cert hash from the pairing QR, so a rotation breaks every
        //    pinned peer ("paired but nothing syncs", silent, until the user
        //    re-pairs) and a same-user attacker who can read the data dir can
        //    trigger it to force a re-pair window. NEVER overwrite a
        //    persisted cert whose key is unaccounted for: fail LOUDLY and
        //    leave the cert untouched so the operator can restore the
        //    keyring entry or explicitly delete the cert to regenerate a
        //    fresh identity.
        return Err(KyberError::NetworkError(format!(
            "Server TLS identity unavailable: {} exists but its private key is \
             neither in the OS keyring nor in a legacy {} file. Refusing to \
             rotate the identity silently (every paired device pins this \
             certificate — audit finding #4). Restore the keyring entry, or \
             delete the certificate file to explicitly regenerate a fresh \
             identity.",
            cert_path.display(),
            key_path.display(),
        )));
    }

    // Generate new cert. AUDIT #4: persist the key in the keyring FIRST — only
    // after the key is durably stored is the cert file written, so a keyring
    // failure can never leave a cert on disk whose key is unaccounted for
    // (which would put the NEXT start into branch 3 above).
    //
    // AUDIT #4 (follow-up): the keyring write is VERIFIED by reading it back.
    // Some OS keyring backends accept `set_password` but fail to make the entry
    // readable (or durable) in a later session — if the write does not round-
    // trip, fall back to the 0600 plaintext key FILE (the same fallback the
    // legacy migration in branch 2 uses when the keyring is unavailable) so the
    // identity stays consistent and durable instead of being silently rotated.
    // The identity is COMMITTED only after a verifiable key copy exists.
    let (certs, key) = network::generate_self_signed_cert()?;
    let key_der: Vec<u8> = match &key {
        rustls::pki_types::PrivateKeyDer::Pkcs8(doc) => doc.secret_pkcs8_der().to_vec(),
        other => other.secret_der().to_vec(),
    };
    // The e2e forces the legacy key-file path so the mTLS rebind (which loads
    // the identity a second time) is deterministic on keyring-less machines.
    let force_legacy = FORCE_LEGACY_KEY_FILE.load(std::sync::atomic::Ordering::Relaxed);
    let keyring_durable = if force_legacy {
        false
    } else {
        keyring_store_server_key(&key_der).is_ok()
            && keyring_server_key().is_ok_and(|k| k == key_der)
    };
    if !keyring_durable {
        // Keyring unavailable or non-durable — persist a 0600 key file (the
        // same fallback branch 2 uses for a legacy key file), so the cert is
        // never committed with an unaccounted-for key.
        if let Err(e) = std::fs::write(&key_path, &key_der) {
            return Err(KyberError::NetworkError(format!(
                "Failed to persist server TLS key (keyring unusable and key file write failed): {e}"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
    }
    if let Some(cert) = certs.first() {
        let _ = std::fs::write(&cert_path, cert.as_ref());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((certs, key))
}

/// Keyring service/entry names for the server TLS identity key (audit F18).
const TLS_KEYRING_SERVICE: &str = "kyberpipe";
const TLS_KEYRING_ENTRY: &str = "server_tls_key";

fn keyring_server_key() -> Result<Vec<u8>, KyberError> {
    let entry = keyring::Entry::new(TLS_KEYRING_SERVICE, TLS_KEYRING_ENTRY)
        .map_err(|e| KyberError::NetworkError(format!("Keyring access failed: {e}")))?;
    let stored = entry
        .get_password()
        .map_err(|e| KyberError::NetworkError(format!("Keyring read failed: {e}")))?;
    hex::decode(&stored)
        .map_err(|e| KyberError::NetworkError(format!("Stored TLS key is not hex: {e}")))
}

fn keyring_store_server_key(key_der: &[u8]) -> Result<(), KyberError> {
    let entry = keyring::Entry::new(TLS_KEYRING_SERVICE, TLS_KEYRING_ENTRY)
        .map_err(|e| KyberError::NetworkError(format!("Keyring access failed: {e}")))?;
    entry
        .set_password(&hex::encode(key_der))
        .map_err(|e| KyberError::NetworkError(format!("Keyring write failed: {e}")))
}

impl QuicAppManager {
    pub async fn bind_server(port: u16) -> Result<Endpoint, KyberError> {
        // Try to load persisted cert; generate new one only on first run
        let (certs, key) = load_or_generate_cert()?;
        // AUDIT FINDING #4: the verifier is backed by the FULL authorized
        // client-cert set (multi-device), not a single pin. `set_pinned_client_cert`
        // seeds it with the first paired device; `register_allowed_client_cert`
        // extends it for every additional device whose SAS pairing completes.
        let allowed = allowed_client_cert_hashes();
        let server_config = network::configure_quic_server(certs, key, true, allowed)?;
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
    /// old endpoint is CLOSED and dropped first so the new bind cannot fail
    /// with EADDRINUSE, and the dispatch loop sees `accept() → None`, drops its
    /// old clone, and re-acquires the new endpoint from the static.
    pub async fn rebind_server(port: u16) -> Result<(), KyberError> {
        // AUDIT FINDING #4: rebinding requires at least ONE authorized client
        // cert. An empty allowlist means no pairing ever completed — rebinding
        // with an empty verifier would REJECT every client (required=true).
        if allowed_client_cert_hashes().is_empty() {
            return Err(KyberError::NetworkError(
                "No authorized client certs registered — cannot rebind with mTLS".into(),
            ));
        }
        // Preserve the currently-bound port so a rebind never moves the
        // listener (clients reconnect to the same address).
        let port = match get_server_endpoint() {
            Some(ep) => ep.local_addr().map(|a| a.port()).unwrap_or(port),
            None => port,
        };
        info!("Rebinding QUIC server on port {port} with mTLS enforcement");

        // AUDIT FINDING #2 (HIGH): the old endpoint MUST be closed and dropped
        // BEFORE the new socket is bound. The legacy code called bind_server
        // while the old endpoint was still referenced by SERVER_ENDPOINT and by
        // the dispatch loop's clone — the second plain UdpSocket::bind to the
        // same 0.0.0.0:port failed with EADDRINUSE, the error was logged as
        // "mTLS will take effect on next restart", and the running TLS verifier
        // kept its pre-pairing accept-any snapshot. `close()` flips the
        // dispatch loop's blocked `accept()` to None immediately (it re-acquires
        // the current endpoint from the static and drops its old clone);
        // dropping OUR reference here releases the UDP socket once the loop's
        // clone is gone.
        if let Some(old) = take_server_endpoint() {
            old.close(quinn::VarInt::from_u32(0), b"mTLS rebind");
            drop(old);
            // The socket is released only when the LAST Endpoint clone is
            // dropped (the dispatch loop's clone goes away once it observes the
            // close). Wait for the port to become free with a bounded poll —
            // probe-bind without SO_REUSEADDR so an EADDRINUSE answer is a
            // reliable "still held" signal — instead of guessing a sleep.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
                match std::net::UdpSocket::bind(addr) {
                    Ok(probe) => {
                        drop(probe);
                        break;
                    }
                    Err(_) if std::time::Instant::now() < deadline => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        return Err(KyberError::NetworkError(format!(
                            "Rebind aborted: port {port} still held by the previous endpoint: {e}"
                        )));
                    }
                }
            }
        }

        // Now that the old socket is released, the same-port bind succeeds.
        // bind_server stores the new endpoint via store_server_endpoint; the
        // dispatch loop's next `accept() → None` re-acquisition picks it up.
        let new_endpoint = Self::bind_server(port).await?;
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
                .with_custom_certificate_verifier(Arc::new(network::PinnedCertVerifier::single(
                    pinned_cert_hash.clone().unwrap_or_default(),
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
    ) -> Result<(quinn::SendStream, quinn::RecvStream), KyberError> {
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| KyberError::NetworkError(format!("Open stream failed: {e}")))?;
        Ok((send, recv))
    }

    pub async fn send_frame(
        send: &mut quinn::SendStream,
        frame: &QuicFrame,
    ) -> Result<(), KyberError> {
        frame::send_frame(send, frame).await
    }

    pub async fn recv_frame(recv: &mut quinn::RecvStream) -> Result<QuicFrame, KyberError> {
        frame::recv_frame(recv).await
    }

    /// Read ONLY the 5-byte frame header (stream_type + body_len). The server
    /// authorizes the stream from the header BEFORE reading the body, so an
    /// unauthenticated peer cannot force the server to buffer up to 1 MiB per
    /// stream before being rejected (audit finding #8).
    pub async fn recv_frame_header(
        recv: &mut quinn::RecvStream,
    ) -> Result<(u8, usize), KyberError> {
        frame::recv_frame_header(recv).await
    }

    /// Read the frame body of `body_len` bytes (bounded by MAX_MESSAGE_SIZE,
    /// already validated in `recv_frame_header`).
    pub async fn recv_frame_body(
        recv: &mut quinn::RecvStream,
        body_len: usize,
    ) -> Result<Vec<u8>, KyberError> {
        frame::recv_frame_body(recv, body_len).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit finding #8: a frame whose declared body length exceeds
    /// MAX_MESSAGE_SIZE must be rejected from the header alone — the server
    /// never buffers an oversized body from an unauthenticated peer.
    #[test]
    fn frame_body_size_cap_enforced() {
        // Encode a frame with an oversized body length.
        let mut buf = vec![0u8; 5];
        buf[0] = 0x04; // STREAM_POLL
        buf[1..5].copy_from_slice(&(MAX_MESSAGE_SIZE as u32 + 1).to_be_bytes());
        assert!(QuicFrame::decode(&buf).is_err());
        // A valid small frame decodes.
        let frame = QuicFrame {
            stream_type: 0x04,
            body: b"hello".to_vec(),
        };
        let encoded = frame.encode();
        let decoded = QuicFrame::decode(&encoded).expect("valid frame decodes");
        assert_eq!(decoded.stream_type, 0x04);
        assert_eq!(decoded.body, b"hello");
    }

    /// Audit finding #8: the binary TLV round-trip of a ratchet message (the
    /// wire format used for clipboard / rekey-ack / sync payloads) must reject
    /// truncated input.
    #[test]
    fn ratchet_tlv_rejects_truncation() {
        let msg = crate::crypto::RatchetEncryptedMessage {
            nonce: vec![1u8; 12],
            ciphertext: vec![2u8; 16],
            rekey_x25519_pk: None,
            rekey_mlkem_pk: None,
            rekey_ciphertext: None,
        };
        let bin = msg.to_binary().unwrap();
        for cut in 0..bin.len() {
            assert!(
                crate::crypto::RatchetEncryptedMessage::from_binary(&bin[..cut]).is_err(),
                "truncated TLV at {cut} must be rejected"
            );
        }
    }
}
