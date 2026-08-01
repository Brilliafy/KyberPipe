use crate::error::KyberError;
use quinn::Connection;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Condvar, LazyLock, Mutex};

struct ConnConfig {
    addr: SocketAddr,
    pinned_cert_hash: Option<String>,
    /// Client identity certificate (DER cert + DER PKCS#8 key) presented on
    /// (re)connect for mTLS authorization post-pairing (audit finding #8).
    client_certs: Option<(Vec<u8>, Vec<u8>)>,
}

pub(crate) struct ManagedConnection {
    pub conn: Option<Connection>,
    config: Option<ConnConfig>,
    last_activity: std::time::Instant,
}

/// Peer identity key for the connection registry. A pinned cert hash is the
/// strong identity; before pairing (or when no pin is provided) we fall back to
/// "ip:port".
pub(crate) fn peer_key(addr: &SocketAddr, pinned_cert_hash: &Option<String>) -> String {
    pinned_cert_hash
        .clone()
        .unwrap_or_else(|| format!("{}:{}", addr.ip(), addr.port()))
}

/// Process-global QUIC connection REGISTRY keyed by peer identity. Unlike the
/// previous single global slot, this supports multiple simultaneous peers —
/// the mesh claim of the product.
static QUIC_CONNECTIONS: LazyLock<Mutex<HashMap<String, ManagedConnection>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The peer key most recently connected to / used. The legacy single-peer FFI
/// surface (`quic_send_and_recv` without a peer argument) routes through it.
static ACTIVE_PEER: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// Reconnect state machine: Idle → Reconnecting → Done/Error
#[derive(PartialEq)]
enum ReconnectState {
    Idle,
    Reconnecting,
    Done,
}

struct ReconnectGuard {
    state: ReconnectState,
    last_attempt: std::time::Instant,
}

/// Minimum interval between reconnect attempts — prevents a thundering herd
/// of reconnect storms when a network handoff fails.
const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// Single mutex + condvar for reconnect coordination.
static RECONNECT_GUARD: LazyLock<(Mutex<ReconnectGuard>, Condvar)> = LazyLock::new(|| {
    (
        Mutex::new(ReconnectGuard {
            state: ReconnectState::Idle,
            last_attempt: std::time::Instant::now() - std::time::Duration::from_secs(60),
        }),
        Condvar::new(),
    )
});

fn connections() -> &'static Mutex<HashMap<String, ManagedConnection>> {
    &QUIC_CONNECTIONS
}

/// Check whether ANY peer connection is alive (recent activity within 30 s).
pub fn is_quic_connected() -> bool {
    let map = connections().lock().unwrap_or_else(|e| e.into_inner());
    map.values().any(|c| {
        c.conn.is_some() && c.last_activity.elapsed() < std::time::Duration::from_secs(30)
    })
}

/// List every registered peer key.
pub fn peer_keys() -> Vec<String> {
    connections()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect()
}

/// Store a connection under its peer key and make it the active peer.
pub fn store_connection(
    conn: Connection,
    addr: SocketAddr,
    pinned_cert_hash: Option<String>,
    client_certs: Option<(Vec<u8>, Vec<u8>)>,
) {
    let key = peer_key(&addr, &pinned_cert_hash);
    let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
    map.insert(
        key.clone(),
        ManagedConnection {
            conn: Some(conn),
            config: Some(ConnConfig {
                addr,
                pinned_cert_hash,
                client_certs,
            }),
            last_activity: std::time::Instant::now(),
        },
    );
    *ACTIVE_PEER.lock().unwrap_or_else(|e| e.into_inner()) = Some(key);
}

/// Close ALL connections gracefully but keep configs for reconnection.
/// Sets last_activity far in the past so `is_quic_connected` returns false.
pub fn close_connection() {
    let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
    for mc in map.values_mut() {
        if let Some(conn) = mc.conn.take() {
            conn.close(0u8.into(), b"client disconnect");
        }
        mc.last_activity = std::time::Instant::now() - std::time::Duration::from_secs(60);
    }
    *ACTIVE_PEER.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Close a single peer's connection (e.g. on unpair of that peer).
pub fn close_peer(peer_key: &str) {
    let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mc) = map.get_mut(peer_key) {
        if let Some(conn) = mc.conn.take() {
            conn.close(0u8.into(), b"peer disconnect");
        }
        mc.last_activity = std::time::Instant::now() - std::time::Duration::from_secs(60);
    }
    if let Ok(mut active) = ACTIVE_PEER.lock() {
        if active.as_deref() == Some(peer_key) {
            *active = None;
        }
    }
}

/// Record that the active connection is still alive (poll handler).
pub fn touch_connection() {
    let active = ACTIVE_PEER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(key) = active {
        if let Ok(mut map) = connections().lock() {
            if let Some(mc) = map.get_mut(&key) {
                mc.last_activity = std::time::Instant::now();
            }
        }
    }
}

/// The active peer's live connection handle, if any.
pub fn active_connection() -> Option<Connection> {
    let active = ACTIVE_PEER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()?;
    let map = connections().lock().unwrap_or_else(|e| e.into_inner());
    let mc = map.get(&active)?;
    mc.conn.clone()
}

/// Get the ACTIVE connection, attempting auto-reconnect if closed.
/// The actual network connect() runs OUTSIDE the shared guard so concurrent
/// senders only wait on the condvar and never serialize on a blocking I/O
/// path. Reconnect attempts are rate-limited with a 1s backoff.
pub fn get_or_reconnect() -> Result<Connection, KyberError> {
    let active = ACTIVE_PEER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or_else(|| {
            KyberError::NetworkError("No active QUIC connection and no reconnect info available".into())
        })?;
    get_or_reconnect_for(&active)
}

/// Get (or reconnect) the connection for a specific peer key.
pub fn get_or_reconnect_for(peer_key: &str) -> Result<Connection, KyberError> {
    // Quick check without lock
    {
        let map = connections().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mc) = map.get(peer_key) {
            if let Some(conn) = &mc.conn {
                if conn.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        } else {
            return Err(KyberError::NetworkError(format!(
                "No QUIC connection registered for peer '{peer_key}' — call quic_connect first"
            )));
        }
    }

    let (lock, cvar) = &*RECONNECT_GUARD;

    // Claim the reconnect slot WITHOUT holding the lock across I/O.
    {
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        while guard.state == ReconnectState::Reconnecting {
            let (g, timed_out) = cvar
                .wait_timeout(guard, std::time::Duration::from_secs(5))
                .unwrap();
            guard = g;
            if timed_out.timed_out() {
                return Err(KyberError::NetworkError(
                    "QUIC reconnect in progress — timed out waiting".into(),
                ));
            }
        }
        if guard.state == ReconnectState::Done {
            guard.state = ReconnectState::Idle;
            let map = connections().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(mc) = map.get(peer_key) {
                if let Some(conn) = &mc.conn {
                    if conn.close_reason().is_none() {
                        return Ok(conn.clone());
                    }
                }
            }
            return Err(KyberError::NetworkError(
                "QUIC reconnect completed but connection unavailable".into(),
            ));
        }
        if guard.last_attempt.elapsed() < RECONNECT_BACKOFF {
            return Err(KyberError::NetworkError(
                "QUIC reconnect rate-limited (backoff)".into(),
            ));
        }
        guard.state = ReconnectState::Reconnecting;
        guard.last_attempt = std::time::Instant::now();
    } // guard dropped BEFORE the blocking connect

    // Perform the reconnect without holding any shared lock.
    let result = (|| -> Result<Connection, KyberError> {
        let config = {
            let map = connections().lock().unwrap_or_else(|e| e.into_inner());
            map.get(peer_key)
                .and_then(|mc| {
                    mc.config.as_ref().map(|c| ConnConfig {
                        addr: c.addr,
                        pinned_cert_hash: c.pinned_cert_hash.clone(),
                        client_certs: c.client_certs.clone(),
                    })
                })
        };
        let config = config.ok_or_else(|| {
            KyberError::NetworkError(format!(
                "No reconnect info available for peer '{peer_key}'"
            ))
        })?;

        let client_certs = config.client_certs.clone().map(|(cert_der, key_der)| {
            (
                vec![rustls::pki_types::CertificateDer::from(cert_der)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
            )
        });
        let new_conn = crate::block_on_sync(crate::quic_app::QuicAppManager::connect(
            config.addr,
            config.pinned_cert_hash,
            client_certs,
        ))?;

        let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mc) = map.get_mut(peer_key) {
            mc.conn = Some(new_conn.clone());
            mc.last_activity = std::time::Instant::now();
        }
        Ok(new_conn)
    })();

    {
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        guard.state = ReconnectState::Done;
    }
    cvar.notify_all();
    result
}

pub async fn quic_send_and_recv_impl(
    conn: &Connection,
    stream_type: u8,
    body_json: &str,
) -> Result<String, KyberError> {
    let (mut send, mut recv) =
        crate::quic_app::QuicAppManager::open_stream(conn, stream_type).await?;

    let body = body_json.as_bytes().to_vec();
    let frame = crate::quic_app::QuicFrame { stream_type, body };
    crate::quic_app::QuicAppManager::send_frame(&mut send, &frame).await?;
    send.finish()
        .map_err(|e| KyberError::NetworkError(format!("QUIC stream finish failed: {e}")))?;

    let response = crate::quic_app::QuicAppManager::recv_frame(&mut recv).await?;
    let text = String::from_utf8(response.body)
        .map_err(|e| KyberError::NetworkError(format!("Response UTF-8 decode error: {e}")))?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_key_derivation() {
        let addr: SocketAddr = "192.168.1.50:9876".parse().unwrap();
        // With a pin, the key is the pin (stable identity across IP changes).
        let pin = Some("aabbcc".to_string());
        assert_eq!(peer_key(&addr, &pin), "aabbcc");
        // Without a pin, the key is ip:port.
        assert_eq!(peer_key(&addr, &None), "192.168.1.50:9876");
    }

    #[test]
    fn test_registry_roundtrip() {
        // Two distinct peers must coexist in the registry.
        let a: SocketAddr = "10.0.0.1:9876".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:9876".parse().unwrap();
        let keys_a = peer_key(&a, &Some("pina".into()));
        let keys_b = peer_key(&b, &Some("pinb".into()));
        assert_ne!(keys_a, keys_b);
        let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
        map.insert(
            keys_a.clone(),
            ManagedConnection {
                conn: None,
                config: Some(ConnConfig {
                    addr: a,
                    pinned_cert_hash: Some("pina".into()),
                    client_certs: None,
                }),
                last_activity: std::time::Instant::now(),
            },
        );
        map.insert(
            keys_b.clone(),
            ManagedConnection {
                conn: None,
                config: Some(ConnConfig {
                    addr: b,
                    pinned_cert_hash: Some("pinb".into()),
                    client_certs: None,
                }),
                last_activity: std::time::Instant::now(),
            },
        );
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&keys_a));
        assert!(map.contains_key(&keys_b));
        map.clear();
    }
}
