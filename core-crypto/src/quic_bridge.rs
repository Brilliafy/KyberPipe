use crate::error::KyberError;
use quinn::Connection;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Connection configuration stored alongside the connection for auto-reconnect.
struct ConnConfig {
    addr: SocketAddr,
    pinned_cert_hash: Option<String>,
}

#[allow(dead_code)]
pub(crate) struct ManagedConnection {
    conn: Option<Connection>,
    config: Option<ConnConfig>,
}

pub(crate) static QUIC_CONNECTION: OnceLock<Mutex<ManagedConnection>> = OnceLock::new();

pub(crate) fn get_quic_connection() -> &'static Mutex<ManagedConnection> {
    QUIC_CONNECTION.get_or_init(|| {
        Mutex::new(ManagedConnection {
            conn: None,
            config: None,
        })
    })
}

/// Store the connection and its config for future reconnection.
pub fn store_connection(conn: Connection, addr: SocketAddr, pinned_cert_hash: Option<String>) {
    let mut mc = get_quic_connection()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    mc.conn = Some(conn);
    mc.config = Some(ConnConfig {
        addr,
        pinned_cert_hash,
    });
}

/// Close the connection gracefully but keep the config for reconnection.
pub fn close_connection() {
    let mut mc = get_quic_connection()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(conn) = mc.conn.take() {
        conn.close(0u8.into(), b"client disconnect");
    }
}

/// Get the active connection, attempting auto-reconnect if closed.
pub fn get_or_reconnect() -> Result<Connection, KyberError> {
    let mut mc = get_quic_connection()
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // Check if existing connection is still usable
    if let Some(ref conn) = mc.conn {
        // Quick check: connection closed?
        if conn.close_reason().is_none() {
            return Ok(conn.clone());
        }
        // Connection is closed — drop it
        mc.conn = None;
    }

    // Try to reconnect using stored config
    let config = mc.config.as_ref().ok_or_else(|| {
        KyberError::NetworkError("No active QUIC connection and no reconnect info available".into())
    })?;

    let new_conn = crate::block_on_sync(crate::quic_app::QuicAppManager::connect(
        config.addr,
        config.pinned_cert_hash.clone(),
        None,
    ))?;
    mc.conn = Some(new_conn.clone());
    Ok(new_conn)
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
