//! QUIC frame CODEC (audit finding #14 — structural decomposition).
//!
//! The wire codec was entangled with the endpoint lifecycle and the mTLS
//! verifier state in the former `quic_app.rs` monolith. Extracted here so a
//! change to the frame format (or a new stream type) touches exactly one
//! module and cannot drift from the endpoint code that consumes it.

use crate::error::KyberError;
use quinn::{RecvStream, SendStream};
use tokio::io::AsyncReadExt;

/// Stream type identifiers for multiplexed QUIC application protocol
pub const STREAM_PAIRING: u8 = 0x01;
pub const STREAM_CLIPBOARD: u8 = 0x02;
pub const STREAM_MEDIA: u8 = 0x03;
pub const STREAM_POLL: u8 = 0x04;
pub const STREAM_UNPAIR: u8 = 0x05;
pub const STREAM_REKEY_ACK: u8 = 0x06;
pub const STREAM_SMS: u8 = 0x07;

/// Maximum message body size (1 MB) — clipboard/media payloads
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Binary frame: [stream_type: 1B][body_len: 4B][body: body_len]
#[derive(Debug)]
pub struct QuicFrame {
    #[allow(dead_code)]
    pub stream_type: u8,
    pub body: Vec<u8>,
}

impl QuicFrame {
    /// Encode the frame to wire bytes. AUDIT P1-4: the length field is u32 on
    /// the wire and the consumer (`decode`/`recv_frame_header`) rejects bodies
    /// over [`MAX_MESSAGE_SIZE`], so the producer MUST enforce the same bound
    /// here — the legacy `body.len() as u32` silently wrapped for any body ≥
    /// 4 GiB, and the send side was the only direction without a size
    /// assertion. Returns an error instead of emitting a length-wrapped frame
    /// the peer would reject (or, on a matching wrap, use to desynchronize
    /// the stream).
    pub fn encode(&self) -> Result<Vec<u8>, KyberError> {
        if self.body.len() > MAX_MESSAGE_SIZE {
            return Err(KyberError::NetworkError(format!(
                "Frame body too large to encode: {} > {MAX_MESSAGE_SIZE}",
                self.body.len()
            )));
        }
        let len = self.body.len() as u32;
        let mut buf = Vec::with_capacity(5 + self.body.len());
        buf.push(self.stream_type);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.body);
        Ok(buf)
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

/// Write a frame to a QUIC stream.
pub async fn send_frame(send: &mut SendStream, frame: &QuicFrame) -> Result<(), KyberError> {
    // AUDIT P1-4: the producer-side size cap now lives in `encode` — an
    // oversized frame fails HERE (before any bytes hit the wire) instead of
    // being length-wrapped and desynchronizing the peer's stream.
    let data = frame.encode()?;
    send.write_all(&data)
        .await
        .map_err(|e| KyberError::NetworkError(format!("Send frame failed: {e}")))
}

/// Read ONE complete frame from a QUIC stream: header (5 bytes) then body.
pub async fn recv_frame(recv: &mut RecvStream) -> Result<QuicFrame, KyberError> {
    let (stream_type, body_len) = recv_frame_header(recv).await?;
    let body = recv_frame_body(recv, body_len).await?;
    Ok(QuicFrame { stream_type, body })
}

/// Read ONLY the 5-byte frame header (stream_type + body_len). The server
/// authorizes the stream from the header BEFORE reading the body, so an
/// unauthenticated peer cannot force the server to buffer up to 1 MiB per
/// stream before being rejected (audit finding #8).
pub async fn recv_frame_header(recv: &mut RecvStream) -> Result<(u8, usize), KyberError> {
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
            "Frame body too large: {body_len} > {MAX_MESSAGE_SIZE}"
        )));
    }
    Ok((stream_type, body_len))
}

/// Read the frame body of `body_len` bytes (bounded by MAX_MESSAGE_SIZE,
/// already validated in `recv_frame_header`).
pub async fn recv_frame_body(
    recv: &mut RecvStream,
    body_len: usize,
) -> Result<Vec<u8>, KyberError> {
    if body_len > MAX_MESSAGE_SIZE {
        return Err(KyberError::NetworkError(format!(
            "Frame body too large: {body_len} > {MAX_MESSAGE_SIZE}"
        )));
    }
    let mut body = Vec::with_capacity(body_len.min(8192));
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
    Ok(body)
}
