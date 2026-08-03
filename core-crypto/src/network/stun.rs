use crate::error::KyberError;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

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
    request[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    request[2..4].copy_from_slice(&0x0000u16.to_be_bytes());
    request[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());

    // Generate random 12-byte Transaction ID and cache it for response verification
    let tx_id_raw: [u8; 12] = rand::random();
    request[8..20].copy_from_slice(&tx_id_raw);
    let cached_tx_id = tx_id_raw;

    socket
        .send_to(&request, stun_addr)
        .await
        .map_err(|e| KyberError::NetworkError(format!("Failed to send STUN request: {e}")))?;

    let mut buf = [0u8; 512];
    let (len, src_addr) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| KyberError::NetworkError("STUN response timeout".to_string()))?
    .map_err(|e| KyberError::NetworkError(format!("Failed to receive STUN response: {e}")))?;

    // Audit KYP-2026-02 #5: the response must come from the resolved STUN
    // server address we sent the request to. STUN Binding is unauthenticated
    // and the transaction ID travels in cleartext, so an on-path attacker who
    // observes the request can inject a spoofed response carrying a fabricated
    // XOR-MAPPED-ADDRESS — unless the source address is verified. A response
    // from any other source is rejected outright.
    if src_addr.ip() != stun_addr.ip() || src_addr.port() != stun_addr.port() {
        return Err(KyberError::NetworkError(format!(
            "STUN response source mismatch: got {src_addr}, expected {stun_addr} — rejecting spoofed response"
        )));
    }

    if len < 20 {
        return Err(KyberError::NetworkError(
            "STUN response too short".to_string(),
        ));
    }
    // Validate STUN message length field (bytes 2-4) against actual payload
    let msg_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if msg_length + 20 > len {
        return Err(KyberError::NetworkError(format!(
            "STUN message length field ({}) exceeds actual payload ({})",
            msg_length + 20,
            len
        )));
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != 0x0101 {
        return Err(KyberError::NetworkError(format!(
            "STUN response was not success: {msg_type:04x}"
        )));
    }

    // Validate transaction ID matches our request (constant-time)
    if subtle::ConstantTimeEq::ct_ne(&cached_tx_id[..], &buf[8..20]).into() {
        return Err(KyberError::NetworkError(
            "STUN transaction ID mismatch".to_string(),
        ));
    }

    let mut pos = 20;
    let mut mapped_addr: Option<SocketAddr> = None;
    let mut fingerprint_ok: Option<bool> = None;

    // Track for FINGERPRINT CRC32 validation
    let _original_len = len;

    while pos < len {
        if pos + 4 > len {
            break;
        }
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        // Validate attr_len before accessing attr_value — attacker-controlled
        // length values could cause out-of-bounds reads.
        if attr_len > 512 || pos + attr_len > len {
            break;
        }
        let attr_value = &buf[pos..pos + attr_len];
        pos += attr_len;

        // 4-byte alignment padding per RFC 5389 §15
        // (STUN attributes are 4-byte aligned in the message)
        let padded_len = (attr_len + 3) & !3;
        pos += padded_len - attr_len;

        match attr_type {
            0x0001 => {
                // MAPPED-ADDRESS
                if attr_len >= 8 {
                    let family = attr_value[1];
                    let port = u16::from_be_bytes([attr_value[2], attr_value[3]]);
                    if family == 1 {
                        let ip = std::net::Ipv4Addr::new(
                            attr_value[4],
                            attr_value[5],
                            attr_value[6],
                            attr_value[7],
                        );
                        mapped_addr = Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                    }
                }
            }
            0x0020 => {
                // XOR-MAPPED-ADDRESS (preferred over MAPPED-ADDRESS)
                if attr_len >= 8 {
                    let family = attr_value[1];
                    let xport = u16::from_be_bytes([attr_value[2], attr_value[3]]);
                    let port = xport ^ 0x2112; // XOR port with magic cookie
                    if family == 1 {
                        let xip = [attr_value[4], attr_value[5], attr_value[6], attr_value[7]];
                        let cookie_bytes = 0x2112A442u32.to_be_bytes();
                        let ip = std::net::Ipv4Addr::new(
                            xip[0] ^ cookie_bytes[0],
                            xip[1] ^ cookie_bytes[1],
                            xip[2] ^ cookie_bytes[2],
                            xip[3] ^ cookie_bytes[3],
                        );
                        mapped_addr = Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                    }
                }
            }
            0x8028
                // FINGERPRINT attribute (RFC 5389 §15.5)
                if attr_len == 4 => {
                    let claimed_crc32 = u32::from_be_bytes([
                        attr_value[0],
                        attr_value[1],
                        attr_value[2],
                        attr_value[3],
                    ]);
                    // Compute CRC32 over the entire STUN message up to the FINGERPRINT
                    // attribute, with the FINGERPRINT attribute's value replaced by 0.
                    // The FINGERPRINT starts at (pos - 4 - attr_len - padding).
                    // We compute CRC32 from byte 0 to the start of FINGERPRINT value.
                    let fp_value_start = pos - attr_len; // Start of FINGERPRINT value (4 bytes)
                    let mut crc_input = buf[..fp_value_start].to_vec();
                    // Append 4 zero bytes for the CRC32 field per RFC 5389
                    crc_input.extend_from_slice(&[0u8; 4]);
                    let computed_crc32 = crc32fast::hash(&crc_input) ^ 0x5354554e;
                    fingerprint_ok = Some(computed_crc32 == claimed_crc32);
                    if !fingerprint_ok.unwrap() {
                        tracing::warn!("STUN FINGERPRINT validation failed");
                    }
                }
            _ => {
                // Unknown attribute — skip per RFC 5389
            }
        }
    }

    // Audit KYP-2026-02 #5: a FINGERPRINT MISMATCH is FATAL — the CRC32
    // FINGERPRINT is not a MAC, but a mismatch still proves the response was
    // corrupted or synthesized, and must never be accepted "with a warning".
    // (A response without a FINGERPRINT attribute is still accepted: it is
    // optional under RFC 5389, and legacy servers omit it.)
    if fingerprint_ok == Some(false) {
        return Err(KyberError::NetworkError(
            "STUN FINGERPRINT validation failed — rejecting response".to_string(),
        ));
    }

    // Prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS per RFC 5389
    if let Some(addr) = mapped_addr {
        return Ok(addr);
    }

    Err(KyberError::NetworkError(
        "No valid mapped address found in STUN response".to_string(),
    ))
}
