use crate::error::KyberError;
use crate::quic_app::MAX_MESSAGE_SIZE;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SensorPacket {
    pub lux: f64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClipboardPacket {
    pub content: String,
    pub hash: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinaryClipboardPacket {
    pub mime_type: String,
    pub data_base64: String,
    pub hash: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SmsPacket {
    pub sender: String,
    pub body: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundSmsPacket {
    pub recipient: String,
    pub body: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationPacket {
    pub sbn_key: String,
    pub title: String,
    pub text: String,
    pub app_package: String,
    pub icon_base64: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationActionPacket {
    pub sbn_key: String,
    pub action_index: u32,
    pub action_title: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HardwareCommandPacket {
    pub command_type: String, // "battery_status", "ping_device", "toggle_silent"
    pub payload_json: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileChunkPacket {
    pub file_id: String,
    pub filename: String,
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub data_base64: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload")]
pub enum KyberMessage {
    Sensor(SensorPacket),
    ClipboardText(ClipboardPacket),
    ClipboardBinary(BinaryClipboardPacket),
    Sms(SmsPacket),
    OutboundSms(OutboundSmsPacket),
    Notification(NotificationPacket),
    NotificationAction(NotificationActionPacket),
    HardwareCommand(HardwareCommandPacket),
    FileChunk(FileChunkPacket),
    PathChallenge {
        challenge_token: String,
    },
    PathResponse {
        response_token: String,
    },
    Ping {
        timestamp: u64,
    },
    Pong {
        timestamp: u64,
    },
    RekeyAck {
        seq: u64,
    },
    /// Explicit session resync. The sender of this message communicates its
    /// current send/recv sequence counter so the peer can re-derive skipped
    /// chain keys after a gap exceeded `max_skip`. Always ratchet-encrypted.
    Synchronize {
        send_count: u64,
    },
}

impl KyberMessage {
    pub fn to_json(&self) -> Result<String, KyberError> {
        serde_json::to_string(self).map_err(|e| KyberError::SerializationError(e.to_string()))
    }

    pub fn from_json(json_str: &str) -> Result<Self, KyberError> {
        serde_json::from_str(json_str).map_err(|e| KyberError::SerializationError(e.to_string()))
    }
}

/// Core payload wrappers carried across QUIC streams
///
/// AUDIT #2 (follow-up): per-field caps are enforced at decode so a single
/// base64 field can never balloon to the whole frame budget and drive
/// multi-copy heap churn on the phone. (The QUIC frame already caps the total
/// at `MAX_MESSAGE_SIZE`, and serde_json bounds nesting at 128 — these close
/// the per-field gap.) `icon_base64` ≤ 256 KiB and a file chunk ≤ 1 MiB of
/// binary, enforced on the base64 character length.
pub fn safe_decode_packet(data: &[u8]) -> Result<KyberMessage, KyberError> {
    if data.is_empty() {
        return Err(KyberError::SerializationError("Empty payload".into()));
    }
    // Defense-in-depth total bound independent of the transport frame cap.
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(KyberError::SerializationError(format!(
            "Payload too large ({} bytes > MAX_MESSAGE_SIZE)",
            data.len()
        )));
    }
    let s = std::str::from_utf8(data)
        .map_err(|e| KyberError::SerializationError(format!("Invalid UTF-8 bytes: {e}")))?;
    let msg = KyberMessage::from_json(s)?;
    match &msg {
        KyberMessage::Notification(n) => {
            if let Some(icon) = &n.icon_base64 {
                if icon.len() > MAX_ICON_BASE64_CHARS {
                    return Err(KyberError::SerializationError(format!(
                        "Notification icon too large ({} base64 chars > {})",
                        icon.len(),
                        MAX_ICON_BASE64_CHARS
                    )));
                }
            }
        }
        KyberMessage::FileChunk(f) => {
            if f.data_base64.len() > MAX_FILE_CHUNK_BASE64_CHARS {
                return Err(KyberError::SerializationError(format!(
                    "File chunk too large ({} base64 chars > {})",
                    f.data_base64.len(),
                    MAX_FILE_CHUNK_BASE64_CHARS
                )));
            }
        }
        _ => {}
    }
    Ok(msg)
}

/// Max base64 chars for a notification icon (≈ 256 KiB of binary). Album art
/// embedded in media notifications must never consume the whole frame budget
/// or drive unbounded heap copies (audit finding #9 follow-up).
pub const MAX_ICON_BASE64_CHARS: usize = 350_000;

/// Max base64 chars for a single file chunk (≈ 1 MiB of binary) — a chunk is a
/// bounded transfer unit, never a full-file blow-up (audit finding #9).
pub const MAX_FILE_CHUNK_BASE64_CHARS: usize = 1_400_000;

pub fn compute_sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
