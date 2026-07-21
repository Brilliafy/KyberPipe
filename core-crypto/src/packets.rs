use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::error::KyberError;

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
    PathChallenge { challenge_token: String },
    PathResponse { response_token: String },
    Ping { timestamp: u64 },
    Pong { timestamp: u64 },
}

impl KyberMessage {
    pub fn to_json(&self) -> Result<String, KyberError> {
        serde_json::to_string(self)
            .map_err(|e| KyberError::SerializationError(e.to_string()))
    }

    pub fn from_json(json_str: &str) -> Result<Self, KyberError> {
        serde_json::from_str(json_str)
            .map_err(|e| KyberError::SerializationError(e.to_string()))
    }
}

/// Zero-panic safe packet decoder for raw untrusted byte streams
pub fn safe_decode_packet(data: &[u8]) -> Result<KyberMessage, KyberError> {
    if data.is_empty() {
        return Err(KyberError::SerializationError("Empty payload".into()));
    }
    let s = std::str::from_utf8(data)
        .map_err(|e| KyberError::SerializationError(format!("Invalid UTF-8 bytes: {e}")))?;
    KyberMessage::from_json(s)
}

pub fn compute_sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
