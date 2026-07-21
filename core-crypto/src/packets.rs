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
pub struct SmsPacket {
    pub sender: String,
    pub body: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationPacket {
    pub title: String,
    pub text: String,
    pub app_package: String,
    pub icon_base64: Option<String>,
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
    Clipboard(ClipboardPacket),
    Sms(SmsPacket),
    Notification(NotificationPacket),
    FileChunk(FileChunkPacket),
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

pub fn compute_sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
