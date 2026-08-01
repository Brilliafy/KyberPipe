use crate::error::KyberError;

pub fn create_sms_packet_impl(
    sender: String,
    body: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = crate::packets::SmsPacket {
        sender,
        body,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

pub fn create_outbound_sms_packet_impl(
    recipient: String,
    body: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = crate::packets::OutboundSmsPacket {
        recipient,
        body,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

pub fn create_notification_packet_impl(
    title: String,
    text: String,
    app_package: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = crate::packets::NotificationPacket {
        sbn_key: format!("{app_package}_{timestamp}"),
        title,
        text,
        app_package,
        icon_base64: None,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

pub fn create_notification_action_packet_impl(
    sbn_key: String,
    action_index: u32,
    action_title: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = crate::packets::NotificationActionPacket {
        sbn_key,
        action_index,
        action_title,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}

pub fn create_hardware_command_packet_impl(
    command_type: String,
    payload_json: String,
    timestamp: u64,
) -> Result<String, KyberError> {
    let pkt = crate::packets::HardwareCommandPacket {
        command_type,
        payload_json,
        timestamp,
    };
    serde_json::to_string(&pkt).map_err(|e| KyberError::SerializationError(e.to_string()))
}
