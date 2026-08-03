use crate::state::AppState;
use std::sync::Arc;

use super::decrypt_json_payload;

/// Handle an encrypted SMS packet forwarded from the Android client over QUIC.
///
/// AUDIT F8 (CRITICAL): the body is the SHARED ratchet-TLV wire format
/// `{"encrypted_ratchet": {"tlv_b64": ...}}` — exactly what the Android
/// `SmsReceiver` produces via `ratchetEncryptMessageBinary`. The legacy
/// session-key hex format (`encrypted.nonce_hex` / `encrypted.ciphertext_hex`)
/// is DELETED: no sender produces it, it was gated on a restart-unfriendly
/// `IS_SESSION_KEY_AUTHENTICATED`/handle pair, and the drift silently dropped
/// every forwarded SMS. Decryption now goes through the same
/// [`decrypt_json_payload`] helper as clipboard/media, so the wire contract is
/// one shape across every stream.
pub(crate) async fn handle_sms(body: Vec<u8>, peer_id: String, s: Arc<AppState>) -> Vec<u8> {
    let decrypted = decrypt_json_payload(&body, &peer_id)
        .and_then(|plain| serde_json::from_str::<core_crypto::packets::SmsPacket>(&plain).ok());

    match decrypted {
        Some(pkt) => {
            s.add_log(format!("[SMS] Received from {} via QUIC", pkt.sender));
            s.add_sms_packet(pkt);
            r#"{"status":"synced"}"#.to_string().into_bytes()
        }
        None => {
            if body.is_empty() {
                return r#"{"status":"synced"}"#.to_string().into_bytes();
            }
            tracing::warn!(
                "[SMS] Non-empty body could not be decrypted as a ratchet-TLV SmsPacket"
            );
            r#"{"status":"error","reason":"Decryption failed"}"#
                .to_string()
                .into_bytes()
        }
    }
}
