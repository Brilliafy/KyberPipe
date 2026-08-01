use crate::state::AppState;
use std::sync::Arc;

pub(crate) async fn handle_rekey_ack(body: Vec<u8>, s: Arc<AppState>) -> Vec<u8> {
    let body_str = String::from_utf8_lossy(&body);
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str) {
        let peer_id = s.get_pairing_initiator_pk();
        if !peer_id.is_empty() {
            if let Some(enc) = json.get("encrypted_ratchet") {
                let nonce_hex = enc.get("nonce_hex").and_then(|v| v.as_str()).unwrap_or("");
                let ct_hex = enc.get("ciphertext_hex").and_then(|v| v.as_str()).unwrap_or("");
                
                if !nonce_hex.is_empty() && !ct_hex.is_empty() {
                    if let (Ok(nonce), Ok(ct)) = (hex::decode(nonce_hex), hex::decode(ct_hex)) {
                        // Decrypt the ACK and parse the JSON payload
                        match core_crypto::ratchet_decrypt_message(peer_id.clone(), nonce, ct) {
                            Ok(pt) => {
                                if let Ok(msg) = core_crypto::packets::KyberMessage::from_json(&String::from_utf8_lossy(&pt)) {
                                    if let core_crypto::packets::KyberMessage::RekeyAck { seq } = msg {
                                        let _ = core_crypto::ratchet_process_rekey_ack(peer_id.clone(), seq);
                                        tracing::info!("[RekeyAck] Successfully processed rekey ACK for seq {} from {}", seq, peer_id);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("[RekeyAck] Failed to decrypt rekey ACK: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
    r#"{"status":"ok"}"#.to_string().into_bytes()
}
