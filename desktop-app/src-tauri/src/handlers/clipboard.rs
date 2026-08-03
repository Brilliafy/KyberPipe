use crate::state::AppState;
use sha2::Digest;
use std::sync::Arc;

/// Truncated SHA-256 hash of a clipboard payload, used for LOGGING ONLY
/// (audit finding #13). The legacy log wrote the first 30 chars of the
/// plaintext — a password copied on the phone would persist in the desktop's
/// in-app log pane. The hash preserves enough to correlate a transfer in the
/// log ("clipboard changed") without persisting the content.
pub(crate) fn clipboard_log_fingerprint(text: &str) -> String {
    let digest = sha2::Sha256::digest(text.as_bytes());
    format!("{}{}", hex::encode(&digest[..8]), "…")
}

/// The ratchet-TLV decrypt used by EVERY inbound handler (clipboard, SMS,
/// media, rekey-ack). Audit KYP-2026-02 #17: the ratchet TLV
/// (`encrypted_ratchet.tlv_b64`) is the ONLY accepted wire format — the legacy
/// session-key hex fallback (`encrypted.nonce_hex` / `encrypted.ciphertext_hex`)
/// is deleted, and a body that carries only those hex fields is a protocol
/// violation that decrypts to None. The single shared implementation lives in
/// `handlers::decrypt_json_payload` so the contract can never drift per stream
/// (audit F8).
pub(crate) async fn handle_clipboard(body: Vec<u8>, peer_id: String, s: Arc<AppState>) -> Vec<u8> {
    // Single wire format: ratchet TLV (audit finding #15 / KYP-2026-02 #17).
    // `peer_id` is resolved per-CONNECTION from the TLS-observed client cert
    // hash (audit F12) so a second paired device decrypts against its OWN
    // session, never the first device's.
    let text = crate::handlers::decrypt_json_payload(&body, &peer_id);

    // A non-empty body that cannot be decrypted is a protocol failure, not a
    // no-op — surface it so clients (and integration tests) can distinguish a
    // successful sync from a silently-dropped payload.
    let Some(decrypted) = text else {
        if body.is_empty() {
            return r#"{"status":"synced"}"#.to_string().into_bytes();
        }
        return r#"{"status":"error","reason":"Decryption failed"}"#
            .to_string()
            .into_bytes();
    };

    if !decrypted.is_empty() && s.check_and_record_clipboard(&decrypted) {
        // AUDIT FINDING #13: inbound clipboard writes are now gated by an
        // explicit one-way policy (`inbound_clipboard_enabled`, default ON).
        // The phone is still authenticated (the payload is ratchet-AEAD
        // verified), but a compromised/repackaged phone app must not be able
        // to push phishing URLs / shell-ish text into the desktop clipboard
        // without a policy the user controls. When the policy is OFF, the
        // payload is decrypted and deduplicated but the OS clipboard is NOT
        // written — an app event lets the UI surface "phone sent clipboard
        // content (blocked)" instead.
        let inbound_enabled = { s.settings.lock().inbound_clipboard_enabled };
        // Hermetic test mode: record but do not write to the OS clipboard.
        #[cfg(test)]
        let hermetic = crate::handlers::FORCE_EMPTY_CLIPBOARD.load(std::sync::atomic::Ordering::Acquire);
        #[cfg(not(test))]
        let hermetic = false;
        if hermetic {
            // The e2e runs fully hermetic: no OS clipboard write path.
            s.add_log(format!(
                "[Clipboard] (test) Received via QUIC: \"{}\" — OS write suppressed",
                clipboard_log_fingerprint(&decrypted)
            ));
        } else if !inbound_enabled {
            // Policy gate: one-way sync (phone reads desktop; desktop does NOT
            // adopt phone content).
            s.add_log(format!(
                "[Clipboard] Inbound clipboard blocked by policy — phone sent {} (audit finding #13)",
                clipboard_log_fingerprint(&decrypted)
            ));
            crate::handlers::emit_app_event(
                "clipboard::inbound-blocked",
                serde_json::json!({"fingerprint": clipboard_log_fingerprint(&decrypted)}),
            );
        } else {
            // Audit finding #9: the OS clipboard write (arboard / wl-copy / xclip
            // subprocesses with multi-second waits) must NEVER execute on the
            // accept-loop worker — it would stall every concurrent QUIC stream.
            // Delegate to the tokio blocking pool, which is sized independently of
            // the 2-worker IO accept-loop runtime.
            let text = decrypted.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = crate::portal::sync_clipboard_text(&text);
            })
            .await;
            s.add_log(format!(
                "[Clipboard] Received via QUIC: \"{}\"",
                clipboard_log_fingerprint(&decrypted)
            ));
        }
    }
    r#"{"status":"synced"}"#.to_string().into_bytes()
}
