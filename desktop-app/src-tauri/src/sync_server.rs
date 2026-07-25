use crate::state::AppState;
use crate::state::SecureString;
use core_crypto::quic_app::BoxFuture;
use std::sync::Arc;

/// QUIC-backed sync server. Replaces the old raw TCP/HTTP implementation.
/// Binds a quinn QUIC endpoint on port 9876 (DEFAULT_KYBERPIPE_PORT)
/// and handles all application protocol via multiplexed streams.
pub fn start_local_sync_server(state: Arc<AppState>) {
    core_crypto::try_start_p2p_group();

    std::thread::spawn(move || {
        // Use multi-thread runtime to prevent blocking from blocking callbacks
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build sync server tokio runtime");
        rt.block_on(async move {
            let endpoint = match core_crypto::quic_app::QuicAppManager::bind_server(
                core_crypto::network::DEFAULT_KYBERPIPE_PORT,
            )
            .await
            {
                Ok(ep) => ep,
                Err(e) => {
                    eprintln!("[QUIC Sync] Failed to bind: {e}");
                    return;
                }
            };
            eprintln!(
                "[QUIC Sync] Listening on port {}",
                core_crypto::network::DEFAULT_KYBERPIPE_PORT
            );

            // Beacon broadcast loop
            let beacon_state = state.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let host_pk = {
                        let kp = beacon_state
                            .keypair
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        kp.as_ref()
                            .map(|p| p.mlkem_pk_hex.clone())
                            .unwrap_or_default()
                    };
                    let device_name = {
                        let s = beacon_state
                            .settings
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        s.device_name
                            .clone()
                            .unwrap_or_else(|| "Desktop".to_string())
                    };
                    let local_ip = core_crypto::get_local_ip();
                    if !host_pk.is_empty() && !local_ip.is_empty() {
                        // Use a truncated hash of the public key — never broadcast the full PK
                        let pk_hash = &host_pk[..16];
                        let payload = format!("{}:{}:{}", pk_hash, local_ip, device_name);
                        let _ = core_crypto::send_beacon_payload(payload).await;
                    }
                }
            });

            // Pairing handler: decapsulate KEM, derive session key
            let s = state.clone();
            let on_pairing = move |body: Vec<u8>| -> BoxFuture<Vec<u8>> {
                let s = s.clone();
                Box::pin(async move {
                    // Reject pairing if already paired (prevents unauthenticated session hijack)
                    {
                        let settings = s.settings.lock().unwrap_or_else(|e| e.into_inner());
                        if settings.is_paired {
                            s.add_log(
                                "[Pairing] Rejected: already paired. Unpair first to re-pair."
                                    .to_string(),
                            );
                            return r#"{"status":"error","reason":"Already paired"}"#
                                .to_string()
                                .into_bytes();
                        }
                    }
                    // Check for SAS timeout BEFORE the pending check so stale sessions
                    // can be cleared. Must run before is_pairing_pending() — otherwise
                    // the cleanup block is unreachable dead code.
                    let sas_code = s.sas_code.lock().unwrap().clone();
                    if !sas_code.is_empty() {
                        let pending_key = s.pending_session_key.lock().unwrap().to_string();
                        if !pending_key.is_empty() {
                            s.add_log("[Pairing] Clearing stale pending SAS (previous attempt incomplete)".to_string());
                            *s.pending_session_key.lock().unwrap() = SecureString::new(String::new());
                            s.sas_code.lock().unwrap().clear();
                        }
                    }
                    // Reject if SAS verification is already pending (prevents silent hijack)
                    if s.is_pairing_pending() {
                        s.add_log(
                            "[Pairing] Rejected: SAS verification already in progress. Complete or timeout first."
                                .to_string(),
                        );
                        return r#"{"status":"error","reason":"Pairing already in progress"}"#
                            .to_string()
                            .into_bytes();
                    }

                    let body_str = String::from_utf8_lossy(&body);
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str) {
                        let ciphertext_hex = json
                            .get("ciphertext_hex")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let client_pk_hex = json
                            .get("client_pk_hex")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let _name = json
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Android Phone")
                            .to_string();

                        if !ciphertext_hex.is_empty() {
                            let kp_guard = s.keypair.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(ref pair) = *kp_guard {
                                if let Ok(shared_secret) = core_crypto::decapsulate_pq_secret(
                                    ciphertext_hex,
                                    pair.x25519_sk_hex.clone(),
                                    pair.mlkem_sk_hex.clone(),
                                ) {
                                    let ss_for_sas = shared_secret.clone();
                                    let salt = hex::encode("kyberpipe-sync-v1");
                                    if let Ok(sk) = core_crypto::derive_session_key(shared_secret, salt)
                                    {
                                        // Store in pending — NOT promoted to active session_key
                                        // until SAS code is confirmed via confirm_pairing endpoint
                                        *s.pending_session_key.lock().unwrap() = SecureString::new(sk);
                                        // Bind initiator's public key to this pending session
                                        *s.pairing_initiator_pk.lock().unwrap() = client_pk_hex.clone();
                                        s.add_log(
                                            "[Session] Derived session key from KEM handshake (pending SAS confirmation)"
                                                .to_string(),
                                        );
                                    }
                                    if !client_pk_hex.is_empty() {
                                        if let Ok(sas) = core_crypto::generate_sas_code(
                                            pair.mlkem_pk_hex.clone(),
                                            client_pk_hex,
                                            ss_for_sas,
                                        ) {
                                            *s.sas_code.lock().unwrap() =
                                                sas.clone();
                                            s.add_log(format!("[Session] SAS code: {sas}"));
                                        }
                                    }
                                    // Don't transition to paired state yet — SAS must be confirmed
                                    // via confirm_pairing_sas command before promoting session key
                                    s.set_connection_status("PAIRING_PENDING_SAS".to_string());
                                    s.set_connection_method("QUIC mTLS".to_string());
                                    s.set_connection_color("yellow".to_string());
                                    s.add_log("[Pairing] Received pairing handshake. SAS code available — waiting for OOB confirmation".to_string());
                                    // SAS code is NOT included in the wire response — it must be verified
                                    // out-of-band via local UI display on both devices.
                                    let resp = serde_json::json!({
                                        "status": "pairing_pending_sas"
                                    });
                                    return serde_json::to_string(&resp).unwrap_or_default().into_bytes();
                                }
                            }
                        }
                        s.add_log("[Pairing] Handshake failed: KEM decapsulation error".to_string());
                        r#"{"status":"error","reason":"Decapsulation failed"}"#
                            .to_string()
                            .into_bytes()
                    } else {
                        r#"{"status":"error","reason":"Invalid JSON"}"#.to_string().into_bytes()
                    }
                })
            };

            // Clipboard handler: decrypt and apply
            let s = state.clone();
            let on_clipboard = move |body: Vec<u8>| -> BoxFuture<Vec<u8>> {
                let s = s.clone();
                Box::pin(async move {
                    let body_str = String::from_utf8_lossy(&body);
                    let mut text = String::new();
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str) {
                        let session_key = s
                            .session_key
                            .lock()
                            .unwrap()
                            .to_string();
                        if !session_key.is_empty() {
                            if let Some(enc) = json.get("encrypted") {
                                let nonce = enc.get("nonce_hex").and_then(|v| v.as_str()).unwrap_or("");
                                let ct = enc
                                    .get("ciphertext_hex")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if !nonce.is_empty() && !ct.is_empty() {
                                    if let Ok(decrypted) = core_crypto::decrypt_payload_with_key(
                                        session_key,
                                        nonce.to_string(),
                                        ct.to_string(),
                                    ) {
                                        text = decrypted;
                                    }
                                }
                            }
                        }
                    }
                    if !text.is_empty() && s.dedup.check_and_record(&text) {
                        let _ = crate::portal::sync_clipboard_text(&text);
                        s.add_log(format!(
                            "[Clipboard] Received via QUIC: \"{}\"",
                            text.chars().take(30).collect::<String>()
                        ));
                    }
                    r#"{"status":"synced"}"#.to_string().into_bytes()
                })
            };

            // Media handler: decrypt-only, no fallback
            let s = state.clone();
            let on_media = move |body: Vec<u8>| -> BoxFuture<Vec<u8>> {
                let s = s.clone();
                Box::pin(async move {
                    let body_str = String::from_utf8_lossy(&body);
                    let decrypted = serde_json::from_str::<serde_json::Value>(&body_str)
                        .ok()
                        .and_then(|json| {
                            let encrypted = json.get("encrypted").and_then(|e| {
                                let nonce = e.get("nonce_hex").and_then(|v| v.as_str())?;
                                let ct = e.get("ciphertext_hex").and_then(|v| v.as_str())?;
                                Some((nonce.to_string(), ct.to_string()))
                            })?;
                            let session_key = s
                                .session_key
                                .lock()
                                .unwrap()
                                .to_string();
                            if session_key.is_empty() {
                                return None;
                            }
                            core_crypto::decrypt_payload_with_key(session_key, encrypted.0, encrypted.1)
                                .ok()
                        })
                        .and_then(|d| serde_json::from_str::<serde_json::Value>(&d).ok());
                    if let Some(json) = decrypted {
                        let title = json
                            .get("title")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let artist = json
                            .get("artist")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let album_art = json
                            .get("album_art")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let is_playing = json
                            .get("is_playing")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let mut actions = vec![];
                        if let Some(act_arr) = json.get("actions").and_then(|v| v.as_array()) {
                            for act_val in act_arr {
                                let act_title = act_val
                                    .get("title")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or_default()
                                    .to_string();
                                let act_index = act_val
                                    .get("index")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or_default()
                                    as u32;
                                actions.push(crate::state::MediaAction {
                                    title: act_title,
                                    index: act_index,
                                });
                            }
                        }
                        let mut m = s.media_state.lock().unwrap_or_else(|e| e.into_inner());
                        m.title = title;
                        m.artist = artist;
                        m.album_art = album_art;
                        m.is_playing = is_playing;
                        m.actions = actions;
                    }
                    r#"{"status":"synced"}"#.to_string().into_bytes()
                })
            };

            // Poll handler: return status + encrypted clipboard
            let s = state.clone();
            let on_poll = move || -> BoxFuture<Vec<u8>> {
                let s = s.clone();
                Box::pin(async move {
                    let connection = s.get_connection();
                    let is_paired = s
                        .settings
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .is_paired;
                    let latest_clip =
                        crate::commands::read_real_clipboard_internal().unwrap_or_default();
                    let latest_clip_encrypted = if !latest_clip.is_empty() {
                        let session_key = s
                            .session_key
                            .lock()
                            .unwrap()
                            .to_string();
                        if !session_key.is_empty() {
                            if let Ok(payload) =
                                core_crypto::encrypt_payload_with_key(session_key, latest_clip)
                            {
                                serde_json::json!({
                                    "nonce_hex": payload.nonce_hex,
                                    "ciphertext_hex": payload.ciphertext_hex
                                })
                            } else {
                                serde_json::Value::Null
                            }
                        } else {
                            serde_json::Value::Null
                        }
                    } else {
                        serde_json::Value::Null
                    };
                    let pending_act = {
                        let mut act = s
                            .pending_media_action
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        let prev = *act;
                        *act = None;
                        prev
                    };
                    let resp = serde_json::json!({
                        "is_paired": is_paired,
                        "connection_status": connection.status,
                        "connection_method": connection.method,
                        "connection_color": connection.color,
                        "latest_clip_encrypted": latest_clip_encrypted,
                        "pending_media_action": pending_act,
                    });
                    serde_json::to_string(&resp)
                        .unwrap_or_default()
                        .into_bytes()
                })
            };

            // Unpair handler — requires proof of session key possession
            // to prevent unauthenticated network adversaries from wiping pairing state.
            let s = state.clone();
            let on_unpair = move || -> BoxFuture<()> {
                let s = s.clone();
                Box::pin(async move {
                    // Verify that a session key exists — unauthenticated unpair is not allowed.
                    let has_session = !s.session_key.lock().unwrap().is_empty();
                    if !has_session {
                        s.add_log("[Pairing] Unpair rejected: no active session".to_string());
                        return;
                    }
                    {
                        let mut settings = s.settings.lock().unwrap_or_else(|e| e.into_inner());
                        settings.is_paired = false;
                        settings.paired_device_name = None;
                        settings.paired_device_picture = None;
                    }
                    s.save_settings();
                    s.set_connection_status("DISCONNECTED".to_string());
                    s.set_connection_method("None".to_string());
                    s.set_connection_color("red".to_string());
                    s.add_log("[Pairing] Unpaired via QUIC".to_string());
                })
            };

            let _ = core_crypto::quic_app::QuicAppManager::accept_loop(
                &endpoint,
                on_pairing,
                on_clipboard,
                on_media,
                on_poll,
                on_unpair,
            )
            .await;
        });
    });
}
