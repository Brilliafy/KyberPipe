use crate::state::AppState;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

/// Clipboard read cache TTL — poll requests arrive every 2.5s from the phone;
/// re-reading the OS clipboard (arboard / wl-paste / xclip, each up to 3s) on
/// EVERY poll would stall the accept-loop runtime. Cache for 1s instead
/// (audit finding #9).
const CLIPBOARD_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// Cached clipboard bytes + wall-clock timestamp.
type ClipboardCacheEntry = (Instant, Vec<u8>);
static CLIPBOARD_CACHE: LazyLock<Mutex<Option<ClipboardCacheEntry>>> =
    LazyLock::new(|| Mutex::new(None));

/// TEST-ONLY hermetic override: when set, the poll handler treats the OS
/// clipboard as empty. The wire-level rekey e2e sets this so the desktop never
/// encrypts real clipboard content during the test — otherwise the desktop's
/// own send chain can cross seq 100 and, as the initiator, suppress the
/// client's rekey proposal (deterministic race outcome required by the test).
#[cfg(test)]
pub(crate) static FORCE_EMPTY_CLIPBOARD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// AUDIT P1-1 (HIGH): the single producer-side clipboard bound. The phone's
/// QUIC frame consumer hard-rejects any poll-response body over
/// `MAX_MESSAGE_SIZE` (1 MiB) at the header — the legacy producer had NO cap
/// (the OS clipboard ceiling is 10 MiB), so a clipboard beyond ~780 KB
/// produced a response the phone rejected on EVERY retry: the poll loop
/// stayed dead until the user cleared the clipboard. This constant is the
/// largest plaintext whose ratchet TLV (plaintext + 16 AEAD tag + 12 nonce +
/// ~22 B framing + up to ~2.3 KiB rekey payload at a rekey boundary) still
/// base64-encodes into a response body comfortably below 1 MiB: 3/4 × 1 MiB
/// is the base64 expansion of the plaintext alone; the 8 KiB slack covers the
/// TLV overhead AND the JSON wrapper plus the poll response's other fields.
/// (Worst case: 778,240 B plaintext → ~780.6 KiB TLV → ~1,040.8 KiB base64 +
/// ~350 B JSON < 1 MiB.) The Android companion enforces the same bound via
/// the shared UniFFI-exported `max_message_size()`.
const MAX_POLL_CLIPBOARD_PLAINTEXT: usize = core_crypto::quic_app::MAX_MESSAGE_SIZE * 3 / 4 - 8192;

/// Read the real clipboard through a 1s cache so the (potentially
/// multi-second) OS clipboard read never runs on the accept-loop workers more
/// than once per second, regardless of poll frequency.
fn cached_clipboard_read() -> Vec<u8> {
    #[cfg(test)]
    if FORCE_EMPTY_CLIPBOARD.load(std::sync::atomic::Ordering::Acquire) {
        return Vec::new();
    }
    let now = Instant::now();
    if let Ok(cache) = CLIPBOARD_CACHE.lock() {
        if let Some((at, bytes)) = cache.as_ref() {
            if now.duration_since(*at) < CLIPBOARD_CACHE_TTL {
                return bytes.clone();
            }
        }
    }
    // Cache miss — perform the blocking read (caller should be on a
    // spawn_blocking thread; see handle_poll).
    let content = crate::commands::read_real_clipboard_internal()
        .unwrap_or_default()
        .into_bytes();
    if let Ok(mut cache) = CLIPBOARD_CACHE.lock() {
        *cache = Some((Instant::now(), content.clone()));
    }
    content
}

/// Encapsulates which encryption method to use for a payload.
/// Encapsulation decision is made once at the start, then dispatched cleanly.
///
/// Audit KYP-2026-02 #17: the session-key hex path is deleted — the ratchet
/// TLV is the ONLY wire format, so the only decision left is whether a
/// ratchet session exists for the peer.
enum EncryptionMethod {
    Ratchet { peer_id: String },
    None,
}

/// Select the encryption method for a peer. Ratchet is used whenever a peer
/// identity is known; without one there is nothing to encrypt against.
fn select_encryption_method(peer_id: &str) -> EncryptionMethod {
    if !peer_id.is_empty() {
        EncryptionMethod::Ratchet {
            peer_id: peer_id.to_string(),
        }
    } else {
        EncryptionMethod::None
    }
}

/// Encrypt clipboard data using the selected method. Returns a JSON Value
/// or Null if encryption fails or is unavailable.
fn encrypt_clipboard_data(method: &EncryptionMethod, latest_clip: &[u8]) -> serde_json::Value {
    // AUDIT P1-1 (HIGH): enforce the producer-side frame bound HERE, at the
    // single place clipboard plaintext enters the wire. The phone's
    // `recv_frame_header` rejects any poll-response body > 1 MiB; an
    // oversized payload made EVERY retry fail identically (the desktop-side
    // dedup is inbound-only, so the clipboard never changed) — a permanent
    // poll-loop outage that also re-encrypted the oversized payload every 30s
    // on both ends. Skipping the payload (Null = "no new clipboard") keeps the
    // poll loop alive; the payload stays in the OS clipboard for a future
    // small copy, and the transfer is observable via the log.
    if latest_clip.len() > MAX_POLL_CLIPBOARD_PLAINTEXT {
        tracing::warn!(
            "[Poll] Skipping clipboard payload of {} bytes (producer cap {} bytes, audit P1-1) — \
             the phone's QUIC frame consumer would reject the >1 MiB response and wedge the poll loop",
            latest_clip.len(),
            MAX_POLL_CLIPBOARD_PLAINTEXT
        );
        return serde_json::Value::Null;
    }
    match method {
        EncryptionMethod::Ratchet { peer_id } => {
            // Audit finding #12: the ratchet payload is serialized as a single
            // base64-wrapped BINARY TLV (the UniFFI Record's `to_binary` framing)
            // instead of five independent hex fields — one serialization
            // contract shared by both platforms, no per-field drift surface.
            match core_crypto::ratchet_encrypt_message_binary(peer_id.clone(), latest_clip.to_vec())
            {
                Ok(bin) => serde_json::json!({
                    "encrypted_ratchet": {
                        "tlv_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin)
                    }
                }),
                Err(e) => {
                    tracing::warn!("[Poll] Ratchet encrypt failed for {peer_id}: {e}");
                    serde_json::Value::Null
                }
            }
        }
        EncryptionMethod::None => serde_json::Value::Null,
    }
}

/// Sync QUIC connection state with AppState.
/// Called on every poll to ensure the UI reflects the actual connection status.
fn sync_connection_state(s: &AppState) {
    core_crypto::quic_bridge::touch_connection();
    if !core_crypto::quic_bridge::is_quic_connected() {
        s.set_connection_status("DISCONNECTED".to_string());
        s.set_connection_color("red".to_string());
    }
}

/// Split of `handle_poll`: read the pairing/session state that drives the
/// response. Pure in-memory reads — no filesystem, keyring, or clipboard I/O
/// (audit finding #18).
fn read_local_state(s: &AppState) -> (String, bool, serde_json::Value, serde_json::Value) {
    let peer_id = s.get_pairing_initiator_pk();
    let is_paired = s.settings.lock().is_paired;
    let connection = s.get_connection();
    let pending_act = s.get_pending_media_action();
    let base = serde_json::json!({
        "is_paired": is_paired,
        "connection_status": connection.status,
        "connection_method": connection.method,
        "connection_color": connection.color,
        "pending_media_action": pending_act,
    });
    (peer_id, is_paired, base, connection.status.clone().into())
}

/// Parse the peer's poll REQUEST body for an ENCRYPTED `Synchronize` packet.
/// The Android poll loop sends its current send counter as a ratchet-encrypted
/// `KyberMessage::Synchronize` (`{ "sync": { nonce_hex, ciphertext_hex } }`);
/// the desktop processes it via `ratchet_process_synchronize`, which decrypts
/// (authenticating the sender), verifies the packet type, and only then resyncs
/// the receiving chain (audit finding #4 — the plaintext counter is NEVER
/// acted on, and resync is rate-limited / budget-bounded / generation-aware).
fn peer_sync_packet(body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    let v = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let sync = v.get("sync")?;
    let tlv_b64 = sync.get("tlv_b64")?.as_str()?;
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64).ok()
}

/// Whether the peer's poll REQUEST explicitly asked for a Synchronize carrier
/// (audit finding #16). The phone sets `need_sync` when its receive chain
/// actually needs realignment (a decrypt gap, or a slow heartbeat); the
/// desktop then attaches its ratchet-encrypted Synchronize packet — advancing
/// its OWN send chain — ONLY when asked. The legacy unconditional carrier
/// advanced the desktop's send chain at least once per poll (~34,560
/// positions/day), firing a rekey every ~4 minutes forever and generating
/// continuous two-sided race pressure.
fn peer_requested_sync(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("need_sync").and_then(|x| x.as_bool()))
        .unwrap_or(false)
}

/// Parse the peer's poll REQUEST body for an ENCRYPTED `RekeyAck` TLV — the
/// phone's outbound RekeyAck channel (audit finding #1). The phone attaches
/// its ack of OUR outgoing proposal to the poll request; we decrypt it
/// rekey-aware and commit the proposal.
fn peer_rekey_ack_packet(body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    let v = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let ack = v.get("rekey_ack_encrypted")?;
    let tlv_b64 = ack.get("tlv_b64")?.as_str()?;
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tlv_b64).ok()
}

/// Dirty-flag gate for ratchet persistence (audit finding #11). The legacy
/// code rewrote the whole `ratchet_sessions.json` AND performed the keyring
/// watermark RPC on EVERY 2.5s poll — ~240k keyring writes/day even when
/// nothing changed. This tracks the last-persisted FULL watermark tuple
/// (epoch, generation, send, recv) per peer and only persists when a ratchet
/// actually mutated. (Type alias keeps the clippy::type_complexity lint happy.)
///
/// AUDIT P1-2: the tuple INCLUDES `pairing_epoch`. A re-pair's fresh session
/// starts at (epoch 1, 0, 0, 0); without the epoch component, a re-pair that
/// happened while this process had no prior entry for the peer (restart
/// between re-pair and the first post-re-pair poll) compared (0,0,0) against
/// (0,0,0) and skipped the persist — leaving the OLD pre-re-pair snapshot in
/// the store, which the epoch-aware restore guard then accepted at the next
/// boot and silently desynced against the phone's fresh session.
type LastPersistedState = std::collections::HashMap<String, (u64, u32, u64, u64)>;
static LAST_PERSISTED_STATE: LazyLock<Mutex<LastPersistedState>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Whether the ratchet for `peer` mutated past what was last persisted. Reads
/// the live watermark WITHOUT advancing anything and WITHOUT serializing the
/// session. `recv` is the receiver's own inbound chain (advanced by processing
/// the peer's sync/ack above), `send` the outbound chain.
///
/// AUDIT #9: the legacy dirty-check called `ratchet_export_session` — a FULL
/// serde_json serialization of the root key, chain keys, ML-KEM/X25519 secret
/// halves and skip keys — every 2.5s on every poll, then re-parsed the JSON
/// for `ratchet_generation`, leaving the complete secret material in a plain
/// (non-Zeroizing) heap Vec ~34,560 times/day. The watermark accessor
/// (`ratchet_session_watermark`) reads the same four counters under the
/// session lock with no serialization at all.
fn ratchet_dirty_since_last_persist(peer: &str) -> bool {
    let wm = match core_crypto::ratchet_session_watermark(peer.to_string()) {
        Ok(Some(w)) => w,
        _ => return false,
    };
    let (epoch, gen, send, recv) = (
        wm.pairing_epoch,
        wm.ratchet_generation,
        wm.send_message_count,
        wm.recv_message_count,
    );
    let mut guard = LAST_PERSISTED_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let last = guard.get(peer).copied().unwrap_or((0, 0, 0, 0));
    let dirty = (epoch, gen, send, recv) != last;
    if dirty {
        guard.insert(peer.to_string(), (epoch, gen, send, recv));
    }
    dirty
}

/// Split of `handle_poll`: consume the peer's poll-REQUEST ratchet fields
/// (Synchronize + RekeyAck), encrypt the clipboard, persist, and produce the
/// response's ratchet-encrypted payloads (clip, ack, sync).
///
/// AUDIT #8: EVERY ratchet-mutating call — processing the peer's Synchronize
/// and RekeyAck, generating our ack peek and our Synchronize carrier — runs
/// inside the SAME spawn_blocking closure as the clipboard read + persistence,
/// so the 2-worker IO accept-loop async task only marshals JSON. The legacy
/// code left ack generation and sync processing inline on the accept-loop
/// task, where `ratchet_encrypt`/`ratchet_decrypt_with_rekey` can run ML-KEM
/// encapsulate/decapsulate inside the per-session mutex (tens of ms) at a
/// rekey boundary — blocking a second peer's stream and the clipboard push.
/// `need_sync` gates the Synchronize carrier (audit finding #16): the desktop
/// only advances its own send chain to attach a sync packet when the phone
/// asked for one.
async fn build_poll_response(
    peer_id: &str,
    base: serde_json::Value,
    need_sync: bool,
    body: Vec<u8>,
) -> serde_json::Value {
    let peer = peer_id.to_string();

    // All blocking I/O (OS clipboard read + keyring + full-file persistence)
    // AND all ratchet-mutating work is delegated to the tokio blocking pool,
    // sized independently of the 2-worker IO accept-loop runtime (audit #8).
    let (latest_clip_encrypted, ack_bin, sync_bin) = tokio::task::spawn_blocking(move || {
        // 1. Consumer for the Synchronize recovery path (audit finding #4):
        // the peer sends its send counter as a RATCHET-ENCRYPTED Synchronize
        // packet. Only an authenticated, verified Synchronize can trigger a
        // resync; the plaintext counter is never acted on. The core
        // additionally refuses resync across an unconsumed pending rekey,
        // enforces a persisted cumulative budget, and rate-limits per peer.
        if !peer.is_empty() {
            if let Some(data) = peer_sync_packet(&body) {
                match core_crypto::ratchet_process_synchronize(peer.clone(), data) {
                    Ok(skipped) => {
                        if skipped > 0 {
                            tracing::info!(
                                "[Sync] Authenticated Synchronize from {peer} advanced receive chain by {skipped}"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::info!("[Sync] Synchronize from {peer} not applied: {e}");
                    }
                }
            }
            // 2. Consumer for the phone's outbound RekeyAck (audit finding
            // #1): the phone attaches its encrypted ack of OUR outgoing
            // proposal to the poll request. Processing it commits our outgoing
            // rekey; without this channel the desktop's
            // rekey_pending_confirm_queue would stay occupied forever.
            if let Some(data) = peer_rekey_ack_packet(&body) {
                match core_crypto::ratchet_process_rekey_ack_binary(peer.clone(), data) {
                    Ok(true) => tracing::info!(
                        "[RekeyAck] Phone acked our outgoing rekey — committed (peer {peer})"
                    ),
                    Ok(false) => {}
                    Err(e) => {
                        tracing::info!("[RekeyAck] Phone RekeyAck not applied: {e}");
                    }
                }
            }
        }

        // 3. Clipboard read + encrypt + persistence (blocking).
        let latest_clip = cached_clipboard_read();
        let latest_clip_encrypted = if latest_clip.is_empty() {
            serde_json::Value::Null
        } else {
            let enc_method = select_encryption_method(&peer);
            encrypt_clipboard_data(&enc_method, &latest_clip)
        };
        // Persist ratchet state after any mutation this poll may have caused.
        // Keyring + full-file serde_json are blocking — keep them here on the
        // blocking pool, not on the accept-loop task. Wrapped with the
        // independent snapshot key (audit finding #15b).
        //
        // AUDIT (test hermeticity): under the FORCE_EMPTY_CLIPBOARD flag the
        // integration e2e runs fully hermetic — NO OS clipboard, NO keyring
        // RPC, NO zbus/D-Bus connection threads. The wire-level e2e exercises
        // pairing/poll/clipboard/rekey over real QUIC; the keyring persistence
        // is orthogonal to what it verifies and its per-poll Secret-Service
        // RPC (and the transient zbus threads it spawns) must not leak into
        // the test process.
        #[cfg(test)]
        let hermetic =
            crate::handlers::FORCE_EMPTY_CLIPBOARD.load(std::sync::atomic::Ordering::Acquire);
        #[cfg(not(test))]
        let hermetic = false;
        if !peer.is_empty() && !hermetic {
            if let Some(sk) = crate::ratchet_store::snapshot_key_from_keyring() {
                // AUDIT FINDING #11: persist ONLY when the ratchet actually
                // mutated since the last write. The legacy unconditional
                // persist performed a keyring watermark RPC + a full
                // `ratchet_sessions.json` rewrite on every 2.5s poll — ~240k
                // keyring writes/day and unbounded snapshot churn even when
                // nothing changed.
                if ratchet_dirty_since_last_persist(&peer) {
                    crate::ratchet_store::persist_all_ratchet_sessions(&sk);
                }
            }
        }

        // 4. Generate OUR ratchet-encrypted response payloads (ratchet-
        // mutating, same blocking closure — audit #8).
        //
        // AUDIT FINDING #6: the ack is generated NON-CONSUMING (peek). The
        // pending carrier is cleared only after the dispatch loop successfully
        // writes the response — if the response is lost on the wire, the ack
        // is re-derived on the next poll instead of being silently dropped.
        let ack_bin = if !peer.is_empty() {
            core_crypto::ratchet_generate_rekey_ack_binary_peek(peer.clone())
                .ok()
                .flatten()
        } else {
            None
        };
        // Producer for the Synchronize recovery path (audit finding #4): our
        // send counter is sent as a RATCHET-ENCRYPTED Synchronize packet so the
        // peer can authenticate the resync target. The packet is encoded as a
        // full BINARY TLV (audit finding #12): a ratchet message may carry a
        // rekey payload at seq 100/200, and dropping those fields would make
        // the ciphertext undecryptable (AEAD binds the rekey params).
        //
        // AUDIT FINDING #16: the carrier is now CONDITIONAL — it is only
        // generated when the phone asked for a sync (`need_sync`). Generating
        // it unconditionally advanced the desktop's send chain on every poll
        // AND collided with the per-peer 15s sync rate limit (5 of every 6
        // phone-requested syncs were rejected before decryption, so the
        // desktop's receive chain lagged the phone's send chain by up to ~6
        // positions every window). With the conditional carrier, the desktop
        // only advances its chain to answer an actual recovery need.
        let sync_bin = if need_sync && !peer.is_empty() {
            core_crypto::ratchet_synchronize_packet(peer.clone())
                .ok()
                .and_then(|m| m.to_binary().ok())
        } else {
            None
        };

        (latest_clip_encrypted, ack_bin, sync_bin)
    })
    .await
    .unwrap_or((serde_json::Value::Null, None, None));

    let mut resp = base;
    // AUDIT FINDING #18 (implicit cross-repo ordering contract): the poll
    // response field ORDER is a wire contract the Android `processResponse`
    // mirrors (clip → ack → sync, each decrypted in the peer's send space). A
    // future contributor reordering the inserts would silently desync the
    // phone (out-of-order decrypts → AEAD failures + Synchronize storms). The
    // response now carries an explicit `manifest` listing the exact insertion
    // order of the ratchet-encrypted fields, so the phone can validate its
    // processing order against the producer's and any drift fails loudly.
    let mut manifest: Vec<&str> = Vec::new();
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("latest_clip_encrypted".to_string(), latest_clip_encrypted);
    }
    manifest.push("latest_clip_encrypted");

    if let Some(bin) = ack_bin {
        if let Some(obj) = resp.as_object_mut() {
            obj.insert("rekey_ack_encrypted".to_string(), serde_json::json!({
                "tlv_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin)
            }));
            manifest.push("rekey_ack_encrypted");
        }
    }
    if let Some(bin) = sync_bin {
        if let Some(obj) = resp.as_object_mut() {
            obj.insert("sync".to_string(), serde_json::json!({
                "tlv_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin),
            }));
            manifest.push("sync");
        }
    }
    if let Some(obj) = resp.as_object_mut() {
        obj.insert(
            "manifest".to_string(),
            serde_json::json!(manifest.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        );
    }
    // AUDIT FINDING #4/#19: the plaintext `ratchet_send_count` field is
    // REMOVED. The only resync trigger is the authenticated Synchronize packet
    // above; a plaintext counter would be an unauthenticated forward-advance
    // oracle (the legacy Android loop acted on it).

    resp
}

pub(crate) async fn handle_poll(body: Vec<u8>, peer_id: String, s: Arc<AppState>) -> Vec<u8> {
    sync_connection_state(&s);
    // AUDIT F12: `peer_id` is resolved per-CONNECTION from the TLS-observed
    // client cert hash, so a second paired device's poll never decrypts
    // against (and corrupts) the first device's ratchet session.
    let (_legacy_peer, _is_paired, base, _conn) = read_local_state(&s);

    // AUDIT FINDING #16: the phone sets `need_sync` only when its receive
    // chain genuinely needs realignment (decrypt gap or slow heartbeat). The
    // desktop then attaches its Synchronize carrier ONLY in that case — never
    // unconditionally — decoupling the sync HEARTBEAT from sync RECOVERY and
    // removing the per-poll send-chain advance + the rate-limit collisions.
    let need_sync = peer_requested_sync(&body);
    // AUDIT #8: ALL ratchet-mutating work (consuming the peer's sync/ack and
    // generating our ack/sync payloads) happens inside the single
    // spawn_blocking closure in build_poll_response — never on this accept-loop
    // async task.
    let resp = build_poll_response(&peer_id, base, need_sync, body).await;
    serde_json::to_string(&resp)
        .unwrap_or_default()
        .into_bytes()
}
