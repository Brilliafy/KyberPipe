use crate::state::AppState;
use crate::state::PairingPhase;
use crate::state::SecureString;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Typed pairing request — supports both raw binary payload bytes and JSON fallback
#[derive(Deserialize)]
struct PairingRequest {
    #[serde(default)]
    ciphertext_hex: String,
    #[serde(default)]
    client_pk_hex: String,
    #[serde(default)]
    client_x25519_pk_hex: String,
    #[serde(default)]
    client_cert_hash_hex: String,
    #[serde(default)]
    #[serde(rename = "cert_hash_hex")]
    cert_hash_hex_alias: String,
    #[serde(default)]
    ciphertext_bytes: Vec<u8>,
    #[serde(default)]
    client_pk_bytes: Vec<u8>,
    #[serde(default)]
    client_x25519_pk_bytes: Vec<u8>,
    #[serde(default)]
    pairing_nonce_hex: String,
    #[serde(default = "default_device_name")]
    #[allow(dead_code)]
    name: String,
}

fn default_device_name() -> String {
    "Android Phone".to_string()
}

use std::collections::HashMap;
use std::net::IpAddr;

/// Per-IP attempt budget per sliding window — defeats spoofed-source-IP
/// spraying of pairing requests (audit finding #20).
const PAIRING_PER_IP_MAX: u32 = 10;
const PAIRING_WINDOW_SECS: u64 = 60;
/// Global attempt budget across ALL sources per window.
const PAIRING_GLOBAL_MAX: u32 = 200;

struct RateEntry {
    last_attempt: Instant,
    attempts: u32,
    window_start: Instant,
}

/// (global-floor instant, per-IP entries, global budget, window start).
type RateLimiterState = (Instant, HashMap<IpAddr, RateEntry>, u32, Instant);

static PAIRING_RATE_LIMITER: std::sync::LazyLock<std::sync::Mutex<RateLimiterState>> =
    std::sync::LazyLock::new(|| {
        std::sync::Mutex::new((
            Instant::now() - std::time::Duration::from_secs(5),
            HashMap::new(),
            0,
            Instant::now(),
        ))
    });

/// Per-IP + global rate limiting with a shared counter. Returns false when the
/// request must be dropped (global throttle, per-IP budget exhausted, or the
/// 2s per-IP cooldown).
fn check_pairing_rate_limit(peer_ip: Option<IpAddr>) -> bool {
    let now = Instant::now();
    let mut guard = PAIRING_RATE_LIMITER
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // Global floor: at most one pairing attempt per 200ms process-wide.
    if now.duration_since(guard.0).as_millis() < 200 {
        return false;
    }
    guard.0 = now;

    // Global budget: reset the window every PAIRING_WINDOW_SECS.
    if now.duration_since(guard.3).as_secs() >= PAIRING_WINDOW_SECS {
        guard.2 = 0;
        guard.3 = now;
        guard.1.clear();
    }
    if guard.2 >= PAIRING_GLOBAL_MAX {
        return false;
    }
    guard.2 += 1;

    if let Some(ip) = peer_ip {
        if guard.1.len() > 1000 {
            guard
                .1
                .retain(|_, e| now.duration_since(e.last_attempt).as_secs() < PAIRING_WINDOW_SECS);
        }
        let is_new = !guard.1.contains_key(&ip);
        let entry = guard.1.entry(ip).or_insert(RateEntry {
            last_attempt: now,
            attempts: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start).as_secs() >= PAIRING_WINDOW_SECS {
            entry.attempts = 0;
            entry.window_start = now;
        }
        // First request from an IP is always allowed; afterwards a 2s cooldown
        // applies between requests.
        if !is_new && now.duration_since(entry.last_attempt).as_secs() < 2 {
            return false;
        }
        if entry.attempts >= PAIRING_PER_IP_MAX {
            return false;
        }
        entry.last_attempt = now;
        entry.attempts += 1;
    }
    true
}

/// Opaque session key handle for the desktop side. Created during pairing,
/// used for decrypt/encrypt instead of passing raw key bytes.
pub(crate) static DESKTOP_SESSION_KEY_HANDLE: AtomicU64 = AtomicU64::new(0);

/// (ciphertext, mlkem_pk, x25519_pk, cert_hash, nonce_hex) of a binary pairing
/// frame. The nonce field was added (audit finding #12): the legacy binary
/// frame carried no nonce, so a binary pairing body could never satisfy the
/// QR-nonce check (which parsed the body as JSON first) and the binary
/// transport was unreachable dead code with a latent nonce-bypass. Both
/// formats now carry and validate the SAME QR-bound nonce.
type PairingFrame = (Vec<u8>, Vec<u8>, Vec<u8>, String, String);

/// Decode a binary pairing frame (audit finding #12: carries the QR nonce).
/// `pub(crate)` so the wire-format tests can pin the decoder contract.
pub(crate) fn decode_binary_pairing_frame(payload: &[u8]) -> Option<PairingFrame> {
    let mut cursor = 0;
    if payload.len() < 4 {
        return None;
    }
    let ct_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    if payload.len() < cursor + ct_len + 4 {
        return None;
    }
    let ct = payload[cursor..cursor + ct_len].to_vec();
    cursor += ct_len;

    let pk_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    if payload.len() < cursor + pk_len + 4 {
        return None;
    }
    let pk = payload[cursor..cursor + pk_len].to_vec();
    cursor += pk_len;

    let x25519_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    if payload.len() < cursor + x25519_len + 4 {
        return None;
    }
    let x25519_pk = payload[cursor..cursor + x25519_len].to_vec();
    cursor += x25519_len;

    let ch_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    if payload.len() < cursor + ch_len {
        return None;
    }
    let cert_hash = String::from_utf8(payload[cursor..cursor + ch_len].to_vec()).ok()?;
    cursor += ch_len;

    // Optional trailing nonce (audit finding #12): length-prefixed so a frame
    // written by a legacy client that never embedded the nonce still decodes
    // (with an empty nonce — which is then REJECTED by the per-format nonce
    // validation, exactly as a JSON body without a nonce is).
    let nonce_hex = if payload.len() >= cursor + 4 {
        let n_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
        cursor += 4;
        if payload.len() < cursor + n_len {
            return None;
        }
        String::from_utf8(payload[cursor..cursor + n_len].to_vec()).ok()?
    } else {
        String::new()
    };

    Some((ct, pk, x25519_pk, cert_hash, nonce_hex))
}

pub(crate) async fn handle_pairing(
    body: Vec<u8>,
    peer_ip: Option<IpAddr>,
    peer_cert_hash: String,
    s: Arc<AppState>,
) -> Vec<u8> {
    // AUDIT #1 (CRITICAL, post-pairing mTLS): the pairing identity MUST be the
    // TLS-OBSERVED client certificate hash. A phone that connects WITHOUT a
    // client cert would leave `peer_cert_hash` empty — the pin/map/mTLS-rebind
    // block in `perform_sas_confirmation` is then skipped and every post-pairing
    // stream is rejected against an empty pinned set ("paired but nothing
    // syncs"). Fail LOUDLY instead: a cert-less pairing can never produce a
    // working data plane, so reject it before any KEM work. The phone presents
    // its per-install identity cert on the bootstrap connect too (single
    // connect path, no cert-less pairing variant). This gate runs BEFORE the
    // rate limiter so a flood of cert-less attempts is not misclassified as
    // rate limiting (and a rejected cert-less attempt does not consume the
    // budget for a legitimate peer).
    if peer_cert_hash.is_empty() {
        s.add_log(
            "[Pairing] Rejected: client did not present an identity certificate — mTLS pairing is mandatory (audit finding #1)"
                .to_string(),
        );
        s.fail_pairing();
        return r#"{"status":"error","reason":"Client certificate required for pairing"}"#
            .to_string()
            .into_bytes();
    }
    if !check_pairing_rate_limit(peer_ip) {
        s.add_log("[Pairing] Rate limited — too many pairing requests".to_string());
        return r#"{"status":"error","reason":"Rate limited"}"#.to_string().into_bytes();
    }
    {
        let settings = s.settings.lock();
        if settings.is_paired {
            s.add_log("[Pairing] Rejected: already paired. Unpair first to re-pair.".to_string());
            // Audit KYP-2026-02 #12: every pairing rejection must terminate the
            // phase machine in Failed — never a dangling PendingKem/Confirmed.
            s.fail_pairing();
            return r#"{"status":"error","reason":"Already paired"}"#
                .to_string()
                .into_bytes();
        }
    }
    // AUDIT #6 (already-in-progress guard): the check MUST run BEFORE
    // clearing stale state. The legacy sequence called `clear_pairing_stale()`
    // (an alias of `begin_pairing_attempt`, which clears sas_code and
    // pending_session_key) FIRST — so `is_pairing_pending()` — which requires
    // BOTH a non-empty SAS code AND a non-empty pending session key — was
    // always false and the "already in progress" rejection could never fire.
    // Two phones scanning the same QR could therefore both pass the nonce gate
    // and clobber each other's pending KEM/SAS state. Inverted: reject while a
    // SAS verification is genuinely pending (a previous KEM landed), then
    // begin a fresh attempt only after the stale-state guard passes.
    //
    // The slot is ALSO gated by the explicit PairingPhase machine: only
    // Idle/TimedOut/Failed may start a new attempt. PendingKem / SasPending /
    // Confirmed are mid-flight (or already-promoted) states that a new attempt
    // must never clobber.
    let phase = s.pairing_phase();
    if matches!(
        phase,
        PairingPhase::PendingKem | PairingPhase::SasPending | PairingPhase::Confirmed
    ) {
        s.add_log(format!(
            "[Pairing] Rejected: pairing phase {phase:?} is mid-flight — complete or timeout first (audit finding #6)"
        ));
        s.fail_pairing();
        return r#"{"status":"error","reason":"Pairing already in progress"}"#
            .to_string()
            .into_bytes();
    }
    if s.is_pairing_pending() {
        s.add_log(
            "[Pairing] Rejected: SAS verification already in progress. Complete or timeout first."
                .to_string(),
        );
        s.fail_pairing();
        return r#"{"status":"error","reason":"Pairing already in progress"}"#
            .to_string()
            .into_bytes();
    }
    // Audit finding #24: every pairing state change flows through the phase
    // transitions on PairingService — begin_pairing_attempt resets the
    // per-attempt fields (and preserves the mandatory QR nonce).
    s.begin_pairing_attempt();

    // Audit KYP-2026-02 #12: ONE bounded SAS-window timeout task per attempt,
    // spawned for EVERY attempt (not only once a SAS code is computed) so a
    // KEM-valid but client-pk-less request can never leave a dangling
    // PendingKem with no timeout. The task captures this attempt's generation
    // and fires only when the generation still matches AND the phase is still
    // SasPending — a later begin_pairing_attempt (generation bump) or
    // confirm/fail/timeout transition invalidates it, preserving the original
    // 180s SAS-window semantics exactly.
    let timeout_state = s.clone();
    let attempt_generation = s.get_pairing_generation();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(180)).await;
        if timeout_state.get_pairing_generation() == attempt_generation
            && timeout_state.pairing_phase() == PairingPhase::SasPending
        {
            timeout_state.timeout_pairing();
            super::IS_SESSION_KEY_AUTHENTICATED.store(false, Ordering::Release);
            timeout_state.set_connection_status("DISCONNECTED".to_string());
            timeout_state.set_connection_color("red".to_string());
            timeout_state
                .add_log("[Pairing] SAS timeout — pending session cleared after 180s".to_string());
            super::emit_app_event("pairing::timeout", serde_json::json!({ "pending": false }));
        }
    });

    // Record the peer identity at pairing time so post-pairing streams can be
    // authorized to this peer only. The identity is the TLS-OBSERVED client
    // certificate hash captured from the QUIC connection at handshake time —
    // unforgeable by the client (audit finding #11). It must NEVER be replaced
    // by a hash the client claims in the request body.
    s.set_pending_client_cert_hash(peer_cert_hash.clone());
    if let Some(ip) = peer_ip {
        s.set_paired_peer_ip(ip.to_string());
    }

    // QR nonce binding (audit finding #20): the phone must echo the nonce this
    // desktop issued when it generated the pairing QR. An attacker who races
    // the legitimate device cannot know the nonce, so blind pairing-slot
    // hijack is defeated. The nonce is MANDATORY: a missing nonce (no QR was
    // ever generated, or it was cleared) rejects the pairing outright — the
    // old empty-nonce skip let any LAN peer with the desktop's public keys
    // complete a KEM handshake before a QR existed.
    let expected_nonce = s.get_pending_pairing_nonce();
    if expected_nonce.is_empty() {
        s.add_log(
            "[Pairing] Rejected: no pairing nonce has been issued — generate a pairing QR first"
                .to_string(),
        );
        s.fail_pairing();
        return r#"{"status":"error","reason":"No pairing nonce issued"}"#
            .to_string()
            .into_bytes();
    }

    // AUDIT #12 (binary pairing frame): the nonce check previously parsed the
    // body as JSON BEFORE the binary-frame branch, so a binary body could never
    // satisfy it (any binary body yields an empty supplied nonce and is
    // rejected) — the binary transport was unreachable dead code, and a naive
    // reorder of the checks would have let the binary path skip the nonce
    // entirely. The nonce is now extracted PER-FORMAT inside the dispatch and
    // both formats validate identically against the same QR-bound nonce.
    //
    // Pure binary QUIC frame transport vs JSON fallback. Returns
    // (ciphertext, client_pk, client_x25519_pk, cert_hash, supplied_nonce).
    let parsed = if body.len() > 3 && body[0] == 0x4B && body[1] == 0x50 && body[2] == 0x00 {
        // Direct zero-copy binary frame transport (No JSON parsing)
        if let Some((ct, pk, x25519_pk, cert_hash, nonce_hex)) =
            decode_binary_pairing_frame(&body[3..])
        {
            (ct, pk, x25519_pk, cert_hash, nonce_hex)
        } else {
            s.fail_pairing();
            return r#"{"status":"error","reason":"Invalid binary frame payload"}"#
                .to_string()
                .into_bytes();
        }
    } else {
        let body_str = String::from_utf8_lossy(&body);
        let req = match serde_json::from_str::<PairingRequest>(&body_str) {
            Ok(r) => r,
            Err(_) => {
                s.fail_pairing();
                return r#"{"status":"error","reason":"Invalid JSON"}"#.to_string().into_bytes();
            }
        };
        let ct = if !req.ciphertext_bytes.is_empty() {
            req.ciphertext_bytes
        } else {
            hex::decode(&req.ciphertext_hex).unwrap_or_default()
        };
        let pk = if !req.client_pk_bytes.is_empty() {
            req.client_pk_bytes
        } else {
            hex::decode(&req.client_pk_hex).unwrap_or_default()
        };
        let x25519_pk = if !req.client_x25519_pk_bytes.is_empty() {
            req.client_x25519_pk_bytes
        } else {
            hex::decode(&req.client_x25519_pk_hex).unwrap_or_default()
        };
        (
            ct,
            pk,
            x25519_pk,
            if req.cert_hash_hex_alias.is_empty() {
                req.client_cert_hash_hex
            } else {
                req.cert_hash_hex_alias
            },
            req.pairing_nonce_hex,
        )
    };
    let (ciphertext, client_pk, client_x25519_pk, cert_hash, supplied_nonce) = parsed;
    // Per-format nonce validation (audit finding #12): BOTH the JSON and the
    // binary path land here with their format's nonce, and both must satisfy
    // the identical QR-bound check. A missing or mismatched nonce is rejected
    // exactly like the JSON path always was — no nonce bypass for binary.
    if supplied_nonce.is_empty() || supplied_nonce != expected_nonce {
        s.add_log(
            "[Pairing] Rejected: pairing QR nonce mismatch — possible blind race".to_string(),
        );
        s.fail_pairing();
        return r#"{"status":"error","reason":"Pairing nonce mismatch"}"#
            .to_string()
            .into_bytes();
    }
    if !ciphertext.is_empty() {
        // AUDIT F6: the ML-KEM decapsulation, session-key derivation and SAS
        // computation are CPU-heavy and can block on keyring RPC. Running them
        // inline on the accept-loop task would starve the 2-worker IO runtime
        // (a single slow pairing would stop accepting new connections). Delegate
        // to the tokio blocking pool exactly like `build_poll_response` does.
        let kem_outcome = {
            let pair = s.get_keypair();
            // AUDIT F14: `get_keypair()` returns a raw PqKeyPair clone whose
            // private halves would linger in freed heap when the clone drops.
            // The private-half clones extracted below are consumed by
            // `decapsulate_pq_secret`, which zeroizes them; the `pair` clone
            // itself is zeroized here before it drops.
            let pair_for_blocking = pair.map(|mut p| {
                let out = (p.mlkem_pk.clone(), p.mlkem_sk.clone(), p.x25519_sk.clone());
                use zeroize::Zeroize;
                p.zeroize();
                out
            });
            let client_pk = client_pk.clone();
            tokio::task::spawn_blocking(move || {
                let (our_mlkem_pk, our_mlkem_sk, our_x25519_sk) = pair_for_blocking?;
                let shared_secret =
                    core_crypto::decapsulate_pq_secret(ciphertext, our_x25519_sk, our_mlkem_sk)
                        .ok()?;
                let ss_for_sas = shared_secret.clone();
                // Canonical domain-separation salt — same bytes both platforms
                // consume (audit finding #2). Never re-encode at a call site.
                let salt = core_crypto::crypto::SESSION_KEY_DERIVATION_SALT.to_vec();
                let sk = core_crypto::derive_session_key(shared_secret, salt).ok()?;
                let sas = if client_pk.is_empty() {
                    None
                } else {
                    core_crypto::generate_sas_code(our_mlkem_pk, client_pk, ss_for_sas.clone()).ok()
                };
                Some((
                    hex::encode(&sk),
                    hex::encode(&ss_for_sas),
                    sas.unwrap_or_default(),
                ))
            })
            .await
            .unwrap_or(None)
        };
        if let Some((sk_hex, ss_hex, sas_code)) = kem_outcome {
            s.set_pending_session_key(SecureString::new(sk_hex));
            s.set_pending_shared_secret(SecureString::new(ss_hex));
            // Audit finding #11: the pinned client identity is the
            // TLS-OBSERVED certificate hash captured at handshake time
            // (already stored above) — never the client-claimed hash
            // from the request body. The claimed hash, when present, is
            // used ONLY as a cross-check and must equal the connection
            // hash; a mismatch is a protocol violation (the client is
            // not presenting the identity it claims).
            if !cert_hash.is_empty() && !peer_cert_hash.is_empty() && cert_hash != peer_cert_hash {
                s.add_log(
                    "[Pairing] Rejected: client-claimed cert hash does not match the TLS-presented certificate".to_string(),
                );
                s.fail_pairing();
                return r#"{"status":"error","reason":"Certificate hash mismatch"}"#
                    .to_string()
                    .into_bytes();
            }

            if !client_pk.is_empty() {
                s.set_pairing_initiator_pk(hex::encode(&client_pk));
            }
            if !client_x25519_pk.is_empty() {
                s.set_pairing_initiator_x25519_pk(hex::encode(&client_x25519_pk));
            }
            s.add_log(
                "[Session] Derived session key from KEM handshake (pending SAS confirmation)"
                    .to_string(),
            );

            if !client_pk.is_empty() && !sas_code.is_empty() {
                s.set_sas_code(sas_code);
                s.add_log("[Session] SAS code generated — awaiting OOB verification".to_string());
                // Transition: PendingKem → SasPending.
                s.promote_to_sas_pending();
                // AUDIT FINDING #15 (single-use nonce): the QR nonce has served
                // its purpose for THIS phone. Consuming it means a SECOND phone
                // that read the same QR (or an attacker who observed it) can no
                // longer reuse it to race the pairing slot — a fresh nonce is
                // re-issued only when the user builds a NEW QR. This bounds the
                // slot race to a single legitimate attempt per QR.
                let consumed_nonce = s.consume_pairing_nonce();
                s.add_log(format!(
                    "[Pairing] QR pairing nonce consumed (single-use) — {} slot locked to this attempt",
                    if consumed_nonce.is_empty() { "no nonce" } else { "nonce" }
                ));
                // Push the SAS to the webview so the UI can render the
                // verification modal (audit finding #7 — the modal was
                // previously dead code because nothing populated it).
                super::emit_app_event(
                    "pairing::sas-ready",
                    serde_json::json!({
                        "sas_code": s.get_sas_code(),
                        "pending": true,
                    }),
                );

                s.set_connection_status("PAIRING_PENDING_SAS".to_string());
                s.set_connection_method("QUIC mTLS".to_string());
                s.set_connection_color("yellow".to_string());
                s.add_log("[Pairing] Received pairing handshake. SAS code available — waiting for OOB confirmation".to_string());
                // The SAS-window timeout for THIS attempt was already
                // spawned right after begin_pairing_attempt() above
                // (audit KYP-2026-02 #12) — it fires only while the
                // phase is still SasPending and the generation matches.
                let resp = serde_json::json!({
                    "status": "pairing_pending_sas",
                });
                return serde_json::to_string(&resp)
                    .unwrap_or_default()
                    .into_bytes();
            }
        }
    }

    s.fail_pairing();
    s.add_log("[Pairing] Handshake failed: KEM decapsulation error".to_string());
    r#"{"status":"error","reason":"Decapsulation failed"}"#
        .to_string()
        .into_bytes()
}
