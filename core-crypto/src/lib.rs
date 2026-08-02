pub mod crypto;
pub mod error;
pub mod network;
pub mod packets;
pub mod qr_scanner;
pub mod quic_app;
pub mod telemetry;

pub mod crypto_api;
pub mod ffi;
pub mod network_api;
pub mod p2p_group;
pub mod pairing_api;
pub mod quic_bridge;
pub mod ratchet_ffi;
pub mod session_handle;
pub mod system_net;

// Re-export domain API modules so callers can use `crate::function_name`
// and UniFFI bindings see a flat namespace.
pub use crypto_api::*;
pub use network_api::*;
pub use pairing_api::*;

use error::KyberError;
use std::future::Future;
use zeroize::Zeroize;

uniffi::setup_scaffolding!();

/// Ensure panics in native Rust code never unwind across FFI boundaries (JNI/C ABI)
/// which causes Undefined Behavior.
static PANIC_HOOK_INIT: std::sync::Once = std::sync::Once::new();

/// Zeroize the process-global pairing keypair registry (audit finding #13).
/// Invoked from the panic hook as a last-resort defense: if a panic cannot be
/// contained (e.g. a double panic that aborts), the raw private halves held in
/// the process-global registry are wiped before the process dies. Safe under
/// poison — a panicked thread that held the lock leaves a poisoned mutex,
/// which we recover via into_inner and take (zeroizing first).
fn zeroize_process_key_registry() {
    if let Some(cell) = PAIRING_KEYPAIR.get() {
        match cell.lock() {
            Ok(mut guard) => {
                if let Some(pair) = guard.as_mut() {
                    pair.zeroize();
                }
                guard.take();
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if let Some(pair) = guard.as_mut() {
                    pair.zeroize();
                }
                guard.take();
            }
        }
    }
}

pub fn ensure_panic_hook_installed() {
    PANIC_HOOK_INIT.call_once(|| {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            eprintln!("[CRITICAL ERROR] Panic occurred in core-crypto native layer: {info}");
            // Last-resort key wipe before the process can abort (double panic)
            // or before unwinding continues.
            zeroize_process_key_registry();
            prev_hook(info);
            // Do NOT abort. UniFFI's generated scaffolding wraps every exported
            // function in `panic::catch_unwind` and converts a panic into a
            // CALL_PANIC status, so a panic inside an FFI call is contained and
            // returned to the caller as a structured error — it never unwinds
            // across the C ABI. Aborting here would kill the whole app (and its
            // in-memory key material) for panics that are fully recoverable
            // (audit finding #13). The release profile is `panic = "unwind"` so
            // catch_unwind actually functions — the abort-contradiction is fixed
            // (audit finding #13).
        }));
    });
}

/// IO runtime for long-lived tasks (QUIC accept loop, beacon listeners).
/// Dedicated thread pool prevents FFI calls from starving the accept loop.
/// Stored as `Mutex<Option<Runtime>>` so `shutdown_io_runtime()` (test
/// teardown) can take ownership and stop the worker threads — a plain
/// `LazyLock<Runtime>` can never be shut down and would keep a test process
/// alive forever.
static IO_RUNTIME: std::sync::LazyLock<std::sync::Mutex<Option<tokio::runtime::Runtime>>> =
    std::sync::LazyLock::new(|| {
        std::sync::Mutex::new(Some(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("kyberpipe-io")
                .worker_threads(2)
                .build()
                .expect("Failed to create IO runtime"),
        ))
    });

/// FFI runtime for short-lived blocking calls from UniFFI (encrypt, decrypt, key ops).
/// Separate from IO_RUNTIME to prevent worker-thread exhaustion under concurrent FFI load.
/// Stored as `Mutex<Option<Runtime>>` so `shutdown_ffi_runtime()` (test teardown) can take
/// ownership and stop the worker threads — a plain `LazyLock<Runtime>` can never be shut
/// down and would keep a test process alive forever.
static FFI_RUNTIME: std::sync::LazyLock<std::sync::Mutex<Option<tokio::runtime::Runtime>>> =
    std::sync::LazyLock::new(|| {
        std::sync::Mutex::new(Some(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("kyberpipe-ffi")
                .worker_threads(2)
                .max_blocking_threads(64)
                .build()
                .expect("Failed to create FFI runtime"),
        ))
    });

/// Block on a future using the FFI runtime. Used for short-lived UniFFI bridge calls.
pub fn block_on_sync<F: Future>(fut: F) -> F::Output {
    let guard = FFI_RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .expect("FFI runtime was shut down (shutdown_ffi_runtime)")
        .block_on(fut)
}

/// Block on a future with timeout using the FFI runtime.
/// Returns `None` if the timeout expires. Use from FFI boundaries (e.g.,
/// Android JNI) where blocking indefinitely would exhaust the platform thread pool.
pub fn block_on_sync_timeout<F: Future>(fut: F, timeout: std::time::Duration) -> Option<F::Output> {
    let guard = FFI_RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .expect("FFI runtime was shut down (shutdown_ffi_runtime)")
        .block_on(tokio::time::timeout(timeout, fut))
        .ok()
}

/// Shut down the FFI runtime. TEST/TEARDOWN ONLY: the runtime is a process-wide
/// LazyLock; calling this in production would break every UniFFI bridge call.
/// The e2e test calls it so the worker threads do not keep the test process
/// alive. Bounded blocking shutdown (drain up to 5s, then hard-stop).
pub fn shutdown_ffi_runtime() {
    if let Ok(mut guard) = FFI_RUNTIME.lock() {
        if let Some(rt) = guard.take() {
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
        }
    }
}

/// Block on a future using the IO runtime. Used for long-lived tasks (accept loop).
pub fn block_on_io<F: Future>(fut: F) -> F::Output {
    let guard = IO_RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .expect("IO runtime was shut down (shutdown_io_runtime)")
        .block_on(fut)
}

/// Shut down the IO runtime. TEST/TEARDOWN ONLY: the runtime is a process-wide
/// LazyLock; calling this in production would break the accept loop. The e2e
/// test calls it after the dispatch loop stops so the test process can exit
/// (the worker threads would otherwise keep the process alive forever). Uses a
/// BOUNDED BLOCKING shutdown (audit finding #4 follow-up): `shutdown_background`
/// could leave worker threads running past the test and keep the harness pipe
/// open; `shutdown_timeout` drains for up to 5s then hard-stops the workers.
pub fn shutdown_io_runtime() {
    if let Ok(mut guard) = IO_RUNTIME.lock() {
        if let Some(rt) = guard.take() {
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
        }
    }
}

/// Generation counter — incremented on self-destruct. In-flight operations
/// with a stale generation are rejected.
static DESTRUCT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Check if the current generation is still valid (no self-destruct occurred).
pub fn check_generation() -> bool {
    DESTRUCT_GENERATION.load(std::sync::atomic::Ordering::Acquire) == 0
}

/// Increment the generation counter (called during self-destruct).
pub fn increment_destruct_generation() {
    DESTRUCT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Release);
}

/// Post-quantum hybrid keypair crossing the UniFFI boundary. Audit finding
/// #16: the private halves must not persist in freed heap after unpairing or
/// self-destruct. UniFFI's Record derive cannot coexist with a Drop impl
/// (its field move-out is incompatible with Drop), so zeroization is done
/// explicitly: every disposal path (desktop `CryptoState::set_keypair(None)`,
/// `clear_all_pairing`, self-destruct, the process-global registry) calls
/// `zeroize()` on the pair before dropping it.
#[derive(Clone, serde::Serialize, uniffi::Record, zeroize::Zeroize)]
pub struct PqKeyPair {
    pub x25519_pk: Vec<u8>,
    pub x25519_sk: Vec<u8>,
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

#[derive(uniffi::Record, zeroize::Zeroize)]
pub struct PqKeyPairRaw {
    pub x25519_pk: Vec<u8>,
    pub x25519_sk: Vec<u8>,
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

/// PUBLIC-ONLY key material for crossing the Tauri webview boundary. The secret
/// halves of the keypair NEVER leave the Rust process — the renderer receives
/// only the public keys needed to build pairing QR payloads, and the pairing
/// handler reads the private halves from Rust state.
#[derive(uniffi::Record, serde::Serialize, Clone)]
pub struct PqPairingPublic {
    pub x25519_pk_hex: String,
    pub mlkem_pk_hex: String,
}

impl From<&PqKeyPair> for PqPairingPublic {
    fn from(pair: &PqKeyPair) -> Self {
        Self {
            x25519_pk_hex: hex::encode(&pair.x25519_pk),
            mlkem_pk_hex: hex::encode(&pair.mlkem_pk),
        }
    }
}

#[derive(uniffi::Record)]
pub struct PqKemResponse {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// A generated per-install client identity certificate (audit finding #8).
/// `cert_der`/`key_der` are DER-encoded; `sha256_hex` is the cert fingerprint
/// the server pins during pairing.
#[derive(uniffi::Record)]
pub struct ClientIdentityCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub sha256_hex: String,
}

#[derive(uniffi::Record)]
pub struct EncryptedPayload {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PathChallengeResult {
    pub challenge_token: String,
    pub expected_response: String,
}

#[derive(uniffi::Record, serde::Serialize, serde::Deserialize, Clone)]
pub struct ConnectionInfo {
    pub active_tier: u32,
    pub active_path_description: String,
    pub latency_ms: f64,
    pub public_endpoint: String,
}

#[derive(uniffi::Record, serde::Serialize, serde::Deserialize, Clone)]
pub struct PairingConfig {
    pub host_identity_pk_hex: String,
    pub local_ip: String,
    pub wifi_direct_mac: String,
    pub p2p_ip: String,
    pub wireguard_pk_hex: String,
    pub stun_endpoint: String,
    pub pairing_nonce_hex: String,
}

// ── Double Ratchet FFI ──
// Double Ratchet FFI — peer-keyed session registry
/// Process-global pairing keypair registry. `generate_pq_pairing_public` stores
/// the FULL keypair (including private halves) here so a pairing handler can
/// decapsulate the peer's KEM ciphertext. Previously the private half was built
/// into a temporary and dropped — a latent API trap (audit finding #14).
static PAIRING_KEYPAIR: std::sync::OnceLock<std::sync::Mutex<Option<PqKeyPair>>> =
    std::sync::OnceLock::new();

/// Retrieve the keypair stored by `generate_pq_pairing_public` (if any).
pub fn get_pq_pairing_keypair() -> Option<PqKeyPair> {
    PAIRING_KEYPAIR
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|g| g.clone())
}

/// PUBLIC-ONLY key material for crossing the Tauri webview boundary. The secret
/// halves of the keypair NEVER leave the Rust process — the renderer receives
/// only the public keys needed to build pairing QR payloads, and the pairing
/// handler reads the private halves from the process-global registry populated
/// here (NOT a dropped temporary — audit finding #14).
#[uniffi::export]
pub fn generate_pq_pairing_public() -> Result<PqPairingPublic, KyberError> {
    ensure_panic_hook_installed();
    let pair = crate::crypto::generate_hybrid_keypair();
    let keypair = PqKeyPair {
        x25519_pk: pair.x25519_pk.to_vec(),
        x25519_sk: pair.x25519_sk.to_vec(),
        mlkem_pk: pair.mlkem_pk.clone(),
        mlkem_sk: pair.mlkem_sk.clone(),
    };
    // Persist the FULL keypair so a future pairing handler can decapsulate.
    let cell = PAIRING_KEYPAIR.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(mut guard) = cell.lock() {
        // Zeroize any previously-registered pair before replacing it (audit
        // finding #16: old private halves must not linger in the registry).
        if let Some(prev) = guard.as_mut() {
            prev.zeroize();
        }
        *guard = Some(keypair.clone());
    }
    Ok(PqPairingPublic::from(&keypair))
}

#[uniffi::export]
pub fn ratchet_init_session(
    peer_identity: String,
    master_shared_secret: Vec<u8>,
    is_initiator: bool,
    peer_x25519_pk: Vec<u8>,
    peer_mlkem_pk: Vec<u8>,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    let x25519 = if peer_x25519_pk.is_empty() {
        None
    } else {
        Some(peer_x25519_pk.as_slice())
    };
    let mlkem = if peer_mlkem_pk.is_empty() {
        None
    } else {
        Some(peer_mlkem_pk.as_slice())
    };
    ratchet_ffi::ratchet_init_session_impl(
        &peer_identity,
        &master_shared_secret,
        is_initiator,
        x25519,
        mlkem,
    )?;
    Ok("Session initialized".to_string())
}

/// Initialize a Double Ratchet session using the caller's OWN pairing keypair
/// as the ratchet's initial DH identity. This is the correct production entry
/// point (audit finding #1): the peer encapsulates rekey payloads to our
/// pairing public keys, so decapsulation must use the matching pairing private
/// keys — never a fresh, unexchanged keypair.
///
/// `our_x25519_pk`, `our_x25519_sk`, `our_mlkem_pk`, `our_mlkem_sk` are the
/// caller's own hybrid keypair (the public halves exchanged during pairing).
#[uniffi::export]
pub fn ratchet_init_session_with_keypair(
    peer_identity: String,
    master_shared_secret: Vec<u8>,
    is_initiator: bool,
    our_x25519_pk: Vec<u8>,
    our_x25519_sk: Vec<u8>,
    our_mlkem_pk: Vec<u8>,
    our_mlkem_sk: Vec<u8>,
    peer_x25519_pk: Vec<u8>,
    peer_mlkem_pk: Vec<u8>,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    let x25519 = if peer_x25519_pk.is_empty() {
        None
    } else {
        Some(peer_x25519_pk.as_slice())
    };
    let mlkem = if peer_mlkem_pk.is_empty() {
        None
    } else {
        Some(peer_mlkem_pk.as_slice())
    };
    ratchet_ffi::ratchet_init_session_with_keypair_impl(
        &peer_identity,
        &master_shared_secret,
        is_initiator,
        Some((our_x25519_pk, our_x25519_sk, our_mlkem_pk, our_mlkem_sk)),
        x25519,
        mlkem,
    )?;
    Ok("Session initialized".to_string())
}

#[uniffi::export]
pub fn ratchet_remove_session(peer_identity: String) -> bool {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_remove_session_impl(&peer_identity)
}
#[uniffi::export]
pub fn ratchet_clear_all_sessions() {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_clear_all_sessions_impl();
}
#[uniffi::export]
pub fn ratchet_peer_ids() -> Vec<String> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_peer_ids_impl()
}
#[uniffi::export]
pub fn ratchet_encrypt_message(
    peer_identity: String,
    plaintext: Vec<u8>,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_encrypt_message_impl(&peer_identity, &plaintext)
}

/// Encrypt a plaintext and return the ratchet message as a BINARY TLV frame
/// (audit finding #12). The binary framing is the single cross-platform
/// serialization contract — no hex-in-JSON drift surface and ~2x smaller than
/// hex-encoded fields.
#[uniffi::export]
pub fn ratchet_encrypt_message_binary(
    peer_identity: String,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    let msg = ratchet_ffi::ratchet_encrypt_message_impl(&peer_identity, &plaintext)?;
    msg.to_binary()
}

/// Decrypt a ratchet message from a BINARY TLV frame, rekey-aware (audit
/// finding #12). Handles the same rekey payloads as the hex path.
#[uniffi::export]
pub fn ratchet_decrypt_message_binary(
    peer_identity: String,
    data: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    let msg = crypto::RatchetEncryptedMessage::from_binary(&data)?;
    if msg.rekey_x25519_pk.is_some()
        || msg.rekey_mlkem_pk.is_some()
        || msg.rekey_ciphertext.is_some()
    {
        let rekey_x = msg
            .rekey_x25519_pk
            .as_deref()
            .map(|s| {
                <[u8; 32]>::try_from(s).map_err(|_| KyberError::InvalidKeyLength {
                    expected: 32,
                    got: s.len() as u64,
                })
            })
            .transpose()?;
        ratchet_ffi::ratchet_decrypt_with_rekey_message_impl(
            &peer_identity,
            &msg.nonce,
            &msg.ciphertext,
            msg.rekey_ciphertext.as_deref(),
            rekey_x.as_ref(),
            msg.rekey_mlkem_pk.as_deref(),
        )
    } else {
        ratchet_ffi::ratchet_decrypt_message_impl(&peer_identity, &msg.nonce, &msg.ciphertext)
    }
}

#[uniffi::export]
pub fn ratchet_decrypt_message(
    peer_identity: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    if nonce.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    ratchet_ffi::ratchet_decrypt_message_impl(&peer_identity, &nonce, &ciphertext)
}

#[uniffi::export]
pub fn ratchet_decrypt_with_rekey_message(
    peer_identity: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    rekey_ciphertext: Option<Vec<u8>>,
    rekey_x25519_pk: Option<Vec<u8>>,
    rekey_mlkem_pk: Option<Vec<u8>>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    if nonce.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    let rekey_x25519 = match rekey_x25519_pk.as_deref() {
        Some(s) => Some(s.try_into().map_err(|_| KyberError::InvalidKeyLength {
            expected: 32,
            got: s.len() as u64,
        })?),
        None => None,
    };
    ratchet_ffi::ratchet_decrypt_with_rekey_message_impl(
        &peer_identity,
        &nonce,
        &ciphertext,
        rekey_ciphertext.as_deref(),
        rekey_x25519,
        rekey_mlkem_pk.as_deref(),
    )
}

#[uniffi::export]
pub fn generate_rekey_ack_message(
    peer_identity: String,
    seq: u64,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::generate_rekey_ack_message_impl(&peer_identity, seq)
}

#[uniffi::export]
pub fn ratchet_process_rekey_ack(peer_identity: String, seq: u64) -> Result<bool, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_process_rekey_ack_impl(&peer_identity, seq)
}

/// Take the pending RekeyAck carrier seq (if any) and produce the encrypted
/// ACK message to send back to the peer. Returns None when no ACK is pending.
#[uniffi::export]
pub fn ratchet_generate_rekey_ack(
    peer_identity: String,
) -> Result<Option<crypto::RatchetEncryptedMessage>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_generate_rekey_ack_impl(&peer_identity)
}

/// Take the pending RekeyAck carrier seq and produce the encrypted ACK as a
/// BINARY TLV (audit finding #12), consuming the carrier in the same session
/// lock. This is the phone's outbound RekeyAck channel: the phone attaches the
/// returned TLV to its next poll request so the desktop can commit its
/// outgoing proposal (audit finding #1 — the missing phone→desktop ack).
#[uniffi::export]
pub fn ratchet_generate_rekey_ack_binary(
    peer_identity: String,
) -> Result<Option<Vec<u8>>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_generate_rekey_ack_binary_impl(&peer_identity)
}

/// NON-CONSUMING variant of `ratchet_generate_rekey_ack_binary`: produces the
/// ack TLV without clearing the pending carrier, so a poll response lost on
/// the wire can be retried (audit finding #6). Callers MUST clear the carrier
/// with `ratchet_consume_rekey_ack` only after the response is written.
#[uniffi::export]
pub fn ratchet_generate_rekey_ack_binary_peek(
    peer_identity: String,
) -> Result<Option<Vec<u8>>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_generate_rekey_ack_binary_peek_impl(&peer_identity)
}

/// Clear the pending RekeyAck carrier — called after a poll response carrying
/// the peeked ack has been successfully written (audit finding #6).
#[uniffi::export]
pub fn ratchet_consume_rekey_ack(peer_identity: String) -> bool {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_consume_rekey_ack_impl(&peer_identity)
}

/// Decrypt (rekey-aware) and process a peer's RekeyAck carried as a BINARY TLV
/// (audit finding #12): commits the peer's ack of OUR outgoing proposal. The
/// ack is decrypted rekey-aware because a ratchet message at a rekey boundary
/// carries a rekey payload whose AEAD tag binds those fields (audit finding
/// #3 — the non-rekey decrypt would drop it).
#[uniffi::export]
pub fn ratchet_process_rekey_ack_binary(
    peer_identity: String,
    data: Vec<u8>,
) -> Result<bool, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_process_rekey_ack_binary_impl(&peer_identity, &data)
}

/// Export a ratchet session as a serialized snapshot (JSON bytes) for
/// encrypted persistence. Returns None if no session exists for the peer.
#[uniffi::export]
pub fn ratchet_export_session(peer_identity: String) -> Result<Option<Vec<u8>>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_export_session_impl(&peer_identity)
}

/// Restore a ratchet session from a previously exported (and decrypted)
/// snapshot. Replaces any existing session for the peer.
#[uniffi::export]
pub fn ratchet_import_session(peer_identity: String, data: Vec<u8>) -> Result<(), KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_import_session_impl(&peer_identity, &data)
}

/// Resynchronize a ratchet session after the peer's authenticated Synchronize
/// message. Returns the number of messages skipped.
#[uniffi::export]
pub fn ratchet_synchronize_session(
    peer_identity: String,
    target_seq: u64,
) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_synchronize_session_impl(&peer_identity, target_seq)
}

/// Build an encrypted `Synchronize` packet carrying our current send counter.
/// The peer processes it via `ratchet_process_synchronize` — the ONLY path that
/// honors a resync target (audit finding #4: the plaintext counter in the poll
/// body is never acted on).
#[uniffi::export]
pub fn ratchet_synchronize_packet(
    peer_identity: String,
) -> Result<crypto::RatchetEncryptedMessage, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_synchronize_packet_impl(&peer_identity)
}

/// Binary-TLV variant of `ratchet_synchronize_packet` (audit finding #12):
/// returns the full TLV framing including any rekey payload the packet carried,
/// so the peer can process it rekey-aware via `ratchet_process_synchronize`.
#[uniffi::export]
pub fn ratchet_synchronize_packet_binary(peer_identity: String) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_synchronize_packet_binary_impl(&peer_identity)
}

/// Process a peer's encrypted Synchronize packet carried as a BINARY TLV:
/// decrypts it rekey-aware (authenticating the sender and adopting any rekey
/// payload the packet carried), verifies it is a `Synchronize`, and only then
/// resyncs our receiving chain to the authenticated target. Returns the number
/// of skipped messages. Refuses (rate-limited / pending rekey / budget
/// exhausted) per the audit finding #4 hardening.
#[uniffi::export]
pub fn ratchet_process_synchronize(
    peer_identity: String,
    data: Vec<u8>,
) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_process_synchronize_impl(&peer_identity, &data)
}

/// The receiver's current recv counter — used to build a Synchronize request
/// when a gap exceeds max_skip.
#[uniffi::export]
pub fn ratchet_recv_count(peer_identity: String) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_recv_count_impl(&peer_identity)
}

/// The sender's current send counter — carried in every poll response so the
/// peer can detect a receive-chain gap exceeding max_skip and resync (the
/// Synchronize recovery path, audit finding #4).
#[uniffi::export]
pub fn ratchet_send_count(peer_identity: String) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    ratchet_ffi::ratchet_send_count_impl(&peer_identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_handshake_flow() {
        let _alice = generate_pq_keypair().unwrap();
        let bob = generate_pq_keypair().unwrap();

        let kem_res = encapsulate_pq_secret(bob.x25519_pk.clone(), bob.mlkem_pk.clone()).unwrap();
        let decapsulated = decapsulate_pq_secret(
            kem_res.ciphertext.clone(),
            bob.x25519_sk.clone(),
            bob.mlkem_sk.clone(),
        )
        .unwrap();

        assert_eq!(kem_res.shared_secret, decapsulated);
    }

    /// Audit #14: `generate_pq_pairing_public` must retain the PRIVATE half of
    /// the pairing keypair in the registry so a pairing handler can later
    /// decapsulate the peer's KEM ciphertext. Regression: the private half used
    /// to be built into a temporary and dropped at the end of the call.
    #[test]
    fn test_pairing_public_retains_private_key() {
        // Clear any prior registry state.
        if let Some(cell) = PAIRING_KEYPAIR.get() {
            if let Ok(mut g) = cell.lock() {
                *g = None;
            }
        }
        let public = generate_pq_pairing_public().expect("pairing public");
        let stored = get_pq_pairing_keypair().expect("private half must survive");
        assert_eq!(stored.mlkem_pk, hex::decode(&public.mlkem_pk_hex).unwrap());
        assert_eq!(
            stored.x25519_pk,
            hex::decode(&public.x25519_pk_hex).unwrap()
        );
        assert!(
            !stored.mlkem_sk.is_empty(),
            "mlkem private key must be retained"
        );
        assert!(
            !stored.x25519_sk.is_empty(),
            "x25519 private key must be retained"
        );
    }
}
