//! Panic hook, destruct-generation counter and the pairing-keypair registry
//! zeroization (audit KYP-2026-02 #22 — extracted from the former `lib.rs`
//! monolith so the runtime lifecycle and the FFI record types live apart from
//! the process-wide destruction machinery).

use crate::error::KyberError;
use crate::kem_handle;
use crate::PqPairingPublic;
use zeroize::Zeroize;

/// Ensure panics in native Rust code never unwind across FFI boundaries (JNI/C ABI)
/// which causes Undefined Behavior.
static PANIC_HOOK_INIT: std::sync::Once = std::sync::Once::new();

/// Zeroize the process-global pairing keypair registry (audit finding #13),
/// every live ratchet session and every session-key handle (audit finding
/// #22). Invoked from the panic hook as a last-resort defense: if a panic
/// cannot be contained (e.g. a double panic that aborts), the raw private
/// halves held in the process-global registries are wiped before the process
/// dies. Safe under poison — a panicked thread that held the lock leaves a
/// poisoned mutex, which we recover via into_inner and take (zeroizing first).
///
/// AUDIT FINDING #22: the hook previously wiped ONLY the pairing keypair, so
/// an uncatchable abort path (double panic, OOM in allocator) left the ratchet
/// sessions (chain keys, ML-KEM secret keys) and session-key handles resident.
/// The documented `trigger_panic_hardware_wipe` covered them, but the LAST-
/// RESORT hook did not — and the abort path is exactly when the hook is the
/// only wipe that runs. All of these are best-effort under poison recovery:
/// a poisoned registry is cleared via into_inner rather than skipped.
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
    // Wipe every live ratchet session — DoubleRatchetState derives Zeroize, so
    // zeroizing the whole session clears chain keys, root keys and the ML-KEM
    // secret halves in one pass. Best-effort: a poisoned per-session mutex is
    // recovered via into_inner and zeroized rather than skipped.
    {
        let map_guard = crate::ratchet_ffi::registry::RATCHET_SESSIONS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for session_arc in map_guard.values() {
            if let Ok(mut session) = session_arc.lock() {
                session.zeroize();
            } else {
                let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
                session.zeroize();
            }
        }
    }
    crate::ratchet_ffi::registry::ratchet_clear_all_sessions_impl();
    // Destroy every session-key handle (zeroizing the key bytes on Arc drop).
    crate::session_handle::session_key_destroy_all();
    // Destroy the opaque KEM / keypair handles so no secret-bearing handle
    // survives the abort path.
    crate::kem_handle::destroy_all_pq_keypair_handles_impl();
    crate::kem_handle::destroy_all_kem_handles_impl();
}

/// Zeroize and clear the process-global pairing keypair registry (audit
/// KYP-2026-02 #15). The registry is the documented source of truth for the
/// pairing handler's private halves; without this, the private halves survived
/// `session_key_destroy_all` / `ratchet_clear_all_sessions` on the documented
/// API path. Wired into the desktop self-destruct, the unpair paths, and kept
/// as the panic-hook backstop via `zeroize_process_key_registry`.
#[uniffi::export]
pub fn clear_pq_pairing_registry() {
    zeroize_process_key_registry();
    // Also destroy the opaque keypair/KEM handles so no secret-bearing handle
    // survives a destruction transition (audit KYP-2026-02 #7/#15).
    kem_handle::destroy_all_pq_keypair_handles_impl();
    kem_handle::destroy_all_kem_handles_impl();
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

/// Process-global pairing keypair registry. Stores the internal
/// [`crate::SecretKeypair`] (audit F14) whose PRIVATE halves are `Zeroizing`
/// buffers — a clone handed out by `get_pq_pairing_keypair` is wiped on drop,
/// so the pairing handler's access path never leaves raw private bytes in freed
/// heap (a plain `PqKeyPair` clone would).
pub(crate) static PAIRING_KEYPAIR: std::sync::OnceLock<
    std::sync::Mutex<Option<crate::SecretKeypair>>,
> = std::sync::OnceLock::new();

/// Retrieve the keypair stored by `generate_pq_pairing_public` (if any).
/// Returns a ZEROIZING clone (audit F14): the private halves of the returned
/// value are wiped from the heap when the caller drops it.
pub fn get_pq_pairing_keypair() -> Option<crate::SecretKeypair> {
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
    let keypair = crate::SecretKeypair {
        x25519_pk: pair.x25519_pk.to_vec(),
        x25519_sk: zeroize::Zeroizing::new(pair.x25519_sk.to_vec()),
        mlkem_pk: pair.mlkem_pk.clone(),
        mlkem_sk: zeroize::Zeroizing::new(pair.mlkem_sk.to_vec()),
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
    Ok(keypair.public())
}
