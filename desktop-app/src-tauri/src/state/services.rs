//! Service singletons (audit F20 split): each service now lives in its own
//! module under `state/services/` — crypto, pairing, network, ui, clipboard,
//! settings — with the coalescing persistence channel promoted to
//! `state/persist.rs`. This file is the module root: it declares the
//! submodules, re-exports the public service types (so every existing
//! `crate::state::services::X` path keeps working) and hosts the shared
//! poisoned-mutex recovery helper.

pub(crate) mod clipboard;
pub(crate) mod crypto;
pub(crate) mod network;
pub(crate) mod pairing;
pub(crate) mod settings;
pub(crate) mod ui;

use std::sync::Mutex;

pub use clipboard::ClipboardService;
pub use crypto::CryptoService;
pub use network::NetworkService;
pub use pairing::PairingService;
pub use settings::SettingsService;
pub use ui::UiService;

pub fn lock_state<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| {
        tracing::error!(
            "[CRITICAL STATE ERROR] Mutex poisoned! Recovering inner state: {:?}",
            e
        );
        e.into_inner()
    })
}
