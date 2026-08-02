pub mod automation;
mod bip39_words;
pub mod clipboard;
pub mod crypto;
pub mod info;
pub mod network;
pub mod network_tauri;
pub mod notifications;
pub mod pairing;
pub mod security;
pub mod settings;

pub use automation::*;
pub use clipboard::*;
pub use crypto::*;
pub use info::*;
pub use network::*;
pub use network_tauri::*;
pub use notifications::*;
pub use pairing::*;
pub use security::*;
pub use settings::*;

/// Uniform Tier-2 (destructive/privileged) gate (audit finding #20). Every
/// destructive Tauri command MUST call this as its FIRST statement, so the
/// privilege-token pattern is enforced per-TIER rather than ad-hoc per command.
/// A missing/expired/consumed token rejects the call before any side effect.
pub fn gate_tier2(action: &str, token: &str) -> Result<(), String> {
    if !security::consume_privilege_token(action, token) {
        return Err(format!(
            "Privileged action '{action}' requires a fresh user-gesture confirmation token"
        ));
    }
    Ok(())
}
