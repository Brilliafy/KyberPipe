pub mod decrypt;
pub mod derive;
pub mod encrypt;
pub(crate) mod policy;
pub(crate) mod previous_generation;
pub(crate) mod resync;
pub mod snapshot;
pub mod state;
pub mod tlv;

#[cfg(test)]
mod tests;

// Re-exports for backward compatibility — the public surface is unchanged by
// the audit-finding-#11 module split: `DoubleRatchetState` + `RekeyCarrier`
// (state.rs), `RatchetSnapshot` (snapshot.rs), `RatchetEncryptedMessage`
// (tlv.rs) all remain reachable at `crate::crypto::ratchet::*`.
pub use snapshot::RatchetSnapshot;
pub use state::*;
pub use tlv::RatchetEncryptedMessage;
