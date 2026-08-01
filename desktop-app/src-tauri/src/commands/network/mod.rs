//! Network command handlers for the Tauri desktop application.
//!
//! # Subsystems
//! This module combines several network subsystems that share the `AppState`
//! dependency but have independent security profiles:
//!
//! - **Connection Status** (`get_connection_status`, `evaluate_connection_status`): Read-only state queries
//! - **Firewall** (`check_firewall`, `request_firewall_open`): OS firewall modification (requires privilege)
//! - **P2P** (`create_p2p_group`): Wi-Fi Direct group creation
//! - **mDNS** (`register_mdns_service`): Local service advertisement
//! - **Tor** (`create_tor_onion`): Onion service creation
//!
//! # Security Notes
//! - Firewall operations use D-Bus Polkit authentication (not pkexec)
//! - P2P passphrases use 128-bit random entropy
//! - Tor control port uses cookie authentication

mod connection;
mod firewall;
mod mdns;
mod p2p;
mod tor;

pub use connection::*;
pub use firewall::*;
pub use mdns::*;
pub use p2p::*;
pub use tor::*;
