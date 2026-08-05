//! Network command handlers for the Tauri desktop application.
//!
//! # Subsystems
//! This module combines several network subsystems that share the `AppState`
//! dependency but have independent security profiles:
//!
//! - **Connection Status** (`get_connection_status`, `evaluate_connection_status`): Read-only state queries
//! - **Firewall** (`check_firewall`, `request_firewall_open`): OS firewall modification (requires privilege)
//! - **mDNS** (`register_mdns_service`): Local service advertisement
//! - **Tor** (`create_tor_onion`): Onion service creation
//!
//! # Security Notes
//! - Firewall operations use D-Bus Polkit authentication (not pkexec)
//! - Tor control port uses cookie authentication
//!
//! # Removed subsystem
//! Wi-Fi Direct (P2P) group creation was REMOVED (audit finding #1): the
//! group was never actually WPA2-secured (the passphrase was never applied to
//! wpa_supplicant) and the Android join path was a dead stub. The `p2p` module
//! and `create_p2p_group` command no longer exist.

mod connection;
mod firewall;
mod mdns;
mod tor;

pub use connection::*;
pub use firewall::*;
pub use mdns::*;
pub use tor::*;
