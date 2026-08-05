pub const DEFAULT_KYBERPIPE_PORT: u16 = 9876;
pub const P2P_BEACON_PORT: u16 = 9877;
pub const BEACON_MAGIC: &[u8] = b"KYBERPIPE_P2P_BEACON_V1";

/// Default STUN endpoint used for NAT traversal.
pub const STUN_DEFAULT: &str = "stun.l.google.com:19302";

/// Fallback STUN servers if the primary is unreachable.
pub const STUN_FALLBACK_SERVERS: &[&str] = &[
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

pub mod beacon;
pub mod path_migration;
pub mod stun;
pub mod tls_config;

pub use beacon::*;
pub use path_migration::*;
pub use stun::*;
pub use tls_config::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_server_client_configs() {
        let (certs, key) = generate_self_signed_cert().unwrap();
        assert!(!certs.is_empty());
        let server_config = configure_quic_server(certs, key, false, vec![]);
        assert!(server_config.is_ok());

        let client_config = configure_quic_client(None);
        assert!(client_config.is_ok());
    }

    #[test]
    fn test_path_migration_challenge_response() {
        let sk = b"test-session-key-0123456789";
        let (challenge, response) = PathMigrationManager::create_path_challenge(sk);
        assert!(PathMigrationManager::verify_path_response(
            sk, &challenge, &response
        ));
        assert!(!PathMigrationManager::verify_path_response(
            sk,
            &challenge,
            "invalid-token"
        ));
    }

    #[tokio::test]
    async fn test_stun_query() {
        let res = query_stun_server("stun.l.google.com:19302").await;
        if let Ok(addr) = res {
            assert!(addr.port() > 0);
        }
    }
}
