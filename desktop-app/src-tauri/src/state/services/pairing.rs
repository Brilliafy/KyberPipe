use super::super::services::lock_state;
use super::super::types::*;
use std::sync::Mutex;

pub struct PairingService {
    inner: Mutex<PairingState>,
}

impl Default for PairingService {
    fn default() -> Self {
        Self {
            inner: Mutex::new(PairingState::default()),
        }
    }
}

impl PairingService {
    pub fn get_pairing_read(&self) -> (String, String) {
        let p = lock_state(&self.inner);
        (p.sas_code.clone(), p.pending_session_key.to_string())
    }
    /// Transition: begin a new KEM pairing attempt. Clears every per-attempt
    /// field (audit finding #24 — ONE transition instead of the old two
    /// divergent "clear" methods) while deliberately PRESERVING the mandatory
    /// QR nonce (audit finding #20) and any confirmed paired identity.
    pub fn begin_pairing_attempt(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        p.phase = PairingPhase::PendingKem;
        // Bump the attempt generation (audit KYP-2026-02 #12): a timeout task
        // spawned for an earlier attempt checks this before firing, so a new
        // attempt invalidates any stale in-flight SAS-window task.
        p.attempt_generation = p.attempt_generation.wrapping_add(1);
        p.sas_code.clear();
        p.pending_session_key = SecureString::new(String::new());
        p.pending_shared_secret = SecureString::new(String::new());
        p.initiator_pk.clear();
        p.initiator_x25519_pk.clear();
        p.attempt_count = 0;
        p.pending_client_cert_hash.clear();
        p.phase
    }
    /// Transition: a SAS code has been computed for the pending KEM.
    pub fn promote_to_sas_pending(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        if p.phase == PairingPhase::PendingKem {
            p.phase = PairingPhase::SasPending;
        }
        p.phase
    }
    /// Transition: SAS verified — the session is promoted. Clears the pending
    /// handshake state (the caller persists the session key + ratchet first).
    pub fn confirm_pairing(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        p.phase = PairingPhase::Confirmed;
        p.sas_code.clear();
        p.pending_session_key = SecureString::new(String::new());
        p.pending_shared_secret = SecureString::new(String::new());
        p.attempt_count = 0;
        p.pending_client_cert_hash.clear();
        p.phase
    }
    /// Transition: the SAS window expired without confirmation.
    pub fn timeout_pairing(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        if p.phase == PairingPhase::SasPending {
            p.phase = PairingPhase::TimedOut;
            p.sas_code.clear();
            p.pending_session_key = SecureString::new(String::new());
            p.pending_shared_secret = SecureString::new(String::new());
            p.pending_client_cert_hash.clear();
        }
        p.phase
    }
    /// Transition: the pairing was explicitly rejected (nonce mismatch, rate
    /// limit, bad KEM).
    pub fn fail_pairing(&self) -> PairingPhase {
        let mut p = lock_state(&self.inner);
        p.phase = PairingPhase::Failed;
        p.sas_code.clear();
        p.pending_session_key = SecureString::new(String::new());
        p.pending_shared_secret = SecureString::new(String::new());
        p.pending_client_cert_hash.clear();
        p.phase
    }
    /// Current pairing phase.
    pub fn phase(&self) -> PairingPhase {
        lock_state(&self.inner).phase
    }
    /// Generation of the current pairing attempt (audit KYP-2026-02 #12). The
    /// spawned SAS-window timeout task captures this at spawn time and only
    /// fires while the generation still matches, so confirm/fail/begin all
    /// invalidate a stale task.
    pub fn get_pairing_generation(&self) -> u64 {
        lock_state(&self.inner).attempt_generation
    }
    pub fn get_sas_code(&self) -> String {
        lock_state(&self.inner).sas_code.clone()
    }
    pub fn set_sas_code(&self, code: String) {
        lock_state(&self.inner).sas_code = code;
    }
    pub fn clear_sas_code(&self) {
        lock_state(&self.inner).sas_code.clear();
    }
    pub fn is_pairing_pending(&self) -> bool {
        let p = lock_state(&self.inner);
        !p.sas_code.is_empty() && !p.pending_session_key.is_empty()
    }
    #[allow(dead_code)] // pairing API surface
    pub fn get_pending_session_key(&self) -> String {
        lock_state(&self.inner).pending_session_key.to_string()
    }
    pub fn set_pending_session_key(&self, key: SecureString) {
        lock_state(&self.inner).pending_session_key = key;
    }
    pub fn get_pending_shared_secret(&self) -> String {
        lock_state(&self.inner).pending_shared_secret.to_string()
    }
    pub fn set_pending_shared_secret(&self, secret: SecureString) {
        lock_state(&self.inner).pending_shared_secret = secret;
    }
    pub fn get_pending_client_cert_hash(&self) -> String {
        lock_state(&self.inner).pending_client_cert_hash.clone()
    }
    pub fn set_pending_client_cert_hash(&self, hash: String) {
        lock_state(&self.inner).pending_client_cert_hash = hash;
    }
    pub fn get_pending_pairing_nonce(&self) -> String {
        lock_state(&self.inner).pending_pairing_nonce.clone()
    }
    pub fn set_pending_pairing_nonce(&self, nonce: String) {
        lock_state(&self.inner).pending_pairing_nonce = nonce;
    }
    /// Issue a FRESH QR pairing nonce (audit finding #20): the nonce gate is
    /// mandatory — every pairing request must echo a nonce this desktop issued,
    /// so an arbitrary LAN peer that never saw the QR cannot occupy the pairing
    /// slot. Issued at app start (not only at QR build) so a pairing attempt
    /// with no nonce is rejected outright instead of bypassing the gate.
    pub fn issue_fresh_nonce(&self) -> String {
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        let nonce = hex::encode(bytes);
        self.set_pending_pairing_nonce(nonce.clone());
        nonce
    }
    /// Consume the QR pairing nonce, making it SINGLE-USE (audit finding #15).
    /// Called when a KEM handshake lands and the attempt advances to SAS-
    /// pending: the nonce has served its purpose for THIS phone, and clearing
    /// it means a SECOND phone that read the same QR (or an attacker who
    /// observed it) can no longer reuse it to race the pairing slot. A fresh
    /// nonce is re-issued only when the user builds a NEW pairing QR
    /// (`get_pairing_config`), so each QR is good for exactly one attempt.
    /// Returns the cleared nonce (for logging the transition).
    pub fn consume_pairing_nonce(&self) -> String {
        let old = self.get_pending_pairing_nonce();
        self.set_pending_pairing_nonce(String::new());
        old
    }
    /// The legacy single-slot paired cert hash (AUDIT F13: authorization now
    /// goes through `is_authorized_peer_cert`, which covers the multi-device
    /// map too). Retained for the e2e test that asserts the pairing flow.
    #[cfg(test)]
    pub fn get_paired_client_cert_hash(&self) -> String {
        lock_state(&self.inner).paired_client_cert_hash.clone()
    }
    pub fn set_paired_client_cert_hash(&self, hash: String) {
        lock_state(&self.inner).paired_client_cert_hash = hash;
    }
    pub fn get_paired_peer_ip(&self) -> String {
        lock_state(&self.inner).paired_peer_ip.clone()
    }
    pub fn set_paired_peer_ip(&self, ip: String) {
        lock_state(&self.inner).paired_peer_ip = ip;
    }
    pub fn get_pairing_initiator_pk(&self) -> String {
        lock_state(&self.inner).initiator_pk.clone()
    }
    pub fn set_pairing_initiator_pk(&self, pk: String) {
        lock_state(&self.inner).initiator_pk = pk;
    }
    /// AUDIT F12 (admission): whether a TLS-observed client certificate hash is
    /// a KNOWN paired peer — it is either the legacy global paired identity or
    /// an entry in the per-peer cert→ratchet-id map. The stream authorization
    /// gate uses this so a SECOND paired device is admitted to the dispatch
    /// (then routed per-peer), instead of being rejected against the single
    /// global cert hash.
    pub fn is_authorized_peer_cert(&self, cert_hash: &str) -> bool {
        if cert_hash.is_empty() {
            return false;
        }
        let p = lock_state(&self.inner);
        if p.paired_client_cert_hash == cert_hash {
            return true;
        }
        p.peer_by_cert_hash.contains_key(cert_hash)
    }

    /// AUDIT F12: register the peer-identity mapping for a confirmed pairing —
    /// the TLS-observed client certificate hash routes to THIS peer's ratchet
    /// session id. Called at SAS confirmation so post-pairing streams decrypt
    /// against the correct session even when a SECOND device pairs.
    pub fn register_peer_cert_mapping(&self, peer_id: &str, cert_hash: &str) {
        if peer_id.is_empty() || cert_hash.is_empty() {
            return;
        }
        lock_state(&self.inner)
            .peer_by_cert_hash
            .insert(cert_hash.to_string(), peer_id.to_string());
    }
    /// AUDIT F13: drop a SINGLE peer's cert→ratchet-id mapping (per-peer
    /// unpair). The global unpair/self-destruct path clears the whole map via
    /// `clear_all_pairing`; a SECOND device's unpair must only remove ITS
    /// entry so the primary (and any other peer) keeps routing.
    pub fn remove_peer_cert_mapping(&self, cert_hash: &str) {
        if cert_hash.is_empty() {
            return;
        }
        lock_state(&self.inner).peer_by_cert_hash.remove(cert_hash);
    }
    /// AUDIT F12: resolve the ratchet peer id for a connection's TLS-observed
    /// client certificate hash. Falls back to the single global pairing id for
    /// legacy/back-compat when the map has no entry (e.g. a session restored
    /// before this mapping existed). The fallback reads the global id AFTER the
    /// map guard is dropped — never while holding it (std Mutex is not
    /// reentrant; a nested lock would deadlock every inbound stream).
    pub fn resolve_peer_for_cert_hash(&self, cert_hash: &str) -> String {
        if cert_hash.is_empty() {
            return self.get_pairing_initiator_pk();
        }
        let mapped = lock_state(&self.inner)
            .peer_by_cert_hash
            .get(cert_hash)
            .cloned();
        mapped.unwrap_or_else(|| self.get_pairing_initiator_pk())
    }
    pub fn get_pairing_initiator_x25519_pk(&self) -> String {
        lock_state(&self.inner).initiator_x25519_pk.clone()
    }
    pub fn set_pairing_initiator_x25519_pk(&self, pk: String) {
        lock_state(&self.inner).initiator_x25519_pk = pk;
    }
    pub fn get_sas_attempt_count(&self) -> u32 {
        lock_state(&self.inner).attempt_count
    }
    pub fn increment_sas_attempt_count(&self) {
        lock_state(&self.inner).attempt_count += 1;
    }
    pub fn reset_sas_attempt_count(&self) {
        lock_state(&self.inner).attempt_count = 0;
    }
    pub fn clear_all_pairing(&self) {
        let mut p = lock_state(&self.inner);
        p.phase = PairingPhase::Idle;
        p.sas_code.clear();
        p.pending_session_key = SecureString::new(String::new());
        p.pending_shared_secret = SecureString::new(String::new());
        p.initiator_pk.clear();
        p.attempt_count = 0;
        p.pending_client_cert_hash.clear();
        p.paired_client_cert_hash.clear();
        p.paired_peer_ip.clear();
        p.pending_pairing_nonce.clear();
        // AUDIT F12: drop every per-peer cert→ratchet-id mapping on unpair /
        // self-destruct so a cleared pairing cannot route traffic to a stale
        // session.
        p.peer_by_cert_hash.clear();
    }
    #[allow(dead_code)] // service API surface
    pub fn lock(&self) -> std::sync::MutexGuard<'_, PairingState> {
        lock_state(&self.inner)
    }

    /// Snapshot the PAIRED identity (public data only: the TLS-observed
    /// client-cert hash, the peer's public key halves and the per-peer
    /// cert→ratchet map) so it can be persisted across restarts (audit F1).
    /// Returns `(paired_client_cert_hash, initiator_pk, initiator_x25519_pk,
    /// peer_by_cert_hash)`.
    pub fn identity_snapshot(
        &self,
    ) -> (
        String,
        String,
        String,
        std::collections::HashMap<String, String>,
    ) {
        let p = lock_state(&self.inner);
        (
            p.paired_client_cert_hash.clone(),
            p.initiator_pk.clone(),
            p.initiator_x25519_pk.clone(),
            p.peer_by_cert_hash.clone(),
        )
    }

    /// Restore the PAIRED identity from persisted settings at startup (audit
    /// F1). Public data only. No-op for empty values.
    pub fn restore_identity(
        &self,
        paired_client_cert_hash: &str,
        initiator_pk: &str,
        initiator_x25519_pk: &str,
        peer_by_cert_hash: &std::collections::HashMap<String, String>,
    ) {
        let mut p = lock_state(&self.inner);
        if !paired_client_cert_hash.is_empty() {
            p.paired_client_cert_hash = paired_client_cert_hash.to_string();
        }
        if !initiator_pk.is_empty() {
            p.initiator_pk = initiator_pk.to_string();
        }
        if !initiator_x25519_pk.is_empty() {
            p.initiator_x25519_pk = initiator_x25519_pk.to_string();
        }
        p.peer_by_cert_hash = peer_by_cert_hash.clone();
    }
}
