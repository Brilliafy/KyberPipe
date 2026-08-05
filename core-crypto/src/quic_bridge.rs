use crate::error::KyberError;
use quinn::Connection;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Condvar, LazyLock, Mutex};

struct ConnConfig {
    addr: SocketAddr,
    pinned_cert_hash: Option<String>,
    /// Client identity certificate (DER cert + DER PKCS#8 key) presented on
    /// (re)connect for mTLS authorization post-pairing (audit finding #8).
    client_certs: Option<(Vec<u8>, Vec<u8>)>,
    /// LAST-KNOWN-GOOD candidate addresses for this peer, primary first (audit
    /// F3 — "Seamless Path Migration"). The stored `addr` is the last address
    /// that WORKED; when it goes stale (DHCP renewal, Wi-Fi→cellular handoff,
    /// subnet change) the reconnect path rotates through this set before
    /// giving up, and a successful connect on a non-primary candidate promotes
    /// it to primary. Populated from every successful connect and from
    /// beacon/mDNS discoveries via `note_peer_candidate_address`.
    candidates: Vec<SocketAddr>,
}

pub(crate) struct ManagedConnection {
    pub conn: Option<Connection>,
    config: Option<ConnConfig>,
    last_activity: std::time::Instant,
}

/// Peer identity key for the connection registry. A pinned cert hash is the
/// strong identity; before pairing (or when no pin is provided) we fall back to
/// "ip:port".
pub(crate) fn peer_key(addr: &SocketAddr, pinned_cert_hash: &Option<String>) -> String {
    pinned_cert_hash
        .clone()
        .unwrap_or_else(|| format!("{}:{}", addr.ip(), addr.port()))
}

/// Process-global QUIC connection REGISTRY keyed by peer identity. Unlike the
/// previous single global slot, this supports multiple simultaneous peers —
/// the mesh claim of the product.
static QUIC_CONNECTIONS: LazyLock<Mutex<HashMap<String, ManagedConnection>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The peer key most recently connected to / used. The legacy single-peer FFI
/// surface (`quic_send_and_recv` without a peer argument) routes through it.
static ACTIVE_PEER: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// Reconnect state machine: Idle → Reconnecting → Done/Error
#[derive(PartialEq)]
enum ReconnectState {
    Idle,
    Reconnecting,
    Done,
}

struct ReconnectGuard {
    state: ReconnectState,
    last_attempt: std::time::Instant,
}

/// Minimum interval between reconnect attempts — prevents a thundering herd
/// of reconnect storms when a network handoff fails.
const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// Per-candidate connect timeout inside the reconnect worker (AUDIT #6): a
/// blackholed path cannot hang the connect forever — each candidate attempt is
/// dropped (the handshake future is cancelled) after this window, so the whole
/// reconnect is bounded by candidates × candidate-timeout even when the FFI
/// caller has already given up waiting.
const RECONNECT_CANDIDATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Total wall-clock budget the FFI caller waits for a reconnect to finish
/// (AUDIT #6). The worker self-terminates within its bounded candidate loop
/// regardless of whether the caller gives up first.
const RECONNECT_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

type ReconnectStateHandle = Arc<(Mutex<ReconnectGuard>, Condvar)>;

/// Per-peer in-flight gate (AUDIT #6): at most ONE QUIC round-trip per peer at
/// a time. The poll loop is single-flight, but the SMS forwarder, media pushes
/// and a second peer's round-trip can otherwise stack concurrent send/recv
/// futures against a blackholed network — each one a potential leaked task on
/// timeout (the pre-#6 code leaked every timed-out future until it completed
/// on its own, progressively exhausting the FFI blocking pool). A bounded wait
/// serializes additional callers behind the in-flight round-trip instead of
/// letting them pile up.
struct InFlightGate {
    busy: Mutex<bool>,
    cvar: Condvar,
}

static IN_FLIGHT_GATES: LazyLock<Mutex<HashMap<String, Arc<InFlightGate>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// RAII release of the per-peer in-flight gate (audit #6).
pub(crate) struct InFlightGuard {
    gate: Arc<InFlightGate>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        *self.gate.busy.lock().unwrap_or_else(|e| e.into_inner()) = false;
        self.gate.cvar.notify_one();
    }
}

/// Acquire the per-peer in-flight gate, waiting up to `wait` for the current
/// round-trip to release it. Returns a guard that releases the gate on drop.
/// A caller that cannot acquire within `wait` fails fast (the peer is already
/// in a round-trip; stacking another one is exactly the pile-up the gate
/// exists to prevent — audit #6).
pub(crate) fn acquire_in_flight(
    peer_key: &str,
    wait: std::time::Duration,
) -> Result<InFlightGuard, KyberError> {
    let gate = {
        let mut map = IN_FLIGHT_GATES.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(peer_key.to_string())
            .or_insert_with(|| {
                Arc::new(InFlightGate {
                    busy: Mutex::new(false),
                    cvar: Condvar::new(),
                })
            })
            .clone()
    };
    let mut busy = gate.busy.lock().unwrap_or_else(|e| e.into_inner());
    let deadline = std::time::Instant::now() + wait;
    while *busy {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(KyberError::NetworkError(format!(
                "A QUIC round-trip for peer '{peer_key}' is already in flight (per-peer gate, audit #6) — retry later"
            )));
        }
        let (g, timed_out) = gate
            .cvar
            .wait_timeout(busy, deadline - now)
            .unwrap_or_else(|e| e.into_inner());
        busy = g;
        if timed_out.timed_out() {
            return Err(KyberError::NetworkError(format!(
                "A QUIC round-trip for peer '{peer_key}' is already in flight (per-peer gate, audit #6) — timed out waiting"
            )));
        }
    }
    *busy = true;
    drop(busy); // release the borrow before moving `gate` into the guard
    Ok(InFlightGuard { gate })
}

/// Drop the per-peer in-flight gate state (peer teardown).
pub fn drop_in_flight_state(peer_key: &str) {
    if let Ok(mut map) = IN_FLIGHT_GATES.lock() {
        map.remove(peer_key);
    }
}

/// Per-PEER reconnect coordination (audit finding #10). Each peer gets its own
/// (Mutex, Condvar) pair, so a Wi-Fi→cellular handoff that reconnects ONE peer
/// can never serialize every other peer's QUIC FFI calls — the old single
/// process-global Condvar parked ALL callers (including SMS encrypt and
/// snapshot persist) behind the one reconnecting peer for up to 5s.
static RECONNECT_STATES: LazyLock<Mutex<HashMap<String, ReconnectStateHandle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn reconnect_state_for(peer_key: &str) -> ReconnectStateHandle {
    let mut map = RECONNECT_STATES.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(peer_key.to_string())
        .or_insert_with(|| {
            Arc::new((
                Mutex::new(ReconnectGuard {
                    state: ReconnectState::Idle,
                    last_attempt: std::time::Instant::now() - std::time::Duration::from_secs(60),
                }),
                Condvar::new(),
            ))
        })
        .clone()
}

/// Drop per-peer reconnect state (used when a peer is unpaired/closed).
pub fn drop_reconnect_state(peer_key: &str) {
    if let Ok(mut map) = RECONNECT_STATES.lock() {
        map.remove(peer_key);
    }
}

fn connections() -> &'static Mutex<HashMap<String, ManagedConnection>> {
    &QUIC_CONNECTIONS
}

/// Check whether ANY peer connection is alive (recent activity within 30 s).
pub fn is_quic_connected() -> bool {
    let map = connections().lock().unwrap_or_else(|e| e.into_inner());
    map.values()
        .any(|c| c.conn.is_some() && c.last_activity.elapsed() < std::time::Duration::from_secs(30))
}

/// List every registered peer key.
pub fn peer_keys() -> Vec<String> {
    connections()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect()
}

/// Store a connection under its peer key and make it the active peer.
pub fn store_connection(
    conn: Connection,
    addr: SocketAddr,
    pinned_cert_hash: Option<String>,
    client_certs: Option<(Vec<u8>, Vec<u8>)>,
) {
    let key = peer_key(&addr, &pinned_cert_hash);
    let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
    map.insert(
        key.clone(),
        ManagedConnection {
            conn: Some(conn),
            config: Some(ConnConfig {
                addr,
                pinned_cert_hash,
                client_certs,
                candidates: vec![addr],
            }),
            last_activity: std::time::Instant::now(),
        },
    );
    *ACTIVE_PEER.lock().unwrap_or_else(|e| e.into_inner()) = Some(key);
}

/// Register a LAST-KNOWN-GOOD candidate address for a peer (audit F3). The
/// reconnect path rotates through the candidate set when the primary address
/// goes stale, so a desktop whose LAN IP changed (DHCP renewal, Wi-Fi→cellular
/// handoff, subnet change) is still reachable via an alternate address the
/// peer learned through beacon/mDNS discovery or a prior successful connect.
/// Returns true when the candidate was newly added (primary-first, deduplicated,
/// capped at MAX_CANDIDATE_ADDRESSES).
pub fn note_peer_candidate_address(peer_key: &str, addr: SocketAddr) -> bool {
    let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
    let Some(mc) = map.get_mut(peer_key) else {
        return false;
    };
    let Some(config) = mc.config.as_mut() else {
        return false;
    };
    if config.candidates.contains(&addr) {
        return false;
    }
    config.candidates.push(addr);
    while config.candidates.len() > MAX_CANDIDATE_ADDRESSES {
        // Drop the oldest non-primary candidate.
        config.candidates.remove(1);
    }
    true
}

/// Cap on the per-peer candidate-address set (audit F3). Bounded so a hostile
/// beacon flood cannot grow the reconnect search space without limit.
const MAX_CANDIDATE_ADDRESSES: usize = 4;

/// Close ALL connections gracefully but keep configs for reconnection.
/// Sets last_activity far in the past so `is_quic_connected` returns false.
pub fn close_connection() {
    let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
    for mc in map.values_mut() {
        if let Some(conn) = mc.conn.take() {
            conn.close(0u8.into(), b"client disconnect");
        }
        mc.last_activity = std::time::Instant::now() - std::time::Duration::from_secs(60);
    }
    *ACTIVE_PEER.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Close a single peer's connection (e.g. on unpair of that peer).
pub fn close_peer(peer_key: &str) {
    let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mc) = map.get_mut(peer_key) {
        if let Some(conn) = mc.conn.take() {
            conn.close(0u8.into(), b"peer disconnect");
        }
        mc.last_activity = std::time::Instant::now() - std::time::Duration::from_secs(60);
    }
    if let Ok(mut active) = ACTIVE_PEER.lock() {
        if active.as_deref() == Some(peer_key) {
            *active = None;
        }
    }
    // Drop the peer's reconnect + in-flight-gate state so a later re-pair
    // starts fresh (audit finding #10 / audit #6).
    drop_reconnect_state(peer_key);
    drop_in_flight_state(peer_key);
}

/// Record that the active connection is still alive (poll handler).
pub fn touch_connection() {
    let active = ACTIVE_PEER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(key) = active {
        if let Ok(mut map) = connections().lock() {
            if let Some(mc) = map.get_mut(&key) {
                mc.last_activity = std::time::Instant::now();
            }
        }
    }
}

/// The active peer's live connection handle, if any.
pub fn active_connection() -> Option<Connection> {
    let active = ACTIVE_PEER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()?;
    let map = connections().lock().unwrap_or_else(|e| e.into_inner());
    let mc = map.get(&active)?;
    mc.conn.clone()
}

/// The active peer key, if any (audit F5 — used to close the wedged
/// connection when a legacy single-peer send/recv times out).
pub fn active_peer_key() -> Option<String> {
    ACTIVE_PEER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Get the ACTIVE connection, attempting auto-reconnect if closed.
/// The actual network connect() runs OUTSIDE the shared guard so concurrent
/// senders only wait on the condvar and never serialize on a blocking I/O
/// path. Reconnect attempts are rate-limited with a 1s backoff.
pub fn get_or_reconnect() -> Result<Connection, KyberError> {
    let active = ACTIVE_PEER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or_else(|| {
            KyberError::NetworkError(
                "No active QUIC connection and no reconnect info available".into(),
            )
        })?;
    get_or_reconnect_for(&active)
}

/// Get (or reconnect) the connection for a specific peer key.
pub fn get_or_reconnect_for(peer_key: &str) -> Result<Connection, KyberError> {
    // Quick check without lock
    {
        let map = connections().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mc) = map.get(peer_key) {
            if let Some(conn) = &mc.conn {
                if conn.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        } else {
            return Err(KyberError::NetworkError(format!(
                "No QUIC connection registered for peer '{peer_key}' — call quic_connect first"
            )));
        }
    }

    let (lock, cvar) = &*reconnect_state_for(peer_key);

    // Claim the reconnect slot WITHOUT holding the lock across I/O.
    {
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        while guard.state == ReconnectState::Reconnecting {
            let (g, timed_out) = cvar
                .wait_timeout(guard, std::time::Duration::from_secs(5))
                .unwrap();
            guard = g;
            if timed_out.timed_out() {
                return Err(KyberError::NetworkError(
                    "QUIC reconnect in progress — timed out waiting".into(),
                ));
            }
        }
        if guard.state == ReconnectState::Done {
            guard.state = ReconnectState::Idle;
            let map = connections().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(mc) = map.get(peer_key) {
                if let Some(conn) = &mc.conn {
                    if conn.close_reason().is_none() {
                        return Ok(conn.clone());
                    }
                }
            }
            return Err(KyberError::NetworkError(
                "QUIC reconnect completed but connection unavailable".into(),
            ));
        }
        if guard.last_attempt.elapsed() < RECONNECT_BACKOFF {
            return Err(KyberError::NetworkError(
                "QUIC reconnect rate-limited (backoff)".into(),
            ));
        }
        guard.state = ReconnectState::Reconnecting;
        guard.last_attempt = std::time::Instant::now();
    } // guard dropped BEFORE the blocking connect

    // Perform the reconnect WITHOUT parking any shared runtime worker (AUDIT
    // #6/#7). The connect is driven on the FFI runtime's BLOCKING POOL
    // (spawn_blocking → max_blocking_threads=64, sized independently of the 2
    // crypto workers) via [`crate::spawn_blocking_on_ffi`], and the FFI caller
    // waits on a PLAIN std channel — no tokio `block_on` — so a handoff
    // reconnect NEVER parks an FFI worker or an IO worker. Two simultaneous
    // reconnects (the multi-device mesh case) therefore cannot stall every
    // concurrent UniFFI crypto call. Each candidate connect is driven on a
    // LOCAL current-thread runtime inside the blocking closure and is bounded
    // by [`RECONNECT_CANDIDATE_TIMEOUT`], so the whole reconnect is bounded
    // and cancellable; if the caller gives up first, the worker still
    // self-terminates within its bounded candidate loop.
    //
    // AUDIT F3: the connect iterates the peer's LAST-KNOWN-GOOD candidate
    // address set (primary first). If the stored address is stale (the
    // desktop's LAN IP changed), the reconnect rotates to the next candidate
    // instead of hammering a dead address indefinitely; a success on a
    // non-primary candidate promotes it to primary for future reconnects.
    let (tx, rx) = std::sync::mpsc::channel::<Result<Connection, KyberError>>();
    let worker_key = peer_key.to_string();
    let handle = crate::spawn_blocking_on_ffi(move || {
        let result = run_reconnect_blocking(&worker_key);
        let _ = tx.send(result);
    });
    let result = match rx.recv_timeout(RECONNECT_TOTAL_TIMEOUT) {
        Ok(r) => r,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // Best-effort abort of the worker (it self-terminates via the
            // per-candidate timeouts even if the abort races it).
            handle.abort();
            Err(KyberError::NetworkError(format!(
                "QUIC reconnect for peer '{peer_key}' timed out after {}s",
                RECONNECT_TOTAL_TIMEOUT.as_secs()
            )))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(KyberError::NetworkError(
            "QUIC reconnect worker exited without a result".into(),
        )),
    };

    {
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        guard.state = ReconnectState::Done;
    }
    cvar.notify_all();
    match result {
        Ok(conn) => {
            let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(mc) = map.get_mut(peer_key) {
                mc.conn = Some(conn.clone());
                mc.last_activity = std::time::Instant::now();
            }
            Ok(conn)
        }
        Err(e) => Err(e),
    }
}

/// Run one peer's reconnect on a DEDICATED blocking-pool thread (audit #7).
/// Drives each candidate connect on a LOCAL current-thread tokio runtime so no
/// shared FFI/IO worker is consumed, and bounds each attempt with
/// [`RECONNECT_CANDIDATE_TIMEOUT`] so a blackholed path cannot hang the worker.
fn run_reconnect_blocking(peer_key: &str) -> Result<Connection, KyberError> {
    let Some((config, addrs)) = ({
        let map = connections().lock().unwrap_or_else(|e| e.into_inner());
        map.get(peer_key).and_then(|mc| {
            mc.config.as_ref().map(|c| {
                let mut addrs = c.candidates.clone();
                // The primary (`c.addr`) is always tried first.
                addrs.retain(|a| *a != c.addr);
                addrs.insert(0, c.addr);
                (
                    ConnConfig {
                        addr: c.addr,
                        pinned_cert_hash: c.pinned_cert_hash.clone(),
                        client_certs: c.client_certs.clone(),
                        candidates: c.candidates.clone(),
                    },
                    addrs,
                )
            })
        })
    }) else {
        return Err(KyberError::NetworkError(format!(
            "No reconnect info available for peer '{peer_key}'"
        )));
    };

    // `PrivateKeyDer` is not Clone, so rebuild the mTLS identity per candidate
    // from the raw DER bytes.
    let raw_client_certs = config.client_certs.clone();
    let mut last_err: Option<KyberError> = None;
    let mut winning: Option<(SocketAddr, Connection)> = None;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| KyberError::NetworkError(format!("Reconnect runtime build failed: {e}")))?;
    for cand in addrs {
        let client_certs = raw_client_certs.clone().map(|(cert_der, key_der)| {
            (
                vec![rustls::pki_types::CertificateDer::from(cert_der)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
            )
        });
        let fut = crate::quic_app::QuicAppManager::connect(
            cand,
            config.pinned_cert_hash.clone(),
            client_certs,
        );
        // AUDIT #6: each candidate attempt is CANCELLED after
        // RECONNECT_CANDIDATE_TIMEOUT — the handshake future is dropped at its
        // next await point instead of hanging the worker forever on a
        // blackholed path.
        match rt.block_on(tokio::time::timeout(RECONNECT_CANDIDATE_TIMEOUT, fut)) {
            Ok(Ok(conn)) => {
                winning = Some((cand, conn));
                break;
            }
            Ok(Err(e)) => last_err = Some(e),
            Err(_elapsed) => {
                last_err = Some(KyberError::NetworkError(format!(
                    "QUIC connect to {cand} timed out after {}s",
                    RECONNECT_CANDIDATE_TIMEOUT.as_secs()
                )));
            }
        }
    }
    // Promote the winning candidate to primary so the next reconnect starts
    // from the address that actually worked (audit F3).
    if let Some((addr, _)) = winning.as_ref() {
        if let Ok(mut map) = connections().lock() {
            if let Some(mc) = map.get_mut(peer_key) {
                if let Some(cfg) = mc.config.as_mut() {
                    cfg.addr = *addr;
                    if !cfg.candidates.contains(addr) {
                        cfg.candidates.push(*addr);
                    }
                    // Keep primary first.
                    cfg.candidates.retain(|a| a != addr);
                    cfg.candidates.insert(0, *addr);
                    while cfg.candidates.len() > MAX_CANDIDATE_ADDRESSES {
                        cfg.candidates.remove(1);
                    }
                }
            }
        }
    }
    match winning {
        Some((_addr, conn)) => Ok(conn),
        None => Err(last_err.unwrap_or_else(|| {
            KyberError::NetworkError("Reconnect exhausted all candidate addresses".into())
        })),
    }
}

pub async fn quic_send_and_recv_impl(
    conn: Connection,
    stream_type: u8,
    body_json: String,
) -> Result<String, KyberError> {
    let (mut send, mut recv) =
        crate::quic_app::QuicAppManager::open_stream(&conn, stream_type).await?;

    let body = body_json.into_bytes();
    let frame = crate::quic_app::QuicFrame { stream_type, body };
    crate::quic_app::QuicAppManager::send_frame(&mut send, &frame).await?;
    send.finish()
        .map_err(|e| KyberError::NetworkError(format!("QUIC stream finish failed: {e}")))?;

    let response = crate::quic_app::QuicAppManager::recv_frame(&mut recv).await?;
    let text = String::from_utf8(response.body)
        .map_err(|e| KyberError::NetworkError(format!("Response UTF-8 decode error: {e}")))?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_key_derivation() {
        let addr: SocketAddr = "192.168.1.50:9876".parse().unwrap();
        // With a pin, the key is the pin (stable identity across IP changes).
        let pin = Some("aabbcc".to_string());
        assert_eq!(peer_key(&addr, &pin), "aabbcc");
        // Without a pin, the key is ip:port.
        assert_eq!(peer_key(&addr, &None), "192.168.1.50:9876");
    }

    #[test]
    fn test_registry_roundtrip() {
        // Two distinct peers must coexist in the registry.
        let a: SocketAddr = "10.0.0.1:9876".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:9876".parse().unwrap();
        let keys_a = peer_key(&a, &Some("pina".into()));
        let keys_b = peer_key(&b, &Some("pinb".into()));
        assert_ne!(keys_a, keys_b);
        // These tests share the process-global registry with other unit tests;
        // isolate by clearing any previously-registered entries first.
        let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
        map.clear();
        map.insert(
            keys_a.clone(),
            ManagedConnection {
                conn: None,
                config: Some(ConnConfig {
                    addr: a,
                    pinned_cert_hash: Some("pina".into()),
                    client_certs: None,
                    candidates: vec![a],
                }),
                last_activity: std::time::Instant::now(),
            },
        );
        map.insert(
            keys_b.clone(),
            ManagedConnection {
                conn: None,
                config: Some(ConnConfig {
                    addr: b,
                    pinned_cert_hash: Some("pinb".into()),
                    client_certs: None,
                    candidates: vec![b],
                }),
                last_activity: std::time::Instant::now(),
            },
        );
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&keys_a));
        assert!(map.contains_key(&keys_b));
        map.clear();
    }

    /// AUDIT F3: the reconnect path must not be pinned to the stale stored
    /// address — a peer's LAST-KNOWN-GOOD candidate set is appended via
    /// `note_peer_candidate_address` (primary-first, deduplicated, capped) so a
    /// desktop whose LAN IP changed is still reachable on reconnect.
    #[test]
    fn test_candidate_address_rotation_and_cap() {
        let a: SocketAddr = "192.168.1.50:9876".parse().unwrap();
        let key = peer_key(&a, &Some("pin".into()));
        {
            let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
            map.insert(
                key.clone(),
                ManagedConnection {
                    conn: None,
                    config: Some(ConnConfig {
                        addr: a,
                        pinned_cert_hash: Some("pin".into()),
                        client_certs: None,
                        candidates: vec![a],
                    }),
                    last_activity: std::time::Instant::now(),
                },
            );
        }
        let b: SocketAddr = "192.168.1.60:9876".parse().unwrap();
        let c: SocketAddr = "10.0.0.5:9876".parse().unwrap();
        let d: SocketAddr = "10.0.0.6:9876".parse().unwrap();
        let e: SocketAddr = "10.0.0.7:9876".parse().unwrap();
        assert!(note_peer_candidate_address(&key, b));
        assert!(note_peer_candidate_address(&key, c));
        assert!(note_peer_candidate_address(&key, d));
        assert!(note_peer_candidate_address(&key, e));
        // `b` was evicted as the oldest non-primary when `e` filled the cap;
        // `c` is still present, so re-adding it is a duplicate no-op.
        assert!(!note_peer_candidate_address(&key, c));
        let map = connections().lock().unwrap_or_else(|e| e.into_inner());
        let config = map.get(&key).unwrap().config.as_ref().unwrap();
        assert_eq!(config.candidates.len(), 4, "candidate set must be capped");
        assert_eq!(config.candidates[0], a, "primary address stays first");
        assert!(
            config.candidates.contains(&e),
            "newest candidate must be retained"
        );
        drop(map);
        // Unregistered peer is a no-op.
        assert!(!note_peer_candidate_address("unknown-peer", b));
        let mut map = connections().lock().unwrap_or_else(|e| e.into_inner());
        map.clear();
    }
}
