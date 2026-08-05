//! Encrypted ratchet-session persistence (facade).
//!
//! The implementation was decomposed into single-purpose submodules (audit
//! P5-1): keyring secrets + wrap derivation (`keys`), the watermark/rollback
//! policy (`watermark`) and the atomic store lifecycle (`snapshot_store`).
//! This module re-exports the public API so the command surface and existing
//! call sites (`crate::ratchet_store::*`) are unchanged, and hosts the
//! persistence regression tests that exercise the composed store end-to-end.

pub mod keys;
pub mod snapshot_store;
pub mod watermark;

/// Crate-internal re-exports consumed by the persistence tests and by
/// sibling modules that need the watermark/rollback machinery directly.
#[cfg(test)]
pub(crate) use keys::KEYRING_RATCHET_WATERMARK;
pub use keys::{
    decrypt_notifications_data, decrypt_settings_media_field, encrypt_notifications_data,
    encrypt_settings_media_field, load_pairing_keypair_from_keyring, session_key_from_keyring,
    snapshot_key_from_keyring, store_pairing_keypair_to_keyring, store_session_key_to_keyring,
    wipe_keyring_entries, SETTINGS_MEDIA_WRAP_MARKER,
};
pub use snapshot_store::{
    clear_ratchet_store, persist_all_ratchet_sessions, remove_ratchet_session_for_peer,
    restore_all_ratchet_sessions,
};
#[cfg(test)]
pub(crate) use watermark::{
    advances, is_rollback, load_watermarks, merge_watermark, save_watermarks, snapshot_watermark,
    watermark_path,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// AUDIT F16 + FINDING #7 + AUDIT #1: the watermark is extracted from the
    /// AEAD-authenticated snapshot and the rollback-refusal predicate is
    /// COMPONENT-WISE — it rejects a snapshot that regresses the high-water
    /// mark in ANY of generation/send/recv (equal = the current snapshot,
    /// accepted). The tuple is EPOCH-AWARE: a fresh re-pair snapshot (newer
    /// epoch, counters reset) outranks an old epoch's large counters.
    #[test]
    fn watermark_is_monotonic_and_rollback_is_refused() {
        let newer =
            br#"{"ratchet_generation":2,"send_message_count":105,"recv_message_count":102}"#;
        let older = br#"{"ratchet_generation":2,"send_message_count":100,"recv_message_count":99}"#;
        let current =
            br#"{"ratchet_generation":2,"send_message_count":105,"recv_message_count":102}"#;
        // AUDIT #1: ahead in send but BEHIND in recv — the lexicographic blind
        // spot that must now be refused.
        let one_sided =
            br#"{"ratchet_generation":2,"send_message_count":150,"recv_message_count":0}"#;

        let w_newer = snapshot_watermark(newer).expect("newer watermark");
        let w_older = snapshot_watermark(older).expect("older watermark");
        let w_current = snapshot_watermark(current).expect("current watermark");
        let w_one_sided = snapshot_watermark(one_sided).expect("one-sided watermark");

        // Legacy JSON (no pairing_epoch) parses with epoch 0.
        assert_eq!(w_newer, (0, 2, 105, 102));
        assert_eq!(w_newer, w_current);

        // The restore predicate: refuse any snapshot that regresses the mark in
        // ANY component, accept equal (the current snapshot after a normal
        // restart) and accept strictly-forward snapshots.
        let high = w_newer;
        assert!(is_rollback(&w_older, &high), "older snapshot refused");
        assert!(
            is_rollback(&w_one_sided, &high),
            "one-sided snapshot (send ahead, recv behind) must be refused — audit #1"
        );
        assert!(
            !is_rollback(&w_current, &high),
            "current snapshot equals the high-water mark and is accepted"
        );
        assert!(!is_rollback(&w_newer, &high));

        // AUDIT FINDING #7: a stale pre-re-pair snapshot (epoch 0, even with
        // LARGER counters) must be refused against a re-paired epoch-1
        // high-water; a fresh epoch-1 snapshot (counters reset) must be
        // accepted.
        let re_paired_high = (1u64, 0u32, 0u64, 0u64);
        let stale_epoch0 = (0u64, 2u32, 999u64, 999u64);
        assert!(
            is_rollback(&stale_epoch0, &re_paired_high),
            "a stale epoch-0 snapshot with larger counters must still be refused after a re-pair"
        );
        let fresh_epoch1 = (1u64, 0u32, 0u64, 0u64);
        assert!(
            !is_rollback(&fresh_epoch1, &re_paired_high),
            "a fresh re-pair snapshot (epoch 1, counters reset) must be accepted"
        );

        // merge_watermark: a one-sided fresh watermark must NOT clobber the
        // recv lead — the merged envelope keeps BOTH chains' maxima.
        let mut merged = high;
        merge_watermark(&mut merged, &w_one_sided);
        assert_eq!(merged, (0, 2, 150, 102));
        // advances() correctly reports both directions.
        assert!(advances(&high, &merged));
        assert!(!advances(&high, &w_current));
    }

    /// AUDIT F16: a malformed snapshot (missing watermark fields) yields no
    /// watermark — restore treats it as uncheckable and still attempts import
    /// (the AEAD tag already authenticated the bytes; missing counters only
    /// weaken the rollback check, never widen the import surface).
    #[test]
    fn watermark_requires_all_three_fields() {
        let missing_send = br#"{"ratchet_generation":1,"recv_message_count":5}"#;
        assert!(snapshot_watermark(missing_send).is_none());
        let empty = b"{}";
        assert!(snapshot_watermark(empty).is_none());
        let garbage = b"not json";
        assert!(snapshot_watermark(garbage).is_none());
    }

    /// AUDIT P1-2 (MEDIUM, one-sided pairing-epoch bump): the desktop's
    /// restore guard (`is_rollback`) refuses a SAME-epoch snapshot whose
    /// counters are behind the recorded high-water. The Android flow bumps the
    /// fresh re-pair session to epoch 1 so a stale pre-re-pair snapshot can
    /// never be mistaken for the fresh one; the desktop did NOT, so a re-pair
    /// followed by a restart refused the fresh epoch-0/0/0/0 snapshot against
    /// the old high-water (epoch 0, send≥1, recv≥1) whenever the watermark
    /// survived the unpair — silent session loss, "paired but nothing syncs".
    ///
    /// This regression test drives the FULL store sequence the audit named:
    /// first pairing (advanced counters) → persist → re-pair (fresh session +
    /// `ratchet_bump_pairing_epoch`) → persist → "restart" (clear registry,
    /// restore from store) → the fresh epoch-1 session must be restored.
    #[test]
    fn re_pair_epoch_bump_restores_fresh_session_after_restart() {
        let dir = directories::ProjectDirs::from("io", "github", "KyberPipe")
            .map(|p| p.data_dir().to_path_buf())
            .unwrap_or_else(std::env::temp_dir);
        let cleanup = || {
            let _ = std::fs::remove_file(dir.join("ratchet_sessions.json"));
            let _ = std::fs::remove_file(dir.join("ratchet_sessions.json.bak"));
            let _ = std::fs::remove_file(dir.join("ratchet_sessions.json.tmp"));
            let _ = std::fs::remove_file(dir.join("ratchet_watermarks.json"));
            let _ = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK)
                .and_then(|e| e.delete_password());
        };
        cleanup();

        let peer = "p1-2-repair-peer";
        let sk = hex::encode([7u8; 32]);
        let shared = b"p1-2-repair-master-secret-0123456789abcdef";

        // 1) FIRST pairing: a long-lived session with advanced counters.
        core_crypto::ratchet_ffi::ratchet_init_session_impl(
            peer,
            shared,
            true,
            Some(&[1u8; 32]),
            Some(&[2u8; 1184]),
        )
        .expect("first pairing init");
        for i in 0..40u64 {
            core_crypto::ratchet_ffi::ratchet_encrypt_message_impl(
                peer,
                format!("m{i}").as_bytes(),
            )
            .expect("advance send chain");
        }
        // Persist: high-water (epoch 0, gen 0, send 40, recv 0).
        persist_all_ratchet_sessions(&sk);

        // 2) RE-PAIR: remove the session and init a FRESH one, then bump the
        //    pairing epoch exactly as `perform_sas_confirmation` now does
        //    (audit P1-2). Without the bump the fresh session would sit at
        //    epoch 0 and the restart below would refuse it — the regression
        //    this test guards.
        assert!(
            core_crypto::ratchet_remove_session(peer.to_string()),
            "re-pair removes the stale session first"
        );
        core_crypto::ratchet_ffi::ratchet_init_session_impl(
            peer,
            shared,
            true,
            Some(&[3u8; 32]),
            Some(&[4u8; 1184]),
        )
        .expect("fresh re-pair init");
        let new_epoch = core_crypto::ratchet_bump_pairing_epoch(peer.to_string())
            .expect("bump: live session exists");
        assert_eq!(new_epoch, 1, "fresh session must be epoch 1 after the bump");
        // Persist the fresh session — the first post-re-pair poll does this.
        persist_all_ratchet_sessions(&sk);

        // 3) RESTART: remove ONLY this peer's live session (the registry is
        //    process-wide and SHARED with other tests in this binary — the
        //    e2e keeps live sessions there, so `ratchet_clear_all_sessions`
        //    must never be used by a unit test) and restore from the store.
        assert!(
            core_crypto::ratchet_remove_session(peer.to_string()),
            "drop the live fresh session to simulate this peer's cold start"
        );
        let restored = restore_all_ratchet_sessions(&sk);
        // The store may also carry OTHER tests' peers (persist_all serializes
        // every live registry session); what matters is that THIS peer's fresh
        // epoch-1 session came back — the pre-fix code refused it outright.
        assert!(restored >= 1, "the fresh session must restore");
        let wm = core_crypto::ratchet_session_watermark(peer.to_string())
            .expect("watermark accessor")
            .expect("session restored");
        assert_eq!(
            wm.pairing_epoch, 1u64,
            "restored session must be the fresh epoch-1 session, not the stale pre-re-pair one"
        );
        assert_eq!(
            wm.send_message_count, 0u64,
            "fresh session counters are reset (re-pair)"
        );

        // Assert the INVARIANT the fix guarantees: without the epoch bump, the
        // fresh (0,0,0,0) snapshot is a rollback against the old (0,0,40,0)
        // high-water — proving the pre-fix failure class this test guards.
        assert!(
            is_rollback(&(0, 0, 0, 0), &(0, 0, 40, 0)),
            "precondition: an unbumped fresh session would be refused against the old high-water"
        );

        // Cleanup: remove only our peer; never clear the shared registry.
        core_crypto::ratchet_remove_session(peer.to_string());
        cleanup();
    }
}

#[cfg(test)]
mod keyring_watermark_tests {
    use super::*;

    /// AUDIT F16 (follow-up): the KEYRING tier of the rollback watermark must
    /// actually be WRITTEN and READ — the earlier "fix" only declared the
    /// constant and never populated it, leaving a same-user file-swap attacker
    /// able to defeat rollback detection. This test drives the real
    /// `save_watermarks`/`load_watermarks` path and asserts the keyring entry
    /// round-trips. Gracefully skips when no keyring backend is available
    /// (headless CI).
    #[test]
    fn keyring_watermark_is_written_and_read() {
        // Graceful skip when the keyring backend is absent or stuck.
        let probe = {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(
                    keyring::Entry::new("kyberpipe", "watermark_probe")
                        .and_then(|e| e.set_password("probe"))
                        .is_ok(),
                );
            });
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .unwrap_or(false)
        };
        if !probe {
            eprintln!("Skipping keyring watermark test: no keyring backend available");
            return;
        }
        let _ =
            keyring::Entry::new("kyberpipe", "watermark_probe").and_then(|e| e.delete_password());

        // Write a watermark via the real persistence path.
        let mut wms = std::collections::HashMap::new();
        // Epoch-aware 4-tuple (audit finding #7).
        wms.insert("peer-a".to_string(), (3u64, 2u32, 200u64, 150u64));
        save_watermarks(&wms);

        // The keyring entry must exist and contain the watermark.
        let stored = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK)
            .and_then(|e| e.get_password())
            .expect("keyring watermark must be written");
        let parsed: serde_json::Value =
            serde_json::from_str(&stored).expect("keyring watermark must be valid JSON");
        assert_eq!(
            parsed["peer-a"],
            serde_json::json!([3, 2, 200, 150]),
            "keyring watermark must contain the saved watermark"
        );

        // load_watermarks must merge the keyring tier back.
        let loaded = load_watermarks();
        assert_eq!(
            loaded.get("peer-a"),
            Some(&(3u64, 2u32, 200u64, 150u64)),
            "load_watermarks must read the keyring tier"
        );

        // Cleanup.
        let _ = keyring::Entry::new("kyberpipe", KEYRING_RATCHET_WATERMARK)
            .and_then(|e| e.delete_password());
        let _ = std::fs::remove_file(watermark_path());
    }
}
