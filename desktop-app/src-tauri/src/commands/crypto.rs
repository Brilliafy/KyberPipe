#[tauri::command]
pub fn generate_shamir_recovery_shares(
    k: usize,
    n: usize,
    token: String,
) -> Result<Vec<String>, String> {
    if !crate::commands::security::consume_privilege_token(
        "generate_shamir_recovery_shares",
        &token,
    ) {
        return Err("Privileged action requires a fresh confirmation token".into());
    }
    if k < 2 {
        return Err("Minimum threshold k=2 required for security. Use k >= 2.".into());
    }
    let keyring_entry = keyring::Entry::new("kyberpipe", "master_identity_key")
        .map_err(|e| format!("Keyring access failed: {e}"))?;
    let master_secret_hex = keyring_entry.get_password().map_err(|_| {
        "No master identity key found in OS keychain. Generate a keypair first.".to_string()
    })?;
    let master_secret = hex::decode(&master_secret_hex)
        .map_err(|e| format!("Invalid master key hex in keyring: {e}"))?;
    let shares = core_crypto::crypto::split_secret_shamir_with_meta(&master_secret, k, n)
        .map_err(|e| e.to_string())?;
    // Self-check every generated share against the master secret before handing
    // them out — a corrupted share set must never be presented as valid.
    for share in &shares {
        if !core_crypto::crypto::verify_share_with_key(share, &master_secret) {
            return Err("Internal integrity check failed while generating shares".into());
        }
    }
    Ok(shares
        .into_iter()
        .map(|s| serde_json::to_string(&s).unwrap_or_default())
        .collect())
}

#[tauri::command]
pub fn reconstruct_key_from_shamir_shares(
    shares_hex: Vec<String>,
    k: usize,
    token: String,
) -> Result<String, String> {
    if !crate::commands::security::consume_privilege_token(
        "reconstruct_key_from_shamir_shares",
        &token,
    ) {
        return Err("Privileged action requires a fresh confirmation token".into());
    }
    // AUDIT #5 (follow-up): reconstruction now goes through the METADATA path
    // (`ShamirShare` JSON, exactly what `generate_shamir_recovery_shares`
    // emits) and is fully validated BEFORE interpolation: every share is
    // checked with the PUBLIC verifier (no master secret needed), cross-split
    // substitution is rejected, and the reconstructed secret must hash to the
    // public reference. The legacy path hex-decoded RAW share bytes and
    // reconstructed without any integrity check — a corrupted share silently
    // produced garbage key material. Raw hex input is refused loudly.
    let shares: Result<Vec<core_crypto::crypto::ShamirShare>, String> = shares_hex
        .into_iter()
        .map(|s| {
            serde_json::from_str::<core_crypto::crypto::ShamirShare>(&s)
                .map_err(|_| "Invalid share JSON — use the share strings produced by generate_shamir_recovery_shares".to_string())
        })
        .collect();
    let parsed = shares?;
    let recovered_bytes =
        core_crypto::crypto::reconstruct_shamir_with_meta(&parsed, k).map_err(|e| e.to_string())?;
    Ok(hex::encode(&recovered_bytes))
}
