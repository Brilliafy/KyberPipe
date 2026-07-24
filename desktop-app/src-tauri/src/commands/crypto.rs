#[tauri::command]
pub fn generate_shamir_recovery_shares(k: usize, n: usize) -> Result<Vec<String>, String> {
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
    let shares = core_crypto::crypto::split_secret_shamir(&master_secret, k, n)
        .map_err(|e| e.to_string())?;
    Ok(shares.into_iter().map(hex::encode).collect())
}

#[tauri::command]
pub fn reconstruct_key_from_shamir_shares(
    shares_hex: Vec<String>,
    k: usize,
) -> Result<String, String> {
    let shares: Result<Vec<Vec<u8>>, _> = shares_hex.into_iter().map(|s| hex::decode(&s)).collect();
    let decoded_shares = shares.map_err(|e| format!("Invalid hex share: {e}"))?;
    let recovered_bytes = core_crypto::crypto::reconstruct_secret_shamir(&decoded_shares, k)
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(&recovered_bytes))
}
