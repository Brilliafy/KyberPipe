use crate::state::AppState;
use core_crypto::generate_pq_keypair;
use tauri::State;

struct PairingState {
    sas_attempt_count: u32,
}

static PAIRING_STATE: std::sync::OnceLock<std::sync::Mutex<PairingState>> =
    std::sync::OnceLock::new();
fn get_pairing_state() -> &'static std::sync::Mutex<PairingState> {
    PAIRING_STATE.get_or_init(|| {
        std::sync::Mutex::new(PairingState {
            sas_attempt_count: 0,
        })
    })
}

#[tauri::command]
pub fn generate_keypair(
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::PqKeyPair, String> {
    let pair = generate_pq_keypair().map_err(|e| e.to_string())?;
    if let Ok(mut lock) = state.keypair.lock() {
        *lock = Some(pair.clone());
    }
    state.add_log("[PQC] Generated Hybrid Keypair (X25519 + ML-KEM-768)".to_string());
    Ok(pair)
}

#[allow(dead_code)]
#[tauri::command]
pub fn confirm_pairing_sas(
    verified_sas: String,
    paired_name: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<String, String> {
    let mut ps = get_pairing_state().lock().unwrap();
    if ps.sas_attempt_count >= 3 {
        *state.pending_session_key.lock().unwrap() = zeroize::Zeroizing::new(String::new());
        state.sas_code.lock().unwrap().clear();
        return Err("Too many SAS attempts. Re-initiate pairing.".into());
    }
    ps.sas_attempt_count += 1;
    drop(ps);

    let (stored_sas, pending_key) = {
        let sas_lock = state.sas_code.lock().unwrap();
        let pend_lock = state.pending_session_key.lock().unwrap();
        (sas_lock.clone(), pend_lock.to_string())
    };

    if stored_sas.is_empty() {
        return Err("No pending pairing SAS code found. Initiate pairing first.".into());
    }
    if stored_sas != verified_sas {
        return Err("SAS code mismatch. Pairing rejected.".into());
    }
    if pending_key.is_empty() {
        return Err("No pending session key. Initiate pairing first.".into());
    }

    *state.session_key.lock().unwrap() = zeroize::Zeroizing::new(pending_key);
    *state.pending_session_key.lock().unwrap() = zeroize::Zeroizing::new(String::new());
    state.sas_code.lock().unwrap().clear();
    {
        let mut settings = state.settings.lock().unwrap_or_else(|e| e.into_inner());
        settings.is_paired = true;
        settings.paired_device_name = Some(paired_name);
    }
    state.save_settings();
    state.set_connection_status("ACTIVE".to_string());
    state.set_connection_method("QUIC mTLS".to_string());
    state.set_connection_color("green".to_string());
    state.add_log("[Pairing] SAS verified. Session key promoted. Fully paired.".to_string());

    get_pairing_state().lock().unwrap().sas_attempt_count = 0;

    Ok("Paired successfully".to_string())
}

#[tauri::command]
pub fn generate_sas_pairing_code(
    host_pk_hex: String,
    client_pk_hex: String,
    shared_secret_hex: String,
) -> Result<String, String> {
    if host_pk_hex.len() < 64 || client_pk_hex.len() < 64 || shared_secret_hex.len() < 32 {
        return Err(
            "Invalid key material — SAS requires valid PQC public keys and shared secret".into(),
        );
    }
    core_crypto::generate_sas_code(host_pk_hex, client_pk_hex, shared_secret_hex)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn store_key_in_secure_enclave(key_name: String, secret_hex: String) -> Result<(), String> {
    let entry = keyring::Entry::new("kyberpipe", &key_name)
        .map_err(|e| format!("Keyring access failed: {e}"))?;
    entry
        .set_password(&secret_hex)
        .map_err(|e| format!("Failed to store secret in OS Secret Service: {e}"))?;
    Ok(())
}

#[tauri::command]
pub fn get_pairing_config(
    host_pk_hex: String,
    wireguard_pk_hex: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<core_crypto::PairingConfig, String> {
    state.add_log("[Pairing] Generated Out-of-Band Pairing Config".to_string());
    core_crypto::generate_pairing_config(host_pk_hex, wireguard_pk_hex).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn generate_wormhole_code() -> String {
    let words = [
        "apple", "bridge", "crane", "dolphin", "eagle", "falcon", "garden", "harbor", "island",
        "jaguar", "knight", "lemon", "mountain", "noble", "ocean", "puzzle", "queen", "river",
        "silver", "tiger", "umbrella", "valley", "winter", "zenith", "anchor", "bloom", "crystal",
        "dragon", "ember", "frost",
    ];
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n1 = rng.gen_range(0..words.len());
    let n2 = rng.gen_range(0..words.len());
    let n3 = rng.gen_range(0..words.len());
    format!("{}-{}-{}", words[n1], words[n2], words[n3])
}
