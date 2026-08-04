//! PAIRING WIRE CODEC (audit #20 — structural decomposition). Extracted from
//! the former `handlers/pairing.rs` monolith so the binary-frame + JSON codec
//! can be fuzz-tested / reused independently of the KEM + rate-policy +
//! phase-machine logic. The `PairingFrame` tuple is the decoded binary shape;
//! `decode_binary_pairing_frame` is the ONLY binary decoder the pairing path
//! consumes (the wire-format tests pin its contract).

/// (ciphertext, mlkem_pk, x25519_pk, cert_hash, nonce_hex) of a binary pairing
/// frame. The nonce field was added (audit finding #12): the legacy binary
/// frame carried no nonce, so a binary pairing body could never satisfy the
/// QR-nonce check (which parsed the body as JSON first) and the binary
/// transport was unreachable dead code with a latent nonce-bypass. Both
/// formats now carry and validate the SAME QR-bound nonce.
/// The trailing SAS echo (audit finding #10) is optional length-prefixed so
/// legacy frames still decode (and are then rejected by the mandatory SAS-echo
/// check — exactly like a JSON body without `sas_hex`).
/// (ciphertext, client_pk, client_x25519_pk, cert_hash, nonce_hex, sas_hex)
pub(crate) type PairingFrame = (Vec<u8>, Vec<u8>, Vec<u8>, String, String, String);

/// Decode a binary pairing frame (audit finding #12: carries the QR nonce).
/// `pub(crate)` so the wire-format tests can pin the decoder contract.
pub(crate) fn decode_binary_pairing_frame(payload: &[u8]) -> Option<PairingFrame> {
    let mut cursor = 0;
    if payload.len() < 4 {
        return None;
    }
    let ct_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    if payload.len() < cursor + ct_len + 4 {
        return None;
    }
    let ct = payload[cursor..cursor + ct_len].to_vec();
    cursor += ct_len;

    let pk_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    if payload.len() < cursor + pk_len + 4 {
        return None;
    }
    let pk = payload[cursor..cursor + pk_len].to_vec();
    cursor += pk_len;

    let x25519_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    if payload.len() < cursor + x25519_len + 4 {
        return None;
    }
    let x25519_pk = payload[cursor..cursor + x25519_len].to_vec();
    cursor += x25519_len;

    let ch_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;
    if payload.len() < cursor + ch_len {
        return None;
    }
    let cert_hash = String::from_utf8(payload[cursor..cursor + ch_len].to_vec()).ok()?;
    cursor += ch_len;

    // Optional trailing nonce (audit finding #12): length-prefixed so a frame
    // written by a legacy client that never embedded the nonce still decodes
    // (with an empty nonce — which is then REJECTED by the per-format nonce
    // validation, exactly as a JSON body without a nonce is).
    let nonce_hex = if payload.len() >= cursor + 4 {
        let n_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
        cursor += 4;
        if payload.len() < cursor + n_len {
            return None;
        }
        let nonce = String::from_utf8(payload[cursor..cursor + n_len].to_vec()).ok()?;
        cursor += n_len;
        nonce
    } else {
        String::new()
    };

    // Optional trailing SAS echo (audit finding #10): length-prefixed, decoded
    // to String::new() when absent — the mandatory SAS-echo check then rejects
    // the pairing exactly as it does a JSON body without `sas_hex`.
    let sas_hex = if payload.len() >= cursor + 4 {
        let s_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
        cursor += 4;
        if payload.len() < cursor + s_len {
            return None;
        }
        String::from_utf8(payload[cursor..cursor + s_len].to_vec()).ok()?
    } else {
        String::new()
    };

    Some((ct, pk, x25519_pk, cert_hash, nonce_hex, sas_hex))
}
