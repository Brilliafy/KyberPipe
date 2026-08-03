//! Wire codec: `RatchetEncryptedMessage` + binary TLV framing (audit finding
//! #11 — extracted from the former `state.rs` monolith so the wire contract
//! lives apart from the live state machine and the persistence DTO).
//!
//! This is the SINGLE cross-platform serialization contract for ratchet
//! payloads — length-prefixed fields, no hex-in-JSON drift surface, ~2x
//! smaller than hex.

use crate::error::KyberError;
use serde::{Deserialize, Serialize};

/// Represents an encrypted ratchet message with optional DH re-key payload.
/// UniFFI Record: nonce and ciphertext are raw byte arrays, no hex encoding.
///
/// AUDIT FINDING #28: the serde path was previously a SECOND, hex-based
/// encoding of the same three rekey fields (via `opt_hex_bytes` custom
/// deserializers). Nothing serializes this record as JSON — the wire and the
/// snapshot both use the length-prefixed binary TLV (`to_binary`/`from_binary`)
/// and the decoded `RatchetSnapshot` DTO respectively — so the hex contract
/// was dead surface that could silently drift from the live wire format. The
/// custom hex deserializers are deleted; serde is retained only as a plain
/// default derive (never exercised by the wire), so exactly ONE (encode,
/// decode) pair exists: the binary TLV.
#[derive(uniffi::Record, Serialize, Deserialize)]
pub struct RatchetEncryptedMessage {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// If Some, this message includes a new ephemeral public key for DH ratchet re-key
    #[serde(default)]
    pub rekey_x25519_pk: Option<Vec<u8>>,
    #[serde(default)]
    pub rekey_mlkem_pk: Option<Vec<u8>>,
    #[serde(default)]
    pub rekey_ciphertext: Option<Vec<u8>>,
}

impl RatchetEncryptedMessage {
    pub fn to_binary(&self) -> Result<Vec<u8>, KyberError> {
        // Audit finding #23: a rekey payload is ALL-OR-NOTHING. A partial set
        // would encode zero-length placeholders that decode as Some(vec![]),
        // poisoning the rekey-aware dispatch and making decapsulation attempt a
        // zero-length KEM ciphertext. Reject partial sets at the boundary.
        let present = self.rekey_x25519_pk.is_some() as u8
            + self.rekey_mlkem_pk.is_some() as u8
            + self.rekey_ciphertext.is_some() as u8;
        if present > 0 && present < 3 {
            return Err(KyberError::SerializationError(
                "Ratchet TLV rekey payload must be all-or-nothing (partial set)".into(),
            ));
        }
        let has_rekey = present == 3;
        let mut buf = Vec::with_capacity(6 + self.nonce.len() + self.ciphertext.len() + 48);
        buf.push(0x01); // version
        buf.push(has_rekey as u8);
        buf.extend_from_slice(&(self.nonce.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        if has_rekey {
            for field in [
                self.rekey_x25519_pk.as_deref(),
                self.rekey_mlkem_pk.as_deref(),
                self.rekey_ciphertext.as_deref(),
            ] {
                let bytes = field.expect("all-or-nothing rekey verified above");
                buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(bytes);
            }
        }
        Ok(buf)
    }

    pub fn from_binary(data: &[u8]) -> Result<Self, KyberError> {
        let mut cursor = 0usize;
        let mut take = |n: usize, what: &str| -> Result<&[u8], KyberError> {
            if data.len() < cursor + n {
                return Err(KyberError::SerializationError(format!(
                    "Ratchet TLV truncated at {what}"
                )));
            }
            let slice = &data[cursor..cursor + n];
            cursor += n;
            Ok(slice)
        };
        let version = take(1, "version")?[0];
        if version != 0x01 {
            return Err(KyberError::SerializationError(format!(
                "Unsupported ratchet TLV version {version}"
            )));
        }
        let has_rekey = take(1, "has_rekey")?[0] != 0;
        let mut read_bytes = |what: &str| -> Result<Vec<u8>, KyberError> {
            let len = u32::from_be_bytes(take(4, what)?.try_into().unwrap()) as usize;
            Ok(take(len, what)?.to_vec())
        };
        let nonce = read_bytes("nonce")?;
        let ciphertext = read_bytes("ciphertext")?;
        let (rekey_x25519_pk, rekey_mlkem_pk, rekey_ciphertext) = if has_rekey {
            let x = read_bytes("rekey_x")?;
            let m = read_bytes("rekey_m")?;
            let ct = read_bytes("rekey_ct")?;
            // Audit finding #23: reject zero-length rekey fields — an empty
            // payload would decode as Some(vec![]) and poison the rekey-aware
            // dispatch. A legitimate payload always has non-empty fields.
            if x.is_empty() || m.is_empty() || ct.is_empty() {
                return Err(KyberError::SerializationError(
                    "Ratchet TLV rekey payload contains empty field(s)".into(),
                ));
            }
            (Some(x), Some(m), Some(ct))
        } else {
            (None, None, None)
        };
        Ok(Self {
            nonce,
            ciphertext,
            rekey_x25519_pk,
            rekey_mlkem_pk,
            rekey_ciphertext,
        })
    }
}
