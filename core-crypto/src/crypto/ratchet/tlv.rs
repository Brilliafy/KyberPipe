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

#[cfg(test)]
mod golden_tests {
    use super::*;

    /// AUDIT P3-2: pin the EXACT wire layout of the ratchet TLV so any future
    /// change to the codec (or a cross-platform drift between the independently
    /// compiled Rust/Tauri and Android/UniFFI consumers) fails the build with a
    /// golden-byte diff instead of producing a silent AEAD/parse desync.
    ///
    /// Wire format (length-prefixed, big-endian):
    ///   [0x01] version
    ///   [has_rekey: 1B]
    ///   [nonce_len: 4B][nonce]
    ///   [ciphertext_len: 4B][ciphertext]
    ///   [if has_rekey] [x_len:4B][rekey_x][m_len:4B][rekey_m][ct_len:4B][rekey_ct]
    #[test]
    fn golden_bytes_pin_the_wire_format() {
        let msg = RatchetEncryptedMessage {
            nonce: vec![
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ],
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
            rekey_x25519_pk: Some(vec![0x01; 32]),
            rekey_mlkem_pk: Some(vec![0x02; 1184]),
            rekey_ciphertext: Some(vec![0x03; 1088]),
        };
        let bytes = msg.to_binary().expect("encode");
        let mut expected = Vec::new();
        expected.push(0x01); // version
        expected.push(0x01); // has_rekey
        expected.extend_from_slice(&12u32.to_be_bytes());
        expected.extend_from_slice(&msg.nonce);
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(&msg.ciphertext);
        expected.extend_from_slice(&32u32.to_be_bytes());
        expected.extend_from_slice(&[0x01; 32]);
        expected.extend_from_slice(&1184u32.to_be_bytes());
        expected.extend_from_slice(&[0x02; 1184]);
        expected.extend_from_slice(&1088u32.to_be_bytes());
        expected.extend_from_slice(&[0x03; 1088]);
        assert_eq!(
            bytes, expected,
            "wire layout must match the pinned golden bytes"
        );

        // Round-trip and a NO-rekey message must keep the same framing.
        let decoded = RatchetEncryptedMessage::from_binary(&bytes).expect("decode");
        assert_eq!(decoded.nonce, msg.nonce);
        assert_eq!(decoded.ciphertext, msg.ciphertext);
        assert_eq!(decoded.rekey_x25519_pk, msg.rekey_x25519_pk);

        let plain = RatchetEncryptedMessage {
            nonce: vec![0x11; 12],
            ciphertext: vec![0x22; 8],
            rekey_x25519_pk: None,
            rekey_mlkem_pk: None,
            rekey_ciphertext: None,
        };
        let plain_bytes = plain.to_binary().expect("encode plain");
        assert_eq!(&plain_bytes[..2], &[0x01, 0x00], "no-rekey flag is 0");
        let plain_decoded = RatchetEncryptedMessage::from_binary(&plain_bytes).expect("decode");
        assert!(plain_decoded.rekey_x25519_pk.is_none());
        assert!(plain_decoded.rekey_mlkem_pk.is_none());
        assert!(plain_decoded.rekey_ciphertext.is_none());
    }

    /// AUDIT P3-2: length-prefixed fields must be rejected when truncated,
    /// versioned out, or carrying empty rekey fields (finding #23).
    #[test]
    fn golden_parser_rejects_malformed_frames() {
        // Truncated after the version.
        assert!(RatchetEncryptedMessage::from_binary(&[0x01]).is_err());
        // Unsupported version.
        assert!(RatchetEncryptedMessage::from_binary(&[0x02, 0x00, 0, 0, 0, 0]).is_err());
        // has_rekey=1 but an empty rekey field.
        let mut bytes = vec![0x01, 0x01];
        bytes.extend_from_slice(&12u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 0]);
        bytes.extend_from_slice(&0u32.to_be_bytes()); // empty rekey_x
        assert!(RatchetEncryptedMessage::from_binary(&bytes).is_err());
    }
}
