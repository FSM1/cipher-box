//! IPNS record creation and marshaling.
//!
//! Produces IPNS records compatible with the TypeScript `ipns` npm package output.
//! - CBOR-encoded data field with V2 signature
//! - Protobuf-encoded IpnsEntry for marshaling
//!
//! IPNS name derivation has been extracted to the `cipherbox-crypto` crate
//! (see `cipherbox_crypto::ipns_name::derive_ipns_name`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ciborium::Value as CborValue;
use thiserror::Error;

use cipherbox_crypto::ed25519::{get_public_key, sign_ed25519};
use cipherbox_crypto::ipns_name::encode_libp2p_public_key;

// Re-export derive_ipns_name for backward compatibility (tests and other code
// that reference `crate::crypto::ipns::derive_ipns_name`).
pub use cipherbox_crypto::ipns_name::derive_ipns_name;

/// IPNS signature prefix per IPFS spec: "ipns-signature:".
const IPNS_SIGNATURE_PREFIX: &[u8] = b"ipns-signature:";

/// Default IPNS record TTL: 300 seconds (5 minutes) in nanoseconds.
/// This matches the ipns npm package default.
const DEFAULT_TTL_NS: u64 = 300_000_000_000;

#[derive(Debug, Error)]
pub enum IpnsError {
    #[error("IPNS record creation failed")]
    CreationFailed,
    #[error("IPNS record marshaling failed")]
    MarshalingFailed,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("CBOR encoding failed")]
    CborEncodingFailed,
    #[error("Signing failed")]
    SigningFailed,
}

/// IPNS record structure matching the TypeScript IPNSRecord type.
#[derive(Debug, Clone)]
pub struct IpnsRecord {
    /// IPFS path value (e.g., "/ipfs/bafy...").
    pub value: String,
    /// RFC3339 validity timestamp with nanosecond precision.
    pub validity: String,
    /// Validity type (0 = EOL).
    pub validity_type: u32,
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// TTL in nanoseconds.
    pub ttl: u64,
    /// 64-byte Ed25519 V1 signature.
    pub signature_v1: Vec<u8>,
    /// 64-byte Ed25519 V2 signature.
    pub signature_v2: Vec<u8>,
    /// CBOR-encoded record data.
    pub data: Vec<u8>,
    /// 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
}

/// Decode the CBOR-encoded data field from a signed IPNS record.
///
/// This is the inverse of `build_cbor_data`. Extracts the `Value` (IPFS path)
/// and `Sequence` (monotonic counter) fields from the CBOR map.
///
/// # Errors
///
/// Returns `Err(IpnsError::CborEncodingFailed)` if:
/// - The buffer is not valid CBOR
/// - The top-level value is not a map
/// - The map is missing the "Value" or "Sequence" key
/// - The "Value" bytes are not valid UTF-8
/// - The "Sequence" integer cannot be converted to u64 (e.g. negative)
pub fn decode_ipns_cbor_data(data: &[u8]) -> Result<(String, u64), IpnsError> {
    let map: CborValue = ciborium::from_reader(data).map_err(|_| IpnsError::CborEncodingFailed)?;
    let entries = match map {
        CborValue::Map(m) => m,
        _ => return Err(IpnsError::CborEncodingFailed),
    };
    let mut value_bytes: Option<Vec<u8>> = None;
    let mut sequence: Option<u64> = None;
    for (k, v) in entries {
        let key = match k {
            CborValue::Text(s) => s,
            _ => continue,
        };
        match key.as_str() {
            "Value" => {
                if value_bytes.is_some() {
                    return Err(IpnsError::CborEncodingFailed);
                }
                value_bytes = match v {
                    CborValue::Bytes(b) => Some(b),
                    _ => return Err(IpnsError::CborEncodingFailed),
                };
            }
            "Sequence" => {
                if sequence.is_some() {
                    return Err(IpnsError::CborEncodingFailed);
                }
                let raw: i128 = match v {
                    CborValue::Integer(i) => i.into(),
                    _ => return Err(IpnsError::CborEncodingFailed),
                };
                sequence = Some(u64::try_from(raw).map_err(|_| IpnsError::CborEncodingFailed)?);
            }
            _ => {}
        }
    }
    let value = String::from_utf8(value_bytes.ok_or(IpnsError::CborEncodingFailed)?)
        .map_err(|_| IpnsError::CborEncodingFailed)?;
    let seq = sequence.ok_or(IpnsError::CborEncodingFailed)?;
    Ok((value, seq))
}

/// Decode the `"Validity"` bytes and `"ValidityType"` from a signed IPNS CBOR data field.
///
/// Companion to `decode_ipns_cbor_data` that extracts the `Validity` field (the RFC3339
/// expiry timestamp stored as UTF-8 bytes) and the `ValidityType` field (an integer; `0`
/// means EOL/expiry per the IPNS spec) from the CBOR map. Used by `bind_verified` in
/// `cipherbox-api-client` for resolve-side EOL/expiry enforcement (D-07, Plan 60-01) and
/// ValidityType binding (Phase 75, gap #7 — this decoder only reports the value, the
/// `== 0` gate lives in `bind_verified`).
///
/// Returns `(Some(validity_bytes), validity_type)` if the "Validity" key is present and
/// contains bytes; `(None, validity_type)` if the "Validity" key is absent (caller must
/// treat absent Validity as fail-closed invalid). `validity_type` is `Some(n)` if the
/// "ValidityType" key is present and is an integer, `None` if the key is absent.
///
/// # Errors
///
/// Returns `Err(IpnsError::CborEncodingFailed)` if the buffer is not valid CBOR, the
/// top-level value is not a map, the "Validity" entry is present but not bytes, the
/// "ValidityType" entry is present but not an integer, or either key appears twice.
pub fn decode_ipns_cbor_validity(
    data: &[u8],
) -> Result<(Option<Vec<u8>>, Option<i64>), IpnsError> {
    let map: CborValue = ciborium::from_reader(data).map_err(|_| IpnsError::CborEncodingFailed)?;
    let entries = match map {
        CborValue::Map(m) => m,
        _ => return Err(IpnsError::CborEncodingFailed),
    };
    // Reject duplicate "Validity"/"ValidityType" keys (parser-differential / first-wins-vs-
    // last-wins hardening), mirroring decode_ipns_cbor_data's duplicate-key rejection.
    let mut validity_bytes: Option<Vec<u8>> = None;
    let mut validity_type: Option<i64> = None;
    for (k, v) in entries {
        let key = match k {
            CborValue::Text(s) => s,
            _ => continue,
        };
        if key == "Validity" {
            if validity_bytes.is_some() {
                return Err(IpnsError::CborEncodingFailed);
            }
            validity_bytes = match v {
                CborValue::Bytes(b) => Some(b),
                _ => return Err(IpnsError::CborEncodingFailed),
            };
        }
        // TODO(RED): ValidityType extraction not yet implemented — GREEN step follows.
    }
    // "Validity"/"ValidityType" keys absent — caller treats as fail-closed.
    Ok((validity_bytes, validity_type))
}

/// Build the CBOR-encoded data field for an IPNS record.
///
/// The field order matches the ipns npm package: TTL, Value, Sequence, Validity, ValidityType.
/// Keys are strings, values match the types used by the ipns package.
fn build_cbor_data(
    value: &str,
    validity: &str,
    sequence: u64,
    ttl: u64,
) -> Result<Vec<u8>, IpnsError> {
    let cbor_map = CborValue::Map(vec![
        (
            CborValue::Text("TTL".to_string()),
            CborValue::Integer(ttl.into()),
        ),
        (
            CborValue::Text("Value".to_string()),
            CborValue::Bytes(value.as_bytes().to_vec()),
        ),
        (
            CborValue::Text("Sequence".to_string()),
            CborValue::Integer(sequence.into()),
        ),
        (
            CborValue::Text("Validity".to_string()),
            CborValue::Bytes(validity.as_bytes().to_vec()),
        ),
        (
            CborValue::Text("ValidityType".to_string()),
            CborValue::Integer(0.into()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&cbor_map, &mut buf).map_err(|_| IpnsError::CborEncodingFailed)?;
    Ok(buf)
}

/// Format a timestamp as RFC3339 with nanosecond precision matching the ipns npm package.
///
/// The ipns package uses format: "2026-02-08T23:31:12.138000000Z"
fn format_validity_timestamp(validity_time: SystemTime) -> String {
    let duration = validity_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = civil_from_days(days as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        year, month, day, hours, minutes, seconds, nanos
    )
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant's civil_from_days.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Compute the V1 signature.
///
/// Per IPNS spec, V1 signature is over: value_bytes + validity_bytes + varint(validityType)
fn compute_v1_signature(
    ed25519_private_key: &[u8; 32],
    value: &str,
    validity: &str,
) -> Result<Vec<u8>, IpnsError> {
    let mut data_to_sign = Vec::new();
    data_to_sign.extend_from_slice(value.as_bytes());
    data_to_sign.extend_from_slice(validity.as_bytes());
    data_to_sign.push(0x00);

    sign_ed25519(&data_to_sign, ed25519_private_key).map_err(|_| IpnsError::SigningFailed)
}

/// Compute the V2 signature.
///
/// Per IPNS spec, V2 signature is over: "ipns-signature:" + cbor_data
fn compute_v2_signature(
    ed25519_private_key: &[u8; 32],
    cbor_data: &[u8],
) -> Result<Vec<u8>, IpnsError> {
    let mut data_to_sign = Vec::with_capacity(IPNS_SIGNATURE_PREFIX.len() + cbor_data.len());
    data_to_sign.extend_from_slice(IPNS_SIGNATURE_PREFIX);
    data_to_sign.extend_from_slice(cbor_data);

    sign_ed25519(&data_to_sign, ed25519_private_key).map_err(|_| IpnsError::SigningFailed)
}

/// Create an IPNS record signed with the given Ed25519 private key.
///
/// Matches the TypeScript `createIpnsRecord` with `v1Compatible: true`.
pub fn create_ipns_record(
    ed25519_private_key: &[u8; 32],
    value: &str,
    sequence_number: u64,
    lifetime_ms: u64,
) -> Result<IpnsRecord, IpnsError> {
    let public_key = get_public_key(ed25519_private_key).map_err(|_| IpnsError::InvalidPrivateKey)?;

    let now = SystemTime::now();
    let lifetime_duration = Duration::from_millis(lifetime_ms);
    let validity_time = now + lifetime_duration;
    let validity = format_validity_timestamp(validity_time);

    let ttl = DEFAULT_TTL_NS;

    let cbor_data = build_cbor_data(value, &validity, sequence_number, ttl)?;

    let signature_v2 = compute_v2_signature(ed25519_private_key, &cbor_data)?;

    let signature_v1 = compute_v1_signature(ed25519_private_key, value, &validity)?;

    Ok(IpnsRecord {
        value: value.to_string(),
        validity,
        validity_type: 0,
        sequence: sequence_number,
        ttl,
        signature_v1,
        signature_v2,
        data: cbor_data,
        public_key,
    })
}

/// Marshal an IPNS record to protobuf bytes.
///
/// IpnsEntry protobuf fields:
/// - field 1 (bytes): Value
/// - field 2 (bytes): signatureV1
/// - field 3 (enum): ValidityType (0 = EOL)
/// - field 4 (bytes): Validity (RFC3339 as bytes)
/// - field 5 (uint64): Sequence
/// - field 6 (uint64): TTL (nanoseconds)
/// - field 7 (bytes): pubKey (libp2p protobuf-wrapped Ed25519 public key)
/// - field 8 (bytes): signatureV2
/// - field 9 (bytes): data (CBOR)
pub fn marshal_ipns_record(record: &IpnsRecord) -> Result<Vec<u8>, IpnsError> {
    let mut buf = Vec::new();

    encode_proto_bytes(&mut buf, 1, record.value.as_bytes());
    encode_proto_bytes(&mut buf, 2, &record.signature_v1);
    encode_proto_varint(&mut buf, 3, record.validity_type as u64);
    encode_proto_bytes(&mut buf, 4, record.validity.as_bytes());
    encode_proto_varint(&mut buf, 5, record.sequence);
    encode_proto_varint(&mut buf, 6, record.ttl);

    let libp2p_pub_key = encode_libp2p_public_key(&record.public_key)
        .map_err(|_| IpnsError::InvalidPublicKey)?;
    encode_proto_bytes(&mut buf, 7, &libp2p_pub_key);

    encode_proto_bytes(&mut buf, 8, &record.signature_v2);
    encode_proto_bytes(&mut buf, 9, &record.data);

    Ok(buf)
}

/// Encode a protobuf length-delimited (bytes) field.
fn encode_proto_bytes(buf: &mut Vec<u8>, field_number: u32, data: &[u8]) {
    encode_varint(buf, ((field_number as u64) << 3) | 2);
    encode_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

/// Encode a protobuf varint field.
fn encode_proto_varint(buf: &mut Vec<u8>, field_number: u32, value: u64) {
    encode_varint(buf, ((field_number as u64) << 3) | 0);
    encode_varint(buf, value);
}

/// Encode a varint (protobuf LEB128).
fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_crypto::ed25519::{generate_ed25519_keypair, verify_ed25519};

    #[test]
    fn create_ipns_record_produces_valid_fields() {
        let (_pub_key, priv_key) = generate_ed25519_keypair();
        let priv_key_arr: [u8; 32] = priv_key[..32].try_into().unwrap();

        let record = create_ipns_record(
            &priv_key_arr,
            "/ipfs/bafytest123",
            42,
            3600000, // 1 hour
        )
        .unwrap();

        assert_eq!(record.value, "/ipfs/bafytest123");
        assert_eq!(record.sequence, 42);
        assert_eq!(record.validity_type, 0);
        assert_eq!(record.ttl, 300_000_000_000);
        assert_eq!(record.signature_v1.len(), 64);
        assert_eq!(record.signature_v2.len(), 64);
        assert_eq!(record.public_key.len(), 32);
        assert!(!record.data.is_empty());
        // Validity should be RFC3339 with nanosecond precision ending in Z
        assert!(record.validity.ends_with('Z'));
        assert!(record.validity.contains('T'));
    }

    #[test]
    fn create_ipns_record_v2_signature_verifiable() {
        let (pub_key, priv_key) = generate_ed25519_keypair();
        let priv_key_arr: [u8; 32] = priv_key[..32].try_into().unwrap();

        let record = create_ipns_record(&priv_key_arr, "/ipfs/bafytest", 0, 60000).unwrap();

        // V2 signature is over "ipns-signature:" + cbor_data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(b"ipns-signature:");
        signed_data.extend_from_slice(&record.data);

        assert!(verify_ed25519(&signed_data, &record.signature_v2, &pub_key));
    }

    #[test]
    fn format_validity_timestamp_epoch_zero() {
        let ts = format_validity_timestamp(UNIX_EPOCH);
        assert_eq!(ts, "1970-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn format_validity_timestamp_known_date() {
        // 2024-01-01T00:00:00Z = 1704067200 seconds since epoch
        let ts = format_validity_timestamp(UNIX_EPOCH + Duration::from_secs(1704067200));
        assert_eq!(ts, "2024-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn format_validity_timestamp_with_nanos() {
        let ts = format_validity_timestamp(
            UNIX_EPOCH + Duration::from_secs(1704067200) + Duration::from_nanos(138000000),
        );
        assert_eq!(ts, "2024-01-01T00:00:00.138000000Z");
    }

    #[test]
    fn civil_from_days_epoch() {
        // Day 0 = 1970-01-01
        let (y, m, d) = civil_from_days(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_one_year() {
        // Day 365 = 1971-01-01 (1970 is not a leap year)
        let (y, m, d) = civil_from_days(365);
        assert_eq!((y, m, d), (1971, 1, 1));
    }

    #[test]
    fn civil_from_days_leap_year() {
        // 1972 is a leap year. Days from epoch to 1972-02-29:
        // 1970: 365 days, 1971: 365 days = 730 days to 1972-01-01
        // Jan 31 + Feb 28 = 59 days to 1972-02-29 => day 730 + 59 = 789
        let (y, m, d) = civil_from_days(789);
        assert_eq!((y, m, d), (1972, 2, 29));
    }

    #[test]
    fn civil_from_days_known_date_2024() {
        // 2024-01-01: 1704067200 / 86400 = 19723 days from epoch
        let (y, m, d) = civil_from_days(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    // ---------- decode_ipns_cbor_data tests (RED first, then implemented) ----------

    #[test]
    fn decode_ipns_cbor_data_round_trips_build() {
        // A CBOR buffer produced by build_cbor_data for known value and sequence
        // must decode back to the same pair via decode_ipns_cbor_data.
        let data = build_cbor_data("/ipfs/bafyTESTcid", "2024-01-01T00:00:00.000000000Z", 7, 300_000_000_000).unwrap();
        let (value, seq) = decode_ipns_cbor_data(&data).unwrap();
        assert_eq!(value, "/ipfs/bafyTESTcid");
        assert_eq!(seq, 7u64);
    }

    #[test]
    fn decode_ipns_cbor_data_round_trips_sequences() {
        let validity = "2024-01-01T00:00:00.000000000Z";
        for &seq in &[0u64, 1u64, u64::MAX / 2] {
            let data = build_cbor_data("/ipfs/bafyRTcid", validity, seq, 300_000_000_000).unwrap();
            let (_, decoded_seq) = decode_ipns_cbor_data(&data).unwrap();
            assert_eq!(decoded_seq, seq, "round-trip failed for seq={}", seq);
        }
    }

    #[test]
    fn decode_ipns_cbor_data_rejects_non_map() {
        // Encode a plain integer — not a map — must return Err(CborEncodingFailed).
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Integer(42u64.into()), &mut buf).unwrap();
        let err = decode_ipns_cbor_data(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    #[test]
    fn decode_ipns_cbor_data_rejects_missing_value_key() {
        // Map without "Value" key must return Err.
        let cbor_map = CborValue::Map(vec![
            (CborValue::Text("Sequence".to_string()), CborValue::Integer(1u64.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let err = decode_ipns_cbor_data(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    #[test]
    fn decode_ipns_cbor_data_rejects_missing_sequence_key() {
        // Map without "Sequence" key must return Err.
        let cbor_map = CborValue::Map(vec![
            (CborValue::Text("Value".to_string()), CborValue::Bytes(b"/ipfs/bafy".to_vec())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let err = decode_ipns_cbor_data(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    #[test]
    fn decode_ipns_cbor_data_rejects_negative_sequence() {
        // Negative integer for "Sequence" must fail u64::try_from → Err.
        let cbor_map = CborValue::Map(vec![
            (CborValue::Text("Value".to_string()), CborValue::Bytes(b"/ipfs/bafy".to_vec())),
            (CborValue::Text("Sequence".to_string()), CborValue::Integer((-1i64).into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let err = decode_ipns_cbor_data(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    #[test]
    fn decode_ipns_cbor_data_rejects_overflow_sequence() {
        // Sequence value greater than u64::MAX (encoded as CBOR bignum tag 2,
        // representing 2^64 = u64::MAX + 1).  ciborium parses tag 2 as a
        // CborValue::Tag, which does not match the Integer arm, so `sequence`
        // stays None and decode returns Err(CborEncodingFailed).
        //
        // Raw CBOR: 0xa2 (map/2) + "Value" key + b"/ipfs/x" bytes value +
        //           "Sequence" key + 0xc2 0x49 <9 bytes: 2^64> bignum value.
        let buf: Vec<u8> = vec![
            0xa2,                                           // map(2)
            0x65, 0x56, 0x61, 0x6c, 0x75, 0x65,           // text(5): "Value"
            0x47, 0x2f, 0x69, 0x70, 0x66, 0x73, 0x2f, 0x78, // bytes(7): "/ipfs/x"
            0x68, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, // text(8): "Sequence"
            0xc2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tag(2)/bignum: 2^64
        ];
        let err = decode_ipns_cbor_data(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    #[test]
    fn decode_ipns_cbor_data_rejects_invalid_utf8_value() {
        // Value bytes that are not valid UTF-8 → String::from_utf8 fails →
        // decode returns Err(CborEncodingFailed).
        let cbor_map = CborValue::Map(vec![
            (CborValue::Text("Value".to_string()), CborValue::Bytes(vec![0xFF, 0xFF])),
            (CborValue::Text("Sequence".to_string()), CborValue::Integer(1u64.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let err = decode_ipns_cbor_data(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    #[test]
    fn decode_ipns_cbor_data_rejects_duplicate_value_key() {
        // A CBOR map with two "Value" (Bytes) entries must return Err(CborEncodingFailed).
        // This guards against cross-language parser-differential attacks where a
        // duplicate key causes last-wins behaviour in one parser and first-wins in another.
        let cbor_map = CborValue::Map(vec![
            (CborValue::Text("Value".to_string()), CborValue::Bytes(b"/ipfs/bafy1".to_vec())),
            (CborValue::Text("Value".to_string()), CborValue::Bytes(b"/ipfs/bafy2".to_vec())),
            (CborValue::Text("Sequence".to_string()), CborValue::Integer(1u64.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let err = decode_ipns_cbor_data(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    #[test]
    fn decode_ipns_cbor_validity_rejects_duplicate_validity_key() {
        // Mirror of the Value/Sequence duplicate-key guard for the resolve-side EOL field:
        // two "Validity" (Bytes) entries must return Err(CborEncodingFailed) so a
        // parser-differential record cannot decode ambiguously across languages.
        let cbor_map = CborValue::Map(vec![
            (
                CborValue::Text("Validity".to_string()),
                CborValue::Bytes(b"2099-01-01T00:00:00.000000000Z".to_vec()),
            ),
            (
                CborValue::Text("Validity".to_string()),
                CborValue::Bytes(b"2000-01-01T00:00:00.000000000Z".to_vec()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let err = decode_ipns_cbor_validity(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    #[test]
    fn decode_ipns_cbor_validity_returns_validity_type_zero() {
        // A map with Validity bytes and ValidityType integer 0 returns both the
        // Validity bytes and Some(0).
        let cbor_map = CborValue::Map(vec![
            (
                CborValue::Text("Validity".to_string()),
                CborValue::Bytes(b"2099-01-01T00:00:00.000000000Z".to_vec()),
            ),
            (
                CborValue::Text("ValidityType".to_string()),
                CborValue::Integer(0.into()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let (validity, validity_type) = decode_ipns_cbor_validity(&buf).unwrap();
        assert_eq!(validity, Some(b"2099-01-01T00:00:00.000000000Z".to_vec()));
        assert_eq!(validity_type, Some(0));
    }

    #[test]
    fn decode_ipns_cbor_validity_returns_validity_type_one() {
        // A map with ValidityType integer 1 returns the Validity bytes and Some(1) — the
        // caller (bind_verified), not this decoder, decides the == 0 gate.
        let cbor_map = CborValue::Map(vec![
            (
                CborValue::Text("Validity".to_string()),
                CborValue::Bytes(b"2099-01-01T00:00:00.000000000Z".to_vec()),
            ),
            (
                CborValue::Text("ValidityType".to_string()),
                CborValue::Integer(1.into()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let (validity, validity_type) = decode_ipns_cbor_validity(&buf).unwrap();
        assert_eq!(validity, Some(b"2099-01-01T00:00:00.000000000Z".to_vec()));
        assert_eq!(validity_type, Some(1));
    }

    #[test]
    fn decode_ipns_cbor_validity_no_validity_type_key_returns_none() {
        // A map with no ValidityType key returns the Validity bytes and None.
        let cbor_map = CborValue::Map(vec![(
            CborValue::Text("Validity".to_string()),
            CborValue::Bytes(b"2099-01-01T00:00:00.000000000Z".to_vec()),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let (validity, validity_type) = decode_ipns_cbor_validity(&buf).unwrap();
        assert_eq!(validity, Some(b"2099-01-01T00:00:00.000000000Z".to_vec()));
        assert_eq!(validity_type, None);
    }

    #[test]
    fn decode_ipns_cbor_validity_rejects_duplicate_validity_type_key() {
        // Mirror of the duplicate-Validity-key guard: two "ValidityType" entries must
        // return Err(CborEncodingFailed) so a parser-differential record cannot decode
        // ambiguously across languages.
        let cbor_map = CborValue::Map(vec![
            (
                CborValue::Text("Validity".to_string()),
                CborValue::Bytes(b"2099-01-01T00:00:00.000000000Z".to_vec()),
            ),
            (
                CborValue::Text("ValidityType".to_string()),
                CborValue::Integer(0.into()),
            ),
            (
                CborValue::Text("ValidityType".to_string()),
                CborValue::Integer(1.into()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        let err = decode_ipns_cbor_validity(&buf).unwrap_err();
        assert!(matches!(err, IpnsError::CborEncodingFailed));
    }

    // ---------- end decode_ipns_cbor_data tests ----------

    #[test]
    fn build_cbor_data_produces_valid_cbor() {
        let data = build_cbor_data("/ipfs/bafytest", "2024-01-01T00:00:00.000000000Z", 5, 300_000_000_000).unwrap();
        // Should be valid CBOR -- attempt to parse it back
        let value: ciborium::Value = ciborium::from_reader(&data[..]).unwrap();
        match value {
            CborValue::Map(entries) => {
                assert_eq!(entries.len(), 5);
                // Check keys present
                let keys: Vec<String> = entries
                    .iter()
                    .filter_map(|(k, _)| {
                        if let CborValue::Text(s) = k {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                assert!(keys.contains(&"TTL".to_string()));
                assert!(keys.contains(&"Value".to_string()));
                assert!(keys.contains(&"Sequence".to_string()));
                assert!(keys.contains(&"Validity".to_string()));
                assert!(keys.contains(&"ValidityType".to_string()));
            }
            _ => panic!("Expected CBOR map"),
        }
    }

    #[test]
    fn different_sequences_produce_different_output() {
        let (_pub_key, priv_key) = generate_ed25519_keypair();
        let priv_key_arr: [u8; 32] = priv_key[..32].try_into().unwrap();

        let record0 = create_ipns_record(&priv_key_arr, "/ipfs/bafytest", 0, 60000).unwrap();
        let record100 = create_ipns_record(&priv_key_arr, "/ipfs/bafytest", 100, 60000).unwrap();

        assert_ne!(record0.data, record100.data);
        assert_ne!(record0.signature_v2, record100.signature_v2);
        assert_eq!(record0.sequence, 0);
        assert_eq!(record100.sequence, 100);
    }

    #[test]
    fn marshal_ipns_record_produces_bytes() {
        let (_pub_key, priv_key) = generate_ed25519_keypair();
        let priv_key_arr: [u8; 32] = priv_key[..32].try_into().unwrap();

        let record = create_ipns_record(&priv_key_arr, "/ipfs/bafytest", 1, 60000).unwrap();
        let marshaled = marshal_ipns_record(&record).unwrap();
        assert!(!marshaled.is_empty());
        // Protobuf: first byte should be field 1, wire type 2 (length-delimited) = 0x0A
        assert_eq!(marshaled[0], 0x0A);
    }
}
