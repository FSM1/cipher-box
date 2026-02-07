//! IPNS record creation, marshaling, and name derivation.
//!
//! Produces IPNS records compatible with the TypeScript `ipns` npm package output.
//! - CBOR-encoded data field with V2 signature
//! - Protobuf-encoded IpnsEntry for marshaling
//! - CIDv1 base36 IPNS name derivation

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ciborium::Value as CborValue;
use thiserror::Error;

use super::ed25519::{get_public_key, sign_ed25519};

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
    #[error("IPNS name derivation failed")]
    DerivationFailed,
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
    // The ipns npm package uses a CBOR map with string keys.
    // Field order (matching ipns npm package output): TTL, Value, Sequence, Validity, ValidityType
    //
    // - TTL: unsigned integer (nanoseconds)
    // - Value: byte string (the IPFS path as bytes)
    // - Sequence: unsigned integer
    // - Validity: byte string (RFC3339 timestamp as bytes)
    // - ValidityType: unsigned integer (0 = EOL)
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
/// This is: full datetime + "." + 9-digit nanoseconds + "Z"
fn format_validity_timestamp(validity_time: SystemTime) -> String {
    let duration = validity_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();

    // Compute date/time components from Unix timestamp
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch to date using civil_from_days algorithm
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
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
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
    // ValidityType 0 as varint = single byte 0x00
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
    // Derive public key
    let public_key = get_public_key(ed25519_private_key).map_err(|_| IpnsError::InvalidPrivateKey)?;

    // Compute validity timestamp
    let now = SystemTime::now();
    let lifetime_duration = Duration::from_millis(lifetime_ms);
    let validity_time = now + lifetime_duration;
    let validity = format_validity_timestamp(validity_time);

    let ttl = DEFAULT_TTL_NS;

    // Build CBOR data
    let cbor_data = build_cbor_data(value, &validity, sequence_number, ttl)?;

    // Compute V2 signature (over "ipns-signature:" + cbor_data)
    let signature_v2 = compute_v2_signature(ed25519_private_key, &cbor_data)?;

    // Compute V1 signature (over value + validity + varint(0))
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

/// Encode the Ed25519 public key in libp2p PublicKey protobuf format.
///
/// message PublicKey { KeyType Type = 1; bytes Data = 2; }
/// where KeyType.Ed25519 = 1
fn encode_libp2p_public_key(ed25519_public_key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Field 1 (Type): varint, field_number=1, wire_type=0 => tag = 0x08
    buf.push(0x08);
    // Value: 1 (Ed25519)
    buf.push(0x01);
    // Field 2 (Data): length-delimited, field_number=2, wire_type=2 => tag = 0x12
    buf.push(0x12);
    // Length of public key (32 bytes)
    buf.push(ed25519_public_key.len() as u8);
    buf.extend_from_slice(ed25519_public_key);
    buf
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

    // Field 1: Value (bytes, tag = 0x0a)
    encode_proto_bytes(&mut buf, 1, record.value.as_bytes());

    // Field 2: signatureV1 (bytes, tag = 0x12)
    encode_proto_bytes(&mut buf, 2, &record.signature_v1);

    // Field 3: ValidityType (enum/varint, tag = 0x18)
    encode_proto_varint(&mut buf, 3, record.validity_type as u64);

    // Field 4: Validity (bytes, tag = 0x22)
    encode_proto_bytes(&mut buf, 4, record.validity.as_bytes());

    // Field 5: Sequence (uint64, tag = 0x28)
    encode_proto_varint(&mut buf, 5, record.sequence);

    // Field 6: TTL (uint64, tag = 0x30)
    encode_proto_varint(&mut buf, 6, record.ttl);

    // Field 7: pubKey (bytes, tag = 0x3a) -- libp2p PublicKey protobuf
    let libp2p_pub_key = encode_libp2p_public_key(&record.public_key);
    encode_proto_bytes(&mut buf, 7, &libp2p_pub_key);

    // Field 8: signatureV2 (bytes, tag = 0x42)
    encode_proto_bytes(&mut buf, 8, &record.signature_v2);

    // Field 9: data (bytes, tag = 0x4a) -- CBOR
    encode_proto_bytes(&mut buf, 9, &record.data);

    Ok(buf)
}

/// Encode a protobuf length-delimited (bytes) field.
fn encode_proto_bytes(buf: &mut Vec<u8>, field_number: u32, data: &[u8]) {
    // Tag: (field_number << 3) | 2 (wire_type = length-delimited)
    encode_varint(buf, ((field_number as u64) << 3) | 2);
    // Length
    encode_varint(buf, data.len() as u64);
    // Data
    buf.extend_from_slice(data);
}

/// Encode a protobuf varint field.
fn encode_proto_varint(buf: &mut Vec<u8>, field_number: u32, value: u64) {
    // Tag: (field_number << 3) | 0 (wire_type = varint)
    encode_varint(buf, ((field_number as u64) << 3) | 0);
    // Value
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

/// Derive the IPNS name (CIDv1 base36) from an Ed25519 public key.
///
/// Steps:
/// 1. Wrap public key in libp2p PublicKey protobuf
/// 2. Create identity multihash: 0x00 (identity) + varint(len) + data
/// 3. Create CIDv1: version=1, codec=0x72 (libp2p-key), multihash
/// 4. Encode as base36 (k... prefix)
pub fn derive_ipns_name(ed25519_public_key: &[u8; 32]) -> Result<String, IpnsError> {
    // Step 1: Wrap in libp2p PublicKey protobuf
    let libp2p_pub_key = encode_libp2p_public_key(ed25519_public_key);

    // Step 2: Create identity multihash
    // Identity multihash: code=0x00, length=varint(data.len()), data
    let mut identity_multihash = Vec::new();
    identity_multihash.push(0x00); // identity hash function code
    // Encode length as unsigned varint
    encode_unsigned_varint(&mut identity_multihash, libp2p_pub_key.len() as u64);
    identity_multihash.extend_from_slice(&libp2p_pub_key);

    // Step 3: Create CIDv1
    // CIDv1 binary: version(1) + codec(0x72, libp2p-key) + multihash
    let mut cid_bytes = Vec::new();
    encode_unsigned_varint(&mut cid_bytes, 1); // CID version 1
    encode_unsigned_varint(&mut cid_bytes, 0x72); // libp2p-key codec
    cid_bytes.extend_from_slice(&identity_multihash);

    // Step 4: Encode as base36 with 'k' prefix
    let base36 = encode_base36(&cid_bytes);
    Ok(format!("k{}", base36))
}

/// Encode unsigned varint (same as protobuf varint / LEB128).
fn encode_unsigned_varint(buf: &mut Vec<u8>, mut value: u64) {
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

/// Encode bytes as base36 (lowercase).
///
/// Base36 alphabet: 0123456789abcdefghijklmnopqrstuvwxyz
fn encode_base36(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert byte array to big integer using repeated division
    let mut num = data.to_vec();
    let mut result = Vec::new();

    while !num.is_empty() {
        let mut remainder: u32 = 0;
        let mut quotient = Vec::new();

        for &byte in &num {
            let acc = (remainder << 8) | (byte as u32);
            let digit = acc / 36;
            remainder = acc % 36;

            if !quotient.is_empty() || digit > 0 {
                quotient.push(digit as u8);
            }
        }

        result.push(ALPHABET[remainder as usize]);
        num = quotient;
    }

    // Add leading '0's for each leading zero byte
    for _ in 0..leading_zeros {
        result.push(b'0');
    }

    result.reverse();
    String::from_utf8(result).unwrap_or_default()
}
