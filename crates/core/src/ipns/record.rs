//! IPNS V2 records: create/sign, byte-stable marshal/unmarshal, and the pure
//! verify chain (blueprint/core.md "IPNS records").
//!
//! A record is the spec-compliant IPFS `IpnsEntry` protobuf: `signatureV2`
//! (field 8) signs the DAG-CBOR `data` (field 9) whose `Value = /ipfs/<CID>` of
//! the DAG-CBOR envelope, and the deprecated top-level fields are emitted for
//! ecosystem compatibility. `sequence` (1 on first publish, the exact expected
//! next on CAS), the 90-day client-signed EOL, and the always-explicit TTL are
//! all caller-injected — core reads no clock and defaults neither (#33 D3); the
//! strict floor gate is the engine's.
//!
//! **Marshal/unmarshal is keyless and byte-stable** (blueprint/core.md
//! "Keyless re-PUT"): [`IpnsRecord::unmarshal`] preserves every field's exact
//! wire segment in order, so [`IpnsRecord::marshal`] reproduces a foreign signed
//! record byte-for-byte with no key material — including fields this codec does
//! not model (`signatureV1`, `pubKey`, any future field), which the republisher
//! and every accelerator depend on.
//!
//! **Verify is pure** (blueprint/core.md "Verify"): the Ed25519 key comes from
//! the [`IpnsName`] itself (never a side channel), `signatureV2` verifies over
//! `"ipns-signature:" || data`, and the signed `data.Value` must equal the
//! top-level `value`.

use crate::codec::{Map, Value, decode, encode_fixed_depth};
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::suite::ed25519::{Ed25519Signature, Ed25519Signer, SIGNATURE_LEN};

use super::name::IpnsName;

/// The `signatureV2` domain-separation prefix, per the IPNS record spec: the
/// signature covers `"ipns-signature:" || data`.
const SIG_V2_DOMAIN: &[u8] = b"ipns-signature:";

/// The only `validityType` this profile admits: `EOL` (an end-of-life
/// timestamp). The IPNS spec defines no other.
const VALIDITY_TYPE_EOL: u64 = 0;

/// The client-signed EOL policy window (blueprint/core.md, #24): a published
/// record is valid for 90 days. The concrete RFC3339 timestamp is injected
/// (core reads no clock); this names the policy the engine applies.
pub const DEFAULT_VALIDITY_DAYS: u64 = 90;

// IPNS `IpnsEntry` protobuf field numbers.
const FIELD_VALUE: u64 = 1;
const FIELD_VALIDITY_TYPE: u64 = 3;
const FIELD_VALIDITY: u64 = 4;
const FIELD_SEQUENCE: u64 = 5;
const FIELD_TTL: u64 = 6;
const FIELD_SIGNATURE_V2: u64 = 8;
const FIELD_DATA: u64 = 9;

// Protobuf wire types (only these two occur in a well-formed IpnsEntry; the
// fixed-width types are preserved verbatim as unknown fields for re-PUT).
const WIRE_VARINT: u64 = 0;
const WIRE_FIXED64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_FIXED32: u64 = 5;

/// The verified, extracted contents of an IPNS record — the values the adoption
/// gate compares (sequence vs floor, EOL for liveness). Taken from the signed
/// `data`, so every field here is authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecord {
    /// The `/ipfs/<CID>` path bytes the name points at.
    pub value: Vec<u8>,
    /// The RFC3339 EOL bytes (opaque to core; the engine parses/compares).
    pub validity: Vec<u8>,
    /// The record sequence number (strictly-newer-vs-floor comparator input).
    pub sequence: u64,
    /// The TTL in nanoseconds (injected from the sync timing profile).
    pub ttl: u64,
}

/// One decoded protobuf field, holding its exact wire segment so marshal is
/// byte-stable regardless of the value's shape.
#[derive(Debug, Clone)]
struct ProtoField {
    number: u64,
    wire_type: u64,
    /// The complete wire segment (tag varint + value), preserved verbatim.
    raw: Vec<u8>,
    /// The decoded value view for typed access.
    value: FieldValue,
}

#[derive(Debug, Clone)]
enum FieldValue {
    /// A varint (wire 0). Its value is validated on parse but not retained: the
    /// verify chain reads sequence/ttl/validityType from the signed `data`, not
    /// from the deprecated top-level fields, so no typed accessor needs it.
    Varint,
    /// Length-delimited (wire 2) payload, or a fixed32/fixed64 payload preserved
    /// verbatim for re-PUT.
    Bytes(Vec<u8>),
}

/// A parsed IPNS record. Holds the ordered protobuf fields verbatim, so it can
/// be re-marshaled byte-for-byte without any key material.
#[derive(Debug, Clone)]
pub struct IpnsRecord {
    fields: Vec<ProtoField>,
}

impl IpnsRecord {
    /// Build and sign a spec-compliant V2 record from the injected signer,
    /// `/ipfs/<CID>` value, sequence, TTL, and RFC3339 EOL. The top-level
    /// compat fields are emitted to match the signed `data`.
    pub fn create_v2(
        signer: &Ed25519Signer,
        value: &[u8],
        sequence: u64,
        ttl_nanos: u64,
        validity_eol: &str,
    ) -> Self {
        let validity = validity_eol.as_bytes();
        let data = encode_data(value, validity, VALIDITY_TYPE_EOL, sequence, ttl_nanos);

        // signatureV2 = Sign(sk, "ipns-signature:" || data).
        let mut preimage = Vec::with_capacity(SIG_V2_DOMAIN.len() + data.len());
        preimage.extend_from_slice(SIG_V2_DOMAIN);
        preimage.extend_from_slice(&data);
        let signature = signer.sign(&preimage);

        // Fields in ascending number order with minimal varints — the canonical
        // shape go-ipfs/helia also emit, so our own records round-trip trivially.
        let fields = vec![
            len_field(FIELD_VALUE, value.to_vec()),
            varint_field(FIELD_VALIDITY_TYPE, VALIDITY_TYPE_EOL),
            len_field(FIELD_VALIDITY, validity.to_vec()),
            varint_field(FIELD_SEQUENCE, sequence),
            varint_field(FIELD_TTL, ttl_nanos),
            len_field(FIELD_SIGNATURE_V2, signature.to_bytes().to_vec()),
            len_field(FIELD_DATA, data),
        ];
        Self { fields }
    }

    /// Parse a foreign signed record, preserving every field verbatim.
    /// **Keyless**: no signing key is involved and no field is dropped, so
    /// [`marshal`](Self::marshal) round-trips the input byte-for-byte.
    pub fn unmarshal(bytes: &[u8]) -> Result<Self, CodecError> {
        let fields = parse_fields(bytes).ok_or(Malformed::IpnsRecordMalformed)?;
        Ok(Self { fields })
    }

    /// Re-serialize the record. Byte-stable for any [`unmarshal`](Self::unmarshal)ed
    /// input (the wire segments are concatenated in their original order).
    pub fn marshal(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in &self.fields {
            out.extend_from_slice(&f.raw);
        }
        out
    }

    /// The full pure verify chain against `name` — whose Ed25519 key is the sole
    /// trust anchor (never a side channel). Fail-closed and two-class: a
    /// structurally incomplete record is [`Malformed::IpnsRecordMalformed`], a
    /// `signatureV2` that does not verify is
    /// [`TrustViolation::IpnsSignatureInvalid`], and a signed `data.Value`
    /// disagreeing with the top-level `value` is
    /// [`TrustViolation::IpnsValueMismatch`].
    pub fn verify(&self, name: &IpnsName) -> Result<VerifiedRecord, CodecError> {
        let top_value = self.unique_len_field(FIELD_VALUE)?;
        let signature_bytes = self.unique_len_field(FIELD_SIGNATURE_V2)?;
        let data = self.unique_len_field(FIELD_DATA)?;

        let sig_array: [u8; SIGNATURE_LEN] = signature_bytes
            .try_into()
            .map_err(|_| Malformed::IpnsRecordMalformed)?;
        let signature = Ed25519Signature::from_bytes(sig_array);
        let mut preimage = Vec::with_capacity(SIG_V2_DOMAIN.len() + data.len());
        preimage.extend_from_slice(SIG_V2_DOMAIN);
        preimage.extend_from_slice(data);
        if !name.public_key().verify(&preimage, &signature) {
            return Err(TrustViolation::IpnsSignatureInvalid.into());
        }

        // The signed data is authoritative; the top-level value must agree.
        let signed = decode_data(data)?;
        if signed.value != top_value {
            return Err(TrustViolation::IpnsValueMismatch.into());
        }
        Ok(signed)
    }

    /// A required length-delimited field that must appear exactly once.
    fn unique_len_field(&self, number: u64) -> Result<&[u8], CodecError> {
        let mut found: Option<&[u8]> = None;
        for f in &self.fields {
            if f.number == number {
                if found.is_some() {
                    return Err(Malformed::IpnsRecordMalformed.into());
                }
                match &f.value {
                    FieldValue::Bytes(b) if f.wire_type == WIRE_LEN => found = Some(b),
                    _ => return Err(Malformed::IpnsRecordMalformed.into()),
                }
            }
        }
        found.ok_or_else(|| Malformed::IpnsRecordMalformed.into())
    }
}

// ---------------------------------------------------------------------------
// The signed `data` field: the DAG-CBOR map with the frozen capitalized keys.
// ---------------------------------------------------------------------------

fn encode_data(
    value: &[u8],
    validity: &[u8],
    validity_type: u64,
    sequence: u64,
    ttl: u64,
) -> Vec<u8> {
    // Map::insert imposes canonical (length-first) key order; the wire order is
    // TTL, Value, Sequence, Validity, ValidityType.
    let mut m = Map::new();
    m.insert("TTL", Value::Unsigned(ttl));
    m.insert("Value", Value::Bytes(value.to_vec()));
    m.insert("Sequence", Value::Unsigned(sequence));
    m.insert("Validity", Value::Bytes(validity.to_vec()));
    m.insert("ValidityType", Value::Unsigned(validity_type));
    encode_fixed_depth(&Value::Map(m))
}

/// Decode + shape-check the signed `data`. Any structural defect (non-canonical
/// CBOR, wrong types, missing keys, an unsupported validity type) is one
/// `ipns-record-malformed` — this is the IPNS verdict domain, so it never leaks
/// a raw codec check name.
fn decode_data(data: &[u8]) -> Result<VerifiedRecord, CodecError> {
    let malformed = || CodecError::from(Malformed::IpnsRecordMalformed);
    let value = decode(data).map_err(|_| malformed())?;
    let map = value.as_map().map_err(|_| malformed())?;

    let get_bytes = |k: &str| -> Result<Vec<u8>, CodecError> {
        map.get(k)
            .ok_or_else(malformed)?
            .as_bytes()
            .map(<[u8]>::to_vec)
            .map_err(|_| malformed())
    };
    let get_uint = |k: &str| -> Result<u64, CodecError> {
        map.get(k)
            .ok_or_else(malformed)?
            .as_unsigned()
            .map_err(|_| malformed())
    };

    if get_uint("ValidityType")? != VALIDITY_TYPE_EOL {
        return Err(malformed());
    }
    Ok(VerifiedRecord {
        value: get_bytes("Value")?,
        validity: get_bytes("Validity")?,
        sequence: get_uint("Sequence")?,
        ttl: get_uint("TTL")?,
    })
}

// ---------------------------------------------------------------------------
// Minimal protobuf: varint + field reader/writer. No prost dependency — the
// IpnsEntry has a handful of scalar/bytes fields, and hand-rolling keeps the
// re-PUT path in full control of the exact bytes.
// ---------------------------------------------------------------------------

/// Read a base-128 varint, bounded to 10 bytes (the u64 ceiling). `None` on
/// truncation or an over-long encoding.
fn read_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

fn write_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            return;
        }
    }
}

/// Parse a whole IpnsEntry into ordered, verbatim-preserving fields. `None` on
/// any malformed wire structure (truncation, an unknown wire type, an over-long
/// varint) — the fail-closed re-PUT boundary.
fn parse_fields(bytes: &[u8]) -> Option<Vec<ProtoField>> {
    let mut pos = 0usize;
    let mut fields = Vec::new();
    while pos < bytes.len() {
        let seg_start = pos;
        let tag = read_varint(bytes, &mut pos)?;
        let number = tag >> 3;
        let wire_type = tag & 0x07;
        let value = match wire_type {
            WIRE_VARINT => {
                read_varint(bytes, &mut pos)?;
                FieldValue::Varint
            }
            WIRE_LEN => {
                let len = usize::try_from(read_varint(bytes, &mut pos)?).ok()?;
                let end = pos.checked_add(len)?;
                let slice = bytes.get(pos..end)?;
                pos = end;
                FieldValue::Bytes(slice.to_vec())
            }
            WIRE_FIXED64 => {
                let end = pos.checked_add(8)?;
                let slice = bytes.get(pos..end)?;
                pos = end;
                FieldValue::Bytes(slice.to_vec())
            }
            WIRE_FIXED32 => {
                let end = pos.checked_add(4)?;
                let slice = bytes.get(pos..end)?;
                pos = end;
                FieldValue::Bytes(slice.to_vec())
            }
            // Groups (3/4) and any reserved wire type: not part of IPNS.
            _ => return None,
        };
        fields.push(ProtoField {
            number,
            wire_type,
            raw: bytes[seg_start..pos].to_vec(),
            value,
        });
    }
    Some(fields)
}

/// A freshly-built length-delimited field (minimal encoding).
fn len_field(number: u64, payload: Vec<u8>) -> ProtoField {
    let mut raw = Vec::new();
    write_varint((number << 3) | WIRE_LEN, &mut raw);
    write_varint(payload.len() as u64, &mut raw);
    raw.extend_from_slice(&payload);
    ProtoField {
        number,
        wire_type: WIRE_LEN,
        raw,
        value: FieldValue::Bytes(payload),
    }
}

/// A freshly-built varint field (minimal encoding).
fn varint_field(number: u64, v: u64) -> ProtoField {
    let mut raw = Vec::new();
    write_varint((number << 3) | WIRE_VARINT, &mut raw);
    write_varint(v, &mut raw);
    ProtoField {
        number,
        wire_type: WIRE_VARINT,
        raw,
        value: FieldValue::Varint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(seed: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed([seed; 32])
    }

    fn name_of(s: &Ed25519Signer) -> IpnsName {
        IpnsName::from_public_key(&s.verifying_key())
    }

    #[test]
    fn create_verify_round_trip_extracts_fields() {
        let s = signer(3);
        let rec = IpnsRecord::create_v2(
            &s,
            b"/ipfs/bafyfixture",
            1,
            3_600_000_000_000,
            "2026-10-18T00:00:00.000000000Z",
        );
        let verified = rec.verify(&name_of(&s)).expect("valid record verifies");
        assert_eq!(verified.value, b"/ipfs/bafyfixture");
        assert_eq!(verified.sequence, 1, "first publish embeds sequence 1");
        assert_eq!(verified.ttl, 3_600_000_000_000);
        assert_eq!(verified.validity, b"2026-10-18T00:00:00.000000000Z");
    }

    #[test]
    fn marshal_unmarshal_is_byte_stable() {
        let s = signer(4);
        let rec = IpnsRecord::create_v2(
            &s,
            b"/ipfs/bafy2",
            7,
            60_000_000_000,
            "2026-01-01T00:00:00Z",
        );
        let bytes = rec.marshal();
        let reparsed = IpnsRecord::unmarshal(&bytes).expect("unmarshal");
        assert_eq!(reparsed.marshal(), bytes, "keyless re-PUT is byte-stable");
        assert_eq!(reparsed.verify(&name_of(&s)).unwrap().sequence, 7);
    }

    #[test]
    fn foreign_unknown_fields_preserved_on_re_put() {
        // Append a signatureV1 (field 2) and a pubKey (field 7) — fields this
        // codec does not model — to a valid record, in ascending order.
        let s = signer(5);
        let rec = IpnsRecord::create_v2(&s, b"/ipfs/x", 2, 1, "2026-01-01T00:00:00Z");
        // Rebuild the wire with extra fields interleaved by ascending number.
        let mut foreign = Vec::new();
        for f in &rec.fields {
            if f.number == FIELD_VALIDITY_TYPE {
                // field 2 signatureV1 goes before field 3.
                foreign.extend_from_slice(&len_field(2, b"legacy-sig".to_vec()).raw);
            }
            if f.number == FIELD_SIGNATURE_V2 {
                // field 7 pubKey goes before field 8.
                foreign.extend_from_slice(&len_field(7, b"pubkey-bytes".to_vec()).raw);
            }
            foreign.extend_from_slice(&f.raw);
        }
        let parsed = IpnsRecord::unmarshal(&foreign).expect("foreign record unmarshals");
        assert_eq!(parsed.marshal(), foreign, "unknown fields survive re-PUT");
        // And verify still works: signatureV2 covers only data.
        assert!(parsed.verify(&name_of(&s)).is_ok());
    }

    #[test]
    fn tampered_data_fails_signature() {
        let s = signer(6);
        let rec = IpnsRecord::create_v2(&s, b"/ipfs/y", 1, 1, "2026-01-01T00:00:00Z");
        let mut bytes = rec.marshal();
        // Flip the last byte (inside the data field) — signatureV2 breaks.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let parsed = IpnsRecord::unmarshal(&bytes).expect("still parses");
        assert_eq!(
            parsed.verify(&name_of(&s)).unwrap_err().check(),
            "ipns-signature-invalid"
        );
    }

    #[test]
    fn wrong_name_fails_signature() {
        let s = signer(7);
        let rec = IpnsRecord::create_v2(&s, b"/ipfs/z", 1, 1, "2026-01-01T00:00:00Z");
        let other = name_of(&signer(8));
        assert_eq!(
            rec.verify(&other).unwrap_err().check(),
            "ipns-signature-invalid"
        );
    }

    #[test]
    fn value_mismatch_between_data_and_top_level() {
        let s = signer(9);
        let rec = IpnsRecord::create_v2(&s, b"/ipfs/aaa", 1, 1, "2026-01-01T00:00:00Z");
        // Replace the top-level value field (1) with a different path; data
        // (hence signatureV2) is unchanged, so the consistency check fires.
        let mut fields = rec.fields.clone();
        fields[0] = len_field(FIELD_VALUE, b"/ipfs/bbb".to_vec());
        let tampered = IpnsRecord { fields };
        assert_eq!(
            tampered.verify(&name_of(&s)).unwrap_err().check(),
            "ipns-value-mismatch"
        );
    }

    #[test]
    fn missing_signature_is_record_malformed() {
        let s = signer(10);
        let rec = IpnsRecord::create_v2(&s, b"/ipfs/c", 1, 1, "2026-01-01T00:00:00Z");
        let fields: Vec<_> = rec
            .fields
            .iter()
            .filter(|f| f.number != FIELD_SIGNATURE_V2)
            .cloned()
            .collect();
        let no_sig = IpnsRecord { fields };
        assert_eq!(
            no_sig.verify(&name_of(&s)).unwrap_err().check(),
            "ipns-record-malformed"
        );
    }

    #[test]
    fn garbage_bytes_are_record_malformed() {
        // A truncated varint tag: unmarshal fails closed.
        assert_eq!(
            IpnsRecord::unmarshal(&[0xff]).unwrap_err().check(),
            "ipns-record-malformed"
        );
    }

    #[test]
    fn varint_round_trips() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(v, &mut buf);
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos), Some(v));
            assert_eq!(pos, buf.len());
        }
    }
}
