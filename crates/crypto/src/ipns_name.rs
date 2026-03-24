//! IPNS name derivation (CIDv1 base36 from Ed25519 public key).
//!
//! This module extracts only the pure IPNS name derivation logic.
//! IPNS record creation/marshaling stays in the desktop app (or cipherbox-core)
//! because it involves domain-specific types and CBOR/protobuf encoding.

use crate::error::CryptoError;

/// Encode the Ed25519 public key in libp2p PublicKey protobuf format.
///
/// message PublicKey { KeyType Type = 1; bytes Data = 2; }
/// where KeyType.Ed25519 = 1
pub fn encode_libp2p_public_key(ed25519_public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ed25519_public_key.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }
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
    Ok(buf)
}

/// Derive the IPNS name (CIDv1 base36) from an Ed25519 public key.
///
/// Steps:
/// 1. Wrap public key in libp2p PublicKey protobuf
/// 2. Create identity multihash: 0x00 (identity) + varint(len) + data
/// 3. Create CIDv1: version=1, codec=0x72 (libp2p-key), multihash
/// 4. Encode as base36 (k... prefix)
pub fn derive_ipns_name(ed25519_public_key: &[u8; 32]) -> Result<String, CryptoError> {
    // Step 1: Wrap in libp2p PublicKey protobuf
    let libp2p_pub_key = encode_libp2p_public_key(ed25519_public_key)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_ipns_name_starts_with_k() {
        let pk = [0xAB; 32];
        let name = derive_ipns_name(&pk).unwrap();
        assert!(name.starts_with('k'));
    }

    #[test]
    fn same_key_produces_same_name() {
        let pk = [0x42; 32];
        let name1 = derive_ipns_name(&pk).unwrap();
        let name2 = derive_ipns_name(&pk).unwrap();
        assert_eq!(name1, name2);
    }

    #[test]
    fn different_keys_produce_different_names() {
        let pk1 = [0x01; 32];
        let pk2 = [0x02; 32];
        let name1 = derive_ipns_name(&pk1).unwrap();
        let name2 = derive_ipns_name(&pk2).unwrap();
        assert_ne!(name1, name2);
    }

    #[test]
    fn encode_unsigned_varint_zero() {
        let mut buf = Vec::new();
        encode_unsigned_varint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn encode_unsigned_varint_one() {
        let mut buf = Vec::new();
        encode_unsigned_varint(&mut buf, 1);
        assert_eq!(buf, vec![0x01]);
    }

    #[test]
    fn encode_unsigned_varint_127() {
        let mut buf = Vec::new();
        encode_unsigned_varint(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);
    }

    #[test]
    fn encode_unsigned_varint_128() {
        let mut buf = Vec::new();
        encode_unsigned_varint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);
    }

    #[test]
    fn encode_unsigned_varint_255() {
        let mut buf = Vec::new();
        encode_unsigned_varint(&mut buf, 255);
        assert_eq!(buf, vec![0xFF, 0x01]);
    }

    #[test]
    fn encode_unsigned_varint_300() {
        let mut buf = Vec::new();
        encode_unsigned_varint(&mut buf, 300);
        // 300 = 0b100101100 => low 7: 0101100 = 0x2C | 0x80 = 0xAC, high: 0b10 = 0x02
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn encode_unsigned_varint_16384() {
        let mut buf = Vec::new();
        encode_unsigned_varint(&mut buf, 16384);
        // 16384 = 0x4000 => 3 varint bytes
        assert_eq!(buf, vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn encode_base36_empty() {
        assert_eq!(encode_base36(&[]), "");
    }

    #[test]
    fn encode_base36_single_byte() {
        // 0x01 = 1 in base36 = "1"
        assert_eq!(encode_base36(&[0x01]), "1");
    }

    #[test]
    fn encode_base36_leading_zeros() {
        let result = encode_base36(&[0x00, 0x00, 0x01]);
        assert!(result.starts_with("00"));
    }

    #[test]
    fn encode_libp2p_public_key_format() {
        let pk = [0xAA; 32];
        let encoded = encode_libp2p_public_key(&pk).unwrap();
        assert_eq!(encoded[0], 0x08); // field 1 tag
        assert_eq!(encoded[1], 0x01); // Ed25519 type
        assert_eq!(encoded[2], 0x12); // field 2 tag
        assert_eq!(encoded[3], 32);   // length
        assert_eq!(&encoded[4..], &pk);
        assert_eq!(encoded.len(), 4 + 32);
    }
}
