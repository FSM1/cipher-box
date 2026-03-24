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
pub fn encode_libp2p_public_key(ed25519_public_key: &[u8]) -> Vec<u8> {
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

/// Derive the IPNS name (CIDv1 base36) from an Ed25519 public key.
///
/// Steps:
/// 1. Wrap public key in libp2p PublicKey protobuf
/// 2. Create identity multihash: 0x00 (identity) + varint(len) + data
/// 3. Create CIDv1: version=1, codec=0x72 (libp2p-key), multihash
/// 4. Encode as base36 (k... prefix)
pub fn derive_ipns_name(ed25519_public_key: &[u8; 32]) -> Result<String, CryptoError> {
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
