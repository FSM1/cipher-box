//! Node read-body / published-envelope JSON encoder.
//!
//! Encodes an in-memory `Node` to plaintext body bytes (no AEAD) with a
//! FIXED field order so the output is byte-identical to the frozen
//! cross-language KAT (`tests/vectors/node-codec.json`, D-04).
//!
//! Analog: `packages/core/src/node/encode.ts::encodeReadBody`.
//!
//! Does NOT apply AEAD — a later Phase-69 plan wires the AEAD seal step
//! (`sealNode`'s Rust twin). Does NOT zero any buffer — caller is the
//! terminal owner of key material (D-09).

use serde::Serialize;

use super::types::{Node, NodeContent, NodeError, NodeWriteBody, PublishedNode, SealedChildRef};

/// Wire representation shared by `folder` and `root` kinds — both carry a
/// `children` array and differ only in the `kind` discriminator string.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FolderRootWire<'a> {
    schema: &'a str,
    kind: &'a str,
    id: &'a str,
    generation: u32,
    children: &'a Vec<SealedChildRef>,
    created_at: u64,
    modified_at: u64,
}

/// Wire representation for the `file` kind.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileWire<'a> {
    schema: &'a str,
    kind: &'a str,
    id: &'a str,
    generation: u32,
    content: &'a NodeContent,
    created_at: u64,
    modified_at: u64,
}

/// Encodes a Node's read-body to canonical JSON bytes (UTF-8).
///
/// Field order is FIXED (`schema`, `kind`, `id`, `generation`, kind-specific
/// `children`/`content`, `createdAt`, `modifiedAt`) so the encoded bytes are
/// deterministic and byte-identical to the frozen KAT (D-04).
pub fn encode_node(node: &Node) -> Result<Vec<u8>, NodeError> {
    let json = match node {
        Node::Folder {
            id,
            generation,
            created_at,
            modified_at,
            children,
        } => serde_json::to_string(&FolderRootWire {
            schema: "node/v3",
            kind: "folder",
            id,
            generation: *generation,
            children,
            created_at: *created_at,
            modified_at: *modified_at,
        }),
        Node::Root {
            id,
            generation,
            created_at,
            modified_at,
            children,
        } => serde_json::to_string(&FolderRootWire {
            schema: "node/v3",
            kind: "root",
            id,
            generation: *generation,
            children,
            created_at: *created_at,
            modified_at: *modified_at,
        }),
        Node::File {
            id,
            generation,
            created_at,
            modified_at,
            content,
        } => serde_json::to_string(&FileWire {
            schema: "node/v3",
            kind: "file",
            id,
            generation: *generation,
            content,
            created_at: *created_at,
            modified_at: *modified_at,
        }),
    }
    .map_err(|_| NodeError::SerializationFailed)?;

    Ok(json.into_bytes())
}

/// Encodes a `PublishedNode` envelope to JSON bytes.
///
/// This plan treats `readSealed`/`writeSealed` as opaque already-sealed
/// base64 strings supplied by the caller — no AEAD sealing happens here.
pub fn encode_published_node(node: &PublishedNode) -> Result<Vec<u8>, NodeError> {
    serde_json::to_vec(node).map_err(|_| NodeError::SerializationFailed)
}

/// Encodes a `NodeWriteBody` to canonical plaintext JSON bytes (no AEAD).
///
/// FIXED field order (`ipnsPrivateKey` then `writeChildren`) so the output is
/// deterministic and, once sealed under the writeKey, byte-identical to the
/// frozen cross-language KAT (`tests/vectors/node-codec.json`
/// `seal_vectors[0].expected_published_node.writeSealed`, D-07/P1a-core).
///
/// `NodeWriteBody` already derives serde camelCase + base64 for
/// `ipns_private_key`, so a direct `serde_json::to_vec` yields the twin of
/// TS `encodeWriteBody`. Twin of `packages/core/src/node/encode.ts::encodeWriteBody`.
///
/// Never logs `wb` (it carries `ipns_private_key`, T-69-15-01).
pub fn encode_write_body(wb: &NodeWriteBody) -> Result<Vec<u8>, NodeError> {
    serde_json::to_vec(wb).map_err(|_| NodeError::SerializationFailed)
}

#[cfg(test)]
mod write_body_tests {
    use super::*;
    use crate::node::decode::decode_write_body;
    use crate::node::types::WriteChildRef;

    #[test]
    fn write_body_round_trip_populated() {
        let wb = NodeWriteBody {
            ipns_private_key: vec![0x44u8; 32],
            write_children: vec![WriteChildRef {
                child_id: "660e8400-e29b-41d4-a716-446655440001".to_string(),
                write_key_sealed: "c2VhbGVkLXdyaXRlLWtleQ==".to_string(),
            }],
            recipient_pins: vec![],
        };

        let encoded = encode_write_body(&wb).expect("encode ok");
        let decoded = decode_write_body(&encoded).expect("decode ok");
        assert_eq!(decoded, wb);
    }

    #[test]
    fn write_body_round_trip_empty_children() {
        let wb = NodeWriteBody {
            ipns_private_key: vec![0x11u8; 32],
            write_children: vec![],
            recipient_pins: vec![],
        };

        let encoded = encode_write_body(&wb).expect("encode ok");
        // FIXED field order: ipnsPrivateKey then writeChildren. An EMPTY
        // recipient_pins is omitted from the wire (skip_serializing_if), so the
        // encoded bytes are byte-identical to the pre-D-03b output — this is the
        // seal_vectors[0] preservation guarantee (D-03b, Pitfall 1).
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.starts_with(r#"{"ipnsPrivateKey":"#));
        assert!(text.ends_with(r#""writeChildren":[]}"#));
        assert!(!text.contains("recipientPins"));

        let decoded = decode_write_body(&encoded).expect("decode ok");
        assert_eq!(decoded, wb);
    }

    #[test]
    fn write_body_round_trip_with_recipient_pins() {
        // Two raw compressed secp256k1 pubkeys (33 bytes each).
        let mut pin1 = vec![0x02u8];
        pin1.extend_from_slice(&[0x11u8; 32]);
        let mut pin2 = vec![0x03u8];
        pin2.extend_from_slice(&[0x22u8; 32]);

        let wb = NodeWriteBody {
            ipns_private_key: vec![0x44u8; 32],
            write_children: vec![],
            recipient_pins: vec![pin1, pin2],
        };

        let encoded = encode_write_body(&wb).expect("encode ok");
        // FIXED field order: ipnsPrivateKey, writeChildren, then recipientPins
        // (matches the TS encodeWriteBody order for cross-language byte parity).
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains(r#""writeChildren":[],"recipientPins":["#));

        let decoded = decode_write_body(&encoded).expect("decode ok");
        assert_eq!(decoded, wb);
    }

    #[test]
    fn decode_write_body_defaults_missing_recipient_pins_to_empty() {
        // Old-format JSON with no recipientPins field must decode to an empty
        // list (serde default) and NEVER error (forward tolerance, D-03b).
        let old_format = br#"{"ipnsPrivateKey":"ERERERERERERERERERERERERERERERERERERERERERE=","writeChildren":[]}"#;
        let decoded = decode_write_body(old_format).expect("decode ok");
        assert!(decoded.recipient_pins.is_empty());
    }

    #[test]
    fn decode_write_body_malformed_bytes_fail_closed() {
        let result = decode_write_body(b"not json at all {{{");
        assert!(matches!(result, Err(NodeError::DeserializationFailed(_))));
    }
}
