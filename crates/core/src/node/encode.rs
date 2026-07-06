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

use super::types::{Node, NodeContent, NodeError, PublishedNode, SealedChildRef};

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
