//! Node read-body / published-envelope JSON decoder.
//!
//! Decodes plaintext body bytes back to an in-memory `Node`. Fail-closed:
//! returns `NodeError` (never panics) on malformed or unknown-schema input
//! (T-69-01-01).
//!
//! Analog: `packages/core/src/node/decode.ts::decodeReadBody`/`validateNode`.
//!
//! Does NOT apply AEAD — a later Phase-69 plan wires the AEAD unseal step
//! (`unsealNode`'s Rust twin). Does NOT zero any caller-supplied buffer —
//! caller is the terminal owner (D-09). Does NOT log key material (T-62-03).

use serde::Deserialize;

use super::types::{Node, NodeContent, NodeError, NodeWriteBody, PublishedNode, SealedChildRef};

/// Wire representation shared by `folder` and `root` kinds.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FolderRootWireOwned {
    schema: String,
    kind: String,
    id: String,
    generation: u32,
    children: Vec<SealedChildRef>,
    created_at: u64,
    modified_at: u64,
}

/// Wire representation for the `file` kind.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileWireOwned {
    schema: String,
    #[allow(dead_code)]
    kind: String,
    id: String,
    generation: u32,
    content: NodeContent,
    created_at: u64,
    modified_at: u64,
}

/// Minimal peek used only to route to the correct wire struct by `kind`.
#[derive(Deserialize)]
struct KindPeek {
    kind: String,
}

/// Decodes a Node's read-body from plaintext wire bytes.
///
/// Mirrors `decodeReadBody`/`validateNode`: fails closed with `NodeError` on
/// any structural or schema-mismatch failure — never panics on untrusted
/// input crossing the IPFS-stored-node-JSON → Rust trust boundary (T-69-01-01).
pub fn decode_node(bytes: &[u8]) -> Result<Node, NodeError> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| NodeError::DeserializationFailed(e.to_string()))?;

    let peek: KindPeek = serde_json::from_str(text)
        .map_err(|e| NodeError::DeserializationFailed(e.to_string()))?;

    match peek.kind.as_str() {
        "file" => {
            let wire: FileWireOwned = serde_json::from_str(text)
                .map_err(|e| NodeError::DeserializationFailed(e.to_string()))?;
            if wire.schema != "node/v3" {
                return Err(NodeError::InvalidFormat("unsupported schema".to_string()));
            }
            Ok(Node::File {
                id: wire.id,
                generation: wire.generation,
                created_at: wire.created_at,
                modified_at: wire.modified_at,
                content: wire.content,
            })
        }
        "folder" | "root" => {
            let wire: FolderRootWireOwned = serde_json::from_str(text)
                .map_err(|e| NodeError::DeserializationFailed(e.to_string()))?;
            if wire.schema != "node/v3" {
                return Err(NodeError::InvalidFormat("unsupported schema".to_string()));
            }
            if wire.kind == "folder" {
                Ok(Node::Folder {
                    id: wire.id,
                    generation: wire.generation,
                    created_at: wire.created_at,
                    modified_at: wire.modified_at,
                    children: wire.children,
                })
            } else {
                Ok(Node::Root {
                    id: wire.id,
                    generation: wire.generation,
                    created_at: wire.created_at,
                    modified_at: wire.modified_at,
                    children: wire.children,
                })
            }
        }
        other => Err(NodeError::InvalidFormat(format!("unknown kind: {other}"))),
    }
}

/// Decodes a `PublishedNode` envelope from JSON bytes.
///
/// This plan treats `readSealed`/`writeSealed` as opaque already-sealed
/// base64 strings — no AEAD unsealing happens here.
pub fn decode_published_node(bytes: &[u8]) -> Result<PublishedNode, NodeError> {
    serde_json::from_slice(bytes).map_err(|e| NodeError::DeserializationFailed(e.to_string()))
}

/// Decodes a `NodeWriteBody` from plaintext wire bytes (twin of TS
/// `decodeWriteBody`). Fail-closed: returns `NodeError` (never panics) on
/// malformed input — mirrors `decode_node`'s idiom (T-69-01-01).
pub fn decode_write_body(bytes: &[u8]) -> Result<NodeWriteBody, NodeError> {
    serde_json::from_slice(bytes).map_err(|e| NodeError::DeserializationFailed(e.to_string()))
}
