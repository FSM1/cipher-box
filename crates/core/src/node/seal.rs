//! AAD-bound Node seal/unseal — Rust twin of `packages/core/src/node/seal.ts`.
//!
//! Composes the already-shipped Phase-61 AES-256-GCM AAD primitive
//! (`seal_aes_gcm_aad`, `unseal_aes_gcm_aad`, `build_node_aad`) from
//! `cipherbox_crypto::aes`. NEVER reimplements AEAD, and NEVER uses ECIES —
//! ECIES remains reserved for the vault-blob root wrap only (NODE-06,
//! SC#1). This is the symmetric-unwrap primitive that replaces the FUSE
//! ECIES fan-out in the 69-09 read-path swap.
//!
//! Role byte table (frozen, D-00 / ADR 0003):
//!   0x01 body           — read-body sealed under its own readKey
//!   0x02 child-readkey   — child readKey sealed under parent readKey
//!   0x04 child-writekey  — child writeKey sealed under parent writeKey
//!   (0x03 content is out of scope for this plan — sealed under a file
//!   node's own readKey by a later Phase-69 plan.)
//!
//! Kind byte table: 0x01 folder / 0x02 file / 0x03 root.
//!
//! Terminal-owner rule (D-09): none of these functions zero caller-supplied
//! or returned key/body buffers — the caller owns that lifecycle.

use base64::Engine as _;
use cipherbox_crypto::aes::{build_node_aad, seal_aes_gcm_aad, unseal_aes_gcm_aad};

use super::encode::{encode_node, encode_write_body};
use super::types::{Node, NodeError, NodeKind, NodeWriteBody, PublishedNode};

/// Role byte: whole read-body/write-body sealed under its own key.
const ROLE_BODY: u8 = 0x01;
/// Role byte: child readKey sealed under the parent readKey.
const ROLE_CHILD_READKEY: u8 = 0x02;
/// Role byte: child writeKey sealed under the parent writeKey (D-07 prep).
const ROLE_CHILD_WRITEKEY: u8 = 0x04;

/// Maps a `NodeKind` to its frozen AAD kind byte (mirrors TS `kindByte`).
fn kind_byte(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Folder => 0x01,
        NodeKind::File => 0x02,
        NodeKind::Root => 0x03,
    }
}

/// Seals a node's plaintext read-body under its own `read_key` (role 0x01).
///
/// `read_body` is the output of `encode_node` (or an equivalent plaintext
/// wire encoding) — this function performs no JSON encoding of its own.
pub fn seal_node(
    read_body: &[u8],
    read_key: &[u8; 32],
    node_id: &str,
    kind: NodeKind,
    generation: u32,
) -> Result<Vec<u8>, NodeError> {
    let aad = build_node_aad(node_id, kind_byte(kind), generation, ROLE_BODY)?;
    let sealed = seal_aes_gcm_aad(read_body, read_key, &aad)?;
    Ok(sealed)
}

/// Unseals a node's read-body sealed by `seal_node`.
///
/// Rebuilds the AAD identically; any mismatch (wrong id/kind/generation, or
/// a tampered/replayed blob) fails the GCM auth-tag check and returns `Err`.
pub fn unseal_node(
    sealed: &[u8],
    read_key: &[u8; 32],
    node_id: &str,
    kind: NodeKind,
    generation: u32,
) -> Result<Vec<u8>, NodeError> {
    let aad = build_node_aad(node_id, kind_byte(kind), generation, ROLE_BODY)?;
    let body = unseal_aes_gcm_aad(sealed, read_key, &aad)?;
    Ok(body)
}

/// Seals a child node's readKey under the parent's readKey (role 0x02).
///
/// The AAD binds the child's id, kind, and generation so the sealed key can
/// only be unwrapped by a holder of the parent readKey presenting the
/// correct child metadata (T-69-04-01).
pub fn seal_child_read_key(
    child_read_key: &[u8; 32],
    parent_read_key: &[u8; 32],
    child_id: &str,
    child_kind: NodeKind,
    child_generation: u32,
) -> Result<Vec<u8>, NodeError> {
    let aad = build_node_aad(
        child_id,
        kind_byte(child_kind),
        child_generation,
        ROLE_CHILD_READKEY,
    )?;
    let sealed = seal_aes_gcm_aad(child_read_key, parent_read_key, &aad)?;
    Ok(sealed)
}

/// Unseals a child node's readKey sealed by `seal_child_read_key`.
///
/// This is the exact call the 69-09 FUSE read-path swap replaces each
/// ECIES key-unwrap call with (SC#1 symmetric-unwrap primitive).
pub fn unseal_child_read_key(
    sealed: &[u8],
    parent_read_key: &[u8; 32],
    child_id: &str,
    child_kind: NodeKind,
    child_generation: u32,
) -> Result<Vec<u8>, NodeError> {
    let aad = build_node_aad(
        child_id,
        kind_byte(child_kind),
        child_generation,
        ROLE_CHILD_READKEY,
    )?;
    let key = unseal_aes_gcm_aad(sealed, parent_read_key, &aad)?;
    Ok(key)
}

/// Seals a child node's writeKey under the parent's writeKey (role 0x04,
/// D-07 dual-keying prep — reserved for the wave-6 write-chain work).
pub fn seal_child_write_key(
    child_write_key: &[u8; 32],
    parent_write_key: &[u8; 32],
    child_id: &str,
    child_kind: NodeKind,
    child_generation: u32,
) -> Result<Vec<u8>, NodeError> {
    let aad = build_node_aad(
        child_id,
        kind_byte(child_kind),
        child_generation,
        ROLE_CHILD_WRITEKEY,
    )?;
    let sealed = seal_aes_gcm_aad(child_write_key, parent_write_key, &aad)?;
    Ok(sealed)
}

/// Unseals a child node's writeKey sealed by `seal_child_write_key`.
pub fn unseal_child_write_key(
    sealed: &[u8],
    parent_write_key: &[u8; 32],
    child_id: &str,
    child_kind: NodeKind,
    child_generation: u32,
) -> Result<Vec<u8>, NodeError> {
    let aad = build_node_aad(
        child_id,
        kind_byte(child_kind),
        child_generation,
        ROLE_CHILD_WRITEKEY,
    )?;
    let key = unseal_aes_gcm_aad(sealed, parent_write_key, &aad)?;
    Ok(key)
}

/// Seals a `Node` into its on-wire `PublishedNode` envelope, sealing BOTH the
/// read-body (under `read_key`, role 0x01) and, when `write_body` is `Some`,
/// the write-body (under `write_key`, role 0x01) — populating
/// `PublishedNode.write_sealed` (previously never populated, D-07/NODE-04).
///
/// `write_body` is an EXPLICIT parameter — the `Node` enum gains no field
/// (research Pattern 1 / Landmine 2): a field-add would force-recompile every
/// `Node::{Folder,File,Root}` construction and collapse the D-02 core/sdk
/// split; the read chain never needs `write_body`.
///
/// Twin of `packages/core/src/node/seal.ts::sealNode(node, readKey, writeKey)`.
/// Composes ONLY `cipherbox_crypto::aes::seal_aes_gcm_aad` + `build_node_aad`
/// (no ECIES — reserved for the TEE `ipnsPrivateKey` wrap, 69-16).
pub fn seal_published_node(
    node: &Node,
    read_key: &[u8; 32],
    write_key: &[u8; 32],
    write_body: Option<&NodeWriteBody>,
) -> Result<PublishedNode, NodeError> {
    let read_body = encode_node(node)?;
    let read_sealed_bytes = seal_node(
        &read_body,
        read_key,
        node.id(),
        node.kind(),
        node.generation(),
    )?;
    let read_sealed = base64::engine::general_purpose::STANDARD.encode(read_sealed_bytes);

    let write_sealed = match write_body {
        Some(wb) => {
            let wb_bytes = encode_write_body(wb)?;
            let aad = build_node_aad(
                node.id(),
                kind_byte(node.kind()),
                node.generation(),
                ROLE_BODY,
            )?;
            let sealed = seal_aes_gcm_aad(&wb_bytes, write_key, &aad)?;
            Some(base64::engine::general_purpose::STANDARD.encode(sealed))
        }
        None => None,
    };

    Ok(PublishedNode {
        schema: "node/v3".to_string(),
        kind: node.kind().as_str().to_string(),
        id: node.id().to_string(),
        generation: node.generation(),
        aead_version: 1,
        read_sealed,
        write_sealed,
    })
}

#[cfg(test)]
mod seal_published_node_tests {
    use super::*;
    use crate::node::decode::decode_write_body;
    use crate::node::types::WriteChildRef;

    fn sample_node() -> Node {
        Node::Folder {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            generation: 0,
            created_at: 1719532800000,
            modified_at: 1719532800000,
            children: vec![],
        }
    }

    fn sample_write_body() -> NodeWriteBody {
        NodeWriteBody {
            ipns_private_key: vec![0x44u8; 32],
            write_children: vec![WriteChildRef {
                child_id: "660e8400-e29b-41d4-a716-446655440001".to_string(),
                write_key_sealed: "c2VhbGVkLXdyaXRlLWtleQ==".to_string(),
            }],
            recipient_pins: vec![],
        }
    }

    #[test]
    fn both_bodies_populated_when_write_body_some() {
        let node = sample_node();
        let read_key = [0x01u8; 32];
        let write_key = [0x02u8; 32];
        let wb = sample_write_body();

        let published = seal_published_node(&node, &read_key, &write_key, Some(&wb))
            .expect("seal_published_node ok");

        assert!(!published.read_sealed.is_empty());
        assert!(published.write_sealed.is_some());
        assert_eq!(published.schema, "node/v3");
        assert_eq!(published.kind, "folder");
        assert_eq!(published.id, node.id());
        assert_eq!(published.generation, node.generation());
        assert_eq!(published.aead_version, 1);
    }

    #[test]
    fn write_sealed_none_when_write_body_none() {
        let node = sample_node();
        let read_key = [0x01u8; 32];
        let write_key = [0x02u8; 32];

        let published = seal_published_node(&node, &read_key, &write_key, None)
            .expect("seal_published_node ok");

        assert!(published.write_sealed.is_none());
    }

    #[test]
    fn write_body_is_recoverable_via_unseal_and_decode() {
        let node = sample_node();
        let read_key = [0x01u8; 32];
        let write_key = [0x02u8; 32];
        let wb = sample_write_body();

        let published = seal_published_node(&node, &read_key, &write_key, Some(&wb))
            .expect("seal_published_node ok");

        let write_sealed_b64 = published.write_sealed.expect("write_sealed present");
        let write_sealed_bytes = base64::engine::general_purpose::STANDARD
            .decode(write_sealed_b64)
            .expect("valid base64");

        let wb_bytes = unseal_node(
            &write_sealed_bytes,
            &write_key,
            node.id(),
            node.kind(),
            node.generation(),
        )
        .expect("unseal_node with write_key ok");
        let recovered = decode_write_body(&wb_bytes).expect("decode_write_body ok");
        assert_eq!(recovered, wb);
    }

    #[test]
    fn aad_transplant_read_key_cannot_open_write_sealed() {
        let node = sample_node();
        let read_key = [0x01u8; 32];
        let write_key = [0x02u8; 32];
        let wb = sample_write_body();

        let published = seal_published_node(&node, &read_key, &write_key, Some(&wb))
            .expect("seal_published_node ok");

        let write_sealed_b64 = published.write_sealed.expect("write_sealed present");
        let write_sealed_bytes = base64::engine::general_purpose::STANDARD
            .decode(write_sealed_b64)
            .expect("valid base64");

        let result = unseal_node(
            &write_sealed_bytes,
            &read_key,
            node.id(),
            node.kind(),
            node.generation(),
        );
        assert!(
            result.is_err(),
            "unsealing the write-body with the READ key must fail (GCM auth-tag mismatch)"
        );
    }
}
