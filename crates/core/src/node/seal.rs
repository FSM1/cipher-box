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

use cipherbox_crypto::aes::{build_node_aad, seal_aes_gcm_aad, unseal_aes_gcm_aad};

use super::types::{NodeError, NodeKind};

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
