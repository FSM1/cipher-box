//! The content-plane cryptographic edge (blueprint/core.md "Open edges":
//! "core ships the content-seal primitive over caller-framed chunks").
//!
//! Two core-owned pieces, and nothing more — chunk framing, DAG assembly shape,
//! and version-retention policy stay engine-owned (#630):
//!
//! - **content-seal** ([`seal::seal_chunk`]/[`seal::open_chunk`]):
//!   XChaCha20-Poly1305 over caller-framed chunk bytes under a caller-supplied
//!   per-version content key, reusing the frozen suite AEAD
//!   ([`crate::suite::aead`]). The content key is caller-owned — the seal never
//!   zeroizes it.
//! - **content-DAG CID** ([`cid::compute_cid`]/[`cid::verify_cid`]): the
//!   deterministic CIDv1 content address over the sealed bytes and a fail-closed
//!   verify. One implementation, one KAT set, byte-identical native + wasm32. The
//!   string codec ([`cid::encode_content_cid_str`]/[`cid::decode_content_cid_str`])
//!   renders that CID as its base32-lowercase multibase `b…` form and strictly
//!   recovers the binary anchor from a scope's `/ipfs/<head_cid>` record value.

pub mod cid;
pub mod seal;

pub use cid::{
    CONTENT_CID_CODEC, CONTENT_CID_LEN, CONTENT_CID_MULTIHASH, compute_cid, decode_content_cid_str,
    encode_content_cid_str, is_wellformed_content_cid, verify_cid,
};
pub use seal::{open_chunk, seal_chunk};
