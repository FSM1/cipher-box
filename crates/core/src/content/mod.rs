//! The content-plane cryptographic edge (blueprint/core.md "Open edges").
//!
//! Two core-owned pieces, and nothing more — chunk framing, DAG assembly shape,
//! and version-retention policy stay engine-owned: the content-seal over
//! caller-framed chunks ([`seal`]), and the content-DAG CID with its fail-closed
//! verify and base32 string codec ([`cid`]).

pub mod cid;
pub mod seal;

pub use cid::{
    CONTENT_CID_CODEC, CONTENT_CID_LEN, CONTENT_CID_MULTIHASH, compute_cid, decode_content_cid_str,
    encode_content_cid_str, is_wellformed_content_cid, verify_cid,
};
pub use seal::{open_chunk, seal_chunk};
