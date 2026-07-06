//! Unified Node model (`node/v3`) — Rust twin of `packages/core/src/node/*.ts`.
//!
//! This module is ADDITIVE alongside the legacy `crate::folder` types; the
//! clean D-04 cutover + call-site migration lands in the 69-10 plan.

mod decode;
mod encode;
pub mod seal;
mod types;

pub use decode::{decode_node, decode_published_node, decode_write_body};
pub use encode::{encode_node, encode_published_node, encode_write_body};
pub use types::{
    Node, NodeContent, NodeError, NodeKind, NodeWriteBody, PublishedNode, SealedChildRef,
    VersionEntry, WriteChildRef,
};
