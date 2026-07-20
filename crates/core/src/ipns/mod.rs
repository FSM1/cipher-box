//! IPNS records and the name codec (blueprint/core.md "Module map: ipns",
//! "IPNS records").
//!
//! Core owns records end-to-end on both platforms (#28 D2); transports are dumb
//! byte movers injected by the engine. This module ships three pure pieces:
//!
//! - [`IpnsName`] — the `ipnsName` codec: encode + strict decode of the base36
//!   CIDv1 libp2p-key of an Ed25519 public key, and the extraction of that key
//!   from the name (the verify chain's sole trust anchor).
//! - [`IpnsRecord`] — spec-compliant V2 record create/sign, byte-stable keyless
//!   marshal/unmarshal for re-PUT, and the pure verify chain.
//! - [`VerifiedRecord`] — the authenticated fields the adoption gate compares.

pub mod name;
pub mod record;

pub use name::IpnsName;
pub use record::{DEFAULT_VALIDITY_DAYS, IpnsRecord, VerifiedRecord};
