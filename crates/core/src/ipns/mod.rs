//! IPNS records and the name codec (blueprint/core.md "Module map: ipns",
//! "IPNS records").
//!
//! Core owns records end-to-end on both platforms (#28 D2); transports are dumb
//! byte movers injected by the engine. Three pure pieces: [`IpnsName`] (the
//! `ipnsName` codec, and the verify chain's sole trust anchor), [`IpnsRecord`]
//! (create/sign, byte-stable keyless marshal/unmarshal for re-PUT, the pure
//! verify chain), and [`VerifiedRecord`] (the authenticated fields the adoption
//! gate compares).

pub mod name;
pub mod record;

pub use name::{IpnsName, MAX_IPNS_NAME_BYTES};
pub use record::{DEFAULT_VALIDITY_DAYS, IpnsRecord, VerifiedRecord};
