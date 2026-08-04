//! The trust layer: the adoption gate and the durable floor law
//! (blueprint/engine.md "Adoption gate and floors").
//!
//! [`adopt`] is the six-stage pipeline every resolved record passes before
//! adoption — a pure composition of `crates/core`'s verify/unseal functions
//! over the engine's [`FloorStore`](crate::seams::FloorStore) floors. [`floor`]
//! is the floor law: the only place floors advance, and only the four ways the
//! law admits (AAD-confirmed unseal, re-point cold-seed, `writeEpoch` on sight,
//! all monotonic-max so regression is impossible).
//!
//! No crypto, no codec, and no cryptographic error code lives here: every
//! cryptographic verdict is a core [`CodecError`](cipherbox_core::error::CodecError)
//! surfaced verbatim; the only engine-domain verdicts are the two floor
//! comparisons.

pub mod floor;

mod adoption;

pub(crate) use adoption::authenticate_section_structures;
pub use adoption::{
    Adopted, Candidate, FLOOR_VERDICTS, GateError, GateRejection, GateStage, PendingAdoption,
    ReaderContext, RejectionReason, SeedBlob, adopt, adopt_deferred,
};
