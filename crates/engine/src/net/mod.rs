//! The net plane: the gated resolve/publish pipeline, CAS, endpoint fan-out,
//! and the liveness jobs (blueprint/engine.md "Resolve/publish pipeline").
//!
//! The engine owns IPNS end-to-end over dumb `/routing/v1` transports (#28 D2):
//! core signs and verifies, the [`RecordTransport`](crate::seams::RecordTransport)
//! seam only moves bytes, and every decision — cache-first rendering, which
//! endpoint's copy is freshest, register-first ordering, CAS sequencing,
//! confirm-by-re-resolve, when to re-PUT or renew or revive — lives here.
//!
//! The adoption gate runs on **every** resolve through the [`resolve::Adopter`]
//! seam; only a gate-passing record touches the snapshot. A lost CAS race is
//! reported, not rebased — it surfaces as
//! [`publish::PublishOutcome::LostRace`] for [`crate::sync::rebase`].

mod adopter;
mod child;
mod fanout;
mod pointer_fetch;

pub mod author;
pub mod eol;
pub mod liveness;
pub mod publish;
pub mod record_publish;
pub mod resolve;
pub mod retire;
pub mod revival;

pub use adopter::{LocalHead, RootAdopter};
pub(crate) use adopter::{assemble_head_envelope, fetch_head_block};
pub use child::ChildAdopter;
pub(crate) use fanout::fanout_get_verify;
pub(crate) use liveness::eol_renew_pass;
pub use liveness::{
    EolRenewResult, HeldRecord, HeldRecords, LivenessControl, RE_PUT_INTERVAL, RePutResult,
    eol_republish, keyless_re_put, run_liveness_loop,
};
pub use pointer_fetch::RecordPointerFetch;
pub use publish::{PublishError, PublishOutcome, PublishReceipt, PublishRequest, publish};
pub use record_publish::{PreflightError, RecordPublishError};
pub use resolve::{AdoptOutcome, Adopter, OwnScopeMaterial, ResolveOutcome, Resolved, resolve};
pub(crate) use resolve::{
    GatedResolve, HeldMaterial, refresh_base_from_outcome, resolve_and_hold, resolve_gated,
};
pub use retire::{retire, root_retire_ready};
pub use revival::{ReviveError, ReviveRequest, revive};
