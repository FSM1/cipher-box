//! The net plane: the gated resolve/publish pipeline, CAS, endpoint fan-out,
//! and the liveness jobs (blueprint/engine.md "Resolve/publish pipeline").
//!
//! The engine owns IPNS end-to-end over dumb `/routing/v1` transports (#28 D2):
//! core signs and verifies, the [`RecordTransport`](crate::seams::RecordTransport)
//! seam only moves bytes, and every decision — cache-first rendering, which
//! endpoint's copy is freshest, register-first ordering, CAS sequencing,
//! confirm-by-re-resolve, when to re-PUT or renew or revive — lives here.
//!
//! - [`resolve`] — cache-first resolve: last-known-good renders immediately, a
//!   fan-out GET + core verify picks the freshest record, and the adoption gate
//!   runs on **every** resolve (through the [`resolve::Adopter`] seam); only a
//!   gate-passing record touches the snapshot.
//! - [`publish`] — register-first, fail-closed publish: core-signed with the
//!   exact CAS sequence, parallel PUT with any-ack success + background retry,
//!   and confirm-by-re-resolve with lost-race detection.
//! - [`liveness`] — the ~hourly keyless re-PUT job and the sub-EOL seq+1
//!   renewal.
//! - [`revival`] — re-mint after a >EOL lapse via the recovery endpoint.
//! - [`retire`] — registry-row retirement (root linger stubbed on the open-edge
//!   migration-window constant).
//! - [`eol`] — the 90-day EOL policy and RFC3339 codec, off the injected clock.
//!
//! What this slice deliberately does not land: rebase (a lost race is reported,
//! not rebased) and the pointer planes (the re-point channels). The seams for
//! both are left where the blueprint expects them — [`resolve::Adopter`] fronts
//! the content/pointer/key assembly, and a lost race surfaces as
//! [`publish::PublishOutcome::LostRace`] for the rebase slice.

mod fanout;

pub mod eol;
pub mod liveness;
pub mod publish;
pub mod resolve;
pub mod retire;
pub mod revival;

pub use liveness::{HeldRecord, RE_PUT_INTERVAL, RePutResult, eol_republish, keyless_re_put};
pub use publish::{PublishError, PublishOutcome, PublishRequest, publish};
pub use resolve::{Adopter, ResolveOutcome, Resolved, resolve};
pub use retire::{retire, root_retire_ready};
pub use revival::{ReviveError, ReviveRequest, revive};
