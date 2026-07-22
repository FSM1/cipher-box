//! The sync core — the state law, the durable op queue, FIFO rebase, budgeted
//! offline staging, the focus-window tick, the staleness ladder, and the
//! pointer planes (blueprint/engine.md "Sync core", "Pointer planes";
//! CONTEXT.md).
//!
//! One model, single owner: rendered state = last-known-good gate-passing
//! snapshot ⊕ pending-op overlay, and the op queue is the only local
//! divergence (#33 D6). Every mutation rides the durable op queue as an intent
//! op carrying its base sequence; offline replay and online CAS rebase re-apply
//! ops through the **same** path — FIFO, onto gate-passing state only, through
//! the five per-op race rules — and a terminally unrebasable op dead-letters
//! with its staged bytes preserved rather than being silently dropped.
//!
//! Submodules:
//!
//! - [`model`] — the working tree (the state law's left operand) and the one
//!   strict name comparator.
//! - [`op`] — the intent-op model and its durable-queue codec.
//! - [`overlay`] — the state law: snapshot ⊕ pending ops → rendered view.
//! - [`rebase`] — FIFO replay, the five race rules, dead-lettering, and
//!   dual-link observed repair.
//! - [`staging`] — the budgeted offline staging policy over `StagingStore`.
//! - [`staleness`] — the staleness ladder and the withheld-update escalation.
//! - [`pointer`] — the scope/vault pointer planes, the re-point object, the
//!   consult discipline, and the cold-start floor cold-seed.
//! - [`tick`] — the jittered focus-window tick, immediate hint ticks, and
//!   on-access refresh.
//!
//! Out of this slice, by design (CONTEXT.md #632): scope-exit rotation
//! *triggering* — a cross-scope relink out of a granted scope **queues** the
//! trigger event ([`rebase::ReplayReport::scope_exit_triggers`]); the rotation
//! primitives themselves land with the rotation slice.

pub mod boot;
pub mod model;
pub mod op;
pub mod overlay;
pub mod pointer;
pub mod rebase;
pub mod staging;
pub mod staleness;
pub mod tick;

pub use boot::{ColdStartError, ColdStartOutcome, ColdStartParams, RootResolve, cold_start};
pub use model::{Link, NodeMeta, Snapshot, collation_key, suffix_name};
pub use op::{Op, OpDecodeError, OpKind};
pub use overlay::apply_overlay;
pub use pointer::{
    ConsultReason, PointerError, PointerFetch, SessionRole, VaultPointerAdoption, cold_seed_floors,
    open_repoint, resolve_vault_pointer, scope_pointer_name, scope_pointer_signer, seal_repoint,
    should_consult, vault_pointer_name,
};
pub use rebase::{
    AppliedOp, DeadLetterReason, DropReason, HeadReconciliation, OpResolution, Repair,
    ReplayReport, apply_repairs, decode_queue, observed_repair, rebase_one, reconcile_head, replay,
};
pub use staging::{StageOutcome, orphan_staging_keys, stage_op};
pub use staleness::{Connectivity, classify, withheld_escalation};
pub use tick::{
    FocusTarget, FocusWindow, ResolveMode, TickCause, TickControl, focus_set, jittered_cadence,
    on_access_refresh_due, resolve_mode, run_tick_loop,
};

/// Whole milliseconds of `duration`, truncating and saturating — the engine's
/// clock is the millisecond [`UnixMillis`](crate::seams::UnixMillis), so every
/// timing threshold compares in the same unit.
pub(crate) fn duration_millis(duration: core::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
