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
//! Out of this slice, by design (CONTEXT.md #632): scope-exit rotation
//! *triggering* — a cross-scope relink out of a granted scope **queues** the
//! trigger event ([`rebase::ReplayReport::scope_exit_triggers`]); the rotation
//! primitives themselves land with the rotation slice.

pub mod boot;
pub(crate) mod cancel;
pub(crate) mod drain;
pub mod model;
pub mod op;
pub mod overlay;
pub mod pointer;
pub(crate) mod project;
pub mod rebase;
pub mod record;
pub mod staging;
pub mod staleness;
pub mod tick;

pub use boot::{ColdStartError, ColdStartOutcome, ColdStartParams, RootResolve, cold_start};
pub use drain::{BlockedOp, DRAINED_OP_MARK_KEY, OP_ATTEMPTS_KEY, UPLOAD_MARK_KEY};
pub use model::{Link, NodeMeta, Snapshot, collation_key, suffix_name};
pub use op::{NewNode, Op, OpDecodeError, OpKind, Replaced, StagedContent};
pub use overlay::apply_overlay;
pub use pointer::{
    ConsultReason, PointerError, PointerFetch, SessionRole, VaultPointerAdoption, open_repoint,
    resolve_vault_pointer, scope_pointer_name, scope_pointer_signer, seal_repoint, should_consult,
    vault_pointer_name,
};
pub use rebase::{
    AppliedOp, DeadLetterReason, DropReason, HeadReconciliation, OpResolution, QueueScan, Repair,
    ReplayReport, apply_repairs, decode_queue, observed_repair, rebase_one, reconcile_head, replay,
};
pub use record::{
    OpRecordError, RecordClass, RecordReader, RecordSeal, RetainedReason, encode_op_record,
    record_content_root_cid,
};
pub use staging::{
    PRESERVED_ROOTS_KEY, orphan_staging_keys, preserve_staged_root, release_version_blocks,
    stage_op,
};
pub use staleness::{Connectivity, classify, withheld_escalation};
pub use tick::{
    FocusTarget, FocusWindow, ResolveMode, TickCause, TickControl, focus_folders,
    focus_folders_due, focus_set, jittered_cadence, on_access_refresh_due, resolve_mode,
    run_tick_loop,
};

/// Whole milliseconds of `duration`, truncating and saturating — the engine's
/// clock is the millisecond [`UnixMillis`](crate::seams::UnixMillis), so every
/// timing threshold compares in the same unit.
pub(crate) fn duration_millis(duration: core::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
