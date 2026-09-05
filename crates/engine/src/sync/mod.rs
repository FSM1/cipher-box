//! The sync core — the state law, the durable op queue, FIFO rebase, budgeted
//! offline staging, the focus-window tick, the staleness ladder, and the
//! pointer planes (blueprint/engine.md "Sync core", "Pointer planes";
//! CONTEXT.md "Sync and refresh").
//!
//! One model, single owner: rendered state = last-known-good gate-passing
//! snapshot ⊕ pending-op overlay, and the op queue is the only local
//! divergence (#33 D6). Every mutation rides the durable op queue as an intent
//! op carrying its base sequence; offline replay and online CAS rebase re-apply
//! ops through the **same** path — FIFO, onto gate-passing state only, through
//! the five per-op race rules — and a terminally unrebasable op dead-letters
//! with its staged bytes preserved rather than being silently dropped.
//!
//! A cross-scope relocation out of a granted scope resolves its source scope
//! root full-depth and queues one trigger per root
//! ([`rebase::ReplayReport::scope_exit_triggers`]);
//! [`consume_scope_exit_triggers`](crate::rotation::consume_scope_exit_triggers)
//! cuts them.

pub mod bookkeeping;
pub mod boot;
pub(crate) mod cancel;
pub(crate) mod doomed;
pub(crate) mod drain;
pub mod model;
pub mod op;
pub mod overlay;
pub mod pointer;
pub(crate) mod project;
pub(crate) mod provision;
pub mod rebase;
pub mod record;
pub(crate) mod refresh;
pub(crate) mod scope_exit_debt;
pub mod staging;
pub mod staleness;
pub mod tick;
pub(crate) mod upload_mark;

pub use bookkeeping::BookkeepingSeal;
pub use boot::{ColdStartError, ColdStartOutcome, ColdStartParams, RootResolve, cold_start};
pub use doomed::{MAX_JOURNAL_REPLAYS, MAX_QUARANTINE_ATTEMPTS, doomed_journal_key};
pub use drain::{
    BlockedOp, DRAINED_OP_MARK_PREFIX, OP_ATTEMPTS_KEY, PUBLISHED_OP_MARK_PREFIX, SettingsHold,
    owner_scoped_key, owner_tag,
};
pub use model::{Link, NodeMeta, Snapshot, case_fold, collation_key, suffix_name};
pub use op::{NewNode, Op, OpDecodeError, OpKind, Replaced, ScopeCrossing, StagedContent};
pub use overlay::apply_overlay;
pub use pointer::{
    ConsultReason, PointerError, PointerFetch, PointerRecord, SessionRole, VaultPointerAdoption,
    open_repoint, resolve_vault_pointer, scope_pointer_name, scope_pointer_signer, seal_repoint,
    should_consult, vault_pointer_name,
};
pub use rebase::{
    AppliedOp, DeadLetterReason, DropReason, HeadReconciliation, OpResolution, QueueScan, Repair,
    ReplayReport, ReplayScopes, apply_repairs, decode_queue, observed_repair, rebase_one,
    reconcile_head, replay,
};
pub use record::{
    OpRecordError, RecordClass, RecordReader, RecordSeal, RetainedReason, encode_op_record,
    record_content_root_cid,
};
pub use scope_exit_debt::{scope_exit_debt_key, seal_owed_cuts};
pub use staging::{orphan_staging_keys, stage_op};
pub use staleness::{Connectivity, classify, withheld_escalation};
pub use tick::{
    FocusTarget, FocusWindow, ResolveMode, TickCause, TickControl, focus_files, focus_folders,
    focus_folders_due, focus_set, on_access_refresh_due, resolve_mode,
};
pub use upload_mark::{UPLOAD_MARK_PREFIX, encode_upload_mark, upload_mark_key};

/// Whole milliseconds of `duration`, truncating and saturating — the engine's
/// clock is the millisecond [`UnixMillis`](crate::seams::UnixMillis), so every
/// timing threshold compares in the same unit.
pub(crate) fn duration_millis(duration: core::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
