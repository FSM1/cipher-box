//! `RetireLedger` — the durable owed-retirement set.

use super::SeamResult;

/// One owed retirement: a doomed version's **root** `contentCid` and the pinned
/// bytes retiring its expansion frees.
///
/// Only the root is journaled. Its leaves are re-derived at drain time from the
/// root block, which is plaintext det-CBOR — so the ledger stays three orders of
/// magnitude smaller than the CID set it stands for, and holds the half that is
/// irrecoverable: once the shortened history publishes, nothing readable names
/// the dropped roots, while a root always names its own leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedRetire {
    /// The doomed version's root `contentCid` (multibase string).
    pub target: String,
    /// The pinned bytes this entry stands for — the vault's pending-reclaim
    /// figure is their sum.
    pub owed_bytes: u64,
}

/// Durable per-owner set of retirements a published prune still owes the
/// registry.
///
/// Distinct from the op queue on all four axes at once: it outlives the op that
/// filled it, it is a **set** rather than a FIFO, it is **never-discard** rather
/// than dead-lettering, and it is not cancellable. Its contract, enforced by the
/// conformance kit (`testkit::conformance::retire_ledger` under the `test-kit`
/// feature):
///
/// - **Owner-scoped**: entries under one `owner_tag` are invisible under every
///   other, and [`settle`](RetireLedger::settle) under one tag never clears
///   another's. Forced, not tidy: the registry's done-signal cannot tell one
///   account's paid debt from another's unpaid one
///   ([`RetireResult`](crate::api::RetireResult)).
/// - **Keyed by target**: [`owe`](RetireLedger::owe)ing a target the store
///   already holds keeps the stored `owed_bytes` rather than adding a second
///   entry, so a replayed prune cannot double the pending figure. Order is not
///   part of the contract.
/// - **Never-discard**: nothing but `settle` removes an entry. There is no
///   attempt budget, no expiry, and no sweep — every failure mode is either
///   self-clearing or ours, and the byte figure is the only record of what was
///   owed.
/// - **Durable**: entries survive reopening the store.
///
/// `owner_tag` is opaque engine-chosen bytes; the store never interprets it.
pub trait RetireLedger {
    /// Journals `entries` under `owner_tag`, keeping the stored `owed_bytes` of
    /// any target already held.
    async fn owe(&self, owner_tag: &[u8], entries: &[OwedRetire]) -> SeamResult<()>;

    /// Every entry owed under `owner_tag`, in unspecified order.
    async fn owed(&self, owner_tag: &[u8]) -> SeamResult<Vec<OwedRetire>>;

    /// Clears `targets` under `owner_tag`. Idempotent: an unheld target
    /// succeeds.
    async fn settle(&self, owner_tag: &[u8], targets: &[String]) -> SeamResult<()>;
}
