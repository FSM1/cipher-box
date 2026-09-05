//! `RetireLedger` — the durable owed-retirement set.

use super::SeamResult;

/// Whether the node owing a retirement still publishes a record of its own.
///
/// The settlement pass decides what a retire may name by reading the owing
/// node's published record, which a node that survived its own shortening always
/// has and a hard-deleted one never will. The answer is a property of the node,
/// so the ledger holds it once per node
/// ([`tombstoned`](RetireLedger::tombstoned)) rather than once per entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwingRecord {
    /// The node outlives the debt — a prune shortened its history. An
    /// unreadable record stands the entry down: retiring what this pass failed
    /// to read is loss, where the row left charged is only a leak.
    Published,
    /// The node's own record is retired with the debt — a hard delete. Nothing
    /// resolves at its name and nothing it named is reachable, so an unreadable
    /// record reads as an empty live set. Without the distinction the debt is
    /// permanently unsettleable against a never-discard ledger.
    Retired,
}

/// One owed retirement: a doomed version's **root** `contentCid` and the pinned
/// bytes retiring its expansion frees.
///
/// Only the root is journaled. Its leaves are re-derived at drain time from the
/// root block, which is plaintext det-CBOR — so the ledger stays three orders of
/// magnitude smaller than the CID set it stands for, and holds the half that is
/// irrecoverable: nothing readable names a dropped root once the shortened
/// history publishes, while a root always names its own leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedRetire {
    /// The node whose history dropped the target. The drain re-reads this
    /// node's published record to decide what the retire may name, so the entry
    /// carries it rather than a snapshot of the answer.
    pub node: [u8; 16],
    /// The doomed version's root `contentCid` (multibase string).
    pub target: String,
    /// The pinned bytes this entry stands for, as the prune quoted them.
    ///
    /// An **upper bound**, and only the fallback figure: it is what the vault
    /// reports as pending on a pass that could not re-expand the entry. A pass
    /// that can re-expand reports what the retire would actually free.
    pub owed_bytes: u64,
    /// The pinned total the doomed manifest must account for — the bound the
    /// expansion holds a hand-framed root to.
    pub manifest_bytes: u64,
}

impl OwedRetire {
    /// A debt quoted at its whole manifest total.
    #[must_use]
    pub fn whole(node: [u8; 16], target: String, pinned_bytes: u64) -> Self {
        Self {
            node,
            target,
            owed_bytes: pinned_bytes,
            manifest_bytes: pinned_bytes,
        }
    }
}

/// Durable per-owner set of retirements a prune still owes the registry.
///
/// Distinct from the op queue on all four axes at once: it outlives the op that
/// filled it, it is a **set** rather than a FIFO, it is **never-discard** rather
/// than dead-lettering, and it is not cancellable. Its contract, enforced by the
/// conformance kit (`testkit::conformance::retire_ledger` under the `test-kit`
/// feature):
///
/// - **Owner-scoped**: entries and tombstones under one `owner_tag` are
///   invisible under every other, and [`settle`](RetireLedger::settle) under one
///   tag never clears another's. Forced, not tidy: the registry's done-signal
///   cannot tell one account's paid debt from another's unpaid one
///   ([`RetireResult`](crate::api::RetireResult)).
/// - **Keyed by target**: [`owe`](RetireLedger::owe)ing a target the store
///   already holds keeps the stored figures rather than adding a second entry,
///   so a replayed prune cannot double the pending figure. Order is not part of
///   the contract.
/// - **Never-discard**: nothing but `settle` removes an entry. There is no
///   attempt budget, no expiry, and no sweep — every failure mode is either
///   self-clearing or ours, and the byte figure is the only record of what was
///   owed.
/// - **Durable**: entries and tombstones survive reopening the store.
///
/// `owner_tag` is opaque engine-chosen bytes; the store never interprets it.
pub trait RetireLedger {
    /// Journals `entries` under `owner_tag`, keeping any target already held
    /// rather than adding a second entry for it.
    async fn owe(&self, owner_tag: &[u8], entries: &[OwedRetire]) -> SeamResult<()>;

    /// Every entry owed under `owner_tag`, in unspecified order.
    async fn owed(&self, owner_tag: &[u8]) -> SeamResult<Vec<OwedRetire>>;

    /// Clears `targets` under `owner_tag`. Idempotent: an unheld target
    /// succeeds.
    async fn settle(&self, owner_tag: &[u8], targets: &[String]) -> SeamResult<()>;

    /// Journals that `node`'s own record is retired, so every debt it owes —
    /// the ones already held included — settles against an empty live set
    /// ([`OwingRecord::Retired`]). Idempotent.
    async fn tombstone(&self, owner_tag: &[u8], node: [u8; 16]) -> SeamResult<()>;

    /// Whether `node` is tombstoned under `owner_tag`. Fail-closed: a value
    /// this identity's key does not open reads as untombstoned, so a planted
    /// key cannot retire a live node's content.
    async fn tombstoned(&self, owner_tag: &[u8], node: [u8; 16]) -> SeamResult<bool>;

    /// Drops `nodes`' tombstones under `owner_tag` — the classification leaves
    /// with the last debt it classified. Idempotent.
    async fn forget_tombstones(&self, owner_tag: &[u8], nodes: &[[u8; 16]]) -> SeamResult<()>;
}
