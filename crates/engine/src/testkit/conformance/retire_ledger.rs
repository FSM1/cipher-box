//! Conformance kit: [`RetireLedger`] owner scoping, set semantics, and
//! durability.

use std::collections::BTreeMap;

use cipherbox_core::content::{compute_cid, encode_content_cid_str};

use crate::content::DAG_ROOT_CODEC;
use crate::seams::{OwedRetire, RetireLedger};
use crate::sync::MAX_BOOKKEEPING_OPENS;

/// A distinct doomed-version root address, spelled as the ledger stores them.
fn root(seed: u8) -> String {
    root_of(usize::from(seed))
}

/// The same, over a seed space wide enough to fill a bounded read.
fn root_of(seed: usize) -> String {
    encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &seed.to_be_bytes()))
}

/// The node one debt is owed against. The kit's targets all ride one file's
/// history, which is the shape a prune journals.
const NODE: [u8; 16] = [0xA7; 16];

fn owed(target: &str, owed_bytes: u64) -> OwedRetire {
    OwedRetire::whole(NODE, target.into(), owed_bytes)
}

/// Every entry owed, read the way a pass reads them: one bounded window at a
/// time, resuming where the last one stopped, until a window opens nothing new.
async fn all<L: RetireLedger>(ledger: &L, owner_tag: &[u8]) -> BTreeMap<String, OwedRetire> {
    let mut seen: BTreeMap<String, OwedRetire> = BTreeMap::new();
    let mut cursor = None;
    loop {
        let page = ledger.owed(owner_tag, cursor.as_deref()).await.unwrap();
        let before = seen.len();
        for entry in page.entries {
            seen.insert(entry.target.clone(), entry);
        }
        if !page.truncated || seen.len() == before {
            return seen;
        }
        cursor = page.cursor;
    }
}

/// The entries as a map, so a kit assertion never depends on an order the
/// contract does not promise.
async fn held<L: RetireLedger>(ledger: &L, owner_tag: &[u8]) -> BTreeMap<String, u64> {
    all(ledger, owner_tag)
        .await
        .into_iter()
        .map(|(target, entry)| (target, entry.owed_bytes))
        .collect()
}

/// Runs the `RetireLedger` contract against an implementation.
///
/// `open` must return a handle over the same durable backing on every call
/// (reopen semantics); the backing must start empty.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<L, F>(mut open: F)
where
    L: RetireLedger,
    F: AsyncFnMut() -> L,
{
    let ledger = open().await;

    let alice = b"alice-owner-tag".as_slice();
    let bob = b"bob-owner-tag".as_slice();
    // A tag that is a strict prefix of another: a store keying entries by
    // concatenation without the tag's own length would leak between them.
    let alice_prefix = b"alice".as_slice();

    let (a, b) = (root(1), root(2));

    assert!(
        held(&ledger, alice).await.is_empty(),
        "a fresh backing owes nothing"
    );

    ledger
        .owe(alice, &[owed(&a, 100), owed(&b, 250)])
        .await
        .unwrap();
    assert_eq!(
        held(&ledger, alice).await,
        BTreeMap::from([(a.clone(), 100), (b.clone(), 250)])
    );

    // Keyed by target: a replayed prune must not add a second entry or move the
    // figure the vault reports as pending.
    ledger
        .owe(alice, &[owed(&a, 999), owed(&a, 7)])
        .await
        .unwrap();
    assert_eq!(
        held(&ledger, alice).await,
        BTreeMap::from([(a.clone(), 100), (b.clone(), 250)]),
        "re-oweing a held target must keep its stored figure"
    );

    // Owner-scoped: the registry's done-signal cannot tell one account's paid
    // debt from another's unpaid one, so the two sets must never see each other.
    assert!(
        held(&ledger, bob).await.is_empty(),
        "entries must not be visible under another owner tag"
    );
    assert!(
        held(&ledger, alice_prefix).await.is_empty(),
        "a tag that prefixes another must not see its entries"
    );
    ledger.owe(bob, &[owed(&a, 3)]).await.unwrap();
    assert_eq!(
        held(&ledger, alice).await[&a],
        100,
        "the same target under two owners is two independent debts"
    );

    // Settle clears exactly what it names, under exactly the owner it names.
    ledger.settle(bob, &[a.clone(), root(9)]).await.unwrap();
    assert!(
        held(&ledger, bob).await.is_empty(),
        "settle must clear the named target, and an unheld one must succeed"
    );
    assert_eq!(
        held(&ledger, alice).await.len(),
        2,
        "settling under one owner must not clear another's"
    );

    ledger.settle(alice, &[a.clone()]).await.unwrap();
    assert_eq!(
        held(&ledger, alice).await,
        BTreeMap::from([(b.clone(), 250)]),
        "settle must leave every target it did not name"
    );

    // Durable: the debt is the only record of what the prune owes, so it must
    // survive the restart a half-drained pass is most likely to hit.
    let reopened = open().await;
    assert_eq!(
        held(&reopened, alice).await,
        BTreeMap::from([(b.clone(), 250)]),
        "owed entries must survive reopen"
    );
    assert!(
        held(&reopened, bob).await.is_empty(),
        "a settle must survive reopen too"
    );

    // A re-owed target that was settled is a fresh debt, not a resurrection of
    // the old figure.
    reopened.owe(alice, &[owed(&a, 42)]).await.unwrap();
    assert_eq!(
        held(&reopened, alice).await,
        BTreeMap::from([(a, 42), (b, 250)])
    );

    // An empty batch is a no-op on both sides.
    reopened.owe(alice, &[]).await.unwrap();
    reopened.settle(alice, &[]).await.unwrap();
    assert_eq!(held(&reopened, alice).await.len(), 2);

    // The owing node is what the drain re-reads to decide what the retire may
    // name, and the manifest total is the bound it holds a hand-framed root to.
    // Both are as durable as the owed figure, and neither moves under a replay.
    let quoted = OwedRetire {
        node: [0x5C; 16],
        target: root(3),
        owed_bytes: 11,
        manifest_bytes: 90,
    };
    reopened.owe(alice, &[quoted.clone()]).await.unwrap();
    reopened
        .owe(alice, &[owed(&quoted.target, quoted.manifest_bytes)])
        .await
        .unwrap();
    let after_reopen = open().await;
    assert_eq!(
        all(&after_reopen, alice).await.get(&quoted.target),
        Some(&quoted),
        "every field survives a replay and a reopen"
    );

    check_bounded_reads(&after_reopen).await;
    check_tombstones(open).await;
}

/// The read is bounded, and rotation is what reaches the entries one window
/// leaves out: nothing is removed for failing to open, so a backing holding
/// more entries than the ceiling must still make progress on all of them.
async fn check_bounded_reads<L: RetireLedger>(ledger: &L) {
    let owner = b"ceiling-owner-tag".as_slice();
    let over = MAX_BOOKKEEPING_OPENS + 3;
    let entries: Vec<OwedRetire> = (0..over).map(|seed| owed(&root_of(seed), 8)).collect();
    ledger.owe(owner, &entries).await.unwrap();

    let page = ledger.owed(owner, None).await.unwrap();
    assert!(
        page.entries.len() <= MAX_BOOKKEEPING_OPENS,
        "one read opens at most the ceiling"
    );
    assert!(page.truncated, "and says the set is larger than the window");
    assert!(
        page.cursor.is_some(),
        "so the next read has somewhere to go"
    );

    let reached = all(ledger, owner).await;
    assert_eq!(
        reached.len(),
        over,
        "every entry is reached by rotation, however many windows it takes"
    );

    let targets: Vec<String> = reached.into_keys().collect();
    ledger.settle(owner, &targets).await.unwrap();
    assert!(all(ledger, owner).await.is_empty());
}

/// The node-keyed half of the contract: which nodes a hard delete retired.
async fn check_tombstones<L, F>(mut open: F)
where
    L: RetireLedger,
    F: AsyncFnMut() -> L,
{
    let ledger = open().await;
    let alice = b"alice-owner-tag".as_slice();
    let bob = b"bob-owner-tag".as_slice();
    let alice_prefix = b"alice".as_slice();
    let (deleted, live) = ([0x11; 16], [0x22; 16]);

    assert!(
        !ledger.tombstoned(alice, deleted).await.unwrap(),
        "a fresh backing tombstones nothing"
    );

    ledger.tombstone(alice, deleted).await.unwrap();
    assert!(ledger.tombstoned(alice, deleted).await.unwrap());
    assert!(
        !ledger.tombstoned(alice, live).await.unwrap(),
        "a tombstone names one node, never the store"
    );

    // Owner-scoped on the same terms the entries are: a retired node under one
    // owner must not settle another owner's debt without a record read.
    assert!(!ledger.tombstoned(bob, deleted).await.unwrap());
    assert!(!ledger.tombstoned(alice_prefix, deleted).await.unwrap());

    // Idempotent: the reclamation replay writes the tombstone on every pass it
    // journals a debt on.
    ledger.tombstone(alice, deleted).await.unwrap();
    assert!(ledger.tombstoned(alice, deleted).await.unwrap());

    // Durable: the classification outlives the pass that made it, or the debts
    // it classifies are unsettleable after a restart.
    let reopened = open().await;
    assert!(reopened.tombstoned(alice, deleted).await.unwrap());
    assert!(!reopened.tombstoned(bob, deleted).await.unwrap());

    // Cleared only where it is named, and an unheld node succeeds.
    reopened.forget_tombstones(bob, &[deleted]).await.unwrap();
    assert!(
        reopened.tombstoned(alice, deleted).await.unwrap(),
        "forgetting under one owner must not clear another's"
    );
    reopened
        .forget_tombstones(alice, &[deleted, live])
        .await
        .unwrap();
    assert!(!open().await.tombstoned(alice, deleted).await.unwrap());

    reopened.forget_tombstones(alice, &[]).await.unwrap();
}
