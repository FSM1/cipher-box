//! Conformance kit: [`RetireLedger`] owner scoping, set semantics, and
//! durability.

use std::collections::BTreeMap;

use cipherbox_core::content::{compute_cid, encode_content_cid_str};

use crate::content::DAG_ROOT_CODEC;
use crate::seams::{OwedRetire, RetireLedger};

/// A distinct doomed-version root address, spelled as the ledger stores them.
fn root(seed: u8) -> String {
    encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &[seed]))
}

fn owed(target: &str, owed_bytes: u64) -> OwedRetire {
    OwedRetire {
        target: target.into(),
        owed_bytes,
    }
}

/// The entries as a map, so a kit assertion never depends on an order the
/// contract does not promise.
async fn held<L: RetireLedger>(ledger: &L, owner_tag: &[u8]) -> BTreeMap<String, u64> {
    ledger
        .owed(owner_tag)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| (entry.target, entry.owed_bytes))
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
}
