//! Conformance kit: [`ReceivedShareStore`] whole-list replacement, durability,
//! and secret round-tripping.

use cipherbox_core::seal::Permission;
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::{SecretBytes, ct_eq};

use crate::grants::{ReceivedShare, ReceivedShareStore, ReceivedSharesList};

/// A list holding one bookmark per `(scope root, pointer read key)` pair given,
/// built through the accept flow's own reconcile so the kit never fabricates a
/// list shape the engine cannot produce.
fn list(entries: &[(&[u8], u8, Permission)]) -> ReceivedSharesList {
    let mut shares = ReceivedSharesList::new();
    for (scope_root_name, key_byte, permission) in entries {
        shares.reconcile(ReceivedShare {
            scope_root_name: scope_root_name.to_vec(),
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "Shared Folder".into(),
            permission: *permission,
            pointer_read_key: SecretBytes::new([*key_byte; 32]),
        });
    }
    shares
}

/// The stored bookmarks as comparable tuples, so a kit assertion never depends
/// on an order the contract does not promise.
async fn held<S: ReceivedShareStore>(store: &S) -> Vec<(Vec<u8>, [u8; 32], Permission)> {
    let mut held: Vec<_> = store
        .load()
        .await
        .unwrap()
        .iter()
        .map(|share| {
            (
                share.scope_root_name.clone(),
                *share.pointer_read_key(),
                share.permission,
            )
        })
        .collect();
    held.sort_by(|a, b| a.0.cmp(&b.0));
    held
}

/// Runs the `ReceivedShareStore` contract against an implementation.
///
/// `open` must return a handle over the same durable backing on every call
/// (reopen semantics); the backing must start empty.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S, F>(mut open: F)
where
    S: ReceivedShareStore,
    F: AsyncFnMut() -> S,
{
    let store = open().await;

    assert!(
        store.load().await.unwrap().is_empty(),
        "a fresh backing holds no bookmarks"
    );

    let one: &[u8] = b"k51scoperoot-one";
    let two: &[u8] = b"k51scoperoot-two";

    store
        .persist(&list(&[(one, 0x8A, Permission::Read)]))
        .await
        .unwrap();
    assert_eq!(
        held(&store).await,
        vec![(one.to_vec(), [0x8A; 32], Permission::Read)],
        "a persisted bookmark reads back with its pointer read key intact"
    );

    // Reopen: the whole point of the store. An accepted share whose mailbox item
    // is already acked is unrecoverable if a restart loses it.
    assert_eq!(
        held(&open().await).await,
        vec![(one.to_vec(), [0x8A; 32], Permission::Read)],
        "bookmarks survive reopening the backing"
    );

    // Whole-list replacement, not a merge: the caller's list is authority, so a
    // healed entry must not read back beside its pre-image.
    store
        .persist(&list(&[
            (one, 0x9C, Permission::Write),
            (two, 0x7D, Permission::Read),
        ]))
        .await
        .unwrap();
    assert_eq!(
        held(&open().await).await,
        vec![
            (one.to_vec(), [0x9C; 32], Permission::Write),
            (two.to_vec(), [0x7D; 32], Permission::Read),
        ],
        "persist replaces the whole list rather than merging into it"
    );

    // A dropped bookmark is genuinely gone, not resurrected by a stale copy.
    store
        .persist(&list(&[(two, 0x7D, Permission::Read)]))
        .await
        .unwrap();
    assert_eq!(
        held(&open().await).await,
        vec![(two.to_vec(), [0x7D; 32], Permission::Read)],
        "a bookmark absent from the persisted list does not survive"
    );

    // An empty list is a state the store must be able to hold, not a no-op that
    // silently keeps the previous one.
    store.persist(&ReceivedSharesList::new()).await.unwrap();
    assert!(
        open().await.load().await.unwrap().is_empty(),
        "persisting an empty list clears the backing"
    );

    // Secret round-trip fidelity under the constant-time comparator the engine
    // uses on this key everywhere else.
    store
        .persist(&list(&[(one, 0xE1, Permission::Read)]))
        .await
        .unwrap();
    let reopened = open().await.load().await.unwrap();
    let stored = reopened.iter().next().expect("one bookmark");
    assert!(
        ct_eq(stored.pointer_read_key(), &[0xE1; 32]),
        "the pointer read key round-trips byte-exact"
    );
}
