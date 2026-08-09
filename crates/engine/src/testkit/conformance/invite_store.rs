//! Conformance kit: [`InviteStore`] whole-set replacement, durability, and
//! field-for-field fidelity of the record conversion trusts.

use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SECRET_LEN;

use crate::grants::{InviteStore, RecordedInvite};
use crate::seams::UnixMillis;

fn record(byte: u8, expires_at: Option<UnixMillis>) -> RecordedInvite {
    RecordedInvite {
        tag: [byte; 32],
        ephemeral_identity_pk: [byte ^ 0x0f; IDENTITY_PUBLIC_LEN],
        ephemeral_enc_pk: [byte ^ 0xf0; SECRET_LEN],
        expires_at,
    }
}

/// The stored records in tag order, so a kit assertion never depends on an
/// order the contract does not promise.
async fn held<S: InviteStore>(store: &S) -> Vec<RecordedInvite> {
    let mut held = store.load().await.unwrap();
    held.sort_by_key(|link| link.tag);
    held
}

/// Runs the `InviteStore` contract against an implementation.
///
/// `open` must return a handle over the same durable backing on every call
/// (reopen semantics); the backing must start empty.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S, F>(mut open: F)
where
    S: InviteStore,
    F: AsyncFnMut() -> S,
{
    let store = open().await;

    assert!(
        store.load().await.unwrap().is_empty(),
        "a fresh backing holds no links"
    );

    let one = record(0x11, Some(UnixMillis(1_700_000_000_000)));
    let two = record(0x22, None);

    store.persist(&[one]).await.unwrap();
    assert_eq!(
        held(&store).await,
        vec![one],
        "a persisted record reads back field for field"
    );
    assert_eq!(
        held(&open().await).await,
        vec![one],
        "records survive reopening the backing"
    );

    // Whole-set replacement, not a merge: the caller's set is the authority, so
    // a re-recorded link must not read back beside its pre-image.
    store.persist(&[one, two]).await.unwrap();
    assert_eq!(held(&open().await).await, vec![one, two]);

    store.persist(&[two]).await.unwrap();
    assert_eq!(
        held(&open().await).await,
        vec![two],
        "a link absent from the persisted set does not survive — this is how a revoke lands"
    );

    store.persist(&[]).await.unwrap();
    assert!(
        open().await.load().await.unwrap().is_empty(),
        "persisting an empty set clears the backing"
    );
}
