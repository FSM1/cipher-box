//! Conformance kit: [`InviteStore`] whole-set replacement, durability, and
//! field-for-field fidelity of the record conversion trusts.

use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SECRET_LEN;

use crate::grants::{InviteStore, InviteStoreError, MAX_INVITE_RECORDS, RecordedInvite};
use crate::seams::UnixMillis;

fn record(byte: u8, expires_at: Option<UnixMillis>) -> RecordedInvite {
    RecordedInvite {
        tag: [byte; 32],
        ephemeral_identity_pk: [byte ^ 0x0f; IDENTITY_PUBLIC_LEN],
        ephemeral_enc_pk: [byte ^ 0xf0; SECRET_LEN],
        expires_at,
    }
}

/// One record past the frozen bound, every tag distinct.
fn over_bound() -> Vec<RecordedInvite> {
    (0..=MAX_INVITE_RECORDS as u32)
        .map(|i| {
            let mut link = record(0x11, None);
            link.tag[..4].copy_from_slice(&i.to_be_bytes());
            link
        })
        .collect()
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

    store.persist(&[one]).await.unwrap();
    assert!(
        matches!(
            store.persist(&over_bound()).await,
            Err(InviteStoreError::Full)
        ),
        "a set past MAX_INVITE_RECORDS is a bound the host can act on, not an outage to retry"
    );

    // The other two write-path refusals are contract, not implementation
    // detail: both leave a link's authority undefined, so every implementation
    // owes the same answer.
    let mut clash = two;
    clash.ephemeral_enc_pk = [0x01; SECRET_LEN];
    assert!(
        matches!(
            store.persist(&[two, clash]).await,
            Err(InviteStoreError::Encode(_))
        ),
        "two records under one tag leave that link's permission and deadline undefined"
    );
    assert!(
        matches!(
            store.persist(&[record(0x33, Some(UnixMillis(0)))]).await,
            Err(InviteStoreError::Encode(_))
        ),
        "a zero deadline is not 'no deadline' — the mint refuses one, so storing it would \
         resurrect a link the mint never made"
    );

    assert_eq!(
        held(&open().await).await,
        vec![one],
        "a refused set leaves the recorded links untouched"
    );

    store.persist(&[]).await.unwrap();
    assert!(
        open().await.load().await.unwrap().is_empty(),
        "persisting an empty set retires every recorded link"
    );
}
