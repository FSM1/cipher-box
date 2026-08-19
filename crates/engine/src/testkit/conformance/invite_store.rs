//! Conformance kit: [`InviteStore`] whole-set replacement, durability, and
//! field-for-field fidelity of the state conversion trusts — the recorded links
//! and the spent claims that keep a claim single-use.

use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SECRET_LEN;

use crate::grants::{
    CLAIM_ID_LEN, ConvertedClaimRecord, InviteRecords, InviteStore, InviteStoreError,
    MAX_CONVERTED_CLAIMS, MAX_INVITE_RECORDS, RecordedInvite,
};
use crate::seams::UnixMillis;

fn record(byte: u8, expires_at: Option<UnixMillis>) -> RecordedInvite {
    RecordedInvite {
        tag: [byte; 32],
        ephemeral_identity_pk: [byte ^ 0x0f; IDENTITY_PUBLIC_LEN],
        ephemeral_enc_pk: [byte ^ 0xf0; SECRET_LEN],
        expires_at,
    }
}

fn claim(byte: u8) -> ConvertedClaimRecord {
    ConvertedClaimRecord {
        claim_id: [byte; CLAIM_ID_LEN],
        link_tag: [byte ^ 0xa5; 32],
        tag: [byte ^ 0x5a; 32],
    }
}

/// One link past the frozen bound, every tag distinct.
fn over_link_bound() -> InviteRecords {
    InviteRecords {
        links: (0..=MAX_INVITE_RECORDS as u32)
            .map(|i| {
                let mut link = record(0x11, None);
                link.tag[..4].copy_from_slice(&i.to_be_bytes());
                link
            })
            .collect(),
        ..Default::default()
    }
}

/// One spent claim past the frozen bound, every claim distinct.
fn over_claim_bound() -> InviteRecords {
    InviteRecords {
        claims: (0..=MAX_CONVERTED_CLAIMS as u32)
            .map(|i| {
                let mut spent = claim(0x11);
                spent.claim_id[..4].copy_from_slice(&i.to_be_bytes());
                spent.tag[..4].copy_from_slice(&i.to_be_bytes());
                spent
            })
            .collect(),
        ..Default::default()
    }
}

/// The stored state in tag / claim-id order, so a kit assertion never depends on
/// an order the contract does not promise.
async fn held<S: InviteStore>(store: &S) -> InviteRecords {
    let mut held = store.load().await.unwrap();
    held.links.sort_by_key(|link| link.tag);
    held.claims.sort_by_key(|spent| spent.claim_id);
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

    assert_eq!(
        store.load().await.unwrap(),
        InviteRecords::default(),
        "a fresh backing holds no links and no spent claims"
    );

    let one = record(0x11, Some(UnixMillis(1_700_000_000_000)));
    let two = record(0x22, None);
    let spent = claim(0x77);
    let linked = |links: &[RecordedInvite]| InviteRecords {
        links: links.to_vec(),
        ..Default::default()
    };

    store.persist(&linked(&[one])).await.unwrap();
    assert_eq!(
        held(&store).await,
        linked(&[one]),
        "a persisted record reads back field for field"
    );
    assert_eq!(
        held(&open().await).await,
        linked(&[one]),
        "records survive reopening the backing"
    );

    // Whole-set replacement, not a merge: the caller's set is the authority, so
    // a re-recorded link must not read back beside its pre-image.
    store.persist(&linked(&[one, two])).await.unwrap();
    assert_eq!(held(&open().await).await, linked(&[one, two]));

    store.persist(&linked(&[two])).await.unwrap();
    assert_eq!(
        held(&open().await).await,
        linked(&[two]),
        "a link absent from the persisted set does not survive — this is how a revoke lands"
    );

    // The spent-claim half is what makes a claim single-use, so it must survive
    // a restart every bit as durably as the links it sits beside.
    let both = InviteRecords {
        links: vec![one],
        claims: vec![spent],
    };
    store.persist(&both).await.unwrap();
    assert_eq!(
        held(&open().await).await,
        both,
        "a spent claim reads back field for field across a reopen"
    );

    assert!(
        matches!(
            store.persist(&over_link_bound()).await,
            Err(InviteStoreError::Full {
                collection: "links",
                ..
            })
        ),
        "a set past MAX_INVITE_RECORDS is a bound the host can act on, not an outage to retry"
    );
    assert!(
        matches!(
            store.persist(&over_claim_bound()).await,
            Err(InviteStoreError::Full {
                collection: "claims",
                ..
            })
        ),
        "the claims bound is reported as its own, since its remedy is not revoking a link"
    );

    // The write-path refusals are contract, not implementation detail: each
    // leaves an authority undefined, so every implementation owes the same
    // answer.
    let mut clash = two;
    clash.ephemeral_enc_pk = [0x01; SECRET_LEN];
    assert!(
        matches!(
            store.persist(&linked(&[two, clash])).await,
            Err(InviteStoreError::Encode(_))
        ),
        "two records under one tag leave that link's permission and deadline undefined"
    );
    assert!(
        matches!(
            store
                .persist(&linked(&[record(0x33, Some(UnixMillis(0)))]))
                .await,
            Err(InviteStoreError::Encode(_))
        ),
        "a zero deadline is not 'no deadline' — the mint refuses one, so storing it would \
         resurrect a link the mint never made"
    );
    let mut same_id = spent;
    same_id.tag = [0x01; 32];
    assert!(
        matches!(
            store
                .persist(&InviteRecords {
                    claims: vec![spent, same_id],
                    ..Default::default()
                })
                .await,
            Err(InviteStoreError::Encode(_))
        ),
        "one claim id cannot name two conversions — the set is a membership test"
    );
    let mut same_grantee = spent;
    same_grantee.claim_id = [0x01; CLAIM_ID_LEN];
    assert!(
        matches!(
            store
                .persist(&InviteRecords {
                    claims: vec![spent, same_grantee],
                    ..Default::default()
                })
                .await,
            Err(InviteStoreError::Encode(_))
        ),
        "one record per grantee per link is what bounds the set by the grants actually published"
    );

    assert_eq!(
        held(&open().await).await,
        both,
        "a refused set leaves the recorded state untouched"
    );

    store.persist(&InviteRecords::default()).await.unwrap();
    assert_eq!(
        open().await.load().await.unwrap(),
        InviteRecords::default(),
        "persisting an empty set retires every recorded link"
    );
}
