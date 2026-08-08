//! Conformance kit: [`ContactStore`] durability, replacement-on-re-import, and
//! the fail-closed import that is its only write path.

use cipherbox_core::kdf;
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::EcdsaSigner;

use crate::grants::{ContactStore, ContactStoreError};

/// A contact code binding `scalar`'s identity to `subkey_scalar`'s encryption
/// subkey, signed by that identity — what an out-of-band exchange hands over.
fn code(scalar: u8, subkey_scalar: u8) -> Vec<u8> {
    let identity = EcdsaSigner::from_scalar(&[scalar; 32]).expect("valid identity scalar");
    ContactCode::create(&identity, kdf::enc_subkey(&[subkey_scalar; 32]).public()).encode()
}

/// The recorded contacts as `(identity, subkey)` byte pairs, sorted so a kit
/// assertion never depends on an order the contract does not promise.
async fn held<S: ContactStore>(store: &S) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut held: Vec<_> = store
        .contacts()
        .await
        .unwrap()
        .iter()
        .map(|c| {
            (
                c.identity_pk().to_sec1().to_vec(),
                c.enc_subkey().to_bytes().to_vec(),
            )
        })
        .collect();
    held.sort();
    held
}

/// Runs the `ContactStore` contract against an implementation.
///
/// `open` must return a handle over the same durable backing on every call
/// (reopen semantics); the backing must start empty.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S, F>(mut open: F)
where
    S: ContactStore,
    F: AsyncFnMut() -> S,
{
    let store = open().await;

    assert!(
        store.contacts().await.unwrap().is_empty(),
        "a fresh backing holds no contacts"
    );

    let alice = code(0x21, 0x21);
    let bob = code(0x22, 0x22);

    let imported = store.record(&alice).await.unwrap();
    assert_eq!(
        held(&store).await,
        vec![(
            imported.identity_pk().to_sec1().to_vec(),
            imported.enc_subkey().to_bytes().to_vec()
        )],
        "a recorded contact reads back as the pair the import verified"
    );
    assert_eq!(
        held(&open().await).await,
        held(&store).await,
        "contacts survive reopening the backing"
    );

    store.record(&bob).await.unwrap();
    assert_eq!(
        held(&open().await).await.len(),
        2,
        "a second contact joins the book rather than replacing it"
    );

    // Re-importing an identity replaces its entry: both codes carry that
    // identity's own signature, so the later one is the contact rotating.
    let rotated = store.record(&code(0x21, 0x77)).await.unwrap();
    let after = held(&open().await).await;
    assert_eq!(after.len(), 2, "a rotation does not grow the book");
    assert!(
        after.contains(&(
            rotated.identity_pk().to_sec1().to_vec(),
            rotated.enc_subkey().to_bytes().to_vec()
        )),
        "the rotated subkey is what the book now holds"
    );

    // A re-import of an unchanged code is idempotent.
    store.record(&bob).await.unwrap();
    assert_eq!(
        held(&open().await).await,
        after,
        "re-recording an unchanged code changes nothing"
    );

    let bob_identity = EcdsaSigner::from_scalar(&[0x22; 32])
        .expect("valid identity scalar")
        .verifying_key()
        .to_sec1();
    store.forget(&bob_identity).await.unwrap();
    assert_eq!(
        held(&open().await).await.len(),
        1,
        "a forgotten contact does not survive"
    );
    store.forget(&bob_identity).await.unwrap();
    assert_eq!(
        held(&open().await).await.len(),
        1,
        "forgetting an identity the book does not hold is a no-op, not an error"
    );

    // The import is the write path, so a code whose binding does not verify
    // never reaches the backing.
    let mut forged = code(0x23, 0x23);
    let last = forged.len() - 1;
    forged[last] ^= 0xFF;
    assert!(
        matches!(
            store.record(&forged).await,
            Err(ContactStoreError::Import(_))
        ),
        "a code that does not import is refused, never recorded"
    );
    assert_eq!(
        held(&open().await).await.len(),
        1,
        "a refused import leaves the book exactly as it was"
    );
}
