//! Conformance kit: [`CredentialStore`] best-effort persistence.

use crate::seams::CredentialStore;

/// Runs the `CredentialStore` contract against an implementation.
///
/// `open` must return a handle over the same backing on every call; the
/// backing must start empty. The contract is deliberately best-effort —
/// web's no-op implementation is valid (blueprint/engine.md seam table) —
/// so the kit asserts consistency, never mandatory persistence: `load`
/// returns the last stored token or `None`, never anything else, and
/// `clear` always results in `None`.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S, F>(mut open: F)
where
    S: CredentialStore,
    F: AsyncFnMut() -> S,
{
    let store = open().await;

    assert_eq!(
        store.load_refresh_token().await.unwrap(),
        None,
        "a fresh backing must hold no token"
    );

    store.store_refresh_token(b"token-1").await.unwrap();
    let loaded = store.load_refresh_token().await.unwrap();
    assert!(
        loaded.is_none() || loaded.as_deref() == Some(b"token-1".as_slice()),
        "load must return the stored token or None, never a different token"
    );
    assert_eq!(
        store.load_refresh_token().await.unwrap(),
        loaded,
        "repeated loads must agree"
    );

    // A persisting implementation must replace on store.
    if loaded.is_some() {
        store.store_refresh_token(b"token-2").await.unwrap();
        assert_eq!(
            store.load_refresh_token().await.unwrap().as_deref(),
            Some(b"token-2".as_slice()),
            "a persisting store must replace the token"
        );

        // ... and keep it across reopen.
        let reopened = open().await;
        assert_eq!(
            reopened.load_refresh_token().await.unwrap().as_deref(),
            Some(b"token-2".as_slice()),
            "a persisting store must keep the token across reopen"
        );
    }

    // Clear always lands on None, durably, and is idempotent.
    let store = open().await;
    store.clear_refresh_token().await.unwrap();
    store.clear_refresh_token().await.unwrap();
    assert_eq!(store.load_refresh_token().await.unwrap(), None);
    let reopened = open().await;
    assert_eq!(
        reopened.load_refresh_token().await.unwrap(),
        None,
        "clear must be durable"
    );
}
