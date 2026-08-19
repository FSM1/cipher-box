//! The keyring seam must take its queue slot when a method is called, not when
//! the returned future is first polled: a credential write still waiting on an
//! unlock prompt must never land after the logout delete issued later
//! (blueprint/engine.md "CredentialStore").
//!
//! This suite owns the whole test binary because it installs keyring's
//! in-process credential builder, which is a process-wide global. No CI runner
//! has an unlocked OS keyring, and the ordering under test is decided before
//! the host call — but the `#[ignore]`d `real_keyring_*` tests in
//! `conformance.rs` need the real backend, so the mock must not reach them.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Waker};

use cipherbox_desktop_seams::KeyringCredentialStore;
use cipherbox_engine::seams::CredentialStore;
use cipherbox_engine::testkit::block_on;

/// Fails the moment any method on the seam path goes back to `async fn`: the
/// write would then take its queue slot at its first poll, behind the delete,
/// and a logout would leave a live refresh token in the keyring. Driven through
/// the [`CredentialStore`] methods the shell calls.
#[test]
fn a_write_built_before_a_delete_runs_first_however_the_futures_are_polled() {
    keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    let store = KeyringCredentialStore::new("com.cipherbox.desktop.test").expect("worker started");

    let write = store.store_refresh_token(b"token");
    let delete = store.clear_refresh_token();

    // Polled in the opposite order to construction. The worker is FIFO, so the
    // delete finishing proves the write already ran.
    block_on(delete).expect("the delete ran");

    assert!(
        pin!(write)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready(),
        "the write was queued at call, so its result is already waiting"
    );
}
