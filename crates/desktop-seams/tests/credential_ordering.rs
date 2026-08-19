//! The keyring seam must take its queue slot when a method is called, not when
//! the returned future is first polled: a credential write still waiting on an
//! unlock prompt must never land after the logout delete issued later
//! (blueprint/engine.md "CredentialStore").
//!
//! This suite owns the whole test binary because it installs a keyring
//! credential builder, which is a process-wide global. No CI runner has an
//! unlocked OS keyring, and the ordering under test is decided before the host
//! call — but the `#[ignore]`d `real_keyring_*` tests in `conformance.rs` need
//! the real backend, so the substitute must not reach them.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use cipherbox_desktop_seams::KeyringCredentialStore;
use cipherbox_engine::seams::CredentialStore;
use cipherbox_engine::testkit::block_on;
use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence};
use zeroize::Zeroizing;

/// An in-process credential backend that survives between entries.
///
/// Not `keyring::mock`: that one hands out a fresh empty credential per
/// `Entry`, so a read after a write always reports nothing and an end-state
/// assertion over it would hold whatever order the operations ran in.
#[derive(Clone, Default)]
struct ProcessKeyring {
    secrets: Arc<Mutex<HashMap<Account, Zeroizing<Vec<u8>>>>>,
}

/// Keyed the way `keyring::Entry` is: service, then account label.
type Account = (String, String);

struct ProcessEntry {
    keyring: ProcessKeyring,
    account: Account,
}

impl CredentialApi for ProcessEntry {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        self.keyring
            .secrets
            .lock()
            .expect("keyring lock")
            .insert(self.account.clone(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        self.keyring
            .secrets
            .lock()
            .expect("keyring lock")
            .get(&self.account)
            .map(|secret| secret.to_vec())
            .ok_or(keyring::Error::NoEntry)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        self.keyring
            .secrets
            .lock()
            .expect("keyring lock")
            .remove(&self.account)
            .map(|_| ())
            .ok_or(keyring::Error::NoEntry)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CredentialBuilderApi for ProcessKeyring {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        account: &str,
    ) -> keyring::Result<Box<Credential>> {
        Ok(Box::new(ProcessEntry {
            keyring: self.clone(),
            account: (service.to_owned(), account.to_owned()),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::ProcessOnly
    }
}

/// Fails the moment any method on the seam path goes back to `async fn`: the
/// write would then take its queue slot at its first poll, behind the delete,
/// and a logout would leave a live refresh token in the keyring. Driven through
/// the [`CredentialStore`] methods the shell calls.
#[test]
fn a_write_built_before_a_delete_runs_first_however_the_futures_are_polled() {
    keyring::set_default_credential_builder(Box::new(ProcessKeyring::default()));
    let store = KeyringCredentialStore::new("com.cipherbox.desktop.test").expect("worker started");

    let write = store.store_refresh_token(b"token");
    let delete = store.clear_refresh_token();

    // Polled in the opposite order to construction. The worker is FIFO, so the
    // delete finishing proves the write already ran.
    block_on(delete).expect("the delete ran");

    let Poll::Ready(written) = pin!(write).poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("the write was queued at call, so its result is already waiting");
    };
    written.expect("the write ran");

    // The end state, which no scheduling can flatter: had the write overtaken
    // the delete it would have left a live token behind for the next login.
    assert_eq!(
        block_on(store.load_refresh_token()).expect("the load ran"),
        None,
        "the delete stayed behind the write in the worker queue"
    );
}
