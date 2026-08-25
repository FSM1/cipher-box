//! The keyring seam must not run on the caller's thread. The engine is a
//! single-writer brain on a current-thread executor, so a seam body that blocks
//! freezes every timer and sync tick — and an OS keyring call can block on a
//! user-facing unlock prompt, which is unbounded (blueprint/engine.md
//! "CredentialStore").
//!
//! Its own test binary: the substitute backend is installed through
//! `set_default_credential_builder`, a process-wide global, so a second suite
//! setting a different one would race this.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};
use std::time::{Duration, Instant};

use cipherbox_desktop_seams::KeyringCredentialStore;
use cipherbox_engine::seams::CredentialStore;
use cipherbox_engine::testkit::block_on;
use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence};
use zeroize::Zeroizing;

/// How long the substitute backend stalls, standing in for an unlock prompt.
/// Long enough that a caller that ran the call inline cannot come back inside
/// it, short enough to keep the suite quick.
const STALL: Duration = Duration::from_millis(300);

/// A backend whose every operation blocks for [`STALL`], the way a keyring
/// blocked on an "Allow" prompt does. Keyed the way `keyring::Entry` is, so the
/// store's two account labels do not alias onto one secret.
#[derive(Clone, Default)]
struct StallingKeyring {
    secrets: Arc<Mutex<HashMap<Account, Zeroizing<Vec<u8>>>>>,
}

type Account = (String, String);

struct StallingEntry {
    keyring: StallingKeyring,
    account: Account,
}

impl CredentialApi for StallingEntry {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        std::thread::sleep(STALL);
        self.keyring
            .secrets
            .lock()
            .expect("keyring lock")
            .insert(self.account.clone(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        std::thread::sleep(STALL);
        self.keyring
            .secrets
            .lock()
            .expect("keyring lock")
            .get(&self.account)
            .map(|secret| secret.to_vec())
            .ok_or(keyring::Error::NoEntry)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        std::thread::sleep(STALL);
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

impl CredentialBuilderApi for StallingKeyring {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        account: &str,
    ) -> keyring::Result<Box<Credential>> {
        Ok(Box::new(StallingEntry {
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

/// The regression this guards: were the seam to run the keyring call inline,
/// the first poll would return `Ready` only after the backend unblocked, and
/// the engine's event loop would be frozen for exactly that long.
#[test]
fn a_stalled_keyring_never_holds_the_calling_thread() {
    keyring::set_default_credential_builder(Box::new(StallingKeyring::default()));
    let store = KeyringCredentialStore::new("com.cipherbox.desktop.test").expect("worker started");

    let issued = Instant::now();
    let mut store_token = pin!(store.store_refresh_token(b"token"));
    let first = store_token
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    let handed_back = issued.elapsed();

    assert!(
        first.is_pending(),
        "the keyring is still stalled, so the call cannot have completed inline"
    );
    assert!(
        handed_back < STALL,
        "the caller waited {handed_back:?} on a backend stalled for {STALL:?} — \
         the call ran on this thread"
    );

    block_on(store_token).expect("the write ran");
    assert_eq!(
        block_on(store.load_refresh_token()).expect("the load ran"),
        Some(b"token".to_vec())
    );
}
