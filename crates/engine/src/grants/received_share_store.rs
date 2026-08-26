//! The [`ReceivedShareStore`](super::ReceivedShareStore) every host gets for
//! free, over the durable staging store it already implements — the shape
//! [`RetireLedger`](crate::seams::RetireLedger) set.
//!
//! It rides the staging store's opaque key space rather than its op queue — the
//! queue is FIFO, cancellable, and swept of what it cannot decode at cold start,
//! and a share bookmark is none of those things — and rather than the snapshot
//! cache, which is contractually a cache of what the network can re-serve.

use core::cell::RefCell;

use crate::entropy::{Entropy, fresh_ephemeral};
use crate::seams::StagingStore;
use crate::sync::owner_scoped_key;
use cipherbox_core::seal::{OwnerLocalKind, open_owner_local, seal_owner_local};
use cipherbox_core::suite::x25519::X25519Secret;

use super::accept::{
    MAX_RECEIVED_SHARES, ReceivedShareStore, ReceivedShareStoreError, ReceivedSharesCodecError,
    ReceivedSharesList, decode_stored_list, encode_stored_list,
};

/// The staging-key prefix the received-shares list is stored under, scoped per
/// identity by [`owner_scoped_key`]. `is_bookkeeping` treats the whole prefix as
/// referenced.
///
/// Kept short: the desktop store spells a staging key as a hex filename, twice
/// its byte length, inside Windows' whole-path budget — the bound every prefix
/// in this space is held to.
pub const RECEIVED_SHARES_PREFIX: &[u8] = b"cbx/rs/";

/// The received-shares store the engine ships over a host's [`StagingStore`].
///
/// One staging key holds the whole list; the replacement is failure-atomic at
/// the seam ([`StagingStore::put_staged_bytes`]).
///
/// The list is sealed HPKE-to-self under the session's `enc-subkey` before it
/// reaches the host, so the `pointerReadKey` of every bookmarked scope stays
/// ciphertext at rest.
pub struct StagingReceivedShareStore<'a, St, E> {
    staging: &'a St,
    enc_secret: &'a X25519Secret,
    entropy: &'a RefCell<E>,
    staging_key: Vec<u8>,
}

impl<'a, St: StagingStore, E: Entropy> StagingReceivedShareStore<'a, St, E> {
    /// Wraps a staging store as the received-shares store for one session.
    pub fn new(staging: &'a St, enc_secret: &'a X25519Secret, entropy: &'a RefCell<E>) -> Self {
        Self {
            staging,
            enc_secret,
            entropy,
            staging_key: owner_scoped_key(RECEIVED_SHARES_PREFIX, enc_secret),
        }
    }

    /// The staging key this identity's list occupies — the entry under
    /// [`RECEIVED_SHARES_PREFIX`] that orphan GC must treat as referenced.
    pub fn staging_key(&self) -> &[u8] {
        &self.staging_key
    }
}

impl<St: StagingStore, E: Entropy> ReceivedShareStore for StagingReceivedShareStore<'_, St, E> {
    async fn persist(&self, shares: &ReceivedSharesList) -> Result<(), ReceivedShareStoreError> {
        if shares.len() > MAX_RECEIVED_SHARES {
            return Err(ReceivedShareStoreError::Full);
        }
        let body = encode_stored_list(shares).map_err(ReceivedShareStoreError::Encode)?;
        let ephemeral = fresh_ephemeral(&mut *self.entropy.borrow_mut())
            .map_err(ReceivedShareStoreError::Entropy)?;
        let blob = seal_owner_local(
            self.enc_secret,
            OwnerLocalKind::ReceivedShares,
            &ephemeral,
            &body,
        )
        .map_err(ReceivedShareStoreError::Seal)?;
        self.staging
            .put_staged_bytes(self.staging_key(), &blob)
            .await?;
        Ok(())
    }

    async fn load(&self) -> Result<ReceivedSharesList, ReceivedShareStoreError> {
        let Some(blob) = self.staging.staged_bytes(self.staging_key()).await? else {
            return Ok(ReceivedSharesList::new());
        };
        let body = open_owner_local(self.enc_secret, OwnerLocalKind::ReceivedShares, &blob)
            .map_err(|e| {
                ReceivedShareStoreError::Unreadable(ReceivedSharesCodecError::DidNotOpen(e))
            })?;
        decode_stored_list(&body).map_err(ReceivedShareStoreError::Unreadable)
    }
}

#[cfg(test)]
mod tests {
    use cipherbox_core::seal::Permission;
    use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
    use cipherbox_core::suite::secret::SecretBytes;

    use super::*;
    use crate::grants::ReceivedShare;
    use crate::sync::orphan_staging_keys;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{FailingEntropy, SeededEntropy, SilentEntropy, block_on, conformance};

    const POINTER_KEY: [u8; 32] = [0xE7; 32];

    fn enc(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    fn one_share() -> ReceivedSharesList {
        let mut shares = ReceivedSharesList::new();
        shares.reconcile(ReceivedShare {
            scope_root_name: b"k51scoperoot".to_vec(),
            scope_id: [0x5c; 16],
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "Shared Folder".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new(POINTER_KEY),
        });
        shares
    }

    #[test]
    fn the_staging_store_passes_the_received_share_store_kit() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x11);
        let entropy = RefCell::new(SeededEntropy::new(9));
        block_on(conformance::received_share_store::check(async || {
            StagingReceivedShareStore::new(&staging, &secret, &entropy)
        }));
    }

    #[test]
    fn the_persisted_blob_never_holds_the_pointer_read_key_in_the_clear() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x21);
        let entropy = RefCell::new(SeededEntropy::new(3));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&one_share())).expect("persist");

        let stored = block_on(staging.staged_bytes(store.staging_key()))
            .expect("staged bytes")
            .expect("the list is stored");
        assert!(
            !stored
                .windows(POINTER_KEY.len())
                .any(|w| w == POINTER_KEY.as_slice()),
            "the pointer read key must never sit in host storage in the clear"
        );
        assert!(
            !stored.windows(12).any(|w| w == b"k51scoperoot"),
            "the bookmarked scope-root name is sealed too"
        );
    }

    #[test]
    fn a_list_this_session_cannot_open_fails_closed_rather_than_reading_empty() {
        let staging = InMemoryStagingStore::default();
        let mine = enc(0x31);
        let entropy = RefCell::new(SeededEntropy::new(5));
        let store = StagingReceivedShareStore::new(&staging, &mine, &entropy);
        block_on(store.persist(&one_share())).expect("persist");

        // Same key space, unreadable bytes.
        block_on(staging.put_staged_bytes(store.staging_key(), b"not a sealed list"))
            .expect("clobber");
        assert!(
            matches!(
                block_on(store.load()),
                Err(ReceivedShareStoreError::Unreadable(
                    ReceivedSharesCodecError::DidNotOpen(_)
                ))
            ),
            "an unreadable stored list is a trust verdict, never a retryable seam failure"
        );
    }

    /// The other arm of the same rule: bytes that open under this session's key
    /// but carry a body grammar this build does not read are still state, not an
    /// empty list.
    #[test]
    fn a_stored_list_this_build_cannot_decode_fails_closed_rather_than_reading_empty() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x32);
        let entropy = RefCell::new(SeededEntropy::new(37));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&one_share())).expect("persist");

        let ephemeral = fresh_ephemeral(&mut SeededEntropy::new(41)).expect("ephemeral");
        let sealed = seal_owner_local(
            &secret,
            OwnerLocalKind::ReceivedShares,
            &ephemeral,
            b"opens, but is not a stored list",
        )
        .expect("seal");
        block_on(staging.put_staged_bytes(store.staging_key(), &sealed)).expect("clobber");
        assert!(
            matches!(
                block_on(store.load()),
                Err(ReceivedShareStoreError::Unreadable(
                    ReceivedSharesCodecError::Codec(_)
                ))
            ),
            "a body this build cannot decode is a trust verdict, never an empty list"
        );
    }

    /// The store names its owner-local kind, so a sibling store's blob is
    /// unreadable state even when its body is a list this build decodes
    /// perfectly — separation is the kind, not the body grammar.
    #[test]
    fn a_blob_from_another_owner_local_store_fails_closed() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x33);
        let entropy = RefCell::new(SeededEntropy::new(43));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);

        let ephemeral = fresh_ephemeral(&mut SeededEntropy::new(47)).expect("ephemeral");
        let body = encode_stored_list(&one_share()).expect("encode");
        let sealed = seal_owner_local(&secret, OwnerLocalKind::ContactBook, &ephemeral, &body)
            .expect("seal");
        block_on(staging.put_staged_bytes(store.staging_key(), &sealed)).expect("stage");
        assert!(
            matches!(
                block_on(store.load()),
                Err(ReceivedShareStoreError::Unreadable(
                    ReceivedSharesCodecError::DidNotOpen(_)
                ))
            ),
            "another store's blob is a trust verdict, never a list to adopt"
        );
    }

    #[test]
    fn another_identitys_list_is_not_this_sessions_list() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(7));
        let alice = enc(0x41);
        let bob = enc(0x42);
        block_on(StagingReceivedShareStore::new(&staging, &alice, &entropy).persist(&one_share()))
            .expect("persist");

        let bobs = StagingReceivedShareStore::new(&staging, &bob, &entropy);
        assert!(
            block_on(bobs.load()).expect("load").is_empty(),
            "one store is shared across accounts; a bookmark must not cross identities"
        );
    }

    #[test]
    fn an_all_zero_ephemeral_fails_closed_before_the_seal() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x51);
        let entropy = RefCell::new(SilentEntropy);
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        assert!(block_on(store.persist(&one_share())).is_err());
        assert!(
            block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged bytes")
                .is_none(),
            "a refused seal writes nothing"
        );
    }

    /// The list shares a key space with staged upload blocks, and its key is
    /// referenced by no op — so without the prefix carve-out orphan GC would
    /// collect every accepted share on the next sweep.
    #[test]
    fn orphan_gc_never_collects_the_persisted_list() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x71);
        let entropy = RefCell::new(SeededEntropy::new(13));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&one_share())).expect("persist");
        block_on(staging.put_staged_bytes(b"upload-residue", b"stale")).expect("stage");

        assert_eq!(
            block_on(async {
                let staged = staging.staged_keys().await.expect("list");
                orphan_staging_keys(&staging, &staged, &[]).await
            })
            .expect("sweep"),
            vec![b"upload-residue".to_vec()],
            "only the residue is collected, never the received-shares list"
        );
    }

    /// The failure a durable whole-set record must survive: the host loses the
    /// replacement write. `put_staged_bytes` is failure-atomic, so the list the
    /// store already holds is what the next load must still read.
    #[test]
    fn a_lost_write_never_destroys_the_readable_list() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x81);
        let entropy = RefCell::new(SeededEntropy::new(19));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&one_share())).expect("first persist");
        let stored = block_on(staging.staged_bytes(store.staging_key()))
            .expect("staged")
            .expect("the list is stored");

        staging.interrupt_staged_write_after(store.staging_key(), 0);
        assert!(
            matches!(
                block_on(store.persist(&ReceivedSharesList::new())),
                Err(ReceivedShareStoreError::Seam(_))
            ),
            "a backing that dropped the write is the one failure a host may retry"
        );
        assert_eq!(
            block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .as_deref(),
            Some(stored.as_slice()),
            "the lost replacement left the stored blob byte-identical"
        );
        assert_eq!(
            block_on(store.load()).expect("load").len(),
            1,
            "the list the store already held is still the one it serves"
        );
    }

    #[test]
    fn an_entropy_failure_leaves_the_stored_list_untouched() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x61);
        let good = RefCell::new(SeededEntropy::new(11));
        block_on(StagingReceivedShareStore::new(&staging, &secret, &good).persist(&one_share()))
            .expect("persist");

        let broken = RefCell::new(FailingEntropy);
        let store = StagingReceivedShareStore::new(&staging, &secret, &broken);
        assert!(matches!(
            block_on(store.persist(&ReceivedSharesList::new())),
            Err(ReceivedShareStoreError::Entropy(_))
        ));
        assert_eq!(
            block_on(store.load()).expect("load").len(),
            1,
            "a failed persist never clears the list it could not replace"
        );
    }
}
