//! The [`ReceivedShareStore`] every host gets for free, over the durable
//! staging store it already implements.
//!
//! The shape [`RetireLedger`](crate::seams::RetireLedger) set (blueprint/
//! engine.md "Host seams"): a grants-layer contract the engine implements over
//! an existing seam, so the host seam set stays at nine.
//!
//! It rides the staging store's opaque key space rather than its op queue — the
//! queue is FIFO, cancellable, and swept of what it cannot decode at cold start,
//! and a share bookmark is none of those things — and rather than the snapshot
//! cache, which is contractually a cache of what the network can re-serve. Once
//! the mailbox item that delivered a share is acked, nothing re-serves its
//! `pointerReadKey`.

use core::cell::RefCell;

use cipherbox_core::seal::{open_received_shares, seal_received_shares};
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::seams::{SeamError, SeamResult, StagingStore};
use crate::sync::drain::owner_tag;

use super::accept::{ReceivedShareStore, ReceivedSharesList};

/// The staging-key prefix the received-shares list is stored under.
///
/// One key per identity, appended with the owner tag every per-identity durable
/// record this device keeps is scoped by; [`orphan_staging_keys`] treats the
/// whole prefix as referenced, every identity's entry included.
///
/// Kept short: the desktop store spells a staging key as a hex filename, twice
/// its byte length, inside Windows' whole-path budget.
///
/// [`orphan_staging_keys`]: crate::sync::orphan_staging_keys
pub const RECEIVED_SHARES_PREFIX: &[u8] = b"cbx/rs/";

/// The received-shares store the engine ships over a host's [`StagingStore`].
///
/// The list is sealed HPKE-to-self under the session's `enc-subkey` before it
/// reaches the host, so the `pointerReadKey` of every bookmarked scope stays
/// ciphertext at rest.
pub struct StagingReceivedShareStore<'a, St, E> {
    staging: &'a St,
    enc_secret: &'a X25519Secret,
    entropy: &'a RefCell<E>,
}

impl<'a, St: StagingStore, E: Entropy> StagingReceivedShareStore<'a, St, E> {
    /// Wraps a staging store as the received-shares store for one session.
    pub fn new(staging: &'a St, enc_secret: &'a X25519Secret, entropy: &'a RefCell<E>) -> Self {
        Self {
            staging,
            enc_secret,
            entropy,
        }
    }

    /// The staging key this identity's list occupies — the one entry under
    /// [`RECEIVED_SHARES_PREFIX`] that orphan GC must treat as referenced.
    pub fn staging_key(&self) -> Vec<u8> {
        let mut key = RECEIVED_SHARES_PREFIX.to_vec();
        key.extend_from_slice(&owner_tag(self.enc_secret));
        key
    }
}

impl<St: StagingStore, E: Entropy> ReceivedShareStore for StagingReceivedShareStore<'_, St, E> {
    async fn persist(&self, shares: &ReceivedSharesList) -> SeamResult<()> {
        let body = Zeroizing::new(
            shares
                .encode()
                .map_err(|e| SeamError::new(format!("received-shares encode failed: {e}")))?,
        );
        let mut ephemeral = Zeroizing::new([0u8; 32]);
        self.entropy
            .borrow_mut()
            .fill(ephemeral.as_mut_slice())
            .map_err(|e| SeamError::new(e.message().to_string()))?;
        // A seam that reports success having written nothing would reuse one
        // ephemeral across every version of this list — a confidentiality break,
        // so it fails closed before the seal.
        if ephemeral.iter().all(|byte| *byte == 0) {
            return Err(SeamError::new(
                "entropy seam produced an all-zero HPKE ephemeral",
            ));
        }
        let blob = seal_received_shares(self.enc_secret, &ephemeral, &body)
            .map_err(|e| SeamError::new(format!("received-shares seal failed: {e}")))?;
        self.staging
            .put_staged_bytes(&self.staging_key(), &blob)
            .await
    }

    async fn load(&self) -> SeamResult<ReceivedSharesList> {
        let Some(blob) = self.staging.staged_bytes(&self.staging_key()).await? else {
            return Ok(ReceivedSharesList::new());
        };
        let body = open_received_shares(self.enc_secret, &blob)
            .map_err(|e| SeamError::new(format!("received-shares open failed: {e}")))?;
        ReceivedSharesList::decode(&body)
            .map_err(|e| SeamError::new(format!("received-shares decode failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use cipherbox_core::seal::Permission;
    use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
    use cipherbox_core::suite::secret::SecretBytes;

    use super::*;
    use crate::entropy::EntropyError;
    use crate::grants::ReceivedShare;
    use crate::sync::orphan_staging_keys;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on, conformance};

    const POINTER_KEY: [u8; 32] = [0xE7; 32];

    fn enc(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    fn one_share() -> ReceivedSharesList {
        let mut shares = ReceivedSharesList::new();
        shares.reconcile(ReceivedShare {
            scope_root_name: b"k51scoperoot".to_vec(),
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "Shared Folder".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new(POINTER_KEY),
        });
        shares
    }

    /// Reports success while writing nothing, so the caller's ephemeral stays
    /// all-zero — a seam that would silently reuse one HPKE ephemeral forever.
    struct SilentEntropy;

    impl Entropy for SilentEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Ok(())
        }
    }

    struct FailingEntropy;

    impl Entropy for FailingEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::new("no entropy"))
        }
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

        let stored = block_on(staging.staged_bytes(&store.staging_key()))
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

        // Same key space, unreadable bytes: reporting empty would let the next
        // persist overwrite every bookmark behind them.
        block_on(staging.put_staged_bytes(&store.staging_key(), b"not a sealed list"))
            .expect("clobber");
        assert!(
            block_on(store.load()).is_err(),
            "an unreadable stored list is an error, never an empty list"
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
            block_on(staging.staged_bytes(&store.staging_key()))
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
            block_on(orphan_staging_keys(&staging, &[])).expect("sweep"),
            vec![b"upload-residue".to_vec()],
            "only the residue is collected, never the received-shares list"
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
        assert!(block_on(store.persist(&ReceivedSharesList::new())).is_err());
        assert_eq!(
            block_on(store.load()).expect("load").len(),
            1,
            "a failed persist never clears the list it could not replace"
        );
    }
}
