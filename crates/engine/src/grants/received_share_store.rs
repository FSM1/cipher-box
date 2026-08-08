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
use crate::seams::{SeamError, SeamResult, StagingStore};
use crate::sync::drain::owner_tag;
use cipherbox_core::seal::{open_received_shares, seal_received_shares};
use cipherbox_core::suite::x25519::X25519Secret;

use super::accept::{ReceivedShareStore, ReceivedSharesList, StoredList};

/// The staging-key prefix the received-shares slots are stored under.
///
/// Scoped by the owner tag every per-identity durable record this device keeps
/// is scoped by; [`orphan_staging_keys`] treats the whole prefix as referenced,
/// every identity's slots included.
///
/// Kept short: the desktop store spells a staging key as a hex filename, twice
/// its byte length, inside Windows' whole-path budget.
///
/// [`orphan_staging_keys`]: crate::sync::orphan_staging_keys
pub const RECEIVED_SHARES_PREFIX: &[u8] = b"cbx/rs/";

/// The two slot suffixes a persist alternates between.
///
/// [`StagingStore::put_staged_bytes`] promises the write replaces the previous
/// bytes, not that the replacement is atomic — a host that truncates before it
/// writes can be interrupted and leave a partial blob. With one key that is
/// terminal: the list would never open again, and the mailbox items that
/// delivered those shares are acked and gone. A persist therefore always writes
/// the slot that is *not* currently newest, so the readable one survives the
/// interruption untouched.
const SLOTS: [u8; 2] = [b'a', b'b'];

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

    /// The staging keys this identity's slots occupy — the entries under
    /// [`RECEIVED_SHARES_PREFIX`] that orphan GC must treat as referenced.
    pub fn slot_keys(&self) -> [Vec<u8>; 2] {
        let tag = owner_tag(self.enc_secret);
        SLOTS.map(|slot| {
            let mut key = RECEIVED_SHARES_PREFIX.to_vec();
            key.extend_from_slice(&tag);
            key.push(slot);
            key
        })
    }

    /// Read one slot. A [`SeamError`] is a host read failure; bytes this build
    /// cannot open or decode are [`Slot::Unreadable`], which is state to be
    /// preserved rather than an outage to be retried.
    async fn read_slot(&self, key: &[u8]) -> SeamResult<Slot> {
        let Some(blob) = self.staging.staged_bytes(key).await? else {
            return Ok(Slot::Empty);
        };
        let Ok(body) = open_received_shares(self.enc_secret, &blob) else {
            return Ok(Slot::Unreadable);
        };
        Ok(match StoredList::decode(&body) {
            Ok(stored) => Slot::Held(stored),
            Err(_) => Slot::Unreadable,
        })
    }

    async fn read_slots(&self) -> SeamResult<[Slot; 2]> {
        let keys = self.slot_keys();
        Ok([
            self.read_slot(&keys[0]).await?,
            self.read_slot(&keys[1]).await?,
        ])
    }
}

/// What one slot holds.
enum Slot {
    /// Nothing has been written here.
    Empty,
    /// Bytes this session cannot open or decode — a torn write, or another
    /// identity's. Never treated as empty: overwriting the last readable slot
    /// on the strength of an unreadable one is how a list is lost.
    Unreadable,
    /// A readable list at its revision.
    Held(StoredList),
}

impl Slot {
    fn revision(&self) -> Option<u64> {
        match self {
            Slot::Held(stored) => Some(stored.revision),
            _ => None,
        }
    }
}

impl<St: StagingStore, E: Entropy> ReceivedShareStore for StagingReceivedShareStore<'_, St, E> {
    async fn persist(&self, shares: &ReceivedSharesList) -> SeamResult<()> {
        let slots = self.read_slots().await?;
        let newest = slots[0].revision().max(slots[1].revision());
        // Write over the stale slot, so an interrupted write cannot take the
        // readable one with it. Both unreadable is the one case with no safe
        // target: either write would drop state this build cannot read.
        let target = match (&slots[0], &slots[1]) {
            (Slot::Unreadable, Slot::Unreadable) => {
                return Err(SeamError::new(
                    "received-shares: both slots are unreadable, refusing to overwrite either",
                ));
            }
            (a, b) if a.revision() > b.revision() => 1,
            _ => 0,
        };

        let body = StoredList::encode(shares, newest.unwrap_or(0).saturating_add(1))
            .map_err(|e| SeamError::new(format!("received-shares encode failed: {e}")))?;
        let ephemeral = fresh_ephemeral(&mut *self.entropy.borrow_mut())
            .map_err(|e| SeamError::new(e.message().to_string()))?;
        let blob = seal_received_shares(self.enc_secret, &ephemeral, &body)
            .map_err(|e| SeamError::new(format!("received-shares seal failed: {e}")))?;
        self.staging
            .put_staged_bytes(&self.slot_keys()[target], &blob)
            .await
    }

    async fn load(&self) -> SeamResult<ReceivedSharesList> {
        let slots = self.read_slots().await?;
        // The higher revision wins; a torn slot beside a readable one loses
        // rather than bricking the list. Only when nothing is readable and
        // something is stored does this fail closed — reporting empty there
        // would let the next persist overwrite bookmarks it never read.
        match slots {
            [Slot::Held(a), Slot::Held(b)] => Ok(if a.revision >= b.revision {
                a.shares
            } else {
                b.shares
            }),
            [Slot::Held(held), _] | [_, Slot::Held(held)] => Ok(held.shares),
            [Slot::Unreadable, _] | [_, Slot::Unreadable] => Err(SeamError::new(
                "received-shares: the stored list did not open",
            )),
            [Slot::Empty, Slot::Empty] => Ok(ReceivedSharesList::new()),
        }
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

        let stored = block_on(staging.staged_bytes(&store.slot_keys()[0]))
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
        block_on(staging.put_staged_bytes(&store.slot_keys()[0], b"not a sealed list"))
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
            block_on(staging.staged_bytes(&store.slot_keys()[0]))
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

    /// The failure the two-slot layout exists for: a host whose write is not
    /// failure-atomic (the browser seam truncates before it writes, then drops
    /// the file) must not be able to take the readable list with it.
    #[test]
    fn a_lost_write_never_destroys_the_readable_list() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x81);
        let entropy = RefCell::new(SeededEntropy::new(19));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&one_share())).expect("first persist");
        let first_slot = store.slot_keys()[0].clone();

        // The next persist targets the *other* slot, so wiping the slot it
        // writes leaves the original readable.
        block_on(store.persist(&ReceivedSharesList::new())).expect("second persist");
        assert!(block_on(store.load()).expect("load").is_empty());
        block_on(staging.remove_staged_bytes(&store.slot_keys()[1])).expect("lose the new slot");
        assert_eq!(
            block_on(store.load()).expect("load").len(),
            1,
            "the surviving slot still holds the older list"
        );
        assert!(
            block_on(staging.staged_bytes(&first_slot))
                .expect("staged")
                .is_some(),
            "the first write was never the target of the second"
        );
    }

    /// A torn slot beside a readable one loses; it does not brick the list.
    #[test]
    fn a_torn_slot_loses_to_the_readable_one() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x91);
        let entropy = RefCell::new(SeededEntropy::new(21));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&one_share())).expect("persist");

        block_on(staging.put_staged_bytes(&store.slot_keys()[1], b"half a blob")).expect("tear");
        assert_eq!(
            block_on(store.load()).expect("load").len(),
            1,
            "the readable slot wins over a torn one"
        );
        // And the next persist overwrites the torn slot, never the good one.
        block_on(store.persist(&one_share())).expect("persist over the torn slot");
        assert_eq!(block_on(store.load()).expect("load").len(), 1);
    }

    /// The higher revision wins, so restoring a stale slot cannot silently roll
    /// the bookmark list back.
    #[test]
    fn the_higher_revision_wins_a_load() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0xA1);
        let entropy = RefCell::new(SeededEntropy::new(25));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&one_share())).expect("revision 1");
        let stale = block_on(staging.staged_bytes(&store.slot_keys()[0]))
            .expect("staged")
            .expect("slot a holds revision 1");

        block_on(store.persist(&ReceivedSharesList::new())).expect("revision 2");
        // Put the older list back in the slot it came from: both slots readable,
        // and the newer revision must still win.
        block_on(staging.put_staged_bytes(&store.slot_keys()[0], &stale)).expect("restore");
        assert!(
            block_on(store.load()).expect("load").is_empty(),
            "revision 2 wins over the restored revision 1"
        );
    }

    /// Both slots unreadable is the one state with no safe write target: either
    /// would drop bookmarks this build cannot read.
    #[test]
    fn a_persist_refuses_when_neither_slot_is_readable() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0xB1);
        let entropy = RefCell::new(SeededEntropy::new(27));
        let store = StagingReceivedShareStore::new(&staging, &secret, &entropy);
        for key in store.slot_keys() {
            block_on(staging.put_staged_bytes(&key, b"not a sealed list")).expect("clobber");
        }
        assert!(block_on(store.load()).is_err());
        assert!(block_on(store.persist(&one_share())).is_err());
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
