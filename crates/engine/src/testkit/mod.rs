//! The engine test kit (`test-kit` feature): in-memory seam fakes, the
//! virtual-clock scheduler, seeded entropy, and the per-seam conformance
//! kits (blueprint/testing.md "crates/engine — seam fakes and the
//! simulation harness", "Seam conformance kits").
//!
//! No network, no docker, no wall clock: engines built on [`FakeWorld`]
//! devices run entirely in memory on virtual time, so CAS races and
//! multi-day EOL timelines execute in milliseconds. Multiple devices share
//! one fake record store, mailbox hub, and clock — the seed of the
//! simulation harness.
//!
//! Host crates enable this feature from dev-dependencies and run each
//! [`conformance`] kit against their real seam implementations: browser
//! seams inside the merge-blocking browser suite, desktop seams in cargo
//! tests. One contract, every platform.

pub mod account;
pub mod checks;
pub mod conformance;
mod content;
mod entropy;
mod executor;
pub mod fakes;
pub mod name_law;
mod owner_root;
pub mod reject;
pub mod retire_entry;
pub mod rotation;
mod world;

pub use account::retire_targets;
pub use content::{
    block_store, doomed_version, frame_version, frame_version_with, gateway, requested_cid, serve,
};
pub use entropy::{FailingEntropy, SeededEntropy, SilentAtWidth, SilentEntropy};

/// A preserved-field map of `bytes` padding under one key — the
/// attacker-sized run a committed write grantee puts on any structure it
/// authors, for a test that must prove the carry does not ride forward.
pub fn padding(bytes: usize) -> cipherbox_core::seal::PreservedFields {
    [(
        "zpad".to_string(),
        cipherbox_core::codec::Value::Bytes(vec![0u8; bytes]),
    )]
    .into_iter()
    .collect()
}

/// `list` with no scope pointer name on any bookmark, the shape of a bookmark
/// stored before the owner posted the name, and so with no link hold.
pub fn without_scope_pointer_names(
    list: &crate::grants::ReceivedSharesList,
) -> crate::grants::ReceivedSharesList {
    let mut bare = crate::grants::ReceivedSharesList::new();
    for share in list.iter() {
        bare.reconcile(crate::grants::ReceivedShare {
            scope_pointer_name: None,
            ..share.clone()
        });
    }
    bare
}

/// The `(ended, grantCut)` values of `share`.
pub fn bookmark_marks(share: &crate::grants::ReceivedShare) -> (Option<u64>, Option<u64>) {
    (share.ended, share.grant_cut)
}

/// Add a bookmark of scope `scope_id` with `marks` to the list that
/// `enc_secret` seals in `staging`, as a later release writes it, and return
/// its key.
pub fn plant_marked_bookmark<S: crate::seams::StagingStore>(
    staging: &S,
    enc_secret: &cipherbox_core::suite::x25519::X25519Secret,
    scope_id: [u8; 16],
    marks: (Option<u64>, Option<u64>),
) -> crate::grants::BookmarkKey {
    use crate::grants::ReceivedShareStore;
    let entropy = core::cell::RefCell::new(SeededEntropy::new(0x5b));
    let store = crate::grants::received_share_store::StagingReceivedShareStore::new(
        staging, enc_secret, &entropy,
    );
    let mut list = block_on(store.load()).expect("the stored list reads");
    let share = crate::grants::ReceivedShare {
        scope_root_name: b"k51plantedroot".to_vec(),
        scope_id,
        sharer_identity_pk: [0x02; cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN],
        display_name: "planted".into(),
        permission: cipherbox_core::seal::Permission::Read,
        pointer_read_key: cipherbox_core::suite::secret::SecretBytes::new([0x5b; 32]),
        scope_pointer_name: None,
        grant_cut: None,
        ended: None,
    };
    let key = share.key();
    list.reconcile(share);
    list.mark_for_test(&key, marks);
    block_on(store.persist(&list)).expect("the planted list persists");
    key
}

/// Set `marks` on the bookmark under `key` in the list that `enc_secret`
/// seals in `staging`, as a later pass writes them.
pub fn mark_bookmark<S: crate::seams::StagingStore>(
    staging: &S,
    enc_secret: &cipherbox_core::suite::x25519::X25519Secret,
    key: &crate::grants::BookmarkKey,
    marks: (Option<u64>, Option<u64>),
) {
    use crate::grants::ReceivedShareStore;
    let entropy = core::cell::RefCell::new(SeededEntropy::new(0x5c));
    let store = crate::grants::received_share_store::StagingReceivedShareStore::new(
        staging, enc_secret, &entropy,
    );
    let mut list = block_on(store.load()).expect("the stored list reads");
    list.mark_for_test(key, marks);
    block_on(store.persist(&list)).expect("the marked list persists");
}

/// The write-epoch lease of one scope, held for a test as a publish of this
/// device holds it, so a sighting raise of that scope defers until the drop.
pub struct HeldWriteEpochLease {
    _lease: crate::gate::floor::WriteEpochLease,
}

/// Take `scope_id`'s write-epoch lease, or `None` when it is already held.
pub fn hold_write_epoch_lease(scope_id: &[u8; 16]) -> Option<HeldWriteEpochLease> {
    crate::gate::floor::acquire_write_epoch_lease(scope_id)
        .map(|lease| HeldWriteEpochLease { _lease: lease })
}

/// Compiles only while the bearer a request carries wipes itself on drop.
/// The proof is the type, so the test never reads the credential.
#[track_caller]
pub fn assert_bearer_wipes_on_drop(request: &crate::seams::HttpRequest) {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let (_, value) = request
        .headers
        .iter()
        .find(|(name, _)| name == crate::seams::AUTHORIZATION)
        .expect("the request carries a bearer");
    wipes_on_drop(value);
}

pub use executor::{block_on, block_on_while_ticking, poll_tasks_once, poll_tasks_until_parked};
pub use owner_root::{
    CARRIED_WRITE_HISTORY_LINK, OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY,
    OWNER_ROOT_PSEUDONYM_SEED, OWNER_ROOT_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED,
    OwnerRootFixture, OwnerRootSpec, owner_root_fixture, owner_root_fixture_at,
    owner_root_fixture_sealed, owner_root_fixture_seeded, owner_root_pseudonym, reencoded,
    with_cut_epoch,
};
pub use owner_root::{assert_section_authenticates, resign_section};
pub use world::{DurableState, FakeDevice, FakeSeamTypes, FakeWorld};
