//! The durable record of the scope-exit cuts this device still owes
//! (CONTEXT.md "Cross-scope move"; blueprint/engine.md "Grantee scope-exit
//! rotations").
//!
//! A move out of a granted scope owes that scope a cut. The op that owed it
//! leaves the queue the moment it publishes, so from the ack onwards nothing
//! but this record names the scope again. A session that held the debt in
//! memory alone left the grantee the move walked away from holding a live read
//! seed as soon as the device restarted, which is a revocation that never
//! happened rather than state a later pass re-derives.
//!
//! One key per identity, under the owner tag every durable bookkeeping surface
//! is scoped by ([`owner_scoped_key`]), sealed under
//! [`OwnerLocalKind::ScopeExitDebt`] as the tier rule requires
//! ([`crate::sync::bookkeeping`]): the value associates this owner with the
//! scope roots a share of theirs was granted at, and an entry that will not
//! open is refused rather than cut. The structure counts no freshness
//! ([`seal_owner_local`](cipherbox_core::seal::seal_owner_local)), which this
//! kind can carry: a replayed entry only ever re-owes a cut, and over-rotating
//! revokes more than the owner asked rather than less.

use core::cell::RefCell;
use std::collections::BTreeSet;

use cipherbox_core::seal::OwnerLocalKind;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::facade::NodeId;
use crate::rotation::{RotateError, ScopeExitRotator, consume_scope_exit_triggers};
use crate::seams::{SeamResult, StagingStore};
use crate::sync::BookkeepingSeal;
use crate::sync::drain::{owed_cuts, owner_scoped_key};

/// The staging-key prefix the owed cuts are journaled under.
/// [`orphan_staging_keys`](crate::sync::orphan_staging_keys) treats the whole
/// prefix as referenced, every owner's entry included.
///
/// Kept short: the desktop store spells a key as a hex filename, at twice its
/// byte length.
pub const SCOPE_EXIT_DEBT_PREFIX: &[u8] = b"cbx/sx/";

/// The entry format tag. The staging store is shared with whatever build wrote
/// it, so bytes that merely happen to parse must not read as a debt.
const FORMAT_V1: u8 = 1;

/// The engine's location-independent node id.
const NODE_ID_LEN: usize = 16;

/// Drive every cut this device owes and answer with the roots still owed after
/// the pass, each with a key-material-free classification of what stopped it.
///
/// The durable record is folded into `session` first and written back after, so
/// a root leaves the store only once its cut is durable, and a root a restart
/// inherited is driven by the session that finds it. Which roots are owed at all
/// is [`owed_cuts`]'s rule.
pub(crate) async fn settle_owed_cuts<St: StagingStore, R: ScopeExitRotator>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
    exits: &R,
    session: &RefCell<BTreeSet<NodeId>>,
    vault_root: NodeId,
) -> Vec<(NodeId, &'static str)> {
    adopt_owed_cuts(staging, seal, enc_secret, session).await;
    if session.borrow().is_empty() {
        return Vec::new();
    }
    let owed = owed_cuts(&session.borrow(), vault_root);
    let cut = consume_scope_exit_triggers(exits, &owed).await;
    let held = {
        let mut held = session.borrow_mut();
        held.remove(&vault_root);
        for (root, _) in &cut.rotated {
            held.remove(root);
        }
        // A floor raise that failed leaves the cut itself published
        // ([`rotate_scope`](crate::rotation::rotate_scope)), so re-driving it
        // would mint a second epoch nothing asked for.
        for (root, error) in &cut.failed {
            if matches!(error, RotateError::Floor(_)) {
                held.remove(root);
            }
        }
        held.clone()
    };
    record_owed_cuts(staging, seal, enc_secret, &held).await;
    cut.failed
        .iter()
        .filter(|(root, _)| held.contains(root))
        .map(|(root, error)| (*root, error.check()))
        .collect()
}

/// Take on one more owed cut, durably, the moment the crossing that owes it is
/// committed.
///
/// Written here rather than only at the settle: everything from the crossing's
/// ack onwards is a window a crash leaves the scope uncut, and the op that owed
/// the cut is out of the queue by then.
pub(crate) async fn owe_cut<St: StagingStore>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
    session: &RefCell<BTreeSet<NodeId>>,
    scope_root: NodeId,
) {
    let owed = {
        let mut session = session.borrow_mut();
        session.insert(scope_root);
        session.clone()
    };
    record_owed_cuts(staging, seal, enc_secret, &owed).await;
}

/// Fold the durable debt into this session's owed set.
///
/// The restart path: an op that has already published has left the queue, so no
/// replay re-supplies its trigger and this record is the only thing that still
/// names the scope the move left.
async fn adopt_owed_cuts<St: StagingStore>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
    session: &RefCell<BTreeSet<NodeId>>,
) {
    let Ok(Some(blob)) = staging.staged_bytes(&scope_exit_debt_key(enc_secret)).await else {
        return;
    };
    let Some(owed) = open_owed_cuts(seal, &blob) else {
        return;
    };
    session.borrow_mut().extend(owed);
}

/// Write `owed` through to the staging store, removing the record once nothing
/// is owed.
///
/// Best effort, and deliberately: the session's own set drives every cut this
/// pass whatever the store answers, and a debt held in memory alone is the
/// state this record improves on rather than a reason to fail the op that owed
/// it.
pub(crate) async fn record_owed_cuts<St: StagingStore>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
    owed: &BTreeSet<NodeId>,
) {
    let key = scope_exit_debt_key(enc_secret);
    if owed.is_empty() {
        let _ = staging.remove_staged_bytes(&key).await;
        return;
    }
    let Ok(blob) = seal_owed_cuts(seal, owed) else {
        return;
    };
    let _ = staging.put_staged_bytes(&key, &blob).await;
}

/// This identity's one scope-exit debt key.
#[must_use]
pub fn scope_exit_debt_key(enc_secret: &X25519Secret) -> Vec<u8> {
    owner_scoped_key(SCOPE_EXIT_DEBT_PREFIX, enc_secret)
}

/// The owed set as the staging store holds it: the encoded roots, sealed.
pub fn seal_owed_cuts(seal: BookkeepingSeal<'_>, owed: &BTreeSet<NodeId>) -> SeamResult<Vec<u8>> {
    seal.seal(OwnerLocalKind::ScopeExitDebt, &encode_owed(owed))
}

/// The stored owed set, or `None` for bytes this identity's key and this
/// build's grammar do not both accept — which read as no record rather than as
/// a debt of their own.
#[must_use]
pub fn open_owed_cuts(seal: BookkeepingSeal<'_>, blob: &[u8]) -> Option<BTreeSet<NodeId>> {
    decode_owed(&seal.open(OwnerLocalKind::ScopeExitDebt, blob)?)
}

/// The record's own encoding, inside the seal: the format tag, then each root's
/// id at its fixed width, ascending.
///
/// The tag is written here and a `BTreeSet<NodeId>` is whole ids in order, so
/// this encoding cannot produce a shape [`decode_owed`] refuses (AGENTS.md
/// rule 8).
///
/// Zeroizing because the plaintext side of a sealed value is what the tier
/// exists to keep off the host ([`crate::sync::bookkeeping`]).
fn encode_owed(owed: &BTreeSet<NodeId>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(1 + owed.len() * NODE_ID_LEN));
    out.push(FORMAT_V1);
    for root in owed {
        out.extend_from_slice(&root.0);
    }
    out
}

/// The roots an entry names, or `None` for a tag this build does not write or a
/// tail that is not whole ids.
fn decode_owed(bytes: &[u8]) -> Option<BTreeSet<NodeId>> {
    let rest = bytes.strip_prefix(&[FORMAT_V1][..])?;
    if rest.len() % NODE_ID_LEN != 0 {
        return None;
    }
    Some(
        rest.chunks_exact(NODE_ID_LEN)
            .map(|id| NodeId(id.try_into().expect("a chunk of exactly one node id")))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::rotation::{RotationOutcome, RotationPublishError};
    use crate::seams::SeamError;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on};

    /// The publish failure a refused cut answers with.
    const NOT_PUBLISHED: RotationPublishError = RotationPublishError::NotPublished;

    fn secret(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 16])
    }

    fn owed() -> BTreeSet<NodeId> {
        BTreeSet::from([node(1), node(2)])
    }

    /// The round trip a restarted session depends on: what one pass sealed is
    /// what the next one drives.
    #[test]
    fn a_sealed_debt_opens_as_the_roots_it_named() {
        let entropy = RefCell::new(SeededEntropy::new(3));
        let mine = secret(9);
        let seal = BookkeepingSeal::new(&mine, &entropy);

        let blob = seal_owed_cuts(seal, &owed()).expect("the debt seals");

        assert_eq!(open_owed_cuts(seal, &blob), Some(owed()));
    }

    /// An empty record is still a record: a pass that settled every cut writes
    /// no root, and the next one must read that as settled rather than refuse
    /// the bytes.
    #[test]
    fn an_empty_debt_round_trips() {
        let entropy = RefCell::new(SeededEntropy::new(4));
        let mine = secret(9);
        let seal = BookkeepingSeal::new(&mine, &entropy);

        let blob = seal_owed_cuts(seal, &BTreeSet::new()).expect("the debt seals");

        assert_eq!(open_owed_cuts(seal, &blob), Some(BTreeSet::new()));
    }

    /// The store is shared with whatever build and whatever identity wrote it.
    /// Neither a stranger's blob nor a tag this build does not write may read as
    /// a debt.
    #[test]
    fn a_strangers_blob_and_a_foreign_tag_both_read_as_no_record() {
        let entropy = RefCell::new(SeededEntropy::new(5));
        let mine = secret(9);
        let theirs = secret(10);
        let blob = seal_owed_cuts(BookkeepingSeal::new(&theirs, &entropy), &owed())
            .expect("the debt seals");

        assert_eq!(
            open_owed_cuts(BookkeepingSeal::new(&mine, &entropy), &blob),
            None,
        );
        assert_eq!(decode_owed(&[]), None, "no tag at all");
        assert_eq!(decode_owed(&[FORMAT_V1 + 1]), None, "another build's tag");
    }

    /// A tail that is not whole ids is a truncated or rewritten record, never a
    /// debt to drive part of.
    #[test]
    fn a_partial_root_refuses_the_whole_record() {
        let mut bytes = encode_owed(&owed()).to_vec();
        bytes.pop();

        assert_eq!(decode_owed(&bytes), None);
    }

    /// The key is per identity, like every other durable bookkeeping surface:
    /// one device holds two accounts' debts without either driving the other's.
    #[test]
    fn two_identities_hold_their_debts_at_different_keys() {
        assert_ne!(
            scope_exit_debt_key(&secret(9)),
            scope_exit_debt_key(&secret(10))
        );
        assert!(scope_exit_debt_key(&secret(9)).starts_with(SCOPE_EXIT_DEBT_PREFIX));
    }

    // -----------------------------------------------------------------------
    // Driving the debt.
    // -----------------------------------------------------------------------

    /// The vault root, which a trigger escalates to and no share reaches.
    const VAULT_ROOT: NodeId = NodeId([0; 16]);

    /// Cuts every root but the one it is told to refuse, and records the order
    /// it was asked in.
    struct Rotator {
        seen: RefCell<Vec<NodeId>>,
        refuse: Option<(NodeId, RotateError)>,
    }

    impl Rotator {
        fn cutting_everything() -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                refuse: None,
            }
        }

        fn refusing(root: NodeId, error: RotateError) -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                refuse: Some((root, error)),
            }
        }
    }

    impl ScopeExitRotator for Rotator {
        async fn rotate_on_scope_exit(
            &self,
            scope_root: NodeId,
        ) -> Result<RotationOutcome, RotateError> {
            self.seen.borrow_mut().push(scope_root);
            match &self.refuse {
                Some((root, error)) if *root == scope_root => Err(error.clone()),
                _ => Ok(RotationOutcome {
                    new_read_epoch: 2,
                    epoch_floor: 2,
                }),
            }
        }
    }

    /// One pass over `session`, against the store every session of a test
    /// shares.
    fn pass(
        staging: &InMemoryStagingStore,
        entropy: &RefCell<SeededEntropy>,
        mine: &X25519Secret,
        exits: &Rotator,
        session: &RefCell<BTreeSet<NodeId>>,
    ) -> Vec<(NodeId, &'static str)> {
        block_on(settle_owed_cuts(
            staging,
            BookkeepingSeal::new(mine, entropy),
            mine,
            exits,
            session,
            VAULT_ROOT,
        ))
    }

    /// The roots the store holds for this identity.
    fn stored(
        staging: &InMemoryStagingStore,
        entropy: &RefCell<SeededEntropy>,
        mine: &X25519Secret,
    ) -> Option<BTreeSet<NodeId>> {
        let blob = block_on(staging.staged_bytes(&scope_exit_debt_key(mine)))
            .expect("the store answers")?;
        open_owed_cuts(BookkeepingSeal::new(mine, entropy), &blob)
    }

    /// The failure the durable record exists to close: the op that owed the cut
    /// has left the queue, so a session that starts with nothing in memory must
    /// still cut the scope the move left.
    #[test]
    fn a_restarted_session_drives_a_cut_the_last_one_could_not_land() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(11));
        let mine = secret(9);
        let refused = Rotator::refusing(node(3), RotateError::Publish(NOT_PUBLISHED));

        pass(
            &staging,
            &entropy,
            &mine,
            &refused,
            &RefCell::new(BTreeSet::from([node(3)])),
        );
        assert_eq!(
            stored(&staging, &entropy, &mine),
            Some(BTreeSet::from([node(3)]))
        );

        let restarted = RefCell::new(BTreeSet::new());
        let cutting = Rotator::cutting_everything();
        pass(&staging, &entropy, &mine, &cutting, &restarted);

        assert_eq!(*cutting.seen.borrow(), vec![node(3)]);
        assert_eq!(stored(&staging, &entropy, &mine), None);
    }

    /// The entry is the obligation, so it stands until the cut is durable — and
    /// goes the moment it is.
    #[test]
    fn an_entry_leaves_the_store_only_once_its_cut_lands() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(12));
        let mine = secret(9);
        let session = RefCell::new(BTreeSet::from([node(3), node(4)]));

        pass(
            &staging,
            &entropy,
            &mine,
            &Rotator::refusing(node(4), RotateError::Publish(NOT_PUBLISHED)),
            &session,
        );

        assert_eq!(
            stored(&staging, &entropy, &mine),
            Some(BTreeSet::from([node(4)])),
            "the cut that landed goes, the one that did not stays"
        );

        pass(
            &staging,
            &entropy,
            &mine,
            &Rotator::cutting_everything(),
            &session,
        );

        assert_eq!(stored(&staging, &entropy, &mine), None);
    }

    /// A cut this session cannot land is answered for, so the host says which
    /// scope still owes one rather than retrying in silence.
    #[test]
    fn the_pass_answers_with_the_scopes_that_still_owe_a_cut() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(13));
        let mine = secret(9);

        let owed = pass(
            &staging,
            &entropy,
            &mine,
            &Rotator::refusing(node(4), RotateError::Publish(NOT_PUBLISHED)),
            &RefCell::new(BTreeSet::from([node(3), node(4)])),
        );

        assert_eq!(owed, vec![(node(4), "publish-failed")]);
    }

    /// A floor raise that failed leaves the cut published, so the debt settles
    /// rather than minting a second epoch — and nothing is reported as still
    /// owed.
    #[test]
    fn a_failed_floor_raise_settles_the_debt_and_reports_nothing() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(14));
        let mine = secret(9);

        let owed = pass(
            &staging,
            &entropy,
            &mine,
            &Rotator::refusing(node(3), RotateError::Floor(SeamError::new("no store"))),
            &RefCell::new(BTreeSet::from([node(3)])),
        );

        assert!(owed.is_empty());
        assert_eq!(stored(&staging, &entropy, &mine), None);
    }

    /// The escalation to the vault root names no grantee, so it is cut by
    /// nobody and left in no record.
    #[test]
    fn the_vault_root_is_cut_by_nobody_and_leaves_no_record() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(15));
        let mine = secret(9);
        let session = RefCell::new(BTreeSet::from([VAULT_ROOT]));
        let exits = Rotator::cutting_everything();

        let owed = pass(&staging, &entropy, &mine, &exits, &session);

        assert!(owed.is_empty());
        assert!(exits.seen.borrow().is_empty());
        assert!(session.borrow().is_empty());
        assert_eq!(stored(&staging, &entropy, &mine), None);
    }

    /// A crossing's ack is where the window opens, so the debt is durable from
    /// the moment it is owed rather than from the end of the pass that owes it.
    #[test]
    fn a_newly_owed_cut_is_durable_before_any_pass_drives_it() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(17));
        let mine = secret(9);
        let session = RefCell::new(BTreeSet::new());

        block_on(owe_cut(
            &staging,
            BookkeepingSeal::new(&mine, &entropy),
            &mine,
            &session,
            node(3),
        ));

        assert_eq!(*session.borrow(), BTreeSet::from([node(3)]));
        assert_eq!(
            stored(&staging, &entropy, &mine),
            Some(BTreeSet::from([node(3)])),
        );
    }

    /// A pass with nothing owed and nothing stored costs no rotation and no
    /// store write.
    #[test]
    fn a_pass_with_no_debt_drives_nothing() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(16));
        let mine = secret(9);
        let exits = Rotator::cutting_everything();

        let owed = pass(
            &staging,
            &entropy,
            &mine,
            &exits,
            &RefCell::new(BTreeSet::new()),
        );

        assert!(owed.is_empty());
        assert!(exits.seen.borrow().is_empty());
        assert!(
            block_on(staging.staged_keys())
                .expect("the store answers")
                .is_empty()
        );
    }
}
