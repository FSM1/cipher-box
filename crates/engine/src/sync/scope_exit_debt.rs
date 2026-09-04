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
//! open is refused rather than cut.

use std::collections::BTreeSet;

use cipherbox_core::seal::OwnerLocalKind;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::facade::NodeId;
use crate::seams::SeamResult;
use crate::sync::BookkeepingSeal;
use crate::sync::drain::owner_scoped_key;

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
/// Every shape [`decode_owed`] refuses is one this encoding cannot produce —
/// the tag is written here and a `BTreeSet<NodeId>` is whole ids in order — so
/// the pair needs no further encode-side refusal (AGENTS.md rule 8).
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

    use core::cell::RefCell;

    use crate::testkit::SeededEntropy;

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
        assert_ne!(scope_exit_debt_key(&secret(9)), scope_exit_debt_key(&secret(10)));
        assert!(scope_exit_debt_key(&secret(9)).starts_with(SCOPE_EXIT_DEBT_PREFIX));
    }
}
