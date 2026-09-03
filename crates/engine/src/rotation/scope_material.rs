//! The read epoch each interior scope root the tick's walk proved seals at.
//!
//! A cross-scope `relink` re-seals the moved subtree at the destination scope's
//! epoch (blueprint/engine.md "Sync core: Ops"). One drain pass holds one
//! scope's seeds, so the destination end of a crossing reaches no epoch: the
//! walk sends both seeds to the per-scope seed caches and drops the epoch its
//! gated envelope carried.

use core::cell::RefCell;
use std::collections::BTreeMap;

use cipherbox_core::suite::secret::SECRET_LEN;
use zeroize::Zeroizing;

use crate::facade::NodeId;
use crate::net::DescendantScopeRoot;

/// What one scope root seals under: both its scope seeds, at the read epoch its
/// own envelope carries. Assembled on read from the cells that own each part.
///
/// Compare either seed with [`cipherbox_core::suite::secret::ct_eq`], never
/// `==`. No `Debug`: both seeds are key material (security rule 2).
pub struct ScopeMaterial {
    /// The scope's current override seed — what a record of this scope seals
    /// its node read keys under.
    pub read_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The scope's write scope seed — what a record of this scope publishes its
    /// `ipnsName` under.
    pub write_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The read epoch the scope root envelope carries.
    pub read_epoch: u64,
}

/// Scope id → the read epoch the last walk proved it at.
///
/// The seeds stay out. The per-scope seed caches already hold them, and they
/// alone run the eviction a floor rise demands (`CachedSeed`), so a third
/// resident copy would outlive that eviction.
pub(crate) type WalkedReadEpochs = BTreeMap<NodeId, u64>;

/// Replace the cell with the read epoch of every scope root this walk proved.
///
/// Replaced rather than merged, unlike the boundary set the same walk feeds
/// ([`crate::net::ScopeWalk::descendant_scope_roots`]): a boundary stays a
/// boundary, while an epoch names a moment.
pub(crate) fn install_walked_read_epochs(
    cell: &RefCell<WalkedReadEpochs>,
    proved: &[DescendantScopeRoot],
) {
    *cell.borrow_mut() = proved
        .iter()
        .map(|scope| (NodeId(scope.scope_id), scope.adopted.epoch))
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::ipns::IpnsName;
    use cipherbox_core::seal::{PreservedFields, ReadBody};

    use crate::gate::Adopted;
    use crate::net::rotation::ScopeWritePlane;

    const NAME: &str = "k51qzi5uqu5dgutdk6i1ynyzgkqngpha5xpgia3a5qqp4jsh0u4csozksxel2r";

    /// One level as a walk proved it. The write-plane epoch is fixed apart from
    /// the read epoch, so a deposit of the wrong one is visible.
    fn proved(n: u8, read_epoch: u64) -> DescendantScopeRoot {
        DescendantScopeRoot {
            scope_id: [n; 16],
            name: IpnsName::parse(NAME).expect("a valid name"),
            parent_node_seed: Zeroizing::new([n; SECRET_LEN]),
            adopted: Adopted {
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: Vec::new(),
                    unknown: PreservedFields::new(),
                },
                sequence: 1,
                epoch: read_epoch,
            },
            read_scope_seed: Zeroizing::new([n; SECRET_LEN]),
            write: Ok(ScopeWritePlane {
                seed: Zeroizing::new([n; SECRET_LEN]),
                epoch: 1,
            }),
        }
    }

    fn recorded(cell: &RefCell<WalkedReadEpochs>) -> Vec<(NodeId, u64)> {
        cell.borrow().iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Each level records its own envelope's read epoch, not the write-plane
    /// epoch beside it and not its parent's.
    #[test]
    fn every_level_records_its_own_read_epoch() {
        let cell = RefCell::new(WalkedReadEpochs::new());
        install_walked_read_epochs(&cell, &[proved(2, 4), proved(3, 9)]);

        assert_eq!(
            recorded(&cell),
            [(NodeId([2; 16]), 4), (NodeId([3; 16]), 9)]
        );
    }

    /// The cell holds what the last walk proved and nothing else: an epoch a
    /// later walk did not re-prove names a moment that has passed.
    #[test]
    fn a_later_walk_replaces_what_an_earlier_one_proved() {
        let cell = RefCell::new(WalkedReadEpochs::new());
        install_walked_read_epochs(&cell, &[proved(2, 4), proved(3, 9)]);
        install_walked_read_epochs(&cell, &[proved(3, 10)]);

        assert_eq!(recorded(&cell), [(NodeId([3; 16]), 10)]);
    }
}
