//! Which identity granted each scope root the render tree holds by graft, the
//! floor namespace ([`SharerScopedFloorStore`]) every leg below such a root
//! reads in, and the cross-plane rule those legs apply to what a foreign body
//! names.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::seal::ChildRef;
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;

use crate::facade::{NodeId, ScopeSeeds, SeedFloor, refresh_seed_floor};
use crate::seams::{FloorStore, SharerScopedFloorStore};
use crate::sync::model::Snapshot;

/// Scope id -> the identity that granted it, over the scope roots a browse may
/// reach by graft. An id more than one bookmark claims answers for no identity,
/// so it is absent.
pub(crate) type GraftedSharers = BTreeMap<[u8; 16], [u8; IDENTITY_PUBLIC_LEN]>;

/// Every bookmarked shared scope id, the contested ones included.
///
/// A contested id renders for nobody, so no leg may link it either: the sharer
/// that linked it would hold it the moment the contest resolves.
pub(crate) type BookmarkedScopeRoots = BTreeSet<[u8; 16]>;

/// The plane one read leg runs on when that plane is a grafted scope.
///
/// A leg on this vault's own plane has no such value. Its records are this
/// vault's own to author, and a rule there would only let a sharer deny the
/// vault a node of its own by bookmarking that node's id.
#[derive(Clone, Copy)]
pub(crate) struct GraftedPlane<'a> {
    /// The scope every body this leg reads is sealed under.
    pub(crate) scope_id: [u8; 16],
    pub(crate) scope_roots: &'a BookmarkedScopeRoots,
}

/// One body's children, split by which plane may speak for each id.
pub(crate) struct PlaneSplit {
    /// The children this plane may link.
    pub(crate) linkable: Vec<ChildRef>,
    /// Ids another plane holds. This plane may neither link them nor depart
    /// them, so they pass to
    /// [`project_folder_partial`](crate::sync::project::project_folder_partial)
    /// as withheld.
    pub(crate) withheld: Vec<[u8; 16]>,
    /// Whether any withheld id is a node of this vault's own tree. A sharer
    /// names their own nodes only, so no honest body makes that claim.
    pub(crate) names_own_tree: bool,
}

impl GraftedPlane<'_> {
    /// Split `children` by whether this plane may speak for each id.
    ///
    /// A sharer names their own nodes only.
    /// [`project_folder`](crate::sync::project::project_folder) never unlinks
    /// the old parent, so a link accepted for an id another tree already holds
    /// leaves the node under both, and the higher `link_counter` wins it
    /// ([`Snapshot::winning_link`]). The same projection rewrites the node's
    /// name, so the id would change hands and change label together.
    pub(crate) fn split(&self, base: &Snapshot, children: &[ChildRef]) -> PlaneSplit {
        let mut split = PlaneSplit {
            linkable: Vec::with_capacity(children.len()),
            withheld: Vec::new(),
            names_own_tree: false,
        };
        for child in children {
            match self.claim(base, NodeId(child.id)) {
                None => split.linkable.push(child.clone()),
                Some(claim) => {
                    split.names_own_tree |= claim == Claim::OwnTree;
                    split.withheld.push(child.id);
                }
            }
        }
        split
    }

    /// Which plane already holds `id`, or `None` when this plane may name it.
    ///
    /// One upward walk: the vault's own root anywhere on the chain is this
    /// vault's tree, and any other bookmarked scope root on it is a second
    /// party's. A body may not name its own scope root either — a scope root is
    /// never a node below itself.
    fn claim(&self, base: &Snapshot, id: NodeId) -> Option<Claim> {
        if id.0 == self.scope_id {
            return Some(Claim::OtherPlane);
        }
        let claim = |node: NodeId| {
            if node == base.root {
                Some(Claim::OwnTree)
            } else if node.0 != self.scope_id && self.scope_roots.contains(&node.0) {
                Some(Claim::OtherPlane)
            } else {
                None
            }
        };
        claim(id).or_else(|| base.ancestors(id).into_iter().find_map(claim))
    }
}

/// Which plane holds an id a foreign body names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Claim {
    /// A node of this vault's own tree.
    OwnTree,
    /// Another bookmarked scope root, a node below one, or this plane's own
    /// root, which is never a node below itself.
    OtherPlane,
}

/// Whether `id` is a node this vault's own tree holds.
pub(crate) fn in_own_tree(base: &Snapshot, id: NodeId) -> bool {
    id == base.root || base.is_descendant_of(id, base.root)
}

/// The floor namespace `scope_id`'s read leg must use, or `None` when no
/// authority answers for the id and the leg may not run at all.
///
/// Fail-closed on the unknown arm: the owner plane is this vault's own
/// namespace, so answering with it for a scope this vault does not own would
/// measure a foreign record against a floor no sharer ever raised. `own_root`
/// is decided ahead of the map, so a bookmark that names this vault's anchor
/// cannot redirect the vault's own leg.
pub(crate) fn floor_view<'a, F>(
    floors: &'a F,
    sharers: &GraftedSharers,
    own_root: &[u8; 16],
    scope_id: &[u8; 16],
) -> Option<SharerScopedFloorStore<'a, F>> {
    if scope_id == own_root {
        return Some(SharerScopedFloorStore::own(floors));
    }
    sharers
        .get(scope_id)
        .map(|sharer| SharerScopedFloorStore::granted_by(floors, *sharer))
}

/// Evict every grafted scope's cached read seed that its granting identity's
/// durable read-epoch floor has passed, and drop outright a seed no identity
/// answers for any more.
///
/// Driven by the cache rather than by the map, so a scope that leaves the map
/// takes its seed with it. Retention is bounded by the floor that entitles the
/// seed, and a seed with no floor to measure has no currency to establish.
pub(crate) async fn evict_grafted_read_seeds<F: FloorStore>(
    floors: &F,
    sharers: &GraftedSharers,
    own_root: &[u8; 16],
    read_seeds: &RefCell<ScopeSeeds>,
) {
    let held: Vec<[u8; 16]> = read_seeds.borrow().keys().copied().collect();
    for scope_id in held {
        if scope_id == *own_root {
            continue;
        }
        match floor_view(floors, sharers, own_root, &scope_id) {
            Some(view) => {
                refresh_seed_floor(&view, read_seeds, &scope_id, SeedFloor::Read).await;
            }
            None => {
                read_seeds.borrow_mut().remove(&scope_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zeroize::Zeroizing;

    use cipherbox_core::seal::{NodeKind as CoreNodeKind, PreservedFields};

    use crate::facade::{NodeKind, deposit_seed};
    use crate::gate::floor;
    use crate::sync::model::NodeMeta;
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryFloorStore;

    const SCOPE: [u8; 16] = [0x5c; 16];
    /// This vault's own root scope — the anchored id every account shares.
    const OWN_ROOT: [u8; 16] = [0u8; 16];
    const SHARER: [u8; IDENTITY_PUBLIC_LEN] = [0x02; IDENTITY_PUBLIC_LEN];

    fn grafted() -> GraftedSharers {
        GraftedSharers::from([(SCOPE, SHARER)])
    }

    fn seeded(scope_id: [u8; 16], stamp: u64) -> RefCell<ScopeSeeds> {
        let cell = RefCell::new(ScopeSeeds::new());
        deposit_seed(&cell, scope_id, Zeroizing::new([0x66; 32]), Some(stamp));
        cell
    }

    const OTHER_SCOPE: [u8; 16] = [0x0b; 16];
    const OWN_CHILD: [u8; 16] = [0xd1; 16];
    const UNDER_OTHER: [u8; 16] = [0xe2; 16];
    const UNCLAIMED: [u8; 16] = [0xf3; 16];

    /// A tree with this vault's own child, the grafted scope `SCOPE`, and a
    /// second grafted scope holding one node of its own.
    fn tree() -> Snapshot {
        let mut base = Snapshot::new(NodeId(OWN_ROOT));
        for (id, parent) in [
            (OWN_CHILD, Some(OWN_ROOT)),
            (SCOPE, None),
            (OTHER_SCOPE, None),
            (UNDER_OTHER, Some(OTHER_SCOPE)),
        ] {
            base.upsert_node(NodeMeta::new(NodeId(id), "n", NodeKind::Folder));
            if let Some(parent) = parent {
                base.link(NodeId(parent), NodeId(id), 1);
            }
        }
        base
    }

    fn split(ids: &[[u8; 16]]) -> PlaneSplit {
        let roots = BookmarkedScopeRoots::from([SCOPE, OTHER_SCOPE]);
        let children: Vec<ChildRef> = ids
            .iter()
            .map(|id| ChildRef {
                id: *id,
                name: "n".to_owned(),
                ipns_name: vec![id[0]],
                kind: CoreNodeKind::Folder,
                link_counter: 1,
                unknown: PreservedFields::new(),
            })
            .collect();
        GraftedPlane {
            scope_id: SCOPE,
            scope_roots: &roots,
        }
        .split(&tree(), &children)
    }

    /// The rule every leg below a grafted root shares: a foreign body reaches
    /// its own subtree and nothing else. A contested scope id counts, since it
    /// renders for nobody and a third sharer would hold it the moment the
    /// contest resolves.
    #[test]
    fn a_grafted_plane_links_only_ids_no_other_plane_holds() {
        let split = split(&[
            OWN_ROOT,
            OWN_CHILD,
            OTHER_SCOPE,
            UNDER_OTHER,
            SCOPE,
            UNCLAIMED,
        ]);

        assert_eq!(
            split.linkable.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![UNCLAIMED],
        );
        assert_eq!(
            split.withheld,
            vec![OWN_ROOT, OWN_CHILD, OTHER_SCOPE, UNDER_OTHER, SCOPE],
        );
    }

    /// A body that names a node of this vault's own tree is attributable: no
    /// honest sharer names an id it does not own.
    #[test]
    fn naming_this_vaults_own_node_is_reported_and_a_foreign_scope_is_not() {
        assert!(split(&[OWN_CHILD]).names_own_tree);
        assert!(!split(&[OTHER_SCOPE, UNDER_OTHER]).names_own_tree);
    }

    /// The accept and render legs raise a granted scope's read-epoch floor under
    /// the granting identity, so a leg reading the plain key sees none of it —
    /// and enforces no revocation on the subtree below that root.
    #[test]
    fn a_grafted_scope_reads_the_floor_its_sharer_raised() {
        let floors = InMemoryFloorStore::default();
        // Raised the way the accept and render legs raise it.
        block_on(SharerScopedFloorStore::granted_by(&floors, SHARER).raise_epoch_floor(&SCOPE, 7))
            .expect("the floor raises");

        let view =
            floor_view(&floors, &grafted(), &OWN_ROOT, &SCOPE).expect("one identity granted it");
        assert_eq!(
            block_on(floor::read_epoch_floor(&view, &SCOPE)),
            Ok(Some(7))
        );
    }

    /// A scope id no identity answers for reaches no floor at all. Falling back
    /// to the owner plane would measure a foreign record against a floor no
    /// sharer ever raised, so a browse of it must be refused instead.
    #[test]
    fn a_scope_no_identity_answers_for_reaches_no_floor() {
        let floors = InMemoryFloorStore::default();

        assert!(floor_view(&floors, &GraftedSharers::new(), &OWN_ROOT, &SCOPE).is_none());
    }

    /// The vault's own root is decided ahead of the map, so a bookmark that
    /// names this vault's anchor cannot redirect the vault's own leg into a
    /// contact's namespace.
    #[test]
    fn the_vaults_own_root_reads_the_owner_plane_whatever_the_map_claims() {
        let floors = InMemoryFloorStore::default();
        block_on(floors.raise_epoch_floor(&OWN_ROOT, 4)).expect("the floor raises");
        let claimed = GraftedSharers::from([(OWN_ROOT, SHARER)]);

        let view = floor_view(&floors, &claimed, &OWN_ROOT, &OWN_ROOT).expect("this vault's own");
        assert_eq!(
            block_on(floor::read_epoch_floor(&view, &OWN_ROOT)),
            Ok(Some(4))
        );
    }

    /// A grafted root has no own-root resolve leg, so without this pass a
    /// revoked epoch's read seed stays resident for the rest of the session.
    #[test]
    fn a_floor_rise_under_the_granting_identity_evicts_the_grafted_seed() {
        let floors = InMemoryFloorStore::default();
        let seeds = seeded(SCOPE, 1);

        block_on(evict_grafted_read_seeds(
            &floors,
            &grafted(),
            &OWN_ROOT,
            &seeds,
        ));
        assert!(
            seeds.borrow().contains_key(&SCOPE),
            "an unmoved floor evicts nothing"
        );

        block_on(SharerScopedFloorStore::granted_by(&floors, SHARER).raise_epoch_floor(&SCOPE, 2))
            .expect("the floor raises");
        block_on(evict_grafted_read_seeds(
            &floors,
            &grafted(),
            &OWN_ROOT,
            &seeds,
        ));

        assert!(!seeds.borrow().contains_key(&SCOPE));
    }

    /// The prefix is the whole point: a floor raised on the owner plane is
    /// another authority's, and must not evict a grafted scope's seed.
    #[test]
    fn an_owner_plane_floor_rise_leaves_the_grafted_seed_alone() {
        let floors = InMemoryFloorStore::default();
        let seeds = seeded(SCOPE, 1);
        block_on(floors.raise_epoch_floor(&SCOPE, 9)).expect("the floor raises");

        block_on(evict_grafted_read_seeds(
            &floors,
            &grafted(),
            &OWN_ROOT,
            &seeds,
        ));

        assert!(seeds.borrow().contains_key(&SCOPE));
    }

    /// A second bookmark on one scope id leaves that id claimed by nobody. The
    /// seed the first sharer's grant installed loses the authority that
    /// entitled it, so it goes rather than staying resident for the session.
    #[test]
    fn a_seed_whose_scope_left_the_map_is_dropped() {
        let floors = InMemoryFloorStore::default();
        let seeds = seeded(SCOPE, 1);

        block_on(evict_grafted_read_seeds(
            &floors,
            &GraftedSharers::new(),
            &OWN_ROOT,
            &seeds,
        ));

        assert!(!seeds.borrow().contains_key(&SCOPE));
    }

    /// The vault's own root scope is evicted on its own resolve leg, against the
    /// floors that leg reads before it stamps a fresh deposit.
    #[test]
    fn the_vaults_own_seed_is_left_to_its_own_leg() {
        let floors = InMemoryFloorStore::default();
        let seeds = seeded(OWN_ROOT, 1);
        block_on(floors.raise_epoch_floor(&OWN_ROOT, 9)).expect("the floor raises");

        block_on(evict_grafted_read_seeds(
            &floors,
            &GraftedSharers::new(),
            &OWN_ROOT,
            &seeds,
        ));

        assert!(seeds.borrow().contains_key(&OWN_ROOT));
    }
}
