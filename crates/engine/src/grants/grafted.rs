//! Which identity granted each scope root the render tree holds by graft, the
//! floor namespace ([`SharerScopedFloorStore`]) every leg below such a root
//! reads in, and the cross-plane rule those legs apply to what a foreign body
//! names.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::seal::ChildRef;
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SecretBytes;

use crate::facade::{NodeId, ScopeSeeds, SeedFloor, refresh_seed_floor};
use crate::seams::{ContactLabel, FloorStore, SharerScopedFloorStore};
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

/// Which body a claim-record entry came from: the scope it is sealed under, and
/// the node whose body it is. A scope root's own body is keyed at its scope id.
///
/// Per body rather than per scope, because a scope's bodies arrive on different
/// legs: the root body on the received-share pass, a folder body only while the
/// focus window holds it. Keyed per scope, a fresh root body would erase what
/// the folder legs below it named.
pub(crate) type BodyKey = ([u8; 16], [u8; 16]);

/// Every node id each renderable grafted body names, by body.
pub(crate) type NamedNodes = BTreeMap<BodyKey, BTreeSet<[u8; 16]>>;

/// The node ids more than one [`NamedNodes`] entry names.
pub(crate) type ContestedNodes = BTreeSet<[u8; 16]>;

/// The node ids more than one **scope** names.
///
/// The contest is between sharers. Two bodies of one scope may name an id
/// between them — a move inside that scope does exactly that, and the two legs
/// that read them run a tick apart — so a scope never contests itself.
pub(crate) fn contested_nodes(named: &NamedNodes) -> ContestedNodes {
    let mut claimed: BTreeMap<[u8; 16], [u8; 16]> = BTreeMap::new();
    let mut contested = ContestedNodes::new();
    for ((scope_id, _), ids) in named {
        for id in ids {
            if *claimed.entry(*id).or_insert(*scope_id) != *scope_id {
                contested.insert(*id);
            }
        }
    }
    contested
}

/// Record what one grafted body names, and answer with the contest the whole
/// record now carries.
///
/// Every leg that reads a grafted body writes its claim here before it applies
/// the split, so a body cannot take an id a second scope's body names however
/// deep in that scope's subtree the id sits.
pub(crate) fn record_body(
    named: &RefCell<NamedNodes>,
    scope_id: [u8; 16],
    node_id: [u8; 16],
    children: &[ChildRef],
) -> ContestedNodes {
    let mut named = named.borrow_mut();
    named.insert(
        (scope_id, node_id),
        children.iter().map(|child| child.id).collect(),
    );
    contested_nodes(&named)
}

/// Drop every entry no live body answers for: a scope outside `renderable`, and
/// a folder body the render tree no longer holds. A departed body names nothing,
/// so keeping its entry would hold a contest open for good.
///
/// A scope root's own entry is kept while its scope is renderable, so a scope
/// this pass could not open does not lose its claim to one it did.
pub(crate) fn retain_live_bodies(
    named: &mut NamedNodes,
    renderable: &BTreeSet<[u8; 16]>,
    base: &Snapshot,
) {
    named.retain(|(scope_id, node_id), _| {
        renderable.contains(scope_id) && (node_id == scope_id || base.contains(NodeId(*node_id)))
    });
}

/// The plane one read leg runs on when that plane is a grafted scope.
///
/// A leg on this vault's own plane has no such value. Its records are this
/// vault's own to author, and a rule there would only let a sharer deny the
/// vault a node of its own by bookmarking that node's id.
///
/// A node id more than one grafted body names renders under no scope, for this
/// pass and for every later pass while both bodies name it; the scope that stays
/// alone on the id renders it on the next pass that reaches its body. The sharer
/// authors every id, so a claim settled by which scope grafted first would be
/// settled by the sharer-authored bookmark order.
#[derive(Clone, Copy)]
pub(crate) struct GraftedPlane<'a> {
    /// The scope every body this leg reads is sealed under.
    pub(crate) scope_id: [u8; 16],
    pub(crate) scope_roots: &'a BookmarkedScopeRoots,
    pub(crate) contested: &'a ContestedNodes,
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
                // A contested id is in neither list, so the merge departs it
                // from the plane that rendered it before the contest.
                Some(Claim::Contested) => {}
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
        claim(id)
            .or_else(|| base.ancestors(id).into_iter().find_map(claim))
            .or_else(|| self.contested.contains(&id.0).then_some(Claim::Contested))
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
    /// An id more than one grafted body names, which no plane holds.
    Contested,
}

/// Whether `id` is a node this vault's own tree holds.
pub(crate) fn in_own_tree(base: &Snapshot, id: NodeId) -> bool {
    id == base.root || base.is_descendant_of(id, base.root)
}

/// Whether this identity answers for `scope_id` itself: the vault root, or a
/// scope root a gated descent proved below it
/// ([`ScopeWalk::descendant_scope_roots`](crate::net::ScopeWalk::descendant_scope_roots)).
/// A grant cut mints one out of this vault's own interior, so no sharer answers
/// for it and its floors and its records are this identity's own.
///
/// Stated once, because two legs read it: [`floor_view`] picks the floor
/// namespace with it, and the focus refresh picks the claim plane with it.
pub(crate) fn is_own_scope(
    own_root: &[u8; 16],
    own_descendants: &BTreeSet<NodeId>,
    scope_id: &[u8; 16],
) -> bool {
    scope_id == own_root || own_descendants.contains(&NodeId(*scope_id))
}

/// The floor namespace `scope_id`'s read leg must use, or `None` when no
/// authority answers for the id and the leg may not run at all.
///
/// Fail-closed on the unknown arm: the owner plane is this vault's own
/// namespace, so answering with it for a scope this vault does not own would
/// measure a foreign record against a floor no sharer ever raised. The owned
/// arm is decided ahead of the map, so a bookmark that names one of this
/// vault's own roots cannot redirect that root's leg.
pub(crate) fn floor_view<'a, F>(
    floors: &'a F,
    sharers: &GraftedSharers,
    contact_label_seed: &SecretBytes,
    own_root: &[u8; 16],
    own_descendants: &BTreeSet<NodeId>,
    scope_id: &[u8; 16],
) -> Option<SharerScopedFloorStore<'a, F>> {
    if is_own_scope(own_root, own_descendants, scope_id) {
        return Some(SharerScopedFloorStore::own(floors));
    }
    sharers.get(scope_id).map(|sharer| {
        SharerScopedFloorStore::granted_by(floors, ContactLabel::of(contact_label_seed, sharer))
    })
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
    contact_label_seed: &SecretBytes,
    own_root: &[u8; 16],
    own_descendants: &BTreeSet<NodeId>,
    read_seeds: &RefCell<ScopeSeeds>,
) {
    let held: Vec<[u8; 16]> = read_seeds.borrow().keys().copied().collect();
    for scope_id in held {
        if scope_id == *own_root {
            continue;
        }
        match floor_view(
            floors,
            sharers,
            contact_label_seed,
            own_root,
            own_descendants,
            &scope_id,
        ) {
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

    use cipherbox_core::kdf;
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

    fn label_seed() -> SecretBytes {
        kdf::contact_label_seed(&[0x4c; 32])
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
        split_contesting(ids, &ContestedNodes::new())
    }

    fn child(id: [u8; 16]) -> ChildRef {
        ChildRef {
            id,
            name: "n".to_owned(),
            ipns_name: vec![id[0]],
            kind: CoreNodeKind::Folder,
            link_counter: 1,
            unknown: PreservedFields::new(),
        }
    }

    fn split_contesting(ids: &[[u8; 16]], contested: &ContestedNodes) -> PlaneSplit {
        let roots = BookmarkedScopeRoots::from([SCOPE, OTHER_SCOPE]);
        let children: Vec<ChildRef> = ids.iter().copied().map(child).collect();
        GraftedPlane {
            scope_id: SCOPE,
            scope_roots: &roots,
            contested,
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

    /// A contested id is left out of both lists. Withholding it would keep it
    /// standing under the plane that rendered it before the contest, and the
    /// rule is that no plane renders it.
    #[test]
    fn a_contested_id_is_neither_linked_nor_withheld() {
        let split = split_contesting(&[UNCLAIMED], &ContestedNodes::from([UNCLAIMED]));

        assert!(split.linkable.is_empty());
        assert!(split.withheld.is_empty());
    }

    /// The contest is between sharers. A body that names a node of this vault's
    /// own tree is attributable whatever a second sharer names.
    #[test]
    fn a_contest_does_not_hide_a_body_that_names_this_vaults_own_node() {
        let split = split_contesting(&[OWN_CHILD], &ContestedNodes::from([OWN_CHILD]));

        assert!(split.names_own_tree);
        assert_eq!(split.withheld, vec![OWN_CHILD]);
    }

    /// The claim record answers over every renderable scope at once, so an id
    /// one scope alone names stays that scope's to render.
    #[test]
    fn only_an_id_two_scopes_name_is_contested() {
        let named = NamedNodes::from([
            ((SCOPE, SCOPE), BTreeSet::from([UNCLAIMED, OWN_CHILD])),
            ((OTHER_SCOPE, OTHER_SCOPE), BTreeSet::from([UNCLAIMED])),
        ]);

        assert_eq!(contested_nodes(&named), ContestedNodes::from([UNCLAIMED]));
    }

    /// The contest is between sharers. One scope's root body and a folder body
    /// below it name an id between them whenever a node moves inside that
    /// scope, and the two legs that read them run a tick apart.
    #[test]
    fn two_bodies_of_one_scope_do_not_contest_each_other() {
        let named = NamedNodes::from([
            ((SCOPE, SCOPE), BTreeSet::from([UNCLAIMED])),
            ((SCOPE, UNDER_OTHER), BTreeSet::from([UNCLAIMED])),
        ]);

        assert!(contested_nodes(&named).is_empty());
    }

    /// Every leg records its own body before it reads the contest back, so a
    /// body cannot take an id a second scope's body names.
    #[test]
    fn a_recorded_body_contests_an_id_a_second_scope_already_named() {
        let named = RefCell::new(NamedNodes::from([(
            (OTHER_SCOPE, UNDER_OTHER),
            BTreeSet::from([UNCLAIMED]),
        )]));

        let contested = record_body(&named, SCOPE, SCOPE, &[child(UNCLAIMED)]);

        assert_eq!(contested, ContestedNodes::from([UNCLAIMED]));
    }

    /// A departed body names nothing. Its entry goes with it, or the contest it
    /// raised would stand for good — while a scope root keeps its entry through
    /// a pass that could not open it.
    #[test]
    fn the_record_keeps_only_a_live_bodys_entry() {
        let mut named = NamedNodes::from([
            ((SCOPE, SCOPE), BTreeSet::from([UNCLAIMED])),
            ((SCOPE, UNDER_OTHER), BTreeSet::from([UNCLAIMED])),
            ((SCOPE, UNCLAIMED), BTreeSet::from([OWN_CHILD])),
            ((OTHER_SCOPE, OTHER_SCOPE), BTreeSet::from([UNDER_OTHER])),
        ]);

        retain_live_bodies(&mut named, &BTreeSet::from([SCOPE]), &tree());

        assert_eq!(
            named.keys().copied().collect::<Vec<_>>(),
            vec![(SCOPE, SCOPE), (SCOPE, UNDER_OTHER)],
            "an unrenderable scope and a body the tree dropped both go"
        );
    }

    /// The accept and render legs raise a granted scope's read-epoch floor under
    /// the granting identity, so a leg reading the plain key sees none of it —
    /// and enforces no revocation on the subtree below that root.
    #[test]
    fn a_grafted_scope_reads_the_floor_its_sharer_raised() {
        let floors = InMemoryFloorStore::default();
        // Raised the way the accept and render legs raise it.
        block_on(
            SharerScopedFloorStore::granted_by(&floors, ContactLabel::of(&label_seed(), &SHARER))
                .raise_epoch_floor(&SCOPE, 7),
        )
        .expect("the floor raises");

        let view = floor_view(
            &floors,
            &grafted(),
            &label_seed(),
            &OWN_ROOT,
            &BTreeSet::new(),
            &SCOPE,
        )
        .expect("one identity granted it");
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

        assert!(
            floor_view(
                &floors,
                &GraftedSharers::new(),
                &label_seed(),
                &OWN_ROOT,
                &BTreeSet::new(),
                &SCOPE
            )
            .is_none()
        );
    }

    /// The vault's own root is decided ahead of the map, so a bookmark that
    /// names this vault's anchor cannot redirect the vault's own leg into a
    /// contact's namespace.
    #[test]
    fn the_vaults_own_root_reads_the_owner_plane_whatever_the_map_claims() {
        let floors = InMemoryFloorStore::default();
        block_on(floors.raise_epoch_floor(&OWN_ROOT, 4)).expect("the floor raises");
        let claimed = GraftedSharers::from([(OWN_ROOT, SHARER)]);

        let view = floor_view(
            &floors,
            &claimed,
            &label_seed(),
            &OWN_ROOT,
            &BTreeSet::new(),
            &OWN_ROOT,
        )
        .expect("this vault's own");
        assert_eq!(
            block_on(floor::read_epoch_floor(&view, &OWN_ROOT)),
            Ok(Some(4))
        );
    }

    /// A grant cut mints a scope root out of this vault's own interior. No
    /// sharer answers for it, so the map arm would refuse it and the leg below
    /// it would never run; its floors are this identity's own.
    #[test]
    fn a_proved_descendant_of_the_vaults_own_root_reads_the_owner_plane() {
        let floors = InMemoryFloorStore::default();
        block_on(floors.raise_epoch_floor(&SCOPE, 5)).expect("the floor raises");

        assert!(
            floor_view(
                &floors,
                &GraftedSharers::new(),
                &label_seed(),
                &OWN_ROOT,
                &BTreeSet::new(),
                &SCOPE,
            )
            .is_none(),
            "a scope no descent proved and no sharer granted reaches no floor",
        );

        let view = floor_view(
            &floors,
            &GraftedSharers::new(),
            &label_seed(),
            &OWN_ROOT,
            &BTreeSet::from([NodeId(SCOPE)]),
            &SCOPE,
        )
        .expect("a gated descent proved it below this vault's own root");
        assert_eq!(
            block_on(floor::read_epoch_floor(&view, &SCOPE)),
            Ok(Some(5))
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
            &label_seed(),
            &OWN_ROOT,
            &BTreeSet::new(),
            &seeds,
        ));
        assert!(
            seeds.borrow().contains_key(&SCOPE),
            "an unmoved floor evicts nothing"
        );

        block_on(
            SharerScopedFloorStore::granted_by(&floors, ContactLabel::of(&label_seed(), &SHARER))
                .raise_epoch_floor(&SCOPE, 2),
        )
        .expect("the floor raises");
        block_on(evict_grafted_read_seeds(
            &floors,
            &grafted(),
            &label_seed(),
            &OWN_ROOT,
            &BTreeSet::new(),
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
            &label_seed(),
            &OWN_ROOT,
            &BTreeSet::new(),
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
            &label_seed(),
            &OWN_ROOT,
            &BTreeSet::new(),
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
            &label_seed(),
            &OWN_ROOT,
            &BTreeSet::new(),
            &seeds,
        ));

        assert!(seeds.borrow().contains_key(&OWN_ROOT));
    }
}
