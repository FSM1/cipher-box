//! Which identity granted each scope root the render tree holds by graft, and
//! the floor namespace ([`SharerScopedFloorStore`]) every leg below such a root
//! reads in.

use core::cell::RefCell;
use std::collections::BTreeMap;

use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;

use crate::facade::{ScopeSeeds, SeedFloor, refresh_seed_floor};
use crate::seams::{FloorStore, SharerScopedFloorStore};

/// Scope id -> the identity that granted it, over the scope roots a browse may
/// reach by graft. An id more than one bookmark claims answers for no identity,
/// so it is absent.
pub(crate) type GraftedSharers = BTreeMap<[u8; 16], [u8; IDENTITY_PUBLIC_LEN]>;

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

    use crate::facade::deposit_seed;
    use crate::gate::floor;
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
