//! The engine's in-memory per-scope seed caches: every recovered scope seed is
//! stamped with a lower bound on its epoch and evicted once a durable floor rises
//! past that stamp (`gate::floor`).

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::ipns::IpnsName;
use zeroize::Zeroizing;

use crate::facade::NodeId;
use crate::gate::floor;
use crate::grants::grafted::FloorNamespace;
use crate::rotation::scope_material::ScopeMaterial;
use crate::rotation::{WalkedReadEpochs, derive_write_name};
use crate::seams::{FloorStore, SeamResult, SharerScopedFloorStore};

/// A recovered scope seed and a lower bound on the epoch it belongs to (see
/// [`deposit_seed`]).
///
/// The bound is the seed's expiry: a rotation that raises the scope's durable
/// floor past it revokes that epoch, so the seed is evicted rather than left
/// resident for the rest of the session. Least privilege is a retention rule,
/// not only an install rule.
///
/// The bound holds only in the namespace it was measured in: two grants may
/// carry one scope id, and a floor in another sharer's namespace says nothing
/// about this seed.
pub(crate) struct CachedSeed {
    seed: Zeroizing<[u8; 32]>,
    floor: u64,
    namespace: FloorNamespace,
}

/// One of the engine's in-memory per-scope seed cells: scope id → the recovered
/// seed (zeroized on removal/drop).
pub(crate) type ScopeSeeds = BTreeMap<[u8; 16], CachedSeed>;

/// Which of a scope's two independent durable floors bounds a cached seed
/// (`gate::floor`: the read-epoch floor is the revocation boundary, the
/// write-epoch floor an owner-only clock).
#[derive(Clone, Copy)]
pub(crate) enum SeedFloor {
    Read,
    Write,
}

impl SeedFloor {
    async fn durable<F: FloorStore>(
        self,
        floors: &F,
        scope_id: &[u8; 16],
    ) -> SeamResult<Option<u64>> {
        match self {
            Self::Read => floor::read_epoch_floor(floors, scope_id).await,
            Self::Write => floor::write_epoch_floor(floors, scope_id).await,
        }
    }
}

/// Read `scope_id`'s durable floor for `which` in the namespace of `floors`,
/// evicting a cached seed stamped below it or deposited in another namespace,
/// and hand the floor back for the pass's own deposits.
///
/// `None` on a floor-store failure, which also evicts: a seed whose currency
/// cannot be established is not held, and nothing may be stamped against a floor
/// that was never read.
pub(crate) async fn refresh_seed_floor<F: FloorStore>(
    floors: &SharerScopedFloorStore<'_, F>,
    cell: &RefCell<ScopeSeeds>,
    scope_id: &[u8; 16],
    which: SeedFloor,
) -> Option<u64> {
    let durable = which
        .durable(floors, scope_id)
        .await
        .ok()
        .map(|floor| floor.unwrap_or(0));
    let namespace = FloorNamespace::of(floors);
    let mut seeds = cell.borrow_mut();
    let stale =
        |cached: &CachedSeed, floor: u64| cached.namespace != namespace || cached.floor < floor;
    if durable.is_none_or(|floor| seeds.get(scope_id).is_some_and(|c| stale(c, floor))) {
        seeds.remove(scope_id);
    }
    durable
}

/// A cached seed as one read served it, with its stamp ([`CachedSeed`]).
pub(crate) struct StampedSeed {
    pub(crate) seed: Zeroizing<[u8; 32]>,
    pub(crate) stamp: u64,
}

/// The scope's cached seed after an eviction pass against `floors`
/// ([`refresh_seed_floor`]): a seed the floor has passed is never served.
pub(crate) async fn current_seed<F: FloorStore>(
    floors: &SharerScopedFloorStore<'_, F>,
    cell: &RefCell<ScopeSeeds>,
    scope_id: &[u8; 16],
    which: SeedFloor,
) -> Option<StampedSeed> {
    refresh_seed_floor(floors, cell, scope_id, which).await?;
    cell.borrow().get(scope_id).map(|cached| StampedSeed {
        seed: cached.seed.clone(),
        stamp: cached.floor,
    })
}

/// The scope roots below the vault root this session owns: the ones a gated
/// descent proved and the ones its own grants minted, which is this vault's
/// floor namespace before any walk re-proves them.
pub(crate) fn own_descendant_scopes(
    proved: &RefCell<BTreeSet<NodeId>>,
    minted: &RefCell<BTreeSet<NodeId>>,
) -> BTreeSet<NodeId> {
    proved.borrow().union(&minted.borrow()).copied().collect()
}

/// Deposit a recovered scope seed under `stamp`, which must be **at or below the
/// epoch the seed belongs to** — the seed's own epoch where the recovery names it
/// (an adopted record's `epoch`, a re-point's vouched floors), else the durable
/// floor read *before* the resolve.
///
/// A pre-resolve floor is a valid stamp because floors are monotonic and every
/// recovery arm refuses an envelope below the floor it read (`gate::adoption`
/// stage 5, `RootAdopter::recover_own_scope_material`). What is *not* valid is a
/// floor re-read after the resolve: a rise that landed mid-pass would be absorbed
/// into the stamp and keep a revoked-epoch seed resident.
///
/// `namespace` is the one the stamp is measured in.
///
/// `None` skips the deposit — the floor could not be read, so nothing can be
/// stamped and the eviction pass has already cleared the cell.
pub(crate) fn deposit_seed(
    cell: &RefCell<ScopeSeeds>,
    scope_id: [u8; 16],
    seed: Zeroizing<[u8; 32]>,
    stamp: Option<u64>,
    namespace: FloorNamespace,
) {
    if let Some(floor) = stamp {
        cell.borrow_mut().insert(
            scope_id,
            CachedSeed {
                seed,
                floor,
                namespace,
            },
        );
    }
}

/// Whether `seed` derives the scope root's own `ipnsName` — the one proof every
/// holder of a write scope seed is held to, stated once so they cannot drift
/// apart: the deposit ([`deposit_write_seed`]), the read
/// ([`Engine::vault_root_scope`](crate::facade::Engine::vault_root_scope)),
/// and the mint of a descendant scope's own write plane
/// ([`ScopeWalk::descendant_scope_roots`](crate::net::ScopeWalk::descendant_scope_roots)).
pub(crate) fn seed_names(
    seed: &[u8; 32],
    scope_id: &[u8; 16],
    root_name: Option<&IpnsName>,
) -> bool {
    root_name.is_some_and(|name| derive_write_name(seed, scope_id) == *name)
}

/// Deposit a recovered scope write seed, but only if it derives the very name
/// the scope root publishes under. A write-capable grantee can commit an
/// owner-write-blob wrapping a seed of its choosing; holding it would make the
/// drain mint every new node's `ipnsName` and signer from a key that party also
/// holds. A seed that cannot name our own root is not our scope's — held
/// keyless, never a trust verdict.
pub(crate) fn deposit_write_seed(
    cell: &RefCell<ScopeSeeds>,
    scope_id: [u8; 16],
    seed: Zeroizing<[u8; 32]>,
    root_name: Option<&IpnsName>,
    floor: Option<u64>,
    namespace: FloorNamespace,
) {
    if seed_names(&seed, &scope_id, root_name) {
        deposit_seed(cell, scope_id, seed, floor, namespace);
    }
}

/// A scope's two durable epoch floors as one resolve pass observed them, before
/// the resolve moved either. `None` on a floor-store failure (see
/// [`refresh_seed_floor`]).
pub(crate) struct SeedFloors {
    pub(crate) read: Option<u64>,
    pub(crate) write: Option<u64>,
}

/// Evict both of an own scope's cached seeds against their durable floors and
/// report those floors, the stamps this pass's deposits carry.
pub(crate) async fn refresh_seed_floors<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    read_seeds: &RefCell<ScopeSeeds>,
    write_seeds: &RefCell<ScopeSeeds>,
) -> SeedFloors {
    let own = FloorNamespace::Own.view(floors);
    SeedFloors {
        read: refresh_seed_floor(&own, read_seeds, scope_id, SeedFloor::Read).await,
        write: refresh_seed_floor(&own, write_seeds, scope_id, SeedFloor::Write).await,
    }
}

/// What each boundary the last walk proved seals under: the read epoch that walk
/// recorded, paired with the two seeds the per-scope caches hold. A boundary
/// missing either seed is left out.
///
/// The copy is not eviction-tracked — [`cached_seed`] runs no floor pass — so it
/// is not the authority on whether a seed is still current. Every consumer
/// re-proves the epoch against a gate-passing scope root record before it
/// authors anything ([`crate::sync::drain::Drain::open_scope_root`]), and a
/// below-floor seed opens no root body at all.
pub(crate) fn walked_boundary_material(
    walked: &RefCell<WalkedReadEpochs>,
    read_seeds: &RefCell<ScopeSeeds>,
    write_seeds: &RefCell<ScopeSeeds>,
) -> BTreeMap<NodeId, ScopeMaterial> {
    walked
        .borrow()
        .iter()
        .filter_map(|(root, read_epoch)| {
            Some((
                *root,
                ScopeMaterial {
                    read_scope_seed: cached_seed(read_seeds, &root.0)?,
                    write_scope_seed: cached_seed(write_seeds, &root.0)?,
                    read_epoch: *read_epoch,
                },
            ))
        })
        .collect()
}

/// The scope's cached seed when it was deposited in `namespace`, without an
/// eviction pass.
pub(crate) fn cached_seed_in(
    cell: &RefCell<ScopeSeeds>,
    scope_id: &[u8; 16],
    namespace: FloorNamespace,
) -> Option<Zeroizing<[u8; 32]>> {
    cached_stamped_seed_in(cell, scope_id, namespace).map(|cached| cached.seed)
}

/// [`cached_seed_in`] with the seed's stamp.
pub(crate) fn cached_stamped_seed_in(
    cell: &RefCell<ScopeSeeds>,
    scope_id: &[u8; 16],
    namespace: FloorNamespace,
) -> Option<StampedSeed> {
    cell.borrow()
        .get(scope_id)
        .filter(|cached| cached.namespace == namespace)
        .map(|cached| StampedSeed {
            seed: cached.seed.clone(),
            stamp: cached.floor,
        })
}

/// The scope's cached seed, without an eviction pass.
pub(crate) fn cached_seed(
    cell: &RefCell<ScopeSeeds>,
    scope_id: &[u8; 16],
) -> Option<Zeroizing<[u8; 32]>> {
    cached_stamped_seed(cell, scope_id).map(|cached| cached.seed)
}

/// The scope's cached seed with its stamp, without an eviction pass.
pub(crate) fn cached_stamped_seed(
    cell: &RefCell<ScopeSeeds>,
    scope_id: &[u8; 16],
) -> Option<StampedSeed> {
    cell.borrow().get(scope_id).map(|cached| StampedSeed {
        seed: cached.seed.clone(),
        stamp: cached.floor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::SeamError;
    use crate::testkit::block_on;

    /// The cache's retention rule, at the mechanism: a seed lives exactly as
    /// long as the durable floor stays at or below its stamp, and an unreadable
    /// floor holds nothing.
    #[test]
    fn a_cached_seed_lives_only_while_the_floor_stays_at_its_stamp() {
        use crate::testkit::fakes::InMemoryFloorStore;

        const SCOPE: [u8; 16] = [4u8; 16];
        let floors = InMemoryFloorStore::default();
        let own = FloorNamespace::Own.view(&floors);
        let cell = RefCell::new(ScopeSeeds::new());
        block_on(async {
            floors.raise_epoch_floor(&SCOPE, 5).await.unwrap();
            let stamp = refresh_seed_floor(&own, &cell, &SCOPE, SeedFloor::Read).await;
            assert_eq!(stamp, Some(5));
            deposit_seed(
                &cell,
                SCOPE,
                Zeroizing::new([3u8; 32]),
                stamp,
                FloorNamespace::Own,
            );

            refresh_seed_floor(&own, &cell, &SCOPE, SeedFloor::Read).await;
            assert!(
                cell.borrow().contains_key(&SCOPE),
                "an unmoved floor keeps the seed"
            );

            floors.raise_epoch_floor(&SCOPE, 6).await.unwrap();
            refresh_seed_floor(&own, &cell, &SCOPE, SeedFloor::Read).await;
            assert!(
                !cell.borrow().contains_key(&SCOPE),
                "the rise past the stamp revokes it"
            );

            // A stamp the caller could not read holds nothing, so a floor-store
            // failure never leaves an unprovable seed resident.
            deposit_seed(
                &cell,
                SCOPE,
                Zeroizing::new([3u8; 32]),
                None,
                FloorNamespace::Own,
            );
            assert!(!cell.borrow().contains_key(&SCOPE));
        });
    }

    /// A read in another namespace evicts the seed ([`CachedSeed`]).
    #[test]
    fn a_cached_seed_read_in_another_namespace_is_evicted() {
        use crate::seams::ContactLabel;
        use crate::testkit::fakes::InMemoryFloorStore;
        use cipherbox_core::kdf;

        const SCOPE: [u8; 16] = [6u8; 16];
        let label_seed = kdf::contact_label_seed(&[0x4c; 32]);
        let first = FloorNamespace::GrantedBy(ContactLabel::of(&label_seed, &[0x02; 33]));
        let second = FloorNamespace::GrantedBy(ContactLabel::of(&label_seed, &[0x03; 33]));
        let floors = InMemoryFloorStore::default();
        let cell = RefCell::new(ScopeSeeds::new());
        block_on(async {
            for other in [second, FloorNamespace::Own] {
                deposit_seed(&cell, SCOPE, Zeroizing::new([3u8; 32]), Some(4), first);
                refresh_seed_floor(&first.view(&floors), &cell, &SCOPE, SeedFloor::Read).await;
                assert!(
                    cell.borrow().contains_key(&SCOPE),
                    "a read in its own namespace keeps the seed"
                );
                assert!(cached_seed_in(&cell, &SCOPE, first).is_some());
                assert!(
                    cached_seed_in(&cell, &SCOPE, other).is_none(),
                    "another namespace is not served the seed"
                );

                refresh_seed_floor(&other.view(&floors), &cell, &SCOPE, SeedFloor::Read).await;
                assert!(
                    !cell.borrow().contains_key(&SCOPE),
                    "a read in another namespace evicts the seed"
                );
            }
        });
    }

    /// A floor store whose reads fail — the seam-outage arm of
    /// [`refresh_seed_floor`], which no in-memory fake exercises.
    struct UnreadableFloors;

    impl FloorStore for UnreadableFloors {
        async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
            Err(SeamError::new("floor store unavailable"))
        }

        async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }

        async fn sequence_floor(&self, _ipns_name: &[u8]) -> SeamResult<Option<u64>> {
            Err(SeamError::new("floor store unavailable"))
        }

        async fn raise_sequence_floor(&self, _ipns_name: &[u8], _sequence: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }

        async fn clear(&self) -> SeamResult<()> {
            Err(SeamError::new("floor store unavailable"))
        }
    }

    /// A floor that cannot be read evicts: a seed whose currency cannot be
    /// established is dropped, not trusted for the rest of the session.
    /// Stamped far above any floor either arm could return, so only the read
    /// failure can account for the eviction.
    #[test]
    fn an_unreadable_floor_evicts_the_cached_seed() {
        const SCOPE: [u8; 16] = [5u8; 16];
        let cell = RefCell::new(ScopeSeeds::new());
        block_on(async {
            for which in [SeedFloor::Read, SeedFloor::Write] {
                cell.borrow_mut().insert(
                    SCOPE,
                    CachedSeed {
                        seed: Zeroizing::new([3u8; 32]),
                        floor: u64::MAX,
                        namespace: FloorNamespace::Own,
                    },
                );
                let unreadable = FloorNamespace::Own.view(&UnreadableFloors);
                let stamp = refresh_seed_floor(&unreadable, &cell, &SCOPE, which).await;
                assert_eq!(stamp, None, "an unread floor stamps nothing");
                assert!(
                    !cell.borrow().contains_key(&SCOPE),
                    "the seed goes with the floor that could not vouch for it"
                );
            }
        });
    }
}
