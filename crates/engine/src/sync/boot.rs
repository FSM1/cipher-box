//! The cold-start live-session data path — the ordered chain composed on top of
//! the seed-derived session identity (blueprint/engine.md "Adoption gate and
//! floors", "Pointer planes"; CONTEXT.md "Vault pointer", "Floor law",
//! "Re-point object").
//!
//! The non-circular cold-start sequence (#38 D3): own vault → scope/vault
//! pointer (first act) → floors seeded → current root name → envelope grant
//! blob → seeds → render. This module composes that chain as a **pure
//! orchestration over the seam traits** — it derives no key material and defines
//! no crypto: the vault-pointer walk ([`resolve_vault_pointer`]), the floor law
//! ([`floor::cold_seed_checked`]), and the gated resolve ([`net::resolve`]) are
//! the machinery it sequences. Determinism is preserved: no clock and no RNG are
//! read here — the entire chain is a function of the injected seams plus the
//! session inputs, so two engines on independent virtual clocks agree.
//!
//! The record plane is fetched through two seam traits:
//! [`PointerFetch`](crate::sync::PointerFetch) fronts the vault-pointer block
//! resolve, and [`Adopter`](crate::net::Adopter) fronts the root-record
//! candidate assembly and the adoption gate. This slice owns the sequencing and
//! the fail-closed points; the concrete fetchers plug in behind these traits.

use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use zeroize::Zeroizing;

use crate::facade::{Event, NodeId};
use crate::gate::GateRejection;
use crate::gate::floor::{self, ColdSeedError, FloorRegression};
use crate::net::{Adopter, GatedResolve, ResolveOutcome, resolve_gated};
use crate::seams::{FloorStore, RecordTransport, SeamError, SnapshotCache};
use crate::sync::model::Snapshot;
use crate::sync::op::Op;
use crate::sync::overlay::apply_overlay;
use crate::sync::pointer::{
    PointerError, PointerFetch, VaultPointerAdoption, resolve_vault_pointer,
};
use crate::sync::project::project_root;

/// The session inputs the cold-start chain needs, all read from the derived
/// [`SessionIdentity`](crate::session::SessionIdentity) and the auth-provided
/// owner identity — never re-derived here.
pub struct ColdStartParams<'a> {
    /// The login secret, for the runtime vault-pointer index probe (owner-plane
    /// name derivation happens inside the pointer walk).
    pub login_secret: &'a [u8],
    /// The contact-code-anchored owner identity that signs the re-point object
    /// (from auth; the vault-pointer walk's fail-closed verify anchor).
    pub owner_identity: &'a EcdsaVerifier,
    /// The root scope id (the vault's own scope) — the floor key and the
    /// pointer-read-key binding.
    pub root_scope_id: [u8; 16],
    /// The re-point payload wire version the walk verifies against.
    pub payload_version: u64,
    /// The vault root node id, anchoring the rendered snapshot.
    pub root: NodeId,
    /// The durable pending-op queue, applied as the overlay on first paint.
    pub pending_ops: &'a [Op],
}

/// A fail-closed cold-start failure. [`ColdStartError::Seam`] is availability
/// (retryable host I/O) and [`ColdStartError::NotStarted`] is a caller-ordering
/// precondition; every other arm is a trust violation the engine never renders
/// past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdStartError {
    /// The vault-pointer walk hit a forged/tampered index — fail-closed.
    VaultPointer(PointerError),
    /// The owner-vouched re-point regressed a durable floor — a rolled-back
    /// pointer, fail-closed (the floor law).
    FloorRegression(FloorRegression),
    /// The current root record failed the adoption gate — fail-closed.
    RootAdoption(GateRejection),
    /// A host seam failure (floor store, snapshot cache, transport) — not a
    /// trust decision.
    Seam(SeamError),
    /// Cold start was invoked before `start` derived the session identity — a
    /// caller-ordering precondition, mirroring `EngineError::NotStarted` rather
    /// than panicking.
    NotStarted,
}

impl core::fmt::Display for ColdStartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ColdStartError::VaultPointer(e) => write!(f, "vault-pointer resolve failed: {e:?}"),
            ColdStartError::FloorRegression(r) => write!(f, "{r}"),
            ColdStartError::RootAdoption(r) => write!(f, "{r}"),
            ColdStartError::Seam(e) => write!(f, "{e}"),
            ColdStartError::NotStarted => f.write_str("engine not started"),
        }
    }
}

impl std::error::Error for ColdStartError {}

/// The gate verdict on the current root record, once a vault pointer was adopted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootResolve {
    /// A gate-passing record was adopted (its bytes are the new last-known-good).
    Adopted,
    /// No newer record than the cached last-known-good (availability staleness).
    NoUpdate,
}

/// What the cold-start data path produced.
///
/// `Debug` is hand-written: [`read_scope_seed`](Self::read_scope_seed) is key
/// material and must never reach a log site (security rule 2), including a
/// test-assertion `{:?}`.
#[derive(Clone, PartialEq, Eq)]
pub struct ColdStartOutcome {
    /// The adopted vault pointer, or `None` on an empty chain (a first-run vault
    /// with no pointer yet — cold start adopts nothing).
    pub vault_pointer: Option<VaultPointerAdoption>,
    /// The current-root gate verdict, or `None` when no pointer was adopted.
    pub root_resolve: Option<RootResolve>,
    /// Whether cache-first rehydrate found last-known-good for the current root.
    pub rehydrated: bool,
    /// The gate-passing base snapshot the engine adopts as the state law's left
    /// operand: the adopted root read-body projected to its direct children
    /// ([`project_root`], E7) when a pointer resolved to a gate-passing record,
    /// else the anchored root ([`Snapshot::new`]) on an empty/degenerate chain.
    pub base: Snapshot,
    /// The rendered view emitted on the first snapshot event: `base` ⊕ the
    /// pending-op overlay.
    pub rendered: Snapshot,
    /// The root-scope read seed a gate-passing adopt recovered from the owner
    /// blob; `None` when nothing adopted. The engine deposits it in its
    /// in-memory per-scope seed cell (never persisted).
    pub read_scope_seed: Option<Zeroizing<[u8; 32]>>,
    /// The (node id, scope write seed) the same adopt recovered from the
    /// owner-write-blob; `None` when nothing adopted or the root is held
    /// keyless. The drain derives every new node's name and per-name signer
    /// from it (never persisted).
    pub write_scope_seed: Option<([u8; 16], Zeroizing<[u8; 32]>)>,
}

impl core::fmt::Debug for ColdStartOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ColdStartOutcome")
            .field("vault_pointer", &self.vault_pointer)
            .field("root_resolve", &self.root_resolve)
            .field("rehydrated", &self.rehydrated)
            .field("base", &self.base)
            .field("rendered", &self.rendered)
            .field(
                "read_scope_seed",
                &self.read_scope_seed.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "write_scope_seed",
                &self.write_scope_seed.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Run the cold-start live-session data path off the injected seams, emitting
/// the first [`Event::SnapshotUpdated`]. Fail-closed at every trust boundary
/// (see [`ColdStartError`]): a trust violation returns `Err`, never silent
/// staleness. Reads no clock and no RNG — the sequence is a pure function of the
/// injected seams and [`ColdStartParams`], so two engines on independent clocks
/// produce the identical outcome.
pub async fn cold_start<Pf, Ad, Fl, T, Sc>(
    pointer_fetch: &Pf,
    adopter: &Ad,
    floors: &Fl,
    transport: &T,
    snapshot_cache: &Sc,
    params: &ColdStartParams<'_>,
    emit: &mut dyn FnMut(Event),
) -> Result<ColdStartOutcome, ColdStartError>
where
    Pf: PointerFetch,
    Ad: Adopter,
    Fl: FloorStore,
    T: RecordTransport,
    Sc: SnapshotCache,
{
    // Step 1 — vault-pointer resolve (the first act). A forged index is
    // fail-closed inside the walk.
    let adoption = resolve_vault_pointer(
        pointer_fetch,
        params.login_secret,
        params.owner_identity,
        &params.root_scope_id,
        params.payload_version,
    )
    .await
    .map_err(ColdStartError::VaultPointer)?;

    let base = Snapshot::new(params.root);
    let Some(adoption) = adoption else {
        // Empty chain: a first-run vault with no pointer yet. Cold start adopts
        // nothing (no floor seeds, no root), but the empty base ⊕ overlay still
        // paints so pending ops render.
        let rendered = apply_overlay(&base, params.pending_ops);
        emit(Event::SnapshotUpdated);
        return Ok(ColdStartOutcome {
            vault_pointer: None,
            root_resolve: None,
            rehydrated: false,
            base,
            rendered,
            read_scope_seed: None,
            write_scope_seed: None,
        });
    };

    // Step 2 — floor cold-seed, fail-closed on regression: a re-point that would
    // move either floor backward is a rolled-back pointer, a trust violation.
    // The anchor role is derived from the session's own root scope id, never
    // chosen here (see `floor::AnchorRole`).
    floor::cold_seed_checked(floors, &adoption.repoint, &params.root_scope_id)
        .await
        .map_err(|e| match e {
            ColdSeedError::Seam(seam) => ColdStartError::Seam(seam),
            ColdSeedError::Regression(reg) => ColdStartError::FloorRegression(reg),
        })?;

    // Step 3 + 5 — current root name adoption through the gated, cache-first
    // resolve: last-known-good rehydrates the first paint (step 5) while the
    // fan-out GET + adoption gate reconcile behind it (step 3). Every resolved
    // record passes the gate; a rejection is fail-closed.
    let GatedResolve {
        resolved,
        read_scope_seed,
        hold: write_scope_seed,
        ..
    } = resolve_gated(
        transport,
        snapshot_cache,
        adopter,
        &adoption.repoint.current_root,
    )
    .await
    .map_err(ColdStartError::Seam)?;
    // Project the gate-passing root read-body to its direct children (E7); an
    // availability-stale current record leaves the base at the anchored root.
    let (root_resolve, base) = match resolved.outcome {
        ResolveOutcome::Adopted(adopted) => {
            let mut base = base;
            project_root(&mut base, params.root, &adopted);
            (RootResolve::Adopted, base)
        }
        // Cold start paints, it does not hold: our own current record at the
        // floor is availability staleness here, same as nothing newer fetched.
        ResolveOutcome::NoUpdate | ResolveOutcome::Current { .. } => (RootResolve::NoUpdate, base),
        ResolveOutcome::TrustViolation(rejection) => {
            return Err(ColdStartError::RootAdoption(rejection));
        }
    };

    // Step 4 — first snapshot event with the pending-op overlay applied.
    let rendered = apply_overlay(&base, params.pending_ops);
    emit(Event::SnapshotUpdated);

    Ok(ColdStartOutcome {
        vault_pointer: Some(adoption),
        root_resolve: Some(root_resolve),
        rehydrated: resolved.last_known_good.is_some(),
        base,
        rendered,
        read_scope_seed,
        write_scope_seed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::UnixMillis;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Journal time for ops whose narrative does not turn on it.
    const AT: UnixMillis = UnixMillis(0);

    use cipherbox_core::ipns::{IpnsName, IpnsRecord};
    use cipherbox_core::kdf;
    use cipherbox_core::payload::RepointObject;
    use cipherbox_core::seal::{PreservedFields, ReadBody};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use crate::facade::NodeId;
    use crate::gate::{Adopted, GateError, GateRejection, GateStage, RejectionReason};
    use crate::seams::{EndpointId, FloorStore, SeamResult, SnapshotCache};
    use crate::sync::op::Op;
    use crate::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};
    use crate::testkit::fakes::{InMemoryFloorStore, InMemoryRecordStore, InMemorySnapshotCache};
    use crate::testkit::{SeededEntropy, block_on};

    const SECRET: &[u8] = b"cold-start-login-secret-fixture";
    const ROOT_SCOPE: [u8; 16] = [0u8; 16];
    const VERSION: u64 = 1;

    fn owner() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[3u8; 32]).expect("valid scalar")
    }

    fn root_id() -> NodeId {
        NodeId([0xAB; 16])
    }

    /// A scripted vault-pointer network: names → sealed re-point blocks; unknown
    /// names are unresolvable (chain gaps).
    #[derive(Clone, Default)]
    struct ScriptedPointers {
        blocks: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl ScriptedPointers {
        fn seal_index(&self, owner: &EcdsaSigner, index: u64, object: &RepointObject) {
            let read_key =
                kdf::pointer_read_key(kdf::owner_pointer_seed(SECRET).as_bytes(), &ROOT_SCOPE);
            let mut entropy = SeededEntropy::new(index);
            let block = seal_repoint(
                SessionRole::Owner,
                &mut entropy,
                read_key.as_bytes(),
                VERSION,
                owner,
                object,
            )
            .unwrap();
            self.blocks
                .lock()
                .unwrap()
                .insert(vault_pointer_name(SECRET, index).as_str().to_owned(), block);
        }
    }

    impl PointerFetch for ScriptedPointers {
        async fn fetch(&self, name: &IpnsName) -> SeamResult<Option<Vec<u8>>> {
            Ok(self.blocks.lock().unwrap().get(name.as_str()).cloned())
        }
    }

    /// A scripted adopter: returns the configured gate verdict for any record.
    #[derive(Clone)]
    struct ScriptedAdopter {
        verdict: Arc<Mutex<Result<Adopted, GateError>>>,
    }

    impl ScriptedAdopter {
        fn adopting() -> Self {
            Self {
                verdict: Arc::new(Mutex::new(Ok(Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: PreservedFields::new(),
                    },
                    sequence: 1,
                    epoch: 1,
                }))),
            }
        }

        fn rejecting() -> Self {
            Self {
                verdict: Arc::new(Mutex::new(Err(GateError::Rejected(GateRejection {
                    stage: GateStage::Unseal,
                    reason: RejectionReason::EpochBelowFloor { floor: 9, epoch: 1 },
                })))),
            }
        }
    }

    impl Adopter for ScriptedAdopter {
        async fn adopt(
            &self,
            _name: &IpnsName,
            _record_bytes: &[u8],
        ) -> Result<crate::net::AdoptOutcome, GateError> {
            self.verdict
                .lock()
                .unwrap()
                .clone()
                .map(|adopted| crate::net::AdoptOutcome {
                    adopted,
                    write_scope_seed: None,
                    node_id: [0u8; 16],
                    read_scope_seed: None,
                })
        }
    }

    fn root_signer() -> Ed25519Signer {
        kdf::ipns_keypair(&[9u8; 32])
    }

    fn repoint(current_root: IpnsName, min_read_epoch: u64, write_epoch: u64) -> RepointObject {
        RepointObject {
            scope_id: ROOT_SCOPE,
            current_root,
            write_epoch,
            min_read_epoch,
            prev_root: None,
        }
    }

    /// Two endpoints with a valid signed IPNS record at the root name.
    fn transport_with_root_record(name: &IpnsName) -> InMemoryRecordStore {
        let store = InMemoryRecordStore::new(vec![EndpointId::new("e1"), EndpointId::new("e2")]);
        let record = IpnsRecord::create_v2(
            &root_signer(),
            b"/ipfs/bafyrootmetadatacid",
            1,
            0,
            "2099-01-01T00:00:00Z",
        )
        .marshal();
        store.seed_record(&EndpointId::new("e1"), name.as_str(), record);
        store
    }

    fn empty_transport() -> InMemoryRecordStore {
        InMemoryRecordStore::new(vec![EndpointId::new("e1"), EndpointId::new("e2")])
    }

    use crate::sync::op::NewNode;

    fn pending_create() -> Vec<Op> {
        vec![Op::create(
            NodeId([1u8; 16]),
            root_id(),
            "pending.txt",
            NewNode::File { content: None },
            1,
            AT,
        )]
    }

    /// Drive `cold_start`, collecting emitted events.
    async fn run<Pf: PointerFetch, Ad: Adopter, Fl: FloorStore, Sc: SnapshotCache>(
        pointers: &Pf,
        adopter: &Ad,
        floors: &Fl,
        transport: &InMemoryRecordStore,
        cache: &Sc,
        pending: &[Op],
    ) -> (Result<ColdStartOutcome, ColdStartError>, Vec<Event>) {
        let events = RefCell::new(Vec::new());
        let params = ColdStartParams {
            login_secret: SECRET,
            owner_identity: &owner().verifying_key(),
            root_scope_id: ROOT_SCOPE,
            payload_version: VERSION,
            root: root_id(),
            pending_ops: pending,
        };
        let out = cold_start(
            pointers,
            adopter,
            floors,
            transport,
            cache,
            &params,
            &mut |e: Event| events.borrow_mut().push(e),
        )
        .await;
        (out, events.into_inner())
    }

    #[test]
    fn empty_chain_paints_an_overlay_only_snapshot() {
        block_on(async {
            let (out, events) = run(
                &ScriptedPointers::default(),
                &ScriptedAdopter::adopting(),
                &InMemoryFloorStore::default(),
                &empty_transport(),
                &InMemorySnapshotCache::default(),
                &pending_create(),
            )
            .await;
            let out = out.unwrap();
            assert_eq!(out.vault_pointer, None, "no pointer on a first-run vault");
            assert_eq!(out.root_resolve, None);
            assert!(!out.rehydrated);
            assert!(
                out.rendered.contains(NodeId([1u8; 16])),
                "the pending create renders over the empty base"
            );
            assert_eq!(
                events,
                vec![Event::SnapshotUpdated],
                "first paint still emits"
            );
        });
    }

    #[test]
    fn adopts_highest_valid_pointer_seeds_floors_and_emits() {
        block_on(async {
            let pointers = ScriptedPointers::default();
            let root_name = IpnsName::from_public_key(&root_signer().verifying_key());
            // Owner authored indices 0 and 1; the highest valid wins.
            pointers.seal_index(&owner(), 0, &repoint(root_name.clone(), 1, 1));
            pointers.seal_index(&owner(), 1, &repoint(root_name.clone(), 3, 2));

            let floors = InMemoryFloorStore::default();
            let (out, events) = run(
                &pointers,
                &ScriptedAdopter::adopting(),
                &floors,
                &transport_with_root_record(&root_name),
                &InMemorySnapshotCache::default(),
                &pending_create(),
            )
            .await;
            let out = out.unwrap();
            assert_eq!(out.vault_pointer.unwrap().index, 1, "highest valid index");
            assert_eq!(out.root_resolve, Some(RootResolve::Adopted));
            assert_eq!(events, vec![Event::SnapshotUpdated]);
            // The re-point's owner-vouched epochs seeded the durable floors.
            assert_eq!(
                floor::read_epoch_floor(&floors, &ROOT_SCOPE).await.unwrap(),
                Some(3)
            );
            assert_eq!(
                floor::write_epoch_floor(&floors, &ROOT_SCOPE)
                    .await
                    .unwrap(),
                Some(2)
            );
        });
    }

    #[test]
    fn rehydrate_on_boot_renders_from_the_snapshot_cache() {
        block_on(async {
            let pointers = ScriptedPointers::default();
            let root_name = IpnsName::from_public_key(&root_signer().verifying_key());
            pointers.seal_index(&owner(), 0, &repoint(root_name.clone(), 1, 1));

            // Pre-seed last-known-good for the root name: cache-first first paint.
            let cache = InMemorySnapshotCache::default();
            cache
                .put(root_name.as_str().as_bytes(), b"cached-last-known-good")
                .await
                .unwrap();

            let (out, events) = run(
                &pointers,
                &ScriptedAdopter::adopting(),
                &InMemoryFloorStore::default(),
                // No network record: NoUpdate, but the cache still rehydrates.
                &empty_transport(),
                &cache,
                &pending_create(),
            )
            .await;
            let out = out.unwrap();
            assert!(
                out.rehydrated,
                "cache-first rehydrate found last-known-good"
            );
            assert_eq!(out.root_resolve, Some(RootResolve::NoUpdate));
            assert_eq!(events, vec![Event::SnapshotUpdated]);
        });
    }

    #[test]
    fn floor_regression_is_fail_closed_and_emits_nothing() {
        block_on(async {
            let pointers = ScriptedPointers::default();
            let root_name = IpnsName::from_public_key(&root_signer().verifying_key());
            // The re-point vouches a lower minReadEpoch than the durable floor.
            pointers.seal_index(&owner(), 0, &repoint(root_name.clone(), 2, 1));

            let floors = InMemoryFloorStore::default();
            floors.raise_epoch_floor(&ROOT_SCOPE, 5).await.unwrap();

            let (out, events) = run(
                &pointers,
                &ScriptedAdopter::adopting(),
                &floors,
                &transport_with_root_record(&root_name),
                &InMemorySnapshotCache::default(),
                &pending_create(),
            )
            .await;
            assert_eq!(
                out,
                Err(ColdStartError::FloorRegression(
                    FloorRegression::ReadEpoch {
                        floor: 5,
                        vouched: 2,
                    }
                ))
            );
            assert!(events.is_empty(), "a trust violation never paints");
        });
    }

    /// End-to-end: the floors a first cold start seeds are the ones a rolled-back
    /// re-point trips on the next boot — no floor pre-seeding in the fixture.
    #[test]
    fn a_rolled_back_repoint_is_fail_closed_against_the_floors_a_prior_boot_seeded() {
        block_on(async {
            let pointers = ScriptedPointers::default();
            let root_name = IpnsName::from_public_key(&root_signer().verifying_key());
            pointers.seal_index(&owner(), 0, &repoint(root_name.clone(), 5, 3));

            let floors = InMemoryFloorStore::default();
            let transport = transport_with_root_record(&root_name);
            let (first, _) = run(
                &pointers,
                &ScriptedAdopter::adopting(),
                &floors,
                &transport,
                &InMemorySnapshotCache::default(),
                &[],
            )
            .await;
            first.expect("the first boot seeds the floors");

            // The owner-signed index is replaced by an older, still validly signed
            // re-point: a replay the signature alone cannot detect.
            pointers.seal_index(&owner(), 0, &repoint(root_name.clone(), 2, 3));
            let (second, events) = run(
                &pointers,
                &ScriptedAdopter::adopting(),
                &floors,
                &transport,
                &InMemorySnapshotCache::default(),
                &[],
            )
            .await;
            assert_eq!(
                second,
                Err(ColdStartError::FloorRegression(
                    FloorRegression::ReadEpoch {
                        floor: 5,
                        vouched: 2,
                    }
                ))
            );
            assert!(events.is_empty(), "a trust violation never paints");
        });
    }

    #[test]
    fn adoption_gate_failure_is_fail_closed_and_emits_nothing() {
        block_on(async {
            let pointers = ScriptedPointers::default();
            let root_name = IpnsName::from_public_key(&root_signer().verifying_key());
            pointers.seal_index(&owner(), 0, &repoint(root_name.clone(), 1, 1));

            let (out, events) = run(
                &pointers,
                &ScriptedAdopter::rejecting(),
                &InMemoryFloorStore::default(),
                &transport_with_root_record(&root_name),
                &InMemorySnapshotCache::default(),
                &pending_create(),
            )
            .await;
            assert!(
                matches!(out, Err(ColdStartError::RootAdoption(_))),
                "a gate rejection is fail-closed, got {out:?}"
            );
            assert!(events.is_empty());
        });
    }

    #[test]
    fn a_forged_pointer_index_is_fail_closed() {
        block_on(async {
            let pointers = ScriptedPointers::default();
            let root_name = IpnsName::from_public_key(&root_signer().verifying_key());
            pointers.seal_index(&owner(), 0, &repoint(root_name.clone(), 1, 1));
            // Index 1 sealed by a rogue identity: it must not open under the owner.
            let rogue = EcdsaSigner::from_scalar(&[7u8; 32]).unwrap();
            pointers.seal_index(&rogue, 1, &repoint(root_name, 9, 9));

            let (out, events) = run(
                &pointers,
                &ScriptedAdopter::adopting(),
                &InMemoryFloorStore::default(),
                &empty_transport(),
                &InMemorySnapshotCache::default(),
                &pending_create(),
            )
            .await;
            assert!(
                matches!(out, Err(ColdStartError::VaultPointer(_))),
                "a forged index stops the walk fail-closed, got {out:?}"
            );
            assert!(events.is_empty());
        });
    }
}
