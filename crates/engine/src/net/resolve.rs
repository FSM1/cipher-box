//! The resolve pipeline: cache-first, fan-out GET, core verify, adoption gate
//! on every resolve (blueprint/engine.md "Resolve/publish pipeline: Resolve",
//! #23 D5, #33 D7).
//!
//! Cache-first — the UI never blocks on network resolution: last-known-good
//! renders immediately and the network reconcile runs behind it. A fan-out GET
//! collects the endpoint set's copies, core verifies each against the name, and
//! the freshest verified record passes the adoption gate. Only a gate-passing
//! record touches the snapshot; a gate failure is a fail-closed trust violation
//! that pins last-known-good and never renders the rejected record.
//!
//! The gate itself is a composition over content-plane and reader state, reached
//! through the [`Adopter`] seam. **Every** fetched record is routed through
//! [`Adopter::adopt`] — there is no ungated path to the snapshot.

use core::cell::RefCell;

use cipherbox_core::ipns::{IpnsName, VerifiedRecord};
use zeroize::Zeroizing;

use super::fanout::fanout_get_verify;
use super::liveness::{HeldKey, HeldRecord, HeldRecords, HeldValue};
use super::publish::head_cid_from_value;
use crate::facade::NodeId;
use crate::gate::{Adopted, GateError, GateRejection, RejectionReason};
use crate::seams::{RecordTransport, SeamError, SnapshotCache};
use crate::session::SessionIdentity;
use crate::sync::model::Snapshot;
use crate::sync::project::{FolderMerge, merge_root};
use crate::sync::tick::ResolveMode;

/// Runs the adoption gate over a fetched record. The concrete implementation
/// assembles the content-plane candidate and the reader's private context and
/// calls [`crate::gate::adopt`]. The resolve pipeline requires only this: every
/// record it fetches is adopted through here before it can touch the snapshot
/// (blueprint/engine.md: "only gate-passing records touch the snapshot").
pub trait Adopter {
    /// Assemble and gate the record fetched under `name`. `Ok` carries the
    /// authenticated read-body and floors plus, for a write-capable holder, the
    /// transient write material the held set derives its renewal signer from;
    /// `Err(GateError::Rejected)` is a fail-closed trust violation;
    /// `Err(GateError::Seam)` is host I/O.
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<AdoptOutcome, GateError>;

    /// Recover the OWNER's own scope material for an equal-floor `Current` own
    /// record: the read seed the child pipeline and the drain seal under, and
    /// the write seed the liveness loop renews with. `Ok(None)` when the record
    /// is not our own or its owner blob will not open. Fail-OPEN: returns a
    /// [`SeamError`], never a `Rejected` verdict (a `Current` must never harden
    /// into a trust error). The default suits every non-owner adopter stub.
    async fn recover_own_scope_material(
        &self,
        _name: &IpnsName,
        _record_bytes: &[u8],
    ) -> Result<Option<OwnScopeMaterial>, SeamError> {
        Ok(None)
    }

    /// Gate the record fetched under `name` **without** advancing the name's
    /// sequence floor, and hand back the read scope seed the gate recovered from
    /// its owner blob (`None` when the reader's arm recovers none). Same
    /// fail-closed verdicts as [`adopt`](Self::adopt); only the floor advance is
    /// dropped.
    async fn probe_read_scope_seed(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError>;
}

/// The owner's own-scope seeds, recovered from a record already at the durable
/// sequence floor. Both come from grant-section structures the gate's stages
/// 1-3 authenticated before the floor stages ran, so an equal-floor `Current`
/// has proved them committed; neither is ever persisted.
pub struct OwnScopeMaterial {
    /// The scope-root node id the seeds belong to.
    pub node_id: [u8; 16],
    /// The scope read seed (the owner blob's override seed).
    pub read_scope_seed: Zeroizing<[u8; 32]>,
    /// The scope write seed, `None` when the root is held keyless (no
    /// owner-write-blob, or it will not open under the durable write floor).
    pub write_scope_seed: Option<Zeroizing<[u8; 32]>>,
    /// The read-body the recovery unsealed, at the floor sequence and epoch it
    /// re-imposed — see [`Resolved::current_at_floor`].
    pub at_floor: Adopted,
}

/// A gate pass plus the transient write material a write-capable holder needs to
/// keep its scope alive (blueprint/engine.md "Liveness").
pub struct AdoptOutcome {
    /// The authenticated read-body and floors.
    pub adopted: Adopted,
    /// The scope write seed, `Some` only for a write-capable holder (a write
    /// grant). `None` for a read-only holder and the owner arm → the record is
    /// held keyless. Transient: [`resolve_and_hold`] derives the narrow per-name
    /// signer and drops it; never persisted (least privilege; security rules
    /// 2/5).
    pub write_scope_seed: Option<Zeroizing<[u8; 32]>>,
    /// The scope-root node id (`id16`, the envelope id) — the held-set key and
    /// signer-derivation input for a gate-surfaced write grant.
    pub node_id: [u8; 16],
    /// The scope read seed a gate-passing owner adopt recovered from the owner
    /// blob. Transient like [`write_scope_seed`](Self::write_scope_seed): the
    /// engine deposits it in its in-memory per-scope seed map (never persisted,
    /// never on the public [`Resolved`]); the child read pipeline derives
    /// per-node read keys from it. `None` for a non-owner adopter.
    pub read_scope_seed: Option<Zeroizing<[u8; 32]>>,
}

/// What a resolve produced for the freshest fetched record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// A newer record passed the adoption gate: its bytes are now the snapshot's
    /// last-known-good and the read-body is authenticated.
    Adopted(Adopted),
    /// Our own current record re-fetched at exactly the durable sequence floor:
    /// no update, but the (already-verified, public/signed) bytes are in hand so
    /// the liveness loop can keep them alive without re-fetching. Carries no
    /// secret.
    Current {
        /// The verified record bytes, byte-stable for a keyless re-PUT.
        record_bytes: Vec<u8>,
    },
    /// The freshest fetched record failed the gate — a fail-closed trust
    /// violation. Last-known-good is pinned; the rejected record is never
    /// rendered.
    TrustViolation(GateRejection),
    /// No newer record was fetched: nothing resolvable (network unreachable /
    /// cold). This is availability staleness, not an error — the cached view
    /// stays usable.
    NoUpdate,
}

/// The result of a resolve: the cache-first last-known-good plus the network
/// reconcile outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Last-known-good record bytes from the snapshot cache, rendered
    /// immediately (cache-first). `None` on a cold cache.
    pub last_known_good: Option<Vec<u8>>,
    /// The gate verdict on the freshest fetched record.
    pub outcome: ResolveOutcome,
    /// The read-body an own [`ResolveOutcome::Current`] root carries, recovered
    /// at the floor by the same stages an adopt runs. A quarantine release rests
    /// on an absence a poll of this session established, so a root that resolves
    /// `Current` must still paint the base
    /// ([ADR 0011](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0011-quarantine-release-rests-on-the-doomed-manifest.md)
    /// D4).
    pub current_at_floor: Option<Adopted>,
}

#[cfg(test)]
impl Resolved {
    /// A resolve carrying `outcome` alone: no cached bytes and no
    /// floor-recovered read-body.
    pub(crate) fn just(outcome: ResolveOutcome) -> Self {
        Self {
            last_known_good: None,
            outcome,
            current_at_floor: None,
        }
    }
}

/// Resolve `name`: return last-known-good immediately, fan-out GET + core
/// verify, then the adoption gate on the freshest verified record; only a
/// gate-passing record is written back to the snapshot. A [`SeamError`] is a
/// genuine host durable-store failure (the snapshot cache, or a floor read
/// inside the gate); per-endpoint transport failures are tolerated upstream as
/// availability staleness.
pub async fn resolve<T, S, A>(
    transport: &T,
    snapshot_cache: &S,
    adopter: &A,
    name: &IpnsName,
    mode: ResolveMode,
) -> Result<Resolved, SeamError>
where
    T: RecordTransport,
    S: SnapshotCache,
    A: Adopter,
{
    // The public resolve drops the transient hold/seed material — only the
    // engine drivers ([`resolve_gated`], [`resolve_and_hold`]) consume it.
    Ok(
        resolve_gated(transport, snapshot_cache, adopter, name, mode)
            .await?
            .resolved,
    )
}

/// The (node id, write scope seed) a gate-surfaced write grant contributes to
/// the held set. `Some` only on a gate pass that carried a write seed.
pub(crate) type AdoptHold = ([u8; 16], Zeroizing<[u8; 32]>);

/// The internal gated-resolve product: the public outcome plus the transient
/// material the engine drivers consume — kept off the public [`Resolved`] so no
/// seed ever rides the facade-visible surface.
pub(crate) struct GatedResolve {
    /// The public resolve result.
    pub(crate) resolved: Resolved,
    /// The held-set (node id, write scope seed) from a gate-surfaced write grant.
    pub(crate) hold: Option<AdoptHold>,
    /// The verified record an alive-worthy outcome rides to the hold, with the
    /// bytes it verified over. Carrying the [`VerifiedRecord`] spares the hold a
    /// second parse+verify of the same bytes.
    pub(crate) held_record: Option<(VerifiedRecord, Vec<u8>)>,
    /// The scope read seed a gate-passing owner adopt recovered.
    pub(crate) read_scope_seed: Option<Zeroizing<[u8; 32]>>,
}

/// What one arm of the gate match yields beside its outcome. Named because four
/// of the five slots are `None` in two of the arms, which a tuple hides.
#[derive(Default)]
struct GatedParts {
    hold: Option<AdoptHold>,
    held_record: Option<(VerifiedRecord, Vec<u8>)>,
    read_scope_seed: Option<Zeroizing<[u8; 32]>>,
    current_at_floor: Option<Adopted>,
}

/// The gated resolve behind [`resolve`]/[`resolve_and_hold`] and the cold-start
/// driver.
pub(crate) async fn resolve_gated<T, S, A>(
    transport: &T,
    snapshot_cache: &S,
    adopter: &A,
    name: &IpnsName,
    mode: ResolveMode,
) -> Result<GatedResolve, SeamError>
where
    T: RecordTransport,
    S: SnapshotCache,
    A: Adopter,
{
    let cache_key = name.as_str().as_bytes();
    // Cache-first: last-known-good renders immediately, reconcile runs behind
    // it. Nocache never reads the cache, so only what the record plane serves
    // this pass can be rendered or reported (#33 D4). A gate-passing record
    // still writes back either way, so a forced refresh only ever leaves the
    // cache fresher.
    let last_known_good = match mode {
        ResolveMode::CacheFirst => snapshot_cache.get(cache_key).await?,
        ResolveMode::NoCache => None,
    };

    let (outcome, parts) = match fanout_get_verify(transport, name).await {
        None => (ResolveOutcome::NoUpdate, GatedParts::default()),
        Some((verified, bytes)) => match adopter.adopt(name, &bytes).await {
            Ok(AdoptOutcome {
                adopted,
                write_scope_seed,
                node_id,
                read_scope_seed,
            }) => {
                // Only gate-passing records touch the snapshot; the same verified
                // bytes ride out to the liveness hold, so no re-fetch/re-get.
                snapshot_cache.put(cache_key, &bytes).await?;
                (
                    ResolveOutcome::Adopted(adopted),
                    GatedParts {
                        hold: write_scope_seed.map(|seed| (node_id, seed)),
                        held_record: Some((verified, bytes)),
                        read_scope_seed,
                        current_at_floor: None,
                    },
                )
            }
            // A record at exactly the durable sequence floor is our own current
            // record re-fetched — no update, never a violation; its verified
            // bytes ride out so the liveness loop holds them without a re-fetch.
            // A strictly older sequence is a replay/rollback and stays a
            // fail-closed trust violation, as does every other gate rejection.
            Err(GateError::Rejected(rejection)) => match &rejection.reason {
                RejectionReason::SequenceNotNewer { floor, sequence } if sequence == floor => {
                    // Our own current root at exactly the floor: recover the
                    // owner's own scope seeds (fail-open) so the liveness loop
                    // can hold+renew it before its EOL lapses and the write
                    // plane keeps the keys it seals under across a session
                    // that adopts nothing. A non-owner record yields neither.
                    let material = adopter.recover_own_scope_material(name, &bytes).await?;
                    let recovered = material.map(|material| GatedParts {
                        hold: material
                            .write_scope_seed
                            .map(|seed| (material.node_id, seed)),
                        held_record: None,
                        read_scope_seed: Some(material.read_scope_seed),
                        current_at_floor: Some(material.at_floor),
                    });
                    (
                        ResolveOutcome::Current {
                            record_bytes: bytes.clone(),
                        },
                        GatedParts {
                            held_record: Some((verified, bytes)),
                            ..recovered.unwrap_or_default()
                        },
                    )
                }
                _ => (
                    ResolveOutcome::TrustViolation(rejection),
                    GatedParts::default(),
                ),
            },
            Err(GateError::Seam(error)) => return Err(error),
        },
    };
    let GatedParts {
        hold,
        held_record,
        read_scope_seed,
        current_at_floor,
    } = parts;

    Ok(GatedResolve {
        resolved: Resolved {
            last_known_good,
            outcome,
            current_at_floor,
        },
        hold,
        held_record,
        read_scope_seed,
    })
}

/// The transient insert-time input for a held record: the resolve/gate path has
/// already unsealed the scope's write seed for this node, so the held set
/// derives the narrow per-name signer from it once at insert and drops the seed
/// (never persisting it — see [`HeldRecord`]). Constructed by the resolve-tick
/// driver ([`Engine::spawn_resolve_tick_loop`](crate::facade)), hence
/// crate-internal.
pub(crate) struct HeldMaterial {
    /// The node id (`id16`) — the held-set key and a signer-derivation input for
    /// an own-scope record. A gate-surfaced write grant overrides it with the
    /// authenticated envelope id.
    pub node_id: [u8; 16],
    /// Our own scope's write seed for an own-scope record (`Current`, or an
    /// adopt with no gate-surfaced seed). `None` when the seed rides the adopt
    /// instead (a write grantee). An insert-time derivation input, never
    /// persisted in the held set.
    pub write_scope_seed: Option<Zeroizing<[u8; 32]>>,
}

/// What [`resolve_and_hold`] produced: the public resolve result plus the
/// transient scope material a gate-passing adopt recovered. Kept off the public
/// [`Resolved`] so no seed ever rides the facade-visible surface.
pub(crate) struct HeldResolve {
    /// The public resolve result.
    pub(crate) resolved: Resolved,
    /// The scope read seed the child read pipeline derives per-node read keys
    /// from.
    pub(crate) read_scope_seed: Option<Zeroizing<[u8; 32]>>,
    /// The (node id, scope write seed) the drain derives new names and per-name
    /// signers from.
    pub(crate) write_scope_seed: Option<AdoptHold>,
}

/// [`resolve`] a name, then hold it for liveness **iff** it passed the gate:
/// on [`ResolveOutcome::Adopted`], insert (replacing any prior entry for the
/// same node) a [`HeldRecord`] so the keyless re-PUT loop keeps it alive. Only a
/// gate-passing record enters the set — a `TrustViolation`/`NoUpdate` never
/// does (blueprint/engine.md "Liveness": never re-PUT a stale record).
/// Additionally surfaces the scope seeds a gate-passing adopt recovered (see
/// [`AdoptOutcome::read_scope_seed`]) for the tick driver's deposit — the write
/// seed among them, because the drain derives every new node's name and signer
/// from it.
pub(crate) async fn resolve_and_hold<T, S, A>(
    transport: &T,
    snapshot_cache: &S,
    adopter: &A,
    name: &IpnsName,
    held: &RefCell<HeldRecords>,
    material: &HeldMaterial,
    mode: ResolveMode,
) -> Result<HeldResolve, SeamError>
where
    T: RecordTransport,
    S: SnapshotCache,
    A: Adopter,
{
    let GatedResolve {
        resolved,
        hold: adopt_hold,
        held_record,
        read_scope_seed,
    } = resolve_gated(transport, snapshot_cache, adopter, name, mode).await?;
    let write_scope_seed = adopt_hold.clone();
    let done = |resolved| HeldResolve {
        resolved,
        read_scope_seed,
        write_scope_seed,
    };
    // A gate-passing adopt (`Adopted`) and our own current record (`Current`)
    // are both alive-worthy and ride their verified bytes back here; a
    // `TrustViolation`/`NoUpdate` holds nothing (blueprint/engine.md "Liveness").
    if let Some((verified, record_bytes)) = held_record {
        // Renew under the record's own adopted head CID, not a caller-supplied
        // one: it comes from the signed `/ipfs/<cid>` value. A gate-passing
        // record always carries a valid value; if it does not, skip the hold
        // rather than renew under `/ipfs/` — an empty head CID would clobber the
        // tip (security rule 8, fail-closed).
        let Some(head_cid) = head_cid_from_value(&verified.value) else {
            return Ok(done(resolved));
        };
        // The renewal (node id, write seed) comes from the gate for a write
        // grantee, else from the caller for an own-scope record. No seed on
        // either side ⇒ nothing to renew with ⇒ held keyless is a later slice, so
        // skip the hold rather than store a signerless record.
        let Some((node_id, write_scope_seed)) = adopt_hold.or_else(|| {
            material
                .write_scope_seed
                .as_ref()
                .map(|seed| (material.node_id, seed.clone()))
        }) else {
            return Ok(done(resolved));
        };
        // Derive the narrow per-name signer once from the transient seed and hold
        // only it — the seed drops at this scope's end. Fail-closed encode-side
        // bind (security rule 8): the derived signer must sign for exactly this
        // name, or the held record could never renew under its routing key — skip
        // the hold rather than store a mismatched signer.
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        if IpnsName::from_public_key(&signer.verifying_key()) != *name {
            return Ok(done(resolved));
        }
        let mut held = held.borrow_mut();
        // The drain is the only source of a head's held content CIDs, so a
        // re-hold carries the set forward rather than wiping it.
        let key = HeldKey::node(node_id);
        let content_cids = held
            .remove(&key)
            .filter(|prior| prior.head_cid() == Some(head_cid.as_str()))
            .map(|prior| prior.content_cids)
            .unwrap_or_default();
        held.insert(
            key,
            HeldRecord {
                routing_key: name.as_str().to_owned(),
                record_bytes,
                signer,
                value: HeldValue::Head(head_cid),
                content_cids,
            },
        );
    }
    Ok(done(resolved))
}

/// Fold a completed resolve's verdict into the shared base cell. A gate-passing
/// `Adopted` re-projects ([`merge_root`], merging over the current base) and
/// reports what the merge changed (the caller emits `SnapshotUpdated`); so does
/// an own `Current` root, from [`Resolved::current_at_floor`].
/// `NoUpdate`/`TrustViolation` leave last-known-good intact and report nothing.
/// Non-await by construction — the short borrows never span an `.await`
/// (facade single-threaded executor rule).
pub(crate) fn refresh_base_from_resolved(
    base: &RefCell<Snapshot>,
    root: NodeId,
    resolved: &Resolved,
) -> FolderMerge {
    let adopted = match (&resolved.outcome, &resolved.current_at_floor) {
        (ResolveOutcome::Adopted(adopted), _) => adopted,
        (ResolveOutcome::Current { .. }, Some(at_floor)) => at_floor,
        _ => return FolderMerge::unchanged(),
    };
    merge_root(&mut base.borrow_mut(), root, adopted)
}

#[cfg(test)]
mod tests {
    use super::{
        HeldMaterial, OwnScopeMaterial, ResolveMode, ResolveOutcome, head_cid_from_value,
        resolve_and_hold,
    };

    use core::cell::RefCell;

    use cipherbox_core::error::TrustViolation;
    use cipherbox_core::ipns::{IpnsName, IpnsRecord};
    use cipherbox_core::seal::{PreservedFields, ReadBody};
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use zeroize::Zeroizing;

    use super::super::eol;
    use crate::gate::{Adopted, GateError, GateRejection, GateStage, RejectionReason};
    use crate::net::{HeldKey, HeldRecord, HeldRecords, HeldValue};
    use crate::seams::{RecordTransport, UnixMillis};
    use crate::session::SessionIdentity;
    use crate::testkit::{FakeWorld, block_on};

    const TTL_NANOS: u64 = 2_000_000_000;
    const VALUE: &[u8] = b"/ipfs/bafyfixturehead";

    #[derive(Clone, Copy)]
    enum Verdict {
        Accept,
        TrustViolation,
        EqualSequence,
    }

    struct StubAdopter {
        verdict: Verdict,
        /// The (write scope seed, node id) a gate-surfaced write grant contributes
        /// on an `Accept` — `None` models a read-only/own-scope adopt.
        grant: Option<([u8; 32], [u8; 16])>,
        /// The (node id, write scope seed) the owner recovers for its own
        /// equal-floor `Current` record — `None` models a non-owner record with
        /// no recoverable seed (held keyless).
        own_seed: Option<([u8; 16], [u8; 32])>,
    }

    impl StubAdopter {
        fn new(verdict: Verdict) -> Self {
            Self {
                verdict,
                grant: None,
                own_seed: None,
            }
        }

        fn write_grant(seed: [u8; 32], node_id: [u8; 16]) -> Self {
            Self {
                verdict: Verdict::Accept,
                grant: Some((seed, node_id)),
                own_seed: None,
            }
        }

        /// An own equal-floor `Current` record whose write seed the owner recovers.
        fn own_current(seed: [u8; 32], node_id: [u8; 16]) -> Self {
            Self {
                verdict: Verdict::EqualSequence,
                grant: None,
                own_seed: Some((node_id, seed)),
            }
        }
    }

    impl super::Adopter for StubAdopter {
        async fn adopt(
            &self,
            name: &IpnsName,
            record_bytes: &[u8],
        ) -> Result<super::AdoptOutcome, GateError> {
            let sequence = IpnsRecord::unmarshal(record_bytes)
                .unwrap()
                .verify(name)
                .unwrap()
                .sequence;
            match self.verdict {
                Verdict::Accept => Ok(super::AdoptOutcome {
                    adopted: Adopted {
                        read_body: ReadBody::Folder {
                            created_at: 0,
                            modified_at: 0,
                            children: Vec::new(),
                            unknown: PreservedFields::new(),
                        },
                        sequence,
                        epoch: 1,
                    },
                    write_scope_seed: self.grant.map(|(seed, _)| Zeroizing::new(seed)),
                    node_id: self.grant.map(|(_, id)| id).unwrap_or([0u8; 16]),
                    read_scope_seed: None,
                }),
                Verdict::TrustViolation => Err(GateError::Rejected(GateRejection {
                    stage: GateStage::RecordVerify,
                    reason: RejectionReason::Trust(TrustViolation::IpnsSignatureInvalid.into()),
                })),
                Verdict::EqualSequence => Err(GateError::Rejected(GateRejection {
                    stage: GateStage::Sequence,
                    reason: RejectionReason::SequenceNotNewer {
                        floor: sequence,
                        sequence,
                    },
                })),
            }
        }

        async fn probe_read_scope_seed(
            &self,
            _name: &IpnsName,
            _record_bytes: &[u8],
        ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError> {
            Ok(None)
        }

        async fn recover_own_scope_material(
            &self,
            _name: &IpnsName,
            _record_bytes: &[u8],
        ) -> Result<Option<OwnScopeMaterial>, crate::seams::SeamError> {
            Ok(self.own_seed.map(|(node_id, seed)| OwnScopeMaterial {
                node_id,
                read_scope_seed: Zeroizing::new([0u8; 32]),
                write_scope_seed: Some(Zeroizing::new(seed)),
                at_floor: Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: PreservedFields::new(),
                    },
                    sequence: 1,
                    epoch: 0,
                },
            }))
        }
    }

    fn record(signer: &Ed25519Signer, sequence: u64) -> Vec<u8> {
        let validity = eol::eol_from(UnixMillis(0));
        IpnsRecord::create_v2(signer, VALUE, sequence, TTL_NANOS, &validity).marshal()
    }

    #[test]
    fn resolve_and_hold_holds_a_gate_passing_record() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        // The held name is the one the material's (seed, node id) derives, so the
        // insert-time signer<->name bind passes.
        let write_scope_seed = [9u8; 32];
        let node_id = [7u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let endpoints = world.record_store.endpoints();
        world
            .record_store
            .seed_record(&endpoints[0], name.as_str(), record(&signer, 1));

        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let material = HeldMaterial {
            node_id,
            write_scope_seed: Some(Zeroizing::new(write_scope_seed)),
        };
        let resolved = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::Accept),
            &name,
            &held,
            &material,
            ResolveMode::CacheFirst,
        ))
        .expect("resolve_and_hold")
        .resolved;

        assert!(matches!(resolved.outcome, ResolveOutcome::Adopted(_)));
        let map = held.borrow();
        assert_eq!(map.len(), 1, "the adopted record is held, keyed by node id");
        let record = map
            .get(&HeldKey::node(node_id))
            .expect("held under its node id");
        assert_eq!(record.routing_key, name.as_str());
        assert!(
            record.content_cids.is_empty(),
            "a first hold registers nothing; the drain supplies the CIDs"
        );
        // The held signer signs for the routing key (the insert-time bind).
        assert_eq!(
            IpnsName::from_public_key(&record.signer.verifying_key()),
            name
        );
    }

    /// The drain registers a head's content CIDs; a re-hold of that same head
    /// must carry them, and a re-hold under a different head must not.
    #[test]
    fn a_re_hold_carries_the_content_cids_held_for_the_same_head() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let write_scope_seed = [9u8; 32];
        let node_id = [7u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let endpoints = world.record_store.endpoints();
        world
            .record_store
            .seed_record(&endpoints[0], name.as_str(), record(&signer, 1));
        let material = HeldMaterial {
            node_id,
            write_scope_seed: Some(Zeroizing::new(write_scope_seed)),
        };

        let registered = vec!["bafyleaf".to_owned()];
        let re_hold = |head_cid: &str| {
            let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
            held.borrow_mut().insert(
                HeldKey::node(node_id),
                HeldRecord {
                    routing_key: name.as_str().to_owned(),
                    record_bytes: Vec::new(),
                    signer: SessionIdentity::write_name_signer(&write_scope_seed, &node_id),
                    value: HeldValue::Head(head_cid.to_owned()),
                    content_cids: registered.clone(),
                },
            );
            block_on(resolve_and_hold(
                &device.record_store,
                &device.snapshot_cache,
                &StubAdopter::new(Verdict::Accept),
                &name,
                &held,
                &material,
                ResolveMode::CacheFirst,
            ))
            .expect("resolve_and_hold");
            held.borrow()[&HeldKey::node(node_id)].content_cids.clone()
        };

        // `VALUE` is `/ipfs/<head>`, so this is the head the re-hold adopts.
        let same_head = core::str::from_utf8(&VALUE[b"/ipfs/".len()..]).unwrap();
        assert_eq!(
            re_hold(same_head),
            registered,
            "the publish's CIDs survive a re-hold of the same head"
        );
        assert!(
            re_hold("bafyotherhead").is_empty(),
            "CIDs registered for another head name a superseded block set"
        );
    }

    #[test]
    fn resolve_and_hold_does_not_hold_a_non_gate_passing_record() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let signer = Ed25519Signer::from_seed([32u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let endpoints = world.record_store.endpoints();
        world
            .record_store
            .seed_record(&endpoints[0], name.as_str(), record(&signer, 5));
        let material = HeldMaterial {
            node_id: [1u8; 16],
            write_scope_seed: Some(Zeroizing::new([0u8; 32])),
        };

        // A fail-closed trust violation is never held.
        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let out = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::TrustViolation),
            &name,
            &held,
            &material,
            ResolveMode::CacheFirst,
        ))
        .unwrap()
        .resolved;
        assert!(matches!(out.outcome, ResolveOutcome::TrustViolation(_)));
        assert!(held.borrow().is_empty(), "a trust violation is never held");
    }

    #[test]
    fn resolve_of_our_own_current_record_yields_current_and_is_held() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        // The held name is the one the material's (seed, node id) derives, so the
        // insert-time signer<->name bind passes for our own record.
        let write_scope_seed = [4u8; 32];
        let node_id = [8u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let endpoints = world.record_store.endpoints();
        let bytes = record(&signer, 3);
        world
            .record_store
            .seed_record(&endpoints[0], name.as_str(), bytes.clone());

        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let material = HeldMaterial {
            node_id,
            write_scope_seed: Some(Zeroizing::new(write_scope_seed)),
        };
        let resolved = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::EqualSequence),
            &name,
            &held,
            &material,
            ResolveMode::CacheFirst,
        ))
        .expect("resolve_and_hold")
        .resolved;

        // Our own current record at the floor is `Current`, carrying the verified
        // bytes verbatim (no re-fetch), and is held for the keyless re-PUT.
        match &resolved.outcome {
            ResolveOutcome::Current { record_bytes } => {
                assert_eq!(record_bytes, &bytes, "Current carries the fetched bytes")
            }
            other => panic!("expected Current, got {other:?}"),
        }
        let map = held.borrow();
        assert_eq!(map.len(), 1, "our own current record is held by node id");
        let hr = map
            .get(&HeldKey::node(node_id))
            .expect("held under its node id");
        assert_eq!(
            hr.record_bytes, bytes,
            "held bytes are the in-hand Current bytes"
        );
        assert_eq!(hr.routing_key, name.as_str());
    }

    #[test]
    fn own_current_root_is_held_with_a_valid_signer_and_real_head_cid() {
        use core::time::Duration;

        use crate::api::ApiClient;
        use crate::net::eol_renew_pass;
        use crate::net::publish::PublishOutcome;
        use crate::profile::SyncTimingProfile;
        use crate::seams::FloorStore;

        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone(); // manual clock, now = 0

        // Our own current root: the seed the owner recovers derives the routing
        // name (the insert-time signer<->name bind passes for our own record).
        let write_scope_seed = [5u8; 32];
        let node_id = [6u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let bytes = record(&signer, 1);
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), bytes.clone());
        }

        // The gate rejects on sequence (equal-floor Current); the adopter recovers
        // the owner's write seed, so the caller carries none of its own.
        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let material = HeldMaterial {
            node_id: [0u8; 16],
            write_scope_seed: None,
        };
        let resolved = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::own_current(write_scope_seed, node_id),
            &name,
            &held,
            &material,
            ResolveMode::CacheFirst,
        ))
        .expect("resolve_and_hold")
        .resolved;
        assert!(matches!(resolved.outcome, ResolveOutcome::Current { .. }));

        let hr = held
            .borrow()
            .get(&HeldKey::node(node_id))
            .cloned()
            .expect("own current root is held by its recovered node id");
        // Held under a valid signer that signs for exactly the routing key.
        assert_eq!(IpnsName::from_public_key(&hr.signer.verifying_key()), name);
        // A real, non-empty head CID from the signed record value (never /ipfs/).
        let value = IpnsRecord::unmarshal(&bytes)
            .unwrap()
            .verify(&name)
            .unwrap()
            .value;
        assert_eq!(
            hr.head_cid().map(str::to_owned),
            head_cid_from_value(&value)
        );
        assert!(!hr.head_cid().expect("a head plane record").is_empty());

        // The held record renews: model adoption (floor → 1), advance into the EOL
        // window, and prove the recovered signer republishes at seq+1.
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 1),
        )
        .unwrap();
        scheduler.advance(Duration::from_secs(65 * 24 * 60 * 60));
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        device.http.enqueue_response(crate::seams::HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        });
        let results = block_on(eol_renew_pass(
            &device.record_store,
            &api,
            &device.floor_store,
            &scheduler,
            &SyncTimingProfile::CI,
            &[hr],
        ));
        assert_eq!(
            results[0].outcome.as_ref().unwrap(),
            &Some(PublishOutcome::Published { sequence: 2 }),
            "the held own current root renews at seq+1 under its recovered signer",
        );
    }

    #[test]
    fn non_owner_current_is_not_force_held() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let signer = Ed25519Signer::from_seed([21u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), record(&signer, 4));
        }

        // Equal-floor Current, but no recoverable owner write seed and no caller
        // material seed: the record is never force-held (least privilege).
        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let material = HeldMaterial {
            node_id: [0u8; 16],
            write_scope_seed: None,
        };
        let resolved = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::EqualSequence),
            &name,
            &held,
            &material,
            ResolveMode::CacheFirst,
        ))
        .expect("resolve_and_hold")
        .resolved;
        assert!(matches!(resolved.outcome, ResolveOutcome::Current { .. }));
        assert!(
            held.borrow().is_empty(),
            "a non-owner current record is never force-held"
        );
    }

    #[test]
    fn grantee_write_holder_derives_a_renewal_signer() {
        use core::time::Duration;

        use crate::api::ApiClient;
        use crate::net::eol_renew_pass;
        use crate::net::publish::PublishOutcome;
        use crate::profile::SyncTimingProfile;
        use crate::seams::FloorStore;

        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone(); // manual clock, now = 0

        // A write-grant adopt: the gate surfaces the scope write seed, so the
        // caller's material carries no seed of its own (a grantee does not know
        // it a priori). The held name is the one the gate-surfaced (seed, node id)
        // derives.
        let write_scope_seed = [5u8; 32];
        let node_id = [6u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), record(&signer, 1));
        }

        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let material = HeldMaterial {
            node_id: [0u8; 16],
            write_scope_seed: None,
        };
        block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::write_grant(write_scope_seed, node_id),
            &name,
            &held,
            &material,
            ResolveMode::CacheFirst,
        ))
        .expect("resolve_and_hold");

        // The gate-surfaced write seed derived the renewal signer, keyed by the
        // gate's node id, and it signs for exactly the held name.
        let hr = held
            .borrow()
            .get(&HeldKey::node(node_id))
            .cloned()
            .expect("write grantee is held by the gate node id");
        assert_eq!(
            IpnsName::from_public_key(&hr.signer.verifying_key()),
            name,
            "the derived signer signs for the held routing key"
        );

        // The held record renews: model adoption (floor → 1), advance into the
        // EOL window, and prove the derived signer republishes at seq+1.
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 1),
        )
        .unwrap();
        scheduler.advance(Duration::from_secs(65 * 24 * 60 * 60));
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        device.http.enqueue_response(crate::seams::HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        });
        let results = block_on(eol_renew_pass(
            &device.record_store,
            &api,
            &device.floor_store,
            &scheduler,
            &SyncTimingProfile::CI,
            &[hr],
        ));
        assert_eq!(
            results[0].outcome.as_ref().unwrap(),
            &Some(PublishOutcome::Published { sequence: 2 }),
            "the held write grantee renews at seq+1 under its derived signer",
        );
    }

    #[test]
    fn resolve_and_hold_takes_the_head_cid_from_the_adopted_record() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let write_scope_seed = [11u8; 32];
        let node_id = [12u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), record(&signer, 1));
        }

        // The caller supplies no head CID (HeldMaterial has none): the held
        // record must take it from the adopted record's own signed value.
        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let material = HeldMaterial {
            node_id,
            write_scope_seed: Some(Zeroizing::new(write_scope_seed)),
        };
        block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::Accept),
            &name,
            &held,
            &material,
            ResolveMode::CacheFirst,
        ))
        .expect("resolve_and_hold");

        let expected = head_cid_from_value(VALUE).expect("fixture value has a head cid");
        assert!(!expected.is_empty());
        let map = held.borrow();
        let record = map
            .get(&HeldKey::node(node_id))
            .expect("held under its node id");
        assert_eq!(
            record.head_cid(),
            Some(expected.as_str()),
            "the held head CID is derived from the adopted record, never empty",
        );
    }

    #[test]
    fn renewal_republishes_under_the_real_head_cid() {
        use core::time::Duration;

        use crate::api::ApiClient;
        use crate::net::eol_renew_pass;
        use crate::net::publish::PublishOutcome;
        use crate::profile::SyncTimingProfile;
        use crate::seams::FloorStore;

        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone(); // manual clock, now = 0

        let write_scope_seed = [2u8; 32];
        let node_id = [3u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), record(&signer, 1));
        }

        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let material = HeldMaterial {
            node_id,
            write_scope_seed: Some(Zeroizing::new(write_scope_seed)),
        };
        block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::Accept),
            &name,
            &held,
            &material,
            ResolveMode::CacheFirst,
        ))
        .expect("resolve_and_hold");
        let hr = held
            .borrow()
            .get(&HeldKey::node(node_id))
            .cloned()
            .expect("held under its node id");
        let expected_head = head_cid_from_value(VALUE).expect("fixture value has a head cid");
        assert_eq!(hr.head_cid(), Some(expected_head.as_str()));

        // Advance into the EOL window and renew, then prove the republished
        // record's value round-trips to the SAME non-empty head CID (never
        // `/ipfs/`).
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 1),
        )
        .unwrap();
        scheduler.advance(Duration::from_secs(65 * 24 * 60 * 60));
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        device.http.enqueue_response(crate::seams::HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        });
        let results = block_on(eol_renew_pass(
            &device.record_store,
            &api,
            &device.floor_store,
            &scheduler,
            &SyncTimingProfile::CI,
            &[hr],
        ));
        assert_eq!(
            results[0].outcome.as_ref().unwrap(),
            &Some(PublishOutcome::Published { sequence: 2 }),
            "renewal republishes at seq+1",
        );

        let endpoint = device.record_store.endpoints()[0].clone();
        let republished = device
            .record_store
            .record_at(&endpoint, name.as_str())
            .expect("republished record present");
        let value = IpnsRecord::unmarshal(&republished)
            .unwrap()
            .verify(&name)
            .unwrap()
            .value;
        assert_eq!(
            head_cid_from_value(&value).as_deref(),
            Some(expected_head.as_str()),
            "renewal preserves the head CID; never /ipfs/",
        );
        assert!(!expected_head.is_empty());
    }

    mod refresh_base {
        use super::super::{Resolved, refresh_base_from_resolved};

        use super::{GateRejection, GateStage, RejectionReason, ResolveOutcome};

        use core::cell::RefCell;

        use cipherbox_core::error::TrustViolation;
        use cipherbox_core::seal::{ChildRef, NodeKind, PreservedFields, ReadBody};

        use crate::facade::NodeId;
        use crate::gate::Adopted;
        use crate::sync::model::Snapshot;
        use crate::sync::overlay::apply_overlay;
        use crate::sync::project::project_child_version;

        fn adopted_with_one_child(child_id: [u8; 16]) -> Adopted {
            Adopted {
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: vec![ChildRef {
                        id: child_id,
                        name: "hello.txt".to_string(),
                        ipns_name: vec![1],
                        kind: NodeKind::File,
                        link_counter: 1,
                        unknown: PreservedFields::new(),
                    }],
                    unknown: PreservedFields::new(),
                },
                sequence: 2,
                epoch: 1,
            }
        }

        #[test]
        fn refresh_base_from_a_newer_adopted_updates_the_cell() {
            let root = NodeId([0u8; 16]);
            let cell = RefCell::new(Snapshot::new(root));
            let child_id = [7u8; 16];

            assert!(
                refresh_base_from_resolved(
                    &cell,
                    root,
                    &Resolved::just(ResolveOutcome::Adopted(adopted_with_one_child(child_id))),
                )
                .changed
            );

            let base = cell.borrow();
            let rendered = apply_overlay(&base, &[]);
            let children = rendered.children(root);
            assert_eq!(children.len(), 1, "the newer child is projected under root");
            assert_eq!(children[0].id, NodeId(child_id));
        }

        #[test]
        fn a_root_advance_keeps_the_values_the_root_body_cannot_express() {
            let root = NodeId([0u8; 16]);
            let child_id = [7u8; 16];
            let cell = RefCell::new(Snapshot::new(root));

            assert!(
                refresh_base_from_resolved(
                    &cell,
                    root,
                    &Resolved::just(ResolveOutcome::Adopted(adopted_with_one_child(child_id))),
                )
                .changed
            );
            // A verified head-version read folds the child's plaintext facts in.
            assert!(project_child_version(
                &mut cell.borrow_mut(),
                NodeId(child_id),
                4_096,
                1_700,
                2,
                Some(b"head-cid"),
            ));

            assert!(
                !refresh_base_from_resolved(
                    &cell,
                    root,
                    &Resolved::just(ResolveOutcome::Adopted(adopted_with_one_child(child_id))),
                )
                .changed,
                "re-projecting the same body repaints nothing"
            );

            let base = cell.borrow();
            let child = base.node(NodeId(child_id)).expect("child still projected");
            assert_eq!(child.size, Some(4_096), "size survives the re-projection");
            assert_eq!(child.mtime, Some(1_700), "mtime survives the re-projection");
            assert_eq!(
                child.content_version,
                Some(2),
                "the version count survives the re-projection"
            );
        }

        /// The tick's own half of the same rule the cold start holds: a root
        /// this session re-fetched at the floor still paints, so a later pass
        /// reads a base some poll of this session established.
        #[test]
        fn a_current_root_paints_the_base_from_its_floor_recovery() {
            let root = NodeId([0u8; 16]);
            let cell = RefCell::new(Snapshot::new(root));
            let child_id = [0x3C; 16];

            assert!(
                refresh_base_from_resolved(
                    &cell,
                    root,
                    &Resolved {
                        last_known_good: None,
                        outcome: ResolveOutcome::Current {
                            record_bytes: vec![9, 9, 9],
                        },
                        current_at_floor: Some(adopted_with_one_child(child_id)),
                    },
                )
                .changed
            );

            assert!(
                cell.borrow().contains(NodeId(child_id)),
                "the root's child is in the base the quarantine proof reads"
            );
        }

        #[test]
        fn non_adopting_outcomes_leave_the_base_untouched() {
            let root = NodeId([9u8; 16]);
            let before = Snapshot::new(root);
            let rejection = GateRejection {
                stage: GateStage::RecordVerify,
                reason: RejectionReason::Trust(TrustViolation::IpnsSignatureInvalid.into()),
            };
            for outcome in [
                ResolveOutcome::NoUpdate,
                ResolveOutcome::Current {
                    record_bytes: vec![1, 2, 3],
                },
                ResolveOutcome::TrustViolation(rejection),
            ] {
                let cell = RefCell::new(before.clone());
                assert!(
                    !refresh_base_from_resolved(&cell, root, &Resolved::just(outcome.clone()))
                        .changed,
                    "{outcome:?} must not repaint the base"
                );
                assert_eq!(
                    *cell.borrow(),
                    before,
                    "{outcome:?} leaves last-known-good byte-identical"
                );
            }
        }
    }
}
