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

use super::fanout::fanout_get_tied_classified;
use super::fork::{Fork, cached_fork, fork_of, served_fork};
use super::last_known_good::{keep_served_last_known_good, keep_then_commit};
use super::liveness::{HeldEnvelope, HeldKey, HeldRecord, HeldRecords, HeldValue};
use super::publish::{Observed, PublishBar, PublishError, head_cid_from_value};
use crate::facade::NodeId;
use crate::gate::floor::PendingSequenceRaise;
use crate::gate::{Adopted, GateError, GateRejection, PendingAdoption, RejectionReason};
use crate::grants::grafted::FloorNamespace;
use crate::seams::{FloorStore, RecordTransport, SeamError, SnapshotCache};
use crate::session::SessionIdentity;
use crate::sync::project::{FolderMerge, merge_root};
use crate::sync::render::BaseSnapshot;
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

    /// Commit the floor-law advance a [`GatePass::Deferred`] pass left
    /// uncommitted, now that its record is durable last-known-good in the
    /// snapshot cache ([`PendingAdoption`]).
    ///
    /// The default refuses, because an adopter that never defers never reaches
    /// it: discarding the advance instead would cache the record under stale
    /// cut-epoch, read-epoch and sequence floors, and leave a replay of an older
    /// valid record above every bar this pass was to raise.
    async fn commit_adoption(&self, _pending: PendingAdoption) -> Result<Adopted, SeamError> {
        Err(SeamError::new(
            "a deferred gate pass reached an adopter that commits no floor",
        ))
    }

    /// Commit the sequence-floor raise a [`GatePass::DeferredSequence`] pass
    /// left uncommitted, now that its record is durable last-known-good in the
    /// snapshot cache ([`PendingSequenceRaise`]).
    ///
    /// Refuses by default on the same terms as
    /// [`commit_adoption`](Self::commit_adoption): dropping the raise would
    /// cache the record under a stale sequence floor and leave a replay of an
    /// older valid record above the bar this pass was to raise.
    async fn commit_sequence_adoption(
        &self,
        _pending: PendingSequenceRaise,
    ) -> Result<Adopted, SeamError> {
        Err(SeamError::new(
            "a deferred sequence raise reached an adopter that commits no floor",
        ))
    }

    /// Recover the OWNER's own scope material for an equal-floor `Current` own
    /// record: the read seed the child pipeline and the drain seal under, and
    /// the write seed the liveness loop renews with. `Ok(None)` when there is
    /// nothing to re-check; a stage the record fails is a `Rejected` verdict,
    /// as it is on an adopt. The default suits every non-owner adopter stub.
    async fn recover_own_scope_material(
        &self,
        _name: &IpnsName,
        _record_bytes: &[u8],
    ) -> Result<Option<OwnScopeMaterial>, GateError> {
        Ok(None)
    }

    /// Gate the record fetched under `name` **without** committing the gate
    /// pass, and hand back the read scope seed the gate recovered from its owner
    /// blob (`None` when the reader's arm recovers none). Same fail-closed
    /// verdicts as [`adopt`](Self::adopt).
    ///
    /// A discarded sighting spends nothing: the name's sequence floor, the
    /// scope's read-epoch floor and the scope's cut-epoch floor all stay where
    /// the probe found them. The restrictive cut-epoch floor included — a
    /// caller that keeps the probed root adopts it, and the adopt files that
    /// floor ([`PendingAdoption`]).
    async fn probe_read_scope_seed(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError>;

    /// Recover a separate confirmed owner copy after a refused owner blob.
    async fn recover_owner_cache(
        &self,
        _name: &IpnsName,
        _rejection: &GateRejection,
    ) -> Result<Option<OwnScopeMaterial>, GateError> {
        Ok(None)
    }

    /// Recover the confirmed owner copy when no endpoint served a record.
    async fn recover_dark_root(
        &self,
        _name: &IpnsName,
    ) -> Result<Option<OwnScopeMaterial>, GateError> {
        Ok(None)
    }

    /// Whether `record_bytes`, tied with a pick this read already gated, passes
    /// the gate at the durable floor the pick left: only such a tie is the
    /// other side of a same-sequence fork (ADR 0066 D1). Moves no floor and
    /// caches nothing.
    async fn gates_tie(&self, name: &IpnsName, record_bytes: &[u8]) -> bool {
        matches!(
            self.adopt(name, record_bytes).await,
            Err(GateError::Rejected(GateRejection {
                reason: RejectionReason::SequenceNotNewer { floor, sequence },
                ..
            })) if floor == sequence
        ) && matches!(
            self.recover_own_scope_material(name, record_bytes).await,
            Ok(Some(_))
        )
    }
}

/// The owner's own-scope seeds, recovered from a record already at the durable
/// sequence floor. Both come from grant-section structures the gate's stages
/// 1-3 authenticated before the floor stages ran, so an equal-floor `Current`
/// has proved them committed. The owner seed cache keeps a sealed recovery copy.
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
    /// The envelope version the record carries.
    pub version: u64,
    /// The floors a renewal of the record must clear.
    pub bar: PublishBar,
}

/// A gate pass, and where its floor-law advance stands.
///
/// The advance is deferred wherever the accepted record has a durability step
/// after the gate: the resolve driver writes the bytes to the snapshot cache and
/// only then commits, so a failure between the two leaves the floors where the
/// pass found them and the retry is a fresh adopt rather than an equal-floor
/// `Current` that projects and caches nothing ([`PendingAdoption`]).
pub enum GatePass {
    /// The floor-law advance is still to be made:
    /// [`Adopter::commit_adoption`] makes it once the record is durable.
    Deferred(PendingAdoption),
    /// The child arm's deferred shape: a sequence-floor raise alone, made by
    /// [`Adopter::commit_sequence_adoption`] once the record is durable. A
    /// child record moves no epoch floor (the floor law).
    DeferredSequence(PendingSequenceRaise),
    /// The floors this record moves already moved inside the pass.
    Advanced(Adopted),
}

impl GatePass {
    /// The adopted state with any deferred advance committed against `floors`
    /// — for the direct-adopt callers (the drain's self-adopt, the write wave's
    /// interior read) that hold the same floor store the pass was gated on and
    /// have already made their record durable. The resolve driver commits
    /// through the [`Adopter`] seam instead, having no floor store of its own.
    pub(crate) async fn commit<F: FloorStore>(self, floors: &F) -> Result<Adopted, SeamError> {
        match self {
            GatePass::Deferred(pending) => pending.commit(floors).await,
            GatePass::DeferredSequence(pending) => pending.commit(floors).await,
            GatePass::Advanced(adopted) => Ok(adopted),
        }
    }
}

/// A gate pass plus the transient write material a write-capable holder needs to
/// keep its scope alive (blueprint/engine.md "Liveness").
pub struct AdoptOutcome {
    /// The authenticated read-body and floors, and whether the floor-law advance
    /// is still owed.
    pub pass: GatePass,
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
    /// engine deposits it in its in-memory per-scope seed map, and the child
    /// read pipeline derives per-node read keys from it. `None` for a non-owner
    /// adopter.
    pub read_scope_seed: Option<Zeroizing<[u8; 32]>>,
    /// The envelope version the gated record carries.
    pub version: u64,
    /// The floors a renewal of the record must clear.
    pub bar: PublishBar,
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
    /// `Current` must still paint the base (ADR 0011 D4).
    pub current_at_floor: Option<Adopted>,
    /// The prior owner copy, re-gated while the network outcome stays a trust violation.
    pub recovered_owner: Option<Adopted>,
    /// The same-sequence fork the gated record met, which is never a trust
    /// violation (ADR 0066 D1).
    pub fork: Option<Fork>,
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
            recovered_owner: None,
            fork: None,
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
    /// Other records served at the fetched record's sequence, record-verified
    /// and never gated: evidence of a split, never bytes to build on.
    pub(crate) tied: Vec<Vec<u8>>,
    /// No record was fetched, and the endpoints agree the name holds none.
    pub(crate) absent: bool,
    /// [`Observed::gated`] for the record the gate passed. `None` when none
    /// passed, or an own `Current` recovered no material.
    pub(crate) observed: Option<Result<Observed, PublishError>>,
    /// The envelope a renewal of [`Self::observed`] is gated on.
    pub(crate) envelope: Option<HeldEnvelope>,
}

/// What one arm of the gate match yields beside its outcome. Named because four
/// of the five slots are `None` in two of the arms, which a tuple hides.
#[derive(Default)]
struct GatedParts {
    hold: Option<AdoptHold>,
    held_record: Option<(VerifiedRecord, Vec<u8>)>,
    read_scope_seed: Option<Zeroizing<[u8; 32]>>,
    current_at_floor: Option<Adopted>,
    observed: Option<Result<Observed, PublishError>>,
    envelope: Option<HeldEnvelope>,
    fork: Option<Fork>,
}

/// Whether a gate refusal reads as unavailable: the sequence stage refused a
/// record strictly below the floor while an endpoint failed (ADR 0071 D1).
pub(crate) fn unavailable_below_floor(reason: &RejectionReason, endpoint_failed: bool) -> bool {
    endpoint_failed
        && matches!(
            reason,
            RejectionReason::SequenceNotNewer { floor, sequence } if sequence < floor
        )
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
    // it. Nocache renders nothing from the cache, so only what the record plane
    // serves this pass can be rendered or reported (#33 D4). A gate-passing record
    // still writes back either way, so a forced refresh only ever leaves the
    // cache fresher.
    let last_known_good = match mode {
        ResolveMode::CacheFirst => snapshot_cache.get(cache_key).await?,
        ResolveMode::NoCache => None,
    };

    let fetch = fanout_get_tied_classified(transport, name).await;
    let absent = fetch.absent;
    let (fetched, tied) = match fetch.pick {
        Some((verified, bytes, tied)) => (Some((verified, bytes)), tied),
        None => (None, Vec::new()),
    };
    let (outcome, mut parts) = match fetched {
        None => (ResolveOutcome::NoUpdate, GatedParts::default()),
        Some((verified, bytes)) => match adopter.adopt(name, &bytes).await {
            Ok(AdoptOutcome {
                pass,
                write_scope_seed,
                node_id,
                read_scope_seed,
                version,
                bar,
            }) => {
                // Only gate-passing records touch the snapshot; the same verified
                // bytes ride out to the liveness hold, so no re-fetch/re-get.
                let adopted = keep_then_commit(snapshot_cache, name, &bytes, async {
                    match pass {
                        GatePass::Deferred(pending) => adopter.commit_adoption(pending).await,
                        GatePass::DeferredSequence(pending) => {
                            adopter.commit_sequence_adoption(pending).await
                        }
                        GatePass::Advanced(adopted) => Ok(adopted),
                    }
                })
                .await?;
                let observed = Some(Observed::gated(name, adopted.sequence, version, &bytes));
                // The adopt left the floor at the pick, so a tie gates there.
                let fork = fork_of(
                    &verified,
                    served_fork(name, &verified, &tied, async |tie| {
                        adopter.gates_tie(name, tie).await
                    })
                    .await,
                    false,
                );
                (
                    ResolveOutcome::Adopted(adopted),
                    GatedParts {
                        hold: write_scope_seed.map(|seed| (node_id, seed)),
                        held_record: Some((verified, bytes)),
                        read_scope_seed,
                        current_at_floor: None,
                        observed,
                        envelope: Some(HeldEnvelope {
                            version,
                            bar,
                            namespace: FloorNamespace::Own,
                        }),
                        fork,
                    },
                )
            }
            // A record at exactly the durable sequence floor is our own current
            // record re-fetched, or one side of a same-sequence fork (ADR 0066)
            // — no update, never a violation; its verified bytes ride out so
            // the liveness loop holds them without a re-fetch.
            // A strictly older sequence is a rollback unless an endpoint failed
            // (ADR 0071); every other gate rejection stays a trust violation.
            Err(GateError::Rejected(rejection)) => match &rejection.reason {
                RejectionReason::SequenceNotNewer { floor, sequence } if sequence == floor => {
                    // Our own current root at exactly the floor: recover the
                    // owner's own scope seeds so the liveness loop can
                    // hold+renew it before its EOL lapses and the write plane
                    // keeps the keys it seals under across a session that
                    // adopts nothing. A non-owner adopter yields neither.
                    match adopter.recover_own_scope_material(name, &bytes).await {
                        Ok(material) => {
                            let cached = match material {
                                Some(_) => {
                                    keep_served_last_known_good(snapshot_cache, name, &bytes)
                                        .await?
                                }
                                None => last_known_good.clone(),
                            };
                            let fork = fork_of(
                                &verified,
                                served_fork(name, &verified, &tied, async |tie| {
                                    adopter.gates_tie(name, tie).await
                                })
                                .await,
                                cached_fork(name, cached.as_deref(), &bytes, &verified),
                            );
                            let recovered = material.map(|material| GatedParts {
                                hold: material
                                    .write_scope_seed
                                    .map(|seed| (material.node_id, seed)),
                                held_record: None,
                                read_scope_seed: Some(material.read_scope_seed),
                                observed: Some(Observed::gated(
                                    name,
                                    material.at_floor.sequence,
                                    material.version,
                                    &bytes,
                                )),
                                envelope: Some(HeldEnvelope {
                                    version: material.version,
                                    bar: material.bar,
                                    namespace: FloorNamespace::Own,
                                }),
                                current_at_floor: Some(material.at_floor),
                                fork: None,
                            });
                            (
                                ResolveOutcome::Current {
                                    record_bytes: bytes.clone(),
                                },
                                GatedParts {
                                    held_record: Some((verified, bytes)),
                                    fork,
                                    ..recovered.unwrap_or_default()
                                },
                            )
                        }
                        Err(GateError::Rejected(refused)) => (
                            ResolveOutcome::TrustViolation(refused),
                            GatedParts::default(),
                        ),
                        Err(GateError::Seam(error)) => return Err(error),
                    }
                }
                reason if unavailable_below_floor(reason, fetch.endpoint_failed) => {
                    (ResolveOutcome::NoUpdate, GatedParts::default())
                }
                _ => (
                    ResolveOutcome::TrustViolation(rejection),
                    GatedParts::default(),
                ),
            },
            Err(GateError::Seam(error)) => return Err(error),
        },
    };
    let recovered_owner = if let ResolveOutcome::TrustViolation(rejection) = &outcome {
        match adopter.recover_owner_cache(name, rejection).await {
            Ok(Some(material)) => {
                parts.read_scope_seed = Some(material.read_scope_seed);
                parts.hold = material
                    .write_scope_seed
                    .map(|seed| (material.node_id, seed));
                Some(material.at_floor)
            }
            // A local fault means no copy; the record keeps its verdict.
            Ok(None) | Err(_) => None,
        }
    } else {
        None
    };
    let GatedParts {
        hold,
        held_record,
        read_scope_seed,
        current_at_floor,
        observed,
        envelope,
        fork,
    } = parts;

    Ok(GatedResolve {
        resolved: Resolved {
            last_known_good,
            outcome,
            current_at_floor,
            recovered_owner,
            fork,
        },
        hold,
        held_record,
        read_scope_seed,
        tied,
        absent,
        observed,
        envelope,
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
        envelope,
        ..
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
    // A record with no envelope rule has nothing to gate its renewal on.
    if let (Some((verified, record_bytes)), Some(envelope)) = (held_record, envelope) {
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
        let key = HeldKey::Node(node_id);
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
                envelope: Some(envelope),
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
    base: &BaseSnapshot,
    root: NodeId,
    resolved: &Resolved,
) -> FolderMerge {
    let adopted = match (&resolved.outcome, &resolved.current_at_floor) {
        (ResolveOutcome::Adopted(adopted), _) => adopted,
        (ResolveOutcome::Current { .. }, Some(at_floor)) => at_floor,
        _ => match &resolved.recovered_owner {
            Some(recovered) => recovered,
            None => return FolderMerge::unchanged(),
        },
    };
    merge_root(&mut base.borrow_mut(), root, adopted)
}

#[cfg(test)]
mod tests {
    use super::{
        GatePass, HeldMaterial, OwnScopeMaterial, PendingSequenceRaise, ResolveMode,
        ResolveOutcome, Resolved, head_cid_from_value, resolve_and_hold, resolve_gated,
    };

    use core::cell::RefCell;

    use cipherbox_core::error::TrustViolation;
    use cipherbox_core::ipns::{IpnsName, IpnsRecord};
    use cipherbox_core::seal::{PreservedFields, ReadBody};
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use zeroize::Zeroizing;

    use super::super::eol;
    use super::super::fork::{Fork, with_unsigned_field};
    use crate::gate::{Adopted, GateError, GateRejection, GateStage, RejectionReason};
    use crate::net::author::ENVELOPE_V;
    use crate::net::publish::PublishError;
    use crate::net::{HeldKey, HeldRecord, HeldRecords, HeldValue};
    use crate::seams::{RecordTransport, SnapshotCache, UnixMillis};
    use crate::session::SessionIdentity;
    use crate::testkit::{FakeWorld, block_on};

    const TTL_NANOS: u64 = 2_000_000_000;
    const VALUE: &[u8] = b"/ipfs/bafyfixturehead";
    const DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;

    #[derive(Clone, Copy)]
    enum Verdict {
        Accept,
        /// A pass that owes a child-shaped sequence raise, on an adopter that
        /// overrides no commit seam.
        DeferSequence,
        TrustViolation,
        EqualSequence,
        /// At the floor, and the floor re-check refuses the record.
        RefusedAtFloor,
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
        /// The envelope version the gated record carries.
        version: u64,
        /// A record the floor re-check refuses, as a tied record that fails
        /// the gate.
        refused: Option<Vec<u8>>,
    }

    impl StubAdopter {
        fn new(verdict: Verdict) -> Self {
            Self {
                verdict,
                grant: None,
                own_seed: None,
                version: ENVELOPE_V,
                refused: None,
            }
        }

        fn write_grant(seed: [u8; 32], node_id: [u8; 16]) -> Self {
            Self {
                verdict: Verdict::Accept,
                grant: Some((seed, node_id)),
                own_seed: None,
                version: ENVELOPE_V,
                refused: None,
            }
        }

        /// An own equal-floor `Current` record whose write seed the owner recovers.
        fn own_current(seed: [u8; 32], node_id: [u8; 16]) -> Self {
            Self {
                verdict: Verdict::EqualSequence,
                grant: None,
                own_seed: Some((node_id, seed)),
                version: ENVELOPE_V,
                refused: None,
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
                    pass: GatePass::Advanced(Adopted {
                        read_body: ReadBody::Folder {
                            created_at: 0,
                            modified_at: 0,
                            children: Vec::new(),
                            unknown: PreservedFields::new(),
                        },
                        sequence,
                        epoch: 1,
                    }),
                    write_scope_seed: self.grant.map(|(seed, _)| Zeroizing::new(seed)),
                    node_id: self.grant.map(|(_, id)| id).unwrap_or([0u8; 16]),
                    read_scope_seed: None,
                    version: self.version,
                    bar: crate::testkit::fakes::ADMITTED_BAR,
                }),
                Verdict::DeferSequence => Ok(super::AdoptOutcome {
                    pass: GatePass::DeferredSequence(PendingSequenceRaise::new(
                        name.as_str().as_bytes(),
                        Adopted {
                            read_body: ReadBody::Folder {
                                created_at: 0,
                                modified_at: 0,
                                children: Vec::new(),
                                unknown: PreservedFields::new(),
                            },
                            sequence,
                            epoch: 1,
                        },
                    )),
                    write_scope_seed: None,
                    node_id: [0u8; 16],
                    read_scope_seed: None,
                    version: self.version,
                    bar: crate::testkit::fakes::ADMITTED_BAR,
                }),
                Verdict::TrustViolation => Err(GateError::Rejected(GateRejection {
                    stage: GateStage::RecordVerify,
                    reason: RejectionReason::Trust(TrustViolation::IpnsSignatureInvalid.into()),
                })),
                Verdict::EqualSequence | Verdict::RefusedAtFloor => {
                    Err(GateError::Rejected(GateRejection {
                        stage: GateStage::Sequence,
                        reason: RejectionReason::SequenceNotNewer {
                            floor: sequence,
                            sequence,
                        },
                    }))
                }
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
            record_bytes: &[u8],
        ) -> Result<Option<OwnScopeMaterial>, GateError> {
            if matches!(self.verdict, Verdict::RefusedAtFloor)
                || self.refused.as_deref() == Some(record_bytes)
            {
                return Err(GateError::Rejected(GateRejection {
                    stage: GateStage::Unseal,
                    reason: RejectionReason::Trust(TrustViolation::SealOpenFailed.into()),
                }));
            }
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
                version: self.version,
                bar: crate::testkit::fakes::ADMITTED_BAR,
            }))
        }
    }

    /// A deferred raise that reaches an adopter with no commit seam must fail
    /// the resolve, not be dropped: the alternative caches the record under a
    /// floor that never moved, leaving a replay of an older valid record above
    /// the bar the pass was to raise.
    #[test]
    fn a_deferred_sequence_raise_no_adopter_commits_fails_the_resolve() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let signer = SessionIdentity::write_name_signer(&[9u8; 32], &[7u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let endpoints = world.record_store.endpoints();
        world
            .record_store
            .seed_record(&endpoints[0], name.as_str(), record(&signer, 1));

        let Err(error) = block_on(resolve_gated(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::DeferSequence),
            &name,
            ResolveMode::CacheFirst,
        )) else {
            panic!("an uncommitted raise must fail the resolve");
        };
        assert!(
            error.message().contains("commits no floor"),
            "unexpected seam error: {error}"
        );
    }

    /// `signer`'s record at `sequence` that points at `value`, at the one EOL
    /// every fixture record carries.
    fn record_of(signer: &Ed25519Signer, value: &[u8], sequence: u64) -> Vec<u8> {
        record_at_eol(signer, value, sequence, UnixMillis(DAY_MILLIS))
    }

    /// The same, at the EOL a write signed at `signed` carries.
    fn record_at_eol(
        signer: &Ed25519Signer,
        value: &[u8],
        sequence: u64,
        signed: UnixMillis,
    ) -> Vec<u8> {
        let validity = eol::eol_from(signed);
        IpnsRecord::create_v2(signer, value, sequence, TTL_NANOS, &validity).marshal()
    }

    /// The signed `data` of `record_bytes`, the key the tie order ranks by.
    fn data_of(name: &IpnsName, record_bytes: &[u8]) -> Vec<u8> {
        IpnsRecord::unmarshal(record_bytes)
            .and_then(|record| record.verify(name))
            .expect("the fixture verifies")
            .data
    }

    /// One resolve at the floor of `name` with `served[i]` on endpoint `i`.
    fn resolve_served(
        device: &crate::testkit::FakeDevice,
        adopter: &StubAdopter,
        name: &IpnsName,
        served: &[&Vec<u8>],
        mode: ResolveMode,
    ) -> Resolved {
        let endpoints = device.record_store.endpoints();
        for (endpoint, record) in endpoints.iter().zip(served.iter().cycle()) {
            device
                .record_store
                .seed_record(endpoint, name.as_str(), (*record).clone());
        }
        block_on(resolve_gated(
            &device.record_store,
            &device.snapshot_cache,
            adopter,
            name,
            mode,
        ))
        .expect("the resolve settles")
        .resolved
    }

    /// Two endpoints serve two records of other values at the floor sequence:
    /// the resolve reports a served fork, never a trust violation, and takes
    /// the record with the higher signed `data` on either endpoint order.
    #[test]
    fn two_records_served_at_the_floor_resolve_as_a_fork() {
        let signer = SessionIdentity::write_name_signer(&[5u8; 32], &[6u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let ours = record_of(&signer, b"/ipfs/ours", 3);
        let theirs = record_of(&signer, b"/ipfs/theirs", 3);
        let pick = if data_of(&name, &ours) > data_of(&name, &theirs) {
            &ours
        } else {
            &theirs
        };

        for served in [[&ours, &theirs], [&theirs, &ours]] {
            let world = FakeWorld::new();
            let device = world.device(b"me");
            let resolved = resolve_served(
                &device,
                &StubAdopter::own_current([5u8; 32], [6u8; 16]),
                &name,
                &served,
                ResolveMode::NoCache,
            );
            assert_eq!(
                resolved.outcome,
                ResolveOutcome::Current {
                    record_bytes: pick.clone()
                }
            );
            assert_eq!(
                resolved.fork,
                Some(Fork {
                    sequence: 3,
                    served: true
                })
            );
        }
    }

    /// A tie is no fork when it signs the pick's own value, when it is the
    /// pick with an unsigned field added, or when it fails the gate.
    #[test]
    fn a_tie_of_one_value_an_altered_copy_or_a_refused_record_is_no_fork() {
        let signer = SessionIdentity::write_name_signer(&[5u8; 32], &[6u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let ours = record_of(&signer, b"/ipfs/ours", 3);
        let renewed = record_at_eol(&signer, b"/ipfs/ours", 3, UnixMillis(0));
        let mut values = [ours.clone(), record_of(&signer, b"/ipfs/theirs", 3)];
        values.sort_by_key(|record| data_of(&name, record));
        let [theirs, ours_higher] = values;
        let refusing = StubAdopter {
            refused: Some(theirs.clone()),
            ..StubAdopter::own_current([5u8; 32], [6u8; 16])
        };

        for (case, adopter, tie) in [
            (
                "one value",
                StubAdopter::own_current([5u8; 32], [6u8; 16]),
                renewed,
            ),
            (
                "an unsigned field",
                StubAdopter::own_current([5u8; 32], [6u8; 16]),
                with_unsigned_field(&ours),
            ),
            ("a refused tie", refusing, theirs.clone()),
        ] {
            let world = FakeWorld::new();
            let device = world.device(b"me");
            let pick = if tie == theirs { &ours_higher } else { &ours };
            let resolved = resolve_served(
                &device,
                &adopter,
                &name,
                &[pick, &tie],
                ResolveMode::NoCache,
            );
            assert!(
                matches!(resolved.outcome, ResolveOutcome::Current { .. }),
                "{case}"
            );
            assert_eq!(resolved.fork, None, "{case}");
        }
    }

    /// The endpoints serve one record at the floor, and the cache holds
    /// another value at that sequence: a cache-first read reports a fork that
    /// is not served and paints the served record, whichever ranks higher.
    #[test]
    fn a_record_at_the_floor_that_differs_from_the_cached_one_is_a_fork() {
        let signer = SessionIdentity::write_name_signer(&[5u8; 32], &[6u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let served = record_of(&signer, b"/ipfs/served", 3);
        let below = record_at_eol(&signer, b"/ipfs/cached", 3, UnixMillis(0));
        let above = record_at_eol(&signer, b"/ipfs/cached", 3, UnixMillis(2 * DAY_MILLIS));

        for cached in [&below, &above] {
            let world = FakeWorld::new();
            let device = world.device(b"me");
            block_on(device.snapshot_cache.put(name.as_str().as_bytes(), cached))
                .expect("seed the cached copy");
            let resolved = resolve_served(
                &device,
                &StubAdopter::new(Verdict::EqualSequence),
                &name,
                &[&served],
                ResolveMode::CacheFirst,
            );
            assert_eq!(
                resolved.outcome,
                ResolveOutcome::Current {
                    record_bytes: served.clone()
                }
            );
            assert_eq!(
                resolved.fork,
                Some(Fork {
                    sequence: 3,
                    served: false
                })
            );
        }
    }

    /// A forced refresh renders nothing from the cache, but the copy the
    /// keeper replaces with the served record is still evidence of a fork,
    /// and the next read finds none.
    #[test]
    fn a_forced_refresh_reports_the_fork_its_keeper_write_replaces() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let (write_scope_seed, node_id) = ([5u8; 32], [6u8; 16]);
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let served = record_of(&signer, b"/ipfs/served", 3);
        let key = name.as_str().as_bytes();
        let cached = record_at_eol(&signer, b"/ipfs/cached", 3, UnixMillis(2 * DAY_MILLIS));
        block_on(device.snapshot_cache.put(key, &cached)).expect("seed the cached copy");
        let adopter = StubAdopter::own_current(write_scope_seed, node_id);

        let resolved = resolve_served(&device, &adopter, &name, &[&served], ResolveMode::NoCache);
        assert_eq!(
            resolved.fork,
            Some(Fork {
                sequence: 3,
                served: false
            })
        );
        assert_eq!(device.snapshot_cache.peek(key), Some(served.clone()));

        let again = resolve_served(&device, &adopter, &name, &[&served], ResolveMode::NoCache);
        assert_eq!(
            again.fork, None,
            "the fork clears once the cache holds the served record"
        );
    }

    /// A fork does not excuse a record at the floor that fails the floor
    /// re-check: that stays a trust violation (rule 6).
    #[test]
    fn a_forked_record_that_fails_the_floor_check_is_a_trust_violation() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let signer = SessionIdentity::write_name_signer(&[5u8; 32], &[6u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let endpoints = device.record_store.endpoints();
        device.record_store.seed_record(
            &endpoints[0],
            name.as_str(),
            record_of(&signer, b"/ipfs/ours", 3),
        );
        device.record_store.seed_record(
            &endpoints[1],
            name.as_str(),
            record_of(&signer, b"/ipfs/theirs", 3),
        );

        let resolved = block_on(resolve_gated(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::RefusedAtFloor),
            &name,
            ResolveMode::NoCache,
        ))
        .expect("the resolve settles")
        .resolved;
        assert!(matches!(
            resolved.outcome,
            ResolveOutcome::TrustViolation(_)
        ));
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
            .get(&HeldKey::Node(node_id))
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

    /// The gated resolve hands out the token of the record it gated, under the
    /// version rule: a record at another envelope version is readable but is no
    /// basis for a publish.
    #[test]
    fn the_gated_resolve_gives_the_token_of_the_record_it_gated() {
        let signer = SessionIdentity::write_name_signer(&[9u8; 32], &[7u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        for (version, expected) in [
            (ENVELOPE_V, Ok(4)),
            (
                ENVELOPE_V + 1,
                Err(PublishError::ForeignVersion {
                    version: ENVELOPE_V + 1,
                }),
            ),
        ] {
            let world = FakeWorld::new();
            let device = world.device(b"me");
            let endpoints = world.record_store.endpoints();
            world
                .record_store
                .seed_record(&endpoints[0], name.as_str(), record(&signer, 4));
            let adopter = StubAdopter {
                version,
                ..StubAdopter::new(Verdict::Accept)
            };

            let gated = block_on(resolve_gated(
                &device.record_store,
                &device.snapshot_cache,
                &adopter,
                &name,
                ResolveMode::NoCache,
            ))
            .expect("the resolve runs");

            let observed = gated.observed.expect("a record passed the gate");
            assert_eq!(
                observed.map(|observed| (observed.name().clone(), observed.sequence())),
                expected.map(|sequence| (name.clone(), sequence)),
                "version {version}"
            );
        }
    }

    /// A record the gate refuses gives no token.
    #[test]
    fn a_refused_record_gives_no_token() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let signer = SessionIdentity::write_name_signer(&[9u8; 32], &[7u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let endpoints = world.record_store.endpoints();
        world
            .record_store
            .seed_record(&endpoints[0], name.as_str(), record(&signer, 4));

        let gated = block_on(resolve_gated(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::TrustViolation),
            &name,
            ResolveMode::NoCache,
        ))
        .expect("the resolve runs");

        assert!(gated.observed.is_none());
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
                HeldKey::Node(node_id),
                HeldRecord {
                    routing_key: name.as_str().to_owned(),
                    record_bytes: Vec::new(),
                    signer: SessionIdentity::write_name_signer(&write_scope_seed, &node_id),
                    value: HeldValue::Head(head_cid.to_owned()),
                    content_cids: registered.clone(),
                    envelope: None,
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
            held.borrow()[&HeldKey::Node(node_id)].content_cids.clone()
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
            &StubAdopter::own_current(write_scope_seed, node_id),
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
            .get(&HeldKey::Node(node_id))
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
        use crate::net::renewal_walk::RenewalSeams;
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
            .get(&HeldKey::Node(node_id))
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
            body: Vec::new().into(),
        });
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &Default::default(),
            },
            &RefCell::new(HeldRecords::from([(HeldKey::Node(node_id), hr)])),
        ));
        assert_eq!(
            results[0].outcome.as_ref().unwrap(),
            &Some(PublishOutcome::Published { sequence: 2 }),
            "the held own current root renews at seq+1 under its recovered signer",
        );
    }

    /// An own root re-read at the floor, where a pass that cached nothing raised
    /// that floor: the re-read is the gate pass that makes these bytes
    /// last-known-good. A record the owner recovers nothing from caches nothing.
    #[test]
    fn an_own_current_root_replaces_an_older_cached_copy_and_a_foreign_one_does_not() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let write_scope_seed = [5u8; 32];
        let node_id = [6u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let current = record(&signer, 3);
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), current.clone());
        }
        let key = name.as_str().as_bytes();
        let older = record(&signer, 2);

        for (adopter, mode, cached) in [
            (
                StubAdopter::new(Verdict::EqualSequence),
                ResolveMode::CacheFirst,
                &older,
            ),
            (
                StubAdopter::own_current(write_scope_seed, node_id),
                ResolveMode::CacheFirst,
                &current,
            ),
            (
                StubAdopter::own_current(write_scope_seed, node_id),
                ResolveMode::NoCache,
                &current,
            ),
        ] {
            block_on(device.snapshot_cache.put(key, &older)).expect("seed the older copy");
            let resolved = block_on(resolve_gated(
                &device.record_store,
                &device.snapshot_cache,
                &adopter,
                &name,
                mode,
            ))
            .expect("the resolve settles")
            .resolved;
            assert!(matches!(resolved.outcome, ResolveOutcome::Current { .. }));
            assert_eq!(device.snapshot_cache.peek(key).as_ref(), Some(cached));
        }
    }

    /// A pass that cached sequence 7 but failed its floor commit leaves the
    /// floor below it, so a later sequence 6 adopts. The newer copy stays.
    #[test]
    fn an_adopt_keeps_a_newer_cached_copy() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let signer = SessionIdentity::write_name_signer(&[5u8; 32], &[6u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), record(&signer, 6));
        }
        let key = name.as_str().as_bytes();
        let newer = record(&signer, 7);

        for mode in [ResolveMode::CacheFirst, ResolveMode::NoCache] {
            block_on(device.snapshot_cache.put(key, &newer)).expect("seed the newer copy");
            let resolved = block_on(resolve_gated(
                &device.record_store,
                &device.snapshot_cache,
                &StubAdopter::new(Verdict::Accept),
                &name,
                mode,
            ))
            .expect("the resolve settles")
            .resolved;
            assert!(matches!(resolved.outcome, ResolveOutcome::Adopted(_)));
            assert_eq!(device.snapshot_cache.peek(key).as_ref(), Some(&newer));
        }
    }

    /// The own at-floor re-read keeps a newer cached copy too, and a forced
    /// refresh reads the cache for that check although it renders nothing from it.
    #[test]
    fn an_own_current_root_keeps_a_newer_cached_copy() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let write_scope_seed = [5u8; 32];
        let node_id = [6u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), record(&signer, 3));
        }
        let key = name.as_str().as_bytes();
        let newer = record(&signer, 4);

        for mode in [ResolveMode::CacheFirst, ResolveMode::NoCache] {
            block_on(device.snapshot_cache.put(key, &newer)).expect("seed the newer copy");
            let resolved = block_on(resolve_gated(
                &device.record_store,
                &device.snapshot_cache,
                &StubAdopter::own_current(write_scope_seed, node_id),
                &name,
                mode,
            ))
            .expect("the resolve settles")
            .resolved;
            assert!(matches!(resolved.outcome, ResolveOutcome::Current { .. }));
            assert_eq!(device.snapshot_cache.peek(key).as_ref(), Some(&newer));
        }
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
        use crate::net::renewal_walk::RenewalSeams;
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
            .get(&HeldKey::Node(node_id))
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
            body: Vec::new().into(),
        });
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &Default::default(),
            },
            &RefCell::new(HeldRecords::from([(HeldKey::Node(node_id), hr)])),
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
            .get(&HeldKey::Node(node_id))
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
        use crate::net::renewal_walk::RenewalSeams;
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
            .get(&HeldKey::Node(node_id))
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
            body: Vec::new().into(),
        });
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &Default::default(),
            },
            &RefCell::new(HeldRecords::from([(HeldKey::Node(node_id), hr)])),
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

    /// While the device has not loaded a co-writer's newer record, the renewal
    /// signs nothing; once the adoption re-held it under the same node id, the
    /// renewal re-signs the newer version.
    #[test]
    fn the_renewal_skips_a_newer_record_it_never_loaded_and_re_signs_one_it_adopted() {
        use core::time::Duration;

        use crate::api::ApiClient;
        use crate::net::eol_renew_pass;
        use crate::net::publish::PublishOutcome;
        use crate::net::renewal_walk::RenewalSeams;
        use crate::profile::SyncTimingProfile;
        use crate::seams::{FloorStore, HttpResponse};

        /// Past the sub-EOL renewal threshold of a record minted at time zero.
        const INSIDE_THE_WINDOW: Duration = Duration::from_secs(65 * 24 * 60 * 60);
        const CO_WRITER_VALUE: &[u8] = b"/ipfs/bafyacowriterhead";

        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone(); // manual clock, now = 0
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let write_scope_seed = [4u8; 32];
        let node_id = [5u8; 16];
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let raise = |sequence| {
            block_on(
                device
                    .floor_store
                    .raise_sequence_floor(name.as_str().as_bytes(), sequence),
            )
            .expect("the floor raises");
        };
        let live_value = || {
            let endpoint = device.record_store.endpoints()[0].clone();
            IpnsRecord::unmarshal(
                &device
                    .record_store
                    .record_at(&endpoint, name.as_str())
                    .expect("a record stands at the name"),
            )
            .unwrap()
            .verify(&name)
            .unwrap()
            .value
        };
        let register_ok = || {
            device.http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Vec::new().into(),
            });
        };

        // What this device adopted at sequence 1, and the floor that left.
        let ours = HeldRecord {
            routing_key: name.as_str().to_owned(),
            record_bytes: record(&signer, 1),
            signer: SessionIdentity::write_name_signer(&write_scope_seed, &node_id),
            value: HeldValue::Head(head_cid_from_value(VALUE).expect("fixture head cid")),
            content_cids: Vec::new(),
            envelope: None,
        };
        raise(1);
        // A co-writer's newer record, standing above that floor. Minted at time
        // zero like ours, so the renewal threshold is what the pass tests.
        for endpoint in device.record_store.endpoints() {
            device.record_store.seed_record(
                &endpoint,
                name.as_str(),
                IpnsRecord::create_v2(
                    &signer,
                    CO_WRITER_VALUE,
                    3,
                    TTL_NANOS,
                    &eol::eol_from(UnixMillis(0)),
                )
                .marshal(),
            );
        }

        scheduler.advance(INSIDE_THE_WINDOW);
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &Default::default(),
            },
            &RefCell::new(HeldRecords::from([(HeldKey::Node(node_id), ours.clone())])),
        ));
        assert_eq!(
            results[0].outcome.as_ref().unwrap(),
            &None,
            "a renewal never signs over a record it did not load",
        );
        assert!(device.http.requests().is_empty(), "nothing is registered");
        assert_eq!(
            live_value(),
            CO_WRITER_VALUE,
            "and the co-writer's record still stands",
        );

        // The same device now loads it. The adopt re-holds the newer record
        // under the same node id, and the gate raises the floor behind it.
        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        held.borrow_mut().insert(HeldKey::Node(node_id), ours);
        block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::Accept),
            &name,
            &held,
            &HeldMaterial {
                node_id,
                write_scope_seed: Some(Zeroizing::new(write_scope_seed)),
            },
            ResolveMode::CacheFirst,
        ))
        .expect("resolve_and_hold");
        raise(3);
        let re_held = held
            .borrow()
            .get(&HeldKey::Node(node_id))
            .cloned()
            .expect("held under its node id");
        assert_eq!(
            re_held.head_cid(),
            head_cid_from_value(CO_WRITER_VALUE).as_deref(),
            "the adoption re-held the record the plane served",
        );

        register_ok();
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &Default::default(),
            },
            &RefCell::new(HeldRecords::from([(HeldKey::Node(node_id), re_held)])),
        ));
        assert_eq!(
            results[0].outcome.as_ref().unwrap(),
            &Some(PublishOutcome::Published { sequence: 4 }),
        );
        assert_eq!(
            live_value(),
            CO_WRITER_VALUE,
            "the renewal re-signed the newer version, never the one it replaced",
        );
    }

    mod refresh_base {
        use super::super::{Resolved, refresh_base_from_resolved};

        use super::{GateRejection, GateStage, RejectionReason, ResolveOutcome};

        use cipherbox_core::error::TrustViolation;
        use cipherbox_core::seal::{ChildRef, NodeKind, PreservedFields, ReadBody};

        use crate::facade::NodeId;
        use crate::gate::Adopted;
        use crate::sync::model::Snapshot;
        use crate::sync::overlay::apply_overlay;
        use crate::sync::project::project_child_version;
        use crate::sync::render::BaseSnapshot;

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
            let cell = BaseSnapshot::new(Snapshot::new(root));
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
            let cell = BaseSnapshot::new(Snapshot::new(root));

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
            let cell = BaseSnapshot::new(Snapshot::new(root));
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
                        recovered_owner: None,
                        fork: None,
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
                let cell = BaseSnapshot::new(before.clone());
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
