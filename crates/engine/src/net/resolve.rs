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
//! The gate itself is a composition over content-plane and reader state that
//! lands with the content/pointer/grants and key-lifecycle slices, so this slice
//! reaches it through the [`Adopter`] seam. The pipeline's contract is fixed
//! now: **every** fetched record is routed through [`Adopter::adopt`] — there is
//! no ungated path to the snapshot.

use core::cell::RefCell;

use cipherbox_core::ipns::IpnsName;
use zeroize::Zeroizing;

use super::fanout::fanout_get_verify;
use super::liveness::{HeldRecord, HeldRecords};
use crate::gate::{Adopted, GateError, GateRejection, RejectionReason};
use crate::seams::{RecordTransport, SeamError, SnapshotCache};
use crate::session::SessionIdentity;

/// Runs the adoption gate over a fetched record. The concrete implementation
/// assembles the content-plane candidate and the reader's private context and
/// calls [`crate::gate::adopt`]; it lands with the content/pointer/grants and
/// key-lifecycle slices. The resolve pipeline requires only this: every record
/// it fetches is adopted through here before it can touch the snapshot
/// (blueprint/engine.md: "only gate-passing records touch the snapshot").
pub trait Adopter {
    /// Assemble and gate the record fetched under `name`. `Ok` carries the
    /// authenticated read-body and floors plus, for a write-capable holder, the
    /// transient write material the held set derives its renewal signer from;
    /// `Err(GateError::Rejected)` is a fail-closed trust violation;
    /// `Err(GateError::Seam)` is host I/O.
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<AdoptOutcome, GateError>;
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
) -> Result<Resolved, SeamError>
where
    T: RecordTransport,
    S: SnapshotCache,
    A: Adopter,
{
    // The public resolve drops the transient hold material — only the liveness
    // driver ([`resolve_and_hold`]) consumes it.
    Ok(resolve_gated(transport, snapshot_cache, adopter, name)
        .await?
        .0)
}

/// The (node id, write scope seed) a gate-surfaced write grant contributes to
/// the held set. `Some` only on a gate pass that carried a write seed.
type AdoptHold = ([u8; 16], Zeroizing<[u8; 32]>);

/// The gated resolve, returning the outcome plus, on a gate pass that surfaced a
/// write seed, the transient hold material the held set consumes. Kept internal
/// so the write seed never rides the public [`Resolved`].
async fn resolve_gated<T, S, A>(
    transport: &T,
    snapshot_cache: &S,
    adopter: &A,
    name: &IpnsName,
) -> Result<(Resolved, Option<AdoptHold>), SeamError>
where
    T: RecordTransport,
    S: SnapshotCache,
    A: Adopter,
{
    let cache_key = name.as_str().as_bytes();
    // Cache-first: last-known-good renders immediately, reconcile runs behind it.
    let last_known_good = snapshot_cache.get(cache_key).await?;

    let (outcome, hold) = match fanout_get_verify(transport, name).await {
        None => (ResolveOutcome::NoUpdate, None),
        Some((_sequence, bytes)) => match adopter.adopt(name, &bytes).await {
            Ok(AdoptOutcome {
                adopted,
                write_scope_seed,
                node_id,
            }) => {
                // Only gate-passing records touch the snapshot.
                snapshot_cache.put(cache_key, &bytes).await?;
                let hold = write_scope_seed.map(|seed| (node_id, seed));
                (ResolveOutcome::Adopted(adopted), hold)
            }
            // A record at exactly the durable sequence floor is our own current
            // record re-fetched — no update, never a violation; its verified
            // bytes are handed back so the liveness loop holds them without a
            // re-fetch. A strictly older sequence is a replay/rollback and stays
            // a fail-closed trust violation, as does every other gate rejection.
            Err(GateError::Rejected(rejection)) => match &rejection.reason {
                RejectionReason::SequenceNotNewer { floor, sequence } if sequence == floor => (
                    ResolveOutcome::Current {
                        record_bytes: bytes,
                    },
                    None,
                ),
                _ => (ResolveOutcome::TrustViolation(rejection), None),
            },
            Err(GateError::Seam(error)) => return Err(error),
        },
    };

    Ok((
        Resolved {
            last_known_good,
            outcome,
        },
        hold,
    ))
}

/// The transient insert-time input for a held record: the resolve/gate path has
/// already unsealed the scope's write seed for this node, so the held set
/// derives the narrow per-name signer from it once at insert and drops the seed
/// (never persisting it — see [`HeldRecord`]). Not yet wired in production
/// (only the #752 resolve-tick driver constructs it), hence crate-internal.
#[allow(dead_code)] // wired by the #752 resolve-tick driver
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
    /// The head/metadata CID the renewal record points at.
    pub head_cid: String,
    /// The content CIDs to re-register/pin at renewal.
    pub content_cids: Vec<String>,
}

/// [`resolve`] a name, then hold it for liveness **iff** it passed the gate:
/// on [`ResolveOutcome::Adopted`], insert (replacing any prior entry for the
/// same node) a [`HeldRecord`] so the keyless re-PUT loop keeps it alive. Only a
/// gate-passing record enters the set — a `TrustViolation`/`NoUpdate` never
/// does (blueprint/engine.md "Liveness": never re-PUT a stale record).
#[allow(dead_code)] // wired by the #752 resolve-tick driver
pub(crate) async fn resolve_and_hold<T, S, A>(
    transport: &T,
    snapshot_cache: &S,
    adopter: &A,
    name: &IpnsName,
    held: &RefCell<HeldRecords>,
    material: &HeldMaterial,
) -> Result<Resolved, SeamError>
where
    T: RecordTransport,
    S: SnapshotCache,
    A: Adopter,
{
    let (resolved, adopt_hold) = resolve_gated(transport, snapshot_cache, adopter, name).await?;
    // A gate-passing adopt (`Adopted`) and our own current record (`Current`)
    // are both alive-worthy; a `TrustViolation`/`NoUpdate` is never held. For
    // `Adopted` the bytes are the cache's fresh last-known-good; for `Current`
    // the verified bytes are already in hand, so no re-fetch (blueprint/engine.md
    // "Liveness").
    let record_bytes = match &resolved.outcome {
        ResolveOutcome::Adopted(_) => {
            // A cache that dropped what it just adopted is a broken durable seam
            // — fail closed rather than hold nothing.
            let cache_key = name.as_str().as_bytes();
            Some(
                snapshot_cache
                    .get(cache_key)
                    .await?
                    .ok_or_else(|| SeamError::new("snapshot cache dropped the adopted record"))?,
            )
        }
        ResolveOutcome::Current { record_bytes } => Some(record_bytes.clone()),
        ResolveOutcome::TrustViolation(_) | ResolveOutcome::NoUpdate => None,
    };
    if let Some(record_bytes) = record_bytes {
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
            return Ok(resolved);
        };
        // Derive the narrow per-name signer once from the transient seed and hold
        // only it — the seed drops at this scope's end. Fail-closed encode-side
        // bind (security rule 8): the derived signer must sign for exactly this
        // name, or the held record could never renew under its routing key — skip
        // the hold rather than store a mismatched signer.
        let signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        if IpnsName::from_public_key(&signer.verifying_key()) != *name {
            return Ok(resolved);
        }
        held.borrow_mut().insert(
            node_id,
            HeldRecord {
                routing_key: name.as_str().to_owned(),
                record_bytes,
                signer,
                head_cid: material.head_cid.clone(),
                content_cids: material.content_cids.clone(),
            },
        );
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::{HeldMaterial, ResolveOutcome, resolve_and_hold};

    use core::cell::RefCell;

    use cipherbox_core::error::TrustViolation;
    use cipherbox_core::ipns::{IpnsName, IpnsRecord};
    use cipherbox_core::seal::ReadBody;
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use zeroize::Zeroizing;

    use super::super::eol;
    use crate::gate::{Adopted, GateError, GateRejection, GateStage, RejectionReason};
    use crate::net::HeldRecords;
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
    }

    impl StubAdopter {
        fn new(verdict: Verdict) -> Self {
            Self {
                verdict,
                grant: None,
            }
        }

        fn write_grant(seed: [u8; 32], node_id: [u8; 16]) -> Self {
            Self {
                verdict: Verdict::Accept,
                grant: Some((seed, node_id)),
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
                            unknown: Vec::new(),
                        },
                        sequence,
                        epoch: 1,
                    },
                    write_scope_seed: self.grant.map(|(seed, _)| Zeroizing::new(seed)),
                    node_id: self.grant.map(|(_, id)| id).unwrap_or([0u8; 16]),
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
            head_cid: "bafyhead".into(),
            content_cids: vec!["bafycontent".into()],
        };
        let resolved = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::Accept),
            &name,
            &held,
            &material,
        ))
        .expect("resolve_and_hold");

        assert!(matches!(resolved.outcome, ResolveOutcome::Adopted(_)));
        let map = held.borrow();
        assert_eq!(map.len(), 1, "the adopted record is held, keyed by node id");
        let record = map.get(&node_id).expect("held under its node id");
        assert_eq!(record.routing_key, name.as_str());
        assert_eq!(record.head_cid, "bafyhead");
        assert_eq!(record.content_cids, vec!["bafycontent".to_owned()]);
        // The held signer signs for the routing key (the insert-time bind).
        assert_eq!(
            IpnsName::from_public_key(&record.signer.verifying_key()),
            name
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
            head_cid: "h".into(),
            content_cids: Vec::new(),
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
        ))
        .unwrap();
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
            head_cid: "bafyhead".into(),
            content_cids: Vec::new(),
        };
        let resolved = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::new(Verdict::EqualSequence),
            &name,
            &held,
            &material,
        ))
        .expect("resolve_and_hold");

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
        let hr = map.get(&node_id).expect("held under its node id");
        assert_eq!(
            hr.record_bytes, bytes,
            "held bytes are the in-hand Current bytes"
        );
        assert_eq!(hr.routing_key, name.as_str());
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
            head_cid: "bafyfixturehead".into(),
            content_cids: Vec::new(),
        };
        block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter::write_grant(write_scope_seed, node_id),
            &name,
            &held,
            &material,
        ))
        .expect("resolve_and_hold");

        // The gate-surfaced write seed derived the renewal signer, keyed by the
        // gate's node id, and it signs for exactly the held name.
        let hr = held
            .borrow()
            .get(&node_id)
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
}
