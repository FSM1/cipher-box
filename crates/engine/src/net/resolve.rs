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
    /// authenticated read-body and floors; `Err(GateError::Rejected)` is a
    /// fail-closed trust violation; `Err(GateError::Seam)` is host I/O.
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<Adopted, GateError>;
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
    let cache_key = name.as_str().as_bytes();
    // Cache-first: last-known-good renders immediately, reconcile runs behind it.
    let last_known_good = snapshot_cache.get(cache_key).await?;

    let outcome = match fanout_get_verify(transport, name).await {
        None => ResolveOutcome::NoUpdate,
        Some((_sequence, bytes)) => match adopter.adopt(name, &bytes).await {
            Ok(adopted) => {
                // Only gate-passing records touch the snapshot.
                snapshot_cache.put(cache_key, &bytes).await?;
                ResolveOutcome::Adopted(adopted)
            }
            // A record at exactly the durable sequence floor is our own current
            // record re-fetched — no update, never a violation; its verified
            // bytes are handed back so the liveness loop holds them without a
            // re-fetch. A strictly older sequence is a replay/rollback and stays
            // a fail-closed trust violation, as does every other gate rejection.
            Err(GateError::Rejected(rejection)) => match &rejection.reason {
                RejectionReason::SequenceNotNewer { floor, sequence } if sequence == floor => {
                    ResolveOutcome::Current {
                        record_bytes: bytes,
                    }
                }
                _ => ResolveOutcome::TrustViolation(rejection),
            },
            Err(GateError::Seam(error)) => return Err(error),
        },
    };

    Ok(Resolved {
        last_known_good,
        outcome,
    })
}

/// The transient insert-time input for a held record: the resolve/gate path has
/// already unsealed the scope's write seed for this node, so the held set
/// derives the narrow per-name signer from it once at insert and drops the seed
/// (never persisting it — see [`HeldRecord`]). Not yet wired in production
/// (only the #752 resolve-tick driver constructs it), hence crate-internal.
#[allow(dead_code)] // wired by the #752 resolve-tick driver
pub(crate) struct HeldMaterial {
    /// The node id (`id16`) — the held-set key and a signer-derivation input.
    pub node_id: [u8; 16],
    /// The scope's unsealed write seed — an insert-time derivation input, never
    /// persisted in the held set.
    pub write_scope_seed: Zeroizing<[u8; 32]>,
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
    let resolved = resolve(transport, snapshot_cache, adopter, name).await?;
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
        // Derive the narrow per-name signer once from the transient seed and
        // hold only it — the scope seed is dropped with `material`. Fail-closed
        // encode-side bind (security rule 8): the derived signer must sign for
        // exactly this name, or the held record could never renew under its
        // routing key — skip the hold rather than store a mismatched signer.
        let signer =
            SessionIdentity::write_name_signer(&material.write_scope_seed, &material.node_id);
        if IpnsName::from_public_key(&signer.verifying_key()) != *name {
            return Ok(resolved);
        }
        held.borrow_mut().insert(
            material.node_id,
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
    }

    impl super::Adopter for StubAdopter {
        async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<Adopted, GateError> {
            let sequence = IpnsRecord::unmarshal(record_bytes)
                .unwrap()
                .verify(name)
                .unwrap()
                .sequence;
            match self.verdict {
                Verdict::Accept => Ok(Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: Vec::new(),
                    },
                    sequence,
                    epoch: 1,
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
            write_scope_seed: Zeroizing::new(write_scope_seed),
            head_cid: "bafyhead".into(),
            content_cids: vec!["bafycontent".into()],
        };
        let resolved = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter {
                verdict: Verdict::Accept,
            },
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
            write_scope_seed: Zeroizing::new([0u8; 32]),
            head_cid: "h".into(),
            content_cids: Vec::new(),
        };

        // A fail-closed trust violation is never held.
        let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
        let out = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter {
                verdict: Verdict::TrustViolation,
            },
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
            write_scope_seed: Zeroizing::new(write_scope_seed),
            head_cid: "bafyhead".into(),
            content_cids: Vec::new(),
        };
        let resolved = block_on(resolve_and_hold(
            &device.record_store,
            &device.snapshot_cache,
            &StubAdopter {
                verdict: Verdict::EqualSequence,
            },
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
}
