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
    /// The freshest fetched record failed the gate — a fail-closed trust
    /// violation. Last-known-good is pinned; the rejected record is never
    /// rendered.
    TrustViolation(GateRejection),
    /// No newer record was fetched: either nothing resolvable (network
    /// unreachable / cold) or only a copy at or below the current record. This
    /// is availability staleness, not an error — the cached view stays usable.
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
            // record re-fetched — no update, never a violation. A strictly older
            // sequence is a replay/rollback and stays a fail-closed trust
            // violation, as does every other gate rejection.
            Err(GateError::Rejected(rejection)) => match &rejection.reason {
                RejectionReason::SequenceNotNewer { floor, sequence } if sequence == floor => {
                    ResolveOutcome::NoUpdate
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

/// The per-name material the held set carries beyond the fetched record: the
/// derivation **inputs** #750's seq+1 renewal rebuilds a `PublishRequest` from
/// (never a live signer — see [`HeldRecord`]). Supplied by the resolve/gate
/// path, which already unsealed the scope's write seed for this node.
pub struct HeldMaterial {
    /// The node id (`id16`) — the held-set key and a signer-derivation input.
    pub node_id: [u8; 16],
    /// The scope's unsealed write seed — a derivation input, not a signer.
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
pub async fn resolve_and_hold<T, S, A>(
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
    if matches!(resolved.outcome, ResolveOutcome::Adopted(_)) {
        // The adopted record is now the snapshot cache's last-known-good; hold
        // exactly those bytes for a byte-stable keyless re-PUT. A cache that
        // dropped what it just adopted is a broken durable seam — fail closed.
        let cache_key = name.as_str().as_bytes();
        let record_bytes = snapshot_cache
            .get(cache_key)
            .await?
            .ok_or_else(|| SeamError::new("snapshot cache dropped the adopted record"))?;
        held.borrow_mut().insert(
            material.node_id,
            HeldRecord {
                routing_key: name.as_str().to_owned(),
                record_bytes,
                node_id: material.node_id,
                write_scope_seed: material.write_scope_seed.clone(),
                head_cid: material.head_cid.clone(),
                content_cids: material.content_cids.clone(),
            },
        );
    }
    Ok(resolved)
}
