//! Durable rotation high-water state machine (ROT-07).
//!
//! Rust port of `packages/sdk/src/state/rotation-high-water.ts` (188 lines,
//! dependency-free). Maintains two independent monotonic-max floors per
//! `node_id`:
//!   - `generation`: the M1 cross-generation rollback defense (design §4.3)
//!   - `seq`: the within-generation sequence rollback defense (design §6.5)
//!
//! Both floors are read through an injected [`HighWaterStore`] seam on every
//! access — there is NO in-instance cache — so a fresh [`RotationHighWater`]
//! constructed over the SAME backing store observes previously-written
//! floors (the restart/persistence semantics proven at the logic tier; the
//! concrete durable implementation is [`crate::floor_store::JsonSidecarFloorStore`]).
//!
//! `enforce_resolved` is a pure pass/reject pre-unseal gate — it never
//! returns or computes any AAD/unseal parameter.

use thiserror::Error;

/// A durable key-value seam for a single high-water floor (generation or seq).
///
/// Mirrors the TS `HighWaterStore` interface. Note the store's own value
/// type is `u64` — negative/fractional/NaN values are a *live-input*
/// concern (see [`EnforceResolvedParams`]), not a stored-value concern,
/// since a validated floor is always a non-negative integer once persisted.
///
/// `#[allow(async_fn_in_trait)]`: this trait is only ever used generically
/// (`RotationHighWater<S: HighWaterStore>`), never as `dyn HighWaterStore`,
/// so the missing auto-trait (`Send`) bound on the generated future is not
/// a concern within this crate.
#[allow(async_fn_in_trait)]
pub trait HighWaterStore {
    /// Read the current floor for `node_id`, or `None` if never set.
    async fn get(&self, node_id: &str) -> Option<u64>;
    /// Persist a new floor value for `node_id`.
    async fn put(&self, node_id: &str, value: u64);
}

/// Parameters supplied to `enforce_resolved` for a freshly-resolved IPNS record.
///
/// `seq`/`generation`/`version_floor` are `i64` (not `u64`) deliberately:
/// they carry *live, not-yet-validated* input from the resolve path, which
/// may be malformed (negative) if fed by a malicious/buggy relay. Rust has
/// no integer NaN, so the "NaN" defense in the TS reference collapses to
/// the negative-value check here (V5 fail-closed).
#[derive(Debug, Clone)]
pub struct EnforceResolvedParams {
    pub node_id: String,
    pub seq: i64,
    pub generation: i64,
    /// Owner-vouched cold-device floor applied only on first contact (no local seq floor yet).
    pub version_floor: i64,
}

/// Errors raised by `enforce_resolved`. Mirrors `GenerationRegressionError` /
/// `SequenceRegressionError` from the TS reference, plus a distinct
/// `InvalidFloorValue` variant for malformed live input (TS folds this into
/// the regression errors with a sentinel `floor: -1`; Rust separates it for
/// a more precise `match`).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum RotationError {
    #[error(
        "Generation regression rejected for node {node_id}: floor={floor}, attempted={attempted}"
    )]
    GenerationRegression {
        node_id: String,
        floor: i64,
        attempted: i64,
    },
    #[error(
        "Sequence regression rejected for node {node_id}: floor={floor}, attempted={attempted}"
    )]
    SequenceRegression {
        node_id: String,
        floor: i64,
        attempted: i64,
    },
    #[error("Invalid {field} value for node {node_id}: {value}")]
    InvalidFloorValue {
        node_id: String,
        field: &'static str,
        value: i64,
    },
    /// Propagated verbatim from an injected `rotate` closure (e.g.
    /// `rotation::scope::maybe_rotate_on_scope_exit`) when the underlying
    /// `rotate_read_from_node` call fails. Fail-closed: never swallowed.
    #[error("Rotation failed: {0}")]
    RotateFailed(String),
}

/// Validates a live input or stored candidate value. Fail-closed (V5):
/// anything that is not a non-negative integer is rejected rather than
/// coerced to a low floor. `i64` has no fractional/NaN representation, so
/// this collapses to the non-negative check (the Rust analog of the TS
/// `Number.isInteger`/`Number.isSafeInteger`/NaN guards).
pub fn is_valid_floor_value(value: i64) -> bool {
    value >= 0
}

/// Reads a floor from the store. The store's value type (`u64`) already
/// guarantees non-negative-integer validity for anything actually
/// persisted, so no extra validation is needed on read (mirrors TS
/// `readFloor`, whose validation exists only because JS storage is
/// untyped).
async fn read_floor<S: HighWaterStore>(store: &S, node_id: &str) -> Option<u64> {
    store.get(node_id).await
}

/// Conditionally raises a floor to `candidate` only if it is higher than the
/// current stored value (monotonic-max). Returns the resulting floor.
///
/// A malformed candidate (negative) is never persisted — the floor stays
/// where it is (mirrors TS `bumpFloor`'s V5-on-writes guard).
async fn bump_floor<S: HighWaterStore>(store: &S, node_id: &str, candidate: i64) -> u64 {
    let current = read_floor(store, node_id).await;
    if !is_valid_floor_value(candidate) {
        return current.unwrap_or(0);
    }
    let candidate_u64 = candidate as u64;
    match current {
        Some(cur) if candidate_u64 <= cur => cur,
        _ => {
            store.put(node_id, candidate_u64).await;
            candidate_u64
        }
    }
}

/// The durable rotation high-water state machine.
///
/// Holds two injected [`HighWaterStore`] seams — one for the generation
/// floor, one for the seq floor. Holds no in-instance cache: every
/// read/write goes through the injected stores.
#[derive(Clone)]
pub struct RotationHighWater<S: HighWaterStore> {
    generation_store: S,
    seq_store: S,
    /// Serializes every `bump_floor` read-compare-write against this
    /// instance (T-70-03): the authoritative max-preserving atomicity lives
    /// in the concrete store's own `put` (e.g.
    /// [`crate::floor_store::JsonSidecarFloorStore`], per RESEARCH A3), so
    /// the persisted floor is always correct even without this guard --
    /// this additionally keeps `bump_floor`'s own read-then-decide window
    /// (and its return value) from interleaving with a concurrent bump on
    /// the SAME `RotationHighWater` instance. `Arc`-wrapped so `Clone`d
    /// instances (e.g. owned prefetch clones) still serialize together.
    bump_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl<S: HighWaterStore> RotationHighWater<S> {
    /// Creates a durable rotation high-water state machine over two injected
    /// [`HighWaterStore`] seams.
    pub fn new(generation_store: S, seq_store: S) -> Self {
        Self {
            generation_store,
            seq_store,
            bump_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub async fn get_generation_floor(&self, node_id: &str) -> Option<u64> {
        read_floor(&self.generation_store, node_id).await
    }

    pub async fn bump_generation(&self, node_id: &str, generation: i64) {
        let _guard = self.bump_lock.lock().await;
        bump_floor(&self.generation_store, node_id, generation).await;
    }

    /// Owner-vouched first-contact seed — raises the generation floor only
    /// if higher (never lowers it).
    pub async fn seed_from_grant(&self, node_id: &str, root_generation: i64) {
        let _guard = self.bump_lock.lock().await;
        bump_floor(&self.generation_store, node_id, root_generation).await;
    }

    pub async fn get_seq_floor(&self, node_id: &str) -> Option<u64> {
        read_floor(&self.seq_store, node_id).await
    }

    pub async fn bump_seq(&self, node_id: &str, seq: i64) {
        let _guard = self.bump_lock.lock().await;
        bump_floor(&self.seq_store, node_id, seq).await;
    }

    /// Fail-closed pre-unseal gate: compares a freshly-resolved seq/generation
    /// against the stored floors. Rejects on any regression; on first
    /// contact (no local seq floor) applies the cold-device `version_floor`
    /// gate; otherwise bumps both floors monotonic-max.
    ///
    /// This is a pure pass/reject decision — it never returns or computes
    /// any AAD/unseal parameter.
    ///
    /// Ordering (exact, matches TS `enforceResolved`):
    ///   1. validate live input (generation, then seq) — fail-closed on
    ///      malformed input BEFORE any floor comparison
    ///   2. generation-floor check
    ///   3. cold-device-versionFloor-or-warm-seq-floor branch
    ///   4. bump both floors monotonic-max
    pub async fn enforce_resolved(
        &self,
        params: EnforceResolvedParams,
    ) -> Result<(), RotationError> {
        let EnforceResolvedParams {
            node_id,
            seq,
            generation,
            version_floor,
        } = params;

        // 1. Fail-closed on the LIVE inputs too, not just stored values.
        if !is_valid_floor_value(generation) {
            return Err(RotationError::InvalidFloorValue {
                node_id,
                field: "generation",
                value: generation,
            });
        }
        if !is_valid_floor_value(seq) {
            return Err(RotationError::InvalidFloorValue {
                node_id,
                field: "seq",
                value: seq,
            });
        }

        // 2. Generation-floor check.
        let generation_floor = read_floor(&self.generation_store, &node_id).await;
        if let Some(floor) = generation_floor {
            if generation < floor as i64 {
                return Err(RotationError::GenerationRegression {
                    node_id,
                    floor: floor as i64,
                    attempted: generation,
                });
            }
        }

        // 3. Cold-device-versionFloor-or-warm-seq-floor branch.
        let seq_floor = read_floor(&self.seq_store, &node_id).await;
        match seq_floor {
            None => {
                // Cold-device / first-contact: apply the owner-vouched
                // versionFloor gate. A malformed versionFloor is rejected
                // rather than treated as "no gate" — first contact is
                // exactly when the gate matters most.
                if !is_valid_floor_value(version_floor) || seq < version_floor {
                    return Err(RotationError::SequenceRegression {
                        node_id,
                        floor: version_floor,
                        attempted: seq,
                    });
                }
            }
            Some(floor) => {
                if seq < floor as i64 {
                    return Err(RotationError::SequenceRegression {
                        node_id,
                        floor: floor as i64,
                        attempted: seq,
                    });
                }
            }
        }

        // 4. Bump both floors monotonic-max, guarded so this read-compare-
        // write cannot interleave against a concurrent bump on this same
        // instance (T-70-03).
        {
            let _guard = self.bump_lock.lock().await;
            bump_floor(&self.generation_store, &node_id, generation).await;
            bump_floor(&self.seq_store, &node_id, seq).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory HashMap-backed test store (mirrors the Vitest in-memory
    /// `Map`-backed HighWaterStore fixture).
    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, u64>>);

    impl HighWaterStore for MemStore {
        async fn get(&self, node_id: &str) -> Option<u64> {
            self.0.lock().unwrap().get(node_id).copied()
        }

        async fn put(&self, node_id: &str, value: u64) {
            self.0.lock().unwrap().insert(node_id.to_string(), value);
        }
    }

    fn rhw() -> RotationHighWater<MemStore> {
        RotationHighWater::new(MemStore::default(), MemStore::default())
    }

    #[test]
    fn is_valid_floor_value_rejects_negative() {
        assert!(is_valid_floor_value(0));
        assert!(is_valid_floor_value(42));
        assert!(!is_valid_floor_value(-1));
    }

    #[tokio::test]
    async fn cold_device_applies_version_floor_gate() {
        let rhw = rhw();
        // No local seq floor yet -- cold device. version_floor=5, seq=5 passes.
        let ok = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 5,
                generation: 0,
                version_floor: 5,
            })
            .await;
        assert!(ok.is_ok());
        assert_eq!(rhw.get_seq_floor("node-1").await, Some(5));
        assert_eq!(rhw.get_generation_floor("node-1").await, Some(0));
    }

    #[tokio::test]
    async fn cold_device_rejects_below_version_floor() {
        let rhw = rhw();
        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 3,
                generation: 0,
                version_floor: 5,
            })
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RotationError::SequenceRegression {
                node_id: "node-1".to_string(),
                floor: 5,
                attempted: 3,
            }
        );
        // Store must remain untouched on rejection.
        assert_eq!(rhw.get_seq_floor("node-1").await, None);
    }

    #[tokio::test]
    async fn warm_device_applies_seq_floor_not_version_floor() {
        let rhw = rhw();
        // Seed a seq floor of 10 (warm device).
        rhw.bump_seq("node-1", 10).await;

        // A resolve with seq=11 (>= floor) and a LOW version_floor (0) still
        // passes -- version_floor is ignored once warm.
        let ok = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 11,
                generation: 0,
                version_floor: 0,
            })
            .await;
        assert!(ok.is_ok());
        assert_eq!(rhw.get_seq_floor("node-1").await, Some(11));
    }

    #[tokio::test]
    async fn warm_device_rejects_seq_regression() {
        let rhw = rhw();
        rhw.bump_seq("node-1", 10).await;

        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 9,
                generation: 0,
                version_floor: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RotationError::SequenceRegression {
                node_id: "node-1".to_string(),
                floor: 10,
                attempted: 9,
            }
        );
        // Floor must not move on rejection.
        assert_eq!(rhw.get_seq_floor("node-1").await, Some(10));
    }

    #[tokio::test]
    async fn generation_regression_is_rejected_even_with_valid_seq() {
        let rhw = rhw();
        rhw.bump_generation("node-1", 3).await;

        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 100,
                generation: 2,
                version_floor: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RotationError::GenerationRegression {
                node_id: "node-1".to_string(),
                floor: 3,
                attempted: 2,
            }
        );
        // Neither floor should move -- generation check happens before any bump.
        assert_eq!(rhw.get_generation_floor("node-1").await, Some(3));
        assert_eq!(rhw.get_seq_floor("node-1").await, None);
    }

    #[tokio::test]
    async fn invalid_generation_input_rejected_before_any_floor_comparison() {
        let rhw = rhw();
        // Seed a generation floor so a false-positive "pass" would be
        // detectable via floor mutation.
        rhw.bump_generation("node-1", 5).await;

        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 0,
                generation: -1,
                version_floor: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RotationError::InvalidFloorValue {
                node_id: "node-1".to_string(),
                field: "generation",
                value: -1,
            }
        );
        // Store must remain untouched.
        assert_eq!(rhw.get_generation_floor("node-1").await, Some(5));
        assert_eq!(rhw.get_seq_floor("node-1").await, None);
    }

    #[tokio::test]
    async fn invalid_seq_input_rejected_before_floor_comparison() {
        let rhw = rhw();
        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: -5,
                generation: 0,
                version_floor: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RotationError::InvalidFloorValue {
                node_id: "node-1".to_string(),
                field: "seq",
                value: -5,
            }
        );
        assert_eq!(rhw.get_seq_floor("node-1").await, None);
    }

    #[tokio::test]
    async fn valid_forward_resolve_bumps_both_floors_monotonic_max() {
        let rhw = rhw();
        rhw.enforce_resolved(EnforceResolvedParams {
            node_id: "node-1".to_string(),
            seq: 2,
            generation: 1,
            version_floor: 0,
        })
        .await
        .unwrap();
        assert_eq!(rhw.get_generation_floor("node-1").await, Some(1));
        assert_eq!(rhw.get_seq_floor("node-1").await, Some(2));

        // A later, still-forward resolve raises both floors again.
        rhw.enforce_resolved(EnforceResolvedParams {
            node_id: "node-1".to_string(),
            seq: 7,
            generation: 4,
            version_floor: 0,
        })
        .await
        .unwrap();
        assert_eq!(rhw.get_generation_floor("node-1").await, Some(4));
        assert_eq!(rhw.get_seq_floor("node-1").await, Some(7));
    }

    #[tokio::test]
    async fn seed_from_grant_never_lowers_the_generation_floor() {
        let rhw = rhw();
        rhw.bump_generation("node-1", 5).await;
        rhw.seed_from_grant("node-1", 2).await;
        assert_eq!(rhw.get_generation_floor("node-1").await, Some(5));

        rhw.seed_from_grant("node-1", 9).await;
        assert_eq!(rhw.get_generation_floor("node-1").await, Some(9));
    }
}
