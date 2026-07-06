//! Scope-exit predicate and gating helper for read-key rotation.
//!
//! Rust port of `packages/sdk-core/src/rotation/scope.ts` (60 lines, pure,
//! no I/O). Implements ROT-02 / SC#4 / design §3.6, §3.8, §3.9 (D-08).
//!
//! `has_covering_grant`: PURE predicate — no I/O, no durable state, no async.
//!   Takes the mutated node's ancestry chain (leaf-first), the relay-supplied
//!   active-grant-root set, and the client's own local grant record; returns
//!   true iff at least one ancestor (or the node itself) is a grant root.
//!
//! `maybe_rotate_on_scope_exit`: gating composition — rotate iff covered.
//!   Takes an injected `rotate` closure so callers/tests can pass a spy
//!   (an `AtomicUsize` call-counter in this crate's tests, mirroring the TS
//!   `vi.fn()` spy in `scope.test.ts`).
//!
//! # Security
//!
//! T-63-17: the relay-supplied `active_grant_root_ipns_names` is a
//! COMPLETENESS AID, never the sole authority. A malicious relay can omit a
//! grant root to suppress rotation — the client's own `local_grant_record` is
//! the anti-malicious-relay cross-check. Both sources are consulted; either
//! one covering an ancestor is sufficient (§3.9).

use std::collections::HashSet;
use std::future::Future;

use super::RotationError;

/// Inputs to the scope-exit coverage predicate (D-08).
///
/// `node_ancestor_ipns_names`    — IPNS k51 names of the mutated node and all
///    its ancestors, ordered leaf-first (the node itself is first, vault
///    root is last). The predicate checks all of them; the first match
///    short-circuits.
///
/// `active_grant_root_ipns_names` — relay-supplied set of IPNS names that are
///    known grant roots (from the API shares query). Treated as a
///    COMPLETENESS AID: a relay can omit an entry to suppress rotation
///    (T-63-17), so it is checked alongside `local_grant_record`, not
///    instead of it.
///
/// `local_grant_record` — the client's own record of a grant it holds on
///    this node's ancestry. When `Some`, `local_grant_record.root_ipns_name`
///    is the anti-malicious-relay cross-check (§3.9): if that IPNS name
///    appears in the ancestry, the node is covered regardless of what the
///    relay reports.
#[derive(Debug, Clone)]
pub struct CoverageParams {
    pub node_ancestor_ipns_names: Vec<String>,
    pub active_grant_root_ipns_names: HashSet<String>,
    pub local_grant_record: Option<LocalGrantRecord>,
}

/// The client's own record of a grant it holds on some ancestry (the
/// anti-malicious-relay cross-check, T-63-17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalGrantRecord {
    pub root_ipns_name: String,
}

/// Result tag for `maybe_rotate_on_scope_exit`.
///
/// `NoRotation` — no covering grant found; zero `rotate_read_from_node`
///    invocations and zero IPNS publishes beyond the parent relink
///    (ROT-02 / SC#4).
/// `Rotated` — a covering grant was found; the injected `rotate` closure
///    was invoked once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeExitResult {
    NoRotation,
    Rotated,
}

// ---------------------------------------------------------------------------
// has_covering_grant — pure predicate (D-08)
// ---------------------------------------------------------------------------

/// Pure predicate: returns true iff the mutated node's ancestry contains a
/// grant root.
///
/// D-08: pure `sdk` function — no I/O, no durable state, no async.
/// §3.9: two independent sources are cross-checked:
///   1. `active_grant_root_ipns_names` (relay-supplied, completeness aid)
///   2. `local_grant_record.root_ipns_name` (client-authoritative,
///      anti-malicious-relay)
///
/// Either source covering any ancestor in `node_ancestor_ipns_names` returns
/// true. Short-circuits at the first match to minimise work on hot
/// delete/move/rename paths.
///
/// # Returns
/// true iff coverage found; false → zero rotation, per ROT-02 / SC#4.
///
/// # Security
/// No I/O. Never logs key material. Pure input→boolean transform.
pub fn has_covering_grant(params: &CoverageParams) -> bool {
    for ancestor in &params.node_ancestor_ipns_names {
        // Check relay-supplied set (completeness aid — §3.9).
        if params.active_grant_root_ipns_names.contains(ancestor) {
            return true;
        }
        // Check client's own local grant record (anti-malicious-relay
        // cross-check — §3.9 / T-63-17).
        if let Some(rec) = &params.local_grant_record {
            if &rec.root_ipns_name == ancestor {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// maybe_rotate_on_scope_exit — gating composition (§3.6, §3.8)
// ---------------------------------------------------------------------------

/// Gating helper: compute `has_covering_grant`; rotate iff covered; return
/// result tag.
///
/// This is the single composition point for the §3.8 "one rule, four call
/// sites" policy. Every delete/move/rename call site passes its ancestry +
/// grant-root context here instead of inline-branching. The injectable
/// `rotate` closure allows tests to assert call counts via a call-counter
/// spy — the SC#4 zero-rotation invariant test (the signature test for this
/// phase) depends on that injection point.
///
/// ROT-02 / SC#4 invariant: when `has_covering_grant` returns false, this
/// function returns `NoRotation` and NEVER invokes `rotate`. Zero IPNS
/// publishes beyond the parent relink. Proved by this module's spy-based
/// tests.
///
/// When `has_covering_grant` returns true, `rotate` is invoked EXACTLY ONCE
/// per scope-exit event (one rotation per delete/move/rename regardless of
/// how many ancestors are grant roots).
///
/// A `rotate` error propagates as `Err` (fail-closed, not swallowed).
///
/// # Security
/// No key material is held or zeroed here. Delegates zeroization to
/// `rotate` (the `rotate_read_from_node` callee, which follows D-09).
pub async fn maybe_rotate_on_scope_exit<F, Fut>(
    params: &CoverageParams,
    rotate: F,
) -> Result<ScopeExitResult, RotationError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), RotationError>>,
{
    if !has_covering_grant(params) {
        // ROT-02 / SC#4: no covering grant → zero rotation, zero IPNS
        // publishes. The caller already performed the parent relink; no
        // further action here.
        return Ok(ScopeExitResult::NoRotation);
    }

    // Covered scope-exit: invoke rotation exactly once. `rotate` is injected
    // for testability (a call-counter spy in this module's tests).
    rotate().await?;
    Ok(ScopeExitResult::Rotated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------
    // has_covering_grant — pure predicate
    // -----------------------------------------------------------------

    #[test]
    fn returns_false_when_ancestry_is_empty() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![],
            active_grant_root_ipns_names: HashSet::from(["k51/root-a".to_string()]),
            local_grant_record: None,
        };
        assert!(!has_covering_grant(&params));
    }

    #[test]
    fn returns_false_when_neither_relay_set_nor_local_record_covers_any_ancestor() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![
                "k51/node-x".to_string(),
                "k51/parent-y".to_string(),
                "k51/root-z".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::from(["k51/other-root".to_string()]),
            local_grant_record: Some(LocalGrantRecord {
                root_ipns_name: "k51/unrelated-root".to_string(),
            }),
        };
        assert!(!has_covering_grant(&params));
    }

    #[test]
    fn returns_false_when_relay_set_is_empty_and_local_record_is_none() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec!["k51/node-x".to_string(), "k51/parent-y".to_string()],
            active_grant_root_ipns_names: HashSet::new(),
            local_grant_record: None,
        };
        assert!(!has_covering_grant(&params));
    }

    #[test]
    fn returns_true_when_a_non_root_ancestor_is_in_the_active_relay_grant_roots() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![
                "k51/node-x".to_string(),
                "k51/shared-folder".to_string(),
                "k51/root-z".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::from(["k51/shared-folder".to_string()]),
            local_grant_record: None,
        };
        assert!(has_covering_grant(&params));
    }

    #[test]
    fn returns_true_when_the_node_itself_is_a_relay_grant_root() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec!["k51/node-x".to_string()],
            active_grant_root_ipns_names: HashSet::from(["k51/node-x".to_string()]),
            local_grant_record: None,
        };
        assert!(has_covering_grant(&params));
    }

    #[test]
    fn returns_true_when_the_top_level_root_ancestor_is_in_the_relay_grant_roots() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![
                "k51/leaf".to_string(),
                "k51/mid".to_string(),
                "k51/root-shared".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::from(["k51/root-shared".to_string()]),
            local_grant_record: None,
        };
        assert!(has_covering_grant(&params));
    }

    /// §3.9 / T-63-17 anti-malicious-relay: relay omits the grant root, but
    /// the client's own `local_grant_record` covers an ancestor → still
    /// covered even when the relay set is empty.
    #[test]
    fn returns_true_when_relay_omits_grant_root_but_local_record_covers_an_ancestor() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![
                "k51/leaf".to_string(),
                "k51/shared-folder".to_string(),
                "k51/root".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::new(), // relay omits it (malicious or stale)
            local_grant_record: Some(LocalGrantRecord {
                root_ipns_name: "k51/shared-folder".to_string(),
            }),
        };
        assert!(has_covering_grant(&params));
    }

    #[test]
    fn returns_true_when_local_record_root_is_the_leaf_node_itself() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec!["k51/file-node".to_string()],
            active_grant_root_ipns_names: HashSet::new(),
            local_grant_record: Some(LocalGrantRecord {
                root_ipns_name: "k51/file-node".to_string(),
            }),
        };
        assert!(has_covering_grant(&params));
    }

    #[test]
    fn does_not_count_local_record_when_its_root_is_not_in_the_ancestry() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec!["k51/node-a".to_string(), "k51/parent-b".to_string()],
            active_grant_root_ipns_names: HashSet::new(),
            local_grant_record: Some(LocalGrantRecord {
                root_ipns_name: "k51/unrelated-root".to_string(),
            }),
        };
        assert!(!has_covering_grant(&params));
    }

    // -----------------------------------------------------------------
    // maybe_rotate_on_scope_exit — gating composition
    // -----------------------------------------------------------------

    /// Call-counter spy mirroring the TS `vi.fn()` rotate spy.
    #[derive(Default)]
    struct RotateSpy(AtomicUsize);

    impl RotateSpy {
        fn calls(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }

        async fn rotate(&self) -> Result<(), RotationError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    // -------------------------------------------------------------------
    // SC#4 / ROT-02: THE ZERO-ROTATION INVARIANT
    //
    // A private delete/move/rename with NO covering grant must:
    //   - call the injected rotate spy ZERO times
    //   - return NoRotation
    //   - produce ZERO IPNS publishes beyond the parent relink
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn sc4_rot02_private_delete_triggers_zero_rotations() {
        let spy = RotateSpy::default();
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![
                "k51/private-leaf".to_string(),
                "k51/private-folder".to_string(),
                "k51/vault-root".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::new(), // no shares exist
            local_grant_record: None,                     // this client holds no grant
        };

        let result = maybe_rotate_on_scope_exit(&params, || spy.rotate())
            .await
            .unwrap();

        // THE INVARIANT: zero rotate invocations.
        assert_eq!(spy.calls(), 0);
        assert_eq!(result, ScopeExitResult::NoRotation);
    }

    #[tokio::test]
    async fn sc4_rot02_private_move_with_non_matching_sources_triggers_zero_rotations() {
        let spy = RotateSpy::default();
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![
                "k51/moved-node".to_string(),
                "k51/src-folder".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::from([
                "k51/other-shared-folder".to_string(), // share for a different subtree
            ]),
            local_grant_record: Some(LocalGrantRecord {
                root_ipns_name: "k51/other-shared-folder".to_string(), // grant on a different subtree
            }),
        };

        let result = maybe_rotate_on_scope_exit(&params, || spy.rotate())
            .await
            .unwrap();

        assert_eq!(spy.calls(), 0);
        assert_eq!(result, ScopeExitResult::NoRotation);
    }

    // -------------------------------------------------------------------
    // Covered case: scope-exit → exactly one rotation invocation
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn calls_rotate_exactly_once_when_an_ancestor_is_a_relay_grant_root() {
        let spy = RotateSpy::default();
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![
                "k51/deleted-node".to_string(),
                "k51/shared-folder".to_string(),
                "k51/root".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::from(["k51/shared-folder".to_string()]),
            local_grant_record: None,
        };

        let result = maybe_rotate_on_scope_exit(&params, || spy.rotate())
            .await
            .unwrap();

        assert_eq!(spy.calls(), 1);
        assert_eq!(result, ScopeExitResult::Rotated);
    }

    #[tokio::test]
    async fn calls_rotate_exactly_once_when_the_node_itself_is_the_relay_grant_root() {
        let spy = RotateSpy::default();
        let params = CoverageParams {
            node_ancestor_ipns_names: vec!["k51/deleted-node".to_string()],
            active_grant_root_ipns_names: HashSet::from(["k51/deleted-node".to_string()]),
            local_grant_record: None,
        };

        let result = maybe_rotate_on_scope_exit(&params, || spy.rotate())
            .await
            .unwrap();

        assert_eq!(spy.calls(), 1);
        assert_eq!(result, ScopeExitResult::Rotated);
    }

    // -------------------------------------------------------------------
    // §3.9 / T-63-17 anti-malicious-relay cross-check
    //
    // Relay omits the grant root (malicious or stale) but the client's own
    // local_grant_record covers the ancestor → rotation MUST still fire.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn t63_17_relay_omits_grant_root_but_local_record_covers_ancestor_still_rotates() {
        let spy = RotateSpy::default();
        let params = CoverageParams {
            node_ancestor_ipns_names: vec![
                "k51/deleted-file".to_string(),
                "k51/shared-folder".to_string(),
                "k51/root".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::new(), // relay maliciously omits 'k51/shared-folder'
            local_grant_record: Some(LocalGrantRecord {
                root_ipns_name: "k51/shared-folder".to_string(), // client knows it owns this grant
            }),
        };

        let result = maybe_rotate_on_scope_exit(&params, || spy.rotate())
            .await
            .unwrap();

        // Anti-malicious-relay: local_grant_record is authoritative cross-check.
        assert_eq!(spy.calls(), 1);
        assert_eq!(result, ScopeExitResult::Rotated);
    }

    #[tokio::test]
    async fn does_not_call_rotate_more_than_once_when_multiple_ancestors_are_grant_roots() {
        let spy = RotateSpy::default();
        let params = CoverageParams {
            // Multiple ancestors are grant roots (e.g., nested shared folders).
            node_ancestor_ipns_names: vec![
                "k51/leaf".to_string(),
                "k51/shared-sub".to_string(),
                "k51/shared-root".to_string(),
            ],
            active_grant_root_ipns_names: HashSet::from([
                "k51/shared-sub".to_string(),
                "k51/shared-root".to_string(),
            ]),
            local_grant_record: Some(LocalGrantRecord {
                root_ipns_name: "k51/shared-root".to_string(),
            }),
        };

        let result = maybe_rotate_on_scope_exit(&params, || spy.rotate())
            .await
            .unwrap();

        // ONE rotation per scope-exit, regardless of how many ancestors are grant roots.
        assert_eq!(spy.calls(), 1);
        assert_eq!(result, ScopeExitResult::Rotated);
    }

    // -------------------------------------------------------------------
    // Fail-closed: a rotate() error propagates as Err, never swallowed.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_error_propagates_as_err_and_is_not_swallowed() {
        let params = CoverageParams {
            node_ancestor_ipns_names: vec!["k51/deleted-node".to_string()],
            active_grant_root_ipns_names: HashSet::from(["k51/deleted-node".to_string()]),
            local_grant_record: None,
        };

        let result = maybe_rotate_on_scope_exit(&params, || async {
            Err(RotationError::RotateFailed(
                "simulated rotate failure".to_string(),
            ))
        })
        .await;

        assert_eq!(
            result.unwrap_err(),
            RotationError::RotateFailed("simulated rotate failure".to_string())
        );
    }
}
