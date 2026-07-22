//! Direct-child-scope index maintenance (blueprint/engine.md "Enumeration walks
//! the write-body's direct-child-scope index", #38 D6).
//!
//! The index enumerates a scope root's directly-descendant scope roots; later
//! rotate/sweep slices walk it for the F-4 cascade. This module is the pure
//! maintenance/ordering logic over `Vec<ChildScopeRef>` — no new seam, no separate
//! store: durability rides the write-body's `direct_child_scope_index` field
//! ([`ChildScopeRef`]), already sealed under the root's `writeKey`, published, and
//! gate-authenticated.
//!
//! # Maintenance semantics
//!
//! Parentage-changing ops (grant, scope dissolution, cross-scope move) maintain
//! the index under **dest-first + observed-repair** (#38 D6):
//!
//! - **Dest-first**: add into the destination parent's index before the
//!   presence-conditional remove from the source, so no window leaves the child
//!   absent from both — orphans are structurally impossible. A race loser undoes
//!   its dest-add ([`undo_dest_add`]).
//! - **Observed repair**: any write-capable client that sees a child missing from
//!   its parent's index repairs it ([`repair_observed`]).
//!
//! # Deterministic convergence
//!
//! Entries are ordered and deduped by `scope_id` byte `Ord` so replayed /
//! multi-writer runs converge to identical bytes. A `scope_id` names exactly one
//! child, so **first-seen** dedup is the deliberate replace-wins operation policy
//! (ops prepend the authoritative entry), not a content tie-break — see
//! [`canonicalize`].

use cipherbox_core::seal::ChildScopeRef;

/// Order `entries` by `scope_id` byte `Ord` and dedup by `scope_id`, keeping the
/// **first-seen** entry for each id. This is the deterministic-convergence
/// primitive: any permutation of a set of **distinct** `scope_id`s yields
/// byte-identical output.
///
/// First-seen (not last) is the rule because the maintenance ops
/// ([`insert_child`], [`repair_observed`]) prepend the authoritative entry, so a
/// fresh add wins over a stale duplicate. A `scope_id` names exactly one child, so
/// differing-content duplicates are an invariant violation the ops never produce;
/// first-seen is the replace-wins operation policy, not a content tie-break a
/// permutation-blind full-entry order could wrongly override.
pub fn canonicalize(entries: &[ChildScopeRef]) -> Vec<ChildScopeRef> {
    let mut sorted: Vec<ChildScopeRef> = entries.to_vec();
    // Stable sort keeps first-seen order among equal ids, so the retain below
    // drops later duplicates.
    sorted.sort_by(|a, b| a.scope_id.cmp(&b.scope_id));
    let mut seen: Option<[u8; 16]> = None;
    sorted.retain(|e| {
        if seen == Some(e.scope_id) {
            false
        } else {
            seen = Some(e.scope_id);
            true
        }
    });
    sorted
}

/// Dest-first add: insert `child`, replacing any existing entry with the same
/// `scope_id`, and re-canonicalize. Idempotent on identical input.
pub fn insert_child(index: &[ChildScopeRef], child: ChildScopeRef) -> Vec<ChildScopeRef> {
    // Prepend so first-seen dedup keeps the fresh entry over any stale duplicate.
    let mut next = Vec::with_capacity(index.len() + 1);
    next.push(child);
    next.extend_from_slice(index);
    canonicalize(&next)
}

/// Presence-conditional remove by `scope_id`. Idempotent: removing an absent
/// `scope_id` is a no-op, never an error.
pub fn remove_child(index: &[ChildScopeRef], scope_id: &[u8; 16]) -> Vec<ChildScopeRef> {
    let next: Vec<ChildScopeRef> = index
        .iter()
        .filter(|e| &e.scope_id != scope_id)
        .cloned()
        .collect();
    // Input is normally already canonical; canonicalize keeps this total.
    canonicalize(&next)
}

/// Dest-first cross-scope move of a scope root: insert `child` into `dest`
/// **then** remove it from `src`, returning `(new_dest, new_src)`. The dest-add
/// is computed before the src-remove, so no returned state has the child absent
/// from both — orphans are structurally impossible (#38 D6). Callers must
/// publish `new_dest` before `new_src`.
pub fn move_child(
    dest: &[ChildScopeRef],
    src: &[ChildScopeRef],
    child: ChildScopeRef,
) -> (Vec<ChildScopeRef>, Vec<ChildScopeRef>) {
    let scope_id = child.scope_id;
    let new_dest = insert_child(dest, child);
    let new_src = remove_child(src, &scope_id);
    (new_dest, new_src)
}

/// Observed-repair self-heal: ensure `child` is present (idempotent insert).
/// Called by the sweep when it encounters a scope root missing from its parent's
/// index (#38 D6).
pub fn repair_observed(index: &[ChildScopeRef], child: ChildScopeRef) -> Vec<ChildScopeRef> {
    insert_child(index, child)
}

/// Race-loser compensation for the dest-first path: undo a dest-add by removing
/// `scope_id`. Semantically identical to [`remove_child`]; named for the
/// compensation call site.
pub fn undo_dest_add(dest: &[ChildScopeRef], scope_id: &[u8; 16]) -> Vec<ChildScopeRef> {
    remove_child(dest, scope_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child(scope_id: u8, name: &str) -> ChildScopeRef {
        ChildScopeRef::new([scope_id; 16], name.as_bytes().to_vec())
    }

    fn ids(index: &[ChildScopeRef]) -> Vec<[u8; 16]> {
        index.iter().map(|e| e.scope_id).collect()
    }

    #[test]
    fn canonical_order_is_permutation_independent() {
        let a = child(0x03, "c");
        let b = child(0x01, "a");
        let c = child(0x02, "b");

        let order1 = canonicalize(&[a.clone(), b.clone(), c.clone()]);
        let order2 = canonicalize(&[c.clone(), a.clone(), b.clone()]);
        let order3 = canonicalize(&[b.clone(), c.clone(), a.clone()]);

        // Byte-for-byte identical ordering, sorted ascending by scope_id.
        assert_eq!(order1, order2);
        assert_eq!(order2, order3);
        assert_eq!(ids(&order1), vec![[0x01; 16], [0x02; 16], [0x03; 16]]);
    }

    #[test]
    fn insert_orders_deterministically_across_insert_sequences() {
        let a = child(0xAA, "a");
        let b = child(0x11, "b");
        let c = child(0x55, "c");

        let built1 = insert_child(
            &insert_child(&insert_child(&[], a.clone()), b.clone()),
            c.clone(),
        );
        let built2 = insert_child(
            &insert_child(&insert_child(&[], c.clone()), b.clone()),
            a.clone(),
        );

        assert_eq!(built1, built2);
        assert_eq!(ids(&built1), vec![[0x11; 16], [0x55; 16], [0xAA; 16]]);
    }

    #[test]
    fn dedup_on_scope_id_keeps_one() {
        let first = child(0x42, "first");
        let dup = ChildScopeRef::new([0x42; 16], b"second".to_vec());

        let out = canonicalize(&[first.clone(), dup]);
        assert_eq!(out.len(), 1);
        // First-seen wins.
        assert_eq!(out[0], first);
    }

    #[test]
    fn insert_replaces_same_scope_id_with_fresh_entry() {
        let stale = ChildScopeRef::new([0x42; 16], b"old-name".to_vec());
        let fresh = ChildScopeRef::new([0x42; 16], b"new-name".to_vec());

        let out = insert_child(&[stale], fresh.clone());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], fresh, "fresh add wins over stale duplicate");
    }

    #[test]
    fn reversed_duplicate_inserts_converge_on_last_authoritative_write() {
        // CR #741: differing-content dups are resolved by the op (last insert
        // wins), not by a permutation-blind tie-break. Convergence tracks the
        // latest authoritative write, independent of prior content or sibling
        // build order.
        let sib = child(0x10, "sib");
        let stale = ChildScopeRef::new([0x42; 16], b"stale".to_vec());
        let fresh = ChildScopeRef::new([0x42; 16], b"fresh".to_vec());

        // Two writers both end with `fresh` inserted last over the same siblings,
        // reached via different prior content / build order → identical bytes.
        let a = insert_child(&insert_child(&[stale.clone()], sib.clone()), fresh.clone());
        let b = insert_child(&insert_child(&[], sib.clone()), fresh.clone());
        assert_eq!(
            a, b,
            "converged bytes independent of prior content and order"
        );
        let entry = |v: &[ChildScopeRef]| {
            v.iter()
                .find(|e| e.scope_id == [0x42; 16])
                .unwrap()
                .ipns_name
                .clone()
        };
        assert_eq!(
            entry(&a),
            b"fresh",
            "last-inserted authoritative entry wins"
        );

        // Inserting `stale` last instead keeps `stale` — replace-wins is the op
        // policy a full-entry canonicalize tie-break would wrongly override.
        let c = insert_child(&insert_child(&[fresh.clone()], sib.clone()), stale.clone());
        assert_eq!(entry(&c), b"stale");
    }

    #[test]
    fn insert_is_idempotent_on_identical_input() {
        let index = insert_child(&[], child(0x07, "x"));
        let once = insert_child(&index, child(0x07, "x"));
        let twice = insert_child(&once, child(0x07, "x"));
        assert_eq!(once, twice);
        assert_eq!(once.len(), 1);
    }

    #[test]
    fn move_child_is_dest_first_no_intermediate_orphan() {
        let moving = child(0x30, "moving");
        let dest = vec![child(0x10, "d1")];
        let src = vec![moving.clone(), child(0x20, "s1")];

        let (new_dest, new_src) = move_child(&dest, &src, moving.clone());

        // Dest gained it, src lost it.
        assert!(new_dest.iter().any(|e| e.scope_id == [0x30; 16]));
        assert!(!new_src.iter().any(|e| e.scope_id == [0x30; 16]));

        // Dest-first invariant: the add is computed before the remove, so the
        // child is present in new_dest at the moment new_src is derived — never
        // absent from both returned states.
        let present_in_dest = new_dest.iter().any(|e| e.scope_id == [0x30; 16]);
        let present_in_src = new_src.iter().any(|e| e.scope_id == [0x30; 16]);
        assert!(present_in_dest || present_in_src, "never absent from both");
        assert!(present_in_dest, "dest-add precedes src-remove");
    }

    #[test]
    fn repair_observed_is_idempotent() {
        let missing = child(0x99, "missing");
        let index = vec![child(0x01, "a")];

        let once = repair_observed(&index, missing.clone());
        let twice = repair_observed(&once, missing.clone());

        assert_eq!(once, twice);
        assert!(once.iter().any(|e| e.scope_id == [0x99; 16]));
    }

    #[test]
    fn remove_absent_scope_id_is_noop() {
        let index = vec![child(0x01, "a"), child(0x02, "b")];
        let out = remove_child(&index, &[0xFF; 16]);
        assert_eq!(out, canonicalize(&index));
    }

    #[test]
    fn remove_is_idempotent() {
        let index = vec![child(0x01, "a"), child(0x02, "b")];
        let once = remove_child(&index, &[0x01; 16]);
        let twice = remove_child(&once, &[0x01; 16]);
        assert_eq!(once, twice);
        assert_eq!(ids(&once), vec![[0x02; 16]]);
    }

    #[test]
    fn undo_dest_add_reverses_insert() {
        let moving = child(0x44, "x");
        let dest = vec![child(0x10, "d1")];
        let added = insert_child(&dest, moving.clone());
        let undone = undo_dest_add(&added, &[0x44; 16]);
        assert_eq!(undone, canonicalize(&dest));
    }
}
