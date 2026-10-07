//! The cross-scope crossing: which scope owns a node, the plan a relocation
//! journals, the authority a drain pass publishes it under, and the cut it owes
//! (CONTEXT.md "Cross-scope move"; blueprint/engine.md "Sync core: Ops").
//!
//! The journaled [`ScopeCrossing`] is a plan; the drain decides from the scope
//! roots it lists now (ADR 0045 D1). Every rule here is pure over node ids and a
//! [`Snapshot`].

use crate::facade::NodeId;
use crate::sync::model::Snapshot;
use crate::sync::op::{Op, ScopeCrossing};

/// The listed scope root at or above `node`, walking it and then its ancestors
/// nearest-first — **full-depth** detection, so a node at depth N resolves the
/// same root a node at depth 1 does (blueprint/engine.md "Rotation primitives:
/// Triggers"; the one-level check is the v1 coverage hole).
///
/// `None` when the chain reaches no listed root. Each caller decides whether to
/// list the vault root; [`scope_of`] gives the absence its meaning.
pub(crate) fn enclosing_scope_root(
    base: &Snapshot,
    node: NodeId,
    scope_roots: &[NodeId],
) -> Option<NodeId> {
    core::iter::once(node)
        .chain(base.ancestors(node))
        .find(|candidate| scope_roots.contains(candidate))
}

/// The scope `node` belongs to, named by its root. `base.root` anchors the
/// vault's initial scope, which every node that reaches no listed root belongs
/// to.
pub(crate) fn scope_of(base: &Snapshot, node: NodeId, scope_roots: &[NodeId]) -> NodeId {
    enclosing_scope_root(base, node, scope_roots).unwrap_or(base.root)
}

/// How one relocation reaches the destination scope: as the single op the
/// caller asked for, or as the two legs a crossing between two interior scopes
/// takes through the vault-root scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationPlan {
    /// One op, carrying the crossing it makes.
    Direct(ScopeCrossing),
    /// Two ops: park the subtree in the vault-root scope, then bring it into
    /// the destination scope. One drain pass anchors on the vault root and
    /// carries one interior end beside it, so a crossing between two interior
    /// scopes names an end no pass holds — while each of these legs has the
    /// vault root at one end ([`ScopeCrossing`]).
    Staged,
}

impl RelocationPlan {
    /// Whether the relocation stays inside one scope, and so re-seals nothing
    /// and cuts nothing.
    pub(crate) fn is_intra(self) -> bool {
        self == Self::Direct(ScopeCrossing::Intra)
    }
}

/// The plan a relocation journals, from the scopes its two ends sit in. `root`
/// is the vault-root scope, which grants nobody; any interior source is a
/// granted one, because the cut that created it granted somebody.
pub(crate) fn plan(source: NodeId, destination: NodeId, root: NodeId) -> RelocationPlan {
    if source == destination {
        RelocationPlan::Direct(ScopeCrossing::Intra)
    } else if source != root && destination != root {
        RelocationPlan::Staged
    } else if source == root {
        RelocationPlan::Direct(ScopeCrossing::Cross)
    } else {
        RelocationPlan::Direct(ScopeCrossing::ExitsGrantedSource)
    }
}

/// What a drain pass publishes a relocation as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authority {
    /// One scope: a plain ref move.
    Relink,
    /// Two scopes: the subtree re-seals into the destination scope.
    Reseal,
    /// The op journaled a crossing whose two ends this pass resolves onto one
    /// scope, which this pass cannot author.
    Unauthorable,
}

/// The authority over a relocation: the two ends the pass proved, not the
/// crossing the op journaled. A grant minted after the journal entry turns an
/// intra-scope relocation into one that leaves a scope somebody now reads.
pub(crate) fn authoritative(
    journaled: ScopeCrossing,
    source: NodeId,
    destination: NodeId,
) -> Authority {
    if source != destination {
        Authority::Reseal
    } else if journaled == ScopeCrossing::Intra {
        Authority::Relink
    } else {
        Authority::Unauthorable
    }
}

/// The scope root a relocation owes a cut, from the scope roots of its two
/// ends. A source in `grants_nobody` owes nothing. A destination that resolves
/// to no listed root, which another writer may have deleted, is no evidence of
/// a crossing: it owes the journaled exit only when the move is known to have
/// `published`.
pub(crate) fn owed_cut(
    source: Option<NodeId>,
    destination: Option<NodeId>,
    grants_nobody: NodeId,
    journaled: ScopeCrossing,
    published: bool,
) -> Option<NodeId> {
    let source = source.filter(|root| *root != grants_nobody)?;
    match destination {
        Some(destination) => (destination != source).then_some(source),
        None => (published && journaled == ScopeCrossing::ExitsGrantedSource).then_some(source),
    }
}

/// [`owed_cut`] for a relocation that already landed, over the scope roots
/// `base` lists. `base.root` grants nobody.
pub(crate) fn landed_cut(
    base: &Snapshot,
    op: &Op,
    scope_roots: &[NodeId],
    published: bool,
) -> Option<NodeId> {
    let (from_parent, new_parent, journaled) = op.relocation()?;
    owed_cut(
        enclosing_scope_root(base, from_parent, scope_roots),
        enclosing_scope_root(base, new_parent, scope_roots),
        base.root,
        journaled,
        published,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::facade::NodeKind;
    use crate::sync::model::NodeMeta;

    const VAULT: NodeId = NodeId([0; 16]);
    const GRANTED: NodeId = NodeId([5; 16]);
    const OTHER: NodeId = NodeId([8; 16]);
    const GONE: NodeId = NodeId([0x33; 16]);

    fn id(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    /// The vault root; a granted scope at id 5 with a chain 10, 11, 12 below
    /// it; a plain folder at 6; a second granted scope at 8 with 9 below it.
    fn tree() -> Snapshot {
        let mut base = Snapshot::new(VAULT);
        for (parent, node) in [
            (VAULT, GRANTED),
            (VAULT, id(6)),
            (GRANTED, id(10)),
            (id(10), id(11)),
            (id(11), id(12)),
            (VAULT, OTHER),
            (OTHER, id(9)),
        ] {
            base.upsert_node(NodeMeta::new(node, "n", NodeKind::Folder));
            base.link(parent, node, 1);
        }
        base
    }

    const LISTED: &[NodeId] = &[VAULT, GRANTED, OTHER];

    #[test]
    fn a_node_belongs_to_the_nearest_listed_root_at_any_depth() {
        let base = tree();
        for (label, node, roots, owner) in [
            ("a scope root owns itself", GRANTED, LISTED, GRANTED),
            ("depth one", id(10), LISTED, GRANTED),
            ("depth three", id(12), LISTED, GRANTED),
            ("a plain folder", id(6), LISTED, VAULT),
            (
                "no listed root falls back to the base root",
                id(12),
                &[][..],
                VAULT,
            ),
            (
                "an unlisted boundary is no boundary",
                id(9),
                &[GRANTED][..],
                VAULT,
            ),
            ("a node the base does not hold", GONE, LISTED, VAULT),
        ] {
            assert_eq!(scope_of(&base, node, roots), owner, "{label}");
        }
        assert_eq!(enclosing_scope_root(&base, GONE, LISTED), None);
    }

    #[test]
    fn the_plan_follows_the_two_scopes_and_the_vault_root() {
        for (label, source, destination, expected) in [
            (
                "one scope",
                GRANTED,
                GRANTED,
                RelocationPlan::Direct(ScopeCrossing::Intra),
            ),
            (
                "the vault scope",
                VAULT,
                VAULT,
                RelocationPlan::Direct(ScopeCrossing::Intra),
            ),
            (
                "into a granted scope",
                VAULT,
                GRANTED,
                RelocationPlan::Direct(ScopeCrossing::Cross),
            ),
            (
                "out of a granted scope",
                GRANTED,
                VAULT,
                RelocationPlan::Direct(ScopeCrossing::ExitsGrantedSource),
            ),
            (
                "between two interior scopes",
                GRANTED,
                OTHER,
                RelocationPlan::Staged,
            ),
        ] {
            assert_eq!(plan(source, destination, VAULT), expected, "{label}");
        }
        assert!(plan(GRANTED, GRANTED, VAULT).is_intra());
        assert!(!RelocationPlan::Staged.is_intra());
    }

    #[test]
    fn the_proved_ends_decide_over_the_journaled_crossing() {
        for (label, journaled, source, destination, expected) in [
            (
                "intra, one scope",
                ScopeCrossing::Intra,
                VAULT,
                VAULT,
                Authority::Relink,
            ),
            (
                "intra, a grant split the ends",
                ScopeCrossing::Intra,
                GRANTED,
                VAULT,
                Authority::Reseal,
            ),
            (
                "cross, two scopes",
                ScopeCrossing::Cross,
                VAULT,
                GRANTED,
                Authority::Reseal,
            ),
            (
                "exit, two scopes",
                ScopeCrossing::ExitsGrantedSource,
                GRANTED,
                VAULT,
                Authority::Reseal,
            ),
            (
                "cross onto one scope",
                ScopeCrossing::Cross,
                VAULT,
                VAULT,
                Authority::Unauthorable,
            ),
            (
                "exit onto one scope",
                ScopeCrossing::ExitsGrantedSource,
                GRANTED,
                GRANTED,
                Authority::Unauthorable,
            ),
        ] {
            assert_eq!(
                authoritative(journaled, source, destination),
                expected,
                "{label}"
            );
        }
    }

    #[test]
    fn a_move_owes_the_cut_of_the_granted_scope_it_left() {
        use ScopeCrossing::{Cross, ExitsGrantedSource as Exit, Intra};
        for (label, source, destination, journaled, published, owed) in [
            (
                "an exit",
                Some(GRANTED),
                Some(VAULT),
                Exit,
                false,
                Some(GRANTED),
            ),
            (
                "an exit journaled intra",
                Some(GRANTED),
                Some(VAULT),
                Intra,
                false,
                Some(GRANTED),
            ),
            (
                "inside one granted scope",
                Some(GRANTED),
                Some(GRANTED),
                Exit,
                true,
                None,
            ),
            (
                "out of the scope that grants nobody",
                Some(VAULT),
                Some(GRANTED),
                Cross,
                true,
                None,
            ),
            (
                "a source under no listed root",
                None,
                Some(VAULT),
                Exit,
                true,
                None,
            ),
            (
                "a lost destination, unpublished",
                Some(GRANTED),
                None,
                Exit,
                false,
                None,
            ),
            (
                "a lost destination, published intra",
                Some(GRANTED),
                None,
                Intra,
                true,
                None,
            ),
            (
                "a lost destination, published exit",
                Some(GRANTED),
                None,
                Exit,
                true,
                Some(GRANTED),
            ),
        ] {
            assert_eq!(
                owed_cut(source, destination, VAULT, journaled, published),
                owed,
                "{label}"
            );
        }
    }

    #[test]
    fn a_landed_move_resolves_both_ends_at_full_depth() {
        let base = tree();
        let relink = |from: NodeId, to: NodeId, crossing| {
            Op::relink(id(7), from, to, 1, crate::seams::UnixMillis(1), crossing)
        };
        for (label, op, published, owed) in [
            (
                "depth one",
                relink(GRANTED, id(6), ScopeCrossing::Intra),
                false,
                Some(GRANTED),
            ),
            (
                "depth three",
                relink(id(12), id(6), ScopeCrossing::Intra),
                false,
                Some(GRANTED),
            ),
            (
                "inside one scope",
                relink(id(12), id(10), ScopeCrossing::Intra),
                false,
                None,
            ),
            (
                "a second scope, destination gone",
                relink(id(9), GONE, ScopeCrossing::Intra),
                true,
                None,
            ),
            (
                "a journaled exit, destination gone",
                relink(id(12), GONE, ScopeCrossing::ExitsGrantedSource),
                true,
                Some(GRANTED),
            ),
            (
                "not a relocation",
                Op::rename(id(7), "r", 1, crate::seams::UnixMillis(1)),
                true,
                None,
            ),
            (
                "a move that renames",
                Op::move_node(
                    id(7),
                    id(12),
                    id(6),
                    "r",
                    None,
                    1,
                    crate::seams::UnixMillis(1),
                    ScopeCrossing::Intra,
                ),
                false,
                Some(GRANTED),
            ),
        ] {
            assert_eq!(landed_cut(&base, &op, LISTED, published), owed, "{label}");
        }
    }

    /// ADR 0020: the op queue reads what the previous release wrote. Each
    /// journaled crossing still decodes, and still reads as the plan it was.
    /// The bodies are pinned bytes, not a round trip of this build.
    #[test]
    fn a_relocation_the_previous_release_journaled_decodes_with_its_crossing() {
        use crate::seams::UnixMillis;
        for (body, crossing, renamed) in [
            (
                r#"{"target":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"base_sequence":4,"authored_at":5,"kind":{"Relink":{"from_parent":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"new_parent":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"crossing":"Intra"}}}"#,
                ScopeCrossing::Intra,
                false,
            ),
            (
                r#"{"target":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"base_sequence":4,"authored_at":5,"kind":{"Move":{"from_parent":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"new_parent":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"new_name":"a","replacing":null,"crossing":"Intra"}}}"#,
                ScopeCrossing::Intra,
                true,
            ),
            (
                r#"{"target":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"base_sequence":4,"authored_at":5,"kind":{"Relink":{"from_parent":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"new_parent":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"crossing":"Cross"}}}"#,
                ScopeCrossing::Cross,
                false,
            ),
            (
                r#"{"target":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"base_sequence":4,"authored_at":5,"kind":{"Move":{"from_parent":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"new_parent":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"new_name":"a","replacing":null,"crossing":"Cross"}}}"#,
                ScopeCrossing::Cross,
                true,
            ),
            (
                r#"{"target":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"base_sequence":4,"authored_at":5,"kind":{"Relink":{"from_parent":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"new_parent":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"crossing":"ExitsGrantedSource"}}}"#,
                ScopeCrossing::ExitsGrantedSource,
                false,
            ),
            (
                r#"{"target":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"base_sequence":4,"authored_at":5,"kind":{"Move":{"from_parent":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"new_parent":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"new_name":"a","replacing":null,"crossing":"ExitsGrantedSource"}}}"#,
                ScopeCrossing::ExitsGrantedSource,
                true,
            ),
        ] {
            let op = Op::decode_body(body.as_bytes()).expect("the previous release's body decodes");
            let expected = if renamed {
                Op::move_node(id(1), id(2), id(3), "a", None, 4, UnixMillis(5), crossing)
            } else {
                Op::relink(id(1), id(2), id(3), 4, UnixMillis(5), crossing)
            };
            assert_eq!(op, expected, "{body}");
            assert_eq!(op.relocation(), Some((id(2), id(3), crossing)));
            assert_eq!(
                op.encode_body(),
                body.as_bytes(),
                "and encodes to the same bytes"
            );
        }
    }
}
