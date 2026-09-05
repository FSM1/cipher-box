//! The doomed-name journal: what a delete still owes once its unlink is live
//! (blueprint/engine.md "Retirement").
//!
//! A delete publishes the shortened parent, then reclaims what that unlink
//! detached. The window between the two is not recoverable from local state: the
//! parent no longer names the target, so a retry finds nothing to remove and the
//! subtree's names and pins are owed by nobody. The journal closes it — written
//! at unlink-ack, replayed by any later pass, removed once the reclamation
//! lands.
//!
//! It rides the staging store's opaque key space on the same terms as the
//! [`retire ledger`](crate::net::StagingRetireLedger): durable, per-owner,
//! never dead-lettered, and sealed at rest under the tier rule
//! ([`crate::sync::bookkeeping`]). The key still says *that* this node has a
//! delete pending; what the seal withholds is the write-plane names the
//! detached subtree published under, which outlive the delete recording them.
//! The seal wraps this codec rather than replacing it: [`FORMAT_V3`] versions
//! the journal's own grammar, independently of the ledger's.

use cipherbox_core::content::{decode_content_cid_str, is_wellformed_content_cid};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::OwnerLocalKind;
use std::collections::BTreeSet;

use crate::facade::NodeId;
use zeroize::Zeroizing;

use crate::seams::{OwedRetire, OwingRecord, SeamError, SeamResult};
use crate::sync::BookkeepingSeal;

/// The staging-key prefix the doomed-name journal writes under. One key per
/// delete target, so two deletes in flight cannot lose each other's entry.
///
/// [`orphan_staging_keys`](crate::sync::orphan_staging_keys) treats the whole
/// prefix as referenced. Kept short: the desktop store spells a key as a hex
/// filename, at twice its byte length.
pub const DOOMED_JOURNAL_PREFIX: &[u8] = b"cbx/dj/";

/// The owner tag every per-identity durable record is scoped by
/// ([`owner_tag`](crate::sync::drain::owner_tag)).
const OWNER_TAG_LEN: usize = 32;

/// The engine's location-independent node id.
const NODE_ID_LEN: usize = 16;

/// The entry format tag. The staging store is shared with whatever build wrote
/// it, so bytes that merely happen to parse must not read as a reclamation.
const FORMAT_V3: u8 = 3;

/// Journal entries one drain pass replays. Each costs a store read and a
/// registry batch, and a device that deleted a great deal offline holds one per
/// target — the ceiling keeps a backlog from spending a whole tick.
pub const MAX_JOURNAL_REPLAYS: usize = 32;

/// Quarantine proofs one drain pass spends, across every entry it replays. Each
/// costs a fresh resolve of one descendant's record, so a delete of a large
/// subtree settles over several passes rather than holding one open.
pub const MAX_QUARANTINE_PROOFS: usize = 32;

/// Passes that may decide against one quarantined descendant before it is
/// dropped unspent. This is what bounds the quarantine.
///
/// A descendant no pass can establish is reachable: an unlinked node joins no
/// eager set, so a scope rotation leaves its record sealed at an epoch the gate
/// refuses, for good. Without the ceiling that one entry holds its journal
/// entry open and spends a proof slot on every pass thereafter, which starves
/// the entries sorting behind it. Dropped, it keeps its name registered and its
/// content pinned — the lawful side, and what the delete path did before the
/// proof existed.
pub const MAX_QUARANTINE_ATTEMPTS: u8 = 8;

/// [`OwingRecord::Published`] as an entry stores it.
const OWING_PUBLISHED: u8 = 0;

/// [`OwingRecord::Retired`] as an entry stores it.
const OWING_RETIRED: u8 = 1;

/// One descendant the delete detached, held until a later pass proves it.
///
/// The delete's own target is never one of these. The shortened parent is a
/// record the delete pass itself resolved and republished, so the target's
/// detachment is a published fact; a descendant's is a claim the walk makes off
/// wire child refs, which any holder of the scope's write seed authors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantined {
    /// The detached node.
    pub node: NodeId,
    /// The name its record publishes under.
    pub name: String,
    /// The debt its history owes, as the owner's own manifest quoted it at
    /// delete time — also the roots the proof re-checks the record against.
    pub owed: Vec<OwedRetire>,
    /// Passes that have decided against it, capped by
    /// [`MAX_QUARANTINE_ATTEMPTS`]. A pass the proof budget never reached
    /// counts none: it did no work.
    pub attempts: u8,
}

impl Quarantined {
    /// The version roots the manifest quoted — the proof's left operand.
    #[must_use]
    pub fn manifest_roots(&self) -> BTreeSet<String> {
        self.owed.iter().map(|entry| entry.target.clone()).collect()
    }
}

/// What a delete owes once its unlink is live: the names its detached subtree
/// publishes under, and the retire debt its history carries.
///
/// The owner's own device authors this at delete time and seals it under the
/// owner's key, which is what makes it a manifest rather than a re-derivation:
/// no writer can redirect a debt into it after the fact.
///
/// Replayed as a residue rather than as a whole: a leg that lands leaves the
/// entry, so no pass re-owes a debt the retire ledger already settled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reclamation {
    /// The delete's own target **first**, then every descendant a later pass
    /// proved, each with the name its record publishes under. These names
    /// retire now.
    pub doomed: Vec<(NodeId, String)>,
    /// The registry debt those nodes owe.
    pub owed: Vec<OwedRetire>,
    /// The descendants still in quarantine: their names stay registered and
    /// their content stays pinned until the proof holds for them.
    pub quarantined: Vec<Quarantined>,
    /// The `deletedAt` of the bin entry a purge reclaimed, for an entry a purge
    /// wrote. The whole doomed subtree is sealed under the bin-held key, and
    /// that key's second input is this value, so a later pass cannot resolve a
    /// quarantined descendant without it. No key material: the account half of
    /// the edge is derived from the login secret, and the target the entry's own
    /// key names is the first input.
    pub binned_at: Option<u64>,
}

impl Reclamation {
    /// Whether there is anything to settle.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.doomed.is_empty() && self.owed.is_empty() && self.quarantined.is_empty()
    }

    /// The names to retire, in enumeration order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.doomed.iter().map(|(_, name)| name.clone()).collect()
    }

    /// Whether this is the entry its key names: the key's target heads the
    /// doomed nodes, every debt is owed by a node whose name this entry retires,
    /// and the target is never one of the quarantined descendants.
    ///
    /// Binding the debt to `doomed` rather than to the whole detached set is
    /// what keeps a descendant's debt inside the proof path: the spent list is
    /// paid without a proof, so a debt may only reach it once the proof has
    /// moved its node there.
    ///
    /// The key scopes an entry; it does not authenticate one, and the owner tag
    /// it carries is the clear tag anyone reading the store already has. Without
    /// this an entry filed under one target could name a stranger's records, and
    /// the replay would retire them — a `Retired` debt is settled without
    /// re-reading the owing node, so nothing downstream would catch it.
    #[must_use]
    pub fn is_for(&self, target: NodeId) -> bool {
        let detached: BTreeSet<[u8; 16]> = self.doomed.iter().map(|(node, _)| node.0).collect();
        self.doomed.first().is_some_and(|(node, _)| *node == target)
            && self.owed.iter().all(|entry| detached.contains(&entry.node))
            && self.quarantined.iter().all(|held| {
                held.node != target && held.owed.iter().all(|entry| entry.node == held.node.0)
            })
    }
}

/// The settle-time half of a quarantined descendant's proof
/// (blueprint/engine.md "Retirement").
///
/// Exact rather than a subset test: a record that gained or lost a version
/// since the owner's manifest is one a writer has moved on from. `None` is a
/// record this pass could not establish, which refuses.
#[must_use]
pub fn record_matches_manifest(
    manifest: &BTreeSet<String>,
    resolved: Option<&BTreeSet<String>>,
) -> bool {
    resolved == Some(manifest)
}

/// One delete's journal key: the prefix, the owner tag, the scope root the
/// delete resolved onto, then the delete's target. Every suffix is fixed-width,
/// so no target can alias another owner's entry.
///
/// The scope root is part of the key because only that scope's material can
/// settle the entry: the names it holds derive from that scope's write seed and
/// the records behind them open under its read seed. A pass replays the entries
/// of the scopes it proved and leaves the rest untouched
/// (`sync/drain.rs::settle`).
#[must_use]
pub fn doomed_journal_key(
    owner_tag: &[u8; OWNER_TAG_LEN],
    scope_root: NodeId,
    target: NodeId,
) -> Vec<u8> {
    let mut key = DOOMED_JOURNAL_PREFIX.to_vec();
    key.extend_from_slice(owner_tag);
    key.extend_from_slice(&scope_root.0);
    key.extend_from_slice(&target.0);
    key
}

/// This owner's journal keys among `staged`, each with the scope root it was
/// written under and the delete target it names — the replay set a pass settles
/// off its own listing.
#[must_use]
pub fn journalled_keys(
    owner_tag: &[u8; OWNER_TAG_LEN],
    staged: &[Vec<u8>],
) -> Vec<(Vec<u8>, NodeId, NodeId)> {
    let owned = {
        let mut owned = DOOMED_JOURNAL_PREFIX.to_vec();
        owned.extend_from_slice(owner_tag);
        owned
    };
    let mut keys: Vec<(Vec<u8>, NodeId, NodeId)> = staged
        .iter()
        .filter_map(|key| {
            let suffix: [u8; NODE_ID_LEN * 2] = key.strip_prefix(&owned[..])?.try_into().ok()?;
            let (scope_root, target) = suffix.split_at(NODE_ID_LEN);
            Some((
                key.clone(),
                NodeId(scope_root.try_into().ok()?),
                NodeId(target.try_into().ok()?),
            ))
        })
        .collect();
    // Store enumeration order is host-dependent; sorted, a pass settles in the
    // same order on every host.
    keys.sort_unstable();
    keys
}

/// One entry as the staging store holds it: the encoded reclamation, sealed.
pub fn seal_reclamation(
    seal: BookkeepingSeal<'_>,
    reclamation: &Reclamation,
) -> SeamResult<Vec<u8>> {
    seal.seal(
        OwnerLocalKind::DoomedJournal,
        &encode_reclamation(reclamation)?,
    )
}

/// One stored entry, or `None` for bytes this identity's key and this build's
/// grammar do not both accept — which read as no journal rather than as a
/// reclamation of their own.
pub fn open_reclamation(seal: BookkeepingSeal<'_>, blob: &[u8]) -> Option<Reclamation> {
    decode_reclamation(&seal.open(OwnerLocalKind::DoomedJournal, blob)?)
}

/// The journal's own encoding, inside the seal.
///
/// Refuses, with a release-active `Err`, every shape [`decode_reclamation`]
/// refuses: an over-long length prefix, a doomed name that is not an
/// `ipnsName`, and a debt target that is not a content CID. A journal entry
/// only ever leaves once its reclamation lands, so one this build could write
/// but neither read back nor spend would sit undrainable forever.
///
/// Zeroizing because the plaintext side of a sealed value is exactly what the
/// tier exists to keep off the host ([`crate::sync::bookkeeping`]).
fn encode_reclamation(reclamation: &Reclamation) -> SeamResult<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(vec![FORMAT_V3]);
    push_len(&mut out, reclamation.doomed.len())?;
    for (node, name) in &reclamation.doomed {
        push_doomed(&mut out, *node, name)?;
    }
    push_owed(&mut out, &reclamation.owed)?;
    push_len(&mut out, reclamation.quarantined.len())?;
    for held in &reclamation.quarantined {
        push_doomed(&mut out, held.node, &held.name)?;
        push_owed(&mut out, &held.owed)?;
        if held.attempts >= MAX_QUARANTINE_ATTEMPTS {
            return Err(SeamError::new("quarantine entry is past its attempts"));
        }
        out.push(held.attempts);
    }
    match reclamation.binned_at {
        Some(deleted_at) => {
            out.push(1);
            out.extend_from_slice(&deleted_at.to_be_bytes());
        }
        None => out.push(0),
    }
    Ok(out)
}

/// One detached node and the name its record publishes under.
fn push_doomed(out: &mut Vec<u8>, node: NodeId, name: &str) -> SeamResult<()> {
    if IpnsName::parse(name).is_err() {
        return Err(SeamError::new("doomed journal name is not an ipnsName"));
    }
    out.extend_from_slice(&node.0);
    push_str(out, name)
}

/// One node's length-prefixed debt list.
fn push_owed(out: &mut Vec<u8>, owed: &[OwedRetire]) -> SeamResult<()> {
    push_len(out, owed.len())?;
    for entry in owed {
        if !is_cid(&entry.target) {
            return Err(SeamError::new("doomed journal debt is not a content CID"));
        }
        out.extend_from_slice(&entry.node);
        out.extend_from_slice(&entry.owed_bytes.to_be_bytes());
        out.extend_from_slice(&entry.manifest_bytes.to_be_bytes());
        out.push(match entry.owing {
            OwingRecord::Published => OWING_PUBLISHED,
            OwingRecord::Retired => OWING_RETIRED,
        });
        push_str(out, &entry.target)?;
    }
    Ok(())
}

/// One encoded reclamation, or `None` for bytes this build did not write.
#[must_use]
fn decode_reclamation(bytes: &[u8]) -> Option<Reclamation> {
    let mut rest = bytes.strip_prefix(&[FORMAT_V3][..])?;
    let mut doomed = Vec::new();
    for _ in 0..take_len(&mut rest)? {
        doomed.push(take_doomed(&mut rest)?);
    }
    let owed = take_owed(&mut rest)?;
    let mut quarantined = Vec::new();
    for _ in 0..take_len(&mut rest)? {
        let (node, name) = take_doomed(&mut rest)?;
        let owed = take_owed(&mut rest)?;
        let attempts = take_array::<1>(&mut rest)?[0];
        if attempts >= MAX_QUARANTINE_ATTEMPTS {
            return None;
        }
        quarantined.push(Quarantined {
            node,
            name,
            owed,
            attempts,
        });
    }
    let binned_at = match take_array::<1>(&mut rest)?[0] {
        0 => None,
        1 => Some(u64::from_be_bytes(take_array::<8>(&mut rest)?)),
        _ => return None,
    };
    rest.is_empty().then_some(Reclamation {
        doomed,
        owed,
        quarantined,
        binned_at,
    })
}

fn take_doomed(rest: &mut &[u8]) -> Option<(NodeId, String)> {
    let node = NodeId(take_array::<NODE_ID_LEN>(rest)?);
    let name = take_str(rest)?;
    IpnsName::parse(&name).ok()?;
    Some((node, name))
}

fn take_owed(rest: &mut &[u8]) -> Option<Vec<OwedRetire>> {
    let mut owed = Vec::new();
    for _ in 0..take_len(rest)? {
        let node = take_array::<NODE_ID_LEN>(rest)?;
        let owed_bytes = u64::from_be_bytes(take_array::<8>(rest)?);
        let manifest_bytes = u64::from_be_bytes(take_array::<8>(rest)?);
        let owing = match take_array::<1>(rest)?[0] {
            OWING_PUBLISHED => OwingRecord::Published,
            OWING_RETIRED => OwingRecord::Retired,
            _ => return None,
        };
        let target = take_str(rest)?;
        if !is_cid(&target) {
            return None;
        }
        owed.push(OwedRetire {
            node,
            owing,
            target,
            owed_bytes,
            manifest_bytes,
        });
    }
    Some(owed)
}

/// Whether `target` is a content CID the retire ledger could key an entry by —
/// the one shape [`StagingRetireLedger::key`] accepts, and a hard error there.
///
/// [`StagingRetireLedger::key`]: crate::net::StagingRetireLedger::key
fn is_cid(target: &str) -> bool {
    decode_content_cid_str(target).is_ok_and(|cid| is_wellformed_content_cid(&cid))
}

fn push_len(out: &mut Vec<u8>, len: usize) -> SeamResult<()> {
    let len = u16::try_from(len)
        .map_err(|_| SeamError::new("doomed journal holds over 65535 entries"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn push_str(out: &mut Vec<u8>, value: &str) -> SeamResult<()> {
    push_len(out, value.len())?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn take_array<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_at_checked(N)?;
    *rest = tail;
    head.try_into().ok()
}

fn take_len(rest: &mut &[u8]) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes(take_array::<2>(rest)?)))
}

fn take_str(rest: &mut &[u8]) -> Option<String> {
    let len = take_len(rest)?;
    let (head, tail) = rest.split_at_checked(len)?;
    *rest = tail;
    String::from_utf8(head.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use cipherbox_core::content::{compute_cid, encode_content_cid_str};
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::x25519::X25519Secret;

    use super::*;
    use crate::testkit::SeededEntropy;

    /// The content-CID codec the retire ledger keys its entries by.
    const CONTENT_CID_CODEC: u8 = 0x55;

    fn node(b: u8) -> NodeId {
        NodeId([b; NODE_ID_LEN])
    }

    /// A real derived write-plane name — the only shape the journal accepts.
    fn name(seed: u8) -> String {
        IpnsName::from_public_key(&Ed25519Signer::from_seed([seed; 32]).verifying_key())
            .as_str()
            .to_owned()
    }

    fn cid(seed: u8) -> String {
        encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, &[seed; 8]))
    }

    fn sample() -> Reclamation {
        Reclamation {
            doomed: vec![(node(1), name(1)), (node(2), name(2))],
            owed: vec![OwedRetire::whole_retired(node(1).0, cid(3), 4_096)],
            quarantined: vec![Quarantined {
                node: node(4),
                name: name(4),
                owed: vec![OwedRetire::whole_retired(node(4).0, cid(5), 512)],
                attempts: 3,
            }],
            binned_at: Some(1_700_000_000_000),
        }
    }

    #[test]
    fn an_entry_round_trips() {
        let encoded = encode_reclamation(&sample()).expect("encode");
        assert_eq!(decode_reclamation(&encoded), Some(sample()));
    }

    #[test]
    fn an_empty_reclamation_round_trips() {
        let encoded = encode_reclamation(&Reclamation::default()).expect("encode");
        assert_eq!(decode_reclamation(&encoded), Some(Reclamation::default()));
        assert!(Reclamation::default().is_empty());
    }

    #[test]
    fn bytes_this_build_did_not_write_read_as_no_journal() {
        let encoded = encode_reclamation(&sample()).expect("encode");
        assert_eq!(decode_reclamation(&[]), None, "empty");
        assert_eq!(decode_reclamation(&[7, 0, 0]), None, "a foreign format tag");
        assert_eq!(
            decode_reclamation(&encoded[..encoded.len() - 1]),
            None,
            "a truncated entry"
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_reclamation(&trailing), None, "trailing bytes");
        let mut foreign_flag = encoded;
        // The stamp is a presence byte and, when present, the eight bytes of the
        // value behind it.
        let at = foreign_flag.len() - 9;
        foreign_flag[at] = 2;
        assert_eq!(
            decode_reclamation(&foreign_flag),
            None,
            "a bin stamp that is neither present nor absent"
        );
        // Planted on the unbinned form, whose absent bin stamp is one byte, so
        // the offsets below count back from the quarantine rather than over it.
        let unbinned = Reclamation {
            binned_at: None,
            ..sample()
        };
        let mut spent = encode_reclamation(&unbinned).expect("encode");
        let at = spent.len() - 2;
        spent[at] = MAX_QUARANTINE_ATTEMPTS;
        assert_eq!(
            decode_reclamation(&spent),
            None,
            "a quarantine planted past its attempts"
        );
        let mut bad_class = encode_reclamation(&unbinned).expect("encode");
        // The owing class is the byte before the last length-prefixed target,
        // which the quarantined descendant's own debt carries; the attempt
        // count is the one byte after it.
        let at = bad_class.len() - cid(5).len() - 5;
        bad_class[at] = 9;
        assert_eq!(decode_reclamation(&bad_class), None, "an unknown class");
    }

    /// The bin stamp is what a later pass derives the bin-held key from, so an
    /// entry a purge wrote must carry it back over the seal unchanged.
    #[test]
    fn a_purge_entry_round_trips_the_stamp_its_held_key_derives_from() {
        for binned_at in [None, Some(0), Some(u64::MAX)] {
            let reclamation = Reclamation {
                binned_at,
                ..sample()
            };
            let encoded = encode_reclamation(&reclamation).expect("encode");
            assert_eq!(
                decode_reclamation(&encoded).and_then(|decoded| decoded.binned_at),
                binned_at,
            );
        }
    }

    /// A name or a debt target the registry would refuse takes every other name
    /// in its entry down with it — the batch is refused whole, and the entry is
    /// never dead-lettered. Both sides refuse the shape instead.
    #[test]
    fn a_shape_the_registry_could_not_spend_is_refused_at_both_ends() {
        let long_name = Reclamation {
            doomed: vec![(node(1), "x".repeat(usize::from(u16::MAX) + 1))],
            ..Reclamation::default()
        };
        let bad_name = Reclamation {
            doomed: vec![(node(1), "not-an-ipns-name".to_owned())],
            ..Reclamation::default()
        };
        let bad_target = Reclamation {
            doomed: vec![(node(1), name(1))],
            owed: vec![OwedRetire::whole_retired(node(1).0, "not-a-cid".into(), 1)],
            ..Reclamation::default()
        };
        let bad_quarantined_name = Reclamation {
            quarantined: vec![Quarantined {
                node: node(4),
                name: "not-an-ipns-name".to_owned(),
                owed: Vec::new(),
                attempts: 0,
            }],
            ..Reclamation::default()
        };
        let bad_quarantined_target = Reclamation {
            quarantined: vec![Quarantined {
                node: node(4),
                name: name(4),
                owed: vec![OwedRetire::whole_retired(node(4).0, "not-a-cid".into(), 1)],
                attempts: 0,
            }],
            ..Reclamation::default()
        };
        for (case, reclamation) in [
            ("a name over the length prefix", long_name),
            ("a name that is not an ipnsName", bad_name),
            ("a debt that is not a content CID", bad_target),
            (
                "a quarantined name that is not an ipnsName",
                bad_quarantined_name,
            ),
            (
                "a quarantined debt that is not a content CID",
                bad_quarantined_target,
            ),
        ] {
            assert!(
                encode_reclamation(&reclamation).is_err(),
                "{case} is never written"
            );
        }

        let spent = Reclamation {
            quarantined: vec![Quarantined {
                node: node(4),
                name: name(4),
                owed: Vec::new(),
                attempts: MAX_QUARANTINE_ATTEMPTS,
            }],
            ..Reclamation::default()
        };
        assert!(
            encode_reclamation(&spent).is_err(),
            "a quarantine past its attempts is dropped, never written"
        );

        // And the same shapes planted directly in the store read as no journal.
        // The CID bytes alone: the attempt count is the byte after them, and one
        // planted field per case keeps the refusal pinned to the check it names.
        let mut planted = encode_reclamation(&sample()).expect("encode");
        let end = planted.len() - 1;
        planted[end - cid(5).len()..end].fill(b'!');
        assert_eq!(decode_reclamation(&planted), None, "a planted debt target");
    }

    /// The key scopes an entry but authenticates nothing, so the replay refuses
    /// one that answers to another target.
    #[test]
    fn an_entry_must_answer_to_the_target_its_key_names() {
        assert!(sample().is_for(node(1)));
        assert!(
            !sample().is_for(node(2)),
            "a node the entry merely detaches is not its target"
        );
        assert!(!sample().is_for(node(4)), "nor is one it quarantines");
        assert!(
            !sample().is_for(node(9)),
            "a target the entry does not name at all"
        );
        let strangers_debt = Reclamation {
            doomed: vec![(node(1), name(1))],
            owed: vec![OwedRetire::whole_retired(node(9).0, cid(3), 1)],
            ..Reclamation::default()
        };
        assert!(
            !strangers_debt.is_for(node(1)),
            "a node this entry never detached owes nothing through it"
        );
        let redirected_quarantine = Reclamation {
            doomed: vec![(node(1), name(1))],
            quarantined: vec![Quarantined {
                node: node(4),
                name: name(4),
                owed: vec![OwedRetire::whole_retired(node(9).0, cid(3), 1)],
                attempts: 0,
            }],
            ..Reclamation::default()
        };
        assert!(
            !redirected_quarantine.is_for(node(1)),
            "a quarantined descendant owes only its own history"
        );
        let quarantined_target = Reclamation {
            doomed: vec![(node(1), name(1))],
            quarantined: vec![Quarantined {
                node: node(1),
                name: name(1),
                owed: Vec::new(),
                attempts: 0,
            }],
            ..Reclamation::default()
        };
        assert!(
            !quarantined_target.is_for(node(1)),
            "the delete's own target is never a quarantined descendant"
        );
        let unproven_debt = Reclamation {
            doomed: vec![(node(1), name(1))],
            owed: vec![OwedRetire::whole_retired(node(4).0, cid(3), 1)],
            quarantined: vec![Quarantined {
                node: node(4),
                name: name(4),
                owed: Vec::new(),
                attempts: 0,
            }],
            binned_at: None,
        };
        assert!(
            !unproven_debt.is_for(node(1)),
            "a quarantined node's debt never reaches the list this pass spends"
        );
    }

    /// The re-check gates an irreversible unpin, so anything but an exact match
    /// refuses.
    #[test]
    fn the_record_re_check_holds_only_on_an_exact_match() {
        let manifest: BTreeSet<String> = [cid(3), cid(5)].into_iter().collect();
        let moved_on: BTreeSet<String> = [cid(3), cid(5), cid(6)].into_iter().collect();
        let shortened: BTreeSet<String> = [cid(3)].into_iter().collect();

        assert!(record_matches_manifest(&manifest, Some(&manifest)));
        assert!(
            !record_matches_manifest(&manifest, None),
            "a record this pass could not establish refuses"
        );
        assert!(
            !record_matches_manifest(&manifest, Some(&moved_on)),
            "a version published since the manifest is a writer still using it"
        );
        assert!(
            !record_matches_manifest(&manifest, Some(&shortened)),
            "and so is a history that shortened under it"
        );

        let nothing = BTreeSet::new();
        assert!(
            record_matches_manifest(&nothing, Some(&nothing)),
            "a folder quotes no root and spends nothing"
        );
    }

    /// The journal joins the sealed tier ([`crate::sync::bookkeeping`]): an
    /// entry's `ipnsName`s are a delete-intent signal that outlives the delete
    /// recording them, so what the store holds is a blob only this identity
    /// opens — never the encoding itself.
    #[test]
    fn an_entry_is_sealed_at_rest() {
        let mine = X25519Secret::from_scalar([0x9d; 32]);
        let theirs = X25519Secret::from_scalar([0x9e; 32]);
        let entropy = RefCell::new(SeededEntropy::new(11));
        let seal = BookkeepingSeal::new(&mine, &entropy);

        let stored = seal_reclamation(seal, &sample()).expect("seal");
        assert_ne!(
            stored,
            *encode_reclamation(&sample()).expect("encode"),
            "the journal grammar never reaches the store on its own"
        );
        assert_eq!(open_reclamation(seal, &stored), Some(sample()));
        assert_eq!(
            open_reclamation(BookkeepingSeal::new(&theirs, &entropy), &stored),
            None,
            "another identity's key opens nothing"
        );

        // The only shape a build that skipped the seal could have written.
        assert_eq!(
            open_reclamation(seal, &encode_reclamation(&sample()).expect("encode")),
            None,
            "an unsealed entry is no journal"
        );
    }

    #[test]
    fn keys_are_owner_scoped_scope_scoped_and_target_addressed() {
        let mine = [1u8; OWNER_TAG_LEN];
        let theirs = [2u8; OWNER_TAG_LEN];
        let vault = node(1);
        let promoted = node(2);
        let key = doomed_journal_key(&mine, vault, node(7));
        assert!(key.starts_with(DOOMED_JOURNAL_PREFIX));
        assert_ne!(key, doomed_journal_key(&theirs, vault, node(7)));
        assert_ne!(key, doomed_journal_key(&mine, vault, node(8)));
        assert_ne!(
            key,
            doomed_journal_key(&mine, promoted, node(7)),
            "one target deleted in two scopes holds two entries"
        );

        let staged = vec![
            doomed_journal_key(&theirs, vault, node(7)),
            doomed_journal_key(&mine, promoted, node(9)),
            key.clone(),
            b"cbx/dj/short".to_vec(),
            b"unrelated".to_vec(),
        ];
        assert_eq!(
            journalled_keys(&mine, &staged),
            vec![
                (key, vault, node(7)),
                (
                    doomed_journal_key(&mine, promoted, node(9)),
                    promoted,
                    node(9)
                ),
            ],
            "only this owner's fixed-width entries, each with the scope that wrote it"
        );
    }
}
