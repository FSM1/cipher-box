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
//! The seal wraps this codec rather than replacing it: [`FORMAT_V1`] versions
//! the journal's own grammar, independently of the ledger's.

use cipherbox_core::content::{decode_content_cid_str, is_wellformed_content_cid};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::OwnerLocalKind;

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
const FORMAT_V1: u8 = 1;

/// Journal entries one drain pass replays. Each costs a store read and a
/// registry batch, and a device that deleted a great deal offline holds one per
/// target — the ceiling keeps a backlog from spending a whole tick.
pub const MAX_JOURNAL_REPLAYS: usize = 32;

/// [`OwingRecord::Published`] as an entry stores it.
const OWING_PUBLISHED: u8 = 0;

/// [`OwingRecord::Retired`] as an entry stores it.
const OWING_RETIRED: u8 = 1;

/// What a delete owes once its unlink is live: the names its detached subtree
/// publishes under, and the retire debt the target's own history carries.
///
/// Replayed as a residue rather than as a whole: a leg that lands leaves the
/// entry, so no pass re-owes a debt the retire ledger already settled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reclamation {
    /// Each detached node and the name its record publishes under.
    pub doomed: Vec<(NodeId, String)>,
    /// The registry debt the delete's own target owes.
    pub owed: Vec<OwedRetire>,
}

impl Reclamation {
    /// Whether there is anything to settle.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.doomed.is_empty() && self.owed.is_empty()
    }

    /// The names to retire, in enumeration order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.doomed.iter().map(|(_, name)| name.clone()).collect()
    }

    /// Whether this is the entry its key names: the key's target is among the
    /// detached nodes, and no other node owes a content debt through it.
    ///
    /// The key scopes an entry; it does not authenticate one, and the owner tag
    /// it carries is the clear tag anyone reading the store already has. Without
    /// this an entry filed under one target could name a stranger's records, and
    /// the replay would retire them — a `Retired` debt is settled without
    /// re-reading the owing node, so nothing downstream would catch it.
    #[must_use]
    pub fn is_for(&self, target: NodeId) -> bool {
        self.doomed.iter().any(|(node, _)| *node == target)
            && self.owed.iter().all(|entry| entry.node == target.0)
    }
}

/// One delete's journal key: the prefix, the owner tag, then the delete's
/// target. Both suffixes are fixed-width, so no target can alias another
/// owner's entry.
#[must_use]
pub fn doomed_journal_key(owner_tag: &[u8; OWNER_TAG_LEN], target: NodeId) -> Vec<u8> {
    let mut key = DOOMED_JOURNAL_PREFIX.to_vec();
    key.extend_from_slice(owner_tag);
    key.extend_from_slice(&target.0);
    key
}

/// This owner's journal keys among `staged`, each with the delete target it
/// names — the replay set a pass settles off its own listing.
#[must_use]
pub fn journalled_keys(
    owner_tag: &[u8; OWNER_TAG_LEN],
    staged: &[Vec<u8>],
) -> Vec<(Vec<u8>, NodeId)> {
    let scope = {
        let mut scope = DOOMED_JOURNAL_PREFIX.to_vec();
        scope.extend_from_slice(owner_tag);
        scope
    };
    let mut keys: Vec<(Vec<u8>, NodeId)> = staged
        .iter()
        .filter_map(|key| {
            let target: [u8; NODE_ID_LEN] = key.strip_prefix(&scope[..])?.try_into().ok()?;
            Some((key.clone(), NodeId(target)))
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
    let mut out = Zeroizing::new(vec![FORMAT_V1]);
    push_len(&mut out, reclamation.doomed.len())?;
    for (node, name) in &reclamation.doomed {
        if IpnsName::parse(name).is_err() {
            return Err(SeamError::new("doomed journal name is not an ipnsName"));
        }
        out.extend_from_slice(&node.0);
        push_str(&mut out, name)?;
    }
    push_len(&mut out, reclamation.owed.len())?;
    for entry in &reclamation.owed {
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
        push_str(&mut out, &entry.target)?;
    }
    Ok(out)
}

/// One encoded reclamation, or `None` for bytes this build did not write.
#[must_use]
fn decode_reclamation(bytes: &[u8]) -> Option<Reclamation> {
    let mut rest = bytes.strip_prefix(&[FORMAT_V1][..])?;
    let mut doomed = Vec::new();
    for _ in 0..take_len(&mut rest)? {
        let node = NodeId(take_array::<NODE_ID_LEN>(&mut rest)?);
        let name = take_str(&mut rest)?;
        IpnsName::parse(&name).ok()?;
        doomed.push((node, name));
    }
    let mut owed = Vec::new();
    for _ in 0..take_len(&mut rest)? {
        let node = take_array::<NODE_ID_LEN>(&mut rest)?;
        let owed_bytes = u64::from_be_bytes(take_array::<8>(&mut rest)?);
        let manifest_bytes = u64::from_be_bytes(take_array::<8>(&mut rest)?);
        let owing = match take_array::<1>(&mut rest)?[0] {
            OWING_PUBLISHED => OwingRecord::Published,
            OWING_RETIRED => OwingRecord::Retired,
            _ => return None,
        };
        let target = take_str(&mut rest)?;
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
    rest.is_empty().then_some(Reclamation { doomed, owed })
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
        let mut bad_class = encoded;
        // The owing class is the byte before the last length-prefixed target.
        let at = bad_class.len() - cid(3).len() - 3;
        bad_class[at] = 9;
        assert_eq!(decode_reclamation(&bad_class), None, "an unknown class");
    }

    /// A name or a debt target the registry would refuse takes every other name
    /// in its entry down with it — the batch is refused whole, and the entry is
    /// never dead-lettered. Both sides refuse the shape instead.
    #[test]
    fn a_shape_the_registry_could_not_spend_is_refused_at_both_ends() {
        let long_name = Reclamation {
            doomed: vec![(node(1), "x".repeat(usize::from(u16::MAX) + 1))],
            owed: Vec::new(),
        };
        let bad_name = Reclamation {
            doomed: vec![(node(1), "not-an-ipns-name".to_owned())],
            owed: Vec::new(),
        };
        let bad_target = Reclamation {
            doomed: vec![(node(1), name(1))],
            owed: vec![OwedRetire::whole_retired(node(1).0, "not-a-cid".into(), 1)],
        };
        for (case, reclamation) in [
            ("a name over the length prefix", long_name),
            ("a name that is not an ipnsName", bad_name),
            ("a debt that is not a content CID", bad_target),
        ] {
            assert!(
                encode_reclamation(&reclamation).is_err(),
                "{case} is never written"
            );
        }

        // And the same shapes planted directly in the store read as no journal.
        let mut planted = encode_reclamation(&sample()).expect("encode");
        let at = planted.len() - cid(3).len();
        planted[at..].fill(b'!');
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
        assert!(
            !sample().is_for(node(9)),
            "a target the entry does not name at all"
        );
        let strangers_debt = Reclamation {
            doomed: vec![(node(1), name(1))],
            owed: vec![OwedRetire::whole_retired(node(9).0, cid(3), 1)],
        };
        assert!(
            !strangers_debt.is_for(node(1)),
            "no other node owes a content debt through this entry"
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
    fn keys_are_owner_scoped_and_target_addressed() {
        let mine = [1u8; OWNER_TAG_LEN];
        let theirs = [2u8; OWNER_TAG_LEN];
        let key = doomed_journal_key(&mine, node(7));
        assert!(key.starts_with(DOOMED_JOURNAL_PREFIX));
        assert_ne!(key, doomed_journal_key(&theirs, node(7)));
        assert_ne!(key, doomed_journal_key(&mine, node(8)));

        let staged = vec![
            doomed_journal_key(&theirs, node(7)),
            doomed_journal_key(&mine, node(9)),
            key.clone(),
            b"cbx/dj/short".to_vec(),
            b"unrelated".to_vec(),
        ];
        assert_eq!(
            journalled_keys(&mine, &staged),
            vec![
                (key, node(7)),
                (doomed_journal_key(&mine, node(9)), node(9)),
            ],
            "only this owner's fixed-width entries, in a host-stable order"
        );
    }
}
