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
//! [`retire ledger`](crate::net::StagingRetireLedger): durable, per-owner, and
//! never dead-lettered.

use crate::facade::NodeId;
use crate::seams::{OwedRetire, OwingRecord, SeamError, SeamResult};

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

/// [`OwingRecord::Published`] as an entry stores it.
const OWING_PUBLISHED: u8 = 0;

/// [`OwingRecord::Retired`] as an entry stores it.
const OWING_RETIRED: u8 = 1;

/// What a delete owes once its unlink is live: the names its detached subtree
/// publishes under, and the retire debt the target's own history carries.
///
/// Replayable as a whole — every step it drives is idempotent, so settling it
/// twice costs a repeated call and changes nothing.
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

/// This owner's journal keys among `staged`, in enumeration order — the replay
/// set a pass settles off its own listing.
#[must_use]
pub fn journalled_keys(owner_tag: &[u8; OWNER_TAG_LEN], staged: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let scope = {
        let mut scope = DOOMED_JOURNAL_PREFIX.to_vec();
        scope.extend_from_slice(owner_tag);
        scope
    };
    let mut keys: Vec<Vec<u8>> = staged
        .iter()
        .filter(|key| {
            key.strip_prefix(&scope[..])
                .is_some_and(|target| target.len() == NODE_ID_LEN)
        })
        .cloned()
        .collect();
    // Store enumeration order is host-dependent; sorted, a pass settles in the
    // same order on every host.
    keys.sort_unstable();
    keys
}

/// One entry as the staging store holds it.
///
/// Every string is length-prefixed as a `u16`, which is the invariant
/// [`decode_reclamation`] refuses on — so this refuses to write one it could
/// not read back, in release as in debug.
pub fn encode_reclamation(reclamation: &Reclamation) -> SeamResult<Vec<u8>> {
    let mut out = vec![FORMAT_V1];
    push_len(&mut out, reclamation.doomed.len())?;
    for (node, name) in &reclamation.doomed {
        out.extend_from_slice(&node.0);
        push_str(&mut out, name)?;
    }
    push_len(&mut out, reclamation.owed.len())?;
    for entry in &reclamation.owed {
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

/// One entry, or `None` for bytes this build did not write — which read as no
/// journal rather than as a reclamation of their own.
#[must_use]
pub fn decode_reclamation(bytes: &[u8]) -> Option<Reclamation> {
    let mut rest = bytes.strip_prefix(&[FORMAT_V1][..])?;
    let mut doomed = Vec::new();
    for _ in 0..take_len(&mut rest)? {
        let node = NodeId(take_array::<NODE_ID_LEN>(&mut rest)?);
        doomed.push((node, take_str(&mut rest)?));
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
        owed.push(OwedRetire {
            node,
            owing,
            target: take_str(&mut rest)?,
            owed_bytes,
            manifest_bytes,
        });
    }
    rest.is_empty().then_some(Reclamation { doomed, owed })
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
    use super::*;

    fn node(b: u8) -> NodeId {
        NodeId([b; NODE_ID_LEN])
    }

    fn sample() -> Reclamation {
        Reclamation {
            doomed: vec![
                (node(1), "k51-target".to_owned()),
                (node(2), "k51-child".to_owned()),
            ],
            owed: vec![OwedRetire::whole_retired(
                node(1).0,
                "bafyroot".to_owned(),
                4_096,
            )],
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
        let at = bad_class.len() - "bafyroot".len() - 3;
        bad_class[at] = 9;
        assert_eq!(decode_reclamation(&bad_class), None, "an unknown class");
    }

    #[test]
    fn a_name_over_the_length_prefix_refuses_to_encode() {
        let over = Reclamation {
            doomed: vec![(node(1), "x".repeat(usize::from(u16::MAX) + 1))],
            owed: Vec::new(),
        };
        assert!(
            encode_reclamation(&over).is_err(),
            "an entry the decoder could not read back is never written"
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
            vec![key, doomed_journal_key(&mine, node(9))],
            "only this owner's fixed-width entries, in a host-stable order"
        );
    }
}
