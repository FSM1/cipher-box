//! The owner-local journal of a subtree re-seal (ADR 0077 D3), sealed under
//! [`OwnerLocalKind::SubtreeReseal`].
//!
//! Each value is a common envelope: a format byte, a caller byte, the source
//! root id, and a payload that the caller owns. This module reads and checks
//! the envelope only, and keeps every entry as it finds it.

use std::collections::BTreeSet;

use cipherbox_core::seal::OwnerLocalKind;
use zeroize::Zeroizing;

use crate::facade::NodeId;
use crate::seams::{SeamError, SeamResult, StagingStore};
use crate::sync::BookkeepingSeal;

/// The staging-key prefix of the journal:
/// `prefix | ownerTag(32) | sourceRoot(16) | part`. The part is the caller's.
pub const RESEAL_JOURNAL_PREFIX: &[u8] = b"cbx/sr/";

/// The envelope format this build reads and writes.
pub const RESEAL_ENVELOPE_V1: u8 = 1;

/// The most payload bytes one value carries.
pub const MAX_RESEAL_PAYLOAD: usize = 128 * 1024;

/// The bytes before the payload: format, caller, source root.
const ENVELOPE_HEAD_LEN: usize = 2 + 16;

/// One journal value: the caller that owns its payload, and the source root
/// of the re-seal.
#[derive(Clone, PartialEq, Eq)]
pub struct ResealEnvelope {
    /// The caller that owns the payload. Zero names no caller.
    pub caller: u8,
    /// The root of the source subtree.
    pub source_root: NodeId,
    /// The caller's own bytes, opened from a sealed value.
    pub payload: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for ResealEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResealEnvelope")
            .field("caller", &self.caller)
            .field("source_root", &self.source_root)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Why an envelope does not encode or decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResealEnvelopeError {
    /// A format byte that this build does not read.
    UnknownFormat(u8),
    /// Fewer bytes than the envelope head.
    Truncated,
    /// The caller byte is zero.
    NoCaller,
    /// The envelope names a source root other than its key.
    RootMismatch,
    /// The payload is over [`MAX_RESEAL_PAYLOAD`].
    PayloadTooLarge,
}

impl ResealEnvelopeError {
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            Self::UnknownFormat(_) => "reseal-envelope-unknown-format",
            Self::Truncated => "reseal-envelope-truncated",
            Self::NoCaller => "reseal-envelope-no-caller",
            Self::RootMismatch => "reseal-envelope-root-mismatch",
            Self::PayloadTooLarge => "reseal-envelope-payload-too-large",
        }
    }
}

/// The check that encode and decode share (AGENTS.md rule 8).
fn check_reseal_envelope(
    caller: u8,
    source_root: NodeId,
    payload: &[u8],
    key_root: NodeId,
) -> Result<(), ResealEnvelopeError> {
    if caller == 0 {
        return Err(ResealEnvelopeError::NoCaller);
    }
    if source_root != key_root {
        return Err(ResealEnvelopeError::RootMismatch);
    }
    if payload.len() > MAX_RESEAL_PAYLOAD {
        return Err(ResealEnvelopeError::PayloadTooLarge);
    }
    Ok(())
}

/// `RESEAL_ENVELOPE_V1 | caller | sourceRoot(16) | payload`, for the value at
/// the key of `key_root`.
pub fn encode_reseal_envelope(
    envelope: &ResealEnvelope,
    key_root: NodeId,
) -> Result<Zeroizing<Vec<u8>>, ResealEnvelopeError> {
    check_reseal_envelope(
        envelope.caller,
        envelope.source_root,
        &envelope.payload,
        key_root,
    )?;
    let mut body = Zeroizing::new(Vec::with_capacity(
        ENVELOPE_HEAD_LEN + envelope.payload.len(),
    ));
    body.push(RESEAL_ENVELOPE_V1);
    body.push(envelope.caller);
    body.extend_from_slice(&envelope.source_root.0);
    body.extend_from_slice(&envelope.payload);
    Ok(body)
}

/// The envelope of the value at the key of `key_root`. A caller that this
/// build has no grammar for still decodes: its payload stays opaque.
pub fn decode_reseal_envelope(
    body: &[u8],
    key_root: NodeId,
) -> Result<ResealEnvelope, ResealEnvelopeError> {
    let (&format, rest) = body.split_first().ok_or(ResealEnvelopeError::Truncated)?;
    if format != RESEAL_ENVELOPE_V1 {
        return Err(ResealEnvelopeError::UnknownFormat(format));
    }
    let (&caller, rest) = rest.split_first().ok_or(ResealEnvelopeError::Truncated)?;
    let (root, payload) = rest
        .split_first_chunk::<16>()
        .ok_or(ResealEnvelopeError::Truncated)?;
    check_reseal_envelope(caller, NodeId(*root), payload, key_root)?;
    Ok(ResealEnvelope {
        caller,
        source_root: NodeId(*root),
        payload: Zeroizing::new(payload.to_vec()),
    })
}

/// What one journal key holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalSlot {
    /// No value.
    Absent,
    /// A value whose envelope reads.
    Kept(ResealEnvelope),
    /// A value that does not open, or whose envelope does not read. It blocks
    /// its source root, and no write replaces it.
    Unreadable,
}

/// The source roots this owner's journal names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Journaled {
    /// Each source root that a key names, whether its value reads or not.
    pub roots: BTreeSet<NodeId>,
    /// A key of this owner too short to name a source root.
    pub unattributed: bool,
}

impl Journaled {
    /// Whether the journal can hold an entry at `root`: a key names it, or a
    /// key names no root.
    pub fn blocks(&self, root: NodeId) -> bool {
        self.unattributed || self.roots.contains(&root)
    }
}

/// Why a journal write did not land.
#[derive(Debug)]
pub enum JournalError {
    /// The envelope does not encode.
    Envelope(ResealEnvelopeError),
    /// The key holds a value that does not read.
    Unreadable,
    /// The key holds an entry of another caller.
    OtherCaller,
    /// The staging store or the seal failed.
    Store(SeamError),
}

/// One owner's journal in the staging store.
pub struct ResealJournal<'a, S> {
    store: &'a S,
    seal: BookkeepingSeal<'a>,
    owner_tag: [u8; 32],
}

impl<'a, S: StagingStore> ResealJournal<'a, S> {
    /// The journal of the owner that `seal` seals to.
    pub fn new(store: &'a S, seal: BookkeepingSeal<'a>) -> Self {
        Self {
            store,
            owner_tag: seal.owner_tag(),
            seal,
        }
    }

    /// The key of `part` of the entry at `source_root`.
    pub fn key(&self, source_root: NodeId, part: &[u8]) -> Vec<u8> {
        [RESEAL_JOURNAL_PREFIX, &self.owner_tag, &source_root.0, part].concat()
    }

    /// What `part` of the entry at `source_root` holds.
    pub async fn read(&self, source_root: NodeId, part: &[u8]) -> SeamResult<JournalSlot> {
        let Some(blob) = self
            .store
            .staged_bytes(&self.key(source_root, part))
            .await?
        else {
            return Ok(JournalSlot::Absent);
        };
        Ok(self
            .seal
            .open(OwnerLocalKind::SubtreeReseal, &blob)
            .and_then(|body| decode_reseal_envelope(&body, source_root).ok())
            .map_or(JournalSlot::Unreadable, JournalSlot::Kept))
    }

    /// Every source root that a key of this owner names. A value need not
    /// open to count.
    pub async fn journaled(&self) -> SeamResult<Journaled> {
        let mut journaled = Journaled::default();
        let owner = [RESEAL_JOURNAL_PREFIX, &self.owner_tag].concat();
        for key in self.store.staged_keys().await? {
            let Some(rest) = key.strip_prefix(owner.as_slice()) else {
                continue;
            };
            match rest.first_chunk::<16>() {
                Some(root) => {
                    journaled.roots.insert(NodeId(*root));
                }
                None => journaled.unattributed = true,
            }
        }
        Ok(journaled)
    }

    /// The part of each key under the entry of `source_root`.
    pub async fn parts(&self, source_root: NodeId) -> SeamResult<Vec<Vec<u8>>> {
        let entry = self.key(source_root, &[]);
        Ok(self
            .store
            .staged_keys()
            .await?
            .into_iter()
            .filter_map(|key| key.strip_prefix(entry.as_slice()).map(<[u8]>::to_vec))
            .collect())
    }

    /// Refuse a value at `part` that does not read, or that another caller
    /// wrote.
    async fn check_owner(
        &self,
        source_root: NodeId,
        part: &[u8],
        caller: u8,
    ) -> Result<(), JournalError> {
        match self
            .read(source_root, part)
            .await
            .map_err(JournalError::Store)?
        {
            JournalSlot::Unreadable => Err(JournalError::Unreadable),
            JournalSlot::Kept(held) if held.caller != caller => Err(JournalError::OtherCaller),
            JournalSlot::Absent | JournalSlot::Kept(_) => Ok(()),
        }
    }

    /// Write `envelope` at `part` of its source root. Refused over a value that
    /// does not read, and over an entry of another caller.
    pub async fn put(&self, part: &[u8], envelope: &ResealEnvelope) -> Result<(), JournalError> {
        let body = encode_reseal_envelope(envelope, envelope.source_root)
            .map_err(JournalError::Envelope)?;
        self.check_owner(envelope.source_root, part, envelope.caller)
            .await?;
        let blob = self
            .seal
            .seal(OwnerLocalKind::SubtreeReseal, &body)
            .map_err(JournalError::Store)?;
        self.store
            .put_staged_bytes(&self.key(envelope.source_root, part), &blob)
            .await
            .map_err(JournalError::Store)
    }

    /// Remove the value of `caller` at `part` of `source_root`. Refused over a
    /// value that does not read, and over an entry of another caller.
    pub async fn remove(
        &self,
        source_root: NodeId,
        part: &[u8],
        caller: u8,
    ) -> Result<(), JournalError> {
        self.check_owner(source_root, part, caller).await?;
        self.store
            .remove_staged_bytes(&self.key(source_root, part))
            .await
            .map_err(JournalError::Store)
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use cipherbox_core::suite::x25519::X25519Secret;

    use super::*;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on};

    const ROOT: NodeId = NodeId([0x51; 16]);

    fn envelope(caller: u8) -> ResealEnvelope {
        ResealEnvelope {
            caller,
            source_root: ROOT,
            payload: b"rows".to_vec().into(),
        }
    }

    fn encoded(caller: u8) -> Vec<u8> {
        encode_reseal_envelope(&envelope(caller), ROOT)
            .expect("encodes")
            .to_vec()
    }

    /// The debug form names the payload length only, never a payload byte.
    #[test]
    fn the_debug_form_of_an_envelope_prints_no_payload_byte() {
        let shown = format!(
            "{:?}",
            ResealEnvelope {
                payload: vec![0xa7; 8].into(),
                ..envelope(1)
            }
        );
        assert!(shown.contains("payload_len: 8"), "{shown}");
        assert!(!shown.contains("167"), "a payload byte in {shown}");
    }

    #[test]
    fn an_envelope_round_trips_with_its_payload() {
        assert_eq!(decode_reseal_envelope(&encoded(1), ROOT), Ok(envelope(1)));
    }

    /// A caller this build has no grammar for keeps its payload as it is.
    #[test]
    fn an_envelope_of_any_caller_decodes_with_an_opaque_payload() {
        for caller in [2, 0xff] {
            assert_eq!(
                decode_reseal_envelope(&encoded(caller), ROOT),
                Ok(envelope(caller))
            );
        }
    }

    #[test]
    fn decode_refuses_each_envelope_the_check_refuses() {
        let mut format_zero = encoded(1);
        format_zero[0] = 0;
        let mut format_two = encoded(1);
        format_two[0] = 2;
        let mut no_caller = encoded(1);
        no_caller[1] = 0;
        let head = encoded(1)[..ENVELOPE_HEAD_LEN - 1].to_vec();
        let mut over_cap = encoded(1)[..ENVELOPE_HEAD_LEN].to_vec();
        over_cap.resize(ENVELOPE_HEAD_LEN + MAX_RESEAL_PAYLOAD + 1, 0);
        for (body, refusal) in [
            (format_zero, ResealEnvelopeError::UnknownFormat(0)),
            (format_two, ResealEnvelopeError::UnknownFormat(2)),
            (Vec::new(), ResealEnvelopeError::Truncated),
            (vec![RESEAL_ENVELOPE_V1], ResealEnvelopeError::Truncated),
            (head, ResealEnvelopeError::Truncated),
            (no_caller, ResealEnvelopeError::NoCaller),
            (over_cap, ResealEnvelopeError::PayloadTooLarge),
        ] {
            assert_eq!(decode_reseal_envelope(&body, ROOT), Err(refusal));
        }
        assert_eq!(
            decode_reseal_envelope(&encoded(1), NodeId([0x52; 16])),
            Err(ResealEnvelopeError::RootMismatch),
            "the value of another root's key"
        );
    }

    /// The `subtree-reseal` body that the core KAT pins decodes, so a layout
    /// change on one side fails here.
    #[test]
    fn the_kat_subtree_reseal_body_decodes() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../core/kat/vectors/owner_local/owner_local_accept.json"
        ))
        .expect("the KAT file parses");
        let body = vectors
            .iter()
            .find(|vector| vector["name"] == "subtree-reseal-body")
            .and_then(|vector| vector["body"].as_str())
            .map(|hex| hex::decode(hex).expect("the KAT body is hex"))
            .expect("the KAT pins the body");

        assert_eq!(
            decode_reseal_envelope(&body, NodeId([0xe5; 16])),
            Ok(ResealEnvelope {
                caller: 1,
                source_root: NodeId([0xe5; 16]),
                payload: b"caller payload".to_vec().into(),
            })
        );
    }

    fn run(test: impl AsyncFnOnce(&ResealJournal<'_, InMemoryStagingStore>)) {
        let store = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(5));
        let secret = X25519Secret::from_scalar([9; 32]);
        let journal = ResealJournal::new(&store, BookkeepingSeal::new(&secret, &entropy));
        block_on(test(&journal));
    }

    #[test]
    fn a_written_entry_reads_back_and_blocks_its_root() {
        run(async |journal| {
            assert_eq!(journal.read(ROOT, b"").await.unwrap(), JournalSlot::Absent);
            journal.put(b"", &envelope(1)).await.unwrap();

            assert_eq!(
                journal.read(ROOT, b"").await.unwrap(),
                JournalSlot::Kept(envelope(1))
            );
            let journaled = journal.journaled().await.unwrap();
            assert!(journaled.blocks(ROOT));
            assert!(!journaled.blocks(NodeId([0x52; 16])));
        });
    }

    /// A value that does not open, and a sealed value whose envelope this
    /// build does not read, are never absent: each blocks its root, and a
    /// write leaves its bytes as they are.
    #[test]
    fn an_unreadable_value_blocks_and_is_never_replaced() {
        run(async |journal| {
            let mut other_format = encoded(1);
            other_format[0] = 2;
            let sealed = journal
                .seal
                .seal(OwnerLocalKind::SubtreeReseal, &other_format)
                .unwrap();
            for blob in [b"not a sealed value".to_vec(), sealed] {
                let key = journal.key(ROOT, b"");
                journal.store.put_staged_bytes(&key, &blob).await.unwrap();

                assert_eq!(
                    journal.read(ROOT, b"").await.unwrap(),
                    JournalSlot::Unreadable
                );
                assert!(journal.journaled().await.unwrap().blocks(ROOT));
                assert!(matches!(
                    journal.put(b"", &envelope(1)).await,
                    Err(JournalError::Unreadable)
                ));
                assert_eq!(journal.store.staged_bytes(&key).await.unwrap(), Some(blob));
            }
        });
    }

    #[test]
    fn a_caller_replaces_its_own_entry() {
        run(async |journal| {
            journal.put(b"", &envelope(1)).await.unwrap();
            let second = ResealEnvelope {
                payload: b"second rows".to_vec().into(),
                ..envelope(1)
            };
            journal.put(b"", &second).await.unwrap();

            assert_eq!(
                journal.read(ROOT, b"").await.unwrap(),
                JournalSlot::Kept(second)
            );
        });
    }

    #[test]
    fn a_caller_removes_only_its_own_readable_value() {
        run(async |journal| {
            journal.put(b"a", &envelope(1)).await.unwrap();
            journal.put(b"b", &envelope(2)).await.unwrap();
            let unreadable = journal.key(ROOT, b"c");
            journal
                .store
                .put_staged_bytes(&unreadable, b"not a sealed value")
                .await
                .unwrap();
            let mut parts = journal.parts(ROOT).await.unwrap();
            parts.sort();
            assert_eq!(parts, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);

            assert!(matches!(
                journal.remove(ROOT, b"b", 1).await,
                Err(JournalError::OtherCaller)
            ));
            assert!(matches!(
                journal.remove(ROOT, b"c", 1).await,
                Err(JournalError::Unreadable)
            ));
            journal.remove(ROOT, b"a", 1).await.unwrap();
            let mut parts = journal.parts(ROOT).await.unwrap();
            parts.sort();
            assert_eq!(parts, [b"b".to_vec(), b"c".to_vec()]);
        });
    }

    #[test]
    fn an_entry_of_another_caller_is_kept_and_never_replaced() {
        run(async |journal| {
            journal.put(b"", &envelope(2)).await.unwrap();

            assert!(matches!(
                journal.put(b"", &envelope(1)).await,
                Err(JournalError::OtherCaller)
            ));
            assert_eq!(
                journal.read(ROOT, b"").await.unwrap(),
                JournalSlot::Kept(envelope(2))
            );
        });
    }

    /// Two identities on one store keep their entries for one root apart:
    /// each key carries the owner tag of the seal, so each owner reads its
    /// own entry and counts only its own roots.
    #[test]
    fn two_identities_keep_their_entries_for_one_root_apart() {
        let store = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(6));
        let (alice, bob) = (
            X25519Secret::from_scalar([9; 32]),
            X25519Secret::from_scalar([10; 32]),
        );
        let alices = ResealJournal::new(&store, BookkeepingSeal::new(&alice, &entropy));
        let bobs = ResealJournal::new(&store, BookkeepingSeal::new(&bob, &entropy));
        let bobs_entry = ResealEnvelope {
            payload: b"bob rows".to_vec().into(),
            ..envelope(1)
        };
        let other_root = NodeId([0x53; 16]);
        block_on(async {
            alices.put(b"", &envelope(1)).await.unwrap();
            bobs.put(b"", &bobs_entry).await.unwrap();
            bobs.put(
                b"",
                &ResealEnvelope {
                    source_root: other_root,
                    ..envelope(1)
                },
            )
            .await
            .unwrap();

            assert_ne!(alices.key(ROOT, b""), bobs.key(ROOT, b""));
            assert_eq!(
                alices.read(ROOT, b"").await.unwrap(),
                JournalSlot::Kept(envelope(1))
            );
            assert_eq!(
                bobs.read(ROOT, b"").await.unwrap(),
                JournalSlot::Kept(bobs_entry)
            );
            assert_eq!(
                alices.journaled().await.unwrap().roots,
                BTreeSet::from([ROOT])
            );
            assert_eq!(
                bobs.journaled().await.unwrap().roots,
                BTreeSet::from([ROOT, other_root])
            );
        });
    }

    #[test]
    fn a_key_that_names_no_root_blocks_every_root() {
        run(async |journal| {
            let short = [RESEAL_JOURNAL_PREFIX, &journal.owner_tag, &[0x51; 4]].concat();
            journal.store.put_staged_bytes(&short, b"x").await.unwrap();
            let other_owner = [RESEAL_JOURNAL_PREFIX, &[4; 32], &[0x52; 16]].concat();
            journal
                .store
                .put_staged_bytes(&other_owner, b"x")
                .await
                .unwrap();

            let journaled = journal.journaled().await.unwrap();
            assert!(journaled.unattributed);
            assert!(
                journaled.roots.is_empty(),
                "another owner's key is not ours"
            );
            assert!(journaled.blocks(ROOT));
        });
    }
}
