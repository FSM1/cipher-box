//! The renewal walk's durable cursor (ADR 0061 D2): where the walk resumes,
//! sealed under [`OwnerLocalKind::RenewalCursor`] at one staging key per
//! identity.
//!
//! The body is a fixed-width layout padded to both caps, so its length is the
//! same for every vault. A cursor that does not open or decode, or a replayed
//! older one, only costs work: the walk starts the cycle again.

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::OwnerLocalKind;
use cipherbox_core::suite::ed25519::{Ed25519Verifier, PUBLIC_LEN};
use cipherbox_core::suite::x25519::X25519Secret;

use crate::seams::{SeamResult, StagingStore, UnixMillis};
use crate::sync::BookkeepingSeal;
use crate::sync::drain::owner_scoped_key;

/// The staging-key prefix the cursor is stored under. Orphan GC treats the
/// whole prefix as referenced.
pub const RENEWAL_CURSOR_PREFIX: &[u8] = b"cbx/wc/";

/// The most folder node ids the cursor's path holds.
pub const MAX_CURSOR_PATH: usize = 64;

/// The most deferred roots the cursor holds.
pub const MAX_DEFERRED_ROOTS: usize = 256;

/// The body version this build writes. A later build still reads it.
const CURSOR_V1: u8 = 1;

const ID_LEN: usize = 16;

/// `v ‖ cycle start ‖ root`.
const HEADER_LEN: usize = 1 + 8 + ROOT_LEN;
/// `class ‖ scope id ‖ node id`.
const ROOT_LEN: usize = 1 + 2 * ID_LEN;
/// `count ‖ ids`.
const PATH_LEN: usize = 1 + MAX_CURSOR_PATH * ID_LEN;
/// `present ‖ id`.
const LAST_CHILD_LEN: usize = 1 + ID_LEN;
/// `scope id ‖ node id ‖ name key`.
const DEFERRED_ENTRY_LEN: usize = 2 * ID_LEN + PUBLIC_LEN;
/// `count ‖ entries`.
const DEFERRED_LEN: usize = 2 + MAX_DEFERRED_ROOTS * DEFERRED_ENTRY_LEN;

/// The one body length every cursor encodes to.
pub const CURSOR_BODY_LEN: usize = HEADER_LEN + PATH_LEN + LAST_CHILD_LEN + DEFERRED_LEN;

/// One root of the walk (ADR 0061 D1), in walk order: every owned scope in
/// scope-id order (the vault root scope's all-zero id first), then each bin
/// index entry in node-id order, then each deferred root in the cursor's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkRoot {
    /// An owned scope, by its scope id.
    Scope([u8; 16]),
    /// A bin index entry, by its node id.
    Bin([u8; 16]),
    /// A deferred root, by its scope id and node id.
    Deferred {
        /// The scope the folder belongs to.
        scope_id: [u8; 16],
        /// The folder.
        node_id: [u8; 16],
    },
}

/// A folder below the depth cap, walked later as a root of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredRoot {
    /// The scope the folder belongs to.
    pub scope_id: [u8; 16],
    /// The folder's node id.
    pub node_id: [u8; 16],
    /// The name its parent named when the walk deferred it.
    pub name: IpnsName,
}

/// Where the renewal walk resumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalCursor {
    /// When the current (or last) cycle began.
    pub cycle_start: UnixMillis,
    /// The root the walk is in, or `None` once the cycle finished.
    pub root: Option<WalkRoot>,
    /// The folder node ids from the root down to the deepest folder the walk
    /// is listing.
    pub path: Vec<[u8; 16]>,
    /// The last child the walk visited in the deepest folder.
    pub last_child: Option<[u8; 16]>,
    /// The folders the walk deferred at the depth cap.
    pub deferred: Vec<DeferredRoot>,
}

impl RenewalCursor {
    /// A cycle that begins at `now`, at no root yet.
    pub fn starting(now: UnixMillis) -> Self {
        Self {
            cycle_start: now,
            root: None,
            path: Vec::new(),
            last_child: None,
            deferred: Vec::new(),
        }
    }
}

/// Why a cursor body did not encode or decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorCodecError {
    /// The path holds more than [`MAX_CURSOR_PATH`] ids.
    PathTooLong,
    /// The set holds more than [`MAX_DEFERRED_ROOTS`] roots.
    TooManyDeferred,
    /// The body is not [`CURSOR_BODY_LEN`] bytes.
    WrongLength,
    /// The body names a version this build does not read.
    UnsupportedVersion,
    /// A field or its padding is not canonical.
    Malformed,
}

/// Encode `cursor`. Refuses what [`decode_cursor`] refuses, release-active
/// (AGENTS.md rule 8).
pub fn encode_cursor(cursor: &RenewalCursor) -> Result<Vec<u8>, CursorCodecError> {
    if cursor.path.len() > MAX_CURSOR_PATH {
        return Err(CursorCodecError::PathTooLong);
    }
    if cursor.deferred.len() > MAX_DEFERRED_ROOTS {
        return Err(CursorCodecError::TooManyDeferred);
    }
    let mut out = Vec::with_capacity(CURSOR_BODY_LEN);
    out.push(CURSOR_V1);
    out.extend_from_slice(&cursor.cycle_start.0.to_be_bytes());
    let (class, scope_id, node_id) = match cursor.root {
        None => (0u8, [0; ID_LEN], [0; ID_LEN]),
        Some(WalkRoot::Scope(scope_id)) => (1, scope_id, [0; ID_LEN]),
        Some(WalkRoot::Bin(node_id)) => (2, [0; ID_LEN], node_id),
        Some(WalkRoot::Deferred { scope_id, node_id }) => (3, scope_id, node_id),
    };
    out.push(class);
    out.extend_from_slice(&scope_id);
    out.extend_from_slice(&node_id);
    out.push(cursor.path.len() as u8);
    for id in &cursor.path {
        out.extend_from_slice(id);
    }
    pad(&mut out, (MAX_CURSOR_PATH - cursor.path.len()) * ID_LEN);
    match cursor.last_child {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id);
        }
        None => {
            out.push(0);
            pad(&mut out, ID_LEN);
        }
    }
    out.extend_from_slice(&(cursor.deferred.len() as u16).to_be_bytes());
    for root in &cursor.deferred {
        out.extend_from_slice(&root.scope_id);
        out.extend_from_slice(&root.node_id);
        out.extend_from_slice(&root.name.public_key().to_bytes());
    }
    pad(
        &mut out,
        (MAX_DEFERRED_ROOTS - cursor.deferred.len()) * DEFERRED_ENTRY_LEN,
    );
    Ok(out)
}

/// Decode a cursor body. Any breach of a cap, a non-zero pad byte or an
/// unknown version is an error, never a partial cursor.
pub fn decode_cursor(bytes: &[u8]) -> Result<RenewalCursor, CursorCodecError> {
    if bytes.len() != CURSOR_BODY_LEN {
        return Err(CursorCodecError::WrongLength);
    }
    let mut reader = Reader(bytes);
    if reader.byte() != CURSOR_V1 {
        return Err(CursorCodecError::UnsupportedVersion);
    }
    let cycle_start = UnixMillis(u64::from_be_bytes(reader.array()));
    let class = reader.byte();
    let scope_id: [u8; ID_LEN] = reader.array();
    let node_id: [u8; ID_LEN] = reader.array();
    let root = match (class, scope_id == [0; ID_LEN], node_id == [0; ID_LEN]) {
        (0, true, true) => None,
        (1, _, true) => Some(WalkRoot::Scope(scope_id)),
        (2, true, _) => Some(WalkRoot::Bin(node_id)),
        (3, _, _) => Some(WalkRoot::Deferred { scope_id, node_id }),
        _ => return Err(CursorCodecError::Malformed),
    };
    let path_len = usize::from(reader.byte());
    if path_len > MAX_CURSOR_PATH {
        return Err(CursorCodecError::PathTooLong);
    }
    let path = (0..path_len).map(|_| reader.array()).collect();
    reader.zeros((MAX_CURSOR_PATH - path_len) * ID_LEN)?;
    let last_child = match reader.byte() {
        0 => {
            reader.zeros(ID_LEN)?;
            None
        }
        1 => Some(reader.array()),
        _ => return Err(CursorCodecError::Malformed),
    };
    let deferred_len = usize::from(u16::from_be_bytes(reader.array()));
    if deferred_len > MAX_DEFERRED_ROOTS {
        return Err(CursorCodecError::TooManyDeferred);
    }
    let mut deferred = Vec::with_capacity(deferred_len);
    for _ in 0..deferred_len {
        let scope_id = reader.array();
        let node_id = reader.array();
        let key = Ed25519Verifier::from_bytes(reader.array()).ok_or(CursorCodecError::Malformed)?;
        deferred.push(DeferredRoot {
            scope_id,
            node_id,
            name: IpnsName::from_public_key(&key),
        });
    }
    reader.zeros((MAX_DEFERRED_ROOTS - deferred_len) * DEFERRED_ENTRY_LEN)?;
    Ok(RenewalCursor {
        cycle_start,
        root,
        path,
        last_child,
        deferred,
    })
}

fn pad(out: &mut Vec<u8>, len: usize) {
    out.resize(out.len() + len, 0);
}

/// A cursor over a body whose total length is already checked.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn byte(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().unwrap_or([0; N])
    }

    fn zeros(&mut self, len: usize) -> Result<(), CursorCodecError> {
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        if head.iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err(CursorCodecError::Malformed)
        }
    }
}

/// The cursor for one identity, under one staging key.
pub struct CursorStore<'a, St> {
    staging: &'a St,
    seal: BookkeepingSeal<'a>,
    key: Vec<u8>,
}

impl<'a, St: StagingStore> CursorStore<'a, St> {
    /// The cursor store of the identity `enc_secret` names.
    pub fn new(staging: &'a St, seal: BookkeepingSeal<'a>, enc_secret: &X25519Secret) -> Self {
        Self {
            staging,
            seal,
            key: owner_scoped_key(RENEWAL_CURSOR_PREFIX, enc_secret),
        }
    }

    /// The stored cursor, or `None` when none is stored or it does not open or
    /// decode.
    pub async fn load(&self) -> SeamResult<Option<RenewalCursor>> {
        let Some(blob) = self.staging.staged_bytes(&self.key).await? else {
            return Ok(None);
        };
        Ok(self
            .seal
            .open(OwnerLocalKind::RenewalCursor, &blob)
            .and_then(|body| decode_cursor(&body).ok()))
    }

    /// Store `cursor`.
    pub async fn save(&self, cursor: &RenewalCursor) -> SeamResult<()> {
        let body = encode_cursor(cursor)
            .map_err(|e| crate::seams::SeamError::new(format!("renewal cursor: {e:?}")))?;
        let blob = self.seal.seal(OwnerLocalKind::RenewalCursor, &body)?;
        self.staging.put_staged_bytes(&self.key, &blob).await
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use super::*;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on};

    fn name(seed: u8) -> IpnsName {
        IpnsName::from_public_key(&Ed25519Signer::from_seed([seed; 32]).verifying_key())
    }

    fn full() -> RenewalCursor {
        RenewalCursor {
            cycle_start: UnixMillis(1_234_567),
            root: Some(WalkRoot::Deferred {
                scope_id: [3; 16],
                node_id: [4; 16],
            }),
            path: (0..MAX_CURSOR_PATH).map(|i| [i as u8 + 1; 16]).collect(),
            last_child: Some([9; 16]),
            deferred: (0..MAX_DEFERRED_ROOTS)
                .map(|i| DeferredRoot {
                    scope_id: [5; 16],
                    node_id: [(i % 251) as u8; 16],
                    name: name((i % 200) as u8 + 1),
                })
                .collect(),
        }
    }

    #[test]
    fn a_cursor_at_both_caps_round_trips() {
        let cursor = full();
        let body = encode_cursor(&cursor).unwrap();
        assert_eq!(body.len(), CURSOR_BODY_LEN);
        assert_eq!(decode_cursor(&body).unwrap(), cursor);
    }

    /// The v1 body as a release wrote it, spelled out field by field rather
    /// than through the encoder, so a codec change that moves or resizes a
    /// field cannot drop the previous release's cursor unnoticed.
    fn committed_v1_body() -> Vec<u8> {
        let mut body = vec![1];
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0x12, 0xd6, 0x87]);
        body.push(3);
        body.extend_from_slice(&[3; 16]);
        body.extend_from_slice(&[4; 16]);
        body.push(2);
        body.extend_from_slice(&[0x11; 16]);
        body.extend_from_slice(&[0x22; 16]);
        body.resize(body.len() + 62 * 16, 0);
        body.push(1);
        body.extend_from_slice(&[9; 16]);
        body.extend_from_slice(&[0, 1]);
        body.extend_from_slice(&[5; 16]);
        body.extend_from_slice(&[6; 16]);
        body.extend_from_slice(&name(1).public_key().to_bytes());
        body.resize(17_470, 0);
        body
    }

    #[test]
    fn a_body_the_previous_release_wrote_still_decodes() {
        let body = committed_v1_body();
        let cursor = decode_cursor(&body).expect("the committed body decodes");
        assert_eq!(
            cursor,
            RenewalCursor {
                cycle_start: UnixMillis(1_234_567),
                root: Some(WalkRoot::Deferred {
                    scope_id: [3; 16],
                    node_id: [4; 16],
                }),
                path: vec![[0x11; 16], [0x22; 16]],
                last_child: Some([9; 16]),
                deferred: vec![DeferredRoot {
                    scope_id: [5; 16],
                    node_id: [6; 16],
                    name: name(1),
                }],
            }
        );
        assert_eq!(encode_cursor(&cursor).unwrap(), body);
    }

    #[test]
    fn every_cursor_encodes_to_one_length() {
        let empty = encode_cursor(&RenewalCursor::starting(UnixMillis(0))).unwrap();
        let mut one = RenewalCursor::starting(UnixMillis(7));
        one.root = Some(WalkRoot::Bin([2; 16]));
        one.path.push([2; 16]);
        assert_eq!(empty.len(), CURSOR_BODY_LEN);
        assert_eq!(encode_cursor(&one).unwrap().len(), CURSOR_BODY_LEN);
        assert_eq!(decode_cursor(&empty).unwrap().root, None);
    }

    /// Release-active, so these fire in a release build too.
    #[test]
    fn the_encoder_refuses_what_the_decoder_refuses() {
        let mut long = full();
        long.path.push([1; 16]);
        assert_eq!(encode_cursor(&long), Err(CursorCodecError::PathTooLong));
        let mut many = full();
        many.deferred.push(many.deferred[0].clone());
        assert_eq!(encode_cursor(&many), Err(CursorCodecError::TooManyDeferred));
    }

    #[test]
    fn the_decoder_refuses_a_count_past_either_cap() {
        let body = encode_cursor(&RenewalCursor::starting(UnixMillis(0))).unwrap();
        let mut path = body.clone();
        path[HEADER_LEN] = MAX_CURSOR_PATH as u8 + 1;
        assert_eq!(decode_cursor(&path), Err(CursorCodecError::PathTooLong));
        let mut deferred = body;
        let at = HEADER_LEN + PATH_LEN + LAST_CHILD_LEN;
        deferred[at..at + 2].copy_from_slice(&(MAX_DEFERRED_ROOTS as u16 + 1).to_be_bytes());
        assert_eq!(
            decode_cursor(&deferred),
            Err(CursorCodecError::TooManyDeferred)
        );
    }

    #[test]
    fn a_non_zero_pad_or_a_short_body_is_refused() {
        let body = encode_cursor(&RenewalCursor::starting(UnixMillis(0))).unwrap();
        let mut padded = body.clone();
        *padded.last_mut().unwrap() = 1;
        assert_eq!(decode_cursor(&padded), Err(CursorCodecError::Malformed));
        assert_eq!(
            decode_cursor(&body[..body.len() - 1]),
            Err(CursorCodecError::WrongLength)
        );
        let mut future = body;
        future[0] = CURSOR_V1 + 1;
        assert_eq!(
            decode_cursor(&future),
            Err(CursorCodecError::UnsupportedVersion)
        );
    }

    #[test]
    fn the_store_reads_back_what_it_saved_and_skips_a_foreign_blob() {
        let staging = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(4));
        let mine = X25519Secret::from_scalar([7; 32]);
        let theirs = X25519Secret::from_scalar([8; 32]);
        let store = CursorStore::new(&staging, BookkeepingSeal::new(&mine, &entropy), &mine);
        let cursor = full();
        block_on(store.save(&cursor)).unwrap();
        assert_eq!(block_on(store.load()).unwrap(), Some(cursor));

        let blob = block_on(staging.staged_bytes(&store.key)).unwrap().unwrap();
        let foreign = CursorStore::new(&staging, BookkeepingSeal::new(&theirs, &entropy), &theirs);
        block_on(staging.put_staged_bytes(&foreign.key, &blob)).unwrap();
        assert_eq!(block_on(foreign.load()).unwrap(), None);
    }
}
