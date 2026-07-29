//! The sealed read-body: the kind-uniform node payload
//! (blueprint/core.md "Envelope and structures", CONTEXT.md "Envelope").
//!
//! `kind` lives *inside* this sealed structure (#27 D4), so an observer of the
//! plaintext envelope cannot tell a file from a folder. The body is a tagged
//! union — `folder { children[] }` or `file { versions[] }` — plus injected
//! timestamps (core reads no clock).
//!
//! A child ref (#27 D7) carries no key wraps and no size/mtime mirrors, so a
//! child write never republishes its parent. File-version content keys are
//! **random per version** and stored inline rather than derived: rotation
//! re-wraps them for free via the metadata re-seal.
//!
//! **Uniqueness is fail-closed at decode** (#39 D7): duplicate child `id`s and
//! duplicate `ipnsName`s reject as trust violations, the latter closing the
//! name-transplant hole the AAD leaves open by design ([`super::aad`]).
//!
//! One strictness policy, everywhere (#27 D10): every map level decodes strict
//! det-CBOR and preserves unknown fields byte-stable, so an old client
//! rewriting a folder under shared write never strips a newer client's fields.

use core::cmp::Ordering;
use core::fmt;
use std::collections::BTreeSet;

use crate::codec::{Map, Value, decode, encode};
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::suite::secret::{SECRET_LEN, SecretBytes};

// ---------------------------------------------------------------------------
// The node kind (the sealed tagged-union discriminant).
// ---------------------------------------------------------------------------

/// A node's kind, sealed inside the read-body and mirrored immutably in every
/// child ref. On the wire it is the text `"folder"`/`"file"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Folder,
    File,
}

impl NodeKind {
    /// The frozen wire string.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::File => "file",
        }
    }

    /// Parse the wire string; `None` for anything but `"folder"`/`"file"`.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "folder" => Some(Self::Folder),
            "file" => Some(Self::File),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Child ref.
// ---------------------------------------------------------------------------

/// A folder's link to one child (#27 D7). Immutable identity fields plus the
/// monotonic `link_counter`; `unknown` preserves any newer-client fields
/// byte-stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildRef {
    /// The child's location-independent node id (16-byte UUID).
    pub id: [u8; 16],
    /// The display name.
    pub name: String,
    /// The child's opaque `ipnsName` bytes, ordered by [`name_cmp`].
    pub ipns_name: Vec<u8>,
    /// The child's immutable kind.
    pub kind: NodeKind,
    /// The monotonic dual-link tiebreak counter (#33 D5).
    pub link_counter: u64,
    /// Preserved unknown fields (never any of the known keys); re-emitted
    /// canonically on rewrite.
    pub unknown: Vec<(String, Value)>,
}

const CHILD_KNOWN: &[&str] = &["id", "ipnsName", "kind", "linkCounter", "name"];

impl ChildRef {
    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        let id = bytes_fixed::<16>(req(map, "id")?, "id")?;
        let name = req(map, "name")?.as_text()?.to_string();
        let ipns_name = req(map, "ipnsName")?.as_bytes()?.to_vec();
        let kind =
            NodeKind::from_wire(req(map, "kind")?.as_text()?).ok_or(Malformed::InvalidNodeKind)?;
        let link_counter = req(map, "linkCounter")?.as_unsigned()?;
        Ok(Self {
            id,
            name,
            ipns_name,
            kind,
            link_counter,
            unknown: collect_unknown(map, CHILD_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("id", Value::Bytes(self.id.to_vec()));
        m.insert("name", Value::Text(self.name.clone()));
        m.insert("ipnsName", Value::Bytes(self.ipns_name.clone()));
        m.insert("kind", Value::Text(self.kind.as_wire().to_string()));
        m.insert("linkCounter", Value::Unsigned(self.link_counter));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

// ---------------------------------------------------------------------------
// File version. Content keys are secret material → zeroizing owning type.
// ---------------------------------------------------------------------------

/// One file version; newest-first in the version list, head is current.
///
/// The private `content_key` is random per-version symmetric key material, held
/// in a zeroizing owner ([`SecretBytes`]) with a redacted `Debug` (never-log-keys
/// rule); read it through [`Version::content_key`].
#[derive(Clone)]
pub struct Version {
    /// The content CID bytes.
    pub content_cid: Vec<u8>,
    content_key: SecretBytes,
    /// The plaintext size in bytes.
    pub size: u64,
    /// The injected modification time.
    pub modified_at: u64,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: Vec<(String, Value)>,
}

const VERSION_KNOWN: &[&str] = &["contentCid", "contentKey", "modifiedAt", "size"];

impl Version {
    /// A version with no preserved unknown fields (the construction path).
    pub fn new(
        content_cid: Vec<u8>,
        content_key: [u8; SECRET_LEN],
        size: u64,
        modified_at: u64,
    ) -> Self {
        Self {
            content_cid,
            content_key: SecretBytes::new(content_key),
            size,
            modified_at,
            unknown: Vec::new(),
        }
    }

    /// Borrow the random content key.
    pub fn content_key(&self) -> &[u8; SECRET_LEN] {
        self.content_key.as_bytes()
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        let content_cid = req(map, "contentCid")?.as_bytes()?.to_vec();
        let content_key = bytes_fixed::<SECRET_LEN>(req(map, "contentKey")?, "contentKey")?;
        let size = req(map, "size")?.as_unsigned()?;
        let modified_at = req(map, "modifiedAt")?.as_unsigned()?;
        Ok(Self {
            content_cid,
            content_key: SecretBytes::new(content_key),
            size,
            modified_at,
            unknown: collect_unknown(map, VERSION_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("contentCid", Value::Bytes(self.content_cid.clone()));
        m.insert(
            "contentKey",
            Value::Bytes(self.content_key.as_bytes().to_vec()),
        );
        m.insert("size", Value::Unsigned(self.size));
        m.insert("modifiedAt", Value::Unsigned(self.modified_at));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Version")
            .field("content_cid", &self.content_cid)
            .field("content_key", &"<redacted>")
            .field("size", &self.size)
            .field("modified_at", &self.modified_at)
            .field("unknown", &self.unknown)
            .finish()
    }
}

impl PartialEq for Version {
    /// Equality is for KAT/round-trip comparison of test vectors, not a
    /// security operation, so the content-key byte comparison needs no
    /// constant-time guarantee (mirrors `kdf::EdgeProbeOutput`).
    fn eq(&self, other: &Self) -> bool {
        self.content_cid == other.content_cid
            && self.content_key.as_bytes() == other.content_key.as_bytes()
            && self.size == other.size
            && self.modified_at == other.modified_at
            && self.unknown == other.unknown
    }
}

impl Eq for Version {}

// ---------------------------------------------------------------------------
// The read-body tagged union.
// ---------------------------------------------------------------------------

/// The sealed node body: `folder` or `file`, with injected timestamps and
/// preserved unknown fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadBody {
    Folder {
        created_at: u64,
        modified_at: u64,
        children: Vec<ChildRef>,
        unknown: Vec<(String, Value)>,
    },
    File {
        created_at: u64,
        modified_at: u64,
        versions: Vec<Version>,
        unknown: Vec<(String, Value)>,
    },
}

const FOLDER_KNOWN: &[&str] = &["children", "createdAt", "kind", "modifiedAt"];
const FILE_KNOWN: &[&str] = &["createdAt", "kind", "modifiedAt", "versions"];

impl ReadBody {
    /// The node's kind.
    pub fn kind(&self) -> NodeKind {
        match self {
            Self::Folder { .. } => NodeKind::Folder,
            Self::File { .. } => NodeKind::File,
        }
    }

    /// The decode-time uniqueness invariants (#39 D7) re-checked on a
    /// *constructed* body: the seal path runs this so it never persists a body
    /// that decode would refuse to reopen.
    pub fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Folder { children, .. } => assert_children_unique(children),
            Self::File { .. } => Ok(()),
        }
    }
}

/// The strict name comparator: a platform-stable total order over opaque
/// `ipnsName` bytes (blueprint/testing.md — the strict name comparator).
///
/// Bytewise-lexicographic order depends only on the bytes — no length prefix,
/// no locale — so duplicate detection is deterministic and identical on native
/// and WASM. Backs the duplicate-`ipnsName` uniqueness check.
pub fn name_cmp(a: &[u8], b: &[u8]) -> Ordering {
    a.cmp(b)
}

/// Decode a sealed read-body plaintext (strict det-CBOR, uniqueness enforced).
///
/// The transient decoded tree carries a verbatim copy of every inline **content
/// key**, so it is scrubbed through the owning [`ScrubOwned`] guard
/// (terminal-owner rule; symmetric with [`encode_read_body`]).
pub fn decode_read_body(bytes: &[u8]) -> Result<ReadBody, CodecError> {
    let value = ScrubOwned(decode(bytes)?);
    let map = value.value().as_map()?;

    let kind =
        NodeKind::from_wire(req(map, "kind")?.as_text()?).ok_or(Malformed::InvalidNodeKind)?;
    let created_at = req(map, "createdAt")?.as_unsigned()?;
    let modified_at = req(map, "modifiedAt")?.as_unsigned()?;

    match kind {
        NodeKind::Folder => {
            let mut children = Vec::new();
            for item in req(map, "children")?.as_array()? {
                children.push(ChildRef::from_value(item)?);
            }
            assert_children_unique(&children)?;
            Ok(ReadBody::Folder {
                created_at,
                modified_at,
                children,
                unknown: collect_unknown(map, FOLDER_KNOWN),
            })
        }
        NodeKind::File => {
            let mut versions = Vec::new();
            for item in req(map, "versions")?.as_array()? {
                versions.push(Version::from_value(item)?);
            }
            Ok(ReadBody::File {
                created_at,
                modified_at,
                versions,
                unknown: collect_unknown(map, FILE_KNOWN),
            })
        }
    }
}

/// Encode a read-body to its canonical det-CBOR plaintext.
///
/// The returned buffer carries inline **content-key** material verbatim, so its
/// caller is the terminal owner and must zeroize it (the seal path,
/// [`seal_read_body`](super::seal_read_body), does).
///
/// Encoding does *not* re-check uniqueness — persisting callers go through
/// [`seal_read_body`](super::seal_read_body) (or [`ReadBody::validate`]), which
/// refuses to seal a body that would not reopen; the `debug_assert` only catches
/// that divergence early in tests.
pub fn encode_read_body(body: &ReadBody) -> Result<Vec<u8>, CodecError> {
    debug_assert!(
        body.validate().is_ok(),
        "encoding a read-body that violates child uniqueness; its bytes would reject on decode"
    );
    let mut m = Map::new();
    match body {
        ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        } => {
            m.insert("kind", Value::Text(NodeKind::Folder.as_wire().to_string()));
            m.insert(
                "children",
                Value::Array(children.iter().map(ChildRef::to_value).collect()),
            );
            m.insert("createdAt", Value::Unsigned(*created_at));
            m.insert("modifiedAt", Value::Unsigned(*modified_at));
            merge_unknown(&mut m, unknown);
        }
        ReadBody::File {
            created_at,
            modified_at,
            versions,
            unknown,
        } => {
            m.insert("kind", Value::Text(NodeKind::File.as_wire().to_string()));
            m.insert(
                "versions",
                Value::Array(versions.iter().map(Version::to_value).collect()),
            );
            m.insert("createdAt", Value::Unsigned(*created_at));
            m.insert("modifiedAt", Value::Unsigned(*modified_at));
            merge_unknown(&mut m, unknown);
        }
    }
    // The transient tree carries a verbatim copy of every inline content key
    // (one `Value::Bytes` per version). Scrub it through the drop guard so the
    // wipe runs on both return and panic-unwind (terminal-owner rule; see
    // [`ScrubOnDrop`]). The returned buffer stays the seal path's
    // ([`seal_read_body`](super::seal_read_body)) to zeroize.
    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    encode(guard.0)
}

/// Scrubs a codec-owned transient `Value` tree on drop, so the secret copies it
/// carries (inline content keys, scope seeds) are wiped on both normal return
/// and panic-unwind (blueprint/core.md terminal-owner rule). It borrows rather
/// than owns the tree, leaving the wiped buffers observable to a caller/test
/// after the guard falls.
pub(crate) struct ScrubOnDrop<'a>(pub(crate) &'a mut Value);

impl Drop for ScrubOnDrop<'_> {
    fn drop(&mut self) {
        self.0.zeroize_bytes();
    }
}

/// The owning sibling of [`ScrubOnDrop`], for the decode side: it takes the
/// decoded tree by value and scrubs it on drop, covering Ok, Err, and unwind.
/// Owning rather than borrowing because decode holds a live `&Map` into the
/// tree, which a `&mut` guard cannot coexist with; read it via [`Self::value`].
pub(crate) struct ScrubOwned(pub(crate) Value);

impl ScrubOwned {
    /// Borrow the guarded tree for reading.
    pub(crate) fn value(&self) -> &Value {
        &self.0
    }
}

impl Drop for ScrubOwned {
    fn drop(&mut self) {
        self.0.zeroize_bytes();
    }
}

/// Fail-closed uniqueness over a set of grant blinded tags (#39 D7): a
/// recipient's tag names at most one grant, so a duplicate is a confused-deputy
/// over read-vs-write authority. Shared by the grant-ledger (write-body) and the
/// grant-set commitment (grant section) decoders/encoders.
pub(crate) fn assert_grant_tags_unique(
    tags: impl IntoIterator<Item = [u8; SECRET_LEN]>,
) -> Result<(), CodecError> {
    let mut seen = BTreeSet::new();
    for t in tags {
        if !seen.insert(t) {
            return Err(TrustViolation::DuplicateGrantTag.into());
        }
    }
    Ok(())
}

/// Fail-closed uniqueness over one folder's child listing (#39 D7).
fn assert_children_unique(children: &[ChildRef]) -> Result<(), CodecError> {
    let mut ids = BTreeSet::new();
    for c in children {
        if !ids.insert(c.id) {
            return Err(TrustViolation::DuplicateId.into());
        }
    }
    // ipnsName uniqueness via the strict name comparator: sort, then reject any
    // adjacent-equal pair.
    let mut names: Vec<&[u8]> = children.iter().map(|c| c.ipns_name.as_slice()).collect();
    names.sort_by(|a, b| name_cmp(a, b));
    for w in names.windows(2) {
        if name_cmp(w[0], w[1]) == Ordering::Equal {
            return Err(TrustViolation::DuplicateIpnsName.into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared schema helpers (also used by the envelope codec).
// ---------------------------------------------------------------------------

/// A required field, or [`Malformed::MissingField`].
pub(super) fn req<'a>(map: &'a Map, field: &'static str) -> Result<&'a Value, CodecError> {
    map.get(field)
        .ok_or_else(|| Malformed::MissingField { field }.into())
}

/// A fixed-length byte field as `[u8; N]`, or [`Malformed::InvalidFieldLength`].
pub(super) fn bytes_fixed<const N: usize>(
    v: &Value,
    field: &'static str,
) -> Result<[u8; N], CodecError> {
    let b = v.as_bytes()?;
    b.try_into().map_err(|_| {
        Malformed::InvalidFieldLength {
            field,
            expected: N,
            found: b.len(),
        }
        .into()
    })
}

/// The map entries whose key is not in `known`, cloned as canonical values.
/// Because the source map decoded strict det-CBOR, each value is already
/// canonical, so re-encoding it verbatim keeps the whole rewrite byte-stable.
pub(super) fn collect_unknown(map: &Map, known: &[&str]) -> Vec<(String, Value)> {
    map.entries()
        .iter()
        .filter(|(k, _)| !known.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Merge preserved unknown fields into a typed map, **typed fields taking
/// precedence**. Decode already partitions the two ([`collect_unknown`]), so the
/// skip-on-collision guard is for the *construction* path: a caller-built
/// `unknown` list carrying a schema key can never overwrite the typed value and
/// forge bytes that disagree with it. `Map::insert` re-imposes canonical order.
pub(super) fn merge_unknown(map: &mut Map, unknown: &[(String, Value)]) {
    for (k, v) in unknown {
        if !map.contains_key(k) {
            map.insert(k.clone(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child(id: u8, name: &str, ipns: &[u8]) -> ChildRef {
        ChildRef {
            id: [id; 16],
            name: name.to_string(),
            ipns_name: ipns.to_vec(),
            kind: NodeKind::File,
            link_counter: 0,
            unknown: Vec::new(),
        }
    }

    fn folder(children: Vec<ChildRef>) -> ReadBody {
        ReadBody::Folder {
            created_at: 100,
            modified_at: 200,
            children,
            unknown: Vec::new(),
        }
    }

    /// Encode a folder read-body directly through the codec, bypassing
    /// `encode_read_body`'s uniqueness debug-assert — the way a hostile or buggy
    /// peer's bytes arrive, so decode-side uniqueness rejection can be tested.
    fn raw_folder_bytes(children: &[ChildRef]) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("kind", Value::Text("folder".into()));
        m.insert(
            "children",
            Value::Array(children.iter().map(ChildRef::to_value).collect()),
        );
        m.insert("createdAt", Value::Unsigned(100));
        m.insert("modifiedAt", Value::Unsigned(200));
        encode(&Value::Map(m)).unwrap()
    }

    #[test]
    fn folder_round_trips_byte_stable() {
        let body = folder(vec![
            child(1, "a.txt", b"name-1"),
            child(2, "b.txt", b"name-2"),
        ]);
        let bytes = encode_read_body(&body).unwrap();
        let decoded = decode_read_body(&bytes).expect("decodes");
        assert_eq!(decoded, body);
        assert_eq!(
            encode_read_body(&decoded).unwrap(),
            bytes,
            "re-encode byte-stable"
        );
        assert_eq!(decoded.kind(), NodeKind::Folder);
    }

    #[test]
    fn file_versions_round_trip_and_preserve_key() {
        let body = ReadBody::File {
            created_at: 1,
            modified_at: 2,
            versions: vec![
                Version::new(b"cid-new".to_vec(), [9; 32], 4096, 2),
                Version::new(b"cid-old".to_vec(), [8; 32], 1024, 1),
            ],
            unknown: Vec::new(),
        };
        let bytes = encode_read_body(&body).unwrap();
        let decoded = decode_read_body(&bytes).expect("decodes");
        assert_eq!(decoded, body);
        if let ReadBody::File { versions, .. } = &decoded {
            assert_eq!(versions[0].content_key(), &[9; 32]);
        } else {
            panic!("expected file");
        }
    }

    #[test]
    fn duplicate_child_id_rejects() {
        let bytes = raw_folder_bytes(&[child(1, "a", b"name-1"), child(1, "b", b"name-2")]);
        assert_eq!(
            decode_read_body(&bytes).unwrap_err().check(),
            "duplicate-id"
        );
    }

    #[test]
    fn duplicate_child_ipns_name_rejects() {
        let bytes = raw_folder_bytes(&[child(1, "a", b"same-name"), child(2, "b", b"same-name")]);
        assert_eq!(
            decode_read_body(&bytes).unwrap_err().check(),
            "duplicate-ipns-name"
        );
    }

    #[test]
    fn unknown_read_body_field_preserved_byte_stable() {
        // A folder body with a future top-level field the current schema does
        // not know: it must survive decode→encode untouched.
        let mut m = Map::new();
        m.insert("kind", Value::Text("folder".into()));
        m.insert("children", Value::Array(vec![]));
        m.insert("createdAt", Value::Unsigned(1));
        m.insert("modifiedAt", Value::Unsigned(2));
        m.insert("futureField", Value::Text("keep me".into()));
        let bytes = encode(&Value::Map(m)).unwrap();
        let decoded = decode_read_body(&bytes).expect("tolerant decode");
        assert_eq!(
            encode_read_body(&decoded).unwrap(),
            bytes,
            "unknown field preserved"
        );
        if let ReadBody::Folder { unknown, .. } = &decoded {
            assert_eq!(unknown.len(), 1);
            assert_eq!(unknown[0].0, "futureField");
        } else {
            panic!("expected folder");
        }
    }

    #[test]
    fn invalid_kind_rejects() {
        let mut m = Map::new();
        m.insert("kind", Value::Text("directory".into()));
        m.insert("children", Value::Array(vec![]));
        m.insert("createdAt", Value::Unsigned(1));
        m.insert("modifiedAt", Value::Unsigned(2));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_read_body(&bytes).unwrap_err().check(),
            "invalid-node-kind"
        );
    }

    #[test]
    fn wrong_id_length_rejects() {
        let mut cm = Map::new();
        cm.insert("id", Value::Bytes(vec![0; 15]));
        cm.insert("name", Value::Text("x".into()));
        cm.insert("ipnsName", Value::Bytes(b"n".to_vec()));
        cm.insert("kind", Value::Text("file".into()));
        cm.insert("linkCounter", Value::Unsigned(0));
        let mut m = Map::new();
        m.insert("kind", Value::Text("folder".into()));
        m.insert("children", Value::Array(vec![Value::Map(cm)]));
        m.insert("createdAt", Value::Unsigned(1));
        m.insert("modifiedAt", Value::Unsigned(2));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_read_body(&bytes).unwrap_err().check(),
            "invalid-field-length"
        );
    }

    #[test]
    fn missing_kind_rejects() {
        let mut m = Map::new();
        m.insert("children", Value::Array(vec![]));
        m.insert("createdAt", Value::Unsigned(1));
        m.insert("modifiedAt", Value::Unsigned(2));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_read_body(&bytes).unwrap_err().check(),
            "missing-field"
        );
    }

    #[test]
    fn name_cmp_is_bytewise_total_order() {
        assert_eq!(name_cmp(b"a", b"a"), Ordering::Equal);
        assert_eq!(name_cmp(b"a", b"b"), Ordering::Less);
        assert_eq!(name_cmp(b"b", b"a"), Ordering::Greater);
        // Bytewise, not length-first: "aa" < "b".
        assert_eq!(name_cmp(b"aa", b"b"), Ordering::Less);
    }

    #[test]
    fn constructed_unknown_cannot_overwrite_typed_field() {
        // A folder whose public `unknown` list carries a key that collides with
        // a schema field must NOT overwrite the typed value on encode: typed
        // wins, so the bytes still decode as a folder.
        let body = ReadBody::Folder {
            created_at: 1,
            modified_at: 2,
            children: Vec::new(),
            unknown: vec![("kind".to_string(), Value::Text("file".into()))],
        };
        let bytes = encode_read_body(&body).unwrap();
        let decoded = decode_read_body(&bytes).expect("decodes");
        assert_eq!(
            decoded.kind(),
            NodeKind::Folder,
            "typed kind wins over unknown"
        );
    }

    #[test]
    fn validate_rejects_duplicate_children() {
        let dup = folder(vec![child(1, "a", b"ipns-a"), child(1, "b", b"ipns-b")]);
        assert_eq!(dup.validate().unwrap_err().check(), "duplicate-id");
        // A file (no children) always validates.
        let file = ReadBody::File {
            created_at: 1,
            modified_at: 2,
            versions: vec![Version::new(b"c".to_vec(), [0; 32], 1, 1)],
            unknown: Vec::new(),
        };
        assert!(file.validate().is_ok());
    }

    #[test]
    fn scrub_on_drop_guard_wipes_tree() {
        let mut value = Value::Array(vec![Value::Bytes(vec![0xab; 32])]);
        {
            let _guard = ScrubOnDrop(&mut value);
        }
        let items = value.as_array().unwrap();
        assert_eq!(
            items[0],
            Value::Bytes(Vec::new()),
            "guard's Drop scrubbed the tree"
        );
    }

    #[test]
    fn scrub_runs_when_encode_fails_closed() {
        // The guard's Drop must wipe the content-key copy on the error return
        // too, not just the Ok one. The secret rides item 0; the nest that trips
        // the release-active `MAX_DEPTH` bound rides item 1.
        let mut deep = Value::Null;
        for _ in 0..crate::codec::MAX_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        let mut value = Value::Array(vec![Value::Bytes(vec![0xab; 32]), deep]);

        let err = {
            let guard = ScrubOnDrop(&mut value);
            encode(guard.0).unwrap_err()
        };
        assert_eq!(err.check(), "depth-exceeded");

        let items = value.as_array().unwrap();
        assert_eq!(
            items[0],
            Value::Bytes(Vec::new()),
            "guard scrubbed the key copy on the error return"
        );
    }
}
