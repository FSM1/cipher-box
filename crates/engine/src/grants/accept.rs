//! The share-accept flow and the self-healing share bookmarks (blueprint/
//! engine.md "Grants and ledger — Accept flow", #25 D3).
//!
//! Trust flows from the resolved record and the verified [`Contact`], never the
//! untrusted pointer: the pointer only says *which name to resolve*, and the gate
//! re-verifies everything against the contact-anchored owner. The blinded-tag
//! ECDH peer is the verified contact's encryption subkey, not the pointer's
//! claimed `sharerPub`.
//!
//! Both share lists are self-healing bookmarks: the published metadata is
//! authority, so a re-accept heals a drifted permission, a rotated pointer read
//! key or a re-pointed scope-root name in place; only a byte-identical
//! re-accept is a true no-op. Persist durably before ack (the flow order lives
//! on [`accept_share`]).

use core::fmt;
use std::collections::BTreeMap;

use cipherbox_core::codec::{Map, RedactedBytes, RedactedText, Value, decode, encode_fixed_depth};
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{AadContext, Permission, STRUCT_TAG_GRANT_BLOB, open_grant_blob};
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::entropy::EntropyError;
use crate::gate::{Candidate, GateError, ReaderContext, RejectionReason, SeedBlob, adopt_deferred};
use crate::mailbox::VerifiedMailboxItem;
use crate::name::MAX_NODE_NAME_BYTES;
use crate::net::GrantedScopeRoot;
use crate::seams::{
    ContactLabel, FloorStore, Mailbox, SeamError, SharerScopedFloorStore, UnixMillis,
};

use super::contact::Contact;
use super::ledger::{PublishedGrantBlob, recipient_blinded_tag, self_locate};

/// The mailbox-delivered share pointer: which scope root to resolve and the
/// courtesy display fields. Opaque application bytes inside the HPKE seal; this
/// is app framing, not crypto. `sharer_identity_pk` is bound to the verified
/// contact before anything is trusted.
#[derive(Clone, PartialEq, Eq)]
pub struct SharePointer {
    /// The scope root's opaque `ipnsName` to resolve.
    pub scope_root_name: Vec<u8>,
    /// The sharer's (owner's) compressed secp256k1 identity key (SEC1) — bound
    /// to the contact-anchored identity on accept.
    pub sharer_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// A host display label (courtesy only).
    pub display_name: String,
    /// The advertised permission (courtesy; the committed ledger is authority).
    pub permission: Permission,
}

impl fmt::Debug for SharePointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharePointer")
            .field("scope_root_name", &RedactedBytes::of(&self.scope_root_name))
            .field(
                "sharer_identity_pk",
                &RedactedBytes::of(&self.sharer_identity_pk),
            )
            .field("display_name", &RedactedText::of(&self.display_name))
            .field("permission", &self.permission)
            .finish()
    }
}

impl SharePointer {
    /// Build a pointer the recipient's own vault can store.
    ///
    /// `display_name` is bounded release-active at [`MAX_NODE_NAME_BYTES`], the
    /// bound the recipient's received-shares codec rejects at in both
    /// directions (AGENTS.md rule 8). A pointer past it is one this build's own
    /// reader can never store and never ack, so it redelivers until its TTL.
    pub fn bounded(
        scope_root_name: Vec<u8>,
        sharer_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
        display_name: String,
        permission: Permission,
    ) -> Result<Self, TooLong> {
        within("displayName", display_name.len(), MAX_NODE_NAME_BYTES)?;
        Ok(Self {
            scope_root_name,
            sharer_identity_pk,
            display_name,
            permission,
        })
    }

    /// Encode to det-CBOR (canonical key order). Unknown fields are not carried:
    /// this is an engine-authored payload, not a re-sealed shared structure.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("displayName", Value::Text(self.display_name.clone()));
        m.insert(
            "permission",
            Value::Text(self.permission.as_wire().to_string()),
        );
        m.insert("scopeRootName", Value::Bytes(self.scope_root_name.clone()));
        m.insert(
            "sharerIdentityPk",
            Value::Bytes(self.sharer_identity_pk.to_vec()),
        );
        encode_fixed_depth(&Value::Map(m))
    }

    /// Decode a share pointer (strict det-CBOR). A missing/mistyped field or an
    /// unknown permission string is [`Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let value = decode(bytes)?;
        let map = value.as_map()?;
        let scope_root_name = req(map, "scopeRootName")?.as_bytes()?.to_vec();
        let sharer_identity_pk =
            fixed::<IDENTITY_PUBLIC_LEN>(req(map, "sharerIdentityPk")?, "sharerIdentityPk")?;
        let display_name = req(map, "displayName")?.as_text()?.to_string();
        let permission = Permission::from_wire(req(map, "permission")?.as_text()?)
            .ok_or(Malformed::InvalidPermission)?;
        Ok(Self {
            scope_root_name,
            sharer_identity_pk,
            display_name,
            permission,
        })
    }
}

/// A received share's identity: the scope id, under the sharer who granted it.
///
/// `scopeId` survives a `rotateScopeWrite` re-point while `ipnsName` does not,
/// so the id is the stable half. The sharer authors it and nothing outside its
/// own record binds it, so it identifies a scope only **under** that sharer.
/// Every per-share map and every durable per-share key uses this pair.
pub type BookmarkKey = ([u8; IDENTITY_PUBLIC_LEN], [u8; 16]);

/// Held by every writer of the received-shares list from its load to its
/// persist, so no writer persists over another's change.
pub(crate) type ReceivedSharesLock = futures_util::lock::Mutex<()>;

/// One received share in the recipient's own vault: the discovery fields plus
/// the persisted `pointerReadKey` (secret). Redacted `Debug`.
#[derive(Clone)]
pub struct ReceivedShare {
    /// The scope root's opaque `ipnsName`.
    pub scope_root_name: Vec<u8>,
    /// The accepted scope's id, as the gate-adopted record's envelope bound it
    /// ([`AcceptOutcome::scope_id`]). Persisted because a grantee cannot derive
    /// it from the name, and the grantee rotation arm addresses a scope by id
    /// ([`GrantedScopeRoots`](crate::rotation::GrantedScopeRoots)).
    pub scope_id: [u8; 16],
    /// The sharer's identity key.
    pub sharer_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// The host display label.
    pub display_name: String,
    /// The granted permission (from the resolved/committed grant).
    pub permission: Permission,
    /// The scope's stable pointer read key, persisted for scope-pointer resolve.
    /// Never public: no host frames a bookmark's secret.
    pub(crate) pointer_read_key: SecretBytes,
}

impl ReceivedShare {
    /// Borrow the persisted pointer read key.
    pub fn pointer_read_key(&self) -> &[u8; 32] {
        self.pointer_read_key.as_bytes()
    }

    /// This bookmark's [`BookmarkKey`].
    pub fn key(&self) -> BookmarkKey {
        (self.sharer_identity_pk, self.scope_id)
    }

    /// Whether two bookmarks for the same scope carry identical authority and
    /// discovery bytes — the "true no-op re-accept" test. A drift in the
    /// re-pointed scope-root name, the committed permission, the rotated pointer
    /// read key, or the courtesy display fields means the freshly-verified
    /// metadata is authority and the stored entry must self-heal to it.
    fn same_bookmark(&self, other: &ReceivedShare) -> bool {
        self.key() == other.key()
            && self.scope_root_name == other.scope_root_name
            && self.display_name == other.display_name
            && self.permission == other.permission
            && self.pointer_read_key == other.pointer_read_key
    }
}

impl fmt::Debug for ReceivedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedShare")
            .field("scope_root_name", &RedactedBytes::of(&self.scope_root_name))
            .field("scope_id", &self.scope_id)
            .field("display_name", &RedactedText::of(&self.display_name))
            .field("permission", &self.permission)
            .field("pointer_read_key", &"<redacted>")
            .finish()
    }
}

/// The link keys a bookmark reads through until a personal blob lands
/// (ADR 0024 D1, D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkHold {
    /// The invite secret, which re-derives both ephemeral halves.
    pub(crate) invite_secret: SecretBytes,
    /// The scope pointer the fragment named. The holder resolves it on every
    /// pass, so a write wave that moves the scope root does not strand it.
    pub scope_pointer_name: IpnsName,
    /// The deadline of the link entry the holder last verified, or `None`
    /// before any verified read or for a link with none.
    pub deadline: Option<UnixMillis>,
}

impl LinkHold {
    /// A hold on the link whose invite secret is `invite_secret`, before any
    /// verified read.
    pub(crate) fn new(invite_secret: SecretBytes, scope_pointer_name: IpnsName) -> Self {
        Self {
            invite_secret,
            scope_pointer_name,
            deadline: None,
        }
    }

    /// Whether `now` has reached the last verified deadline (ADR 0025 D5).
    pub fn is_expired(&self, now: UnixMillis) -> bool {
        now.reached(self.deadline)
    }
}

/// The recipient's received-shares list — a self-healing bookmark keyed by
/// [`ReceivedShare::key`]. The published metadata is the authority; this list
/// only speeds discovery, so a re-accept heals a drifted entry in place rather
/// than duplicating or keeping stale authority.
#[derive(Default)]
pub struct ReceivedSharesList {
    entries: Vec<ReceivedShare>,
    links: BTreeMap<BookmarkKey, LinkHold>,
}

impl ReceivedSharesList {
    /// An empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Where the bookmark under `key` sits, if one is held.
    fn position(&self, key: &BookmarkKey) -> Option<usize> {
        self.entries.iter().position(|e| e.key() == *key)
    }

    /// The bookmark under `key`, if one is held.
    pub fn find(&self, key: &BookmarkKey) -> Option<&ReceivedShare> {
        self.position(key).map(|i| &self.entries[i])
    }

    /// The link keys the bookmark under `key` reads through, if it holds any.
    pub fn link_hold(&self, key: &BookmarkKey) -> Option<&LinkHold> {
        self.links.get(key)
    }

    /// Read the bookmark under `key` through `hold`, replacing any hold it had.
    pub(crate) fn hold_link(&mut self, key: BookmarkKey, hold: LinkHold) {
        self.links.insert(key, hold);
    }

    /// Drop the link keys of the bookmark under `key`, returning them.
    pub(crate) fn drop_link(&mut self, key: &BookmarkKey) -> Option<LinkHold> {
        self.links.remove(key)
    }

    /// Record the deadline the link entry of the bookmark under `key` carried
    /// on its last verified read.
    pub(crate) fn set_link_deadline(&mut self, key: &BookmarkKey, deadline: Option<UnixMillis>) {
        if let Some(hold) = self.links.get_mut(key) {
            hold.deadline = deadline;
        }
    }

    /// Point the bookmark under `key` at the scope root its scope pointer
    /// names now.
    pub(crate) fn heal_root_name(&mut self, key: &BookmarkKey, scope_root_name: Vec<u8>) {
        if let Some(at) = self.position(key) {
            self.entries[at].scope_root_name = scope_root_name;
        }
    }

    /// Reconcile a freshly-verified share into the self-healing bookmark: append
    /// if absent, heal in place if the re-pointed scope-root name, the committed
    /// permission or the pointer read key drifted, no-op if byte-identical
    /// (blueprint/engine.md "self-healing bookmarks"). The returned
    /// [`Reconciled`] carries the pre-image [`revert`](Self::revert) needs if the
    /// durable persist then fails.
    pub(crate) fn reconcile(&mut self, share: ReceivedShare) -> Reconciled {
        match self.position(&share.key()) {
            None => {
                self.entries.push(share);
                Reconciled::Added
            }
            Some(i) if self.entries[i].same_bookmark(&share) => Reconciled::Unchanged,
            Some(i) => {
                let previous = core::mem::replace(&mut self.entries[i], share);
                Reconciled::Healed(Box::new(previous))
            }
        }
    }

    /// Undo a [`reconcile`](Self::reconcile) whose durable persist failed,
    /// restoring the list to its pre-accept state so a persist failure is
    /// redelivery-safe exactly like a gate failure (the in-memory bookmark never
    /// gets ahead of durable storage).
    fn revert(&mut self, key: &BookmarkKey, reconciled: Reconciled) {
        let Some(at) = self.position(key) else {
            return;
        };
        match reconciled {
            Reconciled::Added => {
                self.entries.remove(at);
                self.links.remove(key);
            }
            Reconciled::Healed(previous) => self.entries[at] = *previous,
            Reconciled::Unchanged => {}
        }
    }

    /// The scope roots this device can address by scope id — the caller-held
    /// pairing the grantee rotation arm borrows
    /// ([`GranteeRotationNet`](crate::net::GranteeRotationNet)), derived from the
    /// bookmark rather than cached beside it.
    ///
    /// Two exclusions, both fail-closed. A stored name that is not a well-formed
    /// IPNS name resolves nothing, so it names no rotation destination. And a
    /// scope id carried by more than one bookmark is **ambiguous**: the list is
    /// keyed by [`ReceivedShare::key`], so two sharers may each hold a bookmark
    /// for one id legitimately — but the rotation arm addresses a scope by id
    /// alone, so neither may answer, or a rotation would be aimed at whichever
    /// sorted first while the revokee on the other scope keeps a live seed.
    pub fn granted_scope_roots(&self) -> Vec<GrantedScopeRoot> {
        self.paired(|_| true)
    }

    /// Those same scope roots, restricted to the ones this device can **write**
    /// — the granted half of a sweep round. The lazy wave re-seals and
    /// republishes, so it is "runnable by any write-capable client"
    /// (blueprint/engine.md "sweep"); sweeping a read-only share could only fail
    /// to publish, once per cadence, forever.
    ///
    /// No production caller takes this half yet: the sweep still runs over the
    /// owner's own scopes alone.
    pub fn writable_scope_refs(&self) -> Vec<GrantedScopeRoot> {
        self.paired(|share| share.permission == Permission::Write)
    }

    /// Ambiguity is decided over **every** bookmark, before `keep` or name
    /// validity narrows the field: a claimant this call would discard still
    /// claims the id, and dropping it first would let the survivor answer for an
    /// id two sharers hold.
    fn paired(&self, keep: impl Fn(&ReceivedShare) -> bool) -> Vec<GrantedScopeRoot> {
        let mut claimed: Vec<&ReceivedShare> = self.entries.iter().collect();
        claimed.sort_by_key(|share| share.scope_id);
        claimed
            .chunk_by(|a, b| a.scope_id == b.scope_id)
            .filter(|run| run.len() == 1)
            .filter(|run| keep(run[0]))
            .filter_map(|run| {
                let text = core::str::from_utf8(&run[0].scope_root_name).ok()?;
                Some(GrantedScopeRoot {
                    scope_id: run[0].scope_id,
                    ipns_name: IpnsName::parse(text).ok()?,
                    sharer_identity_pk: run[0].sharer_identity_pk,
                })
            })
            .collect()
    }

    /// The bookmarked shares.
    pub fn iter(&self) -> impl Iterator<Item = &ReceivedShare> {
        self.entries.iter()
    }

    /// The number of bookmarked shares.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The stored-body grammar version this build writes and can read. Distinct
/// from the seal frame's version, which the blob carries: this one versions the
/// engine's list shape inside it.
///
/// The body is a frozen at-rest format. A renamed field or a changed width
/// orphans every stored list, and the mailbox items that delivered those shares
/// are acked — hence this constant and the byte vector pinning the encoding.
pub(crate) const STORED_LIST_V: u64 = 2;

/// The frozen bound on bookmarked shares, and on the two attacker-supplied
/// fields a bookmark carries verbatim from the mailbox pointer.
///
/// The stored list charges the host's staging budget
/// ([`StagingStore::staged_bytes_total`](crate::seams::StagingStore::staged_bytes_total)),
/// which admits every upload, so an unbounded `displayName` from a verified but
/// hostile contact would permanently shrink the vault's upload headroom. Bounded
/// release-active in both directions like every other repeated collection in a
/// sealed structure. The label's own bound is [`MAX_NODE_NAME_BYTES`], because
/// the graft renders it as a node name ([`crate::name`]) and a second bound one
/// byte wider would store a label the render tree could not carry.
pub const MAX_RECEIVED_SHARES: usize = 1024;
/// The bound on a bookmarked scope root's opaque `ipnsName`.
pub(crate) const MAX_SCOPE_ROOT_NAME_BYTES: usize = 128;

/// A collection or field past its frozen bound. Shared by the grants layer's
/// bounded collections: the stored-body codecs, which all enforce their bounds
/// in both directions (AGENTS.md rule 8), the grafted claim record, and the
/// share pointer's own builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooLong {
    /// Which bounded field breached.
    pub field: &'static str,
    /// The length found.
    pub len: usize,
    /// The frozen bound.
    pub limit: usize,
}

impl fmt::Display for TooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { field, len, limit } = self;
        write!(f, "{field} is {len}, past its bound {limit}")
    }
}

/// A bound both codec directions enforce.
pub(super) fn within(field: &'static str, len: usize, limit: usize) -> Result<(), TooLong> {
    if len > limit {
        return Err(TooLong { field, len, limit });
    }
    Ok(())
}

/// Encode the durable received-shares body to det-CBOR, entries in
/// [`ReceivedShare::key`] order so one list has one spelling.
///
/// Rejects a duplicate key release-active, the invariant [`decode_stored_list`]
/// hard-rejects (AGENTS.md rule 8): a list with two bookmarks for one sharer's
/// scope has no defined authority, and emitting one would durably store bytes
/// this build's own reader refuses.
pub(crate) fn encode_stored_list(
    shares: &ReceivedSharesList,
) -> Result<Zeroizing<Vec<u8>>, ReceivedSharesCodecError> {
    let mut sorted: Vec<&ReceivedShare> = shares.entries.iter().collect();
    sorted.sort_by_key(|share| share.key());
    if sorted.windows(2).any(|pair| pair[0].key() == pair[1].key()) {
        return Err(ReceivedSharesCodecError::DuplicateScope);
    }
    within("shares", sorted.len(), MAX_RECEIVED_SHARES)?;
    for share in &sorted {
        within("displayName", share.display_name.len(), MAX_NODE_NAME_BYTES)?;
        within(
            "scopeRootName",
            share.scope_root_name.len(),
            MAX_SCOPE_ROOT_NAME_BYTES,
        )?;
    }
    let encoded_shares = sorted
        .into_iter()
        .map(|share| {
            let mut m = Map::new();
            m.insert("displayName", Value::Text(share.display_name.clone()));
            if let Some(hold) = shares.links.get(&share.key()) {
                if let Some(deadline) = hold.deadline {
                    m.insert("linkDeadline", Value::Unsigned(deadline.0));
                }
                m.insert(
                    "linkSecret",
                    Value::Bytes(hold.invite_secret.as_bytes().to_vec()),
                );
                m.insert(
                    "scopePointerName",
                    Value::Text(hold.scope_pointer_name.as_str().to_owned()),
                );
            }
            m.insert(
                "permission",
                Value::Text(share.permission.as_wire().to_string()),
            );
            m.insert(
                "pointerReadKey",
                Value::Bytes(share.pointer_read_key().to_vec()),
            );
            m.insert("scopeId", Value::Bytes(share.scope_id.to_vec()));
            m.insert("scopeRootName", Value::Bytes(share.scope_root_name.clone()));
            m.insert(
                "sharerIdentityPk",
                Value::Bytes(share.sharer_identity_pk.to_vec()),
            );
            Value::Map(m)
        })
        .collect();
    let mut body = Map::new();
    body.insert("shares", Value::Array(encoded_shares));
    body.insert("v", Value::Unsigned(STORED_LIST_V));
    // Terminal owner of the transient tree: it holds a verbatim copy of
    // every bookmark's pointer read key and link secret.
    let mut tree = Value::Map(body);
    let encoded = Zeroizing::new(encode_fixed_depth(&tree));
    tree.zeroize_bytes();
    Ok(encoded)
}

/// Decode a stored body (strict det-CBOR). A missing/mistyped field, an
/// unknown key, an unreadable version, or a duplicate scope root is a
/// [`ReceivedSharesCodecError`].
pub(crate) fn decode_stored_list(
    bytes: &[u8],
) -> Result<ReceivedSharesList, ReceivedSharesCodecError> {
    let mut tree = decode(bytes)?;
    let decoded = read_stored_list(&tree);
    // Terminal owner of the decoded tree: every pointer read key inside is
    // wiped on every exit, the early returns a malformed body takes included.
    tree.zeroize_bytes();
    decoded
}

fn read_stored_list(tree: &Value) -> Result<ReceivedSharesList, ReceivedSharesCodecError> {
    let map = tree.as_map()?;
    reject_unknown(map, &["shares", "v"])?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != STORED_LIST_V {
        return Err(ReceivedSharesCodecError::UnsupportedVersion { version });
    }
    let raw = req(map, "shares")?.as_array()?;
    within("shares", raw.len(), MAX_RECEIVED_SHARES)?;
    let mut entries: Vec<ReceivedShare> = Vec::with_capacity(raw.len());
    let mut links = BTreeMap::new();
    for item in raw {
        let share = item.as_map()?;
        reject_unknown(
            share,
            &[
                "displayName",
                "linkDeadline",
                "linkSecret",
                "permission",
                "pointerReadKey",
                "scopeId",
                "scopePointerName",
                "scopeRootName",
                "sharerIdentityPk",
            ],
        )?;
        let scope_root_name = req(share, "scopeRootName")?.as_bytes()?.to_vec();
        within(
            "scopeRootName",
            scope_root_name.len(),
            MAX_SCOPE_ROOT_NAME_BYTES,
        )?;
        let display_name = req(share, "displayName")?.as_text()?.to_string();
        within("displayName", display_name.len(), MAX_NODE_NAME_BYTES)?;
        let decoded = ReceivedShare {
            sharer_identity_pk: fixed::<IDENTITY_PUBLIC_LEN>(
                req(share, "sharerIdentityPk")?,
                "sharerIdentityPk",
            )?,
            display_name,
            permission: Permission::from_wire(req(share, "permission")?.as_text()?)
                .ok_or(Malformed::InvalidPermission)?,
            pointer_read_key: SecretBytes::new(fixed::<32>(
                req(share, "pointerReadKey")?,
                "pointerReadKey",
            )?),
            scope_id: fixed::<16>(req(share, "scopeId")?, "scopeId")?,
            scope_root_name,
        };
        let key = decoded.key();
        if entries.iter().any(|e| e.key() == key) {
            return Err(ReceivedSharesCodecError::DuplicateScope);
        }
        if let Some(hold) = read_link_hold(share)? {
            links.insert(key, hold);
        }
        entries.push(decoded);
    }
    Ok(ReceivedSharesList { entries, links })
}

/// The optional link keys of one stored bookmark. `linkSecret` and
/// `scopePointerName` come as a pair, and `linkDeadline` only with them; a
/// bookmark without `linkSecret` is a personal one.
fn read_link_hold(share: &Map) -> Result<Option<LinkHold>, CodecError> {
    let Some(secret) = share.get("linkSecret") else {
        if share.get("scopePointerName").is_some() || share.get("linkDeadline").is_some() {
            return Err(Malformed::MissingField {
                field: "linkSecret",
            }
            .into());
        }
        return Ok(None);
    };
    let scope_pointer_name = IpnsName::parse(req(share, "scopePointerName")?.as_text()?)?;
    let deadline = share
        .get("linkDeadline")
        .map(|value| value.as_unsigned().map(UnixMillis))
        .transpose()?;
    let bytes = Zeroizing::new(fixed::<32>(secret, "linkSecret")?);
    Ok(Some(LinkHold {
        invite_secret: SecretBytes::new(*bytes),
        scope_pointer_name,
        deadline,
    }))
}

/// Why encoding or decoding a stored received-shares body failed.
///
/// Engine-owned rather than a bare [`CodecError`] so a check this format needs
/// does not extend core's frozen `Malformed` registry, whose names the KAT
/// manifest pins.
#[derive(Debug)]
pub enum ReceivedSharesCodecError {
    /// The det-CBOR framing was malformed.
    Codec(CodecError),
    /// The stored blob did not open under this session's `enc-subkey` as a
    /// `received-shares` blob — tampered, another identity's, or another
    /// owner-local store's.
    DidNotOpen(CodecError),
    /// Two bookmarks named one sharer's scope — a list with no defined
    /// authority for that scope, refused in both directions (AGENTS.md rule 8).
    ///
    /// A pre-cutover list can trip this: the key was the scope-root name then,
    /// so a re-pointed scope left two entries this key refuses. Under the
    /// greenfield rule such a store is forgotten, never upgraded.
    DuplicateScope,
    /// A stored body written at a grammar version this build does not read.
    /// Never treated as empty: the bookmarks are there, this build just cannot
    /// interpret them.
    UnsupportedVersion {
        /// The version the stored body declared.
        version: u64,
    },
    /// A collection or field past its frozen bound.
    TooLong(TooLong),
}

impl fmt::Display for ReceivedSharesCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceivedSharesCodecError::Codec(e) => write!(f, "received-shares codec: {e}"),
            ReceivedSharesCodecError::DidNotOpen(e) => {
                write!(f, "received-shares list did not open: {}", e.check())
            }
            ReceivedSharesCodecError::DuplicateScope => {
                f.write_str("received-shares list names one sharer's scope twice")
            }
            ReceivedSharesCodecError::UnsupportedVersion { version } => {
                write!(f, "received-shares body version {version} is not readable")
            }
            ReceivedSharesCodecError::TooLong(e) => write!(f, "received-shares {e}"),
        }
    }
}

impl std::error::Error for ReceivedSharesCodecError {}

impl From<TooLong> for ReceivedSharesCodecError {
    fn from(e: TooLong) -> Self {
        ReceivedSharesCodecError::TooLong(e)
    }
}

impl<E: Into<CodecError>> From<E> for ReceivedSharesCodecError {
    fn from(e: E) -> Self {
        ReceivedSharesCodecError::Codec(e.into())
    }
}

/// Reject any key outside `known` — this build wrote the bytes, so a key it does
/// not emit is not a list it may act on.
pub(super) fn reject_unknown(map: &Map, known: &[&str]) -> Result<(), CodecError> {
    match map
        .entries()
        .iter()
        .find(|(key, _)| !known.contains(&key.as_str()))
    {
        Some((key, _)) => Err(Malformed::UnknownRecordField { key: key.clone() }.into()),
        None => Ok(()),
    }
}

/// What reconciling a freshly-verified grant did to the received-shares
/// bookmark — the durable action the accept flow must persist before it acks.
pub(crate) enum Reconciled {
    /// No entry existed for the scope; a new bookmark was appended.
    Added,
    /// An entry existed but its authority or pointer key had drifted; it was
    /// healed in place. Carries the pre-image for [`ReceivedSharesList::revert`].
    Healed(Box<ReceivedShare>),
    /// A byte-identical entry already existed; nothing changed and no durable
    /// write is needed.
    Unchanged,
}

impl Reconciled {
    /// Whether this reconcile changed durable state (so a persist is required
    /// before the ack). Only a byte-identical re-accept is a true no-op.
    fn is_durable_change(&self) -> bool {
        !matches!(self, Reconciled::Unchanged)
    }
}

/// Durable persistence for the recipient's received-shares bookmark — what the
/// accept flow writes through before it acks the mailbox item.
///
/// Both the ack and the durable sequence-floor advance happen **only** after
/// [`persist`](Self::persist) returns `Ok` (blueprint/engine.md "Mailbox logic —
/// ack after durable"): a floor that advanced ahead of a failed persist would
/// strand the share below it forever. Persist-fail returns un-acked with the
/// floor untouched, so the item redelivers and re-accepts idempotently (the
/// bookmark self-heals).
///
/// A grants-layer contract rather than a tenth host seam, on the
/// [`RetireLedger`](crate::seams::RetireLedger) shape: the engine ships
/// [`StagingReceivedShareStore`](super::StagingReceivedShareStore) over the
/// durable [`StagingStore`](crate::seams::StagingStore) every host already
/// implements, so a host supplies one only if it has a better backing.
///
/// [`persist`](Self::persist) replaces the **whole** list, so exactly one live
/// list per store is a caller invariant: two lists loaded independently and
/// persisted in turn silently erase each other, and the mailbox items behind the
/// lost bookmarks are already acked.
pub trait ReceivedShareStore {
    /// Durably persist the whole received-shares list. A failure means the
    /// accept flow does not ack.
    async fn persist(&self, shares: &ReceivedSharesList) -> Result<(), ReceivedShareStoreError>;

    /// The persisted list, or an empty one on a backing that holds none.
    ///
    /// Fail-closed on bytes it cannot read: an acked mailbox item is gone, so a
    /// stored list this build cannot open is unrecoverable state, and reporting
    /// it as empty would let the next [`persist`](Self::persist) overwrite every
    /// bookmark behind it.
    async fn load(&self) -> Result<ReceivedSharesList, ReceivedShareStoreError>;
}

/// Why a received-shares store operation failed.
///
/// The split that matters is [`Seam`](Self::Seam) — the backing could not be
/// reached, so retry — against [`Unreadable`](Self::Unreadable), a fail-closed
/// verdict on bytes that *are* there. Retrying that one never converges, and a
/// host that treats it as an outage hides an attack signal. The owner-local
/// stores all classify on this shape so one of them cannot drift into reporting
/// a trust violation as availability (ADR 0006).
#[derive(Debug)]
pub enum ReceivedShareStoreError {
    /// Stored bytes this build cannot read as a received-shares list. Never
    /// reported as an empty list: the next persist would overwrite bookmarks it
    /// never saw, and the mailbox items that delivered them are acked and gone.
    Unreadable(ReceivedSharesCodecError),
    /// The list to persist holds more than [`MAX_RECEIVED_SHARES`]. The stored
    /// bytes are fine — the offered list is the one past the bound.
    Full,
    /// The offered list is not one this build may store: two bookmarks for one
    /// sharer's scope, or a field past its bound. A write-path refusal, so never
    /// [`Unreadable`](Self::Unreadable) — nothing was read.
    Encode(ReceivedSharesCodecError),
    /// Entropy acquisition failed, so no list is sealed and none is written.
    Entropy(EntropyError),
    /// Sealing the list for storage failed.
    Seal(CodecError),
    /// The durable backing failed.
    Seam(SeamError),
}

impl fmt::Display for ReceivedShareStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceivedShareStoreError::Unreadable(e) => {
                write!(f, "the stored list is unreadable: {e}")
            }
            ReceivedShareStoreError::Full => write!(
                f,
                "the received-shares list already holds {MAX_RECEIVED_SHARES} bookmarks"
            ),
            ReceivedShareStoreError::Encode(e) => write!(f, "the list cannot be stored: {e}"),
            ReceivedShareStoreError::Entropy(e) => write!(f, "received-shares: {e}"),
            ReceivedShareStoreError::Seal(e) => {
                write!(f, "received-shares seal failed: {}", e.check())
            }
            ReceivedShareStoreError::Seam(e) => write!(f, "received-shares: {e}"),
        }
    }
}

impl std::error::Error for ReceivedShareStoreError {}

impl From<SeamError> for ReceivedShareStoreError {
    fn from(e: SeamError) -> Self {
        ReceivedShareStoreError::Seam(e)
    }
}

/// One owner-side sent-share record — the denormalized index the owner keeps.
#[derive(Clone, PartialEq, Eq)]
pub struct SentShare {
    /// The scope root shared.
    pub scope_root_name: Vec<u8>,
    /// The recipient's identity key.
    pub recipient_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// The permission granted.
    pub permission: Permission,
}

impl fmt::Debug for SentShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SentShare")
            .field("scope_root_name", &RedactedBytes::of(&self.scope_root_name))
            .field(
                "recipient_identity_pk",
                &RedactedBytes::of(&self.recipient_identity_pk),
            )
            .field("permission", &self.permission)
            .finish()
    }
}

/// The owner's denormalized sent-index — a self-healing bookmark keyed by
/// `(scope-root name, recipient)`.
#[derive(Default)]
pub struct SentIndex {
    entries: Vec<SentShare>,
}

impl SentIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sent share, idempotent by `(scope-root name, recipient)`.
    /// Returns `true` if newly recorded.
    pub fn record(&mut self, share: SentShare) -> bool {
        if self.entries.iter().any(|e| {
            e.scope_root_name == share.scope_root_name
                && e.recipient_identity_pk == share.recipient_identity_pk
        }) {
            return false;
        }
        self.entries.push(share);
        true
    }

    /// The recorded sent shares.
    pub fn iter(&self) -> impl Iterator<Item = &SentShare> {
        self.entries.iter()
    }

    /// The number of recorded sent shares.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The result of a successful accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptOutcome {
    /// The accepted scope's id.
    pub scope_id: [u8; 16],
    /// The gate-adopted record sequence.
    pub sequence: u64,
    /// The granted permission (from the resolved record's committed grant view).
    pub permission: Permission,
    /// `true` if this accept newly bookmarked the share (`false` on re-accept).
    pub newly_added: bool,
}

/// Why an accept failed. Every arm is fail-closed and leaves the mailbox item
/// **un-acked**, so nothing is dropped before it is durable.
#[derive(Debug)]
pub enum AcceptError {
    /// The pointer bytes were malformed.
    MalformedPointer(CodecError),
    /// The mailbox sender identity is not this contact — a mis-anchored item.
    SenderNotContact,
    /// The pointer's `sharerPub` does not match the contact-anchored identity.
    SharerMismatch,
    /// The resolved record's name is not the scope root the pointer named — a
    /// mis-paired pointer/record. KDF tag-binding already fails closed on this,
    /// so this is a defense-in-depth early reject.
    NameMismatch,
    /// The record names this vault's own root scope. `scopeId` is authored by
    /// the sharer and bound to nothing outside its own record, so a sender who
    /// mints a scope root at the anchor would have this device adopt a foreign
    /// record as its own vault — its durable floors, its render tree, and the
    /// seed its own writes seal under. No share may ever name it.
    OwnVaultScope,
    /// The sharer's contact encryption subkey is non-contributory — an unusable
    /// key for the blinded-tag ECDH.
    UnusableSharerKey,
    /// No grant blob at your tag on a resolved record — the revocation signal.
    NoBlobAtTag,
    /// A blob exists at your tag but the owner-signed commitment does not commit
    /// that tag — an uncommitted grant, never trusted (core grant.rs: a recipient
    /// verifies its tag is committed before trusting a grant).
    UncommittedTag,
    /// Opening the located grant blob failed (tamper/wrong key).
    GrantBlobOpen(CodecError),
    /// The adoption gate rejected the resolved record.
    Gate(GateError),
    /// Durably persisting the updated received-shares list failed — the item is
    /// left un-acked (never acked before durable), so it redelivers and
    /// re-accepts idempotently. Nothing was lost; whether a redelivery can ever
    /// land is the [`ReceivedShareStoreError`] variant's answer.
    Persist(ReceivedShareStoreError),
    /// Acking the item failed after the durable persist (the share IS recorded;
    /// the item will redeliver and re-accept idempotently).
    Ack(SeamError),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcceptError::MalformedPointer(e) => write!(f, "malformed share pointer: {e}"),
            AcceptError::SenderNotContact => f.write_str("mailbox sender is not the contact"),
            AcceptError::SharerMismatch => f.write_str("pointer sharerPub is not the contact"),
            AcceptError::NameMismatch => {
                f.write_str("resolved record name is not the pointer's scope root")
            }
            AcceptError::OwnVaultScope => {
                f.write_str("the record names this vault's own root scope")
            }
            AcceptError::UnusableSharerKey => f.write_str("sharer contact key is non-contributory"),
            AcceptError::NoBlobAtTag => f.write_str("no grant blob at tag (revocation signal)"),
            AcceptError::UncommittedTag => f.write_str("tag is not in the owner-signed commitment"),
            AcceptError::GrantBlobOpen(e) => write!(f, "grant blob open failed: {e}"),
            AcceptError::Gate(e) => write!(f, "adoption gate rejected: {e}"),
            AcceptError::Persist(e) => write!(f, "durable persist failed before ack: {e}"),
            AcceptError::Ack(e) => write!(f, "ack failed after durable persist: {e}"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Run the accept flow for one sender-verified mailbox item against a resolved
/// scope-root record.
///
/// Order is load-bearing: bind the pointer to the contact, self-locate the blob,
/// unseal the seeds, run the gate, reconcile the received-shares list,
/// **durably persist it via [`ReceivedShareStore`]**, and **only then** ack. Any
/// failure before the durable persist returns without acking; a persist failure
/// rolls the in-memory bookmark back and returns un-acked, so an undelivered
/// accept redelivers and re-runs idempotently (the bookmark self-heals). If a
/// redelivery's strict-sequence anti-replay reject, at exactly the floor, names a
/// scope already in the durable bookmark (a prior ack that failed after the
/// floor advanced), the flow idempotently re-acks that item without re-adopting
/// — clearing a mailbox item that could otherwise redeliver forever.
///
/// `candidate` is the resolved record (hand-fed here; the resolve pipeline is a
/// sibling slice); `grant_blobs` is its published grant section for self-
/// location. `vault_root_scope` is this session's own root scope, which no
/// received share may name ([`AcceptError::OwnVaultScope`]). `received` must be
/// the list `store` handed out — see [`ReceivedShareStore`] for why one live
/// list per store is a caller invariant.
#[allow(clippy::too_many_arguments)]
pub async fn accept_share<F: FloorStore, M: Mailbox, S: ReceivedShareStore>(
    floors: &F,
    mailbox: &M,
    store: &S,
    item: &VerifiedMailboxItem,
    contact: &Contact,
    my_enc_secret: &X25519Secret,
    contact_label_seed: &SecretBytes,
    candidate: &Candidate,
    grant_blobs: &[PublishedGrantBlob],
    vault_root_scope: &[u8; 16],
    received: &mut ReceivedSharesList,
) -> Result<AcceptOutcome, AcceptError> {
    let pointer = SharePointer::decode(&item.payload).map_err(AcceptError::MalformedPointer)?;

    // Bind the untrusted pointer to the verified contact: the mailbox sender and
    // the pointer's sharerPub must both be the contact-anchored owner identity.
    let owner_identity = contact.identity_pk();
    if item.sender_identity != owner_identity {
        return Err(AcceptError::SenderNotContact);
    }
    if pointer.sharer_identity_pk != owner_identity.to_sec1() {
        return Err(AcceptError::SharerMismatch);
    }

    // The resolved record must be the scope root the pointer named. The blinded
    // tag folds the name in, so a mis-paired record already fails closed at the
    // gate (NoBlobAtTag) — bind it explicitly so it is a named reject, not an
    // opaque miss.
    if candidate.name.as_str().as_bytes() != pointer.scope_root_name.as_slice() {
        return Err(AcceptError::NameMismatch);
    }
    // Before the gate, which keys its durable floors on this very scope id.
    if &candidate.envelope.scope == vault_root_scope {
        return Err(AcceptError::OwnVaultScope);
    }

    // Self-locate: the ECDH peer is the VERIFIED contact enc subkey, never the
    // pointer's word for it.
    let tag = recipient_blinded_tag(
        my_enc_secret,
        &contact.enc_subkey(),
        &pointer.scope_root_name,
    )
    .ok_or(AcceptError::UnusableSharerKey)?;
    let blob = self_locate(grant_blobs, &tag).ok_or(AcceptError::NoBlobAtTag)?;

    // A blob at your tag is not enough: the tag must be in the owner-signed
    // commitment, whose permission — not the untrusted pointer's — is authority.
    let permission = candidate
        .grant_section
        .commitment
        .entries
        .iter()
        .find(|e| e.tag == tag)
        .map(|e| e.permission)
        .ok_or(AcceptError::UncommittedTag)?;

    // Unseal the grant blob under the reader's own enc secret, then derive the
    // read key from the recovered read scope seed.
    let grant_aad = AadContext {
        v: candidate.envelope.v,
        id: candidate.envelope.id,
        scope: candidate.envelope.scope,
        epoch: candidate.envelope.epoch,
        struct_tag: STRUCT_TAG_GRANT_BLOB,
    };
    let grant = open_grant_blob(my_enc_secret, &blob.enc, &grant_aad, &blob.ciphertext)
        .map_err(AcceptError::GrantBlobOpen)?;
    let node_seed = kdf::node_seed(grant.read_scope_seed(), &candidate.envelope.id);
    // The derived read key is secret and this fn is its terminal owner.
    let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());

    let reader = ReaderContext {
        owner_identity: &owner_identity,
        scope_id: candidate.envelope.scope,
        read_key: &read_key,
        parent_node_seed: None,
        seed_blob: Some(SeedBlob::Grantee {
            enc_secret: my_enc_secret,
            enc: blob.enc,
            ciphertext: blob.ciphertext.clone(),
            aad: grant_aad,
        }),
    };
    let bookmark_key: BookmarkKey = (pointer.sharer_identity_pk, candidate.envelope.scope);
    let floors = &SharerScopedFloorStore::granted_by(
        floors,
        ContactLabel::of(contact_label_seed, &pointer.sharer_identity_pk),
    );

    // Gate the record but DEFER the floor-law advance so the durable sequence
    // floor never moves ahead of the bookmark it accepts (see `PendingAdoption`).
    // The write-grantee seed the gate surfaces is dropped (the `_`): the focus
    // leg recovers it from this same blob on every pass
    // ([`ReceivedShareStatus::open`](super::received_status)), so keeping it
    // would only store a capability at rest that outlives the grant.
    let pending = match adopt_deferred(floors, &reader, candidate).await {
        Ok((pending, _)) => pending,
        Err(e) => {
            // Idempotent ack-only short-circuit. The record at exactly the
            // sequence floor, for a scope we ALREADY durably hold **under this
            // sharer**, is a redelivery whose floor advance already committed
            // (e.g. a prior ack failed): the bookmark is proof of prior
            // adoption, so just re-ack and never re-adopt or downgrade it. A
            // record below the floor (a replay), any OTHER rejection, a scope
            // this sharer did not grant us, or a retryable `GateError::Seam`
            // (whose `rejection()` is `None`) falls through and propagates
            // unchanged — anti-replay stays intact.
            if let Some(RejectionReason::SequenceNotNewer { floor, sequence }) =
                e.rejection().map(|r| &r.reason)
                && sequence == floor
            {
                if let Some(permission) = received.find(&bookmark_key).map(|s| s.permission) {
                    mailbox.ack(&item.item_id).await.map_err(AcceptError::Ack)?;
                    return Ok(AcceptOutcome {
                        scope_id: candidate.envelope.scope,
                        sequence: *floor,
                        permission,
                        newly_added: false,
                    });
                }
            }
            return Err(AcceptError::Gate(e));
        }
    };

    let reconciled = received.reconcile(ReceivedShare {
        scope_root_name: pointer.scope_root_name.clone(),
        scope_id: candidate.envelope.scope,
        sharer_identity_pk: pointer.sharer_identity_pk,
        display_name: pointer.display_name.clone(),
        permission,
        pointer_read_key: SecretBytes::new(*grant.pointer_read_key()),
    });
    let newly_added = matches!(reconciled, Reconciled::Added);
    // A personal blob opened, so the link keys go (ADR 0024 D2).
    let dropped_link = received.drop_link(&bookmark_key);

    // Persist durably BEFORE the floor advance and the ack; a failure rolls the
    // in-memory bookmark back and returns un-acked, so the item redelivers.
    if reconciled.is_durable_change() || dropped_link.is_some() {
        if let Err(e) = store.persist(received).await {
            received.revert(&bookmark_key, reconciled);
            if let Some(hold) = dropped_link {
                received.hold_link(bookmark_key, hold);
            }
            return Err(AcceptError::Persist(e));
        }
    }

    // The bookmark is durable — now commit the deferred floor advance, then ack.
    let adopted = pending
        .commit(floors)
        .await
        .map_err(|e| AcceptError::Gate(GateError::Seam(e)))?;
    mailbox.ack(&item.item_id).await.map_err(AcceptError::Ack)?;

    Ok(AcceptOutcome {
        scope_id: candidate.envelope.scope,
        sequence: adopted.sequence,
        permission,
        newly_added,
    })
}

/// A required map field, or [`Malformed::MissingField`].
pub(super) fn req<'a>(map: &'a Map, field: &'static str) -> Result<&'a Value, CodecError> {
    map.get(field)
        .ok_or_else(|| Malformed::MissingField { field }.into())
}

/// A fixed-length byte field, or [`Malformed::InvalidFieldLength`].
pub(super) fn fixed<const N: usize>(v: &Value, field: &'static str) -> Result<[u8; N], CodecError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::codec::encode;
    use cipherbox_core::suite::secret::ct_eq;

    fn pointer() -> SharePointer {
        SharePointer {
            scope_root_name: b"k51scoperoot".to_vec(),
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "Shared Folder".to_string(),
            permission: Permission::Read,
        }
    }

    /// A scope root's `ipnsName` is user content, and a peer's identity key is a
    /// stable cross-service identifier for a third party — the ground
    /// [`SharingContact`](crate::SharingContact) already withholds one on.
    #[test]
    fn share_pointer_debug_withholds_the_scope_root_name_and_the_label() {
        let p = pointer();
        let rendered = format!("{p:?}");

        let unredacted = format!("{:?}", p.scope_root_name);
        assert!(
            !rendered.contains(&unredacted),
            "the scope root name never renders: {rendered}"
        );
        assert!(
            !rendered.contains("k51scoperoot"),
            "nor any text rendering of it: {rendered}"
        );
        assert!(
            !rendered.contains(&p.display_name),
            "the label never renders: {rendered}"
        );
        let key = format!("{:?}", p.sharer_identity_pk);
        assert!(
            !rendered.contains(&key),
            "nor the peer's identity key: {rendered}"
        );
        assert!(rendered.contains("SharePointer"), "the shape survives");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn share_pointer_round_trips_byte_stable() {
        let p = pointer();
        let bytes = p.encode();
        let decoded = SharePointer::decode(&bytes).expect("decodes");
        assert_eq!(decoded, p);
        assert_eq!(decoded.encode(), bytes, "byte-stable");
    }

    #[test]
    fn share_pointer_rejects_bad_permission() {
        let mut m = decode(&pointer().encode())
            .unwrap()
            .as_map()
            .unwrap()
            .clone();
        m.insert("permission", Value::Text("admin".into()));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            SharePointer::decode(&bytes).unwrap_err().check(),
            "invalid-permission"
        );
    }

    #[test]
    fn reconcile_appends_then_no_ops_a_byte_identical_reaccept() {
        let mut list = ReceivedSharesList::new();
        let share = ReceivedShare {
            scope_root_name: b"n".to_vec(),
            scope_id: [0x5c; 16],
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "s".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([0x8A; 32]),
        };
        assert!(matches!(list.reconcile(share.clone()), Reconciled::Added));
        assert!(
            matches!(list.reconcile(share), Reconciled::Unchanged),
            "a byte-identical re-accept is a true no-op"
        );
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn reconcile_self_heals_changed_permission_and_rotated_pointer_key() {
        let mut list = ReceivedSharesList::new();
        let base = ReceivedShare {
            scope_root_name: b"n".to_vec(),
            scope_id: [0x5c; 16],
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "s".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([0x8A; 32]),
        };
        assert!(matches!(list.reconcile(base.clone()), Reconciled::Added));

        // Same scope, but the committed permission and pointer key drifted: the
        // stored entry heals to the new values, never keeps the stale ones.
        let healed = ReceivedShare {
            permission: Permission::Write,
            pointer_read_key: SecretBytes::new([0x9C; 32]),
            ..base
        };
        assert!(matches!(list.reconcile(healed), Reconciled::Healed(_)));
        assert_eq!(list.len(), 1);
        let stored = list.iter().next().unwrap();
        assert_eq!(stored.permission, Permission::Write);
        assert!(
            ct_eq(stored.pointer_read_key(), &[0x9C; 32]),
            "pointer read key mismatch"
        );
    }

    #[test]
    fn revert_restores_an_added_then_a_healed_bookmark() {
        let mut list = ReceivedSharesList::new();
        let base = ReceivedShare {
            scope_root_name: b"n".to_vec(),
            scope_id: [0x5c; 16],
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "s".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([0x8A; 32]),
        };
        let key = base.key();

        // Revert an append → the list is empty again (persist-failure rollback).
        let added = list.reconcile(base.clone());
        assert!(matches!(added, Reconciled::Added));
        list.revert(&key, added);
        assert!(list.is_empty());

        // Revert a heal → the stored entry returns to its pre-heal values.
        assert!(matches!(list.reconcile(base.clone()), Reconciled::Added));
        let healed = list.reconcile(ReceivedShare {
            permission: Permission::Write,
            pointer_read_key: SecretBytes::new([0x9C; 32]),
            ..base
        });
        assert!(matches!(healed, Reconciled::Healed(_)));
        list.revert(&key, healed);
        let stored = list.iter().next().unwrap();
        assert_eq!(
            stored.permission,
            Permission::Read,
            "healed field rolled back"
        );
        assert!(
            ct_eq(stored.pointer_read_key(), &[0x8A; 32]),
            "pointer read key mismatch"
        );
    }

    fn share(scope_root_name: &[u8], key_byte: u8) -> ReceivedShare {
        ReceivedShare {
            scope_root_name: scope_root_name.to_vec(),
            scope_id: [key_byte; 16],
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "s".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([key_byte; 32]),
        }
    }

    fn share_at(scope_id: [u8; 16], name: &IpnsName, permission: Permission) -> ReceivedShare {
        ReceivedShare {
            scope_root_name: name.as_str().as_bytes().to_vec(),
            scope_id,
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "s".into(),
            permission,
            pointer_read_key: SecretBytes::new([0x8A; 32]),
        }
    }

    /// The same bookmark under a second sharer — the only way one scope id ends
    /// up claimed twice, since one sharer's re-point heals its entry in place.
    fn from_another_sharer(mut share: ReceivedShare) -> ReceivedShare {
        share.sharer_identity_pk = [0x03; IDENTITY_PUBLIC_LEN];
        share
    }

    fn a_name(seed: u8) -> IpnsName {
        IpnsName::from_public_key(
            &cipherbox_core::suite::ed25519::Ed25519Signer::from_seed([seed; 32]).verifying_key(),
        )
    }

    /// A `rotateScopeWrite` re-point moves the scope root to a freshly derived
    /// name. The bookmark is keyed by the scope id under its sharer, so the new
    /// pointer heals the entry rather than adding a second one that would make
    /// the id ambiguous and stall the rotation arm.
    #[test]
    fn a_repointed_scope_root_heals_its_bookmark_in_place() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share_at([0x5c; 16], &a_name(0x31), Permission::Write));

        let repointed = list.reconcile(share_at([0x5c; 16], &a_name(0x32), Permission::Write));

        assert!(matches!(repointed, Reconciled::Healed(_)));
        assert_eq!(list.len(), 1);
        let granted = list.granted_scope_roots();
        assert_eq!(granted.len(), 1);
        assert_eq!(
            granted[0].ipns_name,
            a_name(0x32),
            "the rotation arm is aimed at the live name, never the superseded one"
        );
    }

    /// A `scopeId` is authored by the sharer, so a hostile contact can present
    /// one a victim already holds from somebody else. Keying the bookmark on the
    /// pair keeps both, so the hostile grant cannot heal over — and overwrite —
    /// the authority of a grant it has none over.
    #[test]
    fn a_second_sharer_cannot_heal_over_the_first_sharers_bookmark() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share_at([0x5c; 16], &a_name(0x31), Permission::Write));

        let hostile = from_another_sharer(share_at([0x5c; 16], &a_name(0x32), Permission::Write));
        assert!(matches!(list.reconcile(hostile), Reconciled::Added));

        assert_eq!(list.len(), 2, "the honest bookmark is still held");
    }

    #[test]
    fn a_bookmark_pairs_its_scope_id_with_the_name_its_root_lives_at() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share_at([0x5c; 16], &a_name(0x31), Permission::Write));

        let granted = list.granted_scope_roots();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].scope_id, [0x5c; 16]);
        assert_eq!(granted[0].ipns_name, a_name(0x31));
        // The rotation arm keys this scope's epoch floors on the granting
        // identity, so a paired root that dropped it could not name them.
        assert_eq!(granted[0].sharer_identity_pk, [0x02; IDENTITY_PUBLIC_LEN]);
        assert_eq!(
            list.writable_scope_refs(),
            granted,
            "the write half carries the same identity the rotation arm files under"
        );
    }

    #[test]
    fn a_scope_id_two_bookmarks_claim_answers_for_neither() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share_at([0x5c; 16], &a_name(0x31), Permission::Write));
        list.reconcile(from_another_sharer(share_at(
            [0x5c; 16],
            &a_name(0x32),
            Permission::Write,
        )));
        list.reconcile(share_at([0x77; 16], &a_name(0x33), Permission::Write));

        let granted = list.granted_scope_roots();
        assert_eq!(
            granted.iter().map(|g| g.scope_id).collect::<Vec<_>>(),
            vec![[0x77; 16]],
            "the ambiguous id is refused, the unambiguous one still answers"
        );
    }

    #[test]
    fn a_read_only_claimant_still_makes_the_id_ambiguous_for_the_sweep_round() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share_at([0x5c; 16], &a_name(0x31), Permission::Write));
        list.reconcile(from_another_sharer(share_at(
            [0x5c; 16],
            &a_name(0x32),
            Permission::Read,
        )));

        assert!(
            list.writable_scope_refs().is_empty(),
            "the write half must not answer for an id the read half also claims"
        );
        assert!(list.granted_scope_roots().is_empty());
    }

    #[test]
    fn a_claimant_with_an_unusable_name_still_makes_the_id_ambiguous() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share_at([0x5c; 16], &a_name(0x31), Permission::Write));
        let mut junk = from_another_sharer(share_at([0x5c; 16], &a_name(0x32), Permission::Write));
        junk.scope_root_name = b"not-an-ipns-name".to_vec();
        list.reconcile(junk);

        assert!(
            list.granted_scope_roots().is_empty(),
            "an unresolvable name is still a claim on the id"
        );
        assert!(list.writable_scope_refs().is_empty());
    }

    #[test]
    fn a_bookmark_whose_stored_name_is_unusable_pairs_with_nothing() {
        let mut list = ReceivedSharesList::new();
        let mut junk = share_at([0x5c; 16], &a_name(0x31), Permission::Write);
        junk.scope_root_name = b"not-an-ipns-name".to_vec();
        list.reconcile(junk);

        assert!(list.granted_scope_roots().is_empty());
    }

    #[test]
    fn a_read_only_share_joins_no_sweep_round() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share_at([0x5c; 16], &a_name(0x31), Permission::Read));

        assert!(list.writable_scope_refs().is_empty());
        assert_eq!(
            list.granted_scope_roots().len(),
            1,
            "it is still a scope this device holds a grant for"
        );
    }

    #[test]
    fn the_stored_list_round_trips_byte_stable_and_keeps_the_pointer_read_key() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share(b"zzz", 0x9C));
        list.reconcile(share(b"aaa", 0x8A));
        let bytes = encode_stored_list(&list).expect("encodes");

        let decoded = decode_stored_list(&bytes).expect("decodes");
        assert_eq!(decoded.len(), 2);
        assert_eq!(
            encode_stored_list(&decoded).expect("re-encodes"),
            bytes,
            "byte-stable"
        );
        let first = decoded.iter().next().unwrap();
        assert_eq!(first.scope_root_name, b"aaa", "entries ride in scope order");
        assert_eq!(
            first.scope_id, [0x8A; 16],
            "the scope id survives the at-rest round trip"
        );
        assert!(ct_eq(first.pointer_read_key(), &[0x8A; 32]));
    }

    /// Rule 8: the decoder hard-rejects two bookmarks for one sharer's scope, so
    /// the encoder must refuse to emit them — with a returned `Err` that
    /// survives a release build, never a stripped assert.
    #[test]
    fn a_duplicate_scope_is_refused_in_both_directions() {
        let mut duplicated = ReceivedSharesList::new();
        duplicated.entries.push(share(b"n", 0x8A));
        duplicated.entries.push(share(b"m", 0x8A));
        assert!(
            matches!(
                encode_stored_list(&duplicated),
                Err(ReceivedSharesCodecError::DuplicateScope)
            ),
            "the encoder refuses a list with no defined authority for a scope"
        );

        let mut one = ReceivedSharesList::new();
        one.reconcile(share(b"n", 0x8A));
        let single = decode(&encode_stored_list(&one).unwrap()).unwrap();
        let mut map = single.as_map().unwrap().clone();
        let mut shares = map.get("shares").unwrap().as_array().unwrap().to_vec();
        shares.push(shares[0].clone());
        map.insert("shares", Value::Array(shares));
        assert!(
            matches!(
                decode_stored_list(&encode(&Value::Map(map)).unwrap()),
                Err(ReceivedSharesCodecError::DuplicateScope)
            ),
            "the decoder refuses the same list it would never emit"
        );
    }

    #[test]
    fn a_stored_list_with_an_unknown_key_is_refused() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share(b"n", 0x8A));
        let decoded = decode(&encode_stored_list(&list).unwrap()).unwrap();
        let mut map = decoded.as_map().unwrap().clone();
        map.insert("extra", Value::Unsigned(1));
        assert!(decode_stored_list(&encode(&Value::Map(map)).unwrap()).is_err());
    }

    /// Frozen: this is the durable at-rest format. A renamed field, a reordered
    /// key, or a changed width orphans every stored list, and the mailbox items
    /// that delivered those shares are acked — so a byte vector pins it rather
    /// than a self-referential round trip.
    const STORED_LIST_V2: &str = concat!(
        "a26176026673686172657381a66773636f70654964508a8a8a8a8a8a8a8a8a8a8a8a8a",
        "8a8a8a6a7065726d697373696f6e64726561646b646973706c61794e616d6561736d73",
        "636f7065526f6f744e616d654c6b353173636f7065726f6f746e706f696e7465725265",
        "61644b657958208a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a",
        "8a8a8a8a707368617265724964656e74697479506b5821020202020202020202020202",
        "020202020202020202020202020202020202020202",
    );

    #[test]
    fn the_stored_list_encoding_is_frozen() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share(b"k51scoperoot", 0x8A));
        let bytes = encode_stored_list(&list).expect("encodes");
        assert_eq!(
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            STORED_LIST_V2,
            "the durable at-rest encoding changed",
        );

        let raw: Vec<u8> = (0..STORED_LIST_V2.len() / 2)
            .map(|i| u8::from_str_radix(&STORED_LIST_V2[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect();
        let decoded = decode_stored_list(&raw).expect("the frozen bytes still decode");
        assert_eq!(decoded.len(), 1);
        assert!(ct_eq(
            decoded.iter().next().unwrap().pointer_read_key(),
            &[0x8A; 32]
        ));
    }

    fn link_hold() -> LinkHold {
        use cipherbox_core::suite::ed25519::Ed25519Signer;
        LinkHold {
            invite_secret: SecretBytes::new([0x4e; 32]),
            scope_pointer_name: IpnsName::from_public_key(
                &Ed25519Signer::from_seed([0x5d; 32]).verifying_key(),
            ),
            deadline: Some(UnixMillis(1_700_000_000_000)),
        }
    }

    /// ADR 0024 C1: the link keys are optional keys of a version 2 bookmark.
    /// A bookmark without them is the frozen personal one; a held one round
    /// trips, keys and deadline included.
    #[test]
    fn a_v2_bookmark_without_link_keys_loads_and_a_held_one_round_trips() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share(b"k51scoperoot", 0x8A));
        let personal = decode_stored_list(&encode_stored_list(&list).expect("encodes"))
            .expect("a bookmark without link keys loads");
        let key = personal.iter().next().expect("one bookmark").key();
        assert!(personal.link_hold(&key).is_none());

        list.hold_link(key, link_hold());
        let bytes = encode_stored_list(&list).expect("encodes");
        let held = decode_stored_list(&bytes).expect("a held bookmark loads");
        assert!(held.link_hold(&key) == Some(&link_hold()));
        assert_eq!(
            encode_stored_list(&held).expect("re-encodes"),
            bytes,
            "byte-stable"
        );

        let mut dropped = held;
        assert!(dropped.drop_link(&key).is_some());
        assert_eq!(
            encode_stored_list(&dropped).expect("encodes"),
            encode_stored_list(&personal).expect("encodes"),
            "a dropped hold leaves the personal bookmark's bytes"
        );
    }

    /// `linkSecret` and `scopePointerName` come as a pair.
    #[test]
    fn a_link_hold_missing_half_its_pair_is_refused() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share(b"k51scoperoot", 0x8A));
        let key = list.iter().next().expect("one bookmark").key();
        list.hold_link(key, link_hold());
        let tree = decode(&encode_stored_list(&list).unwrap()).unwrap();
        for dropped in ["linkSecret", "scopePointerName"] {
            let mut map = tree.as_map().unwrap().clone();
            let shares = map.get("shares").unwrap().as_array().unwrap().to_vec();
            let mut entry = shares[0].as_map().unwrap().clone();
            let kept: Vec<(String, Value)> = entry
                .entries()
                .iter()
                .filter(|(field, _)| field != dropped)
                .cloned()
                .collect();
            entry = Map::new();
            for (field, value) in kept {
                entry.insert(&field, value);
            }
            map.insert("shares", Value::Array(vec![Value::Map(entry)]));
            assert!(
                decode_stored_list(&encode(&Value::Map(map)).unwrap()).is_err(),
                "a hold without {dropped} is refused"
            );
        }
    }

    #[test]
    fn a_stored_body_at_an_unreadable_version_is_refused() {
        let mut list = ReceivedSharesList::new();
        list.reconcile(share(b"n", 0x8A));
        let decoded = decode(&encode_stored_list(&list).unwrap()).unwrap();
        let mut map = decoded.as_map().unwrap().clone();
        map.insert("v", Value::Unsigned(STORED_LIST_V + 1));
        assert!(
            matches!(
                decode_stored_list(&encode(&Value::Map(map)).unwrap()),
                Err(ReceivedSharesCodecError::UnsupportedVersion { .. })
            ),
            "a forward body version is named, never read as empty"
        );
    }

    /// The builder refuses the label the recipient's own store refuses, so no
    /// build posts a pointer it could never bookmark (AGENTS.md rule 8).
    #[test]
    fn a_share_pointer_is_built_only_within_the_store_bound() {
        let at_the_bound = SharePointer::bounded(
            b"name".to_vec(),
            [0x11; IDENTITY_PUBLIC_LEN],
            "x".repeat(MAX_NODE_NAME_BYTES),
            Permission::Read,
        )
        .expect("a label at the bound builds");
        assert_eq!(at_the_bound.display_name.len(), MAX_NODE_NAME_BYTES);

        assert_eq!(
            SharePointer::bounded(
                b"name".to_vec(),
                [0x11; IDENTITY_PUBLIC_LEN],
                "x".repeat(MAX_NODE_NAME_BYTES + 1),
                Permission::Read,
            )
            .err()
            .map(|e| (e.field, e.limit)),
            Some(("displayName", MAX_NODE_NAME_BYTES)),
            "one byte past the bound is refused"
        );
    }

    /// The list charges the host's staging budget and its two display fields
    /// arrive verbatim from an untrusted mailbox pointer, so both directions
    /// refuse anything past the frozen bounds (AGENTS.md rule 8).
    #[test]
    fn an_oversized_bookmark_is_refused_in_both_directions() {
        let mut long_label = ReceivedSharesList::new();
        long_label.reconcile(ReceivedShare {
            display_name: "x".repeat(MAX_NODE_NAME_BYTES + 1),
            ..share(b"n", 0x8A)
        });
        assert!(matches!(
            encode_stored_list(&long_label),
            Err(ReceivedSharesCodecError::TooLong(TooLong {
                field: "displayName",
                ..
            }))
        ));

        let mut long_name = ReceivedSharesList::new();
        long_name.reconcile(share(&[b'n'; MAX_SCOPE_ROOT_NAME_BYTES + 1], 0x8A));
        assert!(matches!(
            encode_stored_list(&long_name),
            Err(ReceivedSharesCodecError::TooLong(TooLong {
                field: "scopeRootName",
                ..
            }))
        ));

        // The decoder refuses the same shapes its encoder will not emit.
        let mut one = ReceivedSharesList::new();
        one.reconcile(share(b"n", 0x8A));
        let decoded = decode(&encode_stored_list(&one).unwrap()).unwrap();
        let mut map = decoded.as_map().unwrap().clone();
        let mut entry = map.get("shares").unwrap().as_array().unwrap()[0]
            .as_map()
            .unwrap()
            .clone();
        entry.insert(
            "displayName",
            Value::Text("x".repeat(MAX_NODE_NAME_BYTES + 1)),
        );
        map.insert("shares", Value::Array(vec![Value::Map(entry)]));
        assert!(matches!(
            decode_stored_list(&encode(&Value::Map(map)).unwrap()),
            Err(ReceivedSharesCodecError::TooLong(TooLong {
                field: "displayName",
                ..
            }))
        ));
    }

    #[test]
    fn a_list_past_the_share_bound_is_refused() {
        let mut list = ReceivedSharesList::new();
        for i in 0..=MAX_RECEIVED_SHARES {
            let mut entry = share(format!("n{i}").as_bytes(), 0x8A);
            entry.scope_id[..2].copy_from_slice(&(i as u16).to_be_bytes());
            list.reconcile(entry);
        }
        assert!(matches!(
            encode_stored_list(&list),
            Err(ReceivedSharesCodecError::TooLong(TooLong {
                field: "shares",
                ..
            }))
        ));
    }

    #[test]
    fn sent_index_is_idempotent_by_name_and_recipient() {
        let mut idx = SentIndex::new();
        let s = SentShare {
            scope_root_name: b"n".to_vec(),
            recipient_identity_pk: [0x03; IDENTITY_PUBLIC_LEN],
            permission: Permission::Write,
        };
        assert!(idx.record(s.clone()));
        assert!(!idx.record(s));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn received_share_debug_redacts_the_pointer_read_key() {
        let share = ReceivedShare {
            scope_root_name: b"n".to_vec(),
            scope_id: [0x5c; 16],
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "s".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([0xAB; 32]),
        };
        let debug = format!("{share:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("171"), "no key bytes render");
    }
}
