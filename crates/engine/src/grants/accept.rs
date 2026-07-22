//! The share-accept flow and the self-healing share bookmarks (blueprint/
//! engine.md "Grants and ledger — Accept flow", #25 D3).
//!
//! Accepting a share is: a sender-verified mailbox pointer → resolve the name →
//! the adoption gate (commitment verified against the contact-anchored owner) →
//! self-locate the grant blob by blinded tag → unseal the seeds → append
//! `{name, sharerPub, displayName, permission}` to the recipient's received-
//! shares list (persisting the `pointerReadKey`) → **then** ack. The owner keeps
//! a denormalized sent-index. Both lists are self-healing bookmarks: the
//! published metadata is the authority, so an append is idempotent by scope-root
//! name.
//!
//! Trust flows from the resolved record and the verified [`Contact`], never from
//! the untrusted pointer: the pointer only says *which name to resolve*, and the
//! gate re-verifies everything against the contact-anchored owner identity. The
//! blinded-tag ECDH peer is taken from the verified contact's encryption subkey,
//! not the pointer's claimed `sharerPub`.

use core::fmt;

use cipherbox_core::codec::{Map, Value, decode, encode};
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::kdf;
use cipherbox_core::seal::{AadContext, Permission, STRUCT_TAG_GRANT_BLOB, open_grant_blob};
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::gate::{Candidate, GateError, ReaderContext, SeedBlob, adopt};
use crate::mailbox::VerifiedMailboxItem;
use crate::seams::{FloorStore, Mailbox};

use super::contact::Contact;
use super::ledger::{PublishedGrantBlob, recipient_blinded_tag, self_locate};

/// The mailbox-delivered share pointer: which scope root to resolve and the
/// courtesy display fields. Opaque application bytes inside the HPKE seal; this
/// is app framing, not crypto. `sharer_identity_pk` is bound to the verified
/// contact before anything is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl SharePointer {
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
        encode(&Value::Map(m))
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

/// One received share in the recipient's own vault: the discovery fields plus
/// the persisted `pointerReadKey` (secret). Redacted `Debug`.
#[derive(Clone)]
pub struct ReceivedShare {
    /// The scope root's opaque `ipnsName`.
    pub scope_root_name: Vec<u8>,
    /// The sharer's identity key.
    pub sharer_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// The host display label.
    pub display_name: String,
    /// The granted permission (from the resolved/committed grant).
    pub permission: Permission,
    /// The scope's stable pointer read key, persisted for scope-pointer resolve.
    pointer_read_key: SecretBytes,
}

impl ReceivedShare {
    /// Borrow the persisted pointer read key.
    pub fn pointer_read_key(&self) -> &[u8; 32] {
        self.pointer_read_key.as_bytes()
    }
}

impl fmt::Debug for ReceivedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedShare")
            .field("scope_root_name", &self.scope_root_name)
            .field("display_name", &self.display_name)
            .field("permission", &self.permission)
            .field("pointer_read_key", &"<redacted>")
            .finish()
    }
}

/// The recipient's received-shares list — a self-healing bookmark keyed by
/// scope-root name. The published metadata is the authority; this list only
/// speeds discovery, so appends are idempotent.
#[derive(Default)]
pub struct ReceivedSharesList {
    entries: Vec<ReceivedShare>,
}

impl ReceivedSharesList {
    /// An empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a share for this scope-root name is already bookmarked.
    pub fn contains(&self, scope_root_name: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|e| e.scope_root_name == scope_root_name)
    }

    /// Append a share, idempotent by scope-root name. Returns `true` if it was
    /// newly added, `false` if already present (a re-accept is a no-op bookmark).
    pub fn append(&mut self, share: ReceivedShare) -> bool {
        if self.contains(&share.scope_root_name) {
            return false;
        }
        self.entries.push(share);
        true
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

/// One owner-side sent-share record — the denormalized index the owner keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentShare {
    /// The scope root shared.
    pub scope_root_name: Vec<u8>,
    /// The recipient's identity key.
    pub recipient_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// The permission granted.
    pub permission: Permission,
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
    /// Acking the item failed after the durable append (the share IS recorded;
    /// the item will redeliver and re-accept idempotently).
    Ack(crate::seams::SeamError),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcceptError::MalformedPointer(e) => write!(f, "malformed share pointer: {e}"),
            AcceptError::SenderNotContact => f.write_str("mailbox sender is not the contact"),
            AcceptError::SharerMismatch => f.write_str("pointer sharerPub is not the contact"),
            AcceptError::UnusableSharerKey => f.write_str("sharer contact key is non-contributory"),
            AcceptError::NoBlobAtTag => f.write_str("no grant blob at tag (revocation signal)"),
            AcceptError::UncommittedTag => f.write_str("tag is not in the owner-signed commitment"),
            AcceptError::GrantBlobOpen(e) => write!(f, "grant blob open failed: {e}"),
            AcceptError::Gate(e) => write!(f, "adoption gate rejected: {e}"),
            AcceptError::Ack(e) => write!(f, "ack failed after durable append: {e}"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Run the accept flow for one sender-verified mailbox item against a resolved
/// scope-root record.
///
/// Order is load-bearing: bind the pointer to the contact, self-locate the blob,
/// unseal the seeds, run the gate, append to the received-shares list, and
/// **only then** ack. Any earlier failure returns without acking, so an
/// undelivered accept redelivers and re-runs idempotently.
///
/// `candidate` is the resolved record (hand-fed here; the resolve pipeline is a
/// sibling slice); `grant_blobs` is its published grant section for self-
/// location.
#[allow(clippy::too_many_arguments)]
pub async fn accept_share<F: FloorStore, M: Mailbox>(
    floors: &F,
    mailbox: &M,
    item: &VerifiedMailboxItem,
    contact: &Contact,
    my_enc_secret: &X25519Secret,
    candidate: &Candidate,
    grant_blobs: &[PublishedGrantBlob],
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
    // The derived read key is secret; this fn is its terminal owner, so wipe it
    // on drop (the gate borrows it and never zeroizes a caller-owned buffer).
    let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());

    // The adoption gate: commitment verified against the contact-anchored owner,
    // grant-section authenticated, seeds cross-checked, read-body unsealed.
    let reader = ReaderContext {
        owner_identity: &owner_identity,
        scope_id: candidate.envelope.scope,
        read_key: &read_key, // Zeroizing<[u8; 32]> derefs to the borrowed array
        parent_node_seed: None,
        seed_blob: Some(SeedBlob::Grantee {
            enc_secret: my_enc_secret,
            enc: blob.enc,
            ciphertext: blob.ciphertext.clone(),
            aad: grant_aad,
        }),
    };
    let adopted = adopt(floors, &reader, candidate)
        .await
        .map_err(AcceptError::Gate)?;

    // Durable append FIRST (the pointer_read_key persists with it).
    let newly_added = received.append(ReceivedShare {
        scope_root_name: pointer.scope_root_name.clone(),
        sharer_identity_pk: pointer.sharer_identity_pk,
        display_name: pointer.display_name.clone(),
        permission,
        pointer_read_key: SecretBytes::new(*grant.pointer_read_key()),
    });

    // ...and only now ack.
    mailbox.ack(&item.item_id).await.map_err(AcceptError::Ack)?;

    Ok(AcceptOutcome {
        scope_id: candidate.envelope.scope,
        sequence: adopted.sequence,
        permission,
        newly_added,
    })
}

/// A required map field, or [`Malformed::MissingField`].
fn req<'a>(map: &'a Map, field: &'static str) -> Result<&'a Value, CodecError> {
    map.get(field)
        .ok_or_else(|| Malformed::MissingField { field }.into())
}

/// A fixed-length byte field, or [`Malformed::InvalidFieldLength`].
fn fixed<const N: usize>(v: &Value, field: &'static str) -> Result<[u8; N], CodecError> {
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

    fn pointer() -> SharePointer {
        SharePointer {
            scope_root_name: b"k51scoperoot".to_vec(),
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "Shared Folder".to_string(),
            permission: Permission::Read,
        }
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
        let bytes = encode(&Value::Map(m));
        assert_eq!(
            SharePointer::decode(&bytes).unwrap_err().check(),
            "invalid-permission"
        );
    }

    #[test]
    fn received_list_append_is_idempotent_by_name() {
        let mut list = ReceivedSharesList::new();
        let share = ReceivedShare {
            scope_root_name: b"n".to_vec(),
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "s".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([0x8A; 32]),
        };
        assert!(list.append(share.clone()), "first append is new");
        assert!(!list.append(share), "re-accept is a no-op bookmark");
        assert_eq!(list.len(), 1);
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
