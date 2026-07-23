//! The share-accept flow and the self-healing share bookmarks (blueprint/
//! engine.md "Grants and ledger — Accept flow", #25 D3).
//!
//! Trust flows from the resolved record and the verified [`Contact`], never the
//! untrusted pointer: the pointer only says *which name to resolve*, and the gate
//! re-verifies everything against the contact-anchored owner. The blinded-tag
//! ECDH peer is the verified contact's encryption subkey, not the pointer's
//! claimed `sharerPub`.
//!
//! Both share lists are self-healing bookmarks keyed by scope-root name: the
//! published metadata is authority, so a re-accept heals a drifted permission or
//! rotated pointer read key in place; only a byte-identical re-accept is a true
//! no-op. Persist durably before ack (the flow order lives on [`accept_share`]).

use core::fmt;

use cipherbox_core::codec::{Map, Value, decode, encode};
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::kdf;
use cipherbox_core::seal::{AadContext, Permission, STRUCT_TAG_GRANT_BLOB, open_grant_blob};
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::gate::{Candidate, GateError, ReaderContext, RejectionReason, SeedBlob, adopt_deferred};
use crate::mailbox::VerifiedMailboxItem;
use crate::seams::{FloorStore, Mailbox, SeamError, SeamResult};

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

    /// Whether two bookmarks for the same scope carry identical authority and
    /// discovery bytes — the "true no-op re-accept" test. A drift in the
    /// committed permission, the rotated pointer read key, or the courtesy
    /// display fields means the freshly-verified metadata is authority and the
    /// stored entry must self-heal to it.
    fn same_bookmark(&self, other: &ReceivedShare) -> bool {
        self.sharer_identity_pk == other.sharer_identity_pk
            && self.display_name == other.display_name
            && self.permission == other.permission
            && crate::secret_util::ct_eq_32(self.pointer_read_key(), other.pointer_read_key())
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
/// speeds discovery, so a re-accept heals a drifted entry in place rather than
/// duplicating or keeping stale authority.
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

    /// Reconcile a freshly-verified share into the self-healing bookmark: append
    /// if absent, heal in place if the committed permission or pointer read key
    /// drifted, no-op if byte-identical (blueprint/engine.md "self-healing
    /// bookmarks"). The returned [`Reconciled`] carries the pre-image
    /// [`revert`](Self::revert) needs if the durable persist then fails.
    fn reconcile(&mut self, share: ReceivedShare) -> Reconciled {
        match self
            .entries
            .iter_mut()
            .position(|e| e.scope_root_name == share.scope_root_name)
        {
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
    fn revert(&mut self, scope_root_name: &[u8], reconciled: Reconciled) {
        match reconciled {
            Reconciled::Added => self
                .entries
                .retain(|e| e.scope_root_name != scope_root_name),
            Reconciled::Healed(previous) => {
                if let Some(e) = self
                    .entries
                    .iter_mut()
                    .find(|e| e.scope_root_name == scope_root_name)
                {
                    *e = *previous;
                }
            }
            Reconciled::Unchanged => {}
        }
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

/// What reconciling a freshly-verified grant did to the received-shares
/// bookmark — the durable action the accept flow must persist before it acks.
enum Reconciled {
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

/// Durable persistence for the recipient's received-shares bookmark — the seam
/// the accept flow writes through before it acks the mailbox item.
///
/// Both the ack and the durable sequence-floor advance happen **only** after this
/// returns `Ok` (blueprint/engine.md "Mailbox logic — ack after durable"): a floor
/// that advanced ahead of a failed persist would strand the share below it forever.
/// Persist-fail returns un-acked with the floor untouched, so the item redelivers
/// and re-accepts idempotently (the bookmark self-heals). Injected as a grants-layer
/// seam, not one of the nine host seams; the facade wires a concrete store when the
/// accept flow is mounted (#635).
pub trait ReceivedShareStore {
    /// Durably persist the whole received-shares list. A failure returns a
    /// [`SeamError`] and the accept flow does not ack.
    async fn persist(&self, shares: &ReceivedSharesList) -> SeamResult<()>;
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
    /// The resolved record's name is not the scope root the pointer named — a
    /// mis-paired pointer/record. KDF tag-binding already fails closed on this,
    /// so this is a defense-in-depth early reject.
    NameMismatch,
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
    /// re-accepts idempotently. Nothing was lost.
    Persist(SeamError),
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
/// redelivery's strict-sequence anti-replay reject names a scope already in the
/// durable bookmark (a prior ack that failed after the floor advanced), the flow
/// idempotently re-acks that item without re-adopting — clearing a mailbox item
/// that could otherwise redeliver forever.
///
/// `candidate` is the resolved record (hand-fed here; the resolve pipeline is a
/// sibling slice); `grant_blobs` is its published grant section for self-
/// location.
#[allow(clippy::too_many_arguments)]
pub async fn accept_share<F: FloorStore, M: Mailbox, S: ReceivedShareStore>(
    floors: &F,
    mailbox: &M,
    store: &S,
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

    // The resolved record must be the scope root the pointer named. The blinded
    // tag folds the name in, so a mis-paired record already fails closed at the
    // gate (NoBlobAtTag) — bind it explicitly so it is a named reject, not an
    // opaque miss.
    if candidate.name.as_str().as_bytes() != pointer.scope_root_name.as_slice() {
        return Err(AcceptError::NameMismatch);
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
    // Gate the record but DEFER the floor-law advance: the durable sequence
    // floor must not move ahead of the bookmark it accepts. If the persist below
    // fails the floor stays put, so redelivery re-adopts cleanly instead of being
    // stranded below an already-advanced floor (a permanently-lost share).
    let pending = match adopt_deferred(floors, &reader, candidate).await {
        Ok(pending) => pending,
        Err(e) => {
            // Idempotent ack-only short-circuit. A strict-sequence anti-replay
            // reject for a scope we ALREADY durably hold is a redelivery whose
            // floor advance already committed (e.g. a prior ack failed): the
            // bookmark is proof of prior adoption, so just re-ack and never
            // re-adopt or downgrade it. Any OTHER rejection, a scope we do not
            // hold (a genuine replay), or a retryable `GateError::Seam` (whose
            // `rejection()` is `None`) falls through and propagates unchanged —
            // anti-replay stays intact.
            if let Some(RejectionReason::SequenceNotNewer { floor, .. }) =
                e.rejection().map(|r| &r.reason)
            {
                if let Some(permission) = received
                    .iter()
                    .find(|s| s.scope_root_name == pointer.scope_root_name)
                    .map(|s| s.permission)
                {
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

    // Reconcile the self-healing bookmark: append if new, heal in place if the
    // committed permission or pointer read key drifted, no-op if byte-identical.
    let reconciled = received.reconcile(ReceivedShare {
        scope_root_name: pointer.scope_root_name.clone(),
        sharer_identity_pk: pointer.sharer_identity_pk,
        display_name: pointer.display_name.clone(),
        permission,
        pointer_read_key: SecretBytes::new(*grant.pointer_read_key()),
    });
    let newly_added = matches!(reconciled, Reconciled::Added);

    // Persist durably BEFORE the floor advance and the ack. A failure rolls the
    // in-memory bookmark back and returns un-acked, so the item redelivers rather
    // than being lost. A true no-op re-accept needs no durable write.
    if reconciled.is_durable_change() {
        if let Err(e) = store.persist(received).await {
            received.revert(&pointer.scope_root_name, reconciled);
            return Err(AcceptError::Persist(e));
        }
    }

    // The bookmark is durable — now commit the deferred floor advance, then ack.
    let adopted = pending.commit(floors).await.map_err(AcceptError::Gate)?;
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
    fn reconcile_appends_then_no_ops_a_byte_identical_reaccept() {
        let mut list = ReceivedSharesList::new();
        let share = ReceivedShare {
            scope_root_name: b"n".to_vec(),
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
            crate::secret_util::ct_eq_32(stored.pointer_read_key(), &[0x9C; 32]),
            "pointer read key mismatch"
        );
    }

    #[test]
    fn revert_restores_an_added_then_a_healed_bookmark() {
        let mut list = ReceivedSharesList::new();
        let base = ReceivedShare {
            scope_root_name: b"n".to_vec(),
            sharer_identity_pk: [0x02; IDENTITY_PUBLIC_LEN],
            display_name: "s".into(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([0x8A; 32]),
        };

        // Revert an append → the list is empty again (persist-failure rollback).
        let added = list.reconcile(base.clone());
        assert!(matches!(added, Reconciled::Added));
        list.revert(b"n", added);
        assert!(list.is_empty());

        // Revert a heal → the stored entry returns to its pre-heal values.
        assert!(matches!(list.reconcile(base.clone()), Reconciled::Added));
        let healed = list.reconcile(ReceivedShare {
            permission: Permission::Write,
            pointer_read_key: SecretBytes::new([0x9C; 32]),
            ..base
        });
        assert!(matches!(healed, Reconciled::Healed(_)));
        list.revert(b"n", healed);
        let stored = list.iter().next().unwrap();
        assert_eq!(
            stored.permission,
            Permission::Read,
            "healed field rolled back"
        );
        assert!(
            crate::secret_util::ct_eq_32(stored.pointer_read_key(), &[0x8A; 32]),
            "pointer read key mismatch"
        );
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
