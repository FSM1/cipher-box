//! The sealed write-body: the scope-root write-plane payload
//! (blueprint/core.md "Envelope and structures: Write-body", #27 D6).
//!
//! Present **only at scope roots**: interior nodes publish no write-body at all
//! — their write material (write seed, `writeKey`, IPNS keypair) is derived flat
//! within the write scope. Sealed under the root's `writeKey` (struct tag
//! `write-body`), it carries the authoritative grant ledger, the write-plane
//! history link (opaque sealed bytes here; codec in [`super::grant`]), and the
//! `directChildScopeIndex` for the F-4 rotation cascade (#38 D6).
//!
//! Writers re-wrap grant blobs for the ledger's recorded set during re-seals but
//! cannot change the set; grant changes are owner-only.
//!
//! One strictness policy, everywhere (#27 D10): every map level decodes strict
//! det-CBOR and preserves unknown fields byte-stable, so an old client
//! re-sealing a write-body under shared write never strips a newer client's
//! fields.

use core::fmt;

use crate::codec::scrub::{ScrubOnDrop, ScrubOwned};
use crate::codec::{
    Map, RedactedBytes, RedactedText, Value, decode, encode, encode_fixed_depth, encoded_len,
    head_len,
};
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::ipns::MAX_IPNS_NAME_BYTES;
use crate::suite::ecdsa::{
    EcdsaSignature, EcdsaSigner, EcdsaVerifier, IDENTITY_PUBLIC_LEN, SIGNATURE_LEN as ECDSA_SIG_LEN,
};
use crate::suite::secret::SECRET_LEN;

use super::body::{
    PreservedFields, assert_grant_ids_unique, assert_unknown_disjoint, assert_within_bound,
    bytes_fixed, collect_unknown, merge_unknown, req,
};
use super::envelope::MAX_BLOCK_BYTES;
use super::grant::Permission;
use super::section::MAX_GRANT_BLOBS;

// ---------------------------------------------------------------------------
// Grant-ledger entry.
// ---------------------------------------------------------------------------

/// One authoritative grant-ledger row. The identity key is the 33-byte
/// compressed secp256k1 SEC1 form; the encryption subkey is a 32-byte X25519
/// public key.
#[derive(Clone, PartialEq, Eq)]
pub struct GrantLedgerEntry {
    /// The recipient's compressed secp256k1 identity public key (SEC1).
    pub recipient_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// The recipient's X25519 encryption subkey public key.
    pub recipient_enc_pk: [u8; SECRET_LEN],
    /// The recipient's permission.
    pub permission: Permission,
    /// The recipient's blinded tag (the grant blob's key).
    pub tag: [u8; SECRET_LEN],
    /// The owner's compact ECDSA signature over this row's recipient binding
    /// (`{ipnsName, recipientEncPk, recipientIdentityPk, tag}`, see
    /// [`encode_recipient_binding`]) at the scope root's `ipnsName`.
    ///
    /// Any committed write-grantee authors this ledger. A re-seal takes the
    /// recipient key from the owner-signed commitment rather than from here, so
    /// this signature is the owner authority over `recipientIdentityPk`, the one
    /// recipient field no commitment entry carries.
    ///
    /// It is transferable, and deliberately so — every co-writer must be able to
    /// verify it, which rules out a designated-verifier construction. A
    /// co-writer can therefore prove grant membership to a third party
    /// (CONTEXT.md "Grant ledger"); the ledger is sealed, so the residual is
    /// bounded to the writer set.
    pub owner_sig: [u8; ECDSA_SIG_LEN],
    /// The via-link reference: the tag of the link row that admitted this
    /// grantee (ADR 0023 D2). Under [`owner_sig`](Self::owner_sig) when present.
    pub via_link: Option<[u8; SECRET_LEN]>,
    /// The grantee name and its source (ADR 0027 D3). Under
    /// [`owner_sig`](Self::owner_sig) when present.
    pub grantee_name: Option<GranteeName>,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

/// Who chose a [`GranteeName`]. On the wire it is the text `"claimant"` or
/// `"owner"`. The flag makes the owner's row signature attest "the claimant
/// asked for this name" until the owner edits it (ADR 0027 D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    Claimant,
    Owner,
}

impl NameSource {
    /// The frozen wire string.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Claimant => "claimant",
            Self::Owner => "owner",
        }
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        match v.as_text()? {
            "claimant" => Ok(Self::Claimant),
            "owner" => Ok(Self::Owner),
            _ => Err(Malformed::InvalidNameSource.into()),
        }
    }
}

/// The longest grantee name, in bytes: the bound a share display name carries.
pub const MAX_GRANTEE_NAME_BYTES: usize = 255;

/// A grantee name with its source: a label on a ledger row, never an identity
/// (CONTEXT.md "Grantee name"). [`Self::new`] is the only constructor and runs
/// the check the decoder runs, so no encode path can emit a name the decoder
/// refuses.
#[derive(Clone, PartialEq, Eq)]
pub struct GranteeName {
    name: String,
    source: NameSource,
}

/// The name labels one grantee, so it renders redacted like the row's keys.
impl fmt::Debug for GranteeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GranteeName")
            .field("name", &RedactedText::of(&self.name))
            .field("source", &self.source)
            .finish()
    }
}

impl GranteeName {
    /// Refuses with [`Malformed::InvalidGranteeName`] a name that is empty,
    /// longer than [`MAX_GRANTEE_NAME_BYTES`], or carries a control character.
    pub fn new(name: String, source: NameSource) -> Result<Self, CodecError> {
        if name.is_empty()
            || name.len() > MAX_GRANTEE_NAME_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(Malformed::InvalidGranteeName.into());
        }
        Ok(Self { name, source })
    }

    /// The name text.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Who chose the name.
    pub fn source(&self) -> NameSource {
        self.source
    }
}

/// Each recipient field names one grantee, and the subkey names that party at
/// every scope granted to them, so a rendered row links the grantees a sealed
/// ledger keeps apart — the law [`GrantSetEntry`](super::grant::GrantSetEntry)
/// renders under. `owner_sig` redacts with them: secp256k1 admits public-key
/// recovery, so a compact signature names its signer.
impl fmt::Debug for GrantLedgerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantLedgerEntry")
            .field(
                "recipient_identity_pk",
                &RedactedBytes::of(&self.recipient_identity_pk),
            )
            .field(
                "recipient_enc_pk",
                &RedactedBytes::of(&self.recipient_enc_pk),
            )
            .field("permission", &self.permission)
            .field("tag", &RedactedBytes::of(&self.tag))
            .field("owner_sig", &RedactedBytes::of(&self.owner_sig))
            .field(
                "via_link",
                &self.via_link.as_ref().map(|t| RedactedBytes::of(t)),
            )
            .field("grantee_name", &self.grantee_name)
            .field("unknown", &self.unknown)
            .finish()
    }
}

const LEDGER_ENTRY_KNOWN: &[&str] = &[
    "granteeName",
    "nameSource",
    "ownerSig",
    "permission",
    "recipientEncPk",
    "recipientIdentityPk",
    "tag",
    "viaLink",
];

impl GrantLedgerEntry {
    /// A ledger entry with no via-link reference, no grantee name, and no
    /// preserved unknown fields.
    pub fn new(
        recipient_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
        recipient_enc_pk: [u8; SECRET_LEN],
        permission: Permission,
        tag: [u8; SECRET_LEN],
        owner_sig: [u8; ECDSA_SIG_LEN],
    ) -> Self {
        Self {
            recipient_identity_pk,
            recipient_enc_pk,
            permission,
            tag,
            owner_sig,
            via_link: None,
            grantee_name: None,
            unknown: PreservedFields::new(),
        }
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        let recipient_identity_pk = bytes_fixed::<IDENTITY_PUBLIC_LEN>(
            req(map, "recipientIdentityPk")?,
            "recipientIdentityPk",
        )?;
        let recipient_enc_pk =
            bytes_fixed::<SECRET_LEN>(req(map, "recipientEncPk")?, "recipientEncPk")?;
        let permission = Permission::from_value(req(map, "permission")?)?;
        let tag = bytes_fixed::<SECRET_LEN>(req(map, "tag")?, "tag")?;
        let owner_sig = bytes_fixed::<ECDSA_SIG_LEN>(req(map, "ownerSig")?, "ownerSig")?;
        let via_link = map
            .get("viaLink")
            .map(|v| bytes_fixed::<SECRET_LEN>(v, "viaLink"))
            .transpose()?;
        let grantee_name = match (map.get("granteeName"), map.get("nameSource")) {
            (None, None) => None,
            (Some(name), Some(source)) => Some(GranteeName::new(
                name.as_text()?.to_owned(),
                NameSource::from_value(source)?,
            )?),
            (Some(_), None) => {
                return Err(Malformed::MissingField {
                    field: "nameSource",
                }
                .into());
            }
            (None, Some(_)) => {
                return Err(Malformed::MissingField {
                    field: "granteeName",
                }
                .into());
            }
        };
        Ok(Self {
            recipient_identity_pk,
            recipient_enc_pk,
            permission,
            tag,
            owner_sig,
            via_link,
            grantee_name,
            unknown: collect_unknown(map, LEDGER_ENTRY_KNOWN),
        })
    }

    /// The optional fields that enter the owner-signature preimage, each only
    /// when present, so a row minted before they existed keeps its bytes.
    fn insert_optional_signed(&self, m: &mut Map) {
        if let Some(via_link) = self.via_link {
            m.insert("viaLink", Value::Bytes(via_link.to_vec()));
        }
        if let Some(name) = &self.grantee_name {
            m.insert("granteeName", Value::Text(name.name.clone()));
            m.insert("nameSource", Value::Text(name.source.as_wire().to_string()));
        }
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        self.insert_optional_signed(&mut m);
        m.insert("ownerSig", Value::Bytes(self.owner_sig.to_vec()));
        m.insert(
            "permission",
            Value::Text(self.permission.as_wire().to_string()),
        );
        m.insert(
            "recipientEncPk",
            Value::Bytes(self.recipient_enc_pk.to_vec()),
        );
        m.insert(
            "recipientIdentityPk",
            Value::Bytes(self.recipient_identity_pk.to_vec()),
        );
        m.insert("tag", Value::Bytes(self.tag.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

// ---------------------------------------------------------------------------
// Recipient binding: the owner-signed authority over one ledger row's keys.
// ---------------------------------------------------------------------------

/// Encode one ledger row's recipient binding to its canonical det-CBOR form —
/// the exact preimage the owner ECDSA-signs into
/// [`GrantLedgerEntry::owner_sig`] and a re-sealer verifies.
///
/// The preimage is `{ipnsName, recipientEncPk, recipientIdentityPk, tag}` plus
/// `viaLink`, `granteeName` and `nameSource` when present, bound to the scope
/// root's `ipnsName` so a row cannot be replayed into another root's ledger. A
/// row without the optional fields keeps the preimage it had before they
/// existed, and a removed field changes the preimage, so verify fails. It
/// excludes `permission` (already owner-signed in the grant-set commitment) and
/// preserved unknowns.
pub fn encode_recipient_binding(ipns_name: &[u8], entry: &GrantLedgerEntry) -> Vec<u8> {
    let mut m = Map::new();
    entry.insert_optional_signed(&mut m);
    m.insert("ipnsName", Value::Bytes(ipns_name.to_vec()));
    m.insert(
        "recipientEncPk",
        Value::Bytes(entry.recipient_enc_pk.to_vec()),
    );
    m.insert(
        "recipientIdentityPk",
        Value::Bytes(entry.recipient_identity_pk.to_vec()),
    );
    m.insert("tag", Value::Bytes(entry.tag.to_vec()));
    encode_fixed_depth(&Value::Map(m))
}

/// Owner-sign one ledger row's recipient binding: RFC 6979 ECDSA over the
/// det-CBOR preimage. Sign the row, then stamp the result into its
/// [`owner_sig`](GrantLedgerEntry::owner_sig).
pub fn sign_recipient_binding(
    signer: &EcdsaSigner,
    ipns_name: &[u8],
    entry: &GrantLedgerEntry,
) -> EcdsaSignature {
    signer.sign_detcbor(&encode_recipient_binding(ipns_name, entry))
}

/// Verify a ledger row's owner signature over its recipient binding. Fails
/// closed with [`TrustViolation::IdentitySignatureInvalid`] when `owner_sig` is
/// not a canonical compact signature, and when the owner identity key did not
/// bind these recipient keys to this scope root — the per-row check a re-sealer
/// runs before re-wrapping a grant to `recipientEncPk`.
pub fn verify_recipient_binding(
    verifier: &EcdsaVerifier,
    ipns_name: &[u8],
    entry: &GrantLedgerEntry,
) -> Result<(), CodecError> {
    let sig = EcdsaSignature::from_compact(&entry.owner_sig)
        .ok_or(TrustViolation::IdentitySignatureInvalid)?;
    if verifier.verify_detcbor(&encode_recipient_binding(ipns_name, entry), &sig) {
        Ok(())
    } else {
        Err(TrustViolation::IdentitySignatureInvalid.into())
    }
}

// ---------------------------------------------------------------------------
// Child-scope index entry.
// ---------------------------------------------------------------------------

/// One directly-descendant scope root, enumerated for the F-4 rotation cascade.
/// `ipns_name` is sealed-body plaintext, so it renders redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct ChildScopeRef {
    /// The child scope root's node id (16-byte UUID) = its scope id.
    pub scope_id: [u8; 16],
    /// The child scope root's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const CHILD_SCOPE_KNOWN: &[&str] = &["ipnsName", "scopeId"];

impl fmt::Debug for ChildScopeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildScopeRef")
            .field("scope_id", &self.scope_id)
            .field("ipns_name", &RedactedBytes::of(&self.ipns_name))
            .field("unknown", &self.unknown)
            .finish()
    }
}

impl ChildScopeRef {
    /// A child-scope ref with no preserved unknown fields.
    pub fn new(scope_id: [u8; 16], ipns_name: Vec<u8>) -> Self {
        Self {
            scope_id,
            ipns_name,
            unknown: PreservedFields::new(),
        }
    }

    /// The one release-active invariant on the type, so decode and every encode
    /// path enforce it identically (AGENTS.md rule 8). The name is opaque bytes
    /// here, bounded at the name codec's own ceiling rather than a second number
    /// of this module's choosing.
    fn validate(&self) -> Result<(), CodecError> {
        assert_unknown_disjoint(&self.unknown, CHILD_SCOPE_KNOWN)?;
        assert_within_bound("ipnsName", self.ipns_name.len(), MAX_IPNS_NAME_BYTES)
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        let scope_id = bytes_fixed::<16>(req(map, "scopeId")?, "scopeId")?;
        let ipns_name = req(map, "ipnsName")?.as_bytes()?;
        assert_within_bound("ipnsName", ipns_name.len(), MAX_IPNS_NAME_BYTES)?;
        Ok(Self {
            scope_id,
            ipns_name: ipns_name.to_vec(),
            unknown: collect_unknown(map, CHILD_SCOPE_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("ipnsName", Value::Bytes(self.ipns_name.clone()));
        m.insert("scopeId", Value::Bytes(self.scope_id.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

// ---------------------------------------------------------------------------
// The write-body.
// ---------------------------------------------------------------------------

/// The sealed write-plane payload of a scope root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBody {
    /// The authoritative grant ledger.
    pub grant_ledger: Vec<GrantLedgerEntry>,
    /// The sealed write-plane history-link blob (opaque, bounded at
    /// [`MAX_WRITE_HISTORY_LINK_BYTES`]). **Empty means no link** — the state at
    /// write epoch 1 — and a consumer must test that before opening, since an
    /// empty blob is below every seal's framing floor and reads as truncated.
    pub write_history_link: Vec<u8>,
    /// The directly-descendant scope roots (the F-4 cascade index).
    pub direct_child_scope_index: Vec<ChildScopeRef>,
    /// Preserved unknown top-level fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const WRITE_BODY_KNOWN: &[&str] = &["directChildScopeIndex", "grantLedger", "writeHistoryLink"];

/// The frozen byte bound on [`WriteBody::write_history_link`] — the write
/// plane's analogue of the read plane's
/// [`MAX_HISTORY_LINKS`](super::MAX_HISTORY_LINKS).
///
/// Any committed writer authors the field and no owner signature covers it, so
/// it is bounded rather than trusted (blueprint/core.md "Write-body"). A
/// well-formed link is ~103 bytes; the rest is headroom for preserved unknown
/// fields.
pub const MAX_WRITE_HISTORY_LINK_BYTES: usize = 512;

/// The frozen bound on [`WriteBody::direct_child_scope_index`]'s entry count.
///
/// Any committed writer authors the index and no owner signature covers it, so
/// it is bounded rather than trusted (blueprint/core.md "Write-body"). The
/// ceiling is headroom over any plausible share fan-out from one root, sized
/// like [`MAX_GRANT_BLOBS`](super::MAX_GRANT_BLOBS); a root's direct children
/// are not counted against that ceiling, so it is not a transitive guarantee.
pub const MAX_DIRECT_CHILD_SCOPES: usize = 1024;

/// The re-seal headroom reserved above [`MAX_WRITE_BODY_BYTES`]: the frozen
/// bytes a re-seal adds around a write-body it carries forward — the symmetric
/// seal framing, the section entry, and the envelope framing.
///
/// It reserves nothing for the grant section's own contents, which are bounded
/// far above it ([`MAX_GRANT_BLOBS`](super::MAX_GRANT_BLOBS) blobs and
/// [`MAX_HISTORY_LINKS`](super::MAX_HISTORY_LINKS) links), so this bound
/// narrows the head-size lever rather than closing it; the whole-record ceiling
/// stays the engine's `HeadTooLarge` backstop.
pub const WRITE_BODY_RESEAL_HEADROOM_BYTES: usize = 64 * 1024;

/// The frozen bound on a write-body plaintext's **total encoded size**.
///
/// The per-field bounds beside it narrow the byte lever a committed write
/// grantee holds but cannot close it: `unknown` maps are preserved byte-stable
/// under the strict-preserve law (#27 D10), so refusing a body for the size of
/// what it preserves would refuse honest forward-compatible bodies too. The
/// total is the one place the lever closes without a per-field treadmill.
///
/// The law governs field *treatment* — never strip, keep unknowns byte-stable —
/// not total size, and a size constant every client shares refuses the same
/// bodies everywhere, so a body an old client re-emits stays conforming by
/// construction (blueprint/core.md "Write-body").
pub const MAX_WRITE_BODY_BYTES: usize = MAX_BLOCK_BYTES - WRITE_BODY_RESEAL_HEADROOM_BYTES;

/// The encoded bytes a `writeHistoryLink` of `link_len` occupies: its det-CBOR
/// byte-string head plus its payload.
fn link_field_len(link_len: usize) -> usize {
    head_len(link_len as u64) + link_len
}

/// A body's encoded length charged with a **maximal** `writeHistoryLink` in
/// place of the one it carries, so the measure is invariant under the one field
/// a re-seal replaces.
///
/// That invariance is what makes "this body decodes" imply "this body still
/// encodes after a cut swaps its link". Without it a committed write-grantee
/// pads a body to exactly the bound with an empty link, and the freshly minted
/// link of the rotation that revokes them pushes the re-encode over — a
/// permanent refusal at a size the attacker chose.
fn charged_len(encoded_len: usize, link_len: usize) -> usize {
    encoded_len - link_field_len(link_len) + link_field_len(MAX_WRITE_HISTORY_LINK_BYTES)
}

/// The collection label [`MAX_WRITE_BODY_BYTES`]'s refusal reports. Private to
/// core; consumers that must tell it from the per-field bounds it shares
/// `too-many-structures` with go through [`is_write_body_over_bound`].
const WRITE_BODY_SIZE_CHECK: &str = "writeBody";

/// True when `e` is the write-body's total-size refusal rather than one of the
/// per-field bounds that raise the same check name.
pub fn is_write_body_over_bound(e: &CodecError) -> bool {
    matches!(
        e,
        CodecError::Malformed(Malformed::TooManyStructures {
            collection: WRITE_BODY_SIZE_CHECK,
            ..
        })
    )
}

/// Decode a write-body plaintext (strict det-CBOR, unknown fields preserved).
///
/// Scope-root-only by construction; this codec cannot enforce that — whether a
/// node is a scope root is the engine's decision.
///
/// The transient decoded tree copies the recipient keys, blinded tags and
/// child-scope `ipnsName`s, so it is scrubbed on drop.
pub fn decode_write_body(bytes: &[u8]) -> Result<WriteBody, CodecError> {
    // The raw length before the codec walks anything: the per-field bounds below
    // leave the preserved-unknown maps open by construction, and this caps the
    // walk itself. The charged total follows once the link's length is known.
    assert_within_bound(WRITE_BODY_SIZE_CHECK, bytes.len(), MAX_WRITE_BODY_BYTES)?;
    let value = ScrubOwned(decode(bytes)?);
    let map = value.value().as_map()?;

    // Bound every writer-authored collection before the ledger walk allocates.
    let write_history_link = req(map, "writeHistoryLink")?.as_bytes()?;
    assert_within_bound(
        "writeHistoryLink",
        write_history_link.len(),
        MAX_WRITE_HISTORY_LINK_BYTES,
    )?;
    assert_within_bound(
        WRITE_BODY_SIZE_CHECK,
        charged_len(bytes.len(), write_history_link.len()),
        MAX_WRITE_BODY_BYTES,
    )?;
    let write_history_link = write_history_link.to_vec();
    let raw_children = req(map, "directChildScopeIndex")?.as_array()?;
    assert_within_bound(
        "directChildScopeIndex",
        raw_children.len(),
        MAX_DIRECT_CHILD_SCOPES,
    )?;

    let raw_ledger = req(map, "grantLedger")?.as_array()?;
    assert_within_bound("grantLedger", raw_ledger.len(), MAX_GRANT_BLOBS)?;

    let mut grant_ledger = Vec::with_capacity(raw_ledger.len());
    for item in raw_ledger {
        grant_ledger.push(GrantLedgerEntry::from_value(item)?);
    }
    assert_grant_ids_unique(
        grant_ledger.iter().map(|e| e.tag),
        TrustViolation::DuplicateGrantTag,
    )?;
    let mut direct_child_scope_index = Vec::with_capacity(raw_children.len());
    for item in raw_children {
        direct_child_scope_index.push(ChildScopeRef::from_value(item)?);
    }

    Ok(WriteBody {
        grant_ledger,
        write_history_link,
        direct_child_scope_index,
        unknown: collect_unknown(map, WRITE_BODY_KNOWN),
    })
}

/// Encode a write-body to its canonical det-CBOR plaintext (sealed under the
/// root's `writeKey` with struct tag `write-body` by the caller / seal path).
///
/// The write body is sealed outside core, so this encode is its release-active
/// fail-closed guard: a duplicate-tag ledger, a `writeHistoryLink` past
/// [`MAX_WRITE_HISTORY_LINK_BYTES`], a `grantLedger` past
/// [`MAX_GRANT_BLOBS`](super::MAX_GRANT_BLOBS) rows, a `directChildScopeIndex`
/// past [`MAX_DIRECT_CHILD_SCOPES`] entries or carrying an `ipnsName` past
/// [`MAX_IPNS_NAME_BYTES`], or a plaintext past [`MAX_WRITE_BODY_BYTES`], fails
/// here with the same verdict [`decode_write_body`] raises, so it never hands
/// back bytes its own decoder rejects. The decoder's grantee-name rejects need
/// no guard here: [`GranteeName::new`] refuses what the decoder refuses, so
/// those bytes are unrepresentable. The optional keys are free, though, so each
/// row's preserved fields must not smuggle one in. Every level's preserved list
/// is held to the same rule, so the encoder never silently drops a caller's
/// field where it errors on the equivalent one a level up.
pub fn encode_write_body(body: &WriteBody) -> Result<Vec<u8>, CodecError> {
    assert_within_bound(
        "writeHistoryLink",
        body.write_history_link.len(),
        MAX_WRITE_HISTORY_LINK_BYTES,
    )?;
    // Bounds before the uniqueness walk, the order the decoder checks them in,
    // so a value violating both gets the same verdict from either side.
    assert_within_bound(
        "directChildScopeIndex",
        body.direct_child_scope_index.len(),
        MAX_DIRECT_CHILD_SCOPES,
    )?;
    assert_within_bound("grantLedger", body.grant_ledger.len(), MAX_GRANT_BLOBS)?;
    assert_grant_ids_unique(
        body.grant_ledger.iter().map(|e| e.tag),
        TrustViolation::DuplicateGrantTag,
    )?;
    assert_unknown_disjoint(&body.unknown, WRITE_BODY_KNOWN)?;
    for entry in &body.grant_ledger {
        assert_unknown_disjoint(&entry.unknown, LEDGER_ENTRY_KNOWN)?;
    }
    for child in &body.direct_child_scope_index {
        child.validate()?;
    }
    let mut m = Map::new();
    m.insert(
        "directChildScopeIndex",
        Value::Array(
            body.direct_child_scope_index
                .iter()
                .map(ChildScopeRef::to_value)
                .collect(),
        ),
    );
    m.insert(
        "grantLedger",
        Value::Array(
            body.grant_ledger
                .iter()
                .map(GrantLedgerEntry::to_value)
                .collect(),
        ),
    );
    m.insert(
        "writeHistoryLink",
        Value::Bytes(body.write_history_link.clone()),
    );
    merge_unknown(&mut m, &body.unknown);
    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    // Measured rather than encoded first: an over-bound body never materializes
    // the plaintext buffer it would only be refused and wiped for.
    assert_within_bound(
        WRITE_BODY_SIZE_CHECK,
        charged_len(encoded_len(guard.0)?, body.write_history_link.len()),
        MAX_WRITE_BODY_BYTES,
    )?;
    encode(guard.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE_ROOT_IPNS: &[u8] = b"scope-root-ipns";

    fn owner() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid identity scalar")
    }

    /// A row already stamped with its owner signature, the way a grant-create
    /// hands one to the ledger.
    fn signed_row(
        identity: [u8; 33],
        enc: [u8; 32],
        permission: Permission,
        tag: [u8; 32],
    ) -> GrantLedgerEntry {
        let mut entry = GrantLedgerEntry::new(identity, enc, permission, tag, [0u8; ECDSA_SIG_LEN]);
        entry.owner_sig = sign_recipient_binding(&owner(), SCOPE_ROOT_IPNS, &entry).to_compact();
        entry
    }

    fn sample() -> WriteBody {
        WriteBody {
            grant_ledger: vec![
                signed_row([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]),
                signed_row([0x03; 33], [0x12; 32], Permission::Write, [0x22; 32]),
            ],
            write_history_link: b"sealed-write-history".to_vec(),
            direct_child_scope_index: vec![ChildScopeRef::new(
                [0x55; 16],
                b"child-scope-name".to_vec(),
            )],
            unknown: PreservedFields::new(),
        }
    }

    /// The encode guard wipes its own transient tree, never the caller's body:
    /// one borrow encodes to the same bytes twice. The round-trip test cannot
    /// catch this — it encodes two distinct values.
    #[test]
    fn encoding_one_borrowed_body_twice_is_byte_identical() {
        let body = sample();
        assert_eq!(
            encode_write_body(&body).unwrap(),
            encode_write_body(&body).unwrap()
        );
    }

    /// A child scope's `ipnsName` is sealed-body plaintext, like a child ref's.
    #[test]
    fn debug_redacts_child_scope_names() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains("child-scope-name"), "{rendered}");
        assert!(rendered.contains("<16 bytes redacted>"), "{rendered}");
        assert!(
            rendered.contains("Read") && rendered.contains("Write"),
            "the ledger's public fields stay legible: {rendered}"
        );
    }

    /// A ledger row renders as an exact redacted shape, and a whole body's
    /// rendering spells no byte of one. Pinned as a golden string, not a search
    /// for a spelling: any added field breaks this test and forces a redaction
    /// decision. The composed half is the disclosure itself — one `{:?}` of a
    /// body would otherwise print the whole grantee list of a scope.
    #[test]
    fn ledger_row_debug_names_no_grantee() {
        let identity: [u8; 33] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(101));
        let enc: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(103));
        let tag: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(107));
        let owner_sig: [u8; ECDSA_SIG_LEN] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(109));

        let mut row = GrantLedgerEntry::new(identity, enc, Permission::Read, tag, owner_sig);
        row.via_link = Some(tag);
        row.grantee_name = Some(GranteeName::new("Alice".to_owned(), NameSource::Owner).unwrap());
        assert_eq!(
            format!("{row:?}"),
            "GrantLedgerEntry { recipient_identity_pk: <33 bytes redacted>, \
             recipient_enc_pk: <32 bytes redacted>, permission: Read, \
             tag: <32 bytes redacted>, owner_sig: <64 bytes redacted>, \
             via_link: Some(<32 bytes redacted>), grantee_name: Some(GranteeName { \
             name: <5 chars redacted>, source: Owner }), unknown: {} }"
        );

        let body = WriteBody {
            grant_ledger: vec![row],
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let rendered = format!("{body:?}");
        for field in [&identity[..], &enc[..], &tag[..], &owner_sig[..]] {
            for run in field.windows(4) {
                let spelled = run.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
                assert!(
                    !rendered.contains(&spelled),
                    "a rendered body spells a recipient field: {rendered}"
                );
            }
        }
    }

    #[test]
    fn write_body_round_trips_byte_stable() {
        let body = sample();
        let bytes = encode_write_body(&body).expect("encodes");
        let decoded = decode_write_body(&bytes).expect("decodes");
        assert_eq!(decoded, body);
        assert_eq!(encode_write_body(&decoded).unwrap(), bytes, "byte-stable");
    }

    #[test]
    fn write_body_epoch_one_has_empty_history_link() {
        let body = WriteBody {
            grant_ledger: Vec::new(),
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let bytes = encode_write_body(&body).expect("encodes");
        assert_eq!(decode_write_body(&bytes).unwrap(), body);
    }

    /// Hand-built write-body wire bytes with an empty grant ledger, the way a
    /// hostile peer's arrive.
    fn raw_body(children: Vec<Value>, write_history_link: Value) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(children));
        m.insert("grantLedger", Value::Array(vec![]));
        m.insert("writeHistoryLink", write_history_link);
        encode(&Value::Map(m)).unwrap()
    }

    /// Encode/decode symmetry on the byte bound (AGENTS.md rule 8): both sides
    /// admit exactly `MAX_WRITE_HISTORY_LINK_BYTES` and refuse one more with the
    /// same verdict.
    #[test]
    fn a_write_history_link_past_its_byte_bound_is_refused_by_both_sides() {
        let at_bound = WriteBody {
            write_history_link: vec![0xab; MAX_WRITE_HISTORY_LINK_BYTES],
            ..sample()
        };
        let bytes = encode_write_body(&at_bound).expect("a link at the bound encodes");
        assert_eq!(decode_write_body(&bytes).unwrap(), at_bound);

        let over = WriteBody {
            write_history_link: vec![0xab; MAX_WRITE_HISTORY_LINK_BYTES + 1],
            ..sample()
        };
        assert_eq!(
            encode_write_body(&over).unwrap_err().check(),
            "too-many-structures"
        );

        assert_eq!(
            decode_write_body(&raw_body(
                vec![],
                Value::Bytes(vec![0xab; MAX_WRITE_HISTORY_LINK_BYTES + 1])
            ))
            .unwrap_err()
            .check(),
            "too-many-structures"
        );
    }

    /// Encode/decode symmetry on the ledger's row count (AGENTS.md rule 8): the
    /// missing member of a bound set the writer-authored collections beside it
    /// already belong to.
    #[test]
    fn a_grant_ledger_past_its_entry_bound_is_refused_by_both_sides() {
        let row = |i: usize| {
            let mut tag = [0u8; 32];
            tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
            signed_row([0x02; 33], [0x11; 32], Permission::Read, tag)
        };
        let at_bound = WriteBody {
            grant_ledger: (0..MAX_GRANT_BLOBS).map(row).collect(),
            ..sample()
        };
        let bytes = encode_write_body(&at_bound).expect("a ledger at the bound encodes");
        assert_eq!(decode_write_body(&bytes).unwrap(), at_bound);

        let over = WriteBody {
            grant_ledger: (0..=MAX_GRANT_BLOBS).map(row).collect(),
            ..sample()
        };
        assert_eq!(
            encode_write_body(&over).unwrap_err().check(),
            "too-many-structures"
        );
        // Empty rows keep the vector small and pin the check order: were the
        // count bound to move after the entry walk, this would say
        // `missing-field` instead.
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert(
            "grantLedger",
            Value::Array(
                (0..=MAX_GRANT_BLOBS)
                    .map(|_| Value::Map(Map::new()))
                    .collect(),
            ),
        );
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        assert_eq!(
            decode_write_body(&encode(&Value::Map(m)).unwrap())
                .unwrap_err()
                .check(),
            "too-many-structures"
        );
    }

    /// Encode/decode symmetry on the total encoded size (AGENTS.md rule 8) — the
    /// bound that closes the preserved-field byte lever the per-field bounds
    /// leave open. Padding rides in a preserved unknown field, which is exactly
    /// the shape the strict-preserve law obliges every decoder to keep.
    #[test]
    fn a_write_body_past_its_total_size_bound_is_refused_by_both_sides() {
        let padded = |pad: usize| WriteBody {
            unknown: PreservedFields::from_iter([(
                "zzPad".to_string(),
                Value::Bytes(vec![0xab; pad]),
            )]),
            ..sample()
        };
        // Step down to the largest accepted pad: the CBOR byte-string head
        // widens as the pad grows, so the first estimate overshoots by that
        // growth and nothing below it can.
        let base = encode_write_body(&padded(0))
            .expect("an unpadded body encodes")
            .len();
        let mut pad = MAX_WRITE_BODY_BYTES - charged_len(base, sample().write_history_link.len());
        let mut bytes = loop {
            match encode_write_body(&padded(pad)) {
                Ok(b) => break b,
                Err(_) => pad -= 1,
            }
        };
        assert_eq!(decode_write_body(&bytes).unwrap(), padded(pad));

        assert_eq!(
            encode_write_body(&padded(pad + 1)).unwrap_err().check(),
            "too-many-structures"
        );

        // The decoder measures the same charged length. Hand-built bytes, since
        // the encoder refuses to produce them: the raw length is under the bound
        // and the charge for an empty link carries it over.
        let raw = |pad: usize| {
            let mut m = Map::new();
            m.insert("directChildScopeIndex", Value::Array(vec![]));
            m.insert("grantLedger", Value::Array(vec![]));
            m.insert("writeHistoryLink", Value::Bytes(vec![]));
            m.insert("zzPad", Value::Bytes(vec![0xab; pad]));
            encode(&Value::Map(m)).unwrap()
        };
        let over_charged = raw(MAX_WRITE_BODY_BYTES - raw(0).len() - 100);
        assert!(
            over_charged.len() <= MAX_WRITE_BODY_BYTES,
            "raw length is under"
        );
        assert!(charged_len(over_charged.len(), 0) > MAX_WRITE_BODY_BYTES);
        assert_eq!(
            decode_write_body(&over_charged).unwrap_err().check(),
            "too-many-structures"
        );

        // And the raw length gate refuses before the codec walks anything.
        bytes.resize(MAX_WRITE_BODY_BYTES + 1, 0xab);
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "too-many-structures"
        );
    }

    /// The bound charges `writeHistoryLink` at its ceiling whatever it actually
    /// carries, so a body a decoder accepts still encodes once a write cut swaps
    /// its link for a freshly minted one. Without that, a committed writer pads
    /// a body to the bound with an empty link and wedges the rotation that
    /// revokes them.
    #[test]
    fn a_body_at_the_bound_still_encodes_after_a_cut_swaps_its_history_link() {
        let padded = |pad: usize, link: Vec<u8>| WriteBody {
            write_history_link: link,
            unknown: PreservedFields::from_iter([(
                "zzPad".to_string(),
                Value::Bytes(vec![0xab; pad]),
            )]),
            ..sample()
        };
        let base = encode_write_body(&padded(0, Vec::new()))
            .expect("an unpadded body encodes")
            .len();
        let mut pad = MAX_WRITE_BODY_BYTES - charged_len(base, 0);
        while encode_write_body(&padded(pad, Vec::new())).is_err() {
            pad -= 1;
        }
        let bytes = encode_write_body(&padded(pad, Vec::new())).expect("at the bound");
        let carried = decode_write_body(&bytes).expect("a body at the bound decodes");

        let cut = WriteBody {
            write_history_link: vec![0xcd; MAX_WRITE_HISTORY_LINK_BYTES],
            ..carried
        };
        let resealed = encode_write_body(&cut).expect("the swapped link still fits");
        assert!(decode_write_body(&resealed).is_ok());
    }

    fn raw_child(ipns_name: Vec<u8>) -> Value {
        let mut c = Map::new();
        c.insert("ipnsName", Value::Bytes(ipns_name));
        c.insert("scopeId", Value::Bytes(vec![0x55; 16]));
        Value::Map(c)
    }

    /// Encode/decode symmetry on the entry count (AGENTS.md rule 8): both sides
    /// admit exactly `MAX_DIRECT_CHILD_SCOPES` and refuse one more with the same
    /// verdict.
    #[test]
    fn a_child_scope_index_past_its_entry_bound_is_refused_by_both_sides() {
        let child = |i: usize| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            ChildScopeRef::new(id, b"child".to_vec())
        };
        let at_bound = WriteBody {
            direct_child_scope_index: (0..MAX_DIRECT_CHILD_SCOPES).map(child).collect(),
            ..sample()
        };
        let bytes = encode_write_body(&at_bound).expect("an index at the bound encodes");
        assert_eq!(decode_write_body(&bytes).unwrap(), at_bound);

        let over = WriteBody {
            direct_child_scope_index: (0..=MAX_DIRECT_CHILD_SCOPES).map(child).collect(),
            ..sample()
        };
        assert_eq!(
            encode_write_body(&over).unwrap_err().check(),
            "too-many-structures"
        );
        let raw_over: Vec<Value> = (0..=MAX_DIRECT_CHILD_SCOPES)
            .map(|_| raw_child(Vec::new()))
            .collect();
        assert_eq!(
            decode_write_body(&raw_body(raw_over, Value::Bytes(vec![])))
                .unwrap_err()
                .check(),
            "too-many-structures"
        );
    }

    /// A preserved field can never override the bounded typed one: `merge_unknown`
    /// skips a key the encoder already inserted, so an over-long `ipnsName` in
    /// `unknown` would otherwise be dropped in silence rather than refused.
    #[test]
    fn a_child_scope_unknown_field_cannot_override_the_bounded_ipns_name() {
        let mut child = ChildScopeRef::new([0x55; 16], b"short".to_vec());
        child.unknown = PreservedFields::from_iter([(
            "ipnsName".to_string(),
            Value::Bytes(vec![0x6b; MAX_IPNS_NAME_BYTES + 1]),
        )]);
        let body = WriteBody {
            direct_child_scope_index: vec![child],
            ..sample()
        };
        assert_eq!(
            encode_write_body(&body).unwrap_err().check(),
            "unknown-field-collision"
        );
    }

    /// The same rule one level up: a top-level preserved field naming a schema
    /// key is refused, not silently dropped.
    #[test]
    fn encode_rejects_a_schema_key_smuggled_through_the_top_level_preserved_list() {
        let body = WriteBody {
            unknown: PreservedFields::from_iter([(
                "writeHistoryLink".to_string(),
                Value::Bytes(vec![0xff; MAX_WRITE_HISTORY_LINK_BYTES + 1]),
            )]),
            ..sample()
        };
        assert_eq!(
            encode_write_body(&body).unwrap_err().check(),
            "unknown-field-collision"
        );
    }

    /// A value violating both the count bound and ledger-tag uniqueness gets one
    /// verdict, whichever side sees it — the decoder's, since encode checks
    /// bounds first for exactly this reason.
    #[test]
    fn a_body_violating_two_invariants_gets_the_same_verdict_from_both_sides() {
        let mut body = WriteBody {
            direct_child_scope_index: (0..=MAX_DIRECT_CHILD_SCOPES)
                .map(|_| ChildScopeRef::new([0x55; 16], b"child".to_vec()))
                .collect(),
            ..sample()
        };
        body.grant_ledger[1].tag = body.grant_ledger[0].tag;

        let raw = raw_body(
            (0..=MAX_DIRECT_CHILD_SCOPES)
                .map(|_| raw_child(Vec::new()))
                .collect(),
            Value::Bytes(vec![]),
        );
        assert_eq!(
            encode_write_body(&body).unwrap_err().check(),
            decode_write_body(&raw).unwrap_err().check()
        );
        assert_eq!(
            encode_write_body(&body).unwrap_err().check(),
            "too-many-structures"
        );
    }

    /// Encode/decode symmetry on the per-entry byte bound (AGENTS.md rule 8).
    #[test]
    fn a_child_scope_ipns_name_past_its_byte_bound_is_refused_by_both_sides() {
        let over_long = vec![0x6b; MAX_IPNS_NAME_BYTES + 1];
        let at_bound = WriteBody {
            direct_child_scope_index: vec![ChildScopeRef::new(
                [0x55; 16],
                vec![0x6b; MAX_IPNS_NAME_BYTES],
            )],
            ..sample()
        };
        let bytes = encode_write_body(&at_bound).expect("a name at the bound encodes");
        assert_eq!(decode_write_body(&bytes).unwrap(), at_bound);

        let over = WriteBody {
            direct_child_scope_index: vec![ChildScopeRef::new([0x55; 16], over_long.clone())],
            ..sample()
        };
        assert_eq!(
            encode_write_body(&over).unwrap_err().check(),
            "too-many-structures"
        );
        assert_eq!(
            decode_write_body(&raw_body(vec![raw_child(over_long)], Value::Bytes(vec![])))
                .unwrap_err()
                .check(),
            "too-many-structures"
        );
    }

    #[test]
    fn invalid_permission_in_ledger_rejects() {
        let mut entry = Map::new();
        entry.insert("ownerSig", Value::Bytes(vec![0x77; ECDSA_SIG_LEN]));
        entry.insert("permission", Value::Text("owner".into()));
        entry.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        entry.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 33]));
        entry.insert("tag", Value::Bytes(vec![0x21; 32]));
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![Value::Map(entry)]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "invalid-permission"
        );
    }

    #[test]
    fn wrong_identity_pk_length_rejects() {
        let mut entry = Map::new();
        entry.insert("ownerSig", Value::Bytes(vec![0x77; ECDSA_SIG_LEN]));
        entry.insert("permission", Value::Text("read".into()));
        entry.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        entry.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 32])); // 32, not 33
        entry.insert("tag", Value::Bytes(vec![0x21; 32]));
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![Value::Map(entry)]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "invalid-field-length"
        );
    }

    #[test]
    fn duplicate_ledger_tag_rejects() {
        // The confused-deputy shape: the same tag appears twice with a different
        // permission and recipientEncPk (a shared-write holder injecting a second
        // row for a victim's tag). Hand-built wire bytes that never passed through
        // any encoder, so decode is what must reject them, the way a hostile
        // peer's bytes arrive.
        let mut a = Map::new();
        a.insert("ownerSig", Value::Bytes(vec![0x77; ECDSA_SIG_LEN]));
        a.insert("permission", Value::Text("read".into()));
        a.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        a.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 33]));
        a.insert("tag", Value::Bytes(vec![0x21; 32]));
        let mut b = Map::new();
        b.insert("ownerSig", Value::Bytes(vec![0x78; ECDSA_SIG_LEN]));
        b.insert("permission", Value::Text("write".into()));
        b.insert("recipientEncPk", Value::Bytes(vec![0x99; 32]));
        b.insert("recipientIdentityPk", Value::Bytes(vec![0x03; 33]));
        b.insert("tag", Value::Bytes(vec![0x21; 32])); // same tag as `a`
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert(
            "grantLedger",
            Value::Array(vec![Value::Map(a), Value::Map(b)]),
        );
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "duplicate-grant-tag"
        );
    }

    #[test]
    fn missing_grant_ledger_rejects() {
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "missing-field"
        );
    }

    #[test]
    fn unknown_top_level_field_preserved_byte_stable() {
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        m.insert("futureField", Value::Text("keep".into()));
        let bytes = encode(&Value::Map(m)).unwrap();
        let decoded = decode_write_body(&bytes).expect("tolerant decode");
        assert_eq!(decoded.unknown.len(), 1);
        assert_eq!(
            encode_write_body(&decoded).unwrap(),
            bytes,
            "unknown preserved"
        );
    }

    /// Wire bytes for a one-row ledger with `extra` added to a well-formed
    /// row, hand-built the way a hostile peer's arrive.
    fn body_with_row_fields(extra: Vec<(&str, Value)>) -> Vec<u8> {
        let mut entry = Map::new();
        entry.insert("ownerSig", Value::Bytes(vec![0x77; ECDSA_SIG_LEN]));
        entry.insert("permission", Value::Text("read".into()));
        entry.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        entry.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 33]));
        entry.insert("tag", Value::Bytes(vec![0x21; 32]));
        for (key, value) in extra {
            entry.insert(key, value);
        }
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![Value::Map(entry)]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        encode(&Value::Map(m)).unwrap()
    }

    /// A row signed with a via-link reference and a claimant-suggested name.
    fn named_row() -> GrantLedgerEntry {
        let mut row = GrantLedgerEntry::new(
            [0x02; 33],
            [0x11; 32],
            Permission::Read,
            [0x21; 32],
            [0u8; ECDSA_SIG_LEN],
        );
        row.via_link = Some([0x31; 32]);
        row.grantee_name =
            Some(GranteeName::new("Alice".to_owned(), NameSource::Claimant).unwrap());
        row.owner_sig = sign_recipient_binding(&owner(), SCOPE_ROOT_IPNS, &row).to_compact();
        row
    }

    /// A row minted while `expiresAt` was a typed field keeps its bytes and its
    /// signature: the retired key is now a preserved unknown field.
    #[test]
    fn a_row_with_the_retired_expiry_key_keeps_its_bytes_and_signature() {
        let mut body = sample();
        body.grant_ledger[0].unknown =
            PreservedFields::from_iter([("expiresAt".to_string(), Value::Unsigned(1_700))]);
        let bytes = encode_write_body(&body).expect("encodes");
        let decoded = decode_write_body(&bytes).expect("decodes");
        assert_eq!(decoded, body);
        assert_eq!(encode_write_body(&decoded).unwrap(), bytes, "byte-stable");
        assert!(
            verify_recipient_binding(
                &owner().verifying_key(),
                SCOPE_ROOT_IPNS,
                &decoded.grant_ledger[0]
            )
            .is_ok()
        );
    }

    #[test]
    fn a_named_row_round_trips_byte_stable_and_verifies() {
        let body = WriteBody {
            grant_ledger: vec![named_row()],
            ..sample()
        };
        let bytes = encode_write_body(&body).expect("encodes");
        let decoded = decode_write_body(&bytes).expect("decodes");
        assert_eq!(decoded, body);
        assert_eq!(encode_write_body(&decoded).unwrap(), bytes, "byte-stable");
        assert!(
            verify_recipient_binding(
                &owner().verifying_key(),
                SCOPE_ROOT_IPNS,
                &decoded.grant_ledger[0]
            )
            .is_ok()
        );
    }

    /// Each optional field is in the preimage when present, so dropping or
    /// editing one detaches the owner signature.
    #[test]
    fn a_removed_or_edited_signed_field_fails_the_verify() {
        let verifier = owner().verifying_key();
        let row = named_row();

        let mut no_link = row.clone();
        no_link.via_link = None;
        let mut no_name = row.clone();
        no_name.grantee_name = None;
        let mut owner_named = row.clone();
        owner_named.grantee_name =
            Some(GranteeName::new("Alice".to_owned(), NameSource::Owner).unwrap());
        let mut renamed = row.clone();
        renamed.grantee_name =
            Some(GranteeName::new("Mallory".to_owned(), NameSource::Claimant).unwrap());

        for (what, tampered) in [
            ("viaLink removed", no_link),
            ("granteeName removed", no_name),
            ("nameSource changed", owner_named),
            ("granteeName changed", renamed),
        ] {
            assert_eq!(
                verify_recipient_binding(&verifier, SCOPE_ROOT_IPNS, &tampered)
                    .unwrap_err()
                    .check(),
                "identity-signature-invalid",
                "{what} must fail closed"
            );
        }
    }

    #[test]
    fn a_malformed_grantee_name_is_refused_at_decode() {
        let named = |name: Value, source: &str| {
            body_with_row_fields(vec![
                ("granteeName", name),
                ("nameSource", Value::Text(source.into())),
            ])
        };
        let over = "a".repeat(MAX_GRANTEE_NAME_BYTES + 1);
        for (what, bytes, check) in [
            (
                "empty",
                named(Value::Text(String::new()), "owner"),
                "invalid-grantee-name",
            ),
            (
                "over the bound",
                named(Value::Text(over), "owner"),
                "invalid-grantee-name",
            ),
            (
                "a newline",
                named(Value::Text("A\nB".into()), "owner"),
                "invalid-grantee-name",
            ),
            (
                "not text",
                named(Value::Unsigned(1), "owner"),
                "unexpected-type",
            ),
            (
                "unknown source",
                named(Value::Text("A".into()), "server"),
                "invalid-name-source",
            ),
            (
                "a name with no source",
                body_with_row_fields(vec![("granteeName", Value::Text("A".into()))]),
                "missing-field",
            ),
            (
                "a source with no name",
                body_with_row_fields(vec![("nameSource", Value::Text("owner".into()))]),
                "missing-field",
            ),
            (
                "a short via-link",
                body_with_row_fields(vec![("viaLink", Value::Bytes(vec![0x31; 31]))]),
                "invalid-field-length",
            ),
        ] {
            assert_eq!(
                decode_write_body(&bytes).unwrap_err().check(),
                check,
                "{what}"
            );
        }
        let at_bound = "a".repeat(MAX_GRANTEE_NAME_BYTES);
        assert!(decode_write_body(&named(Value::Text(at_bound), "owner")).is_ok());
    }

    #[test]
    fn encode_rejects_a_signed_field_smuggled_through_preserved_fields() {
        for key in ["viaLink", "granteeName", "nameSource"] {
            let mut body = sample();
            body.grant_ledger[0].unknown =
                PreservedFields::from_iter([(key.to_string(), Value::Text("x".into()))]);
            assert_eq!(
                encode_write_body(&body).unwrap_err().check(),
                "unknown-field-collision",
                "{key}"
            );
        }
    }

    #[test]
    fn encode_rejects_duplicate_ledger_tags() {
        // Release-active guard: a caller-built ledger with a repeated tag never
        // yields bytes, matching the decoder's fail-closed reject. Exercised
        // without relying on a `debug_assert`.
        let body = WriteBody {
            grant_ledger: vec![
                signed_row([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]),
                signed_row([0x03; 33], [0x12; 32], Permission::Write, [0x21; 32]),
            ],
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        assert_eq!(
            encode_write_body(&body).unwrap_err().check(),
            "duplicate-grant-tag"
        );
    }

    #[test]
    fn a_signed_recipient_binding_verifies() {
        let row = signed_row([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]);
        assert!(
            verify_recipient_binding(&owner().verifying_key(), SCOPE_ROOT_IPNS, &row).is_ok(),
            "the owner's own binding must verify"
        );
    }

    /// The three bound fields and the scope root are exactly what the signature
    /// authorises: change any one and the row is no longer owner-attested.
    #[test]
    fn tampering_with_a_bound_field_breaks_the_recipient_binding() {
        let verifier = owner().verifying_key();
        let row = signed_row([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]);

        let mut swapped_enc_pk = row.clone();
        swapped_enc_pk.recipient_enc_pk = [0x99; 32];
        let mut swapped_identity_pk = row.clone();
        swapped_identity_pk.recipient_identity_pk = [0x03; 33];
        let mut swapped_tag = row.clone();
        swapped_tag.tag = [0x22; 32];

        for (what, tampered) in [
            ("recipientEncPk", swapped_enc_pk),
            ("recipientIdentityPk", swapped_identity_pk),
            ("tag", swapped_tag),
        ] {
            assert_eq!(
                verify_recipient_binding(&verifier, SCOPE_ROOT_IPNS, &tampered)
                    .unwrap_err()
                    .check(),
                "identity-signature-invalid",
                "a tampered {what} must fail closed"
            );
        }
    }

    /// Replay across scope roots: a genuine row lifted into another root's
    /// ledger is not owner-attested there.
    #[test]
    fn a_recipient_binding_does_not_verify_under_another_scope_root() {
        let row = signed_row([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]);
        assert_eq!(
            verify_recipient_binding(&owner().verifying_key(), b"another-scope-root", &row)
                .unwrap_err()
                .check(),
            "identity-signature-invalid"
        );
    }

    /// A row whose signature bytes are not a canonical compact signature fails
    /// the same closed way a mis-signed one does — no second verdict to leak
    /// which of the two it was.
    #[test]
    fn an_unparsable_owner_sig_fails_closed() {
        let mut row = signed_row([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]);
        row.owner_sig = [0xff; ECDSA_SIG_LEN];
        assert_eq!(
            verify_recipient_binding(&owner().verifying_key(), SCOPE_ROOT_IPNS, &row)
                .unwrap_err()
                .check(),
            "identity-signature-invalid"
        );
    }

    /// `permission` and preserved unknowns are outside the preimage.
    #[test]
    fn the_recipient_binding_preimage_excludes_permission_and_unknowns() {
        let read = signed_row([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]);
        let mut write = read.clone();
        write.permission = Permission::Write;
        write.unknown =
            PreservedFields::from_iter([("expiresAt".to_string(), Value::Unsigned(1_700))]);
        assert_eq!(
            encode_recipient_binding(SCOPE_ROOT_IPNS, &read),
            encode_recipient_binding(SCOPE_ROOT_IPNS, &write)
        );
        assert!(
            verify_recipient_binding(&owner().verifying_key(), SCOPE_ROOT_IPNS, &write).is_ok()
        );
    }

    /// Wire bytes for a one-row ledger whose `ownerSig` the caller chooses,
    /// hand-built the way a hostile peer's arrive.
    fn body_with_raw_owner_sig(owner_sig: Option<Value>) -> Vec<u8> {
        let mut entry = Map::new();
        if let Some(sig) = owner_sig {
            entry.insert("ownerSig", sig);
        }
        entry.insert("permission", Value::Text("read".into()));
        entry.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        entry.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 33]));
        entry.insert("tag", Value::Bytes(vec![0x21; 32]));
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![Value::Map(entry)]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        encode(&Value::Map(m)).unwrap()
    }

    #[test]
    fn a_ledger_row_without_an_owner_sig_rejects() {
        assert_eq!(
            decode_write_body(&body_with_raw_owner_sig(None))
                .unwrap_err()
                .check(),
            "missing-field"
        );
    }

    #[test]
    fn a_wrong_length_owner_sig_rejects() {
        assert_eq!(
            decode_write_body(&body_with_raw_owner_sig(Some(Value::Bytes(vec![
                0x77;
                ECDSA_SIG_LEN
                    - 1
            ]))))
            .unwrap_err()
            .check(),
            "invalid-field-length"
        );
    }
}
