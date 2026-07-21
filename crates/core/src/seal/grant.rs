//! The grant section: the seed-bearing structures a scope root carries
//! (blueprint/core.md "Envelope and structures: Grant section", CONTEXT.md).
//!
//! A scope root publishes, alongside its read-body, the structures that hand a
//! scope's seeds to their grantees and ratchet the key-regression epochs:
//!
//! - **Grant blob** — a scope's current seed(s) HPKE-sealed to one recipient
//!   and keyed by their [blinded tag](crate::kdf::blinded_tag)
//!   (`tag → HPKE{readScopeSeed[, writeScopeSeed], epoch, pointerReadKey}`).
//!   Read grants carry the read seed only; write grants carry both.
//! - **Owner blob** — the current override seed HPKE-sealed to the vault
//!   owner's encryption subkey; the owner is an implicit, unrevokable grantee of
//!   every scope.
//! - **Ascent link** — the current override seed HPKE-sealed to an X25519
//!   keypair derived from the **parent's** node seed. The public half rides
//!   plaintext so any writer can re-seal; unsealing needs the parent seed, so
//!   only ancestor-scope readers descend. An ancestor re-derives the expected
//!   keypair and **rejects a mismatched public half** before opening (the
//!   derive-and-verify check).
//! - **History link** — the previous epoch's seed symmetrically sealed under
//!   the current one (struct tag `history-link`); the key-regression ratchet.
//! - **Grant-set commitment** — the owner-signed, **epoch-free**
//!   `{ipnsName, ownerPseudonymPk, [(tag, permission, pseudonymPk)]}`. A
//!   recipient verifies their tag is committed before trusting a grant; being
//!   epoch-free, a grantee-triggered rotation needs no fresh owner signature.
//!
//! All crypto is composed from [`crate::suite`]; the whole-record fail-closed
//! adoption policy over these verdicts is the engine's gate, not this layer.
//! Every seed here is secret material held in a zeroizing owning type, and the
//! encoded plaintext (which carries those seeds) is zeroized at its terminal
//! owner — the seal path — before it drops.

use core::fmt;

use zeroize::Zeroize;

use crate::codec::{Map, Value, decode, encode};
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::kdf;
use crate::suite::ecdsa::{EcdsaSignature, EcdsaSigner, EcdsaVerifier};
use crate::suite::hpke::{self, ENC_LEN, HpkeCiphertext};
use crate::suite::secret::{SECRET_LEN, SecretBytes};
use crate::suite::x25519::{X25519Public, X25519Secret};

use super::aad::{AadContext, build_aad};
use super::body::{
    ScrubOnDrop, assert_grant_tags_unique, bytes_fixed, collect_unknown, merge_unknown, req,
};

/// The HPKE `info` for every grant-section seal. The structured AAD already
/// binds `(v, id, scope, epoch, structTag)`, so no additional info label is
/// needed; it is fixed empty and frozen by the KAT.
const GRANT_HPKE_INFO: &[u8] = b"";

// ---------------------------------------------------------------------------
// Permission — the grant-ledger / grant-set discriminant.
// ---------------------------------------------------------------------------

/// A grant's permission. On the wire it is the text `"read"`/`"write"`: a read
/// grant conveys the read seed only, a write grant conveys both seeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Read,
    Write,
}

impl Permission {
    /// The frozen wire string.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// Parse the wire string; `None` for anything but `"read"`/`"write"`.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            _ => None,
        }
    }

    /// Parse a permission [`Value`], mapping an unknown string to the
    /// [`Malformed::InvalidPermission`] check.
    pub(super) fn from_value(v: &Value) -> Result<Self, CodecError> {
        Self::from_wire(v.as_text()?).ok_or_else(|| Malformed::InvalidPermission.into())
    }
}

// ---------------------------------------------------------------------------
// Grant-blob payload: the sealed plaintext (HPKE to the recipient enc subkey).
// ---------------------------------------------------------------------------

/// A grant blob's sealed plaintext: a scope's current seed(s) plus the routing
/// hint and the stable pointer read key. `write_scope_seed` is present only for
/// write grants. Seeds are secret material in zeroizing owning types with a
/// redacted `Debug`; read them through the accessors.
#[derive(Clone)]
pub struct GrantBlobPayload {
    read_scope_seed: SecretBytes,
    write_scope_seed: Option<SecretBytes>,
    /// The advisory epoch routing hint (the floor law never trusts it directly).
    pub epoch: u64,
    pointer_read_key: SecretBytes,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: Vec<(String, Value)>,
}

const GRANT_BLOB_KNOWN: &[&str] = &["epoch", "pointerReadKey", "readScopeSeed", "writeScopeSeed"];

impl GrantBlobPayload {
    /// A grant-blob payload with no preserved unknown fields.
    pub fn new(
        read_scope_seed: [u8; SECRET_LEN],
        write_scope_seed: Option<[u8; SECRET_LEN]>,
        epoch: u64,
        pointer_read_key: [u8; SECRET_LEN],
    ) -> Self {
        Self {
            read_scope_seed: SecretBytes::new(read_scope_seed),
            write_scope_seed: write_scope_seed.map(SecretBytes::new),
            epoch,
            pointer_read_key: SecretBytes::new(pointer_read_key),
            unknown: Vec::new(),
        }
    }

    /// Borrow the read scope seed.
    pub fn read_scope_seed(&self) -> &[u8; SECRET_LEN] {
        self.read_scope_seed.as_bytes()
    }

    /// Borrow the write scope seed, present only for write grants.
    pub fn write_scope_seed(&self) -> Option<&[u8; SECRET_LEN]> {
        self.write_scope_seed.as_ref().map(SecretBytes::as_bytes)
    }

    /// Borrow the stable per-scope pointer read key.
    pub fn pointer_read_key(&self) -> &[u8; SECRET_LEN] {
        self.pointer_read_key.as_bytes()
    }
}

impl fmt::Debug for GrantBlobPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantBlobPayload")
            .field("read_scope_seed", &"<redacted>")
            .field(
                "write_scope_seed",
                &self.write_scope_seed.as_ref().map(|_| "<redacted>"),
            )
            .field("epoch", &self.epoch)
            .field("pointer_read_key", &"<redacted>")
            .field("unknown", &self.unknown)
            .finish()
    }
}

impl PartialEq for GrantBlobPayload {
    /// Equality is for KAT/round-trip comparison, not a security operation, so
    /// the seed byte comparison needs no constant-time guarantee (mirrors
    /// [`super::body::Version`]).
    fn eq(&self, other: &Self) -> bool {
        self.read_scope_seed.as_bytes() == other.read_scope_seed.as_bytes()
            && self.write_scope_seed.as_ref().map(SecretBytes::as_bytes)
                == other.write_scope_seed.as_ref().map(SecretBytes::as_bytes)
            && self.epoch == other.epoch
            && self.pointer_read_key.as_bytes() == other.pointer_read_key.as_bytes()
            && self.unknown == other.unknown
    }
}

impl Eq for GrantBlobPayload {}

/// Decode a grant-blob plaintext (strict det-CBOR, unknown fields preserved).
pub fn decode_grant_blob_payload(bytes: &[u8]) -> Result<GrantBlobPayload, CodecError> {
    let value = decode(bytes)?;
    let map = value.as_map()?;
    let read_scope_seed = bytes_fixed::<SECRET_LEN>(req(map, "readScopeSeed")?, "readScopeSeed")?;
    let write_scope_seed = match map.get("writeScopeSeed") {
        Some(v) => Some(bytes_fixed::<SECRET_LEN>(v, "writeScopeSeed")?),
        None => None,
    };
    let epoch = req(map, "epoch")?.as_unsigned()?;
    let pointer_read_key =
        bytes_fixed::<SECRET_LEN>(req(map, "pointerReadKey")?, "pointerReadKey")?;
    Ok(GrantBlobPayload {
        read_scope_seed: SecretBytes::new(read_scope_seed),
        write_scope_seed: write_scope_seed.map(SecretBytes::new),
        epoch,
        pointer_read_key: SecretBytes::new(pointer_read_key),
        unknown: collect_unknown(map, GRANT_BLOB_KNOWN),
    })
}

/// Encode a grant-blob payload to its canonical det-CBOR plaintext.
///
/// The buffer carries seed material verbatim, so its caller is the terminal
/// owner and must zeroize it after use ([`seal_grant_blob`] does exactly this).
pub fn encode_grant_blob_payload(payload: &GrantBlobPayload) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("epoch", Value::Unsigned(payload.epoch));
    m.insert(
        "pointerReadKey",
        Value::Bytes(payload.pointer_read_key.as_bytes().to_vec()),
    );
    m.insert(
        "readScopeSeed",
        Value::Bytes(payload.read_scope_seed.as_bytes().to_vec()),
    );
    if let Some(w) = &payload.write_scope_seed {
        m.insert("writeScopeSeed", Value::Bytes(w.as_bytes().to_vec()));
    }
    merge_unknown(&mut m, &payload.unknown);
    // The transient tree carries verbatim seed copies; scrub the whole tree
    // through the drop guard so the wipe runs on return and on panic-unwind
    // (terminal-owner rule). The returned buffer stays the seal path's to zero.
    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    encode(guard.0)
}

/// HPKE-seal a grant blob to `recipient_pub` under the grant-blob AAD for `ctx`
/// (its `struct_tag` must be [`super::STRUCT_TAG_GRANT_BLOB`]). `ephemeral_scalar`
/// is injected entropy that **must be fresh per call** (see [`hpke::hpke_seal`]).
/// The encoded plaintext (carrying the scope seeds) is zeroized here.
pub fn seal_grant_blob(
    recipient_pub: &X25519Public,
    ephemeral_scalar: &[u8; 32],
    ctx: &AadContext,
    payload: &GrantBlobPayload,
) -> HpkeCiphertext {
    let mut plaintext = encode_grant_blob_payload(payload);
    let sealed = hpke::hpke_seal(
        recipient_pub,
        ephemeral_scalar,
        GRANT_HPKE_INFO,
        &build_aad(ctx),
        &plaintext,
    );
    plaintext.zeroize();
    sealed
}

/// Open a grant blob with the recipient's encryption subkey secret. Fails closed
/// with [`TrustViolation::HpkeOpenFailed`] on a tag mismatch (tampering, an
/// `enc`/AAD transplant, or a `v` downgrade bound through the AAD).
pub fn open_grant_blob(
    recipient_secret: &X25519Secret,
    enc: &[u8; ENC_LEN],
    ctx: &AadContext,
    ciphertext: &[u8],
) -> Result<GrantBlobPayload, CodecError> {
    // `hpke_open` returns `Zeroizing<Vec<u8>>`, so this seed-bearing plaintext is
    // wiped on drop — no explicit zeroize needed at this terminal owner.
    let plaintext = hpke::hpke_open(
        recipient_secret,
        enc,
        GRANT_HPKE_INFO,
        &build_aad(ctx),
        ciphertext,
    )?;
    decode_grant_blob_payload(&plaintext)
}

// ---------------------------------------------------------------------------
// Override-seed payload: shared plaintext of the owner blob and the ascent link.
// ---------------------------------------------------------------------------

/// The sealed plaintext of an owner blob and of an ascent link: the scope's
/// current override seed plus the epoch it belongs to. The seed is secret
/// material in a zeroizing owning type; read it through [`Self::override_seed`].
#[derive(Clone)]
pub struct OverrideSeedPayload {
    override_seed: SecretBytes,
    /// The epoch this override seed belongs to.
    pub epoch: u64,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: Vec<(String, Value)>,
}

const OVERRIDE_SEED_KNOWN: &[&str] = &["epoch", "overrideSeed"];

impl OverrideSeedPayload {
    /// An override-seed payload with no preserved unknown fields.
    pub fn new(override_seed: [u8; SECRET_LEN], epoch: u64) -> Self {
        Self {
            override_seed: SecretBytes::new(override_seed),
            epoch,
            unknown: Vec::new(),
        }
    }

    /// Borrow the override seed.
    pub fn override_seed(&self) -> &[u8; SECRET_LEN] {
        self.override_seed.as_bytes()
    }
}

impl fmt::Debug for OverrideSeedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverrideSeedPayload")
            .field("override_seed", &"<redacted>")
            .field("epoch", &self.epoch)
            .field("unknown", &self.unknown)
            .finish()
    }
}

impl PartialEq for OverrideSeedPayload {
    fn eq(&self, other: &Self) -> bool {
        self.override_seed.as_bytes() == other.override_seed.as_bytes()
            && self.epoch == other.epoch
            && self.unknown == other.unknown
    }
}

impl Eq for OverrideSeedPayload {}

/// Decode an override-seed plaintext (strict det-CBOR, unknown fields preserved).
pub fn decode_override_seed_payload(bytes: &[u8]) -> Result<OverrideSeedPayload, CodecError> {
    let value = decode(bytes)?;
    let map = value.as_map()?;
    let override_seed = bytes_fixed::<SECRET_LEN>(req(map, "overrideSeed")?, "overrideSeed")?;
    let epoch = req(map, "epoch")?.as_unsigned()?;
    Ok(OverrideSeedPayload {
        override_seed: SecretBytes::new(override_seed),
        epoch,
        unknown: collect_unknown(map, OVERRIDE_SEED_KNOWN),
    })
}

/// Encode an override-seed payload to its canonical det-CBOR plaintext. The
/// buffer carries the seed verbatim; its caller is the terminal owner and must
/// zeroize it (the seal paths do).
pub fn encode_override_seed_payload(payload: &OverrideSeedPayload) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("epoch", Value::Unsigned(payload.epoch));
    m.insert(
        "overrideSeed",
        Value::Bytes(payload.override_seed.as_bytes().to_vec()),
    );
    merge_unknown(&mut m, &payload.unknown);
    // Whole-tree scrub via the drop guard (terminal-owner rule); the returned
    // buffer stays the seal path's to zeroize.
    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    encode(guard.0)
}

/// HPKE-seal an owner blob to the owner's encryption subkey under the owner-blob
/// AAD for `ctx` (`struct_tag` must be [`super::STRUCT_TAG_OWNER_BLOB`]). The
/// encoded plaintext (carrying the override seed) is zeroized here.
pub fn seal_owner_blob(
    owner_enc_pub: &X25519Public,
    ephemeral_scalar: &[u8; 32],
    ctx: &AadContext,
    payload: &OverrideSeedPayload,
) -> HpkeCiphertext {
    let mut plaintext = encode_override_seed_payload(payload);
    let sealed = hpke::hpke_seal(
        owner_enc_pub,
        ephemeral_scalar,
        GRANT_HPKE_INFO,
        &build_aad(ctx),
        &plaintext,
    );
    plaintext.zeroize();
    sealed
}

/// Open an owner blob with the owner's encryption subkey secret. Fails closed
/// with [`TrustViolation::HpkeOpenFailed`] on a tag mismatch.
pub fn open_owner_blob(
    owner_enc_secret: &X25519Secret,
    enc: &[u8; ENC_LEN],
    ctx: &AadContext,
    ciphertext: &[u8],
) -> Result<OverrideSeedPayload, CodecError> {
    // `hpke_open` returns `Zeroizing<Vec<u8>>`, so this seed-bearing plaintext is
    // wiped on drop — no explicit zeroize needed at this terminal owner.
    let plaintext = hpke::hpke_open(
        owner_enc_secret,
        enc,
        GRANT_HPKE_INFO,
        &build_aad(ctx),
        ciphertext,
    )?;
    decode_override_seed_payload(&plaintext)
}

// ---------------------------------------------------------------------------
// Ascent link: plaintext public half + HPKE-sealed override seed.
// ---------------------------------------------------------------------------

/// An ascent link: the plaintext X25519 public half of the ascent keypair and
/// the HPKE-sealed override seed. The keypair derives from the **parent** node
/// seed ([`kdf::ascent_keypair`]); the public half rides plaintext so any writer
/// can re-seal, while unsealing needs the parent seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AscentLink {
    /// The plaintext ascent X25519 public key (the derive-and-verify anchor).
    pub ascent_public: [u8; ENC_LEN],
    /// The HPKE encapsulated key.
    pub enc: [u8; ENC_LEN],
    /// The HPKE ciphertext (`ciphertext || tag`) of the override-seed payload.
    pub ciphertext: Vec<u8>,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: Vec<(String, Value)>,
}

const ASCENT_LINK_KNOWN: &[&str] = &["ascentPublic", "ciphertext", "enc"];

/// Decode an ascent-link container (strict det-CBOR, unknown fields preserved).
pub fn decode_ascent_link(bytes: &[u8]) -> Result<AscentLink, CodecError> {
    let value = decode(bytes)?;
    let map = value.as_map()?;
    let ascent_public = bytes_fixed::<ENC_LEN>(req(map, "ascentPublic")?, "ascentPublic")?;
    let enc = bytes_fixed::<ENC_LEN>(req(map, "enc")?, "enc")?;
    let ciphertext = req(map, "ciphertext")?.as_bytes()?.to_vec();
    Ok(AscentLink {
        ascent_public,
        enc,
        ciphertext,
        unknown: collect_unknown(map, ASCENT_LINK_KNOWN),
    })
}

/// Encode an ascent-link container to its canonical det-CBOR form.
pub fn encode_ascent_link(link: &AscentLink) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("enc", Value::Bytes(link.enc.to_vec()));
    m.insert("ciphertext", Value::Bytes(link.ciphertext.clone()));
    m.insert("ascentPublic", Value::Bytes(link.ascent_public.to_vec()));
    merge_unknown(&mut m, &link.unknown);
    encode(&Value::Map(m))
}

/// Seal an ascent link: derive the ascent keypair from `parent_node_seed`, put
/// its public half in plaintext, and HPKE-seal `payload` to it under the
/// ascent-link AAD for `ctx` (`struct_tag` must be
/// [`super::STRUCT_TAG_ASCENT_LINK`]). The encoded plaintext is zeroized here.
pub fn seal_ascent_link(
    parent_node_seed: &[u8; SECRET_LEN],
    ephemeral_scalar: &[u8; 32],
    ctx: &AadContext,
    payload: &OverrideSeedPayload,
) -> AscentLink {
    let ascent_secret = kdf::ascent_keypair(parent_node_seed);
    let ascent_public = ascent_secret.public();
    let mut plaintext = encode_override_seed_payload(payload);
    let sealed = hpke::hpke_seal(
        &ascent_public,
        ephemeral_scalar,
        GRANT_HPKE_INFO,
        &build_aad(ctx),
        &plaintext,
    );
    plaintext.zeroize();
    AscentLink {
        ascent_public: ascent_public.to_bytes(),
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        unknown: Vec::new(),
    }
}

/// Open an ascent link as an ancestor reader: re-derive the ascent keypair from
/// `parent_node_seed` and **reject a mismatched public half**
/// ([`TrustViolation::AscentLinkMismatch`]) before opening. A mismatch means the
/// plaintext public half was not derived from this parent seed — the ancestor
/// descends no further. On a match, HPKE-open fails closed on a tag mismatch
/// ([`TrustViolation::HpkeOpenFailed`]).
pub fn open_ascent_link(
    parent_node_seed: &[u8; SECRET_LEN],
    ctx: &AadContext,
    link: &AscentLink,
) -> Result<OverrideSeedPayload, CodecError> {
    let ascent_secret = kdf::ascent_keypair(parent_node_seed);
    if ascent_secret.public().to_bytes() != link.ascent_public {
        return Err(TrustViolation::AscentLinkMismatch.into());
    }
    // `hpke_open` returns `Zeroizing<Vec<u8>>`, so this seed-bearing plaintext is
    // wiped on drop — no explicit zeroize needed at this terminal owner.
    let plaintext = hpke::hpke_open(
        &ascent_secret,
        &link.enc,
        GRANT_HPKE_INFO,
        &build_aad(ctx),
        &link.ciphertext,
    )?;
    decode_override_seed_payload(&plaintext)
}

// ---------------------------------------------------------------------------
// History link: the previous epoch's seed symmetrically sealed under the
// current one (the key-regression ratchet).
// ---------------------------------------------------------------------------

/// A history link's sealed plaintext: the previous epoch's seed and the epoch it
/// belongs to. Symmetrically sealed under the current epoch's structure key
/// (struct tag `history-link`) via [`super::seal`]. The seed is secret material
/// in a zeroizing owning type.
#[derive(Clone)]
pub struct HistoryLinkPayload {
    prev_seed: SecretBytes,
    /// The previous epoch this seed belongs to.
    pub prev_epoch: u64,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: Vec<(String, Value)>,
}

const HISTORY_LINK_KNOWN: &[&str] = &["prevEpoch", "prevSeed"];

impl HistoryLinkPayload {
    /// A history-link payload with no preserved unknown fields.
    pub fn new(prev_seed: [u8; SECRET_LEN], prev_epoch: u64) -> Self {
        Self {
            prev_seed: SecretBytes::new(prev_seed),
            prev_epoch,
            unknown: Vec::new(),
        }
    }

    /// Borrow the previous epoch's seed.
    pub fn prev_seed(&self) -> &[u8; SECRET_LEN] {
        self.prev_seed.as_bytes()
    }
}

impl fmt::Debug for HistoryLinkPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryLinkPayload")
            .field("prev_seed", &"<redacted>")
            .field("prev_epoch", &self.prev_epoch)
            .field("unknown", &self.unknown)
            .finish()
    }
}

impl PartialEq for HistoryLinkPayload {
    fn eq(&self, other: &Self) -> bool {
        self.prev_seed.as_bytes() == other.prev_seed.as_bytes()
            && self.prev_epoch == other.prev_epoch
            && self.unknown == other.unknown
    }
}

impl Eq for HistoryLinkPayload {}

/// Decode a history-link plaintext (strict det-CBOR, unknown fields preserved).
pub fn decode_history_link_payload(bytes: &[u8]) -> Result<HistoryLinkPayload, CodecError> {
    let value = decode(bytes)?;
    let map = value.as_map()?;
    let prev_seed = bytes_fixed::<SECRET_LEN>(req(map, "prevSeed")?, "prevSeed")?;
    let prev_epoch = req(map, "prevEpoch")?.as_unsigned()?;
    Ok(HistoryLinkPayload {
        prev_seed: SecretBytes::new(prev_seed),
        prev_epoch,
        unknown: collect_unknown(map, HISTORY_LINK_KNOWN),
    })
}

/// Encode a history-link payload to its canonical det-CBOR plaintext. The buffer
/// carries the seed verbatim; its caller is the terminal owner and must zeroize
/// it ([`seal_history_link`] does).
pub fn encode_history_link_payload(payload: &HistoryLinkPayload) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("prevEpoch", Value::Unsigned(payload.prev_epoch));
    m.insert(
        "prevSeed",
        Value::Bytes(payload.prev_seed.as_bytes().to_vec()),
    );
    merge_unknown(&mut m, &payload.unknown);
    // Whole-tree scrub via the drop guard (terminal-owner rule); the returned
    // buffer stays the seal path's to zeroize.
    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    encode(guard.0)
}

/// Symmetrically seal a history link under the current epoch's structure `key`
/// and injected `nonce`, binding the history-link AAD for `ctx` (`struct_tag`
/// must be [`super::STRUCT_TAG_HISTORY_LINK`]). Returns the wire sealed blob
/// `nonce(24) || ciphertext||tag`; the encoded plaintext is zeroized here.
pub fn seal_history_link(
    key: &[u8; crate::suite::aead::KEY_LEN],
    nonce: &[u8; crate::suite::aead::NONCE_LEN],
    ctx: &AadContext,
    payload: &HistoryLinkPayload,
) -> Vec<u8> {
    let mut plaintext = encode_history_link_payload(payload);
    let sealed = super::seal(key, nonce, ctx, &plaintext);
    plaintext.zeroize();
    sealed
}

/// Open a history link under the current epoch's structure `key`. Fails closed
/// with [`TrustViolation::SealOpenFailed`] on a tag mismatch or an AAD
/// transplant, and [`Malformed::Truncated`] on a blob below the nonce+tag floor.
pub fn open_history_link(
    key: &[u8; crate::suite::aead::KEY_LEN],
    ctx: &AadContext,
    sealed: &[u8],
) -> Result<HistoryLinkPayload, CodecError> {
    // `unseal` returns a plain buffer carrying the previous epoch's seed; this
    // function is its terminal owner, so wipe it after decode (mirroring
    // `open_read_body`). The HPKE open paths get this for free via `Zeroizing`.
    let mut plaintext = super::unseal(key, ctx, sealed)?;
    let result = decode_history_link_payload(&plaintext);
    plaintext.zeroize();
    result
}

// ---------------------------------------------------------------------------
// Grant-set commitment: the owner-signed, epoch-free tag/pseudonym set.
// ---------------------------------------------------------------------------

/// One committed grant: a recipient's blinded tag, their permission, and the
/// writer pseudonym public key any envelope holder verifies committed-write
/// authorship against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSetEntry {
    /// The recipient's blinded tag.
    pub tag: [u8; SECRET_LEN],
    /// The recipient's permission.
    pub permission: Permission,
    /// The writer pseudonym public key (Ed25519).
    pub pseudonym_pk: [u8; 32],
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: Vec<(String, Value)>,
}

const GRANT_SET_ENTRY_KNOWN: &[&str] = &["permission", "pseudonymPk", "tag"];

impl GrantSetEntry {
    /// A committed grant with no preserved unknown fields.
    pub fn new(tag: [u8; SECRET_LEN], permission: Permission, pseudonym_pk: [u8; 32]) -> Self {
        Self {
            tag,
            permission,
            pseudonym_pk,
            unknown: Vec::new(),
        }
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        let tag = bytes_fixed::<SECRET_LEN>(req(map, "tag")?, "tag")?;
        let permission = Permission::from_value(req(map, "permission")?)?;
        let pseudonym_pk = bytes_fixed::<32>(req(map, "pseudonymPk")?, "pseudonymPk")?;
        Ok(Self {
            tag,
            permission,
            pseudonym_pk,
            unknown: collect_unknown(map, GRANT_SET_ENTRY_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "permission",
            Value::Text(self.permission.as_wire().to_string()),
        );
        m.insert("pseudonymPk", Value::Bytes(self.pseudonym_pk.to_vec()));
        m.insert("tag", Value::Bytes(self.tag.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

/// The owner-signed, epoch-free grant-set commitment: the scope root's
/// `ipnsName`, the owner's own writer-pseudonym public key, and the committed
/// `(tag, permission, pseudonymPk)` entries. A recipient verifies their tag is
/// committed before trusting a grant. Deliberately epoch-free, so a
/// grantee-triggered rotation needs no fresh owner signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSetCommitment {
    /// The scope root's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
    /// The owner's own writer-pseudonym public key (Ed25519).
    pub owner_pseudonym_pk: [u8; 32],
    /// The committed grants.
    pub entries: Vec<GrantSetEntry>,
    /// Preserved unknown top-level fields (never any of the known keys).
    pub unknown: Vec<(String, Value)>,
}

const GRANT_SET_KNOWN: &[&str] = &["entries", "ipnsName", "ownerPseudonymPk"];

/// Decode a grant-set commitment (strict det-CBOR, unknown fields preserved).
pub fn decode_grant_set_commitment(bytes: &[u8]) -> Result<GrantSetCommitment, CodecError> {
    let value = decode(bytes)?;
    let map = value.as_map()?;
    let ipns_name = req(map, "ipnsName")?.as_bytes()?.to_vec();
    let owner_pseudonym_pk = bytes_fixed::<32>(req(map, "ownerPseudonymPk")?, "ownerPseudonymPk")?;
    let mut entries = Vec::new();
    for item in req(map, "entries")?.as_array()? {
        entries.push(GrantSetEntry::from_value(item)?);
    }
    assert_grant_tags_unique(entries.iter().map(|e| e.tag))?;
    Ok(GrantSetCommitment {
        ipns_name,
        owner_pseudonym_pk,
        entries,
        unknown: collect_unknown(map, GRANT_SET_KNOWN),
    })
}

/// Encode a grant-set commitment to its canonical det-CBOR form — the exact
/// preimage the owner ECDSA-signs and a recipient verifies.
///
/// Fails closed on a duplicate-tag commitment with the same `duplicate-grant-tag`
/// verdict `decode_grant_set_commitment` raises, so the sign path never attests
/// bytes every recipient rejects.
pub fn encode_grant_set_commitment(c: &GrantSetCommitment) -> Result<Vec<u8>, CodecError> {
    assert_grant_tags_unique(c.entries.iter().map(|e| e.tag))?;
    let mut m = Map::new();
    m.insert(
        "entries",
        Value::Array(c.entries.iter().map(GrantSetEntry::to_value).collect()),
    );
    m.insert("ipnsName", Value::Bytes(c.ipns_name.clone()));
    m.insert(
        "ownerPseudonymPk",
        Value::Bytes(c.owner_pseudonym_pk.to_vec()),
    );
    merge_unknown(&mut m, &c.unknown);
    Ok(encode(&Value::Map(m)))
}

/// Owner-sign a grant-set commitment: RFC 6979 ECDSA over the det-CBOR preimage.
/// Fails closed before signing on a duplicate-tag commitment, so a release build
/// never publishes an attestation every recipient rejects.
pub fn sign_grant_set(
    signer: &EcdsaSigner,
    c: &GrantSetCommitment,
) -> Result<EcdsaSignature, CodecError> {
    Ok(signer.sign_detcbor(&encode_grant_set_commitment(c)?))
}

/// Verify a grant-set commitment's owner signature. Fails closed with
/// [`TrustViolation::CommitmentInvalid`] when the owner identity key did not
/// attest this tag/pseudonym set — the fail-closed check a recipient runs
/// before trusting a grant. The fail-closed *policy* over this verdict is the
/// engine's adoption gate.
pub fn verify_grant_set(
    verifier: &EcdsaVerifier,
    c: &GrantSetCommitment,
    sig: &EcdsaSignature,
) -> Result<(), CodecError> {
    if verifier.verify_detcbor(&encode_grant_set_commitment(c)?, sig) {
        Ok(())
    } else {
        Err(TrustViolation::CommitmentInvalid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::aead::{KEY_LEN, NONCE_LEN};

    fn grant_ctx(struct_tag: u8) -> AadContext {
        AadContext {
            v: 2,
            id: [0xa0; 16],
            scope: [0xa0; 16],
            epoch: 4,
            struct_tag,
        }
    }

    #[test]
    fn permission_wire_round_trips() {
        for p in [Permission::Read, Permission::Write] {
            assert_eq!(Permission::from_wire(p.as_wire()), Some(p));
        }
        assert_eq!(Permission::from_wire("admin"), None);
    }

    #[test]
    fn grant_blob_payload_round_trips_read_and_write() {
        for write in [None, Some([0x44; 32])] {
            let payload = GrantBlobPayload::new([0x11; 32], write, 7, [0x22; 32]);
            let bytes = encode_grant_blob_payload(&payload);
            let decoded = decode_grant_blob_payload(&bytes).expect("decodes");
            assert_eq!(decoded, payload);
            assert_eq!(encode_grant_blob_payload(&decoded), bytes, "byte-stable");
            assert_eq!(decoded.write_scope_seed().is_some(), write.is_some());
        }
    }

    #[test]
    fn grant_blob_seal_open_round_trip_and_transplant_fails() {
        let recipient = X25519Secret::from_scalar([0x30; 32]);
        let ctx = grant_ctx(super::super::STRUCT_TAG_GRANT_BLOB);
        let payload = GrantBlobPayload::new([0x11; 32], Some([0x44; 32]), 7, [0x22; 32]);
        let sealed = seal_grant_blob(&recipient.public(), &[0x55; 32], &ctx, &payload);
        let opened = open_grant_blob(&recipient, &sealed.enc, &ctx, &sealed.ciphertext).unwrap();
        assert_eq!(opened, payload);
        // A struct-tag transplant recomputes a different AAD → the tag fails.
        let mut wrong = ctx;
        wrong.struct_tag = super::super::STRUCT_TAG_OWNER_BLOB;
        assert_eq!(
            open_grant_blob(&recipient, &sealed.enc, &wrong, &sealed.ciphertext)
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn owner_blob_seal_open_round_trip() {
        let owner = X25519Secret::from_scalar([0x31; 32]);
        let ctx = grant_ctx(super::super::STRUCT_TAG_OWNER_BLOB);
        let payload = OverrideSeedPayload::new([0x77; 32], 4);
        let sealed = seal_owner_blob(&owner.public(), &[0x56; 32], &ctx, &payload);
        let opened = open_owner_blob(&owner, &sealed.enc, &ctx, &sealed.ciphertext).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn ascent_link_derive_and_verify_round_trip() {
        let parent_seed = [0x12; 32];
        let ctx = grant_ctx(super::super::STRUCT_TAG_ASCENT_LINK);
        let payload = OverrideSeedPayload::new([0x77; 32], 4);
        let link = seal_ascent_link(&parent_seed, &[0x57; 32], &ctx, &payload);
        // The plaintext public half is exactly the derived ascent public key.
        assert_eq!(
            link.ascent_public,
            kdf::ascent_keypair(&parent_seed).public().to_bytes()
        );
        let opened = open_ascent_link(&parent_seed, &ctx, &link).unwrap();
        assert_eq!(opened, payload);
        // Container codec is byte-stable.
        let bytes = encode_ascent_link(&link);
        assert_eq!(decode_ascent_link(&bytes).unwrap(), link);
        assert_eq!(
            encode_ascent_link(&decode_ascent_link(&bytes).unwrap()),
            bytes
        );
    }

    #[test]
    fn ascent_link_mismatched_public_half_rejects_before_open() {
        let parent_seed = [0x12; 32];
        let ctx = grant_ctx(super::super::STRUCT_TAG_ASCENT_LINK);
        let payload = OverrideSeedPayload::new([0x77; 32], 4);
        let mut link = seal_ascent_link(&parent_seed, &[0x57; 32], &ctx, &payload);
        // Flip the plaintext public half: derive-and-verify rejects it as a
        // mismatch, never reaching the HPKE open.
        link.ascent_public[0] ^= 0x01;
        assert_eq!(
            open_ascent_link(&parent_seed, &ctx, &link)
                .unwrap_err()
                .check(),
            "ascent-link-mismatch"
        );
        // A different parent seed derives a different keypair → also a mismatch.
        let link2 = seal_ascent_link(&parent_seed, &[0x57; 32], &ctx, &payload);
        assert_eq!(
            open_ascent_link(&[0x13; 32], &ctx, &link2)
                .unwrap_err()
                .check(),
            "ascent-link-mismatch"
        );
    }

    #[test]
    fn history_link_seal_open_round_trip_and_transplant_fails() {
        let key = [0x40; KEY_LEN];
        let nonce = [0x10; NONCE_LEN];
        let ctx = grant_ctx(super::super::STRUCT_TAG_HISTORY_LINK);
        let payload = HistoryLinkPayload::new([0x99; 32], 3);
        let sealed = seal_history_link(&key, &nonce, &ctx, &payload);
        assert_eq!(open_history_link(&key, &ctx, &sealed).unwrap(), payload);
        let mut wrong = ctx;
        wrong.epoch += 1;
        assert_eq!(
            open_history_link(&key, &wrong, &sealed)
                .unwrap_err()
                .check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn grant_set_commitment_round_trips_and_verifies() {
        let owner = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
        let c = GrantSetCommitment {
            ipns_name: b"scope-root-name".to_vec(),
            owner_pseudonym_pk: [0x88; 32],
            entries: vec![
                GrantSetEntry::new([0x01; 32], Permission::Read, [0x02; 32]),
                GrantSetEntry::new([0x03; 32], Permission::Write, [0x04; 32]),
            ],
            unknown: Vec::new(),
        };
        let bytes = encode_grant_set_commitment(&c).expect("encodes");
        assert_eq!(decode_grant_set_commitment(&bytes).unwrap(), c);
        assert_eq!(
            encode_grant_set_commitment(&decode_grant_set_commitment(&bytes).unwrap()).unwrap(),
            bytes,
            "byte-stable"
        );
        let sig = sign_grant_set(&owner, &c).expect("signs");
        assert!(verify_grant_set(&owner.verifying_key(), &c, &sig).is_ok());
        // Tampering with a committed entry fails the commitment.
        let mut tampered = c.clone();
        tampered.entries[0].permission = Permission::Write;
        assert_eq!(
            verify_grant_set(&owner.verifying_key(), &tampered, &sig)
                .unwrap_err()
                .check(),
            "commitment-invalid"
        );
    }

    #[test]
    fn duplicate_grant_set_tag_rejects() {
        // The confused-deputy shape: one tag committed twice with a different
        // permission and pseudonym. Hand-built CBOR, the way a hostile peer's
        // bytes arrive, so decode is what rejects it here.
        let mut a = Map::new();
        a.insert("permission", Value::Text("read".into()));
        a.insert("pseudonymPk", Value::Bytes(vec![0x02; 32]));
        a.insert("tag", Value::Bytes(vec![0x01; 32]));
        let mut b = Map::new();
        b.insert("permission", Value::Text("write".into()));
        b.insert("pseudonymPk", Value::Bytes(vec![0x09; 32]));
        b.insert("tag", Value::Bytes(vec![0x01; 32])); // same tag as `a`
        let mut m = Map::new();
        m.insert("entries", Value::Array(vec![Value::Map(a), Value::Map(b)]));
        m.insert("ipnsName", Value::Bytes(b"n".to_vec()));
        m.insert("ownerPseudonymPk", Value::Bytes(vec![0x88; 32]));
        let bytes = encode(&Value::Map(m));
        assert_eq!(
            decode_grant_set_commitment(&bytes).unwrap_err().check(),
            "duplicate-grant-tag"
        );
    }

    #[test]
    fn encode_and_sign_reject_duplicate_tags() {
        // Release-active guard: a caller-built dup-tag commitment never encodes
        // or gets signed, so the sign path cannot publish bytes decode rejects.
        // Exercised without relying on a `debug_assert`.
        let owner = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
        let c = GrantSetCommitment {
            ipns_name: b"n".to_vec(),
            owner_pseudonym_pk: [0x88; 32],
            entries: vec![
                GrantSetEntry::new([0x01; 32], Permission::Read, [0x02; 32]),
                GrantSetEntry::new([0x01; 32], Permission::Write, [0x04; 32]),
            ],
            unknown: Vec::new(),
        };
        assert_eq!(
            encode_grant_set_commitment(&c).unwrap_err().check(),
            "duplicate-grant-tag"
        );
        assert_eq!(
            sign_grant_set(&owner, &c).unwrap_err().check(),
            "duplicate-grant-tag"
        );
    }

    #[test]
    fn invalid_permission_rejects() {
        let mut entry = Map::new();
        entry.insert("permission", Value::Text("admin".into()));
        entry.insert("pseudonymPk", Value::Bytes(vec![0x02; 32]));
        entry.insert("tag", Value::Bytes(vec![0x01; 32]));
        let mut m = Map::new();
        m.insert("entries", Value::Array(vec![Value::Map(entry)]));
        m.insert("ipnsName", Value::Bytes(b"n".to_vec()));
        m.insert("ownerPseudonymPk", Value::Bytes(vec![0x88; 32]));
        let bytes = encode(&Value::Map(m));
        assert_eq!(
            decode_grant_set_commitment(&bytes).unwrap_err().check(),
            "invalid-permission"
        );
    }
}
