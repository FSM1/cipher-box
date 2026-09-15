//! The shared scope-root re-seal helper (blueprint/engine.md "Rotation
//! primitives: rotateScope", "sweep"; CONTEXT.md "Grant section").
//!
//! [`reseal_scope_root`] assembles a scope root's signed [`GrantSection`] — its
//! grant blobs (re-wrapped for the committed set), owner blob, owner-write-blob
//! (the write-plane mirror, authored beside the write-body), ascent link,
//! per-epoch history links, and sealed write-body — each detached-signed by the
//! rotator's writer pseudonym. It is a **pure composition** of `crates/core`'s
//! seal primitives: no crypto of its own, it samples no entropy (the injected
//! [`Entropy`] seam supplies every HPKE ephemeral scalar and seal nonce), and
//! reads no clock. Its [`ResealSeeds`] source is the axis its callers differ on:
//!
//! - **`rotateScope`** passes a fresh random override seed at a new read epoch
//!   plus the prior seed for a fresh history link — the read-plane root cut.
//! - **the sweep** passes the scope's *existing* seed at the *current* epoch with
//!   `prev = None` — a metadata-only catch-up minting no new seed or history link
//!   (blueprint/engine.md "Sweeps re-seal metadata only").
//! - **`rotateScopeWrite`**'s name wave leaves the read plane alone and passes a
//!   fresh write scope seed at an advanced write epoch with
//!   [`WriteHistory::Cut`].
//!
//! # Revocation completeness is the point
//!
//! A grant blob is re-wrapped for **exactly** the committed set: one blob per
//! grant-ledger entry, and the ledger MUST equal the owner-signed commitment
//! (`(tag → permission)`), enforced fail-closed up front via
//! [`enforce_committed_ledger`] — the encode-side mirror of the adoption gate's
//! resolve check (AGENTS.md rule 8). A grantee removed from the commitment and
//! ledger by the read-revoke trigger is therefore **absent** from the re-wrapped
//! blobs — that absence is the revocation; a divergent ledger is rejected here,
//! never sealed.

use zeroize::{Zeroize, Zeroizing};

use cipherbox_core::error::CodecError;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, AscentLink, ChildScopeRef, GrantBlobPayload, GrantLedgerEntry, GrantSection,
    GrantSetCommitment, HistoryLinkPayload, MAX_GRANT_BLOBS, MAX_HISTORY_LINKS,
    MAX_WRITE_HISTORY_LINK_BYTES, OverrideSeedPayload, OwnerWriteBlobPayload, Permission,
    PreservedFields, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_HISTORY_LINK,
    STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_WRITE_BODY,
    STRUCT_TAG_WRITE_HISTORY_LINK, SignedAscentLink, SignedGrantBlob, SignedOwnerBlob,
    SignedOwnerWriteBlob, SignedSealed, StructureSigInput, WriteBody, encode_grant_section,
    encode_write_body, is_write_body_over_bound, open_ascent_link, open_history_link,
    open_owner_blob, seal, seal_ascent_link_to, seal_grant_blob, seal_history_link,
    seal_owner_blob, seal_owner_history_link, seal_owner_write_blob, sign_structure,
};
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN as ECDSA_SIG_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, ct_eq};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

use super::cascade::CascadeTarget;
use crate::content::limits::{MAX_RETAINED_HISTORY_LINK_BYTES, resealable_section_bytes};
use crate::entropy::{Entropy, EntropyError, fresh_ephemeral, fresh_nonce};
use crate::gate::is_committed_write_pseudonym;
use crate::grants::{enforce_committed_ledger, recipient_blinded_tag};

/// How many history links a re-seal carries forward — the ratchet's retained
/// window, in rotations (blueprint/core.md "History-link retention"). The window
/// is the deepest epoch lag a backward walk can cover; a node past it is
/// readable by nobody, and the sweep reports it unreachable rather than
/// re-sealing it forward.
const MAX_RETAINED_HISTORY_LINKS: usize = 64;

// Under the decode bound, or a re-seal mints sections the decoder refuses; at
// least one, or `keep` below underflows and disables the prune in release.
const _: () = assert!(MAX_RETAINED_HISTORY_LINKS >= 1);
const _: () = assert!(MAX_RETAINED_HISTORY_LINKS <= MAX_HISTORY_LINKS);

/// The key a re-seal mints a descendant scope root's ascent link under.
///
/// The two arms are the two ways a rotator can be entitled to the root: an
/// ancestor holds the seed the keypair derives from, and a grantee holds only
/// the public half the record it is replacing already carries (blueprint/
/// engine.md "rotateScope": a grantee scope-exit rotation re-seals the ascent
/// link to its public half).
#[derive(Clone, Copy)]
pub enum AscentAuthority<'a> {
    /// The parent node seed: derive the keypair, seal to it, and reopen the
    /// result as an ancestor reader would ([`verify_ascent_link`]).
    ParentSeed(&'a [u8; SECRET_LEN]),
    /// The public half the record being replaced already publishes — all a
    /// holder with no ancestor seed has to seal to.
    ///
    /// The carried half is inside the ascent link's own structure signature
    /// (blueprint/core.md "Structure signatures"), so a bare `writeScopeSeed`
    /// holder cannot plant one — the gate refuses a swap it cannot sign for.
    /// The residual is a **committed** writer planting and signing its own key,
    /// which an ancestor reports unreachable rather than attributable (the
    /// ascent-link arm of [`crate::gate::adopt_deferred`]) and which an owner
    /// cut overwrites: that arm derives the public from the parent seed rather
    /// than carrying it.
    CarriedPublic(&'a [u8; 32]),
}

/// The identity, recipients, and signing capability of one scope root — the
/// context-that-does-not-change-across-epochs half of a re-seal.
#[derive(Clone, Copy)]
pub struct ScopeRootIdentity<'a> {
    /// The envelope format+suite version.
    pub v: u64,
    /// The scope-root node id (== scope id; `id` and `scope` in every AAD).
    pub scope_id: [u8; 16],
    /// The scope root's opaque `ipnsName` bytes (the commitment's anchor).
    pub ipns_name: &'a [u8],
    /// The vault owner's X25519 encryption-subkey public — the owner-blob
    /// recipient (the owner is an implicit, unrevokable grantee of every scope).
    pub owner_enc_pub: &'a X25519Public,
    /// The owner's X25519 encryption-subkey secret, when the re-sealer holds it.
    /// Required to mint the write-plane history link a write cut owes
    /// ([`ResealError::OwnerKeyRequiredForWriteCut`]).
    pub owner_enc_secret: Option<&'a X25519Secret>,
    /// What this re-seal mints the ascent link under; `None` at the vault root,
    /// which carries no ascent link.
    pub ascent: Option<AscentAuthority<'a>>,
    /// Whether this root is a descendant scope root, and so owes an ascent link.
    /// Sourced from what the record being replaced carried, or from the role a
    /// freshly minted root takes — never from [`Self::ascent`], which is the
    /// field that would *produce* the link and so cannot also be the evidence one
    /// is owed ([`ResealError::AscentLinkDropped`]).
    pub owes_ascent_link: bool,
    /// The rotator's writer-pseudonym signer — detached-signs every structure.
    pub pseudonym_signer: &'a Ed25519Signer,
}

/// The previous epoch's plane seed, sealed into a fresh history link under the
/// new epoch's structure key (the key-regression ratchet). Used on both planes:
/// the read plane's `historyLinks`, and the write-body's single write-plane
/// link.
pub struct PrevEpochSeed<'a> {
    /// The previous epoch's scope seed on this plane.
    pub seed: &'a [u8; SECRET_LEN],
    /// The previous epoch it belongs to.
    pub epoch: u64,
}

/// The write-plane history link a re-seal publishes in the write-body.
///
/// A **cut cannot carry**, and the type is what makes that unrepresentable. The
/// pre-cut link is authored under the retiring `writeScopeSeed`, which every
/// write grantee holds — including the one a write rotation revokes — so
/// carrying it would owner-sign a revokee's opaque bytes into the moved root,
/// where the seed they name is the one an orphaned-name walk would follow.
pub enum WriteHistory<'a> {
    /// This re-seal mints the write plane with no predecessor — the state at
    /// write epoch 1 ([`ResealError::EmptyWriteHistoryAboveFirstEpoch`]).
    Genesis,
    /// The write plane is untouched (a read rotation or a sweep): the root's
    /// existing opaque link stays byte-for-byte, still openable by the owner at
    /// the write epoch that minted it. A blob past
    /// [`MAX_WRITE_HISTORY_LINK_BYTES`] is refused
    /// ([`ResealError::CarriedWriteHistoryLinkTooLarge`]).
    ///
    /// A committed writer authors the value, so an empty one is that record's
    /// own state and rides through. Refusing it here would hand a write grantee
    /// a scope root the owner can never re-key.
    Carried(&'a [u8]),
    /// The write plane is being cut: mint a fresh link over the retiring write
    /// scope seed, sealed to the owner at the advanced write epoch.
    Cut(PrevEpochSeed<'a>),
}

/// The seed source of a re-seal — the axis that distinguishes a rotation cut
/// (fresh seed, new epoch, `prev = Some`) from a sweep catch-up (existing seed,
/// current epoch, `prev = None`).
pub struct ResealSeeds<'a> {
    /// The scope's read-plane override (read scope) seed sealed into the owner
    /// blob, ascent link, and every grant blob's `readScopeSeed`.
    pub override_seed: &'a [u8; SECRET_LEN],
    /// The read epoch this re-seal publishes at.
    pub read_epoch: u64,
    /// The prior epoch's seed for a fresh history link, or `None` when this
    /// re-seal introduces no new epoch (sweep catch-up).
    pub prev: Option<PrevEpochSeed<'a>>,
    /// The write-plane scope seed — unchanged by a read rotation — used to derive
    /// the write key/seed and sealed into write grants' `writeScopeSeed`.
    pub write_scope_seed: &'a [u8; SECRET_LEN],
    /// The write epoch the write-body publishes at (unchanged by a read rotation).
    pub write_epoch: u64,
    /// The write-plane history link: carried, or minted over the retiring write
    /// scope seed when this re-seal cuts the write plane.
    pub write_history: WriteHistory<'a>,
    /// The stable per-scope pointer read key carried in every grant blob.
    pub pointer_read_key: &'a [u8; SECRET_LEN],
}

impl ResealSeeds<'_> {
    /// Both planes' history links step the ratchet backward, and [`ratchet_step`]
    /// drops one whose epoch is not exactly one below — so a link that does not
    /// sit one below the epoch it seals under is one no walk could follow. The
    /// single home of that invariant across the two planes (AGENTS.md rule 8).
    ///
    /// The two planes part company above that floor. The read plane's links are
    /// a **contiguous chain, one epoch per step** (blueprint/core.md
    /// "History-link retention"), so a gap strands every epoch beyond it. The
    /// write plane carries a single link that "departs from the read plane's
    /// ratchet construction" (blueprint/core.md "Write-body") — there is no
    /// chain to hole, and its epoch is monotonic only, the axis
    /// [`build_repoint_object`](super::rotate_write::build_repoint_object)
    /// enforces on `writeEpoch`.
    ///
    /// The write plane owes one more, held here because every re-seal runs this
    /// check ([`ResealError::EmptyWriteHistoryAboveFirstEpoch`]).
    fn check_history_descends(&self) -> Result<(), ResealError> {
        if let Some(prev) = self.prev.as_ref() {
            if prev.epoch >= self.read_epoch {
                return Err(ResealError::HistoryLinkNotDescending);
            }
            // Cannot overflow: `prev.epoch` is below `read_epoch`.
            if prev.epoch + 1 != self.read_epoch {
                return Err(ResealError::HistoryLinkNotContiguous);
            }
        }
        match &self.write_history {
            WriteHistory::Cut(prev) if prev.epoch >= self.write_epoch => {
                return Err(ResealError::HistoryLinkNotDescending);
            }
            WriteHistory::Genesis if self.write_epoch != 1 => {
                return Err(ResealError::EmptyWriteHistoryAboveFirstEpoch);
            }
            _ => {}
        }
        Ok(())
    }
}

/// The owner-committed grant set plus the write-body content a re-seal carries.
#[derive(Clone, Copy)]
pub struct CommittedSet<'a> {
    /// The owner-signed commitment (reused verbatim on a grantee rotation;
    /// owner-re-signed by the read-revoke trigger before it reaches here). One
    /// grant blob is re-wrapped per entry.
    pub commitment: &'a GrantSetCommitment,
    /// The 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: &'a [u8; ECDSA_SIG_LEN],
    /// The authoritative grant ledger. MUST equal `commitment` as a
    /// `(tag → permission)` set (enforced closed).
    pub grant_ledger: &'a [GrantLedgerEntry],
    /// The directly-descendant scope roots (the F-4 cascade index, #38 D6).
    pub direct_child_scope_index: &'a [ChildScopeRef],
    /// Recipient encryption keys **this scope's** re-key must mint no blob for,
    /// whatever `commitment` says.
    ///
    /// The encryption key, not the identity key: the commitment binds
    /// `recipientEncPk` under the owner's own signature, while
    /// `recipientIdentityPk` is a label any committed writer can re-author.
    ///
    /// Per scope, never carried down a cascade: an ancestor's cut says nothing
    /// about a grant the owner issued independently one level below it. The
    /// cascade fills this from the scope's own durable revocation floor
    /// (`rotation/cascade.rs::effective_revoked_recipients`).
    pub revoked_recipients: &'a [[u8; SECRET_LEN]],
}

/// A fail-closed re-seal failure. Every variant leaves nothing published — the
/// caller ([`rotate_scope`](super::rotate::rotate_scope)) never advances a floor
/// on any of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResealError {
    /// The grant ledger to re-wrap does not match the owner-signed committed set
    /// (a write-grantee tried to add, drop, or re-permission a tag). The same
    /// invariant the adoption gate rejects on resolve, enforced here so a re-seal
    /// never seals a section the gate would refuse (fail-closed symmetry).
    LedgerDivergesFromCommitment,
    /// The rotator's pseudonym signer is not the owner-committed pseudonym key.
    /// Detach-signing every structure under an uncommitted key mints a scope root
    /// the adoption gate always rejects (an unopenable root); the same
    /// signer-binding invariant the gate checks on resolve, enforced here so a
    /// re-seal never signs a section the gate would refuse (fail-closed symmetry).
    SignerNotCommitted,
    /// A committed grant entry's recipient encryption key is unusable
    /// (malformed or low-order X25519). A grant can never be wrapped to an
    /// unopenable key, and the owner signed this one, so the whole re-seal fails
    /// closed rather than skip the entry ([`adopt_recipients`]).
    UnusableRecipientKey,
    /// A committed entry's recipient does not derive the tag it is filed under.
    /// Only raised where the re-sealer holds the owner encryption subkey, which
    /// is the only authority that can tell — the mask came off under the wrong
    /// scope key, or the owner signed a pair its own subkey does not reproduce.
    TagNotBoundToRecipient,
    /// The freshly sealed ascent link does not reopen as this epoch's override
    /// seed — bytes the gate's stage 3 rejects whole-record
    /// ([`verify_ascent_link`]).
    AscentLinkMismatch,
    /// A descendant scope root would be re-sealed with no ascent link, because
    /// no parent node seed was supplied to mint one. The ascent link is what
    /// binds the record to `nodeSeed(parent seed, child)`, and both gates that
    /// prove a claimed child require it, so publishing without one mints a
    /// record this build's own reader permanently rejects. Release-active
    /// (AGENTS.md rule 8).
    AscentLinkDropped,
    /// A scope root that owes no ascent link was handed a parent node seed to
    /// mint one from. Every reader re-derives the parent seed from its own
    /// descent, so a link no descent reproduces is rejected at the gate's ascent
    /// stage on every read — and the name's sequence floor has already advanced,
    /// so the last good record cannot be re-adopted. Release-active (AGENTS.md
    /// rule 8).
    AscentLinkNotOwed,
    /// The carried ascent public half is not a usable X25519 point, so an
    /// ascent link sealed to it could never be opened by the descent it exists
    /// to serve.
    UnusableAscentPublic,
    /// Entropy acquisition failed; no seal proceeds without fresh randomness.
    Entropy(EntropyError),
    /// More carried history links than the codec's frozen bound admits — a set
    /// that could only ever produce a section this build's own encoder rejects.
    TooManyHistoryLinks,
    /// More committed grants than the codec's frozen bound admits — a set that
    /// could only ever produce a section this build's own encoder rejects.
    TooManyCommittedGrants,
    /// A mint on either plane would seal a link over an epoch at or above the one
    /// it is sealed under — a link the ratchet, which only ever steps backward,
    /// could not walk. Release-active (AGENTS.md rule 8).
    HistoryLinkNotDescending,
    /// A read-plane mint would seal a link over an epoch more than one below the
    /// one it is sealed under, holing a chain blueprint/core.md
    /// ("History-link retention") specifies as contiguous — every epoch past the
    /// hole becomes unreachable to every reader. Read plane only: the write
    /// plane carries no chain. Release-active (AGENTS.md rule 8).
    HistoryLinkNotContiguous,
    /// A [`WriteHistory::Genesis`] mint was asked at a write epoch above 1. An
    /// empty `writeHistoryLink` means "no link" — the state at write epoch 1
    /// ([`WriteBody::write_history_link`]) — so the pair advertises a
    /// predecessor epoch it holds no link to walk back to, and an orphaned-name
    /// walk stops there reporting nothing rather than refusing. Release-active,
    /// and held against what this build mints rather than what it carries: the
    /// carried value is a committed writer's, and refusing that would make the
    /// scope un-re-keyable.
    ///
    /// [`WriteBody::write_history_link`]: cipherbox_core::seal::WriteBody::write_history_link
    EmptyWriteHistoryAboveFirstEpoch,
    /// A [`WriteHistory::Cut`] was asked of a re-sealer holding no owner
    /// encryption subkey — only the owner can mint the link
    /// ([`seal_owner_history_link`]).
    OwnerKeyRequiredForWriteCut,
    /// The re-sealed write-body's plaintext is past the codec's frozen total
    /// bound ([`cipherbox_core::seal::MAX_WRITE_BODY_BYTES`]) — bytes this
    /// build's own decoder always rejects. Named apart from the generic encode
    /// fold so an operator can tell an over-budget body from an encoder fault.
    WriteBodyTooLarge,
    /// A freshly minted history link is past
    /// [`MAX_RETAINED_HISTORY_LINK_BYTES`], the bound this same re-seal drops a
    /// carried link at. Publishing one would mint a link this build's own
    /// retention discards on the next pass, taking every older link with it —
    /// the release-active encode half of that drop (AGENTS.md rule 8).
    HistoryLinkTooLarge {
        /// The minted link's sealed length.
        size: usize,
        /// The bound it must stay under.
        limit: usize,
    },
    /// A carried write-plane history link is past
    /// [`MAX_WRITE_HISTORY_LINK_BYTES`]. Emitting an empty link in its place
    /// publishes, above write epoch 1, the very value the
    /// [`WriteHistory::Genesis`] arm refuses. The bound is the decoder's own,
    /// so no gate-passed record reaches this refusal. Release-active (AGENTS.md
    /// rule 8).
    CarriedWriteHistoryLinkTooLarge {
        /// The carried link's sealed length.
        size: usize,
        /// The bound it must stay under.
        limit: usize,
    },
    /// The freshly minted section is past
    /// [`resealable_section_bytes`](crate::content::limits::resealable_section_bytes)
    /// at this root's committed grant count — the budget the scope root's own
    /// authoring reserves room for. Release-active (AGENTS.md rule 8).
    SectionNotResealable {
        /// The minted section's encoded size.
        size: usize,
        /// The budget it met.
        limit: usize,
    },
    /// A re-sealed structure could not be encoded — a duplicate ledger tag, or
    /// nesting past the codec's `MAX_DEPTH`.
    Encode(cipherbox_core::error::CodecError),
}

impl core::fmt::Display for ResealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResealError::LedgerDivergesFromCommitment => {
                f.write_str("grant ledger diverges from the owner-signed committed set")
            }
            ResealError::SignerNotCommitted => {
                f.write_str("rotator signer is not the owner-committed pseudonym key")
            }
            ResealError::UnusableRecipientKey => {
                f.write_str("committed recipient encryption key is unusable")
            }
            ResealError::TagNotBoundToRecipient => {
                f.write_str("a committed recipient does not derive the tag it is filed under")
            }
            ResealError::HistoryLinkTooLarge { size, limit } => {
                write!(
                    f,
                    "minted history link {size} bytes over the {limit}-byte bound"
                )
            }
            ResealError::CarriedWriteHistoryLinkTooLarge { size, limit } => {
                write!(
                    f,
                    "carried write history link {size} bytes over the {limit}-byte bound"
                )
            }
            ResealError::SectionNotResealable { size, limit } => {
                write!(f, "re-sealed grant section {size} > {limit}")
            }
            ResealError::AscentLinkMismatch => {
                f.write_str("sealed ascent link does not reopen as this scope root's override seed")
            }
            ResealError::AscentLinkDropped => {
                f.write_str("descendant scope root re-sealed with no ascent link to bind it")
            }
            ResealError::AscentLinkNotOwed => {
                f.write_str("scope root owing no ascent link was handed a parent seed to mint one")
            }
            ResealError::UnusableAscentPublic => {
                f.write_str("carried ascent public half is not a usable X25519 key")
            }
            ResealError::EmptyWriteHistoryAboveFirstEpoch => {
                f.write_str("write history minted empty at a write epoch above 1")
            }
            ResealError::Entropy(e) => write!(f, "entropy error: {e}"),
            ResealError::TooManyHistoryLinks => {
                f.write_str("carried history links exceed the codec's frozen bound")
            }
            ResealError::TooManyCommittedGrants => {
                f.write_str("committed grants exceed the codec's frozen bound")
            }
            ResealError::HistoryLinkNotDescending => {
                f.write_str("history link would not step the ratchet backward")
            }
            ResealError::HistoryLinkNotContiguous => {
                f.write_str("history link would leave a hole in the read-plane ratchet")
            }
            ResealError::OwnerKeyRequiredForWriteCut => {
                f.write_str("write-plane cut needs the owner encryption subkey to mint its link")
            }
            ResealError::WriteBodyTooLarge => {
                f.write_str("re-sealed write-body exceeds the codec's frozen total bound")
            }
            ResealError::Encode(e) => write!(f, "structure encode failed: {}", e.check()),
        }
    }
}

impl std::error::Error for ResealError {}

impl ResealError {
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            ResealError::LedgerDivergesFromCommitment => "ledger-diverges-from-commitment",
            ResealError::SignerNotCommitted => "signer-not-committed",
            ResealError::UnusableRecipientKey => "unusable-recipient-key",
            ResealError::TagNotBoundToRecipient => "tag-not-bound-to-recipient",
            ResealError::AscentLinkMismatch => "ascent-link-mismatch",
            ResealError::AscentLinkDropped => "ascent-link-dropped",
            ResealError::AscentLinkNotOwed => "ascent-link-not-owed",
            ResealError::UnusableAscentPublic => "unusable-ascent-public",
            ResealError::Entropy(_) => "entropy-error",
            ResealError::TooManyHistoryLinks => "too-many-history-links",
            ResealError::TooManyCommittedGrants => "too-many-committed-grants",
            ResealError::HistoryLinkNotDescending => "history-link-not-descending",
            ResealError::HistoryLinkNotContiguous => "history-link-not-contiguous",
            ResealError::EmptyWriteHistoryAboveFirstEpoch => {
                "empty-write-history-above-first-epoch"
            }
            ResealError::OwnerKeyRequiredForWriteCut => "owner-key-required-for-write-cut",
            ResealError::WriteBodyTooLarge => "write-body-too-large",
            ResealError::HistoryLinkTooLarge { .. } => "history-link-too-large",
            ResealError::CarriedWriteHistoryLinkTooLarge { .. } => {
                "carried-write-history-link-too-large"
            }
            ResealError::SectionNotResealable { .. } => "section-not-resealable",
            ResealError::Encode(_) => "structure-encode-failed",
        }
    }
}

/// Split the write-body encode's own total-size refusal out of the generic
/// encode fold, so the oversize verdict reaches a caller under its own name.
fn write_body_encode_error(error: CodecError) -> ResealError {
    if is_write_body_over_bound(&error) {
        ResealError::WriteBodyTooLarge
    } else {
        ResealError::Encode(error)
    }
}

/// The index of the oldest link in `carried` that still walks as this scope's
/// ratchet from `head`, newest first — everything older than the first link that
/// fails to open is dropped rather than published, since no reader could walk
/// past that break either (blueprint/core.md "History-link retention").
///
/// Truncating rather than refusing is deliberate: the carried set is
/// attacker-influenced — the adoption gate authenticates each link's signature
/// but nothing about their order — so failing the re-seal would let a committed
/// write-grantee permanently block the very rotation that revokes them.
fn walkable_chain_start(
    v: u64,
    scope_id: [u8; 16],
    head: &PrevEpochSeed<'_>,
    carried: &[SignedSealed],
) -> usize {
    let mut seed = Zeroizing::new(*head.seed);
    let mut epoch = head.epoch;
    for (i, link) in carried.iter().enumerate().rev() {
        let Some(prev) = ratchet_step(v, scope_id, &seed, epoch, link) else {
            return i + 1;
        };
        (seed, epoch) = prev;
    }
    0
}

/// One backward step of the key-regression ratchet: open `link` under `seed`'s
/// structure key at `epoch` and yield the epoch before it. `None` when the link
/// will not open, or when its epoch does not descend — a chain that cannot
/// terminate. The one home of the ratchet's key and AAD derivation, so the
/// writer's retention decision ([`walkable_chain_start`]) and the reader's seed
/// recovery ([`seed_at_epoch`]) can never disagree on it.
fn ratchet_step(
    v: u64,
    scope_id: [u8; 16],
    seed: &[u8; SECRET_LEN],
    epoch: u64,
    link: &SignedSealed,
) -> Option<(Zeroizing<[u8; SECRET_LEN]>, u64)> {
    let key = kdf::structure_key(seed, STRUCT_TAG_HISTORY_LINK);
    let ctx = ctx_for(v, scope_id, epoch, STRUCT_TAG_HISTORY_LINK);
    let payload = open_history_link(key.as_bytes(), &ctx, &link.sealed).ok()?;
    // One epoch per step, the decode-side mirror of
    // [`ResealSeeds::check_history_descends`]. `None` truncates the walk rather
    // than refusing it — the carried set is attacker-influenced (blueprint/core.md
    // "History-link retention").
    if payload.prev_epoch.checked_add(1) != Some(epoch) {
        return None;
    }
    Some((Zeroizing::new(*payload.prev_seed()), payload.prev_epoch))
}

/// Walk a scope's key-regression ratchet backward from its current seed to the
/// seed `target_epoch` was sealed under — the read a lagging interior node needs
/// before it can be re-sealed forward (CONTEXT.md "History link").
///
/// `carried_history_links` are a published section's, oldest epoch first, so the
/// newest opens under `current_seed` at `current_epoch`. Every step descends, so
/// an epoch at or above `current_epoch` is only reachable when it *is*
/// `current_epoch`. Returns `None` when the ratchet cannot reach
/// `target_epoch`: a link that will not open, an epoch that does not descend, or
/// an epoch older than the retained window — all unreadable to every reader, not
/// just this one.
pub fn seed_at_epoch(
    v: u64,
    scope_id: [u8; 16],
    current_seed: &[u8; SECRET_LEN],
    current_epoch: u64,
    carried_history_links: &[SignedSealed],
    target_epoch: u64,
) -> Option<Zeroizing<[u8; SECRET_LEN]>> {
    let mut seed = Zeroizing::new(*current_seed);
    let mut epoch = current_epoch;
    for link in carried_history_links.iter().rev() {
        if epoch == target_epoch {
            return Some(seed);
        }
        (seed, epoch) = ratchet_step(v, scope_id, &seed, epoch, link)?;
    }
    (epoch == target_epoch).then_some(seed)
}

/// Seal one read-plane history link — `prev`'s seed under `seed`'s structure
/// key, bound to `epoch` — the ratchet's single backward step.
fn mint_history_link<E: Entropy>(
    entropy: &mut E,
    v: u64,
    scope_id: [u8; 16],
    seed: &[u8; SECRET_LEN],
    epoch: u64,
    prev: &PrevEpochSeed<'_>,
) -> Result<Vec<u8>, ResealError> {
    let structure_key = kdf::structure_key(seed, STRUCT_TAG_HISTORY_LINK);
    let nonce = fresh_nonce(entropy).map_err(ResealError::Entropy)?;
    let ctx = ctx_for(v, scope_id, epoch, STRUCT_TAG_HISTORY_LINK);
    let payload = HistoryLinkPayload::new(*prev.seed, prev.epoch);
    seal_history_link(structure_key.as_bytes(), &nonce, &ctx, &payload).map_err(ResealError::Encode)
}

/// Seal the write plane's single history link — `prev`'s retiring write scope
/// seed sealed by the owner to the owner at `epoch` (see
/// [`seal_owner_history_link`] for why the owner and not the plane seed).
fn mint_owner_history_link<E: Entropy>(
    entropy: &mut E,
    v: u64,
    scope_id: [u8; 16],
    owner_enc_secret: &X25519Secret,
    epoch: u64,
    prev: &PrevEpochSeed<'_>,
) -> Result<Vec<u8>, ResealError> {
    let mut ephemeral = *fresh_ephemeral(entropy).map_err(ResealError::Entropy)?;
    let ctx = ctx_for(v, scope_id, epoch, STRUCT_TAG_WRITE_HISTORY_LINK);
    let payload = HistoryLinkPayload::new(*prev.seed, prev.epoch);
    let sealed = seal_owner_history_link(owner_enc_secret, &ephemeral, &ctx, &payload);
    ephemeral.zeroize();
    sealed.map_err(ResealError::Encode)
}

/// Adopt every committed entry's `recipientEncPk` once, in commitment order —
/// the keys the grant-blob loop wraps to. See [`GrantSetEntry`] for why the
/// recipient comes from the commitment.
///
/// A committed key core refuses to adopt is the owner attesting a key nothing
/// can seal to, so the whole re-seal fails closed rather than skip the entry.
fn adopt_recipients(
    identity: &ScopeRootIdentity<'_>,
    committed: &CommittedSet<'_>,
    pointer_read_key: &[u8; SECRET_LEN],
) -> Result<Vec<X25519Public>, ResealError> {
    committed
        .commitment
        .entries
        .iter()
        .map(|e| {
            let recipient = X25519Public::from_bytes(e.recipient_enc_pk(pointer_read_key))
                .ok_or(ResealError::UnusableRecipientKey)?;
            // The committed tag is `blind(ECDH(ownerEnc, recipient), name)`, so
            // where the owner secret is in hand it proves the unmask used the
            // right scope key. Without it the re-seal would wrap this scope's
            // next seed to bytes nobody holds and lock the whole set out.
            if let Some(owner_enc_secret) = identity.owner_enc_secret
                && recipient_blinded_tag(owner_enc_secret, &recipient, identity.ipns_name)
                    != Some(e.tag)
            {
                return Err(ResealError::TagNotBoundToRecipient);
            }
            Ok(recipient)
        })
        .collect()
}

/// Assemble one scope root's signed [`GrantSection`] at the epoch and seed the
/// `seeds` source dictates, re-wrapping grant blobs for exactly the committed
/// set. Pure composition of core seal primitives; the injected `entropy`
/// supplies every HPKE ephemeral scalar and seal nonce.
///
/// `carried_history_links` keep their sealed bytes verbatim — each stays
/// openable under the epoch key that minted it — but are re-signed at this
/// re-seal's read epoch, the one the gate recomputes every structure at. When
/// `seeds.prev` is `Some`, one freshly-minted link (the prior seed under the new
/// epoch's structure key) is appended, and the wire order is **oldest epoch
/// first**.
///
/// A rotation keeps the retained window's walkable suffix
/// ([`walkable_chain_start`]), so the prune to the newest
/// [`MAX_RETAINED_HISTORY_LINKS`] provably drops the oldest end rather than an
/// assumed one. A sweep publishes at the floor epoch without minting a link, so
/// the record's epoch label can outrun the newest link's minting epoch — the
/// AAD a walk needs, which [`ResealSeeds`] does not carry — leaving it unable to
/// walk or safely prune; it appends nothing, so the set cannot grow there.
/// Callers MUST still source the set from a gate-passed section.
///
/// Fails closed — see [`ResealError`] — before sealing anything on a divergent
/// ledger, an unusable recipient key, or a row not bound to its recipient tag,
/// so a partial, unopenable or misdirected section is never produced. Terminal-owner rule: this function owns only the transient
/// seal plaintexts (zeroized by the core seal primitives); every borrowed seed
/// stays the caller's to zero.
pub fn reseal_scope_root<E: Entropy>(
    entropy: &mut E,
    identity: &ScopeRootIdentity<'_>,
    seeds: &ResealSeeds<'_>,
    committed: &CommittedSet<'_>,
    carried_history_links: &[SignedSealed],
) -> Result<GrantSection, ResealError> {
    // Fail-closed BEFORE any seal (see `ResealError::SignerNotCommitted`). The
    // set is the gate's own stage-3 authority set, so an owner and a committed
    // write grantee are admitted on exactly the terms a reader will re-check.
    // Pseudonym pubkeys are public, so a plain byte compare is correct.
    if !is_committed_write_pseudonym(
        committed.commitment,
        &identity.pseudonym_signer.verifying_key().to_bytes(),
    ) {
        return Err(ResealError::SignerNotCommitted);
    }

    // Fail-closed BEFORE any seal, both directions — the mint below keys off the
    // seed alone (see `ResealError::AscentLinkDropped` and `AscentLinkNotOwed`).
    if identity.owes_ascent_link && identity.ascent.is_none() {
        return Err(ResealError::AscentLinkDropped);
    }
    if !identity.owes_ascent_link && identity.ascent.is_some() {
        return Err(ResealError::AscentLinkNotOwed);
    }

    // Fail-closed BEFORE any seal: a public half no key can open could never
    // serve the descent the ascent link exists for
    // ([`ResealError::UnusableAscentPublic`]).
    let ascent_recipient = match identity.ascent {
        Some(AscentAuthority::ParentSeed(parent_node_seed)) => {
            Some(kdf::ascent_keypair(parent_node_seed).public())
        }
        Some(AscentAuthority::CarriedPublic(public)) => {
            Some(X25519Public::from_bytes(*public).ok_or(ResealError::UnusableAscentPublic)?)
        }
        None => None,
    };

    // Fail-closed BEFORE any seal: the produce-side mirror of the codec's own
    // bounds (AGENTS.md rule 8). The ledger is bounded alongside the commitment
    // because the write body carries it into the same record.
    if carried_history_links.len() > MAX_HISTORY_LINKS {
        return Err(ResealError::TooManyHistoryLinks);
    }
    if committed.commitment.entries.len() > MAX_GRANT_BLOBS
        || committed.grant_ledger.len() > MAX_GRANT_BLOBS
    {
        return Err(ResealError::TooManyCommittedGrants);
    }
    if let WriteHistory::Carried(sealed) = &seeds.write_history
        && sealed.len() > MAX_WRITE_HISTORY_LINK_BYTES
    {
        return Err(ResealError::CarriedWriteHistoryLinkTooLarge {
            size: sealed.len(),
            limit: MAX_WRITE_HISTORY_LINK_BYTES,
        });
    }

    // Fail-closed BEFORE any seal (see `ResealError::HistoryLinkNotDescending`
    // and `ResealError::OwnerKeyRequiredForWriteCut`).
    seeds.check_history_descends()?;
    if matches!(seeds.write_history, WriteHistory::Cut(_)) && identity.owner_enc_secret.is_none() {
        return Err(ResealError::OwnerKeyRequiredForWriteCut);
    }

    // Fail-closed BEFORE any seal (see `ResealError::LedgerDivergesFromCommitment`
    // and the module's revocation-completeness rule).
    enforce_committed_ledger(committed.commitment, committed.grant_ledger)
        .map_err(|_| ResealError::LedgerDivergesFromCommitment)?;

    // Fail-closed BEFORE any seal, and the only adoption pass: the blob loop
    // below wraps to these keys rather than re-adopting the same bytes.
    let recipients = adopt_recipients(identity, committed, seeds.pointer_read_key)?;

    let scope_id = identity.scope_id;
    let read_epoch = seeds.read_epoch;
    let signer = identity.pseudonym_signer;

    // Every structure signature binds the READ epoch, whatever epoch its own AAD
    // seals under: the gate recomputes each preimage from the authenticated
    // envelope, whose epoch tag is the read epoch (gate/adoption.rs stage 3).
    let sign_over = |struct_tag: u8, recipient_tag: Option<[u8; SECRET_LEN]>, bytes: &[u8]| {
        let input = StructureSigInput::over_ciphertext(
            scope_id,
            read_epoch,
            struct_tag,
            recipient_tag,
            bytes,
        );
        sign_structure(signer, &input).to_bytes()
    };

    // --- Grant blobs: one per committed grantee, sorted by tag for a stable
    // wire order that leaks no ledger ordering. ---
    let entries = &committed.commitment.entries;
    let mut grant_blobs: Vec<SignedGrantBlob> = Vec::with_capacity(entries.len());
    for (entry, recipient_pub) in entries.iter().zip(&recipients) {
        // The owner's cut outranks the set the record carries
        // ([`CommittedSet::revoked_recipients`]). Per entry rather than a
        // whole-record refusal: a refusal would let anyone able to republish a
        // descendant root abort the owner's cascade for good.
        if committed
            .revoked_recipients
            .contains(&recipient_pub.to_bytes())
        {
            continue;
        }
        let mut write_seed = match entry.permission {
            Permission::Write => Some(*seeds.write_scope_seed),
            Permission::Read => None,
        };
        let payload = GrantBlobPayload::new(
            *seeds.override_seed,
            write_seed,
            read_epoch,
            *seeds.pointer_read_key,
        );
        // Terminal-owner cleanup: the payload owns its own zeroizing copy, so wipe
        // this local write-seed copy before the next iteration.
        write_seed.zeroize();
        let mut ephemeral = *fresh_ephemeral(entropy).map_err(ResealError::Entropy)?;
        let ctx = ctx_for(identity.v, scope_id, read_epoch, STRUCT_TAG_GRANT_BLOB);
        let sealed = seal_grant_blob(recipient_pub, &ephemeral, &ctx, &payload);
        ephemeral.zeroize();
        let sealed = sealed.map_err(ResealError::Encode)?;
        let signature = sign_over(STRUCT_TAG_GRANT_BLOB, Some(entry.tag), &sealed.ciphertext);
        grant_blobs.push(SignedGrantBlob {
            tag: entry.tag,
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
            signature,
            unknown: PreservedFields::new(),
        });
    }
    grant_blobs.sort_by(|a, b| a.tag.cmp(&b.tag));

    // --- Owner blob: the override seed wrapped to the owner. ---
    let owner_blob = {
        let payload = OverrideSeedPayload::new(*seeds.override_seed, read_epoch);
        let mut ephemeral = *fresh_ephemeral(entropy).map_err(ResealError::Entropy)?;
        let ctx = ctx_for(identity.v, scope_id, read_epoch, STRUCT_TAG_OWNER_BLOB);
        let sealed = seal_owner_blob(identity.owner_enc_pub, &ephemeral, &ctx, &payload);
        ephemeral.zeroize();
        let sealed = sealed.map_err(ResealError::Encode)?;
        let signature = sign_over(STRUCT_TAG_OWNER_BLOB, None, &sealed.ciphertext);
        SignedOwnerBlob {
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
            signature,
            unknown: PreservedFields::new(),
        }
    };

    // --- Owner-write-blob: the write-scope seed wrapped to the owner (the
    // write-plane mirror of the owner blob), authored wherever the write-body
    // lives. Its AAD binds the write epoch — the write plane's own clock. ---
    let owner_write_blob = {
        let payload = OwnerWriteBlobPayload::new(*seeds.write_scope_seed, seeds.write_epoch);
        let mut ephemeral = *fresh_ephemeral(entropy).map_err(ResealError::Entropy)?;
        let ctx = ctx_for(
            identity.v,
            scope_id,
            seeds.write_epoch,
            STRUCT_TAG_OWNER_WRITE_BLOB,
        );
        let sealed = seal_owner_write_blob(identity.owner_enc_pub, &ephemeral, &ctx, &payload);
        ephemeral.zeroize();
        let sealed = sealed.map_err(ResealError::Encode)?;
        let signature = sign_over(STRUCT_TAG_OWNER_WRITE_BLOB, None, &sealed.ciphertext);
        Some(SignedOwnerWriteBlob {
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
            signature,
            unknown: PreservedFields::new(),
        })
    };

    // --- Ascent link: the override seed sealed to the parent-derived keypair
    // (interior scope roots only). ---
    let ascent_link = match (identity.ascent, &ascent_recipient) {
        (Some(authority), Some(recipient)) => {
            let payload = OverrideSeedPayload::new(*seeds.override_seed, read_epoch);
            let mut ephemeral = *fresh_ephemeral(entropy).map_err(ResealError::Entropy)?;
            let ctx = ctx_for(identity.v, scope_id, read_epoch, STRUCT_TAG_ASCENT_LINK);
            let link = seal_ascent_link_to(recipient, &ephemeral, &ctx, &payload);
            ephemeral.zeroize();
            let link = link.map_err(ResealError::Encode)?;
            if let AscentAuthority::ParentSeed(parent_node_seed) = authority {
                verify_ascent_link(parent_node_seed, &ctx, seeds.override_seed, &link)?;
            }
            let signature = sign_over(STRUCT_TAG_ASCENT_LINK, None, &link.sig_body());
            Some(SignedAscentLink {
                ascent_public: link.ascent_public,
                enc: link.enc,
                ciphertext: link.ciphertext,
                signature,
                unknown: PreservedFields::new(),
            })
        }
        _ => None,
    };

    // --- History links: a rotation keeps the retained window's walkable suffix
    // and appends one fresh link; a sweep carries what it has. ---
    let oldest_kept = match &seeds.prev {
        Some(prev) => {
            let window = carried_history_links
                .len()
                .saturating_sub(MAX_RETAINED_HISTORY_LINKS - 1);
            window
                + walkable_chain_start(identity.v, scope_id, prev, &carried_history_links[window..])
        }
        None => 0,
    };
    // The window stays a contiguous suffix, so an over-long link takes every
    // link older than it too. An honest link is a fixed-width seal well under
    // the bound, so this drops nothing the ratchet needs
    // ([`MAX_RETAINED_HISTORY_LINK_BYTES`]).
    let retained = &carried_history_links[oldest_kept..];
    let bounded_start = retained
        .iter()
        .rposition(|link| link.sealed.len() > MAX_RETAINED_HISTORY_LINK_BYTES)
        .map_or(0, |over| over + 1);
    let mut history_links: Vec<SignedSealed> = retained[bounded_start..]
        .iter()
        .map(|link| SignedSealed {
            signature: sign_over(STRUCT_TAG_HISTORY_LINK, None, &link.sealed),
            sealed: link.sealed.clone(),
            unknown: PreservedFields::new(),
        })
        .collect();
    if let Some(prev) = &seeds.prev {
        let sealed = mint_history_link(
            entropy,
            identity.v,
            scope_id,
            seeds.override_seed,
            read_epoch,
            prev,
        )?;
        if sealed.len() > MAX_RETAINED_HISTORY_LINK_BYTES {
            return Err(ResealError::HistoryLinkTooLarge {
                size: sealed.len(),
                limit: MAX_RETAINED_HISTORY_LINK_BYTES,
            });
        }
        let signature = sign_over(STRUCT_TAG_HISTORY_LINK, None, &sealed);
        history_links.push(SignedSealed {
            sealed,
            signature,
            unknown: PreservedFields::new(),
        });
    }

    // --- The write-plane history link: carried, or minted by the cut itself. ---
    let write_history_link = match &seeds.write_history {
        WriteHistory::Genesis => Vec::new(),
        WriteHistory::Carried(sealed) => sealed.to_vec(),
        WriteHistory::Cut(prev) => mint_owner_history_link(
            entropy,
            identity.v,
            scope_id,
            identity
                .owner_enc_secret
                .ok_or(ResealError::OwnerKeyRequiredForWriteCut)?,
            seeds.write_epoch,
            prev,
        )?,
    };

    // --- Write-body: sealed under the write key at the write epoch. ---
    let write_body = {
        // Every carried unknown map is dropped, so the minted section is a
        // function of the frozen counts alone and the re-seal budget is a real
        // bound ([`resealable_section_bytes`]). A rotation is not a
        // republish and owes no byte stability (FSM1/cipher-box-next#27 D10).
        let wb = WriteBody {
            grant_ledger: committed
                .grant_ledger
                .iter()
                .map(|entry| GrantLedgerEntry {
                    recipient_identity_pk: entry.recipient_identity_pk,
                    recipient_enc_pk: entry.recipient_enc_pk,
                    permission: entry.permission,
                    tag: entry.tag,
                    owner_sig: entry.owner_sig,
                    expires_at: entry.expires_at,
                    unknown: PreservedFields::new(),
                })
                .collect(),
            write_history_link,
            direct_child_scope_index: committed
                .direct_child_scope_index
                .iter()
                .map(|child| ChildScopeRef::new(child.scope_id, child.ipns_name.clone()))
                .collect(),
            unknown: PreservedFields::new(),
        };
        let mut plaintext = encode_write_body(&wb).map_err(write_body_encode_error)?;
        let write_seed = kdf::write_seed(seeds.write_scope_seed, &scope_id);
        let write_key = kdf::write_key(write_seed.as_bytes());
        let nonce = fresh_nonce(entropy).map_err(ResealError::Entropy)?;
        let ctx = ctx_for(
            identity.v,
            scope_id,
            seeds.write_epoch,
            STRUCT_TAG_WRITE_BODY,
        );
        let sealed = seal(write_key.as_bytes(), &nonce, &ctx, &plaintext);
        plaintext.zeroize();
        let signature = sign_over(STRUCT_TAG_WRITE_BODY, None, &sealed);
        SignedSealed {
            sealed,
            signature,
            unknown: PreservedFields::new(),
        }
    };

    let section = GrantSection {
        commitment: committed.commitment.clone(),
        commitment_sig: *committed.commitment_sig,
        grant_blobs,
        owner_blob,
        owner_write_blob,
        ascent_link,
        history_links,
        write_body,
        unknown: PreservedFields::new(),
    };
    let size = encode_grant_section(&section)
        .map_err(ResealError::Encode)?
        .len();
    let limit = resealable_section_bytes(committed.commitment.entries.len());
    if size > limit {
        return Err(ResealError::SectionNotResealable { size, limit });
    }
    Ok(section)
}

/// Reopen the freshly sealed ascent link as an ancestor reader does and refuse
/// unless it carries the seed and epoch this re-seal publishes at — the
/// release-active produce-side half of the gate's stage-3 predicate
/// (`gate/adoption.rs`, AGENTS.md rule 8). The expected pair comes from
/// [`ResealSeeds`], never from the payload under test, so the ascent arm cannot
/// drift from the seed and epoch the rest of the section is minted at.
///
/// The mirror covers the seed and epoch, not the ancestor: seal and open derive
/// the ascent keypair from the single `parent_node_seed` this re-seal was handed,
/// so authenticating that seed is the caller's. The threading site that mints
/// descendant roots does it by recovering each parent's seed from the record it
/// publishes (`rotation/cascade.rs::published_seed`); a rotator anchored at one
/// root reads it from the parent its own walk gated
/// (`net/rotation.rs::RotationAncestry`).
///
/// The gate compares the read key the recovered seed derives; comparing the seed
/// is the same predicate one derivation earlier.
fn verify_ascent_link(
    parent_node_seed: &[u8; SECRET_LEN],
    ctx: &AadContext,
    override_seed: &[u8; SECRET_LEN],
    link: &AscentLink,
) -> Result<(), ResealError> {
    let payload = open_ascent_link(parent_node_seed, ctx, link)
        .map_err(|_| ResealError::AscentLinkMismatch)?;
    if payload.epoch != ctx.epoch || !ct_eq(payload.override_seed(), override_seed) {
        return Err(ResealError::AscentLinkMismatch);
    }
    Ok(())
}

/// The half of a same-epoch re-seal a [`CascadeTarget`] does not carry: the
/// scope's own identity, the ascent authority, and the owner subkey the caller
/// holds.
///
/// A resolved target omits the self-identifying `scope_id` / `ipns_name` and the
/// parent node seed on purpose — see [`CascadeTarget`] — so the caller names
/// them here, from the enumerated [`ChildScopeRef`] it resolved under.
#[derive(Clone, Copy)]
pub struct ResealSite<'a> {
    /// The scope-root node id (== scope id).
    pub scope_id: [u8; 16],
    /// The scope root's opaque `ipnsName` bytes.
    pub ipns_name: &'a [u8],
    /// The owner's X25519 encryption subkey — the re-seal re-wraps the owner
    /// blob under it and proves every ledger row is filed under a tag it derives.
    pub owner_enc_secret: &'a X25519Secret,
    /// What this re-seal mints the ascent link under.
    pub ascent: Option<AscentAuthority<'a>>,
    /// Whether this root owes an ascent link
    /// ([`ScopeRootIdentity::owes_ascent_link`]).
    pub owes_ascent_link: bool,
}

/// Re-seal a resolved scope root at its **current** read epoch with one changed
/// [`CommittedSet`] — the metadata-only shape shared by the grant hand-over's
/// descendant re-key and the invite-claim conversion pass.
///
/// Same seed at the same epoch, so `prev` is `None` and the pass mints no
/// history link, and the write plane rides through untouched
/// ([`WriteHistory::Carried`]). Every seed stays the caller's to zero; this
/// function borrows them (AGENTS.md rule 7).
pub fn reseal_at_current_epoch<E: Entropy>(
    entropy: &mut E,
    target: &CascadeTarget,
    site: &ResealSite<'_>,
    committed: &CommittedSet<'_>,
) -> Result<GrantSection, ResealError> {
    reseal_scope_root(
        entropy,
        &ScopeRootIdentity {
            v: target.v,
            scope_id: site.scope_id,
            ipns_name: site.ipns_name,
            owner_enc_pub: &target.owner_enc_pub,
            owner_enc_secret: Some(site.owner_enc_secret),
            ascent: site.ascent,
            owes_ascent_link: site.owes_ascent_link,
            pseudonym_signer: &target.pseudonym_signer,
        },
        &ResealSeeds {
            override_seed: &target.override_seed,
            read_epoch: target.current_read_epoch,
            prev: None,
            write_scope_seed: &target.write_scope_seed,
            write_epoch: target.write_epoch,
            write_history: WriteHistory::Carried(&target.write_history_link),
            pointer_read_key: &target.pointer_read_key,
        },
        committed,
        &target.carried_history_links,
    )
}

/// The override seed a re-sealed section's own owner blob carries, opened as an
/// owner reader opens it.
///
/// The one produce-side read-back of a `reseal_scope_root` output: a section
/// that will not reopen under the owner key the adoption gate re-derives can
/// never be signed (release-active, AGENTS.md rule 8).
pub fn published_override_seed(
    owner_enc_secret: &X25519Secret,
    v: u64,
    scope_id: [u8; 16],
    read_epoch: u64,
    section: &GrantSection,
) -> Option<Zeroizing<[u8; SECRET_LEN]>> {
    let blob = &section.owner_blob;
    let ctx = ctx_for(v, scope_id, read_epoch, STRUCT_TAG_OWNER_BLOB);
    let payload = open_owner_blob(owner_enc_secret, &blob.enc, &ctx, &blob.ciphertext).ok()?;
    // The AAD binds the epoch; the payload carries its own copy, and the two
    // disagreeing is a seed recovered for an epoch it does not belong to
    // (`net/adopter.rs::open_write_scope_seed_at` splits it the same way).
    (payload.epoch == read_epoch).then(|| Zeroizing::new(*payload.override_seed()))
}

/// The AAD context for a scope-root structure: `id == scope == scope_id` (a
/// scope root's node id is its scope id).
fn ctx_for(v: u64, scope_id: [u8; 16], epoch: u64, struct_tag: u8) -> AadContext {
    AadContext {
        v,
        id: scope_id,
        scope: scope_id,
        epoch,
        struct_tag,
    }
}

#[cfg(test)]
mod tests;
