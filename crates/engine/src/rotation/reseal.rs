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
    /// which stays attributable and which an owner cut overwrites: that arm
    /// derives the public from the parent seed rather than carrying it.
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
mod tests {
    use super::*;
    use crate::grants::mint_grant_row;
    use crate::testkit::{SeededEntropy, padding};
    use cipherbox_core::seal::{
        ChildScopeRef, GrantSetEntry, MAX_DIRECT_CHILD_SCOPES, MAX_WRITE_BODY_BYTES,
        encode_grant_section, open_ascent_link, open_grant_blob, open_history_link,
        open_owner_blob, open_owner_history_link, open_owner_write_blob, sign_grant_set,
        sign_recipient_binding, verify_structure,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Verifier};
    use cipherbox_core::suite::secret::ct_eq;
    use cipherbox_core::suite::x25519::X25519Secret;

    const V: u64 = 2;
    const SCOPE: [u8; 16] = [0x5c; 16];
    /// The name every honestly minted fixture set binds.
    const MINTED_NAME: &[u8] = b"minted-scope-root-name";

    /// An entropy seam that panics the moment it is drawn — the probe that turns
    /// "eventually refused" into "refused before the first seal", since every
    /// seal `reseal_scope_root` performs draws a nonce or an HPKE scalar first.
    struct UndrawnEntropy;
    impl Entropy for UndrawnEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            panic!("the guard must reject before any seal draws entropy");
        }
    }

    /// The oversize refusal reaches a caller under its own name, and no other
    /// encode fault is laundered into it — the operator signal the bound exists
    /// to give.
    #[test]
    fn an_over_bound_write_body_is_named_apart_from_every_other_encode_fault() {
        let row = |tag: [u8; 32]| {
            GrantLedgerEntry::new([0x02; 33], [0x11; 32], Permission::Read, tag, [0x77; 64])
        };
        let oversize = WriteBody {
            grant_ledger: vec![row([0x21; 32])],
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::from_iter([(
                "zzPad".to_string(),
                cipherbox_core::codec::Value::Bytes(vec![0xab; MAX_WRITE_BODY_BYTES]),
            )]),
        };
        assert_eq!(
            write_body_encode_error(encode_write_body(&oversize).unwrap_err()),
            ResealError::WriteBodyTooLarge
        );

        let duplicate_tag = WriteBody {
            grant_ledger: vec![row([0x21; 32]), row([0x21; 32])],
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        assert!(matches!(
            write_body_encode_error(encode_write_body(&duplicate_tag).unwrap_err()),
            ResealError::Encode(_)
        ));
    }

    struct Fixture {
        owner_enc: X25519Secret,
        pseudonym: Ed25519Signer,
        owner_ecdsa: EcdsaSigner,
        parent_node_seed: [u8; 32],
        write_scope_seed: [u8; 32],
        pointer_read_key: [u8; 32],
        read_grantee: X25519Secret,
        write_grantee: X25519Secret,
    }

    impl Fixture {
        fn new() -> Self {
            let owner_ecdsa = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
            Self {
                owner_enc: X25519Secret::from_scalar([0x11; 32]),
                pseudonym: Ed25519Signer::from_seed([0x22; 32]),
                owner_ecdsa,
                parent_node_seed: [0x44; 32],
                write_scope_seed: [0x55; 32],
                pointer_read_key: [0x66; 32],
                read_grantee: Self::read_recipient(),
                write_grantee: Self::write_recipient(),
            }
        }

        fn read_tag() -> [u8; 32] {
            [0xa1; 32]
        }
        fn write_tag() -> [u8; 32] {
            [0xb2; 32]
        }
        /// The i-th distinct fixture recipient, for the bound fixtures that need
        /// a commitment entry per grant.
        fn nth_recipient(i: usize) -> X25519Secret {
            let mut scalar = [0x11u8; 32];
            scalar[..8].copy_from_slice(&(i as u64).to_be_bytes());
            X25519Secret::from_scalar(scalar)
        }
        fn read_recipient() -> X25519Secret {
            X25519Secret::from_scalar([0x77; 32])
        }
        fn write_recipient() -> X25519Secret {
            X25519Secret::from_scalar([0x88; 32])
        }

        /// One ledger row the owner attests at `ipns_name` — the shape a re-seal
        /// admits, however the tag was arrived at. Signing is what a re-mint does
        /// too, so a fixture row and a minted one are indistinguishable to a
        /// re-sealer.
        fn attested_row(
            &self,
            recipient_identity_pk: [u8; 33],
            recipient_enc_pk: [u8; 32],
            permission: Permission,
            tag: [u8; 32],
            ipns_name: &[u8],
        ) -> GrantLedgerEntry {
            let mut row = GrantLedgerEntry::new(
                recipient_identity_pk,
                recipient_enc_pk,
                permission,
                tag,
                [0u8; ECDSA_SIG_LEN],
            );
            row.owner_sig = sign_recipient_binding(&self.owner_ecdsa, ipns_name, &row)
                .expect("the owner attests the row it minted")
                .to_compact();
            row
        }

        /// A commitment + matching ledger for a read grantee and a write grantee,
        /// both attested at `ipns_name`.
        fn committed(
            &self,
            ipns_name: &[u8],
        ) -> (
            GrantSetCommitment,
            [u8; ECDSA_SIG_LEN],
            Vec<GrantLedgerEntry>,
        ) {
            let entries = vec![
                GrantSetEntry::new(
                    &self.pointer_read_key,
                    Self::read_tag(),
                    Self::read_recipient().public().to_bytes(),
                    Permission::Read,
                    [0x02; 32],
                ),
                GrantSetEntry::new(
                    &self.pointer_read_key,
                    Self::write_tag(),
                    Self::write_recipient().public().to_bytes(),
                    Permission::Write,
                    [0x03; 32],
                ),
            ];
            let commitment = GrantSetCommitment {
                ipns_name: ipns_name.to_vec(),
                owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
                cut_epoch: 0,
                entries,
                unknown: PreservedFields::new(),
            };
            let sig = sign_grant_set(&self.owner_ecdsa, &commitment)
                .unwrap()
                .to_compact();
            let ledger = vec![
                self.attested_row(
                    [0x02; 33],
                    self.read_grantee.public().to_bytes(),
                    Permission::Read,
                    Self::read_tag(),
                    ipns_name,
                ),
                self.attested_row(
                    [0x03; 33],
                    self.write_grantee.public().to_bytes(),
                    Permission::Write,
                    Self::write_tag(),
                    ipns_name,
                ),
            ];
            (commitment, sig, ledger)
        }

        /// The same pair, but with every tag **honestly minted** at
        /// [`MINTED_NAME`] from the owner–recipient ECDH — what an owner-held
        /// re-sealer re-derives.
        fn minted(
            &self,
        ) -> (
            GrantSetCommitment,
            [u8; ECDSA_SIG_LEN],
            Vec<GrantLedgerEntry>,
        ) {
            let mint = |grantee: &X25519Secret, identity_scalar: [u8; 32], permission| {
                let identity = EcdsaSigner::from_scalar(&identity_scalar).unwrap();
                mint_grant_row(
                    &self.owner_ecdsa,
                    &self.owner_enc,
                    &self.pointer_read_key,
                    identity.verifying_key().to_sec1(),
                    &grantee.public(),
                    &SCOPE,
                    MINTED_NAME,
                    permission,
                )
                .expect("a contributory recipient key")
            };
            let rows = [
                mint(&self.read_grantee, [0x51; 32], Permission::Read),
                mint(&self.write_grantee, [0x52; 32], Permission::Write),
            ];
            let commitment = GrantSetCommitment {
                ipns_name: MINTED_NAME.to_vec(),
                owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
                cut_epoch: 0,
                entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
                unknown: PreservedFields::new(),
            };
            let sig = sign_grant_set(&self.owner_ecdsa, &commitment)
                .unwrap()
                .to_compact();
            let ledger = rows.iter().map(|r| r.ledger_entry.clone()).collect();
            (commitment, sig, ledger)
        }
    }

    // `owner_enc_pub` needs a `&X25519Public`; hold it in a local so the borrow
    // outlives the call.
    fn identity<'a>(
        fx: &'a Fixture,
        owner_pub: &'a X25519Public,
        ipns_name: &'a [u8],
        parent: Option<&'a [u8; 32]>,
    ) -> ScopeRootIdentity<'a> {
        ScopeRootIdentity {
            v: V,
            scope_id: SCOPE,
            ipns_name,
            owner_enc_pub: owner_pub,
            owner_enc_secret: None,
            ascent: parent.map(AscentAuthority::ParentSeed),
            owes_ascent_link: parent.is_some(),
            pseudonym_signer: &fx.pseudonym,
        }
    }

    fn seeds<'a>(
        override_seed: &'a [u8; 32],
        read_epoch: u64,
        prev: Option<PrevEpochSeed<'a>>,
        write_scope_seed: &'a [u8; 32],
        pointer_read_key: &'a [u8; 32],
    ) -> ResealSeeds<'a> {
        ResealSeeds {
            override_seed,
            read_epoch,
            prev,
            write_scope_seed,
            write_epoch: 1,
            write_history: WriteHistory::Genesis,
            pointer_read_key,
        }
    }

    fn committed_set<'a>(
        commitment: &'a GrantSetCommitment,
        sig: &'a [u8; ECDSA_SIG_LEN],
        ledger: &'a [GrantLedgerEntry],
    ) -> CommittedSet<'a> {
        CommittedSet {
            commitment,
            commitment_sig: sig,
            grant_ledger: ledger,
            direct_child_scope_index: &[],
            revoked_recipients: &[],
        }
    }

    fn verifier(fx: &Fixture) -> Ed25519Verifier {
        fx.pseudonym.verifying_key()
    }

    fn blob_sig(sig: &[u8; 64]) -> Ed25519Signature {
        Ed25519Signature::from_bytes(*sig)
    }

    #[test]
    fn a_re_seal_to_a_carried_public_half_still_opens_by_the_ancestors_descent() {
        // A grantee holds no ancestor seed, so it seals to the public half the
        // record it is replacing publishes; the ancestor must still descend.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
        let carried = kdf::ascent_keypair(&fx.parent_node_seed)
            .public()
            .to_bytes();
        let mut id = identity(&fx, &owner_pub, b"scope-root-name", None);
        id.ascent = Some(AscentAuthority::CarriedPublic(&carried));
        id.owes_ascent_link = true;
        let override_seed = [0x9d; 32];

        let section = reseal_scope_root(
            &mut SeededEntropy::new(5),
            &id,
            &seeds(
                &override_seed,
                4,
                None,
                &fx.write_scope_seed,
                &fx.pointer_read_key,
            ),
            &committed_set(&commitment, &sig, &ledger),
            &[],
        )
        .expect("the re-seal completes without an ancestor seed");

        let link = section.ascent_link.expect("a link is owed and minted");
        let ctx = ctx_for(V, SCOPE, 4, STRUCT_TAG_ASCENT_LINK);
        let opened = open_ascent_link(
            &fx.parent_node_seed,
            &ctx,
            &cipherbox_core::seal::AscentLink {
                ascent_public: link.ascent_public,
                enc: link.enc,
                ciphertext: link.ciphertext,
                unknown: PreservedFields::new(),
            },
        )
        .expect("the ancestor's own descent opens it");
        assert!(ct_eq(opened.override_seed(), &override_seed));
    }

    #[test]
    fn an_ascent_public_half_no_key_can_open_is_refused_before_any_seal() {
        // Release-active: a link sealed to bytes that are not an X25519 point
        // could never serve the descent it exists for.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
        // Not the canonical encoding of a prime-order point, so
        // `X25519Public::from_bytes` refuses to address it.
        let unusable = [0xff; 32];
        let mut id = identity(&fx, &owner_pub, b"scope-root-name", None);
        id.ascent = Some(AscentAuthority::CarriedPublic(&unusable));
        id.owes_ascent_link = true;

        assert_eq!(
            reseal_scope_root(
                &mut UndrawnEntropy,
                &id,
                &seeds(
                    &[0x9d; 32],
                    4,
                    None,
                    &fx.write_scope_seed,
                    &fx.pointer_read_key
                ),
                &committed_set(&commitment, &sig, &ledger),
                &[],
            )
            .unwrap_err(),
            ResealError::UnusableAscentPublic,
        );
    }

    #[test]
    fn reseal_round_trips_and_every_structure_is_pseudonym_signed() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let ipns = b"scope-root-name";
        let (commitment, sig, ledger) = fx.committed(ipns);
        let id = identity(&fx, &owner_pub, ipns, Some(&fx.parent_node_seed));

        let override_seed = [0x99; 32];
        let prev_seed = [0x9a; 32];
        let s = seeds(
            &override_seed,
            5,
            Some(PrevEpochSeed {
                seed: &prev_seed,
                epoch: 4,
            }),
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);

        let mut e = SeededEntropy::new(1);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");

        let ver = verifier(&fx);

        // Grant blobs: sorted by tag; read grantee opens read seed only, write
        // grantee opens both — all at the new epoch, all pseudonym-signed.
        assert_eq!(section.grant_blobs.len(), 2);
        for gb in &section.grant_blobs {
            let input = StructureSigInput::over_ciphertext(
                SCOPE,
                5,
                STRUCT_TAG_GRANT_BLOB,
                Some(gb.tag),
                &gb.ciphertext,
            );
            verify_structure(&ver, &input, &blob_sig(&gb.signature)).expect("grant blob signed");
        }

        let read_gb = section
            .grant_blobs
            .iter()
            .find(|b| b.tag == Fixture::read_tag())
            .unwrap();
        let ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_GRANT_BLOB);
        let read_payload =
            open_grant_blob(&fx.read_grantee, &read_gb.enc, &ctx, &read_gb.ciphertext).unwrap();
        assert!(ct_eq(read_payload.read_scope_seed(), &override_seed));
        assert!(
            read_payload.write_scope_seed().is_none(),
            "read grant, no write seed"
        );
        assert_eq!(read_payload.epoch, 5);
        assert!(ct_eq(read_payload.pointer_read_key(), &fx.pointer_read_key));

        let write_gb = section
            .grant_blobs
            .iter()
            .find(|b| b.tag == Fixture::write_tag())
            .unwrap();
        let write_payload =
            open_grant_blob(&fx.write_grantee, &write_gb.enc, &ctx, &write_gb.ciphertext).unwrap();
        assert!(ct_eq(write_payload.read_scope_seed(), &override_seed));
        assert!(
            ct_eq(
                write_payload.write_scope_seed().unwrap(),
                &fx.write_scope_seed
            ),
            "write grant carries the write scope seed"
        );

        // Owner blob → override seed.
        let owner_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_OWNER_BLOB);
        let owner_payload = open_owner_blob(
            &fx.owner_enc,
            &section.owner_blob.enc,
            &owner_ctx,
            &section.owner_blob.ciphertext,
        )
        .unwrap();
        assert!(ct_eq(owner_payload.override_seed(), &override_seed));

        // Owner-write-blob → write scope seed, AAD bound to the WRITE epoch (1),
        // structure signature bound to the READ epoch (5, the envelope's).
        let owb = section
            .owner_write_blob
            .as_ref()
            .expect("owner-write-blob authored beside the write-body");
        let owb_ctx = ctx_for(V, SCOPE, 1, STRUCT_TAG_OWNER_WRITE_BLOB);
        let owb_payload =
            open_owner_write_blob(&fx.owner_enc, &owb.enc, &owb_ctx, &owb.ciphertext).unwrap();
        assert!(ct_eq(owb_payload.write_scope_seed(), &fx.write_scope_seed));
        assert_eq!(owb_payload.write_epoch, 1);
        let owb_sig_input = StructureSigInput::over_ciphertext(
            SCOPE,
            5,
            STRUCT_TAG_OWNER_WRITE_BLOB,
            None,
            &owb.ciphertext,
        );
        verify_structure(&ver, &owb_sig_input, &blob_sig(&owb.signature))
            .expect("owner-write-blob signed at the read epoch");

        // Ascent link → override seed, opened with the parent seed.
        let ascent = section
            .ascent_link
            .as_ref()
            .expect("interior root has ascent");
        let ascent_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_ASCENT_LINK);
        let ascent_link = cipherbox_core::seal::AscentLink {
            ascent_public: ascent.ascent_public,
            enc: ascent.enc,
            ciphertext: ascent.ciphertext.clone(),
            unknown: PreservedFields::new(),
        };
        let ascent_payload =
            open_ascent_link(&fx.parent_node_seed, &ascent_ctx, &ascent_link).unwrap();
        assert!(ct_eq(ascent_payload.override_seed(), &override_seed));

        // History link → prev seed under the new epoch's structure key.
        assert_eq!(section.history_links.len(), 1);
        let hl_key = kdf::structure_key(&override_seed, STRUCT_TAG_HISTORY_LINK);
        let hl_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_HISTORY_LINK);
        let hl = open_history_link(hl_key.as_bytes(), &hl_ctx, &section.history_links[0].sealed)
            .unwrap();
        assert!(ct_eq(hl.prev_seed(), &prev_seed));
        assert_eq!(hl.prev_epoch, 4);

        // The whole section encodes (the release-active dup-tag guard passes).
        encode_grant_section(&section).expect("section encodes");
    }

    /// Release-active (rule 8): the guard returns `Err`, so a `--release` build
    /// refuses exactly the links a debug build does. Every reject row is a link
    /// an ancestor reader rejects whole-record.
    #[test]
    fn an_ascent_link_the_gate_would_reject_is_never_signed() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
        let parent_node_seed = fx.parent_node_seed;
        let override_seed = [0x99; 32];
        let ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_ASCENT_LINK);

        // The link a real re-seal mints passes its own guard.
        let id = identity(&fx, &owner_pub, b"scope-root-name", Some(&parent_node_seed));
        let s = seeds(
            &override_seed,
            ctx.epoch,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        let minted = reseal_scope_root(&mut SeededEntropy::new(13), &id, &s, &cs, &[])
            .expect("reseal")
            .ascent_link
            .expect("interior root has ascent");
        verify_ascent_link(
            &parent_node_seed,
            &ctx,
            &override_seed,
            &AscentLink {
                ascent_public: minted.ascent_public,
                enc: minted.enc,
                ciphertext: minted.ciphertext,
                unknown: PreservedFields::new(),
            },
        )
        .expect("a minted link is the one an ancestor reader opens");

        let sealed = |seed: &[u8; 32], carried: [u8; 32], epoch: u64, c: &AadContext| {
            seal_ascent_link_to(
                &kdf::ascent_keypair(seed).public(),
                &[0x07; 32],
                c,
                &OverrideSeedPayload::new(carried, epoch),
            )
            .expect("seals")
        };
        // A valid foreign public half with this link's own `enc`/ciphertext: the
        // reader re-derives the public half, never trusts the carried one.
        let mut foreign_public = sealed(&parent_node_seed, override_seed, ctx.epoch, &ctx);
        foreign_public.ascent_public = X25519Secret::from_scalar([0x31; 32]).public().to_bytes();
        for link in [
            // Sealed to a keypair no ancestor of this node derives.
            sealed(&[0x45; 32], override_seed, ctx.epoch, &ctx),
            // Carries a seed that does not derive this node's read key.
            sealed(&parent_node_seed, [0x9a; 32], ctx.epoch, &ctx),
            // Carries an epoch the record does not publish at.
            sealed(&parent_node_seed, override_seed, ctx.epoch + 1, &ctx),
            // AAD transplants: the context is load-bearing, not decoration.
            sealed(
                &parent_node_seed,
                override_seed,
                ctx.epoch,
                &ctx_for(V, [0xee; 16], ctx.epoch, STRUCT_TAG_ASCENT_LINK),
            ),
            sealed(
                &parent_node_seed,
                override_seed,
                ctx.epoch,
                &ctx_for(V, SCOPE, ctx.epoch, STRUCT_TAG_OWNER_BLOB),
            ),
            sealed(
                &parent_node_seed,
                override_seed,
                ctx.epoch,
                &ctx_for(V + 1, SCOPE, ctx.epoch, STRUCT_TAG_ASCENT_LINK),
            ),
            foreign_public,
        ] {
            assert_eq!(
                verify_ascent_link(&parent_node_seed, &ctx, &override_seed, &link),
                Err(ResealError::AscentLinkMismatch),
            );
        }
        assert_eq!(
            ResealError::AscentLinkMismatch.check(),
            "ascent-link-mismatch"
        );
    }

    /// The publish arm keys the record's read body off the seed it recovers from
    /// the **owner blob** (`net/rotation.rs`), while an ancestor reader derives
    /// its expected read key from the **ascent link**. A section whose two
    /// structures disagreed would publish a root its own ancestors reject, so the
    /// agreement is asserted on `reseal_scope_root`'s output, not assumed.
    #[test]
    fn the_ascent_link_and_the_owner_blob_carry_one_seed() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
        let override_seed = [0x99; 32];
        let id = identity(
            &fx,
            &owner_pub,
            b"scope-root-name",
            Some(&fx.parent_node_seed),
        );
        let s = seeds(
            &override_seed,
            5,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        let section =
            reseal_scope_root(&mut SeededEntropy::new(17), &id, &s, &cs, &[]).expect("reseal");

        let owner = open_owner_blob(
            &fx.owner_enc,
            &section.owner_blob.enc,
            &ctx_for(V, SCOPE, 5, STRUCT_TAG_OWNER_BLOB),
            &section.owner_blob.ciphertext,
        )
        .expect("owner opens its blob");
        let ascent = section.ascent_link.expect("interior root has ascent");
        let recovered = open_ascent_link(
            &fx.parent_node_seed,
            &ctx_for(V, SCOPE, 5, STRUCT_TAG_ASCENT_LINK),
            &AscentLink {
                ascent_public: ascent.ascent_public,
                enc: ascent.enc,
                ciphertext: ascent.ciphertext,
                unknown: PreservedFields::new(),
            },
        )
        .expect("an ancestor opens the link");
        assert!(ct_eq(recovered.override_seed(), owner.override_seed()));
        assert_eq!(recovered.epoch, owner.epoch);
    }

    #[test]
    fn vault_root_omits_ascent_link() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"root");
        let id = identity(&fx, &owner_pub, b"root", None);
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(2);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");
        assert!(
            section.ascent_link.is_none(),
            "vault root has no ascent link"
        );
        assert!(section.history_links.is_empty(), "no prev, no history link");
    }

    #[test]
    fn sweep_seed_source_mints_no_new_history_link() {
        // prev = None (sweep catch-up): no fresh link, carried sealed bytes kept
        // and re-signed at this read epoch.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"n");
        let id = identity(&fx, &owner_pub, b"n", Some(&fx.parent_node_seed));
        let seed = [0x0e; 32];
        let s = seeds(&seed, 7, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let carried = vec![SignedSealed {
            sealed: b"prior-epoch-link".to_vec(),
            signature: [0x01; 64],
            unknown: PreservedFields::new(),
        }];
        let mut e = SeededEntropy::new(3);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &carried).expect("reseal");
        assert_eq!(section.history_links.len(), 1, "no fresh link minted");
        assert_eq!(
            section.history_links[0].sealed, carried[0].sealed,
            "the sealed link stays openable under the epoch key that minted it"
        );
        let input = StructureSigInput::over_ciphertext(
            SCOPE,
            7,
            STRUCT_TAG_HISTORY_LINK,
            None,
            &carried[0].sealed,
        );
        verify_structure(
            &verifier(&fx),
            &input,
            &blob_sig(&section.history_links[0].signature),
        )
        .expect("the carried link is re-signed at the epoch the gate recomputes at");
    }

    /// The synthetic chain's override seed for epoch `e`.
    fn chain_seed(e: u64) -> [u8; 32] {
        let mut seed = [0x40; 32];
        seed[..8].copy_from_slice(&e.to_be_bytes());
        seed
    }

    /// A real ratchet: links for epochs `2..=newest`, oldest first, each sealed
    /// under its own epoch's structure key and naming the epoch before it —
    /// exactly what `reseal_scope_root` mints, so the walk accepts it.
    fn real_chain(newest: u64) -> Vec<SignedSealed> {
        (2..=newest)
            .map(|e| {
                let key = kdf::structure_key(&chain_seed(e), STRUCT_TAG_HISTORY_LINK);
                let ctx = ctx_for(V, SCOPE, e, STRUCT_TAG_HISTORY_LINK);
                let payload = HistoryLinkPayload::new(chain_seed(e - 1), e - 1);
                SignedSealed {
                    sealed: seal_history_link(key.as_bytes(), &[0x5a; 24], &ctx, &payload).unwrap(),
                    signature: [0x01; 64],
                    unknown: PreservedFields::new(),
                }
            })
            .collect()
    }

    /// Re-seal at `newest + 1`, carrying `carried`.
    fn reseal_over_chain(
        fx: &Fixture,
        newest: u64,
        carried: &[SignedSealed],
    ) -> Result<GrantSection, ResealError> {
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"n");
        let id = identity(fx, &owner_pub, b"n", None);
        let head = chain_seed(newest);
        let fresh = chain_seed(newest + 1);
        let s = seeds(
            &fresh,
            newest + 1,
            Some(PrevEpochSeed {
                seed: &head,
                epoch: newest,
            }),
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        reseal_scope_root(&mut SeededEntropy::new(11), &id, &s, &cs, carried)
    }

    #[test]
    fn retention_keeps_the_newest_window_and_drops_the_oldest() {
        // The ratchet is a contiguous chain, so only the oldest end may be
        // dropped — a hole would strand every epoch beyond it.
        let fx = Fixture::new();
        let newest = MAX_RETAINED_HISTORY_LINKS as u64 + 8;
        let carried = real_chain(newest);
        let section = reseal_over_chain(&fx, newest, &carried).expect("reseal");

        assert_eq!(
            section.history_links.len(),
            MAX_RETAINED_HISTORY_LINKS,
            "the fresh link rides inside the retained window, never past it"
        );
        let kept: Vec<&Vec<u8>> = section.history_links[..MAX_RETAINED_HISTORY_LINKS - 1]
            .iter()
            .map(|l| &l.sealed)
            .collect();
        let newest_carried: Vec<&Vec<u8>> = carried
            [carried.len() - (MAX_RETAINED_HISTORY_LINKS - 1)..]
            .iter()
            .map(|l| &l.sealed)
            .collect();
        assert_eq!(kept, newest_carried, "newest carried links kept, in order");
        let fresh = &section.history_links[MAX_RETAINED_HISTORY_LINKS - 1].sealed;
        assert!(
            !carried.iter().any(|l| &l.sealed == fresh),
            "the freshly minted link is appended last, keeping the wire order oldest-first"
        );
        // Retention is what holds a re-seal inside the codec's frozen bound.
        encode_grant_section(&section).expect("a retained section always encodes");
    }

    /// A mutation that breaks the carried chain inside the retained window, so
    /// the damage is not merely pruned away.
    type ChainBreak = fn(&mut Vec<SignedSealed>);

    #[test]
    fn a_chain_that_does_not_walk_is_truncated_never_refused() {
        // The carried set is attacker-influenced: the gate authenticates each
        // link's signature and nothing about their order. Refusing would let a
        // committed write-grantee block the rotation that revokes them, so the
        // unwalkable remainder is dropped and the cut still lands.
        let cases: [(&str, ChainBreak); 4] = [
            ("reversed", |c| c.reverse()),
            ("gapped", |c| {
                c.remove(c.len() - 3);
            }),
            ("tampered", |c| c.last_mut().unwrap().sealed[30] ^= 0xFF),
            ("interior swap", |c| {
                let n = c.len();
                c.swap(n - 2, n - 3);
            }),
        ];
        let fx = Fixture::new();
        for (name, break_chain) in cases {
            let mut carried = real_chain(12);
            break_chain(&mut carried);
            let section = reseal_over_chain(&fx, 12, &carried)
                .unwrap_or_else(|e| panic!("{name}: a broken chain must not block the cut: {e}"));
            assert!(
                section.history_links.len() < carried.len() + 1,
                "{name}: the unwalkable remainder must be dropped, not carried"
            );
            encode_grant_section(&section).unwrap_or_else(|e| panic!("{name}: encodes: {e}"));
        }
    }

    #[test]
    fn a_link_minted_for_another_scope_is_never_re_signed() {
        // The AAD binds the scope, so a genuine link lifted from another scope
        // opens under no seed this walk reaches — transplant, not tamper.
        let fx = Fixture::new();
        let mut carried = real_chain(12);
        let key = kdf::structure_key(&chain_seed(12), STRUCT_TAG_HISTORY_LINK);
        let ctx = ctx_for(V, [0xee; 16], 12, STRUCT_TAG_HISTORY_LINK);
        let payload = HistoryLinkPayload::new(chain_seed(11), 11);
        carried.last_mut().unwrap().sealed =
            seal_history_link(key.as_bytes(), &[0x5a; 24], &ctx, &payload).unwrap();

        let section = reseal_over_chain(&fx, 12, &carried).expect("the cut still lands");
        assert_eq!(
            section.history_links.len(),
            1,
            "nothing older than the transplant survives; only the fresh link remains"
        );
    }

    #[test]
    fn a_carried_set_past_the_codec_bound_fails_closed_before_any_seal() {
        // Release-active mirror of the codec's own bound: a set this big could
        // only ever produce a section this build's own encoder rejects.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"n");
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(9);
        let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let carried = real_chain(MAX_HISTORY_LINKS as u64 + 3);
        let err = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &carried)
            .expect_err("past the bound");
        assert_eq!(err.check(), "too-many-history-links");
    }

    #[test]
    fn a_full_committed_set_re_seals_inside_the_budget_the_author_reserved() {
        // The other half of the coordination `net/author.rs` enforces: the
        // author holds a scope root's other bytes under the complement of this
        // budget, so a section that fits it always fits beside them. Measured on
        // real bytes at the frozen ceiling of committed rows, since the budget
        // is sized from per-row wire estimates.
        //
        // Every row and every child ref carries a padded unknown map here. The
        // counts are frozen and the per-item sizes are not, so the budget is a
        // bound only because the re-seal drops the carry.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (mut commitment, _, _) = fx.committed(b"n");
        let rows: Vec<(_, _)> = (0..MAX_GRANT_BLOBS)
            .map(|i| {
                let mut tag = [0u8; SECRET_LEN];
                tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let recipient = Fixture::nth_recipient(i).public().to_bytes();
                (
                    GrantSetEntry::new(
                        &fx.pointer_read_key,
                        tag,
                        recipient,
                        Permission::Read,
                        [0x02; 32],
                    ),
                    fx.attested_row([0x02; 33], recipient, Permission::Read, tag, b"n"),
                )
            })
            .collect();
        commitment.entries = rows.iter().map(|(entry, _)| entry.clone()).collect();
        let sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
            .expect("the owner signs the maximal set")
            .to_compact();
        let ledger: Vec<GrantLedgerEntry> = rows
            .into_iter()
            .map(|(_, row)| GrantLedgerEntry {
                unknown: padding(1024),
                ..row
            })
            .collect();

        // Every count axis at its ceiling at once, since only the joint maximum
        // can exhaust the budget.
        let children: Vec<ChildScopeRef> = (0..MAX_DIRECT_CHILD_SCOPES)
            .map(|i| {
                let mut scope_id = [0u8; 16];
                scope_id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                ChildScopeRef {
                    scope_id,
                    ipns_name: crate::rotation::derive_write_name(&[0x5b; SECRET_LEN], &scope_id)
                        .as_str()
                        .as_bytes()
                        .to_vec(),
                    unknown: padding(1024),
                }
            })
            .collect();
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(MAX_HISTORY_LINKS as u64 + 1);
        let s = seeds(
            &seed,
            MAX_HISTORY_LINKS as u64 + 1,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let mut cs = committed_set(&commitment, &sig, &ledger);
        cs.direct_child_scope_index = &children;
        let carried = real_chain(MAX_HISTORY_LINKS as u64);
        let section = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &carried)
            .expect("a maximal committed set re-seals");
        assert_eq!(section.grant_blobs.len(), MAX_GRANT_BLOBS);
        let size = encode_grant_section(&section).expect("encodes").len();
        let budget = resealable_section_bytes(MAX_GRANT_BLOBS);
        // Headroom, so a wire-shape edit fails here rather than at the cliff.
        assert!(
            size + 64 * 1024 <= budget,
            "a maximal re-seal is {size} bytes against a {budget}-byte budget"
        );
    }

    #[test]
    fn a_re_seal_carries_no_preserved_field_a_write_grantee_authored() {
        // A rotation is not a republish and owes no byte stability
        // (FSM1/cipher-box-next#27 D10), and no owner signature covers either
        // map, so carrying one forward hands a committed write grantee a run
        // no count bound can size.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"n");
        let ledger: Vec<GrantLedgerEntry> = ledger
            .into_iter()
            .map(|row| GrantLedgerEntry {
                unknown: padding(64),
                ..row
            })
            .collect();
        let children = vec![ChildScopeRef {
            scope_id: [0x21; 16],
            ipns_name: b"child".to_vec(),
            unknown: padding(64),
        }];
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(1);
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let mut cs = committed_set(&commitment, &sig, &ledger);
        cs.direct_child_scope_index = &children;

        let section = reseal_scope_root(&mut SeededEntropy::new(11), &id, &s, &cs, &[])
            .expect("a padded set re-seals");
        let body = opened_write_body(&section, &fx.write_scope_seed, 1);
        for row in &body.grant_ledger {
            assert!(
                row.unknown.is_empty(),
                "a re-sealed ledger row carries a padded map"
            );
        }
        for child in &body.direct_child_scope_index {
            assert!(
                child.unknown.is_empty(),
                "a re-sealed child scope ref carries a padded map"
            );
        }
    }

    #[test]
    fn every_history_link_this_engine_mints_fits_the_retained_bound() {
        // The bound is only safe to enforce because an honest link never
        // approaches it. Measured on a real minted link, not on the layout the
        // constant was derived from.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"n");
        let id = identity(&fx, &owner_pub, b"n", None);
        let head = chain_seed(4);
        let fresh = chain_seed(5);
        let s = seeds(
            &fresh,
            5,
            Some(PrevEpochSeed {
                seed: &head,
                epoch: 4,
            }),
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        let section = reseal_scope_root(&mut SeededEntropy::new(21), &id, &s, &cs, &[])
            .expect("the rotation mints one fresh link");

        let minted = &section.history_links[0].sealed;
        assert!(
            minted.len() <= MAX_RETAINED_HISTORY_LINK_BYTES,
            "a {}-byte minted link does not survive a {MAX_RETAINED_HISTORY_LINK_BYTES}-byte bound",
            minted.len()
        );

        // The widest honest case: the epoch is the one variable-width field.
        let widest = mint_history_link(
            &mut SeededEntropy::new(22),
            V,
            SCOPE,
            &fresh,
            u64::MAX,
            &PrevEpochSeed {
                seed: &head,
                epoch: u64::MAX - 1,
            },
        )
        .expect("the link mints");
        assert!(
            widest.len() * 2 <= MAX_RETAINED_HISTORY_LINK_BYTES,
            "a {}-byte link leaves too little headroom under {MAX_RETAINED_HISTORY_LINK_BYTES}",
            widest.len()
        );
    }

    #[test]
    fn a_carried_history_link_past_the_retained_bound_is_dropped_with_everything_older() {
        // The sweep path keeps its carried links verbatim (`prev` is `None`),
        // so without this bound one inflated link rides forward for ever and
        // the section budget is an estimate rather than a bound. Dropped, never
        // refused, or whoever inflated it blocks the scope's own re-seal.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"n");
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(3);
        let s = seeds(&seed, 3, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);

        let honest = |byte: u8| SignedSealed {
            sealed: vec![byte; MAX_RETAINED_HISTORY_LINK_BYTES],
            signature: [0u8; 64],
            unknown: padding(32),
        };
        let inflated = SignedSealed {
            sealed: vec![0x22; MAX_RETAINED_HISTORY_LINK_BYTES + 1],
            signature: [0u8; 64],
            unknown: PreservedFields::new(),
        };
        let carried = vec![honest(0x11), inflated, honest(0x33)];

        let section = reseal_scope_root(&mut SeededEntropy::new(12), &id, &s, &cs, &carried)
            .expect("the sweep still re-seals");
        assert_eq!(
            section.history_links.len(),
            1,
            "the inflated link and everything older than it must go"
        );
        assert!(
            section.history_links[0].unknown.is_empty(),
            "and the retained link carries no padded map either"
        );
    }

    #[test]
    fn a_commitment_past_the_codec_bound_fails_closed_before_any_seal() {
        // The owner learns the ceiling here, before one HPKE wrap per committed
        // grant is spent on a section `encode_grant_section` would refuse.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (mut commitment, sig, ledger) = fx.committed(b"n");
        commitment.entries = (0..=MAX_GRANT_BLOBS)
            .map(|i| {
                let mut tag = [0u8; SECRET_LEN];
                tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
                GrantSetEntry::new(
                    &fx.pointer_read_key,
                    tag,
                    Fixture::nth_recipient(i).public().to_bytes(),
                    Permission::Read,
                    [0x02; 32],
                )
            })
            .collect();
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(9);
        let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let err = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &[])
            .expect_err("past the bound");
        assert_eq!(err.check(), "too-many-committed-grants");
    }

    #[test]
    fn a_committed_ledger_past_the_codec_bound_fails_closed_before_any_seal() {
        // The commitment stays inside the bound, so only the ledger — the side the
        // wrap loop walks — trips the guard.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, _) = fx.committed(b"n");
        let ledger: Vec<GrantLedgerEntry> = (0..=MAX_GRANT_BLOBS)
            .map(|i| {
                let mut tag = [0u8; SECRET_LEN];
                tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
                fx.attested_row(
                    [0x02; 33],
                    fx.read_grantee.public().to_bytes(),
                    Permission::Read,
                    tag,
                    b"n",
                )
            })
            .collect();
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(9);
        let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let err =
            reseal_scope_root(&mut UndrawnEntropy, &id, &s, &cs, &[]).expect_err("past the bound");
        assert_eq!(err.check(), "too-many-committed-grants");
    }

    #[test]
    fn a_sweep_carries_its_chain_through_unpruned() {
        // A sweep mints no link, so the record's epoch label can outrun the
        // newest link's minting epoch — the AAD a walk needs. It neither walks
        // nor prunes; appending nothing, it cannot grow the set either.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"n");
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(9);
        let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        // Past the retained window, so a reinstated sweep prune would show up.
        let carried = real_chain(MAX_RETAINED_HISTORY_LINKS as u64 + 8);
        let section = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &carried)
            .expect("a sweep re-seals whatever it carries");
        let sealed: Vec<&Vec<u8>> = section.history_links.iter().map(|l| &l.sealed).collect();
        let carried_sealed: Vec<&Vec<u8>> = carried.iter().map(|l| &l.sealed).collect();
        assert_eq!(
            sealed, carried_sealed,
            "carried through, in order, unpruned"
        );
    }

    #[test]
    fn revoked_grantee_is_absent_survivors_present_at_new_epoch() {
        // The revocation crown jewel: three grantees, revoke the middle one by
        // removing it from BOTH the commitment and the ledger, re-seal, and prove
        // the revokee has no blob while survivors decrypt to the fresh seed.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let revoked = X25519Secret::from_scalar([0xcc; 32]);

        // A real name: the cut binds the commitment to the scope it names.
        let scope_name = super::super::rotate_write::derive_write_name(&[0x5a; 32], &SCOPE);
        let scope_name_bytes = scope_name.as_str().as_bytes();
        // The cut names the revokee by re-deriving this tag from the owner's own
        // ECDH, so the fixture files the row under the tag that key really binds.
        let revoked_tag = crate::grants::recipient_blinded_tag(
            &fx.owner_enc,
            &revoked.public(),
            scope_name_bytes,
        )
        .expect("a contributory recipient key");

        let entries = vec![
            GrantSetEntry::new(
                &fx.pointer_read_key,
                Fixture::read_tag(),
                Fixture::read_recipient().public().to_bytes(),
                Permission::Read,
                [0x02; 32],
            ),
            GrantSetEntry::new(
                &fx.pointer_read_key,
                revoked_tag,
                revoked.public().to_bytes(),
                Permission::Read,
                [0x04; 32],
            ),
            GrantSetEntry::new(
                &fx.pointer_read_key,
                Fixture::write_tag(),
                Fixture::write_recipient().public().to_bytes(),
                Permission::Write,
                [0x03; 32],
            ),
        ];
        let commitment = GrantSetCommitment {
            ipns_name: scope_name_bytes.to_vec(),
            owner_pseudonym_pk: fx.pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries,
            unknown: PreservedFields::new(),
        };
        let ledger = vec![
            fx.attested_row(
                [0x02; 33],
                fx.read_grantee.public().to_bytes(),
                Permission::Read,
                Fixture::read_tag(),
                scope_name_bytes,
            ),
            fx.attested_row(
                [0x04; 33],
                revoked.public().to_bytes(),
                Permission::Read,
                revoked_tag,
                scope_name_bytes,
            ),
            fx.attested_row(
                [0x03; 33],
                fx.write_grantee.public().to_bytes(),
                Permission::Write,
                Fixture::write_tag(),
                scope_name_bytes,
            ),
        ];

        // Revoke: the read-revoke trigger's committed-set cut.
        let commitment_sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
            .unwrap()
            .to_compact();
        let cut = super::super::trigger::revoke_read_grant(
            &super::super::trigger::GrantCutPlan {
                commitment: &commitment,
                commitment_sig: &commitment_sig,
                grant_ledger: &ledger,
                scope_root_name: &scope_name,
                owner_signer: &fx.owner_ecdsa,
                pointer_read_key: &fx.pointer_read_key,
            },
            &revoked_tag,
        )
        .expect("revoke");
        assert!(
            !cut.grant_ledger.iter().any(|e| e.tag == revoked_tag),
            "revokee gone from ledger"
        );
        assert!(
            !cut.commitment.entries.iter().any(|e| e.tag == revoked_tag),
            "revokee gone from commitment"
        );

        let id = identity(&fx, &owner_pub, scope_name_bytes, None);
        let new_seed = [0xef; 32];
        let s = seeds(
            &new_seed,
            2,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = CommittedSet {
            commitment: &cut.commitment,
            commitment_sig: &cut.commitment_sig,
            grant_ledger: &cut.grant_ledger,
            direct_child_scope_index: &[],
            revoked_recipients: &[],
        };
        let mut e = SeededEntropy::new(4);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");

        // The revokee has NO grant blob.
        assert!(
            !section.grant_blobs.iter().any(|b| b.tag == revoked_tag),
            "revoked party's blob is absent — this is the revocation"
        );
        assert_eq!(
            section.grant_blobs.len(),
            2,
            "only survivors are re-wrapped"
        );
        // And the revokee cannot open any survivor's blob (fresh seed).
        let ctx = ctx_for(V, SCOPE, 2, STRUCT_TAG_GRANT_BLOB);
        for b in &section.grant_blobs {
            assert!(
                open_grant_blob(&revoked, &b.enc, &ctx, &b.ciphertext).is_err(),
                "revokee cannot open a survivor's blob"
            );
        }
        // Survivor opens the fresh seed.
        let read_gb = section
            .grant_blobs
            .iter()
            .find(|b| b.tag == Fixture::read_tag())
            .unwrap();
        let payload =
            open_grant_blob(&fx.read_grantee, &read_gb.enc, &ctx, &read_gb.ciphertext).unwrap();
        assert!(ct_eq(payload.read_scope_seed(), &new_seed));
    }

    #[test]
    fn diverging_ledger_fails_closed_release_active() {
        // A write-grantee adds a ledger row the owner never committed. The re-seal
        // rejects it with a runtime `Err` (not a debug_assert) — so a release
        // build never seals a section the gate would reject. This test is active
        // in release.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, mut ledger) = fx.committed(b"n");
        ledger.push(fx.attested_row(
            [0x09; 33],
            X25519Secret::from_scalar([0x0f; 32]).public().to_bytes(),
            Permission::Write,
            [0xff; 32], // uncommitted tag
            b"n",
        ));
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(5);
        let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("diverging ledger");
        assert_eq!(err.check(), "ledger-diverges-from-commitment");
    }

    #[test]
    fn signer_not_committed_fails_closed_release_active() {
        // The rotator's pseudonym signer differs from the owner-committed pseudonym
        // key. The re-seal rejects it with a runtime `Err` (not a debug_assert) — so
        // a release build never signs a scope root the gate would reject as
        // signer-mismatched (an unopenable root). This test is active in release.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
        let wrong_signer = Ed25519Signer::from_seed([0x99; 32]);
        let id = ScopeRootIdentity {
            v: V,
            scope_id: SCOPE,
            ipns_name: b"scope-root-name",
            owner_enc_pub: &owner_pub,
            owner_enc_secret: None,
            ascent: None,
            owes_ascent_link: false,
            pseudonym_signer: &wrong_signer,
        };
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(7);
        let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("signer mismatch");
        assert_eq!(err.check(), "signer-not-committed");
    }

    #[test]
    fn a_descendant_re_sealed_with_no_parent_seed_fails_closed_release_active() {
        // Only `parent_node_seed` mints an ascent link, so a descendant re-sealed
        // without one would publish a record `gated_child_root` permanently
        // rejects — signed, live, and unopenable as anyone's child. The re-seal
        // refuses with a runtime `Err` (not a debug_assert), so a release build
        // cannot mint it. This test is active in release.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
        let id = ScopeRootIdentity {
            owes_ascent_link: true,
            ..identity(&fx, &owner_pub, b"scope-root-name", None)
        };
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(11);
        let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("no link to bind it");
        assert_eq!(err.check(), "ascent-link-dropped");

        // The same identity handed the seed mints the link and seals.
        let ok = ScopeRootIdentity {
            owes_ascent_link: true,
            ..identity(
                &fx,
                &owner_pub,
                b"scope-root-name",
                Some(&fx.parent_node_seed),
            )
        };
        let mut e = SeededEntropy::new(11);
        assert!(
            reseal_scope_root(&mut e, &ok, &s, &cs, &[])
                .expect("the descendant seals")
                .ascent_link
                .is_some()
        );
    }

    #[test]
    fn a_root_that_owes_no_ascent_link_is_never_re_sealed_with_one() {
        // A vault root's readers derive no parent seed, so a minted link is one
        // no descent reproduces: every read is rejected at the gate's ascent
        // stage while the name's sequence floor has already moved past the last
        // good record. Permanent lockout, so the refusal is a runtime `Err` and
        // this test is active in release.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
        let id = ScopeRootIdentity {
            owes_ascent_link: false,
            ..identity(
                &fx,
                &owner_pub,
                b"scope-root-name",
                Some(&fx.parent_node_seed),
            )
        };
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(11);
        let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("a link it does not owe");
        assert_eq!(err.check(), "ascent-link-not-owed");

        // The same identity handed no seed seals, link-less.
        let ok = identity(&fx, &owner_pub, b"scope-root-name", None);
        let mut e = SeededEntropy::new(11);
        assert!(
            reseal_scope_root(&mut e, &ok, &s, &cs, &[])
                .expect("the vault root seals")
                .ascent_link
                .is_none()
        );
    }

    /// The re-seal a holder of the owner encryption subkey runs.
    fn owner_held<'a>(fx: &'a Fixture, owner_pub: &'a X25519Public) -> ScopeRootIdentity<'a> {
        ScopeRootIdentity {
            owner_enc_secret: Some(&fx.owner_enc),
            ..identity(fx, owner_pub, MINTED_NAME, None)
        }
    }

    #[test]
    fn an_owner_held_reseal_wraps_every_honestly_minted_row() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.minted();
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);

        let section = reseal_scope_root(
            &mut SeededEntropy::new(21),
            &owner_held(&fx, &owner_pub),
            &s,
            &cs,
            &[],
        )
        .expect("every row derives the tag it is filed under");
        assert_eq!(section.grant_blobs.len(), 2);
    }

    #[test]
    fn a_relabelled_ledger_row_cannot_redirect_the_blob() {
        // A committed write-grantee re-authors the write body with a victim's
        // `recipientEncPk` replaced by a key of its own. The re-seal wraps to the
        // key the owner signed into the commitment entry, so the relabelling is
        // inert: it neither redirects the blob nor drops it.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let attacker = X25519Secret::from_scalar([0x5f; 32]);
        let (commitment, sig, mut ledger) = fx.minted();
        let victim_tag = ledger[0].tag;
        ledger[0].recipient_enc_pk = attacker.public().to_bytes();
        let seed = [0x01; 32];
        let read_epoch = 1;
        let s = seeds(
            &seed,
            read_epoch,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        let ctx = ctx_for(V, SCOPE, read_epoch, STRUCT_TAG_GRANT_BLOB);

        // Both legs agree, which is the point: the write-grantee re-sealer holds
        // no owner secret and still reaches the owner-committed key.
        for id in [
            owner_held(&fx, &owner_pub),
            identity(&fx, &owner_pub, MINTED_NAME, None),
        ] {
            let section = reseal_scope_root(&mut SeededEntropy::new(23), &id, &s, &cs, &[])
                .expect("the rotation the relabelling was meant to disturb still publishes");
            assert_eq!(
                section.grant_blobs.len(),
                commitment.entries.len(),
                "every committed entry keeps its blob"
            );
            let victim_blob = section
                .grant_blobs
                .iter()
                .find(|b| b.tag == victim_tag)
                .expect("the victim's committed tag still carries a blob");
            let payload = open_grant_blob(
                &fx.read_grantee,
                &victim_blob.enc,
                &ctx,
                &victim_blob.ciphertext,
            )
            .expect("the owner-committed recipient opens its own blob");
            assert!(ct_eq(payload.read_scope_seed(), &seed));
            assert!(
                open_grant_blob(&attacker, &victim_blob.enc, &ctx, &victim_blob.ciphertext)
                    .is_err(),
                "the key the row was relabelled to opens nothing"
            );
        }
    }

    #[test]
    fn a_corrupted_row_signature_costs_the_committed_blob_nothing() {
        // Corrupting the 64 signature bytes needs no key material, so it is the
        // cheapest attack a committed writer has on a co-grantee. The blob is
        // wrapped to the commitment entry, which the owner signs as one set, so
        // the row's own attestation is not what the victim's delivery rests on.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, mut ledger) = fx.minted();
        let victim_tag = ledger[0].tag;
        ledger[0].owner_sig[0] ^= 0xff;
        let seed = [0x01; 32];
        let read_epoch = 1;
        let s = seeds(
            &seed,
            read_epoch,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        let ctx = ctx_for(V, SCOPE, read_epoch, STRUCT_TAG_GRANT_BLOB);

        for id in [
            owner_held(&fx, &owner_pub),
            identity(&fx, &owner_pub, MINTED_NAME, None),
        ] {
            let section = reseal_scope_root(&mut SeededEntropy::new(31), &id, &s, &cs, &[])
                .expect("the re-seal publishes");
            let victim_blob = section
                .grant_blobs
                .iter()
                .find(|b| b.tag == victim_tag)
                .expect("the victim keeps its blob");
            let payload = open_grant_blob(
                &fx.read_grantee,
                &victim_blob.enc,
                &ctx,
                &victim_blob.ciphertext,
            )
            .expect("the owner-committed recipient opens its own blob");
            assert!(ct_eq(payload.read_scope_seed(), &seed));
        }
    }

    #[test]
    fn a_committed_recipient_key_core_will_not_adopt_fails_closed_release_active() {
        // A cofactor twin and the key with bit 255 set both blind to the honest
        // key's tag, so nothing but core's adoption gate separates them from it.
        // The owner signs the commitment, so such an entry is the owner attesting
        // a grant nothing can be sealed to: the whole re-seal fails with a runtime
        // `Err`, never a debug_assert, and `UndrawnEntropy` proves the refusal
        // lands before the first seal. Active in release.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let victim = fx.read_grantee.public();
        let mut high_bit = victim.to_bytes();
        high_bit[31] |= 0x80;

        let unadoptable = cipherbox_core::suite::x25519::cofactor_twins(&victim)
            .into_iter()
            .chain([high_bit]);
        for enc_pk in unadoptable {
            let (mut commitment, _, ledger) = fx.minted();
            commitment.entries[0].set_recipient_enc_pk(&fx.pointer_read_key, enc_pk);
            let sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
                .expect("the owner signs the set it attests")
                .to_compact();
            let seed = [0x01; 32];
            let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
            let cs = committed_set(&commitment, &sig, &ledger);

            // Both legs agree: holding the owner secret buys no way to wrap a
            // grant to a key core will not adopt.
            for id in [
                owner_held(&fx, &owner_pub),
                identity(&fx, &owner_pub, MINTED_NAME, None),
            ] {
                let err = reseal_scope_root(&mut UndrawnEntropy, &id, &s, &cs, &[])
                    .expect_err("a grant can never be wrapped to a key core will not adopt");
                assert_eq!(err.check(), "unusable-recipient-key");
            }
        }
    }

    #[test]
    fn unusable_recipient_key_fails_closed() {
        // A low-order (all-zero) committed recipient key cannot receive a grant,
        // so the whole re-seal fails rather than publish a set one entry short.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let commitment = GrantSetCommitment {
            ipns_name: b"n".to_vec(),
            owner_pseudonym_pk: fx.pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries: vec![GrantSetEntry::new(
                &fx.pointer_read_key,
                Fixture::read_tag(),
                [0u8; 32], // low-order X25519 → from_bytes rejects
                Permission::Read,
                [0x02; 32],
            )],
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
            .unwrap()
            .to_compact();
        let ledger = vec![fx.attested_row(
            [0x02; 33],
            Fixture::read_recipient().public().to_bytes(),
            Permission::Read,
            Fixture::read_tag(),
            b"n",
        )];
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(6);
        let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("bad key");
        assert_eq!(err.check(), "unusable-recipient-key");
    }

    #[test]
    fn determinism_same_entropy_same_bytes() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed(b"n");
        let id = identity(&fx, &owner_pub, b"n", Some(&fx.parent_node_seed));
        let seed = [0x01; 32];
        let prev = [0x02; 32];
        let build = || {
            let s = seeds(
                &seed,
                3,
                Some(PrevEpochSeed {
                    seed: &prev,
                    epoch: 2,
                }),
                &fx.write_scope_seed,
                &fx.pointer_read_key,
            );
            let cs = committed_set(&commitment, &sig, &ledger);
            let mut e = SeededEntropy::new(42);
            encode_grant_section(&reseal_scope_root(&mut e, &id, &s, &cs, &[]).unwrap()).unwrap()
        };
        assert_eq!(
            build(),
            build(),
            "same entropy seed → byte-identical section"
        );
    }

    /// The write scope seed a cut moves TO, and the one it retires.
    const FRESH_WRITE_SCOPE_SEED: [u8; 32] = [0xc1; 32];
    const RETIRING_WRITE_SCOPE_SEED: [u8; 32] = [0xc2; 32];

    /// A cut's seeds: the read plane stands still, the write plane advances from
    /// `prev_write_epoch` to `write_epoch` over a fresh write scope seed.
    fn cut_seeds<'a>(
        override_seed: &'a [u8; 32],
        pointer_read_key: &'a [u8; 32],
        prev: PrevEpochSeed<'a>,
        write_epoch: u64,
    ) -> ResealSeeds<'a> {
        ResealSeeds {
            override_seed,
            read_epoch: 5,
            prev: None,
            write_scope_seed: &FRESH_WRITE_SCOPE_SEED,
            write_epoch,
            write_history: WriteHistory::Cut(prev),
            pointer_read_key,
        }
    }

    /// The write-body a section publishes, opened as any write-key holder does.
    fn opened_write_body(
        section: &GrantSection,
        write_scope_seed: &[u8; 32],
        write_epoch: u64,
    ) -> cipherbox_core::seal::WriteBody {
        let write_seed = kdf::write_seed(write_scope_seed, &SCOPE);
        let write_key = kdf::write_key(write_seed.as_bytes());
        let ctx = ctx_for(V, SCOPE, write_epoch, STRUCT_TAG_WRITE_BODY);
        let plaintext =
            cipherbox_core::seal::unseal(write_key.as_bytes(), &ctx, &section.write_body.sealed)
                .expect("the write body opens under the fresh write key");
        cipherbox_core::seal::decode_write_body(&plaintext).expect("decodes")
    }

    #[test]
    fn a_write_cut_mints_its_history_link_to_the_owner_alone() {
        let fx = Fixture::new();
        let (commitment, sig, ledger) = fx.minted();
        let owner_pub = fx.owner_enc.public();
        let id = ScopeRootIdentity {
            owner_enc_secret: Some(&fx.owner_enc),
            ..identity(&fx, &owner_pub, MINTED_NAME, None)
        };
        let override_seed = [0x0e; 32];
        let s = cut_seeds(
            &override_seed,
            &fx.pointer_read_key,
            PrevEpochSeed {
                seed: &RETIRING_WRITE_SCOPE_SEED,
                epoch: 4,
            },
            5,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(70);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");

        let body = opened_write_body(&section, &FRESH_WRITE_SCOPE_SEED, 5);
        let ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_WRITE_HISTORY_LINK);
        let payload = open_owner_history_link(&fx.owner_enc, &ctx, &body.write_history_link)
            .expect("the link opens for the owner at the new write epoch");
        assert!(ct_eq(payload.prev_seed(), &RETIRING_WRITE_SCOPE_SEED));
        assert_eq!(payload.prev_epoch, 4);

        for seed in [&FRESH_WRITE_SCOPE_SEED, &RETIRING_WRITE_SCOPE_SEED] {
            let key = kdf::structure_key(seed, STRUCT_TAG_HISTORY_LINK);
            assert!(
                open_history_link(key.as_bytes(), &ctx, &body.write_history_link).is_err(),
                "a write-plane seed opens nothing"
            );
        }
    }

    #[test]
    fn a_write_cut_without_the_owner_key_is_refused_before_any_seal() {
        let fx = Fixture::new();
        let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
        let owner_pub = fx.owner_enc.public();
        let id = identity(&fx, &owner_pub, MINTED_NAME, Some(&fx.parent_node_seed));
        let override_seed = [0x0e; 32];
        let s = cut_seeds(
            &override_seed,
            &fx.pointer_read_key,
            PrevEpochSeed {
                seed: &RETIRING_WRITE_SCOPE_SEED,
                epoch: 4,
            },
            5,
        );
        assert_eq!(
            reseal_scope_root(
                &mut UndrawnEntropy,
                &id,
                &s,
                &committed_set(&commitment, &sig, &ledger),
                &[]
            )
            .expect_err("a keyless cut seals nothing")
            .check(),
            "owner-key-required-for-write-cut"
        );
    }

    /// `UndrawnEntropy` is the release-active proof: the refusal returns before
    /// any seal draws a byte, in a build that strips `debug_assert!`. Dropping
    /// the blob instead would publish an empty link above write epoch 1, which
    /// truncates the write-plane regression chain from that epoch onward.
    #[test]
    fn a_carried_write_history_link_past_the_codec_bound_is_refused_before_any_seal() {
        let fx = Fixture::new();
        let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
        let owner_pub = fx.owner_enc.public();
        let id = identity(&fx, &owner_pub, MINTED_NAME, None);
        let override_seed = [0x0e; 32];
        let cs = committed_set(&commitment, &sig, &ledger);
        let at_len = |link: &'static [u8]| ResealSeeds {
            write_history: WriteHistory::Carried(link),
            write_epoch: 3,
            ..seeds(
                &override_seed,
                5,
                None,
                &FRESH_WRITE_SCOPE_SEED,
                &fx.pointer_read_key,
            )
        };
        const BLOATED: &[u8] = &[0x7c; MAX_WRITE_HISTORY_LINK_BYTES + 1];
        const AT_BOUND: &[u8] = &[0x7c; MAX_WRITE_HISTORY_LINK_BYTES];

        assert_eq!(
            reseal_scope_root(&mut UndrawnEntropy, &id, &at_len(BLOATED), &cs, &[])
                .expect_err("an over-length carried link seals nothing")
                .check(),
            "carried-write-history-link-too-large"
        );

        // The bound itself still carries, so the refusal is the codec's own and
        // not one byte narrower.
        let mut e = SeededEntropy::new(71);
        let section = reseal_scope_root(&mut e, &id, &at_len(AT_BOUND), &cs, &[])
            .expect("a link at the bound re-seals");
        assert_eq!(
            opened_write_body(&section, &FRESH_WRITE_SCOPE_SEED, 3).write_history_link,
            AT_BOUND,
        );
    }

    #[test]
    fn a_minted_empty_write_history_above_write_epoch_1_is_refused_before_any_seal() {
        // `UndrawnEntropy` is the release-active proof: the refusal returns
        // before any seal draws a byte, in a build that strips `debug_assert!`.
        let fx = Fixture::new();
        let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
        let owner_pub = fx.owner_enc.public();
        let id = identity(&fx, &owner_pub, MINTED_NAME, Some(&fx.parent_node_seed));
        let override_seed = [0x0e; 32];
        let cs = committed_set(&commitment, &sig, &ledger);
        let at_epoch = |write_epoch| ResealSeeds {
            write_epoch,
            ..seeds(
                &override_seed,
                1,
                None,
                &FRESH_WRITE_SCOPE_SEED,
                &fx.pointer_read_key,
            )
        };

        assert_eq!(
            reseal_scope_root(&mut UndrawnEntropy, &id, &at_epoch(2), &cs, &[])
                .expect_err("an empty link above write epoch 1 seals nothing")
                .check(),
            "empty-write-history-above-first-epoch"
        );

        let mut e = SeededEntropy::new(83);
        reseal_scope_root(&mut e, &id, &at_epoch(1), &cs, &[])
            .expect("the same mint at write epoch 1 re-seals");
    }

    /// The refusal covers what this build mints, never what it carries. The
    /// carried value is a committed writer's, so refusing an empty one would let
    /// that writer make the scope un-re-keyable — the wedge the budget work
    /// elsewhere in this file exists to close.
    #[test]
    fn a_carried_empty_write_history_above_write_epoch_1_still_re_seals() {
        let fx = Fixture::new();
        let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
        let owner_pub = fx.owner_enc.public();
        let id = identity(&fx, &owner_pub, MINTED_NAME, Some(&fx.parent_node_seed));
        let override_seed = [0x0e; 32];
        let cs = committed_set(&commitment, &sig, &ledger);
        let s = ResealSeeds {
            write_epoch: 3,
            write_history: WriteHistory::Carried(&[]),
            ..seeds(
                &override_seed,
                1,
                None,
                &FRESH_WRITE_SCOPE_SEED,
                &fx.pointer_read_key,
            )
        };

        let mut e = SeededEntropy::new(91);
        reseal_scope_root(&mut e, &id, &s, &cs, &[])
            .expect("a foreign empty link must not refuse the owner's re-seal");
    }

    #[test]
    fn a_history_link_that_does_not_descend_is_refused_before_any_seal() {
        // An interior scope root, so `UndrawnEntropy` pins the refusal ahead of
        // every seal the section carries, the ascent link included.
        let fx = Fixture::new();
        let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
        let owner_pub = fx.owner_enc.public();
        let id = identity(&fx, &owner_pub, MINTED_NAME, Some(&fx.parent_node_seed));
        let override_seed = [0x0e; 32];
        let cs = committed_set(&commitment, &sig, &ledger);
        for prev_epoch in [5, 6] {
            let write_cut = cut_seeds(
                &override_seed,
                &fx.pointer_read_key,
                PrevEpochSeed {
                    seed: &RETIRING_WRITE_SCOPE_SEED,
                    epoch: prev_epoch,
                },
                5,
            );
            let read_cut = seeds(
                &override_seed,
                5,
                Some(PrevEpochSeed {
                    seed: &RETIRING_WRITE_SCOPE_SEED,
                    epoch: prev_epoch,
                }),
                &FRESH_WRITE_SCOPE_SEED,
                &fx.pointer_read_key,
            );
            for s in [write_cut, read_cut] {
                assert_eq!(
                    reseal_scope_root(&mut UndrawnEntropy, &id, &s, &cs, &[])
                        .expect_err("a non-descending link seals nothing")
                        .check(),
                    "history-link-not-descending"
                );
            }
        }
    }

    #[test]
    fn a_gapped_read_history_link_is_refused_but_a_gapped_write_cut_is_not() {
        // A gapped write cut is legitimate: the name wave sources the cut's
        // `epoch` from the rotation plan and its `prev.epoch` from the durable
        // write floor (`net/rotation.rs`), so a device whose floor lags the plan
        // mints a gap that must still seal. Plane asymmetry:
        // [`ResealSeeds::check_history_descends`].
        let fx = Fixture::new();
        let (commitment, sig, ledger) = fx.minted();
        let owner_pub = fx.owner_enc.public();
        let id = ScopeRootIdentity {
            owner_enc_secret: Some(&fx.owner_enc),
            ..identity(&fx, &owner_pub, MINTED_NAME, None)
        };
        let override_seed = [0x0e; 32];
        let cs = committed_set(&commitment, &sig, &ledger);

        let read_cut = seeds(
            &override_seed,
            5,
            Some(PrevEpochSeed {
                seed: &RETIRING_WRITE_SCOPE_SEED,
                epoch: 3,
            }),
            &FRESH_WRITE_SCOPE_SEED,
            &fx.pointer_read_key,
        );
        assert_eq!(
            reseal_scope_root(&mut UndrawnEntropy, &id, &read_cut, &cs, &[])
                .expect_err("a gapped read link seals nothing")
                .check(),
            "history-link-not-contiguous"
        );

        let write_cut = cut_seeds(
            &override_seed,
            &fx.pointer_read_key,
            PrevEpochSeed {
                seed: &RETIRING_WRITE_SCOPE_SEED,
                epoch: 3,
            },
            5,
        );
        let section = reseal_scope_root(&mut SeededEntropy::new(70), &id, &write_cut, &cs, &[])
            .expect("a gapped write cut still seals");
        let payload = open_owner_history_link(
            &fx.owner_enc,
            &ctx_for(V, SCOPE, 5, STRUCT_TAG_WRITE_HISTORY_LINK),
            &opened_write_body(&section, &FRESH_WRITE_SCOPE_SEED, 5).write_history_link,
        )
        .expect("the gapped link opens for the owner");
        assert_eq!(payload.prev_epoch, 3);
    }

    // --- The key-regression ratchet walked backward ---

    #[test]
    fn the_ratchet_reaches_every_epoch_its_links_span() {
        // A published record at epoch 5 carrying the links for 2..=5: the seed
        // for any epoch in that span is recoverable, and each one is the epoch's
        // own.
        let links = real_chain(5);
        for target in 1..=5u64 {
            let seed = seed_at_epoch(V, SCOPE, &chain_seed(5), 5, &links, target)
                .unwrap_or_else(|| panic!("epoch {target} is inside the retained window"));
            assert!(ct_eq(&seed, &chain_seed(target)), "epoch {target}");
        }
    }

    #[test]
    fn the_ratchet_never_steps_forward() {
        assert!(seed_at_epoch(V, SCOPE, &chain_seed(5), 5, &real_chain(5), 6).is_none());
    }

    #[test]
    fn an_epoch_older_than_the_retained_window_is_unreachable() {
        // The links only span 4..=5, so epoch 2 is behind the ratchet's reach —
        // unreadable to every reader, not just this one.
        let links = real_chain(5)[3..].to_vec();
        assert!(seed_at_epoch(V, SCOPE, &chain_seed(5), 5, &links, 2).is_none());
    }

    #[test]
    fn a_link_from_another_scope_breaks_the_walk() {
        let links = real_chain(5);
        assert!(seed_at_epoch(V, [0x9e; 16], &chain_seed(5), 5, &links, 4).is_none());
        assert!(
            seed_at_epoch(V, SCOPE, &chain_seed(4), 5, &links, 4).is_none(),
            "nor does a walk started from the wrong seed open the newest link",
        );
    }

    #[test]
    fn a_scope_at_epoch_one_resolves_its_own_seed_with_no_links() {
        let seed = seed_at_epoch(V, SCOPE, &chain_seed(1), 1, &[], 1).expect("the current seed");
        assert!(ct_eq(&seed, &chain_seed(1)));
    }
}
