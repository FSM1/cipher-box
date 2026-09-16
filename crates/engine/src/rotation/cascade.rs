//! Owner-revocation eager cascade — the fresh-seed descendant re-key that
//! **completes** a read revoke (blueprint/engine.md "rotateScope", L243-252;
//! the **eager set law** #26 D2 as amended by #38 D5).
//!
//! # What the cascade is
//!
//! On an owner read-revocation, [`cascade_rotate_scope`] re-keys the rotated
//! scope root **plus every transitively-reachable descendant scope root**, each
//! with a **fresh random override seed**, re-sealing through [`reseal_scope_root`]
//! with `prev = Some(fresh seed)`. Cost is O(descendant scope count), never tree
//! size.
//!
//! # Why only the fresh-seed cascade completes a revoke
//!
//! A party who cached a *descendant* scope root's override seed opens that
//! descendant at **any** epoch — its structure keys derive from the seed and the
//! epoch is only AAD. A floor-raise + **sweep** reuses each descendant's existing
//! seed (`prev = None`), merely walking the revoked reader's cached seed forward;
//! only minting a **fresh** seed per descendant revokes the cached access. This
//! is the cross-slice invariant: revocation re-keys descendants via the
//! fresh-seed cascade, never via floor-raise + sweep.
//!
//! # Top-down seed threading
//!
//! A descendant's ascent link is sealed to a keypair derived from its parent node
//! seed `node_seed(parent_override_seed, child_scope_id)`
//! (`crates/engine/src/gate/adoption.rs`). Re-keying the parent changes that
//! derivation, so the walk runs **top-down**, threading each parent's
//! freshly-minted seed so the child's ascent link re-seals under the parent's
//! **new** seed — else the link still opens under the stale seed, leaving a
//! revoked ancestor a path in.
//!
//! # Which recipients a re-key cuts
//!
//! Per scope, off the engine's own durable **revocation floor**, never carried
//! down from the ancestor under cut ([`effective_revoked_recipients`]).
//!
//! # Fail-closed completeness
//!
//! Skipping any reachable descendant is a silent revocation hole, not staleness.
//! The walk mirrors [`enumerate_eager_set`] — canonicalized frontiers, a
//! `scope_id`-keyed visited set for diamond/cycle termination, and a hard abort
//! naming the first descendant it cannot resolve, re-seal, publish, or
//! floor-raise, never a partial [`CascadeOutcome`] mistakable for a complete
//! revoke. Some re-keys may land before an abort (no distributed transaction) —
//! safe and retryable, since every re-key is monotonic (a fresh seed at a higher
//! epoch); the retry re-resolves current state and rebuilds the plan rather than
//! replaying one whose nodes already advanced (which would lose CAS).
//!
//! # Determinism
//!
//! Entropy enters only through [`Entropy`] and time only through [`Scheduler`];
//! the sole impure edges are the injected [`CascadeResealResolver`] and
//! [`ScopeRootPublisher`] (as `rotate_scope` and the sweep also carry), whose
//! owner arm is `crate::net::rotation::OwnerRotationNet`.
//!
//! [`enumerate_eager_set`]: super::eager_set::enumerate_eager_set

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSection, GrantSetCommitment, SignedSealed,
};
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN as ECDSA_SIG_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, ct_eq};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

use super::eager_set::{ResolveFailure, bind_child_labels};
use super::reseal::{
    AscentAuthority, CommittedSet, PrevEpochSeed, ResealError, ResealSeeds, ScopeRootIdentity,
    WriteHistory, published_override_seed, reseal_scope_root,
};
use super::rotate::{ResealedScopeRoot, RotateScopePlan, RotationPublishError, ScopeRootPublisher};
use crate::entropy::{Entropy, fresh_seed};
use crate::grants::child_index::canonicalize;
use crate::seams::{BoxedTask, FloorRaise, FloorStore, Scheduler, SeamError};
use cipherbox_core::hex::lower as hex_lower;

/// One descendant scope root's current re-seal material, as resolved from its
/// published record — everything [`reseal_scope_root`] needs **except** the
/// parent node seed and any self-identifying `scope_id`/`ipns_name`.
///
/// Both omissions are load-bearing. No `parent_node_seed`: the ascent link
/// re-seals under the parent's **freshly-minted** derivation, threaded top-down,
/// never the descendant's own stale published one. No self-identifying `scope_id` /
/// `ipns_name`: re-seal, publish, parent-seed derivation, and floor-raise all run
/// under the **enumerated** [`ChildScopeRef`] alone, so there is no second copy
/// for a network hint to diverge from.
///
/// Owns its secrets so the cascade is their terminal owner: the seed fields are
/// [`Zeroizing`] and the pseudonym signer zeroizes on drop. Seeds are handed to
/// `reseal_scope_root` **by borrow**; that callee never zeroes caller-owned
/// buffers (AGENTS.md rule 7).
pub struct CascadeTarget {
    /// The envelope format+suite version.
    pub v: u64,
    /// The published record's current read epoch — the new record publishes at
    /// `+ 1`, and this seed+epoch become the fresh history link's prior.
    pub current_read_epoch: u64,
    /// The vault owner's X25519 encryption-subkey public (owner-blob recipient).
    pub owner_enc_pub: X25519Public,
    /// The owner-committed writer pseudonym signer (re-sealer identity).
    pub pseudonym_signer: Ed25519Signer,
    /// The committed pseudonym that structure-signed the record's write body —
    /// the author of the grant ledger below, and so the party an abuse event
    /// over a row that ledger carries names. `None` where the resolver could
    /// name none.
    pub write_body_signer: Option<[u8; 32]>,
    /// The scope's **current** override (read scope) seed — becomes the fresh
    /// history link's prior; the cascade mints a new seed to replace it.
    pub override_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The write-plane scope seed (unchanged by a read-plane rotation).
    pub write_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// The stable per-scope pointer read key carried in every grant blob.
    pub pointer_read_key: Zeroizing<[u8; SECRET_LEN]>,
    /// The write epoch (unchanged by a read-plane rotation).
    pub write_epoch: u64,
    /// The owner-signed commitment.
    pub commitment: GrantSetCommitment,
    /// The 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: [u8; ECDSA_SIG_LEN],
    /// The authoritative grant ledger (one blob re-wrapped per entry).
    pub grant_ledger: Vec<GrantLedgerEntry>,
    /// The opaque write-plane history-link blob (carried through).
    pub write_history_link: Vec<u8>,
    /// This scope root's own direct-child-scope index — the next-level
    /// enumeration adjacency the walk descends into.
    pub direct_child_scope_index: Vec<ChildScopeRef>,
    /// The scope's existing per-epoch history links, oldest first (the cascade
    /// appends one fresh link on the epoch bump). Re-signed and pruned to the
    /// retained window by the re-seal — see
    /// [`reseal_scope_root`](super::reseal::reseal_scope_root).
    pub carried_history_links: Vec<SignedSealed>,
    /// Whether the record this replaces carried an ascent link, and so whether
    /// the re-seal owes one
    /// ([`ScopeRootIdentity::owes_ascent_link`](super::ScopeRootIdentity::owes_ascent_link)).
    /// Read off the record rather than inferred from the walk, on the rule the
    /// sweep's [`SweptScope`](super::sweep::SweptScope) already follows: a root
    /// re-sealed without the link its record carried is orphaned from every
    /// later gated descent.
    pub carried_ascent_link: bool,
}

/// The impure edge that resolves a descendant scope root's current re-seal
/// material — the cascade's analogue of the eager-set walk's `ChildIndexResolver`
/// and the sweep's [`SweepResolver`](super::sweep::SweepResolver). Resolve +
/// adoption-gate + unseal live behind this trait; the owner arm is
/// `crate::net::rotation::OwnerRotationNet`. A resolve either yields the full
/// [`CascadeTarget`] or a fail-closed [`ResolveFailure`] — a partial or
/// gate-failing record is never a work-list entry.
pub trait CascadeResealResolver {
    /// Resolve `scope`'s current re-seal material, or a fail-closed
    /// [`ResolveFailure`] if its record cannot be authoritatively obtained.
    ///
    /// # Binding contract (obligation on the real resolver)
    ///
    /// The resolver MUST gate `scope`'s record under the enumerated
    /// `scope.scope_id` and `scope.ipns_name`, and the gated record's
    /// `commitment.ipns_name` MUST equal `scope.ipns_name`. It returns **no**
    /// self-identifying `scope_id` or `ipns_name` — see [`CascadeTarget`] for
    /// why.
    async fn resolve(&self, scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure>;
}

/// One scope root re-keyed by the cascade: its id and the epochs it now sits at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyedScope {
    /// The scope-root node id (== scope id).
    pub scope_id: [u8; 16],
    /// The new read epoch the scope was cut to (`current_read_epoch + 1`).
    pub new_read_epoch: u64,
    /// The durable `minReadEpoch` floor after the raise (`>= new_read_epoch`).
    pub epoch_floor: u64,
}

/// A completed owner-revocation cascade. Holding one is proof every reachable
/// descendant was re-keyed with a fresh seed — an incomplete cascade returns
/// [`CascadeError`] instead. `rekeyed[0]` is always the rotated root; the rest
/// are its descendants in the deterministic top-down walk order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CascadeOutcome {
    /// Every re-keyed scope root, root first, then descendants (walk order).
    pub rekeyed: Vec<RekeyedScope>,
}

impl CascadeOutcome {
    /// The number of descendant scope roots re-keyed (excludes the root).
    pub fn descendant_count(&self) -> usize {
        self.rekeyed.len().saturating_sub(1)
    }
}

/// A fail-closed cascade failure. Returned instead of a partial [`CascadeOutcome`]
/// whenever the cascade cannot prove every reachable descendant was re-keyed —
/// the completeness guarantee. Each variant names the offending scope.
/// [`CascadeError::is_retryable`] distinguishes an availability stall from a
/// trust violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CascadeError {
    /// A reachable descendant could not be authoritatively resolved — a gate
    /// rejection, host unavailability, or a C2 label conflict (the same
    /// `scope_id` reached via two parents with different `ipns_name`) — so
    /// the cascade is not provably complete.
    Resolve {
        /// The descendant scope root that could not be resolved.
        scope_id: [u8; 16],
        /// Why the resolve failed.
        reason: ResolveFailure,
    },
    /// Re-sealing a scope root failed a trust invariant (divergent ledger,
    /// uncommitted signer, unusable recipient key) or entropy failed. Nothing was
    /// published for it. Trust rejections are fatal; entropy is retryable.
    Reseal {
        /// The scope that could not be legitimately re-sealed.
        scope_id: [u8; 16],
        /// The underlying re-seal rejection.
        error: ResealError,
    },
    /// A re-sealed record did not land (register-first/PUT failed, a concurrent
    /// writer won the CAS, or the publisher refused the bytes). For a revocation
    /// the fresh seed MUST install, so every failure mode aborts — a lost race is
    /// fatal to *this* attempt, not tolerated as it is in the idempotent sweep.
    Publish {
        /// The scope whose record did not land.
        scope_id: [u8; 16],
        /// The publish failure.
        error: RotationPublishError,
    },
    /// The durable epoch floor could not be raised after a confirmed publish. The
    /// record is published (no lockout); the cut completes on retry. Retryable.
    Floor {
        /// The scope whose floor could not be raised.
        scope_id: [u8; 16],
        /// The underlying seam error.
        error: SeamError,
    },
    /// The durable revocation floor could not be read or raised, so which
    /// recipients the owner already cut at this scope is unknown. Fail-closed
    /// before anything is minted or published, because the alternative is to
    /// re-key a scope back to a party the owner removed. Retryable.
    RevocationFloor {
        /// The scope whose revocation floor could not be reached.
        scope_id: [u8; 16],
        /// The underlying seam error.
        error: SeamError,
    },
    /// The re-sealer holds no owner encryption subkey. The cascade is owner-only
    /// and reads each re-key's published seed back through that subkey, so
    /// without it the value threaded to this scope's descendants can never be
    /// checked. A wiring fault, not a record's doing. Release-active, fatal,
    /// nothing minted.
    OwnerSubkeyMissing {
        /// The scope whose re-key could not be checked.
        scope_id: [u8; 16],
    },
    /// The section a re-key was about to publish does not carry the seed it
    /// minted ([`publishes_minted_seed`]) — so the value threaded to this scope's
    /// descendants is not the one their readers recover. Release-active, fatal,
    /// nothing published.
    UnverifiedThreadedSeed {
        /// The scope whose published seed did not match.
        scope_id: [u8; 16],
    },
    /// A scope's read epoch is exhausted (`current_read_epoch == u64::MAX`).
    /// Rotating would reuse the epoch with fresh key material, violating
    /// key-regression monotonicity, so nothing is minted or published for it.
    /// Unreachable in practice. Fatal.
    EpochExhausted {
        /// The scope whose epoch is exhausted.
        scope_id: [u8; 16],
    },
}

impl core::fmt::Display for CascadeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CascadeError::Resolve { scope_id, reason } => write!(
                f,
                "cascade resolve of scope [{}] failed: {reason}",
                hex_lower(scope_id)
            ),
            CascadeError::Reseal { scope_id, error } => write!(
                f,
                "cascade re-seal of scope [{}] rejected: {error}",
                hex_lower(scope_id)
            ),
            CascadeError::Publish { scope_id, error } => write!(
                f,
                "cascade publish of scope [{}] failed: {error}",
                hex_lower(scope_id)
            ),
            CascadeError::Floor { scope_id, error } => write!(
                f,
                "cascade epoch-floor raise of scope [{}] failed: {error}",
                hex_lower(scope_id)
            ),
            CascadeError::RevocationFloor { scope_id, error } => write!(
                f,
                "cascade revocation floor of scope [{}] failed: {error}",
                hex_lower(scope_id)
            ),
            CascadeError::OwnerSubkeyMissing { scope_id } => write!(
                f,
                "cascade re-key of scope [{}] has no owner encryption subkey",
                hex_lower(scope_id)
            ),
            CascadeError::UnverifiedThreadedSeed { scope_id } => write!(
                f,
                "cascade re-key of scope [{}] does not publish the seed it minted",
                hex_lower(scope_id)
            ),
            CascadeError::EpochExhausted { scope_id } => write!(
                f,
                "cascade read epoch of scope [{}] exhausted (u64::MAX)",
                hex_lower(scope_id)
            ),
        }
    }
}

impl std::error::Error for CascadeError {}

impl CascadeError {
    /// Every cascade check, in declaration order — the surface
    /// `crates/engine/tests/kat_rotation.rs` pins (see the module header for the
    /// prefix rule).
    pub const CHECKS: &'static [&'static str] = &[
        "rot-cascade-resolve-failed",
        "rot-cascade-reseal-rejected",
        "rot-cascade-publish-failed",
        "rot-cascade-floor-raise-failed",
        "rot-cascade-revocation-floor-failed",
        "rot-cascade-owner-subkey-missing",
        "rot-cascade-unverified-threaded-seed",
        "rot-cascade-epoch-exhausted",
    ];

    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            CascadeError::Resolve { .. } => "rot-cascade-resolve-failed",
            CascadeError::Reseal { .. } => "rot-cascade-reseal-rejected",
            CascadeError::Publish { .. } => "rot-cascade-publish-failed",
            CascadeError::Floor { .. } => "rot-cascade-floor-raise-failed",
            CascadeError::RevocationFloor { .. } => "rot-cascade-revocation-floor-failed",
            CascadeError::OwnerSubkeyMissing { .. } => "rot-cascade-owner-subkey-missing",
            CascadeError::UnverifiedThreadedSeed { .. } => "rot-cascade-unverified-threaded-seed",
            CascadeError::EpochExhausted { .. } => "rot-cascade-epoch-exhausted",
        }
    }

    /// The class label used in reject vectors. Exhaustive, so a new variant must
    /// state its class rather than inherit `"trust"`.
    pub fn class(&self) -> &'static str {
        match self {
            CascadeError::Resolve { reason, .. } => reason.class(),
            CascadeError::Reseal { error, .. } => error.class(),
            CascadeError::Publish { error, .. } => error.class(),
            CascadeError::Floor { .. } | CascadeError::RevocationFloor { .. } => "availability",
            CascadeError::OwnerSubkeyMissing { .. } => "capability",
            CascadeError::UnverifiedThreadedSeed { .. } => "trust",
            CascadeError::EpochExhausted { .. } => "over-cap",
        }
    }

    /// The offending scope id.
    pub fn scope_id(&self) -> [u8; 16] {
        match self {
            CascadeError::Resolve { scope_id, .. }
            | CascadeError::Reseal { scope_id, .. }
            | CascadeError::Publish { scope_id, .. }
            | CascadeError::Floor { scope_id, .. }
            | CascadeError::RevocationFloor { scope_id, .. }
            | CascadeError::OwnerSubkeyMissing { scope_id }
            | CascadeError::UnverifiedThreadedSeed { scope_id }
            | CascadeError::EpochExhausted { scope_id } => *scope_id,
        }
    }

    /// Whether re-running the cascade could clear this failure — an availability
    /// stall (unavailable resolve, publish not-landed/lost-race, floor-read I/O,
    /// or an entropy hiccup), or a C2 label conflict the re-point wave repairs —
    /// versus a trust violation (a gate-rejected record, a divergent ledger /
    /// uncommitted signer, an exhausted epoch), which no retry can fix.
    pub fn is_retryable(&self) -> bool {
        match self {
            CascadeError::Resolve { reason, .. } => matches!(
                reason,
                ResolveFailure::Unavailable | ResolveFailure::ConflictingChildLabel
            ),
            // A size refusal judges the record the next pass re-resolves, not
            // its trust: a permanent verdict there would let whoever grew a
            // descendant root block the owner's revocation for good.
            CascadeError::Reseal { error, .. } => matches!(
                error,
                ResealError::Entropy(_) | ResealError::SectionNotResealable { .. }
            ),
            // A publish that did not land is availability; one the publisher
            // refused is its own fail-closed verdict on the bytes, and retrying
            // it forever would launder a trust violation into a stall (rule 6).
            CascadeError::Publish { error, .. } => error.is_retryable(),
            CascadeError::Floor { .. } | CascadeError::RevocationFloor { .. } => true,
            CascadeError::OwnerSubkeyMissing { .. }
            | CascadeError::UnverifiedThreadedSeed { .. }
            | CascadeError::EpochExhausted { .. } => false,
        }
    }
}

/// Suffixes that keep the two revocation-floor shapes apart from the two
/// epoch-floor shapes inside [`FloorStore`]'s one epoch namespace, on the
/// convention `gate::floor` already sets for the write-epoch floor. Every key
/// is a 16-byte scope id followed by a distinct tail: the empty tail is the
/// read-epoch floor, `/write-epoch` is the write-epoch floor, and these two are
/// the revocation floor's.
const REVOKED_MARKER_SUFFIX: &[u8] = b"/revoked";
const REVOKED_ENTRY_SUFFIX: &[u8] = b"/revoked/";
const GRANTED_ENTRY_SUFFIX: &[u8] = b"/granted/";

/// The key that carries **whether** this engine ever recorded a cut at
/// `scope_id`. Read first, so the common scope pays one floor read rather than
/// one per committed row.
fn revocation_marker_key(scope_id: &[u8; 16]) -> Vec<u8> {
    [scope_id.as_slice(), REVOKED_MARKER_SUFFIX].concat()
}

/// The key that carries the read epoch of the owner's newest cut of
/// `recipient` at `scope_id`.
fn revocation_floor_key(scope_id: &[u8; 16], recipient: &[u8; SECRET_LEN]) -> Vec<u8> {
    [scope_id.as_slice(), REVOKED_ENTRY_SUFFIX, recipient].concat()
}

/// The key that carries the read epoch of the owner's newest **grant** to
/// `recipient` at `scope_id`. A re-key withholds a blob only while the cut
/// stands above the grant, so an owner who grants again after a cut is served
/// and a replayed pre-cut commitment still is not: only the owner's own grant
/// path raises this, and a replay raises nothing.
fn grant_floor_key(scope_id: &[u8; 16], recipient: &[u8; SECRET_LEN]) -> Vec<u8> {
    [scope_id.as_slice(), GRANTED_ENTRY_SUFFIX, recipient].concat()
}

/// Record one owner grant of `recipient` at `scope_id`, at the read epoch the
/// grant publishes.
///
/// # Caller obligation
///
/// `recipient` MUST be the recipient of a grant **this owner just minted**, and
/// nothing else. Never derive it from a resolved record: a re-key withholds a
/// blob without removing the row, and a committed write grantee can republish a
/// pre-cut owner-signed set, so neither a ledger row nor a commitment entry is
/// evidence that the owner grants that recipient now. Either would lift a
/// standing cut off bytes the attacker chose.
///
/// Call it **after** the publish that carries the row landed. A raise ahead of
/// the publish is not inert, because the row it needs is not the owner's to
/// withhold: a committed write grantee republishes a pre-cut owner-signed set
/// and restores it, so a lift with no publish behind it undoes the cut for
/// good. The cost of that order is a narrow retry gap — a landed publish whose
/// raise then failed leaves the recipient withheld until the owner grants
/// again — which fails toward more restriction, the direction the floor law
/// takes everywhere.
pub(crate) async fn record_grant_floor<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    recipient: &X25519Public,
    read_epoch: u64,
) -> Result<u64, SeamError> {
    floors
        .raise_epoch_floor(
            &grant_floor_key(scope_id, &recipient.to_bytes()),
            read_epoch,
        )
        .await
}

/// Which recipients this scope's re-key must mint no blob for: the cut the
/// owner is driving now, plus every recipient the durable revocation floor
/// records as already cut **at this scope**.
///
/// The floor is what separates the two descendants a record cannot tell apart.
/// A commitment's `cutEpoch` refuses a pre-cut set only at a scope whose cut
/// this device recorded, so on a device that recorded none a pre-cut set the
/// owner really did sign passes every gate stage, and a committed write grantee
/// can republish a descendant root carrying it. This per-recipient floor is the
/// complement: a descendant whose commitment attests the recipient keeps its
/// blob unless the floor says otherwise — the ancestor's cut alone no longer
/// revokes an independent grant one level down.
///
/// A cut stands only while it is newer than the owner's newest grant to the
/// same recipient at the same scope ([`record_grant_floor`]), so an owner who
/// grants again after a cut is served rather than silently withheld for ever.
///
/// The marker read comes first so a scope the owner never cut pays no per-entry
/// floor read at all.
async fn effective_revoked_recipients<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    committed: &CommittedSet<'_>,
    pointer_read_key: &[u8; SECRET_LEN],
) -> Result<Vec<[u8; SECRET_LEN]>, SeamError> {
    let mut revoked: BTreeSet<[u8; SECRET_LEN]> =
        committed.revoked_recipients.iter().copied().collect();
    if floors
        .epoch_floor(&revocation_marker_key(scope_id))
        .await?
        .is_none()
    {
        return Ok(revoked.into_iter().collect());
    }
    for entry in &committed.commitment.entries {
        let recipient = entry.recipient_enc_pk(pointer_read_key);
        if revoked.contains(&recipient) {
            continue;
        }
        let Some(cut) = floors
            .epoch_floor(&revocation_floor_key(scope_id, &recipient))
            .await?
        else {
            continue;
        };
        let granted = floors
            .epoch_floor(&grant_floor_key(scope_id, &recipient))
            .await?;
        if granted.is_none_or(|granted| cut > granted) {
            revoked.insert(recipient);
        }
    }
    Ok(revoked.into_iter().collect())
}

/// Record this scope's cut in the durable revocation floor, at the epoch the
/// re-key publishes.
///
/// Raised **before** the publish, on [`FloorStore::commit_floors`]'s
/// revocation-before-liveness rule: an interrupted raise then leaves the engine
/// more restrictive than the record plane, which the next pass re-converges,
/// where the reverse order would drop the only memory of a cut that landed.
/// The marker goes **last** in the batch, so the store's own ordered fallback
/// can never publish a marker over entries it has not written yet; a cut this
/// pass drove is re-driven from the record until it lands, and re-raises both.
async fn record_revocation_floor<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    revoked: &[[u8; SECRET_LEN]],
    read_epoch: u64,
) -> Result<(), SeamError> {
    if revoked.is_empty() {
        return Ok(());
    }
    let raises: Vec<FloorRaise> = revoked
        .iter()
        .map(|recipient| FloorRaise::epoch(revocation_floor_key(scope_id, recipient), read_epoch))
        .chain([FloorRaise::epoch(
            revocation_marker_key(scope_id),
            read_epoch,
        )])
        .collect();
    floors.commit_floors(&raises).await
}

/// Whether the section a re-key is about to publish carries the very seed the
/// re-key minted — the seed the walk then threads to this scope's descendants as
/// their new parent derivation.
///
/// `reseal_scope_root`'s own ascent mirror cannot cover this axis: it seals and
/// reopens under the single derivation the caller handed it, so it says nothing
/// about the seed that leaves this frame. The reader's half of the same edge is
/// the descendant gate, which derives its expectation from the parent record it
/// already gated (`net/rotation.rs::RotationAncestry`).
fn publishes_minted_seed(
    owner_enc_secret: &X25519Secret,
    v: u64,
    scope_id: [u8; 16],
    read_epoch: u64,
    section: &GrantSection,
    minted: &[u8; SECRET_LEN],
) -> bool {
    published_override_seed(owner_enc_secret, v, scope_id, read_epoch, section)
        .is_some_and(|recovered| ct_eq(&recovered, minted))
}

/// Re-key one scope root: mint a fresh override seed via `entropy`, re-seal at
/// `current_read_epoch + 1` with `prev = Some(current seed)` through
/// [`reseal_scope_root`], CAS-publish, and raise the durable `minReadEpoch`
/// floor — in that fixed **publish → raise-floor** order so a crash between the
/// two never demands an unpublished epoch (the lockout `rotate_scope` documents).
///
/// Returns the re-key outcome and the **fresh seed**, checked against the record
/// that publishes it ([`publishes_minted_seed`]), which the orchestrator threads
/// to this scope's children as their new parent derivation. The seed is
/// [`Zeroizing`]; the caller is its terminal owner.
async fn rekey_one<E, F, P>(
    entropy: &mut E,
    floors: &F,
    publisher: &P,
    plan: &RotateScopePlan<'_>,
) -> Result<(RekeyedScope, Zeroizing<[u8; SECRET_LEN]>), CascadeError>
where
    E: Entropy,
    F: FloorStore,
    P: ScopeRootPublisher,
{
    let scope_id = plan.identity.scope_id;
    // Fail-closed BEFORE minting: the cascade is owner-only, and reads each
    // re-key's published seed back through this subkey.
    let owner_enc_secret = plan
        .identity
        .owner_enc_secret
        .ok_or(CascadeError::OwnerSubkeyMissing { scope_id })?;

    // Fail-closed BEFORE minting: a saturating bump at u64::MAX would republish
    // fresh key material under the same epoch (a key-regression violation), so an
    // exhausted epoch is rejected rather than silently reused. Release-active
    // (runtime `Err`, never a debug_assert) per AGENTS.md rule 8.
    let new_read_epoch = plan
        .current_read_epoch
        .checked_add(1)
        .ok_or(CascadeError::EpochExhausted { scope_id })?;

    // Fail-closed BEFORE minting: a floor this re-key cannot read would wrap the
    // fresh seed back to a party the owner removed.
    let revoked =
        effective_revoked_recipients(floors, &scope_id, &plan.committed, plan.pointer_read_key)
            .await
            .map_err(|error| CascadeError::RevocationFloor { scope_id, error })?;

    // Mint the fresh random override seed — the fresh-seed cut that revokes cached
    // access. `Zeroizing` wipes it on every return path, including a panic unwind.
    let new_override_seed = fresh_seed(entropy).map_err(|e| CascadeError::Reseal {
        scope_id,
        error: ResealError::Entropy(e),
    })?;

    let seeds = ResealSeeds {
        override_seed: &new_override_seed,
        read_epoch: new_read_epoch,
        // The epoch bump ratchets a fresh history link over the prior seed.
        prev: Some(PrevEpochSeed {
            seed: plan.current_override_seed,
            epoch: plan.current_read_epoch,
        }),
        write_scope_seed: plan.write_scope_seed,
        write_epoch: plan.write_epoch,
        write_history: WriteHistory::Carried(plan.write_history_link),
        pointer_read_key: plan.pointer_read_key,
    };

    let committed = CommittedSet {
        revoked_recipients: &revoked,
        ..plan.committed
    };
    let section = reseal_scope_root(
        entropy,
        &plan.identity,
        &seeds,
        &committed,
        plan.carried_history_links,
    )
    .map_err(|error| CascadeError::Reseal { scope_id, error })?;

    // Fail-closed BEFORE the publish, so a record whose own bytes do not carry the
    // seed the walk threads is never reported re-keyed.
    if !publishes_minted_seed(
        owner_enc_secret,
        plan.identity.v,
        scope_id,
        new_read_epoch,
        &section,
        &new_override_seed,
    ) {
        return Err(CascadeError::UnverifiedThreadedSeed { scope_id });
    }

    let record = ResealedScopeRoot {
        scope_id,
        ipns_name: plan.identity.ipns_name.to_vec(),
        read_epoch: new_read_epoch,
        write_epoch: plan.write_epoch,
        section,
    };

    // Durable before the publish, so a crash between the two leaves the cut
    // remembered rather than forgotten ([`record_revocation_floor`]).
    record_revocation_floor(floors, &scope_id, &revoked, new_read_epoch)
        .await
        .map_err(|error| CascadeError::RevocationFloor { scope_id, error })?;

    // Publish CAS. Both NotPublished and a LostRace abort: a revocation must
    // install the fresh seed, so a record that did not land is a fail-closed hole,
    // never a tolerated drop.
    publisher
        .publish_scope_root(&record)
        .await
        .map_err(|error| CascadeError::Publish { scope_id, error })?;

    // Raise the durable minReadEpoch floor — only after a confirmed publish.
    let epoch_floor = floors
        .raise_epoch_floor(&scope_id, new_read_epoch)
        .await
        .map_err(|error| CascadeError::Floor { scope_id, error })?;

    Ok((
        RekeyedScope {
            scope_id,
            new_read_epoch,
            epoch_floor,
        },
        new_override_seed,
    ))
}

/// Perform the owner-revocation `rotateScope`: re-key the root in `root_plan`
/// **and** every transitively-reachable descendant scope root with a fresh
/// override seed, then enqueue the lazy-wave sweep.
///
/// The level-1 frontier is `root_plan`'s own committed `direct_child_scope_index`
/// — the *same* index the re-sealed root record publishes, so the walk can never
/// diverge from what the root commits to (single source of truth, matching how
/// each descendant descends into its resolved `direct_child_scope_index`). The
/// `resolver` supplies each deeper descendant's re-seal material; `publisher`
/// CAS-publishes each re-key; `floors` raises each scope's `minReadEpoch`;
/// `scheduler` receives the sweep task from `make_sweep_task` on success.
///
/// Top-down and fail-closed: the root's fresh seed threads to its children as
/// their new parent derivation, and so on down the tree; any descendant that
/// cannot be resolved, re-sealed, published, or floor-raised aborts with a
/// [`CascadeError`] naming it — never a partial revoke reported as complete.
///
/// This is the read-revoke completion the sweep does **not** provide: it mints a
/// **fresh** seed per descendant (`prev = Some`), where the sweep reuses the
/// existing seed (`prev = None`). Feed it the read-revoke trigger's already-cut
/// committed set (`revoke_read_grant`) for the root; each descendant re-seals its
/// own unchanged committed set.
#[allow(clippy::too_many_arguments)]
pub async fn cascade_rotate_scope<E, F, S, R, P, Mk>(
    entropy: &mut E,
    floors: &F,
    scheduler: &S,
    resolver: &R,
    publisher: &P,
    root_plan: &RotateScopePlan<'_>,
    make_sweep_task: Mk,
) -> Result<CascadeOutcome, CascadeError>
where
    E: Entropy,
    F: FloorStore,
    S: Scheduler,
    R: CascadeResealResolver,
    P: ScopeRootPublisher,
    Mk: FnOnce() -> BoxedTask,
{
    let root_scope_id = root_plan.identity.scope_id;

    // 1) Re-key the root — the thread head. Its fresh seed derives its children's
    //    new parent node seeds.
    let (root_rekeyed, root_fresh_seed) = rekey_one(entropy, floors, publisher, root_plan).await?;
    let mut outcome = CascadeOutcome {
        rekeyed: vec![root_rekeyed],
    };

    // 2) Top-down threaded walk over the descendant tree, each frontier entry
    //    carrying its parent's freshly-minted seed (module docs). Re-implements
    //    `enumerate_eager_set`'s canonicalized-frontier walk — including its C2
    //    label-conflict abort — because the re-key needs the parent edges
    //    the flat `EagerSet` does not carry.
    let mut visited: BTreeSet<[u8; 16]> = BTreeSet::new();
    visited.insert(root_scope_id);

    let mut labels: BTreeMap<[u8; 16], Vec<u8>> = BTreeMap::new();
    let conflict = |scope_id| CascadeError::Resolve {
        scope_id,
        reason: ResolveFailure::ConflictingChildLabel,
    };
    bind_child_labels(
        &mut labels,
        canonicalize(root_plan.committed.direct_child_scope_index).iter(),
        root_scope_id,
    )
    .map_err(conflict)?;

    let mut frontier = canonicalize_frontier(
        root_plan
            .committed
            .direct_child_scope_index
            .iter()
            .map(|child| (child.clone(), root_fresh_seed.clone()))
            .collect(),
    );
    drop(root_fresh_seed);

    while !frontier.is_empty() {
        let mut next: Vec<(ChildScopeRef, Zeroizing<[u8; SECRET_LEN]>)> = Vec::new();
        for (child, parent_seed) in &frontier {
            // A visited scope_id is a diamond re-encounter or a cycle back-edge:
            // never re-key it (it is already freshly sealed under its first-seen
            // parent's derivation). Termination + the O(descendant count) bound.
            if !visited.insert(child.scope_id) {
                continue;
            }

            // Fail-closed: an unresolvable reachable descendant aborts the cascade
            // rather than leaving a stale-seed hole.
            let target = resolver
                .resolve(child)
                .await
                .map_err(|reason| CascadeError::Resolve {
                    scope_id: child.scope_id,
                    reason,
                })?;

            // Bind per-parent (see bind_child_labels).
            bind_child_labels(
                &mut labels,
                canonicalize(&target.direct_child_scope_index).iter(),
                root_scope_id,
            )
            .map_err(conflict)?;

            // Thread: the child's ascent link re-seals under the parent's NEW
            // derivation, `node_seed(parent_fresh_seed, child_scope_id)`.
            let parent_seed_ref: &[u8; SECRET_LEN] = parent_seed;
            let child_parent_node_seed =
                Zeroizing::new(*kdf::node_seed(parent_seed_ref, &child.scope_id).as_bytes());

            let plan = RotateScopePlan {
                identity: ScopeRootIdentity {
                    v: target.v,
                    // The enumerated ChildScopeRef is the sole identity authority
                    // (see CascadeTarget).
                    scope_id: child.scope_id,
                    ipns_name: &child.ipns_name,
                    owner_enc_pub: &target.owner_enc_pub,
                    owner_enc_secret: root_plan.identity.owner_enc_secret,
                    ascent: Some(AscentAuthority::ParentSeed(&child_parent_node_seed)),
                    owes_ascent_link: true,
                    pseudonym_signer: &target.pseudonym_signer,
                },
                committed: CommittedSet {
                    commitment: &target.commitment,
                    commitment_sig: &target.commitment_sig,
                    grant_ledger: &target.grant_ledger,
                    direct_child_scope_index: &target.direct_child_scope_index,
                    // The ancestor's cut does not reach here: a descendant is
                    // cut by its own durable revocation floor
                    // ([`effective_revoked_recipients`]), so an independent
                    // grant one level down survives the cut above it.
                    revoked_recipients: &[],
                },
                current_override_seed: &target.override_seed,
                current_read_epoch: target.current_read_epoch,
                write_scope_seed: &target.write_scope_seed,
                write_epoch: target.write_epoch,
                write_history_link: &target.write_history_link,
                pointer_read_key: &target.pointer_read_key,
                carried_history_links: &target.carried_history_links,
            };

            let (rekeyed, child_fresh_seed) = rekey_one(entropy, floors, publisher, &plan).await?;
            outcome.rekeyed.push(rekeyed);

            // Enqueue this child's children, threaded on THIS child's fresh seed.
            for grandchild in &target.direct_child_scope_index {
                next.push((grandchild.clone(), child_fresh_seed.clone()));
            }
        }
        frontier = canonicalize_frontier(next);
    }

    // 3) Enqueue the lazy-wave sweep — last, after the eager cascade is durable
    //    (blueprint/engine.md "republish the eager set, enqueue the sweep"). The
    //    cascade already re-keyed the whole eager set eagerly, so the sweep finds
    //    nothing lagging; it stays enqueued for index self-heal and idempotence.
    scheduler.spawn(make_sweep_task());

    Ok(outcome)
}

/// Sort a threaded frontier by `child.scope_id` (stable) and dedup by
/// `scope_id`, keeping the **first-seen** `(child, parent_seed)` pair. Matches
/// [`canonicalize`](crate::grants::child_index::canonicalize)'s convention so the
/// walk — and thus which parent's fresh seed threads a diamond descendant — is
/// permutation-independent. This is the frontier's sole normalization, so the
/// resolver-supplied child indexes feed in verbatim.
fn canonicalize_frontier(
    mut pairs: Vec<(ChildScopeRef, Zeroizing<[u8; SECRET_LEN]>)>,
) -> Vec<(ChildScopeRef, Zeroizing<[u8; SECRET_LEN]>)> {
    pairs.sort_by(|a, b| a.0.scope_id.cmp(&b.0.scope_id));
    let mut seen: Option<[u8; 16]> = None;
    pairs.retain(|(child, _)| {
        if seen == Some(child.scope_id) {
            false
        } else {
            seen = Some(child.scope_id);
            true
        }
    });
    pairs
}

#[cfg(test)]
mod tests;
