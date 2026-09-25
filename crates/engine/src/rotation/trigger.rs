//! Rotation triggers (blueprint/engine.md "Rotation primitives: Triggers",
//! #26 D7).
//!
//! Scope-exit and manual rotations re-seal the **unchanged** committed set: a
//! grantee re-wraps blobs verbatim and can neither extend nor shrink the tag set
//! (#26 D5). The other three cut the set through an owner-only edit over the
//! shared [`GrantCutPlan`]. The cut party is thereby absent from the re-wrapped
//! grant blobs: that absence **is** the revocation ("they keep what they saw;
//! they lose everything new, now").
//!
//! A cut on its own revokes nothing: only the fresh-seed eager cascade completes
//! a read revoke, never the sweep (rationale on [`super::cascade`]), and only a
//! write rotation ends a write grant (rationale on [`WriteRevokeKind`]).

use std::collections::BTreeSet;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{
    GrantLedgerEntry, GrantSetBindingError, GrantSetCommitment, Permission, sign_grant_set,
    verify_grant_set_bound,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, SIGNATURE_LEN as ECDSA_SIG_LEN};
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Public;

use super::cascade::{CascadeError, CascadeOutcome};
use super::rotate::{RotateError, RotationOutcome};
use super::rotate_write::{WriteRotateError, WriteRotationOutcome};
use crate::facade::NodeId;
use crate::grants::ledger::{AuthorityViolation, enforce_committed_ledger};

/// Which trigger fired a rotation — a host-facing classifier carrying no key
/// material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationTrigger {
    /// A grantee left a granted scope (a cross-scope move out of a granted
    /// source, full-depth detected). Flat, self-contained, no committed change.
    ScopeExit,
    /// The owner revoked a read grant — the immediate revoking rekey.
    ReadRevoke,
    /// The owner revoked a write grant outright or downgraded it to read
    /// ([`WriteRevokeKind`]).
    WriteRevoke,
    /// An owner session observed a grant past its deadline and pruned it.
    /// Observation-driven; nothing schedules it.
    DiscoveredExpiry,
    /// Manual hygiene rotate-now. No committed change.
    Manual,
}

impl RotationTrigger {
    /// A stable, host-facing name (no key material).
    pub fn name(&self) -> &'static str {
        match self {
            RotationTrigger::ScopeExit => "scope-exit",
            RotationTrigger::ReadRevoke => "read-revoke",
            RotationTrigger::WriteRevoke => "write-revoke",
            RotationTrigger::DiscoveredExpiry => "discovered-expiry",
            RotationTrigger::Manual => "manual",
        }
    }
}

/// The scope-exit rotation edge: cut one scope root that a grantee just left.
///
/// The pure driver ([`consume_scope_exit_triggers`]) owns the ordering and the
/// retention law; this seam owns assembling the root's
/// [`RotateScopePlan`](super::rotate::RotateScopePlan) from its resolved record
/// and running [`rotate_scope`](super::rotate::rotate_scope) over the live
/// plane — [`GranteeRotationNet`](crate::net::GranteeRotationNet) over the real
/// transport.
pub trait ScopeExitRotator {
    /// Run the flat, grantee-triggered [`RotationTrigger::ScopeExit`] cut at
    /// `scope_root`. `Err` means nothing was cut, with the single documented
    /// exception of [`RotateError::Floor`].
    async fn rotate_on_scope_exit(
        &self,
        scope_root: NodeId,
    ) -> Result<RotationOutcome, RotateError>;
}

/// A [`ScopeExitRotator`] over a call.
///
/// The tick's arm borrows a whole seam family, none of which the drain names, so
/// it enters the driver as one call rather than as a second generic surface on
/// every type between the two.
pub struct RotateOnExit<A>(pub A);

impl<A> ScopeExitRotator for RotateOnExit<A>
where
    A: AsyncFn(NodeId) -> Result<RotationOutcome, RotateError>,
{
    async fn rotate_on_scope_exit(
        &self,
        scope_root: NodeId,
    ) -> Result<RotationOutcome, RotateError> {
        (self.0)(scope_root).await
    }
}

/// What one pass of [`consume_scope_exit_triggers`] cut, and what it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeExitReport {
    /// The scope roots this pass durably cut, in the order it cut them.
    pub rotated: Vec<(NodeId, RotationOutcome)>,
    /// The scope roots whose rotation failed, with why. Each is still a live
    /// trigger: the caller re-drives it rather than treating the pass as done.
    pub failed: Vec<(NodeId, RotateError)>,
}

impl ScopeExitReport {
    /// Whether every queued trigger was cut — the only state in which the
    /// caller may consider the scope exits settled.
    pub fn is_complete(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Drive one [`RotationTrigger::ScopeExit`] rotation per queued scope root.
///
/// `roots` is [`ReplayReport::scope_exit_triggers`](crate::sync::ReplayReport),
/// already deduped to one entry per source scope root. A failure neither
/// short-circuits the pass nor is swallowed: the remaining roots still rotate
/// and the failed one comes back in [`ScopeExitReport::failed`], because a
/// scope exit that never rotates leaves a revokee holding a live seed.
pub async fn consume_scope_exit_triggers<R: ScopeExitRotator>(
    rotator: &R,
    roots: &[NodeId],
) -> ScopeExitReport {
    let mut report = ScopeExitReport {
        rotated: Vec::new(),
        failed: Vec::new(),
    };
    for root in roots {
        match rotator.rotate_on_scope_exit(*root).await {
            Ok(outcome) => report.rotated.push((*root, outcome)),
            Err(e) => report.failed.push((*root, e)),
        }
    }
    report
}

/// The owner-authorized inputs every committed-set cut shares.
pub struct GrantCutPlan<'a> {
    /// The scope root's current owner-signed grant-set commitment —
    /// the authoritative set. Every permission a cut acts on is read from here,
    /// never from the write-grantee-authored ledger.
    pub commitment: &'a GrantSetCommitment,
    /// The current 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: &'a [u8; ECDSA_SIG_LEN],
    /// The write-body grant ledger `commitment` commits.
    pub grant_ledger: &'a [GrantLedgerEntry],
    /// The scope root's current `ipnsName`, supplied by the caller rather than
    /// read off `commitment` — a commitment cannot vouch for the scope it names,
    /// so the binding is only worth anything against an independent name
    /// ([`RevokeError::CommitmentScopeMismatch`]).
    pub scope_root_name: &'a IpnsName,
    /// The owner identity signer — MUST be the identity that produced
    /// `commitment_sig`, and re-signs the cut set.
    pub owner_signer: &'a EcdsaSigner,
    /// The scope's stable pointer read key, which unmasks a committed entry's
    /// recipient (see [`GrantSetEntry`](cipherbox_core::seal::GrantSetEntry)).
    pub pointer_read_key: &'a [u8; SECRET_LEN],
}

/// Which planes a committed-set cut must rotate before it is a real revocation.
///
/// Mintable and editable only by this module's cuts. A host that could forge or
/// clear a flag would make [`rotate_on_cut`] skip a plane the cut demands and
/// still report success — a revocation that never happened.
///
/// ```compile_fail
/// let forged = cipherbox_engine::RotationPlanes { read: false, write: false };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPlanes {
    read: bool,
    write: bool,
}

impl RotationPlanes {
    /// Rotate the read plane — the fresh-seed eager cascade.
    pub fn read(&self) -> bool {
        self.read
    }

    /// Rotate the write plane — `rotateScopeWrite`'s name wave.
    pub fn write(&self) -> bool {
        self.write
    }
}

/// The owner-only committed-set cut a trigger produces, and the rotation it is
/// not a revocation without. Mintable only through this module's cuts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RevokedCommittedSet {
    /// The commitment with the cut applied to its `(tag, permission,
    /// pseudonymPk)` entries.
    pub commitment: GrantSetCommitment,
    /// The fresh 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: [u8; ECDSA_SIG_LEN],
    /// The grant ledger with the same cut applied.
    pub grant_ledger: Vec<GrantLedgerEntry>,
    /// The recipient encryption keys the cut removed — what a re-key refuses to
    /// mint a blob for anywhere in the cascade
    /// ([`CommittedSet::revoked_recipients`](super::reseal::CommittedSet::revoked_recipients)).
    pub revoked_recipients: Vec<[u8; SECRET_LEN]>,
    /// Dropped entries whose committed recipient key core refused to adopt, so
    /// the cut names nobody for them. The tag still leaves the set, but the
    /// cascade withholds no blob, so a non-zero count is an incomplete harvest
    /// the caller must surface rather than read as a clean revoke.
    pub unnamed_drops: usize,
    /// Read-only — see [`planes`](Self::planes).
    planes: RotationPlanes,
}

impl RevokedCommittedSet {
    /// The planes [`rotate_on_cut`] must drive for this cut. Carried with the
    /// cut rather than chosen by the caller, and unreachable for writing, so a
    /// cut cannot be driven through planes that do not finish it.
    ///
    /// ```compile_fail
    /// fn clear(cut: &mut cipherbox_engine::RevokedCommittedSet) {
    ///     cut.planes.read = false;
    /// }
    /// ```
    ///
    /// ```
    /// fn inspect(cut: &cipherbox_engine::RevokedCommittedSet) -> (bool, bool) {
    ///     (cut.planes().read(), cut.planes().write())
    /// }
    /// ```
    pub fn planes(&self) -> RotationPlanes {
        self.planes
    }
}

/// A fail-closed committed-set-cut failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeError {
    /// `owner_signer` did not sign the current commitment, so it is not the owner
    /// identity that authorized the set. Re-signing under it would mint a
    /// commitment the adoption gate rejects (an unreadable root); the encode-side
    /// mirror of the gate's owner-identity verify (fail-closed symmetry).
    UnauthorizedSigner,
    /// The owner-authentic commitment names a different scope than the one under
    /// cut. Binds the owner-auth token to the exact scope, as `gate/adoption.rs`
    /// and [`WriteRotateError::CommitmentScopeMismatch`] do, so a valid owner
    /// signature over another scope's commitment cannot authorize this cut.
    CommitmentScopeMismatch,
    /// The tag is not in the committed set — there is no grant to revoke.
    /// Rotating anyway would be a no-op cut, so this is rejected, not silent.
    NotGranted,
    /// The tag is committed with [`Permission::Read`], so there is no write grant
    /// to revoke or downgrade. Rotating the write plane for it would move every
    /// name in the scope without cutting anything.
    NotWriteGranted,
    /// The tag is committed with [`Permission::Write`], so cutting it from the
    /// read plane alone leaves the holder authoring at every current write name.
    /// A write grant is cut by [`revoke_write_grant`], never by a read revoke.
    WriteGranted,
    /// The cut set the owner would sign has a ledger that does not match its own
    /// commitment — the produce-side mirror of the divergence a resolver hard-
    /// rejects (`enforce_committed_ledger`). Release-active, so no build signs a
    /// set its own readers refuse.
    LedgerDiverges(AuthorityViolation),
    /// The scope's cut epoch cannot step again without wrapping. A wrapped
    /// counter would let a later replay sit above the floor a cut installed, so
    /// the cut refuses instead. Release-active (AGENTS.md rule 8).
    CutEpochExhausted,
    /// Re-signing the cut commitment failed (a duplicate tag or an oversized set
    /// — never possible, since no cut adds a tag, but propagated fail-closed).
    Sign(cipherbox_core::error::CodecError),
}

impl core::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RevokeError::UnauthorizedSigner => {
                f.write_str("owner signer did not authorize the current commitment")
            }
            RevokeError::CommitmentScopeMismatch => {
                f.write_str("commitment names a different scope than the one under cut")
            }
            RevokeError::NotGranted => f.write_str("no grant committed under the tag"),
            RevokeError::NotWriteGranted => {
                f.write_str("the committed grant under the tag is read-only")
            }
            RevokeError::WriteGranted => {
                f.write_str("the committed grant under the tag carries write permission")
            }
            RevokeError::LedgerDiverges(v) => write!(f, "cut set rejected: {}", v.description),
            RevokeError::CutEpochExhausted => {
                f.write_str("the scope cut epoch cannot step again without wrapping")
            }
            RevokeError::Sign(e) => write!(f, "commitment re-sign failed: {}", e.check()),
        }
    }
}

impl std::error::Error for RevokeError {}

impl RevokeError {
    /// Every cut check this type owns, in declaration order — the surface
    /// `crates/engine/tests/kat_rotation.rs` pins (see the module header for the
    /// prefix rule). [`RevokeError::LedgerDiverges`] surfaces the grant plane's
    /// own verdict verbatim and so stays off this surface.
    pub const CHECKS: &'static [&'static str] = &[
        "rot-revoke-unauthorized-signer",
        "rot-revoke-commitment-scope-mismatch",
        "rot-revoke-not-granted",
        "rot-revoke-not-write-granted",
        "rot-revoke-write-granted",
        "rot-revoke-cut-epoch-exhausted",
        "rot-revoke-commitment-sign-failed",
    ];

    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            RevokeError::UnauthorizedSigner => "rot-revoke-unauthorized-signer",
            RevokeError::CommitmentScopeMismatch => "rot-revoke-commitment-scope-mismatch",
            RevokeError::NotGranted => "rot-revoke-not-granted",
            RevokeError::NotWriteGranted => "rot-revoke-not-write-granted",
            RevokeError::WriteGranted => "rot-revoke-write-granted",
            RevokeError::LedgerDiverges(v) => v.check(),
            RevokeError::CutEpochExhausted => "rot-revoke-cut-epoch-exhausted",
            RevokeError::Sign(_) => "rot-revoke-commitment-sign-failed",
        }
    }

    /// The class label used in reject vectors. Exhaustive, so a new variant must
    /// state its class rather than inherit `"trust"`.
    pub fn class(&self) -> &'static str {
        match self {
            RevokeError::UnauthorizedSigner
            | RevokeError::CommitmentScopeMismatch
            | RevokeError::NotGranted
            | RevokeError::NotWriteGranted
            | RevokeError::WriteGranted
            | RevokeError::LedgerDiverges(_) => "trust",
            RevokeError::CutEpochExhausted => "over-cap",
            RevokeError::Sign(error) => error.class(),
        }
    }
}

/// The owner gate every cut runs first: the presented signer authored the
/// current commitment, and that commitment names the scope under cut. See
/// [`RevokeError::UnauthorizedSigner`] and
/// [`RevokeError::CommitmentScopeMismatch`] for what each half buys.
fn authorize_cut(plan: &GrantCutPlan<'_>) -> Result<(), RevokeError> {
    let current_sig =
        EcdsaSignature::from_compact(plan.commitment_sig).ok_or(RevokeError::UnauthorizedSigner)?;
    verify_grant_set_bound(
        &plan.owner_signer.verifying_key(),
        plan.commitment,
        &current_sig,
        plan.scope_root_name.as_str().as_bytes(),
    )
    .map_err(|e| match e {
        GrantSetBindingError::Verify(_) => RevokeError::UnauthorizedSigner,
        GrantSetBindingError::ScopeMismatch => RevokeError::CommitmentScopeMismatch,
    })
}

/// The permission the **owner** committed under `tag`, or [`RevokeError::NotGranted`].
fn committed_permission(
    plan: &GrantCutPlan<'_>,
    tag: &[u8; 32],
) -> Result<Permission, RevokeError> {
    plan.commitment
        .entries
        .iter()
        .find(|e| &e.tag == tag)
        .map(|e| e.permission)
        .ok_or(RevokeError::NotGranted)
}

/// Drop `tags` from both halves of the committed set — what every cut but a
/// downgrade does.
fn drop_tags(
    plan: &GrantCutPlan<'_>,
    tags: &BTreeSet<[u8; 32]>,
) -> Result<DroppedSet, RevokeError> {
    let mut commitment = plan.commitment.clone();
    // The cut names the parties it revokes from the owner's own attestation
    // (see [`GrantSetEntry`]), never from a ledger row. A key core will not
    // adopt names nobody rather than refuse: no blob was ever sealed to it, and
    // refusing would leave the cut that removes the bad entry the one operation
    // the scope cannot run. The count travels with the cut, so the caller sees
    // the harvest was incomplete ([`RevokedCommittedSet::unnamed_drops`]).
    let mut unnamed_drops = 0usize;
    let dropped: Vec<X25519Public> = commitment
        .entries
        .iter()
        .filter(|e| tags.contains(&e.tag))
        .filter_map(|e| {
            let adopted = X25519Public::from_bytes(e.recipient_enc_pk(plan.pointer_read_key));
            if adopted.is_none() {
                unnamed_drops += 1;
            }
            adopted
        })
        .collect();
    commitment.entries.retain(|e| !tags.contains(&e.tag));
    Ok(DroppedSet {
        commitment,
        grant_ledger: plan
            .grant_ledger
            .iter()
            .filter(|e| !tags.contains(&e.tag))
            .cloned()
            .collect(),
        revoked_recipients: dropped.iter().map(X25519Public::to_bytes).collect(),
        unnamed_drops,
    })
}

/// A committed set with a cut applied, and who the cut removed.
struct DroppedSet {
    commitment: GrantSetCommitment,
    grant_ledger: Vec<GrantLedgerEntry>,
    revoked_recipients: Vec<[u8; SECRET_LEN]>,
    unnamed_drops: usize,
}

/// Owner-re-sign the cut set, refusing release-active to sign a commitment its
/// own ledger contradicts ([`RevokeError::LedgerDiverges`]).
///
/// The one place a cut epoch steps. It steps off the epoch the owner already
/// signed, which [`authorize_cut`] verified, so the counter cannot be walked
/// backward by whoever republished the record this plan was read from.
fn resign(
    set: DroppedSet,
    planes: RotationPlanes,
    owner_signer: &EcdsaSigner,
) -> Result<RevokedCommittedSet, RevokeError> {
    let DroppedSet {
        mut commitment,
        grant_ledger,
        revoked_recipients,
        unnamed_drops,
    } = set;
    commitment.cut_epoch = commitment
        .cut_epoch
        .checked_add(1)
        .ok_or(RevokeError::CutEpochExhausted)?;
    enforce_committed_ledger(&commitment, &grant_ledger).map_err(RevokeError::LedgerDiverges)?;
    let commitment_sig = sign_grant_set(owner_signer, &commitment)
        .map_err(RevokeError::Sign)?
        .to_compact();
    Ok(RevokedCommittedSet {
        commitment,
        commitment_sig,
        grant_ledger,
        revoked_recipients,
        unnamed_drops,
        planes,
    })
}

/// Perform the read-revoke committed-set cut: remove `revoked_tag`'s grant from
/// the owner-signed commitment and the write-body ledger in `plan`, and
/// owner-re-sign the pruned commitment.
///
/// Owner-only by construction: only the owner-signed commitment authorises the
/// set ([`authorize_cut`]). The tag MUST be committed as [`Permission::Read`]
/// ([`RevokeError::WriteGranted`]). The revokee has no grant blob once the
/// re-seal lands at the new epoch.
pub fn revoke_read_grant(
    plan: &GrantCutPlan<'_>,
    revoked_tag: &[u8; 32],
) -> Result<RevokedCommittedSet, RevokeError> {
    authorize_cut(plan)?;
    if committed_permission(plan, revoked_tag)? == Permission::Write {
        return Err(RevokeError::WriteGranted);
    }

    resign(
        drop_tags(plan, &BTreeSet::from([*revoked_tag]))?,
        RotationPlanes {
            read: true,
            write: false,
        },
        plan.owner_signer,
    )
}

/// Perform the committed-set cut of one owner revoke: remove every tag in
/// `revoked_tags` from both halves of the set in `plan`, with one cut-epoch
/// step and one re-sign (ADR 0025 D4).
///
/// The read plane always rotates. The write plane rotates too when any cut tag
/// is committed with [`Permission::Write`], because only the name wave ends a
/// write grant. Owner-only and scope-bound exactly as [`revoke_read_grant`]
/// is. An empty set, or a tag the set does not commit, is
/// [`RevokeError::NotGranted`].
pub fn revoke_grants(
    plan: &GrantCutPlan<'_>,
    revoked_tags: &BTreeSet<[u8; 32]>,
) -> Result<RevokedCommittedSet, RevokeError> {
    authorize_cut(plan)?;
    if revoked_tags.is_empty() {
        return Err(RevokeError::NotGranted);
    }
    let mut write = false;
    for tag in revoked_tags {
        write |= committed_permission(plan, tag)? == Permission::Write;
    }
    resign(
        drop_tags(plan, revoked_tags)?,
        RotationPlanes { read: true, write },
        plan.owner_signer,
    )
}

/// How far a write revoke cuts.
///
/// Either way the committed-set edit alone revokes nothing on the write plane:
/// the holder keeps the extractable subtree signing keys derived under the
/// current write scope seed, so only
/// [`rotate_scope_write`](super::rotate_write::rotate_scope_write) moves the
/// scope off names they can still author at (blueprint/engine.md "Invites").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteRevokeKind {
    /// Full revoke — the grant leaves the committed set entirely and both planes
    /// rotate.
    Full,
    /// Downgrade to read — the entry stays, demoted to [`Permission::Read`]. The
    /// downgraded recipient keeps a live read grant, so only the write plane
    /// rotates.
    DowngradeToRead,
}

/// Perform the write-revoke committed-set cut: remove ([`WriteRevokeKind::Full`])
/// or demote to read ([`WriteRevokeKind::DowngradeToRead`]) `revoked_tag`'s grant
/// in both the owner-signed commitment and the write-body ledger, and
/// owner-re-sign.
///
/// Owner-only and scope-bound exactly as [`revoke_read_grant`] is. The tag MUST
/// be committed with [`Permission::Write`] ([`RevokeError::NotWriteGranted`]).
pub fn revoke_write_grant(
    plan: &GrantCutPlan<'_>,
    revoked_tag: &[u8; 32],
    kind: WriteRevokeKind,
) -> Result<RevokedCommittedSet, RevokeError> {
    authorize_cut(plan)?;
    if committed_permission(plan, revoked_tag)? != Permission::Write {
        return Err(RevokeError::NotWriteGranted);
    }

    let set = match kind {
        WriteRevokeKind::Full => drop_tags(plan, &BTreeSet::from([*revoked_tag]))?,
        WriteRevokeKind::DowngradeToRead => {
            let mut commitment = plan.commitment.clone();
            let mut grant_ledger = plan.grant_ledger.to_vec();
            for entry in commitment
                .entries
                .iter_mut()
                .filter(|e| &e.tag == revoked_tag)
            {
                entry.permission = Permission::Read;
            }
            for entry in grant_ledger.iter_mut().filter(|e| &e.tag == revoked_tag) {
                entry.permission = Permission::Read;
            }
            // A downgrade keeps the recipient in the set, so nothing is revoked
            // for the re-key to skip.
            DroppedSet {
                commitment,
                grant_ledger,
                revoked_recipients: Vec::new(),
                unnamed_drops: 0,
            }
        }
    };
    resign(
        set,
        RotationPlanes {
            read: kind == WriteRevokeKind::Full,
            write: true,
        },
        plan.owner_signer,
    )
}

/// The write-scope cut a scope root owes before a write row stands on it: drive
/// its committed set unchanged through the write plane alone (ADR 0025 D6,
/// blueprint/engine.md "Grant creation" — "for write grants, the write-scope
/// cut").
///
/// A scope that is not a write scope yet sits at names the scope above
/// derives, so a seed sealed there would derive every name in that scope. The
/// wave moves the subtree onto names only the scope's own `writeScopeSeed`
/// derives, which lets the owner later cut a write grantee without re-keying
/// the scope above. A write mint seals its row before the wave; an upgrade or an
/// appended write row is committed only on the root the wave moved to.
///
/// Owner-only and scope-bound exactly as [`revoke_read_grant`] is: the set is
/// re-used as the owner signed it, so it is verified rather than re-signed.
pub fn cut_for_write_scope(plan: &GrantCutPlan<'_>) -> Result<RevokedCommittedSet, RevokeError> {
    authorize_cut(plan)?;
    enforce_committed_ledger(plan.commitment, plan.grant_ledger)
        .map_err(RevokeError::LedgerDiverges)?;
    Ok(RevokedCommittedSet {
        commitment: plan.commitment.clone(),
        commitment_sig: *plan.commitment_sig,
        grant_ledger: plan.grant_ledger.to_vec(),
        unnamed_drops: 0,
        revoked_recipients: Vec::new(),
        planes: RotationPlanes {
            read: false,
            write: true,
        },
    })
}

/// The rotation edge a committed-set cut is driven over: one arm per plane.
///
/// The pure driver ([`rotate_on_cut`]) owns which planes fire and in what order;
/// this seam owns assembling each plane's plan from the scope's resolved records
/// and running the primitive over the live plane — `OwnerCutNet` over the real
/// transport.
pub trait CutRotator {
    /// Publish `cut`'s committed set at `scope_root` without cutting either
    /// plane's keys — a re-seal at the scope's current seed and read epoch.
    ///
    /// The implementation MUST be idempotent: a root already carrying the cut
    /// set is left alone rather than republished.
    async fn publish_cut_set(
        &self,
        scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<(), CascadeError>;

    /// Run the fresh-seed read cascade at `scope_root` over `cut`
    /// ([`cascade_rotate_scope`](super::cascade::cascade_rotate_scope)).
    async fn rotate_read_plane(
        &self,
        scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<CascadeOutcome, CascadeError>;

    /// Run the write-plane name wave at `scope_root` over `cut`
    /// ([`rotate_scope_write`](super::rotate_write::rotate_scope_write)).
    async fn rotate_write_plane(
        &self,
        scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<WriteRotationOutcome, WriteRotateError>;
}

/// What [`rotate_on_cut`] rotated. Holding one is proof every plane the cut
/// demanded was cut — a partial rotation returns [`RotateOnCutError`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutRotationReport {
    /// The read-plane cascade outcome, present exactly when the cut demanded a
    /// read rotation.
    pub read: Option<CascadeOutcome>,
    /// The write-plane rotation outcome, present exactly when the cut demanded a
    /// write rotation. Its predecessor names are then **dead to survivors, not
    /// merely stale**: the cut party keeps the subtree signing keys derived under
    /// them, so anything published there now is a forgery the old-root tombstone
    /// only advises against, and write-grantee survivors stay exposed for the
    /// wave's duration (blueprint/engine.md "Residuals").
    pub write: Option<WriteRotationOutcome>,
}

/// A fail-closed plane-rotation failure. Named per plane so the caller knows
/// which half of a two-plane cut is outstanding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateOnCutError {
    /// The cut set did not reach the scope root, so the write wave has nothing
    /// to re-mint from. Nothing is cut on either plane.
    PublishCut(CascadeError),
    /// The read-plane cascade did not complete, so the cut is not yet a
    /// revocation: the revokee's blob may still be at its tag.
    Read(CascadeError),
    /// The write-plane wave did not complete. On a full revoke the read cut has
    /// already landed, but the revokee still authors at every current write name
    /// until this does.
    Write(WriteRotateError),
    /// A cut that drives the write plane alone carries recipients to withhold on
    /// the read plane. Only the read cascade records a withheld recipient in the
    /// durable revocation floor, so driving this would withhold a blob the
    /// engine then forgets it withheld. Nothing is cut on either plane.
    WriteOnlyCutWithdrawsRead,
}

impl core::fmt::Display for RotateOnCutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RotateOnCutError::PublishCut(e) => write!(f, "cut-set publish failed: {e}"),
            RotateOnCutError::Read(e) => write!(f, "read-plane cascade failed: {e}"),
            RotateOnCutError::Write(e) => write!(f, "write-plane wave failed: {e}"),
            RotateOnCutError::WriteOnlyCutWithdrawsRead => {
                f.write_str("a write-only cut cannot withhold a read grant")
            }
        }
    }
}

impl std::error::Error for RotateOnCutError {}

impl RotateOnCutError {
    /// Every cut-driver check this type owns — the surface
    /// `crates/engine/tests/kat_rotation.rs` pins (see the module header for the
    /// prefix rule). The three per-plane variants surface the plane's own
    /// verdict verbatim and so stay off this surface.
    pub const CHECKS: &'static [&'static str] = &["rot-cut-write-only-cut-withdraws-read"];

    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            RotateOnCutError::PublishCut(e) | RotateOnCutError::Read(e) => e.check(),
            RotateOnCutError::Write(e) => e.check(),
            RotateOnCutError::WriteOnlyCutWithdrawsRead => "rot-cut-write-only-cut-withdraws-read",
        }
    }

    /// The class label used in reject vectors. Exhaustive, so a new variant must
    /// state its class rather than inherit `"trust"`.
    pub fn class(&self) -> &'static str {
        match self {
            RotateOnCutError::PublishCut(e) | RotateOnCutError::Read(e) => e.class(),
            RotateOnCutError::Write(e) => e.class(),
            RotateOnCutError::WriteOnlyCutWithdrawsRead => "trust",
        }
    }

    /// Whether re-driving the cut could clear this failure — an availability
    /// stall — versus a trust violation no retry can fix.
    pub fn is_retryable(&self) -> bool {
        match self {
            RotateOnCutError::PublishCut(e) | RotateOnCutError::Read(e) => e.is_retryable(),
            RotateOnCutError::Write(e) => e.is_retryable(),
            // A malformed cut: re-driving the same one reaches it again.
            RotateOnCutError::WriteOnlyCutWithdrawsRead => false,
        }
    }
}

/// Drive `cut` through the planes it demands at `scope_root`, which MUST be the
/// scope root the cut was authorized against.
///
/// Read plane first: it publishes the cut set at the name survivors are still
/// reading, which is the definitive revocation signal, and it is the record the
/// write wave then re-mints its grant set from. The write wave moves the scope
/// off every name the cut party can still author at, so it goes last. The first
/// step that does not complete aborts the cut ([`RotateOnCutError`]).
///
/// A cut that rotates the **write plane alone** — a downgrade, and the
/// grant-time write-scope cut — has no read cascade to publish its set, and the
/// wave re-mints only from a root already carrying it
/// (`net/rotation.rs` `remint_grants`). Such a cut therefore publishes its own
/// set first, at the scope's unchanged read seed and epoch.
pub async fn rotate_on_cut<R: CutRotator>(
    rotator: &R,
    scope_root: NodeId,
    cut: &RevokedCommittedSet,
) -> Result<CutRotationReport, RotateOnCutError> {
    if cut.planes.write && !cut.planes.read {
        // Only the read cascade records a withheld recipient in the durable
        // revocation floor, so a write-only cut that withheld one would forget
        // it. Release-active, because the two cuts that reach here build an
        // empty list by construction and nothing else enforces that
        // (AGENTS.md rule 8).
        if !cut.revoked_recipients.is_empty() {
            return Err(RotateOnCutError::WriteOnlyCutWithdrawsRead);
        }
        rotator
            .publish_cut_set(scope_root, cut)
            .await
            .map_err(RotateOnCutError::PublishCut)?;
    }
    let read = if cut.planes.read {
        Some(
            rotator
                .rotate_read_plane(scope_root, cut)
                .await
                .map_err(RotateOnCutError::Read)?,
        )
    } else {
        None
    };
    let write = if cut.planes.write {
        Some(
            rotator
                .rotate_write_plane(scope_root, cut)
                .await
                .map_err(RotateOnCutError::Write)?,
        )
    } else {
        None
    };
    Ok(CutRotationReport { read, write })
}

#[cfg(test)]
mod tests;
