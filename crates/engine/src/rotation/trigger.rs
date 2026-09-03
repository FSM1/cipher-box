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

use std::collections::{BTreeMap, BTreeSet};

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
use crate::seams::UnixMillis;

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
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            RevokeError::UnauthorizedSigner => "unauthorized-signer",
            RevokeError::CommitmentScopeMismatch => "commitment-scope-mismatch",
            RevokeError::NotGranted => "not-granted",
            RevokeError::NotWriteGranted => "not-write-granted",
            RevokeError::WriteGranted => "write-granted",
            RevokeError::LedgerDiverges(v) => v.check(),
            RevokeError::CutEpochExhausted => "cut-epoch-exhausted",
            RevokeError::Sign(_) => "commitment-sign-failed",
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
    /// rotates. A claim on any still-live bearer write link in the scope restores
    /// that same tag to write (`grants::invite`'s upgrade branch), so the owner
    /// must revoke those links alongside the downgrade.
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

/// The write-scope cut a **write grant** owes: drive the scope's already-minted
/// committed set through the write plane alone (blueprint/engine.md "Grant
/// creation" — "for write grants, the write-scope cut").
///
/// No row is cut. The granted scope root is minted at a name the scope it is
/// leaving derives, so until the wave runs, the seed in the grantee's blob
/// derives nothing and the owner still holds every name. The wave is what moves
/// the subtree onto names the granted scope's own `writeScopeSeed` derives — the
/// property that lets the owner later cut this grantee without re-keying the
/// scope above.
///
/// Owner-only and scope-bound exactly as [`revoke_read_grant`] is: the set is
/// re-used as the owner signed it, so it is verified rather than re-signed. A
/// set committing no write row is refused on the same rule
/// [`revoke_write_grant`] follows: the wave would move every name in the scope
/// and hand nobody a seed they did not already hold.
pub fn cut_for_write_grant(plan: &GrantCutPlan<'_>) -> Result<RevokedCommittedSet, RevokeError> {
    authorize_cut(plan)?;
    if !plan
        .commitment
        .entries
        .iter()
        .any(|e| e.permission == Permission::Write)
    {
        return Err(RevokeError::NotWriteGranted);
    }
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

/// Prune every grant the owner's own record puts past its deadline at `now`,
/// from both the commitment and the ledger, and owner-re-sign.
///
/// `owner_deadlines` maps a blinded tag to the deadline **as the owner minted
/// it** (`RecordedInvite::expires_at`). The published `expiresAt` on a ledger row
/// is deliberately not consulted: a write-grantee authors the write body, so
/// trusting that copy would let one forge an early deadline on a peer's row and
/// have the owner revoke a grantee it never chose to, or strip its own and never
/// expire ([`GrantLedgerEntry::expires_at`] — "not a capability boundary").
///
/// `Ok(None)` when nothing has expired — the common case, and the reason this
/// trigger needs no scheduler: it costs an owner session one lookup per recorded
/// deadline on a read it was making anyway. `now` is the injected
/// [`Scheduler::now`](crate::seams::Scheduler::now) instant, never a clock this
/// layer reads, and a grant dies **at** its deadline, not a tick later
/// ([`entry_is_live`](crate::grants::ledger::entry_is_live)).
///
/// Owner-only by construction, exactly as [`revoke_read_grant`] is.
pub fn prune_expired_grants(
    plan: &GrantCutPlan<'_>,
    owner_deadlines: &BTreeMap<[u8; 32], UnixMillis>,
    now: UnixMillis,
) -> Result<Option<RevokedCommittedSet>, RevokeError> {
    authorize_cut(plan)?;

    let mut expired: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut pruned_write_link = false;
    for entry in &plan.commitment.entries {
        match owner_deadlines.get(&entry.tag) {
            Some(deadline) if now.0 >= deadline.0 => {
                expired.insert(entry.tag);
                pruned_write_link |= entry.permission == Permission::Write;
            }
            _ => {}
        }
    }
    if expired.is_empty() {
        return Ok(None);
    }

    resign(
        drop_tags(plan, &expired)?,
        RotationPlanes {
            read: true,
            write: pruned_write_link,
        },
        plan.owner_signer,
    )
    .map(Some)
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
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            RotateOnCutError::PublishCut(e) | RotateOnCutError::Read(e) => e.check(),
            RotateOnCutError::Write(e) => e.check(),
            RotateOnCutError::WriteOnlyCutWithdrawsRead => "write-only-cut-withdraws-read",
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
mod tests {
    use core::cell::RefCell;

    use super::super::rotate_write::derive_write_name;
    use super::*;
    use crate::seams::Scheduler;
    use crate::testkit::block_on;
    use crate::testkit::fakes::VirtualScheduler;
    use cipherbox_core::seal::{PreservedFields, sign_recipient_binding, verify_grant_set};
    use cipherbox_core::suite::ecdsa::EcdsaSignature;

    use crate::grants::ledger::{mint_grant_row, recipient_blinded_tag};
    use cipherbox_core::suite::x25519::X25519Secret;

    /// Records the roots it was asked to cut, failing the ones named in
    /// `refuse` — the driver's only view of the rotation edge.
    struct FakeRotator {
        seen: RefCell<Vec<NodeId>>,
        refuse: Vec<NodeId>,
    }

    impl FakeRotator {
        fn refusing(refuse: &[NodeId]) -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                refuse: refuse.to_vec(),
            }
        }
    }

    impl ScopeExitRotator for FakeRotator {
        async fn rotate_on_scope_exit(
            &self,
            scope_root: NodeId,
        ) -> Result<RotationOutcome, RotateError> {
            self.seen.borrow_mut().push(scope_root);
            if self.refuse.contains(&scope_root) {
                return Err(RotateError::Publish(
                    super::super::rotate::RotationPublishError::NotPublished,
                ));
            }
            Ok(RotationOutcome {
                new_read_epoch: 2,
                epoch_floor: 2,
            })
        }
    }

    fn node(b: u8) -> NodeId {
        NodeId([b; 16])
    }

    #[test]
    fn each_queued_root_is_cut_once_in_order() {
        let rotator = FakeRotator::refusing(&[]);
        let roots = [node(1), node(2)];
        let report = block_on(consume_scope_exit_triggers(&rotator, &roots));

        assert_eq!(*rotator.seen.borrow(), roots);
        assert_eq!(
            report.rotated.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
            roots
        );
        assert!(report.is_complete());
    }

    #[test]
    fn a_failed_rotation_surfaces_and_the_rest_still_cut() {
        // A swallowed failure is a revokee left holding a live seed, and a
        // short-circuit would strand every later root behind it.
        let rotator = FakeRotator::refusing(&[node(2)]);
        let report = block_on(consume_scope_exit_triggers(
            &rotator,
            &[node(1), node(2), node(3)],
        ));

        assert_eq!(*rotator.seen.borrow(), [node(1), node(2), node(3)]);
        assert_eq!(
            report.rotated.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
            [node(1), node(3)]
        );
        assert_eq!(
            report.failed.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
            [node(2)]
        );
        assert!(
            !report.is_complete(),
            "an unsettled trigger keeps the pass incomplete"
        );
    }

    const DEADLINE: UnixMillis = UnixMillis(1_000);
    const NO_SIG: [u8; ECDSA_SIG_LEN] = [0u8; ECDSA_SIG_LEN];

    /// The three recipients the fixture commits, by their X25519 scalar seed.
    /// The scope pointer read key every fixture masks its recipients under.
    const PRK: [u8; SECRET_LEN] = [0x66; SECRET_LEN];
    const READ_RECIPIENT: u8 = 0x11;
    const LINK_RECIPIENT: u8 = 0x12;
    const WRITE_RECIPIENT: u8 = 0x13;

    fn owner_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x5b; 32])
    }

    fn recipient_enc(seed: u8) -> X25519Secret {
        X25519Secret::from_scalar([seed; 32])
    }

    fn scope_name() -> IpnsName {
        derive_write_name(&[0x5a; 32], &[0x01; 16])
    }

    /// The tag the owner commits `seed`'s recipient under at [`scope_name`].
    fn tag_of(seed: u8) -> [u8; 32] {
        recipient_blinded_tag(
            &owner_enc(),
            &recipient_enc(seed).public(),
            scope_name().as_str().as_bytes(),
        )
        .expect("a contributory recipient key")
    }

    fn read_tag() -> [u8; 32] {
        tag_of(READ_RECIPIENT)
    }

    fn link_tag() -> [u8; 32] {
        tag_of(LINK_RECIPIENT)
    }

    fn write_tag() -> [u8; 32] {
        tag_of(WRITE_RECIPIENT)
    }

    /// Three grants the owner committed at one scope root: a plain read grant, a
    /// read link the owner minted with a deadline, and a write grant.
    struct Fixture {
        owner: EcdsaSigner,
        name: IpnsName,
        commitment: GrantSetCommitment,
        commitment_sig: [u8; ECDSA_SIG_LEN],
        ledger: Vec<GrantLedgerEntry>,
    }

    impl Fixture {
        fn new() -> Self {
            let owner = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
            let name = scope_name();
            let mint = |seed: u8, identity: [u8; 33], permission| {
                mint_grant_row(
                    &owner,
                    &owner_enc(),
                    &PRK,
                    identity,
                    &recipient_enc(seed).public(),
                    &[0x01; 16],
                    name.as_str().as_bytes(),
                    permission,
                )
                .expect("a contributory recipient key")
            };
            let rows = [
                mint(READ_RECIPIENT, [0x02; 33], Permission::Read),
                mint(LINK_RECIPIENT, [0x04; 33], Permission::Read),
                mint(WRITE_RECIPIENT, [0x03; 33], Permission::Write),
            ];
            let commitment = GrantSetCommitment {
                ipns_name: name.as_str().as_bytes().to_vec(),
                owner_pseudonym_pk: [0x88; 32],
                cut_epoch: 0,
                entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
                unknown: PreservedFields::new(),
            };
            let commitment_sig = sign_grant_set(&owner, &commitment).unwrap().to_compact();
            let ledger = rows.into_iter().map(|r| r.ledger_entry).collect();
            Self {
                owner,
                name,
                commitment,
                commitment_sig,
                ledger,
            }
        }

        fn plan(&self) -> GrantCutPlan<'_> {
            GrantCutPlan {
                commitment: &self.commitment,
                commitment_sig: &self.commitment_sig,
                grant_ledger: &self.ledger,
                scope_root_name: &self.name,
                owner_signer: &self.owner,
                pointer_read_key: &PRK,
            }
        }

        /// The same plan bound to a different scope root.
        fn plan_at<'a>(&'a self, name: &'a IpnsName) -> GrantCutPlan<'a> {
            GrantCutPlan {
                scope_root_name: name,
                ..self.plan()
            }
        }

        /// The same plan presented by a party that is not the owner.
        fn plan_signed_by<'a>(&'a self, signer: &'a EcdsaSigner) -> GrantCutPlan<'a> {
            GrantCutPlan {
                owner_signer: signer,
                ..self.plan()
            }
        }

        fn verify(&self, cut: &RevokedCommittedSet) {
            let sig = EcdsaSignature::from_compact(&cut.commitment_sig).unwrap();
            verify_grant_set(&self.owner.verifying_key(), &cut.commitment, &sig)
                .expect("the owner's fresh signature covers the cut set");
        }
    }

    /// The owner's own record of what it minted with a deadline.
    fn owner_deadlines(rows: &[([u8; 32], UnixMillis)]) -> BTreeMap<[u8; 32], UnixMillis> {
        rows.iter().copied().collect()
    }

    fn stranger() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x44; 32]).unwrap()
    }

    #[test]
    fn revoke_removes_tag_from_both_and_resigns() {
        let fx = Fixture::new();
        let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("revoke");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == link_tag()));
        assert!(!cut.grant_ledger.iter().any(|e| e.tag == link_tag()));
        assert_eq!(cut.commitment.entries.len(), 2);
        assert_eq!(cut.grant_ledger.len(), 2);
        fx.verify(&cut);
    }

    #[test]
    fn a_cut_names_the_recipient_it_removed_and_no_survivor() {
        // The cascade carries this down every descendant, where a blinded tag
        // cannot reach: a tag is per-scope, a recipient key is vault-wide.
        let fx = Fixture::new();
        let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("revoke");
        assert_eq!(
            cut.revoked_recipients,
            vec![recipient_enc(LINK_RECIPIENT).public().to_bytes()]
        );

        let downgraded =
            revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
                .expect("downgrade");
        assert!(
            downgraded.revoked_recipients.is_empty(),
            "a downgrade keeps the recipient committed, so nothing is revoked"
        );
    }

    /// Relabel the link grant's ledger row. `attest` picks whether the writer
    /// leaves the owner's stale signature in place or the owner is tricked into
    /// re-signing the row as presented — the strongest form of the attack.
    fn relabel_link_row(fx: &mut Fixture, enc_pk: [u8; 32], attest: bool) {
        let owner = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
        let name = fx.name.as_str().as_bytes().to_vec();
        for row in &mut fx.ledger {
            if row.tag == link_tag() {
                row.recipient_enc_pk = enc_pk;
                if attest {
                    row.owner_sig = sign_recipient_binding(&owner, &name, row)
                        .expect("the owner signs the row as presented")
                        .to_compact();
                }
            }
        }
    }

    /// Relabel the link grant's committed recipient key and owner-re-sign the
    /// set, so the cut reads the new key from the owner's own attestation.
    fn relabel_link_entry(fx: &mut Fixture, enc_pk: [u8; 32]) {
        for entry in &mut fx.commitment.entries {
            if entry.tag == link_tag() {
                entry.set_recipient_enc_pk(&PRK, enc_pk);
            }
        }
        fx.commitment_sig = sign_grant_set(&fx.owner, &fx.commitment)
            .expect("the owner signs the set as presented")
            .to_compact();
    }

    #[test]
    fn a_cut_names_the_committed_recipient_though_its_row_was_relabelled() {
        // Any committed writer authors a ledger row. The cut names its revokees
        // from the owner-signed commitment, so relabelling a row neither lets its
        // author escape the cascade nor points the cascade at a bystander whose
        // grants would then be stripped vault-wide.
        let bystander = recipient_enc(0x99).public().to_bytes();
        for attest in [false, true] {
            let mut fx = Fixture::new();
            relabel_link_row(&mut fx, bystander, attest);

            let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("revoke");
            assert_eq!(
                cut.revoked_recipients,
                vec![recipient_enc(LINK_RECIPIENT).public().to_bytes()],
                "the commitment names the revokee, whatever the row was relabelled to"
            );
            assert!(
                !cut.commitment.entries.iter().any(|e| e.tag == link_tag()),
                "the tag still leaves the owner-signed set"
            );
        }
    }

    /// A cofactor twin and a non-canonical spelling both blind to the honest
    /// key's tag, so nothing but core's adoption gate separates them from it.
    /// The cut still lands and names nobody for that entry: no blob was ever
    /// sealed to a key core will not adopt, and a refusal would leave the cut
    /// that removes the bad entry the one operation the scope cannot run.
    #[test]
    fn a_cut_names_nobody_off_a_committed_key_core_will_not_adopt() {
        let honest = recipient_enc(LINK_RECIPIENT).public();
        let mut high_bit = honest.to_bytes();
        high_bit[31] |= 0x80;

        for enc_pk in cipherbox_core::suite::x25519::cofactor_twins(&honest)
            .into_iter()
            .chain([high_bit])
        {
            let mut fx = Fixture::new();
            relabel_link_entry(&mut fx, enc_pk);

            let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("the cut still lands");
            assert!(cut.revoked_recipients.is_empty());
            assert_eq!(
                cut.unnamed_drops, 1,
                "the caller must see the harvest was incomplete"
            );
            assert!(cut.commitment.entries.iter().all(|e| e.tag != link_tag()));
        }
    }

    /// A committed write grantee authors its own ledger row, so it can strip the
    /// `ownerSig` off it before the owner reads the record for the cut. The
    /// commitment entry it cannot touch, and that alone names the recipient.
    #[test]
    fn a_cut_names_the_committed_recipient_with_no_owner_signature_on_the_row() {
        let mut fx = Fixture::new();
        for row in &mut fx.ledger {
            if row.tag == write_tag() {
                row.owner_sig = NO_SIG;
            }
        }
        let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full)
            .expect("full write revoke");
        assert_eq!(
            cut.revoked_recipients,
            vec![recipient_enc(WRITE_RECIPIENT).public().to_bytes()],
            "the commitment names the recipient the stripped signature no longer does"
        );
    }

    #[test]
    fn revoke_preserves_survivors_and_owner_fields() {
        let fx = Fixture::new();
        let cut = revoke_read_grant(&fx.plan(), &read_tag()).expect("revoke");
        assert!(cut.commitment.entries.iter().any(|e| e.tag == link_tag()));
        assert!(cut.commitment.entries.iter().any(|e| e.tag == write_tag()));
        assert_eq!(cut.commitment.ipns_name, fx.commitment.ipns_name);
        assert_eq!(
            cut.commitment.owner_pseudonym_pk,
            fx.commitment.owner_pseudonym_pk
        );
    }

    /// Every cut that re-signs steps the counter, and the one that re-uses the
    /// set the owner already signed does not. A step the write-grant cut made
    /// would raise the floor over a set no cut removed anybody from.
    #[test]
    fn every_re_signed_cut_steps_the_cut_epoch_and_the_re_used_set_does_not() {
        let fx = Fixture::new();
        let before = fx.commitment.cut_epoch;

        for cut in [
            revoke_read_grant(&fx.plan(), &read_tag()).expect("read revoke"),
            revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full)
                .expect("write revoke"),
            revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
                .expect("downgrade"),
        ] {
            assert_eq!(cut.commitment.cut_epoch, before + 1);
            assert!(
                verify_grant_set(
                    &fx.owner.verifying_key(),
                    &cut.commitment,
                    &EcdsaSignature::from_compact(&cut.commitment_sig).expect("compact"),
                )
                .is_ok(),
                "and the stepped counter is inside what the owner signed"
            );
        }

        let reused = cut_for_write_grant(&fx.plan()).expect("write-grant cut");
        assert_eq!(reused.commitment.cut_epoch, before);
    }

    /// A wrapped counter would sit below the floor the previous cut installed,
    /// so every later replay of a pre-cut set would pass. Release-active, never
    /// a debug_assert.
    #[test]
    fn a_cut_at_the_counter_ceiling_fails_closed() {
        let mut fx = Fixture::new();
        fx.commitment.cut_epoch = u64::MAX;
        fx.commitment_sig = sign_grant_set(&fx.owner, &fx.commitment)
            .expect("signs")
            .to_compact();

        let err = revoke_read_grant(&fx.plan(), &read_tag()).expect_err("the ceiling");
        assert_eq!(err.check(), "cut-epoch-exhausted");
    }

    #[test]
    fn revoke_unknown_tag_fails_closed() {
        let fx = Fixture::new();
        let err = revoke_read_grant(&fx.plan(), &[0xff; 32]).expect_err("not granted");
        assert_eq!(err.check(), "not-granted");
    }

    /// A read revoke that drops a write grantee reads as complete — tag gone,
    /// commitment re-signed — while the holder still authors at every current
    /// write name. Only `revoke_write_grant` finishes that cut.
    #[test]
    fn read_revoking_a_write_grantee_fails_closed() {
        let fx = Fixture::new();
        let err = revoke_read_grant(&fx.plan(), &write_tag()).expect_err("write granted");
        assert_eq!(err.check(), "write-granted");
    }

    #[test]
    fn revoke_wrong_signer_fails_closed() {
        // A signer that did not sign the current commitment is rejected before the
        // cut — the encode-side mirror of the gate's owner-identity verify.
        let fx = Fixture::new();
        let stranger = stranger();
        let err = revoke_read_grant(&fx.plan_signed_by(&stranger), &link_tag())
            .expect_err("unauthorized signer");
        assert_eq!(err.check(), "unauthorized-signer");
    }

    #[test]
    fn revoke_tampered_commitment_preimage_fails_closed() {
        // A real owner signer presents a signature it genuinely produced, but over
        // a *different* commitment than the one being cut. verify_grant_set binds
        // the signature to THIS commitment's preimage, so the mismatch is rejected
        // as UnauthorizedSigner — a mutated commitment cannot ride a valid
        // signature over a sibling commitment. Complements the key-identity case
        // (`revoke_wrong_signer_fails_closed`) and the core-layer tamper KAT.
        let fx = Fixture::new();
        let mut tampered = fx.commitment.clone();
        tampered.owner_pseudonym_pk = [0x99; 32];
        let tampered_sig = sign_grant_set(&fx.owner, &tampered).unwrap().to_compact();
        assert_ne!(tampered_sig, fx.commitment_sig);

        let plan = GrantCutPlan {
            commitment_sig: &tampered_sig,
            ..fx.plan()
        };
        let err = revoke_read_grant(&plan, &link_tag()).expect_err("tampered commitment preimage");
        assert_eq!(err.check(), "unauthorized-signer");
    }

    /// The owner gate alone would let one owner-signed commitment be cut against
    /// any scope, so every cut carries the same scope binding `rotate_scope_write`
    /// enforces (`WriteRotateError::CommitmentScopeMismatch`).
    #[test]
    fn a_cut_against_another_scope_fails_closed() {
        let fx = Fixture::new();
        let other = derive_write_name(&[0x5a; 32], &[0x02; 16]);
        assert_ne!(other.as_str(), fx.name.as_str());
        let plan = fx.plan_at(&other);

        for err in [
            revoke_read_grant(&plan, &link_tag()).expect_err("read revoke"),
            revoke_write_grant(&plan, &write_tag(), WriteRevokeKind::Full)
                .expect_err("write revoke"),
            prune_expired_grants(&plan, &owner_deadlines(&[(link_tag(), DEADLINE)]), DEADLINE)
                .expect_err("expiry prune"),
        ] {
            assert_eq!(err.check(), "commitment-scope-mismatch");
        }
    }

    /// A write-grantee authors the ledger, so it can present one that no longer
    /// matches the owner's committed set. Signing a cut over it would mint a set
    /// the resolver hard-rejects.
    #[test]
    fn a_cut_over_a_diverging_ledger_is_refused_release_active() {
        let fx = Fixture::new();
        let mut injected = fx.ledger.clone();
        injected.push(GrantLedgerEntry::new(
            [0x09; 33],
            [0x1f; 32],
            Permission::Write,
            [0x77; 32], // never committed by the owner
            NO_SIG,
        ));
        let plan = GrantCutPlan {
            grant_ledger: &injected,
            ..fx.plan()
        };
        let err = revoke_read_grant(&plan, &link_tag()).expect_err("diverging ledger");
        assert_eq!(err.check(), "ledger-diverges-from-commitment");
    }

    #[test]
    fn a_full_write_revoke_removes_the_writer_and_rotates_both_planes() {
        let fx = Fixture::new();
        let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full)
            .expect("full write revoke");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == write_tag()));
        assert!(!cut.grant_ledger.iter().any(|e| e.tag == write_tag()));
        fx.verify(&cut);
        assert_eq!(
            cut.planes,
            RotationPlanes {
                read: true,
                write: true
            }
        );
    }

    #[test]
    fn a_downgrade_demotes_the_writer_and_rotates_the_write_plane_only() {
        let fx = Fixture::new();
        let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
            .expect("downgrade");

        // The downgraded recipient keeps a live grant at the same tag — the read
        // plane is untouched, so its blob is still there to find.
        let entry = cut
            .commitment
            .entries
            .iter()
            .find(|e| e.tag == write_tag())
            .expect("the downgraded grant is still committed");
        assert_eq!(entry.permission, Permission::Read);
        let committed = fx
            .commitment
            .entries
            .iter()
            .find(|e| e.tag == write_tag())
            .expect("the write grant the fixture committed");
        assert_eq!(
            entry.pseudonym_pk, committed.pseudonym_pk,
            "the pseudonym authorizes structure signing and is the owner's to keep"
        );
        let row = cut
            .grant_ledger
            .iter()
            .find(|e| e.tag == write_tag())
            .expect("the downgraded ledger row survives");
        assert_eq!(row.permission, Permission::Read);
        assert_eq!(cut.commitment.entries.len(), fx.commitment.entries.len());
        fx.verify(&cut);

        assert_eq!(
            cut.planes,
            RotationPlanes {
                read: false,
                write: true
            }
        );
    }

    #[test]
    fn a_write_revoke_of_a_read_grant_fails_closed() {
        // Rotating the write plane for a read-only tag would move every name in
        // the scope without cutting anything.
        let fx = Fixture::new();
        for (tag, check) in [
            (read_tag(), "not-write-granted"),
            ([0xff; 32], "not-granted"),
        ] {
            let err = revoke_write_grant(&fx.plan(), &tag, WriteRevokeKind::Full)
                .expect_err("no write grant");
            assert_eq!(err.check(), check);
        }
    }

    #[test]
    fn nothing_expired_yields_no_cut_and_no_rotation() {
        let fx = Fixture::new();
        let clock = VirtualScheduler::starting_at(UnixMillis(DEADLINE.0 - 1));
        assert!(
            prune_expired_grants(
                &fx.plan(),
                &owner_deadlines(&[(link_tag(), DEADLINE)]),
                clock.now()
            )
            .expect("owner prune")
            .is_none(),
            "an unexpired grant gives the owner session nothing to act on"
        );
    }

    #[test]
    fn a_link_expires_at_its_deadline_instant_not_a_tick_later() {
        let fx = Fixture::new();
        let deadlines = owner_deadlines(&[(link_tag(), DEADLINE)]);
        let clock = VirtualScheduler::starting_at(UnixMillis(DEADLINE.0 - 1));
        assert!(
            prune_expired_grants(&fx.plan(), &deadlines, clock.now())
                .expect("owner prune")
                .is_none()
        );

        clock.advance(core::time::Duration::from_millis(1));
        let cut = prune_expired_grants(&fx.plan(), &deadlines, clock.now())
            .expect("owner prune")
            .expect("the deadline instant expires the link");
        assert!(!cut.commitment.entries.iter().any(|e| e.tag == link_tag()));
    }

    #[test]
    fn an_expired_read_link_is_pruned_from_both_and_rotates_the_read_plane_only() {
        let fx = Fixture::new();
        let cut = prune_expired_grants(
            &fx.plan(),
            &owner_deadlines(&[(link_tag(), DEADLINE)]),
            DEADLINE,
        )
        .expect("owner prune")
        .expect("the read link expired");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == link_tag()));
        assert!(!cut.grant_ledger.iter().any(|e| e.tag == link_tag()));
        assert!(cut.commitment.entries.iter().any(|e| e.tag == read_tag()));
        fx.verify(&cut);

        assert_eq!(
            cut.planes,
            RotationPlanes {
                read: true,
                write: false
            }
        );
    }

    #[test]
    fn an_expired_write_link_additionally_rotates_the_write_plane() {
        // Pruning the committed entry does not expire a write link: its holder
        // keeps the subtree signing keys until the names move.
        let fx = Fixture::new();
        let cut = prune_expired_grants(
            &fx.plan(),
            &owner_deadlines(&[(link_tag(), DEADLINE), (write_tag(), DEADLINE)]),
            DEADLINE,
        )
        .expect("owner prune")
        .expect("both links expired");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == write_tag()));
        assert_eq!(
            cut.planes,
            RotationPlanes {
                read: true,
                write: true
            }
        );
    }

    /// The permission a prune acts on comes from the owner-signed commitment,
    /// never the write-grantee-authored ledger row — otherwise a writer demotes
    /// its own row to `read`, the write plane never rotates, and it keeps the
    /// subtree signing keys the expiry was supposed to end.
    #[test]
    fn a_ledger_row_demoted_by_its_writer_still_rotates_the_write_plane() {
        let fx = Fixture::new();
        let mut forged = fx.ledger.clone();
        forged[2].permission = Permission::Read;
        let plan = GrantCutPlan {
            grant_ledger: &forged,
            ..fx.plan()
        };

        let cut = prune_expired_grants(
            &plan,
            &owner_deadlines(&[(write_tag(), DEADLINE)]),
            DEADLINE,
        )
        .expect("owner prune")
        .expect("the write link expired");
        assert!(
            cut.planes.write,
            "the plane set is read off the owner-signed commitment"
        );
    }

    /// A write-grantee authors `expiresAt`, so a prune driven off the published
    /// row would let one forge an early deadline on a peer and have the owner
    /// revoke a grantee it never chose to.
    #[test]
    fn a_deadline_forged_in_the_ledger_prunes_nothing() {
        let fx = Fixture::new();
        let mut forged = fx.ledger.clone();
        forged[0].expires_at = core::num::NonZeroU64::new(1);
        let plan = GrantCutPlan {
            grant_ledger: &forged,
            ..fx.plan()
        };

        assert!(
            prune_expired_grants(&plan, &owner_deadlines(&[]), UnixMillis(u64::MAX))
                .expect("owner prune")
                .is_none(),
            "only the owner's own record can expire a grant"
        );
    }

    #[test]
    fn a_non_owner_session_cuts_nothing_on_a_discovered_expiry() {
        // A grantee can neither extend nor shrink the committed set, so its
        // observation of the same expired grant changes nothing.
        let fx = Fixture::new();
        let grantee = stranger();
        let err = prune_expired_grants(
            &fx.plan_signed_by(&grantee),
            &owner_deadlines(&[(link_tag(), DEADLINE)]),
            DEADLINE,
        )
        .expect_err("a grantee cannot prune");
        assert_eq!(err.check(), "unauthorized-signer");
    }

    /// Records which arms fired, in call order, failing the ones named. Each
    /// arm also records the permission the cut carries at [`write_tag()`], so a
    /// test can prove the write wave ran over the demoted set rather than the
    /// set the cut replaced.
    struct FakeCutRotator {
        seen: RefCell<Vec<&'static str>>,
        committed_at_write_tag: RefCell<Vec<(&'static str, Permission)>>,
        refuse_read: bool,
        refuse_write: bool,
        refuse_publish: bool,
    }

    impl FakeCutRotator {
        fn new() -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                committed_at_write_tag: RefCell::new(Vec::new()),
                refuse_read: false,
                refuse_write: false,
                refuse_publish: false,
            }
        }

        fn record(&self, arm: &'static str, cut: &RevokedCommittedSet) {
            self.seen.borrow_mut().push(arm);
            if let Some(entry) = cut.commitment.entries.iter().find(|e| e.tag == write_tag()) {
                self.committed_at_write_tag
                    .borrow_mut()
                    .push((arm, entry.permission));
            }
        }
    }

    impl CutRotator for FakeCutRotator {
        async fn publish_cut_set(
            &self,
            scope_root: NodeId,
            cut: &RevokedCommittedSet,
        ) -> Result<(), CascadeError> {
            self.record("publish-cut", cut);
            if self.refuse_publish {
                return Err(CascadeError::Resolve {
                    scope_id: scope_root.0,
                    reason: super::super::eager_set::ResolveFailure::Unavailable,
                });
            }
            Ok(())
        }

        async fn rotate_read_plane(
            &self,
            scope_root: NodeId,
            cut: &RevokedCommittedSet,
        ) -> Result<CascadeOutcome, CascadeError> {
            self.record("read", cut);
            if self.refuse_read {
                return Err(CascadeError::Resolve {
                    scope_id: scope_root.0,
                    reason: super::super::eager_set::ResolveFailure::Unavailable,
                });
            }
            Ok(CascadeOutcome {
                rekeyed: vec![super::super::cascade::RekeyedScope {
                    scope_id: scope_root.0,
                    new_read_epoch: 2,
                    epoch_floor: 2,
                }],
            })
        }

        async fn rotate_write_plane(
            &self,
            _scope_root: NodeId,
            cut: &RevokedCommittedSet,
        ) -> Result<WriteRotationOutcome, WriteRotateError> {
            self.record("write", cut);
            if self.refuse_write {
                return Err(WriteRotateError::EpochExhausted);
            }
            Ok(WriteRotationOutcome {
                new_write_epoch: 2,
                new_root_name: derive_write_name(&[0x77; 32], &[0x01; 16]),
                interior_node_count: 0,
            })
        }
    }

    fn full_write_revoke() -> RevokedCommittedSet {
        let fx = Fixture::new();
        revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full).expect("cut")
    }

    #[test]
    fn a_full_write_revoke_drives_the_read_plane_before_the_write_plane() {
        let rotator = FakeCutRotator::new();
        let report =
            block_on(rotate_on_cut(&rotator, node(1), &full_write_revoke())).expect("both planes");

        assert_eq!(
            *rotator.seen.borrow(),
            ["read", "write"],
            "the read cut lands at the name survivors still read, then the names move"
        );
        assert!(report.read.is_some());
        assert!(report.write.is_some());
    }

    #[test]
    fn a_write_only_cut_that_withholds_a_read_grant_is_refused_before_anything_publishes() {
        // Only the read cascade records a withheld recipient in the durable
        // revocation floor. A write-only cut carrying one would withhold a blob
        // the engine forgets it withheld, and the next re-key would hand it
        // back. Both cuts that reach here build an empty list, so this pins the
        // property rather than a coincidence.
        let fx = Fixture::new();
        let mut cut =
            revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
                .expect("downgrade");
        cut.revoked_recipients.push([0x5e; SECRET_LEN]);
        let rotator = FakeCutRotator::new();

        let err = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect_err("refused");
        assert_eq!(err.check(), "write-only-cut-withdraws-read");
        assert!(!err.is_retryable());
        assert!(
            rotator.seen.borrow().is_empty(),
            "nothing is cut on either plane"
        );
    }

    #[test]
    fn a_downgrade_leaves_the_read_plane_alone() {
        let fx = Fixture::new();
        let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
            .expect("downgrade");
        let rotator = FakeCutRotator::new();
        let report = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("write plane");

        assert_eq!(*rotator.seen.borrow(), ["publish-cut", "write"]);
        assert!(report.read.is_none());
        assert!(report.write.is_some());
    }

    /// The write wave re-mints only from a root already carrying the authorized
    /// set, so a write-only cut owes the publish before the wave — otherwise the
    /// wave reads the pre-cut record and refuses permanently.
    #[test]
    fn a_downgrade_publishes_the_demoted_set_before_the_wave_runs() {
        let fx = Fixture::new();
        let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
            .expect("downgrade");
        let rotator = FakeCutRotator::new();
        block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("write plane");

        assert_eq!(
            *rotator.committed_at_write_tag.borrow(),
            [
                ("publish-cut", Permission::Read),
                ("write", Permission::Read)
            ],
            "the demoted row reaches the record before the wave re-mints from it"
        );
    }

    #[test]
    fn a_refused_cut_set_publish_never_reaches_the_write_plane() {
        let fx = Fixture::new();
        let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
            .expect("downgrade");
        let mut rotator = FakeCutRotator::new();
        rotator.refuse_publish = true;
        let err = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect_err("publish refused");

        assert!(matches!(err, RotateOnCutError::PublishCut(_)));
        assert_eq!(*rotator.seen.borrow(), ["publish-cut"]);
        assert!(err.is_retryable());
    }

    /// A cut that rotates both planes has its set published by the read cascade,
    /// so the pre-wave publish is not owed and never runs.
    #[test]
    fn a_two_plane_cut_owes_no_pre_wave_publish() {
        let rotator = FakeCutRotator::new();
        block_on(rotate_on_cut(&rotator, node(1), &full_write_revoke())).expect("both planes");

        assert_eq!(*rotator.seen.borrow(), ["read", "write"]);
    }

    /// The grant-time write-scope cut drives the same write-only arm: the mint
    /// published the set, so the publish arm still runs and finds it in place.
    #[test]
    fn a_write_grant_cut_carries_the_minted_set_through_the_write_plane() {
        let fx = Fixture::new();
        let cut = cut_for_write_grant(&fx.plan()).expect("the owner's own minted set");

        assert!(!cut.planes().read(), "a grant re-keys no read plane");
        assert!(cut.planes().write());
        assert!(
            cut.revoked_recipients.is_empty(),
            "a grant cuts no recipient"
        );
        assert_eq!(cut.commitment, *fx.plan().commitment);

        let rotator = FakeCutRotator::new();
        block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("the write plane");
        assert_eq!(*rotator.seen.borrow(), ["publish-cut", "write"]);
    }

    #[test]
    fn a_write_grant_cut_refuses_a_set_the_owner_did_not_sign() {
        let fx = Fixture::new();
        let err = cut_for_write_grant(&fx.plan_signed_by(&stranger()))
            .expect_err("a set this signer never authorized");
        assert_eq!(err.check(), "unauthorized-signer");
    }

    #[test]
    fn a_write_grant_cut_refuses_a_set_committing_no_write_row() {
        // Read-only: the wave would move every name and cut nothing.
        let fx = Fixture::new();
        let read_only = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full)
            .expect("the write row leaves the set");
        let sig = read_only.commitment_sig;
        let err = cut_for_write_grant(&GrantCutPlan {
            commitment: &read_only.commitment,
            commitment_sig: &sig,
            grant_ledger: &read_only.grant_ledger,
            ..fx.plan()
        })
        .expect_err("no write row to cut a scope for");
        assert_eq!(err.check(), "not-write-granted");
    }

    #[test]
    fn a_read_revoke_leaves_the_write_plane_alone() {
        let fx = Fixture::new();
        let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("cut");
        let rotator = FakeCutRotator::new();
        let report = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("read plane");

        assert_eq!(*rotator.seen.borrow(), ["read"]);
        assert!(report.write.is_none());
    }

    #[test]
    fn a_refused_read_plane_never_reaches_the_write_plane() {
        // A partial report would be mistakable for a finished revoke.
        let mut rotator = FakeCutRotator::new();
        rotator.refuse_read = true;
        let err = block_on(rotate_on_cut(&rotator, node(1), &full_write_revoke()))
            .expect_err("read plane refused");

        assert!(matches!(err, RotateOnCutError::Read(_)));
        assert_eq!(*rotator.seen.borrow(), ["read"]);
        assert!(err.is_retryable());
    }

    #[test]
    fn a_refused_write_plane_fails_the_whole_revoke() {
        let mut rotator = FakeCutRotator::new();
        rotator.refuse_write = true;
        let err = block_on(rotate_on_cut(&rotator, node(1), &full_write_revoke()))
            .expect_err("write plane refused");

        assert_eq!(err.check(), "epoch-exhausted");
        assert!(!err.is_retryable());
    }

    #[test]
    fn trigger_names_are_stable() {
        assert_eq!(RotationTrigger::ScopeExit.name(), "scope-exit");
        assert_eq!(RotationTrigger::ReadRevoke.name(), "read-revoke");
        assert_eq!(RotationTrigger::WriteRevoke.name(), "write-revoke");
        assert_eq!(
            RotationTrigger::DiscoveredExpiry.name(),
            "discovered-expiry"
        );
        assert_eq!(RotationTrigger::Manual.name(), "manual");
    }
}
