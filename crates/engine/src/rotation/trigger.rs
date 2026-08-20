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
    ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, Permission, sign_grant_set,
    verify_grant_set,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, SIGNATURE_LEN as ECDSA_SIG_LEN};

use super::cascade::{CascadeError, CascadeOutcome};
use super::rotate::{RotateError, RotationOutcome};
use super::rotate_write::{WriteRotateError, WriteRotationOutcome};
use crate::facade::NodeId;
use crate::grants::ReceivedSharesList;
use crate::grants::ledger::{AuthorityViolation, enforce_committed_ledger};
use crate::net::GrantedScopeRoot;
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

/// The caller-held pairing of scope id to scope-root name that every grantee-arm
/// rotation resolves a trigger against.
///
/// A [`NodeId`] locates nothing on its own, and a grantee cannot derive a scope
/// root's name — that derivation runs off the write scope seed only the record
/// conveys — so the pairing has to be held rather than computed
/// ([`GrantedScopeRoot`]). It is seeded at cold start from the durable
/// received-shares bookmark ([`from_bookmarks`](Self::from_bookmarks)) and
/// extended by each accept ([`record`](Self::record)).
///
/// Keyed by scope id: two names for one scope id is a re-point, not two grants,
/// so the freshest name wins in place.
#[derive(Debug, Clone, Default)]
pub struct GrantedScopeRoots {
    by_scope: BTreeMap<[u8; 16], IpnsName>,
}

impl GrantedScopeRoots {
    /// An empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// The inventory the durable received-shares bookmark describes. A bookmark
    /// whose stored name is not a well-formed IPNS name is skipped: nothing can
    /// be resolved at it, and admitting it would hand a rotation an unusable
    /// destination.
    pub fn from_bookmarks(shares: &ReceivedSharesList) -> Self {
        let mut inventory = Self::new();
        for share in shares.iter() {
            let Ok(text) = core::str::from_utf8(&share.scope_root_name) else {
                continue;
            };
            if let Ok(name) = IpnsName::parse(text) {
                inventory.record(share.scope_id, name);
            }
        }
        inventory
    }

    /// Pair `scope_id` with `ipns_name`, replacing any name held for it — the
    /// scope id from an accept's
    /// [`AcceptOutcome`](crate::grants::AcceptOutcome), the name from the share
    /// pointer that accept verified.
    pub fn record(&mut self, scope_id: [u8; 16], ipns_name: IpnsName) {
        self.by_scope.insert(scope_id, ipns_name);
    }

    /// Drop `scope_id` — a share this device no longer holds a grant for.
    pub fn forget(&mut self, scope_id: &[u8; 16]) {
        self.by_scope.remove(scope_id);
    }

    /// The scope root `scope_id` names, as the sweep addresses it. `None` for a
    /// scope this device holds no grant for.
    pub fn scope_ref(&self, scope_id: &[u8; 16]) -> Option<ChildScopeRef> {
        self.by_scope
            .get(scope_id)
            .map(|name| ChildScopeRef::new(*scope_id, name.as_str().as_bytes().to_vec()))
    }

    /// Every scope root this device can rotate, as the grantee rotation arm
    /// borrows them
    /// ([`GranteeRotationNet::granted`](crate::net::GranteeRotationNet)).
    pub fn granted(&self) -> Vec<GrantedScopeRoot> {
        self.by_scope
            .iter()
            .map(|(scope_id, ipns_name)| GrantedScopeRoot {
                scope_id: *scope_id,
                ipns_name: ipns_name.clone(),
            })
            .collect()
    }

    /// The scopes the idle-cadence sweep job covers this round.
    pub fn scope_refs(&self) -> Vec<ChildScopeRef> {
        self.by_scope
            .keys()
            .filter_map(|scope_id| self.scope_ref(scope_id))
            .collect()
    }

    /// How many scope roots are paired.
    pub fn len(&self) -> usize {
        self.by_scope.len()
    }

    /// Whether the inventory holds no pairing.
    pub fn is_empty(&self) -> bool {
        self.by_scope.is_empty()
    }
}

/// The owner-authorized inputs every committed-set cut shares.
pub struct GrantCutPlan<'a> {
    /// The scope root's current owner-signed, epoch-free grant-set commitment —
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
    verify_grant_set(
        &plan.owner_signer.verifying_key(),
        plan.commitment,
        &current_sig,
    )
    .map_err(|_| RevokeError::UnauthorizedSigner)?;

    if plan.commitment.ipns_name != plan.scope_root_name.as_str().as_bytes() {
        return Err(RevokeError::CommitmentScopeMismatch);
    }
    Ok(())
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
) -> (GrantSetCommitment, Vec<GrantLedgerEntry>) {
    let mut commitment = plan.commitment.clone();
    commitment.entries.retain(|e| !tags.contains(&e.tag));
    let grant_ledger = plan
        .grant_ledger
        .iter()
        .filter(|e| !tags.contains(&e.tag))
        .cloned()
        .collect();
    (commitment, grant_ledger)
}

/// Owner-re-sign the cut set, refusing release-active to sign a commitment its
/// own ledger contradicts ([`RevokeError::LedgerDiverges`]).
fn resign(
    commitment: GrantSetCommitment,
    grant_ledger: Vec<GrantLedgerEntry>,
    planes: RotationPlanes,
    owner_signer: &EcdsaSigner,
) -> Result<RevokedCommittedSet, RevokeError> {
    enforce_committed_ledger(&commitment, &grant_ledger).map_err(RevokeError::LedgerDiverges)?;
    let commitment_sig = sign_grant_set(owner_signer, &commitment)
        .map_err(RevokeError::Sign)?
        .to_compact();
    Ok(RevokedCommittedSet {
        commitment,
        commitment_sig,
        grant_ledger,
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

    let (commitment, grant_ledger) = drop_tags(plan, &BTreeSet::from([*revoked_tag]));
    resign(
        commitment,
        grant_ledger,
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

    let (commitment, grant_ledger) = match kind {
        WriteRevokeKind::Full => drop_tags(plan, &BTreeSet::from([*revoked_tag])),
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
            (commitment, grant_ledger)
        }
    };
    resign(
        commitment,
        grant_ledger,
        RotationPlanes {
            read: kind == WriteRevokeKind::Full,
            write: true,
        },
        plan.owner_signer,
    )
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

    let (commitment, grant_ledger) = drop_tags(plan, &expired);
    resign(
        commitment,
        grant_ledger,
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
/// and running the primitive over the live plane. No production arm is landed;
/// tests fake it.
pub trait CutRotator {
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
    /// The read-plane cascade did not complete, so the cut is not yet a
    /// revocation: the revokee's blob may still be at its tag.
    Read(CascadeError),
    /// The write-plane wave did not complete. On a full revoke the read cut has
    /// already landed, but the revokee still authors at every current write name
    /// until this does.
    Write(WriteRotateError),
}

impl RotateOnCutError {
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            RotateOnCutError::Read(e) => e.check(),
            RotateOnCutError::Write(e) => e.check(),
        }
    }

    /// Whether re-driving the cut could clear this failure — an availability
    /// stall — versus a trust violation no retry can fix.
    pub fn is_retryable(&self) -> bool {
        match self {
            RotateOnCutError::Read(e) => e.is_retryable(),
            RotateOnCutError::Write(e) => e.is_retryable(),
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
/// plane that does not complete aborts the cut ([`RotateOnCutError`]).
pub async fn rotate_on_cut<R: CutRotator>(
    rotator: &R,
    scope_root: NodeId,
    cut: &RevokedCommittedSet,
) -> Result<CutRotationReport, RotateOnCutError> {
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
    use crate::seams::{FloorStore, Scheduler};
    use crate::testkit::block_on;
    use crate::testkit::fakes::VirtualScheduler;
    use cipherbox_core::seal::{
        GrantSetEntry, PreservedFields, encode_grant_set_commitment, verify_grant_set,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSignature;

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

    const READ_TAG: [u8; 32] = [0xa1; 32];
    const LINK_TAG: [u8; 32] = [0xb2; 32];
    const WRITE_TAG: [u8; 32] = [0xc3; 32];
    const DEADLINE: UnixMillis = UnixMillis(1_000);

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
            let name = derive_write_name(&[0x5a; 32], &[0x01; 16]);
            let commitment = GrantSetCommitment {
                ipns_name: name.as_str().as_bytes().to_vec(),
                owner_pseudonym_pk: [0x88; 32],
                entries: vec![
                    GrantSetEntry::new(READ_TAG, Permission::Read, [0x02; 32]),
                    GrantSetEntry::new(LINK_TAG, Permission::Read, [0x04; 32]),
                    GrantSetEntry::new(WRITE_TAG, Permission::Write, [0x03; 32]),
                ],
                unknown: PreservedFields::new(),
            };
            let commitment_sig = sign_grant_set(&owner, &commitment).unwrap().to_compact();
            let ledger = vec![
                GrantLedgerEntry::new([0x02; 33], [0x11; 32], Permission::Read, READ_TAG),
                GrantLedgerEntry::new([0x04; 33], [0x12; 32], Permission::Read, LINK_TAG),
                GrantLedgerEntry::new([0x03; 33], [0x13; 32], Permission::Write, WRITE_TAG),
            ];
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
        let cut = revoke_read_grant(&fx.plan(), &LINK_TAG).expect("revoke");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == LINK_TAG));
        assert!(!cut.grant_ledger.iter().any(|e| e.tag == LINK_TAG));
        assert_eq!(cut.commitment.entries.len(), 2);
        assert_eq!(cut.grant_ledger.len(), 2);
        fx.verify(&cut);
    }

    #[test]
    fn revoke_preserves_survivors_and_owner_fields() {
        let fx = Fixture::new();
        let cut = revoke_read_grant(&fx.plan(), &READ_TAG).expect("revoke");
        assert!(cut.commitment.entries.iter().any(|e| e.tag == LINK_TAG));
        assert!(cut.commitment.entries.iter().any(|e| e.tag == WRITE_TAG));
        assert_eq!(cut.commitment.ipns_name, fx.commitment.ipns_name);
        assert_eq!(
            cut.commitment.owner_pseudonym_pk,
            fx.commitment.owner_pseudonym_pk
        );
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
        let err = revoke_read_grant(&fx.plan(), &WRITE_TAG).expect_err("write granted");
        assert_eq!(err.check(), "write-granted");
    }

    #[test]
    fn revoke_wrong_signer_fails_closed() {
        // A signer that did not sign the current commitment is rejected before the
        // cut — the encode-side mirror of the gate's owner-identity verify.
        let fx = Fixture::new();
        let stranger = stranger();
        let err = revoke_read_grant(&fx.plan_signed_by(&stranger), &LINK_TAG)
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
        let err = revoke_read_grant(&plan, &LINK_TAG).expect_err("tampered commitment preimage");
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
            revoke_read_grant(&plan, &LINK_TAG).expect_err("read revoke"),
            revoke_write_grant(&plan, &WRITE_TAG, WriteRevokeKind::Full).expect_err("write revoke"),
            prune_expired_grants(&plan, &owner_deadlines(&[(LINK_TAG, DEADLINE)]), DEADLINE)
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
        ));
        let plan = GrantCutPlan {
            grant_ledger: &injected,
            ..fx.plan()
        };
        let err = revoke_read_grant(&plan, &LINK_TAG).expect_err("diverging ledger");
        assert_eq!(err.check(), "ledger-diverges-from-commitment");
    }

    #[test]
    fn a_full_write_revoke_removes_the_writer_and_rotates_both_planes() {
        let fx = Fixture::new();
        let cut = revoke_write_grant(&fx.plan(), &WRITE_TAG, WriteRevokeKind::Full)
            .expect("full write revoke");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == WRITE_TAG));
        assert!(!cut.grant_ledger.iter().any(|e| e.tag == WRITE_TAG));
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
        let cut = revoke_write_grant(&fx.plan(), &WRITE_TAG, WriteRevokeKind::DowngradeToRead)
            .expect("downgrade");

        // The downgraded recipient keeps a live grant at the same tag — the read
        // plane is untouched, so its blob is still there to find.
        let entry = cut
            .commitment
            .entries
            .iter()
            .find(|e| e.tag == WRITE_TAG)
            .expect("the downgraded grant is still committed");
        assert_eq!(entry.permission, Permission::Read);
        assert_eq!(
            entry.pseudonym_pk, [0x03; 32],
            "the pseudonym authorizes structure signing and is the owner's to keep"
        );
        let row = cut
            .grant_ledger
            .iter()
            .find(|e| e.tag == WRITE_TAG)
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
        for (tag, check) in [(READ_TAG, "not-write-granted"), ([0xff; 32], "not-granted")] {
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
                &owner_deadlines(&[(LINK_TAG, DEADLINE)]),
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
        let deadlines = owner_deadlines(&[(LINK_TAG, DEADLINE)]);
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
        assert!(!cut.commitment.entries.iter().any(|e| e.tag == LINK_TAG));
    }

    #[test]
    fn an_expired_read_link_is_pruned_from_both_and_rotates_the_read_plane_only() {
        let fx = Fixture::new();
        let cut = prune_expired_grants(
            &fx.plan(),
            &owner_deadlines(&[(LINK_TAG, DEADLINE)]),
            DEADLINE,
        )
        .expect("owner prune")
        .expect("the read link expired");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == LINK_TAG));
        assert!(!cut.grant_ledger.iter().any(|e| e.tag == LINK_TAG));
        assert!(cut.commitment.entries.iter().any(|e| e.tag == READ_TAG));
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
            &owner_deadlines(&[(LINK_TAG, DEADLINE), (WRITE_TAG, DEADLINE)]),
            DEADLINE,
        )
        .expect("owner prune")
        .expect("both links expired");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == WRITE_TAG));
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

        let cut = prune_expired_grants(&plan, &owner_deadlines(&[(WRITE_TAG, DEADLINE)]), DEADLINE)
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
            &owner_deadlines(&[(LINK_TAG, DEADLINE)]),
            DEADLINE,
        )
        .expect_err("a grantee cannot prune");
        assert_eq!(err.check(), "unauthorized-signer");
    }

    /// Records which plane arms fired, in call order, failing the ones named.
    struct FakeCutRotator {
        seen: RefCell<Vec<&'static str>>,
        refuse_read: bool,
        refuse_write: bool,
    }

    impl FakeCutRotator {
        fn new() -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                refuse_read: false,
                refuse_write: false,
            }
        }
    }

    impl CutRotator for FakeCutRotator {
        async fn rotate_read_plane(
            &self,
            scope_root: NodeId,
            _cut: &RevokedCommittedSet,
        ) -> Result<CascadeOutcome, CascadeError> {
            self.seen.borrow_mut().push("read");
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
            _cut: &RevokedCommittedSet,
        ) -> Result<WriteRotationOutcome, WriteRotateError> {
            self.seen.borrow_mut().push("write");
            if self.refuse_write {
                return Err(WriteRotateError::EpochExhausted);
            }
            Ok(WriteRotationOutcome {
                new_write_epoch: 2,
                new_root_name: derive_write_name(&[0x77; 32], &[0x01; 16]),
                repoint_accelerators: Vec::new(),
                interior_node_count: 0,
            })
        }
    }

    fn full_write_revoke() -> RevokedCommittedSet {
        let fx = Fixture::new();
        revoke_write_grant(&fx.plan(), &WRITE_TAG, WriteRevokeKind::Full).expect("cut")
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
    fn a_downgrade_leaves_the_read_plane_alone() {
        let fx = Fixture::new();
        let cut = revoke_write_grant(&fx.plan(), &WRITE_TAG, WriteRevokeKind::DowngradeToRead)
            .expect("downgrade");
        let rotator = FakeCutRotator::new();
        let report = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("write plane");

        assert_eq!(*rotator.seen.borrow(), ["write"]);
        assert!(report.read.is_none());
        assert!(report.write.is_some());
    }

    #[test]
    fn a_read_revoke_leaves_the_write_plane_alone() {
        let fx = Fixture::new();
        let cut = revoke_read_grant(&fx.plan(), &LINK_TAG).expect("cut");
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
    // --- The pairing every grantee-arm rotation resolves a trigger against ---

    fn bookmark(scope_id: [u8; 16], name: &IpnsName) -> crate::grants::ReceivedShare {
        crate::grants::ReceivedShare {
            scope_root_name: name.as_str().as_bytes().to_vec(),
            scope_id,
            sharer_identity_pk: [0x02; 33],
            display_name: "shared".into(),
            permission: Permission::Read,
            pointer_read_key: cipherbox_core::suite::secret::SecretBytes::new([0x8a; 32]),
        }
    }

    fn a_name(seed: u8) -> IpnsName {
        IpnsName::from_public_key(
            &cipherbox_core::suite::ed25519::Ed25519Signer::from_seed([seed; 32]).verifying_key(),
        )
    }

    #[test]
    fn the_inventory_pairs_a_scope_id_with_the_name_its_root_lives_at() {
        let name = a_name(0x31);
        let mut inventory = GrantedScopeRoots::new();
        inventory.record([0x5c; 16], name.clone());

        assert_eq!(
            inventory.scope_ref(&[0x5c; 16]),
            Some(ChildScopeRef::new(
                [0x5c; 16],
                name.as_str().as_bytes().to_vec()
            ))
        );
        assert_eq!(inventory.granted().len(), 1);
        assert!(
            inventory.scope_ref(&[0x77; 16]).is_none(),
            "a scope this device holds no grant for resolves to no name"
        );
    }

    /// A scope re-pointed to a fresh name is one grant, not two: the inventory
    /// heals in place, so a rotation is never aimed at a superseded name.
    #[test]
    fn re_recording_a_scope_replaces_its_name() {
        let mut inventory = GrantedScopeRoots::new();
        inventory.record([0x5c; 16], a_name(0x31));
        inventory.record([0x5c; 16], a_name(0x32));

        assert_eq!(inventory.len(), 1);
        assert_eq!(
            inventory.scope_ref(&[0x5c; 16]).unwrap().ipns_name,
            a_name(0x32).as_str().as_bytes()
        );
        inventory.forget(&[0x5c; 16]);
        assert!(inventory.is_empty());
    }

    #[test]
    fn the_inventory_rebuilds_from_the_durable_bookmarks() {
        let mut shares = ReceivedSharesList::new();
        shares.reconcile(bookmark([0x5c; 16], &a_name(0x31)));
        shares.reconcile(bookmark([0x77; 16], &a_name(0x32)));

        let inventory = GrantedScopeRoots::from_bookmarks(&shares);

        assert_eq!(inventory.len(), 2);
        assert_eq!(inventory.scope_refs().len(), 2);
    }

    /// Nothing resolves at a name that is not a well-formed IPNS name, so
    /// admitting one would hand a rotation an unusable destination.
    #[test]
    fn a_bookmark_whose_stored_name_is_unusable_joins_no_inventory() {
        let mut shares = ReceivedSharesList::new();
        let mut junk = bookmark([0x5c; 16], &a_name(0x31));
        junk.scope_root_name = b"not-an-ipns-name".to_vec();
        shares.reconcile(junk);

        assert!(GrantedScopeRoots::from_bookmarks(&shares).is_empty());
    }

    // --- The scope-exit cut is flat: one root, an untouched committed set ---

    const SOURCE: [u8; 16] = [0x5c; 16];
    const DESCENDANT: [u8; 16] = [0xdd; 16];

    /// A [`ScopeExitRotator`] over the **real** [`rotate_scope`], so what the
    /// driver produces is a published record rather than a recorded call.
    struct FlatRotator {
        entropy: RefCell<Option<crate::testkit::SeededEntropy>>,
        floors: crate::testkit::fakes::InMemoryFloorStore,
        scheduler: VirtualScheduler,
        publisher: RecordingPublisher,
        keys: FlatKeys,
        committed: (
            GrantSetCommitment,
            [u8; ECDSA_SIG_LEN],
            Vec<GrantLedgerEntry>,
        ),
        /// The one descendant scope root the source commits to.
        child_index: Vec<ChildScopeRef>,
        current_seed: [u8; 32],
        current_read_epoch: u64,
    }

    struct FlatKeys {
        owner_enc: cipherbox_core::suite::x25519::X25519Secret,
        pseudonym: cipherbox_core::suite::ed25519::Ed25519Signer,
        write_scope_seed: [u8; 32],
        pointer_read_key: [u8; 32],
    }

    #[derive(Default)]
    struct RecordingPublisher {
        published: RefCell<Vec<super::super::rotate::ResealedScopeRoot>>,
    }

    impl super::super::rotate::ScopeRootPublisher for RecordingPublisher {
        async fn publish_scope_root(
            &self,
            record: &super::super::rotate::ResealedScopeRoot,
        ) -> Result<(), super::super::rotate::RotationPublishError> {
            self.published.borrow_mut().push(record.clone());
            Ok(())
        }
    }

    impl ScopeExitRotator for FlatRotator {
        async fn rotate_on_scope_exit(
            &self,
            scope_root: NodeId,
        ) -> Result<RotationOutcome, RotateError> {
            if scope_root.0 != SOURCE {
                return Err(RotateError::Resolve(
                    super::super::eager_set::ResolveFailure::Rejected,
                ));
            }
            let (commitment, sig, ledger) = &self.committed;
            let owner_enc_pub = self.keys.owner_enc.public();
            let plan = super::super::rotate::RotateScopePlan {
                identity: super::super::reseal::ScopeRootIdentity {
                    v: 2,
                    scope_id: SOURCE,
                    ipns_name: b"source-root",
                    owner_enc_pub: &owner_enc_pub,
                    owner_enc_secret: None,
                    ascent: None,
                    owes_ascent_link: false,
                    pseudonym_signer: &self.keys.pseudonym,
                },
                committed: super::super::reseal::CommittedSet {
                    commitment,
                    commitment_sig: sig,
                    grant_ledger: ledger,
                    direct_child_scope_index: &self.child_index,
                },
                current_override_seed: &self.current_seed,
                current_read_epoch: self.current_read_epoch,
                write_scope_seed: &self.keys.write_scope_seed,
                write_epoch: 3,
                write_history_link: b"",
                pointer_read_key: &self.keys.pointer_read_key,
                carried_history_links: &[],
            };
            // Handed out and back rather than borrowed across the await: the
            // seam is `&self`, and a live `RefCell` borrow would outlive it.
            let mut entropy = self.entropy.borrow_mut().take().expect("entropy");
            let outcome = super::super::rotate::rotate_scope(
                &mut entropy,
                &self.floors,
                &self.scheduler,
                &self.publisher,
                &plan,
                || Box::pin(async {}),
            )
            .await;
            *self.entropy.borrow_mut() = Some(entropy);
            outcome
        }
    }

    fn flat_rotator() -> FlatRotator {
        let keys = FlatKeys {
            owner_enc: cipherbox_core::suite::x25519::X25519Secret::from_scalar([0x11; 32]),
            pseudonym: cipherbox_core::suite::ed25519::Ed25519Signer::from_seed([0x22; 32]),
            write_scope_seed: [0x55; 32],
            pointer_read_key: [0x66; 32],
        };
        let owner_ecdsa = EcdsaSigner::from_scalar(&[0x33; 32]).expect("signer");
        let grantee = cipherbox_core::suite::x25519::X25519Secret::from_scalar([0x77; 32]);
        let commitment = GrantSetCommitment {
            ipns_name: b"source-root".to_vec(),
            owner_pseudonym_pk: keys.pseudonym.verifying_key().to_bytes(),
            entries: vec![GrantSetEntry::new(READ_TAG, Permission::Read, [0x02; 32])],
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&owner_ecdsa, &commitment)
            .expect("sign")
            .to_compact();
        let ledger = vec![GrantLedgerEntry::new(
            [0x02; 33],
            grantee.public().to_bytes(),
            Permission::Read,
            READ_TAG,
        )];
        FlatRotator {
            entropy: RefCell::new(Some(crate::testkit::SeededEntropy::new(0xab))),
            floors: crate::testkit::fakes::InMemoryFloorStore::default(),
            scheduler: VirtualScheduler::new(),
            publisher: RecordingPublisher::default(),
            keys,
            committed: (commitment, sig, ledger),
            child_index: vec![ChildScopeRef::new(DESCENDANT, b"descendant-root".to_vec())],
            current_seed: [0xaa; 32],
            current_read_epoch: 4,
        }
    }

    /// The eager-set law's grantee arm: a scope exit cuts the source root and
    /// **nothing below it**. A descendant scope root is committed to by name and
    /// carried verbatim — never re-keyed, never republished.
    #[test]
    fn a_scope_exit_cut_re_keys_the_source_root_and_no_descendant() {
        let rotator = flat_rotator();

        let report = block_on(consume_scope_exit_triggers(&rotator, &[NodeId(SOURCE)]));

        assert!(report.is_complete());
        let published = rotator.publisher.published.borrow();
        assert_eq!(published.len(), 1, "one root cut, no descendant wave");
        assert_eq!(published[0].scope_id, SOURCE);
        assert_eq!(published[0].read_epoch, 5, "the source root advanced");
        assert_eq!(
            published[0].write_epoch, 3,
            "a read-plane cut moves no write epoch"
        );
        assert_eq!(
            block_on(FloorStore::epoch_floor(&rotator.floors, &SOURCE)).expect("floor"),
            Some(5)
        );
        assert_eq!(
            block_on(FloorStore::epoch_floor(&rotator.floors, &DESCENDANT)).expect("floor"),
            None,
            "the descendant scope root is committed to by name, never re-keyed"
        );
    }

    /// A grantee re-wraps the committed tag set verbatim and can neither extend
    /// nor shrink it (#26 D5), so the owner-signed commitment and its signature
    /// must survive the cut byte-for-byte.
    #[test]
    fn a_scope_exit_cut_leaves_the_committed_tag_set_byte_identical() {
        let rotator = flat_rotator();
        let (commitment, sig, _) = &rotator.committed;
        let before = encode_grant_set_commitment(commitment).expect("encodes");

        block_on(consume_scope_exit_triggers(&rotator, &[NodeId(SOURCE)]));

        let published = rotator.publisher.published.borrow();
        let section = &published[0].section;
        assert_eq!(
            encode_grant_set_commitment(&section.commitment).expect("encodes"),
            before,
            "the epoch-free commitment needs no fresh owner signature"
        );
        assert_eq!(&section.commitment_sig, sig);
        assert_eq!(
            section
                .grant_blobs
                .iter()
                .map(|blob| blob.tag)
                .collect::<Vec<_>>(),
            vec![READ_TAG],
            "one re-wrapped blob per committed entry, at the same tags"
        );
    }
}
