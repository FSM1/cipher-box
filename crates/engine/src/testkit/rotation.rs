//! The rotation reject families: one refusal per fail-closed check the
//! rotation planes publish, each produced by driving the live entry point.
//!
//! A vector's `check` and `class` are read off an error value a real call
//! returned, never written down here — so a verdict that quietly moves planes
//! or classes shows up as a diff against the committed vectors
//! (`crates/engine/kat/rotation`, written by `examples/kat_gen.rs`).

use std::collections::BTreeMap;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::payload::pointer::RepointObject;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, Permission,
    PreservedFields, ReadBody, SignedSealed, sign_grant_set,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

use crate::entropy::Entropy;
use crate::facade::NodeId;
use crate::grants::ledger::mint_grant_row;
use crate::rotation::{
    AscentAuthority, CascadeError, CascadeOutcome, CascadeResealResolver, CascadeTarget,
    CommittedSet, GrantCutPlan, LaggingNode, NodeRef, PrevEpochSeed, RecoveredWave, RepointChannel,
    RepublishedNode, ResealError, ResealSeeds, ResealedScopeRoot, ResolveFailure, ResumedRoot,
    RevokeError, RevokedCommittedSet, RotateError, RotateOnCutError, RotateScopePlan,
    RotateScopeWritePlan, RotationPublishError, ScopeRootIdentity, ScopeRootPublisher, SweepError,
    SweepPublisher, SweepResolveFailure, SweepResolver, SweptChild, SweptNode, SweptScope,
    WriteHistory, WritePublishError, WriteRevokeKind, WriteRotateError, WriteRotationOutcome,
    WriteScopeNode, WriteSubtreeResolver, WriteWavePublisher, build_repoint_object,
    cascade_rotate_scope, derive_write_name, reseal_scope_root, revoke_read_grant,
    revoke_write_grant, rotate_on_cut, rotate_scope, rotate_scope_write, sweep_pass,
};
use crate::seams::{FloorStore, SeamError, SeamResult};
use crate::testkit::fakes::{InMemoryFloorStore, VirtualScheduler};
use crate::testkit::reject::{RejectFamily, RejectVector, family, refusal};
use crate::testkit::{SeededEntropy, SilentEntropy, block_on};

/// Every rotation reject family, in a fixed order. Deterministic: two calls
/// give byte-identical output.
pub fn reject_families() -> Vec<RejectFamily> {
    vec![
        reseal_family(),
        revoke_family(),
        read_rotate_family(),
        cascade_family(),
        write_rotate_family(),
        sweep_family(),
        cut_family(),
    ]
}

// --- The one scope every family rotates -------------------------------------

const V: u64 = 2;
const SCOPE: [u8; 16] = [0x5c; 16];
const POINTER_READ_KEY: [u8; 32] = [0x66; 32];
const WRITE_SCOPE_SEED: [u8; 32] = [0x55; 32];
const OWNER_POINTER_SEED: [u8; 32] = [0x57; 32];
const CURRENT_OVERRIDE_SEED: [u8; 32] = [0xaa; 32];
const PARENT_NODE_SEED: [u8; 32] = [0x44; 32];
const CURRENT_READ_EPOCH: u64 = 4;
const CURRENT_WRITE_EPOCH: u64 = 3;
const WRITE_HISTORY_LINK: &[u8] = b"opaque-write-history-link";
/// One fixed stream per driven call: a KAT corpus may not sample entropy.
const ENTROPY_SEED: u64 = 0x5c_07_5e_ed;

/// One scope root, owner-minted: a read grantee and a write grantee committed
/// and ledgered at the scope's own write-plane name, so every tag is the
/// owner–recipient ECDH the re-seal re-derives.
struct ScopeFixture {
    owner_enc: X25519Secret,
    owner_enc_pub: X25519Public,
    owner_identity: EcdsaSigner,
    pseudonym: Ed25519Signer,
    name: IpnsName,
    commitment: GrantSetCommitment,
    commitment_sig: [u8; 64],
    ledger: Vec<GrantLedgerEntry>,
}

fn recipient(scalar: u8) -> X25519Secret {
    X25519Secret::from_scalar([scalar; 32])
}

const READ_RECIPIENT: u8 = 0x71;
const WRITE_RECIPIENT: u8 = 0x72;

impl ScopeFixture {
    fn new() -> Self {
        let owner_enc = X25519Secret::from_scalar([0x11; 32]);
        let owner_identity = EcdsaSigner::from_scalar(&[0x33; 32]).expect("a valid owner scalar");
        let pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let name = derive_write_name(&WRITE_SCOPE_SEED, &SCOPE);
        let rows = [
            (READ_RECIPIENT, [0x02; 33], Permission::Read),
            (WRITE_RECIPIENT, [0x03; 33], Permission::Write),
        ]
        .map(|(scalar, identity_pk, permission)| {
            mint_grant_row(
                &owner_identity,
                &owner_enc,
                &POINTER_READ_KEY,
                identity_pk,
                &recipient(scalar).public(),
                &SCOPE,
                name.as_str().as_bytes(),
                permission,
            )
            .expect("a contributory recipient key")
        });
        let commitment = GrantSetCommitment {
            ipns_name: name.as_str().as_bytes().to_vec(),
            owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
            unknown: PreservedFields::new(),
        };
        let commitment_sig = sign_grant_set(&owner_identity, &commitment)
            .expect("the owner signs its own set")
            .to_compact();
        Self {
            owner_enc_pub: owner_enc.public(),
            owner_enc,
            owner_identity,
            pseudonym,
            name,
            commitment,
            commitment_sig,
            ledger: rows.iter().map(|r| r.ledger_entry.clone()).collect(),
        }
    }

    fn tag(&self, permission: Permission) -> [u8; 32] {
        self.commitment
            .entries
            .iter()
            .find(|e| e.permission == permission)
            .expect("the fixture commits both permissions")
            .tag
    }

    fn committed(&self) -> CommittedSet<'_> {
        CommittedSet {
            commitment: &self.commitment,
            commitment_sig: &self.commitment_sig,
            grant_ledger: &self.ledger,
            direct_child_scope_index: &[],
            revoked_recipients: &[],
        }
    }

    /// The re-sealer identity, optionally holding the owner encryption subkey.
    fn identity<'a>(&'a self, owner_enc_secret: Option<&'a X25519Secret>) -> ScopeRootIdentity<'a> {
        ScopeRootIdentity {
            v: V,
            scope_id: SCOPE,
            ipns_name: self.name.as_str().as_bytes(),
            owner_enc_pub: &self.owner_enc_pub,
            owner_enc_secret,
            ascent: None,
            owes_ascent_link: false,
            pseudonym_signer: &self.pseudonym,
        }
    }

    fn cut_plan(&self) -> GrantCutPlan<'_> {
        GrantCutPlan {
            commitment: &self.commitment,
            commitment_sig: &self.commitment_sig,
            grant_ledger: &self.ledger,
            scope_root_name: &self.name,
            owner_signer: &self.owner_identity,
            pointer_read_key: &POINTER_READ_KEY,
        }
    }
}

/// A scope root whose commitment names another scope's `ipnsName` — the
/// binding every owner-only cut checks the presented name against.
fn other_name() -> IpnsName {
    derive_write_name(&WRITE_SCOPE_SEED, &[0x9e; 16])
}

fn stranger() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&[0x44; 32]).expect("a valid stranger scalar")
}

// --- reseal -----------------------------------------------------------------

fn reseal_seeds<'a>(
    override_seed: &'a [u8; 32],
    write_history: WriteHistory<'a>,
) -> ResealSeeds<'a> {
    ResealSeeds {
        override_seed,
        read_epoch: CURRENT_READ_EPOCH + 1,
        prev: None,
        write_scope_seed: &WRITE_SCOPE_SEED,
        write_epoch: CURRENT_WRITE_EPOCH,
        write_history,
        pointer_read_key: &POINTER_READ_KEY,
    }
}

/// Drive one re-seal to its refusal.
fn reseal_refusal<E: Entropy>(
    name: &'static str,
    entropy: &mut E,
    identity: &ScopeRootIdentity<'_>,
    seeds: &ResealSeeds<'_>,
    committed: &CommittedSet<'_>,
) -> RejectVector {
    refusal!(
        name,
        reseal_scope_root(entropy, identity, seeds, committed, &[])
            .err()
            .unwrap_or_else(|| panic!("{name}: the re-seal must fail closed")),
    )
}

fn reseal_family() -> RejectFamily {
    let fx = ScopeFixture::new();
    let fresh_seed = [0x9d; 32];
    let honest = || reseal_seeds(&fresh_seed, WriteHistory::Carried(WRITE_HISTORY_LINK));
    fn refused(
        name: &'static str,
        identity: &ScopeRootIdentity<'_>,
        seeds: &ResealSeeds<'_>,
        committed: &CommittedSet<'_>,
    ) -> RejectVector {
        reseal_refusal(
            name,
            &mut SeededEntropy::new(ENTROPY_SEED),
            identity,
            seeds,
            committed,
        )
    }

    let mut vectors = Vec::new();

    // A seam stuck at zero: refused before the first seal draws a nonce.
    vectors.push(reseal_refusal(
        "entropy-seam-that-draws-nothing",
        &mut SilentEntropy,
        &fx.identity(None),
        &honest(),
        &fx.committed(),
    ));

    let outsider = Ed25519Signer::from_seed([0x9f; 32]);
    let mut uncommitted_signer = fx.identity(None);
    uncommitted_signer.pseudonym_signer = &outsider;
    vectors.push(refused(
        "signer-outside-the-committed-set",
        &uncommitted_signer,
        &honest(),
        &fx.committed(),
    ));

    let mut dropped = fx.identity(None);
    dropped.owes_ascent_link = true;
    vectors.push(refused(
        "descendant-root-with-no-ascent-authority",
        &dropped,
        &honest(),
        &fx.committed(),
    ));

    let mut unowed = fx.identity(None);
    unowed.ascent = Some(AscentAuthority::ParentSeed(&PARENT_NODE_SEED));
    vectors.push(refused(
        "vault-root-handed-an-ascent-authority",
        &unowed,
        &honest(),
        &fx.committed(),
    ));

    let retiring_write_seed = [0x56; 32];
    let cut = reseal_seeds(
        &fresh_seed,
        WriteHistory::Cut(PrevEpochSeed {
            seed: &retiring_write_seed,
            epoch: CURRENT_WRITE_EPOCH - 1,
        }),
    );
    vectors.push(refused(
        "write-cut-without-the-owner-encryption-subkey",
        &fx.identity(None),
        &cut,
        &fx.committed(),
    ));

    let mut divergent = fx.ledger.clone();
    divergent.push(GrantLedgerEntry::new(
        [0x04; 33],
        recipient(0x73).public().to_bytes(),
        Permission::Read,
        [0xc3; 32],
        [0u8; 64],
    ));
    vectors.push(refused(
        "ledger-with-an-uncommitted-row",
        &fx.identity(None),
        &honest(),
        &CommittedSet {
            grant_ledger: &divergent,
            ..fx.committed()
        },
    ));

    // The owner attesting a key nothing can seal to: not a canonical X25519
    // point, so the whole set would be locked out of the next epoch.
    let mut unusable = fx.commitment.clone();
    unusable.entries[0].set_recipient_enc_pk(&POINTER_READ_KEY, [0xff; 32]);
    vectors.push(refused(
        "committed-recipient-key-no-key-can-open",
        &fx.identity(None),
        &honest(),
        &CommittedSet {
            commitment: &unusable,
            ..fx.committed()
        },
    ));

    // An owner-held re-seal re-derives every tag, so a tag that is not this
    // scope's owner–recipient ECDH names a recipient the owner never bound.
    let unbound_tag = [0xc7; 32];
    let mut unbound = fx.commitment.clone();
    unbound.entries = vec![GrantSetEntry::new(
        &POINTER_READ_KEY,
        unbound_tag,
        recipient(READ_RECIPIENT).public().to_bytes(),
        Permission::Read,
        [0x02; 32],
    )];
    let unbound_ledger = vec![GrantLedgerEntry::new(
        [0x02; 33],
        recipient(READ_RECIPIENT).public().to_bytes(),
        Permission::Read,
        unbound_tag,
        [0u8; 64],
    )];
    vectors.push(refused(
        "tag-that-is-not-the-owner-recipient-ecdh",
        &fx.identity(Some(&fx.owner_enc)),
        &honest(),
        &CommittedSet {
            commitment: &unbound,
            grant_ledger: &unbound_ledger,
            ..fx.committed()
        },
    ));

    family("reseal", ResealError::CHECKS, vectors)
}

// --- revoke -----------------------------------------------------------------

fn revoke_family() -> RejectFamily {
    let fx = ScopeFixture::new();
    let read_tag = fx.tag(Permission::Read);
    let write_tag = fx.tag(Permission::Write);
    let stranger = stranger();
    let elsewhere = other_name();

    let refused = |name, result: Result<RevokedCommittedSet, RevokeError>| {
        refusal!(
            name,
            result
                .err()
                .unwrap_or_else(|| panic!("{name}: the cut must fail closed")),
        )
    };

    // The cut epoch at its ceiling: one more step would wrap the counter a
    // later replay is held below.
    let mut exhausted = fx.commitment.clone();
    exhausted.cut_epoch = u64::MAX;
    let exhausted_sig = sign_grant_set(&fx.owner_identity, &exhausted)
        .expect("the owner signs the set")
        .to_compact();

    let vectors = vec![
        refused(
            "cut-presented-by-a-stranger",
            revoke_read_grant(
                &GrantCutPlan {
                    owner_signer: &stranger,
                    ..fx.cut_plan()
                },
                &read_tag,
            ),
        ),
        refused(
            "commitment-bound-to-another-scope-root",
            revoke_read_grant(
                &GrantCutPlan {
                    scope_root_name: &elsewhere,
                    ..fx.cut_plan()
                },
                &read_tag,
            ),
        ),
        refused(
            "tag-absent-from-the-committed-set",
            revoke_read_grant(&fx.cut_plan(), &[0xc3; 32]),
        ),
        refused(
            "read-tag-presented-to-the-write-revoke",
            revoke_write_grant(&fx.cut_plan(), &read_tag, WriteRevokeKind::Full),
        ),
        refused(
            "write-tag-presented-to-the-read-revoke",
            revoke_read_grant(&fx.cut_plan(), &write_tag),
        ),
        refused(
            "cut-epoch-at-its-ceiling",
            revoke_read_grant(
                &GrantCutPlan {
                    commitment: &exhausted,
                    commitment_sig: &exhausted_sig,
                    ..fx.cut_plan()
                },
                &read_tag,
            ),
        ),
    ];

    family("revoke", RevokeError::CHECKS, vectors)
}

// --- the read-plane publish and floor seams ---------------------------------

/// A publisher that returns one scripted verdict for every record.
struct ScriptedPublisher(Result<(), RotationPublishError>);

impl ScopeRootPublisher for ScriptedPublisher {
    async fn publish_scope_root(
        &self,
        _record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        self.0.clone()
    }
}

/// A floor store that reads benignly and refuses every raise — the crash
/// window where a record landed and its floor did not.
struct RefusingFloorStore;

impl FloorStore for RefusingFloorStore {
    async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
        Ok(None)
    }
    async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
        Err(SeamError::new("floor raise refused"))
    }
    async fn sequence_floor(&self, _ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        Ok(None)
    }
    async fn raise_sequence_floor(&self, _ipns_name: &[u8], _sequence: u64) -> SeamResult<u64> {
        Err(SeamError::new("floor raise refused"))
    }
    async fn clear(&self) -> SeamResult<()> {
        Ok(())
    }
}

fn rotate_plan<'a>(
    fx: &'a ScopeFixture,
    identity: ScopeRootIdentity<'a>,
    current_read_epoch: u64,
    children: &'a [ChildScopeRef],
) -> RotateScopePlan<'a> {
    const NO_LINKS: &[SignedSealed] = &[];
    RotateScopePlan {
        identity,
        committed: CommittedSet {
            direct_child_scope_index: children,
            ..fx.committed()
        },
        current_override_seed: &CURRENT_OVERRIDE_SEED,
        current_read_epoch,
        write_scope_seed: &WRITE_SCOPE_SEED,
        write_epoch: CURRENT_WRITE_EPOCH,
        write_history_link: WRITE_HISTORY_LINK,
        pointer_read_key: &POINTER_READ_KEY,
        carried_history_links: NO_LINKS,
    }
}

// --- read-plane root cut ----------------------------------------------------

/// Drive one read-plane root cut to its refusal.
fn read_rotate_refusal<F: FloorStore, E: Entropy>(
    floors: &F,
    entropy: &mut E,
    publish: Result<(), RotationPublishError>,
    current_read_epoch: u64,
) -> RotateError {
    let fx = ScopeFixture::new();
    let scheduler = VirtualScheduler::new();
    let publisher = ScriptedPublisher(publish);
    let plan = rotate_plan(&fx, fx.identity(None), current_read_epoch, &[]);
    block_on(rotate_scope(
        entropy,
        floors,
        &scheduler,
        &publisher,
        &plan,
        || Box::pin(async {}),
    ))
    .expect_err("the rotation must fail closed")
}

fn read_rotate_family() -> RejectFamily {
    let healthy = InMemoryFloorStore::default();
    let seeded = || SeededEntropy::new(ENTROPY_SEED);
    let vectors = vec![
        refusal!(
            "read-epoch-at-its-ceiling",
            read_rotate_refusal(&healthy, &mut seeded(), Ok(()), u64::MAX),
        ),
        refusal!(
            "entropy-seam-that-draws-nothing",
            read_rotate_refusal(&healthy, &mut SilentEntropy, Ok(()), CURRENT_READ_EPOCH),
        ),
        refusal!(
            "publisher-that-refuses-the-record",
            read_rotate_refusal(
                &healthy,
                &mut seeded(),
                Err(RotationPublishError::Rejected),
                CURRENT_READ_EPOCH,
            ),
        ),
        refusal!(
            "floor-store-that-refuses-the-raise",
            read_rotate_refusal(
                &RefusingFloorStore,
                &mut seeded(),
                Ok(()),
                CURRENT_READ_EPOCH,
            ),
        ),
    ];

    family("read_rotate", RotateError::CHECKS, vectors)
}

// --- the revocation cascade -------------------------------------------------

/// A cascade resolver with one scripted verdict for every descendant.
struct ScriptedCascadeResolver(ResolveFailure);

impl CascadeResealResolver for ScriptedCascadeResolver {
    async fn resolve(&self, _scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure> {
        Err(self.0)
    }
}

/// Drive one revocation cascade to its refusal. `children` is the root's
/// direct-child-scope index; the scripted resolver refuses every descendant
/// the walk reaches.
fn cascade_refusal<F: FloorStore>(
    floors: &F,
    publish: Result<(), RotationPublishError>,
    owner_held: bool,
    current_read_epoch: u64,
    children: &[ChildScopeRef],
) -> CascadeError {
    let fx = ScopeFixture::new();
    let scheduler = VirtualScheduler::new();
    let publisher = ScriptedPublisher(publish);
    let resolver = ScriptedCascadeResolver(ResolveFailure::Rejected);
    let owner_enc = owner_held.then(|| fx.owner_enc.clone());
    let plan = rotate_plan(
        &fx,
        fx.identity(owner_enc.as_ref()),
        current_read_epoch,
        children,
    );
    block_on(cascade_rotate_scope(
        &mut SeededEntropy::new(ENTROPY_SEED),
        floors,
        &scheduler,
        &resolver,
        &publisher,
        &plan,
        || Box::pin(async {}),
    ))
    .expect_err("the cascade must fail closed")
}

fn cascade_family() -> RejectFamily {
    let healthy = InMemoryFloorStore::default();
    let descendant = vec![ChildScopeRef::new(
        [0x7d; 16],
        other_name().as_str().as_bytes().to_vec(),
    )];

    let vectors = vec![
        refusal!(
            "re-key-without-the-owner-encryption-subkey",
            cascade_refusal(&healthy, Ok(()), false, CURRENT_READ_EPOCH, &[]),
        ),
        refusal!(
            "read-epoch-at-its-ceiling",
            cascade_refusal(&healthy, Ok(()), true, u64::MAX, &[]),
        ),
        refusal!(
            "publisher-that-refuses-the-root-record",
            cascade_refusal(
                &healthy,
                Err(RotationPublishError::Rejected),
                true,
                CURRENT_READ_EPOCH,
                &[],
            ),
        ),
        refusal!(
            "floor-store-that-refuses-the-raise",
            cascade_refusal(&RefusingFloorStore, Ok(()), true, CURRENT_READ_EPOCH, &[]),
        ),
        refusal!(
            "descendant-the-gate-refuses",
            cascade_refusal(&healthy, Ok(()), true, CURRENT_READ_EPOCH, &descendant),
        ),
    ];

    family("cascade", CascadeError::CHECKS, vectors)
}

// --- the write-plane name wave ----------------------------------------------

/// The write wave's seams, wired to panic — the probe that turns "eventually
/// refused" into "refused before the wave touched the record plane".
struct UndrivenWave;

impl WriteSubtreeResolver for UndrivenWave {
    async fn resolve_node(
        &self,
        _node_id: &[u8; 16],
        _resumed: Option<&ResumedRoot>,
    ) -> Result<WriteScopeNode, ResolveFailure> {
        panic!("the owner gate must refuse before the wave resolves")
    }
    async fn recover_wave(&self) -> Result<RecoveredWave, ResolveFailure> {
        panic!("the owner gate must refuse before the wave recovers")
    }
}

impl WriteWavePublisher for UndrivenWave {
    async fn is_republished(&self, _new_name: &IpnsName) -> Result<bool, WritePublishError> {
        panic!("the owner gate must refuse before the wave publishes")
    }
    async fn republish(&self, _node: &RepublishedNode) -> Result<(), WritePublishError> {
        panic!("the owner gate must refuse before the wave publishes")
    }
    async fn retire(&self, _old_names: &[IpnsName]) -> Result<(), WritePublishError> {
        panic!("the owner gate must refuse before the wave retires")
    }
    async fn check_repoint_publishable(
        &self,
        _repoint: &RepointObject,
    ) -> Result<(), WritePublishError> {
        panic!("the owner gate must refuse before the wave re-points")
    }
    async fn publish_repoint(
        &self,
        _channel: RepointChannel,
        _block: &[u8],
    ) -> Result<(), WritePublishError> {
        panic!("the owner gate must refuse before the wave re-points")
    }
}

fn write_rotate_family() -> RejectFamily {
    let fx = ScopeFixture::new();
    let stranger = stranger();
    let elsewhere = other_name();

    let run = |owner: &EcdsaSigner, name: &IpnsName, epoch: u64| -> WriteRotateError {
        let plan = RotateScopeWritePlan {
            scope_id: SCOPE,
            payload_version: V,
            owner_pointer_seed: &OWNER_POINTER_SEED,
            commitment: &fx.commitment,
            commitment_sig: &fx.commitment_sig,
            owner_identity_signer: owner,
            current_write_epoch: epoch,
            min_read_epoch: CURRENT_READ_EPOCH,
            current_root_name: name,
            is_vault_anchor: false,
        };
        block_on(rotate_scope_write(
            &mut SeededEntropy::new(ENTROPY_SEED),
            &UndrivenWave,
            &UndrivenWave,
            &plan,
        ))
        .expect_err("the write rotation must fail closed")
    };

    let moved = derive_write_name(&[0x58; 32], &SCOPE);
    let repoint = |name: &'static str, new_root: IpnsName, new_epoch: u64| {
        refusal!(
            name,
            build_repoint_object(
                SCOPE,
                new_root,
                fx.name.clone(),
                new_epoch,
                CURRENT_WRITE_EPOCH,
                CURRENT_READ_EPOCH,
            )
            .err()
            .unwrap_or_else(|| panic!("{name}: the re-point must fail closed")),
        )
    };

    let vectors = vec![
        refusal!(
            "rotation-presented-by-a-stranger",
            run(&stranger, &fx.name, CURRENT_WRITE_EPOCH),
        ),
        refusal!(
            "commitment-bound-to-another-scope-root",
            run(&fx.owner_identity, &elsewhere, CURRENT_WRITE_EPOCH),
        ),
        refusal!(
            "write-epoch-at-its-ceiling",
            run(&fx.owner_identity, &fx.name, u64::MAX),
        ),
        repoint(
            "re-point-that-repeats-the-write-epoch",
            moved,
            CURRENT_WRITE_EPOCH,
        ),
        repoint(
            "re-point-back-to-the-predecessor-name",
            fx.name.clone(),
            CURRENT_WRITE_EPOCH + 1,
        ),
    ];

    family("write_rotate", WriteRotateError::CHECKS, vectors)
}

// --- the lazy sweep ---------------------------------------------------------

/// A scripted sweep read edge: the scope root resolves to `scope`, and each
/// child answers from `children` in the order the walk asks for them.
struct ScriptedSweep {
    scope: Result<SweptScope, SweepResolveFailure>,
    children: BTreeMap<[u8; 16], Result<SweptChild, SweepResolveFailure>>,
    publish: Result<(), RotationPublishError>,
    repair: Result<(), RotationPublishError>,
}

impl SweepResolver for ScriptedSweep {
    async fn resolve_scope(
        &self,
        _scope: &ChildScopeRef,
    ) -> Result<SweptScope, SweepResolveFailure> {
        self.scope.clone()
    }
    async fn consult_pointer(
        &self,
        _scope_id: &[u8; 16],
    ) -> Result<Option<Vec<u8>>, SweepResolveFailure> {
        Ok(None)
    }
    async fn resolve_child(
        &self,
        _scope: &ChildScopeRef,
        child: &NodeRef,
    ) -> Result<SweptChild, SweepResolveFailure> {
        self.children
            .get(&child.node_id)
            .cloned()
            .expect("the walk only asks for scripted children")
    }
}

impl SweepPublisher for ScriptedSweep {
    async fn publish_node(
        &self,
        _scope: &ChildScopeRef,
        _node: &LaggingNode<'_>,
    ) -> Result<(), RotationPublishError> {
        self.publish.clone()
    }
    async fn repair_child_scope_index(
        &self,
        _scope: &ChildScopeRef,
        _index: &[ChildScopeRef],
    ) -> Result<(), RotationPublishError> {
        self.repair.clone()
    }
}

const SWEEP_CHILD: [u8; 16] = [0x0c; 16];
const SWEEP_SCOPE_EPOCH: u64 = 5;

fn empty_folder() -> ReadBody {
    ReadBody::Folder {
        created_at: 0,
        modified_at: 0,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    }
}

fn sweep_family() -> RejectFamily {
    let scope_ref = ChildScopeRef::new(SCOPE, b"scope-root-name".to_vec());
    let child = NodeRef {
        node_id: SWEEP_CHILD,
        ipns_name: b"lagging-node-name".to_vec(),
    };
    let one_child = |direct_child_scope_index: Vec<ChildScopeRef>| SweptScope {
        current_read_epoch: SWEEP_SCOPE_EPOCH,
        children: vec![child.clone()],
        direct_child_scope_index,
    };
    let lagging = SweptChild::Interior(SweptNode {
        current_read_epoch: SWEEP_SCOPE_EPOCH - 1,
        sequence: 7,
        read_body: empty_folder(),
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    });

    let run = |name: &'static str, seam: ScriptedSweep| {
        refusal!(
            name,
            block_on(sweep_pass(&seam, &seam, &scope_ref))
                .err()
                .unwrap_or_else(|| panic!("{name}: the pass must fail closed")),
        )
    };
    let scripted = |scope,
                    children: Vec<([u8; 16], Result<SweptChild, SweepResolveFailure>)>,
                    publish,
                    repair| ScriptedSweep {
        scope,
        children: children.into_iter().collect(),
        publish,
        repair,
    };

    let vectors = vec![
        run(
            "scope-root-the-gate-refuses",
            scripted(
                Err(SweepResolveFailure::Rejected),
                Vec::new(),
                Ok(()),
                Ok(()),
            ),
        ),
        // A node below its own floor whose scope carries no pointer: there is
        // no fresher name the walk could re-resolve it at.
        run(
            "interior-node-below-its-floor-with-no-fresher-name",
            scripted(
                Ok(one_child(Vec::new())),
                vec![(SWEEP_CHILD, Err(SweepResolveFailure::Superseded))],
                Ok(()),
                Ok(()),
            ),
        ),
        run(
            "publisher-that-refuses-a-lagging-node",
            scripted(
                Ok(one_child(Vec::new())),
                vec![(SWEEP_CHILD, Ok(lagging.clone()))],
                Err(RotationPublishError::Rejected),
                Ok(()),
            ),
        ),
        // A descendant scope root the committed index does not name: the walk
        // repairs the index, and the publisher refuses the repair.
        run(
            "index-repair-the-publisher-refuses",
            scripted(
                Ok(one_child(Vec::new())),
                vec![(
                    SWEEP_CHILD,
                    Ok(SweptChild::ScopeRoot(ChildScopeRef::new(
                        SWEEP_CHILD,
                        child.ipns_name.clone(),
                    ))),
                )],
                Ok(()),
                Err(RotationPublishError::Rejected),
            ),
        ),
    ];

    family("sweep", SweepError::CHECKS, vectors)
}

// --- the cut driver ---------------------------------------------------------

/// A cut rotator whose every plane succeeds, leaving the driver's own
/// fail-closed check as the only thing that can refuse.
struct PermissiveRotator;

impl crate::rotation::CutRotator for PermissiveRotator {
    async fn publish_cut_set(
        &self,
        _scope_root: NodeId,
        _cut: &RevokedCommittedSet,
    ) -> Result<(), CascadeError> {
        Ok(())
    }
    async fn rotate_read_plane(
        &self,
        _scope_root: NodeId,
        _cut: &RevokedCommittedSet,
    ) -> Result<CascadeOutcome, CascadeError> {
        Ok(CascadeOutcome::default())
    }
    async fn rotate_write_plane(
        &self,
        _scope_root: NodeId,
        _cut: &RevokedCommittedSet,
    ) -> Result<WriteRotationOutcome, WriteRotateError> {
        Ok(WriteRotationOutcome {
            new_write_epoch: CURRENT_WRITE_EPOCH + 1,
            new_root_name: derive_write_name(&[0x58; 32], &SCOPE),
            interior_node_count: 0,
        })
    }
}

fn cut_family() -> RejectFamily {
    let fx = ScopeFixture::new();
    // A downgrade rotates the write plane alone, so it is the cut that cannot
    // carry a withheld recipient: only the read cascade records one durably.
    let mut downgrade = revoke_write_grant(
        &fx.cut_plan(),
        &fx.tag(Permission::Write),
        WriteRevokeKind::DowngradeToRead,
    )
    .expect("the owner downgrades its own write grant");
    downgrade.revoked_recipients = vec![recipient(WRITE_RECIPIENT).public().to_bytes()];

    let vectors = vec![refusal!(
        "write-only-cut-that-withholds-a-recipient",
        block_on(rotate_on_cut(&PermissiveRotator, NodeId(SCOPE), &downgrade))
            .expect_err("the driver must fail closed"),
    )];

    family("cut", RotateOnCutError::CHECKS, vectors)
}
