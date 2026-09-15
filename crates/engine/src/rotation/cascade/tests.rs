use super::*;
use crate::grants::recipient_blinded_tag;
use crate::testkit::fakes::{InMemoryFloorStore, VirtualScheduler};
use crate::testkit::{CARRIED_WRITE_HISTORY_LINK, SeededEntropy, SilentEntropy, block_on};
use cipherbox_core::seal::{
    AadContext, AscentLink, GrantSetEntry, Permission, PreservedFields, STRUCT_TAG_ASCENT_LINK,
    STRUCT_TAG_OWNER_BLOB, open_ascent_link, open_owner_blob, sign_grant_set,
    sign_recipient_binding,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::secret::ct_eq;
use cipherbox_core::suite::x25519::X25519Secret;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

const V: u64 = 2;

fn sid(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn childref(byte: u8) -> ChildScopeRef {
    ChildScopeRef::new(sid(byte), format!("ipns-{byte:02x}").into_bytes())
}

/// A child ref for scope `byte` carrying a caller-chosen `ipns_name` — to build
/// a diamond where one `scope_id` is reached with differing labels (C2), or an
/// attacker-chosen label the resolver's gate rejects.
fn childref_named(byte: u8, ipns_name: &str) -> ChildScopeRef {
    ChildScopeRef::new(sid(byte), ipns_name.as_bytes().to_vec())
}

/// The single vault owner/pseudonym identity every scope commits to, so
/// `reseal_scope_root`'s signer + committed-ledger guards pass.
struct Owner {
    enc: X25519Secret,
    pseudonym: Ed25519Signer,
    ecdsa: EcdsaSigner,
    grantee: X25519Secret,
}

impl Owner {
    fn new() -> Self {
        Self {
            enc: X25519Secret::from_scalar([0x11; 32]),
            pseudonym: Ed25519Signer::from_seed([0x22; 32]),
            ecdsa: EcdsaSigner::from_scalar(&[0x33; 32]).unwrap(),
            grantee: X25519Secret::from_scalar([0x77; 32]),
        }
    }

    /// The committed set for scope `byte`: one owner-signed read grant to the
    /// shared grantee at `ipns-{byte}`. Shared by every scope fixture (both the
    /// descendant `FakeNet::scope` and the root `RootFx`) so the commitment
    /// shape lives in one place.
    #[allow(clippy::type_complexity)]
    fn committed(
        &self,
        byte: u8,
    ) -> (
        GrantSetCommitment,
        [u8; ECDSA_SIG_LEN],
        Vec<GrantLedgerEntry>,
    ) {
        let ipns_name = format!("ipns-{byte:02x}").into_bytes();
        // Honestly minted and owner-attested, so a plan carrying
        // `owner_enc_secret` passes `reseal_scope_root`'s recipient-tag
        // binding and the row is re-sealed rather than skipped.
        let tag = recipient_blinded_tag(&self.enc, &self.grantee.public(), &ipns_name)
            .expect("a contributory sharer key");
        let mut entry = GrantLedgerEntry::new(
            [0x02; 33],
            self.grantee.public().to_bytes(),
            Permission::Read,
            tag,
            [0u8; ECDSA_SIG_LEN],
        );
        entry.owner_sig = sign_recipient_binding(&self.ecdsa, &ipns_name, &entry).to_compact();
        let commitment = GrantSetCommitment {
            ipns_name,
            owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries: vec![GrantSetEntry::new(
                &scope_pointer_read_key(byte),
                tag,
                self.grantee.public().to_bytes(),
                Permission::Read,
                [0x02; 32],
            )],
            unknown: PreservedFields::new(),
        };
        let commitment_sig = sign_grant_set(&self.ecdsa, &commitment)
            .unwrap()
            .to_compact();
        (commitment, commitment_sig, vec![entry])
    }
}

/// The pointer read key of the scope registered under `byte` — what its
/// committed entries mask their recipients under.
fn scope_pointer_read_key(byte: u8) -> [u8; 32] {
    [byte.wrapping_add(2); 32]
}

/// The immutable per-scope material a descendant resolves to, plus the mutable
/// current epoch a publish advances. The `override_seed` is this scope's
/// pre-cascade seed — the value the cascade must replace.
struct NetScope {
    /// The owner-blob recipient this scope's re-seal wraps to. `None` is the
    /// owner's own subkey; `Some` is a stranger's, so the published owner blob
    /// no longer carries the seed the re-key minted.
    owner_enc_pub: Option<X25519Public>,
    override_seed: [u8; 32],
    write_scope_seed: [u8; 32],
    pointer_read_key: [u8; 32],
    commitment: GrantSetCommitment,
    commitment_sig: [u8; ECDSA_SIG_LEN],
    grant_ledger: Vec<GrantLedgerEntry>,
    children: Vec<ChildScopeRef>,
    current_epoch: u64,
}

/// A fake resolver + publisher over one shared scope map — the cascade's fake
/// "network". A publish records the re-sealed record (so a test can recover the
/// fresh seed from its owner blob) and advances `current_epoch`. Injected
/// faults script an unresolvable descendant or a publish that does not land.
#[derive(Clone)]
struct FakeNet {
    owner: Rc<Owner>,
    scopes: Rc<RefCell<HashMap<[u8; 16], NetScope>>>,
    published: Rc<RefCell<HashMap<[u8; 16], ResealedScopeRoot>>>,
    resolve_faults: Rc<RefCell<HashMap<[u8; 16], ResolveFailure>>>,
    publish_faults: Rc<RefCell<HashMap<[u8; 16], RotationPublishError>>>,
}

impl FakeNet {
    fn new() -> Self {
        Self {
            owner: Rc::new(Owner::new()),
            scopes: Rc::new(RefCell::new(HashMap::new())),
            published: Rc::new(RefCell::new(HashMap::new())),
            resolve_faults: Rc::new(RefCell::new(HashMap::new())),
            publish_faults: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    /// Register a scope root: one read grant to the shared grantee, `children`
    /// as its direct-child index, published at `current_epoch`, pre-cascade
    /// override seed `[byte; 32]`.
    fn scope(self, byte: u8, current_epoch: u64, children: &[u8]) -> Self {
        let refs: Vec<ChildScopeRef> = children.iter().map(|b| childref(*b)).collect();
        self.scope_refs(byte, current_epoch, refs)
    }

    /// Like [`Self::scope`] but with caller-chosen child refs, so a parent can
    /// list a descendant under a specific (possibly conflicting or attacker)
    /// `ipns_name`.
    fn scope_refs(self, byte: u8, current_epoch: u64, children: Vec<ChildScopeRef>) -> Self {
        let (commitment, commitment_sig, grant_ledger) = self.owner.committed(byte);
        self.scopes.borrow_mut().insert(
            sid(byte),
            NetScope {
                owner_enc_pub: None,
                override_seed: [byte; 32],
                write_scope_seed: [byte.wrapping_add(1); 32],
                pointer_read_key: scope_pointer_read_key(byte),
                commitment,
                commitment_sig,
                grant_ledger,
                children,
                current_epoch,
            },
        );
        self
    }

    /// Report `byte`'s owner-blob recipient as a stranger's key, so its re-seal
    /// publishes a seed the owner cannot recover.
    fn stranger_owner_blob(self, byte: u8) -> Self {
        let stranger = X25519Secret::from_scalar([0x5a; 32]).public();
        if let Some(scope) = self.scopes.borrow_mut().get_mut(&sid(byte)) {
            scope.owner_enc_pub = Some(stranger);
        }
        self
    }

    fn resolve_fault(self, byte: u8, reason: ResolveFailure) -> Self {
        self.resolve_faults.borrow_mut().insert(sid(byte), reason);
        self
    }

    fn publish_fault(self, byte: u8, error: RotationPublishError) -> Self {
        self.publish_faults.borrow_mut().insert(sid(byte), error);
        self
    }

    fn pre_cascade_seed(&self, byte: u8) -> [u8; 32] {
        self.scopes
            .borrow()
            .get(&sid(byte))
            .expect("scope")
            .override_seed
    }

    /// Recover the fresh override seed the cascade published for `byte`, by
    /// opening its published record's owner blob with the owner's key.
    fn published_seed(&self, byte: u8) -> [u8; 32] {
        let published = self.published.borrow();
        let record = published.get(&sid(byte)).expect("published record");
        let ob = &record.section.owner_blob;
        let ctx = AadContext {
            v: V,
            id: sid(byte),
            scope: sid(byte),
            epoch: record.read_epoch,
            struct_tag: STRUCT_TAG_OWNER_BLOB,
        };
        let payload = open_owner_blob(&self.owner.enc, &ob.enc, &ctx, &ob.ciphertext)
            .expect("owner opens the published seed");
        *payload.override_seed()
    }

    /// Open `byte`'s published ascent link with `parent_node_seed`, returning
    /// the recovered override seed (or `None` if it does not open under that
    /// derivation).
    fn ascent_seed_under(&self, byte: u8, parent_node_seed: &[u8; 32]) -> Option<[u8; 32]> {
        let published = self.published.borrow();
        let record = published.get(&sid(byte)).expect("published record");
        let ascent = record
            .section
            .ascent_link
            .as_ref()
            .expect("interior ascent");
        let ctx = AadContext {
            v: V,
            id: sid(byte),
            scope: sid(byte),
            epoch: record.read_epoch,
            struct_tag: STRUCT_TAG_ASCENT_LINK,
        };
        let link = AscentLink {
            ascent_public: ascent.ascent_public,
            enc: ascent.enc,
            ciphertext: ascent.ciphertext.clone(),
            unknown: PreservedFields::new(),
        };
        open_ascent_link(parent_node_seed, &ctx, &link)
            .ok()
            .map(|p| *p.override_seed())
    }

    fn published_epoch(&self, byte: u8) -> u64 {
        self.published
            .borrow()
            .get(&sid(byte))
            .expect("record")
            .read_epoch
    }

    /// The recipient tags the scope's published section minted a blob for.
    fn blob_tags(&self, byte: u8) -> Vec<[u8; 32]> {
        self.published
            .borrow()
            .get(&sid(byte))
            .expect("record")
            .section
            .grant_blobs
            .iter()
            .map(|blob| blob.tag)
            .collect()
    }

    fn history_len(&self, byte: u8) -> usize {
        self.published
            .borrow()
            .get(&sid(byte))
            .expect("record")
            .section
            .history_links
            .len()
    }
}

impl CascadeResealResolver for FakeNet {
    async fn resolve(&self, scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure> {
        if let Some(reason) = self.resolve_faults.borrow().get(&scope.scope_id) {
            return Err(*reason);
        }
        let scopes = self.scopes.borrow();
        let s = scopes
            .get(&scope.scope_id)
            .ok_or(ResolveFailure::Unavailable)?;
        // Fidelity to the gate contract: the record's owner-signed commitment
        // binds its ipns_name (adoption gate stage 2). A child ref whose
        // ipns_name is not the committed name has no commitment binding it —
        // the gate rejects, so an attacker-chosen label cannot resolve.
        if scope.ipns_name != s.commitment.ipns_name {
            return Err(ResolveFailure::Rejected);
        }
        Ok(CascadeTarget {
            v: V,
            current_read_epoch: s.current_epoch,
            owner_enc_pub: s.owner_enc_pub.unwrap_or_else(|| self.owner.enc.public()),
            pseudonym_signer: self.owner.pseudonym.clone(),
            write_body_signer: None,
            override_seed: Zeroizing::new(s.override_seed),
            write_scope_seed: Zeroizing::new(s.write_scope_seed),
            pointer_read_key: Zeroizing::new(s.pointer_read_key),
            write_epoch: 1,
            commitment: s.commitment.clone(),
            commitment_sig: s.commitment_sig,
            grant_ledger: s.grant_ledger.clone(),
            write_history_link: Vec::new(),
            direct_child_scope_index: s.children.clone(),
            carried_history_links: Vec::new(),
            // Every scope this resolver reaches is a descendant.
            carried_ascent_link: true,
        })
    }
}

impl ScopeRootPublisher for FakeNet {
    async fn publish_scope_root(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        if let Some(err) = self.publish_faults.borrow().get(&record.scope_id) {
            return Err(err.clone());
        }
        if let Some(s) = self.scopes.borrow_mut().get_mut(&record.scope_id) {
            s.current_epoch = record.read_epoch;
        }
        self.published
            .borrow_mut()
            .insert(record.scope_id, record.clone());
        Ok(())
    }
}

/// The root plan for scope `0x00` (a vault root — no ascent link), the
/// read-grantee's committed set unchanged (the cut itself is exercised in
/// `trigger.rs`; here the focus is the descendant cascade).
struct RootFx {
    net: FakeNet,
    holds_owner_enc_secret: bool,
    owner_pub: X25519Public,
    commitment: GrantSetCommitment,
    commitment_sig: [u8; ECDSA_SIG_LEN],
    grant_ledger: Vec<GrantLedgerEntry>,
    current_seed: [u8; 32],
    write_scope_seed: [u8; 32],
    pointer_read_key: [u8; 32],
    revoked_recipients: Vec<[u8; SECRET_LEN]>,
}

impl RootFx {
    fn new(net: FakeNet) -> Self {
        let owner_pub = net.owner.enc.public();
        let (commitment, commitment_sig, grant_ledger) = net.owner.committed(0x00);
        Self {
            net,
            holds_owner_enc_secret: true,
            owner_pub,
            commitment,
            commitment_sig,
            grant_ledger,
            current_seed: [0x00; 32],
            write_scope_seed: [0x01; 32],
            pointer_read_key: scope_pointer_read_key(0x00),
            revoked_recipients: Vec::new(),
        }
    }

    /// The owner's cut removed `recipient` — carried down every descendant.
    fn revoking(mut self, recipient: [u8; SECRET_LEN]) -> Self {
        self.revoked_recipients.push(recipient);
        self
    }

    /// Withhold the owner encryption subkey — a re-sealer that can neither
    /// prove a recipient key nor read its own published seed back.
    fn keyless(mut self) -> Self {
        self.holds_owner_enc_secret = false;
        self
    }

    fn plan<'a>(&'a self, root_children: &'a [ChildScopeRef]) -> RotateScopePlan<'a> {
        RotateScopePlan {
            identity: ScopeRootIdentity {
                v: V,
                scope_id: sid(0x00),
                ipns_name: b"ipns-00",
                owner_enc_pub: &self.owner_pub,
                owner_enc_secret: self.holds_owner_enc_secret.then_some(&self.net.owner.enc),
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &self.net.owner.pseudonym,
            },
            committed: CommittedSet {
                commitment: &self.commitment,
                commitment_sig: &self.commitment_sig,
                grant_ledger: &self.grant_ledger,
                direct_child_scope_index: root_children,
                revoked_recipients: &self.revoked_recipients,
            },
            current_override_seed: &self.current_seed,
            current_read_epoch: 4,
            write_scope_seed: &self.write_scope_seed,
            write_epoch: 3,
            write_history_link: CARRIED_WRITE_HISTORY_LINK,
            pointer_read_key: &self.pointer_read_key,
            carried_history_links: &[],
        }
    }
}

/// What every cascade run hands back: the outcome, the fake network it ran
/// against, its floors, and the number of tasks it spawned.
type CascadeRun<F = InMemoryFloorStore> = (Result<CascadeOutcome, CascadeError>, FakeNet, F, usize);

fn run(net: FakeNet, root_children: &[u8]) -> CascadeRun {
    let root_index: Vec<ChildScopeRef> = root_children.iter().map(|b| childref(*b)).collect();
    run_with_index(net, root_index)
}

/// [`run`] with a caller-chosen root child index (custom `ipns_name` labels).
fn run_with_index(net: FakeNet, root_index: Vec<ChildScopeRef>) -> CascadeRun {
    run_fx(RootFx::new(net.clone()), net, root_index)
}

/// [`run_fx`] over a caller-built root fixture.
fn run_fx(fx: RootFx, net: FakeNet, root_index: Vec<ChildScopeRef>) -> CascadeRun {
    run_over(
        SeededEntropy::new(0xCA5CADE),
        InMemoryFloorStore::default(),
        fx,
        net,
        root_index,
    )
}

/// An [`InMemoryFloorStore`] that counts the revocation-namespace reads it
/// serves, so a test can measure the per-row cost rather than assume it.
#[derive(Clone, Default)]
struct CountingFloorStore {
    inner: InMemoryFloorStore,
    revocation_reads: Rc<Cell<usize>>,
}

impl FloorStore for CountingFloorStore {
    async fn epoch_floor(&self, key: &[u8]) -> crate::seams::SeamResult<Option<u64>> {
        if key.len() > sid(0).len() {
            self.revocation_reads.set(self.revocation_reads.get() + 1);
        }
        self.inner.epoch_floor(key).await
    }

    async fn raise_epoch_floor(&self, key: &[u8], epoch: u64) -> crate::seams::SeamResult<u64> {
        self.inner.raise_epoch_floor(key, epoch).await
    }

    async fn sequence_floor(&self, key: &[u8]) -> crate::seams::SeamResult<Option<u64>> {
        self.inner.sequence_floor(key).await
    }

    async fn raise_sequence_floor(
        &self,
        key: &[u8],
        sequence: u64,
    ) -> crate::seams::SeamResult<u64> {
        self.inner.raise_sequence_floor(key, sequence).await
    }

    async fn clear(&self) -> crate::seams::SeamResult<()> {
        self.inner.clear().await
    }
}

/// The one cascade run: a caller-chosen entropy seam and floor store, so a
/// test can pre-seed a revocation floor or make one refuse.
fn run_over<E: Entropy, F: FloorStore>(
    mut entropy: E,
    floors: F,
    fx: RootFx,
    net: FakeNet,
    root_index: Vec<ChildScopeRef>,
) -> CascadeRun<F> {
    let scheduler = VirtualScheduler::new();
    let outcome = block_on(async {
        let plan = fx.plan(&root_index);
        cascade_rotate_scope(&mut entropy, &floors, &scheduler, &net, &net, &plan, || {
            Box::pin(async {})
        })
        .await
    });
    let spawned = scheduler.take_spawned_tasks().len();
    (outcome, net, floors, spawned)
}

/// Mark `recipient` cut at scope `byte`, the way a past cascade at that
/// scope left the floor — the entry and the marker that gates the read.
fn cut_at(floors: &InMemoryFloorStore, byte: u8, recipient: &[u8; SECRET_LEN], epoch: u64) {
    block_on(floors.commit_floors(&[
        FloorRaise::epoch(revocation_floor_key(&sid(byte), recipient), epoch),
        FloorRaise::epoch(revocation_marker_key(&sid(byte)), epoch),
    ]))
    .expect("the revocation floor raises");
}

#[test]
fn a_descendant_the_owner_cut_at_that_descendant_gets_no_re_keyed_grant_blob() {
    // The cut here raises the per-recipient floor alone, so no `cutEpoch`
    // floor refuses the descendant's set and a pre-cut one the owner really
    // did sign still passes every gate stage. A current write grantee can
    // therefore republish a descendant root carrying it, at the live read
    // and write epochs. Bound to the record's own set alone, the cascade
    // would wrap the fresh read override seed straight back to the party
    // the owner cut there.
    let net = FakeNet::new().scope(0x0a, 4, &[0x0b]).scope(0x0b, 4, &[]);
    let revokee = net.owner.grantee.public().to_bytes();
    let floors = InMemoryFloorStore::default();
    cut_at(&floors, 0x0a, &revokee, 3);

    let (outcome, after, ..) = run_over(
        SeededEntropy::new(0xCA5CADE),
        floors,
        RootFx::new(net.clone()),
        net.clone(),
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade still runs — a skipped row aborts nothing");
    assert!(
        after.blob_tags(0x0a).is_empty(),
        "the descendant re-admitted the party the owner cut at it"
    );
    assert_eq!(
        after.blob_tags(0x0b).len(),
        1,
        "and a scope with no cut of its own keeps its grantee"
    );
}

#[test]
fn a_recipient_the_owner_granted_again_after_the_cut_is_re_keyed() {
    // The floor is monotonic and never clears, so a cut recorded once would
    // withhold the recipient for ever. An owner who grants again at the same
    // scope must be served, or the re-grant reads to that party as a
    // definitive revocation of a grant the owner just made.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let recipient = net.owner.grantee.public().to_bytes();
    let floors = InMemoryFloorStore::default();
    cut_at(&floors, 0x0a, &recipient, 3);

    // The owner's own grant path, at the epoch the re-grant published.
    block_on(record_grant_floor(
        &floors,
        &sid(0x0a),
        &net.owner.grantee.public(),
        4,
    ))
    .expect("the grant floor raises");

    let (outcome, after, ..) = run_over(
        SeededEntropy::new(0xCA5CADE),
        floors,
        RootFx::new(net.clone()),
        net.clone(),
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade runs");
    assert_eq!(
        after.blob_tags(0x0a).len(),
        1,
        "a cut older than the owner's newest grant must not still withhold"
    );
}

#[test]
fn a_grant_floor_lifts_only_the_recipient_it_names() {
    // The floor must never be raised from a resolved ledger: a re-key
    // withholds a blob without removing the row, and a write grantee can
    // republish a pre-cut owner-signed set, so a row in a ledger is no
    // evidence that the owner grants that recipient now. One grant lifts
    // one cut.
    let net = FakeNet::new().scope(0x0a, 4, &[]).scope(0x0b, 4, &[]);
    let cut_party = net.owner.grantee.public().to_bytes();
    let someone_else = X25519Secret::from_scalar([0x6b; 32]).public();
    let floors = InMemoryFloorStore::default();
    cut_at(&floors, 0x0a, &cut_party, 3);

    // The owner grants somebody else at the same scope.
    block_on(record_grant_floor(&floors, &sid(0x0a), &someone_else, 9))
        .expect("the grant floor raises");

    let (outcome, after, ..) = run_over(
        SeededEntropy::new(0xCA5CADE),
        floors,
        RootFx::new(net.clone()),
        net.clone(),
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade runs");
    assert!(
        after.blob_tags(0x0a).is_empty(),
        "a grant to another recipient must not lift this one's cut"
    );
}

#[test]
fn a_grant_at_the_cuts_own_epoch_lifts_it() {
    // The load-bearing boundary. A claim conversion re-seals at the scope's
    // current read epoch, and the cut recorded that same epoch, so a
    // legitimate re-grant always lands at equality. A strict comparison
    // here would withhold every re-grant.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let recipient = net.owner.grantee.public();
    let floors = InMemoryFloorStore::default();
    cut_at(&floors, 0x0a, &recipient.to_bytes(), 5);
    block_on(record_grant_floor(&floors, &sid(0x0a), &recipient, 5))
        .expect("the grant floor raises");

    let (outcome, after, ..) = run_over(
        SeededEntropy::new(0xCA5CADE),
        floors,
        RootFx::new(net.clone()),
        net.clone(),
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade runs");
    assert_eq!(
        after.blob_tags(0x0a).len(),
        1,
        "a grant at the cut's own epoch must lift it"
    );
}

#[test]
fn a_grant_older_than_the_cut_does_not_lift_it() {
    // The comparison is directional: only a grant at or above the cut's
    // epoch lifts it, so a stale grant record cannot re-admit a cut party.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let recipient = net.owner.grantee.public().to_bytes();
    let floors = InMemoryFloorStore::default();
    block_on(floors.raise_epoch_floor(&grant_floor_key(&sid(0x0a), &recipient), 2))
        .expect("the grant floor raises");
    cut_at(&floors, 0x0a, &recipient, 3);

    let (outcome, after, ..) = run_over(
        SeededEntropy::new(0xCA5CADE),
        floors,
        RootFx::new(net.clone()),
        net.clone(),
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade runs");
    assert!(
        after.blob_tags(0x0a).is_empty(),
        "a grant older than the cut must leave the cut standing"
    );
}

#[test]
fn a_descendant_that_independently_commits_the_cut_recipient_keeps_its_blob() {
    // The revokee holds an owner-issued grant at the root and a separate,
    // uncut one at the descendant. Carrying the root's cut down would take
    // the second with the first, and the descendant's own commitment still
    // names the tag, so its client would read the missing blob as a
    // definitive revocation of a grant the owner never touched.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let revokee = net.owner.grantee.public().to_bytes();
    let (outcome, after, ..) = run_fx(
        RootFx::new(net.clone()).revoking(revokee),
        net.clone(),
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade runs");
    assert_eq!(
        after.blob_tags(0x0a).len(),
        1,
        "the ancestor's cut revoked an independent grant one level down"
    );
}

#[test]
fn the_cut_the_cascade_drives_is_durable_at_the_scope_it_cuts() {
    // What closes the replay next time: the record cannot show that the
    // owner cut this recipient here, so the engine must remember it.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let revokee = net.owner.grantee.public().to_bytes();
    let (outcome, _, floors, _) = run_fx(
        RootFx::new(net.clone()).revoking(revokee),
        net.clone(),
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade runs");
    assert_eq!(
        block_on(floors.epoch_floor(&revocation_floor_key(&sid(0x00), &revokee)))
            .expect("floor read"),
        Some(5),
        "the root cut is recorded at the epoch it published"
    );
    assert_eq!(
        block_on(floors.epoch_floor(&revocation_floor_key(&sid(0x0a), &revokee)))
            .expect("floor read"),
        None,
        "and it is not recorded against a descendant the owner never cut"
    );
}

#[test]
fn no_two_epoch_namespace_key_shapes_collide() {
    // Five producers share the one epoch namespace: the read-epoch floor is
    // the bare scope id, `gate::floor` adds a `/write-epoch` and a
    // `/vault-pointer-index` suffix, and these two add theirs. Every pair
    // must differ for every scope.
    let scope = sid(0x0a);
    let other = sid(0x0b);
    let shapes = [
        scope.to_vec(),
        [scope.as_slice(), b"/write-epoch"].concat(),
        [scope.as_slice(), b"/vault-pointer-index"].concat(),
        [other.as_slice(), b"/vault-pointer-index"].concat(),
        revocation_marker_key(&scope),
        revocation_floor_key(&scope, &[0x07; SECRET_LEN]),
        revocation_floor_key(&scope, &[0x08; SECRET_LEN]),
        revocation_floor_key(&other, &[0x07; SECRET_LEN]),
        revocation_marker_key(&other),
        grant_floor_key(&scope, &[0x07; SECRET_LEN]),
        grant_floor_key(&scope, &[0x08; SECRET_LEN]),
        grant_floor_key(&other, &[0x07; SECRET_LEN]),
    ];
    for (i, a) in shapes.iter().enumerate() {
        for b in &shapes[i + 1..] {
            assert_ne!(a, b, "two distinct floors share one key");
        }
    }
}

#[test]
fn a_scope_with_no_recorded_cut_reads_one_floor_key() {
    // The per-row work is attacker-sized, so the marker must gate it. A
    // scope the owner never cut pays one read and no owner-recipient DH.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let floors = CountingFloorStore::default();
    let (outcome, _, floors, _) = run_over(
        SeededEntropy::new(0xCA5CADE),
        floors,
        RootFx::new(net.clone()),
        net,
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade runs");
    assert_eq!(
        floors.revocation_reads.get(),
        2,
        "one marker read per scope, and nothing per committed row"
    );
}

#[test]
fn a_floor_store_that_refuses_re_keys_nothing() {
    // Fail-closed: an engine that cannot read which recipients it already
    // cut must not publish a fresh seed wrapped to any of them.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let floors = InMemoryFloorStore::default();
    floors.fail_floor_reads();
    let (outcome, net, _, spawned) = run_over(
        SeededEntropy::new(0xCA5CADE),
        floors,
        RootFx::new(net.clone()),
        net,
        vec![childref(0x0a)],
    );
    assert!(matches!(
        outcome.expect_err("the refusal is fail-closed"),
        CascadeError::RevocationFloor { .. }
    ));
    assert!(
        net.published.borrow().is_empty(),
        "no scope root is published under an unreadable revocation floor"
    );
    assert_eq!(spawned, 0);
}

#[test]
fn a_cut_leaves_every_surviving_grantee_re_keyed() {
    // The cut names one recipient; a descendant committing a different one
    // must still receive its blob, or the cascade over-revokes.
    let survivor = [0x07; SECRET_LEN];
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let (outcome, net, ..) = run_fx(
        RootFx::new(net.clone()).revoking(survivor),
        net.clone(),
        vec![childref(0x0a)],
    );
    outcome.expect("the cascade runs");
    assert_eq!(
        net.blob_tags(0x0a).len(),
        1,
        "a recipient the cut never named keeps its re-keyed grant"
    );
}

#[test]
fn a_silent_entropy_seam_re_keys_nothing() {
    // Nothing downstream shadows the draw: the seed is minted before
    // `reseal_scope_root`, and the epoch's own history link would republish
    // the pre-cascade seed under it.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let (outcome, net, floors, spawned) = run_over(
        SilentEntropy,
        InMemoryFloorStore::default(),
        RootFx::new(net.clone()),
        net,
        vec![childref(0x0a)],
    );

    assert!(matches!(
        outcome.expect_err("the zero draw is refused"),
        CascadeError::Reseal {
            error: ResealError::Entropy(_),
            ..
        },
    ));
    assert!(
        net.published.borrow().is_empty(),
        "no scope root is published under a zero seed",
    );
    assert_eq!(block_on(floors.epoch_floor(&sid(0x00))).unwrap(), None);
    assert_eq!(spawned, 0);
}

#[test]
fn every_descendant_gets_a_distinct_fresh_seed_and_root_first() {
    // root(0x00) -> A(0x0a) -> B(0x0b); A also -> C(0x0c).
    let net = FakeNet::new()
        .scope(0x0a, 4, &[0x0b, 0x0c])
        .scope(0x0b, 4, &[])
        .scope(0x0c, 4, &[]);
    let (outcome, net, floors, spawned) = run(net, &[0x0a]);
    let outcome = outcome.expect("cascade completes");

    // Root re-keyed first, then all three descendants.
    assert_eq!(outcome.rekeyed[0].scope_id, sid(0x00));
    assert_eq!(outcome.descendant_count(), 3);
    let rekeyed: Vec<[u8; 16]> = outcome.rekeyed.iter().map(|r| r.scope_id).collect();
    for s in [0x00u8, 0x0a, 0x0b, 0x0c] {
        assert!(rekeyed.contains(&sid(s)), "scope {s:#x} re-keyed");
    }

    // Every re-keyed scope's published seed is FRESH (differs from its
    // pre-cascade seed) and DISTINCT across scopes.
    let mut seeds = Vec::new();
    for s in [0x0au8, 0x0b, 0x0c] {
        let fresh = net.published_seed(s);
        assert!(
            !ct_eq(&fresh, &net.pre_cascade_seed(s)),
            "scope {s:#x} got a fresh seed, not its old one"
        );
        seeds.push(fresh);
    }
    seeds.push(net.published_seed(0x00));
    for i in 0..seeds.len() {
        for j in (i + 1)..seeds.len() {
            assert!(!ct_eq(&seeds[i], &seeds[j]), "seeds {i}/{j} distinct");
        }
    }

    // Each scope's floor rose to its new epoch (4 -> 5), and one sweep enqueued.
    for s in [0x00u8, 0x0a, 0x0b, 0x0c] {
        assert_eq!(block_on(floors.epoch_floor(&sid(s))).unwrap(), Some(5));
    }
    assert_eq!(spawned, 1, "one sweep enqueued after the cascade");
}

#[test]
fn a_keyless_re_sealer_mints_nothing() {
    // The cascade reads each re-key's seed back out of the owner blob, so a
    // re-sealer without the owner encryption subkey can form no opinion on the
    // value it would thread down — and refuses at the root, before the mint.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let (outcome, net, floors, spawned) = run_fx(
        RootFx::new(net.clone()).keyless(),
        net,
        vec![childref(0x0a)],
    );

    let err = outcome.expect_err("a keyless re-sealer cannot check its own re-key");
    assert_eq!(err.check(), "owner-subkey-missing");
    assert_eq!(err.scope_id(), sid(0x00), "it refuses at the root");
    assert!(!err.is_retryable(), "no retry supplies the owner subkey");
    assert!(
        net.published.borrow().is_empty(),
        "nothing published on an unchecked re-key"
    );
    assert_eq!(block_on(floors.epoch_floor(&sid(0x00))).unwrap(), None);
    assert_eq!(spawned, 0);
}

#[test]
fn a_re_key_the_owner_cannot_read_back_is_never_published_release_active() {
    // The end-to-end reject row: a scope whose re-seal wraps its owner blob to
    // someone else publishes a record the owner cannot recover the threaded
    // seed from, so its descendants' ascent links would be minted under a
    // derivation no reader reproduces. The cascade refuses at that scope,
    // before its record lands — in a release build.
    let net = FakeNet::new()
        .scope(0x0a, 4, &[0x0b])
        .scope(0x0b, 4, &[])
        .stranger_owner_blob(0x0a);
    let (outcome, net, floors, spawned) = run(net, &[0x0a]);

    let err = outcome.expect_err("a re-key the owner cannot read back is refused");
    assert_eq!(err.check(), "unverified-threaded-seed");
    assert_eq!(err.scope_id(), sid(0x0a));
    assert!(!err.is_retryable(), "the same bytes reach the same verdict");
    let published = net.published.borrow();
    assert!(
        !published.contains_key(&sid(0x0a)),
        "the unreadable re-key never lands"
    );
    assert!(
        !published.contains_key(&sid(0x0b)),
        "and the walk never descends past it"
    );
    assert_eq!(block_on(floors.epoch_floor(&sid(0x0a))).unwrap(), None);
    assert_eq!(spawned, 0, "an aborted cascade enqueues no sweep");
}

#[test]
fn a_section_that_does_not_carry_the_minted_seed_is_refused_release_active() {
    // The reject row for the value the walk threads down: the record a re-key
    // publishes must carry the very seed its descendants' ascent links are
    // minted under, and any other seed — or the right seed read at the wrong
    // epoch — is refused, in a release build.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let (outcome, net, _floors, _spawned) = run(net, &[0x0a]);
    outcome.expect("the honest cascade completes");

    let minted = net.published_seed(0x0a);
    let published = net.published.borrow();
    let record = published.get(&sid(0x0a)).expect("the descendant published");
    let row = |read_epoch, seed: &[u8; SECRET_LEN]| {
        publishes_minted_seed(
            &net.owner.enc,
            V,
            record.scope_id,
            read_epoch,
            &record.section,
            seed,
        )
    };
    assert!(
        row(record.read_epoch, &minted),
        "the record carries the seed it was sealed with"
    );
    assert!(
        !row(record.read_epoch, &[0x57; SECRET_LEN]),
        "any other seed is refused"
    );
    assert!(
        !row(record.read_epoch + 1, &minted),
        "and so is the right seed read at the wrong epoch"
    );
}

#[test]
fn revocation_is_a_fresh_seed_cascade_not_an_epoch_bump() {
    // THE cross-slice invariant: revocation re-keys descendants via a FRESH
    // seed, never via floor-raise + sweep. A sweep would reuse the existing
    // seed (prev = None): the published seed would EQUAL the pre-cascade seed
    // and NO fresh history link would be appended. The cascade instead mints a
    // fresh seed (published seed CHANGES) and ratchets one history link — which
    // is exactly what locks out a reader holding the old descendant seed.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let (outcome, net, _floors, _spawned) = run(net, &[0x0a]);
    outcome.expect("cascade completes");

    let old = net.pre_cascade_seed(0x0a);
    let published = net.published_seed(0x0a);
    assert!(
        !ct_eq(&published, &old),
        "a sweep would keep the old seed; the cascade minted a fresh one"
    );
    assert_eq!(net.published_epoch(0x0a), 5, "epoch bumped 4 -> 5");
    assert_eq!(
        net.history_len(0x0a),
        1,
        "the fresh-seed ratchet appended one history link (a sweep appends none)"
    );
}

#[test]
fn old_descendant_seed_holder_is_locked_out() {
    // A reader who cached A's OLD seed can derive keys only from that seed.
    // Post-cascade, A's records seal under a FRESH seed, so every key the old
    // seed derives is stale — the reader is locked out. Proven at the seed
    // level: the published seed differs, so read_key(node_seed(old, id)) can no
    // longer match the current record's key.
    let net = FakeNet::new().scope(0x0a, 4, &[]);
    let (outcome, net, _f, _s) = run(net, &[0x0a]);
    outcome.expect("completes");

    let old = net.pre_cascade_seed(0x0a);
    let fresh = net.published_seed(0x0a);
    let id = sid(0x0a);
    let old_read_key = kdf::read_key(kdf::node_seed(&old, &id).as_bytes());
    let fresh_read_key = kdf::read_key(kdf::node_seed(&fresh, &id).as_bytes());
    assert!(
        !ct_eq(old_read_key.as_bytes(), fresh_read_key.as_bytes()),
        "the cached old seed no longer derives A's current read key"
    );
}

#[test]
fn parent_child_seed_threading_is_correct() {
    // root -> A(0x0a) -> B(0x0b). B's published ascent link must open ONLY under
    // node_seed(A_fresh_seed, B_scope_id) — the parent's NEW derivation — and
    // NOT under node_seed(A_old_seed, B_scope_id). This is the threading proof
    // AND the ancestor-path lockout: an ancestor holding A's old derivation
    // cannot reach B.
    let net = FakeNet::new().scope(0x0a, 4, &[0x0b]).scope(0x0b, 4, &[]);
    let (outcome, net, _f, _s) = run(net, &[0x0a]);
    outcome.expect("completes");

    let a_fresh = net.published_seed(0x0a);
    let a_old = net.pre_cascade_seed(0x0a);
    let b_id = sid(0x0b);
    let b_fresh = net.published_seed(0x0b);

    let under_new = kdf::node_seed(&a_fresh, &b_id);
    let recovered = net
        .ascent_seed_under(0x0b, under_new.as_bytes())
        .expect("B's ascent opens under A's NEW parent derivation");
    assert!(
        ct_eq(&recovered, &b_fresh),
        "the ascent link carries B's fresh override seed"
    );

    let under_old = kdf::node_seed(&a_old, &b_id);
    assert!(
        net.ascent_seed_under(0x0b, under_old.as_bytes()).is_none(),
        "B's ascent must NOT open under A's stale parent derivation"
    );
}

#[test]
fn diamond_descendant_rekeyed_once_under_first_seen_parent() {
    // Test E (regression): root -> A(0x0a), B(0x0b); both A and B list D(0x0d)
    // with the SAME ipns_name (childref). D is re-keyed exactly once, threaded
    // from the canonically-first parent A (0x0a < 0x0b) — no C2 abort.
    let net = FakeNet::new()
        .scope(0x0a, 4, &[0x0d])
        .scope(0x0b, 4, &[0x0d])
        .scope(0x0d, 4, &[]);
    let (outcome, net, _f, _s) = run(net, &[0x0a, 0x0b]);
    let outcome = outcome.expect("diamond completes");

    // A, B, D each appear exactly once (plus the root).
    let mut ids: Vec<[u8; 16]> = outcome.rekeyed.iter().map(|r| r.scope_id).collect();
    ids.sort();
    assert_eq!(ids, vec![sid(0x00), sid(0x0a), sid(0x0b), sid(0x0d)]);

    // D threads from A (first-seen), not B: its ascent opens under
    // node_seed(A_fresh, D) and not node_seed(B_fresh, D).
    let a_fresh = net.published_seed(0x0a);
    let b_fresh = net.published_seed(0x0b);
    let d_id = sid(0x0d);
    assert!(
        net.ascent_seed_under(0x0d, kdf::node_seed(&a_fresh, &d_id).as_bytes())
            .is_some(),
        "D threads from first-seen parent A"
    );
    assert!(
        net.ascent_seed_under(0x0d, kdf::node_seed(&b_fresh, &d_id).as_bytes())
            .is_none(),
        "D does not thread from the later parent B"
    );
}

#[test]
fn c2_conflicting_ipns_name_aborts_fail_closed_permutation_independent() {
    // Test B (C2): root -> A(0x0a), B(0x0b); both list D(0x0d) but under
    // DIFFERENT ipns_name labels. First-seen would be a coin-flip that could
    // re-key a dead name and leave the real D unrotated — a revocation hole —
    // so the walk aborts fail-closed naming D, identically under either parent
    // order (the frontier is canonicalized, so A is always seen before B).
    let build = || {
        FakeNet::new()
            .scope_refs(0x0a, 4, vec![childref_named(0x0d, "ipns-0d")])
            .scope_refs(0x0b, 4, vec![childref_named(0x0d, "ipns-old")])
            .scope(0x0d, 4, &[])
    };
    let forward = run_with_index(build(), vec![childref(0x0a), childref(0x0b)]).0;
    let reversed = run_with_index(build(), vec![childref(0x0b), childref(0x0a)]).0;

    let fwd = forward.expect_err("conflict aborts");
    let rev = reversed.expect_err("conflict aborts");
    assert_eq!(fwd, rev, "abort is permutation-independent");
    assert_eq!(fwd.check(), "resolve-failed");
    assert_eq!(fwd.scope_id(), sid(0x0d), "the conflict names scope D");
    assert!(
        fwd.is_retryable(),
        "a label conflict is retryable (re-point wave)"
    );
}

#[test]
fn c2_conflict_is_retryable_and_succeeds_after_repoint_wave() {
    // Test C (legitimate mid-wave): parent A points D at its new name while B is
    // not-yet-repaired (still the stale name) -> C2 abort, retryable. Once the
    // re-point wave repairs B to the same name, a retried walk resolves D once.
    let mid_wave = FakeNet::new()
        .scope_refs(0x0a, 4, vec![childref_named(0x0d, "ipns-0d")])
        .scope_refs(0x0b, 4, vec![childref_named(0x0d, "ipns-old")])
        .scope(0x0d, 4, &[]);
    let (out, _net, _f, spawned) = run_with_index(mid_wave, vec![childref(0x0a), childref(0x0b)]);
    let err = out.expect_err("mid-wave conflict aborts");
    assert_eq!(err.scope_id(), sid(0x0d));
    assert!(
        err.is_retryable(),
        "converges once the re-point wave repairs B"
    );
    assert_eq!(spawned, 0, "no sweep enqueued on a fail-closed abort");

    // After the wave: both parents agree on D's current committed name.
    let repaired = FakeNet::new()
        .scope_refs(0x0a, 4, vec![childref_named(0x0d, "ipns-0d")])
        .scope_refs(0x0b, 4, vec![childref_named(0x0d, "ipns-0d")])
        .scope(0x0d, 4, &[]);
    let (out, net, _f, spawned) = run_with_index(repaired, vec![childref(0x0a), childref(0x0b)]);
    let outcome = out.expect("repaired walk completes");
    let d_rekeys = outcome
        .rekeyed
        .iter()
        .filter(|r| r.scope_id == sid(0x0d))
        .count();
    assert_eq!(d_rekeys, 1, "D re-keyed exactly once at the agreed name");
    assert!(
        !ct_eq(&net.published_seed(0x0d), &[0x0d; 32]),
        "D got a fresh seed"
    );
    assert_eq!(spawned, 1, "the repaired cascade enqueues the sweep");
}

#[test]
fn attacker_label_without_commitment_binding_is_fatal() {
    // Test D: A lists D(0x0d) under an attacker-chosen ipns_name that no
    // owner-signed commitment binds. There is no conflict (a single label), so
    // the record resolves — and the gate rejects it because the commitment does
    // not bind that name. Trust rests on the owner-signed commitment, not the
    // parent label: the reject is FATAL, not a retryable stall.
    let net = FakeNet::new()
        .scope_refs(0x0a, 4, vec![childref_named(0x0d, "ipns-attacker")])
        .scope(0x0d, 4, &[]);
    let (out, _net, _f, spawned) = run_with_index(net, vec![childref(0x0a)]);
    let err = out.expect_err("attacker label is rejected");
    assert_eq!(err.check(), "resolve-failed");
    assert_eq!(err.scope_id(), sid(0x0d));
    assert!(!err.is_retryable(), "a commitment-gate rejection is fatal");
    assert_eq!(spawned, 0);
}

#[test]
fn cycle_back_edge_terminates() {
    // A -> B -> A (a corrupt/adversarial back-edge). The cascade must terminate
    // and re-key A and B once each.
    let net = FakeNet::new()
        .scope(0x0a, 4, &[0x0b])
        .scope(0x0b, 4, &[0x0a]);
    let (outcome, _net, _f, _s) = run(net, &[0x0a]);
    let outcome = outcome.expect("cyclic index terminates");
    assert_eq!(outcome.descendant_count(), 2);
}

#[test]
fn unresolvable_descendant_aborts_fail_closed() {
    // root -> A -> B, but B fails the adoption gate. The cascade must abort,
    // naming B — never report a partial revoke as complete. This encode-side
    // fail-closed guard is release-active (a runtime `Err`, not a debug_assert).
    let net = FakeNet::new()
        .scope(0x0a, 4, &[0x0b])
        .scope(0x0b, 4, &[])
        .resolve_fault(0x0b, ResolveFailure::Rejected);
    let (outcome, _net, floors, spawned) = run(net, &[0x0a]);
    let err = outcome.expect_err("rejected descendant fails closed");
    assert_eq!(err.check(), "resolve-failed");
    assert_eq!(err.scope_id(), sid(0x0b));
    assert!(!err.is_retryable(), "a gate rejection is fatal");
    // No sweep enqueued on an aborted cascade (the enqueue is the last step).
    assert_eq!(spawned, 0, "no sweep enqueued on a fail-closed abort");
    // B never floored (it never published).
    assert_eq!(block_on(floors.epoch_floor(&sid(0x0b))).unwrap(), None);
}

#[test]
fn publish_not_landed_aborts_fail_closed() {
    // A descendant whose re-key does not land aborts the cascade — a revocation
    // that cannot install the fresh seed is a hole, not a tolerated drop.
    let net = FakeNet::new()
        .scope(0x0a, 4, &[])
        .publish_fault(0x0a, RotationPublishError::NotPublished);
    let (outcome, _net, _f, spawned) = run(net, &[0x0a]);
    let err = outcome.expect_err("unpublished descendant fails closed");
    assert_eq!(err.check(), "publish-failed");
    assert_eq!(err.scope_id(), sid(0x0a));
    assert!(err.is_retryable(), "not-landed is an availability stall");
    assert_eq!(spawned, 0);
}

/// A publisher that refuses the bytes has made its own fail-closed verdict,
/// so the abort is fatal — retrying it forever would launder a trust
/// violation into an availability stall (AGENTS.md rule 6).
#[test]
fn a_publish_the_publisher_refused_is_fatal_not_retryable() {
    let net = FakeNet::new()
        .scope(0x0a, 4, &[])
        .publish_fault(0x0a, RotationPublishError::Rejected);
    let (outcome, _net, _f, spawned) = run(net, &[0x0a]);
    let err = outcome.expect_err("a refused publish fails closed");
    assert_eq!(err.check(), "publish-failed");
    assert!(!err.is_retryable());
    assert_eq!(spawned, 0);
}

#[test]
fn lost_race_aborts_unlike_the_sweep() {
    // A lost CAS race aborts the revocation cascade (the fresh seed did not
    // install), where the idempotent sweep would merely drop and re-resolve.
    let net = FakeNet::new()
        .scope(0x0a, 4, &[])
        .publish_fault(0x0a, RotationPublishError::LostRace);
    let (outcome, _net, _f, _s) = run(net, &[0x0a]);
    let err = outcome.expect_err("lost race aborts the cascade");
    assert_eq!(err.check(), "publish-failed");
    assert_eq!(err.scope_id(), sid(0x0a));
}

#[test]
fn epoch_exhausted_descendant_aborts_release_active() {
    // A descendant at u64::MAX cannot bump without reusing the epoch with fresh
    // key material (a key-regression violation). Release-active fail-closed:
    // a runtime `Err`, never a debug_assert.
    let net = FakeNet::new().scope(0x0a, u64::MAX, &[]);
    let (outcome, net, _f, spawned) = run(net, &[0x0a]);
    let err = outcome.expect_err("exhausted epoch fails closed");
    assert_eq!(err.check(), "epoch-exhausted");
    assert_eq!(err.scope_id(), sid(0x0a));
    assert!(!err.is_retryable());
    assert_eq!(spawned, 0);
    // Nothing published for A on an exhausted epoch.
    assert!(!net.published.borrow().contains_key(&sid(0x0a)));
}

#[test]
fn re_run_is_deterministic_and_locks_out_each_time() {
    // Idempotence/re-run safety consistent with the rotation module: two runs
    // over the same tree and entropy seed produce byte-identical published
    // seeds, and every run mints fresh seeds (a re-run never resurrects an old
    // seed).
    let build = || {
        let net = FakeNet::new().scope(0x0a, 4, &[0x0b]).scope(0x0b, 4, &[]);
        let (outcome, net, _f, _s) = run(net, &[0x0a]);
        outcome.expect("completes");
        (net.published_seed(0x0a), net.published_seed(0x0b))
    };
    let (a1, b1) = build();
    let (a2, b2) = build();
    assert!(
        ct_eq(&a1, &a2) && ct_eq(&b1, &b2),
        "same seed → same fresh seeds"
    );
    assert!(!ct_eq(&a1, &[0x0a; 32]), "A never keeps its old seed");
    assert!(!ct_eq(&b1, &[0x0b; 32]), "B never keeps its old seed");
}

#[test]
fn leaf_root_with_no_descendants_still_rekeys_root_and_enqueues_sweep() {
    let net = FakeNet::new();
    let (outcome, net, floors, spawned) = run(net, &[]);
    let outcome = outcome.expect("leaf root completes");
    assert_eq!(outcome.descendant_count(), 0);
    assert_eq!(outcome.rekeyed[0].scope_id, sid(0x00));
    assert_eq!(block_on(floors.epoch_floor(&sid(0x00))).unwrap(), Some(5));
    assert_eq!(spawned, 1);
    assert!(!ct_eq(&net.published_seed(0x00), &[0x00; 32]));
}
