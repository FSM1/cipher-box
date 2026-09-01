//! Convergence across the owner's own devices once a cut has made an interior
//! folder a scope root of its own: the browser tab writes inside it, and the
//! mounted desktop must see what it published.
//!
//! Every assertion lands on published bytes, a drained queue, or a rendered
//! view — what the other device would see.

use core::task::{Context, Poll, Waker};

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{
    GrantSection, GrantSetCommitment, PreservedFields, ReadBody, decode_envelope,
    decode_grant_section, grant_section_bytes, open_read_body, sign_grant_set,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;

use cipherbox_engine::net::author::{
    ENVELOPE_V, EnvelopeAuthoring, author_scope_root_with_section,
};
use cipherbox_engine::rotation::published_override_seed;
use cipherbox_engine::seams::{BoxedTask, OpId, RecordTransport, StagingStore};
use cipherbox_engine::sync::SessionRole;
use cipherbox_engine::sync::pointer::{seal_repoint, vault_pointer_name};
use cipherbox_engine::testkit::account::{
    Blocks, EOL, POINTER_PAYLOAD_VERSION, ROOT, SCOPE, SECRET, TTL_NANOS, owner_identity,
    serve_http,
};
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH as EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    SeededEntropy, block_on, poll_tasks_until_parked,
};
use cipherbox_engine::{
    ApiBaseUrl, Command, CommandOutcome, CommittedSet, ContentProfile, DeadLetterReason, Engine,
    EngineError, Event, EventStream, GatewayConfig, LoginSecret, NodeId, NodeKind, Permission,
    ResealSeeds, ScopeRootIdentity, StoragePolicy, SyncTimingProfile, WriteHistory,
    reseal_scope_root,
};

/// The contact the owner grants to — a second account, so the cut the grant
/// performs is the real one and not a self-share.
const RECIPIENT_SECRET: [u8; 32] = [0x5B; 32];
/// Seal-input seeds held apart so no two plaintexts share a (key, nonce) pair
/// (blueprint/core.md "Crypto suite").
const POINTER_SEAL_ENTROPY_SEED: u64 = 0;
const ROOT_SEAL_ENTROPY_SEED: u64 = 1;
const ROOT_BODY_NONCE: [u8; 24] = [0x31; 24];

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn secret() -> LoginSecret {
    LoginSecret::new(SECRET.to_vec())
}

fn engine_on_api(device: &FakeDevice, entropy_seed: u64) -> (Engine<FakeSeamTypes>, EventStream) {
    Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(entropy_seed)),
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy::CI,
        ApiBaseUrl::parse("http://api.test").expect("a base"),
        GatewayConfig {
            accelerator: Some("https://gw.test".into()),
            public_fallbacks: Vec::new(),
        },
    )
}

/// The owner's writer pseudonym for `SCOPE`: a re-seal signed by a key the
/// committed set does not name is refused, so the seeded root commits this one.
fn owner_pseudonym() -> Ed25519Signer {
    kdf::pseudonym_sign(kdf::owner_pseudonym_seed(&SECRET).as_bytes(), &SCOPE)
}

fn owner_pointer_read_key() -> [u8; 32] {
    *kdf::pointer_read_key(kdf::owner_pointer_seed(&SECRET).as_bytes(), &SCOPE).as_bytes()
}

/// Publish the account's initial state: an empty owner root at sequence 1 whose
/// committed set is the owner's own, and the vault pointer naming it.
fn seed_vault(world: &FakeWorld, blocks: &Blocks) -> IpnsName {
    let owner_identity = owner_identity();
    let pseudonym = owner_pseudonym();
    let owner_enc = kdf::enc_subkey(&SECRET);
    let owner_enc_pub = owner_enc.public();
    let name = write_name(ROOT);

    let commitment = GrantSetCommitment {
        ipns_name: name.as_str().as_bytes().to_vec(),
        owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
        cut_epoch: 0,
        entries: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(&owner_identity, &commitment)
        .expect("the owner signs its own grant set")
        .to_compact();
    let pointer_read_key = owner_pointer_read_key();
    let section = reseal_scope_root(
        &mut SeededEntropy::new(ROOT_SEAL_ENTROPY_SEED),
        &ScopeRootIdentity {
            v: ENVELOPE_V,
            scope_id: SCOPE,
            ipns_name: name.as_str().as_bytes(),
            owner_enc_pub: &owner_enc_pub,
            owner_enc_secret: Some(&owner_enc),
            ascent: None,
            owes_ascent_link: false,
            pseudonym_signer: &pseudonym,
        },
        &ResealSeeds {
            override_seed: &READ_SCOPE_SEED,
            read_epoch: EPOCH,
            prev: None,
            write_scope_seed: &WRITE_SCOPE_SEED,
            write_epoch: EPOCH,
            write_history: WriteHistory::Carried(&[]),
            pointer_read_key: &pointer_read_key,
        },
        &CommittedSet {
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &[],
            direct_child_scope_index: &[],
            revoked_recipients: &[],
        },
        &[],
    )
    .expect("the seeded root seals");

    let head = author_scope_root_with_section(
        EnvelopeAuthoring {
            node_id: ROOT.0,
            scope_id: SCOPE,
            epoch: EPOCH,
            read_key: &read_key_under(&READ_SCOPE_SEED, ROOT),
            nonce: &ROOT_BODY_NONCE,
            body: &ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children: Vec::new(),
                unknown: PreservedFields::new(),
            },
            carried_unknown: PreservedFields::new(),
            carried_epoch_tag_unknown: PreservedFields::new(),
        },
        &name,
        &section,
        &owner_identity.verifying_key(),
    )
    .expect("the seeded root authors");
    blocks.put(head.block.clone());

    let root_signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &ROOT.0).as_bytes());
    let root_record = IpnsRecord::create_v2(
        &root_signer,
        format!("/ipfs/{}", head.cid).as_bytes(),
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();

    let pointer_block = seal_repoint(
        SessionRole::Owner,
        &mut SeededEntropy::new(POINTER_SEAL_ENTROPY_SEED),
        &pointer_read_key,
        POINTER_PAYLOAD_VERSION,
        &owner_identity,
        &RepointObject {
            scope_id: SCOPE,
            current_root: name.clone(),
            write_epoch: EPOCH,
            min_read_epoch: EPOCH,
            prev_root: None,
        },
    )
    .expect("seal the re-point");
    let pointer_name = vault_pointer_name(&SECRET, 0);
    let pointer_record = IpnsRecord::create_v2(
        &kdf::vault_pointer_index(&SECRET, 0),
        &pointer_block,
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();

    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), root_record.clone());
        world
            .record_store
            .seed_record(&endpoint, pointer_name.as_str(), pointer_record.clone());
    }
    name
}

/// A cold-started session on `device`, loops parked at their first sleep.
fn boot(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    entropy_seed: u64,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    serve_http(device, blocks, 600);
    let (mut engine, events) = engine_on_api(device, entropy_seed);
    block_on(engine.start(secret())).expect("cold start adopts the owner root");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    (engine, events, tasks)
}

/// Run one resolve-tick interval, which is also one drain pass.
fn tick(world: &FakeWorld, engine: &Engine<FakeSeamTypes>, tasks: &mut [BoxedTask]) {
    world.scheduler.advance(engine.profile().poll_cadence);
    poll_tasks_until_parked(tasks);
}

/// Drive one command to completion with the spawned loops running beside it —
/// what a manual refresh needs, since it parks on the pass the tick loop runs.
fn command_while_ticking(
    engine: &mut Engine<FakeSeamTypes>,
    command: Command,
    tasks: &mut [BoxedTask],
) -> Result<CommandOutcome, EngineError> {
    let mut pending = Box::pin(engine.command(command));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(outcome) = pending.as_mut().poll(&mut cx) {
            return outcome;
        }
        poll_tasks_until_parked(tasks);
    }
    panic!("the command never settled against the running loops");
}

/// Create `name` under `parent` and drive it to the record plane.
fn create_published_folder(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    parent: NodeId,
    name: &str,
) -> NodeId {
    block_on(engine.command(Command::Create {
        parent,
        name: name.into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages");
    tick(world, engine, tasks);
    listed(engine, parent)
        .into_iter()
        .find(|(child_name, _)| child_name == name)
        .unwrap_or_else(|| panic!("no child named {name}"))
        .1
}

/// The `(name, id)` pairs a device's rendered view lists under `parent`.
fn listed(engine: &Engine<FakeSeamTypes>, parent: NodeId) -> Vec<(String, NodeId)> {
    block_on(engine.view())
        .expect("a rendered view")
        .children(parent)
        .into_iter()
        .map(|child| (child.name, child.id))
        .collect()
}

/// The names a device's rendered view lists under `parent`, sorted.
fn listed_names(engine: &Engine<FakeSeamTypes>, parent: NodeId) -> Vec<String> {
    let mut names: Vec<String> = listed(engine, parent)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    names.sort();
    names
}

/// Every event the engine has emitted and not yet been read.
fn events_so_far(events: &mut EventStream) -> Vec<Event> {
    let mut out = Vec::new();
    while let Some(event) = events.try_next() {
        out.push(event);
    }
    out
}

/// Why `op` was abandoned, over the events emitted since the last read.
fn dead_letters(events: &mut EventStream, op: OpId) -> Vec<DeadLetterReason> {
    events_so_far(events)
        .into_iter()
        .filter_map(|event| match event {
            Event::DeadLetter { op_id, reason } if op_id == op => Some(reason),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Record-plane inspection
// ---------------------------------------------------------------------------

/// A node's write-plane IPNS name under the vault's own write scope seed.
fn write_name(node: NodeId) -> IpnsName {
    IpnsName::from_public_key(
        &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes()).verifying_key(),
    )
}

/// A node's per-node read key under `scope_seed`.
fn read_key_under(scope_seed: &[u8; 32], node: NodeId) -> [u8; 32] {
    *kdf::read_key(kdf::node_seed(scope_seed, &node.0).as_bytes()).as_bytes()
}

/// The head block published at `name`, verified under that name.
fn published_head(world: &FakeWorld, blocks: &Blocks, name: &IpnsName) -> Option<Vec<u8>> {
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())?;
    let verified = IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(name))
        .expect("the published record verifies under its own name");
    let cid = core::str::from_utf8(&verified.value)
        .expect("utf8 value")
        .strip_prefix("/ipfs/")
        .expect("an /ipfs/ pointer");
    Some(blocks.get(cid).expect("the head block is on the plane"))
}

/// The grant section published at `name`, if the record there is a scope root.
fn published_grant_section(
    world: &FakeWorld,
    blocks: &Blocks,
    name: &IpnsName,
) -> Option<GrantSection> {
    let head = published_head(world, blocks, name)?;
    let envelope = decode_envelope(&head).expect("the head decodes");
    grant_section_bytes(&envelope).map(|bytes| decode_grant_section(bytes).expect("it decodes"))
}

/// The read-scope seed the scope root published at `scope` currently hands its
/// owner — the seed every node below it is sealed under.
fn owner_scope_seed(world: &FakeWorld, blocks: &Blocks, scope: NodeId) -> [u8; 32] {
    let name = write_name(scope);
    let head = published_head(world, blocks, &name).expect("a published scope root");
    let envelope = decode_envelope(&head).expect("the head decodes");
    let section =
        published_grant_section(world, blocks, &name).expect("the record answers as a scope root");
    *published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        scope.0,
        envelope.epoch,
        &section,
    )
    .expect("the owner blob yields the scope's override seed")
}

/// The child names the record published at `node` seals, opened under
/// `scope_seed`.
fn published_names(
    world: &FakeWorld,
    blocks: &Blocks,
    scope_seed: &[u8; 32],
    node: NodeId,
) -> Vec<String> {
    let head = published_head(world, blocks, &write_name(node)).expect("a published record");
    let envelope = decode_envelope(&head).expect("the head decodes");
    let ReadBody::Folder { children, .. } =
        open_read_body(&envelope, &read_key_under(scope_seed, node))
            .expect("the body opens under the scope's own read seed")
    else {
        panic!("expected a folder body");
    };
    let mut names: Vec<String> = children.iter().map(|child| child.name.clone()).collect();
    names.sort();
    names
}

/// The ops still sitting in `device`'s durable queue.
fn queued(device: &FakeDevice) -> usize {
    block_on(StagingStore::queued_ops(&device.staging_store))
        .expect("the queue reads")
        .len()
}

// ---------------------------------------------------------------------------
// The contact a grant cuts for
// ---------------------------------------------------------------------------

fn recipient_identity() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&RECIPIENT_SECRET).expect("valid identity scalar")
}

/// Import the recipient, which is the only thing that makes their encryption
/// subkey usable as a grant target.
fn import_recipient(engine: &mut Engine<FakeSeamTypes>) {
    let code = ContactCode::create(
        &recipient_identity(),
        kdf::enc_subkey(&RECIPIENT_SECRET).public(),
    )
    .encode();
    block_on(engine.command(Command::ImportContact { contact_code: code }))
        .expect("the recipient's code imports");
}

/// Grant `node` to the imported recipient — the cut that promotes a folder to a
/// nested scope root.
fn grant_to_recipient(engine: &mut Engine<FakeSeamTypes>, node: NodeId) {
    assert_eq!(
        block_on(engine.command(Command::Grant {
            node,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done),
        "the grant cuts the folder into a scope root of its own"
    );
}

// ---------------------------------------------------------------------------
// A folder a grant promoted to a scope root of its own
// ---------------------------------------------------------------------------

/// The tab writes inside a folder its own grant just cut into a nested scope
/// root. The write is the owner's, on the owner's own vault, so it has to reach
/// the record plane and then the owner's other device.
#[test]
#[ignore = "this build reads and writes one scope per session: the child gate refuses a \
            record carrying a grant section, and the drain opens one scope's material, so \
            an owner's own nested scope root is unreachable from either plane"]
fn a_folder_created_inside_a_granted_scope_root_reaches_the_owners_second_device() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    // Device T: the browser tab, addressed at the owner's own identity key.
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, mut events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");

    import_recipient(&mut engine_t);
    grant_to_recipient(&mut engine_t, shared);
    assert!(
        published_grant_section(&world, &blocks, &write_name(shared)).is_some(),
        "the folder now answers as a scope root"
    );

    // The write inside the promoted scope.
    let op = block_on(engine_t.command(Command::Create {
        parent: shared,
        name: "2026".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a create inside the granted folder stages")
    .op_id()
    .expect("a create queues an op");
    let _ = events_so_far(&mut events_t);
    // More passes than the attempt budget: a write that neither lands nor
    // dead-letters is jammed on an uncharged halt, with nothing surfaced.
    for _ in 0..8 {
        tick(&world, &engine_t, &mut tasks_t);
    }

    assert_eq!(
        dead_letters(&mut events_t, op),
        Vec::new(),
        "no reason to abandon the owner's own write"
    );
    assert_eq!(
        queued(&tab),
        0,
        "the owner's own write below a nested scope root drains"
    );
    let scope_seed = owner_scope_seed(&world, &blocks, shared);
    assert_eq!(
        published_names(&world, &blocks, &scope_seed, shared),
        ["2026"],
        "and the promoted root publishes the child that names it"
    );

    // Device M: the mounted desktop, which only ever saw the network.
    let mount = world.device(b"mounted-desktop");
    let (mut engine_m, _events_m, mut tasks_m) = boot(&world, &blocks, &mount, 7);
    block_on(engine_m.command(Command::SetFocus { node: Some(shared) }))
        .expect("focus moves to the granted folder");
    let refreshed = command_while_ticking(&mut engine_m, Command::ManualRefresh, &mut tasks_m);
    assert!(
        refreshed.is_ok(),
        "the focus refresh reads the granted folder's own record: {refreshed:?}"
    );
    tick(&world, &engine_m, &mut tasks_m);

    assert_eq!(
        listed_names(&engine_m, shared),
        ["2026"],
        "the owner's second device lists what the tab published inside the cut scope"
    );
}

/// The read half on its own: the child predates the cut, so nothing has to
/// publish below the promoted root for the second device to render it. Only the
/// child-record read path stands between the mount and the folder's contents.
#[test]
#[ignore = "this build reads one scope per session: the child gate refuses a record \
            carrying a grant section, so an owner's own nested scope root never opens"]
fn a_folder_that_predates_a_grant_lists_on_the_owners_second_device() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    create_published_folder(&world, &mut engine_t, &mut tasks_t, shared, "2026");

    import_recipient(&mut engine_t);
    grant_to_recipient(&mut engine_t, shared);

    let mount = world.device(b"mounted-desktop");
    let (mut engine_m, _events_m, mut tasks_m) = boot(&world, &blocks, &mount, 7);
    block_on(engine_m.command(Command::SetFocus { node: Some(shared) }))
        .expect("focus moves to the granted folder");
    let refreshed = command_while_ticking(&mut engine_m, Command::ManualRefresh, &mut tasks_m);
    assert!(
        refreshed.is_ok(),
        "the focus refresh reads the granted folder's own record: {refreshed:?}"
    );
    tick(&world, &engine_m, &mut tasks_m);

    assert_eq!(
        listed_names(&engine_m, shared),
        ["2026"],
        "the promoted root's own children still render on a device that only read them"
    );
}

// ---------------------------------------------------------------------------
// A write staged across a cut that re-keyed its scope
// ---------------------------------------------------------------------------

/// A cut raises the scope's read-epoch floor, and the lazy wave has swept none
/// of the interior nodes yet. A write already staged against one of them is the
/// user's own, on the user's own scope: the drain must publish it, not refuse
/// it as a trust violation and burn its attempt budget.
#[test]
fn a_write_staged_across_a_cut_publishes_rather_than_dead_lettering() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let mount = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &mount, 42);
    let reports = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");

    // Staged, not yet drained: the op is in the durable queue when the cut runs.
    let op = block_on(engine.command(Command::Create {
        parent: reports,
        name: "q3".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a create stages")
    .op_id()
    .expect("a create queues an op");
    assert_eq!(queued(&mount), 1);

    assert_eq!(
        block_on(engine.command(Command::RotateNow { node: ROOT })),
        Ok(CommandOutcome::Done),
        "the cut re-keys the scope the staged op writes into"
    );
    let _ = events_so_far(&mut events);

    // More passes than the attempt budget, so a charged halt has dead-lettered
    // by the time this loop ends.
    for _ in 0..8 {
        tick(&world, &engine, &mut tasks);
    }

    assert_eq!(
        dead_letters(&mut events, op),
        Vec::new(),
        "a good write is not abandoned because its scope was re-keyed under it"
    );
    assert_eq!(queued(&mount), 0, "the staged op drains after the cut");
    let scope_seed = owner_scope_seed(&world, &blocks, ROOT);
    assert_eq!(
        published_names(&world, &blocks, &scope_seed, reports),
        ["q3"],
        "and the write lands on the record plane"
    );
}
