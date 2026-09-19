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
use cipherbox_engine::seams::{BoxedTask, FloorStore, OpId, RecordTransport, StagingStore};
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
    ResealSeeds, ScopeRootIdentity, StoragePolicy, SyncTimingProfile, WriteHistory, WriteTarget,
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

/// A second device that only ever saw the network, booted with `scope` in focus
/// and one refresh taken.
fn mounted_reader(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    scope: NodeId,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    let (mut engine, events, mut tasks) = boot(world, blocks, device, 7);
    block_on(engine.command(Command::SetFocus { node: Some(scope) }))
        .expect("focus moves to the granted folder");
    let refreshed = command_while_ticking(&mut engine, Command::ManualRefresh, &mut tasks);
    assert!(
        refreshed.is_ok(),
        "the focus refresh reads the granted folder's own record: {refreshed:?}"
    );
    tick(world, &engine, &mut tasks);
    (engine, events, tasks)
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

/// The epoch tag the record published at `node` carries.
fn published_epoch(world: &FakeWorld, blocks: &Blocks, node: NodeId) -> u64 {
    let head = published_head(world, blocks, &write_name(node)).expect("a published record");
    decode_envelope(&head).expect("the head decodes").epoch
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

/// Write `plaintext` as one committed version, the way a host does.
fn write_file(
    engine: &mut Engine<FakeSeamTypes>,
    target: WriteTarget,
    plaintext: &[u8],
) -> Result<OpId, EngineError> {
    let handle = block_on(engine.begin_write(target, plaintext.len() as u64))?;
    for slice in plaintext.chunks(64) {
        block_on(engine.push_chunk(handle, slice))?;
    }
    block_on(engine.commit_write(handle))
}

/// Grant `node` to the imported recipient — the cut that promotes a folder to a
/// nested scope root.
fn grant_to_recipient(engine: &mut Engine<FakeSeamTypes>, node: NodeId) {
    grant_to_recipient_at(engine, node, Permission::Read);
}

fn grant_to_recipient_at(engine: &mut Engine<FakeSeamTypes>, node: NodeId, permission: Permission) {
    assert_eq!(
        block_on(engine.command(Command::Grant {
            node,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission,
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
    let (engine_m, _events_m, _tasks_m) = mounted_reader(&world, &blocks, &mount, shared);

    assert_eq!(
        listed_names(&engine_m, shared),
        ["2026"],
        "the owner's second device lists what the tab published inside the cut scope"
    );
}

/// The same write with content behind it. The version's key blob binds the scope
/// the version is authored in, and the pass that drains it opens the blob under
/// that same pair — a drain that opened it under any other one destroys the
/// version rather than publishing it.
#[test]
fn a_file_written_inside_a_granted_scope_root_publishes_its_version() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, mut events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");

    import_recipient(&mut engine_t);
    grant_to_recipient(&mut engine_t, shared);

    let op = write_file(
        &mut engine_t,
        WriteTarget::NewFile {
            parent: shared,
            name: "notes.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("a write inside the granted folder commits");
    let _ = events_so_far(&mut events_t);
    for _ in 0..8 {
        tick(&world, &engine_t, &mut tasks_t);
    }

    assert_eq!(
        dead_letters(&mut events_t, op),
        Vec::new(),
        "the version's key blob opens on the pass that publishes it"
    );
    assert_eq!(queued(&tab), 0, "the write drains");
    let scope_seed = owner_scope_seed(&world, &blocks, shared);
    assert_eq!(
        published_names(&world, &blocks, &scope_seed, shared),
        ["notes.bin"],
        "and the promoted root publishes the file the tab wrote"
    );
}

/// The write half from the other side: the mount writes inside a folder the
/// tab's grant cut. The mount minted nothing, so no local state anchors that
/// scope's write-epoch floor and only the promoted root's own write plane can.
#[test]
fn a_mount_write_inside_a_promoted_scope_root_publishes_on_a_non_minting_device() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    // Device T: the tab makes the grant, so it is the minting device.
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    import_recipient(&mut engine_t);
    grant_to_recipient(&mut engine_t, shared);

    // Device M: the mounted desktop, which only ever saw the network.
    let mount = world.device(b"mounted-desktop");
    let (mut engine_m, mut events_m, mut tasks_m) = mounted_reader(&world, &blocks, &mount, shared);

    let op = block_on(engine_m.command(Command::Create {
        parent: shared,
        name: "2026".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a create inside the granted folder stages")
    .op_id()
    .expect("a create queues an op");
    let _ = events_so_far(&mut events_m);
    for _ in 0..8 {
        tick(&world, &engine_m, &mut tasks_m);
    }

    assert_eq!(
        dead_letters(&mut events_m, op),
        Vec::new(),
        "no reason to abandon the owner's own write"
    );
    assert_eq!(
        queued(&mount),
        0,
        "the mount's write below a promoted scope root drains on a device that made no grant"
    );
    let scope_seed = owner_scope_seed(&world, &blocks, shared);
    assert_eq!(
        published_names(&world, &blocks, &scope_seed, shared),
        ["2026"],
        "and the promoted root publishes the child the mount named"
    );
}

/// The read half on its own: the child predates the cut, so nothing has to
/// publish below the promoted root for the second device to render it. Only the
/// child-record read path stands between the mount and the folder's contents.
#[test]
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
    let (engine_m, _events_m, _tasks_m) = mounted_reader(&world, &blocks, &mount, shared);

    assert_eq!(
        listed_names(&engine_m, shared),
        ["2026"],
        "the promoted root's own children still render on a device that only read them"
    );
}

/// A file with two versions under `parent`: `bodies[0]` then `bodies[1]`, each
/// drained to the record plane.
fn file_with_two_versions(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    parent: NodeId,
    name: &str,
    bodies: &[Vec<u8>; 2],
) -> NodeId {
    write_file(
        engine,
        WriteTarget::NewFile {
            parent,
            name: name.into(),
        },
        &bodies[0],
    )
    .expect("the first version commits");
    tick(world, engine, tasks);
    let node = listed(engine, parent)
        .into_iter()
        .find(|(child_name, _)| child_name == name)
        .unwrap_or_else(|| panic!("no file named {name}"))
        .1;
    write_file(
        engine,
        WriteTarget::Version {
            node,
            expected_version: None,
        },
        &bodies[1],
    )
    .expect("the second version commits");
    for _ in 0..4 {
        tick(world, engine, tasks);
    }
    node
}

/// The owner reads `file` whole, lists its prior version, and reads that
/// version, all on `engine`.
fn assert_reads_both_versions(
    engine: &Engine<FakeSeamTypes>,
    file: NodeId,
    bodies: &[Vec<u8>; 2],
    who: &str,
) {
    assert_eq!(
        block_on(engine.read_content(file)).map_err(|e| e.to_string()),
        Ok(bodies[1].clone()),
        "{who} reads the head version"
    );
    let versions = block_on(engine.file_versions(file)).expect("the version history reads");
    assert_eq!(versions.len(), 1, "{who} lists the one prior version");
    assert_eq!(
        block_on(engine.read_version_content(file, &versions[0].content_cid))
            .map_err(|e| e.to_string()),
        Ok(bodies[0].clone()),
        "{who} reads the prior version"
    );
}

fn two_bodies(salt: u8) -> [Vec<u8>; 2] {
    [
        (0..90u8).map(|byte| byte ^ salt).collect(),
        (0..70u8).map(|byte| byte ^ salt.wrapping_add(1)).collect(),
    ]
}

/// A grant re-seals the granted folder's interior into the scope it mints, so
/// the owner's own read of a file there opens under that scope's read seed.
#[test]
fn the_owner_reads_a_file_inside_a_folder_it_granted() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let before = two_bodies(3);
    let early = file_with_two_versions(
        &world,
        &mut engine_t,
        &mut tasks_t,
        shared,
        "early.bin",
        &before,
    );

    import_recipient(&mut engine_t);
    grant_to_recipient(&mut engine_t, shared);
    assert_reads_both_versions(&engine_t, early, &before, "the granting device, at once");
    for _ in 0..4 {
        tick(&world, &engine_t, &mut tasks_t);
    }
    assert_reads_both_versions(&engine_t, early, &before, "the granting device");

    let after = two_bodies(9);
    let late = file_with_two_versions(
        &world,
        &mut engine_t,
        &mut tasks_t,
        shared,
        "late.bin",
        &after,
    );
    assert_reads_both_versions(&engine_t, late, &after, "the granting device");

    let mount = world.device(b"mounted-desktop");
    let (engine_m, _events_m, _tasks_m) = mounted_reader(&world, &blocks, &mount, shared);
    assert_reads_both_versions(&engine_m, early, &before, "the owner's second device");
    assert_reads_both_versions(&engine_m, late, &after, "the owner's second device");
}

/// A share hands its own device the minted scope's read seed, so a read needs
/// no boundary walk to prove the scope first, and the passes that run while no
/// walk can reach the network keep that seed. Both gestures that mint a scope:
/// a contact grant, and an invite link on a write share, whose cut moves the
/// scope's names but not its read plane.
#[test]
fn the_owner_reads_a_shared_folder_no_walk_has_proved() {
    for by_link in [false, true] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_vault(&world, &blocks);

        let tab = world.device(&owner_identity().verifying_key().to_sec1());
        let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
        let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
        let before = two_bodies(7);
        let file = file_with_two_versions(
            &world,
            &mut engine_t,
            &mut tasks_t,
            shared,
            "early.bin",
            &before,
        );

        if by_link {
            assert!(
                matches!(
                    block_on(engine_t.command(Command::CreateInviteLink {
                        node: shared,
                        permission: Permission::Write,
                        expires_at: None,
                    })),
                    Ok(CommandOutcome::InviteLinkMinted(_))
                ),
                "the link mints the folder's scope"
            );
        } else {
            import_recipient(&mut engine_t);
            grant_to_recipient(&mut engine_t, shared);
        }
        let who = if by_link {
            "the linking device"
        } else {
            "the granting device"
        };
        assert_reads_both_versions(&engine_t, file, &before, who);

        for endpoint in world.record_store.endpoints() {
            world.record_store.fail_endpoint(&endpoint);
        }
        for _ in 0..4 {
            tick(&world, &engine_t, &mut tasks_t);
        }
        for endpoint in world.record_store.endpoints() {
            world.record_store.heal_endpoint(&endpoint);
        }
        assert_reads_both_versions(&engine_t, file, &before, who);
    }
}

/// The recipient's own session: a vault of its own, the owner imported as a
/// contact, and the passes run until the owner's share is grafted in.
fn recipient_with_the_share(
    world: &FakeWorld,
    blocks: &Blocks,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    let device = world.device(&recipient_identity().verifying_key().to_sec1());
    serve_http(&device, blocks, 2_000);
    let (mut engine, events) = engine_on_api(&device, 21);
    block_on(engine.start(LoginSecret::new(RECIPIENT_SECRET.to_vec())))
        .expect("the recipient's own session starts");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    let owner = ContactCode::create(&owner_identity(), kdf::enc_subkey(&SECRET).public()).encode();
    block_on(engine.command(Command::ImportContact {
        contact_code: owner,
    }))
    .expect("the owner's code imports");
    for _ in 0..4 {
        world.scheduler.advance(SyncTimingProfile::CI.stale_after);
        poll_tasks_until_parked(&mut tasks);
    }
    let rows = block_on(engine.received_shares()).expect("the list reads");
    assert_eq!(rows.len(), 1, "the recipient accepted the one share");
    (engine, events, tasks)
}

/// The id the recipient's render lists `name` under, below the grafted root.
fn grafted_child(engine: &Engine<FakeSeamTypes>, root: NodeId, name: &str) -> NodeId {
    listed(engine, root)
        .into_iter()
        .find(|(child_name, _)| child_name == name)
        .unwrap_or_else(|| panic!("the grafted root lists no {name}"))
        .1
}

/// A file below a grafted root is sealed under the granted scope, so the
/// recipient opens it under that scope's read seed and the sharer's floors,
/// whether the owner wrote it before or after the grant, on a read grant and
/// on a write grant alike.
#[test]
fn the_recipient_reads_a_file_below_a_grafted_root() {
    for permission in [Permission::Read, Permission::Write] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_vault(&world, &blocks);

        let tab = world.device(&owner_identity().verifying_key().to_sec1());
        let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
        let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
        let before = two_bodies(5);
        file_with_two_versions(
            &world,
            &mut engine_t,
            &mut tasks_t,
            shared,
            "early.bin",
            &before,
        );
        import_recipient(&mut engine_t);
        grant_to_recipient_at(&mut engine_t, shared, permission);
        let after = two_bodies(11);
        file_with_two_versions(
            &world,
            &mut engine_t,
            &mut tasks_t,
            shared,
            "late.bin",
            &after,
        );

        let (engine_r, _events_r, _tasks_r) = recipient_with_the_share(&world, &blocks);
        let who = format!("the {permission:?} recipient");
        let early = grafted_child(&engine_r, shared, "early.bin");
        assert_reads_both_versions(&engine_r, early, &before, &who);
        let late = grafted_child(&engine_r, shared, "late.bin");
        assert_reads_both_versions(&engine_r, late, &after, &who);
    }
}

/// The owner's cut raises the recipient's read-epoch floor for the shared
/// scope, and a read-only recipient can carry no wave. A file no write has
/// re-sealed still reads, under the seed the gated scope root's ratchet reaches
/// (ADR 0021).
#[test]
fn the_recipient_reads_a_lagging_file_after_the_owner_cuts() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let bodies = two_bodies(5);
    file_with_two_versions(
        &world,
        &mut engine_t,
        &mut tasks_t,
        shared,
        "early.bin",
        &bodies,
    );
    import_recipient(&mut engine_t);
    grant_to_recipient(&mut engine_t, shared);
    for _ in 0..4 {
        tick(&world, &engine_t, &mut tasks_t);
    }
    let (engine_r, _events_r, mut tasks_r) = recipient_with_the_share(&world, &blocks);
    let early = grafted_child(&engine_r, shared, "early.bin");
    assert_reads_both_versions(&engine_r, early, &bodies, "the recipient before the cut");
    let epoch_before = published_epoch(&world, &blocks, shared);

    assert_eq!(
        block_on(engine_t.command(Command::RotateNow { node: shared })),
        Ok(CommandOutcome::Done),
    );
    tick(&world, &engine_t, &mut tasks_t);
    for _ in 0..4 {
        world.scheduler.advance(SyncTimingProfile::CI.stale_after);
        poll_tasks_until_parked(&mut tasks_r);
    }
    assert!(
        published_epoch(&world, &blocks, shared) > epoch_before,
        "the cut moved the shared scope to a new epoch",
    );

    assert_reads_both_versions(&engine_r, early, &bodies, "the recipient after the cut");
}

/// A folder the lazy wave has not re-sealed renders on the focus refresh of a
/// device that has not listed it before: the refresh opens it under the gated
/// scope root's ratchet (ADR 0021) and accuses nobody.
#[test]
fn the_focus_refresh_lists_a_lagging_folder_after_a_cut() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let reports = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "reports");
    create_published_folder(&world, &mut engine_t, &mut tasks_t, reports, "q3");
    let mount = world.device(b"mounted-desktop");
    let (mut engine_m, mut events_m, mut tasks_m) = boot(&world, &blocks, &mount, 7);
    let reports_epoch = published_epoch(&world, &blocks, reports);

    assert_eq!(
        block_on(engine_t.command(Command::RotateNow { node: ROOT })),
        Ok(CommandOutcome::Done),
    );
    tick(&world, &engine_t, &mut tasks_t);
    tick(&world, &engine_m, &mut tasks_m);
    assert!(
        published_epoch(&world, &blocks, ROOT) > reports_epoch,
        "the folder lags the scope root",
    );
    let _ = events_so_far(&mut events_m);

    block_on(engine_m.command(Command::SetFocus {
        node: Some(reports),
    }))
    .expect("focus moves to the lagging folder");
    let refreshed = command_while_ticking(&mut engine_m, Command::ManualRefresh, &mut tasks_m);
    assert!(
        refreshed.is_ok(),
        "the refresh reads the lagging folder: {refreshed:?}"
    );

    assert_eq!(listed_names(&engine_m, reports), ["q3"]);
    assert!(
        !events_so_far(&mut events_m)
            .iter()
            .any(|event| matches!(event, Event::AttributableAbuse { .. })),
        "a lagging record is not abuse",
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
    // A record left tagged behind opens under the right key and is still
    // refused by the device's own epoch floor.
    assert_eq!(
        published_epoch(&world, &blocks, reports),
        published_epoch(&world, &blocks, ROOT),
        "the re-authored node is tagged at the epoch its scope root now carries"
    );
}

// ---------------------------------------------------------------------------
// A write share, and the last-known-good the wave leaves behind
// ---------------------------------------------------------------------------

/// How the owner shares the folder with write permission.
#[derive(Debug, Clone, Copy)]
enum WriteShare {
    Contact,
    InviteLink,
}

/// A folder holding one file with `bodies` as its two versions, published and
/// drained, then shared with write permission. Answers the folder and the file.
fn file_under_a_write_share(
    world: &FakeWorld,
    blocks: &Blocks,
    tab: &FakeDevice,
    share: WriteShare,
    bodies: &[Vec<u8>; 2],
) -> (Engine<FakeSeamTypes>, NodeId, NodeId) {
    let (mut engine, _events, mut tasks) = boot(world, blocks, tab, 42);
    let shared = create_published_folder(world, &mut engine, &mut tasks, ROOT, "shared");
    let file = file_with_two_versions(world, &mut engine, &mut tasks, shared, "notes.bin", bodies);
    assert_eq!(queued(tab), 0, "both versions drain before the share");

    let outcome = match share {
        WriteShare::Contact => {
            import_recipient(&mut engine);
            block_on(engine.command(Command::Grant {
                node: shared,
                recipient_identity_public_key:
                    recipient_identity().verifying_key().to_sec1().to_vec(),
                permission: Permission::Write,
            }))
        }
        WriteShare::InviteLink => block_on(engine.command(Command::CreateInviteLink {
            node: shared,
            permission: Permission::Write,
            expires_at: None,
        })),
    };
    assert!(
        outcome.is_ok(),
        "the {share:?} write share lands: {outcome:?}"
    );
    (engine, shared, file)
}

/// The sequence of the record `bytes` holds, verified under `name`.
fn record_sequence(name: &IpnsName, bytes: &[u8]) -> u64 {
    IpnsRecord::unmarshal(bytes)
        .and_then(|record| record.verify(name))
        .expect("the cached record verifies under its own name")
        .sequence
}

/// A write share re-seals the folder interior and runs the name wave, which
/// adopts each re-sealed record. No floor it raises may pass the bytes it
/// leaves as last-known-good: a read that finds no source opens the cached copy
/// at that floor.
#[test]
fn a_write_share_leaves_every_record_it_touches_cached_at_its_sequence_floor() {
    for share in [WriteShare::Contact, WriteShare::InviteLink] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_vault(&world, &blocks);
        let tab = world.device(&owner_identity().verifying_key().to_sec1());
        let (_engine, shared, file) =
            file_under_a_write_share(&world, &blocks, &tab, share, &two_bodies(5));

        for node in [ROOT, shared, file] {
            let name = write_name(node);
            let floor = block_on(tab.floors(&SECRET).sequence_floor(name.as_str().as_bytes()))
                .expect("the floor store answers")
                .expect("every record the share touched holds a sequence floor");
            let cached = tab
                .snapshot_cache
                .peek(name.as_str().as_bytes())
                .expect("every record the share touched is cached");
            assert_eq!(
                record_sequence(&name, &cached),
                floor,
                "{share:?}: the cached record of {node:?} sits at the floor the share raised"
            );
        }
    }
}

/// After a write share, a read that finds no record source opens the file
/// from its last-known-good: the head content, the version list, and a prior
/// version.
#[test]
fn a_file_under_a_write_share_reads_with_every_record_endpoint_down() {
    for share in [WriteShare::Contact, WriteShare::InviteLink] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_vault(&world, &blocks);
        let tab = world.device(&owner_identity().verifying_key().to_sec1());
        let bodies = two_bodies(11);
        let (engine, _shared, file) =
            file_under_a_write_share(&world, &blocks, &tab, share, &bodies);
        for endpoint in world.record_store.endpoints() {
            world.record_store.fail_endpoint(&endpoint);
        }
        assert_reads_both_versions(&engine, file, &bodies, &format!("{share:?}, offline"));
    }
}
