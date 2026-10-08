//! Convergence across the owner's own devices once a cut has made an interior
//! folder a scope root of its own: the browser tab writes inside it, and the
//! mounted desktop must see what it published.
//!
//! Every assertion lands on published bytes, a drained queue, or a rendered
//! view — what the other device would see.

use core::cell::RefCell;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

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

use cipherbox_engine::gate::floor;
use cipherbox_engine::grants::{ReceivedShareStore, ReceivedSharesList, StagingReceivedShareStore};
use cipherbox_engine::net::author::{
    ENVELOPE_V, EnvelopeAuthoring, author_scope_root_with_section,
};
use cipherbox_engine::rotation::published_override_seed;
use cipherbox_engine::seams::{BoxedTask, FloorStore, OpId, RecordTransport, StagingStore};
use cipherbox_engine::sync::SessionRole;
use cipherbox_engine::sync::pointer::{scope_pointer_name, seal_repoint, vault_pointer_name};
use cipherbox_engine::testkit::account::{
    Blocks, EOL, POINTER_PAYLOAD_VERSION, ROOT, SCOPE, SECRET, TTL_NANOS, floor_label,
    owner_identity, serve_http,
};
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH as EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    SeededEntropy, block_on, block_on_while_ticking, poll_tasks_until_parked,
    without_scope_pointer_names,
};
use cipherbox_engine::{
    ApiBaseUrl, Command, CommandOutcome, CommittedSet, ContentProfile, DeadLetterReason, Engine,
    EngineError, Event, EventStream, GatewayConfig, LoginSecret, NodeId, NodeKind, Permission,
    RecordReader, ResealSeeds, ScopeRootIdentity, StoragePolicy, SyncTimingProfile, WriteHistory,
    WriteTarget, decode_queue, reseal_scope_root,
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

/// The owner root at the seeded epoch, with no children, signed at
/// `sequence`.
fn initial_root_record(blocks: &Blocks, sequence: u64) -> Vec<u8> {
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
    IpnsRecord::create_v2(
        &root_signer,
        format!("/ipfs/{}", head.cid).as_bytes(),
        sequence,
        TTL_NANOS,
        EOL,
    )
    .marshal()
}

/// Publish the account's initial state: an empty owner root at sequence 1 whose
/// committed set is the owner's own, and the vault pointer naming it.
fn seed_vault(world: &FakeWorld, blocks: &Blocks) -> IpnsName {
    let owner_identity = owner_identity();
    let name = write_name(ROOT);
    let pointer_read_key = owner_pointer_read_key();
    let root_record = initial_root_record(blocks, 1);

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
    block_on(engine.start(secret(), None)).expect("cold start adopts the owner root");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    (engine, events, tasks)
}

/// Run one resolve-tick interval, which is also one drain pass.
fn tick(world: &FakeWorld, engine: &Engine<FakeSeamTypes>, tasks: &mut [BoxedTask]) {
    world.scheduler.advance(engine.profile().poll_cadence);
    poll_tasks_until_parked(tasks);
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
    let refreshed = block_on_while_ticking(engine.command(Command::ManualRefresh), &mut tasks);
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
            Event::DeadLetter { op_id, reason, .. } if op_id == op => Some(reason),
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

/// The ops still pending in `device`'s durable queue.
fn queued(device: &FakeDevice) -> usize {
    block_on(device.pending_ops())
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
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
        "the grant cuts the folder into a scope root of its own"
    );
}

// ---------------------------------------------------------------------------
// A read cut of the vault root and the cold-start anchor
// ---------------------------------------------------------------------------

/// Cut the vault root's read epoch by hand. The lazy wave the cut spawns is
/// dropped: these cases assert what a cold start reads, not what the wave
/// re-seals.
fn cut_vault_root(world: &FakeWorld, engine: &mut Engine<FakeSeamTypes>) {
    assert_eq!(
        block_on(engine.command(Command::RotateNow { node: ROOT })),
        Ok(CommandOutcome::Done),
        "the owner cuts the vault root's read epoch"
    );
    drop(world.scheduler.take_spawned_tasks());
}

/// The `minReadEpoch` the vault pointer at index 0 vouches.
fn vouched_min_read_epoch(world: &FakeWorld) -> u64 {
    vault_repoint(world).min_read_epoch
}

/// The vault-pointer record at the first endpoint.
fn vault_pointer_record(world: &FakeWorld) -> Option<Vec<u8>> {
    let endpoint = world.record_store.endpoints()[0].clone();
    world
        .record_store
        .record_at(&endpoint, vault_pointer_name(&SECRET, 0).as_str())
}

/// The re-point the vault pointer at index 0 carries.
fn vault_repoint(world: &FakeWorld) -> RepointObject {
    let name = vault_pointer_name(&SECRET, 0);
    let bytes = vault_pointer_record(world).expect("the vault pointer is published");
    let record = IpnsRecord::unmarshal(&bytes).expect("a record");
    let entry = record.verify(&name).expect("the record verifies");
    cipherbox_engine::sync::pointer::open_repoint(
        &owner_pointer_read_key(),
        POINTER_PAYLOAD_VERSION,
        &SCOPE,
        &owner_identity().verifying_key(),
        &entry.value,
    )
    .expect("the owner re-point opens")
}

/// The reproduction: a manual read cut of the vault root raises this device's
/// durable read floor, so the anchor the next cold start seeds from must vouch
/// the epoch the cut made durable.
#[test]
fn a_read_cut_of_the_vault_root_leaves_the_device_able_to_start_again() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    cut_vault_root(&world, &mut engine);
    assert_eq!(
        vouched_min_read_epoch(&world),
        published_epoch(&world, &blocks, ROOT),
        "the anchor vouches the epoch the cut published"
    );
    tick(&world, &engine, &mut tasks);
    drop((engine, tasks));

    let (engine, _events, _tasks) = boot(&world, &blocks, &owner, 43);
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);
}

/// A device that never ran the cut adopts the cut root on its first start, which
/// raises its own floor to the cut epoch: its second start must pass too.
#[test]
fn a_second_device_starts_twice_after_a_read_cut_of_the_vault_root() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    cut_vault_root(&world, &mut engine);

    let mount = world.device(b"mounted-desktop");
    let (second, _events_m, mut tasks_m) = boot(&world, &blocks, &mount, 7);
    tick(&world, &second, &mut tasks_m);
    assert_eq!(listed_names(&second, ROOT), ["reports"]);
    drop((second, tasks_m));

    let (second, _events_m, _tasks_m) = boot(&world, &blocks, &mount, 8);
    assert_eq!(listed_names(&second, ROOT), ["reports"]);
}

/// Drive one command to completion on the virtual clock alone, so its retries
/// wake while the session's own loops stay parked.
fn command_on_the_clock(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    command: Command,
) -> Result<CommandOutcome, EngineError> {
    let cadence = engine.profile().poll_cadence;
    settle_on_the_clock(world, cadence, &mut Box::pin(engine.command(command)))
}

/// Poll `pending` to completion, advancing the virtual clock by `cadence`
/// between polls; a bounded number of steps, so a hung command fails.
fn settle_on_the_clock<O>(
    world: &FakeWorld,
    cadence: Duration,
    pending: &mut Pin<Box<impl Future<Output = O>>>,
) -> O {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(outcome) = pending.as_mut().poll(&mut cx) {
            return outcome;
        }
        world.scheduler.advance(cadence);
    }
    panic!("the command did not settle in 64 steps of {cadence:?} on the virtual clock");
}

/// Whether `events` carries a `RenewalFailed` at `name`.
fn renewal_failed_at(events: &mut EventStream, name: &IpnsName) -> bool {
    events_so_far(events).into_iter().any(|event| {
        matches!(event, Event::RenewalFailed { routing_key, .. } if routing_key == name.as_str())
    })
}

/// The epoch-floor reads of the vault root a start makes before the catch-up
/// reads it: the cold seed's and the adopt's.
const CATCH_UP_FLOOR_READ: u64 = 2;

/// Run one cut of the vault root that lands its root and runs out of retries
/// before its vouch lands. Returns the epoch it published.
fn cut_whose_vouch_runs_out(
    world: &FakeWorld,
    blocks: &Blocks,
    engine: &mut Engine<FakeSeamTypes>,
) -> u64 {
    let anchor = vault_pointer_name(&SECRET, 0);
    world.record_store.fail_put_for(anchor.as_str());
    let cut = command_on_the_clock(world, engine, Command::RotateNow { node: ROOT });
    assert!(
        matches!(cut, Err(EngineError::Seam { .. })),
        "a cut that could not vouch its epoch is not reported done: {cut:?}"
    );
    drop(world.scheduler.take_spawned_tasks());
    world.record_store.heal_put_for(anchor.as_str());
    let published = published_epoch(world, blocks, ROOT);
    assert_eq!(published, EPOCH + 1);
    assert_eq!(vouched_min_read_epoch(world), EPOCH);
    published
}

/// The anchor refuses every publish of the cut: the root lands, the anchor
/// does not, and the cut reports it. The next start that adopts the cut root
/// vouches its epoch, and the owner device then starts again.
#[test]
fn a_cut_whose_anchor_never_landed_converges_at_the_next_start() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    let cut_epoch = cut_whose_vouch_runs_out(&world, &blocks, &mut engine);
    drop((engine, tasks));

    let mount = world.device(b"mounted-desktop");
    let (second, _events_m, _tasks_m) = boot(&world, &blocks, &mount, 7);
    assert_eq!(listed_names(&second, ROOT), ["reports"]);
    assert_eq!(
        vouched_min_read_epoch(&world),
        cut_epoch,
        "the start that adopted the cut root vouches its epoch"
    );
    drop(second);

    let (engine, _events, _tasks) = boot(&world, &blocks, &owner, 44);
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);
}

/// A start that adopts the cut root and cannot vouch its epoch says so.
#[test]
fn a_start_that_cannot_vouch_the_adopted_epoch_surfaces_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let anchor = vault_pointer_name(&SECRET, 0);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, _tasks) = boot(&world, &blocks, &owner, 42);
    world.record_store.fail_put_for(anchor.as_str());
    let cut = command_on_the_clock(&world, &mut engine, Command::RotateNow { node: ROOT });
    assert!(cut.is_err(), "{cut:?}");
    drop(world.scheduler.take_spawned_tasks());
    assert_eq!(published_epoch(&world, &blocks, ROOT), EPOCH + 1);

    let mount = world.device(b"mounted-desktop");
    let (_second, mut events, _tasks) = boot(&world, &blocks, &mount, 7);
    assert!(
        renewal_failed_at(&mut events, &anchor),
        "the failed vouch is surfaced, never silent"
    );
    assert_eq!(vouched_min_read_epoch(&world), EPOCH);
}

/// A cut that cannot read the anchor cannot vouch at it, so it publishes no
/// root that would leave the floor ahead of the anchor.
#[test]
fn a_cut_that_cannot_read_the_anchor_publishes_no_root() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let anchor = vault_pointer_name(&SECRET, 0);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, _tasks) = boot(&world, &blocks, &owner, 42);
    world.record_store.fail_get_for(anchor.as_str());
    let cut = command_on_the_clock(&world, &mut engine, Command::RotateNow { node: ROOT });
    assert!(matches!(cut, Err(EngineError::Seam { .. })), "{cut:?}");
    drop(world.scheduler.take_spawned_tasks());
    world.record_store.heal_get_for(anchor.as_str());
    assert_eq!(published_epoch(&world, &blocks, ROOT), EPOCH);
    assert_eq!(vouched_min_read_epoch(&world), EPOCH);
}

/// The root does not land, so nothing may vouch its epoch: an anchor ahead of
/// the only root there is would seed every device above it.
#[test]
fn a_cut_whose_root_never_landed_leaves_the_anchor_alone() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    world.record_store.fail_put_for(root_name.as_str());
    let cut = command_on_the_clock(&world, &mut engine, Command::RotateNow { node: ROOT });
    assert!(cut.is_err(), "the cut did not land: {cut:?}");
    drop(world.scheduler.take_spawned_tasks());
    world.record_store.heal_put_for(root_name.as_str());
    assert_eq!(vouched_min_read_epoch(&world), EPOCH);
    drop((engine, tasks));

    let second = world.device(b"mounted-desktop");
    let (engine, _events, _tasks) = boot(&world, &blocks, &second, 7);
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);
    let (engine, _events, _tasks) = boot(&world, &blocks, &owner, 43);
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);
}

/// Publish an owner re-point at vault-pointer index 0, above the seeded one.
fn republish_vault_pointer(world: &FakeWorld, repoint: &RepointObject, sequence: u64) {
    let block = seal_repoint(
        SessionRole::Owner,
        &mut SeededEntropy::new(99),
        &owner_pointer_read_key(),
        POINTER_PAYLOAD_VERSION,
        &owner_identity(),
        repoint,
    )
    .expect("seal the re-point");
    let record = IpnsRecord::create_v2(
        &kdf::vault_pointer_index(&SECRET, 0),
        &block,
        sequence,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    let name = vault_pointer_name(&SECRET, 0);
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
}

/// The standing re-point names a root this cut never read, so the cut could
/// not vouch its epoch there and must not cut.
#[test]
fn a_cut_refuses_to_vouch_for_a_root_the_vault_pointer_does_not_name() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, _tasks) = boot(&world, &blocks, &owner, 42);
    let elsewhere = RepointObject {
        scope_id: SCOPE,
        current_root: write_name(NodeId([0x77; 16])),
        write_epoch: EPOCH + 1,
        min_read_epoch: EPOCH,
        prev_root: Some(root_name),
    };
    republish_vault_pointer(&world, &elsewhere, 2);

    let cut = command_on_the_clock(&world, &mut engine, Command::RotateNow { node: ROOT });
    assert!(
        matches!(cut, Err(EngineError::TrustViolation { .. })),
        "{cut:?}"
    );
    drop(world.scheduler.take_spawned_tasks());
    assert_eq!(
        published_epoch(&world, &blocks, ROOT),
        EPOCH,
        "nothing was cut"
    );
    assert_eq!(vouched_min_read_epoch(&world), EPOCH, "nothing was vouched");
}

/// The retry meets a floor that rose above the root the cut published: that
/// root no longer passes the gate, so no vouch of its epoch is signed.
#[test]
fn a_retry_below_the_durable_floor_vouches_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let anchor = vault_pointer_name(&SECRET, 0);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, _tasks) = boot(&world, &blocks, &owner, 42);
    world.record_store.fail_put_for(anchor.as_str());
    let cadence = engine.profile().poll_cadence;
    let mut cut = Box::pin(engine.command(Command::RotateNow { node: ROOT }));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        cut.as_mut().poll(&mut cx).is_pending(),
        "the first attempt lands the root, fails the vouch and waits to retry"
    );
    world.record_store.heal_put_for(anchor.as_str());
    block_on(cipherbox_engine::seams::FloorStore::raise_epoch_floor(
        &owner.floors(&SECRET),
        &SCOPE,
        EPOCH + 5,
    ))
    .expect("the floor rises");
    let settled = settle_on_the_clock(&world, cadence, &mut cut);
    assert!(
        matches!(settled, Err(EngineError::TrustViolation { .. })),
        "{settled:?}"
    );
    drop(world.scheduler.take_spawned_tasks());
    assert_eq!(vouched_min_read_epoch(&world), EPOCH, "nothing was vouched");
}

/// A caller retry after a cut that published its root and not its vouch
/// finishes that cut: it vouches the published epoch and mints no other root.
#[test]
fn a_retried_cut_of_the_vault_root_completes_the_outstanding_vouch() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    let cut_epoch = cut_whose_vouch_runs_out(&world, &blocks, &mut engine);

    let retry = command_on_the_clock(&world, &mut engine, Command::RotateNow { node: ROOT });
    assert_eq!(retry, Ok(CommandOutcome::Done));
    drop(world.scheduler.take_spawned_tasks());
    assert_eq!(
        published_epoch(&world, &blocks, ROOT),
        cut_epoch,
        "the retry mints no new root"
    );
    assert_eq!(vouched_min_read_epoch(&world), cut_epoch);
    drop((engine, tasks));

    let (engine, _events, _tasks) = boot(&world, &blocks, &owner, 43);
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);
}

/// The start that adopts a cut root cannot read its own floor to vouch it: it
/// says so, and a later cut of the vault root in the same session finishes the
/// vouch.
#[test]
fn a_start_whose_floor_read_fails_surfaces_it_and_a_later_cut_vouches() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let anchor = vault_pointer_name(&SECRET, 0);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    let cut_epoch = cut_whose_vouch_runs_out(&world, &blocks, &mut engine);
    drop((engine, tasks));

    let mount = world.device(b"mounted-desktop");
    mount
        .floor_store
        .fail_epoch_floor_reads_after(&floor_label(&SCOPE), CATCH_UP_FLOOR_READ);
    let (mut second, mut events, _tasks) = boot(&world, &blocks, &mount, 7);
    mount.floor_store.heal_floors();
    assert!(
        renewal_failed_at(&mut events, &anchor),
        "the unread floor is surfaced, never silent"
    );
    assert_eq!(vouched_min_read_epoch(&world), EPOCH);

    let later = command_on_the_clock(&world, &mut second, Command::RotateNow { node: ROOT });
    assert_eq!(later, Ok(CommandOutcome::Done));
    drop(world.scheduler.take_spawned_tasks());
    assert_eq!(published_epoch(&world, &blocks, ROOT), cut_epoch);
    assert_eq!(vouched_min_read_epoch(&world), cut_epoch);
    drop(second);

    let (second, _events, _tasks) = boot(&world, &blocks, &mount, 8);
    assert_eq!(listed_names(&second, ROOT), ["reports"]);
}

/// The owner's only device: a session that ticks after a cut of the vault root
/// that did not vouch its epoch, then starts again.
fn the_owner_starts_again_after_its_session_adopts_the_cut_root(
    world: &FakeWorld,
    blocks: &Blocks,
    owner: &FakeDevice,
    engine: Engine<FakeSeamTypes>,
    mut tasks: Vec<BoxedTask>,
) {
    tick(world, &engine, &mut tasks);
    assert!(
        block_on(floor::read_epoch_floor(&owner.floors(&SECRET), &SCOPE)).expect("the floor reads")
            > Some(vouched_min_read_epoch(world)),
        "the session adopted the cut root above the epoch the anchor vouches"
    );
    drop((engine, tasks));

    serve_http(owner, blocks, 600);
    let (mut engine, _events) = engine_on_api(owner, 45);
    let started = block_on(engine.start(secret(), None));
    assert!(
        started.is_ok(),
        "the device that cut the vault root starts again: {started:?}"
    );
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);
}

/// The anchor PUT fails past the retry bound while every read works, and the
/// session adopts the cut root before it ends. No other device exists.
#[test]
fn a_one_device_owner_starts_after_a_vouch_that_ran_out_and_a_tick() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    cut_whose_vouch_runs_out(&world, &blocks, &mut engine);

    the_owner_starts_again_after_its_session_adopts_the_cut_root(
        &world, &blocks, &owner, engine, tasks,
    );
}

/// GETs of the vault root a cut reads before the confirm of its root publish.
const ROOT_GETS_BEFORE_CONFIRM: usize = 2;

/// The root PUT lands, but every confirm and every retry reads no record
/// there, so the cut reports the root unconfirmed and never vouches. The
/// session then adopts the root that did land. No other device exists.
#[test]
fn a_one_device_owner_starts_after_an_unconfirmed_root_that_landed_and_a_tick() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    world.record_store.serve_gets_for_after(
        root_name.as_str(),
        ROOT_GETS_BEFORE_CONFIRM,
        usize::MAX,
        None,
    );
    let cut = command_on_the_clock(&world, &mut engine, Command::RotateNow { node: ROOT });
    world
        .record_store
        .serve_gets_for_after(root_name.as_str(), 0, 0, None);
    assert!(cut.is_err(), "the root publish is unconfirmed: {cut:?}");
    drop(world.scheduler.take_spawned_tasks());
    assert_eq!(
        published_epoch(&world, &blocks, ROOT),
        EPOCH + 1,
        "the root landed"
    );
    assert_eq!(vouched_min_read_epoch(&world), EPOCH, "nothing was vouched");

    the_owner_starts_again_after_its_session_adopts_the_cut_root(
        &world, &blocks, &owner, engine, tasks,
    );
}

/// A start whose pointer lags the root it adopts holds the root read seed at
/// the adopted epoch, so a child read before any tick opens.
#[test]
fn a_child_read_right_after_a_lag_start_has_the_root_seed() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("a write at the vault root commits");
    tick_n(&world, &engine, &mut tasks, 4);
    let (_, file) = listed(&engine, ROOT)
        .into_iter()
        .find(|(name, _)| name == "notes.bin")
        .expect("the file lists");
    cut_whose_vouch_runs_out(&world, &blocks, &mut engine);
    tick(&world, &engine, &mut tasks);
    drop((engine, tasks));

    serve_http(&owner, &blocks, 600);
    let (mut engine, _events) = engine_on_api(&owner, 45);
    block_on(engine.start(secret(), None)).expect("the lag start passes");
    let versions = block_on(engine.file_versions(file));
    assert!(
        versions.is_ok(),
        "the root read seed opens the file record: {versions:?}"
    );
}

/// The sequence of the vault-root record the network serves.
fn published_root_sequence(world: &FakeWorld, root_name: &IpnsName) -> u64 {
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], root_name.as_str())
        .expect("the vault root is published");
    record_sequence(root_name, &bytes)
}

/// After its session adopts the cut root, and before any vouch of the cut
/// epoch lands, the session refuses an owner-signed root at the pre-cut epoch
/// whose sequence is above the cut root's.
#[test]
fn a_session_refuses_a_pre_cut_root_above_the_cut_roots_sequence() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    cut_whose_vouch_runs_out(&world, &blocks, &mut engine);
    tick(&world, &engine, &mut tasks);
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);

    let above = published_root_sequence(&world, &root_name) + 1;
    let stale = initial_root_record(&blocks, above);
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, root_name.as_str(), stale.clone());
    }
    tick_n(&world, &engine, &mut tasks, 2);

    assert_eq!(
        listed_names(&engine, ROOT),
        ["reports"],
        "the session keeps the cut root and does not adopt the pre-cut epoch"
    );
}

/// Serve the seeded re-point again, which vouches the pre-cut epoch, above
/// every sequence the vault pointer has reached.
fn replay_pre_cut_vault_pointer(world: &FakeWorld, root_name: &IpnsName) {
    let pre_cut = RepointObject {
        scope_id: SCOPE,
        current_root: root_name.clone(),
        write_epoch: EPOCH,
        min_read_epoch: EPOCH,
        prev_root: None,
    };
    republish_vault_pointer(world, &pre_cut, 100);
}

/// A cold start of `device` that must refuse the vault pointer as rolled back.
fn assert_start_refuses_a_rolled_back_pointer(
    blocks: &Blocks,
    device: &FakeDevice,
    entropy_seed: u64,
) {
    serve_http(device, blocks, 600);
    let (mut engine, _events) = engine_on_api(device, entropy_seed);
    let started = block_on(engine.start(secret(), None));
    assert!(
        matches!(
            &started,
            Err(EngineError::ColdStart { message }) if message.contains("read-epoch floor regression")
        ),
        "a pointer below the epoch it vouched to this device is a rollback: {started:?}"
    );
}

/// The cut's vouch lands, so this device holds the cut epoch as vouched: a
/// replay of the pre-cut pointer is refused at the next start.
#[test]
fn a_replayed_pre_cut_pointer_is_refused_after_a_landed_vouch() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    cut_vault_root(&world, &mut engine);
    drop((engine, tasks));

    replay_pre_cut_vault_pointer(&world, &root_name);
    assert_start_refuses_a_rolled_back_pointer(&blocks, &owner, 43);
}

/// The network serves a pointer below the sequence this device published at
/// the name, at the epoch the device vouched: the start goes on, and its
/// catch-up does not sign that pointer's fields again.
#[test]
fn a_catch_up_over_a_pointer_below_the_published_sequence_publishes_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    cut_whose_vouch_runs_out(&world, &blocks, &mut engine);
    tick(&world, &engine, &mut tasks);
    drop((engine, tasks));
    let anchor = vault_pointer_name(&SECRET, 0);
    block_on(
        owner
            .floors(&SECRET)
            .raise_sequence_floor(anchor.as_str().as_bytes(), 5),
    )
    .expect("this device published the pointer at sequence 5");
    let before = vault_pointer_record(&world);

    let (engine, mut events, _tasks) = boot(&world, &blocks, &owner, 43);
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);
    assert!(
        renewal_failed_at(&mut events, &anchor),
        "the refused catch-up is surfaced, never silent"
    );
    assert_eq!(
        vault_pointer_record(&world),
        before,
        "nothing was published"
    );
}

/// The start after a cut whose vouch ran out lands the vouch at its catch-up,
/// so a later replay of the pre-cut pointer is refused.
#[test]
fn a_replayed_pre_cut_pointer_is_refused_after_the_catch_up_vouch() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    let cut_epoch = cut_whose_vouch_runs_out(&world, &blocks, &mut engine);
    tick(&world, &engine, &mut tasks);
    drop((engine, tasks));

    let (engine, _events, _tasks) = boot(&world, &blocks, &owner, 43);
    assert_eq!(
        vouched_min_read_epoch(&world),
        cut_epoch,
        "the start vouches the epoch its session adopted"
    );
    drop(engine);

    replay_pre_cut_vault_pointer(&world, &root_name);
    assert_start_refuses_a_rolled_back_pointer(&blocks, &owner, 44);
}

/// Every other owner action that could reach the vault root is refused there or
/// leaves its read epoch alone, so none of them owes the anchor a vouch.
#[test]
fn no_other_owner_action_moves_the_vault_roots_read_epoch() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    let reports = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    import_recipient(&mut engine);
    let recipient = recipient_identity().verifying_key().to_sec1().to_vec();
    for command in [
        Command::Grant {
            node: ROOT,
            recipient_identity_public_key: recipient.clone(),
            permission: Permission::Write,
            grantee_name: None,
        },
        Command::Revoke {
            node: ROOT,
            recipient_identity_public_key: recipient.clone(),
        },
        Command::ChangePermission {
            node: ROOT,
            recipient_identity_public_key: recipient.clone(),
            permission: Permission::Read,
        },
    ] {
        let name = command.name();
        let refused = block_on(engine.command(command));
        assert!(refused.is_err(), "{name} at the vault root: {refused:?}");
    }
    grant_to_recipient_at(&mut engine, reports, Permission::Write);
    for _ in 0..4 {
        tick(&world, &engine, &mut tasks);
    }
    drop(world.scheduler.take_spawned_tasks());
    assert_eq!(published_epoch(&world, &blocks, ROOT), EPOCH);
    drop((engine, tasks));

    let (engine, _events, _tasks) = boot(&world, &blocks, &owner, 43);
    assert_eq!(listed_names(&engine, ROOT), ["reports"]);
}

/// A write grant, the one command that cuts a write scope with no grant in
/// place, is refused at the vault root. A write grant, a downgrade and a revoke
/// below it leave the vault pointer on the same root at the same write epoch.
#[test]
fn no_command_runs_a_write_cut_of_the_vault_root() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);
    let reports = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");
    import_recipient(&mut engine);
    let recipient = recipient_identity().verifying_key().to_sec1().to_vec();
    let revoke = |node| Command::Revoke {
        node,
        recipient_identity_public_key: recipient.clone(),
    };
    let downgrade = |node| Command::ChangePermission {
        node,
        recipient_identity_public_key: recipient.clone(),
        permission: Permission::Read,
    };
    let refused = block_on(engine.command(Command::Grant {
        node: ROOT,
        recipient_identity_public_key: recipient.clone(),
        permission: Permission::Write,
        grantee_name: None,
    }));
    assert!(
        matches!(
            refused,
            Err(EngineError::UnsupportedTarget {
                check: "grant-target-is-the-vault-root"
            })
        ),
        "a write grant at the vault root: {refused:?}"
    );
    for command in [downgrade(reports), revoke(reports)] {
        grant_to_recipient_at(&mut engine, reports, Permission::Write);
        let name = command.name();
        let cut = block_on_while_ticking(engine.command(command), &mut tasks);
        assert!(cut.is_ok(), "{name} below the vault root: {cut:?}");
        tick_n(&world, &engine, &mut tasks, 4);
    }
    drop(world.scheduler.take_spawned_tasks());

    let repoint = vault_repoint(&world);
    assert_eq!(repoint.current_root, root_name);
    assert_eq!(repoint.write_epoch, EPOCH);
}

/// A write rotate-now at the vault root is refused before it publishes, so
/// the vault pointer stays on the same root at the same write epoch.
#[test]
fn a_write_rotate_now_of_the_vault_root_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks);

    let owner = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &owner, 42);

    assert_eq!(
        block_on(engine.command(Command::RotateWriteNow { node: ROOT })),
        Err(EngineError::UnsupportedTarget {
            check: "rotate-write-target-is-the-vault-root"
        }),
    );
    tick_n(&world, &engine, &mut tasks, 4);

    let repoint = vault_repoint(&world);
    assert_eq!(repoint.current_root, root_name);
    assert_eq!(repoint.write_epoch, EPOCH);
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
/// a contact grant, and an invite link.
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
                        owner_name: String::new(),
                        admission_cap: None,
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
    recipient_on_with_the_share(world, blocks, &device)
}

/// [`recipient_with_the_share`] on `device`.
fn recipient_on_with_the_share(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    serve_http(device, blocks, 2_000);
    let (mut engine, events) = engine_on_api(device, 21);
    block_on(engine.start(LoginSecret::new(RECIPIENT_SECRET.to_vec()), None))
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
    let refreshed = block_on_while_ticking(engine_m.command(Command::ManualRefresh), &mut tasks_m);
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

/// A write grantee restores a prior version below the grafted root. The owner
/// then reads the restored content as the head, and the outgoing head as the
/// prior version.
#[test]
fn a_write_grantees_version_restore_reaches_the_owner() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let bodies = two_bodies(7);
    let file = file_with_two_versions(
        &world,
        &mut engine_t,
        &mut tasks_t,
        shared,
        "doc.bin",
        &bodies,
    );
    import_recipient(&mut engine_t);
    grant_to_recipient_at(&mut engine_t, shared, Permission::Write);

    let (mut engine_r, _events_r, mut tasks_r) = recipient_with_the_share(&world, &blocks);
    assert_eq!(grafted_child(&engine_r, shared, "doc.bin"), file);
    let prior = block_on(engine_r.file_versions(file)).expect("the grantee reads the history");
    assert_eq!(prior.len(), 1);
    block_on(engine_r.command(Command::RestoreVersion {
        node: file,
        content_cid: prior[0].content_cid.clone(),
    }))
    .expect("a version restore below a proved write root journals");
    tick_n(&world, &engine_r, &mut tasks_r, 4);

    tick_n(&world, &engine_t, &mut tasks_t, 4);
    assert_reads_both_versions(
        &engine_t,
        file,
        &[bodies[1].clone(), bodies[0].clone()],
        "the owner",
    );
}

// ---------------------------------------------------------------------------
// The lazy wave a cut leaves behind
// ---------------------------------------------------------------------------

/// Every record every endpoint holds, as `(endpoint, routing key, record)`.
fn records(world: &FakeWorld) -> Vec<(String, String, Vec<u8>)> {
    let store = &world.record_store;
    store
        .endpoints()
        .into_iter()
        .flat_map(|endpoint| {
            store.routing_keys(&endpoint).into_iter().map(move |key| {
                let record = store.record_at(&endpoint, &key);
                (
                    endpoint.0.clone(),
                    key,
                    record.expect("a listed key holds a record"),
                )
            })
        })
        .collect()
}

/// The highest epoch any record on the plane carries for `node` sealed in
/// `scope`, whatever name it publishes under.
fn epoch_in_scope(world: &FakeWorld, blocks: &Blocks, scope: NodeId, node: NodeId) -> u64 {
    records(world)
        .into_iter()
        .filter_map(|(_, key, bytes)| {
            let name = IpnsName::parse(&key).ok()?;
            let record = IpnsRecord::unmarshal(&bytes).ok()?.verify(&name).ok()?;
            let cid = core::str::from_utf8(&record.value)
                .ok()?
                .strip_prefix("/ipfs/")?
                .to_owned();
            let envelope = decode_envelope(&blocks.get(&cid)?).ok()?;
            (envelope.id == node.0 && envelope.scope == scope.0).then_some(envelope.epoch)
        })
        .max()
        .unwrap_or_else(|| panic!("no record of the node in the scope"))
}

/// Run the tasks a command spawned until each ends, one poll cadence apart.
fn run_spawned_to_end(world: &FakeWorld, mut spawned: Vec<BoxedTask>, step: core::time::Duration) {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..16 {
        spawned.retain_mut(|task| task.as_mut().poll(&mut cx).is_pending());
        if spawned.is_empty() {
            return;
        }
        world.scheduler.advance(step);
    }
    panic!("a spawned task never ended");
}

/// How many poll cadences one idle sweep cadence spans.
fn polls_per_sweep(engine: &Engine<FakeSeamTypes>) -> u32 {
    let profile = engine.profile();
    u32::try_from(profile.sweep_cadence.as_secs() / profile.poll_cadence.as_secs())
        .expect("a small ratio")
}

/// Advance the clock one poll cadence at a time, `times` times, polling `tasks`.
fn tick_n(world: &FakeWorld, engine: &Engine<FakeSeamTypes>, tasks: &mut [BoxedTask], times: u32) {
    for _ in 0..times {
        tick(world, engine, tasks);
    }
}

/// A cut enqueues the lazy wave. The spawned task re-seals the interior folder
/// the cut left at the old epoch, before any idle round or write reaches it.
#[test]
fn the_sweep_a_cut_enqueues_re_seals_the_folder_it_left_behind() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let device = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 42);
    let reports = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "reports");

    assert_eq!(
        block_on(engine.command(Command::RotateNow { node: ROOT })),
        Ok(CommandOutcome::Done)
    );
    let cut = published_epoch(&world, &blocks, ROOT);
    assert!(
        published_epoch(&world, &blocks, reports) < cut,
        "the cut leaves the folder at the old epoch"
    );

    // The clock does not move, so neither the tick nor the idle job wakes.
    let mut spawned = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut spawned);

    assert_eq!(published_epoch(&world, &blocks, reports), cut);
}

/// A cut whose own sweep failed leaves the folder behind, and nothing of the
/// wave is durable. After a restart the idle sweep job finds the scope past its
/// genesis epoch and converges the folder with no write to it.
#[test]
fn after_a_restart_the_idle_sweep_converges_what_a_failed_sweep_left() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let device = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 42);
    let shared = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "shared");
    let inner = create_published_folder(&world, &mut engine, &mut tasks, shared, "inner");
    import_recipient(&mut engine);
    grant_to_recipient(&mut engine, shared);

    assert_eq!(
        block_on(engine.command(Command::RotateNow { node: shared })),
        Ok(CommandOutcome::Done)
    );
    for endpoint in world.record_store.endpoints() {
        world.record_store.fail_endpoint(&endpoint);
    }
    run_spawned_to_end(
        &world,
        world.scheduler.take_spawned_tasks(),
        engine.profile().poll_cadence,
    );
    tick_n(&world, &engine, &mut tasks, 4);
    drop(tasks);
    drop(engine);
    for endpoint in world.record_store.endpoints() {
        world.record_store.heal_endpoint(&endpoint);
    }
    let cut = epoch_in_scope(&world, &blocks, shared, shared);
    assert!(
        epoch_in_scope(&world, &blocks, shared, inner) < cut,
        "no sweep landed before the restart"
    );

    let (restarted, _events, mut tasks) = boot(&world, &blocks, &device, 43);
    assert!(
        epoch_in_scope(&world, &blocks, shared, inner) < cut,
        "a cold start alone re-seals nothing"
    );
    let polls = polls_per_sweep(&restarted);
    tick_n(&world, &restarted, &mut tasks, 2 * polls);

    assert_eq!(epoch_in_scope(&world, &blocks, shared, inner), cut);
}

/// A read grantee holds no write seed for the scope, so its session never
/// sweeps it: the folder a cut left behind stays behind, and no record on the
/// plane changes, until the owner's own idle job re-seals it.
#[test]
fn a_read_only_member_never_runs_the_wave() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let inner = create_published_folder(&world, &mut engine_t, &mut tasks_t, shared, "inner");
    import_recipient(&mut engine_t);
    grant_to_recipient(&mut engine_t, shared);
    let (engine_r, _events_r, mut tasks_r) = recipient_with_the_share(&world, &blocks);

    assert_eq!(
        block_on(engine_t.command(Command::RotateNow { node: shared })),
        Ok(CommandOutcome::Done)
    );
    drop(world.scheduler.take_spawned_tasks());
    let cut = epoch_in_scope(&world, &blocks, shared, shared);
    assert!(
        epoch_in_scope(&world, &blocks, shared, inner) < cut,
        "the cut leaves the folder at the old epoch"
    );

    let before = records(&world);
    let polls = polls_per_sweep(&engine_r);
    tick_n(&world, &engine_r, &mut tasks_r, 3 * polls);
    assert_eq!(
        records(&world),
        before,
        "the read-only member publishes nothing"
    );

    tick_n(&world, &engine_t, &mut tasks_t, 2 * polls);
    assert_eq!(
        epoch_in_scope(&world, &blocks, shared, inner),
        cut,
        "the owner's idle job carries the wave"
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

/// A folder holding one file with `bodies` as its two versions, published and
/// drained, then granted to a contact with write permission. Answers the folder
/// and the file.
fn file_under_a_write_share(
    world: &FakeWorld,
    blocks: &Blocks,
    tab: &FakeDevice,
    bodies: &[Vec<u8>; 2],
) -> (Engine<FakeSeamTypes>, NodeId, NodeId) {
    let (mut engine, _events, mut tasks) = boot(world, blocks, tab, 42);
    let shared = create_published_folder(world, &mut engine, &mut tasks, ROOT, "shared");
    let file = file_with_two_versions(world, &mut engine, &mut tasks, shared, "notes.bin", bodies);
    assert_eq!(queued(tab), 0, "both versions drain before the share");

    import_recipient(&mut engine);
    let outcome = block_on(engine.command(Command::Grant {
        node: shared,
        recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        permission: Permission::Write,
        grantee_name: None,
    }));
    assert!(outcome.is_ok(), "the write share lands: {outcome:?}");
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
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (_engine, shared, file) = file_under_a_write_share(&world, &blocks, &tab, &two_bodies(5));

    for node in [ROOT, shared, file] {
        let name = write_name(node);
        let floor = block_on(tab.floors(&SECRET).sequence_floor(name.as_str().as_bytes()))
            .expect("the floor store answers")
            .expect("every record the share touched holds a sequence floor");
        let cached = tab
            .snapshot_cache
            .peek(name.as_str().as_bytes())
            .expect("every record the share touched is cached");
        let sequence = record_sequence(&name, &cached);
        if node == file {
            assert_eq!(
                sequence, floor,
                "the cached record of {node:?} sits at the floor the share raised"
            );
        } else {
            // The owner's own confirmed scope root publish is cached before a
            // read adopts it (ADR 0068 D2), so it may sit above the floor.
            assert!(
                sequence >= floor,
                "the floor the share raised does not pass the cached record of {node:?}"
            );
        }
    }
}

/// After a write share, a read that finds no record source opens the file
/// from its last-known-good: the head content, the version list, and a prior
/// version.
#[test]
fn a_file_under_a_write_share_reads_with_every_record_endpoint_down() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let bodies = two_bodies(11);
    let (engine, _shared, file) = file_under_a_write_share(&world, &blocks, &tab, &bodies);
    for endpoint in world.record_store.endpoints() {
        world.record_store.fail_endpoint(&endpoint);
    }
    assert_reads_both_versions(&engine, file, &bodies, "offline");
}

/// The grantee's stored bookmarks, read past the engine.
fn recipient_bookmarks(recipient: &FakeDevice) -> ReceivedSharesList {
    let entropy = RefCell::new(SeededEntropy::new(29));
    let enc = kdf::enc_subkey(&RECIPIENT_SECRET);
    block_on(StagingReceivedShareStore::new(&recipient.staging_store, &enc, &entropy).load())
        .expect("the bookmarks read")
}

/// Drop the scope pointer name from each of the grantee's stored bookmarks.
fn forget_scope_pointer_names(recipient: &FakeDevice) {
    let bare = without_scope_pointer_names(&recipient_bookmarks(recipient));
    let entropy = RefCell::new(SeededEntropy::new(31));
    let enc = kdf::enc_subkey(&RECIPIENT_SECRET);
    block_on(
        StagingReceivedShareStore::new(&recipient.staging_store, &enc, &entropy).persist(&bare),
    )
    .expect("the bookmarks persist");
}

/// What the grantee's device holds, and what the name wave does with its
/// kept ops, in [`kept_ops_through_a_downgrade`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum DowngradeCase {
    /// The bookmark holds the scope pointer name, and the wave carries the ops.
    Carried,
    /// The bookmark holds the scope pointer name, and the wave reads each
    /// record the ops wrote as it stood before them.
    Lost,
    /// The bookmark holds no scope pointer name, and the wave carries the ops.
    NoPointerName,
}

/// What the grantee's passes after a downgrade did.
struct AfterTheDowngrade {
    /// The dead-letter notices.
    notices: usize,
    /// The GETs at the names the wave moved below the scope root: only the
    /// drain's read of the moved tree makes them.
    moved_reads: usize,
}

/// The owner's `doc.bin` holds three versions, `nested` one folder below the
/// shared scope root. A write grantee runs `act` on it, and the queue keeps
/// each op after its publish. The owner then downgrades the grantee to read,
/// and `owner_sees` checks the moved tree. Every op on the file leaves the
/// grantee's queue, and a later op publishes.
fn kept_ops_through_a_downgrade(
    case: DowngradeCase,
    nested: bool,
    act: impl FnOnce(&World<'_>, &mut Engine<FakeSeamTypes>, &mut Vec<BoxedTask>, NodeId),
    owner_sees: impl FnOnce(&World<'_>, &mut Engine<FakeSeamTypes>, &mut Vec<BoxedTask>, NodeId, NodeId),
) -> AfterTheDowngrade {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let parent = if nested {
        create_published_folder(&world, &mut engine_t, &mut tasks_t, shared, "sub")
    } else {
        shared
    };
    let file = file_with_two_versions(
        &world,
        &mut engine_t,
        &mut tasks_t,
        parent,
        "doc.bin",
        &two_bodies(9),
    );
    write_file(
        &mut engine_t,
        WriteTarget::Version {
            node: file,
            expected_version: None,
        },
        &THIRD_BODY,
    )
    .expect("the third version commits");
    tick_n(&world, &engine_t, &mut tasks_t, 4);
    import_recipient(&mut engine_t);
    grant_to_recipient_at(&mut engine_t, shared, Permission::Write);

    let recipient = world.device(&recipient_identity().verifying_key().to_sec1());
    let (mut engine_r, mut events_r, mut tasks_r) =
        recipient_on_with_the_share(&world, &blocks, &recipient);
    if nested {
        block_on(engine_r.command(Command::SetFocus { node: Some(parent) }))
            .expect("the grantee opens the folder");
        tick_n(&world, &engine_r, &mut tasks_r, 2);
    }
    let endpoints = world.record_store.endpoints();
    let records = || -> std::collections::BTreeMap<String, Vec<u8>> {
        world
            .record_store
            .routing_keys(&endpoints[0])
            .into_iter()
            .filter_map(|key| {
                let record = world.record_store.record_at(&endpoints[0], &key)?;
                Some((key, record))
            })
            .collect()
    };
    let before_the_ops = records();
    act(&World(&world), &mut engine_r, &mut tasks_r, file);
    block_on(engine_r.command(Command::SetFocus { node: None }))
        .expect("the grantee closes the folder");
    tick_n(&world, &engine_r, &mut tasks_r, 4);
    let holds_an_op = || {
        let raw =
            block_on(StagingStore::queued_ops(&recipient.staging_store)).expect("the queue reads");
        decode_queue(
            &RecordReader::new(&kdf::enc_subkey(&RECIPIENT_SECRET)),
            &raw,
        )
        .mine
        .iter()
        .any(|(_, op)| op.target == file)
    };
    assert_eq!(queued(&recipient), 0, "the ops published");
    assert!(holds_an_op(), "and the queue keeps them");

    if case == DowngradeCase::NoPointerName {
        forget_scope_pointer_names(&recipient);
        tab.mailbox.set_post_failing(true);
    }
    // Served each record from before the ops, the wave carries the file as
    // it stood before them.
    let written: Vec<(String, Vec<u8>)> = if case == DowngradeCase::Lost {
        before_the_ops
            .into_iter()
            .filter(|(key, record)| {
                world.record_store.record_at(&endpoints[0], key).as_ref() != Some(record)
            })
            .collect()
    } else {
        Vec::new()
    };
    for (key, record) in &written {
        world
            .record_store
            .serve_gets_for_after(key, 0, endpoints.len() * 8, Some(record.clone()));
    }
    let before_the_wave: std::collections::BTreeSet<String> = records().into_keys().collect();
    assert_eq!(
        block_on(engine_t.command(Command::ChangePermission {
            node: shared,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done)
    );
    for (key, _) in &written {
        world.record_store.serve_gets_for_after(key, 0, 0, None);
    }
    block_on(engine_t.command(Command::SetFocus { node: Some(parent) }))
        .expect("the owner opens the folder");
    tick_n(&world, &engine_t, &mut tasks_t, 2);
    owner_sees(&World(&world), &mut engine_t, &mut tasks_t, parent, file);

    let gets_before = moved_gets(&world, &before_the_wave, shared);
    let _ = events_so_far(&mut events_r);
    tick_n(&world, &engine_r, &mut tasks_r, 16);
    assert_eq!(
        block_on(engine_r.received_shares()).expect("the list reads")[0].permission,
        Permission::Read,
        "the grantee holds the read grant"
    );
    assert_eq!(
        recipient_bookmarks(&recipient)
            .iter()
            .all(|share| share.scope_pointer_name.is_some()),
        case != DowngradeCase::NoPointerName,
        "the bookmark holds the scope pointer name unless the case drops it"
    );
    let moved_reads = moved_reads(&world, &recipient, &gets_before);
    assert!(!holds_an_op(), "each kept op left the queue");
    let notices = dead_letter_events(&mut events_r).len();
    let own_root = block_on(engine_r.view()).expect("a rendered view").root();
    block_on(engine_r.command(Command::Create {
        parent: own_root,
        name: "later".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a create in the grantee's own vault stages");
    tick_n(&world, &engine_r, &mut tasks_r, 4);

    assert_eq!(queued(&recipient), 0, "the later op published");
    AfterTheDowngrade {
        notices,
        moved_reads,
    }
}

/// The GET count of each name the wave moved below the shared scope root:
/// each key the store holds now that `before` lacks, but the scope pointer.
fn moved_gets(
    world: &FakeWorld,
    before: &std::collections::BTreeSet<String>,
    shared: NodeId,
) -> Vec<(String, usize)> {
    let pointer = scope_pointer_name(kdf::owner_pointer_seed(&SECRET).as_bytes(), &shared.0);
    let endpoint = &world.record_store.endpoints()[0];
    world
        .record_store
        .routing_keys(endpoint)
        .into_iter()
        .filter(|key| !before.contains(key) && *key != pointer.as_str())
        .map(|key| {
            let count = world.record_store.get_count(&key);
            (key, count)
        })
        .collect()
}

/// The GETs since `before` at the moved names, but the moved root that the
/// grantee's bookmark now names: only the drain's read of the moved tree
/// makes them.
fn moved_reads(world: &FakeWorld, recipient: &FakeDevice, before: &[(String, usize)]) -> usize {
    let roots: Vec<Vec<u8>> = recipient_bookmarks(recipient)
        .iter()
        .map(|share| share.scope_root_name.clone())
        .collect();
    before
        .iter()
        .filter(|(key, _)| !roots.contains(&key.as_bytes().to_vec()))
        .map(|(key, count)| world.record_store.get_count(key) - count)
        .sum()
}

/// The world a grantee's `act` ticks in.
struct World<'w>(&'w FakeWorld);

/// The third version of `doc.bin`, its head before the grantee acts.
const THIRD_BODY: [u8; 50] = [7u8; 50];

/// The grantee commits one version of the file.
fn edit(
    world: &World<'_>,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut Vec<BoxedTask>,
    file: NodeId,
) {
    write_file(
        engine,
        WriteTarget::Version {
            node: file,
            expected_version: None,
        },
        &[3u8; 70],
    )
    .expect("the grantee's version commits");
    tick_n(world.0, engine, tasks, 2);
}

/// The owner reads the grantee's edit exactly when the wave carried it.
fn edit_carried(
    carried: bool,
) -> impl FnOnce(&World<'_>, &mut Engine<FakeSeamTypes>, &mut Vec<BoxedTask>, NodeId, NodeId) {
    move |_, engine, _, _, file| {
        assert_eq!(
            block_on(engine.read_content(file)).map_err(|e| e.to_string()) == Ok(vec![3u8; 70]),
            carried,
            "the moved tree carries the grantee's edit exactly when the case does"
        );
    }
}

/// A downgrade takes the write seed, so a kept edit does not apply again. With
/// no scope pointer name the device cannot read the moved tree, so the edit
/// dead-letters at the keyless budget rather than halt the queue for ever
/// (ADR 0069 D3).
#[test]
fn a_downgraded_grantees_kept_edit_does_not_stop_its_queue() {
    let after = kept_ops_through_a_downgrade(
        DowngradeCase::NoPointerName,
        false,
        edit,
        edit_carried(true),
    );
    assert_eq!(after.notices, 1, "as a dead letter");
    assert_eq!(after.moved_reads, 0, "and no read of the moved tree");
}

/// A downgraded grantee reads the moved tree under the pointer read key, sees
/// that the wave carried its kept edit, and the edit leaves with no notice
/// (ADR 0069 D3).
#[test]
fn a_downgraded_grantees_carried_kept_edit_leaves_with_no_notice() {
    for nested in [false, true] {
        let after =
            kept_ops_through_a_downgrade(DowngradeCase::Carried, nested, edit, edit_carried(true));
        assert_eq!(after.notices, 0, "nested {nested}: no notice");
        assert!(
            after.moved_reads > 0,
            "nested {nested}: after a read of the moved tree"
        );
    }
}

/// The same kept edit, which the wave did not carry, dead-letters with a
/// notice after the read of the moved tree (ADR 0069 D3).
#[test]
fn a_downgraded_grantees_lost_kept_edit_dead_letters_after_the_read() {
    let after = kept_ops_through_a_downgrade(DowngradeCase::Lost, false, edit, edit_carried(false));
    assert_eq!(after.notices, 1, "as a dead letter");
    assert!(after.moved_reads > 0, "after a read of the moved tree");
}

/// A rename that the wave carried leaves with no notice after the read of the
/// moved tree shows its result.
#[test]
fn a_downgraded_grantees_carried_kept_rename_leaves_with_no_notice() {
    let after = kept_ops_through_a_downgrade(
        DowngradeCase::Carried,
        true,
        |world, engine, tasks, file| {
            block_on(engine.command(Command::Rename {
                node: file,
                new_name: "b.bin".into(),
            }))
            .expect("the rename stages");
            tick_n(world.0, engine, tasks, 2);
        },
        |_, engine, _, parent, _| {
            assert_eq!(
                listed_names(engine, parent),
                vec!["b.bin".to_owned()],
                "the moved tree carries the rename"
            );
        },
    );
    assert_eq!(after.notices, 0, "no notice");
    assert!(after.moved_reads > 0, "after a read of the moved tree");
}

/// A kept delete whose folder the owner deletes after the wave. A read of the
/// moved tree drops the folder from the base, so the delete leaves with no
/// notice (ADR 0069 D6).
#[test]
fn a_downgraded_grantees_kept_delete_whose_folder_went_leaves_with_no_notice() {
    let after = kept_ops_through_a_downgrade(
        DowngradeCase::Carried,
        true,
        |world, engine, tasks, file| {
            block_on(engine.command(Command::Delete { node: file })).expect("the delete stages");
            tick_n(world.0, engine, tasks, 2);
        },
        |world, engine, tasks, parent, _| {
            block_on(engine.command(Command::Delete { node: parent }))
                .expect("the owner deletes the folder");
            tick_n(world.0, engine, tasks, 4);
        },
    );
    assert_eq!(after.notices, 0, "no notice");
}

/// The cut set of a downgrade lands before the wave re-points the scope
/// pointer. While the pointer names a root of no later write epoch than the
/// kept edit's, the read of that tree cannot show that the wave carried the
/// edit, so the edit does not leave with no notice (ADR 0069 D3).
#[test]
fn a_kept_edit_stays_while_the_pointer_names_its_own_write_epoch() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let file = file_with_two_versions(
        &world,
        &mut engine_t,
        &mut tasks_t,
        shared,
        "doc.bin",
        &two_bodies(9),
    );
    import_recipient(&mut engine_t);
    grant_to_recipient_at(&mut engine_t, shared, Permission::Write);
    let recipient = world.device(&recipient_identity().verifying_key().to_sec1());
    let (mut engine_r, mut events_r, mut tasks_r) =
        recipient_on_with_the_share(&world, &blocks, &recipient);
    let change = |engine: &mut Engine<FakeSeamTypes>, permission| {
        block_on(engine.command(Command::ChangePermission {
            node: shared,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission,
        }))
    };
    // A first downgrade and upgrade put the scope pointer up at a moved root.
    for permission in [Permission::Read, Permission::Write] {
        assert_eq!(change(&mut engine_t, permission), Ok(CommandOutcome::Done));
        tick_n(&world, &engine_t, &mut tasks_t, 2);
        tick_n(&world, &engine_r, &mut tasks_r, 8);
    }
    assert_eq!(
        block_on(engine_r.received_shares()).expect("the list reads")[0].permission,
        Permission::Write,
        "the grantee writes again"
    );
    write_file(
        &mut engine_r,
        WriteTarget::Version {
            node: file,
            expected_version: None,
        },
        &[3u8; 70],
    )
    .expect("the grantee's version commits");
    tick_n(&world, &engine_r, &mut tasks_r, 4);
    let holds_the_edit = || {
        let raw =
            block_on(StagingStore::queued_ops(&recipient.staging_store)).expect("the queue reads");
        decode_queue(
            &RecordReader::new(&kdf::enc_subkey(&RECIPIENT_SECRET)),
            &raw,
        )
        .mine
        .iter()
        .any(|(_, op)| op.target == file)
    };
    assert_eq!(queued(&recipient), 0, "the edit published");
    assert!(holds_the_edit(), "and the queue keeps it");

    // The grantee reads the scope pointer as it stood before the second
    // downgrade: the re-point has not reached it.
    let pointer = scope_pointer_name(kdf::owner_pointer_seed(&SECRET).as_bytes(), &shared.0);
    let endpoints = world.record_store.endpoints();
    let before = world
        .record_store
        .record_at(&endpoints[0], pointer.as_str())
        .expect("the first downgrade put the pointer up");
    assert_eq!(
        change(&mut engine_t, Permission::Read),
        Ok(CommandOutcome::Done)
    );
    tick_n(&world, &engine_t, &mut tasks_t, 2);
    world
        .record_store
        .serve_gets_for_after(pointer.as_str(), 0, 10_000, Some(before));
    let _ = events_so_far(&mut events_r);
    tick_n(&world, &engine_r, &mut tasks_r, 16);

    assert!(
        holds_the_edit() || dead_letter_events(&mut events_r).len() == 1,
        "the edit stays, or dead-letters with a notice"
    );
}

/// Two renames of one file that the wave lost. The moved tree shows the name
/// before both, which is the result of neither, so each dead-letters with a
/// notice: only the op's own result decides it under a keyless scope.
#[test]
fn a_downgraded_grantees_lost_rename_chain_dead_letters_each_rename() {
    let after = kept_ops_through_a_downgrade(
        DowngradeCase::Lost,
        true,
        |world, engine, tasks, file| {
            for name in ["b.bin", "c.bin"] {
                block_on(engine.command(Command::Rename {
                    node: file,
                    new_name: name.into(),
                }))
                .expect("the rename stages");
                tick_n(world.0, engine, tasks, 2);
            }
        },
        |_, engine, _, parent, _| {
            assert_eq!(
                listed_names(engine, parent),
                vec!["doc.bin".to_owned()],
                "the moved tree carries neither rename"
            );
        },
    );
    assert_eq!(after.notices, 2, "each rename dead-letters");
    assert!(after.moved_reads > 0, "after a read of the moved tree");
}

/// Two version restores of one file that the wave lost. The moved head is the
/// head before both, which is the result of neither, so each dead-letters
/// with a notice.
#[test]
fn a_downgraded_grantees_lost_restore_chain_dead_letters_each_restore() {
    let after = kept_ops_through_a_downgrade(
        DowngradeCase::Lost,
        true,
        |world, engine, tasks, file| {
            let prior =
                block_on(engine.file_versions(file)).expect("the grantee reads the history");
            assert_eq!(prior.len(), 2, "two prior versions");
            for version in prior.iter().rev() {
                block_on(engine.command(Command::RestoreVersion {
                    node: file,
                    content_cid: version.content_cid.clone(),
                }))
                .expect("the restore stages");
                tick_n(world.0, engine, tasks, 2);
            }
        },
        |_, engine, _, _, file| {
            assert_eq!(
                block_on(engine.read_content(file)).map_err(|e| e.to_string()),
                Ok(THIRD_BODY.to_vec()),
                "the moved tree carries neither restore"
            );
        },
    );
    assert_eq!(after.notices, 2, "each restore dead-letters");
    assert!(after.moved_reads > 0, "after a read of the moved tree");
}

/// A write grantee's delete of a folder directly below the shared scope root
/// stays kept after its publish, and its note names the root. The owner then
/// downgrades the grantee, after a read of the root when `owner_reads_first`.
/// Answers whether the moved tree lists the folder, and the grantee's
/// dead-letter notices; the kept delete has left the queue.
fn kept_root_delete_through_a_downgrade(owner_reads_first: bool) -> (bool, usize) {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let gone = create_published_folder(&world, &mut engine_t, &mut tasks_t, shared, "gone");
    import_recipient(&mut engine_t);
    grant_to_recipient_at(&mut engine_t, shared, Permission::Write);

    let recipient = world.device(&recipient_identity().verifying_key().to_sec1());
    let (mut engine_r, mut events_r, mut tasks_r) =
        recipient_on_with_the_share(&world, &blocks, &recipient);
    block_on(engine_r.command(Command::Delete { node: gone }))
        .expect("the grantee's delete stages");
    tick_n(&world, &engine_r, &mut tasks_r, 4);
    let holds_the_delete = || {
        let raw =
            block_on(StagingStore::queued_ops(&recipient.staging_store)).expect("the queue reads");
        decode_queue(
            &RecordReader::new(&kdf::enc_subkey(&RECIPIENT_SECRET)),
            &raw,
        )
        .mine
        .iter()
        .any(|(_, op)| op.target == gone)
    };
    assert_eq!(queued(&recipient), 0, "the delete published");
    assert!(holds_the_delete(), "and the queue keeps it");

    if owner_reads_first {
        block_on(engine_t.command(Command::SetFocus { node: Some(shared) }))
            .expect("the owner opens the folder");
        tick_n(&world, &engine_t, &mut tasks_t, 4);
    }
    assert_eq!(
        block_on(engine_t.command(Command::ChangePermission {
            node: shared,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done)
    );
    block_on(engine_t.command(Command::SetFocus { node: Some(shared) }))
        .expect("the owner opens the folder");
    tick_n(&world, &engine_t, &mut tasks_t, 2);
    let listed = listed_names(&engine_t, shared).contains(&"gone".to_owned());
    let _ = events_so_far(&mut events_r);
    tick_n(&world, &engine_r, &mut tasks_r, 8);

    assert!(!holds_the_delete(), "the kept delete left the queue");
    (listed, dead_letter_events(&mut events_r).len())
}

/// The owner's wave carries the deleted folder back, so the moved tree shows
/// the delete lost: it takes the keyless charge and dead-letters with a
/// notice, as a lost kept edit does (ADR 0069 D3).
#[test]
fn a_downgraded_grantees_kept_delete_dead_letters_at_the_keyless_budget() {
    assert_eq!(
        kept_root_delete_through_a_downgrade(false),
        (true, 1),
        "the moved tree lists the folder, and the delete dead-letters"
    );
}

/// The owner reads the root before the downgrade, so the wave carries the
/// delete, and the healed root listing shows the folder gone: the delete
/// leaves with no notice (ADR 0069 D6).
#[test]
fn a_downgraded_grantees_carried_root_delete_leaves_with_no_notice() {
    assert_eq!(
        kept_root_delete_through_a_downgrade(true),
        (false, 0),
        "the moved tree lacks the folder, and the delete leaves with no notice"
    );
}

/// A downgraded write grantee's kept delete of X in /shared/A/B/X, after a
/// restart that does not read B before the grantee's passes run. The scope
/// is keyless, so the delete still takes the keyless charge and
/// dead-letters with a notice; it never leaves as gone (ADR 0069 D3).
#[test]
fn a_downgraded_grantees_deep_kept_delete_dead_letters_after_a_restart() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let a = create_published_folder(&world, &mut engine_t, &mut tasks_t, shared, "a");
    let b = create_published_folder(&world, &mut engine_t, &mut tasks_t, a, "b");
    let x = create_published_folder(&world, &mut engine_t, &mut tasks_t, b, "x");
    import_recipient(&mut engine_t);
    grant_to_recipient_at(&mut engine_t, shared, Permission::Write);

    let recipient = world.device(&recipient_identity().verifying_key().to_sec1());
    let (mut engine_r, _events_r, mut tasks_r) =
        recipient_on_with_the_share(&world, &blocks, &recipient);
    for folder in [a, b] {
        block_on(engine_r.command(Command::SetFocus { node: Some(folder) }))
            .expect("the grantee opens the folder");
        tick_n(&world, &engine_r, &mut tasks_r, 2);
    }
    block_on(engine_r.command(Command::Delete { node: x })).expect("the grantee's delete stages");
    tick_n(&world, &engine_r, &mut tasks_r, 4);
    let holds_the_delete = || {
        let raw =
            block_on(StagingStore::queued_ops(&recipient.staging_store)).expect("the queue reads");
        decode_queue(
            &RecordReader::new(&kdf::enc_subkey(&RECIPIENT_SECRET)),
            &raw,
        )
        .mine
        .iter()
        .any(|(_, op)| op.target == x)
    };
    assert_eq!(queued(&recipient), 0, "the delete published");
    assert!(holds_the_delete(), "and the queue keeps it");

    assert_eq!(
        block_on(engine_t.command(Command::ChangePermission {
            node: shared,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done)
    );
    tick_n(&world, &engine_t, &mut tasks_t, 2);
    drop((engine_r, tasks_r));
    let (mut engine_r, mut events_r) = engine_on_api(&recipient, 22);
    block_on(engine_r.start(LoginSecret::new(RECIPIENT_SECRET.to_vec()), None))
        .expect("the grantee's session restarts");
    let mut tasks_r = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks_r);
    tick_n(&world, &engine_r, &mut tasks_r, 10);

    assert!(!holds_the_delete(), "the kept delete left the queue");
    assert_eq!(
        dead_letter_events(&mut events_r).len(),
        1,
        "as a dead letter with a notice"
    );
}

/// The dead-letter notices on `events` since the last read.
fn dead_letter_events(events: &mut EventStream) -> Vec<Event> {
    events_so_far(events)
        .into_iter()
        .filter(|event| matches!(event, Event::DeadLetter { .. }))
        .collect()
}

/// A write grantee's create lands in the old tree after the name wave of its
/// downgrade read the folder, so the moved tree does not carry it. The grantee
/// holds no new write seed, so the create dead-letters on its device with a
/// notice (ADR 0069 D3).
#[test]
fn a_downgraded_grantees_write_the_wave_did_not_carry_dead_letters() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks);
    let tab = world.device(&owner_identity().verifying_key().to_sec1());
    let (mut engine_t, _events_t, mut tasks_t) = boot(&world, &blocks, &tab, 42);
    let shared = create_published_folder(&world, &mut engine_t, &mut tasks_t, ROOT, "shared");
    let child = create_published_folder(&world, &mut engine_t, &mut tasks_t, shared, "child");
    import_recipient(&mut engine_t);
    grant_to_recipient_at(&mut engine_t, shared, Permission::Write);

    let recipient = world.device(&recipient_identity().verifying_key().to_sec1());
    let (mut engine_r, mut events_r, mut tasks_r) =
        recipient_on_with_the_share(&world, &blocks, &recipient);
    block_on(engine_r.command(Command::SetFocus { node: Some(child) }))
        .expect("the grantee opens the folder");
    tick_n(&world, &engine_r, &mut tasks_r, 2);
    let endpoints = world.record_store.endpoints();
    let walked: std::collections::BTreeMap<String, Vec<u8>> = world
        .record_store
        .routing_keys(&endpoints[0])
        .into_iter()
        .filter_map(|key| {
            let record = world.record_store.record_at(&endpoints[0], &key)?;
            Some((key, record))
        })
        .collect();
    block_on(engine_r.command(Command::Create {
        parent: child,
        name: "late".into(),
        kind: NodeKind::Folder,
    }))
    .expect("the grantee's create stages");
    tick_n(&world, &engine_r, &mut tasks_r, 2);
    assert_eq!(queued(&recipient), 0, "the create published");
    let written: Vec<(String, Vec<u8>)> = walked
        .into_iter()
        .filter(|(key, record)| {
            world.record_store.record_at(&endpoints[0], key).as_ref() != Some(record)
        })
        .collect();
    assert!(!written.is_empty(), "the create moved a folder record");

    for (key, record) in &written {
        world
            .record_store
            .serve_gets_for_after(key, 0, endpoints.len() * 8, Some(record.clone()));
    }
    block_on(engine_r.command(Command::SetFocus { node: None }))
        .expect("the grantee closes the folder");
    let before_the_wave: std::collections::BTreeSet<String> = world
        .record_store
        .routing_keys(&endpoints[0])
        .into_iter()
        .collect();
    assert_eq!(
        block_on(engine_t.command(Command::ChangePermission {
            node: shared,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done)
    );
    for (key, _) in &written {
        world.record_store.serve_gets_for_after(key, 0, 0, None);
    }
    block_on(engine_t.command(Command::SetFocus { node: Some(child) }))
        .expect("the owner opens the folder");
    tick_n(&world, &engine_t, &mut tasks_t, 4);
    assert!(
        !listed_names(&engine_t, child).contains(&"late".to_owned()),
        "the moved tree does not carry the create"
    );
    let gets_before = moved_gets(&world, &before_the_wave, shared);
    let _ = events_so_far(&mut events_r);

    tick_n(&world, &engine_r, &mut tasks_r, 10);

    assert!(
        moved_reads(&world, &recipient, &gets_before) > 0,
        "the grantee read the moved tree"
    );

    assert!(
        recipient_bookmarks(&recipient)
            .iter()
            .all(|share| share.scope_pointer_name.is_some()),
        "the grantee reads the moved tree under its scope pointer"
    );
    assert_eq!(
        dead_letter_events(&mut events_r).len(),
        1,
        "the create dead-letters with a notice"
    );
    let status = block_on(engine_r.status()).expect("the session status reads");
    assert_eq!(status.dead_letters.len(), 1, "and the member can name it");
}
