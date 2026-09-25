//! Convergence across the owner's own devices once a cut has made an interior
//! folder a scope root of its own: the browser tab writes inside it, and the
//! mounted desktop must see what it published.
//!
//! Every assertion lands on published bytes, a drained queue, or a rendered
//! view — what the other device would see.

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
    SeededEntropy, block_on, block_on_while_ticking, poll_tasks_until_parked,
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
    let name = vault_pointer_name(&SECRET, 0);
    let endpoint = world.record_store.endpoints()[0].clone();
    let bytes = world
        .record_store
        .record_at(&endpoint, name.as_str())
        .expect("the vault pointer is published");
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
    .min_read_epoch
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
        .fail_epoch_floor_reads_after(&SCOPE, CATCH_UP_FLOOR_READ);
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
        },
        Command::Revoke {
            node: ROOT,
            recipient_identity_public_key: recipient.clone(),
        },
        Command::Downgrade {
            node: ROOT,
            recipient_identity_public_key: recipient.clone(),
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
        assert_eq!(
            record_sequence(&name, &cached),
            floor,
            "the cached record of {node:?} sits at the floor the share raised"
        );
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
