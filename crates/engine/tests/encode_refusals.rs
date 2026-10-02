//! Encode-side refusals of the engine's own formats, and of the produce-side
//! gate every record publish passes (AGENTS.md rule 8). CI also runs this file
//! under `--release`, where `debug_assert!` is compiled out, so a refusal that
//! leans on one fails there.

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildRef, NodeKind as CoreNodeKind, PreservedFields, ReadBody, encode_envelope, seal_read_body,
};
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_engine::api::ApiClient;
use cipherbox_engine::gate::{floor, record_cut_epoch_floor};
use cipherbox_engine::grants::conversion::{
    ConversionRecord, MAX_CLAIM_PAYLOAD_BYTES, encode_conversions,
};
use cipherbox_engine::grants::{
    AckedClaim, CLAIM_ID_LEN, InviteClaim, InviteError, InviteFragment, MAX_INVITE_FRAGMENT_BYTES,
};
use cipherbox_engine::net::author::ENVELOPE_V;
use cipherbox_engine::net::renewal_walk::cursor::{
    CursorCodecError, DeferredRoot, MAX_CURSOR_PATH, MAX_DEFERRED_ROOTS, RenewalCursor,
    encode_cursor,
};
use cipherbox_engine::net::{
    BarFloor, Observed, PublishBar, PublishError, PublishOutcome, PublishRequest, publish,
};
use cipherbox_engine::rotation::derive_write_name;
use cipherbox_engine::seams::{
    BoxedTask, FloorStore, HttpResponse, RecordTransport, StagingStore, UnixMillis,
};
use cipherbox_engine::sync::BookkeepingSeal;
use cipherbox_engine::sync::owed_rotation::{
    MAX_OWED_ENTRIES, OwedEntry, OwedRecord, OwedRecordError, OwedStep, seal_owed_record,
};
use cipherbox_engine::testkit::SeededEntropy;
use cipherbox_engine::testkit::account::{
    Blocks, EOL, ROOT, SCOPE as ACCOUNT_SCOPE, SECRET, TTL_NANOS, floor_label, fresh_observed,
    seed_account, seed_account_sealed, seed_account_with, serve_http,
};
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH, OWNER_ROOT_SCOPE_SEED,
    OWNER_ROOT_WRITE_SCOPE_SEED, block_on, poll_tasks_until_parked,
};
use cipherbox_engine::{
    ApiBaseUrl, Command, ContentProfile, Engine, EventStream, GatewayConfig, LoginSecret, NodeId,
    NodeKind, StoragePolicy, SyncTimingProfile,
};
use core::cell::RefCell;

fn pointer_name() -> IpnsName {
    IpnsName::from_public_key(&Ed25519Signer::from_seed([0x5d; 32]).verifying_key())
}

/// The decoder refuses a fragment past its bound, so the encoder refuses to
/// produce one: an owner contact code of the whole bound leaves no room.
#[test]
fn a_fragment_whose_contact_code_fills_the_bound_is_refused_at_encode() {
    let fragment = InviteFragment {
        invite_secret: SecretBytes::new([0x4e; 32]),
        owner_contact_code: vec![0xa5; MAX_INVITE_FRAGMENT_BYTES],
        scope_id: [0x5c; 16],
        scope_pointer_name: IpnsName::from_public_key(
            &Ed25519Signer::from_seed([0x5d; 32]).verifying_key(),
        ),
        pointer_read_key: SecretBytes::new([0x66; 32]),
        owner_name: String::new(),
        folder_name: "Photos".to_owned(),
        names_sig: [0; SIGNATURE_LEN],
    };
    assert_eq!(
        fragment.encode().map(|_| ()),
        Err(InviteError::FragmentTooLarge)
    );
}

/// The decoder refuses a claim whose name no ledger row can carry, so the
/// encoder refuses to produce one.
#[test]
fn a_claim_with_an_unusable_name_is_refused_at_encode() {
    let claim = InviteClaim {
        claim_id: [0x71; CLAIM_ID_LEN],
        scope_pointer_name: pointer_name(),
        contact_code: vec![0x02; 40],
        name: "a\u{7}b".to_owned(),
    };
    assert_eq!(claim.encode(), Err(InviteError::InvalidClaimName));
}

/// The conversion record's decoder refuses a claim payload past its bound, so
/// its encoder refuses to write one.
#[test]
fn a_conversion_record_holding_a_payload_past_its_bound_is_refused_at_encode() {
    let mut record = ConversionRecord::default();
    record.hold_for_ack(AckedClaim {
        sender: [0x02; IDENTITY_PUBLIC_LEN],
        payload: vec![0; MAX_CLAIM_PAYLOAD_BYTES + 1],
        acked_at: UnixMillis(1),
    });
    assert!(encode_conversions(&record).is_err());
}

/// The renewal cursor's decoder refuses a path or a deferred set past its cap,
/// so its encoder refuses to write one.
#[test]
fn a_renewal_cursor_past_either_cap_is_refused_at_encode() {
    let mut cursor = RenewalCursor::starting(UnixMillis(0));
    cursor.path = vec![[1; 16]; MAX_CURSOR_PATH + 1];
    assert_eq!(encode_cursor(&cursor), Err(CursorCodecError::PathTooLong));

    let mut cursor = RenewalCursor::starting(UnixMillis(0));
    cursor.deferred = vec![
        DeferredRoot {
            scope_id: [2; 16],
            node_id: [3; 16],
            name: pointer_name(),
        };
        MAX_DEFERRED_ROOTS + 1
    ];
    assert_eq!(
        encode_cursor(&cursor),
        Err(CursorCodecError::TooManyDeferred)
    );
}

// ---------------------------------------------------------------------------
// The produce-side gate every record publish passes (`net::publish`).
// ---------------------------------------------------------------------------

const SCOPE: [u8; 16] = [0x3c; 16];

/// Publish a fresh head over `observed` under `bar`.
fn publish_under(
    device: &FakeDevice,
    signer: &Ed25519Signer,
    observed: &Observed,
    bar: Option<PublishBar>,
) -> Result<PublishOutcome, PublishError> {
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    device.http.enqueue_response(HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: Vec::new(),
    });
    block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.scheduler,
        &SyncTimingProfile::CI,
        &PublishRequest {
            observed,
            signer,
            head_cid: "bafyhead".to_owned(),
            content_cids: Vec::new(),
            bar,
        },
    ))
    .map(|receipt| receipt.outcome)
}

fn nothing_reached_the_transport(device: &FakeDevice, name: &IpnsName) -> bool {
    device.record_store.endpoints().iter().all(|endpoint| {
        device
            .record_store
            .record_at(endpoint, name.as_str())
            .is_none()
    })
}

fn root_bar(read_epoch: u64, write_epoch: u64, cut_epoch: u64) -> PublishBar {
    PublishBar {
        scope_id: SCOPE,
        read_epoch,
        write_epoch: Some(write_epoch),
        cut_epoch: Some(cut_epoch),
    }
}

fn name_of(signer: &Ed25519Signer) -> IpnsName {
    IpnsName::from_public_key(&signer.verifying_key())
}

/// The gate refuses a record below each durable floor of its bar at the
/// signature, so no build signs a record its own adoption gate refuses for
/// good.
#[test]
fn a_record_below_any_floor_of_its_bar_is_refused_at_the_signature() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    block_on(device.floor_store.raise_epoch_floor(&SCOPE, 5)).unwrap();
    block_on(floor::seed_scope_root_write_epoch(
        &device.floor_store,
        &SCOPE,
        4,
    ))
    .unwrap();
    block_on(record_cut_epoch_floor(&device.floor_store, &SCOPE, 3)).unwrap();
    for (seed, bar, floor, at, epoch) in [
        (0x41, root_bar(4, 4, 3), BarFloor::Read, 5, 4),
        (0x42, root_bar(5, 3, 3), BarFloor::Write, 4, 3),
        (0x43, root_bar(5, 4, 2), BarFloor::Cut, 3, 2),
    ] {
        let signer = Ed25519Signer::from_seed([seed; 32]);
        let name = name_of(&signer);
        assert_eq!(
            publish_under(&device, &signer, &fresh_observed(&name), Some(bar)),
            Err(PublishError::BelowBar { floor, at, epoch }),
        );
        assert!(nothing_reached_the_transport(&device, &name));
    }
    let signer = Ed25519Signer::from_seed([0x44; 32]);
    let name = name_of(&signer);
    assert_eq!(
        publish_under(
            &device,
            &signer,
            &fresh_observed(&name),
            Some(root_bar(5, 4, 3))
        ),
        Ok(PublishOutcome::Published { sequence: 1 }),
    );
}

/// A record built on a newer client's envelope never yields a token to
/// publish with: republishing it would downgrade `v`.
#[test]
fn a_gated_read_at_another_envelope_version_yields_no_token() {
    let name = pointer_name();
    assert_eq!(
        Observed::gated(&name, 1, ENVELOPE_V + 1),
        Err(PublishError::ForeignVersion {
            version: ENVELOPE_V + 1
        }),
    );
    assert!(Observed::gated(&name, 1, ENVELOPE_V).is_ok());
}

/// The signature lands strictly above the observed record even where the
/// durable floor has not adopted it, and above the floor where the floor is
/// the higher of the two.
#[test]
fn the_signature_lands_above_both_the_observed_record_and_the_floor() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let signer = Ed25519Signer::from_seed([0x51; 32]);
    let name = name_of(&signer);
    let observed = Observed::gated(&name, 7, ENVELOPE_V).unwrap();
    assert_eq!(
        publish_under(&device, &signer, &observed, None),
        Ok(PublishOutcome::Published { sequence: 8 }),
    );

    let signer = Ed25519Signer::from_seed([0x52; 32]);
    let name = name_of(&signer);
    block_on(
        device
            .floor_store
            .raise_sequence_floor(name.as_str().as_bytes(), 9),
    )
    .unwrap();
    let observed = Observed::gated(&name, 2, ENVELOPE_V).unwrap();
    assert_eq!(
        publish_under(&device, &signer, &observed, None),
        Ok(PublishOutcome::Published { sequence: 10 }),
    );
}

/// No sequence exists above `u64::MAX`, so the gate refuses rather than wrap.
#[test]
fn an_observed_record_at_the_sequence_ceiling_is_refused() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let signer = Ed25519Signer::from_seed([0x53; 32]);
    let name = name_of(&signer);
    let observed = Observed::gated(&name, u64::MAX, ENVELOPE_V).unwrap();
    assert_eq!(
        publish_under(&device, &signer, &observed, None),
        Err(PublishError::SequenceExhausted),
    );
    assert!(nothing_reached_the_transport(&device, &name));
}
/// The decoder refuses an owed rotation record past its entry bound, and an
/// entry whose steps are not in command order, so the encoder refuses both.
#[test]
fn an_owed_rotation_record_the_decoder_refuses_is_refused_at_encode() {
    let enc = kdf::enc_subkey(&[0x31; 32]);
    let entropy = RefCell::new(SeededEntropy::new(3));
    let entry = |steps| OwedEntry {
        cut_epoch: 1,
        first_stop: None,
        steps,
    };

    let full: OwedRecord = (0..=MAX_OWED_ENTRIES)
        .map(|n| {
            let mut scope = [0; 16];
            scope[..8].copy_from_slice(&(n as u64).to_be_bytes());
            (NodeId(scope), entry(vec![OwedStep::ReadCut]))
        })
        .collect();
    assert_eq!(
        seal_owed_record(BookkeepingSeal::new(&enc, &entropy), &full),
        Err(OwedRecordError::Full)
    );

    let reversed = OwedRecord::from([(
        NodeId([4; 16]),
        entry(vec![
            OwedStep::WriteCut { write_epoch: 2 },
            OwedStep::ReadCut,
        ]),
    )]);
    assert_eq!(
        seal_owed_record(BookkeepingSeal::new(&enc, &entropy), &reversed),
        Err(OwedRecordError::StepsOutOfOrder)
    );
}

// ---------------------------------------------------------------------------
// Each author's publish goes through that gate.
// ---------------------------------------------------------------------------

type Session = (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>);

/// A started session on a seeded account, its loops parked.
fn booted(world: &FakeWorld, blocks: &Blocks, device: &FakeDevice) -> Session {
    serve_http(device, blocks, 400);
    let (mut engine, events) = Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(7)),
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy::CI,
        ApiBaseUrl::offline(),
        GatewayConfig {
            accelerator: Some("https://gw.test".into()),
            public_fallbacks: Vec::new(),
        },
    );
    block_on(engine.start(LoginSecret::new(SECRET.to_vec()), None)).expect("the session starts");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    (engine, events, tasks)
}

fn tick(world: &FakeWorld, engine: &Engine<FakeSeamTypes>, tasks: &mut [BoxedTask]) {
    world.scheduler.advance(engine.profile().poll_cadence);
    poll_tasks_until_parked(tasks);
}

fn record_at(world: &FakeWorld, name: &IpnsName) -> Option<Vec<u8>> {
    world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
}

/// The drain's publish passes the gate: a read-epoch floor that rises after
/// the drain proved its scope and before the signature refuses the record.
#[test]
fn a_drain_publish_whose_scope_floor_rises_inside_its_window_publishes_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let device = world.device(b"me");
    let (mut engine, _events, mut tasks) = booted(&world, &blocks, &device);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("the create stages");
    let folder = block_on(engine.view())
        .expect("a rendered view")
        .children(ROOT)
        .into_iter()
        .find(|child| child.name == "photos")
        .expect("the staged folder renders")
        .id;
    let name = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &folder.0);
    device.floor_store.raise_epoch_floor_on_sequence_read(
        &floor_label(name.as_str().as_bytes()),
        &floor_label(&ACCOUNT_SCOPE),
        OWNER_ROOT_EPOCH + 1,
    );
    tick(&world, &engine, &mut tasks);

    assert!(
        nothing_reached_the_transport(&device, &name),
        "the record sealed below the risen floor never reached the plane"
    );
    assert_eq!(queued(&device), 1, "and the create is still queued");
}

fn queued(device: &FakeDevice) -> usize {
    block_on(StagingStore::queued_ops(&device.staging_store))
        .expect("the queue reads")
        .len()
}

/// The drain anchors its pass on the scope root through the gate's version
/// rule: a root a newer client last wrote is never re-authored.
#[test]
fn a_drain_publish_never_re_authors_a_scope_root_at_another_envelope_version() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account_sealed(&world, &blocks, Vec::new(), Vec::new(), ENVELOPE_V + 1);
    let root_record = record_at(&world, &root_name);
    let device = world.device(b"me");
    let (mut engine, _events, mut tasks) = booted(&world, &blocks, &device);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("the create stages");
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        record_at(&world, &root_name),
        root_record,
        "the root at the newer version was never republished"
    );
    assert_eq!(queued(&device), 1, "and the create is still queued");
}

/// The drain re-authors a folder through the gate's version rule: a folder a
/// newer client last wrote is never re-sealed under this build's version.
#[test]
fn a_drain_publish_never_re_authors_a_folder_at_another_envelope_version() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let folder = NodeId([0x6f; 16]);
    let name = derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &folder.0);
    let body = ReadBody::Folder {
        created_at: 0,
        modified_at: 0,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let read_key = kdf::read_key(kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &folder.0).as_bytes());
    let envelope = seal_read_body(
        read_key.as_bytes(),
        &[0x4d; 24],
        ENVELOPE_V + 1,
        folder.0,
        ACCOUNT_SCOPE,
        OWNER_ROOT_EPOCH,
        &body,
    )
    .expect("the folder seals");
    let cid = blocks.put(encode_envelope(&envelope).expect("the head encodes"));
    let record = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &folder.0).as_bytes()),
        format!("/ipfs/{cid}").as_bytes(),
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
    seed_account_with(
        &world,
        &blocks,
        Vec::new(),
        vec![ChildRef {
            id: folder.0,
            name: "newer".into(),
            ipns_name: name.as_str().as_bytes().to_vec(),
            kind: CoreNodeKind::Folder,
            link_counter: 1,
            unknown: PreservedFields::new(),
        }],
    );
    let device = world.device(b"me");
    let (mut engine, _events, mut tasks) = booted(&world, &blocks, &device);
    block_on(engine.command(Command::Create {
        parent: folder,
        name: "inside".into(),
        kind: NodeKind::Folder,
    }))
    .expect("the create stages");
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        record_at(&world, &name),
        Some(record),
        "the folder at the newer version was never republished"
    );
    assert_eq!(queued(&device), 1, "and the create is still queued");
}
