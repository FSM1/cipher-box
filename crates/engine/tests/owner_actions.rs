//! The owner-action command arms, joined end to end over the fake seam world:
//! a manual rotation cuts the read plane, a revoke drives the cascade that
//! actually ends a grant, a grant refuses fail-closed, and a second account's
//! engine accepts a share it was sent.
//!
//! Every assertion lands on published bytes, a durable floor, or the recipient's
//! inbox — what another device would see — never on a command's return alone.

use core::cell::RefCell;

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{
    GrantSection, GrantSetCommitment, Permission as CorePermission, PreservedFields, ReadBody,
    decode_envelope, decode_grant_section, grant_section_bytes, open_read_body, sign_grant_set,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;

use zeroize::Zeroizing;

use cipherbox_engine::gate::floor;
use cipherbox_engine::grants::{
    CLAIM_ID_LEN, EphemeralInvitee, GrantRow, InviteClaim, InviteFragment, InviteRecords,
    InviteStore, MintedInvite, RecordedInvite, StagingInviteStore, import_contact, mint_grant_row,
    mint_invite_grant, post_invite_claim,
};
use cipherbox_engine::net::author::{
    ENVELOPE_V, EnvelopeAuthoring, author_scope_root_with_section,
};
use cipherbox_engine::rotation::{MAX_ROTATION_ATTEMPTS, published_override_seed};
use cipherbox_engine::seams::{BoxedTask, Mailbox, RecordTransport, Scheduler, UnixMillis};
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
    ApiBaseUrl, Command, CommandOutcome, CommittedSet, ContentProfile, Engine, EngineError,
    EventStream, GatewayConfig, LoginSecret, NodeId, NodeKind, Permission, ResealSeeds,
    ScopeRootIdentity, SharePointer, SharingInviteLinks, StoragePolicy, SyncTimingProfile,
    WriteHistory, post_sealed, reseal_scope_root,
};

/// The recipient account's login secret — every key their engine derives, and
/// the contact code the owner imports, hangs off it.
const RECIPIENT_SECRET: [u8; 32] = [0x5B; 32];
/// A second grantee's login secret — committed at the same root, and never the
/// party a revoke names.
const BYSTANDER_SECRET: [u8; 32] = [0x7C; 32];
/// The entropy seed the seeded vault pointer's re-point seal draws its nonce
/// from, and the one the seeded root's grant section draws its HPKE ephemerals
/// from. Named apart because a single (key, nonce) pair must never cover two
/// plaintexts (blueprint/core.md "Crypto suite").
const POINTER_SEAL_ENTROPY_SEED: u64 = 0;
const ROOT_SEAL_ENTROPY_SEED: u64 = 1;
/// The seeded root body's seal nonce and the share pointer's HPKE ephemeral,
/// held apart for the same reason.
const ROOT_BODY_NONCE: [u8; 24] = [0x31; 24];
const SHARE_POINTER_EPHEMERAL: [u8; 32] = [0x42; 32];

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn secret() -> LoginSecret {
    LoginSecret::new(SECRET.to_vec())
}

/// An engine against a configured API — the mode every owner action needs,
/// because the rotation and grant arms publish through the API client.
fn engine_on_api(device: &FakeDevice, entropy_seed: u64) -> (Engine<FakeSeamTypes>, EventStream) {
    engine_with(
        device,
        entropy_seed,
        ApiBaseUrl::parse("http://api.test").expect("a base"),
    )
}

fn engine_with(
    device: &FakeDevice,
    entropy_seed: u64,
    api_base_url: ApiBaseUrl,
) -> (Engine<FakeSeamTypes>, EventStream) {
    Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(entropy_seed)),
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy::CI,
        api_base_url,
        GatewayConfig {
            accelerator: Some("https://gw.test".into()),
            public_fallbacks: Vec::new(),
        },
    )
}

/// The owner's writer pseudonym for `SCOPE`. Every re-seal this session authors
/// signs under it, and a re-seal by a signer the set does not commit is refused
/// — so the seeded root must commit exactly this key.
fn owner_pseudonym() -> Ed25519Signer {
    kdf::pseudonym_sign(kdf::owner_pseudonym_seed(&SECRET).as_bytes(), &SCOPE)
}

/// The per-scope pointer read key the owner's own session derives.
fn owner_pointer_read_key() -> [u8; 32] {
    *kdf::pointer_read_key(kdf::owner_pointer_seed(&SECRET).as_bytes(), &SCOPE).as_bytes()
}

/// Publish the account's initial state: an owner root at sequence 1 carrying
/// `grants` as its committed set, and the vault pointer naming it.
fn seed_vault(world: &FakeWorld, blocks: &Blocks, grants: Vec<GrantRow>) -> IpnsName {
    let owner_identity = owner_identity();
    let pseudonym = owner_pseudonym();
    let owner_enc = kdf::enc_subkey(&SECRET);
    let owner_enc_pub = owner_enc.public();
    let name = write_name(ROOT);

    let commitment = GrantSetCommitment {
        ipns_name: name.as_str().as_bytes().to_vec(),
        owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
        entries: grants
            .iter()
            .map(|row| row.commitment_entry.clone())
            .collect(),
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(&owner_identity, &commitment)
        .expect("the owner signs its own grant set")
        .to_compact();
    let ledger: Vec<_> = grants.iter().map(|row| row.ledger_entry.clone()).collect();
    let pointer_read_key = owner_pointer_read_key();
    let section = reseal_scope_root(
        &mut SeededEntropy::new(ROOT_SEAL_ENTROPY_SEED + grants.len() as u64),
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
            owner_identity: &owner_identity.verifying_key(),
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &ledger,
            direct_child_scope_index: &[],
        },
        &[],
    )
    .expect("the seeded root seals");

    let head = author_scope_root_with_section(
        EnvelopeAuthoring {
            node_id: ROOT.0,
            scope_id: SCOPE,
            epoch: EPOCH,
            read_key: &read_key_of(ROOT),
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

/// A cold-started owner engine over a seeded vault, with the spawned loops
/// parked at their first sleep.
fn boot_owner(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    serve_http(device, blocks, 600);
    let (mut engine, events) = engine_on_api(device, 42);
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

/// Create `name` under `parent` and drive it all the way to the record plane.
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
    block_on(engine.view())
        .expect("a rendered view")
        .children(parent)
        .into_iter()
        .find(|child| child.name == name)
        .unwrap_or_else(|| panic!("no child named {name}"))
        .id
}

// ---------------------------------------------------------------------------
// Record-plane inspection
// ---------------------------------------------------------------------------

/// A node's write-plane IPNS name (`writeSeed(writeScopeSeed, id)` → keypair).
fn write_name(node: NodeId) -> IpnsName {
    IpnsName::from_public_key(
        &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes()).verifying_key(),
    )
}

/// A node's per-node read key under the account's first read-scope seed
/// (`nodeSeed(scopeSeed, id)` → `readKey`).
fn read_key_of(node: NodeId) -> [u8; 32] {
    *kdf::read_key(kdf::node_seed(&READ_SCOPE_SEED, &node.0).as_bytes()).as_bytes()
}

/// The head block of the record currently published under `name`, verified
/// under that name.
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

/// The read epoch the record published at `node` is sealed at.
fn published_read_epoch(world: &FakeWorld, blocks: &Blocks, node: NodeId) -> u64 {
    let head = published_head(world, blocks, &write_name(node)).expect("a published record");
    decode_envelope(&head).expect("the head decodes").epoch
}

/// The grant section the record published at `node` carries, if it is a scope
/// root at all.
fn published_grant_section(
    world: &FakeWorld,
    blocks: &Blocks,
    node: NodeId,
) -> Option<GrantSection> {
    let head = published_head(world, blocks, &write_name(node))?;
    let envelope = decode_envelope(&head).expect("the head decodes");
    grant_section_bytes(&envelope)
        .map(|bytes| decode_grant_section(bytes).expect("the section decodes"))
}

/// The sequence of the record published at `name`, verified under it.
fn sequence_at(world: &FakeWorld, name: &IpnsName) -> u64 {
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
        .expect("a record is published at the name");
    IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(name))
        .expect("the published record verifies under its own name")
        .sequence
}

// ---------------------------------------------------------------------------
// The recipient: a second account on the same world.
// ---------------------------------------------------------------------------

/// The recipient's identity signer — the key their contact code binds and the
/// address their inbox answers at.
fn recipient_identity() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&RECIPIENT_SECRET).expect("valid identity scalar")
}

/// A peer's contact code: the self-signed bundle a real import receives out of
/// band.
fn contact_code(scalar: &[u8; 32]) -> Vec<u8> {
    let identity = EcdsaSigner::from_scalar(scalar).expect("valid identity scalar");
    ContactCode::create(&identity, kdf::enc_subkey(scalar).public()).encode()
}

/// The recipient's committed grant row at the vault root — the row a revoke has
/// to find in the owner-signed set before it can cut anything.
fn recipient_row_at_root() -> GrantRow {
    mint_grant_row(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        recipient_identity().verifying_key().to_sec1(),
        &kdf::enc_subkey(&RECIPIENT_SECRET).public(),
        &SCOPE,
        write_name(ROOT).as_str().as_bytes(),
        CorePermission::Read,
    )
    .expect("a contributory recipient key")
}

/// A second grantee's committed row, carrying an `ownerSig` no owner key
/// verifies — a stale or corrupted signature over an otherwise honest row.
fn bystander_row_with_corrupt_sig() -> GrantRow {
    let bystander = EcdsaSigner::from_scalar(&BYSTANDER_SECRET).expect("valid identity scalar");
    let mut row = mint_grant_row(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        bystander.verifying_key().to_sec1(),
        &kdf::enc_subkey(&BYSTANDER_SECRET).public(),
        &SCOPE,
        write_name(ROOT).as_str().as_bytes(),
        CorePermission::Read,
    )
    .expect("a contributory recipient key");
    row.ledger_entry.owner_sig[0] ^= 0xff;
    row
}

/// An invite link over the vault root's scope: the row the owner commits, and
/// the record that is the owner's only authority for calling that row a link.
fn invite_link_at_root(secret_byte: u8) -> MintedInvite {
    expiring_invite_link_at_root(secret_byte, None)
}

/// [`invite_link_at_root`] carrying a deadline.
fn expiring_invite_link_at_root(secret_byte: u8, expires_at: Option<UnixMillis>) -> MintedInvite {
    let invitee = EphemeralInvitee::from_secret(&[secret_byte; 32]).expect("a valid scalar");
    mint_invite_grant(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        &invitee,
        &SCOPE,
        &WRITE_SCOPE_SEED,
        CorePermission::Read,
        expires_at,
    )
    .expect("a contributory invitee key")
}

/// Put `links` in the owner's durable invite records, as a mint would have.
fn record_links(device: &FakeDevice, links: &[RecordedInvite]) {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(11));
    block_on(
        StagingInviteStore::new(&device.staging_store, &enc, &entropy).persist(&InviteRecords {
            links: links.to_vec(),
            claims: Vec::new(),
        }),
    )
    .expect("the records persist");
}

/// The links the owner still records.
fn recorded_links(device: &FakeDevice) -> Vec<RecordedInvite> {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(12));
    block_on(StagingInviteStore::new(&device.staging_store, &enc, &entropy).load())
        .expect("the records load")
        .links
}

/// Import the recipient into the owner's contact book, which is the only thing
/// that makes their encryption subkey usable as a grant target.
fn import_recipient(engine: &mut Engine<FakeSeamTypes>) {
    block_on(engine.command(Command::ImportContact {
        contact_code: contact_code(&RECIPIENT_SECRET),
    }))
    .expect("the recipient's code imports");
}

/// The sealed blobs sitting on the recipient's inbox.
fn inbox(device: &FakeDevice) -> Vec<Vec<u8>> {
    block_on(device.mailbox.poll())
        .expect("the inbox answers")
        .into_iter()
        .map(|item| item.sealed_payload)
        .collect()
}

/// An owner engine over a seeded vault plus a published folder to grant, and the
/// recipient's device bound to the address their identity key names.
struct GrantScenario {
    world: FakeWorld,
    blocks: Blocks,
    owner_device: FakeDevice,
    recipient_device: FakeDevice,
    engine: Engine<FakeSeamTypes>,
    _events: EventStream,
    _tasks: Vec<BoxedTask>,
    folder: NodeId,
}

impl GrantScenario {
    fn new() -> Self {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_vault(&world, &blocks, Vec::new());
        // Addressed at the owner's own identity key, which is where a claim is
        // routed.
        let owner_device = world.device(&owner_identity().verifying_key().to_sec1());
        let recipient_device = world.device(&recipient_identity().verifying_key().to_sec1());
        let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &owner_device);
        let folder = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "shared");
        import_recipient(&mut engine);
        Self {
            world,
            blocks,
            owner_device,
            recipient_device,
            engine,
            _events,
            _tasks: tasks,
            folder,
        }
    }

    fn grant_folder_to_recipient(&mut self) -> Result<CommandOutcome, EngineError> {
        block_on(self.engine.command(Command::Grant {
            node: self.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        }))
    }

    /// Mint a link at the folder and hand back only what a host holds: the URL
    /// fragment.
    fn mint_link(&mut self) -> Zeroizing<String> {
        let outcome = block_on(self.engine.command(Command::CreateInviteLink {
            node: self.folder,
            permission: Permission::Read,
            expires_at: None,
        }))
        .expect("the link mints");
        let CommandOutcome::InviteLinkMinted(link) = outcome else {
            panic!("minting a link answers with the link");
        };
        link.fragment
    }

    /// The bearer's own session, holding nothing but what the fragment carries.
    fn bearer(&self) -> (Engine<FakeSeamTypes>, EventStream) {
        serve_http(&self.recipient_device, &self.blocks, 64);
        let (mut engine, events) = engine_with(&self.recipient_device, 21, ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(RECIPIENT_SECRET.to_vec())))
            .expect("the bearer's own session starts");
        (engine, events)
    }

    /// The identity keys the folder's own committed set names as grantees.
    fn granted_to(&self) -> Vec<Vec<u8>> {
        block_on(self.engine.sharing(self.folder))
            .expect("a sharing read")
            .state
            .expect("the shared scope root resolved")
            .grants
            .into_iter()
            .map(|grant| grant.recipient_identity_public_key)
            .collect()
    }

    fn convert(&mut self) -> Result<CommandOutcome, EngineError> {
        block_on(
            self.engine
                .command(Command::ConvertInviteClaims { node: self.folder }),
        )
    }
}

// ---------------------------------------------------------------------------
// RotateNow
// ---------------------------------------------------------------------------

/// A hygiene rotation is only real once the network and the device's own
/// revocation boundary have both moved: the scope root republishes at the next
/// read epoch, and the durable read-epoch floor follows it.
#[test]
fn a_manual_rotation_cuts_the_read_plane_and_raises_the_durable_floor() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_vault(&world, &blocks, Vec::new());
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    assert_eq!(published_read_epoch(&world, &blocks, ROOT), EPOCH);
    let before = sequence_at(&world, &root_name);

    assert_eq!(
        block_on(engine.command(Command::RotateNow { node: ROOT })),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        published_read_epoch(&world, &blocks, ROOT),
        EPOCH + 1,
        "the cut republished the scope root at the next read epoch"
    );
    assert!(
        sequence_at(&world, &root_name) > before,
        "over the record the account was reading"
    );
    assert_eq!(
        block_on(floor::read_epoch_floor(&alice.floor_store, &SCOPE)).expect("floor read"),
        Some(EPOCH + 1),
        "and the durable revocation boundary followed it"
    );
}

/// Manual rotation re-seals the unchanged committed set, so a scope already at
/// the epoch this session adopted has no already-current state to no-op on: the
/// second run is another clean cut, never a refusal.
#[test]
fn a_second_manual_rotation_cuts_again_rather_than_refusing_a_current_scope() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks, Vec::new());
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    for expected_epoch in [EPOCH + 1, EPOCH + 2] {
        assert_eq!(
            block_on(engine.command(Command::RotateNow { node: ROOT })),
            Ok(CommandOutcome::Done),
            "the rotation to epoch {expected_epoch} must cut, not refuse"
        );
        assert_eq!(published_read_epoch(&world, &blocks, ROOT), expected_epoch);
        assert_eq!(
            block_on(floor::read_epoch_floor(&alice.floor_store, &SCOPE)).expect("floor read"),
            Some(expected_epoch),
        );
    }
}

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

/// Both refusals the grant arm owes are decided before any key material is
/// wrapped: an unimported recipient has no verified subkey to seal to, and a
/// write grant owes a write-scope cut this build does not author.
#[test]
fn a_grant_the_engine_refuses_publishes_nothing() {
    let mut fx = GrantScenario::new();
    let root_name = write_name(ROOT);
    let folder_name = write_name(fx.folder);
    let root_before = sequence_at(&fx.world, &root_name);
    let folder_before = sequence_at(&fx.world, &folder_name);

    let stranger = EcdsaSigner::from_scalar(&[0x7C; 32])
        .expect("valid identity scalar")
        .verifying_key()
        .to_sec1()
        .to_vec();
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: stranger,
            permission: Permission::Read,
        })),
        Err(EngineError::MalformedInput {
            check: "recipient-not-imported"
        }),
    );
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Write,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "write-grants-need-a-write-scope-cut"
        }),
    );

    assert_eq!(sequence_at(&fx.world, &root_name), root_before);
    assert_eq!(sequence_at(&fx.world, &folder_name), folder_before);
    assert!(
        published_grant_section(&fx.world, &fx.blocks, fx.folder).is_none(),
        "a refused grant mints no scope at the target folder"
    );
    assert!(inbox(&fx.recipient_device).is_empty(), "and shares nothing");
}

/// A first promotion against the production publisher: the minted scope root
/// must open under the fresh derivation the grantee holds, or their first read
/// fails.
#[test]
fn a_grant_promotes_the_folder_to_a_scope_root_the_grantee_can_open() {
    let mut fx = GrantScenario::new();
    assert!(
        published_grant_section(&fx.world, &fx.blocks, fx.folder).is_none(),
        "the folder starts as an ordinary node, not a scope root"
    );
    let root_before = sequence_at(&fx.world, &write_name(ROOT));

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let section = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the granted folder now answers as a scope root");
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        1,
        "a read grant anchors the fresh scope at read epoch 1"
    );

    // The whole point of the promotion: the body carried forward re-seals under
    // `readKey(nodeSeed(freshOverrideSeed, scopeId))`, so the seed the grantee's
    // blob conveys opens the record they resolve.
    let head =
        published_head(&fx.world, &fx.blocks, &write_name(fx.folder)).expect("a published record");
    let envelope = decode_envelope(&head).expect("the head decodes");
    let override_seed = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        1,
        &section,
    )
    .expect("the owner blob yields the fresh override seed");
    let read_key = kdf::read_key(kdf::node_seed(&override_seed, &fx.folder.0).as_bytes());
    open_read_body(&envelope, read_key.as_bytes())
        .expect("the grantee's first read opens the promoted root");

    assert!(
        sequence_at(&fx.world, &write_name(ROOT)) > root_before,
        "and the parent republished its index naming the new scope"
    );
    assert_eq!(
        inbox(&fx.recipient_device).len(),
        1,
        "the share pointer reached the recipient"
    );
}

/// The read the share dialog renders from: engine truth, not a tally of the
/// commands this session happened to issue. The contact book comes from the
/// durable store, and the grant rows off the scope root's own committed ledger —
/// so a reload, or another device's grant, reports the same list.
#[test]
fn the_sharing_read_reports_the_contact_book_and_the_scopes_committed_grants() {
    let mut fx = GrantScenario::new();
    let recipient_pk = recipient_identity().verifying_key().to_sec1().to_vec();

    let before = block_on(fx.engine.sharing(fx.folder)).expect("a sharing read");
    assert_eq!(
        before
            .contacts
            .iter()
            .map(|contact| contact.identity_public_key.clone())
            .collect::<Vec<_>>(),
        vec![recipient_pk.clone()],
        "the imported contact is offered as a recipient with no re-import"
    );
    assert_eq!(
        before.state.map(|state| state.grants),
        Some(Vec::new()),
        "an ordinary folder is not a scope root, so nothing is granted at it — \
         reported as an empty list, never as an unreachable one"
    );

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let after = block_on(fx.engine.sharing(fx.folder)).expect("a sharing read");
    assert_eq!(after.scope, fx.folder);
    let rows = after.state.expect("the granted scope root resolved").grants;
    assert_eq!(rows.len(), 1, "the granted scope commits one row");
    assert_eq!(
        rows[0].recipient_identity_public_key, recipient_pk,
        "the row names the recipient the grant went to"
    );
    assert_eq!(rows[0].permission, Permission::Read);

    // Absence is not emptiness: an unreachable record plane withholds the grant
    // list rather than reporting a shared folder as shared with nobody, and the
    // durable contact book answers regardless.
    for endpoint in fx.world.record_store.endpoints() {
        fx.world.record_store.fail_endpoint(&endpoint);
    }
    let offline = block_on(fx.engine.sharing(fx.folder)).expect("the contact book is local");
    assert!(offline.state.is_none());
    assert_eq!(offline.contacts.len(), 1);

    assert_eq!(
        block_on(fx.engine.sharing(NodeId([0xEE; 16]))),
        Err(EngineError::UnknownNode),
        "a node this vault does not hold is a caller error, not an empty list"
    );
    assert_eq!(
        block_on(floor::write_epoch_floor(
            &fx.owner_device.floor_store,
            &fx.folder.0
        ))
        .expect("floor read"),
        Some(EPOCH),
        "the mint seeded the new scope's write-epoch floor, or its own          owner-write-blob would never open"
    );
}

/// Any committed **writer** authors the write body a grant ledger rides in, so a
/// row's recipient bytes are only owner truth where the owner's own binding
/// signature covers them. A row the owner cannot vouch for is filed under the
/// all-zero identity rather than naming a party they never signed — otherwise a
/// co-writer could hide their own grant behind a stranger's key on the very
/// surface the owner revokes from.
#[test]
fn the_sharing_read_will_not_name_a_recipient_the_owner_never_signed() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(
        &world,
        &blocks,
        vec![recipient_row_at_root(), bystander_row_with_corrupt_sig()],
    );
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);

    let rows = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the vault root resolved")
        .grants;

    let named: Vec<Vec<u8>> = rows
        .iter()
        .map(|row| row.recipient_identity_public_key.clone())
        .collect();
    assert!(
        named.contains(&recipient_identity().verifying_key().to_sec1().to_vec()),
        "the row the owner signed names its recipient"
    );
    assert!(
        named.contains(&vec![0u8; 33]),
        "and the row it did not sign is filed unattested, not under its claimed key"
    );
    assert!(
        !named.contains(
            &EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
                .expect("valid identity scalar")
                .verifying_key()
                .to_sec1()
                .to_vec()
        ),
        "an unverifiable owner signature must not lend a key the owner's word"
    );
}

/// A share mints a fresh scope at the node, so a node that is not one yet is
/// exactly where a host may still offer the mint — and nothing is shared there
/// to report, by grant or by link. The vault root is refused on its own ground,
/// which is not the one a node that already names a scope reports.
#[test]
fn the_sharing_read_offers_a_mint_only_at_a_node_that_names_no_scope() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks, Vec::new());
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    let folder = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "plain");

    let plain = block_on(engine.sharing(folder))
        .expect("a sharing read")
        .state
        .expect("a node that is not a scope root settles the read");
    assert_eq!(plain.grant_refusal, None);
    assert_eq!(plain.invite_link_refusal, None);
    assert_eq!(plain.grants, Vec::new());
    assert_eq!(plain.invite_links, Some(SharingInviteLinks::default()));

    let scope = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the vault root resolved");
    assert_eq!(
        scope.grant_refusal,
        Some("grant-target-is-the-vault-root"),
        "the vault root's scope is the session's, and a host must be told that \
         rather than a rule it does not break"
    );
    assert_eq!(
        scope.invite_link_refusal,
        Some("invite-target-is-the-vault-root")
    );
}

/// A grant and a link are different actions to a user, so the vault root refuses
/// each under its own name — and the read a share dialog is drawn from reports
/// exactly what dispatching those commands returns.
#[test]
fn the_vault_root_refuses_both_shares_with_the_names_its_read_reports() {
    let mut fx = GrantScenario::new();

    let state = block_on(fx.engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the vault root resolved");

    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Err(EngineError::UnsupportedTarget {
            check: state.grant_refusal.expect("the read refuses the grant"),
        }),
    );
    assert_eq!(
        block_on(fx.engine.command(Command::CreateInviteLink {
            node: ROOT,
            permission: Permission::Read,
            expires_at: None,
        })),
        Err(EngineError::UnsupportedTarget {
            check: state
                .invite_link_refusal
                .expect("the read refuses the link"),
        }),
    );
    assert_eq!(state.grant_refusal, Some("grant-target-is-the-vault-root"));
    assert_eq!(
        state.invite_link_refusal,
        Some("invite-target-is-the-vault-root")
    );
}

/// A second share of a folder would mint another scope at epoch 1, replacing the
/// seed every existing grantee holds. The read and the commands decide that on
/// one rule, so a host offers nothing the mint would then refuse — and each
/// command still answers under its own name.
#[test]
fn a_second_share_of_a_scope_is_refused_with_the_names_its_read_reports() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let state = block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the granted scope root resolved");
    assert_eq!(
        state.grant_refusal,
        Some("grant-target-already-names-a-scope")
    );
    assert_eq!(
        state.invite_link_refusal,
        Some("invite-target-already-names-a-scope")
    );

    let grant_refusal = state.grant_refusal.expect("the read refuses the grant");
    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::UnsupportedTarget {
            check: grant_refusal
        }),
        "a reported standing and the refusal the command returns cannot disagree"
    );
    assert_eq!(
        block_on(fx.engine.command(Command::CreateInviteLink {
            node: fx.folder,
            permission: Permission::Read,
            expires_at: None,
        })),
        Err(EngineError::UnsupportedTarget {
            check: state
                .invite_link_refusal
                .expect("the read refuses the link"),
        }),
    );
}

/// The link half of a share dialog: the deadline the owner minted, read back
/// from the owner's own record rather than the ledger's forgeable hint. The
/// link's row is not a grant — its recipient is a throwaway identity only the
/// fragment holder answers for — so it renders as the link it is and nowhere
/// else.
#[test]
fn the_sharing_read_reports_the_live_link_apart_from_the_grants() {
    let deadline = UnixMillis(1_800_000_000_000);
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let link = expiring_invite_link_at_root(0x4e, Some(deadline));
    let grantee = recipient_row_at_root();
    seed_vault(&world, &blocks, vec![link.row.clone(), grantee.clone()]);
    let alice = world.device(b"alice");
    record_links(&alice, &[link.link]);
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    let view = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(
        view.invite_links,
        Some(SharingInviteLinks {
            live: true,
            expires_at: Some(deadline),
            expired: false,
            spent: 0,
        })
    );

    let named: Vec<Vec<u8>> = view
        .grants
        .into_iter()
        .map(|grant| grant.recipient_identity_public_key)
        .collect();
    assert_eq!(
        named,
        vec![grantee.ledger_entry.recipient_identity_pk.to_vec()],
        "the grant list is the personal grants, with the link's own row filtered out"
    );

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink { node: ROOT })),
        Ok(CommandOutcome::Done)
    );
    let revoked = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(
        revoked.invite_links,
        Some(SharingInviteLinks::default()),
        "the cut landed and took the record with it, so there is nothing left to prune"
    );
}

/// The deadline is the engine's verdict to render, not a timestamp for a host to
/// race its own clock against: a link past its deadline is still the one a revoke
/// cuts, and reads back as live and expired together.
#[test]
fn the_sharing_read_calls_a_live_link_past_its_deadline_expired() {
    let deadline = UnixMillis(60_000);
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let link = expiring_invite_link_at_root(0x6a, Some(deadline));
    seed_vault(&world, &blocks, vec![link.row.clone()]);
    let alice = world.device(b"alice");
    record_links(&alice, &[link.link]);
    let (engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    let before = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(
        before.invite_links,
        Some(SharingInviteLinks {
            live: true,
            expires_at: Some(deadline),
            expired: false,
            spent: 0,
        })
    );

    // The claim path refuses at the deadline, so the read reports it there too.
    world.scheduler.advance_to(deadline);
    let after = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(
        after.invite_links,
        Some(SharingInviteLinks {
            live: true,
            expires_at: Some(deadline),
            expired: true,
            spent: 0,
        })
    );
}

/// A record the scope's own commitment no longer carries is spent: a mint whose
/// publish failed, or a cut whose record outlived it. The read reports exactly
/// what a prune would drop, so a host can offer the reclaim without guessing.
#[test]
fn the_sharing_read_counts_the_records_a_prune_would_drop() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let grantee = recipient_row_at_root();
    seed_vault(&world, &blocks, vec![grantee]);
    let alice = world.device(b"alice");
    record_links(&alice, &[invite_link_at_root(0x5f).link]);
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    let view = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(
        view.invite_links,
        Some(SharingInviteLinks {
            live: false,
            expires_at: None,
            expired: false,
            spent: 1,
        })
    );

    assert_eq!(
        block_on(engine.command(Command::PruneInviteLinks { node: ROOT })),
        Ok(CommandOutcome::Done)
    );
    assert!(
        recorded_links(&alice).is_empty(),
        "the count the read reported is the count the prune dropped"
    );
    assert_eq!(
        block_on(engine.sharing(ROOT))
            .expect("a sharing read")
            .state
            .expect("the scope root resolved")
            .invite_links,
        Some(SharingInviteLinks::default())
    );
}

/// The mailbox post is the last step of the mint and nothing compensates it, so
/// a grant that cannot commit the granted scope root must leave the recipient
/// with nothing: an item naming a root that never published would never resolve
/// and never ack.
#[test]
fn a_grant_that_cannot_publish_the_granted_scope_root_posts_no_share_pointer() {
    let mut fx = GrantScenario::new();
    // The promotion's own CAS is the whole fault: the folder gates, the root
    // mints, and the PUT never lands.
    fx.world
        .record_store
        .fail_put_for(write_name(fx.folder).as_str());
    let root_before = sequence_at(&fx.world, &write_name(ROOT));

    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::Seam {
            message: "rotation record not published".to_owned(),
        }),
    );
    assert!(
        published_grant_section(&fx.world, &fx.blocks, fx.folder).is_none(),
        "no scope root was committed at the granted folder"
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(ROOT)),
        root_before,
        "and the parent index never named a scope that does not exist"
    );
    assert!(
        inbox(&fx.recipient_device).is_empty(),
        "and no share pointer was posted"
    );
}

// ---------------------------------------------------------------------------
// AcceptShare
// ---------------------------------------------------------------------------

/// A share already delivered: the owner published a scope root committing the
/// recipient's read row, and the sealed pointer naming it sits on their inbox.
struct ShareScenario {
    recipient_device: FakeDevice,
}

impl ShareScenario {
    /// The pointer advertises `Write` while the record commits `Read`, so an
    /// accept that trusted the pointer would be visible in the outcome.
    fn new() -> Self {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        let name = seed_vault(&world, &blocks, vec![recipient_row_at_root()]);
        let owner_device = world.device(b"alice");
        let recipient_device = world.device(&recipient_identity().verifying_key().to_sec1());

        let pointer = SharePointer {
            scope_root_name: name.as_str().as_bytes().to_vec(),
            sharer_identity_pk: owner_identity().verifying_key().to_sec1(),
            display_name: "shared".to_owned(),
            permission: CorePermission::Write,
        };
        block_on(post_sealed(
            &owner_device.mailbox,
            &kdf::enc_subkey(&RECIPIENT_SECRET).public(),
            &recipient_identity().verifying_key(),
            &SHARE_POINTER_EPHEMERAL,
            POINTER_PAYLOAD_VERSION,
            &owner_identity(),
            &pointer.encode(),
            "share-1",
        ))
        .expect("the sealed pointer posts");

        serve_http(&recipient_device, &blocks, 64);
        Self { recipient_device }
    }

    /// The recipient's own started engine, and the sealed item waiting on its
    /// inbox.
    fn recipient_engine(&self) -> (Engine<FakeSeamTypes>, EventStream, Vec<u8>) {
        let (mut engine, events) = engine_with(&self.recipient_device, 9, ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(RECIPIENT_SECRET.to_vec())))
            .expect("the recipient's own session starts");
        let sealed = inbox(&self.recipient_device)
            .pop()
            .expect("one sealed item is waiting");
        (engine, events, sealed)
    }
}

/// The recipient's own engine, on nothing but the shared record store and the
/// sealed item on its inbox, adopts the share — at the permission the owner
/// committed on the record, never the one the pointer advertises.
#[test]
fn the_recipient_accepts_a_shared_scope_at_the_owner_committed_permission() {
    let fx = ShareScenario::new();
    let (mut recipient, _events, sealed) = fx.recipient_engine();
    block_on(recipient.command(Command::ImportContact {
        contact_code: contact_code(&SECRET),
    }))
    .expect("the sharer's code imports");

    let outcome = block_on(recipient.command(Command::AcceptShare {
        sealed_share_pointer: sealed,
    }))
    .expect("the share is accepted end to end");
    let CommandOutcome::ShareAccepted(accepted) = outcome else {
        panic!("accepting a share answers with the adopted share");
    };
    assert_eq!(accepted.scope_id, SCOPE);
    assert_eq!(
        accepted.permission,
        CorePermission::Read,
        "the committed ledger is authority, not the pointer's claim"
    );
    assert!(accepted.newly_added);
    assert!(
        inbox(&fx.recipient_device).is_empty(),
        "the item is acked only once the share is durable"
    );
}

/// The mailbox is integrity-untrusted, so authorship comes from the contact book
/// alone: a sender this vault never imported is refused, and the item stays on
/// the inbox for redelivery rather than being acked away.
#[test]
fn an_accept_from_a_sender_this_vault_never_imported_fails_closed() {
    let fx = ShareScenario::new();
    let (mut recipient, _events, sealed) = fx.recipient_engine();

    assert_eq!(
        block_on(recipient.command(Command::AcceptShare {
            sealed_share_pointer: sealed,
        })),
        Err(EngineError::MalformedInput {
            check: "recipient-not-imported"
        }),
    );
    assert_eq!(
        inbox(&fx.recipient_device).len(),
        1,
        "a refused accept acks nothing"
    );
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

/// Cutting the row is bookkeeping; the revocation is the fresh-seed cascade that
/// republishes the scope root at a higher read epoch with no blob the revokee
/// can open. Assert that absence directly — it is the whole of the revoke.
#[test]
fn revoking_a_read_grant_republishes_the_root_without_the_revokees_blob() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let row = recipient_row_at_root();
    seed_vault(&world, &blocks, vec![row.clone()]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);

    let before = published_grant_section(&world, &blocks, ROOT).expect("the root is a scope root");
    assert!(
        before.grant_blobs.iter().any(|blob| blob.tag == row.tag),
        "the recipient starts out able to self-locate a blob"
    );

    assert_eq!(
        block_on(engine.command(Command::Revoke {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        published_read_epoch(&world, &blocks, ROOT),
        EPOCH + 1,
        "the cut drove a fresh-seed cascade, not just a commitment edit"
    );
    let after = published_grant_section(&world, &blocks, ROOT).expect("the root republished");
    assert!(
        !after.grant_blobs.iter().any(|blob| blob.tag == row.tag),
        "the revokee's blob is gone from the re-sealed set"
    );
    assert!(
        !after.commitment.entries.iter().any(|e| e.tag == row.tag),
        "and their row is no longer committed"
    );
}

/// The owner's own encryption subkey is the stronger of the two authorities over
/// a ledger row's `recipientEncPk`: it re-derives the committed tag, so a row it
/// proves survives an `ownerSig` that verifies against nothing. The owner cut is
/// an adoption site like any other, and adopts in that order too.
#[test]
fn a_cut_keeps_a_row_its_own_subkey_proves_despite_an_unverifiable_owner_signature() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let revokee = recipient_row_at_root();
    let bystander = bystander_row_with_corrupt_sig();
    seed_vault(&world, &blocks, vec![revokee.clone(), bystander.clone()]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);

    assert_eq!(
        block_on(engine.command(Command::Revoke {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Ok(CommandOutcome::Done)
    );

    let after = published_grant_section(&world, &blocks, ROOT).expect("the root republished");
    assert!(
        !after.grant_blobs.iter().any(|blob| blob.tag == revokee.tag),
        "the revokee's blob is gone from the re-sealed set"
    );
    assert!(
        after
            .grant_blobs
            .iter()
            .any(|blob| blob.tag == bystander.tag),
        "and the bystander keeps a blob its tag proves it is entitled to"
    );
}

/// A stalled cut spends **one** retry bound, the per-plane one `OwnerCutNet`
/// carries. The read cascade mints a fresh override seed on every run, so a
/// second bound around the driver would re-drive a landed cut — and the spacing
/// it costs is what counts the attempts.
#[test]
fn a_stalled_cut_re_drives_the_read_cascade_under_one_bound() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks, vec![recipient_row_at_root()]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    // The cut's own publish is the whole fault: every attempt re-keys, fails to
    // land, and leaves the network where the previous one found it.
    world.record_store.fail_put_for(write_name(ROOT).as_str());
    let cadence = u64::try_from(engine.profile().poll_cadence.as_millis()).expect("a sane cadence");
    let before = world.scheduler.now();
    // The spacing between attempts is virtual time nothing else here advances.
    let _clock = world.scheduler.clone().with_auto_advance();

    assert!(
        block_on(engine.command(Command::Revoke {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        }))
        .is_err(),
        "the cut that never published is not a revocation"
    );

    assert_eq!(
        world.scheduler.now(),
        UnixMillis(before.0 + cadence * u64::from(MAX_ROTATION_ATTEMPTS - 1)),
        "one bound's worth of attempts, not a bound multiplied by a second one"
    );
    assert_eq!(
        published_read_epoch(&world, &blocks, ROOT),
        EPOCH,
        "and nothing the stall re-drove landed"
    );
}

// ---------------------------------------------------------------------------
// Invite links
// ---------------------------------------------------------------------------

/// Revoking a link is the read revoke it is made of: the row leaves the
/// owner-signed set, the read plane cuts so the bearer's blob is gone from
/// everything published after it, and only then does the owner forget the
/// record.
#[test]
fn revoking_an_invite_link_cuts_its_row_rotates_the_read_plane_and_forgets_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let bystander = recipient_row_at_root();
    let link = invite_link_at_root(0x4e);
    seed_vault(&world, &blocks, vec![link.row.clone(), bystander.clone()]);
    let alice = world.device(b"alice");
    record_links(&alice, &[link.link]);
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    let before = published_grant_section(&world, &blocks, ROOT).expect("the root is a scope root");
    assert!(
        before
            .grant_blobs
            .iter()
            .any(|blob| blob.tag == link.row.tag),
        "the bearer starts out able to self-locate a blob"
    );

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink { node: ROOT })),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        published_read_epoch(&world, &blocks, ROOT),
        EPOCH + 1,
        "the cut drove a fresh-seed cascade, not just a commitment edit"
    );
    let after = published_grant_section(&world, &blocks, ROOT).expect("the root republished");
    assert!(
        !after
            .commitment
            .entries
            .iter()
            .any(|e| e.tag == link.row.tag),
        "the link's row is no longer committed, so a claim on it is refused"
    );
    assert!(
        !after
            .grant_blobs
            .iter()
            .any(|blob| blob.tag == link.row.tag),
        "and the bearer has no blob in the re-sealed set"
    );
    assert!(
        after
            .grant_blobs
            .iter()
            .any(|blob| blob.tag == bystander.tag),
        "revoking a link ends future claims, not the grants it already produced"
    );
    assert!(
        recorded_links(&alice).is_empty(),
        "the cut landed, so the record it was derived from is spent"
    );
}

/// Every node of a scope publishes at a derived name, so a folder that is no
/// scope root answers there with an ordinary record the gate refuses. That is
/// the caller naming the wrong node, not an abuse event — and the difference is
/// what a host alarms on.
#[test]
fn revoking_a_link_at_an_ordinary_folder_is_a_target_refusal_not_a_trust_violation() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(&world, &blocks, Vec::new());
    let alice = world.device(b"alice");
    record_links(&alice, &[invite_link_at_root(0x4e).link]);
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    let folder = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "plain");

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink { node: folder })),
        Err(EngineError::UnsupportedTarget {
            check: "revoke-link-target-is-not-a-scope-root"
        }),
    );
    assert_eq!(
        recorded_links(&alice).len(),
        1,
        "a refused revoke forgets nothing"
    );
}

/// A tag the owner does not record as a link belongs to some grantee, so a
/// revoke that could reach it would cut an ordinary grant. It publishes nothing
/// instead.
#[test]
fn revoking_a_link_the_owner_never_recorded_publishes_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let grantee = recipient_row_at_root();
    let root_name = seed_vault(&world, &blocks, vec![grantee.clone()]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    let before = sequence_at(&world, &root_name);

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink { node: ROOT })),
        Err(EngineError::MalformedInput {
            check: "link-not-committed"
        }),
    );

    assert_eq!(sequence_at(&world, &root_name), before);
    let after = published_grant_section(&world, &blocks, ROOT).expect("the root is unchanged");
    assert!(
        after
            .commitment
            .entries
            .iter()
            .any(|e| e.tag == grantee.tag),
        "the grantee's row is untouched"
    );
}

/// The reclaim a failed publish owes: a record the scope's own commitment does
/// not carry names a row that is not live, so its slot comes back — while a
/// record the commitment does carry stays, because forgetting it would leave a
/// live link nothing can revoke.
#[test]
fn pruning_drops_the_records_the_commitment_does_not_carry_and_keeps_the_rest() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let live = invite_link_at_root(0x4e);
    let never_published = invite_link_at_root(0x5f);
    seed_vault(&world, &blocks, vec![live.row.clone()]);
    let alice = world.device(b"alice");
    record_links(&alice, &[live.link, never_published.link]);
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    assert_eq!(
        block_on(engine.command(Command::PruneInviteLinks { node: ROOT })),
        Ok(CommandOutcome::Done)
    );

    let kept = recorded_links(&alice);
    assert_eq!(
        kept,
        vec![live.link],
        "only the record the owner-signed commitment still carries survives"
    );
}

// ---------------------------------------------------------------------------
// Invite claims
// ---------------------------------------------------------------------------

/// The whole path a bearer link exists for: a holder of nothing but the fragment
/// reaches the owner's inbox, and the owner's conversion turns that into a
/// personal grant on the scope's own owner-signed set — anchored to the
/// claimant's contact identity, never to the link's throwaway one.
#[test]
fn a_claim_from_the_fragment_alone_becomes_a_personal_grant_on_the_scope() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let bearer_pk = recipient_identity().verifying_key().to_sec1().to_vec();
    assert!(
        !fx.granted_to().contains(&bearer_pk),
        "the link commits its throwaway identity, never the bearer's own"
    );

    let (mut bearer, _bearer_events) = fx.bearer();
    assert_eq!(
        block_on(bearer.command(Command::ClaimInviteLink { fragment })),
        Ok(CommandOutcome::Done),
    );
    assert_eq!(
        inbox(&fx.owner_device).len(),
        1,
        "the claim reached the owner's inbox"
    );
    let root = bearer.root();
    assert_eq!(
        block_on(bearer.sharing(root))
            .expect("a sharing read")
            .contacts
            .into_iter()
            .map(|contact| contact.identity_public_key)
            .collect::<Vec<_>>(),
        vec![owner_identity().verifying_key().to_sec1().to_vec()],
        "a posted claim records the owner it sealed to — the anchor the grant \
         this claim produces will arrive under",
    );

    assert_eq!(
        block_on(
            fx.engine
                .command(Command::ConvertInviteClaims { node: fx.folder })
        ),
        Ok(CommandOutcome::Done),
    );

    assert!(
        fx.granted_to().contains(&bearer_pk),
        "conversion re-anchors the link to the claimant's contact identity"
    );
    assert!(
        inbox(&fx.owner_device).is_empty(),
        "the claim is acked only once the grant it made is published and recorded"
    );
    assert_eq!(
        inbox(&fx.recipient_device).len(),
        1,
        "and the claimant is told which scope root to resolve"
    );
}

/// The mailbox chooses what to redeliver, so the second delivery of one claim
/// must not have the owner re-sign anything: the spent record refuses it, and
/// the item is acked rather than left to redeliver forever.
#[test]
fn a_redelivered_claim_converts_once() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut bearer, _bearer_events) = fx.bearer();
    block_on(bearer.command(Command::ClaimInviteLink {
        fragment: fragment.clone(),
    }))
    .expect("the first claim posts");
    block_on(
        fx.engine
            .command(Command::ConvertInviteClaims { node: fx.folder }),
    )
    .expect("the first conversion lands");
    let sequence_after_first = sequence_at(&fx.world, &write_name(fx.folder));
    let granted_after_first = fx.granted_to();

    // The same holder claiming again is what a redelivery looks like from the
    // owner's side: a fresh item carrying a claim for a grant already made.
    block_on(bearer.command(Command::ClaimInviteLink { fragment })).expect("a second claim posts");
    assert_eq!(
        block_on(
            fx.engine
                .command(Command::ConvertInviteClaims { node: fx.folder })
        ),
        Ok(CommandOutcome::Done),
    );

    assert_eq!(
        sequence_at(&fx.world, &write_name(fx.folder)),
        sequence_after_first,
        "a claim that grants nothing new republishes nothing"
    );
    assert_eq!(
        fx.granted_to(),
        granted_after_first,
        "and files one grant for the claimant, not a second"
    );
}

/// A fragment is bearer key material a host hands over unread, so anything that
/// is not one is a fail-closed refusal that reaches no mailbox — never a partial
/// reconstruction of an identity nobody committed.
#[test]
fn a_fragment_that_is_not_one_claims_nothing() {
    let fx = GrantScenario::new();
    let (mut bearer, _bearer_events) = fx.bearer();

    for fragment in ["", "not a fragment", "Zm9vYmFy"] {
        assert_eq!(
            block_on(bearer.command(Command::ClaimInviteLink {
                fragment: Zeroizing::new(fragment.to_owned())
            })),
            Err(EngineError::MalformedInput {
                check: "malformed-invite-fragment"
            }),
        );
    }
    assert!(
        inbox(&fx.owner_device).is_empty(),
        "a refused claim posts nothing"
    );
}

/// A claim that matched a recorded link but can never become convertible is a
/// dead item only this owner can retire: leaving it would hold an inbox slot
/// until its TTL, and a bearer can post as many as it likes.
#[test]
fn a_claim_that_can_never_convert_is_acked_rather_than_left_to_redeliver() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    // The claim path's own read of the fragment; a host never does this.
    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    let invitee =
        EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");

    // An all-zero id is the one a client with a broken entropy seam emits, and
    // converting it would spend the id every later claimant would draw.
    block_on(post_invite_claim(
        &fx.recipient_device.mailbox,
        &import_contact(&opened.owner_contact_code).expect("the owner bundle verifies"),
        &invitee,
        &[0x7d; 32],
        ENVELOPE_V,
        &InviteClaim {
            claim_id: [0u8; CLAIM_ID_LEN],
            scope_root_name: opened.scope_root_name.clone(),
            contact_code: contact_code(&RECIPIENT_SECRET),
        },
        "dead-claim",
    ))
    .expect("the claim posts");
    assert_eq!(inbox(&fx.owner_device).len(), 1);
    let committed = fx.granted_to();

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert!(
        inbox(&fx.owner_device).is_empty(),
        "the dead claim is retired, not redelivered forever"
    );
    assert_eq!(
        fx.granted_to(),
        committed,
        "and it granted nothing on the way out"
    );
}

/// The inbox is shared by every consumer, so a pass must leave what it does not
/// own — acking a share pointer would destroy an item only `AcceptShare` can
/// act on.
#[test]
fn a_conversion_pass_leaves_an_item_that_is_not_its_own() {
    let mut fx = GrantScenario::new();
    let _fragment = fx.mint_link();
    block_on(post_sealed(
        &fx.recipient_device.mailbox,
        &kdf::enc_subkey(&SECRET).public(),
        &owner_identity().verifying_key(),
        &SHARE_POINTER_EPHEMERAL,
        ENVELOPE_V,
        &recipient_identity(),
        &SharePointer {
            scope_root_name: write_name(ROOT).as_str().as_bytes().to_vec(),
            sharer_identity_pk: recipient_identity().verifying_key().to_sec1(),
            display_name: "theirs".to_owned(),
            permission: CorePermission::Read,
        }
        .encode(),
        "not-a-claim",
    ))
    .expect("the pointer posts");

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert_eq!(
        inbox(&fx.owner_device).len(),
        1,
        "the share pointer is still there for the arm that owns it"
    );
}
