//! The owner-action command arms, joined end to end over the fake seam world:
//! a manual rotation cuts the read plane, a revoke drives the cascade that
//! actually ends a grant, a grant refuses fail-closed, and a second account's
//! engine accepts a share it was sent.
//!
//! Every assertion lands on published bytes, a durable floor, or the recipient's
//! inbox — what another device would see — never on a command's return alone.

use core::cell::RefCell;

use cipherbox_core::hex::lower as hex_lower;
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{
    AadContext, AscentLink, BinEntry, ChildRef, GrantSection, GrantSetCommitment,
    NodeKind as CoreNodeKind, Permission as CorePermission, PreservedFields, ReadBody,
    STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_WRITE_BODY, decode_envelope,
    decode_grant_section, decode_write_body, grant_section_bytes, open_ascent_link,
    open_grant_blob, open_read_body, sign_grant_set, unseal,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::{EcdsaSigner, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::ct_eq;

use zeroize::Zeroizing;

use cipherbox_engine::gate::floor;
use cipherbox_engine::grants::{
    CLAIM_ID_LEN, Contact, ConvertedClaimRecord, EphemeralInvitee, GrantRow, InviteClaim,
    InviteFragment, InviteRecords, InviteStore, MintedInvite, RecordedInvite, StagingInviteStore,
    import_contact, mint_grant_row, mint_invite_grant, post_invite_claim, recipient_blinded_tag,
};
use cipherbox_engine::net::author::{
    ENVELOPE_V, EnvelopeAuthoring, author_child_envelope, author_scope_root_with_section,
};
use cipherbox_engine::rotation::{
    MAX_ROTATION_ATTEMPTS, derive_write_name, published_override_seed,
};
use cipherbox_engine::seams::{
    BoxedTask, FloorStore, Mailbox, RecordTransport, Scheduler, SnapshotCache, StagingStore,
    UnixMillis,
};
use cipherbox_engine::settings::VaultSettings;
use cipherbox_engine::sync::MAX_QUARANTINE_ATTEMPTS;
use cipherbox_engine::sync::SessionRole;
use cipherbox_engine::sync::op::ScopeCrossing;
use cipherbox_engine::sync::pointer::{
    open_repoint, scope_pointer_name, seal_repoint, vault_pointer_name,
};
use cipherbox_engine::testkit::account::{
    Blocks, EOL, POINTER_PAYLOAD_VERSION, ROOT, SCOPE, SECRET, TTL_NANOS, owner_identity,
    retire_targets, sequence_floor_label, serve_http,
};
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH as EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    SeededEntropy, block_on, poll_tasks_until_parked,
};
use cipherbox_engine::{
    ApiBaseUrl, BinIndexKeys, BinIndexLoad, Command, CommandOutcome, CommittedSet, ContentProfile,
    DeadLetterReason, Engine, EngineError, Event, EventStream, GatewayConfig, LoginSecret, NodeId,
    NodeKind, Permission, RecordReader, ResealSeeds, ScopeRootIdentity, SessionBearer,
    SharePointer, SharingInviteLinks, StoragePolicy, SyncTimingProfile, WriteHistory, decode_queue,
    load_bin_index, poll_verified, post_sealed, reseal_scope_root,
};

/// The recipient account's login secret — every key their engine derives, and
/// the contact code the owner imports, hangs off it.
const RECIPIENT_SECRET: [u8; 32] = [0x5B; 32];
/// A second grantee's login secret — committed at the same root, and never the
/// party a revoke names.
const BYSTANDER_SECRET: [u8; 32] = [0x7C; 32];
/// The first byte of the `n`th throwaway claimant's login scalar, and of the
/// HPKE ephemeral its claim seals under. Two ranges, held apart so no claimant
/// key doubles as a seal ephemeral.
const CLAIMANT_SCALAR_BASE: u8 = 0x90;
const CLAIM_EPHEMERAL_BASE: u8 = 0x10;
/// The entropy seed the seeded vault pointer's re-point seal draws its nonce
/// from, and the one the seeded root's grant section draws its HPKE ephemerals
/// from. Named apart because a single (key, nonce) pair must never cover two
/// plaintexts (blueprint/core.md "Crypto suite").
const POINTER_SEAL_ENTROPY_SEED: u64 = 0;
const ROOT_SEAL_ENTROPY_SEED: u64 = 1;
/// The seeded root body's seal nonce and the share pointer's HPKE ephemeral,
/// held apart for the same reason.
const ROOT_BODY_NONCE: [u8; 24] = [0x31; 24];
/// Two folders of a seeded vault root: one a boundary walk must name a scope
/// root, one an ordinary folder of the vault's own scope.
const SHARED: NodeId = NodeId([0xa1; 16]);
const PHOTOS: NodeId = NodeId([0xa2; 16]);
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
    seed_vault_naming(world, blocks, grants, Vec::new())
}

/// [`seed_vault`] over a root whose read body already names `children` — the
/// state a session boots into, rather than one it authored.
fn seed_vault_naming(
    world: &FakeWorld,
    blocks: &Blocks,
    grants: Vec<GrantRow>,
    children: Vec<ChildRef>,
) -> IpnsName {
    let owner_identity = owner_identity();
    let pseudonym = owner_pseudonym();
    let owner_enc = kdf::enc_subkey(&SECRET);
    let owner_enc_pub = owner_enc.public();
    let name = write_name(ROOT);

    let commitment = GrantSetCommitment {
        ipns_name: name.as_str().as_bytes().to_vec(),
        owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
        cut_epoch: 0,
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
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &ledger,
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
            read_key: &read_key_of(ROOT),
            nonce: &ROOT_BODY_NONCE,
            body: &ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children,
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

/// Re-seal `node`'s record under `scope_id`'s derivation at `epoch` and publish
/// it past the sequence it answers at now.
///
/// A mint promotes a folder to a scope root under a fresh override seed and
/// leaves the interior nodes it carried sealed under the scope they left, so a
/// test that needs the granted subtree readable inside the fresh scope stands
/// that re-seal in here.
fn reseal_interior_node(
    world: &FakeWorld,
    blocks: &Blocks,
    node: NodeId,
    scope_id: [u8; 16],
    override_seed: &[u8; 32],
    epoch: u64,
) {
    let name = write_name(node);
    let read_key = kdf::read_key(kdf::node_seed(override_seed, &node.0).as_bytes());
    let head = author_child_envelope(EnvelopeAuthoring {
        node_id: node.0,
        scope_id,
        epoch,
        read_key: read_key.as_bytes(),
        nonce: &[0x5e; 24],
        body: &ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        },
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the interior node re-seals");
    blocks.put(head.block.clone());
    let record = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes()),
        format!("/ipfs/{}", head.cid).as_bytes(),
        sequence_at(world, &name) + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
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
    published_grant_section_at(world, blocks, &write_name(node))
}

/// The grant section published at `name`, if the record there is a scope root.
/// The by-name form a write-scope cut needs: the wave moves the root off the
/// name [`write_name`] derives.
fn published_grant_section_at(
    world: &FakeWorld,
    blocks: &Blocks,
    name: &IpnsName,
) -> Option<GrantSection> {
    let head = published_head(world, blocks, name)?;
    let envelope = decode_envelope(&head).expect("the head decodes");
    grant_section_bytes(&envelope)
        .map(|bytes| decode_grant_section(bytes).expect("the section decodes"))
}

/// The write-scope seed the recipient's own grant blob at `name` conveys — the
/// only channel a grantee ever receives one on.
fn grantee_write_scope_seed(
    section: &GrantSection,
    name: &IpnsName,
    scope_id: &[u8; 16],
    read_epoch: u64,
) -> [u8; 32] {
    let recipient_enc = kdf::enc_subkey(&RECIPIENT_SECRET);
    let owner_enc_pub = kdf::enc_subkey(&SECRET).public();
    let tag = recipient_blinded_tag(&recipient_enc, &owner_enc_pub, name.as_str().as_bytes())
        .expect("a contributory owner key");
    let blob = section
        .grant_blobs
        .iter()
        .find(|b| b.tag == tag)
        .expect("the recipient self-locates its blob at the name the record asserts");
    let payload = open_grant_blob(
        &recipient_enc,
        &blob.enc,
        &AadContext {
            v: ENVELOPE_V,
            id: *scope_id,
            scope: *scope_id,
            epoch: read_epoch,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        },
        &blob.ciphertext,
    )
    .expect("the recipient opens its own blob");
    *payload
        .write_scope_seed()
        .expect("a write grant's blob carries the write scope seed")
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

/// The `FloorStore` key a scope's write-epoch floor is raised under, unscoped:
/// the fake strips the owner tag before it matches an injected fault.
fn write_epoch_floor_key(scope: &[u8; 16]) -> Vec<u8> {
    let mut key = scope.to_vec();
    key.extend_from_slice(b"/write-epoch");
    key
}

/// The re-point object `scope`'s own pointer record carries — the owner-signed
/// authority for where a write-scope cut moved that scope's root to.
fn scope_repoint(world: &FakeWorld, scope: &[u8; 16]) -> RepointObject {
    let owner_pointer_seed = kdf::owner_pointer_seed(&SECRET);
    let pointer_name = scope_pointer_name(owner_pointer_seed.as_bytes(), scope);
    // A pointer record carries its sealed block inline, not an `/ipfs/`
    // address, so it is read off the verified record rather than the plane.
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], pointer_name.as_str())
        .expect("the write-scope cut published the scope pointer");
    let block = IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(&pointer_name))
        .expect("the pointer record verifies under its own name")
        .value;
    open_repoint(
        kdf::pointer_read_key(owner_pointer_seed.as_bytes(), scope).as_bytes(),
        POINTER_PAYLOAD_VERSION,
        scope,
        &owner_identity().verifying_key(),
        &block,
    )
    .expect("the re-point object opens under the scope's own pointer read key")
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
fn recipient_row_at_root(permission: CorePermission) -> GrantRow {
    mint_grant_row(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        &owner_pointer_read_key(),
        recipient_identity().verifying_key().to_sec1(),
        &kdf::enc_subkey(&RECIPIENT_SECRET).public(),
        &SCOPE,
        write_name(ROOT).as_str().as_bytes(),
        permission,
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
        &owner_pointer_read_key(),
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
        &owner_pointer_read_key(),
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

/// The spent claims the owner records, which is what keeps a claim single-use
/// against a transport that chooses what to redeliver.
fn recorded_claims(device: &FakeDevice) -> Vec<ConvertedClaimRecord> {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(12));
    block_on(StagingInviteStore::new(&device.staging_store, &enc, &entropy).load())
        .expect("the records load")
        .claims
}

/// The staging key the owner's invite records live under — the write a
/// conversion makes durable before it acks the claim.
fn invite_staging_key(device: &FakeDevice) -> Vec<u8> {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(12));
    StagingInviteStore::new(&device.staging_store, &enc, &entropy)
        .staging_key()
        .to_vec()
}

/// The one share pointer waiting on `device`'s inbox, opened under the
/// recipient's own encryption subkey.
fn delivered_share_pointer(device: &FakeDevice) -> SharePointer {
    let mut items = block_on(poll_verified(
        &device.mailbox,
        &kdf::enc_subkey(&RECIPIENT_SECRET),
        ENVELOPE_V,
    ))
    .expect("the inbox answers");
    assert_eq!(items.len(), 1, "one share pointer per grant");
    SharePointer::decode(&items.remove(0).payload).expect("the pointer decodes")
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
        self.grant_folder_at(Permission::Read)
    }

    fn grant_folder_at(&mut self, permission: Permission) -> Result<CommandOutcome, EngineError> {
        block_on(self.engine.command(Command::Grant {
            node: self.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission,
        }))
    }

    /// Drive a grant whose parent index update fails, which is the state a
    /// mint leaves when the grantee root is live and no index names it.
    /// Returns that root's grant section.
    fn strand_the_grantee_scope(&mut self) -> GrantSection {
        self.world
            .record_store
            .fail_put_for(write_name(ROOT).as_str());
        assert!(
            self.grant_folder_to_recipient().is_err(),
            "the parent index update fails, so the mint reports the partial commit"
        );
        self.world
            .record_store
            .heal_put_for(write_name(ROOT).as_str());
        published_grant_section(&self.world, &self.blocks, self.folder)
            .expect("the grantee scope root is live at its derived name")
    }

    /// Drive a write share whose owed name wave fails: the grantee scope is
    /// live, the parent index names it at the name the **parent's** own write
    /// seed derives, and the recipient was never told where it answers.
    ///
    /// The mint adopts the root it publishes, so one read of that scope's
    /// cut-epoch bar is spent by the time the cut's own resolve makes the next
    /// one — which is the read this fails.
    fn strand_the_owed_wave(&mut self) {
        let mut cut_epoch_floor = self.folder.0.to_vec();
        cut_epoch_floor.extend_from_slice(b"/cut-epoch");
        self.owner_device
            .floor_store
            .fail_epoch_floor_reads_after(&cut_epoch_floor, 1);
        assert!(
            self.grant_folder_at(Permission::Write).is_err(),
            "the write-scope cut fails, so the share never reaches its delivery"
        );
        self.owner_device.floor_store.heal_floors();
    }

    /// Grant `name`, a folder inside the already-granted one, and report it.
    /// A grant refuses a subtree still sealed at the epoch it held before the
    /// enclosing mint, so the folder converges onto the enclosing scope first.
    fn grant_nested_folder(&mut self, name: &str) -> NodeId {
        let inner = create_published_folder(
            &self.world,
            &mut self.engine,
            &mut self._tasks,
            self.folder,
            name,
        );
        assert_eq!(self.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
        let enclosing = published_grant_section(&self.world, &self.blocks, self.folder)
            .expect("the granted folder is a scope root");
        let enclosing_seed = published_override_seed(
            &kdf::enc_subkey(&SECRET),
            ENVELOPE_V,
            self.folder.0,
            1,
            &enclosing,
        )
        .expect("the owner blob yields the enclosing scope's override seed");
        reseal_interior_node(
            &self.world,
            &self.blocks,
            inner,
            self.folder.0,
            &enclosing_seed,
            1,
        );
        assert_eq!(
            block_on(self.engine.command(Command::Grant {
                node: inner,
                recipient_identity_public_key:
                    recipient_identity().verifying_key().to_sec1().to_vec(),
                permission: Permission::Read,
            })),
            Ok(CommandOutcome::Done),
        );
        inner
    }

    fn granted_scope_repoint(&self) -> RepointObject {
        scope_repoint(&self.world, &self.folder.0)
    }

    /// The recipient's blinded tag at `name` — derived from the owner's own half
    /// of the pairwise ECDH, as every self-location is.
    fn recipient_tag(name: &IpnsName) -> [u8; 32] {
        recipient_blinded_tag(
            &kdf::enc_subkey(&RECIPIENT_SECRET),
            &kdf::enc_subkey(&SECRET).public(),
            name.as_str().as_bytes(),
        )
        .expect("a contributory owner key")
    }

    /// The permission the owner's own commitment at `name` carries for the
    /// recipient, or `None` when it commits no row for them. A name no section
    /// answers at panics, so `None` reports the tag and never a silent
    /// non-publish.
    fn committed_permission(&self, name: &IpnsName) -> Option<CorePermission> {
        let tag = Self::recipient_tag(name);
        published_grant_section_at(&self.world, &self.blocks, name)
            .expect("a scope root answers at the name the pointer vouches for")
            .commitment
            .entries
            .iter()
            .find(|e| e.tag == tag)
            .map(|e| e.permission)
    }

    /// Whether the recipient's blob at `name` conveys a write scope seed, or
    /// `None` when they hold no blob there.
    fn granted_blob_carries_write_seed(&self, name: &IpnsName) -> Option<bool> {
        let tag = Self::recipient_tag(name);
        let section = published_grant_section_at(&self.world, &self.blocks, name)?;
        let blob = section.grant_blobs.iter().find(|b| b.tag == tag)?;
        let payload = open_grant_blob(
            &kdf::enc_subkey(&RECIPIENT_SECRET),
            &blob.enc,
            &AadContext {
                v: ENVELOPE_V,
                id: self.folder.0,
                scope: self.folder.0,
                epoch: 1,
                struct_tag: STRUCT_TAG_GRANT_BLOB,
            },
            &blob.ciphertext,
        )
        .expect("the recipient opens its own blob");
        Some(payload.write_scope_seed().is_some())
    }

    /// Mint a link at the folder and hand back only what a host holds: the URL
    /// fragment.
    fn mint_link(&mut self) -> Zeroizing<String> {
        self.mint_link_at(Permission::Read)
    }

    fn mint_link_at(&mut self, permission: Permission) -> Zeroizing<String> {
        let outcome = block_on(self.engine.command(Command::CreateInviteLink {
            node: self.folder,
            permission,
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
        self.bearer_on(&self.recipient_device, &RECIPIENT_SECRET, 21)
    }

    /// A bearer session for `secret` on `device`. A secret other than the
    /// recipient's is a claimant this owner's contact book has never held.
    fn bearer_on(
        &self,
        device: &FakeDevice,
        secret: &[u8; 32],
        entropy_seed: u64,
    ) -> (Engine<FakeSeamTypes>, EventStream) {
        serve_http(device, &self.blocks, 64);
        let (mut engine, events) = engine_with(device, entropy_seed, ApiBaseUrl::offline());
        block_on(engine.start(LoginSecret::new(secret.to_vec())))
            .expect("the bearer's own session starts");
        (engine, events)
    }

    /// The device a claimant's identity key addresses, holding its own stores.
    fn device_for(&self, secret: &[u8; 32]) -> FakeDevice {
        let identity = EcdsaSigner::from_scalar(secret).expect("valid identity scalar");
        self.world.device(&identity.verifying_key().to_sec1())
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

    /// Post `count` claims on `fragment`, one per throwaway claimant identity —
    /// what a bearer link looks like when one holder claims from many. Answers
    /// the claimants' identity keys in the order they were posted.
    ///
    /// Straight to the mailbox rather than through a claimant engine each: the
    /// owner's conversion pass reads the same items either way, and a session
    /// per claimant would price the pass out of the suite.
    fn post_claims(&self, fragment: &str, count: usize) -> Vec<Vec<u8>> {
        let opened = InviteFragment::decode(fragment).expect("the mint's own fragment");
        let invitee =
            EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
        let owner = import_contact(&opened.owner_contact_code).expect("the owner bundle verifies");
        (0..count)
            .map(|i| {
                let index = u8::try_from(i).expect("the fixture stays under 256 claimants");
                let scalar = [CLAIMANT_SCALAR_BASE + index; 32];
                // Never all-zero, which the conversion refuses outright.
                let mut claim_id = [1u8; CLAIM_ID_LEN];
                claim_id[0] = index;
                let claim = InviteClaim {
                    claim_id,
                    scope_root_name: opened.scope_root_name.clone(),
                    contact_code: contact_code(&scalar),
                };
                self.post_claim(&owner, &invitee, index, &claim, &format!("claim-{i}"));
                EcdsaSigner::from_scalar(&scalar)
                    .expect("valid identity scalar")
                    .verifying_key()
                    .to_sec1()
                    .to_vec()
            })
            .collect()
    }

    /// Post one claim under `idempotency_key`. `index` picks this post's own
    /// HPKE ephemeral: a (key, nonce) pair must never cover two plaintexts
    /// (blueprint/core.md).
    fn post_claim(
        &self,
        owner: &Contact,
        invitee: &EphemeralInvitee,
        index: u8,
        claim: &InviteClaim,
        idempotency_key: &str,
    ) {
        block_on(post_invite_claim(
            &self.recipient_device.mailbox,
            owner,
            invitee,
            &[CLAIM_EPHEMERAL_BASE + index; 32],
            ENVELOPE_V,
            claim,
            idempotency_key,
        ))
        .expect("the claim posts");
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
        block_on(floor::read_epoch_floor(&alice.floors(&SECRET), &SCOPE)).expect("floor read"),
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
            block_on(floor::read_epoch_floor(&alice.floors(&SECRET), &SCOPE)).expect("floor read"),
            Some(expected_epoch),
        );
    }
}

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

/// The refusal the grant arm owes is decided before any key material is
/// wrapped: an unimported recipient has no verified subkey to seal to. Both
/// permissions refuse the same way, so a write grant costs no publish either.
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
    for permission in [Permission::Read, Permission::Write] {
        assert_eq!(
            block_on(fx.engine.command(Command::Grant {
                node: fx.folder,
                recipient_identity_public_key: stranger.clone(),
                permission,
            })),
            Err(EngineError::MalformedInput {
                check: "recipient-not-imported"
            }),
        );
    }

    assert_eq!(sequence_at(&fx.world, &root_name), root_before);
    assert_eq!(sequence_at(&fx.world, &folder_name), folder_before);
    assert!(
        published_grant_section(&fx.world, &fx.blocks, fx.folder).is_none(),
        "a refused grant mints no scope at the target folder"
    );
    assert!(inbox(&fx.recipient_device).is_empty(), "and shares nothing");
}

/// The write-scope cut, against the production publisher: a write grant hands
/// the grantee a `writeScopeSeed` the vault above cannot derive, and moves the
/// granted subtree onto the names that seed derives
/// (blueprint/engine.md "Grant creation").
///
/// The two halves are one property. A seed the grantee holds that still derived
/// the parent's names would be write capability over the whole vault; a subtree
/// left at the parent's names would leave the seed deriving nothing.
#[test]
fn a_write_grant_cuts_the_granted_subtree_into_its_own_write_scope() {
    let mut fx = GrantScenario::new();
    let inherited_name = write_name(fx.folder);

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );

    // The scope pointer is the owner-signed authority for where the root sits.
    let repoint = fx.granted_scope_repoint();
    let moved_name = repoint.current_root.clone();
    assert_eq!(repoint.prev_root.as_ref(), Some(&inherited_name));
    assert_ne!(
        moved_name, inherited_name,
        "the wave moved the root off the name the parent's write scope derives"
    );

    // The grantee's own blob is the only channel that carries the seed, and it
    // must be the one the moved names derive from. That equality also settles
    // that the seed is not the vault's: the vault's derives `inherited_name`.
    let section = published_grant_section_at(&fx.world, &fx.blocks, &moved_name)
        .expect("the moved root answers as a scope root");
    let seed = grantee_write_scope_seed(&section, &moved_name, &fx.folder.0, 1);
    assert_eq!(
        derive_write_name(&seed, &fx.folder.0),
        moved_name,
        "the seed in the grantee's blob derives the root they resolve"
    );
    assert_eq!(
        inbox(&fx.recipient_device).len(),
        1,
        "the share pointer reached the recipient"
    );
}

/// The pointer is the only thing that tells a grantee where to look, and a write
/// grant's name wave moves the scope root after the mint. So the post runs past
/// the wave: a pointer naming the pre-wave root would send the grantee to a name
/// their own seed does not derive.
#[test]
fn a_write_grants_share_pointer_names_the_root_its_wave_moved_to() {
    let mut fx = GrantScenario::new();
    let inherited_name = write_name(fx.folder);

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );

    let moved_name = fx.granted_scope_repoint().current_root;
    assert_ne!(moved_name, inherited_name);
    let pointer = delivered_share_pointer(&fx.recipient_device);
    assert_eq!(
        pointer.scope_root_name,
        moved_name.as_str().as_bytes(),
        "the grantee is sent to the root the wave moved to"
    );
    assert_eq!(pointer.permission, CorePermission::Write);
}

/// The record the mint publishes before the wave lingers for ever — the wave
/// retires interior names, never the root it moved off — and the recipient's tag
/// at that name is the one it commits. So the seed it hands them has to be the
/// mint's own cut, never the seed the scope above publishes under.
///
/// This is the one regression that would hand out vault-wide write capability,
/// and the moved root cannot show it: its blob always carries the wave's fresh
/// seed, whatever the mint sealed.
#[test]
fn the_record_a_write_grant_publishes_before_the_wave_withholds_the_vaults_seed() {
    let mut fx = GrantScenario::new();
    let interim_name = write_name(fx.folder);

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );

    let interim = published_grant_section_at(&fx.world, &fx.blocks, &interim_name)
        .expect("the pre-wave root lingers at the name the vault's seed derives");
    let seed = grantee_write_scope_seed(&interim, &interim_name, &fx.folder.0, 1);
    assert_ne!(
        derive_write_name(&seed, &ROOT.0),
        write_name(ROOT),
        "the interim blob must not convey the seed the vault's own names derive from"
    );
    assert_ne!(
        derive_write_name(&seed, &fx.folder.0),
        interim_name,
        "nor the seed that derives the name the record itself sits at"
    );
}

/// The revoke control must survive a downgrade. The wave moves the scope root,
/// and the owner reaches an interior root through the vault root's own index —
/// so a cut that moves a root and leaves that index behind strands every later
/// owner action on the scope at a name it has moved off.
#[test]
fn a_downgraded_grant_can_still_be_revoked() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let recipient = recipient_identity().verifying_key().to_sec1().to_vec();
    assert_eq!(
        block_on(fx.engine.command(Command::Downgrade {
            node: fx.folder,
            recipient_identity_public_key: recipient.clone(),
        })),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: recipient,
        })),
        Ok(CommandOutcome::Done),
        "the owner still reaches the scope the downgrade's wave moved"
    );
    assert_eq!(
        fx.committed_permission(&fx.granted_scope_repoint().current_root),
        None,
        "and the revoke cut their row from the moved root"
    );
}

/// The downgrade arm, end to end against the production `CutRotator`.
///
/// The write wave re-mints the grant set only from a root already carrying the
/// authorized commitment, and a downgrade rotates no read plane — so the cut
/// publishes the demoted set itself before the wave. Assert the **published**
/// permission, which is what the wave reads.
#[test]
fn a_downgrade_publishes_the_demoted_commitment_and_moves_the_scope() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let granted = fx.granted_scope_repoint();
    assert_eq!(
        fx.committed_permission(&granted.current_root),
        Some(CorePermission::Write)
    );

    assert_eq!(
        block_on(fx.engine.command(Command::Downgrade {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Ok(CommandOutcome::Done),
        "the downgrade completes rather than refusing permanently at the wave"
    );

    let after = fx.granted_scope_repoint();
    assert_eq!(
        after.write_epoch,
        granted.write_epoch + 1,
        "the wave ran, so the demoted party's derived names are dead"
    );
    assert_eq!(after.prev_root, Some(granted.current_root.clone()));
    assert_eq!(
        fx.committed_permission(&after.current_root),
        Some(CorePermission::Read),
        "the moved root commits the recipient at the demoted permission"
    );
    assert_eq!(
        fx.granted_blob_carries_write_seed(&after.current_root),
        Some(false),
        "and their blob no longer conveys a write scope seed"
    );
}

/// A wave over the vault root's own scope opens a window: the root moves, and
/// the session's cached write scope seed still derives the name it moved off —
/// a name the demoted party keeps the write-name key for. The next
/// owner action must refuse rather than drive a cut nobody reads, and must
/// recover once a tick adopts at the moved root.
#[test]
fn an_owner_action_refuses_while_the_cached_seed_names_the_superseded_root() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let seeded_root = seed_vault(
        &world,
        &blocks,
        vec![recipient_row_at_root(CorePermission::Write)],
    );
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);

    assert_eq!(
        block_on(engine.command(Command::Downgrade {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Ok(CommandOutcome::Done)
    );
    let moved = scope_repoint(&world, &SCOPE).current_root;
    assert_ne!(
        moved, seeded_root,
        "the wave moved the vault root off the name the cached seed derives"
    );
    let superseded_sequence = sequence_at(&world, &seeded_root);

    assert_eq!(
        block_on(engine.command(Command::RotateNow { node: ROOT })),
        Err(EngineError::ContentUnavailable {
            message: "held-write-seed-does-not-name-the-current-root".to_owned(),
        }),
        "the next owner action refuses rather than cutting the superseded root"
    );
    assert_eq!(
        sequence_at(&world, &seeded_root),
        superseded_sequence,
        "and published nothing at the name the demoted party still authors at"
    );

    tick(&world, &engine, &mut tasks);

    assert_eq!(
        block_on(engine.command(Command::RotateNow { node: ROOT })),
        Ok(CommandOutcome::Done),
        "a tick that adopts at the moved root clears the refusal"
    );
}

/// The wave publishes before the cut raises its durable floor, so a floor-store
/// failure leaves the root moved with the floor still low. The session must
/// still know the root moved, or both defences fall together and the next owner
/// action anchors on the name the demoted party authors at.
#[test]
fn a_cut_whose_floor_raise_fails_still_refuses_the_next_owner_action() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let seeded_root = seed_vault(
        &world,
        &blocks,
        vec![recipient_row_at_root(CorePermission::Write)],
    );
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    alice
        .floor_store
        .fail_floor_raises_for(&write_epoch_floor_key(&SCOPE));

    assert!(
        block_on(engine.command(Command::Downgrade {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        }))
        .is_err(),
        "the cut reports the floor it could not raise"
    );
    assert_ne!(
        scope_repoint(&world, &SCOPE).current_root,
        seeded_root,
        "and the wave moved the root before it failed"
    );

    assert_eq!(
        block_on(engine.command(Command::RotateNow { node: ROOT })),
        Err(EngineError::ContentUnavailable {
            message: "held-write-seed-does-not-name-the-current-root".to_owned(),
        }),
        "so the next owner action still refuses the superseded root"
    );
}

/// A write revoke drives both planes: the read cascade cuts the row and the wave
/// moves the scope off every name the revokee's seed derives. Only the re-key
/// cuts access, so assert both halves.
#[test]
fn revoking_a_write_grant_cuts_the_row_and_moves_the_scope_off_the_revokees_names() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let granted = fx.granted_scope_repoint();
    let revokee_seed = {
        let section = published_grant_section_at(&fx.world, &fx.blocks, &granted.current_root)
            .expect("the granted root");
        grantee_write_scope_seed(&section, &granted.current_root, &fx.folder.0, 1)
    };

    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Ok(CommandOutcome::Done)
    );

    let after = fx.granted_scope_repoint();
    assert_ne!(
        derive_write_name(&revokee_seed, &fx.folder.0),
        after.current_root,
        "the revokee's seed no longer derives the name the scope pointer vouches for"
    );
    assert_eq!(
        fx.committed_permission(&after.current_root),
        None,
        "and the moved root commits no row at their tag"
    );
}

/// Key regression, stated at the write plane: after the cut, the vault's write
/// scope seed no longer names anything in the granted scope. That is what lets
/// a later revoke of this grantee re-key one scope instead of the vault, and
/// what stops the parent scope's writers authoring inside the granted one.
#[test]
fn a_write_grants_cut_leaves_the_parent_scopes_seed_naming_nothing_granted() {
    let mut fx = GrantScenario::new();
    let inherited_name = write_name(fx.folder);

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );

    let repoint = fx.granted_scope_repoint();
    assert_ne!(
        repoint.current_root, inherited_name,
        "the scope the parent's seed named is not the scope the grantee reads"
    );
    assert_eq!(
        repoint.write_epoch, 2,
        "the cut advanced the granted scope's own write clock"
    );
    assert_eq!(
        repoint.min_read_epoch, 1,
        "and left the read plane's clock at the epoch the mint anchored"
    );
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

/// A relocation is classified from both ends. A move out of the folder a grant
/// just promoted leaves that scope and journals the crossing the drain acts on;
/// a move that stays inside that folder crosses nothing and journals an
/// intra-scope relink.
#[test]
fn a_move_out_of_a_granted_folder_journals_the_crossing_it_makes() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let album = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "album",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    block_on(fx.engine.command(Command::Relink {
        node: album,
        new_parent: holiday,
    }))
    .expect("a relocation between two folders of the granted scope queues");
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Intra],
        "a move that stays inside the granted scope crosses nothing"
    );

    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: ROOT,
    }))
    .expect("a move out of the granted scope journals its crossing");
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Intra, ScopeCrossing::ExitsGrantedSource],
        "and the source end names the granted scope the next one leaves, which \
         owes it a cut"
    );
}

/// A session that does not hold the target cannot name the scope the move would
/// leave, so it reports the target gone rather than anchoring on the vault root.
/// Anchored there, both ends resolve to the root and the move reads intra-scope,
/// whatever scope the target really sits in.
#[test]
fn a_relocation_whose_source_the_view_does_not_hold_reports_it_gone() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let (mut fresh, _events, _tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    assert!(
        block_on(fresh.view())
            .expect("a rendered view")
            .children(fx.folder)
            .is_empty(),
        "this session has not read into the granted scope"
    );
    assert!(
        matches!(
            block_on(fresh.command(Command::Relink {
                node: holiday,
                new_parent: ROOT,
            })),
            Err(EngineError::UnknownNode)
        ),
        "the same verdict every other read gives a node it does not hold"
    );
    assert_eq!(
        queued_crossings(&fx.owner_device).len(),
        0,
        "and nothing was journaled, so no drain pass can publish it"
    );
}

/// The vault root has no parent to move it out of. It is the one target
/// `refuse_outside_vault` exempts, so the relocation path owns the refusal.
#[test]
fn a_relocation_of_the_vault_root_is_an_unsupported_target() {
    let mut fx = GrantScenario::new();

    assert!(
        matches!(
            block_on(fx.engine.command(Command::Relink {
                node: ROOT,
                new_parent: fx.folder,
            })),
            Err(EngineError::UnsupportedTarget { .. })
        ),
        "the root is refused as a target, not classified as a crossing"
    );
    assert_eq!(
        queued_crossings(&fx.owner_device).len(),
        0,
        "and nothing was journaled, so no pass can link the root under a folder"
    );
}

/// The tick's descendant walk gates every interior scope root. Both its seeds
/// already reach the seed caches; the read epoch its envelope carries now
/// reaches the session too, which is what a cross-scope re-seal publishes at.
#[test]
fn the_tick_resolves_the_material_of_an_owner_minted_interior_scope() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    // The read plane cuts and the write plane does not, so the two epochs part
    // and only the read one satisfies the assertion below.
    assert_eq!(
        block_on(fx.engine.command(Command::RotateNow { node: fx.folder })),
        Ok(CommandOutcome::Done)
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let material = block_on(fx.engine.walked_scope_material(fx.folder))
        .expect("the walk resolved the scope the grant minted");
    let epoch = published_read_epoch(&fx.world, &fx.blocks, fx.folder);
    assert_eq!(
        epoch, 2,
        "the cut moved the read epoch off the write plane's"
    );
    assert_eq!(
        material.read_epoch, epoch,
        "the epoch is the one the scope root envelope carries"
    );
    let floor = block_on(floor::read_epoch_floor(
        &fx.owner_device.floors(&SECRET),
        &fx.folder.0,
    ))
    .expect("the floor reads")
    .expect("the cut raised the scope's read-epoch floor");
    assert_eq!(
        material.read_epoch, floor,
        "and the cut left the floor at the epoch it published"
    );
    let section = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the granted folder answers as a scope root");
    let published = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        epoch,
        &section,
    )
    .expect("the owner blob yields the scope's override seed");
    assert!(
        ct_eq(&material.read_scope_seed, &published),
        "the read seed is the one this scope's own owner blob carries"
    );
    assert_eq!(
        derive_write_name(&material.write_scope_seed, &fx.folder.0),
        write_name(fx.folder),
        "and the write seed derives the name the scope root publishes under"
    );
}

/// One node linked from a folder of the vault's own scope and from a folder of
/// an owner-minted interior scope, with the interior folder's read key.
///
/// Both links are planted while both folders are still the vault's own; the
/// grant is what moves one of them under a boundary, which is also how a live
/// vault reaches this state.
fn dual_linked_across_a_grant(fx: &mut GrantScenario) -> (NodeId, NodeId, NodeId, [u8; 32]) {
    let keep = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "keep");
    let deep = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, keep, "deep");
    let inner =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "box");
    concurrent_add(
        &fx.world,
        &fx.blocks,
        inner,
        &read_key_of(inner),
        SCOPE,
        ChildRef {
            id: deep.0,
            name: "deep".to_owned(),
            ipns_name: write_name(deep).as_str().as_bytes().to_vec(),
            kind: CoreNodeKind::Folder,
            // Above the create's own, so the folder the grant moves is the one
            // a reader resolves the node under, and so the one whose plane the
            // node's own record is re-keyed to.
            link_counter: 1,
            unknown: PreservedFields::new(),
        },
    );
    block_on(fx.engine.command(Command::SetFocus { node: Some(inner) })).expect("the focus moves");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.engine.view())
            .expect("a rendered view")
            .children(inner)
            .iter()
            .any(|child| child.id == deep),
        "the second link is in gate-passing state"
    );

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (override_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    let inner_read_key =
        *kdf::read_key(kdf::node_seed(&override_seed, &inner.0).as_bytes()).as_bytes();
    assert_eq!(
        published_child_names(&fx.world, &fx.blocks, inner, &inner_read_key),
        vec!["deep".to_owned()],
        "the grant left the second link standing in a scope of its own"
    );
    assert_eq!(
        published_child_names(&fx.world, &fx.blocks, keep, &read_key_of(keep)),
        vec!["deep".to_owned()],
        "and the first where it was"
    );
    (keep, deep, inner, inner_read_key)
}

/// A soft delete unlinks its target from every folder that links it, and a
/// grant minted since one of those links landed puts that folder in another
/// scope. The pass carries both ends, so each folder republishes under its own
/// plane (blueprint/engine.md "Delete branch").
#[test]
fn a_delete_unlinks_a_node_from_a_folder_in_each_end_of_the_pass() {
    let mut fx = GrantScenario::new();
    let (keep, deep, inner, inner_read_key) = dual_linked_across_a_grant(&mut fx);

    block_on(fx.engine.command(Command::Delete { node: deep })).expect("the delete stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        published_child_names(&fx.world, &fx.blocks, inner, &inner_read_key),
        Vec::<String>::new(),
        "the folder inside the grant republished under the second end's plane"
    );
    assert_eq!(
        published_child_names(&fx.world, &fx.blocks, keep, &read_key_of(keep)),
        Vec::<String>::new(),
        "and the folder in the vault's own scope under the anchor's"
    );
}

/// The `ipnsName` `folder`'s published record names `child` by, read under
/// `read_key`. A promoted scope names its own nodes, so the parent's record is
/// the one plane that spells them.
fn published_child_name(
    world: &FakeWorld,
    blocks: &Blocks,
    folder: &IpnsName,
    read_key: &[u8; 32],
    child: &str,
) -> IpnsName {
    let head = published_head(world, blocks, folder).expect("a published record");
    let envelope = decode_envelope(&head).expect("the head block decodes");
    let ReadBody::Folder { children, .. } =
        open_read_body(&envelope, read_key).expect("the folder body opens")
    else {
        panic!("expected a folder body");
    };
    let named = children
        .iter()
        .find(|entry| entry.name == child)
        .unwrap_or_else(|| panic!("no child named {child}"));
    IpnsName::parse(core::str::from_utf8(&named.ipns_name).expect("a utf8 ipnsName"))
        .expect("a canonical ipnsName")
}

/// A node's per-node read key under `scope_seed`.
fn read_key_under(scope_seed: &[u8; 32], node: NodeId) -> [u8; 32] {
    *kdf::read_key(kdf::node_seed(scope_seed, &node.0).as_bytes()).as_bytes()
}

/// Every target this device has asked the registry to retire, in order.
fn retired(device: &FakeDevice) -> Vec<String> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/registry/retire"))
        .flat_map(|request| {
            retire_targets(
                request
                    .body
                    .as_deref()
                    .expect("a retire call carries a body"),
            )
        })
        .collect()
}

/// A delete below a promoted scope root is journaled under that scope, and only
/// that scope's material derives the names it holds or opens the records behind
/// them. A tick that cannot prove the scope leaves the entry alone rather than
/// spending a quarantine attempt on a verdict it cannot reach, and the tick that
/// does prove it retires the descendants (blueprint/engine.md "Retirement").
#[test]
fn a_delete_inside_a_promoted_scope_retires_the_descendants_that_scope_owns() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    // A zero retention, so the delete below runs the reclamation itself rather
    // than binning the subtree for a later purge.
    block_on(fx.engine.command(Command::SaveVaultSettings {
        settings: VaultSettings {
            bin_retention_days: 0,
            ..VaultSettings::default()
        },
    }))
    .expect("the settings publish");

    // Two levels inside the promoted scope.
    let album = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "album",
    );
    let deep = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, album, "deep");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let (scope_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    let album_name = published_child_name(
        &fx.world,
        &fx.blocks,
        &write_name(fx.folder),
        &read_key_under(&scope_seed, fx.folder),
        "album",
    );
    let deep_name = published_child_name(
        &fx.world,
        &fx.blocks,
        &album_name,
        &read_key_under(&scope_seed, album),
        "deep",
    );
    assert_ne!(deep, album, "the descendant is a node of its own");

    let mark = retired(&fx.owner_device).len();
    block_on(fx.engine.command(Command::Delete { node: album })).expect("the delete stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    // A whole attempt budget of ticks that cannot reach the promoted root, and
    // so cannot attribute the entry that scope's delete wrote. The cached
    // record goes with it: a scope this device can still answer out of its own
    // cache is one the tick can still prove.
    let promoted = write_name(fx.folder);
    fx.world.record_store.fail_get_for(promoted.as_str());
    block_on(
        fx.owner_device
            .snapshot_cache
            .remove(promoted.as_str().as_bytes()),
    )
    .expect("the promoted root leaves the cache");
    for _ in 0..=MAX_QUARANTINE_ATTEMPTS {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    fx.world.record_store.heal_get_for(promoted.as_str());

    // The tick converges the snapshot, the next proves the descendant, and the
    // one after spends the debt the proof owed.
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    let retired = retired(&fx.owner_device)[mark..].to_vec();
    assert!(
        retired.contains(&album_name.as_str().to_owned()),
        "the delete's own target leaves the inventory the republisher walks"
    );
    assert!(
        retired.contains(&deep_name.as_str().to_owned()),
        "and so does the descendant, which no attempt spent by a settle that \
         could not attribute it was allowed to strand"
    );
}

/// A link under a boundary this tick proved no material for is charged, never
/// dropped: dropping it publishes the dangling link the delete exists to
/// prevent, and holding it stalls the strict-FIFO head with nothing reported.
#[test]
fn a_delete_charges_a_link_under_a_boundary_no_pass_can_seal() {
    let mut fx = GrantScenario::new();
    let (keep, deep, inner, inner_read_key) = dual_linked_across_a_grant(&mut fx);
    let epoch = published_read_epoch(&fx.world, &fx.blocks, fx.folder);
    block_on(
        fx.owner_device
            .floors(&SECRET)
            .raise_epoch_floor(&fx.folder.0, epoch + 1),
    )
    .expect("the floor raises");

    block_on(fx.engine.command(Command::Delete { node: deep })).expect("the delete stages");
    // The drain's attempt budget, spent one charge per pass.
    for _ in 0..5 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert_eq!(
        block_on(fx.engine.status())
            .expect("the status reads")
            .dead_letters
            .into_iter()
            .map(|letter| letter.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted],
        "the spent budget is what reports it"
    );
    assert_eq!(
        published_child_names(&fx.world, &fx.blocks, inner, &inner_read_key),
        vec!["deep".to_owned()],
        "and neither folder published a part-way unlink"
    );
    assert_eq!(
        published_child_names(&fx.world, &fx.blocks, keep, &read_key_of(keep)),
        vec!["deep".to_owned()],
    );
}

/// A target every link of which sits under one scope root other than this
/// pass's own is that scope's own pass to take. Charging it here would spend a
/// budget on an op another pass publishes, and abandon one whose material is
/// only a tick away.
#[test]
fn a_delete_wholly_inside_a_dark_grant_waits_rather_than_charging() {
    let mut fx = GrantScenario::new();
    let inner =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "box");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let epoch = published_read_epoch(&fx.world, &fx.blocks, fx.folder);
    block_on(
        fx.owner_device
            .floors(&SECRET)
            .raise_epoch_floor(&fx.folder.0, epoch + 1),
    )
    .expect("the floor raises");

    block_on(fx.engine.command(Command::Delete { node: inner })).expect("the delete stages");
    // The drain's attempt budget, spent one charge per pass.
    for _ in 0..5 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert!(
        block_on(fx.engine.status())
            .expect("the status reads")
            .dead_letters
            .is_empty(),
        "the op waits on the scope that holds every link"
    );
}

/// The minting session is the only one that ever held this material without a
/// walk. A second session over the same vault must reach the same seeds and the
/// same epoch, or the destination end of a crossing depends on which session
/// happens to publish it.
#[test]
fn a_session_that_minted_no_grant_resolves_the_same_interior_material() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let minted = block_on(fx.engine.walked_scope_material(fx.folder))
        .expect("the minting session walked the scope it minted");

    let (fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);

    let walked = block_on(fresh.walked_scope_material(fx.folder))
        .expect("a session that minted nothing still walks the durable index");
    assert!(
        ct_eq(&walked.read_scope_seed, &minted.read_scope_seed)
            && ct_eq(&walked.write_scope_seed, &minted.write_scope_seed),
        "both sessions seal under the same scope material"
    );
    assert_eq!(walked.read_epoch, minted.read_epoch, "at the same epoch");
}

/// The read-epoch floor is the revocation boundary. A level below it supplies
/// no material at all, and its own subtree is what that costs: the level above
/// keeps what its own gated record proved.
#[test]
fn a_level_below_its_read_epoch_floor_supplies_no_material() {
    let mut fx = GrantScenario::new();
    let inner = fx.grant_nested_folder("in");

    // The control and the assertion both run on a session that minted nothing,
    // so only the floor differs between them.
    let (before, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &before, &mut tasks);
    assert!(
        block_on(before.walked_scope_material(fx.folder)).is_some()
            && block_on(before.walked_scope_material(inner)).is_some(),
        "a cold session reaches both levels while each record sits at its floor"
    );

    let epoch = published_read_epoch(&fx.world, &fx.blocks, inner);
    block_on(
        fx.owner_device
            .floors(&SECRET)
            .raise_epoch_floor(&inner.0, epoch + 1),
    )
    .expect("the floor raises");

    let (after, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &after, &mut tasks);
    assert!(
        block_on(after.walked_scope_material(inner)).is_none(),
        "a record below the revocation boundary supplies no material"
    );
    assert!(
        block_on(after.walked_scope_material(fx.folder)).is_some(),
        "and the level above it keeps the material its own record proved"
    );
}

// ---------------------------------------------------------------------------
// The tick's boundary walk: which failure it met, and what the session does
// ---------------------------------------------------------------------------

/// Everything the stream holds now.
fn events_so_far(events: &mut EventStream) -> Vec<Event> {
    let mut out = Vec::new();
    while let Some(event) = events.try_next() {
        out.push(event);
    }
    out
}

/// How many abuse events the stream holds.
fn abuse_events(events: &mut EventStream) -> usize {
    events_so_far(events)
        .into_iter()
        .filter(|event| matches!(event, Event::AttributableAbuse { .. }))
        .count()
}

/// The value the record published at `name` carries.
fn published_value(world: &FakeWorld, name: &IpnsName) -> Vec<u8> {
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
        .expect("a published record");
    IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(name))
        .expect("the published record verifies under its own name")
        .value
        .to_vec()
}

/// Publish `value` at `node`'s write-plane name, one sequence past what stands.
/// Every committed writer of a scope holds this name's key, so this is the
/// record such a writer can always land.
fn publish_value_at(world: &FakeWorld, node: NodeId, value: &[u8]) {
    let name = write_name(node);
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes());
    let record = IpnsRecord::create_v2(
        &signer,
        value,
        sequence_at(world, &name) + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
}

/// Two folders of the vault's own scope, for a relocation that crosses nothing
/// while the session names every boundary below the root.
fn two_root_folders(fx: &mut GrantScenario) -> (NodeId, NodeId) {
    let photos = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "photos");
    let albums = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "albums");
    (photos, albums)
}

/// A trust rejection anywhere on the walk leaves the session naming no boundary
/// below the rejected root, so a move out of that scope would read intra-scope
/// and the drain would publish the moved subtree still sealed where its
/// grantees read it. The session refuses every relocation instead, and says so
/// once. Only a later walk that names the whole set lifts the refusal.
#[test]
fn a_rejected_descendant_refuses_every_relocation_until_a_later_walk_succeeds() {
    let mut fx = GrantScenario::new();
    let (photos, albums) = two_root_folders(&mut fx);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let gate_passing = published_value(&fx.world, &write_name(fx.folder));

    let (mut fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    // The vault root's own record at the granted scope's name: owner-signed,
    // and refused by every gate because its commitment names another name.
    publish_value_at(
        &fx.world,
        fx.folder,
        &published_value(&fx.world, &write_name(ROOT)),
    );
    let _ = events_so_far(&mut events);
    tick(&fx.world, &fresh, &mut tasks);

    assert_eq!(
        abuse_events(&mut events),
        1,
        "a fail-closed rejection is attributable abuse, never a silent retry"
    );
    assert!(
        matches!(
            block_on(fresh.command(Command::Relink {
                node: photos,
                new_parent: albums,
            })),
            Err(EngineError::TrustViolation { .. })
        ),
        "and every relocation is refused while the session cannot name its boundaries"
    );
    assert_eq!(
        queued_crossings(&fx.owner_device).len(),
        0,
        "so no drain pass can publish one"
    );

    publish_value_at(&fx.world, fx.folder, &gate_passing);
    tick(&fx.world, &fresh, &mut tasks);

    assert!(
        matches!(
            block_on(fresh.command(Command::Relink {
                node: photos,
                new_parent: albums,
            })),
            Ok(CommandOutcome::Queued { .. })
        ),
        "a walk that names the whole boundary set again lifts the refusal"
    );
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Intra]
    );
}

/// A descendant no endpoint serves is availability. The session keeps the retry
/// it has, refuses nothing, and accuses nobody — a refusal on every dark record
/// would be a denial of service on the owner's own moves.
#[test]
fn an_unavailable_descendant_keeps_the_retry_and_refuses_nothing() {
    let mut fx = GrantScenario::new();
    let (photos, albums) = two_root_folders(&mut fx);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let (mut fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    fx.world
        .record_store
        .fail_get_for(write_name(fx.folder).as_str());
    let _ = events_so_far(&mut events);
    tick(&fx.world, &fresh, &mut tasks);

    assert_eq!(
        abuse_events(&mut events),
        0,
        "a record the network did not serve names no party"
    );
    assert!(
        matches!(
            block_on(fresh.command(Command::Relink {
                node: photos,
                new_parent: albums,
            })),
            Ok(CommandOutcome::Queued { .. })
        ),
        "and the relocation the session can classify still queues"
    );
}

/// The proved-descent half of the boundary set, end to end: a session that
/// minted no grant walks two levels through the production wiring, renders into
/// the deeper scope, and plans a move between two shared folders off boundaries
/// it only walked — the classification the minted half alone cannot reach,
/// because this session minted nothing.
#[test]
fn a_session_that_minted_nothing_plans_a_move_between_two_walked_scopes() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let inner = fx.grant_nested_folder("in");
    let deep = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, inner, "deep");
    let beside =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, inner, "beside");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let (mut fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    assert!(
        block_on(fresh.walked_scope_material(inner)).is_some(),
        "the walk proved the depth-2 scope root through the production wiring"
    );
    block_on(fresh.command(Command::SetFocus { node: Some(inner) })).expect("the window opens");
    tick(&fx.world, &fresh, &mut tasks);
    assert!(
        block_on(fresh.view())
            .expect("a rendered view")
            .children(inner)
            .iter()
            .any(|child| child.id == deep),
        "and its read leg placed the subtree this session did not author"
    );

    assert!(
        matches!(
            block_on(fresh.command(Command::Relink {
                node: deep,
                new_parent: beside,
            })),
            Ok(CommandOutcome::Queued { .. })
        ),
        "a move that stays inside the walked scope crosses nothing"
    );
    assert!(
        matches!(
            block_on(fresh.command(Command::Relink {
                node: deep,
                new_parent: holiday,
            })),
            Ok(CommandOutcome::Queued { .. })
        ),
        "and a move into the scope above it journals its legs"
    );
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![
            ScopeCrossing::Intra,
            ScopeCrossing::ExitsGrantedSource,
            ScopeCrossing::Cross,
        ],
        "as the two legs the walked boundaries make it, behind the move that \
         crossed nothing: out of the deeper scope, then into the one above"
    );
}

/// The direct-child-scope index the scope root published at `node` carries,
/// by scope id. A read grant cuts no write scope, so the granted scope's write
/// body opens under the write key the vault root's own seed derives.
fn published_child_scope_index(
    world: &FakeWorld,
    blocks: &Blocks,
    node: NodeId,
    write_epoch: u64,
) -> Vec<[u8; 16]> {
    let section =
        published_grant_section(world, blocks, node).expect("the node is a published scope root");
    let write_key = kdf::write_key(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes());
    let plaintext = unseal(
        write_key.as_bytes(),
        &AadContext {
            v: ENVELOPE_V,
            id: node.0,
            scope: node.0,
            epoch: write_epoch,
            struct_tag: STRUCT_TAG_WRITE_BODY,
        },
        &section.write_body.sealed,
    )
    .expect("the scope's own write key opens its write body");
    decode_write_body(&plaintext)
        .expect("the write body decodes")
        .direct_child_scope_index
        .into_iter()
        .map(|child| child.scope_id)
        .collect()
}

/// The refusal end to end, over what another device would see: the member hears
/// it at the command, neither enclosing scope root publishes, both indices still
/// name the truth, and a cold session's boundary walk still reaches the nested
/// scope root down the index chain.
#[test]
fn a_move_that_carries_a_shared_folder_into_another_scope_is_refused() {
    let mut fx = GrantScenario::new();
    let inner = fx.grant_nested_folder("in");
    let holiday =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "holiday");
    let carton = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "carton",
    );
    assert!(
        matches!(
            block_on(fx.engine.command(Command::Relink {
                node: inner,
                new_parent: carton,
            })),
            Ok(CommandOutcome::Queued { .. })
        ),
        "a move that keeps the scope root inside its own scope crosses nothing"
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let root_before = sequence_at(&fx.world, &write_name(ROOT));
    let enclosing_before = sequence_at(&fx.world, &write_name(fx.folder));
    for (node, why) in [
        (carton, "a folder that holds a granted folder"),
        (inner, "and the granted folder itself"),
    ] {
        assert!(
            matches!(
                block_on(fx.engine.command(Command::Relink {
                    node,
                    new_parent: holiday,
                })),
                Err(EngineError::ScopeExitRefused { .. })
            ),
            "{why} is refused at the command, before any subtree walk"
        );
    }
    assert_eq!(
        (
            sequence_at(&fx.world, &write_name(ROOT)),
            sequence_at(&fx.world, &write_name(fx.folder))
        ),
        (root_before, enclosing_before),
        "a refused crossing publishes nothing at either enclosing scope root"
    );

    assert_eq!(
        published_child_scope_index(&fx.world, &fx.blocks, ROOT, EPOCH),
        vec![fx.folder.0],
        "the vault root still names the one scope it directly holds"
    );
    assert_eq!(
        published_child_scope_index(&fx.world, &fx.blocks, fx.folder, 1),
        vec![inner.0],
        "and the scope the move would have emptied still names the nested root"
    );

    let (fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    assert!(
        block_on(fresh.walked_scope_material(inner)).is_some(),
        "so an enumeration down the index chain still reaches the nested scope root"
    );
}

/// The child-scope index rides a body every committed writer of the scope
/// authors, so an entry one of them removes erases a boundary. The name law
/// states it independently: a folder publishing under a name this scope's write
/// seed does not derive is a scope root, and a move into it is a crossing.
#[test]
fn a_child_the_scopes_write_seed_does_not_name_is_a_boundary_no_index_states() {
    for (label, shared_name, expected) in [
        (
            "a name this scope's write seed does not derive",
            derive_write_name(&[0x5A; 32], &SHARED.0),
            ScopeCrossing::Cross,
        ),
        (
            "the name this scope's write seed derives",
            write_name(SHARED),
            ScopeCrossing::Intra,
        ),
    ] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_vault_naming(
            &world,
            &blocks,
            Vec::new(),
            vec![
                named_child(SHARED, "shared", &shared_name),
                named_child(PHOTOS, "photos", &write_name(PHOTOS)),
            ],
        );
        let device = world.device(&owner_identity().verifying_key().to_sec1());
        let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &device);
        tick(&world, &engine, &mut tasks);

        assert!(
            matches!(
                block_on(engine.command(Command::Relink {
                    node: PHOTOS,
                    new_parent: SHARED,
                })),
                Ok(CommandOutcome::Queued { .. })
            ),
            "{label}: the relocation queues"
        );
        assert_eq!(
            queued_crossings(&device),
            vec![expected],
            "{label}: and carries the crossing the boundary set names"
        );
    }
}

/// Another writer publishes `folder`'s next record, adding `extra` on top of
/// whatever the folder currently carries.
fn concurrent_add(
    world: &FakeWorld,
    blocks: &Blocks,
    folder: NodeId,
    read_key: &[u8; 32],
    scope_id: [u8; 16],
    extra: ChildRef,
) {
    let name = write_name(folder);
    let head = published_head(world, blocks, &name).expect("the folder is published");
    let envelope = decode_envelope(&head).expect("the head block decodes");
    let ReadBody::Folder {
        created_at,
        modified_at,
        mut children,
        unknown,
    } = open_read_body(&envelope, read_key).expect("the folder body opens")
    else {
        panic!("expected a folder body");
    };
    children.push(extra);
    let authored = author_child_envelope(EnvelopeAuthoring {
        node_id: folder.0,
        scope_id,
        epoch: envelope.epoch,
        read_key,
        nonce: &[0x77; 24],
        body: &ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        },
        carried_unknown: envelope.unknown.clone(),
        carried_epoch_tag_unknown: envelope.epoch_tag_unknown.clone(),
    })
    .expect("the concurrent writer authors a valid record");
    blocks.put(authored.block.clone());
    let record = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &folder.0).as_bytes()),
        format!("/ipfs/{}", authored.cid).as_bytes(),
        sequence_at(world, &name) + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
}

/// The names `folder`'s published record carries, read under `read_key`.
fn published_child_names(
    world: &FakeWorld,
    blocks: &Blocks,
    folder: NodeId,
    read_key: &[u8; 32],
) -> Vec<String> {
    let head = published_head(world, blocks, &write_name(folder)).expect("a published record");
    let envelope = decode_envelope(&head).expect("the head block decodes");
    let ReadBody::Folder { children, .. } =
        open_read_body(&envelope, read_key).expect("the folder body opens")
    else {
        panic!("expected a folder body");
    };
    children.iter().map(|child| child.name.clone()).collect()
}

/// A folder of the vault root's own scope, published at `name`.
fn named_child(node: NodeId, name: &str, ipns_name: &IpnsName) -> ChildRef {
    ChildRef {
        id: node.0,
        name: name.to_owned(),
        ipns_name: ipns_name.as_str().as_bytes().to_vec(),
        kind: CoreNodeKind::Folder,
        link_counter: 1,
        unknown: PreservedFields::new(),
    }
}

/// The override seed the owner's own blob at `node`'s scope root conveys, with
/// the read epoch that record carries.
fn scope_material_of(
    world: &FakeWorld,
    blocks: &Blocks,
    node: NodeId,
) -> (Zeroizing<[u8; 32]>, u64) {
    let epoch = published_read_epoch(world, blocks, node);
    let section = published_grant_section(world, blocks, node).expect("a scope root");
    let seed = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        node.0,
        epoch,
        &section,
    )
    .expect("the owner blob yields the scope's override seed");
    (seed, epoch)
}

/// Stand a node the mint left behind onto the scope it now belongs to. A mint
/// promotes a folder to a scope root under a fresh override seed and leaves the
/// nodes it carried sealed under the scope they left; the lazy wave converges
/// them, and no drain pass drives that wave.
fn converge_into_granted_scope(fx: &GrantScenario, node: NodeId) {
    let (seed, epoch) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    reseal_interior_node(&fx.world, &fx.blocks, node, fx.folder.0, &seed, epoch);
}

/// The scope id and read epoch the record at `name` binds, and its read body
/// under `read_key` — `None` where that key does not open it.
fn published_seal(
    world: &FakeWorld,
    blocks: &Blocks,
    name: &IpnsName,
    read_key: &[u8; 32],
) -> ([u8; 16], u64, Option<ReadBody>) {
    let head = published_head(world, blocks, name).expect("a published record");
    let envelope = decode_envelope(&head).expect("the head decodes");
    let body = open_read_body(&envelope, read_key).ok();
    (envelope.scope, envelope.epoch, body)
}

/// The per-node read key one scope's override seed derives.
fn node_read_key(scope_seed: &[u8; 32], node: NodeId) -> [u8; 32] {
    *kdf::read_key(kdf::node_seed(scope_seed, &node.0).as_bytes()).as_bytes()
}

/// Whether a folder body names `child`.
fn names_child(body: &Option<ReadBody>, child: NodeId) -> bool {
    matches!(body, Some(ReadBody::Folder { children, .. })
        if children.iter().any(|entry| entry.id == child.0))
}

/// The blueprint rule for a move out of a granted folder, end to end: the
/// crossing publishes on the first pass, the moved subtree re-seals at the
/// destination scope's epoch, and the grantee of the source scope no longer
/// reaches it — the source root's listing has dropped it, and the seed that
/// grantee holds no longer opens its record.
#[test]
fn a_move_out_of_a_granted_folder_re_seals_the_subtree_into_the_destination() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, holiday);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let (granted_seed, granted_epoch) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    let (scope, epoch, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(holiday),
        &node_read_key(&granted_seed, holiday),
    );
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (fx.folder.0, granted_epoch, true),
        "the moved node starts inside the granted scope, at that scope's epoch"
    );

    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move out of the granted scope journals its crossing");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "the crossing published on the first pass rather than halting"
    );
    let vault_epoch = published_read_epoch(&fx.world, &fx.blocks, ROOT);
    let (scope, epoch, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(holiday),
        &node_read_key(&READ_SCOPE_SEED, holiday),
    );
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (ROOT.0, vault_epoch, true),
        "and it now binds the destination scope, at the destination's own epoch"
    );
    assert!(
        published_seal(
            &fx.world,
            &fx.blocks,
            &write_name(holiday),
            &node_read_key(&granted_seed, holiday),
        )
        .2
        .is_none(),
        "the source scope's read key at the source epoch no longer opens it"
    );
    assert!(
        !names_child(
            &published_seal(
                &fx.world,
                &fx.blocks,
                &write_name(fx.folder),
                &node_read_key(&granted_seed, fx.folder),
            )
            .2,
            holiday,
        ),
        "the granted scope root republished under its own end, without the node"
    );
    assert!(
        names_child(
            &published_seal(
                &fx.world,
                &fx.blocks,
                &write_name(album),
                &node_read_key(&READ_SCOPE_SEED, album),
            )
            .2,
            holiday,
        ),
        "and the destination folder names it"
    );
}

/// A relocation that leaves a granted source is a scope-exit rotation trigger
/// for the source (blueprint/engine.md "Sync core: Ops"). The cut runs once per
/// source scope however many ops left it, and raises that scope's durable
/// read-epoch floor, which is the boundary every later read of it is measured
/// against.
#[test]
fn a_move_out_of_a_granted_folder_cuts_the_scope_it_left_once() {
    let mut fx = GrantScenario::new();
    let one = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "one");
    let two = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "two");
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, one);
    converge_into_granted_scope(&fx, two);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let before = published_read_epoch(&fx.world, &fx.blocks, fx.folder);
    for node in [one, two] {
        block_on(fx.engine.command(Command::Relink {
            node,
            new_parent: album,
        }))
        .expect("a move out of the granted scope journals its crossing");
    }
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "both crossings published"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before + 1,
        "two exits from one scope are one cut, not two"
    );
    assert_eq!(
        block_on(floor::read_epoch_floor(
            &fx.owner_device.floors(&SECRET),
            &fx.folder.0
        )),
        Ok(Some(before + 1)),
        "and the cut raised the durable read-epoch floor of the scope it left"
    );
}

/// A source-remove that confirms at its name and then fails a local step is the
/// move complete on the network. Its published-op mark drops the op on the next
/// pass, so what the re-seal published commits at that failure or never: the
/// destination holds, the vacated names, and the cut the exit owes. The cut is
/// the half a later read observes; the fault that fails the self-adopt fails
/// the cut's own read of that root too, so a healed later pass drives it.
#[test]
fn a_source_remove_that_confirms_and_then_fails_still_commits_the_crossing() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, holiday);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (granted_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    let before = published_read_epoch(&fx.world, &fx.blocks, fx.folder);

    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move out of the granted scope journals its crossing");
    // The source-remove is the one publish this pass makes at the source
    // root's name, and the raise is its self-adopt's last step: the record is
    // live when the failure lands.
    fx.owner_device
        .floor_store
        .fail_floor_raises_for(&sequence_floor_label(
            write_name(fx.folder).as_str().as_bytes(),
        ));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    fx.owner_device.floor_store.heal_floors();

    assert!(
        names_child(
            &published_seal(
                &fx.world,
                &fx.blocks,
                &write_name(album),
                &node_read_key(&READ_SCOPE_SEED, album),
            )
            .2,
            holiday,
        ),
        "the dest-add landed"
    );
    assert!(
        !names_child(
            &published_seal(
                &fx.world,
                &fx.blocks,
                &write_name(fx.folder),
                &node_read_key(&granted_seed, fx.folder),
            )
            .2,
            holiday,
        ),
        "and the source-remove confirmed at its name before its self-adopt failed"
    );

    // The owed cut is driven on a pass, and a queue the mark emptied runs
    // none: one more op gives the next tick a pass.
    create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "later");
    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "the next pass dropped the op through its published-op mark"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before + 1,
        "and drove the cut the commit at the failure owed the scope the move left"
    );
}

/// A crossing between two scopes that grant nobody owes no cut. The vault root
/// is that scope: no share reaches it, so a move *into* a granted folder leaves
/// nothing behind a rotation would protect.
#[test]
fn a_move_into_a_granted_folder_re_seals_and_cuts_nothing() {
    let mut fx = GrantScenario::new();
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let before = published_read_epoch(&fx.world, &fx.blocks, ROOT);
    block_on(fx.engine.command(Command::Relink {
        node: album,
        new_parent: fx.folder,
    }))
    .expect("a move into the granted scope journals its crossing");
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Cross],
        "the source is the vault root, which grants nobody"
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "the crossing published on the first pass"
    );
    let (granted_seed, granted_epoch) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    let (scope, epoch, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(album),
        &node_read_key(&granted_seed, album),
    );
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (fx.folder.0, granted_epoch, true),
        "the moved node re-sealed into the granted scope at that scope's epoch"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, ROOT),
        before,
        "and the source scope, which grants nobody, was not cut"
    );
}

/// Two granted sibling folders and a node inside the first, ready to move. The
/// mint leaves the node sealed under the scope it left, so it converges onto
/// the enclosing scope before the move reads it.
fn two_granted_folders(fx: &mut GrantScenario) -> (NodeId, NodeId) {
    let moving = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(fx, moving);
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: album,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done),
        "the second folder is granted too, so both ends are interior scopes"
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    (moving, album)
}

/// A move from one shared folder straight into another, end to end. One drain
/// pass carries the vault root and one interior end, so the command journals
/// two legs and the drain publishes one a tick: out of the granted source into
/// the vault-root scope, then into the destination scope. The subtree lands
/// bound to the destination scope at that scope's epoch, and the granted source
/// is cut once — by the leg that left it.
#[test]
fn a_move_between_two_granted_folders_re_seals_into_the_destination_scope() {
    let mut fx = GrantScenario::new();
    let (holiday, album) = two_granted_folders(&mut fx);
    let source_before = published_read_epoch(&fx.world, &fx.blocks, fx.folder);
    let destination_before = published_read_epoch(&fx.world, &fx.blocks, album);

    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move between two shared folders is no longer refused");
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::ExitsGrantedSource, ScopeCrossing::Cross],
        "as two legs, the first of which owes the cut the whole move owes"
    );

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (vault_scope, vault_epoch, vault_opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(holiday),
        &node_read_key(&READ_SCOPE_SEED, holiday),
    );
    assert_eq!(
        (vault_scope, vault_opened.is_some()),
        (ROOT.0, true),
        "the first leg parked the subtree in the vault-root scope"
    );
    assert_eq!(
        vault_epoch,
        published_read_epoch(&fx.world, &fx.blocks, ROOT),
        "at that scope's own epoch"
    );

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "and the second leg published, leaving no leg queued"
    );
    let (album_seed, album_epoch) = scope_material_of(&fx.world, &fx.blocks, album);
    let (scope, epoch, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(holiday),
        &node_read_key(&album_seed, holiday),
    );
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (album.0, album_epoch, true),
        "the subtree binds the destination scope, at that scope's epoch"
    );
    assert!(
        names_child(
            &published_seal(
                &fx.world,
                &fx.blocks,
                &write_name(album),
                &node_read_key(&album_seed, album),
            )
            .2,
            holiday,
        ),
        "the destination scope root names it"
    );
    let (source_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    assert!(
        !names_child(
            &published_seal(
                &fx.world,
                &fx.blocks,
                &write_name(fx.folder),
                &node_read_key(&source_seed, fx.folder),
            )
            .2,
            holiday,
        ),
        "and the source scope root no longer does"
    );
    assert_eq!(
        (
            published_read_epoch(&fx.world, &fx.blocks, fx.folder),
            published_read_epoch(&fx.world, &fx.blocks, album),
        ),
        (source_before + 1, destination_before),
        "the granted source was cut exactly once, and the destination not at all"
    );
    assert_eq!(
        block_on(floor::read_epoch_floor(
            &fx.owner_device.floors(&SECRET),
            &fx.folder.0
        )),
        Ok(Some(source_before + 1)),
        "which raised the durable read-epoch floor of the scope the move left"
    );
}

/// The legs are two durable ops, so a restart between them resumes at the one
/// still queued. The cut belongs to the leg that already published, and the
/// debt it settled is durable: the resumed leg publishes the arrival and cuts
/// nothing a second time.
#[test]
fn a_restart_between_the_legs_of_a_staged_move_cuts_the_source_once() {
    let mut fx = GrantScenario::new();
    let (holiday, album) = two_granted_folders(&mut fx);
    let source_before = published_read_epoch(&fx.world, &fx.blocks, fx.folder);

    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move between two shared folders is no longer refused");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Cross],
        "the first leg published, leaving the arriving one queued"
    );

    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        source_before + 1,
        "and cut the scope it left"
    );

    // What the ended session left spawned dies with it, as it would in a crash.
    drop(fx.world.scheduler.take_spawned_tasks());
    let (restarted, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &restarted, &mut tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "the restarted session drained the leg the crash left"
    );
    let (album_seed, album_epoch) = scope_material_of(&fx.world, &fx.blocks, album);
    let (scope, epoch, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(holiday),
        &node_read_key(&album_seed, holiday),
    );
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (album.0, album_epoch, true),
        "the subtree binds the destination scope at that scope's epoch"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        source_before + 1,
        "and the source scope carries the one cut its exit owed, not a second"
    );
}

/// Every pass of a tick reads the whole queue, and a pass that carries no
/// interior end can author no crossing. The arriving leg waits for the tick
/// whose second end is its destination, so the passes it waits through leave it
/// where it is: one that spent the attempt budget instead would dead-letter a
/// move the next tick was about to publish.
#[test]
fn the_passes_that_cannot_author_a_staged_move_do_not_spend_it() {
    let mut fx = GrantScenario::new();
    let (holiday, album) = two_granted_folders(&mut fx);
    for name in ["one", "two", "three", "four"] {
        let bystander =
            create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, name);
        assert_eq!(
            block_on(fx.engine.command(Command::Grant {
                node: bystander,
                recipient_identity_public_key:
                    recipient_identity().verifying_key().to_sec1().to_vec(),
                permission: Permission::Read,
            })),
            Ok(CommandOutcome::Done),
            "each bystander is a scope with a pass of its own"
        );
    }
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("the move journals its legs");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "both legs published"
    );
    let (album_seed, album_epoch) = scope_material_of(&fx.world, &fx.blocks, album);
    let (scope, epoch, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(holiday),
        &node_read_key(&album_seed, holiday),
    );
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (album.0, album_epoch, true),
        "and the subtree arrived in the destination scope rather than dead-lettering"
    );
}

/// The second end's epoch arrives from the tick's boundary walk, and a rotation
/// elsewhere supersedes it. The pass proves the end against the scope root's own
/// record before it authors anything under it, so a superseded end publishes
/// nothing at all rather than sealing a live record under a revoked seed and
/// learning it past the PUT.
#[test]
fn a_second_end_the_record_plane_moved_past_publishes_nothing() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, holiday);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        block_on(fx.engine.command(Command::RotateNow { node: fx.folder })),
        Ok(CommandOutcome::Done),
        "the walked material is now one cut behind the record it was read from"
    );

    let album_sequence = sequence_at(&fx.world, &write_name(album));
    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move out of the granted scope journals its crossing");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::ExitsGrantedSource],
        "the superseded end held the op rather than publishing under it"
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(album)),
        album_sequence,
        "and the destination folder never republished, so the halt came before \
         the first authoring"
    );
}

/// A crossing whose boundary this session has proved no material for is one it
/// cannot author. It is charged rather than held: a member watching a move that
/// will never publish reads a dead letter, never a vault that says it is fresh.
#[test]
fn a_crossing_whose_boundary_material_is_absent_dead_letters() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    // The mint recorded the boundary, so the crossing is classified; the walk
    // that would resolve what it seals under reads below the floor and proves
    // nothing.
    let epoch = published_read_epoch(&fx.world, &fx.blocks, fx.folder);
    block_on(
        fx.owner_device
            .floors(&SECRET)
            .raise_epoch_floor(&fx.folder.0, epoch + 1),
    )
    .expect("the floor raises");
    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move out of the granted scope journals its crossing");

    // One charge per pass, past the drain's own attempt budget.
    for _ in 0..8 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "a bounded budget ends the retries rather than holding the queue head"
    );
    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert_eq!(
        status
            .dead_letters
            .iter()
            .map(|dead| dead.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted],
        "and the member reads why the move never published"
    );
}

/// Every entry the account's published bin index carries.
fn published_bin_entries(fx: &GrantScenario) -> Vec<BinEntry> {
    serve_http(&fx.owner_device, &fx.blocks, 8);
    let keys = BinIndexKeys::derive(&SECRET);
    let load = block_on(load_bin_index(
        &fx.owner_device.record_store,
        &GatewayConfig {
            accelerator: None,
            public_fallbacks: vec!["http://gateway.test".to_owned()],
        }
        .into_gateway(SessionBearer::default()),
        &fx.owner_device.http,
        &fx.owner_device.floor_store,
        &fx.owner_device.snapshot_cache,
        &fx.world.scheduler,
        fx.engine.profile(),
        &keys,
    ))
    .enrol(&RefCell::new(None), None);
    let (BinIndexLoad::Resolved(index) | BinIndexLoad::Stale { index, .. }) = load else {
        panic!("the account's bin index reads");
    };
    index.entries
}

/// Every publish helper resolves the plane of the node it seals, so a pass that
/// carries a second end serves the ops inside that scope from it. A soft delete
/// of a node in the granted scope files its bin entry under **that** scope's id
/// and under the name that scope's own write seed derives; the source end's id
/// would name a scope the entry's record does not belong to, and a restore
/// would re-key it into the wrong one.
#[test]
fn a_delete_inside_the_second_end_files_its_bin_entry_under_that_scope() {
    let mut fx = GrantScenario::new();
    let keeper = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "keeper",
    );
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, keeper);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (granted_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    let granted_write_seed = block_on(fx.engine.walked_scope_material(fx.folder))
        .expect("the walk proved the granted scope")
        .write_scope_seed;

    block_on(fx.engine.command(Command::Delete { node: keeper }))
        .expect("a soft delete inside the granted scope queues");
    // A move into the granted folder is what gives the pass its second end, and
    // it leaves the vault root, which grants nobody, so nothing rotates under
    // the assertions below.
    block_on(fx.engine.command(Command::Relink {
        node: album,
        new_parent: fx.folder,
    }))
    .expect("the crossing queues");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let entries = published_bin_entries(&fx);
    let entry = entries
        .iter()
        .find(|entry| entry.node_id == keeper.0)
        .expect("the soft delete filed a bin entry");
    assert_eq!(
        entry.scope_id, fx.folder.0,
        "the entry names the scope the deleted node belonged to"
    );
    assert_eq!(
        entry.ipns_name(),
        derive_write_name(&granted_write_seed, &keeper.0)
            .as_str()
            .as_bytes(),
        "at the name that scope's own write seed derives"
    );
    let (scope, _, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(keeper),
        &node_read_key(&granted_seed, keeper),
    );
    assert_eq!(
        (scope, opened.is_some()),
        (fx.folder.0, false),
        "and the soft branch left the record published under that scope, re-keyed \
         out of the seed the grantee still holds"
    );
}

/// The same per-node plane resolution on the authoring side: a create under a
/// parent that resolves onto the second end seals its new record into that
/// scope, at that scope's epoch. Under the source end it would seal a record the
/// granted scope's own readers reject as a transplant, and probe the wrong name
/// for a replay of its own publish.
#[test]
fn a_create_inside_the_second_end_seals_into_that_scope() {
    let mut fx = GrantScenario::new();
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (granted_seed, granted_epoch) = scope_material_of(&fx.world, &fx.blocks, fx.folder);

    block_on(fx.engine.command(Command::Create {
        parent: fx.folder,
        name: "note".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a create inside the granted scope queues");
    block_on(fx.engine.command(Command::Relink {
        node: album,
        new_parent: fx.folder,
    }))
    .expect("and the crossing that gives the pass its second end");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let note = block_on(fx.engine.view())
        .expect("a rendered view")
        .children(fx.folder)
        .into_iter()
        .find(|child| child.name == "note")
        .expect("the create published")
        .id;
    let (scope, epoch, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(note),
        &node_read_key(&granted_seed, note),
    );
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (fx.folder.0, granted_epoch, true),
        "the new record binds the scope its parent sits in, at that scope's epoch"
    );
}

/// A relocation carries the crossing it was classified under, and a grant
/// minted after it was queued moves the boundary under it. The drain reads the
/// two planes it actually resolved rather than that stale field: publishing the
/// move as a plain ref move would carry the subtree out of the granted scope
/// still sealed where the new grantee opens it.
#[test]
fn a_relink_the_grant_overtook_still_re_seals_and_cuts() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    // Journaled while both ends are still the vault root's.
    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("an intra-scope relink queues");
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Intra],
        "the boundary the grant is about to mint does not exist yet"
    );

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, holiday);
    let (granted_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    let before = published_read_epoch(&fx.world, &fx.blocks, fx.folder);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "the move published"
    );
    let vault_epoch = published_read_epoch(&fx.world, &fx.blocks, ROOT);
    let (scope, epoch, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(holiday),
        &node_read_key(&READ_SCOPE_SEED, holiday),
    );
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (ROOT.0, vault_epoch, true),
        "and it re-sealed into the destination scope all the same"
    );
    assert!(
        published_seal(
            &fx.world,
            &fx.blocks,
            &write_name(holiday),
            &node_read_key(&granted_seed, holiday),
        )
        .2
        .is_none(),
        "the scope it left no longer opens it"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before + 1,
        "and that scope was cut, off the plane the pass proved rather than the \
         crossing the op carries"
    );
}

/// The crossing every relocation on this device's durable queue carries, in
/// queue order.
fn queued_crossings(device: &FakeDevice) -> Vec<ScopeCrossing> {
    let raw = block_on(device.staging_store.queued_ops()).expect("the queue reads");
    let enc_subkey = kdf::enc_subkey(&SECRET);
    decode_queue(&RecordReader::new(&enc_subkey), &raw)
        .mine
        .iter()
        .filter_map(|(_, op)| op.relocation().map(|(_, _, crossing)| crossing))
        .collect()
}

/// The parent's index is written last, so a mint that published the grantee
/// scope root and then failed leaves a live scope the index does not name.
/// Re-driving the same share resumes against that root: it draws no second
/// override seed, and the index catches up.
#[test]
fn a_second_share_of_a_folder_whose_scope_the_index_lost_resumes_that_scope() {
    let mut fx = GrantScenario::new();
    let stranded = fx.strand_the_grantee_scope();
    let first_seed = stranded_override_seed(&stranded, fx.folder);
    let root_before = sequence_at(&fx.world, &write_name(ROOT));

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let resumed = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the resumed scope answers");
    // The commitment alone would hold across a second mint: it carries the row,
    // the name and the cut epoch, and none of those move. The override seed
    // rides the owner blob, so it is what separates a resume from a re-mint.
    assert!(
        stranded_override_seed(&resumed, fx.folder) == first_seed,
        "the re-drive resumed against the published root and minted no second seed",
    );
    assert_eq!(
        resumed.commitment, stranded.commitment,
        "over the same committed set",
    );
    assert!(
        sequence_at(&fx.world, &write_name(ROOT)) > root_before,
        "and the parent republished the index the first attempt owed"
    );
}

/// The override seed in a scope root's owner blob, opened under the owner's own
/// encryption subkey at the scope's first read epoch.
fn stranded_override_seed(section: &GrantSection, node: NodeId) -> Zeroizing<[u8; 32]> {
    published_override_seed(&kdf::enc_subkey(&SECRET), ENVELOPE_V, node.0, 1, section)
        .expect("the owner blob yields the scope's override seed")
}

/// A live scope root the index lost commits the grant that minted it. A share
/// of the same folder to another recipient is refused there rather than
/// resumed, so no second recipient is grafted onto a scope whose committed set
/// holds nothing for them.
#[test]
fn a_share_to_another_recipient_over_a_scope_the_index_lost_is_refused() {
    let mut fx = GrantScenario::new();
    let stranded = fx.strand_the_grantee_scope();

    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second recipient's code imports");
    assert_eq!(
        block_on(
            fx.engine.command(Command::Grant {
                node: fx.folder,
                recipient_identity_public_key: EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
                    .expect("valid identity scalar")
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
                permission: Permission::Read,
            })
        ),
        Err(EngineError::UnsupportedTarget {
            check: "resume-not-this-grant"
        }),
    );
    assert_eq!(
        published_grant_section(&fx.world, &fx.blocks, fx.folder)
            .expect("the stranded scope still answers")
            .commitment,
        stranded.commitment,
        "and the first grantee's scope is untouched"
    );
}

/// A direct-child-scope index carries no signature of its own: it rides the
/// sealed write body, which any committed writer of that scope may author.
/// Dropping an entry cannot be forged into a different name, but it would move
/// the anchor of a later share up a level, and hand whoever dropped it the
/// derivation of the scope that share mints. The walk refuses instead.
#[test]
fn a_share_below_a_scope_root_the_index_lost_is_refused() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "in");
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    assert!(
        fx.grant_folder_to_recipient().is_err(),
        "the parent index update fails, so the scope goes live unnamed"
    );
    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());

    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: inner,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "enclosing-scope-index-lost-a-root"
        }),
    );
}

/// The gate reports a record below this device's own read-epoch floor as a
/// plain rejection, which the derived-name probe would otherwise read as "no
/// scope here". Only a scope root ever raises a floor at its own scope id, so
/// the floor alone refuses the mint.
#[test]
fn a_second_share_is_refused_when_the_stranded_root_reads_below_the_floor() {
    let mut fx = GrantScenario::new();
    block_on(
        fx.owner_device
            .floors(&SECRET)
            .raise_epoch_floor(&fx.folder.0, 9),
    )
    .expect("a floor a scope root adopted at this id left behind");

    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::UnsupportedTarget {
            check: "grant-target-already-names-a-scope"
        }),
    );
}

/// A grant on a folder that already sits inside a granted scope anchors under
/// **that** scope, not the vault root: its commitment, seeds and index are the
/// ones the mint re-seals, and the fresh scope's ascent link is sealed to the
/// derivation only that scope's own reader can walk.
#[test]
fn a_grant_inside_a_granted_scope_anchors_under_that_scope() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "in");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let enclosing = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the granted folder is a scope root");
    let enclosing_override_seed = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        1,
        &enclosing,
    )
    .expect("the owner blob yields the enclosing scope's override seed");
    reseal_interior_node(
        &fx.world,
        &fx.blocks,
        inner,
        fx.folder.0,
        &enclosing_override_seed,
        1,
    );

    let root_before = sequence_at(&fx.world, &write_name(ROOT));
    let enclosing_before = sequence_at(&fx.world, &write_name(fx.folder));
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: inner,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done),
    );

    assert_eq!(
        sequence_at(&fx.world, &write_name(ROOT)),
        root_before,
        "the vault root's index never gains a scope it does not directly hold"
    );
    assert!(
        sequence_at(&fx.world, &write_name(fx.folder)) > enclosing_before,
        "the enclosing scope re-sealed its own index instead"
    );

    // The ascent link is the decisive binding: it opens only under
    // `nodeSeed(overrideSeed, inner)` of the scope that encloses `inner`, so a
    // mint that had anchored at the vault root could not produce it.
    let section = published_grant_section(&fx.world, &fx.blocks, inner)
        .expect("the nested folder now answers as a scope root");
    let ascent = section
        .ascent_link
        .as_ref()
        .expect("a nested scope root carries an ascent link");
    open_ascent_link(
        kdf::node_seed(&enclosing_override_seed, &inner.0).as_bytes(),
        &AadContext {
            v: ENVELOPE_V,
            id: inner.0,
            scope: inner.0,
            epoch: 1,
            struct_tag: STRUCT_TAG_ASCENT_LINK,
        },
        &AscentLink {
            ascent_public: ascent.ascent_public,
            enc: ascent.enc,
            ciphertext: ascent.ciphertext.clone(),
            unknown: PreservedFields::new(),
        },
    )
    .expect("the enclosing scope's derivation opens the nested scope's ascent link");
}

/// The interior travels with the folder. A grantee derives every key from the
/// scope it is granted, and that scope's first epoch carries no history link, so
/// a node left under the derivation of the scope the folder left is a node the
/// grantee opens the root above and nothing inside.
#[test]
fn a_granted_folders_interior_re_seals_into_the_scope_the_grant_mints() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let section = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the granted folder answers as a scope root");
    let override_seed = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        1,
        &section,
    )
    .expect("the owner blob yields the fresh override seed");

    let head = published_head(&fx.world, &fx.blocks, &write_name(inner))
        .expect("the interior node is published");
    let envelope = decode_envelope(&head).expect("the head decodes");
    assert_eq!(
        envelope.scope, fx.folder.0,
        "the node now belongs to the scope the grant minted"
    );
    assert_eq!(envelope.epoch, 1, "at that scope's first epoch");
    let read_key = kdf::read_key(kdf::node_seed(&override_seed, &inner.0).as_bytes());
    open_read_body(&envelope, read_key.as_bytes())
        .expect("the grantee's own derivation opens the node inside the folder");
}

/// The move the mint owes is re-drivable. A grant that stalls part way through
/// its interior leaves nodes in two scopes, and re-driving the owner action
/// finishes the move against the root the first attempt promoted rather than
/// minting a second scope over it.
#[test]
fn a_stalled_grant_re_drives_into_the_scope_the_first_attempt_promoted() {
    let mut fx = GrantScenario::new();
    let one = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "one");
    let two = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "two");
    // The walk publishes in node-id order, so stalling the higher id leaves the
    // lower one already moved when the re-drive picks the move up.
    let (moved, stalled) = if one.0 < two.0 {
        (one, two)
    } else {
        (two, one)
    };

    fx.world
        .record_store
        .fail_put_for(write_name(stalled).as_str());
    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::PartialCommit {
            check: "interior-publish-failed",
        }),
    );
    let promoted = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the folder answers as a scope root the stall did not undo");
    let first_seed = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        1,
        &promoted,
    )
    .expect("the owner blob yields the scope's override seed");

    fx.world
        .record_store
        .heal_put_for(write_name(stalled).as_str());
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let resumed = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the folder still answers as a scope root");
    let second_seed = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        1,
        &resumed,
    )
    .expect("the owner blob yields the scope's override seed");
    assert!(
        first_seed == second_seed,
        "the re-drive resumed against the published root and minted no second seed",
    );

    for node in [moved, stalled] {
        let head = published_head(&fx.world, &fx.blocks, &write_name(node))
            .expect("the interior node is published");
        let envelope = decode_envelope(&head).expect("the head decodes");
        assert_eq!(
            envelope.scope, fx.folder.0,
            "every node of the subtree belongs to the scope the grant minted",
        );
        assert_eq!(envelope.epoch, 1, "at that scope's first epoch");
        let read_key = kdf::read_key(kdf::node_seed(&second_seed, &node.0).as_bytes());
        open_read_body(&envelope, read_key.as_bytes())
            .expect("the granted scope's own derivation opens it");
    }
}

/// A floor read ahead of the resume probe strands a grant that stalls twice:
/// half moved, and with no command that can finish it.
#[test]
fn a_grant_that_stalls_twice_is_still_re_drivable() {
    let mut fx = GrantScenario::new();
    let one = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "one");
    let two = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "two");
    let stalled = if one.0 < two.0 { two } else { one };

    fx.world
        .record_store
        .fail_put_for(write_name(stalled).as_str());
    for drive in 1..=2 {
        assert!(
            fx.grant_folder_to_recipient().is_err(),
            "drive {drive} stalls in the interior move"
        );
    }
    let promoted = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the folder answers as a scope root both stalls left standing");
    let first_seed = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        1,
        &promoted,
    )
    .expect("the owner blob yields the scope's override seed");
    assert!(
        block_on(floor::read_epoch_floor(
            &fx.owner_device.floors(&SECRET),
            &fx.folder.0
        ))
        .expect("floor read")
        .is_some(),
        "the second drive's resume probe adopted the promoted root and floored its scope id"
    );

    fx.world
        .record_store
        .heal_put_for(write_name(stalled).as_str());
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let resumed = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the folder still answers as a scope root");
    let second_seed = published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        1,
        &resumed,
    )
    .expect("the owner blob yields the scope's override seed");
    assert!(
        first_seed == second_seed,
        "the third drive resumed against the root the first attempt promoted",
    );
    for node in [one, two] {
        let head = published_head(&fx.world, &fx.blocks, &write_name(node))
            .expect("the interior node is published");
        assert_eq!(
            decode_envelope(&head).expect("the head decodes").scope,
            fx.folder.0,
            "the move finished: every node of the subtree belongs to the granted scope",
        );
    }
}

/// A stalled interior publish leaves the grantee a scope root whose interior
/// they cannot open, so the share pointer that names it is never posted.
#[test]
fn an_interior_node_that_cannot_publish_posts_no_share_pointer() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    fx.world
        .record_store
        .fail_put_for(write_name(inner).as_str());

    // The promoted root is already on the network and the move it stalled in is
    // re-drivable, which is what the partial-commit class reports.
    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::PartialCommit {
            check: "interior-publish-failed",
        }),
    );
    assert!(
        inbox(&fx.recipient_device).is_empty(),
        "and no share pointer names a scope whose interior the grantee cannot open"
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
            &fx.owner_device.floors(&SECRET),
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
        vec![
            recipient_row_at_root(CorePermission::Read),
            bystander_row_with_corrupt_sig(),
        ],
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

/// A committed writer authors the ledger, and no commitment entry carries
/// `recipientIdentityPk` — so a write grantee can rewrite the very label the
/// owner revokes by. Filing the rewritten row under the all-zero identity would
/// leave the owner a live grant no command can name, so the label is resolved
/// from the owner's own commitment instead: the committed `recipientEncPk`
/// names the contact a cut of that tag reaches. The rewrite is still reported.
#[test]
fn the_sharing_read_names_a_rewritten_row_from_the_owners_own_commitment() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let mut poisoned = recipient_row_at_root(CorePermission::Write);
    let honest = poisoned.ledger_entry.recipient_identity_pk;
    poisoned.ledger_entry.recipient_identity_pk = [0x11; IDENTITY_PUBLIC_LEN];
    seed_vault(&world, &blocks, vec![poisoned.clone()]);
    let alice = world.device(b"alice");
    let (mut engine, mut events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    let _ = events_so_far(&mut events);

    let named: Vec<Vec<u8>> = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the vault root resolved")
        .grants
        .into_iter()
        .map(|grant| grant.recipient_identity_public_key)
        .collect();

    assert_eq!(
        named,
        vec![honest.to_vec()],
        "the owner sees the party their own commitment names, so a revoke can \
         reach the tag"
    );
    assert!(
        !named.contains(&vec![0x11; IDENTITY_PUBLIC_LEN]),
        "and never the label the writer chose"
    );
    let reported: Vec<String> = events_so_far(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            Event::AttributableAbuse { description } => Some(description),
            _ => None,
        })
        .collect();
    let signer = hex_lower(&owner_pseudonym().verifying_key().to_bytes());
    assert!(
        reported.iter().any(
            |description| description.contains(&hex_lower(&poisoned.tag))
                && description.contains(&signer)
        ),
        "the rewritten row is reported as abuse, naming the tag and the pseudonym \
         that signed the body it rode in: {reported:?}"
    );
}

/// The name wave re-mints every committed row, and files the all-zero
/// placeholder for one whose recipient binding the owner never signed. Doing
/// that silently would leave the owner a live grant they can neither name nor
/// explain, so the wave reports the row with its tag and with the committed
/// pseudonym that signed the body it rode in.
#[test]
fn a_name_wave_reports_the_row_it_re_mints_without_an_owner_binding() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let rewritten = bystander_row_with_corrupt_sig();
    seed_vault(
        &world,
        &blocks,
        vec![
            recipient_row_at_root(CorePermission::Write),
            rewritten.clone(),
        ],
    );
    let alice = world.device(b"alice");
    let (mut engine, mut events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    let _ = events_so_far(&mut events);

    assert_eq!(
        block_on(engine.command(Command::Downgrade {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Ok(CommandOutcome::Done),
        "the write cut drives the wave that re-mints the set"
    );

    let reported: Vec<String> = events_so_far(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            Event::AttributableAbuse { description } => Some(description),
            _ => None,
        })
        .collect();
    let signer = hex_lower(&owner_pseudonym().verifying_key().to_bytes());
    assert!(
        reported.iter().any(
            |description| description.contains(&hex_lower(&rewritten.tag))
                && description.contains(&signer)
        ),
        "the re-minted row is reported as abuse, naming the tag and the pseudonym \
         that signed the body it rode in: {reported:?}"
    );
}

/// A re-mint that cannot vouch for a row's label files the all-zero placeholder
/// under the owner's **own** signature rather than laundering a writer's choice
/// into it, so the row reads as attested and still names nobody. The commitment
/// resolves it the same way, and nothing is reported: the owner signed that row.
#[test]
fn the_sharing_read_names_a_row_the_owner_signed_without_a_label() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let relabelled = mint_grant_row(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        &owner_pointer_read_key(),
        [0u8; IDENTITY_PUBLIC_LEN],
        &kdf::enc_subkey(&RECIPIENT_SECRET).public(),
        &SCOPE,
        write_name(ROOT).as_str().as_bytes(),
        CorePermission::Write,
    )
    .expect("a contributory recipient key");
    seed_vault(&world, &blocks, vec![relabelled]);
    let alice = world.device(b"alice");
    let (mut engine, mut events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    let _ = events_so_far(&mut events);

    let named: Vec<Vec<u8>> = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the vault root resolved")
        .grants
        .into_iter()
        .map(|grant| grant.recipient_identity_public_key)
        .collect();

    assert_eq!(
        named,
        vec![recipient_identity().verifying_key().to_sec1().to_vec()],
        "the owner sees the party their own commitment names"
    );
    assert_eq!(
        abuse_events(&mut events),
        0,
        "and a row the owner signed is no abuse to report"
    );
}

/// A contact code binds an encryption subkey under its **own** holder's
/// signature, so a second holder can bind the subkey a contact the owner already
/// holds is named by. Either name would then answer for the same committed
/// entry, and the label is what a host revokes from — so an ambiguous match
/// leaves the row unattested rather than naming a party the owner never granted.
#[test]
fn the_sharing_read_leaves_a_row_two_contacts_claim_unattested() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let mut poisoned = recipient_row_at_root(CorePermission::Write);
    poisoned.ledger_entry.recipient_identity_pk = [0x11; IDENTITY_PUBLIC_LEN];
    seed_vault(&world, &blocks, vec![poisoned]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    let impostor = EcdsaSigner::from_scalar(&BYSTANDER_SECRET).expect("valid identity scalar");
    block_on(engine.command(Command::ImportContact {
        contact_code:
            ContactCode::create(&impostor, kdf::enc_subkey(&RECIPIENT_SECRET).public()).encode(),
    }))
    .expect("a code its own holder signed imports");

    let named: Vec<Vec<u8>> = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the vault root resolved")
        .grants
        .into_iter()
        .map(|grant| grant.recipient_identity_public_key)
        .collect();

    assert_eq!(
        named,
        vec![vec![0u8; IDENTITY_PUBLIC_LEN]],
        "neither claimant is named for the row"
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
    let grantee = recipient_row_at_root(CorePermission::Read);
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
    let grantee = recipient_row_at_root(CorePermission::Read);
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
// Revoke
// ---------------------------------------------------------------------------

/// Cutting the row is bookkeeping; the revocation is the fresh-seed cascade that
/// republishes the scope root at a higher read epoch with no blob the revokee
/// can open. Assert that absence directly — it is the whole of the revoke.
#[test]
fn revoking_a_read_grant_republishes_the_root_without_the_revokees_blob() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let row = recipient_row_at_root(CorePermission::Read);
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
    let revokee = recipient_row_at_root(CorePermission::Read);
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
    seed_vault(
        &world,
        &blocks,
        vec![recipient_row_at_root(CorePermission::Read)],
    );
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
    let bystander = recipient_row_at_root(CorePermission::Read);
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

/// A revoke and a downgrade are different actions to a user, so an ordinary
/// folder refuses each under its own name.
#[test]
fn a_cut_at_an_ordinary_folder_reports_the_name_of_the_command_it_refused() {
    let mut fx = GrantScenario::new();
    let recipient = recipient_identity().verifying_key().to_sec1().to_vec();

    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: recipient.clone(),
        })),
        Err(EngineError::UnsupportedTarget {
            check: "revoke-target-is-not-a-scope-root"
        }),
    );
    assert_eq!(
        block_on(fx.engine.command(Command::Downgrade {
            node: fx.folder,
            recipient_identity_public_key: recipient,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "downgrade-target-is-not-a-scope-root"
        }),
    );
}

/// A tag the owner does not record as a link belongs to some grantee, so a
/// revoke that could reach it would cut an ordinary grant. It publishes nothing
/// instead.
#[test]
fn revoking_a_link_the_owner_never_recorded_publishes_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let grantee = recipient_row_at_root(CorePermission::Read);
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

/// The write link end to end. Its scope's cut moves the root the fragment and
/// the recorded tag both bind, so the fragment seals at the moved name and the
/// record is located by the tag the moved set carries.
#[test]
fn a_write_invite_link_claims_and_converts_across_its_own_cut() {
    let mut fx = GrantScenario::new();
    let inherited_name = write_name(fx.folder);
    let fragment = fx.mint_link_at(Permission::Write);

    let moved_name = fx.granted_scope_repoint().current_root;
    assert_ne!(
        moved_name, inherited_name,
        "the write link's own cut moved the scope root"
    );
    assert_eq!(
        InviteFragment::decode(&fragment)
            .expect("the mint's own fragment")
            .scope_root_name,
        moved_name.as_str().as_bytes(),
        "the bearer is sent to the root the wave moved to"
    );

    let bearer_pk = recipient_identity().verifying_key().to_sec1().to_vec();
    let (mut bearer, _bearer_events) = fx.bearer();
    assert_eq!(
        block_on(bearer.command(Command::ClaimInviteLink { fragment })),
        Ok(CommandOutcome::Done),
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
        "the claim converted into a personal grant on the moved scope"
    );
}

/// The owner half of the same rule: the record holds the tag the mint made, and
/// the cut re-minted the row under another one. A revoke names the tag the set
/// carries now, and forgets the record it was derived from.
#[test]
fn a_write_invite_link_is_revoked_after_its_cut() {
    let mut fx = GrantScenario::new();
    fx.mint_link_at(Permission::Write);
    assert_eq!(recorded_links(&fx.owner_device).len(), 1);

    assert_eq!(
        block_on(
            fx.engine
                .command(Command::RevokeInviteLink { node: fx.folder })
        ),
        Ok(CommandOutcome::Done),
    );

    assert!(
        recorded_links(&fx.owner_device).is_empty(),
        "the cut landed, so the record it was derived from is spent"
    );
    let after = fx.granted_scope_repoint().current_root;
    assert!(
        published_grant_section_at(&fx.world, &fx.blocks, &after)
            .expect("the moved root answers")
            .commitment
            .entries
            .is_empty(),
        "and the link's row is no longer committed, so a claim on it is refused"
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

/// One conversion pass, one publish. Each claim converts against the set the
/// pass is accumulating in memory, and the whole set re-seals and publishes
/// once — so K claimants move the scope root's record forward by one sequence,
/// not by K.
#[test]
fn a_conversion_pass_publishes_the_scope_root_once_for_every_claim_it_converts() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 3);
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert_eq!(
        sequence_at(&fx.world, &name),
        before + 1,
        "one re-seal and one publish carried every conversion"
    );
    let granted = fx.granted_to();
    for claimant in &claimants {
        assert!(
            granted.contains(claimant),
            "every claim of the pass became a personal grant"
        );
    }
    assert!(
        inbox(&fx.owner_device).is_empty(),
        "and every claim is acked, because the one publish landed"
    );
}

/// A claimant that claims twice before the owner presses convert puts two items
/// carrying one claim id in one pass. The pass converts against the records it
/// has already made in memory, so the second item mints no second spent record
/// and no second grant.
#[test]
fn one_claim_delivered_twice_in_one_pass_is_recorded_once() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    let invitee =
        EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
    let owner = import_contact(&opened.owner_contact_code).expect("the owner bundle verifies");
    let claim = InviteClaim {
        claim_id: [0x33; CLAIM_ID_LEN],
        scope_root_name: opened.scope_root_name.clone(),
        contact_code: contact_code(&RECIPIENT_SECRET),
    };
    fx.post_claim(&owner, &invitee, 0, &claim, "twice-a");
    fx.post_claim(&owner, &invitee, 1, &claim, "twice-b");
    assert_eq!(inbox(&fx.owner_device).len(), 2);
    let before = sequence_at(&fx.world, &write_name(fx.folder));

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert_eq!(
        recorded_claims(&fx.owner_device).len(),
        1,
        "one claim id spends one record, whatever the transport delivered"
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(fx.folder)),
        before + 1,
        "and the pass publishes once"
    );
    assert!(inbox(&fx.owner_device).is_empty());
}

/// Ack-after-durable, at the batch scale: nothing this pass converted reached
/// the record plane, so no claim may be acked and no spent record may become
/// durable. Every item redelivers, and the next press converts them all.
#[test]
fn a_conversion_pass_that_cannot_publish_acks_no_claim() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 3);
    let name = write_name(fx.folder);
    let committed = fx.granted_to();
    fx.world.record_store.fail_put_for(name.as_str());

    assert!(
        fx.convert().is_err(),
        "a publish nothing accepted is reported, never swallowed"
    );

    assert_eq!(inbox(&fx.owner_device).len(), 3, "no claim is acked");
    assert_eq!(
        fx.granted_to(),
        committed,
        "and no grant reached the record plane"
    );

    fx.world.record_store.heal_put_for(name.as_str());
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let granted = fx.granted_to();
    for claimant in &claimants {
        assert!(
            granted.contains(claimant),
            "the next press converts every claim the failed one left"
        );
    }
}

/// Ack-after-durable per item, after the one publish: a spent-record write that
/// fails leaves its claim un-acked, so the next press converts it again. That
/// re-conversion changes a set the record plane already carries, so it
/// publishes nothing more.
#[test]
fn a_record_write_that_fails_after_the_publish_leaves_its_claim_convertible() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 2);
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);
    fx.owner_device
        .staging_store
        .interrupt_staged_write_after(&invite_staging_key(&fx.owner_device), 0);

    assert!(
        fx.convert().is_err(),
        "the pass reports the record write it could not make durable"
    );

    assert_eq!(
        sequence_at(&fx.world, &name),
        before + 1,
        "the one publish still landed"
    );
    assert_eq!(
        inbox(&fx.owner_device).len(),
        1,
        "only the claim whose record failed is left to redeliver"
    );

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_eq!(
        sequence_at(&fx.world, &name),
        before + 1,
        "the re-conversion grants nothing new, so it republishes nothing"
    );
    assert!(inbox(&fx.owner_device).is_empty());
    let granted = fx.granted_to();
    for claimant in &claimants {
        assert!(
            granted.contains(claimant),
            "both claimants hold their grant"
        );
    }
}

/// A press past the API's per-account content throttle
/// (`apps/api/src/ops/throttling.ts`): a publish per claim would trip it
/// mid-pass and strand the rest. One publish for the whole pass cannot.
#[test]
fn a_pass_of_more_claims_than_the_content_throttle_admits_makes_one_publish() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 61);
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert_eq!(
        sequence_at(&fx.world, &name),
        before + 1,
        "one publish, whatever the claim count"
    );
    let granted = fx.granted_to();
    for claimant in &claimants {
        assert!(granted.contains(claimant));
    }
    assert!(inbox(&fx.owner_device).is_empty());
}

/// Revocation is the immediate-cut control, and `revoke` resolves its recipient
/// in the contact book alone. A grant an invite link produced is therefore only
/// real if the conversion recorded the claimant it granted.
#[test]
fn the_cut_of_a_converted_grant_returns_the_room_the_claim_took() {
    /// Whether the owner's book holds `identity_pk`, read the way a host does.
    fn book_holds(fx: &GrantScenario, identity_pk: &[u8]) -> bool {
        block_on(fx.engine.sharing(fx.folder))
            .expect("the sharing read")
            .contacts
            .iter()
            .any(|contact| contact.identity_public_key == identity_pk)
    }

    let mut fx = GrantScenario::new();
    let imported = recipient_identity().verifying_key().to_sec1().to_vec();
    let fragment = fx.mint_link();
    let claimant_device = fx.device_for(&BYSTANDER_SECRET);
    let claimant_pk = EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
        .expect("valid identity scalar")
        .verifying_key()
        .to_sec1()
        .to_vec();
    let (mut claimant, _claimant_events) = fx.bearer_on(&claimant_device, &BYSTANDER_SECRET, 33);
    block_on(claimant.command(Command::ClaimInviteLink { fragment })).expect("the claim posts");
    fx.convert().expect("the conversion lands");
    assert!(
        book_holds(&fx, &claimant_pk),
        "the conversion recorded the claimant so its grant can be cut"
    );

    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: claimant_pk.clone(),
        })),
        Ok(CommandOutcome::Done),
    );
    assert!(
        !book_holds(&fx, &claimant_pk),
        "the cut of its last converted grant returns the room the claim took"
    );
    assert!(
        book_holds(&fx, &imported),
        "and a contact the owner imported by hand is never dropped by a cut"
    );
}

/// A grant the owner issues records no scope on a claim-sourced entry, so the
/// collector must not take that entry out on the next cut: the claimant would
/// keep a live grant no revoke could name a recipient for. The owner grant is a
/// vouch, and it outranks whatever the claim wrote.
#[test]
fn a_cut_after_an_owner_grant_leaves_the_claimant_revokable() {
    let mut fx = GrantScenario::new();
    let other = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "second");
    let fragment = fx.mint_link();
    let claimant_device = fx.device_for(&BYSTANDER_SECRET);
    let claimant_pk = EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
        .expect("valid identity scalar")
        .verifying_key()
        .to_sec1()
        .to_vec();
    let (mut claimant, _claimant_events) = fx.bearer_on(&claimant_device, &BYSTANDER_SECRET, 35);
    block_on(claimant.command(Command::ClaimInviteLink { fragment })).expect("the claim posts");
    fx.convert().expect("the conversion lands");

    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: other,
            recipient_identity_public_key: claimant_pk.clone(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done),
        "the owner grants the claimant a second scope"
    );
    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: claimant_pk.clone(),
        })),
        Ok(CommandOutcome::Done),
    );
    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: other,
            recipient_identity_public_key: claimant_pk,
        })),
        Ok(CommandOutcome::Done),
        "the second grant is still cuttable, so the first cut kept the recipient"
    );
}

#[test]
fn a_converted_claim_records_the_claimant_so_its_grant_can_be_cut() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    // A claimant this owner has never imported: the invite path is the only
    // thing that puts them in the book.
    let claimant_device = fx.device_for(&BYSTANDER_SECRET);
    let claimant_pk = EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
        .expect("valid identity scalar")
        .verifying_key()
        .to_sec1()
        .to_vec();
    let (mut claimant, _claimant_events) = fx.bearer_on(&claimant_device, &BYSTANDER_SECRET, 31);
    block_on(claimant.command(Command::ClaimInviteLink { fragment })).expect("the claim posts");
    fx.convert().expect("the conversion lands");
    assert!(
        fx.granted_to().contains(&claimant_pk),
        "the conversion granted the claimant"
    );

    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: claimant_pk.clone(),
        })),
        Ok(CommandOutcome::Done),
        "a converted grantee resolves as a recipient"
    );
    assert!(
        !fx.granted_to().contains(&claimant_pk),
        "and the cut leaves no committed row behind"
    );
}

/// The book a conversion writes is durable, so the session that converted is
/// not the only one that can name the recipient it granted.
#[test]
fn a_converted_claimant_stays_in_the_book_for_the_next_session() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimant_device = fx.device_for(&BYSTANDER_SECRET);
    let claimant_pk = EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
        .expect("valid identity scalar")
        .verifying_key()
        .to_sec1()
        .to_vec();
    let (mut claimant, _claimant_events) = fx.bearer_on(&claimant_device, &BYSTANDER_SECRET, 32);
    block_on(claimant.command(Command::ClaimInviteLink { fragment })).expect("the claim posts");
    fx.convert().expect("the conversion lands");

    let (next, _next_events, _next_tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    assert!(
        block_on(next.sharing(next.root()))
            .expect("a sharing read")
            .contacts
            .into_iter()
            .any(|contact| contact.identity_public_key == claimant_pk),
        "the next session resolves the claimant a conversion recorded"
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

/// A write share publishes the grantee scope and names it in the parent index
/// before it runs the name wave that moves the scope onto the names the granted
/// seed derives. A cut that fails there leaves a scope the recipient was never
/// told about, at the name the parent's own write seed still derives. The same
/// share re-driven finishes that wave and delivers, rather than making the owner
/// revoke a grant nobody holds.
#[test]
fn a_write_share_whose_cut_failed_is_finished_by_the_same_share() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);
    let minted = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the grantee scope is live at the parent-derived name");
    assert_eq!(
        fx.committed_permission(&stalled),
        Some(CorePermission::Write),
        "the stalled scope commits the recipient's write row"
    );
    assert!(
        inbox(&fx.recipient_device).is_empty(),
        "and delivered nothing"
    );

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );

    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(moved, stalled, "the re-drive ran the owed wave");
    let resumed = published_grant_section_at(&fx.world, &fx.blocks, &moved)
        .expect("the moved root answers as a scope root");
    // A write cut leaves the read plane alone, so the seed the mint sealed is
    // the same one at the moved root — which is what separates a resume from a
    // second mint over a scope the grantee already holds a blob for.
    assert!(
        stranded_override_seed(&resumed, fx.folder) == stranded_override_seed(&minted, fx.folder),
        "against the scope the first attempt minted, not a second one"
    );
    assert_eq!(
        fx.granted_blob_carries_write_seed(&moved),
        Some(true),
        "the grantee's blob at the moved root conveys the granted write seed"
    );
    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        moved.as_str().as_bytes(),
        "and the pointer the share owed names the root the wave moved to"
    );
}

/// The re-drive is the unfinished share, never a further one. A share whose wave
/// ran has moved its scope off the name the parent's seed derives, so the index
/// no longer names it there and the standing refuses as before.
#[test]
fn a_second_write_share_of_a_finished_scope_is_still_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let moved = fx.granted_scope_repoint().current_root;

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Err(EngineError::UnsupportedTarget {
            check: "grant-target-already-names-a-scope"
        }),
    );
    assert_eq!(
        fx.granted_scope_repoint().current_root,
        moved,
        "and the scope stayed where its own wave left it"
    );
}

/// The pre-wave root lingers at the parent-derived name for ever, and the
/// write-epoch floor that refuses it is durable and **local**. A second owner
/// device that never saw the wave holds no such floor, so the parent index is
/// the only authority that separates an owed wave from a finished one.
#[test]
fn a_write_share_of_a_finished_scope_is_refused_on_a_device_that_missed_the_wave() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let moved = fx.granted_scope_repoint().current_root;

    let second = fx.world.device(b"the owner's second device");
    let (mut engine, _events, _tasks) = boot_owner(&fx.world, &fx.blocks, &second);
    import_recipient(&mut engine);

    assert_eq!(
        block_on(engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Write,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "grant-target-already-names-a-scope"
        }),
    );
    assert_eq!(
        fx.granted_scope_repoint().current_root,
        moved,
        "and the scope stayed where its own wave left it"
    );
}

/// A read share cuts no write scope, so its scope root sits at the
/// parent-derived name for good. Only the write row the stalled scope commits
/// says a wave is owed there — without that proof a write share over a read
/// grantee's live scope would re-key the scope they already hold.
#[test]
fn a_write_share_over_a_read_granted_scope_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Err(EngineError::UnsupportedTarget {
            check: "grant-target-already-names-a-scope"
        }),
    );
    assert_eq!(
        fx.committed_permission(&write_name(fx.folder)),
        Some(CorePermission::Read),
        "and the read grantee's row is untouched"
    );
}

/// The share that finishes a stalled one is the same share. A read share of a
/// folder whose stalled scope commits a **write** row is a different grant, and
/// finishing it would deliver a pointer naming a permission the scope's own
/// committed set contradicts.
#[test]
fn a_read_share_over_a_stalled_write_scope_is_refused() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);

    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::UnsupportedTarget {
            check: "grant-target-already-names-a-scope"
        }),
    );
    assert!(
        inbox(&fx.recipient_device).is_empty(),
        "so no pointer was delivered"
    );
    assert_eq!(
        fx.granted_scope_repoint().current_root,
        stalled,
        "and the owed wave is still owed"
    );
}

/// The row the stalled scope commits names one recipient. A share of that folder
/// to anyone else is a share of a scope whose committed set holds nothing for
/// them, which is refused rather than resumed.
#[test]
fn a_write_share_to_another_recipient_over_a_stalled_scope_is_refused() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);

    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second recipient's code imports");
    assert_eq!(
        block_on(
            fx.engine.command(Command::Grant {
                node: fx.folder,
                recipient_identity_public_key: EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
                    .expect("valid identity scalar")
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
                permission: Permission::Write,
            })
        ),
        Err(EngineError::UnsupportedTarget {
            check: "grant-target-already-names-a-scope"
        }),
    );
    assert_eq!(
        fx.granted_scope_repoint().current_root,
        stalled,
        "and the owed wave is still owed"
    );
}
