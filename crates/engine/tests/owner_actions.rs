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
    AadContext, AscentLink, GrantSection, GrantSetCommitment, Permission as CorePermission,
    PreservedFields, ReadBody, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, decode_envelope,
    decode_grant_section, grant_section_bytes, open_ascent_link, open_grant_blob, open_read_body,
    sign_grant_set,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;

use zeroize::Zeroizing;

use cipherbox_engine::gate::floor;
use cipherbox_engine::grants::{
    CLAIM_ID_LEN, EphemeralInvitee, GrantRow, InviteClaim, InviteFragment, InviteRecords,
    InviteStore, MintedInvite, RecordedInvite, StagingInviteStore, import_contact, mint_grant_row,
    mint_invite_grant, post_invite_claim, recipient_blinded_tag,
};
use cipherbox_engine::net::author::{
    ENVELOPE_V, EnvelopeAuthoring, author_child_envelope, author_scope_root_with_section,
};
use cipherbox_engine::rotation::{
    MAX_ROTATION_ATTEMPTS, derive_write_name, published_override_seed,
};
use cipherbox_engine::seams::{
    BoxedTask, FloorStore, Mailbox, RecordTransport, Scheduler, UnixMillis,
};
use cipherbox_engine::sync::SessionRole;
use cipherbox_engine::sync::pointer::{
    open_repoint, scope_pointer_name, seal_repoint, vault_pointer_name,
};
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
        self.grant_folder_at(Permission::Read)
    }

    fn grant_folder_at(&mut self, permission: Permission) -> Result<CommandOutcome, EngineError> {
        block_on(self.engine.command(Command::Grant {
            node: self.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission,
        }))
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

/// The parent's index is written last, so a mint that published the grantee
/// scope root and then failed leaves a live scope the index does not name. A
/// second share of that folder must refuse: republishing at the same derived
/// name under a fresh override seed would cut the first grantee off a scope
/// they still hold.
#[test]
fn a_second_share_of_a_folder_whose_scope_the_index_lost_is_refused() {
    let mut fx = GrantScenario::new();
    // The grantee root publishes first and the parent's index update fails, so
    // the scope goes live and nothing names it.
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    assert!(
        fx.grant_folder_to_recipient().is_err(),
        "the parent index update fails, so the mint reports the partial commit"
    );
    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());
    let stranded = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the grantee scope root is live at its derived name");

    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::UnsupportedTarget {
            check: "grant-target-already-names-a-scope"
        }),
        "the second share is refused against the name, not the index",
    );
    assert_eq!(
        published_grant_section(&fx.world, &fx.blocks, fx.folder)
            .expect("the stranded scope still answers")
            .commitment,
        stranded.commitment,
        "and the first grantee's scope is untouched"
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
        let name = seed_vault(
            &world,
            &blocks,
            vec![recipient_row_at_root(CorePermission::Read)],
        );
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

/// `scopeId` is authored by the sharer and bound to nothing outside its own
/// record, and every vault anchors its own root at the same id. A share that
/// names that anchor would have the recipient adopt a foreign record as its own
/// vault, so it is refused before the gate keys a durable floor on it. The
/// fixture's sharer grants at its own root, which is exactly that id.
#[test]
fn a_share_naming_this_vaults_own_root_scope_is_refused_and_poisons_no_floor() {
    let fx = ShareScenario::new();
    let (mut recipient, _events, sealed) = fx.recipient_engine();
    block_on(recipient.command(Command::ImportContact {
        contact_code: contact_code(&SECRET),
    }))
    .expect("the sharer's code imports");

    assert_eq!(
        block_on(recipient.command(Command::AcceptShare {
            sealed_share_pointer: sealed,
        })),
        Err(EngineError::TrustViolation {
            message: "the record names this vault's own root scope".to_owned(),
        }),
    );
    assert_eq!(
        inbox(&fx.recipient_device).len(),
        1,
        "a refused accept acks nothing"
    );
    assert_eq!(
        block_on(fx.recipient_device.floor_store.epoch_floor(&SCOPE)),
        Ok(None),
        "and the refusal lands before anything moves this vault's own floor"
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

/// Revocation is the immediate-cut control, and `revoke` resolves its recipient
/// in the contact book alone. A grant an invite link produced is therefore only
/// real if the conversion recorded the claimant it granted.
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
