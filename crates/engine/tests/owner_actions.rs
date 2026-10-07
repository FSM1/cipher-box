//! The owner-action command arms, joined end to end over the fake seam world:
//! a manual rotation cuts the read plane, a revoke drives the cascade that
//! actually ends a grant, a grant refuses fail-closed, and a second account's
//! engine accepts a share it was sent.
//!
//! Every assertion lands on published bytes, a durable floor, or the recipient's
//! inbox — what another device would see — never on a command's return alone.

use core::cell::RefCell;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::BTreeSet;

use cipherbox_core::hex::lower as hex_lower;
use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{
    AadContext, AscentLink, BinEntry, ChildRef, GrantLedgerEntry, GrantSection, GrantSetEntryKind,
    GranteeName, NameSource, NodeKind as CoreNodeKind, Permission as CorePermission,
    PreservedFields, ReadBody, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB,
    STRUCT_TAG_WRITE_BODY, STRUCT_TAG_WRITE_HISTORY_LINK, WriteBody, decode_envelope,
    decode_grant_section, decode_write_body, grant_section_bytes, open_ascent_link,
    open_grant_blob, open_owner_history_link, open_read_body, unseal,
};
use cipherbox_core::seal::{
    ChildScopeRef, SignedSealed, StructureSigInput, encode_envelope, encode_grant_section,
    encode_write_body, seal, set_grant_section, sign_structure,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::{EcdsaSigner, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::secret::ct_eq;
use cipherbox_engine::testkit::fakes::InMemoryRecordStore;

use zeroize::Zeroizing;

use cipherbox_core::content::encode_content_cid_str;
use cipherbox_engine::api::RetireEntry;
use cipherbox_engine::gate::{floor, record_cut_epoch_floor};
use cipherbox_engine::grants::conversion::{
    CONVERSION_RECORD_PREFIX, ConversionRecord, MAX_CONVERSION_ENTRIES, POINTER_RETRY_WINDOW,
    conversions_key, load_conversions, persist_conversions,
};
use cipherbox_engine::grants::{
    AckedClaim, CLAIM_ID_LEN, CLAIM_REPOST_FIRST_WAIT, CommittedLink, Contact, ContactStore,
    ContactStoreError, DEFAULT_ADMISSION_CAP, DEFAULT_LINK_LIFETIME, EphemeralInvitee, GrantRow,
    InviteClaim, InviteFragment, LinkHold, LinkTerms, MAX_ADMISSION_CAP, MAX_LINK_CONTACTS,
    ReceivedShareStore, ResolutionClass, StagingContactStore, StagingGranteeNameCache,
    StagingReceivedShareStore, import_contact, mint_grant_row, mint_invite_grant,
    post_invite_claim, recipient_blinded_tag, row_is_owner_attested,
};
use cipherbox_engine::net::RE_PUT_INTERVAL;
use cipherbox_engine::net::author::{ENVELOPE_V, EnvelopeAuthoring, author_child_envelope};
use cipherbox_engine::net::eol::eol_from;
use cipherbox_engine::rotation::{
    MAX_ROTATION_ATTEMPTS, derive_write_name, published_override_seed,
};
use cipherbox_engine::seams::{
    BoxedTask, ContactLabel, EndpointId, FloorStore, Mailbox, RecordTransport, Scheduler,
    SharerScopedFloorStore, SnapshotCache, StagingStore, UnixMillis,
};
use cipherbox_engine::settings::VaultSettings;
use cipherbox_engine::sync::kept_op::{KEPT_OP_BOUND, KEPT_OP_NOTES_PREFIX};
use cipherbox_engine::sync::op::{Op, OpKind, ScopeCrossing};
use cipherbox_engine::sync::owed_rotation::{
    DROP_BOUND, DROP_BOUND_PASSES, OWED_ROTATION_PREFIX, OwedEntry, OwedRecord, OwedStep,
    ROTATION_WORK_OWED, open_owed_record, owed_rotation_key, seal_owed_record,
};
use cipherbox_engine::sync::pointer::{open_repoint, scope_pointer_name};
use cipherbox_engine::sync::{
    BookkeepingSeal, MAX_QUARANTINE_ATTEMPTS, PUBLISHED_OP_MARK_PREFIX, doomed_journal_key,
    owner_scoped_key, owner_tag, scope_exit_debt_key, seal_owed_cuts,
};
use cipherbox_engine::testkit::account::{
    Blocks, EOL, POINTER_PAYLOAD_VERSION, ROOT, SCOPE, SECRET, TTL_NANOS, floor_label,
    owner_identity, owner_pointer_read_key, owner_pseudonym, retire_targets, seed_account_with,
    serve_http,
};
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH as EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    SeededEntropy, block_on, block_on_while_ticking, padding, poll_tasks_until_parked,
};
use cipherbox_engine::{
    ApiBaseUrl, BinIndexKeys, BinIndexLoad, Command, CommandOutcome, ContentProfile,
    DeadLetterReason, DropCause, Engine, EngineError, Event, EventStream, GatewayConfig,
    InvitePreview, LinkPreviewState, LoginSecret, NodeId, NodeKind, OwedWorkClass, Permission,
    PreviewEntry, PreviewNames, QueueHold, QueueHoldReason, RecordReader, ScopeEpochs,
    SessionBearer, SharePointer, SharingInviteLink, StoragePolicy, SyncTimingProfile, WriteTarget,
    decode_queue, load_bin_index, poll_verified, post_sealed,
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

/// Publish the account's initial state: an owner root at sequence 1 carrying
/// `grants` as its committed set, and the vault pointer naming it.
fn seed_vault(world: &FakeWorld, blocks: &Blocks, grants: Vec<GrantRow>) -> IpnsName {
    seed_account_with(world, blocks, grants, Vec::new())
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
    let cid = published_head_cid(world, name)?;
    Some(blocks.get(&cid).expect("the head block is on the plane"))
}

/// The head CID of the record currently published under `name`.
fn published_head_cid(world: &FakeWorld, name: &IpnsName) -> Option<String> {
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
    Some(cid.to_owned())
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

/// The second grantee's identity key.
fn bystander_identity() -> Vec<u8> {
    EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
        .expect("valid identity scalar")
        .verifying_key()
        .to_sec1()
        .to_vec()
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

/// A link entry over the vault root's scope. The committed row is the owner's
/// only record of the link.
fn invite_link_at_root(secret_byte: u8) -> GrantRow {
    expiring_invite_link_at_root(secret_byte, UnixMillis(u64::MAX))
}

/// [`invite_link_at_root`] under the deadline `deadline`.
fn expiring_invite_link_at_root(secret_byte: u8, deadline: UnixMillis) -> GrantRow {
    invite_link_under(secret_byte, deadline, &WRITE_SCOPE_SEED)
}

/// A link entry over the vault root's scope, at the root name
/// `write_scope_seed` derives.
fn invite_link_under(
    secret_byte: u8,
    deadline: UnixMillis,
    write_scope_seed: &[u8; 32],
) -> GrantRow {
    let invitee = EphemeralInvitee::from_secret(&[secret_byte; 32]).expect("a valid scalar");
    mint_invite_grant(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        &owner_pointer_read_key(),
        &invitee,
        &SCOPE,
        write_scope_seed,
        &LinkTerms {
            deadline,
            conversion_permission: CorePermission::Read,
            admission_cap: DEFAULT_ADMISSION_CAP,
        },
    )
    .expect("a contributory invitee key")
}

/// The link the ephemeral identity `secret_byte` derives holds, at `tag`, under
/// the terms [`invite_link_at_root`] mints.
fn committed_link_at(secret_byte: u8, tag: [u8; 32]) -> CommittedLink {
    let invitee = EphemeralInvitee::from_secret(&[secret_byte; 32]).expect("a valid scalar");
    link_of(&invitee, tag)
}

fn link_of(invitee: &EphemeralInvitee, tag: [u8; 32]) -> CommittedLink {
    CommittedLink {
        tag,
        ephemeral_identity_pk: invitee.identity_pk().to_sec1(),
        ephemeral_enc_pk: invitee.enc_public().to_bytes(),
        deadline: UnixMillis(u64::MAX),
        conversion_permission: CorePermission::Read,
        admission_cap: DEFAULT_ADMISSION_CAP,
    }
}

/// The committed link `fragment` minted, at the tag the sharing read lists it
/// under in `listed`.
fn minted_link(fragment: &str, listed: &SharingInviteLink) -> CommittedLink {
    let opened = InviteFragment::decode(fragment).expect("the mint's own fragment");
    let invitee =
        EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
    CommittedLink {
        deadline: listed.expires_at,
        conversion_permission: listed.permission.into(),
        admission_cap: listed.admission_cap,
        ..link_of(
            &invitee,
            <[u8; 32]>::try_from(listed.tag.as_slice()).expect("a 32-byte tag"),
        )
    }
}

/// The one share pointer waiting on `device`'s inbox, opened under the
/// recipient's own encryption subkey.
fn delivered_share_pointer(device: &FakeDevice) -> SharePointer {
    delivered_share_pointer_for(device, &RECIPIENT_SECRET)
}

/// The one share pointer waiting on `device`'s inbox, opened under the
/// encryption subkey `secret` derives.
fn delivered_share_pointer_for(device: &FakeDevice, secret: &[u8; 32]) -> SharePointer {
    let mut items = block_on(poll_verified(
        &device.mailbox,
        &kdf::enc_subkey(secret),
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
            grantee_name: None,
        }))
    }

    fn grant_named(
        &mut self,
        permission: Permission,
        name: &str,
    ) -> Result<CommandOutcome, EngineError> {
        block_on(self.engine.command(Command::Grant {
            node: self.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission,
            grantee_name: Some(name.to_owned()),
        }))
    }

    /// Import the second grantee and grant them the folder.
    fn grant_bystander(&mut self, permission: Permission) -> Result<CommandOutcome, EngineError> {
        block_on(self.engine.command(Command::ImportContact {
            contact_code: contact_code(&BYSTANDER_SECRET),
        }))
        .expect("the second recipient's code imports");
        block_on(self.engine.command(Command::Grant {
            node: self.folder,
            recipient_identity_public_key: bystander_identity(),
            permission,
            grantee_name: None,
        }))
    }

    /// Drive a grant whose parent index update fails, which is the state a
    /// mint leaves when the grantee root is live and no index names it.
    /// Returns that root's grant section.
    fn strand_the_grantee_scope(&mut self) -> GrantSection {
        self.world
            .record_store
            .fail_put_for(write_name(ROOT).as_str());
        assert_eq!(
            self.grant_folder_to_recipient(),
            Ok(CommandOutcome::Done),
            "the parent index update fails after the promotion, so the move is owed"
        );
        assert_eq!(self.owed_scopes(), vec![self.folder]);
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
    /// The mint's scope-root publish spends two reads of that scope's cut-epoch
    /// bar, the early refusal and the signature, so the cut's own resolve makes
    /// the next one — which is the read this fails.
    fn strand_the_owed_wave(&mut self) {
        self.with_a_failing_cut(|fx| {
            assert_eq!(
                fx.grant_folder_at(Permission::Write),
                Ok(CommandOutcome::Done),
                "the write-scope cut fails after the promotion, so it and the delivery are owed"
            );
        });
        assert_eq!(self.owed_scopes(), vec![self.folder]);
    }

    /// The scope roots the engine has reported owed rotation work at since the
    /// last read of the stream.
    fn owed_scopes(&mut self) -> Vec<NodeId> {
        owed_scopes(&mut self._events)
    }

    /// Grant the folder with the vault root's publish failing, so its
    /// interior move is owed, then heal that publish.
    fn stall_the_owed_move(&mut self) {
        let root = write_name(ROOT);
        self.world.record_store.fail_put_for(root.as_str());
        assert_eq!(self.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
        assert_eq!(
            self.owed_scopes(),
            vec![self.folder],
            "the interior move is owed"
        );
        self.world.record_store.heal_put_for(root.as_str());
    }

    /// Run `share` with this folder's cut-epoch bar unreadable past the two
    /// reads its scope-root publish makes, then heal it.
    fn with_a_failing_cut(&mut self, share: impl FnOnce(&mut Self)) {
        let mut cut_epoch_floor = self.folder.0.to_vec();
        cut_epoch_floor.extend_from_slice(b"/cut-epoch");
        self.owner_device
            .floor_store
            .fail_epoch_floor_reads_after(&floor_label(&cut_epoch_floor), 2);
        share(self);
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
                grantee_name: None,
            })),
            Ok(CommandOutcome::Done),
        );
        inner
    }

    /// A second device of the same owner, booted and ticked once, holding no
    /// contact book of its own.
    fn second_owner_device(&self) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
        let device = self.world.device(b"the owner's second device");
        let (engine, events, mut tasks) = boot_owner(&self.world, &self.blocks, &device);
        tick(&self.world, &engine, &mut tasks);
        (engine, events, tasks)
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
        let outcome = self.try_mint_link_at(permission).expect("the link mints");
        let CommandOutcome::InviteLinkMinted(link) = outcome else {
            panic!("minting a link answers with the link");
        };
        link.fragment
    }

    fn try_mint_link_at(&mut self, permission: Permission) -> Result<CommandOutcome, EngineError> {
        block_on(self.engine.command(Command::CreateInviteLink {
            node: self.folder,
            permission,
            expires_at: None,
            owner_name: "owner".to_owned(),
            admission_cap: None,
        }))
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
        block_on(engine.start(LoginSecret::new(secret.to_vec()), None))
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
        (0..count)
            .map(|i| {
                let index = u8::try_from(i).expect("the fixture stays under 256 claimants");
                self.post_claimant(fragment, index, index)
            })
            .collect()
    }

    /// Post the claim of throwaway claimant `index` under HPKE ephemeral
    /// `ephemeral`, and answer its identity key. The claim bytes turn on
    /// `index` alone, so a second call with a fresh `ephemeral` is a re-post.
    fn post_claimant(&self, fragment: &str, index: u8, ephemeral: u8) -> Vec<u8> {
        let opened = InviteFragment::decode(fragment).expect("the mint's own fragment");
        let invitee =
            EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
        let owner = import_contact(&opened.owner_contact_code).expect("the owner bundle verifies");
        let scalar = [CLAIMANT_SCALAR_BASE + index; 32];
        let mut claim_id = [1u8; CLAIM_ID_LEN];
        claim_id[0] = index;
        let claim = InviteClaim {
            claim_id,
            scope_pointer_name: opened.scope_pointer_name.clone(),
            contact_code: contact_code(&scalar),
            name: String::new(),
        };
        self.post_claim(
            &owner,
            &invitee,
            ephemeral,
            &claim,
            &format!("claim-{index}"),
        );
        EcdsaSigner::from_scalar(&scalar)
            .expect("valid identity scalar")
            .verifying_key()
            .to_sec1()
            .to_vec()
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
            &claim.encode().expect("the claim encodes"),
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
                grantee_name: None,
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
    assert_eq!(
        pointer.scope_pointer_name,
        Some(folder_pointer(&fx)),
        "and holds the scope pointer name it follows after a later cut"
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
        block_on(fx.engine.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: recipient.clone(),
            permission: Permission::Read,
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
        block_on(fx.engine.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
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
        block_on(engine.command(Command::ChangePermission {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
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
    let (mut engine, mut events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    alice
        .floor_store
        .fail_floor_raises_for(&floor_label(&write_epoch_floor_key(&SCOPE)));

    assert_eq!(
        block_on(engine.command(Command::ChangePermission {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done),
        "the cut set is published, so the floor it could not raise is owed"
    );
    assert_eq!(owed_scopes(&mut events), vec![ROOT], "and reported owed");
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

/// A `child` folder under the granted folder, holding a `grand` folder.
fn nested_subtree(fx: &mut GrantScenario) -> (NodeId, NodeId) {
    let child = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "child",
    );
    let grandchild =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, child, "grand");
    (child, grandchild)
}

/// A write grant over a folder holding `child`, which holds `grandchild`, and
/// the write scope seed the grant hands the recipient.
fn write_granted_nested_subtree(fx: &mut GrantScenario) -> (NodeId, NodeId, [u8; 32]) {
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let (child, grandchild) = nested_subtree(fx);
    let root = fx.granted_scope_repoint().current_root;
    let revokee_seed = grantee_write_scope_seed(&fx.folder_section(), &root, &fx.folder.0, 1);
    (child, grandchild, revokee_seed)
}

/// The granted scope's read override seed at `epoch`, off its current root.
fn granted_override_seed(fx: &GrantScenario, epoch: u64) -> Zeroizing<[u8; 32]> {
    published_override_seed(
        &kdf::enc_subkey(&SECRET),
        ENVELOPE_V,
        fx.folder.0,
        epoch,
        &fx.folder_section(),
    )
    .expect("the owner blob yields the scope's override seed")
}

/// The read cut runs first, so every interior node lags the root's new read
/// epoch when the write wave reads it. The wave reads each one through the
/// root's ratchet and moves it, so the revokee's seed names no live node.
#[test]
fn a_write_revoke_moves_a_nested_subtree_that_lags_the_read_cut() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );

    let after = fx.granted_scope_repoint();
    assert_ne!(
        derive_write_name(&revokee_seed, &fx.folder.0),
        after.current_root,
        "the revokee's seed no longer derives the root the pointer vouches for"
    );
    assert_eq!(after.write_epoch, 3, "the revoke stepped the write epoch");
    assert_eq!(after.min_read_epoch, 2, "after the read cut");
    let root_seed = granted_override_seed(&fx, 2);
    let child_name = published_child_name(
        &fx.world,
        &fx.blocks,
        &after.current_root,
        &read_key_under(&root_seed, fx.folder),
        "child",
    );
    assert_ne!(
        derive_write_name(&revokee_seed, &child.0),
        child_name,
        "the moved root names the child at a name the revokee's seed does not derive"
    );
    let grandchild_name = published_child_name(
        &fx.world,
        &fx.blocks,
        &child_name,
        &read_key_under(&root_seed, child),
        "grand",
    );
    assert_ne!(
        derive_write_name(&revokee_seed, &grandchild.0),
        grandchild_name,
        "and the moved child names the grandchild at a name it does not derive"
    );
    let head = published_head(&fx.world, &fx.blocks, &grandchild_name)
        .expect("the grandchild is live at its moved name");
    let envelope = decode_envelope(&head).expect("the head decodes");
    assert_eq!(
        envelope.epoch, 2,
        "re-sealed forward at the root's read epoch"
    );
    assert!(
        open_read_body(&envelope, &read_key_under(&root_seed, grandchild)).is_ok(),
        "under the read key of that epoch"
    );
}

fn raw_queue(device: &FakeDevice) -> usize {
    block_on(device.staging_store.queued_ops())
        .expect("the queue reads")
        .len()
}

/// A published op stays queued at its write epoch, and leaves once it waited
/// out the bound with no new write epoch (ADR 0069 D5).
#[test]
fn a_kept_op_leaves_the_queue_once_it_waits_out_the_bound() {
    let mut fx = GrantScenario::new();
    let before = raw_queue(&fx.owner_device);
    create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "kept");
    assert_eq!(queued_ops(&fx.owner_device), 0, "the op published");
    assert_eq!(
        raw_queue(&fx.owner_device),
        before + 1,
        "and stays queued as a kept op"
    );
    let cadence = fx.engine.profile().poll_cadence;

    fx.world
        .scheduler
        .advance(KEPT_OP_BOUND.saturating_sub(cadence * 3));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        raw_queue(&fx.owner_device),
        before + 1,
        "inside the bound it waits"
    );

    fx.world.scheduler.advance(cadence * 3);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        raw_queue(&fx.owner_device),
        0,
        "past the bound it leaves, as the ops the scenario kept do"
    );
}

/// A kept op with no note, as an op a store lost the note of, gets one check
/// against the live tree, and an op the tree shows leaves (ADR 0069 D6).
#[test]
fn a_kept_op_with_no_note_leaves_once_the_live_tree_shows_it() {
    let mut fx = GrantScenario::new();
    let before = raw_queue(&fx.owner_device);
    create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "kept");
    assert_eq!(raw_queue(&fx.owner_device), before + 1, "the op is kept");
    let notes = owner_scoped_key(KEPT_OP_NOTES_PREFIX, &kdf::enc_subkey(&SECRET));
    assert!(
        block_on(fx.owner_device.staging_store.staged_bytes(&notes))
            .expect("the store reads")
            .is_some(),
        "with its note"
    );
    block_on(fx.owner_device.staging_store.remove_staged_bytes(&notes)).expect("the note goes");

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        raw_queue(&fx.owner_device),
        0,
        "the op left, as the ops the scenario kept do"
    );
    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert!(
        status.dead_letters.is_empty(),
        "as landed, not as a dead letter"
    );
}

/// The read epoch of the record at `name`, and the granted scope's read
/// override seed at that epoch.
fn granted_seed_at(fx: &GrantScenario, name: &IpnsName) -> Zeroizing<[u8; 32]> {
    let head = published_head(&fx.world, &fx.blocks, name).expect("a published record");
    let epoch = decode_envelope(&head).expect("the head decodes").epoch;
    granted_override_seed(fx, epoch)
}

/// A write lands in the old tree after the name wave read it. The wave moves
/// the old record, so the moved tree does not name the write. The writer keeps
/// the op, sees the new write epoch on its next pass, and applies the op again
/// under the new seed (ADR 0069 D1 to D3).
#[test]
fn a_write_the_name_wave_did_not_carry_applies_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let root = fx.granted_scope_repoint().current_root;
    let mut late = None;

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name], |fx| {
        late = Some(create_published_folder(
            &fx.world,
            &mut fx.engine,
            &mut fx._tasks,
            child,
            "late",
        ));
    });
    let late = late.expect("the write ran");
    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(moved, root, "the wave moved the scope");

    passes_after_the_flip(&mut fx);

    let seed = granted_seed_at(&fx, &moved);
    let moved_child = published_child_name(
        &fx.world,
        &fx.blocks,
        &moved,
        &read_key_under(&seed, fx.folder),
        "child",
    );
    let late_name = published_child_name(
        &fx.world,
        &fx.blocks,
        &moved_child,
        &read_key_under(&seed, child),
        "late",
    );
    let head = published_head(&fx.world, &fx.blocks, &late_name)
        .expect("the write is live in the moved tree");
    let envelope = decode_envelope(&head).expect("the head decodes");
    assert!(
        open_read_body(&envelope, &read_key_under(&seed, late)).is_ok(),
        "and it opens there"
    );
}

/// A second apply whose publish loses a tie once is charged and tried again,
/// so the write still lands in the moved tree (ADR 0069 D3).
#[test]
fn a_second_apply_that_loses_a_tie_once_lands_on_a_later_pass() {
    let mut fx = GrantScenario::new();
    let survivor = second_apply_under_a_survivor(&mut fx);
    let SurvivorApply {
        child,
        late,
        ref moved_child,
        ..
    } = survivor;
    let cid = published_head_cid(&fx.world, moved_child).expect("the moved parent has a record");
    let sibling = survivor.record(
        format!("/ipfs/{cid}").as_bytes(),
        sequence_at(&fx.world, moved_child) + 1,
    );
    // The survivor's record lands at the second apply's own sequence just
    // after its PUT, so the confirm reads a tie it lost.
    fx.world.record_store.seed_record_after_put(
        moved_child.as_str(),
        moved_child.as_str(),
        sibling,
    );

    passes_after_the_flip(&mut fx);
    passes_after_the_flip(&mut fx);

    assert!(
        live_names(&fx, moved_child, child).contains(&"late".to_owned()),
        "the write landed in the moved tree"
    );
    assert!(
        queued_targets(&fx.owner_device).contains(&late),
        "and stays kept at the new write epoch"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// What [`second_apply_under_a_survivor`] set up.
struct SurvivorApply {
    child: NodeId,
    /// The create's node.
    late: NodeId,
    /// The surviving grantee's new write scope seed.
    survivor_seed: [u8; 32],
    /// The moved child's name.
    moved_child: IpnsName,
}

impl SurvivorApply {
    /// A record at the moved child's name, signed by the surviving grantee.
    fn record(&self, value: &[u8], sequence: u64) -> Vec<u8> {
        IpnsRecord::create_v2(
            &kdf::ipns_keypair(kdf::write_seed(&self.survivor_seed, &self.child.0).as_bytes()),
            value,
            sequence,
            TTL_NANOS,
            EOL,
        )
        .marshal()
    }
}

/// A write-granted child, a second write grantee, and a create in the child
/// that the cut of that second grantee does not carry.
fn second_apply_under_a_survivor(fx: &mut GrantScenario) -> SurvivorApply {
    second_apply_of(fx, "late", |fx, child| {
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, child, "late")
    })
}

/// [`second_apply_under_a_survivor`], with `write` the create of `name` in the
/// child, which returns the created node.
fn second_apply_of(
    fx: &mut GrantScenario,
    name: &str,
    write: impl FnOnce(&mut GrantScenario, NodeId) -> NodeId,
) -> SurvivorApply {
    let (child, _) = write_granted_child(fx);
    assert_eq!(
        fx.grant_bystander(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (root, _) = live_scope(fx);
    let child_name = live_child(fx, &root, fx.folder, "child");
    let mut late = None;
    cut_by_demoting_after_a_write_the_walk_misses(
        fx,
        &[&child_name],
        |fx| late = Some(write(fx, child)),
        bystander_identity(),
    );
    let late = late.expect("the write ran");
    let moved = fx.granted_scope_repoint().current_root;
    let survivor_seed = survivor_write_seed(fx);
    let moved_child = live_child(fx, &moved, fx.folder, "child");
    assert_eq!(derive_write_name(&survivor_seed, &child.0), moved_child);
    assert!(
        !live_names(fx, &moved_child, child).contains(&name.to_owned()),
        "the moved tree does not carry the create"
    );
    let _ = dead_letter_events(&mut fx._events);
    SurvivorApply {
        child,
        late,
        survivor_seed,
        moved_child,
    }
}

/// A surviving write grantee plants a record the gate refuses at the moved
/// parent's name. The second apply cannot land, so it dead-letters with a
/// notice at the budget, and the member can still name it.
#[test]
fn a_second_apply_under_a_refused_parent_dead_letters_with_a_notice() {
    let mut fx = GrantScenario::new();
    let survivor = second_apply_under_a_survivor(&mut fx);
    let SurvivorApply {
        late,
        ref moved_child,
        ..
    } = survivor;
    let epoch = decode_envelope(
        &published_head(&fx.world, &fx.blocks, moved_child).expect("the moved parent"),
    )
    .expect("the head decodes")
    .epoch;
    let planted = author_child_envelope(EnvelopeAuthoring {
        node_id: [0xee; 16],
        scope_id: fx.folder.0,
        epoch,
        read_key: &[0x13; 32],
        nonce: &[0x5e; 24],
        body: &folder_body(Vec::new()),
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the planted record seals");
    fx.blocks.put(planted.block.clone());
    let refused = survivor.record(
        format!("/ipfs/{}", planted.cid).as_bytes(),
        sequence_at(&fx.world, moved_child) + 2,
    );
    // The plant lands once the second apply has put the create's own record,
    // so the pass reads the moved parent first and then meets the plant.
    fx.world.record_store.seed_record_after_put(
        derive_write_name(&survivor.survivor_seed, &late.0).as_str(),
        moved_child.as_str(),
        refused,
    );

    for _ in 0..12 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert!(
        !queued_targets(&fx.owner_device).contains(&late),
        "the op left the queue"
    );
    assert_eq!(
        dead_letter_events(&mut fx._events).len(),
        1,
        "with a notice"
    );
    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert_eq!(
        status
            .dead_letters
            .iter()
            .map(|dead| dead.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted],
        "and the member can name it"
    );
}

/// The cut of a second write grantee misses this device's create, and the
/// surviving grantee then plants a record the gate refuses at the moved scope
/// root. This device restarts, sees the cut on the pointer, and cannot prove
/// the root; the clock then moves past the kept-op bound. Returns the fixture
/// and the moved root's honest record.
fn kept_create_past_the_bound_under_a_refused_moved_root(
    fx: &mut GrantScenario,
) -> (SurvivorApply, Vec<u8>) {
    let survivor = second_apply_of(fx, "late.bin", |fx, child| {
        write_version(
            fx,
            WriteTarget::NewFile {
                parent: child,
                name: "late.bin".into(),
            },
            &[7u8; 96],
        );
        block_on(fx.engine.view())
            .expect("a rendered view")
            .children(child)
            .into_iter()
            .find(|row| row.name == "late.bin")
            .expect("the file is listed")
            .id
    });
    let moved = fx.granted_scope_repoint().current_root;
    let honest = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], moved.as_str())
        .expect("the moved root has a record");
    assert_eq!(
        plant_root_at(
            fx,
            &survivor.survivor_seed,
            sequence_at(&fx.world, &moved) + 1
        ),
        moved
    );
    restart_owner(fx);
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    fx.world.scheduler.advance(KEPT_OP_BOUND);
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    (survivor, honest)
}

/// A cut this device has seen is a flip, so a kept op under a moved root the
/// walk cannot prove waits past the bound rather than leave unseen
/// (ADR 0069 D5).
#[test]
fn a_kept_op_under_a_refused_moved_root_waits_past_the_bound() {
    let mut fx = GrantScenario::new();
    let (survivor, _) = kept_create_past_the_bound_under_a_refused_moved_root(&mut fx);

    let held = queued_mine(&fx.owner_device)
        .into_iter()
        .find(|op| op.target == survivor.late)
        .expect("the op is still queued");
    let root_cid = held
        .staged_content()
        .expect("the create stages a version")
        .root_cid
        .clone();
    assert!(
        block_on(fx.owner_device.staging_store.staged_bytes(&root_cid))
            .expect("the store reads")
            .is_some(),
        "its staged version is still held"
    );
    assert!(
        dead_letter_events(&mut fx._events).is_empty(),
        "with no notice"
    );
}

/// Once the walk proves the moved root again, the kept op applies again and
/// the write lands in the moved tree (ADR 0069 D3).
#[test]
fn a_kept_op_under_a_moved_root_applies_again_once_the_walk_proves_it() {
    let mut fx = GrantScenario::new();
    let (survivor, honest) = kept_create_past_the_bound_under_a_refused_moved_root(&mut fx);
    let moved = fx.granted_scope_repoint().current_root;
    let value = IpnsRecord::unmarshal(&honest)
        .and_then(|record| record.verify(&moved))
        .expect("the honest root verifies")
        .value;
    let healed = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(&survivor.survivor_seed, &fx.folder.0).as_bytes()),
        &value,
        sequence_at(&fx.world, &moved) + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, moved.as_str(), healed.clone());
    }

    passes_after_the_flip(&mut fx);

    assert!(
        live_names(&fx, &survivor.moved_child, survivor.child).contains(&"late.bin".to_owned()),
        "the write landed in the moved tree"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// The surviving write grantee's write scope seed at the granted scope's
/// live root.
fn survivor_write_seed(fx: &GrantScenario) -> [u8; 32] {
    let moved = fx.granted_scope_repoint().current_root;
    let head = published_head(&fx.world, &fx.blocks, &moved).expect("the moved root");
    let epoch = decode_envelope(&head).expect("the head decodes").epoch;
    grantee_write_scope_seed(&fx.folder_section(), &moved, &fx.folder.0, epoch)
}

/// A kept file create whose second apply meets a refused parent dead-letters
/// with a notice, and its version survives a restart: recovered once the
/// parent reads again, it publishes the same bytes.
#[test]
fn a_kept_file_create_under_a_refused_parent_keeps_its_bytes_across_a_restart() {
    let mut fx = GrantScenario::new();
    let (child, _) = write_granted_child(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (root, _) = live_scope(&fx);
    let child_name = live_child(&fx, &root, fx.folder, "child");
    let bytes = vec![7u8; 96];
    cut_by_demoting_after_a_write_the_walk_misses(
        &mut fx,
        &[&child_name],
        |fx| {
            write_version(
                fx,
                WriteTarget::NewFile {
                    parent: child,
                    name: "late.bin".into(),
                },
                &bytes,
            );
        },
        bystander_identity(),
    );
    let late = block_on(fx.engine.view())
        .expect("a rendered view")
        .children(child)
        .into_iter()
        .find(|row| row.name == "late.bin")
        .expect("the file is listed")
        .id;
    let survivor_seed = survivor_write_seed(&fx);
    let moved_child = derive_write_name(&survivor_seed, &child.0);
    let honest = published_head_cid(&fx.world, &moved_child).expect("the moved parent");
    let sequence = sequence_at(&fx.world, &moved_child);
    let signed = |value: &[u8], sequence| {
        IpnsRecord::create_v2(
            &kdf::ipns_keypair(kdf::write_seed(&survivor_seed, &child.0).as_bytes()),
            value,
            sequence,
            TTL_NANOS,
            EOL,
        )
        .marshal()
    };
    let planted = author_child_envelope(EnvelopeAuthoring {
        node_id: [0xee; 16],
        scope_id: fx.folder.0,
        epoch: 1,
        read_key: &[0x13; 32],
        nonce: &[0x5e; 24],
        body: &folder_body(Vec::new()),
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the planted record seals");
    fx.blocks.put(planted.block.clone());
    // The plant lands once the second apply has put the file's own record,
    // so the pass reads the moved parent first and then meets the plant.
    fx.world.record_store.seed_record_after_put(
        derive_write_name(&survivor_seed, &late.0).as_str(),
        moved_child.as_str(),
        signed(format!("/ipfs/{}", planted.cid).as_bytes(), sequence + 2),
    );
    let _ = dead_letter_events(&mut fx._events);

    for _ in 0..12 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(
        dead_letter_events(&mut fx._events).len(),
        1,
        "the create dead-letters with a notice"
    );

    restart_owner(&mut fx);
    let parked = block_on(fx.engine.status())
        .expect("the session status reads")
        .dead_letters;
    assert_eq!(parked.len(), 1, "the restart still names it");
    let healed = signed(format!("/ipfs/{honest}").as_bytes(), sequence + 3);
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, moved_child.as_str(), healed.clone());
    }
    passes_after_the_flip(&mut fx);
    block_on(fx.engine.command(Command::RecoverDeadLetter {
        op_id: parked[0].op_id,
    }))
    .expect("the parked version re-queues");
    passes_after_the_flip(&mut fx);

    let recovered = block_on(fx.engine.view())
        .expect("a rendered view")
        .children(child)
        .into_iter()
        .find(|row| row.name == "late.bin")
        .expect("the recovered file is listed")
        .id;
    assert!(
        block_on(fx.engine.read_content(recovered)).expect("the file reads") == bytes,
        "the preserved version publishes the create's bytes"
    );
}

/// A kept edit whose head read meets a record the gate refuses at the moved
/// file's name is charged, so it dead-letters with a notice at the budget and
/// the op behind it publishes. A later edit does not end an earlier one, so
/// each of the two kept edits dead-letters on its own.
#[test]
fn a_kept_edit_under_a_refused_file_record_dead_letters_and_frees_the_queue() {
    let mut fx = GrantScenario::new();
    let (child, _) = write_granted_child(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let doc = published_file(&mut fx, child, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    let (root, _) = live_scope(&fx);
    let doc_name = live_child(
        &fx,
        &live_child(&fx, &root, fx.folder, "child"),
        child,
        "doc.bin",
    );
    cut_by_demoting_after_a_write_the_walk_misses(
        &mut fx,
        &[&doc_name],
        |fx| publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[2u8; 64]),
        bystander_identity(),
    );
    let survivor_seed = survivor_write_seed(&fx);
    let moved_doc = derive_write_name(&survivor_seed, &doc.0);
    let planted = author_child_envelope(EnvelopeAuthoring {
        node_id: [0xee; 16],
        scope_id: fx.folder.0,
        epoch: 1,
        read_key: &[0x13; 32],
        nonce: &[0x5e; 24],
        body: &folder_body(Vec::new()),
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the planted record seals");
    fx.blocks.put(planted.block.clone());
    let refused = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(&survivor_seed, &doc.0).as_bytes()),
        format!("/ipfs/{}", planted.cid).as_bytes(),
        sequence_at(&fx.world, &moved_doc) + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, moved_doc.as_str(), refused.clone());
    }
    let _ = dead_letter_events(&mut fx._events);

    for _ in 0..20 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(
        dead_letter_events(&mut fx._events).len(),
        2,
        "each kept edit dead-letters with a notice"
    );
    assert!(
        !queued_targets(&fx.owner_device).contains(&doc),
        "and leaves the queue"
    );

    block_on(fx.engine.command(Command::Create {
        parent: ROOT,
        name: "after the edit".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a later create queues");
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    published_child_name(
        &fx.world,
        &fx.blocks,
        &write_name(ROOT),
        &read_key_of(ROOT),
        "after the edit",
    );
}

/// Every op on this device's durable queue, kept ops included.
fn queued_mine(device: &FakeDevice) -> Vec<Op> {
    let raw = block_on(device.staging_store.queued_ops()).expect("the queue reads");
    let enc_subkey = kdf::enc_subkey(&SECRET);
    decode_queue(&RecordReader::new(&enc_subkey), &raw)
        .mine
        .into_iter()
        .map(|(_, op)| op)
        .collect()
}

/// The targets of every op on this device's durable queue, kept ops included.
fn queued_targets(device: &FakeDevice) -> Vec<NodeId> {
    queued_mine(device)
        .into_iter()
        .map(|op| op.target)
        .collect()
}

/// Write `bytes` as the next version of `node` on `engine`, and publish it.
fn publish_version(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    node: NodeId,
    bytes: &[u8],
) {
    let handle = block_on(engine.begin_write(
        WriteTarget::Version {
            node,
            expected_version: None,
        },
        bytes.len() as u64,
    ))
    .expect("a version write opens");
    block_on(engine.push_chunk(handle, bytes)).expect("the bytes stage");
    block_on(engine.commit_write(handle)).expect("the version commits");
    tick(world, engine, tasks);
}

/// A file in the granted folder, created and published on this device.
fn published_file_in_folder(fx: &mut GrantScenario, name: &str) -> NodeId {
    let folder = fx.folder;
    published_file(fx, folder, name)
}

/// A file under `parent`, created and published on this device.
fn published_file(fx: &mut GrantScenario, parent: NodeId, name: &str) -> NodeId {
    block_on(fx.engine.command(Command::Create {
        parent,
        name: name.into(),
        kind: NodeKind::File,
    }))
    .expect("a metadata create stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    block_on(fx.engine.view())
        .expect("a rendered view")
        .children(parent)
        .into_iter()
        .find(|child| child.name == name)
        .expect("the file is listed")
        .id
}

/// Demote the recipient to read on another owner device, which cuts the write
/// scope and runs the name wave.
fn cut_the_write_scope(fx: &GrantScenario, device: &mut Engine<FakeSeamTypes>) {
    demote(
        fx,
        device,
        recipient_identity().verifying_key().to_sec1().to_vec(),
    );
}

/// Demote the grantee `identity` names to read on `device`.
fn demote(fx: &GrantScenario, device: &mut Engine<FakeSeamTypes>, identity: Vec<u8>) {
    assert_eq!(
        block_on(device.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: identity,
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done)
    );
}

/// A kept edit whose node a later writer edited again cannot apply after the
/// flip. Its version landed, so it leaves with no notice and retires nothing.
#[test]
fn a_kept_edit_a_later_writer_overtook_leaves_quietly_after_the_flip() {
    let mut fx = GrantScenario::new();
    grant_write(&mut fx);
    let doc = published_file_in_folder(&mut fx, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    let (mut phone, _phone_events, mut phone_tasks) = phone_on(&fx, fx.folder);
    publish_version(&fx.world, &mut phone, &mut phone_tasks, doc, &[2u8; 64]);
    cut_the_write_scope(&fx, &mut phone);
    assert_eq!(
        block_on(fx.engine.read_content(doc)).expect("the head reads"),
        vec![2u8; 64],
        "this device reads the later version"
    );
    let retired_before = retired(&fx.owner_device).len();

    passes_after_the_flip(&mut fx);

    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert!(
        status.dead_letters.is_empty(),
        "no notice for a landed write"
    );
    assert_eq!(
        retired(&fx.owner_device).len(),
        retired_before,
        "and nothing retires"
    );
    assert!(
        !queued_targets(&fx.owner_device).contains(&doc),
        "the edit left the queue"
    );
    assert_eq!(
        block_on(fx.engine.read_content(doc)).expect("the head reads"),
        vec![2u8; 64],
        "and the later writer's version stays the head"
    );
}

/// A grant on a folder inside a write scope moves the nearest scope root of
/// the ops under it. That move is a flip: a kept op there gets its check
/// soon, not at the bound (ADR 0069 D5).
#[test]
fn a_kept_op_under_a_new_scope_root_gets_its_check_after_the_grant() {
    let mut fx = GrantScenario::new();
    grant_write(&mut fx);
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    let late = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, inner, "late");
    assert!(
        queued_targets(&fx.owner_device).contains(&late),
        "the create is kept"
    );

    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: inner,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );
    passes_after_the_flip(&mut fx);

    assert!(
        !queued_targets(&fx.owner_device).contains(&late),
        "the new scope root shows the create, so it left"
    );
    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert!(status.dead_letters.is_empty(), "as landed");
}

/// A version delete leaves the queue at its publish, so a flip after it
/// gives no notice and retires nothing again.
#[test]
fn a_version_delete_leaves_the_queue_at_publish() {
    let mut fx = GrantScenario::new();
    grant_write(&mut fx);
    let doc = published_file_in_folder(&mut fx, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[2u8; 64]);
    let prior = block_on(fx.engine.file_versions(doc))
        .expect("the list reads")
        .first()
        .expect("a prior version")
        .content_cid
        .clone();
    block_on(fx.engine.command(Command::DeleteVersion {
        node: doc,
        content_cid: prior,
    }))
    .expect("the delete queues");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.engine.file_versions(doc))
            .expect("the list reads")
            .is_empty(),
        "the delete landed"
    );
    let (mut phone, _phone_events, _phone_tasks) = fx.second_owner_device();
    cut_the_write_scope(&fx, &mut phone);
    let retired_before = retired(&fx.owner_device).len();

    passes_after_the_flip(&mut fx);

    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert!(
        status.dead_letters.is_empty(),
        "no notice for a landed delete"
    );
    assert_eq!(
        retired(&fx.owner_device).len(),
        retired_before,
        "and nothing retires again"
    );
    assert!(
        !queued_targets(&fx.owner_device).contains(&doc),
        "the delete left the queue"
    );
}

/// The ops this device holds on its durable queue for `node`, kept ops
/// included.
fn queued_ops_on(device: &FakeDevice, node: NodeId) -> Vec<OpKind> {
    queued_mine(device)
        .into_iter()
        .filter(|op| op.target == node)
        .map(|op| op.kind.clone())
        .collect()
}

/// The live root of the granted scope and the read seed its records seal
/// under.
fn live_scope(fx: &GrantScenario) -> (IpnsName, Zeroizing<[u8; 32]>) {
    let root = fx.granted_scope_repoint().current_root;
    let seed = granted_seed_at(fx, &root);
    (root, seed)
}

/// The body of the record at `name`, opened with the read key of `node`.
fn live_body(fx: &GrantScenario, name: &IpnsName, node: NodeId) -> ReadBody {
    let (_, seed) = live_scope(fx);
    published_seal(&fx.world, &fx.blocks, name, &read_key_under(&seed, node))
        .2
        .expect("the body opens")
}

/// The child names of the folder `node` at `name` in the live tree.
fn live_names(fx: &GrantScenario, name: &IpnsName, node: NodeId) -> Vec<String> {
    let (_, seed) = live_scope(fx);
    child_names_at(&fx.world, &fx.blocks, name, &read_key_under(&seed, node))
}

/// The content CIDs of the file `node` at `name` in the live tree, head
/// first.
fn live_versions(fx: &GrantScenario, name: &IpnsName, node: NodeId) -> Vec<Vec<u8>> {
    let ReadBody::File { versions, .. } = live_body(fx, name, node) else {
        panic!("expected a file body");
    };
    versions
        .into_iter()
        .map(|version| version.content_cid)
        .collect()
}

/// The name of `child` in the live folder `node` at `name`.
fn live_child(fx: &GrantScenario, name: &IpnsName, node: NodeId, child: &str) -> IpnsName {
    let (_, seed) = live_scope(fx);
    published_child_name(
        &fx.world,
        &fx.blocks,
        name,
        &read_key_under(&seed, node),
        child,
    )
}

/// Run `write` on this device, then cut the write scope on another owner
/// device while the walk reads each record in `held` from before the write.
/// The moved tree does not carry the write.
fn cut_after_a_write_the_walk_misses(
    fx: &mut GrantScenario,
    held: &[&IpnsName],
    write: impl FnOnce(&mut GrantScenario),
) {
    let demoted = recipient_identity().verifying_key().to_sec1().to_vec();
    cut_by_demoting_after_a_write_the_walk_misses(fx, held, write, demoted);
}

/// [`cut_after_a_write_the_walk_misses`], with the cut a demotion of the
/// grantee `demoted` names.
fn cut_by_demoting_after_a_write_the_walk_misses(
    fx: &mut GrantScenario,
    held: &[&IpnsName],
    write: impl FnOnce(&mut GrantScenario),
    demoted: Vec<u8>,
) {
    let endpoints = fx.world.record_store.endpoints();
    let walked: Vec<_> = held
        .iter()
        .map(|name| {
            fx.world
                .record_store
                .record_at(&endpoints[0], name.as_str())
        })
        .collect();
    let (mut phone, _phone_events, _phone_tasks) = fx.second_owner_device();
    write(fx);
    for (name, record) in held.iter().zip(walked) {
        fx.world
            .record_store
            .serve_gets_for_after(name.as_str(), 0, endpoints.len() * 8, record);
    }
    demote(fx, &mut phone, demoted);
    for name in held {
        fx.world
            .record_store
            .serve_gets_for_after(name.as_str(), 0, 0, None);
    }
}

/// Six passes of this device: the pointer consult is paced, so a flip shows a
/// few passes after the cut.
fn passes_after_the_flip(fx: &mut GrantScenario) {
    for _ in 0..6 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
}

/// Grant the recipient write on the scenario's folder.
fn grant_write(fx: &mut GrantScenario) {
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
}

/// A second owner device that has opened `folder`.
fn phone_on(
    fx: &GrantScenario,
    folder: NodeId,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    let (mut phone, events, mut tasks) = fx.second_owner_device();
    block_on(phone.command(Command::SetFocus { node: Some(folder) }))
        .expect("the phone opens the folder");
    tick(&fx.world, &phone, &mut tasks);
    (phone, events, tasks)
}

/// The live versions of `doc.bin` in the granted folder, head first.
fn live_doc_versions(fx: &GrantScenario, doc: NodeId) -> Vec<Vec<u8>> {
    let (root, _) = live_scope(fx);
    live_versions(fx, &live_child(fx, &root, fx.folder, "doc.bin"), doc)
}

/// A write-granted folder holding `child`, and `child`'s live name.
fn write_granted_child(fx: &mut GrantScenario) -> (NodeId, IpnsName) {
    grant_write(fx);
    let child = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "child",
    );
    let (root, _) = live_scope(fx);
    let child_name = live_child(fx, &root, fx.folder, "child");
    (child, child_name)
}

/// A delete that lands in the old tree after the walk is not in the moved
/// tree. The writer keeps the op and deletes the node again there.
#[test]
fn a_delete_the_name_wave_did_not_carry_applies_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let gone = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, child, "gone");
    let gone_name = live_child(&fx, &child_name, child, "gone");

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name, &gone_name], |fx| {
        block_on(fx.engine.command(Command::Delete { node: gone })).expect("the delete stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    assert!(
        live_names(&fx, &moved_child, child).contains(&"gone".to_owned()),
        "the moved tree does not carry the delete"
    );

    passes_after_the_flip(&mut fx);

    let moved_child = live_child(&fx, &root, fx.folder, "child");
    assert!(
        !live_names(&fx, &moved_child, child).contains(&"gone".to_owned()),
        "the delete applied again in the moved tree"
    );
}

/// A delete that this device publishes in the old tree after the walk, and
/// that the wave carries back, with no read of its folder at the folder's
/// live name before the bound. The base no longer holds the node, so the
/// delete waits past the bound for the drain's own read of that folder, and
/// then applies again (ADR 0069 D6).
fn carried_back_delete(fx: &mut GrantScenario) -> (NodeId, NodeId, IpnsName) {
    let (child, child_name) = write_granted_child(fx);
    let gone = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, child, "gone");
    let gone_name = live_child(fx, &child_name, child, "gone");
    cut_after_a_write_the_walk_misses(fx, &[&child_name, &gone_name], |fx| {
        block_on(fx.engine.command(Command::Delete { node: gone })).expect("the delete stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(fx);
    let moved_child = live_child(fx, &root, fx.folder, "child");
    assert!(
        live_names(fx, &moved_child, child).contains(&"gone".to_owned()),
        "the moved tree carries the node back"
    );
    (child, gone, moved_child)
}

#[test]
fn a_kept_delete_the_wave_carried_back_waits_past_the_bound_for_its_parent() {
    let mut fx = GrantScenario::new();
    let (child, gone, moved_child) = carried_back_delete(&mut fx);
    fx.world
        .record_store
        .serve_gets_for_after(moved_child.as_str(), 0, 10_000, None);

    passes_after_the_flip(&mut fx);
    fx.world.scheduler.advance(KEPT_OP_BOUND);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        queued_ops_on(&fx.owner_device, gone)
            .iter()
            .any(|kind| matches!(kind, OpKind::Delete { .. })),
        "the delete waits past the bound for the read of its folder"
    );

    fx.world
        .record_store
        .serve_gets_for_after(moved_child.as_str(), 0, 0, None);
    passes_after_the_flip(&mut fx);

    assert!(
        !live_names(&fx, &moved_child, child).contains(&"gone".to_owned()),
        "the read showed the node alive, and the delete applied again"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A kept delete that waits for the read of its folder keeps the folder in
/// its note across a restart, so the restarted session reaches the same
/// verdict: the read shows the node alive, and the delete applies again.
#[test]
fn a_kept_delete_that_waits_for_its_parent_keeps_its_note_across_a_restart() {
    let mut fx = GrantScenario::new();
    let (child, gone, moved_child) = carried_back_delete(&mut fx);
    fx.world
        .record_store
        .serve_gets_for_after(moved_child.as_str(), 0, 10_000, None);
    passes_after_the_flip(&mut fx);
    fx.world.scheduler.advance(KEPT_OP_BOUND);

    restart_owner(&mut fx);
    passes_after_the_flip(&mut fx);
    assert!(
        queued_ops_on(&fx.owner_device, gone)
            .iter()
            .any(|kind| matches!(kind, OpKind::Delete { .. })),
        "the restarted session holds the delete past the bound"
    );
    fx.world
        .record_store
        .serve_gets_for_after(moved_child.as_str(), 0, 0, None);
    passes_after_the_flip(&mut fx);

    assert!(
        !live_names(&fx, &moved_child, child).contains(&"gone".to_owned()),
        "the delete applied again"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A kept delete of X in /A/B/X under the granted root, published before a
/// cut, and a restart. No read of B at its live name answers until the
/// returned name is served again, so nothing shows that B is gone. Returns
/// B, X and B's live name.
fn deep_kept_delete_after_a_cut_and_a_restart(
    fx: &mut GrantScenario,
) -> (NodeId, NodeId, IpnsName) {
    let (a, _) = write_granted_child(fx);
    let b = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, a, "b");
    let x = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, b, "x");
    block_on(fx.engine.command(Command::Delete { node: x })).expect("the delete stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        queued_ops_on(&fx.owner_device, x)
            .iter()
            .any(|kind| matches!(kind, OpKind::Delete { .. })),
        "the delete is kept"
    );
    let (mut phone, _phone_events, _phone_tasks) = fx.second_owner_device();
    cut_the_write_scope(fx, &mut phone);
    let (root, _) = live_scope(fx);
    let a_name = live_child(fx, &root, fx.folder, "child");
    let b_name = live_child(fx, &a_name, a, "b");
    fx.world
        .record_store
        .serve_gets_for_after(b_name.as_str(), 0, 10_000, None);
    restart_owner(fx);
    (b, x, b_name)
}

/// With no read of B after the restart, nothing shows that B is gone, so
/// the delete does not leave before the bound.
#[test]
fn a_deep_kept_delete_does_not_leave_before_the_bound_with_no_read_of_its_folder() {
    let mut fx = GrantScenario::new();
    let (_, x, _) = deep_kept_delete_after_a_cut_and_a_restart(&mut fx);

    passes_after_the_flip(&mut fx);

    assert!(
        queued_ops_on(&fx.owner_device, x)
            .iter()
            .any(|kind| matches!(kind, OpKind::Delete { .. })),
        "the delete waits"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A pass that reads B at its live name after the restart shows X unlinked,
/// so the delete leaves at once, before the bound, with no notice.
#[test]
fn a_deep_kept_delete_leaves_after_a_read_of_its_folder_after_a_restart() {
    let mut fx = GrantScenario::new();
    let (b, x, b_name) = deep_kept_delete_after_a_cut_and_a_restart(&mut fx);
    passes_after_the_flip(&mut fx);
    assert!(
        !queued_ops_on(&fx.owner_device, x).is_empty(),
        "the delete waits for a read of its folder"
    );

    fx.world
        .record_store
        .serve_gets_for_after(b_name.as_str(), 0, 0, None);
    block_on(fx.engine.command(Command::SetFocus { node: Some(b) })).expect("the focus moves");
    passes_after_the_flip(&mut fx);

    assert!(
        queued_ops_on(&fx.owner_device, x).is_empty(),
        "the delete left before the bound"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// The wave copies /A/B/X. In its window, this device deletes X, and a peer
/// unlinks B at the name A has before the flip. This device reads A at that
/// name and sees B unlinked. After the flip, that read shows only the old
/// tree, so the delete stays, and it applies again in the new tree, which
/// still holds B and X (ADR 0069 D6).
#[test]
fn a_kept_delete_stays_when_its_folder_is_unlinked_only_in_the_old_tree() {
    let mut fx = GrantScenario::new();
    let (a, a_name) = write_granted_child(&mut fx);
    let b = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, a, "b");
    let x = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, b, "x");
    let b_name = live_child(&fx, &a_name, a, "b");
    let x_name = live_child(&fx, &b_name, b, "x");
    let peer_device = fx.world.device(b"the owner's third device");
    let (mut peer, _peer_events, mut peer_tasks) = boot_owner(&fx.world, &fx.blocks, &peer_device);
    tick(&fx.world, &peer, &mut peer_tasks);
    block_on(peer.command(Command::SetFocus { node: Some(b) })).expect("the peer opens B");
    tick(&fx.world, &peer, &mut peer_tasks);
    let endpoints = fx.world.record_store.endpoints();
    let held = [&a_name, &b_name, &x_name];
    let walked: Vec<_> = held
        .iter()
        .map(|name| {
            fx.world
                .record_store
                .record_at(&endpoints[0], name.as_str())
        })
        .collect();
    block_on(fx.engine.command(Command::SetFocus { node: Some(a) })).expect("the focus moves");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    block_on(fx.engine.command(Command::Delete { node: x })).expect("the delete stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    // The peer reads B after this device's unlink of X, so its unlink of B
    // does not lose to that edit.
    tick(&fx.world, &peer, &mut peer_tasks);
    block_on(peer.command(Command::Delete { node: b })).expect("the peer's unlink stages");
    for _ in 0..4 {
        tick(&fx.world, &peer, &mut peer_tasks);
    }
    // This device reads A at its name before the cut, and sees B unlinked.
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    for (name, record) in held.iter().zip(walked) {
        fx.world
            .record_store
            .serve_gets_for_after(name.as_str(), 0, endpoints.len() * 8, record);
    }
    // Another device cuts: the peer's own cache holds the B it unlinked.
    let (mut phone, _phone_events, _phone_tasks) = fx.second_owner_device();
    cut_the_write_scope(&fx, &mut phone);
    for name in held {
        fx.world
            .record_store
            .serve_gets_for_after(name.as_str(), 0, 0, None);
    }
    let (root, _) = live_scope(&fx);
    let moved_a = live_child(&fx, &root, fx.folder, "child");
    let moved_b = live_child(&fx, &moved_a, a, "b");
    assert!(
        live_names(&fx, &moved_b, b).contains(&"x".to_owned()),
        "the new tree holds B and X"
    );

    passes_after_the_flip(&mut fx);
    passes_after_the_flip(&mut fx);

    assert!(
        !live_names(&fx, &moved_b, b).contains(&"x".to_owned()),
        "the delete stayed and applied again in the new tree"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// After the flip, the folder of a kept delete reads at its live name as a
/// record the gate refuses. The refusal is a trust violation, never a sign
/// that the node is gone: the halt is charged to the delete, which
/// dead-letters with a notice at the budget.
#[test]
fn a_kept_delete_whose_parent_the_gate_refuses_is_charged_and_never_read_as_gone() {
    let mut fx = GrantScenario::new();
    let (child, _) = write_granted_child(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let gone = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, child, "gone");
    let (root, _) = live_scope(&fx);
    let child_name = live_child(&fx, &root, fx.folder, "child");
    let gone_name = live_child(&fx, &child_name, child, "gone");
    cut_by_demoting_after_a_write_the_walk_misses(
        &mut fx,
        &[&child_name, &gone_name],
        |fx| {
            block_on(fx.engine.command(Command::Delete { node: gone })).expect("the delete stages");
            tick(&fx.world, &fx.engine, &mut fx._tasks);
        },
        bystander_identity(),
    );
    let moved = fx.granted_scope_repoint().current_root;
    let moved_child = live_child(&fx, &moved, fx.folder, "child");
    assert!(
        live_names(&fx, &moved_child, child).contains(&"gone".to_owned()),
        "the moved tree carries the node back"
    );
    let epoch = decode_envelope(
        &published_head(&fx.world, &fx.blocks, &moved_child).expect("the moved parent"),
    )
    .expect("the head decodes")
    .epoch;
    let planted = author_child_envelope(EnvelopeAuthoring {
        node_id: [0xee; 16],
        scope_id: fx.folder.0,
        epoch,
        read_key: &[0x13; 32],
        nonce: &[0x5e; 24],
        body: &folder_body(Vec::new()),
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the planted record seals");
    fx.blocks.put(planted.block.clone());
    let survivor_seed = survivor_write_seed(&fx);
    let refused = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(&survivor_seed, &child.0).as_bytes()),
        format!("/ipfs/{}", planted.cid).as_bytes(),
        sequence_at(&fx.world, &moved_child) + 2,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, moved_child.as_str(), refused.clone());
    }
    let _ = events_so_far(&mut fx._events);

    passes_after_the_flip(&mut fx);

    assert!(
        !abuse_descriptions(&mut fx._events).is_empty(),
        "the read is a trust violation"
    );
    assert!(
        queued_ops_on(&fx.owner_device, gone)
            .iter()
            .any(|kind| matches!(kind, OpKind::Delete { .. })),
        "the delete is not read as gone"
    );
    for _ in 0..12 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert!(
        queued_ops_on(&fx.owner_device, gone).is_empty(),
        "the op left the queue"
    );
    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert_eq!(
        status
            .dead_letters
            .iter()
            .map(|dead| dead.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted],
        "with a notice the member can name"
    );
}

/// The folder of a kept delete is gone from the live tree: a later writer
/// deleted it after the cut. The node went with it, so after the flip the
/// delete leaves before the bound, with no second apply and no notice.
#[test]
fn a_kept_delete_whose_parent_a_later_writer_deleted_leaves_with_no_notice() {
    let mut fx = GrantScenario::new();
    let (child, gone, _) = carried_back_delete(&mut fx);
    let (mut phone, _phone_events, mut phone_tasks) = phone_on(&fx, fx.folder);
    block_on(phone.command(Command::Delete { node: child })).expect("the phone deletes");
    tick(&fx.world, &phone, &mut phone_tasks);
    let (root, _) = live_scope(&fx);
    assert!(
        !live_names(&fx, &root, fx.folder).contains(&"child".to_owned()),
        "the later writer's delete landed"
    );

    passes_after_the_flip(&mut fx);

    assert!(
        queued_ops_on(&fx.owner_device, gone).is_empty(),
        "the delete left before the bound"
    );
    assert!(
        !live_names(&fx, &root, fx.folder).contains(&"child".to_owned()),
        "and brought nothing back"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A delete that the wave carried shows in the moved tree, so it gets no
/// second apply. The drain reads the folder at its live name, sees the node
/// gone, and the op leaves with no notice before the bound (ADR 0069 D6).
#[test]
fn a_delete_the_name_wave_carried_gets_no_second_apply() {
    let mut fx = GrantScenario::new();
    let (child, _) = write_granted_child(&mut fx);
    let gone = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, child, "gone");
    block_on(fx.engine.command(Command::Delete { node: gone })).expect("the delete stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        queued_ops_on(&fx.owner_device, gone)
            .iter()
            .any(|kind| matches!(kind, OpKind::Delete { .. })),
        "the delete is kept"
    );
    let (mut phone, _phone_events, _phone_tasks) = fx.second_owner_device();
    cut_the_write_scope(&fx, &mut phone);
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    let endpoint = &fx.world.record_store.endpoints()[0];
    let carried = fx
        .world
        .record_store
        .record_at(endpoint, moved_child.as_str());

    passes_after_the_flip(&mut fx);

    assert_eq!(
        fx.world
            .record_store
            .record_at(endpoint, moved_child.as_str()),
        carried,
        "no second publish"
    );
    assert!(
        queued_ops_on(&fx.owner_device, gone).is_empty(),
        "the delete left after the read, before the bound"
    );
    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert!(status.dead_letters.is_empty(), "and no notice");
}

/// A content edit that lands in the old tree after the walk is not in the
/// moved tree. The writer keeps the op and writes the version again there.
#[test]
fn an_edit_the_name_wave_did_not_carry_applies_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    let doc_name = live_child(&fx, &child_name, child, "doc.bin");
    let before = live_versions(&fx, &doc_name, doc);

    cut_after_a_write_the_walk_misses(&mut fx, &[&doc_name], |fx| {
        publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[2u8; 64]);
    });
    let (root, _) = live_scope(&fx);
    let moved_doc = live_child(
        &fx,
        &live_child(&fx, &root, fx.folder, "child"),
        child,
        "doc.bin",
    );
    assert_eq!(
        live_versions(&fx, &moved_doc, doc),
        before,
        "the moved tree does not carry the edit"
    );

    passes_after_the_flip(&mut fx);

    let versions = live_versions(&fx, &moved_doc, doc);
    assert_eq!(versions.len(), before.len() + 1, "the edit applied again");
    assert_eq!(versions[1..], before[..], "on top of the carried history");
}

/// A rename stays a kept op after its publish. A later writer's rename then
/// stays after a flip: the check sees another name and the op leaves with no
/// apply.
#[test]
fn a_rename_stays_kept_and_a_later_rename_stays() {
    let mut fx = GrantScenario::new();
    let (child, _) = write_granted_child(&mut fx);
    block_on(fx.engine.command(Command::Rename {
        node: child,
        new_name: "mine".into(),
    }))
    .expect("the rename stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        queued_ops_on(&fx.owner_device, child)
            .iter()
            .any(|kind| matches!(kind, OpKind::Rename { .. })),
        "the rename stays queued as a kept op"
    );
    let (mut phone, _phone_events, mut phone_tasks) = fx.second_owner_device();
    block_on(phone.command(Command::Rename {
        node: child,
        new_name: "later".into(),
    }))
    .expect("the later rename stages");
    tick(&fx.world, &phone, &mut phone_tasks);
    cut_the_write_scope(&fx, &mut phone);
    let (root, _) = live_scope(&fx);
    let endpoint = &fx.world.record_store.endpoints()[0];
    let carried = fx.world.record_store.record_at(endpoint, root.as_str());

    passes_after_the_flip(&mut fx);

    assert_eq!(
        fx.world.record_store.record_at(endpoint, root.as_str()),
        carried,
        "no second publish"
    );
    assert!(
        live_names(&fx, &root, fx.folder).contains(&"later".to_owned()),
        "the later rename stays"
    );
    assert!(
        queued_ops_on(&fx.owner_device, child).is_empty(),
        "the rename left with no apply"
    );
}

/// A move inside one scope stays a kept op after its publish. A later
/// writer's move then stays after a flip.
#[test]
fn a_move_stays_kept_and_a_later_move_stays() {
    let mut fx = GrantScenario::new();
    let (child, _) = write_granted_child(&mut fx);
    let there = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "there",
    );
    let elsewhere = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "elsewhere",
    );
    let moved = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, child, "moved");
    block_on(fx.engine.command(Command::Move {
        node: moved,
        new_parent: there,
        new_name: "moved".into(),
        replacing: None,
    }))
    .expect("the move stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        queued_ops_on(&fx.owner_device, moved)
            .iter()
            .any(|kind| matches!(kind, OpKind::Move { .. })),
        "the move stays queued as a kept op"
    );
    let (mut phone, _phone_events, mut phone_tasks) = phone_on(&fx, there);
    block_on(phone.command(Command::Move {
        node: moved,
        new_parent: elsewhere,
        new_name: "moved".into(),
        replacing: None,
    }))
    .expect("the later move stages");
    tick(&fx.world, &phone, &mut phone_tasks);
    cut_the_write_scope(&fx, &mut phone);

    passes_after_the_flip(&mut fx);

    let (root, _) = live_scope(&fx);
    let live_elsewhere = live_child(&fx, &root, fx.folder, "elsewhere");
    assert!(
        live_names(&fx, &live_elsewhere, elsewhere).contains(&"moved".to_owned()),
        "the later move stays"
    );
    assert!(
        queued_ops_on(&fx.owner_device, moved).is_empty(),
        "the move left with no apply"
    );
}

/// A version restore stays a kept op after its publish. A later writer's
/// restore then stays after a flip.
#[test]
fn a_version_restore_stays_kept_and_a_later_restore_stays() {
    let mut fx = GrantScenario::new();
    grant_write(&mut fx);
    let doc = published_file_in_folder(&mut fx, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[2u8; 64]);
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[3u8; 64]);
    let history = live_doc_versions(&fx, doc);
    block_on(fx.engine.command(Command::RestoreVersion {
        node: doc,
        content_cid: history[1].clone(),
    }))
    .expect("the restore queues");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        queued_ops_on(&fx.owner_device, doc)
            .iter()
            .any(|kind| matches!(kind, OpKind::RestoreVersion { .. })),
        "the restore stays queued as a kept op"
    );
    let (mut phone, _phone_events, mut phone_tasks) = phone_on(&fx, fx.folder);
    block_on(phone.command(Command::RestoreVersion {
        node: doc,
        content_cid: history[2].clone(),
    }))
    .expect("the later restore queues");
    tick(&fx.world, &phone, &mut phone_tasks);
    cut_the_write_scope(&fx, &mut phone);

    passes_after_the_flip(&mut fx);

    let versions = live_doc_versions(&fx, doc);
    assert_eq!(versions[0], history[2], "the later restore stays");
    assert!(
        queued_ops_on(&fx.owner_device, doc).is_empty(),
        "the restore left with no apply"
    );
}

/// A rename that lands in the old tree after the walk is not in the moved
/// tree. The writer keeps the op and applies the rename again after the flip.
#[test]
fn a_rename_the_name_wave_did_not_carry_applies_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name], |fx| {
        block_on(fx.engine.command(Command::Rename {
            node: doc,
            new_name: "renamed.bin".into(),
        }))
        .expect("the rename stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    assert!(
        live_names(&fx, &moved_child, child).contains(&"doc.bin".to_owned()),
        "the moved tree does not carry the rename"
    );

    passes_after_the_flip(&mut fx);

    let names = live_names(&fx, &moved_child, child);
    assert!(
        names.contains(&"renamed.bin".to_owned()) && !names.contains(&"doc.bin".to_owned()),
        "the rename applied again"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A move that lands in the old tree after the walk is not in the moved tree.
/// The writer keeps the op and applies the move again after the flip.
#[test]
fn a_move_the_name_wave_did_not_carry_applies_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let there = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "there",
    );
    let doc = published_file(&mut fx, child, "doc.bin");
    let (root, _) = live_scope(&fx);
    let there_name = live_child(&fx, &root, fx.folder, "there");

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name, &there_name], |fx| {
        block_on(fx.engine.command(Command::Move {
            node: doc,
            new_parent: there,
            new_name: "doc.bin".into(),
            replacing: None,
        }))
        .expect("the move stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    let moved_there = live_child(&fx, &root, fx.folder, "there");
    assert!(
        live_names(&fx, &moved_child, child).contains(&"doc.bin".to_owned()),
        "the moved tree does not carry the move"
    );

    passes_after_the_flip(&mut fx);

    assert!(
        live_names(&fx, &moved_there, there).contains(&"doc.bin".to_owned()),
        "the move applied again"
    );
    assert!(
        !live_names(&fx, &moved_child, child).contains(&"doc.bin".to_owned()),
        "and the source no longer names the file"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A version restore that lands in the old tree after the walk is not in the
/// moved tree. The writer keeps the op and restores the version again after
/// the flip.
#[test]
fn a_version_restore_the_name_wave_did_not_carry_applies_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[2u8; 64]);
    let doc_name = live_child(&fx, &child_name, child, "doc.bin");
    let history = live_versions(&fx, &doc_name, doc);

    cut_after_a_write_the_walk_misses(&mut fx, &[&doc_name], |fx| {
        block_on(fx.engine.command(Command::RestoreVersion {
            node: doc,
            content_cid: history[1].clone(),
        }))
        .expect("the restore queues");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_doc = live_child(
        &fx,
        &live_child(&fx, &root, fx.folder, "child"),
        child,
        "doc.bin",
    );
    assert_eq!(
        live_versions(&fx, &moved_doc, doc)[0],
        history[0],
        "the moved tree does not carry the restore"
    );

    passes_after_the_flip(&mut fx);

    assert_eq!(
        live_versions(&fx, &moved_doc, doc)[0],
        history[1],
        "the restore applied again"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A create and a rename of the same node land in the old tree after the
/// walk. The rename does not end the create: the create makes the node again
/// and the rename applies again over it.
#[test]
fn a_create_then_a_rename_the_name_wave_did_not_carry_apply_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name], |fx| {
        let late = published_file(fx, child, "late.bin");
        block_on(fx.engine.command(Command::Rename {
            node: late,
            new_name: "renamed.bin".into(),
        }))
        .expect("the rename stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    assert!(
        live_names(&fx, &moved_child, child).is_empty(),
        "the moved tree does not carry the create"
    );

    passes_after_the_flip(&mut fx);

    assert_eq!(
        live_names(&fx, &moved_child, child),
        vec!["renamed.bin".to_owned()],
        "the node is live under the new name"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A kept restore applies again only over the head its check read. A head
/// that another writer publishes between that check and the publish stays.
#[test]
fn a_kept_restore_does_not_apply_over_a_head_published_after_its_check() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");
    for byte in 1u8..=3 {
        publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[byte; 64]);
    }
    let doc_name = live_child(&fx, &child_name, child, "doc.bin");
    let history = live_versions(&fx, &doc_name, doc);

    cut_after_a_write_the_walk_misses(&mut fx, &[&doc_name], |fx| {
        block_on(fx.engine.command(Command::RestoreVersion {
            node: doc,
            content_cid: history[1].clone(),
        }))
        .expect("the restore queues");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_doc = live_child(
        &fx,
        &live_child(&fx, &root, fx.folder, "child"),
        child,
        "doc.bin",
    );
    let endpoints = fx.world.record_store.endpoints();
    let checked = fx
        .world
        .record_store
        .record_at(&endpoints[0], moved_doc.as_str());
    let (mut phone, _phone_events, mut phone_tasks) = phone_on(&fx, child);
    block_on(phone.command(Command::RestoreVersion {
        node: doc,
        content_cid: history[2].clone(),
    }))
    .expect("the later restore queues");
    tick(&fx.world, &phone, &mut phone_tasks);
    assert_eq!(live_versions(&fx, &moved_doc, doc)[0], history[2]);
    // The check reads the head from before the later restore.
    fx.world
        .record_store
        .serve_gets_for_after(moved_doc.as_str(), 0, endpoints.len(), checked);

    passes_after_the_flip(&mut fx);

    assert_eq!(
        live_versions(&fx, &moved_doc, doc)[0],
        history[2],
        "the later restore stays"
    );
}

/// A rename and a delete of one node land in the old tree after the walk.
/// The delete decides the node, so it applies again with no replay of the
/// rename.
#[test]
fn a_rename_then_a_delete_the_name_wave_did_not_carry_applies_only_the_delete() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");
    let doc_name = live_child(&fx, &child_name, child, "doc.bin");

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name, &doc_name], |fx| {
        block_on(fx.engine.command(Command::Rename {
            node: doc,
            new_name: "renamed.bin".into(),
        }))
        .expect("the rename stages");
        block_on(fx.engine.command(Command::Delete { node: doc })).expect("the delete stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    assert_eq!(
        live_names(&fx, &moved_child, child),
        vec!["doc.bin".to_owned()],
        "the moved tree does not carry the rename or the delete"
    );
    let puts = fx.world.record_store.put_count(moved_child.as_str());

    passes_after_the_flip(&mut fx);

    assert!(
        live_names(&fx, &moved_child, child).is_empty(),
        "the delete applied again"
    );
    assert_eq!(
        fx.world.record_store.put_count(moved_child.as_str()) - puts,
        fx.world.record_store.endpoints().len(),
        "one publish of the folder: no replay of the rename"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A soft delete and a bin restore of one node land in the old tree after
/// the walk. The restore decides the node, so the delete does not apply
/// again and the file stays live.
#[test]
fn a_delete_then_a_bin_restore_the_name_wave_did_not_carry_leave_the_file_live() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name], |fx| {
        block_on(fx.engine.command(Command::Delete { node: doc })).expect("the delete stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        block_on(fx.engine.command(Command::Restore {
            node: doc,
            into: None,
        }))
        .expect("the restore stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");

    passes_after_the_flip(&mut fx);

    assert_eq!(
        live_names(&fx, &moved_child, child),
        vec!["doc.bin".to_owned()],
        "the file is live after the flip"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A create and a content edit of one node land in the old tree after the
/// walk. The edit does not end the create: the create makes the file again
/// and the edit writes its version on it.
#[test]
fn a_create_then_an_edit_the_name_wave_did_not_carry_apply_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);

    let mut edited = Vec::new();
    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name], |fx| {
        let late = published_file(fx, child, "late.bin");
        publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, late, &[7u8; 64]);
        let old_name = live_child(fx, &child_name, child, "late.bin");
        edited = live_versions(fx, &old_name, late);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    assert!(
        live_names(&fx, &moved_child, child).is_empty(),
        "the moved tree does not carry the create"
    );

    passes_after_the_flip(&mut fx);

    let late = block_on(fx.engine.view())
        .expect("a rendered view")
        .children(child)
        .into_iter()
        .find(|node| node.name == "late.bin")
        .expect("the file is listed")
        .id;
    let late_name = live_child(&fx, &moved_child, child, "late.bin");
    assert_eq!(
        live_versions(&fx, &late_name, late),
        edited,
        "the file is live with the edited content"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// Two content edits of one file land in the old tree after the walk. The
/// later edit does not end the earlier one: both apply again in order.
#[test]
fn an_edit_then_an_edit_the_name_wave_did_not_carry_apply_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    let doc_name = live_child(&fx, &child_name, child, "doc.bin");
    let before = live_versions(&fx, &doc_name, doc);

    let mut edited = Vec::new();
    cut_after_a_write_the_walk_misses(&mut fx, &[&doc_name], |fx| {
        publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[2u8; 64]);
        publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[3u8; 64]);
        edited = live_versions(fx, &doc_name, doc);
    });
    let (root, _) = live_scope(&fx);
    let moved_doc = live_child(
        &fx,
        &live_child(&fx, &root, fx.folder, "child"),
        child,
        "doc.bin",
    );
    assert_eq!(
        live_versions(&fx, &moved_doc, doc),
        before,
        "the moved tree does not carry the edits"
    );

    passes_after_the_flip(&mut fx);

    assert_eq!(
        live_versions(&fx, &moved_doc, doc),
        edited,
        "the file shows the last edit on top of the first"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A create, a soft delete and a bin restore of one file land in the old
/// tree after the walk. The restore cancels the delete, so the create applies
/// again and the file is live.
#[test]
fn a_create_a_delete_and_a_bin_restore_the_name_wave_did_not_carry_leave_the_file_live() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name], |fx| {
        let late = published_file(fx, child, "late.bin");
        block_on(fx.engine.command(Command::Delete { node: late })).expect("the delete stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        block_on(fx.engine.command(Command::Restore {
            node: late,
            into: None,
        }))
        .expect("the restore stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    assert!(
        live_names(&fx, &moved_child, child).is_empty(),
        "the moved tree does not carry the create"
    );

    passes_after_the_flip(&mut fx);

    assert_eq!(
        live_names(&fx, &moved_child, child),
        vec!["late.bin".to_owned()],
        "the file is live after the flip"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A version restore and then a content edit of one file land in the old
/// tree after the walk. Both apply again in order, so the file shows the
/// edit.
#[test]
fn a_version_restore_then_an_edit_the_name_wave_did_not_carry_apply_again_after_the_flip() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[2u8; 64]);
    let doc_name = live_child(&fx, &child_name, child, "doc.bin");
    let history = live_versions(&fx, &doc_name, doc);

    let mut edited = Vec::new();
    cut_after_a_write_the_walk_misses(&mut fx, &[&doc_name], |fx| {
        block_on(fx.engine.command(Command::RestoreVersion {
            node: doc,
            content_cid: history[1].clone(),
        }))
        .expect("the restore queues");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[3u8; 64]);
        edited = live_versions(fx, &doc_name, doc);
    });
    let (root, _) = live_scope(&fx);
    let moved_doc = live_child(
        &fx,
        &live_child(&fx, &root, fx.folder, "child"),
        child,
        "doc.bin",
    );
    assert_eq!(
        live_versions(&fx, &moved_doc, doc),
        history,
        "the moved tree does not carry the restore or the edit"
    );

    passes_after_the_flip(&mut fx);

    assert_eq!(
        live_versions(&fx, &moved_doc, doc)[0],
        edited[0],
        "the file shows the edit"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// A soft delete stops after its bin entry, and the user restores the file
/// from the bin. The retry of the delete and the restore publish in one pass,
/// so the delete becomes kept in that pass. The restore still cancels it
/// durably, across a restart: after the flip the file is live.
#[test]
fn a_bin_restore_cancels_a_delete_that_became_kept_in_the_same_pass() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");
    let doc_name = live_child(&fx, &child_name, child, "doc.bin");

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name, &doc_name], |fx| {
        fx.world.record_store.fail_put_for(child_name.as_str());
        block_on(fx.engine.command(Command::Delete { node: doc })).expect("the delete stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        assert!(
            queued_ops_on(&fx.owner_device, doc)
                .iter()
                .any(|kind| matches!(kind, OpKind::Delete { .. })),
            "the delete stopped before its publish"
        );
        block_on(fx.engine.command(Command::Restore {
            node: doc,
            into: None,
        }))
        .expect("the restore stages");
        fx.world.record_store.heal_put_for(child_name.as_str());
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");

    restart_owner(&mut fx);
    passes_after_the_flip(&mut fx);

    assert_eq!(
        live_names(&fx, &moved_child, child),
        vec!["doc.bin".to_owned()],
        "the file is live after the flip"
    );
    assert!(dead_letter_events(&mut fx._events).is_empty());
}

/// The residual over a chain: this device renames A to B and then to C, and
/// a later writer sets A again. A reads as the value before the chain, so the
/// whole chain applies again and C stays.
#[test]
fn a_later_rename_back_to_the_name_before_a_chain_applies_the_whole_chain_again() {
    let mut fx = GrantScenario::new();
    let (child, _) = write_granted_child(&mut fx);
    for name in ["b", "c"] {
        block_on(fx.engine.command(Command::Rename {
            node: child,
            new_name: name.into(),
        }))
        .expect("the rename stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let (mut phone, _phone_events, mut phone_tasks) = fx.second_owner_device();
    block_on(phone.command(Command::Rename {
        node: child,
        new_name: "child".into(),
    }))
    .expect("the later rename stages");
    tick(&fx.world, &phone, &mut phone_tasks);
    cut_the_write_scope(&fx, &mut phone);

    passes_after_the_flip(&mut fx);

    let (root, _) = live_scope(&fx);
    let names = live_names(&fx, &root, fx.folder);
    assert!(
        names.contains(&"c".to_owned()) && !names.contains(&"child".to_owned()),
        "the chain applied again over the later rename"
    );
}

/// The residual of ADR 0069 D2: a later writer who sets the name from before
/// a kept rename looks like a lost rename, so the rename applies again.
#[test]
fn a_later_rename_back_to_the_name_before_reads_as_lost_and_the_rename_applies_again() {
    let mut fx = GrantScenario::new();
    let (child, _) = write_granted_child(&mut fx);
    block_on(fx.engine.command(Command::Rename {
        node: child,
        new_name: "mine".into(),
    }))
    .expect("the rename stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (mut phone, _phone_events, mut phone_tasks) = fx.second_owner_device();
    block_on(phone.command(Command::Rename {
        node: child,
        new_name: "child".into(),
    }))
    .expect("the later rename stages");
    tick(&fx.world, &phone, &mut phone_tasks);
    cut_the_write_scope(&fx, &mut phone);

    passes_after_the_flip(&mut fx);

    let (root, _) = live_scope(&fx);
    let names = live_names(&fx, &root, fx.folder);
    assert!(
        names.contains(&"mine".to_owned()) && !names.contains(&"child".to_owned()),
        "the rename applied again over the later rename"
    );
}

/// A guard: a move out of a granted folder re-seals into another scope, so
/// it leaves the queue at its publish and is no kept op.
#[test]
fn a_move_out_of_its_scope_leaves_the_queue_at_publish() {
    let mut fx = GrantScenario::new();
    let one = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "one");
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, one);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    block_on(fx.engine.command(Command::Relink {
        node: one,
        new_parent: album,
    }))
    .expect("the move journals its crossing");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        queued_ops_on(&fx.owner_device, one).is_empty(),
        "the move left the queue at publish"
    );
}

/// A kept rename keeps its result in its note across a restart, so the
/// restarted session reaches the same verdict: the rename applies again.
#[test]
fn a_kept_rename_keeps_its_result_across_a_restart() {
    let mut fx = GrantScenario::new();
    let (child, child_name) = write_granted_child(&mut fx);
    let doc = published_file(&mut fx, child, "doc.bin");

    cut_after_a_write_the_walk_misses(&mut fx, &[&child_name], |fx| {
        block_on(fx.engine.command(Command::Rename {
            node: doc,
            new_name: "renamed.bin".into(),
        }))
        .expect("the rename stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    });
    let (root, _) = live_scope(&fx);
    let moved_child = live_child(&fx, &root, fx.folder, "child");
    assert!(
        live_names(&fx, &moved_child, child).contains(&"doc.bin".to_owned()),
        "the moved tree does not carry the rename"
    );

    restart_owner(&mut fx);
    passes_after_the_flip(&mut fx);

    let names = live_names(&fx, &moved_child, child);
    assert!(
        names.contains(&"renamed.bin".to_owned()) && !names.contains(&"doc.bin".to_owned()),
        "the restarted session applied the rename again"
    );
}

/// A lagging record opens under the seed its epoch ratchets to. A record that
/// does not open there is a gate refusal, so the drain reports it as abuse
/// and does not retry it as an upload.
#[test]
fn a_lagging_record_that_does_not_open_is_refused_as_abuse() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let sub = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "sub");
    assert_eq!(
        block_on(fx.engine.command(Command::RotateNow { node: fx.folder })),
        Ok(CommandOutcome::Done)
    );
    // The folder lags at epoch 1, and its record seals under a key that no
    // seed of the scope derives.
    plant_node(
        &fx,
        &WRITE_SCOPE_SEED,
        sub,
        &folder_body(Vec::new()),
        &[0x77; 32],
        1,
        true,
    );
    events_so_far(&mut fx._events);

    block_on(fx.engine.command(Command::Create {
        parent: sub,
        name: "inside".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a create under the folder stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        abuse_events(&mut fx._events) > 0,
        "the refused record is reported as abuse"
    );
}

/// A kept create whose node a later writer deleted finds no node and a live
/// parent, so it links the node again. The op does not record its result, so
/// the check cannot tell a lost create from a later delete. This test pins
/// that residual.
#[test]
fn a_kept_create_brings_back_a_node_a_later_writer_deleted() {
    let mut fx = GrantScenario::new();
    grant_write(&mut fx);
    let late =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "late");
    let (mut phone, _phone_events, mut phone_tasks) = phone_on(&fx, fx.folder);
    block_on(phone.command(Command::Delete { node: late })).expect("the later delete stages");
    tick(&fx.world, &phone, &mut phone_tasks);
    let (root, _) = live_scope(&fx);
    assert!(
        !live_names(&fx, &root, fx.folder).contains(&"late".to_owned()),
        "the later writer deleted the node"
    );
    cut_the_write_scope(&fx, &mut phone);

    passes_after_the_flip(&mut fx);

    let (root, _) = live_scope(&fx);
    assert!(
        live_names(&fx, &root, fx.folder).contains(&"late".to_owned()),
        "the kept create linked the node again"
    );
}

/// A kept edit B over A, then a later writer restores A and deletes B from the
/// history. After the flip the history does not name B and the head is A, the
/// base of the edit, so the edit publishes B again. This test pins that
/// residual.
#[test]
fn a_kept_edit_whose_version_a_later_writer_removed_publishes_again() {
    let mut fx = GrantScenario::new();
    grant_write(&mut fx);
    let doc = published_file_in_folder(&mut fx, "doc.bin");
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[1u8; 64]);
    publish_version(&fx.world, &mut fx.engine, &mut fx._tasks, doc, &[2u8; 64]);
    let history = live_doc_versions(&fx, doc);
    let (edited, base) = (history[0].clone(), history[1].clone());
    let (mut phone, _phone_events, mut phone_tasks) = phone_on(&fx, fx.folder);
    block_on(phone.command(Command::RestoreVersion {
        node: doc,
        content_cid: base.clone(),
    }))
    .expect("the later restore queues");
    tick(&fx.world, &phone, &mut phone_tasks);
    block_on(phone.command(Command::DeleteVersion {
        node: doc,
        content_cid: edited.clone(),
    }))
    .expect("the later version delete queues");
    tick(&fx.world, &phone, &mut phone_tasks);
    assert_eq!(
        live_doc_versions(&fx, doc),
        vec![base.clone()],
        "the later writer left the base alone in the history"
    );
    cut_the_write_scope(&fx, &mut phone);

    passes_after_the_flip(&mut fx);

    let versions = live_doc_versions(&fx, doc);
    assert_eq!(versions.len(), 2, "the kept edit published a version again");
    assert_eq!(versions[1], base, "over the base");
}

/// A manual rotation leaves the subtree lagging just as a revoke's read cut
/// does, so a downgrade right after it still moves every node.
#[test]
fn a_downgrade_right_after_a_manual_rotation_moves_the_lagging_subtree() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    assert_eq!(
        block_on(fx.engine.command(Command::RotateNow { node: fx.folder })),
        Ok(CommandOutcome::Done)
    );
    let rotated = fx.granted_scope_repoint();

    assert_eq!(
        block_on(fx.engine.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done)
    );

    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, rotated.write_epoch + 1, "the wave ran");
    assert_ne!(
        derive_write_name(&revokee_seed, &fx.folder.0),
        after.current_root,
        "so the demoted party's seed no longer derives the root"
    );
}

/// A read revoke leaves the subtree lagging, so the write grant that follows
/// moves lagging nodes off the names the vault's write seed derives.
#[test]
fn a_write_grant_right_after_a_read_revoke_moves_the_lagging_subtree() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let (child, _) = nested_subtree(&mut fx);
    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        fx.grant_bystander(Permission::Write),
        Ok(CommandOutcome::Done)
    );

    let after = fx.granted_scope_repoint();
    let root_seed = granted_override_seed(&fx, 2);
    let child_name = published_child_name(
        &fx.world,
        &fx.blocks,
        &after.current_root,
        &read_key_under(&root_seed, fx.folder),
        "child",
    );
    assert_ne!(
        child_name,
        write_name(child),
        "the wave moved the child off the vault seed's name"
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

/// The boundary walk reads an owner-minted scope root whose cached copy is
/// another value at its sequence: the session reports that fork once, and the
/// served record replaces the cached copy, so the fork clears.
#[test]
fn a_walk_that_reads_an_owned_scope_root_forked_reports_it_once() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let name = write_name(fx.folder);
    let endpoints = fx.world.record_store.endpoints();
    let held = fx
        .world
        .record_store
        .record_at(&endpoints[0], name.as_str())
        .expect("the scope root is published");
    let held = IpnsRecord::unmarshal(&held)
        .and_then(|record| record.verify(&name))
        .expect("the scope root verifies");
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &fx.folder.0).as_bytes());
    let other = IpnsRecord::create_v2(
        &signer,
        b"/ipfs/bafyanotherscoperoot",
        held.sequence,
        held.ttl,
        "2098-01-01T00:00:00Z",
    )
    .marshal();
    block_on(
        fx.owner_device
            .snapshot_cache
            .put(name.as_str().as_bytes(), &other),
    )
    .expect("seed the cached copy");
    drop(events_so_far(&mut fx._events));

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let forks = events_so_far(&mut fx._events)
        .into_iter()
        .filter(|event| {
            matches!(event, Event::SameSequenceFork { routing_key } if routing_key == name.as_str())
        })
        .count();
    assert_eq!(forks, 1);
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
            link_counter: 2,
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

/// A node linked from `keep`, a folder of the vault's own scope, at the
/// create's counter of 1, and from `inner`, a folder inside the granted folder,
/// at `inner_counter`, then the folder shared by `share`. `keep` is drawn so
/// its id falls below `inner`'s when `keep_below` holds, and above it
/// otherwise.
fn dual_linked_at(
    fx: &mut GrantScenario,
    inner_counter: u64,
    keep_below: bool,
    share: impl FnOnce(&mut GrantScenario),
) -> (NodeId, NodeId, NodeId) {
    let inner =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "box");
    let keep = (0..16)
        .map(|i| {
            create_published_folder(
                &fx.world,
                &mut fx.engine,
                &mut fx._tasks,
                ROOT,
                &format!("keep {i}"),
            )
        })
        .find(|keep| (keep.0 < inner.0) == keep_below)
        .expect("a folder id on the asked side of the inner folder's");
    let deep = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, keep, "deep");
    dual_link(fx, inner, deep, inner_counter);
    share(fx);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    (keep, deep, inner)
}

/// Another writer links `deep` from `holder` at `counter`, and the owner
/// focuses `holder` and refreshes.
fn dual_link(fx: &mut GrantScenario, holder: NodeId, deep: NodeId, counter: u64) {
    let mut link = named_child(deep, "deep", &write_name(deep));
    link.link_counter = counter;
    concurrent_add(
        &fx.world,
        &fx.blocks,
        holder,
        &read_key_of(holder),
        SCOPE,
        link,
    );
    block_on(fx.engine.command(Command::SetFocus { node: Some(holder) })).expect("the focus moves");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
}

/// Whether the record at `node`'s write name opens under `read_key`.
fn opens_under(fx: &GrantScenario, node: NodeId, read_key: &[u8; 32]) -> bool {
    published_seal(&fx.world, &fx.blocks, &write_name(node), read_key)
        .2
        .is_some()
}

/// A `share` for [`dual_linked_at`]: a direct grant at `permission`.
fn granted_at(permission: Permission) -> impl FnOnce(&mut GrantScenario) {
    move |fx| assert_eq!(fx.grant_folder_at(permission), Ok(CommandOutcome::Done))
}

/// Whether `inner`'s link to the node wins over `keep`'s at counter 1.
fn inner_wins(inner_counter: u64, keep_below: bool) -> bool {
    inner_counter > 1 || (inner_counter == 1 && !keep_below)
}

/// The child names of the folder record published at `name`, read under
/// `read_key`.
fn child_names_at(
    world: &FakeWorld,
    blocks: &Blocks,
    name: &IpnsName,
    read_key: &[u8; 32],
) -> Vec<String> {
    let head = published_head(world, blocks, name).expect("a published record");
    let envelope = decode_envelope(&head).expect("the head block decodes");
    let ReadBody::Folder { children, .. } =
        open_read_body(&envelope, read_key).expect("the folder body opens")
    else {
        panic!("expected a folder body");
    };
    children.iter().map(|child| child.name.clone()).collect()
}

/// `deep` stays in the vault's own scope: `keep` names it at the name it held,
/// and its record there opens under the vault scope's key.
fn assert_held_in_the_vault_scope(fx: &GrantScenario, keep: NodeId, deep: NodeId, case: &str) {
    assert_eq!(
        published_child_name(
            &fx.world,
            &fx.blocks,
            &write_name(keep),
            &read_key_of(keep),
            "deep"
        ),
        write_name(deep),
        "{case}: the vault's folder names the node at the name it held"
    );
    assert!(
        opens_under(fx, deep, &read_key_of(deep)),
        "{case}: and the node there seals in the vault's own scope"
    );
}

/// The grant re-seals a dual-linked node into the granted scope only when the
/// link rank (highest counter, then lowest parent id) puts it under the granted
/// folder. Otherwise it drops the losing ref. A soft delete then unlinks the
/// node from both folders, in either parent-id order.
fn assert_grant_and_delete_follow_the_link_rank(inner_counter: u64) {
    for keep_below in [true, false] {
        let mut fx = GrantScenario::new();
        let (keep, deep, inner) = dual_linked_at(
            &mut fx,
            inner_counter,
            keep_below,
            granted_at(Permission::Read),
        );
        let case = format!("inner counter {inner_counter}, keep below {keep_below}");

        let (override_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
        if inner_wins(inner_counter, keep_below) {
            assert!(
                opens_under(&fx, deep, &read_key_under(&override_seed, deep)),
                "{case}: deep moved into the granted scope"
            );
        } else {
            assert_held_in_the_vault_scope(&fx, keep, deep, &case);
            assert_eq!(
                published_child_names(
                    &fx.world,
                    &fx.blocks,
                    inner,
                    &read_key_under(&override_seed, inner)
                ),
                Vec::<String>::new(),
                "{case}: the grant dropped the losing ref"
            );
        }

        block_on(fx.engine.command(Command::Delete { node: deep })).expect("the delete stages");
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        assert_eq!(
            published_child_names(
                &fx.world,
                &fx.blocks,
                inner,
                &read_key_under(&override_seed, inner)
            ),
            Vec::<String>::new(),
            "{case}: the folder inside the grant does not name the node"
        );
        assert_eq!(
            published_child_names(&fx.world, &fx.blocks, keep, &read_key_of(keep)),
            Vec::<String>::new(),
            "{case}: and the folder in the vault's own scope dropped it"
        );
    }
}

/// A write grant succeeds over a dual-linked node in either parent-id order.
/// When the rank holds the node outside, the name wave moves the granted
/// folder's own nodes and leaves the held node at its name, in the vault's own
/// scope.
fn assert_write_grant_follows_the_link_rank(inner_counter: u64) {
    for keep_below in [true, false] {
        let mut fx = GrantScenario::new();
        let (keep, deep, inner) = dual_linked_at(
            &mut fx,
            inner_counter,
            keep_below,
            granted_at(Permission::Write),
        );
        if inner_wins(inner_counter, keep_below) {
            continue;
        }
        let case = format!("inner counter {inner_counter}, keep below {keep_below}");
        let (override_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
        let moved_inner = published_child_name(
            &fx.world,
            &fx.blocks,
            &fx.granted_scope_repoint().current_root,
            &read_key_under(&override_seed, fx.folder),
            "box",
        );
        assert_ne!(
            moved_inner,
            write_name(inner),
            "{case}: the wave moved the granted folder's own nodes"
        );
        assert_eq!(
            child_names_at(
                &fx.world,
                &fx.blocks,
                &moved_inner,
                &read_key_under(&override_seed, inner)
            ),
            Vec::<String>::new(),
            "{case}: and the moved folder holds no ref to the held node"
        );
        assert_held_in_the_vault_scope(&fx, keep, deep, &case);
    }
}

/// A node `keep` names and the granted folder's `box` holds by a losing ref,
/// then a read grant that drops that ref. A second owner device loaded `box`
/// with the ref before the grant, and never the winning parent.
fn a_second_device_that_lacks_the_winner(
    fx: &mut GrantScenario,
) -> (
    NodeId,
    NodeId,
    Engine<FakeSeamTypes>,
    EventStream,
    Vec<BoxedTask>,
) {
    let second = fx.world.device(b"owner-second-device");
    let mut session = None;
    let (keep, deep, _inner) = dual_linked_at(fx, 0, true, |fx| {
        serve_http(&second, &fx.blocks, 600);
        let (mut engine, events) = engine_on_api(&second, 7);
        block_on(engine.start(secret(), None)).expect("the second device starts");
        let mut tasks = fx.world.scheduler.take_spawned_tasks();
        poll_tasks_until_parked(&mut tasks);
        block_on(engine.command(Command::SetFocus {
            node: Some(fx.folder),
        }))
        .unwrap();
        tick(&fx.world, &engine, &mut tasks);
        let inner = block_on(engine.view())
            .unwrap()
            .children(fx.folder)
            .into_iter()
            .find(|child| child.name == "box")
            .expect("the second device lists the inner folder")
            .id;
        block_on(engine.command(Command::SetFocus { node: Some(inner) })).unwrap();
        tick(&fx.world, &engine, &mut tasks);
        assert_eq!(
            block_on(engine.view()).unwrap().children(inner).len(),
            1,
            "the second device loaded the losing parent with its ref"
        );
        session = Some((engine, events, tasks));
        granted_at(Permission::Read)(fx);
    });
    let (engine, mut events, tasks) = session.expect("the second device booted");
    events_so_far(&mut events);
    assert!(
        !block_on(engine.view())
            .unwrap()
            .children(keep)
            .iter()
            .any(|child| child.id == deep),
        "the second device never loaded the winning parent"
    );
    (keep, deep, engine, events, tasks)
}

/// A read grant drops the losing ref of a node the granted folder holds. A
/// second owner device that loaded that folder but never the winning parent
/// sees a departure, and must not bin the node the winning parent still names.
#[test]
fn a_grant_dropping_a_losing_ref_is_no_capture_on_a_device_that_lacks_the_winner() {
    let mut fx = GrantScenario::new();
    let (keep, deep, engine, mut events, mut tasks) =
        a_second_device_that_lacks_the_winner(&mut fx);
    for _ in 0..4 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert!(
        published_bin_entries(&fx)
            .iter()
            .all(|entry| entry.node_id != deep.0),
        "the node the winning parent names is no capture"
    );
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert_held_in_the_vault_scope(&fx, keep, deep, "second device");
}

/// The node the grant held in the vault scope then leaves `keep` too. The
/// second device saw it leave `box`, so its capture is the granted scope's,
/// but the record that seals the node opens under the vault scope's end: the
/// capture bins there, and no record is reported faulty.
#[test]
fn a_held_node_that_leaves_both_parents_bins_in_the_scope_that_seals_it() {
    let mut fx = GrantScenario::new();
    let (keep, deep, engine, mut events, mut tasks) =
        a_second_device_that_lacks_the_winner(&mut fx);
    unlink_from_keep(&fx, keep, deep);
    for _ in 0..8 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert_eq!(
        bin_scopes_of(&fx, deep),
        vec![SCOPE],
        "the node bins in the scope that seals it"
    );
}

/// The same departure, with the node's record sealed under a key no own scope
/// derives: the capture is refused once, and nothing bins.
#[test]
fn a_captured_record_no_own_scope_opens_is_one_trust_violation() {
    let mut fx = GrantScenario::new();
    let (keep, deep, engine, mut events, mut tasks) =
        a_second_device_that_lacks_the_winner(&mut fx);
    unlink_from_keep(&fx, keep, deep);
    let (_, epoch, _) =
        published_seal(&fx.world, &fx.blocks, &write_name(deep), &read_key_of(deep));
    reseal_interior_node(&fx.world, &fx.blocks, deep, SCOPE, &[0x42; 32], epoch);
    for _ in 0..8 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 1, "the record is refused once");
    assert_eq!(
        bin_scopes_of(&fx, deep),
        Vec::<[u8; 16]>::new(),
        "nothing bins"
    );
}

/// The writer that unlinked a node leaves it at a record below the vault
/// scope's read epoch, with a seal that the seed the scope's history gives
/// for that epoch does not open. The gate refuses it, the capture is reported
/// once, and nothing bins.
#[test]
fn a_captured_record_below_the_epoch_floor_that_does_not_open_is_one_trust_violation() {
    let mut fx = GrantScenario::new();
    let (mut engine, mut events, mut tasks) = fx.second_owner_device();
    let doomed = unlinked_by_another_writer(&mut fx, &mut engine, &mut tasks, |fx, doomed| {
        let (_, epoch, _) = published_seal(
            &fx.world,
            &fx.blocks,
            &write_name(doomed),
            &read_key_of(doomed),
        );
        reseal_interior_node(&fx.world, &fx.blocks, doomed, SCOPE, &[0x42; 32], epoch);
        assert_eq!(
            block_on(fx.engine.command(Command::RotateNow { node: ROOT })),
            Ok(CommandOutcome::Done)
        );
    });
    events_so_far(&mut events);
    for _ in 0..8 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 1, "the record is refused once");
    assert_eq!(
        bin_scopes_of(&fx, doomed),
        Vec::<[u8; 16]>::new(),
        "nothing bins"
    );
}

/// The record reads one capture pass spends to find sealing scopes, as the
/// drain bounds them.
const MAX_SEALER_READS: usize = 64;

/// Six read grants leave seven own scopes that derive one captured name. A
/// writer unlinks eight nodes and leaves each at a record that no own key
/// opens. Each pass reads within its bound, a capture the pass does not finish
/// resumes on a later pass, and each record is reported once.
#[test]
fn the_search_for_sealing_scopes_reads_within_its_bound_and_resumes() {
    let mut fx = GrantScenario::new();
    for i in 0..6 {
        let folder = create_published_folder(
            &fx.world,
            &mut fx.engine,
            &mut fx._tasks,
            ROOT,
            &format!("granted {i}"),
        );
        assert_eq!(
            block_on(fx.engine.command(Command::Grant {
                node: folder,
                recipient_identity_public_key:
                    recipient_identity().verifying_key().to_sec1().to_vec(),
                permission: Permission::Read,
                grantee_name: None,
            })),
            Ok(CommandOutcome::Done)
        );
    }
    let device = fx.world.device(b"the owner's second device");
    let (mut engine, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &device);
    tick(&fx.world, &engine, &mut tasks);
    let plain = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "plain");
    let doomed: Vec<NodeId> = (0..8)
        .map(|i| {
            create_published_folder(
                &fx.world,
                &mut fx.engine,
                &mut fx._tasks,
                plain,
                &format!("doomed {i}"),
            )
        })
        .collect();
    block_on(engine.command(Command::SetFocus { node: Some(plain) })).unwrap();
    tick(&fx.world, &engine, &mut tasks);
    assert_eq!(block_on(engine.view()).unwrap().children(plain).len(), 8);
    for node in &doomed {
        let (_, epoch, _) = published_seal(
            &fx.world,
            &fx.blocks,
            &write_name(*node),
            &read_key_of(*node),
        );
        reseal_interior_node(&fx.world, &fx.blocks, *node, SCOPE, &[0x42; 32], epoch);
    }
    concurrent_edit(
        &fx.world,
        &fx.blocks,
        plain,
        &read_key_of(plain),
        SCOPE,
        |children| children.clear(),
    );
    events_so_far(&mut events);
    let names: Vec<Vec<u8>> = doomed
        .iter()
        .map(|node| write_name(*node).as_str().as_bytes().to_vec())
        .collect();
    let reads = || {
        device
            .snapshot_cache
            .reads()
            .iter()
            .filter(|key| names.contains(key))
            .count()
    };
    let mut reported = Vec::new();
    for _ in 0..8 {
        let before = reads();
        tick(&fx.world, &engine, &mut tasks);
        assert!(
            reads() - before <= MAX_SEALER_READS,
            "one pass reads within its bound"
        );
        reported.push(abuse_events(&mut events));
    }
    assert_eq!(
        reported.iter().sum::<usize>(),
        8,
        "each record is reported once"
    );
    assert!(
        reported.iter().all(|count| *count < 8),
        "no one pass reads every record under every end"
    );
    assert!(
        doomed
            .iter()
            .all(|node| bin_scopes_of(&fx, *node).is_empty()),
        "nothing bins"
    );
}

/// The writer that unlinked a node then publishes a signed record with a head
/// that does not decode at the node's name. The gate refuses it, the capture
/// is reported once, and nothing bins.
#[test]
fn a_captured_node_with_a_malformed_head_is_one_trust_violation() {
    let mut fx = GrantScenario::new();
    let (mut engine, mut events, mut tasks) = fx.second_owner_device();
    let doomed = unlinked_by_another_writer(&mut fx, &mut engine, &mut tasks, |_, _| {});
    let cid = fx.blocks.put(b"not an envelope".to_vec());
    publish_value_at(&fx.world, doomed, format!("/ipfs/{cid}").as_bytes());
    events_so_far(&mut events);
    for _ in 0..8 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 1, "the record is refused once");
    assert_eq!(
        bin_scopes_of(&fx, doomed),
        Vec::<[u8; 16]>::new(),
        "nothing bins"
    );
}

/// A node another writer unlinked, whose re-key lands on `device` while the
/// bin index publish does not.
fn rekeyed_with_no_entry(
    fx: &mut GrantScenario,
    device: &FakeDevice,
) -> (NodeId, Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    let (mut engine, events, mut tasks) = boot_owner(&fx.world, &fx.blocks, device);
    tick(&fx.world, &engine, &mut tasks);
    let doomed = unlinked_by_another_writer(fx, &mut engine, &mut tasks, |_, _| {});
    let bin = BinIndexKeys::derive(&SECRET);
    fx.world.record_store.fail_put_for(bin.name().as_str());
    let before = published_head_cid(&fx.world, &write_name(doomed));
    for _ in 0..8 {
        if published_head_cid(&fx.world, &write_name(doomed)) != before {
            break;
        }
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_ne!(
        published_head_cid(&fx.world, &write_name(doomed)),
        before,
        "the re-key landed"
    );
    assert!(bin_scopes_of(fx, doomed).is_empty(), "and no entry did");
    fx.world.record_store.heal_put_for(bin.name().as_str());
    (doomed, engine, events, tasks)
}

/// The re-key of a capture lands and the bin index publish does not. The
/// next pass opens the node under the bin's held key and bins it, with no
/// record reported faulty.
#[test]
fn a_capture_whose_bin_publish_failed_bins_on_the_next_pass() {
    let mut fx = GrantScenario::new();
    let device = fx.world.device(b"the owner's second device");
    let (doomed, engine, mut events, mut tasks) = rekeyed_with_no_entry(&mut fx, &device);
    for _ in 0..8 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert_eq!(
        bin_scopes_of(&fx, doomed),
        vec![SCOPE],
        "the node bins on a later pass"
    );
}

/// The same, with a rotation of the vault scope before the next pass: the
/// re-keyed record is then below the read-epoch floor, and it still opens
/// under the bin's held key, so the node bins with no record reported faulty.
#[test]
fn a_capture_whose_bin_publish_failed_bins_after_a_rotation() {
    let mut fx = GrantScenario::new();
    let device = fx.world.device(b"the owner's second device");
    let (doomed, engine, mut events, mut tasks) = rekeyed_with_no_entry(&mut fx, &device);
    assert_eq!(
        block_on(fx.engine.command(Command::RotateNow { node: ROOT })),
        Ok(CommandOutcome::Done)
    );
    for _ in 0..8 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert_eq!(
        bin_scopes_of(&fx, doomed),
        vec![SCOPE],
        "the node bins on a later pass"
    );
}

/// The sequence-floor reads of the node's name that answer before the
/// capture's held-key read.
const HELD_KEY_READ_BUDGET: u64 = 2;

/// The same, with the capture's held-key read failing after the scope key
/// refused the record: the read did not answer, so no record is reported
/// faulty, and the node bins once the reads answer again.
#[test]
fn a_held_key_read_with_no_answer_is_no_trust_violation() {
    let mut fx = GrantScenario::new();
    let device = fx.world.device(b"the owner's second device");
    let (doomed, engine, mut events, mut tasks) = rekeyed_with_no_entry(&mut fx, &device);
    device.floor_store.fail_sequence_floor_reads_after(
        &floor_label(write_name(doomed).as_str().as_bytes()),
        HELD_KEY_READ_BUDGET,
    );
    for _ in 0..8 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert!(
        bin_scopes_of(&fx, doomed).is_empty(),
        "the held-key read did not answer"
    );
    device.floor_store.heal_floors();
    for _ in 0..8 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert_eq!(
        bin_scopes_of(&fx, doomed),
        vec![SCOPE],
        "the node bins once the reads answer"
    );
}

/// A second owner device loads a node in the vault scope. A grant then makes
/// its folder a scope root, the node converges onto that scope, and a writer
/// of the scope unlinks it. The departure is the granted scope's capture,
/// which bins there with no faulty record reported, under the name the
/// granted scope derives. With `reads_the_wave` unset, the second device does
/// not read the folder between a write grant's name wave and the unlink, so
/// its capture carries the name from before the wave.
fn assert_a_node_a_grant_moved_bins_in_the_granted_scope(
    permission: Permission,
    reads_the_wave: bool,
) {
    let mut fx = GrantScenario::new();
    let (inner, doomed) = nested_subtree(&mut fx);
    let (mut second, mut events, mut tasks) = fx.second_owner_device();
    for node in [fx.folder, inner] {
        block_on(second.command(Command::SetFocus { node: Some(node) })).unwrap();
        tick(&fx.world, &second, &mut tasks);
    }
    assert_eq!(
        block_on(second.view()).unwrap().children(inner).len(),
        1,
        "the second device loads the doomed node"
    );
    block_on(second.command(Command::SetFocus { node: None })).unwrap();
    tick(&fx.world, &second, &mut tasks);
    assert_eq!(fx.grant_folder_at(permission), Ok(CommandOutcome::Done));
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    // A write grant's name wave moves and re-seals the folder's nodes; a read
    // grant leaves them to the lazy wave.
    let (write_seed, read_seed) = match permission {
        Permission::Read => {
            for node in [inner, doomed] {
                converge_into_granted_scope(&fx, node);
            }
            tick(&fx.world, &second, &mut tasks);
            let (seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
            (Zeroizing::new(WRITE_SCOPE_SEED), seed)
        }
        Permission::Write => {
            // The second device reads the folder as the wave left it, at the
            // name its scope now derives, or reads only the granted root, so
            // its base holds the folder's children at their old names.
            let read = if reads_the_wave { inner } else { fx.folder };
            block_on(second.command(Command::SetFocus { node: Some(read) })).unwrap();
            for _ in 0..2 {
                tick(&fx.world, &second, &mut tasks);
            }
            let root = fx.granted_scope_repoint().current_root;
            let seed = grantee_write_scope_seed(&fx.folder_section(), &root, &fx.folder.0, 1);
            (Zeroizing::new(seed), granted_override_seed(&fx, 1))
        }
    };
    concurrent_edit_under(
        &fx.world,
        &fx.blocks,
        inner,
        &write_seed,
        &read_key_under(&read_seed, inner),
        fx.folder.0,
        |children| children.retain(|child| child.id != doomed.0),
    );
    events_so_far(&mut events);
    block_on(second.command(Command::SetFocus { node: Some(inner) })).unwrap();
    for _ in 0..8 {
        tick(&fx.world, &second, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert_eq!(
        bin_scopes_of(&fx, doomed),
        vec![fx.folder.0],
        "the unlinked node bins in the scope that seals it"
    );
    assert_eq!(
        published_bin_entries(&fx)
            .iter()
            .filter(|entry| entry.node_id == doomed.0)
            .map(|entry| entry.ipns_name().to_vec())
            .collect::<Vec<_>>(),
        vec![
            derive_write_name(&write_seed, &doomed.0)
                .as_str()
                .as_bytes()
                .to_vec()
        ],
        "the entry names the record the re-key sealed"
    );
}

#[test]
fn a_node_a_read_grant_moved_bins_in_the_granted_scope() {
    assert_a_node_a_grant_moved_bins_in_the_granted_scope(Permission::Read, true);
}

#[test]
fn a_node_a_write_grant_moved_bins_in_the_granted_scope() {
    assert_a_node_a_grant_moved_bins_in_the_granted_scope(Permission::Write, true);
}

#[test]
fn a_node_a_write_grant_moved_bins_on_a_device_that_holds_its_old_name() {
    assert_a_node_a_grant_moved_bins_in_the_granted_scope(Permission::Write, false);
}

/// A second owner device that loaded the folder's subtree, then read nothing
/// while the owner's first device ran a write grant's name wave over it.
fn idle_through_a_write_grant(
    fx: &mut GrantScenario,
) -> (NodeId, Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    let (inner, _) = nested_subtree(fx);
    let (mut second, mut events, mut tasks) = fx.second_owner_device();
    for node in [fx.folder, inner] {
        block_on(second.command(Command::SetFocus { node: Some(node) })).unwrap();
        tick(&fx.world, &second, &mut tasks);
    }
    block_on(second.command(Command::SetFocus { node: None })).unwrap();
    tick(&fx.world, &second, &mut tasks);
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    events_so_far(&mut events);
    (inner, second, events, tasks)
}

/// Navigate `engine` to `node`, then run four ticks.
fn navigate_and_settle(
    fx: &GrantScenario,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    node: NodeId,
) {
    block_on_while_ticking(
        engine.command(Command::SetFocus { node: Some(node) }),
        tasks,
    )
    .unwrap();
    for _ in 0..4 {
        tick(&fx.world, engine, tasks);
    }
}

/// A navigation into the granted subtree, before any walk names the granted
/// root, reads no honest record as abuse.
#[test]
fn a_navigation_below_a_root_another_device_granted_reports_no_abuse() {
    let mut fx = GrantScenario::new();
    let (inner, mut second, mut events, mut tasks) = idle_through_a_write_grant(&mut fx);
    navigate_and_settle(&fx, &mut second, &mut tasks, inner);
    assert_eq!(abuse_descriptions(&mut events), Vec::<String>::new());
}

/// A navigation to the granted root itself reads no honest record as abuse.
#[test]
fn a_navigation_to_a_root_another_device_granted_reports_no_abuse() {
    let mut fx = GrantScenario::new();
    let (_, mut second, mut events, mut tasks) = idle_through_a_write_grant(&mut fx);
    let folder = fx.folder;
    navigate_and_settle(&fx, &mut second, &mut tasks, folder);
    assert_eq!(abuse_descriptions(&mut events), Vec::<String>::new());
}

/// A granted root whose head fails its content address is still abuse.
#[test]
fn a_malformed_root_another_device_granted_is_still_abuse() {
    let mut fx = GrantScenario::new();
    let (_, mut second, mut events, mut tasks) = idle_through_a_write_grant(&mut fx);
    corrupt_published_head(&fx, &fx.granted_scope_repoint().current_root);
    let folder = fx.folder;
    navigate_and_settle(&fx, &mut second, &mut tasks, folder);
    assert!(abuse_events(&mut events) > 0, "the rejection is reported");
}

/// A vault-scope writer unlinks `deep` from `keep`.
fn unlink_from_keep(fx: &GrantScenario, keep: NodeId, deep: NodeId) {
    concurrent_edit(
        &fx.world,
        &fx.blocks,
        keep,
        &read_key_of(keep),
        SCOPE,
        |children| children.retain(|child| child.id != deep.0),
    );
}

/// The scope id of each published bin entry for `node`.
fn bin_scopes_of(fx: &GrantScenario, node: NodeId) -> Vec<[u8; 16]> {
    published_bin_entries(fx)
        .into_iter()
        .filter(|entry| entry.node_id == node.0)
        .map(|entry| entry.scope_id)
        .collect()
}

/// A granted folder keeps the ref its parent named it by, under the parent's
/// write seed, so the vault scope's capture walk reads it under its own end.
/// Another writer's unlink in the vault scope then bins, and no record is
/// reported faulty.
fn assert_a_capture_walk_reads_a_granted_folder_under_its_own_end(permission: Permission) {
    let mut fx = GrantScenario::new();
    let (mut engine, mut events, mut tasks) = fx.second_owner_device();
    assert_eq!(fx.grant_folder_at(permission), Ok(CommandOutcome::Done));
    let doomed = unlinked_by_another_writer(&mut fx, &mut engine, &mut tasks, |_, _| {});
    events_so_far(&mut events);
    for _ in 0..4 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert!(
        published_bin_entries(&fx)
            .iter()
            .any(|entry| entry.node_id == doomed.0),
        "the unlinked node bins"
    );
}

#[test]
fn a_capture_walk_reads_a_read_granted_folder_under_its_own_end() {
    assert_a_capture_walk_reads_a_granted_folder_under_its_own_end(Permission::Read);
}

#[test]
fn a_capture_walk_reads_a_write_granted_folder_under_its_own_end() {
    assert_a_capture_walk_reads_a_granted_folder_under_its_own_end(Permission::Write);
}

/// A folder `doomed` under a new vault folder, which `second` loads and then
/// sees another writer unlink. `before_unlink` runs between the two.
fn unlinked_by_another_writer(
    fx: &mut GrantScenario,
    second: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    before_unlink: impl FnOnce(&mut GrantScenario, NodeId),
) -> NodeId {
    let plain = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "plain");
    let doomed =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, plain, "doomed");
    block_on(second.command(Command::SetFocus { node: Some(plain) })).unwrap();
    tick(&fx.world, second, tasks);
    assert_eq!(block_on(second.view()).unwrap().children(plain).len(), 1);
    before_unlink(fx, doomed);
    concurrent_edit(
        &fx.world,
        &fx.blocks,
        plain,
        &read_key_of(plain),
        SCOPE,
        |children| children.retain(|child| child.id != doomed.0),
    );
    doomed
}

/// A folder that a name wave left at a name the scope's write seed does not
/// derive is a folder the walk cannot read. Here such a folder links the
/// departed node, so the node does not bin.
#[test]
fn a_folder_at_a_name_the_scope_does_not_derive_holds_the_capture() {
    let mut fx = GrantScenario::new();
    let (mut engine, _events, mut tasks) = fx.second_owner_device();
    let top = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "top");
    let stray = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, top, "stray");
    let doomed = unlinked_by_another_writer(&mut fx, &mut engine, &mut tasks, |fx, doomed| {
        concurrent_add(
            &fx.world,
            &fx.blocks,
            stray,
            &read_key_of(stray),
            SCOPE,
            named_child(doomed, "doomed", &write_name(doomed)),
        );
        let old_seed = [0x5a; 32];
        let record = IpnsRecord::create_v2(
            &kdf::ipns_keypair(kdf::write_seed(&old_seed, &stray.0).as_bytes()),
            &published_value(&fx.world, &write_name(stray)),
            1,
            TTL_NANOS,
            EOL,
        )
        .marshal();
        for endpoint in fx.world.record_store.endpoints() {
            fx.world.record_store.seed_record(
                &endpoint,
                derive_write_name(&old_seed, &stray.0).as_str(),
                record.clone(),
            );
        }
        concurrent_edit(
            &fx.world,
            &fx.blocks,
            top,
            &read_key_of(top),
            SCOPE,
            |children| {
                for child in children.iter_mut().filter(|child| child.id == stray.0) {
                    child.ipns_name = derive_write_name(&old_seed, &stray.0)
                        .as_str()
                        .as_bytes()
                        .to_vec();
                }
            },
        );
    });
    for _ in 0..4 {
        tick(&fx.world, &engine, &mut tasks);
    }
    assert!(
        published_bin_entries(&fx)
            .iter()
            .all(|entry| entry.node_id != doomed.0),
        "a folder the walk cannot read links the node"
    );
}

/// The owner moves a node from a vault folder into a folder under a granted
/// folder. A second owner device that never loaded the destination sees a
/// departure. Its walk reads the granted subtree under that scope's own end,
/// finds the link, and bins nothing.
fn assert_a_move_under_a_granted_folder_is_no_capture(permission: Permission) {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    let (mut second, mut events, mut tasks) = fx.second_owner_device();
    assert_eq!(fx.grant_folder_at(permission), Ok(CommandOutcome::Done));
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let plain = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "plain");
    let doomed =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, plain, "doomed");
    block_on(second.command(Command::SetFocus { node: Some(plain) })).unwrap();
    tick(&fx.world, &second, &mut tasks);
    assert_eq!(block_on(second.view()).unwrap().children(plain).len(), 1);
    block_on(fx.engine.command(Command::Relink {
        node: doomed,
        new_parent: inner,
    }))
    .expect("the move journals");
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert!(
        block_on(fx.engine.view())
            .unwrap()
            .children(inner)
            .iter()
            .any(|child| child.id == doomed),
        "the owner moved the node under the granted folder"
    );
    let before = published_head(&fx.world, &fx.blocks, &write_name(doomed));
    events_so_far(&mut events);
    for _ in 0..6 {
        tick(&fx.world, &second, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert!(
        published_bin_entries(&fx)
            .iter()
            .all(|entry| entry.node_id != doomed.0),
        "the moved node does not bin"
    );
    assert_eq!(
        published_head(&fx.world, &fx.blocks, &write_name(doomed)),
        before,
        "nothing re-keys the node at its vault name"
    );
}

#[test]
fn a_move_under_a_read_granted_folder_is_no_capture() {
    assert_a_move_under_a_granted_folder_is_no_capture(Permission::Read);
}

#[test]
fn a_move_under_a_write_granted_folder_is_no_capture() {
    assert_a_move_under_a_granted_folder_is_no_capture(Permission::Write);
}

/// A granted folder inside an unlinked folder is a scope root, so the re-key
/// of the unlinked folder stops at it, and no record is reported faulty.
#[test]
fn the_rekey_of_a_captured_folder_stops_at_a_granted_folder_inside_it() {
    let mut fx = GrantScenario::new();
    let (mut second, mut events, mut tasks) = fx.second_owner_device();
    assert_eq!(
        fx.grant_folder_at(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "outer");
    let plain = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, outer, "plain");
    block_on(fx.engine.command(Command::Relink {
        node: fx.folder,
        new_parent: plain,
    }))
    .expect("the move journals");
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert!(
        block_on(fx.engine.view())
            .unwrap()
            .children(plain)
            .iter()
            .any(|child| child.id == fx.folder),
        "the granted folder sits under the folder that departs"
    );
    block_on(second.command(Command::SetFocus { node: Some(outer) })).unwrap();
    tick(&fx.world, &second, &mut tasks);
    concurrent_edit(
        &fx.world,
        &fx.blocks,
        outer,
        &read_key_of(outer),
        SCOPE,
        |children| children.retain(|child| child.id != plain.0),
    );
    events_so_far(&mut events);
    for _ in 0..6 {
        tick(&fx.world, &second, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert!(
        published_bin_entries(&fx)
            .iter()
            .any(|entry| entry.node_id == plain.0),
        "the unlinked folder bins"
    );
}

/// The owner moves a node out of a folder under a granted folder into a vault
/// folder. A second owner device that loaded only the granted side sees a
/// departure in the granted scope. Its walk starts at the vault root, finds the
/// link, and bins nothing.
fn assert_a_move_out_of_a_granted_folder_is_no_capture(permission: Permission) {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    let (mut second, mut events, mut tasks) = fx.second_owner_device();
    assert_eq!(fx.grant_folder_at(permission), Ok(CommandOutcome::Done));
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let doomed =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, inner, "doomed");
    let plain = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "plain");
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    block_on(second.command(Command::SetFocus { node: Some(inner) })).unwrap();
    for _ in 0..2 {
        tick(&fx.world, &second, &mut tasks);
    }
    assert_eq!(block_on(second.view()).unwrap().children(inner).len(), 1);
    block_on(fx.engine.command(Command::Relink {
        node: doomed,
        new_parent: plain,
    }))
    .expect("the move journals");
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert!(
        block_on(fx.engine.view())
            .unwrap()
            .children(plain)
            .iter()
            .any(|child| child.id == doomed),
        "the owner moved the node into the vault folder"
    );
    events_so_far(&mut events);
    for _ in 0..8 {
        tick(&fx.world, &second, &mut tasks);
    }
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert!(
        published_bin_entries(&fx)
            .iter()
            .all(|entry| entry.node_id != doomed.0),
        "the moved node does not bin"
    );
}

#[test]
fn a_move_out_of_a_read_granted_folder_is_no_capture() {
    assert_a_move_out_of_a_granted_folder_is_no_capture(Permission::Read);
}

#[test]
fn a_move_out_of_a_write_granted_folder_is_no_capture() {
    assert_a_move_out_of_a_granted_folder_is_no_capture(Permission::Write);
}

/// The owner bins a folder that holds a granted folder, then purges it. The
/// purge walk stops at the granted root, which the bin never re-keyed.
fn assert_a_purge_stops_at_a_granted_folder_it_holds(permission: Permission) {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_at(permission), Ok(CommandOutcome::Done));
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "outer");
    let plain = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, outer, "plain");
    block_on(fx.engine.command(Command::Relink {
        node: fx.folder,
        new_parent: plain,
    }))
    .expect("the move journals");
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    block_on(fx.engine.command(Command::Delete { node: plain })).expect("the delete journals");
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert!(
        published_bin_entries(&fx)
            .iter()
            .any(|entry| entry.node_id == plain.0),
        "the folder is in the bin"
    );
    events_so_far(&mut fx._events);
    block_on(fx.engine.command(Command::Purge { node: plain })).expect("the purge journals");
    for _ in 0..8 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    assert!(
        block_on(fx.engine.status())
            .expect("the status reads")
            .dead_letters
            .is_empty(),
        "the purge does not dead-letter"
    );
    assert!(
        published_bin_entries(&fx)
            .iter()
            .all(|entry| entry.node_id != plain.0),
        "the purge drops the entry"
    );
}

#[test]
fn a_purge_stops_at_a_read_granted_folder_it_holds() {
    assert_a_purge_stops_at_a_granted_folder_it_holds(Permission::Read);
}

#[test]
fn a_purge_stops_at_a_write_granted_folder_it_holds() {
    assert_a_purge_stops_at_a_granted_folder_it_holds(Permission::Write);
}

#[test]
fn a_dual_link_tie_moves_with_a_grant_only_under_the_lower_parent_id() {
    assert_grant_and_delete_follow_the_link_rank(1);
}

#[test]
fn a_dual_link_the_granted_folder_loses_stays_in_the_vault_scope() {
    assert_grant_and_delete_follow_the_link_rank(0);
}

#[test]
fn a_write_grant_leaves_a_tied_node_held_outside_at_its_name() {
    assert_write_grant_follows_the_link_rank(1);
}

#[test]
fn a_write_grant_leaves_a_node_whose_granted_link_loses_at_its_name() {
    assert_write_grant_follows_the_link_rank(0);
}

/// A downgrade and then a revoke each cut the write plane of a scope the grant
/// left a held node beside. Both succeed, and the node stays where it was.
#[test]
fn a_downgrade_and_a_revoke_leave_a_held_node_in_the_vault_scope() {
    let mut fx = GrantScenario::new();
    let (keep, deep, _) = dual_linked_at(&mut fx, 0, true, granted_at(Permission::Write));
    let recipient = recipient_identity().verifying_key().to_sec1().to_vec();
    assert_eq!(
        block_on(fx.engine.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: recipient.clone(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done)
    );
    assert_held_in_the_vault_scope(&fx, keep, deep, "after the downgrade");
    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: recipient,
        })),
        Ok(CommandOutcome::Done)
    );
    assert_held_in_the_vault_scope(&fx, keep, deep, "after the revoke");
}

/// The write conversion of an invite link cuts the write plane of a scope the
/// mint left a held node beside, and the node stays where it was.
#[test]
fn a_write_link_conversion_leaves_a_held_node_in_the_vault_scope() {
    let mut fx = GrantScenario::new();
    let (keep, deep, _) = dual_linked_at(&mut fx, 0, true, |fx| {
        let fragment = fx.mint_link_at(Permission::Write);
        fx.post_claims(&fragment, 1);
    });
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_held_in_the_vault_scope(&fx, keep, deep, "after the conversion");
}

/// Another device moves the held node into the granted folder after this
/// device last refreshed: it raises the inside ref above the outside one and
/// drops the outside ref. The grant must not drop the ref that is now the
/// winner. The interior move and the root promotion both refuse with
/// `held-ref-relinked`, never a trust violation, and a retry after a refresh
/// moves the node into the granted scope.
fn assert_a_relinked_ref_refuses_then_moves(via_root: bool) {
    let mut fx = GrantScenario::new();
    let (keep, deep, holder) = if via_root {
        let keep = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "keep");
        let deep = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, keep, "deep");
        let folder = fx.folder;
        dual_link(&mut fx, folder, deep, 0);
        (keep, deep, folder)
    } else {
        dual_linked_at(&mut fx, 0, true, |_| {})
    };
    let case = if via_root { "root" } else { "interior" };
    concurrent_edit(
        &fx.world,
        &fx.blocks,
        holder,
        &read_key_of(holder),
        SCOPE,
        |children| {
            for child in children.iter_mut().filter(|child| child.id == deep.0) {
                child.link_counter = 3;
            }
        },
    );
    concurrent_edit(
        &fx.world,
        &fx.blocks,
        keep,
        &read_key_of(keep),
        SCOPE,
        |children| children.retain(|child| child.id != deep.0),
    );

    // Before the root publish nothing is left behind, so a refresh and a retry
    // recover; after it, the stalled move is owed (ADR 0063 D5).
    if via_root {
        assert_eq!(
            fx.grant_folder_to_recipient(),
            Err(EngineError::Seam {
                message: "grant creation failed: held-ref-relinked".to_owned(),
            }),
            "{case}: the grant refuses the move, never as a trust violation"
        );
    } else {
        assert_eq!(
            fx.grant_folder_to_recipient(),
            Ok(CommandOutcome::Done),
            "{case}: the root landed, so the stalled move is owed"
        );
        assert_eq!(fx.owed_scopes(), vec![fx.folder]);
    }
    if !via_root {
        assert_eq!(
            published_child_names(&fx.world, &fx.blocks, holder, &read_key_of(holder)),
            vec!["deep".to_owned()],
            "{case}: the folder still names the node"
        );
    }

    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(
        fx.grant_folder_to_recipient(),
        Ok(CommandOutcome::Done),
        "{case}: a retry after a refresh succeeds"
    );
    let (override_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    assert!(
        opens_under(&fx, deep, &read_key_under(&override_seed, deep)),
        "{case}: and the node moves into the granted scope"
    );
}

#[test]
fn a_grant_refuses_to_drop_a_ref_relinked_since_its_snapshot() {
    assert_a_relinked_ref_refuses_then_moves(false);
}

#[test]
fn a_promotion_refuses_to_drop_a_ref_relinked_since_its_snapshot() {
    assert_a_relinked_ref_refuses_then_moves(true);
}

/// A held node of another granted scope seals under that scope's keys, and a
/// held scope root is a boundary the grant does not plan. The grant over a
/// folder that holds a losing ref to either still succeeds, drops the ref, and
/// leaves the node in its own scope.
fn assert_a_grant_beside_a_held_node_of_another_scope(held_is_the_scope_root: bool) {
    let mut fx = GrantScenario::new();
    let shared = fx.folder;
    let other = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "other");
    let deep = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, other, "deep");
    fx.folder = other;
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    fx.folder = shared;
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (other_seed, _) = scope_material_of(&fx.world, &fx.blocks, other);

    let held = if held_is_the_scope_root { other } else { deep };
    let inner =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "box");
    dual_link(&mut fx, inner, held, 0);

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let (override_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    assert_eq!(
        published_child_names(
            &fx.world,
            &fx.blocks,
            inner,
            &read_key_under(&override_seed, inner)
        ),
        Vec::<String>::new(),
        "the grant dropped the losing ref"
    );
    assert!(
        published_grant_section(&fx.world, &fx.blocks, other).is_some(),
        "the other scope root still stands"
    );
    assert!(
        opens_under(&fx, deep, &read_key_under(&other_seed, deep)),
        "the node stays sealed in its own scope"
    );
}

#[test]
fn a_grant_beside_a_held_node_of_another_scope_succeeds() {
    assert_a_grant_beside_a_held_node_of_another_scope(false);
}

#[test]
fn a_grant_beside_a_held_scope_root_succeeds() {
    assert_a_grant_beside_a_held_node_of_another_scope(true);
}

/// The grantee reads the granted folder of a held node with no trust
/// violation, and the folder holds no ref the grantee could re-rank.
#[test]
fn a_grantee_reads_a_folder_whose_losing_ref_the_grant_dropped() {
    let mut fx = GrantScenario::new();
    let (_, deep, inner) = dual_linked_at(&mut fx, 0, true, granted_at(Permission::Read));
    let (mut grantee, mut events, mut tasks) = recipient_session(&fx);
    settle(&fx, &grantee, &mut tasks);
    block_on(grantee.command(Command::SetFocus { node: Some(inner) }))
        .expect("the grantee opens the folder");
    settle(&fx, &grantee, &mut tasks);

    let view = block_on(grantee.view()).expect("a rendered view");
    assert!(
        view.children(fx.folder)
            .iter()
            .any(|child| child.id == inner),
        "the grantee renders the granted folder"
    );
    assert!(
        view.children(inner).iter().all(|child| child.id != deep),
        "the held node is not visible to the grantee"
    );
    assert_eq!(abuse_events(&mut events), 0, "and no read is refused");
}

/// ADR 0074 D1: a read grantee that holds no write seed follows the scope
/// pointer to the root a write cut moved to, and sees a write that the owner
/// made after the cut.
#[test]
fn a_personal_read_grantee_reads_the_moved_tree_after_a_write_cut() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.grant_bystander(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let (grantee, mut events, mut tasks) = recipient_session(&fx);
    settle(&fx, &grantee, &mut tasks);
    let before = fx.granted_scope_repoint().current_root;
    assert_eq!(
        fx.revoke_person(&bystander_identity()),
        Ok(CommandOutcome::Done)
    );
    assert_ne!(
        fx.granted_scope_repoint().current_root,
        before,
        "the write cut moved the scope root"
    );
    assert_the_grantee_sees_a_write_after_the_cut(&mut fx, grantee, &mut tasks);
    assert_eq!(abuse_events(&mut events), 0, "and no read is refused");
}

/// ADR 0074 D2: the downgrade posts the share pointer to the downgraded
/// writer, so the writer follows the scope pointer as a read grantee.
#[test]
fn a_downgraded_writer_reads_the_moved_tree_after_its_downgrade() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let (grantee, mut events, mut tasks) = recipient_session(&fx);
    settle(&fx, &grantee, &mut tasks);
    assert_eq!(
        block_on(fx.engine.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done)
    );
    assert_the_grantee_sees_a_write_after_the_cut(&mut fx, grantee, &mut tasks);
    assert_eq!(abuse_events(&mut events), 0, "and no read is refused");
}

/// The owner adds a folder in the granted scope after the cut. The grantee
/// then lists it.
fn assert_the_grantee_sees_a_write_after_the_cut(
    fx: &mut GrantScenario,
    mut grantee: Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
) {
    let added = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "after-the-cut",
    );
    settle(fx, &grantee, tasks);
    block_on(grantee.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the grantee opens the folder");
    settle(fx, &grantee, tasks);
    let view = block_on(grantee.view()).expect("a rendered view");
    assert!(
        view.children(fx.folder)
            .iter()
            .any(|child| child.id == added),
        "the grantee lists the folder the owner added after the cut"
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

#[test]
fn deleting_a_granted_scope_root_refuses_before_any_publish() {
    for permission in [Permission::Read, Permission::Write] {
        for retention in [0, 30] {
            let mut fx = GrantScenario::new();
            assert_eq!(fx.grant_folder_at(permission), Ok(CommandOutcome::Done));
            tick(&fx.world, &fx.engine, &mut fx._tasks);
            block_on(fx.engine.command(Command::SaveVaultSettings {
                settings: VaultSettings {
                    bin_retention_days: retention,
                    ..VaultSettings::default()
                },
            }))
            .expect("the retention choice publishes");
            events_so_far(&mut fx._events);

            let records = || {
                let mut records = Vec::new();
                for endpoint in fx.world.record_store.endpoints() {
                    for name in fx.world.record_store.routing_keys(&endpoint) {
                        let record = fx.world.record_store.record_at(&endpoint, &name);
                        records.push((endpoint.clone(), name, record));
                    }
                }
                records
            };
            let before = records();
            assert_eq!(
                block_on(fx.engine.command(Command::Delete { node: fx.folder })),
                Err(EngineError::UnsupportedTarget {
                    check: "delete-target-is-a-scope-root",
                }),
                "{permission:?}, retention {retention}"
            );
            assert_eq!(records(), before, "the refusal publishes nothing");
            assert_eq!(queued_ops(&fx.owner_device), 0, "no delete is queued");
            for _ in 0..12 {
                tick(&fx.world, &fx.engine, &mut fx._tasks);
            }
            assert_eq!(abuse_events(&mut fx._events), 0);
            assert!(
                block_on(fx.engine.status())
                    .unwrap()
                    .dead_letters
                    .is_empty()
            );
            assert!(published_bin_entries(&fx).is_empty());
            assert!(
                block_on(fx.engine.view())
                    .unwrap()
                    .children(ROOT)
                    .iter()
                    .any(|child| child.id == fx.folder)
            );
        }
    }
}

/// Restarts the owner engine on the same device, before its first boundary walk.
fn restart_owner(fx: &mut GrantScenario) {
    fx._tasks.clear();
    let (engine, events, tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    fx.engine = engine;
    fx._events = events;
    fx._tasks = tasks;
}

fn dead_lettered_as_scope_root(
    events: &[Event],
    op_id: cipherbox_engine::seams::OpId,
    folder: NodeId,
) -> bool {
    events.iter().any(|event| {
        matches!(event,
            Event::DeadLetter { op_id: reported, target, reason: DeadLetterReason::TargetIsScopeRoot }
                if *reported == op_id && *target == Some(folder)
        )
    })
}

/// A held delete is a reported hold on its target, and strict FIFO keeps each
/// later op behind it until a pass proves the target's plane.
#[test]
fn an_offline_delete_of_a_plain_folder_queues_and_waits_for_its_plane() {
    let mut fx = GrantScenario::new();
    let name = write_name(fx.folder);
    restart_owner(&mut fx);
    fx.world.record_store.fail_get_for(name.as_str());
    let op_id = block_on(fx.engine.command(Command::Delete { node: fx.folder }))
        .expect("an offline delete queues before the first boundary walk")
        .op_id()
        .unwrap();
    block_on(fx.engine.command(Command::Create {
        parent: ROOT,
        name: "behind the held delete".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a later create queues");
    let parent_sequence = sequence_at(&fx.world, &write_name(ROOT));
    for _ in 0..16 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let held = Some(QueueHold {
        op_id,
        node: fx.folder,
        reason: QueueHoldReason::DeletePlane,
    });
    assert_eq!(block_on(fx.engine.status()).unwrap().queue_hold, held);
    assert_eq!(block_on(fx.engine.snapshot(ROOT)).unwrap().queue_hold, held);
    assert_eq!(queued_ops(&fx.owner_device), 2, "the later create waits");
    assert_eq!(sequence_at(&fx.world, &write_name(ROOT)), parent_sequence);
    assert!(published_bin_entries(&fx).is_empty());
    assert!(
        block_on(fx.engine.status())
            .unwrap()
            .dead_letters
            .is_empty()
    );
    assert_eq!(abuse_events(&mut fx._events), 0);

    fx.world.record_store.heal_get_for(name.as_str());
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(queued_ops(&fx.owner_device), 0);
    assert_eq!(published_bin_entries(&fx)[0].node_id, fx.folder.0);
    published_child_name(
        &fx.world,
        &fx.blocks,
        &write_name(ROOT),
        &read_key_of(ROOT),
        "behind the held delete",
    );
    assert_eq!(block_on(fx.engine.status()).unwrap().queue_hold, None);
}

fn stage_legacy_folder_delete(fx: &GrantScenario) -> cipherbox_engine::seams::OpId {
    let enc = kdf::enc_subkey(&SECRET);
    let sequence = sequence_at(&fx.world, &write_name(fx.folder));
    block_on(cipherbox_engine::sync::stage_op(
        &fx.owner_device.staging_store,
        cipherbox_engine::sync::RecordSeal {
            owner_enc_secret: &enc,
            ephemeral_scalar: Zeroizing::new([0x6a; 32]),
        },
        &cipherbox_engine::sync::Op::delete(
            fx.folder,
            sequence,
            fx.world.scheduler.now(),
            sequence,
            true,
        ),
    ))
    .expect("the prior release queued the scope-root delete")
}

/// A queued delete of a root the walk names but cannot prove leaves at once,
/// the same as a proved root, and a later op publishes behind it.
#[test]
fn a_restarted_delete_of_a_named_unproved_root_dead_letters() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let op_id = stage_legacy_folder_delete(&fx);
    fx.world
        .record_store
        .fail_get_for(write_name(fx.folder).as_str());

    assert_a_known_root_delete_dead_letters(&mut fx, op_id);
}

/// A root whose record the gate refuses stays in the known set, so its queued
/// delete leaves the same way.
#[test]
fn a_restarted_delete_of_a_refused_root_dead_letters() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let root = fx.granted_scope_repoint().current_root;
    plant_root_at(&fx, &revokee_seed, sequence_at(&fx.world, &root) + 1);
    let op_id = stage_legacy_folder_delete(&fx);

    assert_a_known_root_delete_dead_letters(&mut fx, op_id);
}

/// A kept create under a root the gate refuses landed before the plant. The
/// refused root is no flip, so after a restart the op waits uncharged and
/// leaves at the bound with no dead letter (ADR 0069 D5).
#[test]
fn a_kept_create_under_a_refused_root_shows_no_dead_letter_after_a_restart() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let root = fx.granted_scope_repoint().current_root;
    plant_root_at(&fx, &revokee_seed, sequence_at(&fx.world, &root) + 1);

    restart_owner(&mut fx);
    let before = raw_queue(&fx.owner_device);
    for _ in 0..16 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(
        raw_queue(&fx.owner_device),
        before,
        "the kept ops wait, uncharged"
    );
    fx.world.scheduler.advance(KEPT_OP_BOUND);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(raw_queue(&fx.owner_device), 0, "and leave at the bound");
    let dead = dead_letter_events(&mut fx._events);
    assert!(dead.is_empty(), "a landed create is no failure: {dead:?}");
    assert!(
        block_on(fx.engine.status())
            .expect("the session status reads")
            .dead_letters
            .is_empty()
    );
}

/// The dead-letter notices on `events` since the last read.
fn dead_letter_events(events: &mut EventStream) -> Vec<Event> {
    events_so_far(events)
        .into_iter()
        .filter(|event| matches!(event, Event::DeadLetter { .. }))
        .collect()
}

/// Restarts the owner on the staged delete `op_id`, queues a later create, and
/// asserts the delete dead-letters with its target and the create publishes.
fn assert_a_known_root_delete_dead_letters(
    fx: &mut GrantScenario,
    op_id: cipherbox_engine::seams::OpId,
) {
    restart_owner(fx);
    block_on(fx.engine.command(Command::Create {
        parent: ROOT,
        name: "after the refused delete".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a later create queues");
    for _ in 0..16 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert_eq!(queued_ops(&fx.owner_device), 0);
    let events = events_so_far(&mut fx._events);
    assert!(dead_lettered_as_scope_root(&events, op_id, fx.folder));
    let status = block_on(fx.engine.status()).unwrap();
    let delete: Vec<_> = status
        .dead_letters
        .iter()
        .filter(|dead| dead.op_id == op_id)
        .collect();
    assert_eq!(delete.len(), 1);
    assert_eq!(delete[0].reason, DeadLetterReason::TargetIsScopeRoot);
    assert_eq!(status.queue_hold, None);
    published_child_name(
        &fx.world,
        &fx.blocks,
        &write_name(ROOT),
        &read_key_of(ROOT),
        "after the refused delete",
    );
    assert!(published_bin_entries(fx).is_empty());
    assert_eq!(
        block_on(fx.engine.command(Command::Delete { node: fx.folder })),
        Err(EngineError::UnsupportedTarget {
            check: "delete-target-is-a-scope-root"
        }),
    );
}

#[test]
fn a_delete_probes_a_root_omitted_from_the_index_before_it_bins_anything() {
    assert_unindexed_delete_is_refused(false);
}

#[test]
fn a_delete_probes_a_scope_root_mislabeled_as_a_file() {
    assert_unindexed_delete_is_refused(true);
}

fn assert_unindexed_delete_is_refused(mislabeled: bool) {
    let mut fx = GrantScenario::new();
    let unindexed = published_value(&fx.world, &write_name(ROOT));
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    publish_value_at(&fx.world, ROOT, &unindexed);
    if mislabeled {
        let head = published_head(&fx.world, &fx.blocks, &write_name(ROOT)).unwrap();
        let mut envelope = decode_envelope(&head).unwrap();
        let mut body = open_read_body(&envelope, &read_key_of(ROOT)).unwrap();
        let ReadBody::Folder { children, .. } = &mut body else {
            panic!("a folder body");
        };
        children
            .iter_mut()
            .find(|child| child.id == fx.folder.0)
            .unwrap()
            .kind = CoreNodeKind::File;
        envelope.read_sealed = cipherbox_core::seal::seal_read_body(
            &read_key_of(ROOT),
            &[0x7b; 24],
            envelope.v,
            envelope.id,
            envelope.scope,
            envelope.epoch,
            &body,
        )
        .unwrap()
        .read_sealed;
        let cid = fx.blocks.put(encode_envelope(&envelope).unwrap());
        publish_value_at(&fx.world, ROOT, format!("/ipfs/{cid}").as_bytes());
    }
    let op_id = stage_legacy_folder_delete(&fx);
    restart_owner(&mut fx);
    let parent_sequence = sequence_at(&fx.world, &write_name(ROOT));
    let name = write_name(fx.folder);
    fx.world.record_store.fail_get_for(name.as_str());
    for _ in 0..16 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(queued_ops(&fx.owner_device), 1);
    assert!(
        block_on(fx.engine.status())
            .unwrap()
            .dead_letters
            .is_empty()
    );
    assert!(published_bin_entries(&fx).is_empty());
    assert_eq!(abuse_events(&mut fx._events), 0);
    fx.world.record_store.heal_get_for(name.as_str());
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let events = events_so_far(&mut fx._events);
    assert!(dead_lettered_as_scope_root(&events, op_id, fx.folder));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::AttributableAbuse { .. }))
    );
    let status = block_on(fx.engine.status()).unwrap();
    assert_eq!(status.dead_letters[0].op_id, op_id);
    assert_eq!(
        status.dead_letters[0].reason,
        DeadLetterReason::TargetIsScopeRoot
    );
    assert_eq!(sequence_at(&fx.world, &write_name(ROOT)), parent_sequence);
    assert!(published_bin_entries(&fx).is_empty());
}

/// One endpoint fails and the other serves the folder and its parent from
/// before a grant this device never saw. The plain record still opens under the
/// parent plane, so the delete holds rather than re-keying the granted root.
#[test]
fn a_delete_holds_when_a_failed_endpoint_can_withhold_a_grant() {
    let mut fx = GrantScenario::new();
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let endpoints = fx.world.record_store.endpoints();
    let (failing, serving) = (&endpoints[0], &endpoints[1]);
    let names = [write_name(ROOT), write_name(fx.folder)];
    let before: Vec<Vec<u8>> = names
        .iter()
        .map(|name| {
            fx.world
                .record_store
                .record_at(serving, name.as_str())
                .expect("a published record")
        })
        .collect();
    let op_id = block_on(fx.engine.command(Command::Delete { node: fx.folder }))
        .expect("the delete queues")
        .op_id()
        .unwrap();
    let peer = fx.world.device(b"peer owner device");
    let (mut engine, _events, _tasks) = boot_owner(&fx.world, &fx.blocks, &peer);
    import_recipient(&mut engine);
    assert_eq!(
        block_on(engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );
    for (name, record) in names.iter().zip(&before) {
        fx.world
            .record_store
            .seed_record(serving, name.as_str(), record.clone());
    }
    fx.world.record_store.fail_endpoint(failing);
    for _ in 0..12 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert_eq!(
        block_on(fx.engine.status()).unwrap().queue_hold,
        Some(QueueHold {
            op_id,
            node: fx.folder,
            reason: QueueHoldReason::DeletePlane,
        })
    );
    assert_eq!(queued_ops(&fx.owner_device), 1);
    assert!(published_bin_entries(&fx).is_empty());
    for (name, record) in names.iter().zip(&before) {
        assert_eq!(
            fx.world
                .record_store
                .record_at(serving, name.as_str())
                .as_ref(),
            Some(record),
            "the delete publishes nothing"
        );
    }
}

#[test]
fn a_later_owner_session_refuses_to_delete_a_granted_scope_root() {
    for permission in [Permission::Read, Permission::Write] {
        let mut fx = GrantScenario::new();
        assert_eq!(fx.grant_folder_at(permission), Ok(CommandOutcome::Done));
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        let later = fx.world.device(b"later owner device");
        let (mut engine, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &later);
        tick(&fx.world, &engine, &mut tasks);
        assert_eq!(
            block_on(engine.command(Command::Delete { node: fx.folder })),
            Err(EngineError::UnsupportedTarget {
                check: "delete-target-is-a-scope-root",
            }),
        );
        for _ in 0..12 {
            tick(&fx.world, &engine, &mut tasks);
        }
        assert_eq!(queued_ops(&later), 0);
        assert_eq!(abuse_events(&mut events), 0);
        assert!(block_on(engine.status()).unwrap().dead_letters.is_empty());
        assert!(published_bin_entries(&fx).is_empty());
    }
}

#[test]
fn a_queued_delete_loses_to_a_grant_on_another_owner_device() {
    for permission in [Permission::Read, Permission::Write] {
        let mut fx = GrantScenario::new();
        for _ in 0..4 {
            tick(&fx.world, &fx.engine, &mut fx._tasks);
        }
        let op_id = block_on(fx.engine.command(Command::Delete { node: fx.folder }))
            .expect("the delete queues")
            .op_id()
            .unwrap();
        let peer = fx.world.device(b"peer owner device");
        let (mut engine, _events, _tasks) = boot_owner(&fx.world, &fx.blocks, &peer);
        import_recipient(&mut engine);
        assert_eq!(
            block_on(engine.command(Command::Grant {
                node: fx.folder,
                recipient_identity_public_key:
                    recipient_identity().verifying_key().to_sec1().to_vec(),
                permission,
                grantee_name: None,
            })),
            Ok(CommandOutcome::Done)
        );
        events_so_far(&mut fx._events);
        for _ in 0..12 {
            tick(&fx.world, &fx.engine, &mut fx._tasks);
        }
        assert_eq!(queued_ops(&fx.owner_device), 0);
        let events = events_so_far(&mut fx._events);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::AttributableAbuse { .. }))
        );
        assert!(dead_lettered_as_scope_root(&events, op_id, fx.folder));
        let status = block_on(fx.engine.status()).unwrap();
        assert_eq!(status.dead_letters.len(), 1);
        assert_eq!(status.dead_letters[0].op_id, op_id);
        assert_eq!(
            status.dead_letters[0].reason,
            DeadLetterReason::TargetIsScopeRoot
        );
        assert!(published_bin_entries(&fx).is_empty());
        assert!(
            block_on(fx.engine.view())
                .unwrap()
                .children(ROOT)
                .iter()
                .any(|child| child.id == fx.folder)
        );
    }
}

/// Every retire entry this device sent, as the record it names and its
/// targets.
fn retire_entries(device: &FakeDevice) -> Vec<(Option<String>, Vec<String>)> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/registry/retire"))
        .flat_map(|request| {
            serde_json::from_slice::<Vec<RetireEntry>>(
                request
                    .body
                    .as_deref()
                    .expect("a retire call carries a body"),
            )
            .expect("a retire body is a JSON array of entries")
        })
        .map(|entry| (entry.ipns_name, entry.targets))
        .collect()
}

/// One version of `file` written through the facade.
fn write_version(fx: &mut GrantScenario, target: WriteTarget, body: &[u8]) {
    let handle =
        block_on(fx.engine.begin_write(target, body.len() as u64)).expect("a version write opens");
    block_on(fx.engine.push_chunk(handle, body)).expect("the bytes stage");
    block_on(fx.engine.commit_write(handle)).expect("the version commits");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
}

/// A file with two versions in a write-granted folder, and the name it
/// publishes at: one under the grant's own write seed, which the vault's seed
/// does not derive.
fn file_in_a_write_granted_folder(fx: &mut GrantScenario) -> (NodeId, IpnsName) {
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let folder = fx.folder;
    write_version(
        fx,
        WriteTarget::NewFile {
            parent: folder,
            name: "clip.bin".into(),
        },
        &[1u8; 200],
    );
    let file = block_on(fx.engine.view())
        .expect("a rendered view")
        .children(folder)
        .into_iter()
        .find(|child| child.name == "clip.bin")
        .expect("the file is listed")
        .id;
    write_version(
        fx,
        WriteTarget::Version {
            node: file,
            expected_version: None,
        },
        &[2u8; 200],
    );
    let moved_name = fx.granted_scope_repoint().current_root;
    let section = published_grant_section_at(&fx.world, &fx.blocks, &moved_name)
        .expect("the moved root answers as a scope root");
    let seed = grantee_write_scope_seed(&section, &moved_name, &folder.0, 1);
    let owing = derive_write_name(&seed, &file.0);
    assert_ne!(
        owing,
        write_name(file),
        "the vault's seed does not derive it"
    );
    (file, owing)
}

/// The records each retire entry since `mark` named `target` under.
fn namings_since(device: &FakeDevice, mark: usize, target: &str) -> BTreeSet<Option<String>> {
    retire_entries(device)[mark..]
        .iter()
        .filter(|(_, targets)| targets.iter().any(|sent| sent == target))
        .map(|(record, _)| record.clone())
        .collect()
}

/// The debt of a version that a file in a write-granted folder drops retires
/// under the file's own name, the record that owes it, and settles (ADR 0070
/// D2).
#[test]
fn a_dropped_version_in_a_write_granted_folder_retires_under_the_files_own_name() {
    let mut fx = GrantScenario::new();
    let (file, owing) = file_in_a_write_granted_folder(&mut fx);
    let versions = block_on(fx.engine.file_versions(file)).expect("the history reads");
    assert_eq!(versions.len(), 1, "two writes, one prior version");

    let mark = retire_entries(&fx.owner_device).len();
    block_on(fx.engine.command(Command::DeleteVersion {
        node: file,
        content_cid: versions[0].content_cid.clone(),
    }))
    .expect("the version delete stages");
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert_eq!(
        namings_since(
            &fx.owner_device,
            mark,
            &encode_content_cid_str(&versions[0].content_cid)
        ),
        BTreeSet::from([Some(owing.as_str().to_owned())]),
        "the dropped version retires under the record that owes it"
    );
    assert_eq!(fx.engine.pending_reclaim_bytes(), 0, "the debt settles");
}

/// A version delete journals its debt under the file's own name. The file
/// then moves to another folder of the same scope before the settle, and keeps
/// its name. The settle retires the dropped version under that name, and no
/// CID of the live copy.
#[test]
fn a_debt_journaled_before_a_move_retires_none_of_the_live_copy() {
    let mut fx = GrantScenario::new();
    let (file, owing) = file_in_a_write_granted_folder(&mut fx);
    let folder = fx.folder;
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "inner");
    let versions = block_on(fx.engine.file_versions(file)).expect("the history reads");
    let head = block_on(fx.engine.snapshot(folder))
        .expect("the granted folder opens")
        .children
        .into_iter()
        .find(|child| child.id == file)
        .and_then(|child| child.content_cid)
        .expect("the file has a head");

    fx.blocks.refuse_retire(true);
    block_on(fx.engine.command(Command::DeleteVersion {
        node: file,
        content_cid: versions[0].content_cid.clone(),
    }))
    .expect("the version delete stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        fx.engine.pending_reclaim_bytes() > 0,
        "the debt is journaled and unpaid"
    );
    block_on(fx.engine.command(Command::Move {
        node: file,
        new_parent: inner,
        new_name: "clip.bin".into(),
        replacing: None,
    }))
    .expect("the move stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.engine.view())
            .expect("a rendered view")
            .children(inner)
            .iter()
            .any(|child| child.id == file),
        "the file moved before the settle"
    );

    let mark = retire_entries(&fx.owner_device).len();
    fx.blocks.refuse_retire(false);
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    let entries = &retire_entries(&fx.owner_device)[mark..];
    let head = encode_content_cid_str(&head);
    assert!(
        entries.iter().all(|(_, targets)| !targets.contains(&head)),
        "the live copy's head is never retired"
    );
    assert_eq!(
        namings_since(
            &fx.owner_device,
            mark,
            &encode_content_cid_str(&versions[0].content_cid)
        ),
        BTreeSet::from([Some(owing.as_str().to_owned())]),
        "the dropped version retires under the record that owes it"
    );
    assert_eq!(fx.engine.pending_reclaim_bytes(), 0, "the debt settles");
}

/// A hard delete of a file in a write-granted folder retires its content under
/// the file's own name, the record the delete retires, and under no name the
/// vault's seed derives (ADR 0070 D2).
#[test]
fn a_hard_delete_in_a_write_granted_folder_retires_under_the_files_own_name() {
    let mut fx = GrantScenario::new();
    block_on(fx.engine.command(Command::SaveVaultSettings {
        settings: VaultSettings {
            bin_retention_days: 0,
            ..VaultSettings::default()
        },
    }))
    .expect("the settings publish");
    let (file, owing) = file_in_a_write_granted_folder(&mut fx);
    let head = block_on(fx.engine.snapshot(fx.folder))
        .expect("the granted folder opens")
        .children
        .into_iter()
        .find(|child| child.id == file)
        .and_then(|child| child.content_cid)
        .expect("the file has a head");

    let mark = retire_entries(&fx.owner_device).len();
    block_on(fx.engine.command(Command::Delete { node: file })).expect("the delete stages");
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert_eq!(
        namings_since(&fx.owner_device, mark, &encode_content_cid_str(&head)),
        BTreeSet::from([Some(owing.as_str().to_owned())]),
        "the head retires under the record that owes it"
    );
    assert_eq!(fx.engine.pending_reclaim_bytes(), 0, "the debt settles");
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

/// The scope roots the stream reports owed rotation work at, once each.
fn owed_scopes(events: &mut EventStream) -> Vec<NodeId> {
    let mut scopes: Vec<NodeId> = events_so_far(events)
        .into_iter()
        .filter_map(|event| match event {
            Event::RotationWorkOwed { scope_root, .. } => Some(scope_root),
            _ => None,
        })
        .collect();
    scopes.dedup();
    scopes
}

/// The owed rotation work the stream reports: scope root, check, retryable,
/// class.
fn owed_reports(events: &mut EventStream) -> Vec<(NodeId, String, bool, OwedWorkClass)> {
    events_so_far(events)
        .into_iter()
        .filter_map(|event| match event {
            Event::RotationWorkOwed {
                scope_root,
                detail,
                retryable,
                class,
            } => Some((scope_root, detail, retryable, class)),
            _ => None,
        })
        .collect()
}

/// The abuse descriptions the stream holds.
fn abuse_descriptions(events: &mut EventStream) -> Vec<String> {
    events_so_far(events)
        .into_iter()
        .filter_map(|event| match event {
            Event::AttributableAbuse { description } => Some(description),
            _ => None,
        })
        .collect()
}

/// How many abuse events the stream holds.
fn abuse_events(events: &mut EventStream) -> usize {
    abuse_descriptions(events).len()
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

/// Publish `value` at the name `write_scope_seed` derives for `node`, one
/// sequence past what stands: the record a writer holding that seed can land.
fn publish_value_under(world: &FakeWorld, write_scope_seed: &[u8; 32], node: NodeId, value: &[u8]) {
    let name = derive_write_name(write_scope_seed, &node.0);
    let signer = kdf::ipns_keypair(kdf::write_seed(write_scope_seed, &node.0).as_bytes());
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

/// The crossing a command journals is a plan, not the authority. A session that
/// has run no pass names no boundary below the render root, so the overlay
/// places a queued create under a granted scope root and the move out of it
/// journals as intra-scope. The drain re-derives the crossing from the two
/// planes its own pass proved, so the subtree still re-seals at the destination
/// scope and the source scope still carries its cut.
#[test]
fn a_move_journaled_before_any_walk_verdict_re_seals_and_cuts_at_the_drain() {
    let mut fx = GrantScenario::new();
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let source_before = published_read_epoch(&fx.world, &fx.blocks, fx.folder);

    // The authoring session ends, so nothing it proved carries over.
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    block_on(fresh.command(Command::Create {
        parent: fx.folder,
        name: "note".into(),
        kind: NodeKind::Folder,
    }))
    .expect("the create stages under the granted root");
    let note = block_on(fresh.view())
        .expect("a rendered view")
        .children(fx.folder)
        .into_iter()
        .find(|child| child.name == "note")
        .expect("the overlay places the queued create under the granted root")
        .id;

    assert!(
        matches!(
            block_on(fresh.command(Command::Relink {
                node: note,
                new_parent: album,
            })),
            Ok(CommandOutcome::Queued { .. })
        ),
        "the move queues before any walk has named a boundary"
    );
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Intra],
        "and a boundary this session has not proved reads as no boundary"
    );

    tick(&fx.world, &fresh, &mut tasks);
    tick(&fx.world, &fresh, &mut tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "the pass published the move"
    );
    let (scope, epoch, opened) =
        published_seal(&fx.world, &fx.blocks, &write_name(note), &read_key_of(note));
    assert_eq!(
        (scope, epoch, opened.is_some()),
        (
            ROOT.0,
            published_read_epoch(&fx.world, &fx.blocks, ROOT),
            true
        ),
        "the moved subtree binds the destination scope, not the one it was journaled in"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        source_before + 1,
        "and the scope the move really left carries its cut"
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
    published_write_body(world, blocks, node, write_epoch)
        .direct_child_scope_index
        .into_iter()
        .map(|child| child.scope_id)
        .collect()
}

/// The grant ledger the scope root at `node` publishes at its first write
/// epoch.
fn published_ledger(world: &FakeWorld, blocks: &Blocks, node: NodeId) -> Vec<GrantLedgerEntry> {
    published_write_body(world, blocks, node, 1).grant_ledger
}

/// The write body of the scope root at `node`, opened under the write key the
/// vault root's own seed derives.
fn published_write_body(
    world: &FakeWorld,
    blocks: &Blocks,
    node: NodeId,
    write_epoch: u64,
) -> WriteBody {
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
    decode_write_body(&plaintext).expect("the write body decodes")
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
        seed_account_with(
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
    concurrent_edit(world, blocks, folder, read_key, scope_id, |children| {
        children.push(extra);
    });
}

/// Another writer publishes `folder`'s next record, with `edit` applied to the
/// children the folder currently carries.
fn concurrent_edit(
    world: &FakeWorld,
    blocks: &Blocks,
    folder: NodeId,
    read_key: &[u8; 32],
    scope_id: [u8; 16],
    edit: impl FnOnce(&mut Vec<ChildRef>),
) {
    concurrent_edit_under(
        world,
        blocks,
        folder,
        &WRITE_SCOPE_SEED,
        read_key,
        scope_id,
        edit,
    );
}

/// [`concurrent_edit`] at the name `write_scope_seed` derives for `folder`.
fn concurrent_edit_under(
    world: &FakeWorld,
    blocks: &Blocks,
    folder: NodeId,
    write_scope_seed: &[u8; 32],
    read_key: &[u8; 32],
    scope_id: [u8; 16],
    edit: impl FnOnce(&mut Vec<ChildRef>),
) {
    let name = derive_write_name(write_scope_seed, &folder.0);
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
    edit(&mut children);
    let sequence = sequence_at(world, &name) + 1;
    // One key seals every record of this folder, so each sequence takes its own
    // nonce.
    let mut nonce = [0x77; 24];
    nonce[..8].copy_from_slice(&sequence.to_le_bytes());
    let authored = author_child_envelope(EnvelopeAuthoring {
        node_id: folder.0,
        scope_id,
        epoch: envelope.epoch,
        read_key,
        nonce: &nonce,
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
        &kdf::ipns_keypair(kdf::write_seed(write_scope_seed, &folder.0).as_bytes()),
        format!("/ipfs/{}", authored.cid).as_bytes(),
        sequence,
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
        .fail_floor_raises_for(&floor_label(write_name(fx.folder).as_str().as_bytes()));
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

/// A move whose two ends sit in one granted scope leaves nothing behind, so it
/// owes no cut, even on the vault-root pass that carries that scope as its
/// second end. The pass anchor is not the scope the move stays in.
#[test]
fn a_move_inside_a_granted_folder_on_the_vault_root_pass_cuts_nothing() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    let item =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "item");
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, inner);
    converge_into_granted_scope(&fx, item);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let before = published_read_epoch(&fx.world, &fx.blocks, fx.folder);

    // The head crossing makes the granted scope the vault-root pass's second
    // end, so the move behind it runs on that pass.
    for (node, new_parent) in [(album, fx.folder), (item, inner)] {
        block_on(fx.engine.command(Command::Relink { node, new_parent }))
            .expect("the relocation queues");
    }
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Cross, ScopeCrossing::Intra]
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "both moves published"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before,
        "and the move that stayed inside the granted scope cut nothing"
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
            grantee_name: None,
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

/// Both legs of a staged move are journaled or neither is (ADR 0045 D6). With
/// the arriving leg's journal refused and removal refused too, no cleanup can
/// take the parking leg back, so only a set written as one leaves nothing.
#[test]
fn a_staged_move_whose_arriving_leg_will_not_journal_journals_no_leg() {
    let mut fx = GrantScenario::new();
    let (holiday, album) = two_granted_folders(&mut fx);
    let staging = fx.owner_device.staging_store.inner();
    staging.fail_enqueue_after(1);
    staging.fail_remove_op();

    let refused = block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }));

    assert!(refused.is_err(), "the caller hears that the move failed");
    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "and no leg of it is queued"
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
                grantee_name: None,
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
    let (granted_root, walked, _other) = cut_from_another_device(&fx);

    let album_sequence = sequence_at(&fx.world, &write_name(album));
    let holiday_sequence = sequence_at(&fx.world, &write_name(holiday));
    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move out of the granted scope journals its crossing");
    serve_the_walk_one_cut_behind(&fx, &granted_root, walked);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::ExitsGrantedSource],
        "the superseded end held the op rather than publishing under it"
    );
    assert_eq!(
        (
            sequence_at(&fx.world, &write_name(album)),
            sequence_at(&fx.world, &write_name(holiday)),
        ),
        (album_sequence, holiday_sequence),
        "and neither the moved folder nor its destination republished, so the \
         halt came before the first authoring"
    );
}

/// A crossing re-seals each node at a name whose record can sit above this
/// device's sequence floor: a rotation's sweep publishes without adopting. The
/// publish signs above what the name serves, so the move lands rather than
/// losing the CAS race.
#[test]
fn a_crossing_publishes_above_the_record_a_rotation_left_at_the_destination() {
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
        "the cut re-seals the granted subtree at the name the crossing publishes at"
    );
    let served = sequence_at(&fx.world, &write_name(holiday));

    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move out of the granted scope journals its crossing");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "both legs published"
    );
    assert!(
        sequence_at(&fx.world, &write_name(holiday)) > served,
        "the re-seal signed above the record the name served"
    );
    let (scope, _, opened) = published_seal(
        &fx.world,
        &fx.blocks,
        &write_name(holiday),
        &read_key_of(holiday),
    );
    assert_eq!(
        (scope, opened.is_some()),
        (ROOT.0, true),
        "and the folder now reads in the destination scope"
    );
}

/// A writer at the destination name can serve a record at `u64::MAX`, above
/// which no re-seal can sign. The refusal repeats on every retry, so the move
/// spends its attempt budget and dead-letters rather than holding the queue
/// head for the outage budget.
#[test]
fn a_crossing_with_no_sequence_left_at_the_destination_dead_letters() {
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
    let name = write_name(holiday);
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &holiday.0).as_bytes());
    let exhausted = IpnsRecord::create_v2(
        &signer,
        &published_value(&fx.world, &name),
        u64::MAX,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, name.as_str(), exhausted.clone());
    }

    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("a move out of the granted scope journals its crossing");
    for _ in 0..8 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert!(
        queued_crossings(&fx.owner_device).is_empty(),
        "the attempt budget ends the retries"
    );
    let status = block_on(fx.engine.status()).expect("the session status reads");
    assert_eq!(
        status
            .dead_letters
            .iter()
            .map(|dead| dead.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted],
    );
}

/// A bin re-key re-seals each node at the name it already holds, whose record
/// can sit above this device's sequence floor: a rotation's sweep publishes
/// without adopting. The re-key signs above what the name serves, so the
/// delete lands rather than losing the CAS race.
#[test]
fn a_bin_re_key_publishes_above_the_record_a_rotation_left_at_the_name() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, holiday);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        block_on(fx.engine.command(Command::RotateNow { node: fx.folder })),
        Ok(CommandOutcome::Done),
        "the cut re-seals the granted subtree at the name the re-key publishes at"
    );
    let served = sequence_at(&fx.world, &write_name(holiday));

    block_on(fx.engine.command(Command::Delete { node: holiday })).expect("the delete stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(queued_ops(&fx.owner_device), 0, "the delete left the queue");
    assert!(
        sequence_at(&fx.world, &write_name(holiday)) > served,
        "the re-key signed above the record the name served"
    );
}

/// The bin re-key runs under the same end proof as a crossing: a delete under
/// a second end the record plane moved past publishes nothing.
#[test]
fn a_bin_re_key_under_a_superseded_end_publishes_nothing() {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    converge_into_granted_scope(&fx, holiday);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (granted_root, walked, _other) = cut_from_another_device(&fx);

    let holiday_sequence = sequence_at(&fx.world, &write_name(holiday));
    block_on(fx.engine.command(Command::Delete { node: holiday })).expect("the delete stages");
    serve_the_walk_one_cut_behind(&fx, &granted_root, walked);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(queued_ops(&fx.owner_device), 1, "the delete is held");
    assert_eq!(
        sequence_at(&fx.world, &write_name(holiday)),
        holiday_sequence,
        "and nothing was re-sealed under the superseded end"
    );
}

type Session = (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>);

/// Another owner device cuts the granted scope. Returns the granted root's
/// name, the record this device's walk proved before the cut, and the other
/// device's session.
fn cut_from_another_device(fx: &GrantScenario) -> (IpnsName, Option<Vec<u8>>, Session) {
    let granted_root = write_name(fx.folder);
    let walked = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], granted_root.as_str());
    let (mut other, other_events, other_tasks) = fx.second_owner_device();
    assert_eq!(
        block_on(other.command(Command::RotateNow { node: fx.folder })),
        Ok(CommandOutcome::Done),
        "another device cuts the granted scope"
    );
    (granted_root, walked, (other, other_events, other_tasks))
}

/// The walk's fan-out GET, one per endpoint, still reads the record it proved
/// last tick, so the end it hands the pass is one cut behind the record the
/// end proof reads.
fn serve_the_walk_one_cut_behind(fx: &GrantScenario, root: &IpnsName, walked: Option<Vec<u8>>) {
    fx.world.record_store.serve_gets_for_after(
        root.as_str(),
        0,
        fx.world.record_store.endpoints().len(),
        walked,
    );
}

fn queued_ops(device: &FakeDevice) -> usize {
    block_on(device.pending_ops())
        .expect("the queue reads")
        .len()
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
    .enrol(&RefCell::new(cipherbox_engine::HeldRecords::new()), None);
    let (BinIndexLoad::Resolved(index) | BinIndexLoad::Stale { index, .. }) = load else {
        panic!("the account's bin index reads");
    };
    index.entries
}

/// The scope `node`'s entry is filed under in the account's published bin
/// index, or `None` when the index holds no entry for it.
fn binned_scope(fx: &GrantScenario, node: NodeId) -> Option<[u8; 16]> {
    published_bin_entries(fx)
        .into_iter()
        .find(|entry| entry.node_id == node.0)
        .map(|entry| entry.scope_id)
}

/// A restore re-keys in place under the scope its entry was filed under, so a
/// destination in another scope is refused when the command is given, with its
/// own code, and nothing reaches the queue to dead-letter.
#[test]
fn a_restore_into_a_folder_of_another_scope_is_refused_at_command_time() {
    let mut fx = GrantScenario::new();
    let loose = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "loose");
    block_on(fx.engine.command(Command::Delete { node: loose })).expect("the delete queues");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        block_on(fx.engine.command(Command::Restore {
            node: loose,
            into: Some(fx.folder),
        })),
        Err(EngineError::RestoreCrossesScope),
        "the shared folder is another scope than the vault root the entry names"
    );
    assert_eq!(
        queued_ops(&fx.owner_device),
        0,
        "the refusal stages nothing"
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.engine.status())
            .unwrap()
            .dead_letters
            .is_empty()
    );
    assert!(
        binned_scope(&fx, loose).is_some(),
        "the entry stands for another try"
    );
}

/// The owner shares the folder a node was deleted from after the delete, so
/// that folder is now a scope root and a default restore crosses into it. The
/// refusal is the cross-scope one, and a folder of the entry's own scope still
/// takes the node.
#[test]
fn a_default_restore_into_an_origin_shared_after_the_delete_is_refused() {
    let mut fx = GrantScenario::new();
    let draft = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "draft",
    );
    block_on(fx.engine.command(Command::Delete { node: draft })).expect("the delete queues");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        block_on(fx.engine.command(Command::Restore {
            node: draft,
            into: None,
        })),
        Err(EngineError::RestoreCrossesScope),
        "the origin folder became its own scope after the delete"
    );
    assert!(binned_scope(&fx, draft).is_some());

    block_on(fx.engine.command(Command::Restore {
        node: draft,
        into: Some(ROOT),
    }))
    .expect("a folder of the entry's own scope takes the restore");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(binned_scope(&fx, draft).is_none(), "and the restore lands");
    assert!(
        block_on(fx.engine.view())
            .unwrap()
            .children(ROOT)
            .iter()
            .any(|child| child.id == draft)
    );
}

/// Before the session's first boundary walk lands, the engine knows no scope
/// root below the vault, so it cannot tell where a destination lies. A restore
/// waits for the walk, retryably, rather than queue a crossing or refuse a
/// restore that is in scope.
#[test]
fn a_restore_before_the_first_boundary_walk_is_refused_retryably() {
    let mut fx = GrantScenario::new();
    let loose = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "loose");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let draft = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "draft",
    );
    for node in [loose, draft] {
        block_on(fx.engine.command(Command::Delete { node })).expect("the delete queues");
    }
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        binned_scope(&fx, draft),
        Some(fx.folder.0),
        "the draft's entry is filed under the shared folder's scope"
    );

    let (mut fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    let walk_pending = |outcome: Result<CommandOutcome, EngineError>| {
        matches!(outcome, Err(EngineError::Seam { .. }))
    };
    assert!(
        walk_pending(block_on(fresh.command(Command::Restore {
            node: loose,
            into: Some(fx.folder),
        }))),
        "a crossing is not queued before the walk names the shared folder's scope"
    );
    assert!(
        walk_pending(block_on(fresh.command(Command::Restore {
            node: draft,
            into: None,
        }))),
        "an in-scope restore is not refused as a crossing before the walk"
    );
    assert_eq!(queued_ops(&fx.owner_device), 0);

    tick(&fx.world, &fresh, &mut tasks);
    assert_eq!(
        block_on(fresh.command(Command::Restore {
            node: loose,
            into: Some(fx.folder),
        })),
        Err(EngineError::RestoreCrossesScope)
    );
    assert!(matches!(
        block_on(fresh.command(Command::Restore {
            node: draft,
            into: None,
        })),
        Ok(CommandOutcome::Queued { .. })
    ));
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

#[test]
fn an_interrupted_bin_delete_waits_for_its_interior_scope_pass() {
    interrupted_bin_delete_across_passes(true);
}

#[test]
fn an_interrupted_vault_bin_delete_is_not_abandoned_by_an_interior_pass() {
    interrupted_bin_delete_across_passes(false);
}

fn interrupted_bin_delete_across_passes(interior: bool) {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let source = if interior { fx.folder } else { ROOT };
    let parent =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, source, "parent");
    let doomed =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, parent, "doomed");
    let leaf = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, doomed, "leaf");
    block_on(fx.engine.command(Command::SetFocus { node: Some(parent) })).unwrap();
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (seed, _) = if interior {
        scope_material_of(&fx.world, &fx.blocks, fx.folder)
    } else {
        (Zeroizing::new(READ_SCOPE_SEED), EPOCH)
    };
    let scope_id = if interior { fx.folder.0 } else { SCOPE };
    fx.blocks.refuse_upload(Box::new(move |block| {
        decode_envelope(block)
            .ok()
            .filter(|envelope| envelope.id == leaf.0)
            .map(|_| {
                Err(cipherbox_engine::seams::SeamError::new(
                    "interrupted re-key",
                ))
            })
    }));
    block_on(fx.engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let entries = published_bin_entries(&fx);
    let entry = entries
        .iter()
        .find(|entry| entry.node_id == doomed.0)
        .unwrap();
    assert_eq!(entry.scope_id, scope_id);
    let held = BinIndexKeys::derive(&SECRET).held_key(&doomed.0, entry.deleted_at);
    let head = published_head(&fx.world, &fx.blocks, &write_name(parent)).unwrap();
    let envelope = decode_envelope(&head).unwrap();
    let authored = author_child_envelope(EnvelopeAuthoring {
        node_id: parent.0,
        scope_id,
        epoch: envelope.epoch,
        read_key: &node_read_key(&seed, parent),
        nonce: &[0x77; 24],
        body: &ReadBody::Folder {
            created_at: 0,
            modified_at: 1,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        },
        carried_unknown: envelope.unknown,
        carried_epoch_tag_unknown: envelope.epoch_tag_unknown,
    })
    .unwrap();
    fx.blocks.put(authored.block);
    publish_value_at(
        &fx.world,
        parent,
        format!("/ipfs/{}", authored.cid).as_bytes(),
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.engine.status())
            .unwrap()
            .dead_letters
            .is_empty()
    );
    assert!(!block_on(fx.owner_device.pending_ops()).unwrap().is_empty());
    fx.blocks.refuse_upload(Box::new(|_| None));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.engine.status())
            .unwrap()
            .dead_letters
            .is_empty()
    );
    assert!(block_on(fx.owner_device.pending_ops()).unwrap().is_empty());
    for node in [doomed, leaf] {
        assert!(
            published_seal(
                &fx.world,
                &fx.blocks,
                &write_name(node),
                &node_read_key(&held, node)
            )
            .2
            .is_some()
        );
        assert!(
            published_seal(
                &fx.world,
                &fx.blocks,
                &write_name(node),
                &node_read_key(&seed, node)
            )
            .2
            .is_none()
        );
    }
    block_on(fx.engine.command(Command::Restore {
        node: doomed,
        into: Some(parent),
    }))
    .unwrap();
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        published_bin_entries(&fx)
            .iter()
            .all(|entry| entry.node_id != doomed.0)
    );
    assert!(
        published_seal(
            &fx.world,
            &fx.blocks,
            &write_name(leaf),
            &node_read_key(&seed, leaf)
        )
        .2
        .is_some()
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

/// The overtaken relink of [`a_relink_the_grant_overtook_still_re_seals_and_cuts`],
/// with the device stopped after the source-remove confirms and before the
/// crossing commits. Answers the granted scope's read epoch before the stop.
/// The caller boots the device again with [`resume`].
fn stop_an_overtaken_relink_before_its_commit() -> (GrantScenario, u64) {
    let mut fx = GrantScenario::new();
    let holiday = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "holiday",
    );
    let album = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "album");
    block_on(fx.engine.command(Command::Relink {
        node: holiday,
        new_parent: album,
    }))
    .expect("an intra-scope relink queues");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Intra],
        "the grant leaves the relink queued as it was journaled"
    );
    converge_into_granted_scope(&fx, holiday);
    let before = published_read_epoch(&fx.world, &fx.blocks, fx.folder);

    let mark = owner_scoped_key(PUBLISHED_OP_MARK_PREFIX, &kdf::enc_subkey(&SECRET));
    let staging = fx.owner_device.staging_store.inner();
    staging.park_after_staged_write(&mark);
    for _ in 0..2 {
        if !staging.holds_parked_write() {
            tick(&fx.world, &fx.engine, &mut fx._tasks);
        }
    }
    assert!(
        staging.holds_parked_write(),
        "the source-remove confirmed and the pass stopped at its mark"
    );
    // The stop: the pass and its session go.
    fx._tasks.clear();
    staging.release_parked_write();
    (fx, before)
}

/// Boot the stopped device again.
fn resume(fx: &mut GrantScenario) -> EventStream {
    let (engine, events, tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    fx.engine = engine;
    fx._tasks = tasks;
    events
}

/// Whether the device's raw queue still holds a relocation. The published-op
/// mark hides a published op from [`FakeDevice::pending_ops`], so this reads
/// the queue itself.
fn relink_queued(device: &FakeDevice) -> bool {
    let raw = block_on(device.staging_store.queued_ops()).expect("the queue reads");
    decode_queue(&RecordReader::new(&kdf::enc_subkey(&SECRET)), &raw)
        .mine
        .iter()
        .any(|(_, op)| op.relocation().is_some())
}

/// Whether `events` told the member that `scope_root` still owes a cut.
fn tells_cut_owed(events: &mut EventStream, scope_root: NodeId) -> bool {
    events_so_far(events).iter().any(|event| {
        matches!(event, Event::ScopeExitCutOwed { scope_root: owed, .. } if *owed == scope_root)
    })
}

/// On resume the op leaves the queue with no publish left to prove the planes
/// from, so the crossing is derived again from the scope roots the resumed
/// session lists.
#[test]
fn a_relink_the_grant_overtook_still_cuts_after_a_stop_before_its_commit() {
    let (mut fx, before) = stop_an_overtaken_relink_before_its_commit();
    assert!(
        relink_queued(&fx.owner_device),
        "the stop left the relink queued"
    );
    resume(&mut fx);
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before,
        "the stop came before the cut"
    );

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "later");
    assert!(
        !relink_queued(&fx.owner_device),
        "the resumed session dropped the published relink"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before + 1,
        "and still cut the scope it left"
    );
}

/// A cut an earlier session owed and could not land stands in the durable
/// record. The resumed session owes the relink's cut before any settle reads
/// that record, and the earlier debt must survive the write.
#[test]
fn an_earlier_sessions_owed_cut_survives_a_resumed_relinks_cut() {
    const EARLIER: NodeId = NodeId([0x9d; 16]);
    let (mut fx, before) = stop_an_overtaken_relink_before_its_commit();
    let enc_secret = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(77));
    let sealed = seal_owed_cuts(
        BookkeepingSeal::new(&enc_secret, &entropy),
        &BTreeSet::from([EARLIER]),
    )
    .expect("the debt seals");
    block_on(
        fx.owner_device
            .staging_store
            .put_staged_bytes(&scope_exit_debt_key(&enc_secret), &sealed),
    )
    .expect("the debt persists");

    let mut events = resume(&mut fx);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before + 1,
        "the relink's cut landed"
    );
    assert!(
        tells_cut_owed(&mut events, EARLIER),
        "and the earlier debt is still owed"
    );
}

/// The op is the only thing that names the cut until the debt is durable, so a
/// refused debt write keeps it queued for the next pass, and an op that drains
/// past it in the meantime must not carry the drained mark over it.
#[test]
fn a_refused_debt_write_keeps_the_resumed_relink_queued() {
    let (mut fx, before) = stop_an_overtaken_relink_before_its_commit();
    let debt = scope_exit_debt_key(&kdf::enc_subkey(&SECRET));
    let staging = fx.owner_device.staging_store.inner().clone();
    assert!(
        relink_queued(&fx.owner_device),
        "the stop left the relink queued"
    );
    staging.fail_staged_writes_at(&debt);

    resume(&mut fx);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        relink_queued(&fx.owner_device),
        "the refused write kept the relink queued"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before,
        "and owed no cut that is not durable"
    );
    // The kept ops around the relink expire, and a later rename publishes and
    // leaves while the write is still refused, so the drained mark reaches as
    // far as the relink lets it.
    let later = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "later");
    fx.world.scheduler.advance(KEPT_OP_BOUND);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    block_on(fx.engine.command(Command::Rename {
        node: later,
        new_name: "renamed".into(),
    }))
    .expect("the rename queues");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        relink_queued(&fx.owner_device),
        "the relink outlived the ops around it"
    );

    staging.heal_staged_writes();
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        !relink_queued(&fx.owner_device),
        "the next pass owed the cut and dropped it"
    );
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before + 1,
        "and the cut landed"
    );
}

/// A boundary the resumed session knows but has not proved still owes its cut:
/// owing one needs only the boundary, and the cut waits for the material.
#[test]
fn a_resumed_relink_out_of_an_unproved_scope_still_owes_its_cut() {
    let (mut fx, before) = stop_an_overtaken_relink_before_its_commit();
    let source = write_name(fx.folder);
    fx.world.record_store.fail_get_for(source.as_str());

    let mut events = resume(&mut fx);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        tells_cut_owed(&mut events, fx.folder),
        "the cut is owed while the scope is unproved"
    );

    fx.world.record_store.heal_get_for(source.as_str());
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        before + 1,
        "and lands once the scope is proved"
    );
}

/// The crossing every relocation on this device's durable queue carries, in
/// queue order.
fn queued_crossings(device: &FakeDevice) -> Vec<ScopeCrossing> {
    let raw = block_on(device.pending_ops()).expect("the queue reads");
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

/// A live scope root the index lost commits the grant that minted it, and the
/// move it stalled in is owed. A share of the same folder to another recipient
/// finishes that grant first (ADR 0063 D5), so the second recipient is
/// appended to a scope that stands rather than grafted onto a stalled one.
#[test]
fn a_share_to_another_recipient_over_a_scope_the_index_lost_finishes_it_then_appends() {
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
                grantee_name: None,
            })
        ),
        Ok(CommandOutcome::Done),
    );
    let section =
        published_grant_section(&fx.world, &fx.blocks, fx.folder).expect("the scope still answers");
    assert!(
        stranded_override_seed(&section, fx.folder) == stranded_override_seed(&stranded, fx.folder),
        "the first grant finished against the root it promoted"
    );
    assert_eq!(
        section.commitment.entries.len(),
        2,
        "and the second recipient is appended to it"
    );
    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        write_name(fx.folder).as_str().as_bytes(),
        "the first grant's owed delivery landed"
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
    assert_eq!(
        fx.grant_folder_to_recipient(),
        Ok(CommandOutcome::Done),
        "the parent index update fails, so the scope goes live unnamed and its move is owed"
    );
    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());

    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: inner,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "enclosing-scope-index-lost-a-root"
        }),
    );
}

/// The derived-name probe asks only whether a live scope root answers there.
/// A scope pointer the owner access would refuse, here one below this device's
/// write-epoch floor, must not turn that root into "no scope here" and let the
/// share anchor a level up.
#[test]
fn an_unindexed_scope_probe_does_not_read_a_refused_pointer_as_no_scope() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "in");
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    assert_eq!(
        fx.grant_folder_to_recipient(),
        Ok(CommandOutcome::Done),
        "the parent index update fails, so the scope goes live unnamed and its move is owed"
    );
    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());
    let vouched = fx.granted_scope_repoint().write_epoch;
    block_on(floor::advance_write_epoch_on_sight(
        &fx.owner_device.floors(&SECRET),
        &fx.folder.0,
        vouched + 1,
    ))
    .expect("the floor store answers");
    let inner_before = sequence_at(&fx.world, &write_name(inner));

    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: inner,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "enclosing-scope-index-lost-a-root"
        }),
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(inner)),
        inner_before,
        "no scope root was minted over the inner folder"
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
            check: "grant-target-index-lost-a-root"
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
            grantee_name: None,
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
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.owed_scopes(),
        vec![fx.folder],
        "the interior move is owed"
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
        assert_eq!(
            fx.grant_folder_to_recipient(),
            Ok(CommandOutcome::Done),
            "drive {drive} stalls in the interior move, which stays owed"
        );
        assert_eq!(fx.owed_scopes(), vec![fx.folder]);
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

    // The promoted root is already on the network, so the move it stalled in
    // and the delivery after it are owed (ADR 0063 D5).
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(fx.owed_scopes(), vec![fx.folder]);
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
    let reported = abuse_descriptions(&mut events);
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

/// The labels the sharing read gives each committed row at `node`.
fn sharing_labels(engine: &Engine<FakeSeamTypes>, node: NodeId) -> Vec<Vec<u8>> {
    block_on(engine.sharing(node))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved")
        .grants
        .into_iter()
        .map(|grant| grant.recipient_identity_public_key)
        .collect()
}

/// A write grantee's row with the label it rewrote, over the recipient the
/// owner granted.
fn relabelled_write_row() -> GrantRow {
    let mut row = recipient_row_at_root(CorePermission::Write);
    row.ledger_entry.recipient_identity_pk = [0x11; IDENTITY_PUBLIC_LEN];
    row
}

/// ADR 0025 D3: a write grantee authors the ledger, so it can rewrite the
/// label of its own row. The revoke reaches the row through the owner's own
/// commitment, as the sharing read names it, and cuts no row it does not name.
#[test]
fn a_revoke_reaches_a_row_its_writer_relabelled() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_vault(
        &world,
        &blocks,
        vec![relabelled_write_row(), bystander_row_with_corrupt_sig()],
    );
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    let honest = recipient_identity().verifying_key().to_sec1().to_vec();
    assert!(sharing_labels(&engine, ROOT).contains(&honest));

    assert_eq!(
        block_on(engine.command(Command::Revoke {
            node: ROOT,
            recipient_identity_public_key: honest,
        })),
        Ok(CommandOutcome::Done)
    );
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        sharing_labels(&engine, ROOT),
        vec![vec![0u8; IDENTITY_PUBLIC_LEN]],
        "the relabelled row is cut, and the bystander row no contact names stays"
    );
}

/// ADR 0025 D1: `remove_grantees` takes a row that names the link even when
/// its writer broke the owner's signature over it.
#[test]
fn a_link_revoke_with_remove_grantees_takes_a_row_its_writer_relabelled() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let link = invite_link_at_root(0x4e);
    let mut joined = relabelled_write_row();
    joined.ledger_entry.via_link = Some(link.tag);
    seed_vault(
        &world,
        &blocks,
        vec![link, joined, bystander_row_with_corrupt_sig()],
    );
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink {
            node: ROOT,
            link_tag: None,
            remove_grantees: true,
        })),
        Ok(CommandOutcome::Done)
    );
    tick(&world, &engine, &mut tasks);

    let state = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the vault root resolved");
    assert!(state.invite_links.is_empty(), "the link is cut");
    assert_eq!(
        state
            .grants
            .into_iter()
            .map(|grant| grant.recipient_identity_public_key)
            .collect::<Vec<_>>(),
        vec![vec![0u8; IDENTITY_PUBLIC_LEN]],
        "with the row that joined through it, and not the bystander row"
    );
}

/// ADR 0025 D1: a write grantee that joined through a link and then stripped
/// the via-link reference from its own row breaks the owner's signature over
/// it. The owner's contact book still names the link that sourced the
/// grantee, so `remove_grantees` still takes the row. A direct grantee stays.
#[test]
fn a_link_revoke_with_remove_grantees_takes_a_row_whose_via_link_its_writer_stripped() {
    revoke_a_link_over_a_stripped_row(false);
}

/// A write downgrade drives a wave at the vault root. The wave moves the link
/// tag, and it re-mints the stripped row as an owner-signed row with no label.
/// A revoke with `remove_grantees` still takes that row.
#[test]
fn a_link_revoke_with_remove_grantees_takes_a_stripped_row_a_write_wave_re_minted() {
    revoke_a_link_over_a_stripped_row(true);
}

/// Seed the vault root with the link `0x4e`, a write row that joined through
/// it and then stripped its via-link reference, and a direct write grantee.
/// The book records the stripped row's grantee under the link. With `wave`, a
/// downgrade of the direct grantee drives a write wave first. Then revoke the
/// link with `remove_grantees`: the stripped row goes, and the direct grantee
/// stays.
fn revoke_a_link_over_a_stripped_row(wave: bool) {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let link = invite_link_at_root(0x4e);
    let link_tag = link.tag;
    let mut stripped = recipient_row_at_root(CorePermission::Write);
    stripped.ledger_entry.via_link = Some(link_tag);
    stripped.ledger_entry.owner_sig = cipherbox_core::seal::sign_recipient_binding(
        &owner_identity(),
        write_name(ROOT).as_str().as_bytes(),
        &stripped.ledger_entry,
    )
    .to_compact();
    stripped.ledger_entry.via_link = None;
    let bystander = EcdsaSigner::from_scalar(&BYSTANDER_SECRET).expect("valid identity scalar");
    let direct = mint_grant_row(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        &owner_pointer_read_key(),
        bystander.verifying_key().to_sec1(),
        &kdf::enc_subkey(&BYSTANDER_SECRET).public(),
        &SCOPE,
        write_name(ROOT).as_str().as_bytes(),
        CorePermission::Write,
    )
    .expect("a contributory recipient key");
    let seeded_root = seed_vault(&world, &blocks, vec![link, stripped, direct]);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let book = StagingContactStore::new(&alice.staging_store, &enc_subkey, &entropy);
    block_on(book.record_from_link(
        &contact_code(&RECIPIENT_SECRET),
        &committed_link_at(0x4e, link_tag),
        &SCOPE,
    ))
    .expect("the conversion records the grantee under the link");
    if wave {
        block_on(engine.command(Command::ImportContact {
            contact_code: contact_code(&BYSTANDER_SECRET),
        }))
        .expect("the direct grantee's code imports");
        assert_eq!(
            block_on(engine.command(Command::ChangePermission {
                node: ROOT,
                recipient_identity_public_key: bystander.verifying_key().to_sec1().to_vec(),
                permission: Permission::Read,
            })),
            Ok(CommandOutcome::Done)
        );
        assert_ne!(scope_repoint(&world, &SCOPE).current_root, seeded_root);
        tick(&world, &engine, &mut tasks);
    }
    let links = |engine: &Engine<FakeSeamTypes>| {
        block_on(engine.sharing(ROOT))
            .expect("a sharing read")
            .state
            .expect("the vault root resolved")
            .invite_links
    };
    let [listed] = <[SharingInviteLink; 1]>::try_from(links(&engine)).expect("one link");
    assert_eq!(
        listed.tag != link_tag,
        wave,
        "only the wave moves the link tag"
    );

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink {
            node: ROOT,
            link_tag: None,
            remove_grantees: true,
        })),
        Ok(CommandOutcome::Done)
    );
    tick(&world, &engine, &mut tasks);

    assert!(links(&engine).is_empty(), "the link is cut");
    assert_eq!(
        block_on(engine.sharing(ROOT))
            .expect("a sharing read")
            .state
            .expect("the vault root resolved")
            .grants
            .into_iter()
            .map(|grant| grant.recipient_identity_public_key)
            .collect::<Vec<_>>(),
        vec![bystander.verifying_key().to_sec1().to_vec()],
        "the stripped row leaves with the link, and the direct grantee stays"
    );
}

/// A claim through a second link that grants nothing admits no one, so the
/// contact keeps the link that admitted it. A revoke of the second link with
/// `remove_grantees` keeps the person, and a revoke of the first link cuts
/// the person.
#[test]
fn a_claim_that_grants_nothing_leaves_the_person_with_the_link_that_admitted_it() {
    let mut fx = GrantScenario::new();
    let first = fx.mint_link();
    let [first_link] = <[SharingInviteLink; 1]>::try_from(folder_links(&fx)).expect("one link");
    let person = fx.post_claimant(&first, 0, 0);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let second = fx.mint_link();
    let second_link = folder_links(&fx)
        .into_iter()
        .find(|link| link.tag != first_link.tag)
        .expect("the second link");
    assert_eq!(fx.post_claimant(&second, 0, 1), person);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(
        inbox(&fx.owner_device).is_empty(),
        "the second claim converted"
    );

    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let book = StagingContactStore::new(&fx.owner_device.staging_store, &enc_subkey, &entropy);
    let source = block_on(book.contacts_with_sources())
        .expect("the book opens")
        .into_iter()
        .find(|(contact, _)| contact.identity_pk().to_sec1().to_vec() == person)
        .and_then(|(_, source)| source);
    assert!(
        source.is_some_and(|source| source.names(&minted_link(&first, &first_link))),
        "the contact stays with the link that admitted it"
    );

    let revoke = |fx: &mut GrantScenario, tag: &[u8]| {
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: Some(tag.to_vec()),
            remove_grantees: true,
        }))
    };
    assert_eq!(revoke(&mut fx, &second_link.tag), Ok(CommandOutcome::Done));
    assert!(
        fx.granted_to().contains(&person),
        "the person keeps access past the second link's revoke"
    );
    assert_eq!(revoke(&mut fx, &first_link.tag), Ok(CommandOutcome::Done));
    assert!(
        !fx.granted_to().contains(&person),
        "the first link's revoke cuts the person"
    );
}

/// A key change is a revoke and a re-grant by the owner. A claim from a known
/// identity under another encryption subkey is refused with
/// `claim-recipient-key-changed` on the link it came through, and the book
/// keeps the subkey the revoke fallback reaches the old rows by.
#[test]
fn a_claim_under_a_rotated_key_is_refused_and_the_book_keeps_the_old_key() {
    let mut fx = GrantScenario::new();
    let first = fx.mint_link();
    let [first_link] = <[SharingInviteLink; 1]>::try_from(folder_links(&fx)).expect("one link");
    let person = fx.post_claimant(&first, 0, 0);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let second = fx.mint_link();
    let second_refused = |fx: &GrantScenario| {
        folder_links(fx)
            .into_iter()
            .find(|link| link.tag != first_link.tag)
            .expect("the second link")
            .refused_claims
    };
    assert_eq!(second_refused(&fx), 0);

    let opened = InviteFragment::decode(&second).expect("the mint's own fragment");
    let scalar = [CLAIMANT_SCALAR_BASE; 32];
    let identity = EcdsaSigner::from_scalar(&scalar).expect("valid identity scalar");
    let rotated = kdf::enc_subkey(&[0x3d; 32]).public();
    fx.post_claim(
        &import_contact(&opened.owner_contact_code).expect("the owner bundle verifies"),
        &EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret"),
        1,
        &InviteClaim {
            claim_id: [0x2c; CLAIM_ID_LEN],
            scope_pointer_name: opened.scope_pointer_name.clone(),
            contact_code: ContactCode::create(&identity, rotated).encode(),
            name: String::new(),
        },
        "claim-rotated",
    );
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_eq!(
        second_refused(&fx),
        1,
        "the claim shows as refused on its link"
    );

    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let book = StagingContactStore::new(&fx.owner_device.staging_store, &enc_subkey, &entropy);
    let held = block_on(book.contacts_with_sources())
        .expect("the book opens")
        .into_iter()
        .find(|(contact, _)| contact.identity_pk().to_sec1().to_vec() == person)
        .expect("the book holds the person");
    assert_eq!(
        held.0.enc_subkey().to_bytes(),
        kdf::enc_subkey(&scalar).public().to_bytes(),
        "the book keeps the old subkey"
    );
    assert!(
        held.1
            .is_some_and(|source| source.names(&minted_link(&first, &first_link)))
    );

    assert_eq!(fx.revoke_person(&person), Ok(CommandOutcome::Done));
    assert!(
        !fx.granted_to().contains(&person),
        "the revoke reaches the old row"
    );
}

/// A claim that would grant a new row to a known identity under another
/// encryption subkey is refused with `claim-recipient-key-changed`, and grants
/// nothing: the book keeps the subkey a revoke reaches the old rows by.
#[test]
fn a_claim_that_would_grant_under_a_rotated_key_is_refused() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let scalar = [CLAIMANT_SCALAR_BASE; 32];
    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&scalar),
    }))
    .expect("the owner imports the person by hand");
    let identity = EcdsaSigner::from_scalar(&scalar).expect("valid identity scalar");
    let person = identity.verifying_key().to_sec1().to_vec();

    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    fx.post_claim(
        &import_contact(&opened.owner_contact_code).expect("the owner bundle verifies"),
        &EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret"),
        0,
        &InviteClaim {
            claim_id: [0x2d; CLAIM_ID_LEN],
            scope_pointer_name: opened.scope_pointer_name.clone(),
            contact_code: ContactCode::create(&identity, kdf::enc_subkey(&[0x3d; 32]).public())
                .encode(),
            name: String::new(),
        },
        "claim-rotated",
    );
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert!(
        !fx.granted_to().contains(&person),
        "the claim grants nothing"
    );
    let [link] = <[SharingInviteLink; 1]>::try_from(folder_links(&fx)).expect("one link");
    assert_eq!(link.refused_claims, 1, "the claim shows as refused");
}

/// A hand import of a rotated code keeps the former subkey, so a person
/// revoke still reaches a row granted under it whose label the owner does not
/// attest, and the row under the new subkey in the same cut.
#[test]
fn a_person_revoke_after_a_rotated_re_import_cuts_the_row_under_the_former_subkey() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let mut stripped = recipient_row_at_root(CorePermission::Read);
    stripped.ledger_entry.owner_sig[0] ^= 0xff;
    let rotated = kdf::enc_subkey(&[0x3d; 32]).public();
    let current = mint_grant_row(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        &owner_pointer_read_key(),
        recipient_identity().verifying_key().to_sec1(),
        &rotated,
        &SCOPE,
        write_name(ROOT).as_str().as_bytes(),
        CorePermission::Read,
    )
    .expect("a contributory recipient key");
    seed_vault(&world, &blocks, vec![stripped, current]);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    block_on(engine.command(Command::ImportContact {
        contact_code: ContactCode::create(&recipient_identity(), rotated).encode(),
    }))
    .expect("the rotated code imports");

    assert_eq!(
        block_on(engine.command(Command::Revoke {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Ok(CommandOutcome::Done)
    );
    tick(&world, &engine, &mut tasks);

    assert!(
        block_on(engine.sharing(ROOT))
            .expect("a sharing read")
            .state
            .expect("the vault root resolved")
            .grants
            .is_empty(),
        "both rows leave in one revoke"
    );
}

/// A claim may carry a contact code that binds the former subkey of another
/// identity. The book refuses it, so a link revoke with `remove_grantees`
/// keeps the row the other identity holds under that subkey without an
/// attested label.
#[test]
fn a_link_revoke_keeps_a_row_under_a_subkey_another_identity_bound_before() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let link = invite_link_at_root(0x4e);
    let link_tag = link.tag;
    let mut stripped = recipient_row_at_root(CorePermission::Read);
    stripped.ledger_entry.owner_sig[0] ^= 0xff;
    seed_vault(&world, &blocks, vec![link, stripped]);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    block_on(
        engine.command(Command::ImportContact {
            contact_code: ContactCode::create(
                &recipient_identity(),
                kdf::enc_subkey(&[0x3d; 32]).public(),
            )
            .encode(),
        }),
    )
    .expect("the rotated code imports");
    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let book = StagingContactStore::new(&alice.staging_store, &enc_subkey, &entropy);
    let bystander = EcdsaSigner::from_scalar(&BYSTANDER_SECRET).expect("valid identity scalar");
    let recorded = block_on(book.record_from_link(
        &ContactCode::create(&bystander, kdf::enc_subkey(&RECIPIENT_SECRET).public()).encode(),
        &committed_link_at(0x4e, link_tag),
        &SCOPE,
    ));

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink {
            node: ROOT,
            link_tag: None,
            remove_grantees: true,
        })),
        Ok(CommandOutcome::Done)
    );
    tick(&world, &engine, &mut tasks);

    let state = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the vault root resolved");
    assert!(state.invite_links.is_empty(), "the link is cut");
    assert_eq!(state.grants.len(), 1, "the row of the other identity stays");
    assert!(
        matches!(recorded, Err(ContactStoreError::RecipientKeyChanged)),
        "the book refuses a subkey another identity bound before"
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
        block_on(engine.command(Command::ChangePermission {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done),
        "the write cut drives the wave that re-mints the set"
    );

    let reported = abuse_descriptions(&mut events);
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
/// holds is named by. The book refuses that code, so the committed key of the
/// row still names the one contact the owner imported.
#[test]
fn a_contact_code_that_binds_the_subkey_of_another_contact_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let mut poisoned = recipient_row_at_root(CorePermission::Write);
    poisoned.ledger_entry.recipient_identity_pk = [0x11; IDENTITY_PUBLIC_LEN];
    seed_vault(&world, &blocks, vec![poisoned]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    import_recipient(&mut engine);
    let impostor = EcdsaSigner::from_scalar(&BYSTANDER_SECRET).expect("valid identity scalar");
    assert!(matches!(
        block_on(
            engine.command(Command::ImportContact {
                contact_code: ContactCode::create(
                    &impostor,
                    kdf::enc_subkey(&RECIPIENT_SECRET).public()
                )
                .encode(),
            })
        ),
        Err(EngineError::TrustViolation { .. })
    ));

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
        "the committed key names the contact the owner imported"
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
    assert_eq!(plain.invite_links, Vec::new());

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
            grantee_name: None,
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
            owner_name: String::new(),
            admission_cap: None,
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

/// The one link the sharing read reports at a scope carrying `link`.
fn listed_link(link: &GrantRow, expires_at: UnixMillis, expired: bool) -> Vec<SharingInviteLink> {
    vec![SharingInviteLink {
        tag: link.tag.to_vec(),
        permission: Permission::Read,
        expires_at,
        expired,
        admission_cap: DEFAULT_ADMISSION_CAP,
        pending_claims: 0,
        contact_budget_full: false,
        refused_claims: 0,
    }]
}

/// The details dialog shows a node's `ipnsName` off the snapshot row: the name
/// its parent's child reference carries, which is the node's write name.
#[test]
fn a_snapshot_row_carries_the_ipns_name_of_a_published_child() {
    let mut fx = GrantScenario::new();
    block_on(fx.engine.command(Command::Create {
        parent: ROOT,
        name: "notes.txt".into(),
        kind: NodeKind::File,
    }))
    .expect("a metadata create stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let children = block_on(fx.engine.snapshot(ROOT))
        .expect("the root lists")
        .children;
    let file = children
        .iter()
        .find(|child| child.kind == NodeKind::File)
        .expect("the file is listed");
    let folder = children
        .iter()
        .find(|child| child.id == fx.folder)
        .expect("the folder is listed");
    for row in [file, folder] {
        assert_eq!(row.ipns_name.as_deref(), Some(write_name(row.id).as_str()));
    }
}

/// A navigation into a folder the owner granted on this device lands before
/// any walk proves the new scope root. The navigation leg must hold it as a
/// scope root, never read its record as an ordinary child and report the
/// owner's own honest record as abuse.
#[test]
fn a_navigation_right_after_a_grant_reads_no_new_scope_root_as_a_child() {
    let mut fx = GrantScenario::new();
    events_so_far(&mut fx._events);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    block_on(fx.engine.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the granted folder takes the focus");
    block_on(fx.engine.command(Command::Create {
        parent: fx.folder,
        name: "after-the-grant.bin".into(),
        kind: NodeKind::File,
    }))
    .expect("a metadata create stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    let listed: Vec<String> = block_on(fx.engine.snapshot(fx.folder))
        .expect("the granted folder opens")
        .children
        .into_iter()
        .map(|child| child.name)
        .collect();
    assert_eq!(listed, vec!["after-the-grant.bin".to_owned()]);
}

/// The navigation's file leg reads a file of a scope root the owner just
/// minted under that root's own seed and floors, before any walk proves it.
#[test]
fn a_navigation_right_after_a_grant_reads_a_file_of_the_new_scope() {
    let mut fx = GrantScenario::new();
    block_on(fx.engine.command(Command::Create {
        parent: fx.folder,
        name: "doc.bin".into(),
        kind: NodeKind::File,
    }))
    .expect("a metadata create stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let doc = block_on(fx.engine.view())
        .expect("a rendered view")
        .children(fx.folder)
        .into_iter()
        .find(|child| child.name == "doc.bin")
        .expect("the file is listed")
        .id;
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    // A second owner device writes the bytes, so only the network carries the
    // size this device paints.
    let (mut second, _second_events, mut second_tasks) = fx.second_owner_device();
    block_on(second.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the second device opens the folder");
    tick(&fx.world, &second, &mut second_tasks);
    let handle = block_on(second.begin_write(
        WriteTarget::Version {
            node: doc,
            expected_version: None,
        },
        200,
    ))
    .expect("a version write opens");
    block_on(second.push_chunk(handle, &[7u8; 200])).expect("the bytes stage");
    block_on(second.commit_write(handle)).expect("the version commits");
    for _ in 0..3 {
        tick(&fx.world, &second, &mut second_tasks);
    }

    events_so_far(&mut fx._events);
    block_on(fx.engine.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the granted folder takes the focus");

    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    let size = block_on(fx.engine.snapshot(fx.folder))
        .expect("the granted folder opens")
        .children
        .into_iter()
        .find(|child| child.id == doc)
        .and_then(|child| child.size);
    assert_eq!(size, Some(200), "the navigation read the file's version");
}

/// Write 200 bytes to `target` on `engine`, then run three ticks.
fn commit_doc(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    target: WriteTarget,
) {
    let handle = block_on(engine.begin_write(target, 200)).expect("a write opens");
    block_on(engine.push_chunk(handle, &[7u8; 200])).expect("the bytes stage");
    block_on(engine.commit_write(handle)).expect("the write commits");
    for _ in 0..3 {
        tick(world, engine, tasks);
    }
}

/// A second owner device writes 200 bytes to `doc`.
fn write_doc_on_second_device(fx: &GrantScenario, doc: NodeId) {
    let (mut second, _second_events, mut second_tasks) = fx.second_owner_device();
    block_on(second.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the second device opens the folder");
    tick(&fx.world, &second, &mut second_tasks);
    commit_doc(
        &fx.world,
        &mut second,
        &mut second_tasks,
        WriteTarget::Version {
            node: doc,
            expected_version: None,
        },
    );
}

fn painted_size(fx: &GrantScenario, doc: NodeId) -> Option<u64> {
    block_on(fx.engine.snapshot(fx.folder))
        .expect("the folder opens")
        .children
        .into_iter()
        .find(|child| child.id == doc)
        .and_then(|child| child.size)
}

/// This device's own edit of a scope set moves that scope root past the last
/// walk. The navigation still reads at once.
#[test]
fn a_navigation_right_after_an_own_scope_set_edit_reads_the_scope() {
    let mut fx = GrantScenario::new();
    let doc = published_file_in_folder(&mut fx, "doc.bin");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    write_doc_on_second_device(&fx, doc);

    events_so_far(&mut fx._events);
    block_on(fx.engine.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the granted folder takes the focus");

    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    assert_eq!(
        painted_size(&fx, doc),
        Some(200),
        "the navigation read the file's version"
    );
}

/// A second owner device grants `inner` to the second recipient, then writes
/// `doc.bin` of 200 bytes in it. Answers the file's id.
fn grant_inner_on_second_device(fx: &GrantScenario, inner: NodeId) -> NodeId {
    let (mut second, _second_events, mut second_tasks) = fx.second_owner_device();
    block_on(second.command(Command::SetFocus { node: Some(inner) }))
        .expect("the second device opens the folder");
    block_on(second.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second recipient's code imports");
    assert_eq!(
        block_on(second.command(Command::Grant {
            node: inner,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );
    for _ in 0..2 {
        tick(&fx.world, &second, &mut second_tasks);
    }
    write_doc_in(&fx.world, &mut second, &mut second_tasks, inner)
}

/// The size `engine` paints for `file` in `folder`.
fn size_in(engine: &Engine<FakeSeamTypes>, folder: NodeId, file: NodeId) -> Option<u64> {
    block_on(engine.snapshot(folder))
        .ok()?
        .children
        .into_iter()
        .find(|child| child.id == file)
        .and_then(|child| child.size)
}

/// Navigate this device to `inner`, which another owner device granted after
/// the last walk, and check that the navigation reads nothing there and sends
/// no abuse event, and that one tick paints the file.
fn navigate_into_the_new_root(fx: &mut GrantScenario, inner: NodeId, doc: NodeId) {
    events_so_far(&mut fx._events);
    block_on(fx.engine.command(Command::SetFocus { node: Some(inner) }))
        .expect("the folder takes the focus");
    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    assert_eq!(
        size_in(&fx.engine, inner, doc),
        None,
        "the navigation read nothing"
    );

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    assert_eq!(
        size_in(&fx.engine, inner, doc),
        Some(200),
        "the tick read the file"
    );
}

/// A grant by another owner device makes a folder inside a descendant scope a
/// scope root of its own. A navigation into it before the next walk reads
/// nothing and sends no abuse event; the next tick reads.
#[test]
fn a_navigation_after_a_grant_by_another_device_sends_no_abuse_event() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let folder = fx.folder;
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "inner");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let doc = grant_inner_on_second_device(&fx, inner);

    navigate_into_the_new_root(&mut fx, inner, doc);
}

/// The record bytes `node`'s scope root name serves on the first endpoint.
fn served_root_bytes(fx: &GrantScenario, node: NodeId) -> Vec<u8> {
    let endpoints = fx.world.record_store.endpoints();
    fx.world
        .record_store
        .record_at(&endpoints[0], write_name(node).as_str())
        .expect("the scope root is published")
}

/// [`served_root_bytes`], verified.
fn served_root(fx: &GrantScenario, node: NodeId) -> VerifiedRecord {
    IpnsRecord::unmarshal(&served_root_bytes(fx, node))
        .and_then(|record| record.verify(&write_name(node)))
        .expect("the scope root verifies")
}

/// The value `node`'s scope root name serves now, signed at the `held`
/// sequence with a later EOL, so the total order picks it over the held
/// record: another owner device's edit as a same-sequence fork.
fn forked_over(fx: &GrantScenario, node: NodeId, held: u64) -> Vec<u8> {
    let edited = served_root(fx, node);
    assert!(edited.sequence > held, "the other device published");
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes());
    IpnsRecord::create_v2(
        &signer,
        &edited.value,
        held,
        edited.ttl,
        "2098-01-01T00:00:00Z",
    )
    .marshal()
}

/// Serve `record` at `node`'s scope root name from every endpoint.
fn serve_root(fx: &GrantScenario, node: NodeId, record: &[u8]) {
    let name = write_name(node);
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.to_vec());
    }
}

/// Another owner device grants a folder inside a descendant scope, and its
/// scope root record stands at the sequence this device's walk gated. A
/// navigation into the new root before the next walk reads nothing and sends
/// no abuse event; the next tick reads.
#[test]
fn a_navigation_after_a_same_sequence_grant_by_another_device_reads_nothing() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let folder = fx.folder;
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "inner");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let held = sequence_at(&fx.world, &write_name(folder));
    let doc = grant_inner_on_second_device(&fx, inner);
    let fork = forked_over(&fx, folder, held);
    serve_root(&fx, folder, &fork);

    navigate_into_the_new_root(&mut fx, inner, doc);
}

/// The same fork, which surfaces after this device's walk and before its
/// drain writes the scope root. The drain publish over the forked record does
/// not hold the root, so a navigation into the new root reads nothing and
/// sends no abuse event.
#[test]
fn a_drain_write_over_a_same_sequence_fork_does_not_hold_the_root() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let folder = fx.folder;
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "inner");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let held = sequence_at(&fx.world, &write_name(folder));
    let held_bytes = served_root_bytes(&fx, folder);
    let doc = grant_inner_on_second_device(&fx, inner);
    let fork = forked_over(&fx, folder, held);
    serve_root(&fx, folder, &held_bytes);
    // The fork lands once this device's drain has written the vault root,
    // after the walk and before the drain reads the granted scope root.
    fx.world.record_store.seed_record_after_put(
        write_name(ROOT).as_str(),
        write_name(folder).as_str(),
        fork,
    );

    for (parent, name) in [(ROOT, "elsewhere"), (folder, "other")] {
        block_on(fx.engine.command(Command::Create {
            parent,
            name: name.into(),
            kind: NodeKind::Folder,
        }))
        .expect("a metadata create stages");
    }
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        sequence_at(&fx.world, &write_name(folder)) > held,
        "the drain wrote the scope root"
    );

    navigate_into_the_new_root(&mut fx, inner, doc);
}

/// A write grant moves the scope root to a fresh name, and the walk adopts it
/// at a low sequence. Sequences this device published at the old name do not
/// hold the fresh one, so a grant by another owner device there still skips
/// the navigation's reads.
#[test]
fn a_navigation_after_a_name_wave_and_a_grant_by_another_device_reads_nothing() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let folder = fx.folder;
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "inner");
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done),
        "the write grant moves the scope root to a fresh name"
    );
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let doc = grant_inner_on_second_device(&fx, inner);

    navigate_into_the_new_root(&mut fx, inner, doc);
}

/// Another owner device grants a folder, then this device grants another one
/// over that publish before a walk, and repeats that grant. The own publish
/// does not hold the root, and the repeat raises the floor at the root without
/// a walk. A navigation into the first folder reads nothing and sends no abuse
/// event.
#[test]
fn an_own_publish_over_another_devices_grant_does_not_hold_the_root() {
    let mut fx = GrantScenario::new();
    let other = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "other");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let folder = fx.folder;
    let doc = grant_inner_on_second_device(&fx, folder);
    let grant_other = |fx: &mut GrantScenario| {
        block_on(fx.engine.command(Command::Grant {
            node: other,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        }))
    };
    assert_eq!(grant_other(&mut fx), Ok(CommandOutcome::Done));
    assert_eq!(
        grant_other(&mut fx),
        Ok(CommandOutcome::Done),
        "the repeat lands"
    );

    navigate_into_the_new_root(&mut fx, folder, doc);
}

/// Inside a granted folder, another owner device grants `inner` inside `outer`
/// after this device read the records, and the grant surfaces once this device
/// PUTs at `surfaces_after` (`outer` or `inner`). The handover of this
/// device's grant of `outer` then stalls on evidence of that edit, so the
/// promoted root holds no value, and a navigation into `inner` reads nothing
/// and sends no abuse event.
fn assert_a_stall_over_a_concurrent_grant_holds_no_value(surfaces_after: &str) {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let folder = fx.folder;
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "outer");
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, outer, "inner");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let names = [write_name(folder), write_name(inner)];
    let trigger = match surfaces_after {
        "outer" => write_name(outer),
        _ => write_name(inner),
    };
    let store = &fx.world.record_store;
    let read_at: Vec<(EndpointId, &IpnsName, Vec<u8>)> = store
        .endpoints()
        .into_iter()
        .flat_map(|endpoint| {
            names.iter().map(move |name| {
                let record = store.record_at(&endpoint, name.as_str()).expect("a record");
                (endpoint.clone(), name, record)
            })
        })
        .collect();
    let doc = grant_inner_on_second_device(&fx, inner);
    let edited: Vec<(&IpnsName, Vec<u8>)> = names
        .iter()
        .map(|name| {
            let record = store
                .record_at(&store.endpoints()[0], name.as_str())
                .expect("an edited record");
            (name, record)
        })
        .collect();
    for (endpoint, name, record) in read_at {
        store.seed_record(&endpoint, name.as_str(), record);
    }
    for (name, record) in edited {
        store.seed_record_after_put(trigger.as_str(), name.as_str(), record);
    }
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: outer,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
        "{surfaces_after}"
    );
    assert_eq!(
        fx.owed_scopes(),
        vec![outer],
        "{surfaces_after}: the handover stalled"
    );

    navigate_into_the_new_root(&mut fx, inner, doc);
}

/// The other device's grant surfaces after this device re-seals `inner`, so
/// the handover loses a race.
#[test]
fn a_navigation_after_a_grant_handover_that_lost_a_race_reads_nothing() {
    assert_a_stall_over_a_concurrent_grant_holds_no_value("inner");
}

/// The other device's grant surfaces after the promotion and before the
/// interior read, so the handover finds an interior node that no longer
/// converges, before any interior PUT.
#[test]
fn a_navigation_after_a_grant_handover_whose_interior_did_not_converge_reads_nothing() {
    assert_a_stall_over_a_concurrent_grant_holds_no_value("outer");
}

/// Inside a granted folder, another owner device grants a folder inside a
/// folder, then this device grants the outer folder before a walk. The
/// promoted root names the inner scope root, which this device's sets do not
/// hold, so a navigation into the inner folder reads nothing and sends no
/// abuse event.
#[test]
fn a_promoted_root_over_another_devices_grant_does_not_hold_the_root() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let folder = fx.folder;
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "outer");
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, outer, "inner");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let doc = grant_inner_on_second_device(&fx, inner);
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: outer,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );

    navigate_into_the_new_root(&mut fx, inner, doc);
}

/// An upload into the vault root republishes the vault root. The navigation
/// right after it still reads the vault scope.
#[test]
fn a_navigation_right_after_an_upload_into_the_vault_root_reads_at_once() {
    let mut fx = GrantScenario::new();
    let doc = published_file_in_folder(&mut fx, "doc.bin");
    write_doc_on_second_device(&fx, doc);
    block_on(fx.engine.command(Command::SetFocus { node: None }))
        .expect("the root takes the focus");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let root = write_name(ROOT);
    let before = sequence_at(&fx.world, &root);
    let handle = block_on(fx.engine.begin_write(
        WriteTarget::NewFile {
            parent: ROOT,
            name: "top.bin".into(),
        },
        50,
    ))
    .expect("a new file write opens");
    block_on(fx.engine.push_chunk(handle, &[9u8; 50])).expect("the bytes stage");
    block_on(fx.engine.commit_write(handle)).expect("the file commits");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        sequence_at(&fx.world, &root) > before,
        "the upload republished the vault root"
    );

    events_so_far(&mut fx._events);
    block_on(fx.engine.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the folder takes the focus");
    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    assert_eq!(
        painted_size(&fx, doc),
        Some(200),
        "the navigation read the file"
    );
}

/// Write `doc.bin` of 200 bytes into `parent` on `engine` and answer its id.
fn write_doc_in(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    parent: NodeId,
) -> NodeId {
    commit_doc(
        world,
        engine,
        tasks,
        WriteTarget::NewFile {
            parent,
            name: "doc.bin".into(),
        },
    );
    block_on(engine.view())
        .expect("a rendered view")
        .children(parent)
        .into_iter()
        .find(|row| row.name == "doc.bin")
        .expect("the file is listed")
        .id
}

/// A recipient navigates into a subfolder of a received share. The pass that
/// grafted the share gated its root, so the navigation reads at once and sends
/// no abuse event.
#[test]
fn a_navigation_into_a_received_share_reads_at_once() {
    let mut fx = GrantScenario::new();
    let folder = fx.folder;
    let sub = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "sub");
    let doc = write_doc_in(&fx.world, &mut fx.engine, &mut fx._tasks, sub);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let (mut grantee, mut events, mut tasks) = recipient_session(&fx);
    settle(&fx, &grantee, &mut tasks);
    assert_eq!(
        size_in(&grantee, sub, doc),
        None,
        "no leg read the file yet"
    );

    events_so_far(&mut events);
    block_on(grantee.command(Command::SetFocus { node: Some(sub) }))
        .expect("the grantee opens the subfolder");
    assert_eq!(abuse_events(&mut events), 0, "no record is faulty");
    assert_eq!(
        size_in(&grantee, sub, doc),
        Some(200),
        "the navigation read the file"
    );
}

/// A navigation to a folder the base does not hold yet lists down to it and
/// then refreshes the window. It reads the vault root's record once.
#[test]
fn a_navigation_to_an_unlisted_folder_probes_the_root_once() {
    let mut fx = GrantScenario::new();
    let folder = fx.folder;
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, folder, "inner");
    let (mut second, _second_events, _second_tasks) = fx.second_owner_device();
    let root = write_name(ROOT);
    let before = fx.world.record_store.get_count(root.as_str());
    block_on(second.command(Command::SetFocus { node: Some(inner) }))
        .expect("the folder takes the focus");
    assert!(
        block_on(second.snapshot(inner)).is_ok(),
        "the navigation listed down to the folder"
    );
    assert_eq!(
        fx.world.record_store.get_count(root.as_str()) - before,
        fx.world.record_store.endpoints().len(),
        "one fan-out read of the root"
    );

    let before = fx.world.record_store.get_count(root.as_str());
    block_on(second.command(Command::SetFocus { node: Some(inner) }))
        .expect("the folder takes the focus again");
    assert_eq!(
        fx.world.record_store.get_count(root.as_str()),
        before,
        "a repeat visit with nothing due reads no root"
    );
}

/// A probe of a scope root with no answer reads nothing for that scope and
/// sends no abuse event. The next tick reads.
#[test]
fn a_navigation_whose_root_probe_has_no_answer_reads_nothing() {
    let mut fx = GrantScenario::new();
    let doc = published_file_in_folder(&mut fx, "doc.bin");
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    write_doc_on_second_device(&fx, doc);

    let root = write_name(fx.folder);
    fx.world.record_store.fail_get_for(root.as_str());
    events_so_far(&mut fx._events);
    block_on(fx.engine.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the folder takes the focus");
    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    assert_ne!(
        painted_size(&fx, doc),
        Some(200),
        "the navigation read nothing"
    );

    fx.world.record_store.heal_get_for(root.as_str());
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
    assert_eq!(painted_size(&fx, doc), Some(200), "the tick read the file");
}

/// A tick whose walk does not answer must not read the record of a scope root
/// the owner just minted as a child of the vault scope.
#[test]
fn a_tick_whose_walk_fails_reads_no_new_scope_root_as_a_child() {
    let mut fx = GrantScenario::new();
    block_on(fx.engine.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the folder takes the focus");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    events_so_far(&mut fx._events);
    // The vault root's write plane does not open, so the walk proves no set.
    fx.owner_device
        .floor_store
        .fail_epoch_floor_reads_for(&floor_label(&write_epoch_floor_key(&SCOPE)));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    fx.owner_device.floor_store.heal_floors();

    assert_eq!(abuse_events(&mut fx._events), 0, "no record is faulty");
}

/// A grant whose interior move landed seals the interior under the new scope.
/// A tick whose walk proves no set must still read that interior there.
#[test]
fn a_tick_whose_walk_fails_reads_a_moved_interior_under_the_new_scope() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    block_on(fx.engine.command(Command::SetFocus { node: Some(inner) }))
        .expect("the interior folder takes the focus");
    events_so_far(&mut fx._events);
    let reads = fx.world.record_store.get_count(write_name(inner).as_str());
    // The vault root's write plane does not open, so the walk proves no set.
    fx.owner_device
        .floor_store
        .fail_epoch_floor_reads_for(&floor_label(&write_epoch_floor_key(&SCOPE)));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    fx.owner_device.floor_store.heal_floors();

    assert!(
        fx.world.record_store.get_count(write_name(inner).as_str()) > reads,
        "the focus leg reads the moved interior"
    );
    assert_eq!(abuse_descriptions(&mut fx._events), Vec::<String>::new());
}

/// The control of `a_tick_whose_walk_fails_reads_a_moved_interior_under_the_new_scope`:
/// a record at the moved interior node that opens under no seed of the new
/// scope is still one trust violation.
#[test]
fn a_tick_whose_walk_fails_still_reports_a_hostile_moved_interior_node() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let (_, epoch) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
    reseal_interior_node(
        &fx.world,
        &fx.blocks,
        inner,
        fx.folder.0,
        &[0x5a; 32],
        epoch,
    );
    block_on(fx.engine.command(Command::SetFocus { node: Some(inner) }))
        .expect("the interior folder takes the focus");
    events_so_far(&mut fx._events);
    fx.owner_device
        .floor_store
        .fail_epoch_floor_reads_for(&floor_label(&write_epoch_floor_key(&SCOPE)));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    fx.owner_device.floor_store.heal_floors();

    let reported = abuse_descriptions(&mut fx._events);
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert!(
        reported[0].ends_with("[unseal]: [seal-open-failed]"),
        "{reported:?}"
    );
}

/// Where a grant's handover stops, which leaves its interior move owed.
#[derive(Clone, Copy, Debug)]
enum HandoverStop {
    /// The reseal stops at its first node: the interior stays in the vault scope.
    Reseal,
    /// The reseal stops part of the way: the outer interior moved, the inner
    /// did not.
    PartialReseal,
    /// The parent index publish stops: the whole interior moved.
    ParentIndex,
}

/// A granted folder whose interior move is owed after `stop`, over an interior
/// folder `inner` and a folder `deep` inside it, with a file in each.
struct OwedMove {
    fx: GrantScenario,
    inner: NodeId,
    deep: NodeId,
    /// The name whose publish stopped the handover.
    stopped_at: IpnsName,
    /// Whether the handover resealed `deep` under the new scope.
    deep_moved: bool,
}

impl OwedMove {
    fn after(stop: HandoverStop) -> Self {
        let owed = Self::stalled(stop);
        owed.fx
            .world
            .record_store
            .heal_put_for(owed.stopped_at.as_str());
        owed
    }

    /// [`Self::after`] with the publish that stopped the handover still
    /// failing, so a re-drive cannot land the move.
    fn stalled(stop: HandoverStop) -> Self {
        let mut fx = GrantScenario::new();
        let inner = create_published_folder(
            &fx.world,
            &mut fx.engine,
            &mut fx._tasks,
            fx.folder,
            "inner",
        );
        let deep =
            create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, inner, "deep");
        for parent in [inner, deep] {
            block_on(fx.engine.command(Command::Create {
                parent,
                name: "doc.bin".into(),
                kind: NodeKind::File,
            }))
            .expect("a metadata create stages");
        }
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        let failing = match stop {
            HandoverStop::Reseal => write_name(inner),
            HandoverStop::PartialReseal => write_name(deep),
            HandoverStop::ParentIndex => write_name(ROOT),
        };
        fx.world.record_store.fail_put_for(failing.as_str());
        assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
        assert_eq!(
            fx.owed_scopes(),
            vec![fx.folder],
            "{stop:?}: the move is owed"
        );
        let (override_seed, _) = scope_material_of(&fx.world, &fx.blocks, fx.folder);
        let moved = |node| opens_under(&fx, node, &read_key_under(&override_seed, node));
        let expected = match stop {
            HandoverStop::Reseal => (false, false),
            HandoverStop::PartialReseal => (true, false),
            HandoverStop::ParentIndex => (true, true),
        };
        assert_eq!((moved(inner), moved(deep)), expected, "{stop:?}: the seals");
        Self {
            fx,
            inner,
            deep,
            stopped_at: failing,
            deep_moved: expected.1,
        }
    }

    /// A second session of the same device over this state.
    fn restarted(self) -> Self {
        let (engine, events, tasks) =
            boot_owner(&self.fx.world, &self.fx.blocks, &self.fx.owner_device);
        Self {
            fx: GrantScenario {
                engine,
                _events: events,
                _tasks: tasks,
                ..self.fx
            },
            ..self
        }
    }

    /// Another device adds a folder `added` named `name` to `deep`, sealed
    /// where `deep` is sealed now.
    fn add_to_deep(&self, added: NodeId, name: &str) {
        let (read_key, scope) = if self.deep_moved {
            let (seed, _) = scope_material_of(&self.fx.world, &self.fx.blocks, self.fx.folder);
            (read_key_under(&seed, self.deep), self.fx.folder.0)
        } else {
            (read_key_of(self.deep), SCOPE)
        };
        concurrent_add(
            &self.fx.world,
            &self.fx.blocks,
            self.deep,
            &read_key,
            scope,
            named_child(added, name, &write_name(added)),
        );
    }

    /// Whether the rendered view lists `name` in `deep`.
    fn deep_lists(&self, name: &str) -> bool {
        block_on(self.fx.engine.view())
            .expect("a rendered view")
            .children(self.deep)
            .iter()
            .any(|child| child.name == name)
    }

    /// The abuse the navigation into `deep` reports.
    fn navigate(&mut self) -> Vec<String> {
        let fx = &mut self.fx;
        events_so_far(&mut fx._events);
        for node in [fx.folder, self.inner, self.deep] {
            block_on(fx.engine.command(Command::SetFocus { node: Some(node) }))
                .expect("the folder takes the focus");
        }
        abuse_descriptions(&mut fx._events)
    }

    /// The abuse one tick reports.
    fn tick(&mut self) -> Vec<String> {
        let fx = &mut self.fx;
        events_so_far(&mut fx._events);
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        abuse_descriptions(&mut fx._events)
    }

    /// Each leg on its own: the navigation adopts a changed `deep`, then the
    /// tick adopts the next change, and neither reports abuse.
    fn assert_each_leg_reads_deep(&mut self, case: &str) {
        self.add_to_deep(NodeId([0xa1; 16]), "seen at navigation");
        assert_eq!(self.navigate(), Vec::<String>::new(), "{case}: navigation");
        assert!(
            self.deep_lists("seen at navigation"),
            "{case}: the navigation adopts the folder"
        );
        self.add_to_deep(NodeId([0xa2; 16]), "seen at the tick");
        assert_eq!(self.tick(), Vec::<String>::new(), "{case}: tick");
        assert!(
            self.deep_lists("seen at the tick"),
            "{case}: the tick adopts the folder"
        );
    }
}

/// While a grant's interior move is owed, each interior node opens under the
/// scope its epoch tag names, wherever the handover stopped (ADR 0072 D1).
#[test]
fn an_owed_interior_move_reads_each_interior_node_under_the_scope_it_names() {
    for stop in [
        HandoverStop::Reseal,
        HandoverStop::PartialReseal,
        HandoverStop::ParentIndex,
    ] {
        OwedMove::after(stop).assert_each_leg_reads_deep(&format!("{stop:?}"));
    }
}

/// The owed entry is durable, so a session that starts again over a move that
/// is still owed holds the entry's root as a scope root at each leg, and reads
/// no record of it as a child (ADR 0072 D1).
#[test]
fn an_owed_interior_move_holds_its_root_after_a_restart() {
    for stop in [HandoverStop::Reseal, HandoverStop::ParentIndex] {
        let mut restarted = OwedMove::stalled(stop).restarted();
        assert_eq!(
            restarted.tick(),
            Vec::<String>::new(),
            "{stop:?}: first tick"
        );
        assert_eq!(
            restarted.navigate(),
            Vec::<String>::new(),
            "{stop:?}: navigation"
        );
        assert_eq!(restarted.tick(), Vec::<String>::new(), "{stop:?}: tick");
    }
}

/// The control of D1: a record whose epoch tag names a scope the owed move
/// binds but that does not open under its seed, and a record whose tag names
/// a third scope, are each exactly one trust violation.
#[test]
fn an_owed_interior_move_still_reports_a_hostile_interior_node() {
    for (case, scope) in [("bound scope", SCOPE), ("third scope", [0x33; 16])] {
        let mut owed = OwedMove::after(HandoverStop::Reseal);
        reseal_interior_node(
            &owed.fx.world,
            &owed.fx.blocks,
            owed.deep,
            scope,
            &[0x5a; 32],
            published_read_epoch(&owed.fx.world, &owed.fx.blocks, ROOT),
        );
        let navigation = owed.navigate();
        assert_eq!(navigation.len(), 1, "{case}: navigation {navigation:?}");
        assert!(
            navigation[0].ends_with("[unseal]: [seal-open-failed]"),
            "{case}: {navigation:?}"
        );
        let ticked = owed.tick();
        assert_eq!(ticked.len(), 1, "{case}: tick {ticked:?}");
        assert!(
            ticked[0].ends_with("[unseal]: [seal-open-failed]"),
            "{case}: {ticked:?}"
        );
    }
}

/// A revoke runs several gated scope-root reads, so its refusal names the read
/// that refused. The command read runs on the last copy, and a read-only cut
/// keeps the stop at the read cascade (ADR 0068 D1 and D3).
#[test]
fn a_revoke_refused_by_the_gate_names_the_read_that_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    // The vault root's own record at the granted scope's name: owner-signed,
    // and refused by the gate because its commitment names another name.
    publish_value_at(
        &fx.world,
        fx.folder,
        &published_value(&fx.world, &write_name(ROOT)),
    );

    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Err(EngineError::TrustViolation {
            message: format!(
                "read-plane cascade failed: cascade resolve of scope [{}] failed: \
                 descendant record rejected by adoption gate",
                hex_lower(&fx.folder.0)
            ),
        })
    );
}

/// The share dialog's epoch row reads the scope root's published record, so a
/// person revoke steps the read epoch by one and leaves the write epoch alone.
#[test]
fn the_sharing_read_steps_the_read_epoch_by_one_on_a_person_revoke() {
    let mut fx = GrantScenario::new();
    let epochs = |fx: &GrantScenario| {
        block_on(fx.engine.sharing(fx.folder))
            .expect("a sharing read")
            .state
            .expect("the scope resolved")
            .epochs
    };
    assert_eq!(
        epochs(&fx),
        None,
        "an ordinary folder is not a scope root, so it has no epochs"
    );

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let granted = epochs(&fx).expect("a scope root carries its epochs");

    assert_eq!(
        block_on(fx.engine.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        })),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        epochs(&fx),
        Some(ScopeEpochs {
            read_epoch: granted.read_epoch + 1,
            write_epoch: granted.write_epoch,
        })
    );
}

/// The link half of a share dialog: the deadline the owner-signed link entry
/// carries. The link's row is not a grant, because its recipient is a throwaway
/// identity only the link holder answers for, so it renders as the link it
/// is and nowhere else.
#[test]
fn the_sharing_read_reports_the_live_link_apart_from_the_grants() {
    let deadline = UnixMillis(1_800_000_000_000);
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let link = expiring_invite_link_at_root(0x4e, deadline);
    let grantee = recipient_row_at_root(CorePermission::Read);
    seed_vault(&world, &blocks, vec![link.clone(), grantee.clone()]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    let view = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(view.invite_links, listed_link(&link, deadline, false));

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
        block_on(engine.command(Command::RevokeInviteLink {
            node: ROOT,
            link_tag: None,
            remove_grantees: false,
        })),
        Ok(CommandOutcome::Done)
    );
    let revoked = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(
        revoked.invite_links,
        Vec::new(),
        "the cut landed, so the set commits no link"
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
    let link = expiring_invite_link_at_root(0x6a, deadline);
    seed_vault(&world, &blocks, vec![link.clone()]);
    let alice = world.device(b"alice");
    let (engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    let before = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(before.invite_links, listed_link(&link, deadline, false));

    // The claim path refuses at the deadline, so the read reports it there too.
    world.scheduler.advance_to(deadline);
    let after = block_on(engine.sharing(ROOT))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(after.invite_links, listed_link(&link, deadline, true));
}

/// ADR 0026 D3: the contact share is charged per link, and a fresh link carries
/// its own. A full share refuses that link's conversions, never a mint, so the
/// read flags the link and leaves the scope's mint open.
#[test]
fn an_expired_link_with_a_full_contact_share_flags_the_link_and_refuses_no_mint() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let [link] = <[SharingInviteLink; 1]>::try_from(folder_links(&fx)).expect("one link");
    let committed = minted_link(&fragment, &link);

    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let book = StagingContactStore::new(&fx.owner_device.staging_store, &enc_subkey, &entropy);
    for claimant in 0..u8::try_from(MAX_LINK_CONTACTS).expect("in range") {
        let mut scalar = [0x11; 32];
        scalar[31] = claimant;
        block_on(book.record_from_link(&contact_code(&scalar), &committed, &fx.folder.0))
            .expect("a claim under the share records");
    }
    fx.world.scheduler.advance_to(link.expires_at);

    let state = block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved");
    assert_eq!(state.invite_link_refusal, None);
    assert_eq!(
        state.invite_links,
        vec![SharingInviteLink {
            expired: true,
            contact_budget_full: true,
            ..link
        }]
    );
}

/// A write claim converts through a write-scope cut, which moves the root and
/// every link tag with it. The book records a link by its ephemeral identity,
/// so the share of a link minted before the cut still counts the contacts it
/// admitted: the sharing read still flags it full, and it refuses the next
/// claim.
#[test]
fn a_links_contact_share_survives_the_write_scope_cut_of_a_write_claim() {
    let mut fx = GrantScenario::new();
    let read_link = fx.mint_link();
    let [before] = <[SharingInviteLink; 1]>::try_from(folder_links(&fx)).expect("one link");
    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let book = StagingContactStore::new(&fx.owner_device.staging_store, &enc_subkey, &entropy);
    let committed = minted_link(&read_link, &before);
    for claimant in 1..u8::try_from(MAX_LINK_CONTACTS).expect("in range") {
        let mut scalar = [0x22; 32];
        scalar[31] = claimant;
        block_on(book.record_from_link(&contact_code(&scalar), &committed, &fx.folder.0))
            .expect("a claim under the share records");
    }
    let admitted = fx.post_claimant(&read_link, 0, 0);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(
        fx.granted_to().contains(&admitted),
        "the read link admits the last contact of its share"
    );

    let write_link = fx.mint_link_at(Permission::Write);
    let minted = fx.granted_scope_repoint();
    fx.post_claimant(&write_link, 1, 1);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        minted.write_epoch + 1,
        "the write claim converts through one write-scope cut"
    );

    let read_listed = |fx: &GrantScenario| {
        folder_links(fx)
            .into_iter()
            .find(|link| link.permission == Permission::Read)
            .expect("the read link stays")
    };
    let after = read_listed(&fx);
    assert_ne!(after.tag, before.tag, "the cut moved the read link's tag");
    assert!(
        after.contact_budget_full,
        "the share still counts every contact the link admitted"
    );
    let refused = fx.post_claimant(&read_link, 2, 2);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(!fx.granted_to().contains(&refused));
    assert_eq!(
        read_listed(&fx).refused_claims,
        1,
        "the full share refuses the next claim"
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
/// owner-signed set, and the read plane cuts so the bearer's blob is gone from
/// everything published after it.
#[test]
fn revoking_an_invite_link_cuts_its_row_and_rotates_the_read_plane() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let bystander = recipient_row_at_root(CorePermission::Read);
    let link = invite_link_at_root(0x4e);
    seed_vault(&world, &blocks, vec![link.clone(), bystander.clone()]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);

    let before = published_grant_section(&world, &blocks, ROOT).expect("the root is a scope root");
    assert!(
        before.grant_blobs.iter().any(|blob| blob.tag == link.tag),
        "the bearer starts out able to self-locate a blob"
    );

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink {
            node: ROOT,
            link_tag: None,
            remove_grantees: false,
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
        !after.commitment.entries.iter().any(|e| e.tag == link.tag),
        "the link's row is no longer committed, so a claim on it is refused"
    );
    assert!(
        !after.grant_blobs.iter().any(|blob| blob.tag == link.tag),
        "and the bearer has no blob in the re-sealed set"
    );
    assert!(
        after
            .grant_blobs
            .iter()
            .any(|blob| blob.tag == bystander.tag),
        "revoking a link ends future claims, not the grants it already produced"
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
    seed_vault(&world, &blocks, vec![invite_link_at_root(0x4e)]);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);
    let folder = create_published_folder(&world, &mut engine, &mut tasks, ROOT, "plain");

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink {
            node: folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "revoke-link-target-is-not-a-scope-root"
        }),
    );
}

/// A revoke and a permission change are different actions to a user, so an
/// ordinary folder refuses each under its own name.
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
        block_on(fx.engine.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: recipient,
            permission: Permission::Read,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "permission-change-target-is-not-a-scope-root"
        }),
    );
}

/// A revoke cuts only a committed link entry. A row of any other kind belongs to
/// a grantee, so a scope that commits no link entry publishes nothing.
#[test]
fn revoking_a_link_on_a_scope_with_no_link_entry_publishes_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let grantee = recipient_row_at_root(CorePermission::Read);
    let root_name = seed_vault(&world, &blocks, vec![grantee.clone()]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    let before = sequence_at(&world, &root_name);

    assert_eq!(
        block_on(engine.command(Command::RevokeInviteLink {
            node: ROOT,
            link_tag: None,
            remove_grantees: false,
        })),
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

/// The invite links the sharing read reports at `fx`'s folder.
fn folder_links(fx: &GrantScenario) -> Vec<SharingInviteLink> {
    block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved")
        .invite_links
}

/// A folder carries any number of links (ADR 0026 D2), so the sharing read
/// lists each, with the claims its own ephemeral identity signed. A revoke that
/// names a link by its tag cuts that link alone. The revoke first converts the
/// waiting write claim, whose write-scope cut moves the root and every tag with
/// it, and still cuts the link the host named.
#[test]
fn two_links_are_both_listed_and_a_revoke_by_tag_cuts_only_that_one() {
    let mut fx = GrantScenario::new();
    fx.mint_link();
    let write_fragment = fx.mint_link_at(Permission::Write);
    let claimants = fx.post_claims(&write_fragment, 1);
    // A delete that gives no answer keeps the acked claim waiting.
    fx.owner_device.mailbox.set_ack_failing(true);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    fx.owner_device.mailbox.set_ack_failing(false);

    let listed = folder_links(&fx);
    assert_eq!(listed.len(), 2, "both links are live");
    let by = |permission| {
        listed
            .iter()
            .find(|link| link.permission == permission)
            .expect("one link per permission")
            .clone()
    };
    let (read, write) = (by(Permission::Read), by(Permission::Write));
    for link in [&read, &write] {
        assert!(!link.expired);
        assert_eq!(link.admission_cap, DEFAULT_ADMISSION_CAP);
    }
    assert_eq!(
        (read.pending_claims, write.pending_claims),
        (0, 1),
        "a claim counts on the link that signed it"
    );

    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: Some(read.tag.clone()),
            remove_grantees: false,
        })),
        Ok(CommandOutcome::Done)
    );

    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the claim converted"
    );
    let [left] = <[SharingInviteLink; 1]>::try_from(folder_links(&fx)).expect("one link");
    assert_eq!(
        left.permission,
        Permission::Write,
        "the other link stays listed"
    );
    assert_ne!(left.tag, write.tag, "the conversion's cut moved its tag");
    let moved = fx.granted_scope_repoint().current_root;
    let committed: Vec<Vec<u8>> = published_grant_section_at(&fx.world, &fx.blocks, &moved)
        .expect("the moved scope root republished")
        .commitment
        .entries
        .iter()
        .filter(|entry| entry.kind == GrantSetEntryKind::Link)
        .map(|entry| entry.tag.to_vec())
        .collect();
    assert_eq!(committed, vec![left.tag], "the named link is cut");
}

/// The owner's chosen cap is what the link entry commits, on the mint that
/// makes the scope and on the mint that appends to it.
#[test]
fn a_chosen_admission_cap_shows_on_the_sharing_read() {
    let mut fx = GrantScenario::new();
    for cap in [3, MAX_ADMISSION_CAP] {
        assert!(matches!(
            block_on(fx.engine.command(Command::CreateInviteLink {
                node: fx.folder,
                permission: Permission::Read,
                expires_at: None,
                owner_name: String::new(),
                admission_cap: Some(cap),
            })),
            Ok(CommandOutcome::InviteLinkMinted(_))
        ));
    }

    let mut caps: Vec<u64> = folder_links(&fx)
        .into_iter()
        .map(|link| link.admission_cap)
        .collect();
    caps.sort_unstable();
    assert_eq!(caps, vec![3, MAX_ADMISSION_CAP]);
}

/// A cap of zero admits no one, and one past the grant-set ceiling promises
/// admissions the set cannot hold: both are refused before anything publishes.
#[test]
fn an_admission_cap_out_of_range_is_refused_and_publishes_nothing() {
    let mut fx = GrantScenario::new();
    for cap in [0, MAX_ADMISSION_CAP + 1] {
        assert_eq!(
            block_on(fx.engine.command(Command::CreateInviteLink {
                node: fx.folder,
                permission: Permission::Read,
                expires_at: None,
                owner_name: String::new(),
                admission_cap: Some(cap),
            })),
            Err(EngineError::MalformedInput {
                check: "invite-admission-cap-out-of-range"
            })
        );
    }
    assert!(published_grant_section(&fx.world, &fx.blocks, fx.folder).is_none());
}

/// A deadline not after now mints a link expired before anyone reads it, so it
/// is refused before anything publishes. One past now mints.
#[test]
fn an_invite_deadline_not_after_now_is_refused_and_publishes_nothing() {
    let mut fx = GrantScenario::new();
    // The fixture clock starts at the epoch; `now - 1` needs it past zero.
    fx.world.scheduler.advance(Duration::from_secs(60));
    let now = fx.world.scheduler.now().0;
    for at in [0, now - 1, now] {
        assert_eq!(
            block_on(fx.engine.command(Command::CreateInviteLink {
                node: fx.folder,
                permission: Permission::Read,
                expires_at: Some(UnixMillis(at)),
                owner_name: String::new(),
                admission_cap: None,
            })),
            Err(EngineError::MalformedInput {
                check: "invite-deadline-out-of-range"
            }),
            "{at}"
        );
    }
    assert!(published_grant_section(&fx.world, &fx.blocks, fx.folder).is_none());
    assert!(matches!(
        block_on(fx.engine.command(Command::CreateInviteLink {
            node: fx.folder,
            permission: Permission::Read,
            expires_at: Some(UnixMillis(now + 1)),
            owner_name: String::new(),
            admission_cap: None,
        })),
        Ok(CommandOutcome::InviteLinkMinted(_))
    ));
}

/// With two links and no tag, a revoke has no defined cut, so it refuses and
/// publishes nothing.
#[test]
fn a_revoke_with_no_tag_over_two_links_is_refused_and_publishes_nothing() {
    let mut fx = GrantScenario::new();
    fx.mint_link();
    fx.mint_link();
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);

    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Err(EngineError::MalformedInput {
            check: "link-ambiguous"
        }),
    );

    assert_eq!(sequence_at(&fx.world, &name), before, "nothing publishes");
    assert_eq!(folder_links(&fx).len(), 2);
    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: Some(vec![0x11; 32]),
            remove_grantees: false,
        })),
        Err(EngineError::MalformedInput {
            check: "link-not-committed"
        }),
        "a tag no link carries names nothing"
    );
    assert_eq!(sequence_at(&fx.world, &name), before);
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
        block_on(bearer.command(Command::ClaimInviteLink {
            fragment,
            name: String::new(),
        })),
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

/// The claims waiting at `fx.folder`, as the folder's row and the link standing
/// each report them.
fn waiting_claims(fx: &GrantScenario) -> (u32, u32) {
    let row = block_on(fx.engine.snapshot(ROOT))
        .expect("the root lists")
        .children
        .into_iter()
        .find(|child| child.id == fx.folder)
        .expect("the shared folder is listed")
        .pending_invite_claims;
    let links = block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the link standing reads")
        .invite_links[0]
        .pending_claims;
    (row, links)
}

/// The claims the link at `fx.folder` refused for good.
fn refused_claims(fx: &GrantScenario) -> u32 {
    block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the link standing reads")
        .invite_links[0]
        .refused_claims
}

/// ADR 0023 D3: every tick acks and converts, so a claim needs no press, and
/// the owner sees a transient "joined" notice for each new grantee.
#[test]
fn the_tick_converts_a_claim_with_no_command() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 2);
    assert_eq!(
        waiting_claims(&fx),
        (0, 0),
        "nothing counts before a pass polls"
    );
    events_so_far(&mut fx._events);

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        inbox(&fx.owner_device).is_empty(),
        "the tick acked each claim"
    );
    let granted = fx.granted_to();
    for claimant in &claimants {
        assert!(granted.contains(claimant), "and converted each one");
    }
    assert_eq!(waiting_claims(&fx), (0, 0));
    let joined = events_so_far(&mut fx._events)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                Event::GranteeJoined { scope_root, fingerprint, .. }
                    if *scope_root == fx.folder && !fingerprint.is_empty()
            )
        })
        .count();
    assert_eq!(joined, 2, "one notice per new grantee");
}

/// ADR 0023 D3, ADR 0024 D4: any owner device converts on its tick, and the
/// tick holds the same cut authority as the command. A write claim on a
/// folder with no write scope converts on the other device's tick after
/// exactly one write-scope cut, and the parent's index names the moved root.
#[test]
fn a_write_claim_converts_on_the_other_owner_devices_tick_with_one_cut() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link_at(Permission::Write);
    let minted = fx.granted_scope_repoint();
    let claimants = fx.post_claims(&fragment, 1);
    let phone = fx.world.device(&owner_identity().verifying_key().to_sec1());
    let (phone_engine, _phone_events, mut phone_tasks) = boot_owner(&fx.world, &fx.blocks, &phone);

    tick(&fx.world, &phone_engine, &mut phone_tasks);

    assert!(inbox(&fx.owner_device).is_empty(), "the phone acked it");
    let moved = fx.granted_scope_repoint();
    assert_eq!(
        moved.write_epoch,
        minted.write_epoch + 1,
        "exactly one write-scope cut ran"
    );
    let state = block_on(phone_engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the phone reads the moved root through the parent's index");
    let row = state
        .grants
        .iter()
        .find(|grant| grant.recipient_identity_public_key == claimants[0])
        .expect("the claimant holds a row");
    assert_eq!(row.permission, Permission::Write);
    assert_eq!(state.invite_links[0].pending_claims, 0, "nothing waits");
}

/// The minting device holds the write-epoch floor its own mint seeded. The
/// other device's write-scope cut seals the moved root's owner-write-blob one
/// epoch higher, so the minting device must consult the scope pointer when it
/// next reads that root, or it cannot read the sharing state nor act on it.
#[test]
fn the_minting_device_reads_the_root_another_owner_devices_write_cut_moved() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link_at(Permission::Write);
    let minted = fx.granted_scope_repoint();
    let claimants = fx.post_claims(&fragment, 1);
    let floors = fx.owner_device.floors(&SECRET);
    let floor_before =
        block_on(floor::write_epoch_floor(&floors, &fx.folder.0)).expect("the floor store answers");
    assert_eq!(
        floor_before,
        Some(minted.write_epoch),
        "the mint seeded the floor"
    );
    let (phone_engine, _phone_events, mut phone_tasks) = fx.owner_phone();

    tick(&fx.world, &phone_engine, &mut phone_tasks);

    let moved = fx.granted_scope_repoint();
    assert_eq!(
        moved.write_epoch,
        minted.write_epoch + 1,
        "the phone cut the write scope"
    );
    let state = block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the minting device reads the moved root");
    let row = state
        .grants
        .iter()
        .find(|grant| grant.recipient_identity_public_key == claimants[0])
        .expect("the claimant holds a row");
    assert_eq!(row.permission, Permission::Write);
    assert_eq!(
        block_on(floor::write_epoch_floor(&floors, &fx.folder.0)).expect("the floor store answers"),
        Some(moved.write_epoch),
        "the pointer consult raised the floor to the epoch the owner signed"
    );
    assert!(
        matches!(
            fx.try_mint_link_at(Permission::Read),
            Ok(CommandOutcome::InviteLinkMinted(_))
        ),
        "the minting device mints on the moved root"
    );
    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: Some(state.invite_links[0].tag.clone()),
            remove_grantees: true,
        })),
        Ok(CommandOutcome::Done),
        "the minting device revokes the write link with its joiner"
    );
    assert!(
        !fx.granted_to().contains(&claimants[0]),
        "the joiner leaves with the link"
    );
}

/// A scope pointer below the write-epoch floor this device holds is a rollback,
/// so the on-access consult refuses it as a trust violation. The verdict holds
/// for the consult interval: an access inside it reads the pointer no more and
/// reports nothing again, and the first access past it consults again.
#[test]
fn an_on_access_pointer_consult_below_the_floor_is_a_trust_violation() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link_at(Permission::Write);
    fx.post_claims(&fragment, 1);
    let (phone_engine, _phone_events, mut phone_tasks) = fx.owner_phone();
    tick(&fx.world, &phone_engine, &mut phone_tasks);
    let vouched = fx.granted_scope_repoint().write_epoch;
    let floors = fx.owner_device.floors(&SECRET);
    block_on(floor::advance_write_epoch_on_sight(
        &floors,
        &fx.folder.0,
        vouched + 1,
    ))
    .expect("the floor store answers");
    abuse_events(&mut fx._events);
    let pointer = scope_pointer_name(kdf::owner_pointer_seed(&SECRET).as_bytes(), &fx.folder.0);
    let store = fx.world.record_store.clone();
    let pointer_reads = || store.get_count(pointer.as_str());
    let before = pointer_reads();

    let sharing = block_on(fx.engine.sharing(fx.folder)).expect("a sharing read");

    assert!(sharing.state.is_none(), "a refused root answers no state");
    assert_eq!(abuse_events(&mut fx._events), 1, "the refusal is reported");
    let consulted = pointer_reads();
    assert!(consulted > before, "the access consulted the pointer");
    assert!(
        matches!(
            fx.try_mint_link_at(Permission::Read),
            Err(EngineError::TrustViolation { .. })
        ),
        "a command on the refused root fails closed"
    );
    assert_eq!(
        pointer_reads(),
        consulted,
        "inside the interval, no second read"
    );
    assert_eq!(abuse_events(&mut fx._events), 0, "nor a second report");

    fx.world
        .scheduler
        .advance(fx.engine.profile().pointer_consult_interval);
    block_on(fx.engine.sharing(fx.folder)).expect("a sharing read");
    assert!(
        pointer_reads() > consulted,
        "past the interval, it reads again"
    );
}

/// A command pass before this session's first walk knows no scope root, so
/// it cannot place a pending entry. It keeps the entry, and the first tick
/// after the walk converts it. The record is durable, so a fresh engine on
/// the same device reads the entry the last one acked.
#[test]
fn a_command_pass_before_the_first_walk_keeps_a_pending_entry_it_cannot_place() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let name = write_name(fx.folder);
    fx.world.record_store.fail_put_for(name.as_str());
    assert!(fx.convert().is_err(), "the publish fails");
    fx.world.record_store.heal_put_for(name.as_str());
    assert!(inbox(&fx.owner_device).is_empty(), "the claim was acked");

    serve_http(&fx.owner_device, &fx.blocks, 600);
    let (mut restarted, _restarted_events) = engine_on_api(&fx.owner_device, 43);
    block_on(restarted.start(secret(), None)).expect("the restart adopts the owner root");
    let mut tasks = fx.world.scheduler.take_spawned_tasks();
    assert_eq!(
        block_on(restarted.command(Command::ConvertInviteClaims { node: fx.folder })),
        Ok(CommandOutcome::Done),
    );
    assert!(!fx.granted_to().contains(&claimants[0]));

    poll_tasks_until_parked(&mut tasks);
    tick(&fx.world, &restarted, &mut tasks);
    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the tick after the walk converts the entry the restart kept"
    );
}

/// A claim acked past its link's owner-signed deadline can never convert, so
/// the conversion acks it, settles it, and grants nothing.
#[test]
fn a_claim_on_an_expired_link_is_acked_and_stops_counting() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    fx.post_claims(&fragment, 1);
    let waiting = |fx: &GrantScenario| {
        block_on(fx.engine.sharing(fx.folder))
            .expect("a sharing read")
            .state
            .expect("the link standing reads")
            .invite_links[0]
            .pending_claims
    };
    fx.world
        .scheduler
        .advance(DEFAULT_LINK_LIFETIME + Duration::from_secs(1));
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(inbox(&fx.owner_device).is_empty(), "the claim is acked");
    assert_eq!(waiting(&fx), 0);
    assert!(fx.granted_to().is_empty(), "and it granted nothing");
}

/// ADR 0024 D4: a write link mints a read link entry and runs no write cut. Its
/// conversion on a folder with no write scope runs one write-scope cut first,
/// and then mints the personal row at write.
#[test]
fn a_write_link_mints_at_read_and_its_conversion_runs_one_write_cut() {
    let mut fx = GrantScenario::new();
    let inherited_name = write_name(fx.folder);
    let fragment = fx.mint_link_at(Permission::Write);

    let minted = fx.granted_scope_repoint();
    assert_eq!(
        minted.current_root, inherited_name,
        "no write cut moved the scope root"
    );
    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    assert_eq!(
        opened.scope_pointer_name,
        scope_pointer_name(kdf::owner_pointer_seed(&SECRET).as_bytes(), &fx.folder.0),
        "the bearer follows the scope pointer, not a root name"
    );
    assert_eq!(
        opened.verified_names(&owner_identity().verifying_key()),
        Some(("owner", "shared")),
        "the names verify under the owner signature"
    );
    let link_row = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the link's scope root answers")
        .commitment
        .entries;
    assert_eq!(link_row.len(), 1);
    assert_eq!(link_row[0].permission, CorePermission::Read);
    assert_eq!(
        link_row[0].conversion_permission,
        Some(CorePermission::Write)
    );

    let bearer_pk = recipient_identity().verifying_key().to_sec1().to_vec();
    let (mut bearer, _bearer_events) = fx.bearer();
    assert_eq!(
        block_on(bearer.command(Command::ClaimInviteLink {
            fragment,
            name: String::new(),
        })),
        Ok(CommandOutcome::Done),
    );
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    let moved = fx.granted_scope_repoint();
    assert_eq!(
        moved.write_epoch,
        minted.write_epoch + 1,
        "exactly one write-scope cut ran"
    );
    assert_ne!(moved.current_root, inherited_name);
    assert!(fx.granted_to().contains(&bearer_pk));
    assert_eq!(
        fx.committed_permission(&moved.current_root),
        Some(CorePermission::Write),
        "the claimant holds write at the root the cut moved to"
    );
}

/// ADR 0023 D3: a second claim by an identity the set already names is a
/// no-op, so the owner re-signs nothing and appends no row.
#[test]
fn a_second_claim_by_one_identity_appends_no_row() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    let invitee =
        EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
    let owner = import_contact(&opened.owner_contact_code).expect("the owner bundle verifies");
    let claim = |id: u8| InviteClaim {
        claim_id: [id; CLAIM_ID_LEN],
        scope_pointer_name: opened.scope_pointer_name.clone(),
        contact_code: contact_code(&RECIPIENT_SECRET),
        name: String::new(),
    };
    fx.post_claim(&owner, &invitee, 0, &claim(0x51), "first");
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let sequence_after_first = sequence_at(&fx.world, &write_name(fx.folder));
    let granted_after_first = fx.granted_to();

    fx.post_claim(&owner, &invitee, 1, &claim(0x52), "second");
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert!(
        inbox(&fx.owner_device).is_empty(),
        "the second claim is acked"
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(fx.folder)),
        sequence_after_first,
        "a claim that grants nothing new republishes nothing"
    );
    assert_eq!(fx.granted_to(), granted_after_first);
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
/// in one pass. The pass converts against the set it accumulates in memory, so
/// the second item finds the first item's row and grants nothing more.
#[test]
fn one_claim_delivered_twice_in_one_pass_grants_once() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    let invitee =
        EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
    let owner = import_contact(&opened.owner_contact_code).expect("the owner bundle verifies");
    let claim = InviteClaim {
        claim_id: [0x33; CLAIM_ID_LEN],
        scope_pointer_name: opened.scope_pointer_name.clone(),
        contact_code: contact_code(&RECIPIENT_SECRET),
        name: String::new(),
    };
    fx.post_claim(&owner, &invitee, 0, &claim, "twice-a");
    fx.post_claim(&owner, &invitee, 1, &claim, "twice-b");
    assert_eq!(inbox(&fx.owner_device).len(), 2);
    let before = sequence_at(&fx.world, &write_name(fx.folder));

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    let claimant = recipient_identity().verifying_key().to_sec1().to_vec();
    assert_eq!(
        fx.granted_to().iter().filter(|pk| **pk == claimant).count(),
        1,
        "one claimant holds one grant, whatever the transport delivered"
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(fx.folder)),
        before + 1,
        "and the pass publishes once"
    );
    assert!(inbox(&fx.owner_device).is_empty());
}

/// ADR 0023 D5: the ack comes first, so a failed publish leaves every acked
/// claim in the conversion record, and the next pass converts them all.
#[test]
fn a_conversion_that_cannot_publish_keeps_every_acked_claim_for_the_retry() {
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
    assert!(
        inbox(&fx.owner_device).is_empty(),
        "each claim was acked first"
    );
    assert_eq!(
        fx.granted_to(),
        committed,
        "no grant reached the record plane"
    );
    assert_eq!(
        waiting_claims(&fx),
        (3, 3),
        "the conversion record holds all three"
    );

    fx.world.record_store.heal_put_for(name.as_str());
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let granted = fx.granted_to();
    for claimant in &claimants {
        assert!(granted.contains(claimant), "the retry converts every claim");
    }
    assert_eq!(waiting_claims(&fx), (0, 0));
}

/// A claim that can never convert settles in the pass that reads it, so a
/// publish that fails keeps only the claims the retry can still grant.
#[test]
fn a_terminal_claim_leaves_the_count_when_the_publish_fails() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    fx.post_claims(&fragment, 1);
    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    let invitee =
        EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
    let owner = import_contact(&opened.owner_contact_code).expect("the owner bundle verifies");
    // The owner's own code: a conversion refuses it for good.
    let terminal = InviteClaim {
        claim_id: [0x44; CLAIM_ID_LEN],
        scope_pointer_name: opened.scope_pointer_name.clone(),
        contact_code: contact_code(&SECRET),
        name: String::new(),
    };
    fx.post_claim(&owner, &invitee, 9, &terminal, "terminal");

    let name = write_name(fx.folder);
    fx.world.record_store.fail_put_for(name.as_str());
    assert!(fx.convert().is_err(), "the publish fails");
    fx.world.record_store.heal_put_for(name.as_str());

    assert!(inbox(&fx.owner_device).is_empty(), "both claims were acked");
    assert_eq!(
        waiting_claims(&fx),
        (1, 1),
        "only the claim the retry can grant waits"
    );
}

/// ADR 0023 D9: a link admits at most its cap of claimants. The claim past the
/// cap is refused and counted, and the pass still publishes once.
#[test]
fn a_link_at_its_admission_cap_refuses_the_next_claim() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let cap = usize::try_from(DEFAULT_ADMISSION_CAP).expect("a small cap");
    let claimants = fx.post_claims(&fragment, cap + 1);
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert_eq!(sequence_at(&fx.world, &name), before + 1, "one publish");
    let granted = fx.granted_to();
    assert_eq!(
        claimants.iter().filter(|c| granted.contains(c)).count(),
        cap,
        "the link admits its cap and no more"
    );
    assert!(!granted.contains(&claimants[cap]));
    assert_eq!(refused_claims(&fx), 1, "the refusal shows on the link");
    assert_eq!(waiting_claims(&fx), (0, 0));
    assert!(inbox(&fx.owner_device).is_empty());
}

/// Fill the link at `fx.folder` to its admission cap and one past it. Answers
/// the claimants and the index of the refused one.
fn a_link_past_its_cap(fx: &mut GrantScenario) -> (Zeroizing<String>, Vec<Vec<u8>>, u8) {
    let fragment = fx.mint_link();
    let cap = usize::try_from(DEFAULT_ADMISSION_CAP).expect("a small cap");
    let claimants = fx.post_claims(&fragment, cap + 1);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_eq!(refused_claims(fx), 1);
    (fragment, claimants, u8::try_from(cap).expect("a small cap"))
}

/// ADR 0024 D3, ADR 0025 E7: a grantee revoke also cuts the link that
/// admitted the grantee, so the claims that link refused retire with it.
#[test]
fn a_grantee_revoke_retires_the_claims_its_admitting_link_refused() {
    let mut fx = GrantScenario::new();
    let (_, claimants, _) = a_link_past_its_cap(&mut fx);
    assert_eq!(recorded_refusals(&fx), 1);

    assert_eq!(fx.revoke_person(&claimants[0]), Ok(CommandOutcome::Done));

    assert_eq!(fx.link_entries(), 0, "the admitting link is cut");
    assert_eq!(recorded_refusals(&fx), 0, "and its refusals are retired");
}

/// The owner can dismiss a refusal, and the count leaves the link.
#[test]
fn a_dismissed_refusal_leaves_the_link() {
    let mut fx = GrantScenario::new();
    a_link_past_its_cap(&mut fx);

    assert_eq!(
        block_on(
            fx.engine
                .command(Command::DismissRefusedClaims { node: fx.folder })
        ),
        Ok(CommandOutcome::Done),
    );
    assert_eq!(refused_claims(&fx), 0);
}

/// The cut of a link retires the claims it refused: none of them can convert
/// through a link the set no longer carries.
#[test]
fn the_cut_of_a_link_retires_the_claims_it_refused() {
    let mut fx = GrantScenario::new();
    a_link_past_its_cap(&mut fx);
    assert_eq!(recorded_refusals(&fx), 1);

    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Ok(CommandOutcome::Done),
    );
    assert!(folder_links(&fx).is_empty(), "the link is cut");
    assert_eq!(recorded_refusals(&fx), 0, "and its refusals are retired");
}

/// The refused entries the owner device's conversion record holds.
fn recorded_refusals(fx: &GrantScenario) -> usize {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(9));
    let (events, _) = futures_channel::mpsc::unbounded();
    block_on(load_conversions(
        &fx.owner_device.staging_store,
        BookkeepingSeal::new(&enc, &entropy),
        &enc,
        &events,
    ))
    .expect("the record reads")
    .entries()
    .iter()
    .filter(|entry| entry.refused().is_some())
    .count()
}

/// ADR 0023 D5, E1: both owner devices read the same claims, and the other
/// device's acks land first. This device's acks remove nothing, so it
/// converts nothing: each claimant holds one grant, from one publish.
#[test]
fn an_ack_that_lost_the_race_converts_nothing() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 2);
    fx.owner_device.mailbox.answer_next_poll_as_of_now();
    let phone = fx.world.device(&owner_identity().verifying_key().to_sec1());
    let (phone_engine, _phone_events, mut phone_tasks) = boot_owner(&fx.world, &fx.blocks, &phone);
    tick(&fx.world, &phone_engine, &mut phone_tasks);
    let name = write_name(fx.folder);
    let after_the_winner = sequence_at(&fx.world, &name);

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    assert_eq!(
        sequence_at(&fx.world, &name),
        after_the_winner,
        "the loser publishes nothing"
    );
    let granted = fx.granted_to();
    for claimant in &claimants {
        assert_eq!(
            granted.iter().filter(|pk| *pk == claimant).count(),
            1,
            "the winner granted each claimant once"
        );
    }
    assert_eq!(waiting_claims(&fx), (0, 0), "and nothing waits here");
}

/// ADR 0023 D3: conversion runs on any owner device. A claim the first device
/// never reads converts on the tick of the second.
#[test]
fn a_claim_converts_on_the_owners_other_device() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let phone = fx.world.device(&owner_identity().verifying_key().to_sec1());
    let (phone_engine, _phone_events, mut phone_tasks) = boot_owner(&fx.world, &fx.blocks, &phone);

    tick(&fx.world, &phone_engine, &mut phone_tasks);

    assert!(
        inbox(&fx.owner_device).is_empty(),
        "the other device acked it"
    );
    assert!(
        fx.granted_to().contains(&claimants[0]),
        "and its grant reads back on the first device"
    );
}

/// ADR 0023 D5: the retry runs the whole conversion again, checks included. An
/// identity another owner device granted in the meantime is a no-op, and a
/// deadline that passed after the ack does not refuse the claim.
#[test]
fn a_retry_after_a_failed_publish_runs_the_checks_again() {
    let mut fx = GrantScenario::new();
    let deadline = UnixMillis(fx.world.scheduler.now().0 + 3_600_000);
    let CommandOutcome::InviteLinkMinted(link) =
        block_on(fx.engine.command(Command::CreateInviteLink {
            node: fx.folder,
            permission: Permission::Read,
            expires_at: Some(deadline),
            owner_name: "owner".to_owned(),
            admission_cap: None,
        }))
        .expect("the link mints")
    else {
        panic!("minting a link answers with the link");
    };
    let opened = InviteFragment::decode(&link.fragment).expect("the mint's own fragment");
    let invitee =
        EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
    let owner = import_contact(&opened.owner_contact_code).expect("the owner bundle verifies");
    let known = |id: u8| InviteClaim {
        claim_id: [id; CLAIM_ID_LEN],
        scope_pointer_name: opened.scope_pointer_name.clone(),
        contact_code: contact_code(&RECIPIENT_SECRET),
        name: String::new(),
    };
    fx.post_claim(&owner, &invitee, 30, &known(0x61), "known-a");
    let late = fx.post_claims(&link.fragment, 1);
    let name = write_name(fx.folder);
    fx.world.record_store.fail_put_for(name.as_str());
    assert!(fx.convert().is_err(), "the publish fails");
    fx.world.record_store.heal_put_for(name.as_str());

    fx.post_claim(&owner, &invitee, 31, &known(0x62), "known-b");
    let phone = fx.world.device(&owner_identity().verifying_key().to_sec1());
    let (phone_engine, _phone_events, mut phone_tasks) = boot_owner(&fx.world, &fx.blocks, &phone);
    tick(&fx.world, &phone_engine, &mut phone_tasks);
    assert!(
        fx.granted_to()
            .contains(&recipient_identity().verifying_key().to_sec1().to_vec()),
        "the other device granted the recipient"
    );
    fx.world.scheduler.advance_to(deadline);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    let recipient = recipient_identity().verifying_key().to_sec1().to_vec();
    let granted = fx.granted_to();
    assert_eq!(
        granted.iter().filter(|pk| **pk == recipient).count(),
        1,
        "the retry found the grant and appended no row"
    );
    assert!(
        granted.contains(&late[0]),
        "the deadline verdict is the one at the ack"
    );
    assert_eq!(waiting_claims(&fx), (0, 0));
}

/// A revoke with no tag over two links refuses before it reads the inbox, so
/// a waiting claim is not acked or converted and the root does not publish.
#[test]
fn a_revoke_with_no_tag_over_two_links_leaves_a_waiting_claim_on_the_inbox() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);

    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Err(EngineError::MalformedInput {
            check: "link-ambiguous"
        }),
    );

    assert_eq!(sequence_at(&fx.world, &name), before, "nothing publishes");
    assert!(!fx.granted_to().contains(&claimants[0]), "nothing converts");
    assert_eq!(waiting_claims(&fx), (0, 0), "nothing is acked");
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the claim stayed on the inbox"
    );
}

/// ADR 0023 D7: a link with a pending conversion is not cut, so no acked claim
/// loses the link it converts through.
#[test]
fn a_link_with_a_pending_conversion_refuses_the_revoke() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let name = write_name(fx.folder);
    fx.world.record_store.fail_put_for(name.as_str());
    assert!(fx.convert().is_err(), "the publish fails");

    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Err(EngineError::Seam {
            message: "link-has-a-pending-conversion".to_owned()
        }),
    );

    fx.world.record_store.heal_put_for(name.as_str());
    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Ok(CommandOutcome::Done),
        "the revoke converts the pending claim first, then cuts"
    );
    assert!(fx.granted_to().contains(&claimants[0]));
}

/// A claimant the API holds no account for can never receive its share
/// pointer. The record carries its row once the set publishes, so its entry
/// waits only for the pointer, and a revoke of the link still runs.
#[test]
fn a_claimant_the_api_does_not_know_does_not_block_the_revoke() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    fx.world.mailbox_hub.forget_recipient(&claimants[0]);

    assert!(fx.convert().is_err(), "the share pointer does not land");
    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the grant published"
    );
    assert_eq!(waiting_claims(&fx), (0, 0), "and no conversion waits");
    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Ok(CommandOutcome::Done),
    );
}

// ---------------------------------------------------------------------------
// Link-first revocation and the expired-link sweep (ADR 0025)
// ---------------------------------------------------------------------------

impl GrantScenario {
    /// The folder's grant section at the root its scope pointer names now.
    fn folder_section(&self) -> GrantSection {
        published_grant_section_at(
            &self.world,
            &self.blocks,
            &self.granted_scope_repoint().current_root,
        )
        .expect("the folder's scope root answers")
    }

    /// How many link entries the folder's owner-signed set commits.
    fn link_entries(&self) -> usize {
        self.folder_section()
            .commitment
            .entries
            .iter()
            .filter(|entry| entry.kind == GrantSetEntryKind::Link)
            .count()
    }

    fn cut_epoch(&self) -> u64 {
        self.folder_section().commitment.cut_epoch
    }

    fn revoke_link(&mut self, remove_grantees: bool) -> Result<CommandOutcome, EngineError> {
        block_on(self.engine.command(Command::RevokeInviteLink {
            node: self.folder,
            link_tag: None,
            remove_grantees,
        }))
    }

    fn revoke_person(&mut self, identity_pk: &[u8]) -> Result<CommandOutcome, EngineError> {
        block_on(self.engine.command(Command::Revoke {
            node: self.folder,
            recipient_identity_public_key: identity_pk.to_vec(),
        }))
    }

    /// Mint a link at the folder that expires at `deadline`.
    fn mint_link_until(
        &mut self,
        permission: Permission,
        deadline: UnixMillis,
    ) -> Zeroizing<String> {
        let outcome = block_on(self.engine.command(Command::CreateInviteLink {
            node: self.folder,
            permission,
            expires_at: Some(deadline),
            owner_name: "owner".to_owned(),
            admission_cap: None,
        }))
        .expect("the link mints");
        let CommandOutcome::InviteLinkMinted(link) = outcome else {
            panic!("minting a link answers with the link");
        };
        link.fragment
    }

    /// A second session of the owner on its own device, which never minted
    /// anything.
    fn owner_phone(&self) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
        let phone = self
            .world
            .device(&owner_identity().verifying_key().to_sec1());
        boot_owner(&self.world, &self.blocks, &phone)
    }

    fn an_hour_from_now(&self) -> UnixMillis {
        UnixMillis(self.world.scheduler.now().0 + 3_600_000)
    }
}

/// The instant `engine`'s sweep first cuts a link with `deadline`.
fn swept_at(engine: &Engine<FakeSeamTypes>, deadline: UnixMillis) -> UnixMillis {
    deadline.saturating_add(engine.profile().link_sweep_grace)
}

/// ADR 0025 D1: a link revoke ends every link holder at once, and the
/// grantees who joined through the link keep access. A read cut runs no name
/// wave.
#[test]
fn a_link_revoke_without_remove_grantees_keeps_the_grantees_who_joined_through_it() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 2);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let cut_epoch = fx.cut_epoch();
    let read_epoch = published_read_epoch(&fx.world, &fx.blocks, fx.folder);
    let write_epoch = fx.granted_scope_repoint().write_epoch;

    assert_eq!(fx.revoke_link(false), Ok(CommandOutcome::Done));

    assert_eq!(fx.link_entries(), 0, "the link row is cut");
    let granted = fx.granted_to();
    for claimant in &claimants {
        assert!(granted.contains(claimant), "a grantee keeps access");
    }
    assert_eq!(fx.cut_epoch(), cut_epoch + 1);
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        read_epoch + 1
    );
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        write_epoch,
        "no name wave ran"
    );
}

/// ADR 0025 D1, D4: with `remove_grantees`, the link and every grantee who
/// joined through it leave in one cut.
#[test]
fn a_link_revoke_with_remove_grantees_removes_them_in_one_cut() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    fx.post_claims(&fragment, 2);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let cut_epoch = fx.cut_epoch();
    let read_epoch = published_read_epoch(&fx.world, &fx.blocks, fx.folder);

    assert_eq!(fx.revoke_link(true), Ok(CommandOutcome::Done));

    assert_eq!(fx.link_entries(), 0);
    assert!(fx.granted_to().is_empty(), "both people are removed");
    assert_eq!(fx.cut_epoch(), cut_epoch + 1, "one cut-epoch step");
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        read_epoch + 1,
        "one rotation"
    );
}

/// ADR 0024 D3, ADR 0025 D4: a person revoke also cuts the link that admitted
/// the person, in the same rotation. Another person who joined through it
/// keeps access.
#[test]
fn a_person_revoke_cuts_the_admitting_link_in_the_same_rotation() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 2);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let cut_epoch = fx.cut_epoch();
    let read_epoch = published_read_epoch(&fx.world, &fx.blocks, fx.folder);

    assert_eq!(fx.revoke_person(&claimants[0]), Ok(CommandOutcome::Done));

    assert_eq!(fx.link_entries(), 0, "the admitting link is cut");
    let granted = fx.granted_to();
    assert!(!granted.contains(&claimants[0]));
    assert!(granted.contains(&claimants[1]));
    assert_eq!(fx.cut_epoch(), cut_epoch + 1);
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        read_epoch + 1
    );
}

/// A claim left on an inbox that does not answer could never convert after
/// the cut of the link that admitted the person, so that person's revoke is
/// refused as the link revoke is.
#[test]
fn a_mailbox_outage_refuses_the_revoke_of_a_link_admitted_grantee() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    fx.owner_device.mailbox.set_poll_failing(true);

    assert_eq!(
        fx.revoke_person(&claimants[0]),
        Err(EngineError::Seam {
            message: "mailbox-unavailable".to_owned()
        }),
    );
    assert!(fx.granted_to().contains(&claimants[0]));
    assert_eq!(fx.link_entries(), 1, "the link stays committed");

    fx.owner_device.mailbox.set_poll_failing(false);
    assert_eq!(fx.revoke_person(&claimants[0]), Ok(CommandOutcome::Done));
    assert!(fx.granted_to().is_empty());
}

/// A failed ack stops the intake, so a claim behind it stays on the inbox. The
/// person revoke that cuts the link the claim came through is refused as the
/// link revoke is. A direct grantee's revoke cuts no link, so it still runs.
#[test]
fn a_failed_ack_refuses_the_revoke_of_a_link_admitted_grantee_whose_claim_it_left_on_the_inbox() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let admitted = fx.post_claimant(&fragment, 0, 0);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let behind = fx.post_claimant(&fragment, 1, 1);
    fx.owner_device.mailbox.set_ack_failing(true);

    assert!(
        matches!(
            fx.revoke_person(&admitted),
            Err(EngineError::Seam { message }) if message.starts_with("mailbox ack")
        ),
        "the failed ack refuses the revoke"
    );
    assert_eq!(inbox(&fx.owner_device).len(), 1, "the claim waits");
    assert_eq!(fx.link_entries(), 1, "the link stays committed");
    assert!(fx.granted_to().contains(&admitted));

    let direct = recipient_identity().verifying_key().to_sec1().to_vec();
    assert_eq!(fx.revoke_person(&direct), Ok(CommandOutcome::Done));
    assert!(!fx.granted_to().contains(&direct));

    fx.owner_device.mailbox.set_ack_failing(false);
    assert_eq!(fx.revoke_person(&admitted), Ok(CommandOutcome::Done));
    let granted = fx.granted_to();
    assert!(!granted.contains(&admitted));
    assert!(
        granted.contains(&behind),
        "the waiting claim converts first"
    );
    assert_eq!(fx.link_entries(), 0, "the admitting link is cut");
}

/// No link admitted a direct grantee, so an inbox that does not answer holds
/// no claim the revoke could strand.
#[test]
fn a_mailbox_outage_leaves_the_revoke_of_a_direct_grantee() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    fx.owner_device.mailbox.set_poll_failing(true);

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done),
    );
    assert!(fx.granted_to().is_empty());
}

/// A retire whose write fails behind a landed cut refuses nothing: the
/// revoke still drops the contact the conversion recorded, and the next hold
/// of the conversion record retires the entries the cut link refused.
#[test]
fn a_retire_that_does_not_persist_is_finished_by_the_next_hold() {
    let mut fx = GrantScenario::new();
    let (_, claimants, _) = a_link_past_its_cap(&mut fx);
    let contacts = |fx: &GrantScenario| -> Vec<Vec<u8>> {
        block_on(fx.engine.sharing(fx.folder))
            .expect("a sharing read")
            .contacts
            .into_iter()
            .map(|contact| contact.identity_public_key)
            .collect()
    };
    assert!(contacts(&fx).contains(&claimants[0]));
    // The retire empties the record, so its write is the removal.
    fx.owner_device
        .staging_store
        .inner()
        .interrupt_staged_removal_after(&conversions_key(&kdf::enc_subkey(&SECRET)), 0);

    assert_eq!(fx.revoke_person(&claimants[0]), Ok(CommandOutcome::Done));
    assert_eq!(fx.link_entries(), 0, "the admitting link is cut");
    assert!(
        !contacts(&fx).contains(&claimants[0]),
        "the contact the conversion recorded is dropped"
    );
    assert_eq!(recorded_refusals(&fx), 1, "the retire did not persist");

    fx.world
        .scheduler
        .advance(fx.engine.profile().link_sweep_cadence);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(recorded_refusals(&fx), 0, "the sweep's hold retires it");
}

/// One sweep cuts the expired links of at most eight scope roots, and the
/// next tick continues with no cadence to wait out.
#[test]
fn a_sweep_past_its_cut_cap_continues_on_the_next_tick() {
    let mut fx = GrantScenario::new();
    let deadline = fx.an_hour_from_now();
    let folders: Vec<NodeId> = (0..9)
        .map(|i| {
            let folder = create_published_folder(
                &fx.world,
                &mut fx.engine,
                &mut fx._tasks,
                ROOT,
                &format!("linked-{i}"),
            );
            assert!(matches!(
                block_on(fx.engine.command(Command::CreateInviteLink {
                    node: folder,
                    permission: Permission::Read,
                    expires_at: Some(deadline),
                    owner_name: "owner".to_owned(),
                    admission_cap: None,
                })),
                Ok(CommandOutcome::InviteLinkMinted(_))
            ));
            folder
        })
        .collect();
    let live = |fx: &GrantScenario| {
        folders
            .iter()
            .filter(|folder| {
                !block_on(fx.engine.sharing(**folder))
                    .expect("a sharing read")
                    .state
                    .expect("the folder resolves")
                    .invite_links
                    .is_empty()
            })
            .count()
    };
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    fx.world
        .scheduler
        .advance_to(swept_at(&fx.engine, deadline));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(live(&fx), 1, "one sweep cuts eight scope roots");

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(live(&fx), 0, "and the next tick cuts the rest");
}

/// ADR 0025 D3: the revoke reads the person's key off the owner-attested row,
/// so an owner device whose contact book never held the person revokes.
#[test]
fn a_person_revoke_runs_on_an_owner_device_that_never_saw_the_person() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let (mut phone, _phone_events, mut phone_tasks) = fx.owner_phone();
    tick(&fx.world, &phone, &mut phone_tasks);

    assert_eq!(
        block_on(phone.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: claimants[0].clone(),
        })),
        Ok(CommandOutcome::Done),
    );

    assert!(fx.granted_to().is_empty());
    assert_eq!(fx.link_entries(), 0);
}

/// ADR 0023 D2: a write wave re-mints every row at a new tag and re-maps each
/// via-link reference, so `remove_grantees` still finds the grantees the link
/// admitted after the scope root moved.
#[test]
fn after_a_write_wave_the_via_link_references_name_the_moved_link() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link_at(Permission::Write);
    let claimants = fx.post_claims(&fragment, 1);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let converted_at = fx.granted_scope_repoint().current_root;
    assert_eq!(
        block_on(fx.engine.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: claimants[0].clone(),
            permission: Permission::Read,
        })),
        Ok(CommandOutcome::Done),
    );
    assert_ne!(
        fx.granted_scope_repoint().current_root,
        converted_at,
        "the downgrade's name wave moved the scope root"
    );
    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the downgrade keeps the grantee"
    );

    assert_eq!(fx.revoke_link(true), Ok(CommandOutcome::Done));

    assert!(
        fx.granted_to().is_empty(),
        "the re-mapped reference still names the link"
    );
    assert_eq!(fx.link_entries(), 0);
}

/// ADR 0025 D2: the sweep runs on any owner device, so a link expires on a
/// device that never minted it.
#[test]
fn the_sweep_cuts_an_expired_link_on_a_device_that_never_minted_it() {
    let mut fx = GrantScenario::new();
    let deadline = fx.an_hour_from_now();
    fx.mint_link_until(Permission::Read, deadline);
    let (phone, _phone_events, mut phone_tasks) = fx.owner_phone();
    let read_epoch = published_read_epoch(&fx.world, &fx.blocks, fx.folder);

    fx.world.scheduler.advance(Duration::from_secs(60));
    tick(&fx.world, &phone, &mut phone_tasks);
    assert_eq!(fx.link_entries(), 1, "a live link is not cut");

    fx.world.scheduler.advance_to(swept_at(&phone, deadline));
    tick(&fx.world, &phone, &mut phone_tasks);

    assert_eq!(fx.link_entries(), 0, "the expired link is cut");
    assert_eq!(
        published_read_epoch(&fx.world, &fx.blocks, fx.folder),
        read_epoch + 1
    );
}

/// A claim that one owner device acked before the deadline is not in the
/// conversion record of another. The sweep of the other device waits the
/// grace past the deadline, so the device that holds the claim converts it
/// first. After the grace, the sweep cuts the link.
#[test]
fn a_claim_another_owner_device_acked_converts_inside_the_sweep_grace() {
    let mut fx = GrantScenario::new();
    let deadline = fx.an_hour_from_now();
    let fragment = fx.mint_link_until(Permission::Read, deadline);
    let (phone, _phone_events, mut phone_tasks) = fx.owner_phone();
    let claimants = fx.post_claims(&fragment, 1);
    let name = write_name(fx.folder);
    fx.world.record_store.fail_put_for(name.as_str());
    assert!(fx.convert().is_err(), "the conversion cannot publish");
    fx.world.record_store.heal_put_for(name.as_str());
    assert_eq!(waiting_claims(&fx), (1, 1), "this device acked the claim");

    fx.world.scheduler.advance_to(deadline);
    tick(&fx.world, &phone, &mut phone_tasks);
    assert_eq!(fx.link_entries(), 1, "the other device waits for the grace");

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the device that acked the claim converts it inside the grace"
    );
    assert_eq!(fx.link_entries(), 1);

    fx.world.scheduler.advance_to(swept_at(&phone, deadline));
    tick(&fx.world, &phone, &mut phone_tasks);
    assert_eq!(
        fx.link_entries(),
        0,
        "after the grace the sweep cuts the link"
    );
}

/// ADR 0023 D4: a claim acked before the deadline converts before the sweep
/// cuts its link, so the claimant keeps the grant.
#[test]
fn a_pending_claim_on_an_expired_link_converts_before_the_cut() {
    let mut fx = GrantScenario::new();
    let deadline = fx.an_hour_from_now();
    let fragment = fx.mint_link_until(Permission::Read, deadline);
    let claimants = fx.post_claims(&fragment, 1);
    let name = write_name(fx.folder);
    fx.world.record_store.fail_put_for(name.as_str());
    assert!(fx.convert().is_err(), "the conversion cannot publish");
    fx.world.record_store.heal_put_for(name.as_str());
    assert_eq!(waiting_claims(&fx), (1, 1));

    fx.world
        .scheduler
        .advance_to(swept_at(&fx.engine, deadline));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the claim converted"
    );
    assert_eq!(fx.link_entries(), 0, "and then the link was cut");
}

/// ADR 0023 D4, ADR 0024 D4: a write claim acked before the deadline at a
/// folder with no write scope of its own stays pending while the folder does
/// not resolve. The next tick converts it through the write-scope cut, and the
/// sweep then cuts the expired link, on the owner device that never minted it.
#[test]
fn an_expired_write_link_with_a_pending_write_claim_converts_then_the_sweep_cuts_it() {
    let mut fx = GrantScenario::new();
    let deadline = fx.an_hour_from_now();
    let (mut phone, _phone_events, mut phone_tasks) = fx.owner_phone();
    tick(&fx.world, &phone, &mut phone_tasks);
    let outcome = block_on(phone.command(Command::CreateInviteLink {
        node: fx.folder,
        permission: Permission::Write,
        expires_at: Some(deadline),
        owner_name: "owner".to_owned(),
        admission_cap: None,
    }));
    let Ok(CommandOutcome::InviteLinkMinted(link)) = outcome else {
        panic!("the phone mints the link: {outcome:?}");
    };
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let claimants = fx.post_claims(&link.fragment, 1);
    let inherited_root = fx.granted_scope_repoint().current_root;
    let name = write_name(fx.folder);
    fx.world.record_store.fail_get_for(name.as_str());
    assert!(fx.convert().is_err(), "the folder does not resolve");
    fx.world.record_store.heal_get_for(name.as_str());
    assert_eq!(waiting_claims(&fx), (1, 1), "the write claim is pending");
    assert_eq!(
        fx.granted_scope_repoint().current_root,
        inherited_root,
        "and the folder still has no write scope of its own"
    );

    fx.world
        .scheduler
        .advance_to(swept_at(&fx.engine, deadline));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the write claim converted"
    );
    assert_ne!(
        fx.granted_scope_repoint().current_root,
        inherited_root,
        "through a write-scope cut"
    );
    assert_eq!(fx.link_entries(), 0, "and then the link was cut");
}

/// A grantee revoke takes the conversion lock only for a grantee a link
/// admitted, so the sweep holding it blocks no revoke of a direct grantee.
#[test]
fn a_direct_grantee_revoke_runs_while_the_sweep_holds_the_lock() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let other = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "other");
    assert!(matches!(
        block_on(fx.engine.command(Command::CreateInviteLink {
            node: other,
            permission: Permission::Read,
            expires_at: None,
            owner_name: "owner".to_owned(),
            admission_cap: None,
        })),
        Ok(CommandOutcome::InviteLinkMinted(_))
    ));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    // The tick reads `other` once on each endpoint before the sweep does.
    fx.world
        .record_store
        .stall_gets_for_after(write_name(other).as_str(), 2);
    fx.world
        .scheduler
        .advance(fx.engine.profile().link_sweep_cadence);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: other,
            remove_grantees: false,
            link_tag: None,
        })),
        Err(EngineError::Seam {
            message: "a-conversion-pass-is-running".to_owned()
        }),
        "the sweep holds the lock"
    );

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done),
    );
    assert!(fx.granted_to().is_empty());
}

/// Republish the vault root with `extra` added to its direct-child-scope
/// index, signed as any committed writer can sign it.
fn index_under_the_vault_root(fx: &GrantScenario, extra: ChildScopeRef) {
    let name = write_name(ROOT);
    let head = published_head(&fx.world, &fx.blocks, &name).expect("the vault root is published");
    let mut envelope = decode_envelope(&head).expect("the head decodes");
    let mut section = decode_grant_section(grant_section_bytes(&envelope).expect("a scope root"))
        .expect("the section decodes");
    let mut body = published_write_body(&fx.world, &fx.blocks, ROOT, envelope.epoch);
    body.direct_child_scope_index.push(extra);
    let sealed = seal(
        kdf::write_key(kdf::write_seed(&WRITE_SCOPE_SEED, &ROOT.0).as_bytes()).as_bytes(),
        &[0x5e; 24],
        &AadContext {
            v: ENVELOPE_V,
            id: ROOT.0,
            scope: ROOT.0,
            epoch: envelope.epoch,
            struct_tag: STRUCT_TAG_WRITE_BODY,
        },
        &encode_write_body(&body).expect("the body encodes"),
    );
    section.write_body = SignedSealed {
        signature: sign_structure(
            &owner_pseudonym(),
            &StructureSigInput::over_ciphertext(
                ROOT.0,
                envelope.epoch,
                STRUCT_TAG_WRITE_BODY,
                None,
                &sealed,
            ),
        )
        .to_bytes(),
        sealed,
        unknown: PreservedFields::new(),
    };
    set_grant_section(
        &mut envelope,
        encode_grant_section(&section).expect("the section encodes"),
    );
    let cid = fx
        .blocks
        .put(encode_envelope(&envelope).expect("the envelope encodes"));
    let record = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &ROOT.0).as_bytes()),
        format!("/ipfs/{cid}").as_bytes(),
        sequence_at(&fx.world, &name) + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
}

/// ADR 0025 E3: an index entry that names a scope root under the wrong
/// parent fails the gate there, and the parent that holds it still reaches it,
/// so the sweep still cuts its expired link.
#[test]
fn the_sweep_cuts_a_link_under_its_real_parent_when_another_index_names_it() {
    let mut fx = GrantScenario::new();
    let inner = fx.grant_nested_folder("inner");
    let deadline = fx.an_hour_from_now();
    assert!(matches!(
        block_on(fx.engine.command(Command::CreateInviteLink {
            node: inner,
            permission: Permission::Read,
            expires_at: Some(deadline),
            owner_name: "owner".to_owned(),
            admission_cap: None,
        })),
        Ok(CommandOutcome::InviteLinkMinted(_))
    ));
    index_under_the_vault_root(
        &fx,
        ChildScopeRef::new(inner.0, write_name(inner).as_str().as_bytes().to_vec()),
    );
    let links_at_inner = |fx: &GrantScenario| {
        published_grant_section(&fx.world, &fx.blocks, inner)
            .expect("the inner scope root answers")
            .commitment
            .entries
            .iter()
            .filter(|entry| entry.kind == GrantSetEntryKind::Link)
            .count()
    };
    assert_eq!(links_at_inner(&fx), 1);

    fx.world
        .scheduler
        .advance_to(swept_at(&fx.engine, deadline));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        links_at_inner(&fx),
        0,
        "the link is cut under its real parent"
    );
}

/// ADR 0025 D2: the sweep batches the expired links of one scope root into one
/// cut, so two cost one rotation. A personal grant there stands.
#[test]
fn two_expired_links_in_one_folder_cost_one_rotation() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let deadline = UnixMillis(world.scheduler.now().0 + 60_000);
    let grantee = recipient_row_at_root(CorePermission::Read);
    seed_vault(
        &world,
        &blocks,
        vec![
            expiring_invite_link_at_root(0x4e, deadline),
            expiring_invite_link_at_root(0x4f, deadline),
            grantee.clone(),
        ],
    );
    let alice = world.device(b"alice");
    let (engine, _events, mut tasks) = boot_owner(&world, &blocks, &alice);

    world.scheduler.advance_to(swept_at(&engine, deadline));
    tick(&world, &engine, &mut tasks);

    let section = published_grant_section(&world, &blocks, ROOT).expect("the root republished");
    assert_eq!(
        section
            .commitment
            .entries
            .iter()
            .map(|entry| entry.tag)
            .collect::<Vec<_>>(),
        vec![grantee.tag],
        "both links are cut and the grant stands"
    );
    assert_eq!(section.commitment.cut_epoch, 1, "one cut-epoch step");
    assert_eq!(
        published_read_epoch(&world, &blocks, ROOT),
        EPOCH + 1,
        "one rotation"
    );
}

/// ADR 0025 D2: two owner devices sweep one expired link in one window. Each
/// cut resolves the scope root again before it signs, so the second device
/// finds the link cut and publishes nothing: one record per sequence on every
/// endpoint.
#[test]
fn two_owner_devices_sweeping_one_window_publish_one_cut() {
    let mut fx = GrantScenario::new();
    let deadline = fx.an_hour_from_now();
    fx.mint_link_until(Permission::Read, deadline);
    let (phone, _phone_events, mut phone_tasks) = fx.owner_phone();
    let name = write_name(fx.folder);
    let sequence = sequence_at(&fx.world, &name);

    fx.world
        .scheduler
        .advance_to(swept_at(&fx.engine, deadline));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    tick(&fx.world, &phone, &mut phone_tasks);

    assert_eq!(fx.link_entries(), 0);
    assert_eq!(
        sequence_at(&fx.world, &name),
        sequence + 1,
        "one cut landed"
    );
    let served: Vec<_> = fx
        .world
        .record_store
        .endpoints()
        .iter()
        .map(|endpoint| fx.world.record_store.record_at(endpoint, name.as_str()))
        .collect();
    assert!(
        served.windows(2).all(|pair| pair[0] == pair[1]),
        "every endpoint serves the one record"
    );
}

/// A share pointer that does not land is posted again on each pass, and the
/// entry settles only when it lands, so a claimant converted near the link
/// deadline still gets its pointer.
#[test]
fn a_pointer_that_does_not_land_is_posted_again_until_it_does() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    fx.world.mailbox_hub.forget_recipient(&claimants[0]);

    assert!(fx.convert().is_err(), "the share pointer does not land");
    assert!(fx.granted_to().contains(&claimants[0]));
    assert!(fx.world.mailbox_hub.posted_keys(&claimants[0]).is_empty());

    fx.world.mailbox_hub.remember_recipient(&claimants[0]);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.world.mailbox_hub.posted_keys(&claimants[0]).len(),
        1,
        "the next pass posts the pointer"
    );
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.world.mailbox_hub.posted_keys(&claimants[0]).len(),
        1,
        "and the entry settled"
    );
}

/// The retry window of a share pointer runs from the conversion, not the ack.
/// A claim that converts past the window after its ack still gets the posts
/// of a whole window, and past that window a post that still fails settles
/// the entry.
#[test]
fn a_pointer_is_posted_again_for_the_window_after_its_conversion() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let name = write_name(fx.folder);
    let window = Duration::from_millis(POINTER_RETRY_WINDOW + 1);
    fx.world.record_store.fail_put_for(name.as_str());
    assert!(fx.convert().is_err(), "the publish fails");
    fx.world.record_store.heal_put_for(name.as_str());
    fx.world.scheduler.advance(window);
    fx.world.mailbox_hub.forget_recipient(&claimants[0]);

    assert!(fx.convert().is_err(), "the share pointer does not land");
    assert!(fx.granted_to().contains(&claimants[0]));
    assert!(
        fx.convert().is_err(),
        "the post runs again inside the window"
    );

    fx.world.scheduler.advance(window);
    assert_eq!(
        fx.convert(),
        Ok(CommandOutcome::Done),
        "past the window the failed post settles the entry"
    );
    fx.world.mailbox_hub.remember_recipient(&claimants[0]);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(
        fx.world.mailbox_hub.posted_keys(&claimants[0]).is_empty(),
        "no entry is left to post the pointer"
    );
}

/// A claim whose delete gave no answer is not converted in the pass that
/// acked it. The next pass sees the item again, deletes it, and converts it
/// once.
#[test]
fn a_claim_whose_delete_errored_converts_on_the_next_pass() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    fx.owner_device.mailbox.set_ack_failing(true);

    assert!(fx.convert().is_err(), "the delete fails");
    assert!(fx.granted_to().is_empty(), "nothing is granted");
    assert_eq!(waiting_claims(&fx), (1, 1), "one acked entry waits");

    fx.owner_device.mailbox.set_ack_failing(false);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(inbox(&fx.owner_device).is_empty());
    assert_eq!(
        fx.granted_to()
            .iter()
            .filter(|pk| **pk == claimants[0])
            .count(),
        1
    );
    assert_eq!(fx.world.mailbox_hub.posted_keys(&claimants[0]).len(), 1);
}

/// An intake whose record write fails leaves the claim on the inbox, and a
/// claim left there could never convert after the cut, so the link revoke is
/// refused. The next revoke holds the claim, converts it and cuts.
#[test]
fn a_record_write_that_fails_at_intake_refuses_the_link_revoke() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    fx.owner_device
        .staging_store
        .inner()
        .interrupt_staged_write_family_after(CONVERSION_RECORD_PREFIX, 0);
    let revoke = |fx: &mut GrantScenario| {
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        }))
    };

    assert_eq!(
        revoke(&mut fx),
        Err(EngineError::Seam {
            message: "a-claim-could-not-be-held".to_owned()
        }),
    );
    assert_eq!(inbox(&fx.owner_device).len(), 1, "the claim waits");
    assert_eq!(folder_links(&fx).len(), 1, "the link stays committed");

    assert_eq!(revoke(&mut fx), Ok(CommandOutcome::Done));
    assert!(fx.granted_to().contains(&claimants[0]));
    assert!(folder_links(&fx).is_empty(), "the link is cut");
}

/// A conversion record with no room leaves a claim on the inbox, and a claim
/// left there could never convert after the cut, so the link revoke is
/// refused. The same pass settles the entries that can never convert, so the
/// next revoke converts the claim and cuts.
#[test]
fn a_full_conversion_record_refuses_the_link_revoke() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let mut full = ConversionRecord::default();
    for i in 0..MAX_CONVERSION_ENTRIES {
        let [high, low] = u16::try_from(i).expect("fits").to_be_bytes();
        let mut sender = [0u8; IDENTITY_PUBLIC_LEN];
        sender[..2].copy_from_slice(&[high, low]);
        let claim = AckedClaim {
            sender,
            payload: vec![0xEE; 8],
            acked_at: fx.world.scheduler.now(),
        };
        full.hold_for_ack(claim.clone());
        full.settle_ack(&claim, true);
    }
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(9));
    block_on(persist_conversions(
        &fx.owner_device.staging_store,
        BookkeepingSeal::new(&enc, &entropy),
        &enc,
        &full,
    ))
    .expect("the full record stages");

    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Err(EngineError::Seam {
            message: "the-conversion-record-is-full".to_owned()
        }),
    );
    assert_eq!(inbox(&fx.owner_device).len(), 1, "the claim waits");

    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Ok(CommandOutcome::Done),
    );
    assert!(fx.granted_to().contains(&claimants[0]));
}

/// An ack that fails stops the intake, so a claim behind it stays on the inbox
/// with no entry. A claim left there could never convert after the cut, so
/// the revoke of its link is refused and publishes nothing. The next revoke
/// holds the claim, converts it and cuts.
#[test]
fn an_ack_that_fails_refuses_the_revoke_of_a_link_whose_claim_it_left_on_the_inbox() {
    let mut fx = GrantScenario::new();
    let revoked_fragment = fx.mint_link();
    let [revoked] = <[SharingInviteLink; 1]>::try_from(folder_links(&fx)).expect("one link");
    let other_fragment = fx.mint_link();
    let ahead = fx.post_claimant(&other_fragment, 0, 0);
    let behind = fx.post_claimant(&revoked_fragment, 1, 1);
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);
    fx.owner_device.mailbox.set_ack_failing(true);
    let revoke = |fx: &mut GrantScenario| {
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: Some(revoked.tag.clone()),
            remove_grantees: false,
        }))
    };

    assert!(
        matches!(
            revoke(&mut fx),
            Err(EngineError::Seam { message }) if message.starts_with("mailbox ack")
        ),
        "the failed ack refuses the revoke"
    );
    assert_eq!(inbox(&fx.owner_device).len(), 2, "both claims wait");
    assert_eq!(folder_links(&fx).len(), 2, "the link stays committed");
    assert_eq!(sequence_at(&fx.world, &name), before, "nothing publishes");

    fx.owner_device.mailbox.set_ack_failing(false);
    assert_eq!(revoke(&mut fx), Ok(CommandOutcome::Done));
    let granted = fx.granted_to();
    assert!(granted.contains(&ahead) && granted.contains(&behind));
    let [left] = <[SharingInviteLink; 1]>::try_from(folder_links(&fx)).expect("one link");
    assert_ne!(left.tag, revoked.tag, "the named link is cut");
}

/// The entry is written before the delete of its item. A crash after the
/// delete and before the next write keeps the claim, and a fresh engine on the
/// same store converts it, whatever that delete answered.
#[test]
fn a_crash_between_the_ack_and_the_record_write_keeps_the_claim() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let name = write_name(fx.folder);
    fx.world.record_store.fail_put_for(name.as_str());
    fx.owner_device
        .staging_store
        .inner()
        .interrupt_staged_write_family_after(CONVERSION_RECORD_PREFIX, 1);

    assert!(fx.convert().is_err(), "the write after the ack fails");
    assert!(inbox(&fx.owner_device).is_empty(), "the delete ran");
    fx.world.record_store.heal_put_for(name.as_str());

    serve_http(&fx.owner_device, &fx.blocks, 600);
    let (mut restarted, _restarted_events) = engine_on_api(&fx.owner_device, 43);
    block_on(restarted.start(secret(), None)).expect("the restart adopts the owner root");
    let mut tasks = fx.world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&fx.world, &restarted, &mut tasks);
    assert!(
        fx.granted_to().contains(&claimants[0]),
        "the restart converts the claim the first write kept"
    );
}

/// ADR 0024 D4: the write-scope cut moves the folder before the parent's
/// index names the moved root. When that parent publish fails, the next pass
/// finds the moved root through the owner-signed scope pointer, repairs the
/// index, and converts the claim with no second cut.
#[test]
fn a_failed_repoint_after_a_write_cut_is_repaired_by_the_next_pass() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link_at(Permission::Write);
    let minted = fx.granted_scope_repoint();
    let claimants = fx.post_claims(&fragment, 1);
    let parent = write_name(ROOT);
    fx.world.record_store.fail_put_for(parent.as_str());

    assert!(fx.convert().is_err(), "the parent publish fails");
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        minted.write_epoch + 1,
        "the write-scope cut moved the folder"
    );
    fx.world.record_store.heal_put_for(parent.as_str());

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(fx.granted_to().contains(&claimants[0]));
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        minted.write_epoch + 1,
        "exactly one write-scope cut ran"
    );
    let moved = fx.granted_scope_repoint().current_root;
    assert!(
        published_write_body(&fx.world, &fx.blocks, ROOT, EPOCH)
            .direct_child_scope_index
            .iter()
            .any(|child| child.scope_id == fx.folder.0
                && child.ipns_name == moved.as_str().as_bytes()),
        "the parent's index names the moved root"
    );
}

/// An inbox that does not answer refuses the link revoke: a claim it holds
/// could never convert after the cut. The link stays committed.
#[test]
fn a_mailbox_outage_refuses_the_link_revoke() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    fx.owner_device.mailbox.set_poll_failing(true);

    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Err(EngineError::Seam {
            message: "mailbox-unavailable".to_owned()
        }),
    );
    assert!(
        block_on(fx.engine.sharing(fx.folder))
            .expect("a sharing read")
            .state
            .expect("the link standing reads")
            .invite_links
            .len()
            == 1,
        "the link stays committed"
    );

    fx.owner_device.mailbox.set_poll_failing(false);
    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Ok(CommandOutcome::Done),
    );
    assert!(fx.granted_to().contains(&claimants[0]));
}

/// A failed inbox poll still runs the tick's conversion pass, so the claims
/// already acked convert during a mailbox outage.
#[test]
fn a_failed_poll_still_converts_the_claims_already_acked() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let name = write_name(fx.folder);
    fx.world.record_store.fail_put_for(name.as_str());
    assert!(fx.convert().is_err(), "the publish fails");
    fx.world.record_store.heal_put_for(name.as_str());
    assert_eq!(waiting_claims(&fx), (1, 1), "one acked entry waits");

    fx.owner_device.mailbox.set_poll_failing(true);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert!(fx.granted_to().contains(&claimants[0]));
    assert_eq!(waiting_claims(&fx), (0, 0));
}

/// A payload the conversion record cannot store leaves the mailbox and is
/// dropped, and the other claims of the pass convert.
#[test]
fn an_oversized_claim_leaves_the_mailbox_and_the_rest_convert() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    let invitee =
        EphemeralInvitee::from_secret(opened.invite_secret.as_bytes()).expect("valid secret");
    let owner = import_contact(&opened.owner_contact_code).expect("the owner bundle verifies");
    let oversized = InviteClaim {
        claim_id: [0x77; CLAIM_ID_LEN],
        scope_pointer_name: opened.scope_pointer_name.clone(),
        contact_code: vec![0x02; 4096],
        name: String::new(),
    };
    fx.post_claim(&owner, &invitee, 40, &oversized, "oversized");

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(inbox(&fx.owner_device).is_empty());
    assert!(fx.granted_to().contains(&claimants[0]));
    assert_eq!(waiting_claims(&fx), (0, 0));
}

/// Only a claim that passes every check asks for a write-scope cut. A claim
/// through a write link past its deadline runs none.
#[test]
fn a_write_claim_the_link_refuses_runs_no_write_cut() {
    let mut fx = GrantScenario::new();
    let deadline = UnixMillis(fx.world.scheduler.now().0 + 60_000);
    let CommandOutcome::InviteLinkMinted(link) =
        block_on(fx.engine.command(Command::CreateInviteLink {
            node: fx.folder,
            permission: Permission::Write,
            expires_at: Some(deadline),
            owner_name: "owner".to_owned(),
            admission_cap: None,
        }))
        .expect("the link mints")
    else {
        panic!("minting a link answers with the link");
    };
    let claimants = fx.post_claims(&link.fragment, 1);
    let minted = fx.granted_scope_repoint();
    fx.world.scheduler.advance_to(deadline);

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        minted.write_epoch,
        "no cut ran"
    );
    assert!(!fx.granted_to().contains(&claimants[0]));
    assert_eq!(waiting_claims(&fx), (0, 0), "the refused claim settled");
}

/// A second claim command on one link returns the claim already held and posts
/// nothing new.
#[test]
fn a_second_claim_command_returns_the_held_claim() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut bearer, _bearer_events) = fx.bearer();
    claim(&mut bearer, &fragment);
    claim(&mut bearer, &fragment);

    assert_eq!(
        fx.world
            .mailbox_hub
            .posted_keys(&owner_identity().verifying_key().to_sec1())
            .len(),
        1
    );
    assert_eq!(inbox(&fx.owner_device).len(), 1);
}

fn claim(bearer: &mut Engine<FakeSeamTypes>, fragment: &str) {
    assert_eq!(
        block_on(bearer.command(Command::ClaimInviteLink {
            fragment: Zeroizing::new(fragment.to_owned()),
            name: "Grace".to_owned(),
        })),
        Ok(CommandOutcome::Done),
    );
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
    block_on(claimant.command(Command::ClaimInviteLink {
        fragment,
        name: String::new(),
    }))
    .expect("the claim posts");
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
    block_on(claimant.command(Command::ClaimInviteLink {
        fragment,
        name: String::new(),
    }))
    .expect("the claim posts");
    fx.convert().expect("the conversion lands");

    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: other,
            recipient_identity_public_key: claimant_pk.clone(),
            permission: Permission::Read,
            grantee_name: None,
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
    block_on(claimant.command(Command::ClaimInviteLink {
        fragment,
        name: String::new(),
    }))
    .expect("the claim posts");
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
    block_on(claimant.command(Command::ClaimInviteLink {
        fragment,
        name: String::new(),
    }))
    .expect("the claim posts");
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

/// ADR 0024 D1: a holder reads at once. The join bookmarks the share with the
/// link keys, and the pass it forces reads the folder through the scope
/// pointer before the owner converts anything. The row names the folder the
/// owner signed, and reports that it reads through the link.
#[test]
fn a_link_holder_reads_the_folder_before_any_conversion() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);

    assert_eq!(
        block_on_while_ticking(
            holder.command(Command::ClaimInviteLink {
                fragment,
                name: String::new(),
            }),
            &mut holder_tasks
        ),
        Ok(CommandOutcome::Done),
    );
    // The claim files the pass and does not wait for it.
    poll_tasks_until_parked(&mut holder_tasks);

    let shares = block_on(holder.received_shares()).expect("the list reads");
    assert_eq!(shares.len(), 1, "the join bookmarked the share");
    assert_eq!(shares[0].scope, fx.folder);
    assert_eq!(shares[0].display_name, "shared");
    assert_eq!(shares[0].permission, Permission::Read);
    assert_eq!(shares[0].resolution, Some(ResolutionClass::Granted));
    assert!(shares[0].via_link, "no personal blob has landed yet");
    assert_eq!(
        inbox(&fx.owner_device).len(),
        1,
        "the claim waits for the owner"
    );
}

/// ADR 0024 D2, D4: a write conversion runs a real write wave that moves the
/// scope root. A holder that still reads through the link follows the scope
/// pointer to the moved root, and the converted claimant holds write there.
#[test]
fn a_link_holder_reads_through_the_root_a_write_conversion_moved() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link_at(Permission::Write);
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment.clone()),
        Ok(CommandOutcome::Done)
    );
    // The holder's claim is lost on the way, so it stays a link holder.
    for item in block_on(fx.owner_device.mailbox.poll()).expect("the inbox answers") {
        block_on(fx.owner_device.mailbox.ack(&item.item_id)).expect("the ack lands");
    }
    let minted = fx.granted_scope_repoint();
    let writer = fx.post_claims(&fragment, 1);

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));

    let moved = fx.granted_scope_repoint();
    assert_eq!(
        moved.write_epoch,
        minted.write_epoch + 1,
        "one write wave ran"
    );
    assert_ne!(
        moved.current_root, minted.current_root,
        "and moved the root"
    );
    let writer_row = block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved")
        .grants
        .into_iter()
        .find(|grant| grant.recipient_identity_public_key == writer[0])
        .expect("the claimant holds a row");
    assert_eq!(writer_row.permission, Permission::Write);

    tick(&fx.world, &holder, &mut holder_tasks);
    let shares = block_on(holder.received_shares()).expect("the list reads");
    assert_eq!(shares.len(), 1);
    assert!(
        shares[0].via_link,
        "the holder still reads through the link"
    );
    assert_eq!(
        shares[0].resolution,
        Some(ResolutionClass::Granted),
        "at the root the wave moved to"
    );
}

/// ADR 0023 D4: the holder's own tick posts the claim again when it falls
/// due, under the key of the first post.
#[test]
fn a_link_holders_tick_posts_the_claim_again_under_one_key() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Ok(CommandOutcome::Done)
    );

    fx.world
        .scheduler
        .advance(core::time::Duration::from_millis(CLAIM_REPOST_FIRST_WAIT));
    poll_tasks_until_parked(&mut holder_tasks);

    let keys = fx
        .world
        .mailbox_hub
        .posted_keys(&owner_identity().verifying_key().to_sec1());
    assert_eq!(keys.len(), 2, "the tick posted the claim again");
    assert_eq!(keys[0], keys[1], "under the key of the first post");
    assert_eq!(inbox(&fx.owner_device).len(), 1, "the owner holds it once");
}

/// Claim `fragment` on `holder` and let the pass it files run.
fn join_link(
    holder: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    fragment: Zeroizing<String>,
) -> Result<CommandOutcome, EngineError> {
    let outcome = block_on(holder.command(Command::ClaimInviteLink {
        fragment,
        name: String::new(),
    }));
    poll_tasks_until_parked(tasks);
    outcome
}

/// The link hold the recipient's durable list keeps for the owner's folder.
fn stored_link_hold(fx: &GrantScenario) -> Option<LinkHold> {
    let entropy = RefCell::new(SeededEntropy::new(41));
    let enc = kdf::enc_subkey(&RECIPIENT_SECRET);
    let list = block_on(
        StagingReceivedShareStore::new(&fx.recipient_device.staging_store, &enc, &entropy).load(),
    )
    .expect("the list loads");
    list.link_hold(&(owner_identity().verifying_key().to_sec1(), fx.folder.0))
        .cloned()
}

/// Whether the recipient's durable list holds a bookmark for the owner's
/// folder.
fn bookmarked(fx: &GrantScenario) -> bool {
    let entropy = RefCell::new(SeededEntropy::new(41));
    let enc = kdf::enc_subkey(&RECIPIENT_SECRET);
    block_on(
        StagingReceivedShareStore::new(&fx.recipient_device.staging_store, &enc, &entropy).load(),
    )
    .expect("the list loads")
    .find(&(owner_identity().verifying_key().to_sec1(), fx.folder.0))
    .is_some()
}

/// ADR 0027 D5 as amended: the owner signature over the fragment names covers
/// the scope pointer name. A forwarder changes the name and serves at it a
/// valid owner-signed re-point object from before a write cut, which would
/// pin the holder to the old root. The preview and the join refuse the
/// fragment, and nothing is persisted.
#[test]
fn a_fragment_with_an_altered_pointer_name_is_refused_at_the_preview_and_the_join() {
    let mut fx = GrantScenario::new();
    let mut altered = InviteFragment::decode(&fx.mint_link()).expect("the mint's own fragment");
    let owner_pointer = altered.scope_pointer_name.clone();
    let endpoints = fx.world.record_store.endpoints();
    let pre_cut = IpnsRecord::unmarshal(
        &fx.world
            .record_store
            .record_at(&endpoints[0], owner_pointer.as_str())
            .expect("the mint published the scope pointer"),
    )
    .and_then(|record| record.verify(&owner_pointer))
    .expect("the pointer record verifies")
    .value;
    let before = fx.granted_scope_repoint().current_root;
    assert_eq!(
        fx.grant_bystander(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    assert_ne!(
        fx.granted_scope_repoint().current_root,
        before,
        "the write cut moved the root"
    );
    let forwarder = cipherbox_core::suite::ed25519::Ed25519Signer::from_seed([0x6e; 32]);
    let theirs = IpnsName::from_public_key(&forwarder.verifying_key());
    let replayed = IpnsRecord::create_v2(&forwarder, &pre_cut, 1, TTL_NANOS, EOL).marshal();
    for endpoint in &endpoints {
        fx.world
            .record_store
            .seed_record(endpoint, theirs.as_str(), replayed.clone());
    }
    altered.scope_pointer_name = theirs;
    let fragment = altered.encode().expect("inside the bound");
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);

    // The web host reads this exact message as a changed link.
    let refusal = block_on(holder.preview_invite_link(&fragment)).expect_err("the preview refuses");
    assert!(matches!(refusal, EngineError::TrustViolation { .. }));
    assert_eq!(
        refusal.to_string(),
        "trust violation: invite-names-do-not-verify"
    );
    assert!(matches!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Err(EngineError::TrustViolation { .. })
    ));
    assert!(!bookmarked(&fx), "nothing is bookmarked");
    assert!(stored_link_hold(&fx).is_none(), "no link keys are stored");
    assert!(inbox(&fx.owner_device).is_empty(), "no claim posts");
}

/// ADR 0074 D2: a downgrade whose wave stands owed still posts the share
/// pointer, with the name, to the downgraded writer. The cut set landed with
/// the row at read, and the name does not depend on the root the wave moves to.
#[test]
fn an_owed_downgrade_still_posts_the_pointer_name_to_the_writer() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let granted = fx.granted_scope_repoint();
    fx.world
        .record_store
        .serve_gets_for_after(granted.current_root.as_str(), 5, usize::MAX, None);
    let folder = fx.folder;
    assert_eq!(
        command_across_retries(
            &mut fx,
            Command::ChangePermission {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
                permission: Permission::Read,
            }
        ),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the wave stands owed");
    let pointers: Vec<SharePointer> = block_on(poll_verified(
        &fx.recipient_device.mailbox,
        &kdf::enc_subkey(&RECIPIENT_SECRET),
        ENVELOPE_V,
    ))
    .expect("the inbox answers")
    .iter()
    .map(|item| SharePointer::decode(&item.payload).expect("the pointer decodes"))
    .collect();
    let downgrade = pointers
        .iter()
        .find(|pointer| pointer.permission == CorePermission::Read)
        .expect("the downgrade posts a read pointer");
    assert_eq!(downgrade.scope_pointer_name, Some(folder_pointer(&fx)));
}

/// ADR 0074 D2: a downgrade from the last copy of a planted root keeps no
/// row, and its wave stops before the moved root lands. No pointer and no
/// notice go to the writer.
#[test]
fn a_downgrade_whose_wave_stops_first_posts_nothing() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    let inbox_before = inbox(&fx.recipient_device).len();
    let old_root = fx.granted_scope_repoint().current_root;
    plant_root_at(&fx, &writer_seed, sequence_at(&fx.world, &old_root) + 1);
    fx.world
        .record_store
        .fail_put_for(folder_pointer(&fx).as_str());
    events_so_far(&mut fx._events);

    assert_eq!(downgrade_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    assert_eq!(
        inbox(&fx.recipient_device).len(),
        inbox_before,
        "no share pointer is posted"
    );
    let folder = fx.folder;
    let events = events_so_far(&mut fx._events);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::RotationWorkOwed { scope_root, .. } if *scope_root == folder
        )),
        "the wave stopped and stands owed"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::SharePointerNotPosted { .. })),
        "and no notice is sent"
    );
}

/// ADR 0074 D2: a downgrade whose share pointer post fails still completes,
/// and the owner hears of the failed post.
#[test]
fn a_downgrade_whose_pointer_post_fails_sends_the_notice() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    events_so_far(&mut fx._events);
    fx.owner_device.mailbox.set_post_failing(true);

    assert_eq!(downgrade_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    fx.owner_device.mailbox.set_post_failing(false);
    let folder = fx.folder;
    assert!(
        events_so_far(&mut fx._events).iter().any(|event| matches!(
            event,
            Event::SharePointerNotPosted { scope_root } if *scope_root == folder
        )),
        "the owner hears that the grantee was not told"
    );
}

/// ADR 0024 D5: the pointer consult runs ahead of every write. A fragment
/// whose owner code names another identity fails the re-point object's
/// verify, so the join posts no claim, records no contact and bookmarks
/// nothing.
#[test]
fn a_fragment_with_a_forged_owner_code_posts_and_records_nothing() {
    let mut fx = GrantScenario::new();
    let mut forged = InviteFragment::decode(&fx.mint_link()).expect("the mint's own fragment");
    forged.owner_contact_code = contact_code(&BYSTANDER_SECRET);
    let forger = fx.device_for(&BYSTANDER_SECRET);
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);

    assert!(matches!(
        join_link(
            &mut holder,
            &mut holder_tasks,
            forged.encode().expect("inside the bound"),
        ),
        Err(EngineError::TrustViolation { .. })
    ));
    assert!(inbox(&forger).is_empty(), "no claim posts");
    assert!(inbox(&fx.owner_device).is_empty());
    let forger_pk = EcdsaSigner::from_scalar(&BYSTANDER_SECRET)
        .expect("valid identity scalar")
        .verifying_key()
        .to_sec1()
        .to_vec();
    assert!(
        !block_on(holder.sharing(holder.root()))
            .expect("a sharing read")
            .contacts
            .into_iter()
            .any(|contact| contact.identity_public_key == forger_pk),
        "no contact is recorded"
    );
    assert!(
        block_on(holder.received_shares())
            .expect("the list reads")
            .is_empty(),
        "nothing is bookmarked"
    );
}

/// ADR 0025 D5: a join past the link's deadline answers that state and
/// posts no claim.
#[test]
fn a_join_past_the_link_deadline_is_refused_and_posts_nothing() {
    let mut fx = GrantScenario::new();
    let deadline = fx
        .world
        .scheduler
        .now()
        .saturating_add(Duration::from_secs(60));
    let outcome = block_on(fx.engine.command(Command::CreateInviteLink {
        node: fx.folder,
        permission: Permission::Read,
        expires_at: Some(deadline),
        owner_name: String::new(),
        admission_cap: None,
    }))
    .expect("the link mints");
    let CommandOutcome::InviteLinkMinted(link) = outcome else {
        panic!("minting a link answers with the link");
    };
    fx.world.scheduler.advance_to(deadline);
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);

    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, link.fragment),
        Err(EngineError::UnsupportedTarget {
            check: "link-expired"
        }),
    );
    assert!(inbox(&fx.owner_device).is_empty(), "no claim posts");
    assert!(
        block_on(holder.received_shares())
            .expect("the list reads")
            .is_empty()
    );
}

/// A pointer no endpoint answers never fails the join: the claim posts, the
/// bookmark holds the link keys, and a later pass reads the folder.
#[test]
fn a_join_whose_pointer_does_not_answer_posts_and_a_later_pass_reads() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let pointer = InviteFragment::decode(&fragment)
        .expect("the mint's own fragment")
        .scope_pointer_name;
    fx.world.record_store.fail_get_for(pointer.as_str());
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);

    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(inbox(&fx.owner_device).len(), 1, "the claim posts");
    let shares = block_on(holder.received_shares()).expect("the list reads");
    assert_eq!(shares.len(), 1, "the join bookmarked the share");
    assert!(shares[0].via_link);
    assert_ne!(shares[0].resolution, Some(ResolutionClass::Granted));

    fx.world.record_store.heal_get_for(pointer.as_str());
    block_on_while_ticking(holder.command(Command::ManualRefresh), &mut holder_tasks)
        .expect("the refresh runs");
    let shares = block_on(holder.received_shares()).expect("the list reads");
    assert_eq!(shares[0].resolution, Some(ResolutionClass::Granted));
}

/// A second join of one link keeps the deadline the first one's pass
/// verified.
#[test]
fn a_second_join_of_one_link_keeps_the_verified_deadline() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment.clone()),
        Ok(CommandOutcome::Done)
    );
    let verified = stored_link_hold(&fx)
        .expect("the join holds the link keys")
        .deadline;
    assert!(verified.is_some(), "the pass verified the link's deadline");

    assert_eq!(
        block_on(holder.command(Command::ClaimInviteLink {
            fragment,
            name: String::new(),
        })),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        stored_link_hold(&fx).expect("the link keys stay").deadline,
        verified
    );
}

/// ADR 0027 D5 as amended: a join of a fragment whose names the owner
/// signature does not cover is refused, and bookmarks nothing.
#[test]
fn a_join_whose_names_do_not_verify_is_refused() {
    let mut fx = GrantScenario::new();
    let mut relabelled = InviteFragment::decode(&fx.mint_link()).expect("the mint's own fragment");
    relabelled.folder_name = "Taxes".to_owned();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);

    assert!(matches!(
        join_link(
            &mut holder,
            &mut holder_tasks,
            relabelled.encode().expect("inside the bound"),
        ),
        Err(EngineError::TrustViolation { .. })
    ));
    assert!(
        block_on(holder.received_shares())
            .expect("the list reads")
            .is_empty()
    );
}

/// Preview `fragment` on `holder`.
fn preview(holder: &Engine<FakeSeamTypes>, fragment: &str) -> Result<InvitePreview, EngineError> {
    block_on(holder.preview_invite_link(fragment))
}

/// ADR 0028 D3: a preview reads the link and the scope root, and every store
/// it could write holds what it held: no floor, no bookmark, no contact, no
/// cache entry, no record and no mailbox item.
#[test]
fn a_preview_leaves_every_seam_store_unchanged() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);
    let before = fx.recipient_device.durable_state();

    let preview = preview(&holder, &fragment).expect("the preview reads");

    assert_eq!(preview.state, LinkPreviewState::Live);
    assert_eq!(preview.permission, Some(Permission::Read));
    assert!(!preview.joined);
    assert!(
        fx.recipient_device.durable_state() == before,
        "the preview wrote nothing"
    );
    assert!(
        fx.world.scheduler.take_spawned_tasks().is_empty(),
        "and filed no pass"
    );
}

/// ADR 0027 D5 as amended: the names show under the owner signature, and a
/// relabelled fragment is refused.
#[test]
fn a_preview_shows_the_names_only_when_the_owner_signature_verifies() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);

    assert_eq!(
        preview(&holder, &fragment)
            .expect("the preview reads")
            .names,
        Some(PreviewNames {
            owner_name: "owner".to_owned(),
            folder_name: "shared".to_owned(),
        })
    );

    let mut relabelled = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    relabelled.folder_name = "Taxes".to_owned();
    assert!(matches!(
        preview(&holder, &relabelled.encode().expect("inside the bound")),
        Err(EngineError::TrustViolation { .. })
    ));
}

/// ADR 0028 D2: one read of the scope root lists its direct children by name
/// and kind, and nothing below them.
#[test]
fn a_preview_lists_the_direct_children_by_name_and_kind_only() {
    let mut fx = GrantScenario::new();
    let drafts = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "drafts",
    );
    create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, drafts, "deep");
    block_on(fx.engine.command(Command::Create {
        parent: fx.folder,
        name: "notes.txt".into(),
        kind: NodeKind::File,
    }))
    .expect("a metadata create stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let fragment = fx.mint_link();
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);

    assert_eq!(
        preview(&holder, &fragment)
            .expect("the preview reads")
            .listing,
        vec![
            PreviewEntry {
                name: "drafts".to_owned(),
                kind: NodeKind::Folder,
            },
            PreviewEntry {
                name: "notes.txt".to_owned(),
                kind: NodeKind::File,
            },
        ]
    );
}

/// A fragment whose owner code names another identity fails the re-point
/// object's verify: a trust violation, and still no store changes.
#[test]
fn a_preview_of_a_forged_re_point_is_a_trust_violation_that_writes_nothing() {
    let mut fx = GrantScenario::new();
    let mut forged = InviteFragment::decode(&fx.mint_link()).expect("the mint's own fragment");
    forged.owner_contact_code = contact_code(&BYSTANDER_SECRET);
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);
    let before = fx.recipient_device.durable_state();

    assert!(matches!(
        preview(&holder, &forged.encode().expect("inside the bound")),
        Err(EngineError::TrustViolation { .. })
    ));
    assert!(
        fx.recipient_device.durable_state() == before,
        "the refused preview wrote nothing"
    );
}

/// ADR 0028 D5: a link past its deadline previews as expired, with the
/// permission it would have granted and no listing.
#[test]
fn a_preview_past_the_link_deadline_is_expired() {
    let mut fx = GrantScenario::new();
    let deadline = fx
        .world
        .scheduler
        .now()
        .saturating_add(Duration::from_secs(60));
    let CommandOutcome::InviteLinkMinted(link) =
        block_on(fx.engine.command(Command::CreateInviteLink {
            node: fx.folder,
            permission: Permission::Read,
            expires_at: Some(deadline),
            owner_name: String::new(),
            admission_cap: None,
        }))
        .expect("the link mints")
    else {
        panic!("minting a link answers with the link");
    };
    fx.world.scheduler.advance_to(deadline);
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);

    let preview = preview(&holder, &link.fragment).expect("the preview reads");
    assert_eq!(preview.state, LinkPreviewState::Expired);
    assert_eq!(preview.permission, Some(Permission::Read));
    assert!(preview.listing.is_empty());
}

/// A revoked link previews as revoked: the scope pointer names the root the
/// cut moved to, and its set commits no link.
#[test]
fn a_preview_of_a_revoked_link_is_revoked() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    assert_eq!(
        block_on(fx.engine.command(Command::RevokeInviteLink {
            node: fx.folder,
            link_tag: None,
            remove_grantees: false,
        })),
        Ok(CommandOutcome::Done)
    );
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);

    let preview = preview(&holder, &fragment).expect("the preview reads");
    assert_eq!(preview.state, LinkPreviewState::Revoked);
    assert_eq!(preview.permission, None);
}

/// A head block that fails its content address under the scope root's own
/// record is a gate rejection: a trust violation, never an unresolvable link.
#[test]
fn a_preview_whose_root_head_fails_its_content_address_is_a_trust_violation() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    corrupt_published_head(&fx, &write_name(fx.folder));
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);
    let before = fx.recipient_device.durable_state();

    assert!(matches!(
        preview(&holder, &fragment),
        Err(EngineError::TrustViolation { .. })
    ));
    assert!(
        fx.recipient_device.durable_state() == before,
        "the refused preview wrote nothing"
    );
}

/// Serve the head block the record at `name` points at with one byte flipped:
/// a block that fails its own content address.
fn corrupt_published_head(fx: &GrantScenario, name: &IpnsName) {
    let value = published_value(&fx.world, name);
    let cid = core::str::from_utf8(&value)
        .expect("utf8 value")
        .strip_prefix("/ipfs/")
        .expect("an /ipfs/ pointer")
        .to_owned();
    let mut head = fx.blocks.get(&cid).expect("the head block is on the plane");
    head[0] ^= 0x01;
    fx.blocks.replace(&cid, head);
}

/// Run `engine`'s loops through four stale windows.
fn settle(fx: &GrantScenario, engine: &Engine<FakeSeamTypes>, tasks: &mut [BoxedTask]) {
    for _ in 0..4 {
        fx.world.scheduler.advance(engine.profile().stale_after);
        poll_tasks_until_parked(tasks);
    }
}

/// The inbox walk assembles the scope root a share pointer names. A head block
/// that fails its content address is a gate rejection there: a trust
/// violation, and no share lands.
#[test]
fn an_inbox_pointer_whose_root_head_fails_its_content_address_is_a_trust_violation() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    corrupt_published_head(&fx, &fx.granted_scope_repoint().current_root);
    let (grantee, mut events, mut tasks) = recipient_session(&fx);

    settle(&fx, &grantee, &mut tasks);

    assert!(abuse_events(&mut events) > 0, "the rejection is reported");
    assert!(
        block_on(grantee.received_shares())
            .expect("the list reads")
            .is_empty(),
        "and no share lands"
    );
}

/// The refresh leg assembles an accepted share's scope root on every pass. A
/// head block that fails its content address is a gate rejection there: a
/// trust violation, and the share keeps the state the last pass left.
#[test]
fn a_refresh_whose_root_head_fails_its_content_address_is_a_trust_violation() {
    let mut fx = GrantScenario::new();
    create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "earlier",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let (grantee, mut events, mut tasks) = recipient_session(&fx);
    settle(&fx, &grantee, &mut tasks);
    let shares = block_on(grantee.received_shares()).expect("the list reads");
    assert_eq!(shares.len(), 1, "the grantee accepted the share");
    let listed = |engine: &Engine<FakeSeamTypes>| {
        block_on(engine.view())
            .expect("a rendered view")
            .children(fx.folder)
            .iter()
            .map(|child| child.id)
            .collect::<Vec<_>>()
    };
    let rendered = listed(&grantee);
    assert_eq!(rendered.len(), 1, "the grantee renders the shared folder");
    let _ = events_so_far(&mut events);

    create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "later",
    );
    corrupt_published_head(&fx, &fx.granted_scope_repoint().current_root);
    settle(&fx, &grantee, &mut tasks);

    assert!(abuse_events(&mut events) > 0, "the rejection is reported");
    let after = block_on(grantee.received_shares()).expect("the list reads");
    assert_eq!(
        after
            .iter()
            .map(|row| (row.scope, row.permission, row.resolution))
            .collect::<Vec<_>>(),
        vec![(
            shares[0].scope,
            shares[0].permission,
            Some(ResolutionClass::Unresolvable)
        )],
        "the share stays, and a rejected record is never a revocation"
    );
    assert_eq!(listed(&grantee), rendered, "the render does not move");
}

/// The withheld-update escalations on the stream, by name.
fn escalations(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::WithheldUpdateEscalation { ipns_name } => Some(ipns_name.clone()),
            _ => None,
        })
        .collect()
}

/// A grantee whose accepted scope root endpoint B serves one sequence behind
/// the floor while endpoint A fails (ADR 0071 D1), and the scope root's name.
fn withheld_share() -> (
    GrantScenario,
    Engine<FakeSeamTypes>,
    EventStream,
    Vec<BoxedTask>,
    Vec<u8>,
) {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let (grantee, mut events, mut tasks) = recipient_session(&fx);
    settle(&fx, &grantee, &mut tasks);
    assert_eq!(
        block_on(grantee.received_shares())
            .expect("the list reads")
            .len(),
        1,
        "the grantee accepted the share"
    );
    let name = fx
        .granted_scope_repoint()
        .current_root
        .as_str()
        .as_bytes()
        .to_vec();
    let endpoints = fx.world.record_store.endpoints();
    let (a, b) = (endpoints[0].clone(), endpoints[1].clone());
    fx.world.record_store.fail_put_endpoint(&b);
    create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "later",
    );
    fx.world.record_store.heal_put_endpoint(&b);
    settle(&fx, &grantee, &mut tasks);
    fx.world.record_store.fail_endpoint(&a);
    let _ = events_so_far(&mut events);
    (fx, grantee, events, tasks, name)
}

/// ADR 0071 Residuals: a shared scope held withheld past the escalation
/// window, while the vault root still resolves, sends one escalation and no
/// trust event.
#[test]
fn a_shared_scope_withheld_past_the_window_sends_one_escalation() {
    let (fx, grantee, mut events, mut tasks, name) = withheld_share();
    settle(&fx, &grantee, &mut tasks);
    settle(&fx, &grantee, &mut tasks);

    let seen = events_so_far(&mut events);
    assert_eq!(escalations(&seen), vec![name]);
    assert!(
        !seen
            .iter()
            .any(|event| matches!(event, Event::AttributableAbuse { .. })),
        "the hold is unavailable, not a trust verdict"
    );

    settle(&fx, &grantee, &mut tasks);
    assert!(
        escalations(&events_so_far(&mut events)).is_empty(),
        "one time per hold"
    );
}

/// A hold while no other resolve succeeds is an outage: the vault root does
/// not resolve either, so no escalation goes out, and that time does not
/// count toward the window. Once the vault root resolves again, the same
/// hold escalates one window later.
#[test]
fn a_shared_scope_withheld_in_a_full_outage_sends_no_escalation() {
    let (fx, grantee, mut events, mut tasks, name) = withheld_share();
    let store = &fx.world.record_store;
    let others: Vec<String> = store
        .routing_keys(&store.endpoints()[1])
        .into_iter()
        .filter(|key| key.as_bytes() != name.as_slice())
        .collect();
    for key in &others {
        store.fail_get_for(key);
    }
    settle(&fx, &grantee, &mut tasks);
    settle(&fx, &grantee, &mut tasks);
    assert!(escalations(&events_so_far(&mut events)).is_empty());

    for key in &others {
        fx.world.record_store.heal_get_for(key);
    }
    for _ in 0..4 {
        tick(&fx.world, &grantee, &mut tasks);
    }
    assert!(
        escalations(&events_so_far(&mut events)).is_empty(),
        "the window starts at the first healthy pass"
    );
    settle(&fx, &grantee, &mut tasks);
    assert_eq!(escalations(&events_so_far(&mut events)), vec![name]);
}

/// A grantee with a folder inside the shared scope in its focus window, whose
/// record endpoint B serves one sequence behind the floor while endpoint A
/// fails. The scope root stays honest. Answers the folder's record name.
fn withheld_shared_child() -> (
    GrantScenario,
    Engine<FakeSeamTypes>,
    EventStream,
    Vec<BoxedTask>,
    String,
) {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let (grantee, mut events, mut tasks) = recipient_session(&fx);
    settle(&fx, &grantee, &mut tasks);
    block_on(grantee.set_focus(Some(inner))).expect("the focus moves");
    settle(&fx, &grantee, &mut tasks);
    let store = &fx.world.record_store;
    let endpoints = store.endpoints();
    let (a, b) = (endpoints[0].clone(), endpoints[1].clone());
    store.fail_put_endpoint(&b);
    create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, inner, "deep");
    let store = &fx.world.record_store;
    store.heal_put_endpoint(&b);
    let lagging: Vec<String> = store
        .routing_keys(&a)
        .into_iter()
        .filter(|key| {
            store
                .record_at(&b, key)
                .is_some_and(|old| store.record_at(&a, key) != Some(old))
        })
        .collect();
    let [name] = lagging.as_slice() else {
        panic!("B lags on the inner folder alone: {lagging:?}");
    };
    let name = name.clone();
    settle(&fx, &grantee, &mut tasks);
    fx.world.record_store.fail_endpoint(&a);
    let _ = events_so_far(&mut events);
    (fx, grantee, events, tasks, name)
}

/// A withheld folder inside a shared scope, read by the focus leg while the
/// vault root resolves, sends one escalation after the window.
#[test]
fn a_withheld_shared_child_sends_one_escalation_after_the_window() {
    let (fx, grantee, mut events, mut tasks, name) = withheld_shared_child();
    tick(&fx.world, &grantee, &mut tasks);
    assert!(
        escalations(&events_so_far(&mut events)).is_empty(),
        "inside the window"
    );

    settle(&fx, &grantee, &mut tasks);
    let seen = events_so_far(&mut events);
    assert_eq!(escalations(&seen), vec![name.into_bytes()]);
    assert_eq!(abuse_events_in(&seen), 0, "the hold is no trust verdict");

    settle(&fx, &grantee, &mut tasks);
    assert!(
        escalations(&events_so_far(&mut events)).is_empty(),
        "one time per hold"
    );
}

/// A pass that gets no answer for the folder keeps the hold: a no-answer
/// read alone opens none, and the withheld reads around it count as one
/// hold. The focus leg reads the folder once per staleness interval, so each
/// phase spans at least one read.
#[test]
fn a_shared_child_hold_survives_a_pass_with_no_answer() {
    let (fx, grantee, mut events, mut tasks, name) = withheld_shared_child();
    let store = &fx.world.record_store;
    let ticks = |count: usize, tasks: &mut Vec<BoxedTask>| {
        for _ in 0..count {
            tick(&fx.world, &grantee, tasks);
        }
    };
    store.fail_get_for(&name);
    ticks(8, &mut tasks);
    assert!(
        escalations(&events_so_far(&mut events)).is_empty(),
        "no answer opens no hold"
    );

    store.heal_get_for(&name);
    ticks(3, &mut tasks);
    store.fail_get_for(&name);
    ticks(3, &mut tasks);
    store.heal_get_for(&name);
    ticks(4, &mut tasks);
    assert_eq!(
        escalations(&events_so_far(&mut events)),
        vec![name.into_bytes()],
        "the hold kept its start across the pass with no answer"
    );
}

/// A manual refresh reads with no cache, so a withheld read there has no
/// body to render. It still keeps the hold, and the event comes on time.
#[test]
fn a_manual_refresh_inside_the_window_keeps_the_shared_child_hold() {
    let (fx, mut grantee, mut events, mut tasks, name) = withheld_shared_child();
    let manual = |grantee: &mut Engine<FakeSeamTypes>, tasks: &mut Vec<BoxedTask>| {
        let _ = block_on_while_ticking(grantee.command(Command::ManualRefresh), tasks);
    };
    tick(&fx.world, &grantee, &mut tasks);
    manual(&mut grantee, &mut tasks);
    for _ in 0..3 {
        tick(&fx.world, &grantee, &mut tasks);
    }
    manual(&mut grantee, &mut tasks);
    tick(&fx.world, &grantee, &mut tasks);
    assert!(escalations(&events_so_far(&mut events)).is_empty());
    tick(&fx.world, &grantee, &mut tasks);
    assert_eq!(
        escalations(&events_so_far(&mut events)),
        vec![name.into_bytes()]
    );
}

/// A read of the folder that reaches a record ends the hold, so a later hold
/// measures a new window.
#[test]
fn a_reached_shared_child_ends_the_hold() {
    let (fx, grantee, mut events, mut tasks, name) = withheld_shared_child();
    let a = fx.world.record_store.endpoints()[0].clone();
    for _ in 0..4 {
        tick(&fx.world, &grantee, &mut tasks);
    }
    fx.world.record_store.heal_endpoint(&a);
    tick(&fx.world, &grantee, &mut tasks);
    fx.world.record_store.fail_endpoint(&a);
    for _ in 0..4 {
        tick(&fx.world, &grantee, &mut tasks);
    }
    assert!(
        escalations(&events_so_far(&mut events)).is_empty(),
        "the reached record restarted the window"
    );

    settle(&fx, &grantee, &mut tasks);
    assert_eq!(
        escalations(&events_so_far(&mut events)),
        vec![name.into_bytes()]
    );
}

/// A name that leaves the focus window ends its hold, so a hold after it
/// comes back measures a new window.
#[test]
fn a_shared_child_that_leaves_the_view_ends_its_hold() {
    let (fx, grantee, mut events, mut tasks, name) = withheld_shared_child();
    let inner = block_on(grantee.view())
        .expect("a rendered view")
        .children(fx.folder)
        .iter()
        .find(|child| child.name == "inner")
        .expect("the shared folder lists inner")
        .id;
    for _ in 0..4 {
        tick(&fx.world, &grantee, &mut tasks);
    }
    block_on(grantee.set_focus(None)).expect("the focus moves");
    for _ in 0..8 {
        tick(&fx.world, &grantee, &mut tasks);
    }
    block_on(grantee.set_focus(Some(inner))).expect("the focus moves");
    for _ in 0..3 {
        tick(&fx.world, &grantee, &mut tasks);
    }
    assert!(
        escalations(&events_so_far(&mut events)).is_empty(),
        "the hold ended when the folder left the view"
    );

    settle(&fx, &grantee, &mut tasks);
    assert_eq!(
        escalations(&events_so_far(&mut events)),
        vec![name.into_bytes()]
    );
}

/// The trust events on the stream.
fn abuse_events_in(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, Event::AttributableAbuse { .. }))
        .count()
}

/// A pointer no endpoint answers is availability, never a verdict.
#[test]
fn a_preview_whose_pointer_does_not_answer_is_unresolvable() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let pointer = InviteFragment::decode(&fragment)
        .expect("the mint's own fragment")
        .scope_pointer_name;
    fx.world.record_store.fail_get_for(pointer.as_str());
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);

    let preview = preview(&holder, &fragment).expect("the preview reads");
    assert_eq!(preview.state, LinkPreviewState::Unresolvable);
    assert!(preview.listing.is_empty());
}

/// ADR 0071 D1: endpoint B lags the joined root and endpoint A fails, so the
/// preview reads the root as unresolvable. With A up and serving B's old
/// record too, the old record is a trust violation.
#[test]
fn a_preview_of_a_lagging_root_while_an_endpoint_fails_is_unresolvable() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment.clone()),
        Ok(CommandOutcome::Done)
    );
    let endpoints = fx.world.record_store.endpoints();
    let (a, b) = (endpoints[0].clone(), endpoints[1].clone());
    fx.world.record_store.fail_put_endpoint(&b);
    create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "drafts",
    );
    fx.world.record_store.heal_put_endpoint(&b);
    tick(&fx.world, &holder, &mut holder_tasks);
    let name = write_name(fx.folder);
    let old = fx
        .world
        .record_store
        .record_at(&b, name.as_str())
        .expect("B holds the old root");
    fx.world.record_store.fail_endpoint(&a);

    let seen = preview(&holder, &fragment).expect("an endpoint failed: no verdict");
    assert_eq!(seen.state, LinkPreviewState::Unresolvable);

    fx.world.record_store.heal_endpoint(&a);
    fx.world.record_store.seed_record(&a, name.as_str(), old);
    assert!(matches!(
        preview(&holder, &fragment),
        Err(EngineError::TrustViolation { .. })
    ));
}

/// The sequence stage runs ahead of the link verdict: a rollback of the
/// joined root to a set from before the link (one that commits an older link
/// only) is a trust violation, never a revoked link. While an endpoint fails,
/// it is unresolvable (ADR 0071 D1).
#[test]
fn a_rollback_to_a_root_from_before_the_link_is_no_revoked_link() {
    let mut fx = GrantScenario::new();
    fx.mint_link();
    let name = write_name(fx.folder);
    let before_link = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], name.as_str())
        .expect("the folder root is published");
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment.clone()),
        Ok(CommandOutcome::Done)
    );
    let endpoints = fx.world.record_store.endpoints();
    for endpoint in &endpoints {
        fx.world
            .record_store
            .seed_record(endpoint, name.as_str(), before_link.clone());
    }

    assert!(matches!(
        preview(&holder, &fragment),
        Err(EngineError::TrustViolation { .. })
    ));

    fx.world.record_store.fail_endpoint(&endpoints[0]);
    let seen = preview(&holder, &fragment).expect("an endpoint failed: no verdict");
    assert_eq!(seen.state, LinkPreviewState::Unresolvable);
}

/// ADR 0028 D5: a link this account joined previews as joined, names the
/// folder the join bookmarked, and the root its pass adopted still lists.
#[test]
fn a_preview_of_a_joined_link_reads_the_root_the_join_adopted() {
    let mut fx = GrantScenario::new();
    create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "drafts",
    );
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment.clone()),
        Ok(CommandOutcome::Done)
    );
    let before = fx.recipient_device.durable_state();

    let preview = preview(&holder, &fragment).expect("the preview reads");
    assert!(preview.joined);
    assert_eq!(preview.scope, fx.folder);
    let received = block_on(holder.received_shares()).expect("the list reads");
    assert!(received.iter().any(|share| share.scope == preview.scope));
    assert_eq!(preview.state, LinkPreviewState::Live);
    assert_eq!(preview.listing.len(), 1);
    assert!(
        fx.recipient_device.durable_state() == before,
        "the preview wrote nothing"
    );
}

/// ADR 0025 E4: a person the owner cut keeps the bookmark at rest, but the
/// owner-signed set no longer grants that person. A new live link previews as
/// not joined, and the join posts a claim and holds the link again, which the
/// owner converts back into a personal grant.
#[test]
fn a_person_the_owner_cut_joins_again_through_a_new_link() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    tick(&fx.world, &holder, &mut holder_tasks);
    let recipient = recipient_identity().verifying_key().to_sec1().to_vec();
    assert_eq!(fx.revoke_person(&recipient), Ok(CommandOutcome::Done));
    fx.world.scheduler.advance(holder.profile().stale_after);
    poll_tasks_until_parked(&mut holder_tasks);
    let shares = block_on(holder.received_shares()).expect("the list reads");
    assert_eq!(
        shares[0].resolution,
        Some(ResolutionClass::RevocationSignal)
    );
    assert!(inbox(&fx.owner_device).is_empty(), "nothing waits");

    let again = fx.mint_link();
    let seen = preview(&holder, &again).expect("the preview reads");
    assert_eq!(seen.state, LinkPreviewState::Live);
    assert!(!seen.joined, "a cut bookmark is not a join");
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, again),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(inbox(&fx.owner_device).len(), 1, "the join posted a claim");
    assert!(
        stored_link_hold(&fx).is_some_and(|hold| hold.claim.is_some()),
        "the join holds the new link with its claim"
    );

    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    tick(&fx.world, &holder, &mut holder_tasks);
    let shares = block_on(holder.received_shares()).expect("the list reads");
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].resolution, Some(ResolutionClass::Granted));
    assert!(!shares[0].via_link, "the owner granted the person again");
    assert!(stored_link_hold(&fx).is_none(), "the link keys dropped");
}

/// Bookmarks live on each device. A device of a granted account that holds no
/// bookmark for the folder is offered the join, and the join records the
/// bookmark with no claim and no link hold.
#[test]
fn a_granted_account_on_a_device_with_no_bookmark_joins_with_no_claim() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    tick(&fx.world, &holder, &mut holder_tasks);

    let laptop = fx.world.device(b"the recipient's second device");
    serve_http(&laptop, &fx.blocks, 8_000);
    let (mut second, _second_events) = engine_on_api(&laptop, 23);
    block_on(second.start(LoginSecret::new(RECIPIENT_SECRET.to_vec()), None))
        .expect("the recipient's second session starts");
    let mut second_tasks = fx.world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut second_tasks);
    assert!(
        block_on(second.received_shares())
            .expect("the list reads")
            .is_empty()
    );

    let again = fx.mint_link();
    let seen = preview(&second, &again).expect("the preview reads");
    assert_eq!(seen.state, LinkPreviewState::Live);
    assert!(!seen.joined, "this device holds no bookmark to open");
    assert_eq!(
        join_link(&mut second, &mut second_tasks, again),
        Ok(CommandOutcome::Done)
    );
    assert!(
        inbox(&fx.owner_device).is_empty(),
        "the join posted no claim"
    );
    settle(&fx, &second, &mut second_tasks);
    let shares = block_on(second.received_shares()).expect("the list reads");
    assert_eq!(shares.len(), 1, "the join recorded the bookmark");
    assert_eq!(shares[0].resolution, Some(ResolutionClass::Granted));
    assert!(!shares[0].via_link, "it reads through the personal grant");
}

/// A person the owner still grants who opens another link of the same folder
/// has joined already: the preview says so, and the join posts nothing.
#[test]
fn a_granted_person_previews_a_new_link_as_joined_and_posts_nothing() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    tick(&fx.world, &holder, &mut holder_tasks);

    let second = fx.mint_link();
    let seen = preview(&holder, &second).expect("the preview reads");
    assert_eq!(seen.state, LinkPreviewState::Live);
    assert!(seen.joined, "a granted person has joined");
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, second),
        Ok(CommandOutcome::Done)
    );
    assert!(
        inbox(&fx.owner_device).is_empty(),
        "the join posted nothing"
    );
    assert!(stored_link_hold(&fx).is_none(), "and holds no link");
}

/// Gate stage 2 refuses a scope root whose owner commitment does not verify,
/// here one a later cut on this device's floor superseded: a trust violation,
/// never an unresolvable link, and no store changes.
#[test]
fn a_preview_of_a_root_whose_commitment_does_not_verify_is_a_trust_violation() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let scope_id = InviteFragment::decode(&fragment)
        .expect("the mint's own fragment")
        .scope_id;
    let (holder, _holder_events, _holder_tasks) = recipient_session(&fx);
    let floors = fx.recipient_device.floors(&RECIPIENT_SECRET);
    block_on(record_cut_epoch_floor(
        &SharerScopedFloorStore::granted_by(
            &floors,
            ContactLabel::of(
                &kdf::contact_label_seed(&RECIPIENT_SECRET),
                &owner_identity().verifying_key().to_sec1(),
            ),
        ),
        &scope_id,
        u64::MAX,
    ))
    .expect("the floor raises");
    let before = fx.recipient_device.durable_state();

    assert!(matches!(
        preview(&holder, &fragment),
        Err(EngineError::TrustViolation { .. })
    ));
    assert!(
        fx.recipient_device.durable_state() == before,
        "the refused preview wrote nothing"
    );
}

/// Run the sweeps a stalled mint filed to completion. The mint files the
/// parent's sweep, whose index self-heal names the promoted root.
fn settle_filed_sweeps(fx: &GrantScenario) {
    let mut cx = Context::from_waker(Waker::noop());
    for mut sweep in fx.world.scheduler.take_spawned_tasks() {
        let settled = (0..64).any(|_| {
            let ready = sweep.as_mut().poll(&mut cx).is_ready();
            fx.world.scheduler.advance(fx.engine.profile().poll_cadence);
            ready
        });
        assert!(settled, "the parent sweep settles");
    }
}

/// The fragment is the only copy of the invite secret. A parent publish that
/// fails after the scope root landed still hands it over, the holder joins
/// through it. The parent's sweep names the promoted root in its index, so a
/// further mint appends a link to that root.
#[test]
fn a_mint_whose_parent_publish_fails_still_hands_over_a_working_link() {
    let mut fx = GrantScenario::new();
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    let fragment = fx.mint_link();
    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());
    settle_filed_sweeps(&fx);

    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Ok(CommandOutcome::Done)
    );
    let shares = block_on(holder.received_shares()).expect("the list reads");
    assert_eq!(shares[0].resolution, Some(ResolutionClass::Granted));

    assert!(
        block_on(fx.engine.sharing(fx.folder))
            .expect("a sharing read")
            .state
            .expect("the healed index names the scope")
            .invite_links
            .len()
            == 1,
        "the sharing read reports the live link"
    );
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);
    fx.mint_link();
    assert_eq!(
        sequence_at(&fx.world, &name),
        before + 1,
        "a further mint appends a link to the indexed root"
    );
}

/// A stalled handover leaves the owner's own session holding the minted scope:
/// with no second mint, an owner write into the folder reaches the link holder.
#[test]
fn a_stalled_link_mint_leaves_the_owner_reading_the_folder() {
    let mut fx = GrantScenario::new();
    let inside = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inside",
    );
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    let fragment = fx.mint_link();
    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());
    settle_filed_sweeps(&fx);
    let later = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, inside, "later");

    let (mut holder, _holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Ok(CommandOutcome::Done)
    );
    block_on(holder.command(Command::SetFocus { node: Some(inside) })).expect("the focus moves");
    tick(&fx.world, &holder, &mut holder_tasks);
    assert!(
        block_on(holder.view())
            .expect("a rendered view")
            .children(inside)
            .iter()
            .any(|child| child.id == later),
        "the owner's write after the stall lands under the scope the link reads"
    );
}

/// A link mint whose interior move stalls files the parent's sweep, and that
/// sweep names the promoted root in the parent index. A later share of the
/// folder then appends a row to that root, and the interior move must still
/// finish, or no reader of the granted scope opens the interior.
#[test]
fn a_share_after_the_parent_sweep_heals_the_index_finishes_the_stalled_interior_move() {
    let mut fx = GrantScenario::new();
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    block_on(fx.engine.command(Command::Create {
        parent: inner,
        name: "notes.txt".into(),
        kind: NodeKind::File,
    }))
    .expect("a metadata create stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    fx.world
        .record_store
        .fail_put_for(write_name(inner).as_str());
    fx.mint_link();
    fx.world
        .record_store
        .heal_put_for(write_name(inner).as_str());
    settle_filed_sweeps(&fx);
    assert!(
        block_on(fx.engine.sharing(fx.folder))
            .expect("a sharing read")
            .state
            .is_some(),
        "the parent sweep named the promoted root in the index"
    );

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let lists_the_file = |engine: &Engine<FakeSeamTypes>| {
        block_on(engine.view())
            .expect("a rendered view")
            .children(inner)
            .iter()
            .any(|child| child.name == "notes.txt")
    };
    block_on(fx.engine.command(Command::SetFocus { node: Some(inner) })).expect("the focus moves");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        lists_the_file(&fx.engine),
        "the owner reads the interior folder"
    );

    let (mut grantee, _grantee_events, mut grantee_tasks) = recipient_session(&fx);
    settle(&fx, &grantee, &mut grantee_tasks);
    block_on(grantee.command(Command::SetFocus { node: Some(inner) })).expect("the focus moves");
    settle(&fx, &grantee, &mut grantee_tasks);
    assert!(
        lists_the_file(&grantee),
        "the grantee reads the interior folder"
    );

    let head = published_head(&fx.world, &fx.blocks, &write_name(inner))
        .expect("the interior node is published");
    assert_eq!(
        decode_envelope(&head).expect("the head decodes").scope,
        fx.folder.0,
        "the interior node belongs to the granted scope"
    );
}

/// The name of the folder's scope pointer, which a name wave re-points last.
fn folder_pointer(fx: &GrantScenario) -> IpnsName {
    scope_pointer_name(kdf::owner_pointer_seed(&SECRET).as_bytes(), &fx.folder.0)
}

/// Revoke the recipient's write grant while the scope pointer refuses every
/// publish, so the wave stops after the cut set lands. The pointer stays
/// refused until the caller heals it.
fn stop_the_revoke_wave(fx: &mut GrantScenario) {
    let _ = fx.owed_scopes();
    fx.world
        .record_store
        .fail_put_for(folder_pointer(fx).as_str());
    let folder = fx.folder;
    assert_eq!(
        command_across_retries(
            fx,
            Command::Revoke {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
            }
        ),
        Ok(CommandOutcome::Done),
        "the cut set is published, so the wave that stops is owed, not refused"
    );
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "and reported owed");
}

/// A write grant, then a revoke whose write wave stops after the read cascade
/// published the cut set. Returns the revokee's write scope seed.
fn strand_a_write_revoke(fx: &mut GrantScenario) -> [u8; 32] {
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let granted = fx.granted_scope_repoint();
    let section = published_grant_section_at(&fx.world, &fx.blocks, &granted.current_root)
        .expect("the granted root");
    let revokee_seed = grantee_write_scope_seed(&section, &granted.current_root, &fx.folder.0, 1);
    stop_the_revoke_wave(fx);
    fx.world
        .record_store
        .heal_put_for(folder_pointer(fx).as_str());
    assert_eq!(
        fx.granted_scope_repoint().current_root,
        granted.current_root,
        "the wave did not re-point the scope"
    );
    revokee_seed
}

/// The retryable refusal of a command while owed work stands at its scope.
fn work_owed() -> Result<CommandOutcome, EngineError> {
    Err(EngineError::Seam {
        message: ROTATION_WORK_OWED.to_owned(),
    })
}

/// The scope roots the stream reports owed work dropped at, with why.
fn abandoned(events: &mut EventStream) -> Vec<(NodeId, String)> {
    events_so_far(events)
        .into_iter()
        .filter_map(|event| match event {
            Event::RotationWorkAbandoned { scope_root, detail } => Some((scope_root, detail)),
            _ => None,
        })
        .collect()
}

/// ADR 0063 D5: while a cut is owed at a scope, a revoke that names another
/// grantee is refused, retryably, and that grantee keeps the grant.
#[test]
fn a_revoke_of_another_grantee_while_a_cut_is_owed_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    stop_the_revoke_wave(&mut fx);

    let folder = fx.folder;
    assert_eq!(
        command_across_retries(
            &mut fx,
            Command::Revoke {
                node: folder,
                recipient_identity_public_key: bystander_identity(),
            }
        ),
        work_owed()
    );
    assert!(
        fx.granted_to().contains(&bystander_identity()),
        "the other grantee keeps the grant"
    );
}

/// A revoke of a grantee whose share pointer is still owed cancels that
/// delivery, so no later pass hands them the grant the revoke cut.
#[test]
fn a_revoke_of_a_grantee_whose_delivery_is_owed_cancels_the_delivery() {
    let mut fx = GrantScenario::new();
    let recipient = recipient_identity().verifying_key().to_sec1();
    fx.world.mailbox_hub.forget_recipient(&recipient);
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the delivery is owed");

    assert_eq!(fx.revoke_person(&recipient), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.committed_permission(&fx.granted_scope_repoint().current_root),
        None,
        "the revoke cut the row"
    );

    fx.world.mailbox_hub.remember_recipient(&recipient);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        inbox(&fx.recipient_device).is_empty(),
        "and no pass delivers the grant the revoke cut"
    );
}

/// ADR 0063 D2: a link revoke over a scope with an owed write cut is refused
/// before any publish, so the cut stays owed and the pass finishes it.
#[test]
fn a_link_revoke_while_a_write_cut_is_owed_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let _ = fx.mint_link();
    stop_the_revoke_wave(&mut fx);
    fx.world
        .record_store
        .heal_put_for(folder_pointer(&fx).as_str());

    assert_eq!(fx.revoke_link(false), work_owed());
    assert_eq!(fx.link_entries(), 1, "the link stands");

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        3,
        "the pass finished the owed write cut"
    );
}

/// The expired-link sweep leaves a scope with owed work to a later pass, and
/// cuts the link once the owed work has landed.
#[test]
fn the_link_sweep_leaves_a_scope_with_owed_work_to_a_later_pass() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let deadline = fx.an_hour_from_now();
    let _ = fx.mint_link_until(Permission::Read, deadline);
    stop_the_revoke_wave(&mut fx);

    fx.world
        .scheduler
        .advance_to(swept_at(&fx.engine, deadline));
    fx.world
        .scheduler
        .advance(fx.engine.profile().link_sweep_cadence);
    for _ in 0..12 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(
        fx.link_entries(),
        1,
        "the sweep leaves the owed scope alone"
    );

    fx.world
        .record_store
        .heal_put_for(folder_pointer(&fx).as_str());
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    fx.world
        .scheduler
        .advance(fx.engine.profile().link_sweep_cadence);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        3,
        "the pass finished the owed write cut"
    );
    assert_eq!(fx.link_entries(), 0, "and a later sweep cut the link");
}

/// ADR 0063 D2: a share to another recipient while a mint's interior move is
/// owed is refused, and the first recipient's owed delivery still lands.
#[test]
fn a_share_to_another_recipient_while_a_mint_is_owed_is_refused() {
    let mut fx = GrantScenario::new();
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.owed_scopes(),
        vec![fx.folder],
        "the interior move is owed"
    );

    assert_eq!(fx.grant_bystander(Permission::Read), work_owed());

    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        write_name(fx.folder).as_str().as_bytes(),
        "the first recipient's owed delivery landed"
    );
}

/// A downgrade whose cut-set publish failed, with a read-back that did not
/// answer, leaves an entry whose cut never landed. Within the bound the pass
/// keeps it and runs no wave over the uncut set, and the downgrade runs again
/// over it (ADR 0068 D4).
#[test]
fn a_downgrade_whose_cut_set_never_landed_runs_again_with_no_wave_before_it() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let root = fx.granted_scope_repoint().current_root;
    let mut cut_epoch_floor = fx.folder.0.to_vec();
    cut_epoch_floor.extend_from_slice(b"/cut-epoch");
    fx.world.record_store.fail_put_for(root.as_str());
    fx.owner_device
        .floor_store
        .fail_epoch_floor_reads_after(&floor_label(&cut_epoch_floor), 1);
    let folder = fx.folder;
    let downgrade = || Command::ChangePermission {
        node: folder,
        recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        permission: Permission::Read,
    };
    assert!(
        command_across_retries(&mut fx, downgrade()).is_err(),
        "the cut set did not publish"
    );
    fx.owner_device.floor_store.heal_floors();
    fx.world.record_store.heal_put_for(root.as_str());
    let _ = events_so_far(&mut fx._events);

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        abandoned(&mut fx._events),
        vec![],
        "the pass keeps the entry"
    );
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        2,
        "no wave ran over the uncut set"
    );

    assert_eq!(
        command_across_retries(&mut fx, downgrade()),
        Ok(CommandOutcome::Done),
        "the scope still resolves, so the downgrade runs again"
    );
    assert_eq!(
        fx.committed_permission(&fx.granted_scope_repoint().current_root),
        Some(CorePermission::Read)
    );
}

/// Owed work that can never land is dropped once, with the reason, rather
/// than retried on every pass: here a delivery to a recipient this device's
/// contact book does not hold.
#[test]
fn owed_work_whose_recipient_is_unknown_is_abandoned_once() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    stage_owed_delivery_to_a_stranger(&fx);

    let (fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    for _ in 0..3 {
        tick(&fx.world, &fresh, &mut tasks);
    }
    assert_eq!(
        abandoned(&mut events),
        vec![(fx.folder, "owed-grant-recipient-unknown".to_owned())],
        "the entry is dropped once, with why"
    );
    for _ in 0..2 {
        tick(&fx.world, &fresh, &mut tasks);
    }
    let later = events_so_far(&mut events);
    assert!(
        !later.iter().any(|event| matches!(
            event,
            Event::RotationWorkOwed { .. } | Event::RotationWorkAbandoned { .. }
        )),
        "and no later pass reports it"
    );
}

/// The owner device's owed entry at the granted folder, from the record it
/// holds now.
fn owed_entry(fx: &GrantScenario) -> Option<OwedEntry> {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(11));
    block_on(
        fx.owner_device
            .staging_store
            .staged_bytes(&owed_rotation_key(&enc)),
    )
    .expect("the store answers")
    .and_then(|blob| {
        open_owed_record(BookkeepingSeal::new(&enc, &entropy), &blob)
            .expect("the record opens")
            .remove(&fx.folder)
    })
}

/// A share run again over its standing mint keeps the time the entry first
/// stopped, so a re-run does not start the bound of ADR 0065 D3 again.
#[test]
fn a_share_re_run_over_its_standing_mint_keeps_the_first_stop() {
    let mut fx = GrantScenario::new();
    let root = write_name(ROOT);
    fx.world.record_store.fail_put_for(root.as_str());
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let first = owed_entry(&fx).expect("an entry is staged").first_stop;
    assert!(first.is_some(), "the stalled move set the first stop");

    fx.world.scheduler.advance(Duration::from_secs(60));
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the move is still owed");
    assert_eq!(
        owed_entry(&fx).expect("an entry is staged").first_stop,
        first
    );
}

/// Seal `record` as the owner's owed rotation record on the owner device, for
/// the next session to read.
fn stage_owed_record(fx: &GrantScenario, record: &OwedRecord) {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(11));
    let blob =
        seal_owed_record(BookkeepingSeal::new(&enc, &entropy), record).expect("the record seals");
    block_on(
        fx.owner_device
            .staging_store
            .put_staged_bytes(&owed_rotation_key(&enc), &blob),
    )
    .expect("stage the record");
}

/// Stage an owed delivery of the folder to an identity the contact book does
/// not hold.
fn stage_owed_delivery_to_a_stranger(fx: &GrantScenario) {
    let unknown: [u8; IDENTITY_PUBLIC_LEN] = bystander_identity()
        .try_into()
        .expect("a compressed identity key");
    stage_owed_record(
        fx,
        &OwedRecord::from([(
            fx.folder,
            OwedEntry {
                cut_epoch: 0,
                first_stop: None,
                steps: vec![OwedStep::DeliverGrant {
                    recipient_identity_pk: unknown,
                    write: false,
                }],
            },
        )]),
    );
}

/// The owed delivery of the folder to the recipient at read, after an owed
/// interior move out of `left_scope`.
fn owed_move_from(fx: &GrantScenario, left_scope: NodeId) -> OwedRecord {
    OwedRecord::from([(
        fx.folder,
        OwedEntry {
            cut_epoch: 0,
            first_stop: None,
            steps: vec![
                OwedStep::InteriorMove { left_scope },
                OwedStep::DeliverGrant {
                    recipient_identity_pk: recipient_identity().verifying_key().to_sec1(),
                    write: false,
                },
            ],
        },
    )])
}

/// A folder that the writer-authored tree files under a scope other than the
/// one its owed interior move left is no grounds to drop the move: each pass
/// reports it owed, retryably, and none drops it.
#[test]
fn an_owed_move_whose_folder_sits_under_another_scope_stays_owed() {
    let mut fx = GrantScenario::new();
    let elsewhere =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "elsewhere");
    stage_owed_record(&fx, &owed_move_from(&fx, elsewhere));

    let (fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    for _ in 0..3 {
        tick(&fx.world, &fresh, &mut tasks);
    }
    let reported = events_so_far(&mut events);
    assert!(
        reported.iter().any(|event| matches!(
            event,
            Event::RotationWorkOwed { scope_root, detail, retryable: true, .. }
                if *scope_root == fx.folder && detail == "owed-interior-move-source-moved"
        )),
        "each pass reports the move owed"
    );
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, Event::RotationWorkAbandoned { .. })),
        "and none drops it"
    );
}

/// A share re-run over an owed move whose scope is already indexed would run
/// as an append, which moves no interior: it is refused, and the move stays
/// owed.
#[test]
fn a_share_re_run_over_an_indexed_scope_keeps_the_move_owed() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let elsewhere =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "elsewhere");
    stage_owed_record(&fx, &owed_move_from(&fx, elsewhere));

    let (mut fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    assert_eq!(
        block_on(fresh.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        work_owed()
    );
    let _ = events_so_far(&mut events);
    tick(&fx.world, &fresh, &mut tasks);
    assert_eq!(
        owed_scopes(&mut events),
        vec![fx.folder],
        "the move is owed"
    );
}

/// An owner relocation that carries a folder with an owed interior move into
/// another scope is refused while the move is owed, and the move stays owed.
#[test]
fn an_owner_move_of_a_folder_with_an_owed_move_into_another_scope_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let carried =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "carried");
    let root = write_name(ROOT);
    fx.world.record_store.fail_put_for(root.as_str());
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: carried,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );
    fx.world.record_store.heal_put_for(root.as_str());
    fx.world
        .record_store
        .fail_get_for(write_name(carried).as_str());

    let (mut fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    let moved = block_on(fresh.command(Command::Relink {
        node: carried,
        new_parent: fx.folder,
    }));
    assert_eq!(moved, work_owed());
    tick(&fx.world, &fresh, &mut tasks);
    assert_eq!(owed_scopes(&mut events), vec![carried], "the move is owed");
}

/// A delete of a folder whose interior move is owed is refused while the move
/// is owed: it takes the folder from the scope the move re-seals it into.
#[test]
fn a_delete_of_a_folder_with_an_owed_move_is_refused() {
    let mut fx = GrantScenario::new();
    fx.stall_the_owed_move();
    assert_eq!(
        block_on(fx.engine.command(Command::Delete { node: fx.folder })),
        work_owed()
    );
}

/// A delete of a folder above one whose interior move is owed is refused too:
/// it takes that folder from the scope the move re-seals it into.
#[test]
fn a_delete_of_a_folder_above_an_owed_move_is_refused() {
    let mut fx = GrantScenario::new();
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "outer");
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, outer, "inner");
    let root = write_name(ROOT);
    fx.world.record_store.fail_put_for(root.as_str());
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: inner,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.owed_scopes(), vec![inner], "the interior move is owed");
    fx.world.record_store.heal_put_for(root.as_str());

    assert_eq!(
        block_on(fx.engine.command(Command::Delete { node: outer })),
        work_owed()
    );
}

/// Bin `outer`, created under `parent`, and the folder inside it, and stage an
/// owed interior move of that folder out of the vault root's scope for the next
/// session.
fn bin_a_folder_over_an_owed_move(fx: &mut GrantScenario, parent: NodeId) -> (NodeId, NodeId) {
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, parent, "outer");
    let inner = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, outer, "inner");
    assert!(matches!(
        block_on(fx.engine.command(Command::Delete { node: outer })),
        Ok(CommandOutcome::Queued { .. })
    ));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    stage_owed_record(
        fx,
        &OwedRecord::from([(
            inner,
            OwedEntry {
                cut_epoch: 0,
                first_stop: None,
                steps: vec![OwedStep::InteriorMove { left_scope: ROOT }],
            },
        )]),
    );
    (outer, inner)
}

/// A restore into the binned folder's own scope is refused while a folder
/// inside it owes an interior move out of another scope: the restore would take
/// that folder from the scope the move re-seals it into.
#[test]
fn a_restore_of_a_binned_folder_above_an_owed_move_out_of_another_scope_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let folder = fx.folder;
    let (outer, _) = bin_a_folder_over_an_owed_move(&mut fx, folder);
    assert_eq!(
        binned_scope(&fx, outer),
        Some(folder.0),
        "the entry is filed under the shared folder's scope"
    );

    let (mut fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    assert_eq!(
        block_on(fresh.command(Command::Restore {
            node: outer,
            into: Some(folder),
        })),
        work_owed()
    );
}

/// A purge of a binned folder above one whose interior move is owed is
/// refused while the move is owed.
#[test]
fn a_purge_of_a_binned_folder_above_an_owed_move_is_refused() {
    let mut fx = GrantScenario::new();
    let (outer, _) = bin_a_folder_over_an_owed_move(&mut fx, ROOT);

    let (mut fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    assert_eq!(
        block_on(fresh.command(Command::Purge { node: outer })),
        work_owed()
    );
}

/// A restore of a binned folder whose interior move is owed is refused into
/// another scope, and lands in the scope the move left.
#[test]
fn a_restore_of_a_folder_with_an_owed_move_into_another_scope_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let binned = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "binned");
    assert!(matches!(
        block_on(fx.engine.command(Command::Delete { node: binned })),
        Ok(CommandOutcome::Queued { .. })
    ));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    stage_owed_record(
        &fx,
        &OwedRecord::from([(
            binned,
            OwedEntry {
                cut_epoch: 0,
                first_stop: None,
                steps: vec![OwedStep::InteriorMove { left_scope: ROOT }],
            },
        )]),
    );

    let (mut fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    assert_eq!(
        block_on(fresh.command(Command::Restore {
            node: binned,
            into: Some(fx.folder),
        })),
        Err(EngineError::RestoreCrossesScope)
    );
    assert!(
        matches!(
            block_on(fresh.command(Command::Restore {
                node: binned,
                into: None,
            })),
            Ok(CommandOutcome::Queued { .. })
        ),
        "a restore into the scope the move left is not refused"
    );
}

/// A crossing queued before the share waits while the interior move of the
/// folder it carries is owed: no attempt is spent and no trust violation is
/// raised over the owner's own promoted root.
#[test]
fn a_queued_crossing_of_a_folder_with_an_owed_move_waits_for_the_move() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let carried =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "carried");
    assert!(matches!(
        block_on(fx.engine.command(Command::Relink {
            node: carried,
            new_parent: fx.folder,
        })),
        Ok(CommandOutcome::Queued { .. })
    ));
    let root = write_name(ROOT);
    fx.world.record_store.fail_put_for(root.as_str());
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: carried,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.owed_scopes(), vec![carried], "the interior move is owed");

    for _ in 0..8 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(
        abuse_events(&mut fx._events),
        0,
        "no trust violation is raised"
    );
    assert!(
        block_on(fx.engine.status())
            .expect("the status reads")
            .dead_letters
            .is_empty(),
        "and no attempt is spent"
    );
    assert_eq!(
        queued_crossings(&fx.owner_device),
        vec![ScopeCrossing::Cross],
        "the crossing waits for the move"
    );

    fx.world.record_store.heal_put_for(root.as_str());
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(fx.owed_scopes(), vec![], "the owed move landed");
}

/// An owed rotation record this build cannot open is left as it is, and a
/// command that would owe work refuses before its first publish rather than
/// write a fresh record over it.
#[test]
fn an_owed_record_that_does_not_open_is_never_written_over() {
    let fx = GrantScenario::new();
    let key = owed_rotation_key(&kdf::enc_subkey(&SECRET));
    let unreadable = b"not an owed rotation record".to_vec();
    block_on(
        fx.owner_device
            .staging_store
            .put_staged_bytes(&key, &unreadable),
    )
    .expect("stage the bytes");
    let root_before = sequence_at(&fx.world, &write_name(ROOT));

    let (mut fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    assert!(
        block_on(fresh.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        }))
        .is_err(),
        "the grant refuses"
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(ROOT)),
        root_before,
        "before any publish"
    );
    assert_eq!(
        block_on(fx.owner_device.staging_store.staged_bytes(&key)),
        Ok(Some(unreadable)),
        "and the stored record is untouched"
    );
}

/// A record at the folder's name with no grant section does not prove a
/// promotion never ran: a parent-scope writer can publish one. The interior
/// move stays owed rather than being dropped.
#[test]
fn an_interior_move_over_a_root_with_no_grant_section_stays_owed() {
    let mut fx = GrantScenario::new();
    let unpromoted = published_value(&fx.world, &write_name(fx.folder));
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.owed_scopes(),
        vec![fx.folder],
        "the interior move is owed"
    );
    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());

    publish_value_at(&fx.world, fx.folder, &unpromoted);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        fx.owed_scopes(),
        vec![fx.folder],
        "the entry stays owed and is reported"
    );
}

/// ADR 0063 D4: the walk reads the owed scopes from the record the re-drive
/// reads, so a staging read that fails after the session loaded it does not
/// stall the walk.
#[test]
fn the_renewal_walk_reads_the_owed_record_the_re_drive_reads() {
    let mut fx = GrantScenario::new();
    let recipient = recipient_identity().verifying_key().to_sec1();
    fx.world.mailbox_hub.forget_recipient(&recipient);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "outer");
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let outer_before = sequence_at(&fx.world, &write_name(outer));

    fx.owner_device
        .staging_store
        .inner()
        .fail_staged_reads_under(OWED_ROTATION_PREFIX);
    fx.world
        .scheduler
        .advance(Duration::from_secs(65 * 24 * 60 * 60));
    let _ = events_so_far(&mut fx._events);
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert!(
        !events_so_far(&mut fx._events).iter().any(|event| matches!(
            event,
            Event::RenewalFailed { detail, .. } if detail.contains("owed rotation record")
        )),
        "the walk does not stall on the store read"
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(outer)),
        outer_before + 1,
        "and renews the scope with no owed work"
    );
}

/// Drive `command` to its end, moving virtual time on by one poll cadence each
/// time it sleeps between attempts.
fn command_across_retries(
    fx: &mut GrantScenario,
    command: Command,
) -> Result<CommandOutcome, EngineError> {
    run_across_retries(&fx.world, &mut fx.engine, command)
}

/// [`command_across_retries`] on any engine of `world`.
fn run_across_retries(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    command: Command,
) -> Result<CommandOutcome, EngineError> {
    let cadence = engine.profile().poll_cadence;
    let scheduler = world.scheduler.clone();
    let mut future = pin!(engine.command(command));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(outcome) = future.as_mut().poll(&mut cx) {
            return outcome;
        }
        scheduler.advance(cadence);
    }
    panic!("the command never settled");
}

/// The revoke's cut is done: the scope moved one write epoch, the revokee's
/// seed derives no name it answers at, and the moved root commits no row for
/// them.
fn assert_the_revoke_finished(fx: &GrantScenario, revokee_seed: &[u8; 32]) {
    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, 3, "one wave past the grant's");
    assert_ne!(
        derive_write_name(revokee_seed, &fx.folder.0),
        after.current_root,
        "the revokee's seed no longer derives the scope's root"
    );
    assert_eq!(fx.committed_permission(&after.current_root), None);
}

/// ADR 0063 D3: a revoke whose write wave stops after the cut set publishes
/// is owed work, and the next sync pass finishes it with no command.
#[test]
fn a_revoke_whose_write_wave_stops_is_finished_by_the_next_pass() {
    let mut fx = GrantScenario::new();
    let revokee_seed = strand_a_write_revoke(&mut fx);

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_the_revoke_finished(&fx, &revokee_seed);
    assert!(fx.owed_scopes().is_empty(), "and nothing is owed");
}

/// ADR 0063 D5: the same revoke run again re-drives the owed work. The row is
/// already cut, so the command finishes what it owes and is not refused as a
/// revoke of a grant nobody holds.
#[test]
fn a_revoke_run_again_over_its_owed_wave_finishes_it() {
    let mut fx = GrantScenario::new();
    let revokee_seed = strand_a_write_revoke(&mut fx);

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );

    assert_the_revoke_finished(&fx, &revokee_seed);
    assert!(fx.owed_scopes().is_empty(), "and nothing is owed");
}

/// ADR 0063 D5: once the pass has finished the owed revoke, the same revoke
/// finds no entry and no grant, and says so.
#[test]
fn a_revoke_after_the_pass_finished_it_is_refused_as_not_granted() {
    let mut fx = GrantScenario::new();
    let _ = strand_a_write_revoke(&mut fx);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Err(EngineError::MalformedInput {
            check: "rot-revoke-not-granted",
        })
    );
}

/// The owner's second device holds no owed entry, so it finishes the write
/// cut of a stalled revoke with a write rotate-now. The first device's pass
/// then finds the cut landed, clears its entry, and cuts nothing again.
#[test]
fn another_owner_device_finishes_a_stalled_write_revoke() {
    let mut fx = GrantScenario::new();
    let revokee_seed = strand_a_write_revoke(&mut fx);
    // The revoke's one-shot sweep would end inside the other device's boot.
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut other, _other_events, _other_tasks) = fx.second_owner_device();

    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut other,
            Command::RotateWriteNow { node: fx.folder }
        ),
        Ok(CommandOutcome::Done),
    );
    assert_the_revoke_finished(&fx, &revokee_seed);
    let landed = fx.granted_scope_repoint();
    assert!(
        owed_entry(&fx).is_some(),
        "the first device still owes the cut"
    );

    tick(&fx.world, &fx.engine, &mut fx._tasks);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        fx.granted_scope_repoint(),
        landed,
        "the first device's re-drive cut nothing again"
    );
    assert!(owed_entry(&fx).is_none(), "and cleared its entry");
    assert!(fx.owed_scopes().is_empty(), "and reports nothing owed");
}

/// A grant whose write-scope cut stalled leaves a root whose name its write
/// seed does not derive. Another owner device finishes that cut with a write
/// rotate-now, and the moved root conveys the write seed to the grantee.
#[test]
fn another_owner_device_finishes_a_stalled_write_scope_cut() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);
    let (mut other, _other_events, _other_tasks) = fx.second_owner_device();

    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut other,
            Command::RotateWriteNow { node: fx.folder }
        ),
        Ok(CommandOutcome::Done),
    );

    let moved = fx.granted_scope_repoint();
    assert_ne!(moved.current_root, stalled, "the write cut ran");
    assert_eq!(
        fx.granted_blob_carries_write_seed(&moved.current_root),
        Some(true)
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        fx.granted_scope_repoint(),
        moved,
        "the first device's re-drive cut nothing again"
    );
}

/// The owner's second device appends a row after this device's command read
/// the root. The cut set the command read no longer stands, so the command
/// publishes nothing, and the appended row survives.
#[test]
fn a_write_rotate_now_over_a_stale_read_keeps_a_row_another_device_appended() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    drop(fx.world.scheduler.take_spawned_tasks());
    let before = fx.granted_scope_repoint();
    let root = before.current_root.clone();
    let read = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    let (mut other, _other_events, _other_tasks) = fx.second_owner_device();
    block_on(other.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second recipient's code imports");
    assert_eq!(
        block_on(other.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
        "the other device appends a row"
    );
    serve_the_walk_one_cut_behind(&fx, &root, read);
    let folder = fx.folder;

    let outcome = command_across_retries(&mut fx, Command::RotateWriteNow { node: folder });

    assert!(outcome.is_err(), "the stale cut is refused: {outcome:?}");
    assert_eq!(fx.granted_scope_repoint(), before, "no wave ran");
    let bystander_tag = recipient_blinded_tag(
        &kdf::enc_subkey(&BYSTANDER_SECRET),
        &kdf::enc_subkey(&SECRET).public(),
        root.as_str().as_bytes(),
    )
    .expect("a contributory owner key");
    assert!(
        published_grant_section_at(&fx.world, &fx.blocks, &root)
            .expect("the root")
            .commitment
            .entries
            .iter()
            .any(|entry| entry.tag == bystander_tag),
        "the appended row survives"
    );
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// ADR 0068 D1, D3 and D5: the revokee plants a record the gate refuses at
/// the root name, and the device that owes the stalled cut is gone. Another
/// owner device's write rotate-now reads the root from its last copy, moves
/// the root first, keeps no grant row, and reports the refusal once.
#[test]
fn a_write_rotate_now_cuts_a_planted_root_from_its_last_copy() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut other, mut other_events, _other_tasks) = fx.second_owner_device();
    let old_root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    assert_eq!(plant_root_at(&fx, &revokee_seed, sequence), old_root);
    let planted = published_value(&fx.world, &old_root);
    let _ = events_so_far(&mut other_events);

    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut other,
            Command::RotateWriteNow { node: fx.folder }
        ),
        Ok(CommandOutcome::Done)
    );

    let events = events_so_far(&mut other_events);
    assert_eq!(root_refusals(&fx, &events, sequence), 1, "one trust event");
    assert_the_revokee_is_cut(&fx, &revokee_seed);
    let moved = fx.granted_scope_repoint().current_root;
    assert!(
        published_grant_section_at(&fx.world, &fx.blocks, &moved)
            .expect("the moved root")
            .commitment
            .entries
            .is_empty(),
        "the cut from the last copy keeps no grant row"
    );
    assert_eq!(
        published_value(&fx.world, &old_root),
        planted,
        "nothing publishes at the old root name"
    );
}

/// ADR 0068 D5: a writer plants at the root name after the command read the
/// root whole, and the root already carried the cut set. The wave's root read
/// falls back to the last copy, and a cut that keeps rows does not run over a
/// copy, so the wave stays owed. The next call re-drives it as a cut from the
/// last copy that keeps no row, and tells the host once.
#[test]
fn a_write_rotate_now_over_a_root_planted_after_its_read_owes_the_wave() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    let before = fx.granted_scope_repoint();
    let root = before.current_root.clone();
    let honest = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    let sequence = sequence_at(&fx.world, &root) + 1;
    assert_eq!(plant_root_at(&fx, &writer_seed, sequence), root);
    let planted = published_value(&fx.world, &root);
    // The command read and the cut-set publish read meet the honest root;
    // every later read meets the plant.
    let endpoints = fx.world.record_store.endpoints().len();
    fx.world
        .record_store
        .serve_gets_for_after(root.as_str(), 0, 2 * endpoints, honest);
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.granted_scope_repoint(), before, "no wave ran");
    assert_eq!(
        owed_entry(&fx).map(|entry| entry.steps),
        Some(vec![OwedStep::WriteCut {
            write_epoch: before.write_epoch + 1
        }])
    );

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done)
    );
    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, before.write_epoch + 1);
    assert_ne!(
        derive_write_name(&writer_seed, &fx.folder.0),
        after.current_root
    );
    assert!(
        published_grant_section_at(&fx.world, &fx.blocks, &after.current_root)
            .expect("the moved root")
            .commitment
            .entries
            .is_empty(),
        "the cut from the last copy keeps no row"
    );
    assert_eq!(published_value(&fx.world, &root), planted);
    assert_eq!(
        abandoned(&mut fx._events),
        vec![(folder, "owed-grants-dropped-from-last-copy".to_owned())]
    );
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// ADR 0068 D5: every plane read before the wave meets the honest root, and
/// the wave's own root read meets a plant. That read falls back to the last
/// copy, so the wave refuses before it publishes, and the writer gets no
/// fresh write seed.
#[test]
fn a_write_rotate_now_whose_wave_root_read_falls_back_owes_the_wave() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    let before = fx.granted_scope_repoint();
    let root = before.current_root.clone();
    let honest = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    let sequence = sequence_at(&fx.world, &root) + 1;
    assert_eq!(plant_root_at(&fx, &writer_seed, sequence), root);
    let planted = published_value(&fx.world, &root);
    // The command read, the cut-set publish read and the write plane's read
    // meet the honest root; the wave's root read meets the plant.
    let endpoints = fx.world.record_store.endpoints().len();
    fx.world
        .record_store
        .serve_gets_for_after(root.as_str(), 0, 3 * endpoints, honest);
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(fx.granted_scope_repoint(), before, "no wave ran");
    assert_eq!(published_value(&fx.world, &root), planted);
    assert_eq!(
        owed_entry(&fx).map(|entry| entry.steps),
        Some(vec![OwedStep::WriteCut {
            write_epoch: before.write_epoch + 1
        }])
    );
}

/// ADR 0063 D5: this device's owed write cut re-drives first, and the
/// finished re-drive is the cut, so the scope moves one write epoch.
#[test]
fn a_write_rotate_now_finishes_this_devices_owed_write_cut_once() {
    let mut fx = GrantScenario::new();
    let revokee_seed = strand_a_write_revoke(&mut fx);
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done)
    );

    assert_the_revoke_finished(&fx, &revokee_seed);
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// ADR 0063 D5: an owed entry with no write cut re-drives first, and the
/// command still cuts the write plane after it.
#[test]
fn a_write_rotate_now_cuts_after_an_owed_entry_with_no_write_cut() {
    let mut fx = GrantScenario::new();
    fx.stall_the_owed_move();
    let before = fx.granted_scope_repoint();
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done)
    );

    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, before.write_epoch + 1);
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// ADR 0063 D5: an owed entry the re-drive cannot finish refuses the
/// command, retryably, and stays for the sync pass.
#[test]
fn a_write_rotate_now_over_work_still_owed_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    stop_the_revoke_wave(&mut fx);
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        work_owed()
    );
    assert!(owed_entry(&fx).is_some(), "the entry stands for the pass");
}

/// Device A owes a write cut that device B already ran. Device B then revokes
/// a second writer and its wave stalls. A's write rotate-now finds its own
/// entry landed, which ran no wave in the call, so it cuts the write plane
/// itself and the second writer's seed derives no new root name.
#[test]
fn a_write_rotate_now_over_a_write_cut_landed_elsewhere_still_cuts() {
    let mut fx = GrantScenario::new();
    let _ = strand_a_write_revoke(&mut fx);
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut other, _other_events, _other_tasks) = fx.second_owner_device();
    let folder = fx.folder;
    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut other,
            Command::RotateWriteNow { node: folder }
        ),
        Ok(CommandOutcome::Done)
    );
    block_on(other.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second writer's code imports");
    assert_eq!(
        block_on(other.command(Command::Grant {
            node: folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Write,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );
    let granted = fx.granted_scope_repoint();
    fx.world
        .record_store
        .fail_put_for(folder_pointer(&fx).as_str());
    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut other,
            Command::Revoke {
                node: folder,
                recipient_identity_public_key: bystander_identity(),
            }
        ),
        Ok(CommandOutcome::Done),
        "the second revoke's wave stalls and is owed on device B"
    );
    fx.world
        .record_store
        .heal_put_for(folder_pointer(&fx).as_str());
    assert_eq!(fx.granted_scope_repoint(), granted, "no wave re-pointed");
    assert!(
        owed_entry(&fx).is_some(),
        "device A still holds its old entry"
    );

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done)
    );

    let after = fx.granted_scope_repoint();
    assert_eq!(
        after.write_epoch,
        granted.write_epoch + 1,
        "one wave in the call"
    );
    let bystander_tag = recipient_blinded_tag(
        &kdf::enc_subkey(&BYSTANDER_SECRET),
        &kdf::enc_subkey(&SECRET).public(),
        after.current_root.as_str().as_bytes(),
    )
    .expect("a contributory owner key");
    assert!(
        published_grant_section_at(&fx.world, &fx.blocks, &after.current_root)
            .expect("the moved root")
            .commitment
            .entries
            .iter()
            .all(|entry| entry.tag != bystander_tag),
        "the revoked second writer holds no row at the moved root"
    );
    assert_ne!(after.current_root, granted.current_root);
    assert!(owed_entry(&fx).is_none(), "and device A owes nothing");
}

/// ADR 0068 D4 as amended: a write rotate-now over an entry whose cut never
/// landed runs its own cut, which replaces the entry, and the host learns
/// that the first cut went.
#[test]
fn a_write_rotate_now_over_a_cut_that_never_landed_replaces_it() {
    let mut fx = GrantScenario::new();
    let (_, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    let old_root = fx.granted_scope_repoint().current_root;
    let honest = published_value(&fx.world, &old_root);
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    plant_root_at(&fx, &revokee_seed, sequence);
    let _ = revoke_the_recipient(&mut fx);
    // The root the gate admits stands again, so the re-drive finds the cut
    // never landed.
    sign_at(&fx, &revokee_seed, fx.folder, &honest, sequence + 1);
    let before = fx.granted_scope_repoint();
    let _ = events_so_far(&mut fx._events);
    let folder = fx.folder;

    let outcome = command_across_retries(&mut fx, Command::RotateWriteNow { node: folder });

    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(
        abandoned(&mut fx._events),
        vec![(fx.folder, "owed-cut-replaced".to_owned())]
    );
    // The planted head still stops the wave, so the command's own cut is
    // what stands owed now.
    assert_eq!(
        owed_entry(&fx).map(|entry| entry.steps),
        Some(vec![OwedStep::WriteCut {
            write_epoch: before.write_epoch + 1
        }])
    );
}

/// An owed read cut on a scope with a write row, then a plant at the root.
/// The re-drive reads the last copy, and its cut of every row runs a wave,
/// which is the one write wave of the call.
#[test]
fn a_write_rotate_now_whose_re_drive_waved_cuts_no_second_time() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    stage_owed_record(
        &fx,
        &OwedRecord::from([(
            fx.folder,
            OwedEntry {
                cut_epoch: fx.cut_epoch(),
                first_stop: None,
                steps: vec![OwedStep::ReadCut],
            },
        )]),
    );
    let before = fx.granted_scope_repoint();
    let sequence = sequence_at(&fx.world, &before.current_root) + 1;
    plant_root_at(&fx, &writer_seed, sequence);
    let (mut fresh, _events, _tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    let folder = fx.folder;

    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut fresh,
            Command::RotateWriteNow { node: folder }
        ),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        before.write_epoch + 1,
        "exactly one write wave"
    );
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// Device B ran the cut, and nothing is stalled. Device A's write rotate-now
/// is a rotation the owner asked for: one more wave, the rows stay, and
/// nothing is owed.
#[test]
fn a_write_rotate_now_after_another_device_cut_rotates_once_more() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut other, _other_events, _other_tasks) = fx.second_owner_device();
    let folder = fx.folder;
    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut other,
            Command::RotateWriteNow { node: folder }
        ),
        Ok(CommandOutcome::Done)
    );
    let cut = fx.granted_scope_repoint();

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done)
    );

    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, cut.write_epoch + 1);
    assert_eq!(
        fx.committed_permission(&after.current_root),
        Some(CorePermission::Write),
        "the grant row stays"
    );
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// Device A reads the root before device B revokes the writer, and the writer
/// then plants at the root. A's cut falls back to the last copy, which is B's
/// later set, so the cut is refused, retryably, and no wave gives the writer
/// a fresh write seed.
#[test]
fn a_write_rotate_now_over_a_later_set_in_the_last_copy_is_refused() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut device_a, _a_events, _a_tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    let (mut device_b, _b_events, _b_tasks) = fx.second_owner_device();
    let granted = fx.granted_scope_repoint();
    let root = granted.current_root.clone();
    let pre_revoke = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    fx.world
        .record_store
        .fail_put_for(folder_pointer(&fx).as_str());
    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut device_b,
            Command::Revoke {
                node: fx.folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
            }
        ),
        Ok(CommandOutcome::Done),
        "device B cuts the writer, and its wave stalls"
    );
    fx.world
        .record_store
        .heal_put_for(folder_pointer(&fx).as_str());
    // Device A's command read still meets the root from before the revoke.
    serve_the_walk_one_cut_behind(&fx, &root, pre_revoke);
    let cadence = device_a.profile().poll_cadence;
    let scheduler = fx.world.scheduler.clone();
    let folder = fx.folder;

    let outcome = {
        let mut future = pin!(device_a.command(Command::RotateWriteNow { node: folder }));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            future.as_mut().poll(&mut cx).is_pending(),
            "the first attempt meets device B's later set"
        );
        let sequence = sequence_at(&fx.world, &root) + 1;
        assert_eq!(plant_root_at(&fx, &writer_seed, sequence), root);
        let mut settled = None;
        for _ in 0..64 {
            if let Poll::Ready(outcome) = future.as_mut().poll(&mut cx) {
                settled = Some(outcome);
                break;
            }
            scheduler.advance(cadence);
        }
        settled.expect("the command settles")
    };

    assert!(
        matches!(outcome, Err(EngineError::Seam { .. })),
        "a retryable refusal: {outcome:?}"
    );
    assert_eq!(
        fx.granted_scope_repoint(),
        granted,
        "no wave ran, so the writer got no fresh write seed"
    );
    assert!(
        owed_entry(&fx).is_none(),
        "device A sent no PUT, so it owes nothing"
    );
}

/// Device A reads the root before device B revokes the writer, and the writer
/// plants at the root before A's first plane read. A's cut keeps the writer's
/// row and its plane reads fall back to a last copy, so the cut is refused,
/// retryably (ADR 0068 D5), owes nothing, and the writer gets no fresh write
/// seed. The next call cuts from the last copy, keeps no row, and tells the
/// host once.
#[test]
fn a_write_rotate_now_over_a_root_planted_before_its_plane_reads_is_refused() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut device_a, mut a_events, _a_tasks) =
        boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    let (mut device_b, _b_events, _b_tasks) = fx.second_owner_device();
    let granted = fx.granted_scope_repoint();
    let root = granted.current_root.clone();
    let pre_revoke = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    fx.world
        .record_store
        .fail_put_for(folder_pointer(&fx).as_str());
    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut device_b,
            Command::Revoke {
                node: fx.folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
            }
        ),
        Ok(CommandOutcome::Done),
        "device B cuts the writer, and its wave stalls"
    );
    fx.world
        .record_store
        .heal_put_for(folder_pointer(&fx).as_str());
    let sequence = sequence_at(&fx.world, &root) + 1;
    assert_eq!(plant_root_at(&fx, &writer_seed, sequence), root);
    let planted = published_value(&fx.world, &root);
    // Device A's command reads still meet the root from before the revoke, so
    // its cut keeps the writer's row; its plane reads meet the plant.
    let endpoints = fx.world.record_store.endpoints().len();
    fx.world
        .record_store
        .serve_gets_for_after(root.as_str(), 0, endpoints, pre_revoke);
    let folder = fx.folder;

    let outcome = run_across_retries(
        &fx.world,
        &mut device_a,
        Command::RotateWriteNow { node: folder },
    );

    assert!(
        matches!(outcome, Err(EngineError::Seam { .. })),
        "a retryable refusal: {outcome:?}"
    );
    assert_eq!(
        fx.granted_scope_repoint(),
        granted,
        "no wave ran, so the writer got no fresh write seed"
    );
    assert_eq!(published_value(&fx.world, &root), planted);
    assert!(
        owed_entry(&fx).is_none(),
        "device A sent no PUT, so it owes nothing"
    );
    assert!(abandoned(&mut a_events).is_empty());

    // The next call's own read falls back, so it cuts from the last copy.
    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut device_a,
            Command::RotateWriteNow { node: folder }
        ),
        Ok(CommandOutcome::Done)
    );
    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, granted.write_epoch + 1);
    assert_ne!(
        derive_write_name(&writer_seed, &fx.folder.0),
        after.current_root
    );
    assert!(
        published_grant_section_at(&fx.world, &fx.blocks, &after.current_root)
            .expect("the moved root")
            .commitment
            .entries
            .is_empty(),
        "the cut from the last copy keeps no row"
    );
    assert_eq!(
        abandoned(&mut a_events),
        vec![(fx.folder, "owed-grants-dropped-from-last-copy".to_owned())],
        "the host hears once that the rows went"
    );
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// Device B revokes the writer and stalls. Device A, from a read before that
/// revoke, revokes a reader: the root carries B's later set, so A's read
/// plane refuses the cut, retryably, and the root stays as B left it.
#[test]
fn a_revoke_over_a_later_set_at_the_root_is_refused() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut device_a, _a_events, _a_tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    block_on(device_a.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the reader's code imports");
    assert_eq!(
        block_on(device_a.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
        "device A grants a reader"
    );
    let (mut device_b, _b_events, _b_tasks) = fx.second_owner_device();
    let granted = fx.granted_scope_repoint();
    let root = granted.current_root.clone();
    let pre_revoke = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    fx.world
        .record_store
        .fail_put_for(folder_pointer(&fx).as_str());
    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut device_b,
            Command::Revoke {
                node: fx.folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
            }
        ),
        Ok(CommandOutcome::Done),
        "device B cuts the writer, and its wave stalls"
    );
    fx.world
        .record_store
        .heal_put_for(folder_pointer(&fx).as_str());
    let b_root = published_value(&fx.world, &root);
    serve_the_walk_one_cut_behind(&fx, &root, pre_revoke);
    let folder = fx.folder;

    let outcome = run_across_retries(
        &fx.world,
        &mut device_a,
        Command::Revoke {
            node: folder,
            recipient_identity_public_key: bystander_identity(),
        },
    );

    assert!(
        matches!(outcome, Err(EngineError::Seam { .. })),
        "a retryable refusal: {outcome:?}"
    );
    assert_eq!(
        published_value(&fx.world, &root),
        b_root,
        "the root stays as device B left it"
    );
    assert_eq!(
        fx.granted_scope_repoint(),
        granted,
        "no wave ran, so no revokee got a fresh seed"
    );
    assert!(
        owed_entry(&fx).is_none(),
        "device A published nothing it owes"
    );
}

/// Two writers share the scope, and a writer plants at the root before the
/// first plane read of a downgrade. The downgrade keeps rows, so the first
/// call is refused retryably and owes nothing. The second call reads the last
/// copy, cuts every row, and tells the host once (ADR 0068 D5).
#[test]
fn a_downgrade_over_a_root_planted_before_its_plane_reads_cuts_every_row_on_the_next_call() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second writer's code imports");
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Write,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
        "a second writer"
    );
    drop(fx.world.scheduler.take_spawned_tasks());
    let granted = fx.granted_scope_repoint();
    let root = granted.current_root.clone();
    let honest = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    let sequence = sequence_at(&fx.world, &root) + 1;
    assert_eq!(plant_root_at(&fx, &writer_seed, sequence), root);
    // The command read meets the honest root; the plane reads meet the plant.
    serve_the_walk_one_cut_behind(&fx, &root, honest);
    let _ = abandoned(&mut fx._events);
    let folder = fx.folder;
    let downgrade = || Command::ChangePermission {
        node: folder,
        recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        permission: Permission::Read,
    };

    let first = command_across_retries(&mut fx, downgrade());
    assert!(
        matches!(first, Err(EngineError::Seam { .. })),
        "a retryable refusal: {first:?}"
    );
    assert!(owed_entry(&fx).is_none(), "no PUT, so nothing is owed");
    assert_eq!(fx.granted_scope_repoint(), granted, "no wave ran");
    assert!(abandoned(&mut fx._events).is_empty());

    assert_eq!(
        command_across_retries(&mut fx, downgrade()),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        abandoned(&mut fx._events),
        vec![(fx.folder, "owed-grants-dropped-from-last-copy".to_owned())],
        "the host hears once that the rows went"
    );
    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, granted.write_epoch + 1);
    assert!(
        published_grant_section_at(&fx.world, &fx.blocks, &after.current_root)
            .expect("the moved root")
            .commitment
            .entries
            .is_empty(),
        "the cut from the last copy keeps no row"
    );
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// A revoke of one writer keeps the reader's row. Its root PUT goes out and
/// fails, and the read after it falls back to the last copy, so the cut is
/// unknown and its entry stands with no notice. The re-drive cuts every row
/// from the last copy and tells the host once (ADR 0068 D5).
#[test]
fn a_redrive_that_cuts_every_row_after_an_unconfirmed_revoke_tells_the_host_once() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the reader's code imports");
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
        "a reader"
    );
    let root = fx.granted_scope_repoint().current_root;
    let honest = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    let sequence = sequence_at(&fx.world, &root) + 1;
    assert_eq!(plant_root_at(&fx, &writer_seed, sequence), root);
    // Every read before the PUT meets the honest root; the read after it
    // meets the plant.
    let endpoints = fx.world.record_store.endpoints().len();
    fx.world
        .record_store
        .serve_gets_for_after(root.as_str(), 0, 4 * endpoints, honest);
    fx.world.record_store.fail_put_for(root.as_str());
    let _ = events_so_far(&mut fx._events);

    assert!(revoke_the_recipient(&mut fx).is_err());
    assert!(abandoned(&mut fx._events).is_empty(), "no notice yet");
    assert!(
        owed_entry(&fx).is_some(),
        "the PUT went out, so the entry stands"
    );

    fx.world.record_store.heal_put_for(root.as_str());
    let mut told = Vec::new();
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        told.extend(abandoned(&mut fx._events));
    }
    assert_eq!(
        told,
        vec![(fx.folder, "owed-grants-dropped-from-last-copy".to_owned())],
        "the host hears once that the rows went"
    );
    assert_the_revokee_is_cut(&fx, &writer_seed);
    assert_no_grant_at(&fx, &fx.granted_scope_repoint().current_root);
}

/// The command read and the first plane read fall back to the last copy, and
/// the endpoints then recover and serve the honest root from before the cut. The wave's
/// re-mint meets a set other than the cut's, which is a race, so it stops
/// retryably and sends no trust event.
#[test]
fn a_wave_that_meets_the_honest_pre_cut_root_after_a_fallback_stops_retryably() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    let before = fx.granted_scope_repoint();
    let root = before.current_root.clone();
    let honest = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], root.as_str());
    let sequence = sequence_at(&fx.world, &root) + 1;
    assert_eq!(plant_root_at(&fx, &writer_seed, sequence), root);
    let endpoints = fx.world.record_store.endpoints().len();
    fx.world.record_store.serve_gets_for_after(
        root.as_str(),
        2 * endpoints,
        64 * endpoints,
        honest,
    );
    let _ = events_so_far(&mut fx._events);
    let folder = fx.folder;

    let outcome = command_across_retries(&mut fx, Command::RotateWriteNow { node: folder });

    let events = events_so_far(&mut fx._events);
    assert_eq!(outcome, Ok(CommandOutcome::Done), "the wave stands owed");
    // The re-mint's Superseded refusal reaches the host as the retryable
    // availability stop of the write publish, never a trust stop.
    let owed: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::RotationWorkOwed {
                detail,
                retryable,
                class,
                ..
            } => Some((detail.as_str(), *retryable, *class)),
            _ => None,
        })
        .collect();
    assert_eq!(
        owed,
        vec![(
            "rot-write-publish-failed",
            true,
            OwedWorkClass::Availability
        )]
    );
    assert!(owed_entry(&fx).is_some(), "the wave is owed");
    assert_eq!(
        root_refusals(&fx, &events, sequence),
        1,
        "only the plant sends a trust event"
    );
    assert_eq!(fx.granted_scope_repoint(), before, "no wave landed");
}

/// A revoke whose root publish is refused at register-first, before the PUT,
/// owes nothing, even when the follow-up read of the root finds no record: no
/// PUT went out (ADR 0063 D5).
#[test]
fn a_revoke_whose_root_publish_fails_before_the_put_owes_nothing() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    let root = fx.granted_scope_repoint().current_root;
    fx.blocks.refuse_register(Vec::new());
    // The reads before the publish answer; the follow-up read finds no record.
    let endpoints = fx.world.record_store.endpoints().len();
    fx.world
        .record_store
        .serve_gets_for_after(root.as_str(), 4 * endpoints, 64 * endpoints, None);

    let outcome = revoke_the_recipient(&mut fx);
    fx.blocks.accept_registrations();

    assert!(
        matches!(&outcome, Err(EngineError::Seam { message })
            if message.contains("cascade publish") && message.contains("not published")),
        "the root publish stops before its PUT: {outcome:?}"
    );
    assert!(owed_entry(&fx).is_none(), "no PUT, so nothing is owed");
}

/// A revoke whose root publish is refused at the floor gate of the signature,
/// after register-first and before the PUT: the cut-epoch floor rises inside
/// the publish window. No PUT goes out, and nothing is owed (ADR 0063 D5).
#[test]
fn a_revoke_refused_at_the_publish_floor_gate_sends_no_put_and_owes_nothing() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    let root = fx.granted_scope_repoint().current_root;
    let puts = fx.world.record_store.put_count(root.as_str());
    let mut cut_epoch_floor = fx.folder.0.to_vec();
    cut_epoch_floor.extend_from_slice(b"/cut-epoch");
    fx.owner_device
        .floor_store
        .raise_epoch_floor_on_sequence_read_after(
            &floor_label(root.as_str().as_bytes()),
            &floor_label(&cut_epoch_floor),
            u64::from(u32::MAX),
            2,
        );

    // The third sequence-floor read of the root name is the signature's
    // floor gate, after register-first.
    let outcome = revoke_the_recipient(&mut fx);

    assert!(
        matches!(&outcome, Err(EngineError::TrustViolation { message })
            if message.contains("cascade publish")),
        "the root publish stops at its floor gate: {outcome:?}"
    );
    assert_eq!(
        fx.world.record_store.put_count(root.as_str()),
        puts,
        "no PUT went out"
    );
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// A cut from the last copy keeps no row. Its root PUT goes out and fails,
/// and the read after it falls back to this device's own copy from before
/// the PUT. The copy does not show whether the PUT landed, so the entry
/// stands (ADR 0063 D5).
#[test]
fn a_cut_whose_put_went_out_and_whose_follow_up_read_falls_back_stays_owed() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let root = fx.granted_scope_repoint().current_root;
    let endpoints = fx.world.record_store.endpoints();
    let before_grant = fx
        .world
        .record_store
        .record_at(&endpoints[0], root.as_str())
        .expect("the root");
    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second reader's code imports");
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
        "a second reader"
    );
    let honest = fx
        .world
        .record_store
        .record_at(&endpoints[0], root.as_str());
    // Every endpoint serves a record below the sequence floor, which falls
    // back, except to the plane reads, which meet the honest root.
    for endpoint in &endpoints {
        fx.world
            .record_store
            .seed_record(endpoint, root.as_str(), before_grant.clone());
    }
    fx.world.record_store.serve_gets_for_after(
        root.as_str(),
        endpoints.len(),
        3 * endpoints.len(),
        honest,
    );
    fx.world.record_store.fail_put_for(root.as_str());

    let outcome = revoke_the_recipient(&mut fx);
    fx.world.record_store.heal_put_for(root.as_str());

    assert!(
        matches!(outcome, Err(EngineError::Seam { .. })),
        "a retryable refusal: {outcome:?}"
    );
    assert!(owed_entry(&fx).is_some(), "the PUT can have landed");
}

/// A revoke from the last copy asks for the only row there, so it tells the
/// host nothing, and its wave stops. Another owner device then grants a
/// reader at the same cut epoch, and this device reads that row. The
/// re-drive over a new plant drops the reader's row too, and tells the host
/// once (ADR 0068 D5).
#[test]
fn a_redrive_that_drops_a_row_granted_after_a_silent_cut_tells_the_host_once() {
    let mut fx = GrantScenario::new();
    let (_, grandchild, writer_seed) = write_granted_nested_subtree(&mut fx);
    plant_an_unserved_head(&fx, &writer_seed, grandchild);
    drop(fx.world.scheduler.take_spawned_tasks());
    let (mut other, _other_events, _other_tasks) = fx.second_owner_device();
    let root = fx.granted_scope_repoint().current_root;
    let endpoints = fx.world.record_store.endpoints();
    let honest = fx
        .world
        .record_store
        .record_at(&endpoints[0], root.as_str())
        .expect("the root");
    plant_root_at(&fx, &writer_seed, sequence_at(&fx.world, &root) + 1);
    let _ = events_so_far(&mut fx._events);

    let _ = revoke_the_recipient(&mut fx);
    let mut events = events_so_far(&mut fx._events);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::RotationWorkAbandoned { .. })),
        "the revoke asked for the only row, so it tells nothing"
    );
    assert!(owed_entry(&fx).is_some(), "the cut is owed");

    for endpoint in &endpoints {
        fx.world
            .record_store
            .seed_record(endpoint, root.as_str(), honest.clone());
    }
    block_on(other.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the reader's code imports");
    assert_eq!(
        block_on(other.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
        "the other device grants a reader"
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    events.extend(events_so_far(&mut fx._events));
    plant_root_at(&fx, &writer_seed, sequence_at(&fx.world, &root) + 1);
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        events.extend(events_so_far(&mut fx._events));
    }

    let told: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::RotationWorkAbandoned { scope_root, detail } => {
                Some((*scope_root, detail.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        told,
        vec![(fx.folder, "owed-grants-dropped-from-last-copy".to_owned())]
    );
}

/// The re-drive runs the owed wave, and the owed delivery after it names a
/// recipient that is not in the contact book, so the entry drops. The wave
/// was the one of the call, so the command cuts no second time.
#[test]
fn a_write_rotate_now_whose_re_drive_waved_then_dropped_cuts_no_second_time() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let before = fx.granted_scope_repoint();
    let unknown: [u8; IDENTITY_PUBLIC_LEN] = bystander_identity()
        .try_into()
        .expect("a compressed identity key");
    stage_owed_record(
        &fx,
        &OwedRecord::from([(
            fx.folder,
            OwedEntry {
                cut_epoch: fx.cut_epoch(),
                first_stop: None,
                steps: vec![
                    OwedStep::WriteCut {
                        write_epoch: before.write_epoch + 1,
                    },
                    OwedStep::DeliverGrant {
                        recipient_identity_pk: unknown,
                        write: true,
                    },
                ],
            },
        )]),
    );
    let (mut fresh, _events, _tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    let folder = fx.folder;

    assert_eq!(
        run_across_retries(
            &fx.world,
            &mut fresh,
            Command::RotateWriteNow { node: folder }
        ),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        before.write_epoch + 1,
        "exactly one write wave"
    );
    assert!(owed_entry(&fx).is_none(), "and nothing is owed");
}

/// A write rotate-now on a scope with no owed work moves the write plane one
/// epoch, so a revoked writer's seed derives none of the new names.
#[test]
fn a_write_rotate_now_moves_the_scope_one_write_epoch() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let before = fx.granted_scope_repoint();
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done),
    );

    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, before.write_epoch + 1);
    assert_ne!(after.current_root, before.current_root);
    assert!(fx.owed_scopes().is_empty(), "and nothing is owed");
}

/// The parent's index is writer-authored, so a parent writer that drops the
/// owed scope from it does not drop the owed cut: the pass places the scope
/// from its owner-signed pointer, finishes the cut, and indexes it again.
#[test]
fn an_owed_cut_whose_parent_index_omits_the_scope_is_finished_from_its_pointer() {
    let mut fx = GrantScenario::new();
    let unindexed_root = published_value(&fx.world, &write_name(ROOT));
    let revokee_seed = strand_a_write_revoke(&mut fx);
    publish_value_at(&fx.world, ROOT, &unindexed_root);
    let _ = events_so_far(&mut fx._events);

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        abandoned(&mut fx._events),
        vec![],
        "the entry is not dropped"
    );
    assert_the_revoke_finished(&fx, &revokee_seed);
}

/// A downgrade whose wave stops before it reads the cut set still holds the
/// gate at the cut it published, so the downgraded writer's replay of the root
/// before the cut does not read as a cut that never landed. The pass runs the
/// owed wave from the last copy (ADR 0068 D1).
#[test]
fn a_replayed_pre_cut_root_does_not_drop_an_owed_downgrade() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let granted = fx.granted_scope_repoint();
    let section = published_grant_section_at(&fx.world, &fx.blocks, &granted.current_root)
        .expect("the granted root");
    let writer_seed = grantee_write_scope_seed(&section, &granted.current_root, &fx.folder.0, 1);
    let pre_cut = published_value(&fx.world, &granted.current_root);
    // The command's reads and the cut-set publish answer; the wave's first
    // read of the root, ahead of any adoption of the cut set, does not.
    fx.world
        .record_store
        .serve_gets_for_after(granted.current_root.as_str(), 5, usize::MAX, None);
    let folder = fx.folder;
    assert_eq!(
        command_across_retries(
            &mut fx,
            Command::ChangePermission {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
                permission: Permission::Read,
            }
        ),
        Ok(CommandOutcome::Done),
        "the cut set is published, so the wave that stops is owed"
    );
    assert_eq!(
        owed_reports(&mut fx._events),
        vec![(
            fx.folder,
            "rot-write-resolve-failed".to_owned(),
            true,
            OwedWorkClass::Availability
        )],
        "the wave stopped at its first read of the root"
    );
    fx.world
        .record_store
        .serve_gets_for_after(granted.current_root.as_str(), 0, 0, None);
    publish_value_under(&fx.world, &writer_seed, fx.folder, &pre_cut);

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    // The replay sends the re-drive to the last copy, so the wave keeps no
    // row (ADR 0068 D5); only the dropped grant is reported.
    assert_eq!(
        abandoned(&mut fx._events),
        vec![(fx.folder, "owed-grants-dropped-from-last-copy".to_owned())],
        "the replay does not drop the owed wave"
    );
    assert_eq!(
        fx.granted_scope_repoint().write_epoch,
        3,
        "the pass runs the owed wave"
    );
}

/// An entry left standing behind a wave that landed and an index that names
/// the moved root is finished by the next pass, which takes the owner-signed
/// pointer naming that root as the vouch, rather than owed on every pass.
#[test]
fn an_entry_that_outlives_its_landed_wave_is_cleared_by_the_next_pass() {
    let mut fx = GrantScenario::new();
    let revokee_seed = strand_a_write_revoke(&mut fx);
    let enc = kdf::enc_subkey(&SECRET);
    fx.owner_device
        .staging_store
        .inner()
        .interrupt_staged_removal_after(&owed_rotation_key(&enc), 0);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_the_revoke_finished(&fx, &revokee_seed);

    let _ = fx.owed_scopes();
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(fx.owed_scopes(), vec![], "nothing is owed on a later pass");
}

/// ADR 0063 D5: a permission change over a write mint whose wave is still owed
/// is refused, retryably, and publishes nothing: the owed entry, not the
/// change, runs the wave.
#[test]
fn a_permission_change_over_an_owed_wave_publishes_nothing() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);
    fx.world
        .scheduler
        .advance(fx.engine.profile().pointer_consult_interval * 2);
    fx.world
        .record_store
        .fail_get_for(folder_pointer(&fx).as_str());
    let before = sequence_at(&fx.world, &stalled);
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(
            &mut fx,
            Command::ChangePermission {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
                permission: Permission::Read,
            }
        ),
        work_owed()
    );
    assert_eq!(
        sequence_at(&fx.world, &stalled),
        before,
        "no cut is published behind the owed entry"
    );
}

/// A rename over a scope with owed work is refused, retryably, while the
/// re-drive cannot finish it.
#[test]
fn a_rename_over_owed_work_is_refused() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    fx.world
        .scheduler
        .advance(fx.engine.profile().pointer_consult_interval * 2);
    fx.world
        .record_store
        .fail_get_for(folder_pointer(&fx).as_str());
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(
            &mut fx,
            Command::RenameGrantee {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
                name: "Robin".to_owned(),
            }
        ),
        work_owed()
    );
}

/// A claim at a scope whose write link mint still owes its interior move
/// waits: the conversion does not move the scope off the write epoch the owed
/// move resumes at, and both land once the parent publishes again.
#[test]
fn a_claim_at_a_scope_with_an_owed_move_waits_for_the_move() {
    let mut fx = GrantScenario::new();
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    let fragment = fx.mint_link_at(Permission::Write);
    assert_eq!(
        fx.owed_scopes(),
        vec![fx.folder],
        "the interior move is owed"
    );
    let claimant = fx.post_claims(&fragment, 1);
    assert_eq!(fx.convert(), work_owed(), "the claim waits for the move");

    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let _ = fx.owed_scopes();
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(fx.owed_scopes(), vec![], "the owed move landed");
    assert!(
        fx.granted_to().contains(&claimant[0]),
        "and the claim converted after it"
    );
}

/// A conversion whose owed record does not read waits, and says the record
/// did not read rather than that work is owed.
#[test]
fn a_claim_over_an_unreadable_owed_record_reports_the_store() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link_at(Permission::Read);
    let claimant = fx.post_claims(&fragment, 1);
    fx.owner_device
        .staging_store
        .inner()
        .fail_staged_reads_under(&owed_rotation_key(&kdf::enc_subkey(&SECRET)));

    let (mut fresh, _events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    let converted = block_on(fresh.command(Command::ConvertInviteClaims { node: fx.folder }));
    assert!(
        matches!(&converted, Err(EngineError::Seam { message }) if message != ROTATION_WORK_OWED),
        "{converted:?}"
    );
    assert!(
        !fx.granted_to().contains(&claimant[0]),
        "and the claim waits"
    );
}

/// An upgrade's write-scope cut runs under an owed entry: a wave that stops
/// leaves it owed, the command is refused retryably, and the next pass
/// finishes the wave.
#[test]
fn an_upgrade_whose_wave_stops_is_owed_and_finished_by_the_pass() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let minted = fx.granted_scope_repoint().write_epoch;
    fx.world
        .record_store
        .fail_put_for(folder_pointer(&fx).as_str());
    let folder = fx.folder;
    let upgrade = || Command::ChangePermission {
        node: folder,
        recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        permission: Permission::Write,
    };
    assert_eq!(command_across_retries(&mut fx, upgrade()), work_owed());
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "and the wave is owed");

    fx.world
        .record_store
        .heal_put_for(folder_pointer(&fx).as_str());
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let moved = fx.granted_scope_repoint();
    assert_eq!(moved.write_epoch, minted + 1, "the pass ran the owed wave");

    assert_eq!(
        command_across_retries(&mut fx, upgrade()),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        fx.committed_permission(&fx.granted_scope_repoint().current_root),
        Some(CorePermission::Write)
    );
}

/// A drop whose clear the store refuses is not told: the entry still stands,
/// so the pass reports it owed, and the pass that drops it tells once.
#[test]
fn an_abandon_whose_clear_fails_is_told_once_the_clear_lands() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    stage_owed_delivery_to_a_stranger(&fx);
    fx.owner_device
        .staging_store
        .inner()
        .interrupt_staged_removal_after(&owed_rotation_key(&kdf::enc_subkey(&SECRET)), 0);

    let (fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    let first = events_so_far(&mut events);
    assert!(
        !first
            .iter()
            .any(|event| matches!(event, Event::RotationWorkAbandoned { .. })),
        "a drop that did not land is not told"
    );
    assert!(
        first.iter().any(|event| matches!(
            event,
            Event::RotationWorkOwed { scope_root, .. } if *scope_root == fx.folder
        )),
        "the entry still stands, so it is owed"
    );

    for _ in 0..2 {
        tick(&fx.world, &fresh, &mut tasks);
    }
    assert_eq!(
        abandoned(&mut events),
        vec![(fx.folder, "owed-grant-recipient-unknown".to_owned())],
        "the drop that lands is told once"
    );
}

/// A share re-run over an owed move whose mint stops before its first publish
/// writes the move back; when the store refuses that write, the command says
/// so rather than losing the move in silence.
#[test]
fn a_share_re_run_whose_write_back_fails_reports_the_store() {
    let mut fx = GrantScenario::new();
    fx.stall_the_owed_move();
    fx.world
        .record_store
        .fail_get_for(write_name(fx.folder).as_str());
    let enc = kdf::enc_subkey(&SECRET);
    fx.owner_device
        .staging_store
        .inner()
        .interrupt_staged_write_after(&owed_rotation_key(&enc), 1);

    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::Seam {
            message: "owed-rotation-not-durable".to_owned(),
        })
    );
}

/// A share re-run over an owed move keeps the move owed until its own mint
/// replaces the entry: a session that ends while the re-run reads still owes
/// the move.
#[test]
fn a_share_re_run_cut_short_still_owes_the_move() {
    let mut fx = GrantScenario::new();
    fx.stall_the_owed_move();
    fx.world
        .record_store
        .fail_get_for(write_name(fx.folder).as_str());
    let _ = owed_scopes(&mut fx._events);
    // The re-drive reads the vault root six times, so the re-run parks on its
    // first read of it.
    let root = write_name(ROOT);
    fx.world.record_store.stall_gets_for_after(root.as_str(), 6);
    {
        let mut rerun = pin!(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
            grantee_name: None,
        }));
        assert!(
            rerun
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "the re-run parks on the vault root"
        );
        assert_eq!(
            owed_scopes(&mut fx._events),
            vec![fx.folder],
            "after the re-drive left the move owed"
        );
    }
    fx.world.record_store.release_gets_for(root.as_str());

    let (fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);
    assert_eq!(
        owed_scopes(&mut events),
        vec![fx.folder],
        "the move is still owed"
    );
}

/// ADR 0063 D3: a promoted write scope whose write-scope cut did not run is
/// finished by the next sync pass, which also delivers the pointer it owed.
#[test]
fn a_promoted_scope_whose_write_cut_did_not_run_is_finished_by_the_pass() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(moved, stalled, "the pass ran the owed write cut");
    assert_eq!(fx.granted_blob_carries_write_seed(&moved), Some(true));
    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        moved.as_str().as_bytes(),
        "and delivered the pointer at the moved root"
    );
}

/// ADR 0063 D2 and D3: the entry is durable, so a session started later on the
/// same device finishes the owed work at its first pass.
#[test]
fn a_session_started_later_on_the_same_device_finishes_the_owed_work() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);

    let (fresh, mut events, mut tasks) = boot_owner(&fx.world, &fx.blocks, &fx.owner_device);
    tick(&fx.world, &fresh, &mut tasks);

    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(moved, stalled, "the first pass ran the owed write cut");
    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        moved.as_str().as_bytes(),
    );
    assert!(owed_scopes(&mut events).is_empty(), "and nothing is owed");
}

/// ADR 0063 D1: the delivery of a write grant is owed work of its own. A
/// pointer the mailbox refuses leaves the grant owed, and the pass delivers it
/// once the mailbox takes it.
#[test]
fn a_write_grant_whose_delivery_fails_is_delivered_by_the_pass() {
    let mut fx = GrantScenario::new();
    let recipient = recipient_identity().verifying_key().to_sec1();
    fx.world.mailbox_hub.forget_recipient(&recipient);

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the delivery is owed");
    assert!(inbox(&fx.recipient_device).is_empty());

    fx.world.mailbox_hub.remember_recipient(&recipient);
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let moved = fx.granted_scope_repoint().current_root;
    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        moved.as_str().as_bytes(),
        "the pass delivered the pointer at the root the cut moved to"
    );
    assert!(fx.owed_scopes().is_empty(), "and nothing is owed");
}

/// ADR 0063 D2: an entry that cannot be made durable refuses the command
/// before its first publish, and leaves nothing owed.
#[test]
fn an_entry_that_is_not_durable_refuses_the_grant_before_any_publish() {
    let mut fx = GrantScenario::new();
    fx.owner_device
        .staging_store
        .inner()
        .interrupt_staged_write_family_after(OWED_ROTATION_PREFIX, 0);

    assert!(
        fx.grant_folder_at(Permission::Write).is_err(),
        "the grant is refused"
    );
    assert_eq!(
        published_grant_section(&fx.world, &fx.blocks, fx.folder),
        None,
        "before anything publishes"
    );
    assert!(fx.owed_scopes().is_empty(), "and nothing is owed");

    // The session holds no entry the store refused, so a retry is the grant.
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        fx.granted_scope_repoint().current_root.as_str().as_bytes(),
        "the retry mints and delivers the grant"
    );
}

/// ADR 0063 D2: the same refusal for a cut. The revoke publishes nothing, and
/// the recipient keeps the row.
#[test]
fn an_entry_that_is_not_durable_refuses_the_revoke_before_any_publish() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let before = fx.granted_scope_repoint();
    fx.owner_device
        .staging_store
        .inner()
        .interrupt_staged_write_family_after(OWED_ROTATION_PREFIX, 0);

    assert!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1())
            .is_err(),
        "the revoke is refused"
    );
    let after = fx.granted_scope_repoint();
    assert_eq!(after.current_root, before.current_root, "nothing moved");
    assert_eq!(
        fx.committed_permission(&after.current_root),
        Some(CorePermission::Write),
        "and the row stands"
    );
    assert!(fx.owed_scopes().is_empty(), "and nothing is owed");
}

/// ADR 0063 D4: the renewal walk renews no name of a scope whose owed work
/// stopped less than the bound ago, and still renews the names of every
/// other scope.
#[test]
fn the_renewal_walk_skips_a_scope_with_owed_work() {
    const DAY: u64 = 24 * 60 * 60;
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "outer");
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let child_name = derive_write_name(&revokee_seed, &child.0);
    let child_before = sequence_at(&fx.world, &child_name);
    let outer_before = sequence_at(&fx.world, &write_name(outer));
    // A downgrade cuts the write plane alone, so no read sweep re-seals the
    // scope. Its wave first stops close to the names' renewal, so the walk
    // meets the owed scope within the bound.
    fx.world.scheduler.advance(Duration::from_secs(62 * DAY));
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    let folder = fx.folder;
    assert_eq!(
        command_across_retries(
            &mut fx,
            Command::ChangePermission {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
                permission: Permission::Read,
            }
        ),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(fx.owed_scopes(), vec![folder], "the wave is owed");

    let GrantScenario {
        world,
        blocks,
        owner_device,
        engine,
        _tasks,
        ..
    } = fx;
    let (world, mut events, (_device, engine, mut tasks)) = start_after(
        world,
        &blocks,
        owner_device,
        (engine, _tasks),
        Duration::from_secs(DAY),
    );
    // The re-drive's bounded retries hold each pass a while.
    for _ in 0..64 {
        if sequence_at(&world, &write_name(outer)) > outer_before {
            break;
        }
        tick(&world, &engine, &mut tasks);
    }

    assert_eq!(
        sequence_at(&world, &write_name(outer)),
        outer_before + 1,
        "the vault root's scope renews"
    );
    assert_eq!(
        sequence_at(&world, &child_name),
        child_before,
        "the owed scope does not"
    );
    assert_eq!(
        owed_scopes(&mut events),
        vec![folder],
        "the later session still reports the scope owed"
    );
}

/// A stored owed record that does not open skips no scope: the walk renews
/// every name as if no work were owed, and reports the record on each pass.
#[test]
fn the_renewal_walk_renews_past_an_owed_record_that_does_not_open() {
    let mut fx = GrantScenario::new();
    let recipient = recipient_identity().verifying_key().to_sec1();
    fx.world.mailbox_hub.forget_recipient(&recipient);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the delivery is owed");
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "outer");
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let inner_before = sequence_at(&fx.world, &write_name(inner));
    let outer_before = sequence_at(&fx.world, &write_name(outer));
    let key = owed_rotation_key(&kdf::enc_subkey(&SECRET));
    block_on(
        fx.owner_device
            .staging_store
            .put_staged_bytes(&key, b"not an owed rotation record"),
    )
    .expect("stage the bytes");

    let (world, mut events, _later) = restart_later_on_the_same_device(fx);

    assert_eq!(
        sequence_at(&world, &write_name(outer)),
        outer_before + 1,
        "the vault root's scope renews"
    );
    assert_eq!(
        sequence_at(&world, &write_name(inner)),
        inner_before + 1,
        "and so does the scope the record cannot say is owed"
    );
    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::RenewalFailed { detail, .. } if detail.contains("owed rotation record")
        )),
        "the host is told the record does not read"
    );
}

/// ADR 0063 consequence 8: a device that holds no owed entry meets a scope
/// root whose name the write seed it holds does not derive. The walk tells
/// the owner the write cut did not finish.
#[test]
fn the_walk_reports_a_write_cut_that_did_not_finish() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let folder = fx.folder;

    let (world, mut events, (_device, later, mut tasks)) = restart_later(fx);
    // The later device's first boundary walk opens no write blob of the
    // scope yet, so the walk pass after the next one reports it.
    world.scheduler.advance(RE_PUT_INTERVAL);
    tick(&world, &later, &mut tasks);

    let mut unfinished: Vec<NodeId> = events_so_far(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            Event::WriteCutUnfinished { scope_root } => Some(scope_root),
            _ => None,
        })
        .collect();
    unfinished.dedup();
    assert_eq!(
        unfinished,
        vec![folder],
        "the walk reports the unfinished write cut at its scope root"
    );
}

/// ADR 0061 D4 holds per name, not through the owed skip: with an owed record
/// that does not open, the walk renews the granted scope root and still signs
/// nothing at a name only the superseded seed derives.
#[test]
fn an_unopenable_owed_record_signs_no_name_the_current_seed_does_not_derive() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let mid = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "mid");
    let leaf = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, mid, "leaf");
    let material = block_on(fx.engine.walked_scope_material(fx.folder))
        .expect("the walk resolved the granted scope");
    let scope_root = derive_write_name(&material.write_scope_seed, &fx.folder.0);
    let current_leaf = derive_write_name(&material.write_scope_seed, &leaf.0);
    let superseded = superseded_write_seed(
        &fx.world,
        &fx.blocks,
        fx.folder,
        &fx.granted_scope_repoint(),
        &material.write_scope_seed,
    );
    let (old_leaf, _) = publish_at_seed_name(&fx.world, &superseded, leaf, &current_leaf);
    name_child_at(
        &fx.world,
        &fx.blocks,
        &material.write_scope_seed,
        &material.read_scope_seed,
        mid,
        leaf,
        &old_leaf,
    );
    let leaf_before = sequence_at(&fx.world, &old_leaf);
    let root_before = sequence_at(&fx.world, &scope_root);
    let key = owed_rotation_key(&kdf::enc_subkey(&SECRET));

    let (world, _events, _later) = restart_later_with(fx, |device| {
        block_on(
            device
                .staging_store
                .put_staged_bytes(&key, b"not an owed rotation record"),
        )
        .expect("stage the bytes");
    });

    assert_eq!(
        sequence_at(&world, &scope_root),
        root_before + 1,
        "the walk renews the granted scope root"
    );
    assert_eq!(
        sequence_at(&world, &old_leaf),
        leaf_before,
        "and signs nothing under the superseded seed"
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
                fragment: Zeroizing::new(fragment.to_owned()),
                name: String::new(),
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

/// A claim that matched a committed link but can never become convertible is a
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

    // The owner's own bundle, which the invite URL carries: a self-grant is
    // refused for good.
    block_on(post_invite_claim(
        &fx.recipient_device.mailbox,
        &import_contact(&opened.owner_contact_code).expect("the owner bundle verifies"),
        &invitee,
        &[0x7d; 32],
        ENVELOPE_V,
        &InviteClaim {
            claim_id: [0x7e; CLAIM_ID_LEN],
            scope_pointer_name: opened.scope_pointer_name.clone(),
            contact_code: contact_code(&SECRET),
            name: String::new(),
        }
        .encode()
        .expect("the claim encodes"),
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
            scope_pointer_name: None,
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

/// ADR 0025 D3: the phone cut a grantee, and the owner committed the grantee
/// again through a new link. The re-commit reaches the cut epoch of the
/// phone's cut, so the phone's next re-key serves the grantee a blob.
#[test]
fn a_device_serves_a_grantee_again_once_another_device_commits_it_again() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let claimants = fx.post_claims(&fragment, 1);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    let (mut phone, _phone_events, mut phone_tasks) = fx.owner_phone();
    tick(&fx.world, &phone, &mut phone_tasks);
    assert_eq!(
        block_on(phone.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: claimants[0].clone(),
        })),
        Ok(CommandOutcome::Done),
    );
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let fragment = fx.mint_link();
    fx.post_claimant(&fragment, 0, 0x40);
    let other = fx.post_claimant(&fragment, 2, 0x42);
    assert_eq!(fx.convert(), Ok(CommandOutcome::Done));
    assert!(fx.granted_to().contains(&claimants[0]), "committed again");

    tick(&fx.world, &phone, &mut phone_tasks);
    assert_eq!(
        block_on(phone.command(Command::Revoke {
            node: fx.folder,
            recipient_identity_public_key: other,
        })),
        Ok(CommandOutcome::Done),
        "the phone re-keys the folder"
    );

    assert_eq!(fx.granted_to(), vec![claimants[0].clone()]);
    let section = fx.folder_section();
    let personal: Vec<[u8; 32]> = section
        .commitment
        .entries
        .iter()
        .filter(|entry| entry.kind == GrantSetEntryKind::Personal)
        .map(|entry| entry.tag)
        .collect();
    assert_eq!(personal.len(), 1);
    assert!(
        section
            .grant_blobs
            .iter()
            .any(|blob| blob.tag == personal[0]),
        "the phone serves the grantee a blob"
    );
}

// ---------------------------------------------------------------------------
// Appending to a shared scope, and a grantee's permission and name
// ---------------------------------------------------------------------------

/// A grant on a folder that already names a scope appends one row to that scope
/// (ADR 0026 D1): the scope root publishes once at its current epoch, under the
/// seed every grantee already holds, and the parent's index does not move. The
/// sharing read offers the append, so it reports no refusal there.
#[test]
fn a_second_grant_on_a_scope_root_appends_a_row_and_publishes_once() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let name = write_name(fx.folder);
    let first = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the granted folder is a scope root");
    let folder_before = sequence_at(&fx.world, &name);
    let root_before = sequence_at(&fx.world, &write_name(ROOT));
    let state = block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the granted scope root resolved");
    assert_eq!(state.grant_refusal, None);
    assert_eq!(state.invite_link_refusal, None);

    let bystander_device = fx.device_for(&BYSTANDER_SECRET);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        sequence_at(&fx.world, &name),
        folder_before + 1,
        "the scope root publishes once"
    );
    assert_eq!(
        sequence_at(&fx.world, &write_name(ROOT)),
        root_before,
        "and the parent's index does not move"
    );
    let after = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the scope root still answers at its name");
    assert_eq!(after.commitment.entries.len(), 2, "one more row");
    assert!(
        first
            .commitment
            .entries
            .iter()
            .all(|entry| after.commitment.entries.contains(entry)),
        "and the first grantee's row stands"
    );
    assert!(
        stranded_override_seed(&after, fx.folder) == stranded_override_seed(&first, fx.folder),
        "under the seed the scope already had"
    );
    assert_eq!(
        delivered_share_pointer_for(&bystander_device, &BYSTANDER_SECRET).scope_root_name,
        name.as_str().as_bytes(),
        "and the new grantee is sent to the root that stands"
    );
    assert_eq!(
        fx.granted_to(),
        vec![
            recipient_identity().verifying_key().to_sec1().to_vec(),
            bystander_identity(),
        ]
    );
}

/// A link on a folder that already names a scope is one more link row, and a
/// folder carries any number of live links beside its direct grants
/// (ADR 0026 D2, D3). Each mint publishes the scope root once and draws no seed.
#[test]
fn links_append_to_a_shared_folder_and_coexist() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let name = write_name(fx.folder);
    let first = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the granted folder is a scope root");
    let before = sequence_at(&fx.world, &name);

    let read_link = fx.mint_link();
    let write_link = fx.mint_link_at(Permission::Write);

    assert_ne!(read_link, write_link, "two links, two capabilities");
    assert_eq!(
        sequence_at(&fx.world, &name),
        before + 2,
        "one publish each"
    );
    let after = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the scope root still answers at its name");
    let kinds: Vec<GrantSetEntryKind> = after
        .commitment
        .entries
        .iter()
        .map(|entry| entry.kind)
        .collect();
    assert_eq!(kinds.len(), 3);
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == GrantSetEntryKind::Link)
            .count(),
        2
    );
    assert!(
        stranded_override_seed(&after, fx.folder) == stranded_override_seed(&first, fx.folder),
        "under the seed the scope already had"
    );
    for fragment in [&read_link, &write_link] {
        let opened = InviteFragment::decode(fragment).expect("the mint's own fragment");
        assert_eq!(
            opened.scope_id, fx.folder.0,
            "each link names the one scope"
        );
    }
}

/// A grant at the permission the grantee already holds changes no set and
/// re-posts their share pointer to the root that stands, so a grant retried
/// after a failed post still delivers (ADR 0026 D4). A permission change to
/// that permission is the command that says nothing changes.
#[test]
fn a_grant_at_the_held_permission_re_delivers_and_a_change_to_it_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let moved = fx.granted_scope_repoint().current_root;
    let before = sequence_at(&fx.world, &moved);

    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        block_on(fx.engine.command(Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Write,
        })),
        Err(EngineError::MalformedInput {
            check: "grant-recipient-already-has-access"
        }),
    );

    assert_eq!(sequence_at(&fx.world, &moved), before, "nothing publishes");
    assert_eq!(
        fx.granted_scope_repoint().current_root,
        moved,
        "and the scope stays where its own wave left it"
    );
    assert_eq!(
        inbox(&fx.recipient_device).len(),
        2,
        "the repeated grant posted its pointer again"
    );
}

/// A grant whose share pointer never reached the recipient leaves the row
/// committed and the inbox empty. The same grant retried delivers one pointer
/// to the live root and publishes nothing.
#[test]
fn a_grant_retried_after_a_failed_pointer_post_delivers_the_pointer() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    for item in block_on(fx.recipient_device.mailbox.poll()).expect("the inbox answers") {
        block_on(fx.recipient_device.mailbox.ack(&item.item_id)).expect("the ack lands");
    }
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        name.as_str().as_bytes(),
        "one pointer, naming the root that stands"
    );
    assert_eq!(
        sequence_at(&fx.world, &name),
        before,
        "and nothing publishes"
    );
}

/// The grant floor the owner raises for the recipient at `scope`, as the engine
/// keys it before the owner view labels it.
fn grant_floor_key(scope: &[u8; 16], recipient_secret: &[u8; 32]) -> Vec<u8> {
    [
        scope.as_slice(),
        b"/granted/",
        &kdf::enc_subkey(recipient_secret).public().to_bytes(),
    ]
    .concat()
}

/// A grant whose row published and whose floor raise failed leaves the
/// recipient withheld at the next cut. The same grant retried raises the floor
/// before it re-posts the pointer.
#[test]
fn a_grant_retried_after_a_failed_floor_raise_raises_the_floor() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let floor = grant_floor_key(&fx.folder.0, &RECIPIENT_SECRET);
    let raised = |fx: &GrantScenario| {
        block_on(fx.owner_device.floors(&SECRET).epoch_floor(&floor)).expect("the floor reads")
    };
    fx.owner_device
        .floor_store
        .fail_floor_raises_for(&floor_label(&floor));
    assert!(
        fx.grant_folder_to_recipient().is_err(),
        "the row publishes and its floor raise fails"
    );
    fx.owner_device.floor_store.heal_floors();
    assert!(
        fx.granted_to()
            .contains(&recipient_identity().verifying_key().to_sec1().to_vec()),
        "the row is committed"
    );
    assert_eq!(raised(&fx), None);

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    assert_eq!(
        raised(&fx),
        Some(published_read_epoch(&fx.world, &fx.blocks, fx.folder))
    );
    assert_eq!(
        inbox(&fx.recipient_device).len(),
        1,
        "and the pointer posts"
    );
}

/// A direct grant vouches for a link-sourced contact, so no later cut of the
/// link collects a contact that holds a grant. A vouch that failed after the
/// publish is not lost: the retry at the held permission vouches again.
#[test]
fn a_grant_retried_after_a_failed_vouch_vouches_the_contact() {
    let mut fx = GrantScenario::new();
    let recipient = recipient_identity().verifying_key().to_sec1();
    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let staging = fx.owner_device.staging_store.clone();
    let book = StagingContactStore::new(&staging, &enc_subkey, &entropy);
    block_on(book.forget(&recipient)).expect("the hand import is dropped");
    block_on(book.record_from_link(
        &contact_code(&RECIPIENT_SECRET),
        &committed_link_at(0x33, [0x33; 32]),
        &fx.folder.0,
    ))
    .expect("the recipient records from a link");

    staging
        .inner()
        .interrupt_staged_write_after(book.staging_key(), 0);
    assert!(
        matches!(
            fx.grant_folder_to_recipient(),
            Err(EngineError::Seam { .. })
        ),
        "the vouch after the publish fails"
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    block_on(book.forget_link_grant(&recipient, &fx.folder.0)).expect("the cut lands");
    assert!(
        block_on(book.contacts())
            .expect("load")
            .iter()
            .any(|contact| contact.identity_pk().to_sec1() == recipient),
        "the vouched contact outlives the link's cut"
    );
}

/// A grant whose handover stalls after its root landed still vouches for a
/// link-sourced recipient, so the link's cut does not collect the contact its
/// owed delivery is for.
#[test]
fn a_grant_whose_handover_stalls_vouches_the_contact() {
    let mut fx = GrantScenario::new();
    let recipient = recipient_identity().verifying_key().to_sec1();
    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let staging = fx.owner_device.staging_store.clone();
    let book = StagingContactStore::new(&staging, &enc_subkey, &entropy);
    block_on(book.forget(&recipient)).expect("the hand import is dropped");
    block_on(book.record_from_link(
        &contact_code(&RECIPIENT_SECRET),
        &committed_link_at(0x33, [0x33; 32]),
        &fx.folder.0,
    ))
    .expect("the recipient records from a link");

    fx.stall_the_owed_move();

    block_on(book.forget_link_grant(&recipient, &fx.folder.0)).expect("the cut lands");
    assert!(
        block_on(book.contacts())
            .expect("load")
            .iter()
            .any(|contact| contact.identity_pk().to_sec1() == recipient),
        "the vouched contact outlives the link's cut"
    );
}

/// A contact re-imported under a new encryption subkey cannot open the blob
/// its row seals to its old one, so a grant retry refuses rather than post a
/// pointer that restores nothing. The owner revokes and grants again.
#[test]
fn a_grant_retry_to_a_contact_whose_encryption_key_changed_is_refused() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    block_on(
        fx.engine.command(Command::ImportContact {
            contact_code: ContactCode::create(
                &recipient_identity(),
                kdf::enc_subkey(&BYSTANDER_SECRET).public(),
            )
            .encode(),
        }),
    )
    .expect("the same identity re-imports under a new subkey");
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);
    let delivered = inbox(&fx.recipient_device);

    assert_eq!(
        fx.grant_folder_to_recipient(),
        Err(EngineError::MalformedInput {
            check: "grant-recipient-key-changed"
        }),
    );

    assert_eq!(inbox(&fx.recipient_device), delivered, "no pointer posts");
    assert_eq!(sequence_at(&fx.world, &name), before, "nothing publishes");
}

/// A grantee name is used only on a row the grant mints, so an existing row's
/// retry ignores a name the row could not carry, while a first grant refuses it
/// before anything publishes.
#[test]
fn a_name_the_row_cannot_carry_is_ignored_on_a_retry_and_refused_on_a_mint() {
    let mut fx = GrantScenario::new();
    let too_long = "x".repeat(256);
    let refused = GranteeName::new(too_long.clone(), NameSource::Owner)
        .expect_err("a name past the bound is no name")
        .check();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);

    assert_eq!(
        fx.grant_named(Permission::Read, &too_long),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        inbox(&fx.recipient_device).len(),
        2,
        "the retry re-posts the pointer"
    );

    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second recipient's code imports");
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: Some(too_long),
        })),
        Err(EngineError::MalformedInput { check: refused }),
    );
    assert_eq!(sequence_at(&fx.world, &name), before, "nothing publishes");
}

/// The parent index names the moved root, so a second owner device that never
/// saw the wave still finds the grantee, and re-delivers to the moved root.
#[test]
fn a_grant_the_grantee_holds_re_delivers_on_a_device_that_missed_the_wave() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let moved = fx.granted_scope_repoint().current_root;
    for item in block_on(fx.recipient_device.mailbox.poll()).expect("the inbox answers") {
        block_on(fx.recipient_device.mailbox.ack(&item.item_id)).expect("the ack lands");
    }

    let (mut engine, _events, _tasks) = fx.second_owner_device();
    import_recipient(&mut engine);

    assert_eq!(
        block_on(engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Write,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done),
    );
    assert_eq!(fx.granted_scope_repoint().current_root, moved);
    assert_eq!(
        delivered_share_pointer(&fx.recipient_device).scope_root_name,
        moved.as_str().as_bytes(),
    );
}

/// A write grant to a read grantee is an upgrade (ADR 0026 D4, ADR 0025 D6).
/// The folder is not a write scope yet, so one write-scope cut runs first, and
/// the write row is committed only at the root it moved to: the record left at
/// the inherited name never hands the grantee the seed the vault's names derive
/// from.
#[test]
fn a_write_grant_to_a_read_grantee_upgrades_it_after_one_write_scope_cut() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let inherited = write_name(fx.folder);

    assert_eq!(
        fx.grant_named(Permission::Write, "Carol"),
        Ok(CommandOutcome::Done)
    );
    let names: Vec<Option<(String, NameSource)>> = block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved")
        .grants
        .into_iter()
        .map(|grant| grant.grantee_name)
        .collect();
    assert_eq!(names, vec![None], "a permission change applies no name");

    let repoint = fx.granted_scope_repoint();
    assert_eq!(repoint.write_epoch, 2, "one write-scope cut ran");
    assert_eq!(repoint.prev_root.as_ref(), Some(&inherited));
    let moved = repoint.current_root;
    assert_eq!(fx.committed_permission(&moved), Some(CorePermission::Write));
    let section = published_grant_section_at(&fx.world, &fx.blocks, &moved)
        .expect("the moved root answers as a scope root");
    let seed = grantee_write_scope_seed(&section, &moved, &fx.folder.0, 1);
    assert_eq!(
        derive_write_name(&seed, &fx.folder.0),
        moved,
        "the grantee's seed derives the root they resolve"
    );
    assert_eq!(
        fx.granted_blob_carries_write_seed(&inherited),
        Some(false),
        "and the record at the inherited name conveys no write seed"
    );
}

/// ADR 0025 D3 and D6 from an owner device that never imported the grantee: the
/// row the owner signed names them, so an upgrade and a downgrade both run. The
/// downgrade is a write cut, and the grantee still reads.
#[test]
fn a_permission_change_runs_from_the_owner_signed_row_on_any_owner_device() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let (mut engine, _events, _tasks) = fx.second_owner_device();
    let folder = fx.folder;
    let change = |engine: &mut Engine<FakeSeamTypes>, permission| {
        block_on(engine.command(Command::ChangePermission {
            node: folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission,
        }))
    };

    assert_eq!(
        change(&mut engine, Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let upgraded = fx.granted_scope_repoint();
    assert_eq!(
        fx.committed_permission(&upgraded.current_root),
        Some(CorePermission::Write)
    );
    assert_eq!(
        fx.granted_blob_carries_write_seed(&upgraded.current_root),
        Some(true)
    );

    assert_eq!(
        change(&mut engine, Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let downgraded = fx.granted_scope_repoint();
    assert_eq!(
        downgraded.write_epoch,
        upgraded.write_epoch + 1,
        "the downgrade ran a write cut"
    );
    assert_eq!(
        fx.committed_permission(&downgraded.current_root),
        Some(CorePermission::Read)
    );
    assert_eq!(
        fx.granted_blob_carries_write_seed(&downgraded.current_root),
        Some(false),
        "and the grantee still holds a read blob"
    );
}

/// A link's permission is fixed (ADR 0025 D7), the owner is no grantee, and a
/// change names a grantee the set commits.
#[test]
fn a_permission_change_refuses_a_link_the_owner_and_a_stranger() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link();
    let opened = InviteFragment::decode(&fragment).expect("the mint's own fragment");
    let link_identity = EphemeralInvitee::from_secret(opened.invite_secret.as_bytes())
        .expect("valid secret")
        .identity_pk()
        .to_sec1()
        .to_vec();
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);

    for (identity, refusal) in [
        (
            link_identity,
            EngineError::UnsupportedTarget {
                check: "grant-row-is-a-link",
            },
        ),
        (
            owner_identity().verifying_key().to_sec1().to_vec(),
            EngineError::MalformedInput {
                check: "recipient-is-the-owner",
            },
        ),
        (
            bystander_identity(),
            EngineError::MalformedInput {
                check: "grant-recipient-not-granted",
            },
        ),
    ] {
        assert_eq!(
            block_on(fx.engine.command(Command::ChangePermission {
                node: fx.folder,
                recipient_identity_public_key: identity,
                permission: Permission::Write,
            })),
            Err(refusal),
        );
    }
    assert_eq!(sequence_at(&fx.world, &name), before, "nothing publishes");
}

/// A grantee name edit is a row update with the source `owner` and one root
/// publish (ADR 0027 D3). Only that row's name and signature move, and this
/// device caches the name to pre-fill it elsewhere (D4).
#[test]
fn a_grantee_name_edit_changes_only_that_row_and_publishes_once() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let name = write_name(fx.folder);
    let before = sequence_at(&fx.world, &name);
    let section_before = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the granted folder is a scope root");
    let ledger_before = published_ledger(&fx.world, &fx.blocks, fx.folder);
    let recipient = recipient_identity().verifying_key().to_sec1();

    assert_eq!(
        block_on(fx.engine.command(Command::RenameGrantee {
            node: fx.folder,
            recipient_identity_public_key: recipient.to_vec(),
            name: "Alice".to_owned(),
        })),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(sequence_at(&fx.world, &name), before + 1, "one publish");
    let section_after = published_grant_section(&fx.world, &fx.blocks, fx.folder)
        .expect("the scope root still answers");
    assert_eq!(
        section_after.commitment, section_before.commitment,
        "the committed set does not move"
    );
    let ledger_after = published_ledger(&fx.world, &fx.blocks, fx.folder);
    assert_eq!(ledger_after.len(), ledger_before.len());
    for (before, after) in ledger_before.iter().zip(&ledger_after) {
        if after.recipient_identity_pk != recipient {
            assert_eq!(after, before, "no other row moves");
            continue;
        }
        let granted = after
            .grantee_name
            .as_ref()
            .expect("the row carries the name");
        assert_eq!(granted.name(), "Alice");
        assert_eq!(granted.source(), NameSource::Owner);
        let mut unchanged = after.clone();
        unchanged.grantee_name = None;
        unchanged.owner_sig = before.owner_sig;
        assert_eq!(&unchanged, before, "only the name and its signature move");
        assert!(row_is_owner_attested(
            &owner_identity().verifying_key(),
            after,
            name.as_str().as_bytes(),
        ));
    }

    let view = block_on(fx.engine.sharing(fx.folder)).expect("a sharing read");
    let grant = view
        .state
        .expect("the scope root resolved")
        .grants
        .into_iter()
        .find(|grant| grant.recipient_identity_public_key == recipient)
        .expect("the renamed grantee");
    assert_eq!(
        grant.grantee_name,
        Some(("Alice".to_owned(), NameSource::Owner))
    );
    let contact = view
        .contacts
        .into_iter()
        .find(|contact| contact.identity_public_key == recipient)
        .expect("the imported recipient");
    assert_eq!(contact.cached_name.as_deref(), Some("Alice"));
}

/// The name cache is a pre-fill and no authority, so a cache that does not open
/// is cleared, reported once, and the sharing read goes on without its names.
#[test]
fn a_name_cache_that_does_not_open_is_cleared_and_the_sharing_read_goes_on() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let key = StagingGranteeNameCache::new(&fx.owner_device.staging_store, &enc, &entropy)
        .staging_key()
        .to_vec();
    block_on(
        fx.owner_device
            .staging_store
            .put_staged_bytes(&key, b"not a sealed cache"),
    )
    .expect("the corrupt blob stores");
    events_so_far(&mut fx._events);

    let view = block_on(fx.engine.sharing(fx.folder)).expect("the sharing read succeeds");

    assert!(!view.contacts.is_empty());
    assert!(
        view.contacts
            .iter()
            .all(|contact| contact.cached_name.is_none())
    );
    assert!(view.state.is_some(), "the scope's own sharing still reads");
    assert_eq!(
        block_on(fx.owner_device.staging_store.staged_bytes(&key)).expect("the store reads"),
        None,
        "the cache is cleared"
    );
    block_on(fx.engine.sharing(fx.folder)).expect("a second read");
    assert_eq!(
        events_so_far(&mut fx._events)
            .into_iter()
            .filter(|event| *event == Event::GranteeNamesCleared)
            .count(),
        1,
        "reported once"
    );
}

/// The row the stalled write share committed names the grantee, so a read
/// share over it is a downgrade (ADR 0026 D4). It runs the owed wave and then
/// its own: two write-epoch steps.
#[test]
fn a_read_share_over_a_stalled_write_scope_is_a_downgrade() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);

    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));

    let repoint = fx.granted_scope_repoint();
    assert_ne!(
        repoint.current_root, stalled,
        "the downgrade ran the write cut"
    );
    assert_eq!(repoint.write_epoch, 3, "after the wave the mint owed");
    assert_eq!(
        fx.committed_permission(&repoint.current_root),
        Some(CorePermission::Read)
    );
}

/// A write share to another recipient over a stalled write scope appends a
/// row. The one wave it runs is the one the stalled share owed.
#[test]
fn a_write_share_to_another_recipient_over_a_stalled_scope_appends_after_one_wave() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);
    let bystander_device = fx.device_for(&BYSTANDER_SECRET);

    assert_eq!(
        fx.grant_bystander(Permission::Write),
        Ok(CommandOutcome::Done)
    );

    let repoint = fx.granted_scope_repoint();
    assert_eq!(repoint.prev_root.as_ref(), Some(&stalled));
    assert_eq!(repoint.write_epoch, 2, "one wave");
    assert_eq!(
        fx.committed_permission(&repoint.current_root),
        Some(CorePermission::Write),
        "the first grantee's row survives the wave"
    );
    assert_eq!(
        delivered_share_pointer_for(&bystander_device, &BYSTANDER_SECRET).scope_root_name,
        repoint.current_root.as_str().as_bytes(),
        "and the new grantee is sent to the moved root"
    );
}

/// ADR 0027 D2: a grant names its grantee on the row it mints, with the source
/// `owner`, on a fresh scope and on an append alike, and the owner's binding
/// signature covers the name. A name the row cannot carry is refused before
/// anything publishes.
#[test]
fn a_grant_names_its_grantee_on_the_row_it_mints_or_appends() {
    let mut fx = GrantScenario::new();
    let refused = GranteeName::new(String::new(), NameSource::Owner)
        .expect_err("an empty name is no name")
        .check();
    assert_eq!(
        fx.grant_named(Permission::Read, ""),
        Err(EngineError::MalformedInput { check: refused }),
    );
    assert_eq!(
        published_grant_section(&fx.world, &fx.blocks, fx.folder),
        None,
        "and nothing is minted"
    );

    assert_eq!(
        fx.grant_named(Permission::Read, "Alice"),
        Ok(CommandOutcome::Done)
    );
    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second recipient's code imports");
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: Some("Bob".to_owned()),
        })),
        Ok(CommandOutcome::Done)
    );

    let name = write_name(fx.folder);
    let recipient = recipient_identity().verifying_key().to_sec1().to_vec();
    for row in published_ledger(&fx.world, &fx.blocks, fx.folder) {
        let expected = if row.recipient_identity_pk.to_vec() == recipient {
            "Alice"
        } else {
            "Bob"
        };
        let granted = row.grantee_name.as_ref().expect("the row carries a name");
        assert_eq!(granted.name(), expected);
        assert_eq!(granted.source(), NameSource::Owner);
        assert!(row_is_owner_attested(
            &owner_identity().verifying_key(),
            &row,
            name.as_str().as_bytes(),
        ));
    }
    let names: Vec<Option<(String, NameSource)>> = block_on(fx.engine.sharing(fx.folder))
        .expect("a sharing read")
        .state
        .expect("the scope root resolved")
        .grants
        .into_iter()
        .map(|grant| grant.grantee_name)
        .collect();
    assert_eq!(
        names,
        vec![
            Some(("Alice".to_owned(), NameSource::Owner)),
            Some(("Bob".to_owned(), NameSource::Owner)),
        ]
    );
}

/// A name a grant gives goes into this device's name cache, on a fresh scope
/// and on an append alike, so the sharing read of another folder pre-fills it
/// (ADR 0027 D4).
#[test]
fn a_named_grant_pre_fills_the_name_on_another_folder() {
    let mut fx = GrantScenario::new();
    let other = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "other");
    assert_eq!(
        fx.grant_named(Permission::Read, "Alice"),
        Ok(CommandOutcome::Done)
    );
    block_on(fx.engine.command(Command::ImportContact {
        contact_code: contact_code(&BYSTANDER_SECRET),
    }))
    .expect("the second recipient's code imports");
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node: fx.folder,
            recipient_identity_public_key: bystander_identity(),
            permission: Permission::Read,
            grantee_name: Some("Bob".to_owned()),
        })),
        Ok(CommandOutcome::Done)
    );

    let contacts = block_on(fx.engine.sharing(other))
        .expect("a sharing read")
        .contacts;
    let cached = |identity: &[u8]| {
        contacts
            .iter()
            .find(|contact| contact.identity_public_key == identity)
            .expect("an imported contact")
            .cached_name
            .clone()
    };
    let recipient = recipient_identity().verifying_key().to_sec1();
    assert_eq!(cached(&recipient).as_deref(), Some("Alice"));
    assert_eq!(cached(&bystander_identity()).as_deref(), Some("Bob"));
}

/// A committed writer authors the ledger, so it can relabel a row. A row whose
/// owner binding no longer verifies names nobody, so a permission change and a
/// rename of it are refused and nothing publishes (ADR 0027 D6).
#[test]
fn a_row_a_co_writer_relabelled_is_refused_for_a_change_and_a_rename() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let mut relabelled = recipient_row_at_root(CorePermission::Write);
    let honest = relabelled.ledger_entry.recipient_identity_pk;
    relabelled.ledger_entry.recipient_identity_pk = [0x11; IDENTITY_PUBLIC_LEN];
    let root = seed_vault(&world, &blocks, vec![relabelled]);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    let before = sequence_at(&world, &root);

    for identity in [honest, [0x11; IDENTITY_PUBLIC_LEN]] {
        for command in [
            Command::ChangePermission {
                node: ROOT,
                recipient_identity_public_key: identity.to_vec(),
                permission: Permission::Read,
            },
            Command::RenameGrantee {
                node: ROOT,
                recipient_identity_public_key: identity.to_vec(),
                name: "Mallory".to_owned(),
            },
        ] {
            assert_eq!(
                block_on(engine.command(command)),
                Err(EngineError::MalformedInput {
                    check: "grant-recipient-not-granted"
                }),
            );
        }
    }
    assert_eq!(sequence_at(&world, &root), before, "nothing publishes");
}

/// An upgrade of a folder granted inside a granted folder cuts that folder's
/// own write scope: the seed its grantee receives derives the name the nested
/// root moved to, and is not the enclosing scope's.
#[test]
fn a_nested_root_upgrade_seals_its_own_write_scope_seed() {
    let mut fx = GrantScenario::new();
    let inner = fx.grant_nested_folder("inner");

    assert_eq!(
        block_on(fx.engine.command(Command::ChangePermission {
            node: inner,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Write,
        })),
        Ok(CommandOutcome::Done)
    );

    let repoint = scope_repoint(&fx.world, &inner.0);
    assert_eq!(repoint.write_epoch, 2, "one write-scope cut ran");
    let moved = repoint.current_root;
    let section = published_grant_section_at(&fx.world, &fx.blocks, &moved)
        .expect("the moved nested root answers as a scope root");
    let seed = grantee_write_scope_seed(&section, &moved, &inner.0, 1);
    assert_eq!(derive_write_name(&seed, &inner.0), moved);
    assert!(
        seed != WRITE_SCOPE_SEED,
        "the nested grantee never holds the enclosing scope's seed"
    );
}

/// A grantee with two owner-attested rows names no single row, so a permission
/// change refuses and publishes nothing.
#[test]
fn a_permission_change_refuses_a_grantee_that_holds_more_than_one_row() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let second = mint_grant_row(
        &owner_identity(),
        &kdf::enc_subkey(&SECRET),
        &owner_pointer_read_key(),
        recipient_identity().verifying_key().to_sec1(),
        &kdf::enc_subkey(&BYSTANDER_SECRET).public(),
        &SCOPE,
        write_name(ROOT).as_str().as_bytes(),
        CorePermission::Write,
    )
    .expect("a contributory recipient key");
    seed_vault(
        &world,
        &blocks,
        vec![recipient_row_at_root(CorePermission::Write), second],
    );
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot_owner(&world, &blocks, &alice);
    let before = published_grant_section(&world, &blocks, ROOT).expect("the root answers");

    assert_eq!(
        block_on(engine.command(Command::ChangePermission {
            node: ROOT,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "grantee-holds-more-than-one-row"
        }),
    );
    assert_eq!(
        published_grant_section(&world, &blocks, ROOT).expect("the root answers"),
        before,
        "nothing is published"
    );
}
// ---------------------------------------------------------------------------
// A write grantee's delete, end to end
// ---------------------------------------------------------------------------

/// The recipient's own session against the configured API, started on their
/// own login secret, with their loops parked.
fn recipient_session(fx: &GrantScenario) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    serve_http(&fx.recipient_device, &fx.blocks, 8_000);
    let (mut engine, events) = engine_on_api(&fx.recipient_device, 21);
    block_on(engine.start(LoginSecret::new(RECIPIENT_SECRET.to_vec()), None))
        .expect("the recipient's own session starts");
    let mut tasks = fx.world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    block_on(engine.command(Command::ImportContact {
        contact_code: contact_code(&SECRET),
    }))
    .expect("the owner's code imports");
    (engine, events, tasks)
}

/// ADR 0024 D4: the conversion of a write claim cuts the write scope, which
/// moves the scope root. The session that joined through the link renders the
/// root at the name it joined at, so the root must move to the healed bookmark
/// name, or the drain writes under a name the new write seed does not derive.
/// The host also hears of the tick that makes the folder writable.
#[test]
fn a_write_link_holder_writes_in_the_joining_session_after_the_other_device_converts() {
    let mut fx = GrantScenario::new();
    let fragment = fx.mint_link_at(Permission::Write);
    let joined_at = fx.granted_scope_repoint().current_root;
    let (mut holder, mut holder_events, mut holder_tasks) = recipient_session(&fx);
    assert_eq!(
        join_link(&mut holder, &mut holder_tasks, fragment),
        Ok(CommandOutcome::Done)
    );
    settle(&fx, &holder, &mut holder_tasks);
    let shared = block_on(holder.received_shares()).expect("the list reads")[0].scope;
    assert_eq!(
        block_on(holder.snapshot(shared))
            .expect("a view")
            .permission,
        Permission::Read,
        "a link holder reads before the conversion"
    );
    let (mut phone_engine, _phone_events, mut phone_tasks) = fx.owner_phone();
    tick(&fx.world, &phone_engine, &mut phone_tasks);
    assert_ne!(
        fx.granted_scope_repoint().current_root,
        joined_at,
        "the conversion moved the scope root"
    );

    let mut writable = false;
    for _ in 0..4 {
        events_so_far(&mut holder_events);
        tick(&fx.world, &holder, &mut holder_tasks);
        let repainted = events_so_far(&mut holder_events)
            .iter()
            .any(|event| matches!(event, Event::SnapshotUpdated));
        if block_on(holder.snapshot(shared))
            .expect("a view")
            .permission
            == Permission::Write
        {
            assert!(
                repainted,
                "the tick that makes the folder writable repaints"
            );
            writable = true;
            break;
        }
    }
    assert!(writable, "the joining session gets write");

    block_on(holder.command(Command::Create {
        parent: shared,
        name: "from the link holder".into(),
        kind: NodeKind::Folder,
    }))
    .expect("the create journals");
    for _ in 0..4 {
        tick(&fx.world, &holder, &mut holder_tasks);
    }
    assert!(
        block_on(fx.recipient_device.pending_ops())
            .expect("the queue reads")
            .is_empty(),
        "the drain published the create under the moved root"
    );
    block_on(phone_engine.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the phone opens the folder");
    for _ in 0..4 {
        tick(&fx.world, &phone_engine, &mut phone_tasks);
    }
    assert!(
        block_on(phone_engine.view())
            .expect("a rendered view")
            .children(fx.folder)
            .iter()
            .any(|child| child.name == "from the link holder"),
        "the owner reads the write at the moved root"
    );
}

/// A write grantee's delete only unlinks the node from its folder in the granted
/// scope. The owner's engine then bins the node by owner capture, and the
/// grantee's own bin stays empty (CONTEXT.md "Owner capture").
#[test]
fn a_write_grantees_delete_reaches_the_owners_bin_by_owner_capture() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let doomed = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "doomed",
    );
    block_on(fx.engine.command(Command::SetFocus {
        node: Some(fx.folder),
    }))
    .expect("the owner opens the granted folder");

    let (mut grantee, _grantee_events, mut grantee_tasks) = recipient_session(&fx);
    for _ in 0..4 {
        fx.world.scheduler.advance(grantee.profile().stale_after);
        poll_tasks_until_parked(&mut grantee_tasks);
    }
    let shares = block_on(grantee.received_shares()).expect("the list reads");
    assert_eq!(shares.len(), 1, "the grantee accepted the share");
    let shared = shares[0].scope;
    assert!(
        block_on(grantee.view())
            .expect("a rendered view")
            .children(shared)
            .iter()
            .any(|child| child.id == doomed),
        "the grantee renders the owner's folder"
    );

    block_on(grantee.command(Command::Delete { node: doomed }))
        .expect("the grantee's delete journals");
    for _ in 0..4 {
        fx.world.scheduler.advance(grantee.profile().poll_cadence);
        poll_tasks_until_parked(&mut grantee_tasks);
    }
    assert!(
        block_on(grantee.bin())
            .expect("the grantee's bin reads")
            .entries
            .is_empty(),
        "the grantee wrote no bin entry"
    );

    assert!(
        block_on(fx.recipient_device.pending_ops())
            .expect("the queue reads")
            .is_empty(),
        "the grantee's grafted pass published the unlink"
    );
    for _ in 0..4 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert!(
        block_on(fx.engine.view())
            .expect("a rendered view")
            .children(fx.folder)
            .is_empty(),
        "the owner reads the unlink"
    );
    let entries = published_bin_entries(&fx);
    let entry = entries
        .iter()
        .find(|entry| entry.node_id == doomed.0)
        .expect("the owner's capture binned the grantee's unlink");
    assert_eq!(entry.scope_id, fx.folder.0);
    assert_eq!(entry.origin_parent, fx.folder.0);
}

/// A received share holds no scope the grantee's own vault owes work at, so
/// the grantee's own owed record, even one that does not open, does not stop
/// a delete inside the share.
#[test]
fn a_grantees_delete_in_a_share_does_not_read_its_own_owed_record() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let doomed = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "doomed",
    );
    let key = owed_rotation_key(&kdf::enc_subkey(&RECIPIENT_SECRET));
    block_on(
        fx.recipient_device
            .staging_store
            .put_staged_bytes(&key, b"not an owed rotation record"),
    )
    .expect("stage the bytes");
    let (mut grantee, _grantee_events, mut grantee_tasks) = recipient_session(&fx);
    for _ in 0..4 {
        fx.world.scheduler.advance(grantee.profile().stale_after);
        poll_tasks_until_parked(&mut grantee_tasks);
    }
    assert!(
        block_on(grantee.received_shares())
            .expect("the list reads")
            .iter()
            .any(|share| share.scope == fx.folder),
        "the grantee accepted the share"
    );

    block_on(grantee.command(Command::Delete { node: doomed })).expect("the delete journals");
}

/// Stop the owner's session, then start it on a later device once the walk
/// window has opened, and let the walk run. The later session stays alive in
/// the returned device, engine and tasks.
fn restart_later(
    fx: GrantScenario,
) -> (
    FakeWorld,
    EventStream,
    (FakeDevice, Engine<FakeSeamTypes>, Vec<BoxedTask>),
) {
    restart_later_with(fx, |_| {})
}

/// [`restart_later`], with `prepare` run on the later device before it starts.
fn restart_later_with(
    fx: GrantScenario,
    prepare: impl FnOnce(&FakeDevice),
) -> (
    FakeWorld,
    EventStream,
    (FakeDevice, Engine<FakeSeamTypes>, Vec<BoxedTask>),
) {
    let GrantScenario {
        world,
        blocks,
        engine,
        _tasks,
        ..
    } = fx;
    let device = world.device(b"the owner's later device");
    prepare(&device);
    start_later_on(world, &blocks, device, (engine, _tasks))
}

/// [`restart_later`], on the owner's own device, so what it staged carries.
fn restart_later_on_the_same_device(
    fx: GrantScenario,
) -> (
    FakeWorld,
    EventStream,
    (FakeDevice, Engine<FakeSeamTypes>, Vec<BoxedTask>),
) {
    let GrantScenario {
        world,
        blocks,
        owner_device,
        engine,
        _tasks,
        ..
    } = fx;
    start_later_on(world, &blocks, owner_device, (engine, _tasks))
}

fn start_later_on(
    world: FakeWorld,
    blocks: &Blocks,
    device: FakeDevice,
    stopped: (Engine<FakeSeamTypes>, Vec<BoxedTask>),
) -> (
    FakeWorld,
    EventStream,
    (FakeDevice, Engine<FakeSeamTypes>, Vec<BoxedTask>),
) {
    start_after(
        world,
        blocks,
        device,
        stopped,
        Duration::from_secs(65 * 24 * 60 * 60),
    )
}

/// [`start_later_on`], `gap` after the stopped session.
fn start_after(
    world: FakeWorld,
    blocks: &Blocks,
    device: FakeDevice,
    stopped: (Engine<FakeSeamTypes>, Vec<BoxedTask>),
    gap: Duration,
) -> (
    FakeWorld,
    EventStream,
    (FakeDevice, Engine<FakeSeamTypes>, Vec<BoxedTask>),
) {
    drop(stopped);
    drop(world.scheduler.take_spawned_tasks());
    world.scheduler.advance(gap);
    let (engine, events, mut tasks) = boot_owner(&world, blocks, &device);
    for _ in 0..3 {
        tick(&world, &engine, &mut tasks);
    }
    (world, events, (device, engine, tasks))
}

/// ADR 0061 D1: a folder a grant cut into a scope root of its own is a walk
/// root of its own. The walk waits for the boundary walk that names it, so a
/// folder inside it renews at the next start, and the walk reports nothing for
/// the scope root it meets as a child of the vault root.
#[test]
fn a_folder_inside_a_granted_scope_renews_at_the_next_start() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(
        abuse_events(&mut fx._events),
        0,
        "the session that minted the scope reports nothing either"
    );
    let before = sequence_at(&fx.world, &write_name(inner));
    let (world, mut events, _later) = restart_later(fx);

    assert_eq!(
        sequence_at(&world, &write_name(inner)),
        before + 1,
        "the walk reached the folder through the granted scope's own root"
    );
    assert_eq!(
        abuse_events(&mut events),
        0,
        "a known scope root is no violation"
    );
}

/// A doomed-name journal entry that does not open stops the walk only under
/// its own scope root: a folder in another owned scope still renews, and the
/// stall names the entry's scope root alone.
#[test]
fn an_unreadable_journal_entry_stops_the_walk_under_its_own_scope_only() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    let outer = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "outer");
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let inner_before = sequence_at(&fx.world, &write_name(inner));
    let outer_before = sequence_at(&fx.world, &write_name(outer));
    let (world, mut events, _later) = restart_later_with(fx, |device| {
        let entry =
            doomed_journal_key(&owner_tag(&kdf::enc_subkey(&SECRET)), ROOT, NodeId([7; 16]));
        block_on(
            device
                .staging_store
                .put_staged_bytes(&entry, b"not a sealed reclamation"),
        )
        .expect("stage the entry");
    });

    assert_eq!(
        sequence_at(&world, &write_name(inner)),
        inner_before + 1,
        "the granted scope still renews"
    );
    assert_eq!(
        sequence_at(&world, &write_name(outer)),
        outer_before,
        "the entry's scope does not"
    );
    let stalled: std::collections::BTreeSet<String> = events_so_far(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            Event::RenewalFailed {
                routing_key,
                detail,
            } if detail.contains("doomed-name journal") => Some(routing_key),
            _ => None,
        })
        .collect();
    assert_eq!(
        stalled,
        std::collections::BTreeSet::from([write_name(ROOT).as_str().to_owned()]),
        "the stall names the vault root alone"
    );
}

/// A folder that predates the grant stays sealed under the scope it left until
/// the lazy wave reaches it. The walk still renews it, and reports nothing.
#[test]
fn a_folder_that_predates_a_grant_renews_at_the_next_start() {
    let mut fx = GrantScenario::new();
    let older = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "older",
    );
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let before = sequence_at(&fx.world, &write_name(older));
    let (world, mut events, _later) = restart_later(fx);

    assert_eq!(
        sequence_at(&world, &write_name(older)),
        before + 1,
        "the walk renewed the folder the lazy wave has not re-sealed"
    );
    assert_eq!(
        abuse_events(&mut events),
        0,
        "a lagging node is no violation"
    );
}

/// Stand in for a name wave that stopped before it reached `child`: publish
/// `parent` at its current name, under `write_seed`, naming `child` at
/// `child_name` instead.
fn name_child_at(
    world: &FakeWorld,
    blocks: &Blocks,
    write_seed: &[u8; 32],
    read_seed: &[u8; 32],
    parent: NodeId,
    child: NodeId,
    child_name: &IpnsName,
) {
    let parent_name = derive_write_name(write_seed, &parent.0);
    let head = published_head(world, blocks, &parent_name).expect("the parent is published");
    let envelope = decode_envelope(&head).expect("the head block decodes");
    let read_key = node_read_key(read_seed, parent);
    let ReadBody::Folder {
        created_at,
        modified_at,
        mut children,
        unknown,
    } = open_read_body(&envelope, &read_key).expect("the parent opens under the scope's seed")
    else {
        panic!("expected a folder body");
    };
    for entry in &mut children {
        if entry.id == child.0 {
            entry.ipns_name = child_name.as_str().as_bytes().to_vec();
        }
    }
    let authored = author_child_envelope(EnvelopeAuthoring {
        node_id: parent.0,
        scope_id: envelope.scope,
        epoch: envelope.epoch,
        read_key: &read_key,
        nonce: &[0x4D; 24],
        body: &ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        },
        carried_unknown: envelope.unknown.clone(),
        carried_epoch_tag_unknown: envelope.epoch_tag_unknown.clone(),
    })
    .expect("a well-formed parent record");
    blocks.put(authored.block.clone());
    let record = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(write_seed, &parent.0).as_bytes()),
        format!("/ipfs/{}", authored.cid).as_bytes(),
        sequence_at(world, &parent_name) + 1,
        TTL_NANOS,
        &eol_from(world.scheduler.now()),
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, parent_name.as_str(), record.clone());
    }
}

/// Publish the head `from` points at under `node`'s name for `signer_seed`,
/// one sequence above what that name holds, as a writer who holds that seed
/// would. Returns the name and the sequence.
fn publish_at_seed_name(
    world: &FakeWorld,
    signer_seed: &[u8; 32],
    node: NodeId,
    from: &IpnsName,
) -> (IpnsName, u64) {
    let name = derive_write_name(signer_seed, &node.0);
    let sequence = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
        .map_or(1, |_| sequence_at(world, &name) + 1);
    let record = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(signer_seed, &node.0).as_bytes()),
        &published_value(world, from),
        sequence,
        TTL_NANOS,
        &eol_from(world.scheduler.now()),
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
    (name, sequence)
}

/// The write seed the owner's history link at the scope root `repoint` names
/// supersedes.
fn superseded_write_seed(
    world: &FakeWorld,
    blocks: &Blocks,
    scope: NodeId,
    repoint: &RepointObject,
    current: &[u8; 32],
) -> [u8; 32] {
    let section = published_grant_section_at(world, blocks, &repoint.current_root)
        .expect("the scope root answers");
    let write_key = kdf::write_key(kdf::write_seed(current, &scope.0).as_bytes());
    let ctx = |struct_tag| AadContext {
        v: ENVELOPE_V,
        id: scope.0,
        scope: scope.0,
        epoch: repoint.write_epoch,
        struct_tag,
    };
    let body = decode_write_body(
        &unseal(
            write_key.as_bytes(),
            &ctx(STRUCT_TAG_WRITE_BODY),
            &section.write_body.sealed,
        )
        .expect("the current write key opens the write body"),
    )
    .expect("the write body decodes");
    *open_owner_history_link(
        &kdf::enc_subkey(&SECRET),
        &ctx(STRUCT_TAG_WRITE_HISTORY_LINK),
        &body.write_history_link,
    )
    .expect("the owner opens its own history link")
    .prev_seed()
}

/// A write grant moves the granted scope onto a fresh write seed. When the
/// name wave stops before a node, the node's parent still names the node's
/// old name, which only the superseded seed derives. The walk signs only under
/// the seed that derives the scope root's name, so it leaves that node to
/// lapse, and it never renews a write under the superseded seed either.
#[test]
fn a_node_a_stopped_wave_did_not_reach_is_not_renewed_at_its_old_name() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let mid = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "mid");
    let leaf = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, mid, "leaf");
    let material = block_on(fx.engine.walked_scope_material(fx.folder))
        .expect("the walk resolved the granted scope");
    let current_leaf = derive_write_name(&material.write_scope_seed, &leaf.0);
    let current_mid = derive_write_name(&material.write_scope_seed, &mid.0);
    let superseded = superseded_write_seed(
        &fx.world,
        &fx.blocks,
        fx.folder,
        &fx.granted_scope_repoint(),
        &material.write_scope_seed,
    );

    // The stopped wave: the leaf's record sits at the name the superseded seed
    // derives, and the parent names it there.
    let (old_leaf, _) = publish_at_seed_name(&fx.world, &superseded, leaf, &current_leaf);
    name_child_at(
        &fx.world,
        &fx.blocks,
        &material.write_scope_seed,
        &material.read_scope_seed,
        mid,
        leaf,
        &old_leaf,
    );
    // A later write under the superseded seed, at a name no parent names.
    let (old_mid, stray) = publish_at_seed_name(&fx.world, &superseded, mid, &current_mid);
    let before = sequence_at(&fx.world, &old_leaf);
    let (world, mut events, _later) = restart_later(fx);

    assert_eq!(
        sequence_at(&world, &old_leaf),
        before,
        "nothing signs under the superseded seed"
    );
    assert_eq!(
        sequence_at(&world, &old_mid),
        stray,
        "a write at an old name no parent names is not renewed"
    );
    assert_eq!(abuse_events(&mut events), 0);
}

// ---------------------------------------------------------------------------
// ADR 0065: the name wave drops a node it cannot move
// ---------------------------------------------------------------------------

/// A drop the stream reports: scope root, node, cause.
fn as_drop(event: &Event) -> Option<(NodeId, NodeId, DropCause)> {
    match event {
        Event::NodeDropped {
            scope_root,
            node_id,
            cause,
        } => Some((*scope_root, *node_id, *cause)),
        _ => None,
    }
}

/// The nodes the stream reports a write cut dropped.
fn dropped_nodes(events: &mut EventStream) -> Vec<(NodeId, NodeId, DropCause)> {
    events_so_far(events).iter().filter_map(as_drop).collect()
}

/// The revokee signs a record for `node` at the name `signer_seed` derives,
/// over `body` sealed at `epoch` under `read_key`. The head block is served
/// only when `serve_head` holds. Returns the name.
#[allow(clippy::too_many_arguments)]
fn plant_node(
    fx: &GrantScenario,
    signer_seed: &[u8; 32],
    node: NodeId,
    body: &ReadBody,
    read_key: &[u8; 32],
    epoch: u64,
    serve_head: bool,
) -> IpnsName {
    let name = derive_write_name(signer_seed, &node.0);
    let planted = author_child_envelope(EnvelopeAuthoring {
        node_id: node.0,
        scope_id: fx.folder.0,
        epoch,
        read_key,
        nonce: &[0x5f; 24],
        body,
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the planted node seals");
    if serve_head {
        fx.blocks.put(planted.block.clone());
    }
    let sequence = fx
        .world
        .record_store
        .record_at(&fx.world.record_store.endpoints()[0], name.as_str())
        .map_or(0, |_| sequence_at(&fx.world, &name));
    let record = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(signer_seed, &node.0).as_bytes()),
        format!("/ipfs/{}", planted.cid).as_bytes(),
        sequence + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
    name
}

/// A folder body naming `children`.
fn folder_body(children: Vec<ChildRef>) -> ReadBody {
    ReadBody::Folder {
        created_at: 0,
        modified_at: 0,
        children,
        unknown: PreservedFields::new(),
    }
}

/// The read key of `node` in the granted scope at read epoch 1, which the
/// write grantee holds before the revoke.
fn granted_read_key(fx: &GrantScenario, node: NodeId) -> [u8; 32] {
    read_key_under(&granted_override_seed(fx, 1), node)
}

/// The revoke finished: the cut moved the scope root off the revokee's seed,
/// nothing stays owed, and the moved root names `child` at a name the
/// revokee's seed does not derive.
fn assert_revoke_finished(fx: &mut GrantScenario, revokee_seed: &[u8; 32], child: NodeId) {
    assert!(fx.owed_scopes().is_empty(), "no work stays owed");
    let after = fx.granted_scope_repoint();
    assert_eq!(after.write_epoch, 3, "the revoke stepped the write epoch");
    assert_ne!(
        derive_write_name(revokee_seed, &fx.folder.0),
        after.current_root,
        "the revokee's seed no longer derives the root"
    );
    assert_ne!(
        derive_write_name(revokee_seed, &child.0),
        moved_child_name(fx, "child"),
        "nor the child the moved root names"
    );
}

/// The child names the moved root gives it, read under the epoch-2 key.
fn moved_children(fx: &GrantScenario, parent_name: &IpnsName, parent: NodeId) -> Vec<ChildRef> {
    let head = published_head(&fx.world, &fx.blocks, parent_name).expect("a published record");
    let envelope = decode_envelope(&head).expect("the head decodes");
    match open_read_body(
        &envelope,
        &read_key_under(&granted_override_seed(fx, 2), parent),
    )
    .expect("the body opens")
    {
        ReadBody::Folder { children, .. } => children,
        ReadBody::File { .. } => Vec::new(),
    }
}

/// The name the moved root gives its child named `display`.
fn moved_child_name(fx: &GrantScenario, display: &str) -> IpnsName {
    published_child_name(
        &fx.world,
        &fx.blocks,
        &fx.granted_scope_repoint().current_root,
        &read_key_under(&granted_override_seed(fx, 2), fx.folder),
        display,
    )
}

/// The revokee plants a grandchild that does not unseal under the key
/// of its epoch. The revoke drops it at once, finishes the cut, retires its
/// old name, and tells the owner which node it left out (ADR 0065 D1).
#[test]
fn a_write_revoke_drops_a_planted_node_that_does_not_unseal() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let planted = plant_node(
        &fx,
        &revokee_seed,
        grandchild,
        &folder_body(Vec::new()),
        &[0x13; 32],
        1,
        true,
    );

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        dropped_nodes(&mut fx._events),
        vec![(fx.folder, grandchild, DropCause::RecordRefused)]
    );
    assert_revoke_finished(&mut fx, &revokee_seed, child);
    assert!(
        moved_children(&fx, &moved_child_name(&fx, "child"), child).is_empty(),
        "the moved child names no ref to the dropped node"
    );
    assert!(
        retired(&fx.owner_device).contains(&planted.as_str().to_owned()),
        "and the dropped node's old name retires"
    );
}

/// The revokee plants a child at an epoch no held history link
/// reaches. The revoke drops it, and the subtree below it, at once.
#[test]
fn a_write_revoke_drops_a_planted_node_beyond_the_ratchet() {
    let mut fx = GrantScenario::new();
    let (child, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_node(
        &fx,
        &revokee_seed,
        child,
        &folder_body(Vec::new()),
        &[0x13; 32],
        0,
        true,
    );

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(
        dropped_nodes(&mut fx._events),
        vec![(fx.folder, child, DropCause::EpochUnreachable)]
    );
    assert!(fx.owed_scopes().is_empty(), "no work stays owed");
    let after = fx.granted_scope_repoint();
    assert_ne!(
        derive_write_name(&revokee_seed, &fx.folder.0),
        after.current_root
    );
    assert!(
        moved_children(&fx, &after.current_root, fx.folder).is_empty(),
        "the moved root names no ref to the dropped child"
    );
}

/// The revokee adds a second ref to a real node, at a name of its own,
/// in a folder the walk reads first. The wave keeps the ref at the name the
/// old write seed derives, and drops the other ref (ADR 0065 D2). No node
/// drops, so the owner is told of none.
#[test]
fn a_write_revoke_drops_a_planted_second_ref_to_a_real_node() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    // "a" sorts before "child", so the walk reads the planted ref first.
    let sibling =
        create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, fx.folder, "a");
    let (child, grandchild) = nested_subtree(&mut fx);
    let root = fx.granted_scope_repoint().current_root;
    let revokee_seed = grantee_write_scope_seed(&fx.folder_section(), &root, &fx.folder.0, 1);
    let planted_seed = [0x77; 32];
    let elsewhere = plant_node(
        &fx,
        &planted_seed,
        grandchild,
        &folder_body(Vec::new()),
        &granted_read_key(&fx, grandchild),
        1,
        true,
    );
    plant_node(
        &fx,
        &revokee_seed,
        sibling,
        &folder_body(vec![named_child(grandchild, "grand", &elsewhere)]),
        &granted_read_key(&fx, sibling),
        1,
        true,
    );

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(dropped_nodes(&mut fx._events), Vec::new());
    assert_revoke_finished(&mut fx, &revokee_seed, child);
    assert!(
        moved_children(&fx, &moved_child_name(&fx, "a"), sibling).is_empty(),
        "the moved sibling drops the second ref"
    );
    let grand = moved_children(&fx, &moved_child_name(&fx, "child"), child);
    assert_eq!(grand.len(), 1, "the moved child keeps its ref");
    assert_ne!(
        grand[0].ipns_name,
        elsewhere.as_str().as_bytes(),
        "at a name of the new seed"
    );
    assert_ne!(
        grand[0].ipns_name,
        derive_write_name(&revokee_seed, &grandchild.0)
            .as_str()
            .as_bytes()
    );
}

/// The revokee adds a ref to an id that has no record.
fn plant_a_ref_to_nothing(
    fx: &GrantScenario,
    revokee_seed: &[u8; 32],
    grandchild: NodeId,
) -> NodeId {
    let read_key = granted_read_key(fx, grandchild);
    plant_a_ref_to(fx, revokee_seed, grandchild, NodeId([0x66; 16]), &read_key)
}

/// The revokee re-signs `grandchild` with one ref, to `ghost`, which has no
/// record.
fn plant_a_ref_to(
    fx: &GrantScenario,
    revokee_seed: &[u8; 32],
    grandchild: NodeId,
    ghost: NodeId,
    read_key: &[u8; 32],
) -> NodeId {
    plant_node(
        fx,
        revokee_seed,
        grandchild,
        &folder_body(vec![named_child(
            ghost,
            "ghost",
            &derive_write_name(&[0x55; 32], &ghost.0),
        )]),
        read_key,
        1,
        true,
    );
    ghost
}

/// The revokee republishes a node at a head block no endpoint serves.
fn plant_an_unserved_head(fx: &GrantScenario, revokee_seed: &[u8; 32], grandchild: NodeId) {
    plant_node(
        fx,
        revokee_seed,
        grandchild,
        &folder_body(Vec::new()),
        &granted_read_key(fx, grandchild),
        1,
        false,
    );
}

/// Revoke over a planted stop an endpoint can cause: the wave stops, and the
/// cut is owed.
fn revoke_into_a_bounded_stop(fx: &mut GrantScenario) {
    let folder = fx.folder;
    assert_eq!(
        command_across_retries(
            fx,
            Command::Revoke {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
            }
        ),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        owed_reports(&mut fx._events),
        vec![(
            fx.folder,
            "rot-write-resolve-failed".to_owned(),
            true,
            OwedWorkClass::Availability
        )],
        "a stop an endpoint can cause waits for the bound"
    );
}

/// What sync passes reported once `stops` more of them stopped at the owed
/// cut, or once one dropped a node: the stops counted, and the drops.
struct PassRun {
    stops: usize,
    dropped: Vec<(NodeId, NodeId, DropCause)>,
}

/// Tick until `stops` passes report the cut owed, or a pass drops a node.
fn run_passes(
    world: &FakeWorld,
    engine: &Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    events: &mut EventStream,
    stops: usize,
) -> PassRun {
    let mut run = PassRun {
        stops: 0,
        dropped: Vec::new(),
    };
    for _ in 0..256 {
        if run.stops >= stops || !run.dropped.is_empty() {
            return run;
        }
        tick(world, engine, tasks);
        for event in events_so_far(events) {
            if matches!(event, Event::RotationWorkOwed { .. }) {
                run.stops += 1;
            }
            run.dropped.extend(as_drop(&event));
        }
    }
    panic!("the passes never settled");
}

/// [`run_passes`] on the scenario's own session.
fn passes(fx: &mut GrantScenario, stops: usize) -> PassRun {
    run_passes(
        &fx.world,
        &fx.engine,
        &mut fx._tasks,
        &mut fx._events,
        stops,
    )
}

/// Past the bound, a planted ref to an id with no record drops, and the cut
/// ends.
#[test]
fn a_write_revoke_drops_a_ref_to_an_id_with_no_record_past_the_bound() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let ghost = plant_a_ref_to_nothing(&fx, &revokee_seed, grandchild);
    revoke_into_a_bounded_stop(&mut fx);

    fx.world.scheduler.advance(DROP_BOUND);
    let run = passes(&mut fx, usize::MAX);

    assert_eq!(run.dropped, vec![(fx.folder, ghost, DropCause::NoRecord)]);
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

/// Past the bound, a planted node whose head block no endpoint serves drops.
#[test]
fn a_write_revoke_drops_a_node_with_no_served_head_block_past_the_bound() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    revoke_into_a_bounded_stop(&mut fx);

    fx.world.scheduler.advance(DROP_BOUND);
    let run = passes(&mut fx, usize::MAX);

    assert_eq!(
        run.dropped,
        vec![(fx.folder, grandchild, DropCause::NoHeadBlock)]
    );
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

/// A planted node at an epoch above the root's: no held seed opens it, and a
/// read rotation on another device can publish such a node, so it drops only
/// past the bound.
#[test]
fn a_write_revoke_drops_a_planted_node_sealed_above_the_roots_epoch_past_the_bound() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_node(
        &fx,
        &revokee_seed,
        grandchild,
        &folder_body(Vec::new()),
        &[0x13; 32],
        9,
        true,
    );
    revoke_into_a_bounded_stop(&mut fx);

    fx.world.scheduler.advance(DROP_BOUND);
    let run = passes(&mut fx, usize::MAX);

    assert_eq!(
        run.dropped,
        vec![(fx.folder, grandchild, DropCause::EpochAboveRoot)]
    );
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

/// The bound needs its time: passes alone do not drop a node.
#[test]
fn a_bounded_stop_holds_over_many_passes_before_its_time() {
    let mut fx = GrantScenario::new();
    let (_, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    revoke_into_a_bounded_stop(&mut fx);

    let run = passes(&mut fx, 2 * DROP_BOUND_PASSES as usize);

    assert!(run.dropped.is_empty(), "nothing drops");
    assert_eq!(
        run.stops,
        2 * DROP_BOUND_PASSES as usize,
        "the cut stays owed"
    );
}

/// The bound needs its passes: time alone does not drop a node. The revoke
/// was the first stop, so the pass after `K - 1` more stops drops it.
#[test]
fn a_bounded_stop_holds_past_its_time_until_enough_passes() {
    let mut fx = GrantScenario::new();
    let (_, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    revoke_into_a_bounded_stop(&mut fx);

    fx.world.scheduler.advance(DROP_BOUND);
    let run = passes(&mut fx, DROP_BOUND_PASSES as usize - 1);
    assert!(run.dropped.is_empty(), "nothing drops");

    let run = passes(&mut fx, usize::MAX);
    assert_eq!(run.stops, 0, "the next pass does not stop");
    assert_eq!(
        run.dropped,
        vec![(fx.folder, grandchild, DropCause::NoHeadBlock)],
        "it drops the node"
    );
}

/// The passes are the session's own: a later session past the bound's time
/// still sees the stop on `K` passes of its own before it drops.
#[test]
fn a_restart_past_the_bound_needs_its_own_passes() {
    let mut fx = GrantScenario::new();
    let (_, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    revoke_into_a_bounded_stop(&mut fx);
    let run = passes(&mut fx, DROP_BOUND_PASSES as usize);
    assert!(run.dropped.is_empty());
    let folder = fx.folder;

    let GrantScenario {
        world,
        blocks,
        owner_device,
        engine,
        _tasks,
        ..
    } = fx;
    drop((engine, _tasks));
    drop(world.scheduler.take_spawned_tasks());
    world.scheduler.advance(DROP_BOUND);
    let (engine, mut events, mut tasks) = boot_owner(&world, &blocks, &owner_device);

    let run = run_passes(
        &world,
        &engine,
        &mut tasks,
        &mut events,
        DROP_BOUND_PASSES as usize,
    );
    assert!(
        run.dropped.is_empty(),
        "the later session drops nothing before its own passes"
    );
    let run = run_passes(&world, &engine, &mut tasks, &mut events, usize::MAX);
    assert_eq!(
        run.dropped,
        vec![(folder, grandchild, DropCause::NoHeadBlock)]
    );
}

/// ADR 0065 D4: past the bound's time, the renewal walk renews the names of
/// an owed scope that its root's current write seed derives. The time is
/// durable, so the first passes of a later session renew it.
#[test]
fn the_renewal_walk_renews_an_owed_scope_past_the_bound() {
    let mut fx = GrantScenario::new();
    let recipient = recipient_identity().verifying_key().to_sec1();
    fx.world.mailbox_hub.forget_recipient(&recipient);
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the delivery is owed");
    let inner = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "inner",
    );
    let inner_before = sequence_at(&fx.world, &write_name(inner));
    let folder = fx.folder;

    let (world, mut events, _later) = restart_later_on_the_same_device(fx);

    assert_eq!(
        sequence_at(&world, &write_name(inner)),
        inner_before + 1,
        "past the bound the walk renews it"
    );
    assert_eq!(
        owed_scopes(&mut events),
        vec![folder],
        "and the work is still owed"
    );
}

/// ADR 0065 D3: past its time, an entry that held the wave on K passes drops
/// every held node, so a new ref to nothing on each pass does not hold the
/// cut for ever.
#[test]
fn a_new_ref_to_nothing_on_each_pass_does_not_hold_the_cut() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_a_ref_to_nothing(&fx, &revokee_seed, grandchild);
    let read_key = granted_read_key(&fx, grandchild);
    revoke_into_a_bounded_stop(&mut fx);
    fx.world.scheduler.advance(DROP_BOUND);

    let mut dropped = Vec::new();
    for fresh in 0..=DROP_BOUND_PASSES {
        let ghost = NodeId([0x70 + u8::try_from(fresh).expect("a small count"); 16]);
        plant_a_ref_to(&fx, &revokee_seed, grandchild, ghost, &read_key);
        let run = passes(&mut fx, 1);
        if !run.dropped.is_empty() {
            dropped = run.dropped;
            break;
        }
    }

    assert_eq!(dropped.len(), 1, "the cut ends within K + 1 passes");
    assert_eq!(dropped[0].2, DropCause::NoRecord);
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

/// ADR 0065 D3: with one endpoint down, a ref to nothing reads as no endpoint
/// that answers, but the other endpoints answered, so a new ref to nothing on
/// each pass still ends at the entry count.
#[test]
fn a_new_ref_to_nothing_on_each_pass_beside_a_down_endpoint_does_not_hold_the_cut() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_a_ref_to_nothing(&fx, &revokee_seed, grandchild);
    let read_key = granted_read_key(&fx, grandchild);
    revoke_into_a_bounded_stop(&mut fx);
    fx.world.scheduler.advance(DROP_BOUND);
    let down = fx
        .world
        .record_store
        .endpoints()
        .last()
        .cloned()
        .expect("an endpoint");
    fx.world.record_store.fail_endpoint(&down);

    let mut dropped = Vec::new();
    for fresh in 0..=DROP_BOUND_PASSES {
        let ghost = NodeId([0x70 + u8::try_from(fresh).expect("a small count"); 16]);
        plant_a_ref_to(&fx, &revokee_seed, grandchild, ghost, &read_key);
        let run = passes(&mut fx, 1);
        if !run.dropped.is_empty() {
            dropped = run.dropped;
            break;
        }
    }

    fx.world.record_store.heal_endpoint(&down);
    assert_eq!(dropped.len(), 1, "the cut ends within K + 1 passes");
    assert_eq!(dropped[0].2, DropCause::EndpointUnavailable);
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

/// A V2-only IPNS record at `ghost`'s planted name: the spec permits it with
/// no top-level value, and the record verify refuses it.
fn plant_a_v2_only_record(fx: &GrantScenario, ghost: NodeId) {
    let write_seed = kdf::write_seed(&[0x55; 32], &ghost.0);
    let signer = kdf::ipns_keypair(write_seed.as_bytes());
    let mut record = IpnsRecord::create_v2(
        &signer,
        b"/ipfs/bafkqaaa",
        1,
        0,
        "2099-01-01T00:00:00.000000000Z",
    )
    .marshal();
    assert_eq!(record[0], 0x0a, "the value field leads");
    record.drain(..2 + usize::from(record[1]));
    let name = derive_write_name(&[0x55; 32], &ghost.0);
    let parsed = IpnsRecord::unmarshal(&record).expect("a V2-only record parses");
    assert!(parsed.verify(&name).is_err());
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
}

/// ADR 0065 D3: a ref to a name where every endpoint serves a record that
/// does not verify reads as no endpoint that answers, but each endpoint
/// served bytes, so a new such ref on each pass still ends at the entry count.
#[test]
fn a_new_ref_to_an_unverifiable_record_on_each_pass_does_not_hold_the_cut() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_a_ref_to_nothing(&fx, &revokee_seed, grandchild);
    let read_key = granted_read_key(&fx, grandchild);
    revoke_into_a_bounded_stop(&mut fx);
    fx.world.scheduler.advance(DROP_BOUND);

    let mut dropped = Vec::new();
    for fresh in 0..=DROP_BOUND_PASSES {
        let ghost = NodeId([0x70 + u8::try_from(fresh).expect("a small count"); 16]);
        plant_a_ref_to(&fx, &revokee_seed, grandchild, ghost, &read_key);
        plant_a_v2_only_record(&fx, ghost);
        let run = passes(&mut fx, 1);
        if !run.dropped.is_empty() {
            dropped = run.dropped;
            break;
        }
    }

    assert_eq!(dropped.len(), 1, "the cut ends within K + 1 passes");
    assert_eq!(dropped[0].2, DropCause::EndpointUnavailable);
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

/// ADR 0065 D3: past the entry count, a node held for a cause that a revokee
/// cannot plant on a fresh id waits for its own passes.
#[test]
fn an_honest_node_no_endpoint_answers_waits_past_the_entry_count() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let honest = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "honest",
    );
    plant_a_ref_to_nothing(&fx, &revokee_seed, grandchild);
    let read_key = granted_read_key(&fx, grandchild);
    revoke_into_a_bounded_stop(&mut fx);
    fx.world.scheduler.advance(DROP_BOUND);

    for fresh in 0..DROP_BOUND_PASSES {
        let ghost = NodeId([0x70 + u8::try_from(fresh).expect("a small count"); 16]);
        plant_a_ref_to(&fx, &revokee_seed, grandchild, ghost, &read_key);
        let run = passes(&mut fx, 1);
        assert!(run.dropped.is_empty(), "the entry count is not yet K");
    }
    let honest_name = derive_write_name(&revokee_seed, &honest.0);
    fx.world.record_store.fail_get_for(honest_name.as_str());
    let run = passes(&mut fx, 1);
    assert_eq!(
        run.dropped,
        Vec::new(),
        "one pass with no endpoint answer does not drop the honest node"
    );

    fx.world.record_store.heal_get_for(honest_name.as_str());
    let run = passes(&mut fx, usize::MAX);
    assert_eq!(run.dropped.len(), 1);
    assert_eq!(run.dropped[0].2, DropCause::NoRecord);
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

/// A command run again inside one sync pass re-drives the cut, but adds no
/// pass to a node's count.
#[test]
fn command_re_drives_inside_one_pass_count_as_one_pass() {
    let mut fx = GrantScenario::new();
    let (_, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    revoke_into_a_bounded_stop(&mut fx);
    fx.world.scheduler.advance(DROP_BOUND);

    let folder = fx.folder;
    for _ in 0..DROP_BOUND_PASSES {
        let _ = command_across_retries(
            &mut fx,
            Command::Revoke {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
            },
        );
    }
    let run = passes(&mut fx, 1);

    assert_eq!(dropped_nodes(&mut fx._events), Vec::new());
    assert!(run.dropped.is_empty(), "two passes are not K");
}

/// Serve wrong bytes for the head block of the record at `name`. Returns the
/// CID and the block, to serve again.
fn break_head_block(fx: &GrantScenario, name: &IpnsName) -> (String, Vec<u8>) {
    let cid = published_head_cid(&fx.world, name).expect("the node is published");
    let block = fx.blocks.get(&cid).expect("its head block is served");
    fx.blocks
        .replace(&cid, b"not the block the record names".to_vec());
    (cid, block)
}

/// A node that resolves starts its count again: earlier faults do not carry
/// over to a fault past the entry's time.
#[test]
fn a_node_that_resolves_starts_its_count_again() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let honest = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "honest",
    );
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    revoke_into_a_bounded_stop(&mut fx);
    let honest_name = derive_write_name(&revokee_seed, &honest.0);

    for _ in 0..DROP_BOUND_PASSES {
        let (cid, block) = break_head_block(&fx, &honest_name);
        let run = passes(&mut fx, 1);
        assert!(run.dropped.is_empty());
        fx.blocks.replace(&cid, block);
    }
    let run = passes(&mut fx, 1);
    assert!(run.dropped.is_empty());

    fx.world.scheduler.advance(DROP_BOUND);
    let (cid, block) = break_head_block(&fx, &honest_name);
    let run = passes(&mut fx, 1);
    assert_eq!(
        run.dropped,
        Vec::new(),
        "the honest node has one pass since it resolved"
    );

    fx.blocks.replace(&cid, block);
    let run = passes(&mut fx, usize::MAX);
    assert_eq!(
        run.dropped,
        vec![(fx.folder, grandchild, DropCause::NoHeadBlock)]
    );
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

/// ADR 0065 D3: the bound counts each node's own passes. An entry past its
/// time meets an honest node whose head block one pass cannot fetch, and that
/// node does not drop.
#[test]
fn a_node_new_to_an_entry_past_its_time_does_not_drop_on_its_first_stop() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let honest = create_published_folder(
        &fx.world,
        &mut fx.engine,
        &mut fx._tasks,
        fx.folder,
        "honest",
    );
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    revoke_into_a_bounded_stop(&mut fx);
    fx.world.scheduler.advance(DROP_BOUND);
    let run = passes(&mut fx, DROP_BOUND_PASSES as usize - 1);
    assert!(run.dropped.is_empty());

    let cid = published_head_cid(&fx.world, &derive_write_name(&revokee_seed, &honest.0))
        .expect("the honest node is published");
    let block = fx.blocks.get(&cid).expect("its head block is served");
    fx.blocks
        .replace(&cid, b"not the block the record names".to_vec());
    let run = passes(&mut fx, 1);
    assert_eq!(
        run.dropped,
        Vec::new(),
        "the honest node holds the pass, and nothing drops"
    );

    fx.blocks.replace(&cid, block);
    let run = passes(&mut fx, usize::MAX);
    assert_eq!(
        run.dropped,
        vec![(fx.folder, grandchild, DropCause::NoHeadBlock)]
    );
    assert_revoke_finished(&mut fx, &revokee_seed, child);
}

// ---------------------------------------------------------------------------
// ADR 0068: a planted record at the scope root name
// ---------------------------------------------------------------------------

/// The revokee signs `value` at the name `signer_seed` derives for `node`, at
/// `sequence`, on every endpoint. Returns the name.
fn sign_at(
    fx: &GrantScenario,
    signer_seed: &[u8; 32],
    node: NodeId,
    value: &[u8],
    sequence: u64,
) -> IpnsName {
    let name = derive_write_name(signer_seed, &node.0);
    let record = IpnsRecord::create_v2(
        &kdf::ipns_keypair(kdf::write_seed(signer_seed, &node.0).as_bytes()),
        value,
        sequence,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in fx.world.record_store.endpoints() {
        fx.world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
    name
}

/// The revokee plants a record the gate refuses at the scope root name its
/// seed derives, at `sequence`: a folder envelope with no grant section.
/// Returns the name.
fn plant_root_at(fx: &GrantScenario, revokee_seed: &[u8; 32], sequence: u64) -> IpnsName {
    plant_root_served_at(fx, revokee_seed, fx.folder, sequence, true)
}

/// [`plant_root_at`] at the scope root `node`, with a head block that no
/// endpoint serves when `served` is false.
fn plant_root_served_at(
    fx: &GrantScenario,
    revokee_seed: &[u8; 32],
    node: NodeId,
    sequence: u64,
    served: bool,
) -> IpnsName {
    let planted = author_child_envelope(EnvelopeAuthoring {
        node_id: node.0,
        scope_id: node.0,
        epoch: 1,
        read_key: &[0x13; 32],
        nonce: &[0x5f; 24],
        body: &folder_body(Vec::new()),
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the planted root seals");
    if served {
        fx.blocks.put(planted.block.clone());
    }
    sign_at(
        fx,
        revokee_seed,
        node,
        format!("/ipfs/{}", planted.cid).as_bytes(),
        sequence,
    )
}

/// The revokee plants the honest root, with its grant section, under a body
/// that leaves no room for a re-seal, at `sequence`.
fn plant_unresealable_root_at(fx: &GrantScenario, revokee_seed: &[u8; 32], sequence: u64) {
    let name = derive_write_name(revokee_seed, &fx.folder.0);
    let head = published_head(&fx.world, &fx.blocks, &name).expect("the honest root");
    let mut envelope = decode_envelope(&head).expect("the head decodes");
    let pad = cipherbox_core::seal::MAX_BLOCK_BYTES - head.len() - 64;
    envelope.unknown = envelope
        .unknown
        .entries()
        .iter()
        .cloned()
        .chain(padding(pad).entries().iter().cloned())
        .collect();
    let block = encode_envelope(&envelope).expect("the plant encodes");
    assert!(block.len() <= cipherbox_core::seal::MAX_BLOCK_BYTES);
    let cid = fx.blocks.put(block);
    sign_at(
        fx,
        revokee_seed,
        fx.folder,
        format!("/ipfs/{cid}").as_bytes(),
        sequence,
    );
}

/// A revoke of the write grantee, across the retries of its bounded steps.
fn revoke_the_recipient(fx: &mut GrantScenario) -> Result<CommandOutcome, EngineError> {
    let folder = fx.folder;
    command_across_retries(
        fx,
        Command::Revoke {
            node: folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
        },
    )
}

/// A revoke of the bystander's read grant, across the retries of its bounded
/// steps.
fn revoke_the_bystander(fx: &mut GrantScenario) -> Result<CommandOutcome, EngineError> {
    let folder = fx.folder;
    command_across_retries(
        fx,
        Command::Revoke {
            node: folder,
            recipient_identity_public_key: bystander_identity(),
        },
    )
}

/// A downgrade of the write grantee to read, across the retries of its
/// bounded steps.
fn downgrade_the_recipient(fx: &mut GrantScenario) -> Result<CommandOutcome, EngineError> {
    let folder = fx.folder;
    command_across_retries(
        fx,
        Command::ChangePermission {
            node: folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        },
    )
}

/// Revoke the write grantee of `node` while its scope pointer refuses every
/// publish, so the wave is owed, then heal the pointer.
fn owe_the_wave(fx: &mut GrantScenario, node: NodeId) {
    let pointer = scope_pointer_name(kdf::owner_pointer_seed(&SECRET).as_bytes(), &node.0);
    fx.world.record_store.fail_put_for(pointer.as_str());
    assert_eq!(
        command_across_retries(
            fx,
            Command::Revoke {
                node,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
            }
        ),
        Ok(CommandOutcome::Done)
    );
    fx.world.record_store.heal_put_for(pointer.as_str());
}

/// The abuse events in `events` that report the scope root refused at
/// `sequence`.
fn root_refusals(fx: &GrantScenario, events: &[Event], sequence: u64) -> usize {
    let scope = hex_lower(&fx.folder.0);
    let refused = format!("refused at sequence {sequence}");
    events
        .iter()
        .filter(|event| {
            matches!(event, Event::AttributableAbuse { description }
                if description.contains(&scope) && description.contains(&refused))
        })
        .count()
}

/// The cut moved the root to a name the revokee's seed does not derive, and
/// the moved root gives the revokee no row and no blob.
fn assert_the_revokee_is_cut(fx: &GrantScenario, revokee_seed: &[u8; 32]) {
    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(derive_write_name(revokee_seed, &fx.folder.0), moved);
    assert_eq!(
        fx.committed_permission(&moved),
        None,
        "no row for the revokee"
    );
    assert_eq!(
        fx.granted_blob_carries_write_seed(&moved),
        None,
        "and no blob"
    );
}

/// ADR 0068 D1 and D3: the revokee plants a record the gate refuses at the
/// root name before the revoke. The revoke reads the root from its last copy,
/// moves the root first, cuts the read plane at the moved root, and
/// publishes nothing more at the old name. The refusal is a trust event.
#[test]
fn a_write_revoke_runs_on_the_last_copy_of_a_planted_root() {
    let mut fx = GrantScenario::new();
    let (child, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let old_root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    assert_eq!(plant_root_at(&fx, &revokee_seed, sequence), old_root);
    let planted = published_value(&fx.world, &old_root);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let events = events_so_far(&mut fx._events);
    assert!(
        root_refusals(&fx, &events, sequence) > 0,
        "the refusal is reported"
    );
    assert_revoke_finished(&mut fx, &revokee_seed, child);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
    let moved = fx.granted_scope_repoint().current_root;
    let head = published_head(&fx.world, &fx.blocks, &moved).expect("the moved root");
    assert_eq!(
        decode_envelope(&head).expect("the head decodes").epoch,
        2,
        "the read cut ran at the moved root"
    );
    assert_eq!(
        published_value(&fx.world, &old_root),
        planted,
        "nothing publishes at the old root name"
    );
}

/// A signed owner blob with another seed is refused after restart. The cut
/// moves the root and drops the old copy's whole grant set (ADR 0068 D3, D5).
#[test]
fn a_restarted_owner_cuts_a_disagreeing_seed_from_its_durable_copy() {
    use cipherbox_core::seal::{OverrideSeedPayload, STRUCT_TAG_OWNER_BLOB, seal_owner_blob};
    for sequence_offset in [0, 1, u64::MAX] {
        let mut fx = GrantScenario::new();
        let (child, _, writer_seed) = write_granted_nested_subtree(&mut fx);
        assert_eq!(
            fx.grant_bystander(Permission::Read),
            Ok(CommandOutcome::Done)
        );
        let name = fx.granted_scope_repoint().current_root;
        for _ in 0..2 {
            tick(&fx.world, &fx.engine, &mut fx._tasks);
        }
        let honest_value = published_value(&fx.world, &name);
        let honest_cid = std::str::from_utf8(&honest_value)
            .unwrap()
            .strip_prefix("/ipfs/")
            .unwrap();
        let head = published_head(&fx.world, &fx.blocks, &name).unwrap();
        let mut envelope = decode_envelope(&head).unwrap();
        let mut section = decode_grant_section(grant_section_bytes(&envelope).unwrap()).unwrap();
        let blob = seal_owner_blob(
            &kdf::enc_subkey(&SECRET).public(),
            &[0x99; 32],
            &AadContext {
                v: envelope.v,
                id: envelope.id,
                scope: envelope.scope,
                epoch: envelope.epoch,
                struct_tag: STRUCT_TAG_OWNER_BLOB,
            },
            &OverrideSeedPayload::new([0x98; 32], envelope.epoch),
        )
        .unwrap();
        let (shared, _) = cipherbox_engine::grants::recipient_self_location(
            &kdf::enc_subkey(&RECIPIENT_SECRET),
            &kdf::enc_subkey(&SECRET).public(),
            name.as_str().as_bytes(),
        )
        .unwrap();
        let writer = kdf::pseudonym_sign(shared.as_bytes(), &fx.folder.0);
        section.owner_blob.enc = blob.enc;
        section.owner_blob.ciphertext = blob.ciphertext;
        cipherbox_engine::testkit::resign_section(
            &mut section,
            fx.folder.0,
            envelope.epoch,
            &writer,
        );
        set_grant_section(&mut envelope, encode_grant_section(&section).unwrap());
        let cid = fx.blocks.put(encode_envelope(&envelope).unwrap());
        let sequence = sequence_at(&fx.world, &name).saturating_add(sequence_offset);
        sign_at(
            &fx,
            &writer_seed,
            fx.folder,
            format!("/ipfs/{cid}").as_bytes(),
            sequence,
        );
        let planted = published_value(&fx.world, &name);
        fx.blocks.fail_block(honest_cid);
        block_on(fx.owner_device.snapshot_cache.clear()).unwrap();
        restart_owner(&mut fx);
        assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));
        let events = events_so_far(&mut fx._events);
        assert!(root_refusals(&fx, &events, sequence) > 0);
        assert_revoke_finished(&mut fx, &writer_seed, child);
        let moved = fx.granted_scope_repoint().current_root;
        assert_ne!(moved, name);
        assert_no_grant_at(&fx, &moved);
        assert_eq!(published_value(&fx.world, &name), planted);
    }
}

#[test]
fn deleting_a_folder_removes_its_previous_scope_copy() {
    delete_with_previous_scope_copy(false);
}

#[test]
fn a_stale_delete_keeps_the_live_folders_scope_copy() {
    delete_with_previous_scope_copy(true);
}

/// The staged key and sealed bytes of `fx.folder`'s durable scope copy.
fn scope_copy(fx: &GrantScenario) -> Option<(Vec<u8>, Vec<u8>)> {
    use cipherbox_core::seal::{OwnerLocalKind, decode_owner_seed_record, open_owner_local};
    block_on(fx.owner_device.staging_store.staged_keys())
        .unwrap()
        .into_iter()
        .find_map(|key| {
            let blob = block_on(fx.owner_device.staging_store.staged_bytes(&key)).unwrap()?;
            let record = open_owner_local(
                &kdf::enc_subkey(&SECRET),
                OwnerLocalKind::OwnerSeedCache,
                &blob,
            )
            .and_then(|body| decode_owner_seed_record(&body))
            .ok()?;
            (record.scope_id == fx.folder.0).then_some((key, blob))
        })
}

/// A granted folder, read twice, with the durable copy its confirmed scope saved.
fn granted_with_scope_copy() -> (GrantScenario, Vec<u8>, Vec<u8>) {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    let (key, blob) = scope_copy(&fx).expect("the confirmed scope has a durable copy");
    (fx, key, blob)
}

/// A plain folder whose id holds the durable copy that a granted run of the
/// same scenario saved.
fn folder_with_scope_copy() -> (GrantScenario, Vec<u8>, Vec<u8>) {
    let (previous, key, blob) = granted_with_scope_copy();
    let fx = GrantScenario::new();
    assert_eq!(previous.folder, fx.folder);
    drop(previous);
    block_on(fx.owner_device.staging_store.put_staged_bytes(&key, &blob)).unwrap();
    (fx, key, blob)
}

#[test]
fn a_store_fault_on_the_scope_copy_does_not_stop_the_delete() {
    let (mut fx, _, _) = folder_with_scope_copy();
    fx.owner_device
        .staging_store
        .inner()
        .fail_staged_removals_under(cipherbox_engine::grants::OWNER_SEED_CACHE_PREFIX);
    block_on(fx.engine.command(Command::Delete { node: fx.folder })).unwrap();
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    fx.world.scheduler.advance(KEPT_OP_BOUND);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.owner_device.staging_store.queued_ops())
            .unwrap()
            .is_empty()
    );
    assert!(
        !block_on(fx.engine.view())
            .unwrap()
            .children(ROOT)
            .iter()
            .any(|child| child.id == fx.folder)
    );
}

/// The copy goes before the publish that completes the delete. A live scope
/// that lost its copy in that window gets it again at its next confirmed read.
#[test]
fn a_delete_drops_the_copy_before_its_publish_and_a_live_scope_saves_it_again() {
    let (mut fx, key, _) = folder_with_scope_copy();
    let root = write_name(ROOT);
    let linked = published_value(&fx.world, &root);
    fx.world.record_store.fail_put_for(root.as_str());
    block_on(fx.engine.command(Command::Delete { node: fx.folder })).unwrap();
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.owner_device.staging_store.staged_bytes(&key))
            .unwrap()
            .is_none()
    );
    assert_eq!(published_value(&fx.world, &root), linked);

    let (mut fx, key, _) = granted_with_scope_copy();
    block_on(fx.owner_device.staging_store.remove_staged_bytes(&key)).unwrap();
    restart_owner(&mut fx);
    for _ in 0..2 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert!(scope_copy(&fx).is_some());
}

fn delete_with_previous_scope_copy(concurrent: bool) {
    let (mut fx, key, blob) = folder_with_scope_copy();
    if concurrent {
        use cipherbox_engine::sync::{Op, RecordSeal, stage_op};
        let current = sequence_at(&fx.world, &write_name(fx.folder));
        let stale = Op::delete(
            fx.folder,
            sequence_at(&fx.world, &write_name(ROOT)),
            UnixMillis(0),
            current - 1,
            true,
        );
        block_on(stage_op(
            &fx.owner_device.staging_store,
            RecordSeal {
                owner_enc_secret: &kdf::enc_subkey(&SECRET),
                ephemeral_scalar: Zeroizing::new([0x79; 32]),
            },
            &stale,
        ))
        .unwrap();
    } else {
        block_on(fx.engine.command(Command::Delete { node: fx.folder })).unwrap();
    }
    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    fx.world.scheduler.advance(KEPT_OP_BOUND);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(
        block_on(fx.owner_device.staging_store.queued_ops())
            .unwrap()
            .is_empty()
    );
    let held = block_on(fx.owner_device.staging_store.staged_bytes(&key)).unwrap();
    if concurrent {
        assert!(
            block_on(fx.engine.view())
                .unwrap()
                .children(ROOT)
                .iter()
                .any(|child| child.id == fx.folder)
        );
        assert!(held.as_ref().is_some_and(|held| held == &blob));
    } else {
        assert!(held.is_none());
    }
}

/// ADR 0068 D3: a plant at the sequence ceiling blocks each publish at the
/// old root name, and the revoke publishes none there.
#[test]
fn a_write_revoke_moves_a_root_planted_at_the_sequence_ceiling() {
    let mut fx = GrantScenario::new();
    let (child, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_root_at(&fx, &revokee_seed, u64::MAX);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    assert_revoke_finished(&mut fx, &revokee_seed, child);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
}

/// ADR 0068 D1 and D3: a plant that leaves no room for a re-seal, at the
/// sequence ceiling, also runs on the last copy and moves the root first.
#[test]
fn a_write_revoke_moves_an_unresealable_root_planted_at_the_sequence_ceiling() {
    let mut fx = GrantScenario::new();
    let (child, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_unresealable_root_at(&fx, &revokee_seed, u64::MAX);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let events = events_so_far(&mut fx._events);
    assert!(root_refusals(&fx, &events, u64::MAX) > 0);
    assert_revoke_finished(&mut fx, &revokee_seed, child);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
}

/// ADR 0068 D1: the revokee replays the root from before an earlier cut at a
/// higher sequence. The gate refuses it below the cut-epoch floor, and the
/// revoke runs on the last copy.
#[test]
fn a_write_revoke_reads_past_a_replayed_pre_cut_root() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let old_root = fx.granted_scope_repoint().current_root;
    let pre_cut = published_value(&fx.world, &old_root);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let folder = fx.folder;
    assert_eq!(
        revoke_the_bystander(&mut fx),
        Ok(CommandOutcome::Done),
        "a read revoke cuts the set at the same root name"
    );
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    sign_at(&fx, &revokee_seed, folder, &pre_cut, sequence);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let events = events_so_far(&mut fx._events);
    assert!(root_refusals(&fx, &events, sequence) > 0);
    assert_eq!(fx.granted_scope_repoint().write_epoch, 3);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
}

/// ADR 0068 D3 and D5: a downgrade over a planted root publishes no cut set
/// at the old name. The wave re-mints a set with no row at the moved root.
#[test]
fn a_downgrade_over_a_planted_root_keeps_no_grant_row() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let old_root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    plant_root_at(&fx, &revokee_seed, sequence);
    let planted = published_value(&fx.world, &old_root);
    let folder = fx.folder;

    assert_eq!(downgrade_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let moved = fx.granted_scope_repoint();
    assert_eq!(moved.write_epoch, 3, "the downgrade moved the root");
    assert_ne!(
        derive_write_name(&revokee_seed, &folder.0),
        moved.current_root
    );
    assert_no_grant_at(&fx, &moved.current_root);
    assert_eq!(published_value(&fx.world, &old_root), planted);
}

/// ADR 0068 D3 and D5: a read revoke over a planted root keeps no row, so it
/// also cuts the write grantee that planted it, and the wave moves the root.
/// The trust event names the refused record.
#[test]
fn a_read_revoke_over_a_planted_root_also_cuts_the_write_grantee() {
    let mut fx = GrantScenario::new();
    let (_, _, writer_seed) = write_granted_nested_subtree(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let old_root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    plant_root_at(&fx, &writer_seed, sequence);
    let planted = published_value(&fx.world, &old_root);

    assert_eq!(revoke_the_bystander(&mut fx), Ok(CommandOutcome::Done));

    let events = events_so_far(&mut fx._events);
    assert!(root_refusals(&fx, &events, sequence) > 0);
    assert_the_revokee_is_cut(&fx, &writer_seed);
    assert_no_grant_at(&fx, &fx.granted_scope_repoint().current_root);
    assert_eq!(published_value(&fx.world, &old_root), planted);
}

/// ADR 0068 D5: the last copy cannot prove that its grant set is current, so
/// a revoke over a planted root keeps no row of another grantee and seals the
/// fresh seed to nobody. The owner then shares again over the moved root.
#[test]
fn a_revoke_over_a_planted_root_keeps_no_other_grant_row() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let old_root = fx.granted_scope_repoint().current_root;
    plant_root_at(&fx, &revokee_seed, sequence_at(&fx.world, &old_root) + 1);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(derive_write_name(&revokee_seed, &fx.folder.0), moved);
    assert_no_grant_at(&fx, &moved);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done),
        "the owner shares again over the root the cut published"
    );
    let shared = fx.granted_scope_repoint().current_root;
    assert_eq!(committed_rows(&fx, &shared), 1);
    assert_eq!(opened_blobs(&fx, &shared, &BYSTANDER_SECRET), 1);
    assert_eq!(opened_blobs(&fx, &shared, &RECIPIENT_SECRET), 0);
}

/// ADR 0068 D5: a revoke over a root the gate admits keeps the other rows.
#[test]
fn a_revoke_over_a_gated_root_keeps_the_other_grant_rows() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let moved = fx.granted_scope_repoint().current_root;
    assert_eq!(committed_rows(&fx, &moved), 1, "the bystander row stays");
    assert_eq!(opened_blobs(&fx, &moved, &BYSTANDER_SECRET), 1);
    assert_eq!(opened_blobs(&fx, &moved, &RECIPIENT_SECRET), 0);
}

/// The rows the grant-set commitment at `name` commits.
fn committed_rows(fx: &GrantScenario, name: &IpnsName) -> usize {
    published_grant_section_at(&fx.world, &fx.blocks, name)
        .expect("a scope root answers at the name")
        .commitment
        .entries
        .len()
}

/// The grant blobs at `name` that the holder of `secret` opens.
fn opened_blobs(fx: &GrantScenario, name: &IpnsName, secret: &[u8; 32]) -> usize {
    let section =
        published_grant_section_at(&fx.world, &fx.blocks, name).expect("a scope root answers");
    let enc = kdf::enc_subkey(secret);
    section
        .grant_blobs
        .iter()
        .filter(|blob| {
            (0..=section.commitment.cut_epoch + 4).any(|epoch| {
                open_grant_blob(
                    &enc,
                    &blob.enc,
                    &AadContext {
                        v: ENVELOPE_V,
                        id: fx.folder.0,
                        scope: fx.folder.0,
                        epoch,
                        struct_tag: STRUCT_TAG_GRANT_BLOB,
                    },
                    &blob.ciphertext,
                )
                .is_ok()
            })
        })
        .count()
}

/// The scope root at `name` commits no row and carries no grant blob that the
/// recipient or the bystander opens.
fn assert_no_grant_at(fx: &GrantScenario, name: &IpnsName) {
    assert_eq!(committed_rows(fx, name), 0, "no committed row");
    let section =
        published_grant_section_at(&fx.world, &fx.blocks, name).expect("a scope root answers");
    assert!(section.grant_blobs.is_empty(), "no grant blob");
    for secret in [&RECIPIENT_SECRET, &BYSTANDER_SECRET] {
        assert_eq!(opened_blobs(fx, name, secret), 0);
    }
}

/// ADR 0068 D1 and D4: the read cut lands, the wave stops at its re-point,
/// and the revokee then plants at the root. The owner runs the revoke again,
/// and its re-drive reads the cut set from the last copy and moves the root.
#[test]
fn a_redrive_reads_a_planted_root_from_its_last_copy() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let folder = fx.folder;
    owe_the_wave(&mut fx, folder);
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the wave is owed");
    let old_root = derive_write_name(&revokee_seed, &fx.folder.0);
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    plant_root_at(&fx, &revokee_seed, sequence);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let events = events_so_far(&mut fx._events);
    assert!(root_refusals(&fx, &events, sequence) > 0);
    assert!(!owes_any(&events), "no work stays owed");
    assert_eq!(fx.granted_scope_repoint().write_epoch, 3);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
}

/// ADR 0068 D3 and D4: after a fallback the wave moves the root first, and
/// the read cut at the moved root stops. The entry stays owed, and the next
/// re-drive finishes the cut.
#[test]
fn a_read_cut_that_stops_at_the_moved_root_finishes_in_the_redrive() {
    let mut fx = GrantScenario::new();
    let (child, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let old_root = fx.granted_scope_repoint().current_root;
    plant_root_at(&fx, &revokee_seed, sequence_at(&fx.world, &old_root) + 1);
    let read_epoch_floor = floor_label(&fx.folder.0);
    fx.owner_device
        .floor_store
        .fail_floor_raises_for(&read_epoch_floor);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the read cut is owed");
    assert_ne!(
        fx.granted_scope_repoint().current_root,
        old_root,
        "the wave moved the root first"
    );
    fx.owner_device.floor_store.heal_floors();
    let _ = events_so_far(&mut fx._events);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    assert!(
        !owes_any(&events_so_far(&mut fx._events)),
        "no work stays owed"
    );
    assert_revoke_finished(&mut fx, &revokee_seed, child);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
}

/// Whether `events` report work owed at any scope.
fn owes_any(events: &[Event]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, Event::RotationWorkOwed { .. }))
}

/// Whether `events` drop owed work at `scope`. The re-drive cannot tell the
/// rows the owner asked to remove from the others, so its rows-dropped notice
/// is not counted.
fn drops_owed_work(events: &[Event], scope: NodeId) -> bool {
    events.iter().any(|event| {
        matches!(event, Event::RotationWorkAbandoned { scope_root, detail }
            if *scope_root == scope && detail != "owed-grants-dropped-from-last-copy")
    })
}

/// The events that report work owed at `scope`, or abandoned there.
fn owed_or_abandoned(events: &[Event], scope: NodeId) -> (bool, bool) {
    let owed = events.iter().any(
        |event| matches!(event, Event::RotationWorkOwed { scope_root, .. } if *scope_root == scope),
    );
    let abandoned = events.iter().any(|event| {
        matches!(event, Event::RotationWorkAbandoned { scope_root, .. } if *scope_root == scope)
    });
    (owed, abandoned)
}

/// ADR 0068 D4 and D5: the revokee plants at the root before the revoke, and
/// the wave that runs first stops. Each sync pass builds the cut of every row
/// again from the last copy, so the entry stays owed within the bound, and
/// past it the unserved node drops and the cut lands with no command.
#[test]
fn a_first_wave_that_stops_leaves_a_cut_the_redrive_finishes_past_the_bound() {
    let mut fx = GrantScenario::new();
    let (_, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    let old_root = fx.granted_scope_repoint().current_root;
    plant_root_at(&fx, &revokee_seed, sequence_at(&fx.world, &old_root) + 1);

    let _ = revoke_the_recipient(&mut fx);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let events = events_so_far(&mut fx._events);
    assert!(
        owed_or_abandoned(&events, fx.folder).0 && !drops_owed_work(&events, fx.folder),
        "the cut is owed, and the re-drive keeps it"
    );

    let mut events = Vec::new();
    for _ in 0..2 * DROP_BOUND_PASSES + 2 {
        fx.world.scheduler.advance(DROP_BOUND / 4);
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        events.extend(events_so_far(&mut fx._events));
    }
    assert!(
        events
            .iter()
            .filter_map(as_drop)
            .any(|drop| drop == (fx.folder, grandchild, DropCause::NoHeadBlock)),
        "the node drops past the bound"
    );
    assert!(!drops_owed_work(&events, fx.folder), "nothing is dropped");
    assert_the_revokee_is_cut(&fx, &revokee_seed);
    assert_no_grant_at(&fx, &fx.granted_scope_repoint().current_root);
}

/// ADR 0068 D4 as amended, with ADR 0065 D3: a root plant and an interior node
/// whose head block no endpoint serves. Each run of the revoke again keeps the
/// first stop of the entry and the passes the node held, so the node drops
/// past the bound and the revoke ends.
#[test]
fn a_rerun_keeps_the_first_stop_so_an_unserved_node_drops_past_the_bound() {
    let mut fx = GrantScenario::new();
    let (child, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    let old_root = fx.granted_scope_repoint().current_root;
    plant_root_at(&fx, &revokee_seed, sequence_at(&fx.world, &old_root) + 1);

    let _ = revoke_the_recipient(&mut fx);
    let mut events = Vec::new();
    for _ in 0..2 * DROP_BOUND_PASSES + 2 {
        fx.world.scheduler.advance(DROP_BOUND / 4);
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        let _ = revoke_the_recipient(&mut fx);
        events.extend(events_so_far(&mut fx._events));
    }

    assert!(
        events
            .iter()
            .filter_map(as_drop)
            .any(|drop| drop == (fx.folder, grandchild, DropCause::NoHeadBlock)),
        "the node drops past the bound"
    );
    assert!(
        !drops_owed_work(&events, fx.folder),
        "no entry is abandoned"
    );
    assert_eq!(fx.granted_scope_repoint().write_epoch, 3);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
    assert_ne!(
        derive_write_name(&revokee_seed, &child.0),
        moved_child_name(&fx, "child"),
        "the moved root names the child at a new name"
    );
}

/// ADR 0068 D1 as amended: the revokee publishes a root record whose head
/// block every block source answers it does not hold, before the first
/// revoke. The command read runs on the last copy at once, and the revoke ends
/// in one pass.
#[test]
fn a_revoke_over_a_root_whose_head_block_no_endpoint_serves_ends_in_one_pass() {
    let mut fx = GrantScenario::new();
    let (child, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let old_root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    plant_root_served_at(&fx, &revokee_seed, fx.folder, sequence, false);

    let outcome = block_on(fx.engine.command(Command::Revoke {
        node: fx.folder,
        recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
    }));

    assert_eq!(outcome, Ok(CommandOutcome::Done));
    let events = events_so_far(&mut fx._events);
    assert!(
        root_refusals(&fx, &events, sequence) > 0,
        "the drop is reported"
    );
    assert_eq!(owed_or_abandoned(&events, fx.folder), (false, false));
    assert_revoke_finished(&mut fx, &revokee_seed, child);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
}

/// Assert that a revoke stopped as unavailable at the honest root at
/// `sequence`, with no fallback, no trust event, and nothing owed.
fn assert_unavailable_with_no_fallback(
    fx: &mut GrantScenario,
    outcome: Result<CommandOutcome, EngineError>,
    root: &IpnsName,
    sequence: u64,
) {
    assert!(
        matches!(outcome, Err(EngineError::Seam { .. })),
        "the revoke is unavailable: {outcome:?}"
    );
    let events = events_so_far(&mut fx._events);
    assert_eq!(root_refusals(fx, &events, sequence), 0, "no trust event");
    assert_eq!(owed_or_abandoned(&events, fx.folder), (false, false));
    assert_eq!(
        &fx.granted_scope_repoint().current_root,
        root,
        "the root did not move"
    );
}

/// ADR 0068 D1: a gateway timeout on the root head block is a transport
/// fault, so the command does not fall back.
#[test]
fn a_revoke_over_a_root_head_block_the_gateway_times_out_on_does_not_fall_back() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    let root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &root);
    let cid = published_head_cid(&fx.world, &root).expect("the root is published");
    fx.blocks.fail_block(&cid);
    let _ = events_so_far(&mut fx._events);

    let outcome = revoke_the_recipient(&mut fx);

    assert_unavailable_with_no_fallback(&mut fx, outcome, &root, sequence);
}

/// ADR 0068 D1 with ADR 0071 D1: the revokee publishes a root whose head
/// block no block source holds, and one record endpoint fails. The revoke is
/// unavailable, with no fallback and no trust event.
#[test]
fn a_revoke_over_an_absent_root_head_block_while_an_endpoint_fails_is_unavailable() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &root) + 1;
    plant_root_served_at(&fx, &revokee_seed, fx.folder, sequence, false);
    let failing = fx.world.record_store.endpoints()[1].clone();
    fx.world.record_store.fail_endpoint(&failing);
    let _ = events_so_far(&mut fx._events);

    let outcome = revoke_the_recipient(&mut fx);

    assert_unavailable_with_no_fallback(&mut fx, outcome, &root, sequence);
}

/// ADR 0068 D1: another owner device moved the root on, and the snapshot
/// cache write of the new record fails. A local fault, so the command does
/// not fall back.
#[test]
fn a_revoke_whose_cache_write_fails_does_not_fall_back() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    let (mut second, _second_events, mut second_tasks) = fx.second_owner_device();
    create_published_folder(
        &fx.world,
        &mut second,
        &mut second_tasks,
        fx.folder,
        "newer",
    );
    let root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &root);
    fx.owner_device.snapshot_cache.fail_puts();
    let _ = events_so_far(&mut fx._events);

    let outcome = revoke_the_recipient(&mut fx);

    assert_unavailable_with_no_fallback(&mut fx, outcome, &root, sequence);
}

/// ADR 0068 D1 as amended: every endpoint answers with the root below the
/// sequence floor. The command runs on the last copy at once.
#[test]
fn a_revoke_over_a_root_below_the_sequence_floor_falls_back_at_once() {
    let mut fx = GrantScenario::new();
    let (child, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &root) - 1;
    let value = published_value(&fx.world, &root);
    sign_at(&fx, &revokee_seed, fx.folder, &value, sequence);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let events = events_so_far(&mut fx._events);
    assert!(
        root_refusals(&fx, &events, sequence) > 0,
        "the drop is reported"
    );
    assert_revoke_finished(&mut fx, &revokee_seed, child);
    assert_the_revokee_is_cut(&fx, &revokee_seed);
}

/// The cost of ADR 0068 D1 as amended: another owner device publishes the
/// scope root, and no endpoint serves its head block yet. A revoke on this
/// device runs on its older copy, so the moved root drops the child that the
/// other device added, and the trust event reports it.
#[test]
fn a_revoke_over_honest_lag_runs_on_the_older_copy() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let (mut second, _second_events, mut second_tasks) = fx.second_owner_device();
    create_published_folder(
        &fx.world,
        &mut second,
        &mut second_tasks,
        fx.folder,
        "newer",
    );
    let root = fx.granted_scope_repoint().current_root;
    let sequence = sequence_at(&fx.world, &root);
    let cid = published_head_cid(&fx.world, &root).expect("the newer root is published");
    fx.blocks
        .replace(&cid, b"not the block the record names".to_vec());

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let events = events_so_far(&mut fx._events);
    assert!(
        root_refusals(&fx, &events, sequence) > 0,
        "the drop is reported"
    );
    assert_the_revokee_is_cut(&fx, &revokee_seed);
    let moved = fx.granted_scope_repoint().current_root;
    assert!(
        moved_children(&fx, &moved, fx.folder)
            .iter()
            .all(|child| child.name != "newer"),
        "the moved root does not carry the child of the newer root"
    );
}

/// Write-grant `node` to the recipient, revoke it with the scope pointer
/// publish failing so the wave is owed, then plant at the root. Returns the
/// revokee's write scope seed of `node`.
fn owe_a_wave_then_plant_the_root(fx: &mut GrantScenario, node: NodeId) -> [u8; 32] {
    assert_eq!(
        block_on(fx.engine.command(Command::Grant {
            node,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Write,
            grantee_name: None,
        })),
        Ok(CommandOutcome::Done)
    );
    let root = scope_repoint(&fx.world, &node.0).current_root;
    let section =
        published_grant_section_at(&fx.world, &fx.blocks, &root).expect("the granted root");
    let revokee_seed = grantee_write_scope_seed(&section, &root, &node.0, 1);
    owe_the_wave(fx, node);
    let sequence = sequence_at(&fx.world, &root) + 1;
    plant_root_served_at(fx, &revokee_seed, node, sequence, true);
    revokee_seed
}

/// ADR 0068 as amended: two scope roots with an owed wave each, and a root
/// plant at each. The walk refuses both, and one sync pass re-drives both.
#[test]
fn a_sync_pass_redrives_two_owed_cuts_while_both_roots_are_planted() {
    let mut fx = GrantScenario::new();
    let other = create_published_folder(&fx.world, &mut fx.engine, &mut fx._tasks, ROOT, "other");
    let folder = fx.folder;
    let seeds = [
        (folder, owe_a_wave_then_plant_the_root(&mut fx, folder)),
        (other, owe_a_wave_then_plant_the_root(&mut fx, other)),
    ];

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    for (node, revokee_seed) in seeds {
        let moved = scope_repoint(&fx.world, &node.0);
        assert_eq!(moved.write_epoch, 3, "the wave of {node:?} landed");
        assert_ne!(
            derive_write_name(&revokee_seed, &node.0),
            moved.current_root
        );
    }
}

/// ADR 0068 D4 as amended: a revoke of another grantee over an entry whose
/// cut never landed replaces that entry, and the host learns that the first
/// cut went.
#[test]
fn a_different_cut_over_a_cut_that_never_landed_reports_the_replaced_work() {
    let mut fx = GrantScenario::new();
    let (_, grandchild, revokee_seed) = write_granted_nested_subtree(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    plant_an_unserved_head(&fx, &revokee_seed, grandchild);
    let old_root = fx.granted_scope_repoint().current_root;
    let honest = published_value(&fx.world, &old_root);
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    plant_root_at(&fx, &revokee_seed, sequence);
    let _ = revoke_the_recipient(&mut fx);
    // The root the gate admits stands again, so the next cut keeps its rows.
    sign_at(&fx, &revokee_seed, fx.folder, &honest, sequence + 1);
    let _ = events_so_far(&mut fx._events);

    let _ = revoke_the_bystander(&mut fx);

    assert_eq!(
        abandoned(&mut fx._events),
        vec![(fx.folder, "owed-cut-replaced".to_owned())]
    );
}

/// ADR 0068 D4 as amended: an entry whose cut never landed does not hold a
/// link expiry. The sweep cuts the expired link over it, and the host learns
/// that the cut that never landed went.
#[test]
fn the_sweep_cuts_an_expired_link_over_a_cut_that_never_landed() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let deadline = fx.an_hour_from_now();
    fx.mint_link_until(Permission::Read, deadline);
    let root = fx.granted_scope_repoint().current_root;
    let mut cut_epoch_floor = fx.folder.0.to_vec();
    cut_epoch_floor.extend_from_slice(b"/cut-epoch");
    // The PUT goes out and fails, and the read after it does not answer, so
    // the cut is unknown and its entry stands.
    fx.world.record_store.fail_put_for(root.as_str());
    fx.owner_device
        .floor_store
        .fail_epoch_floor_reads_after(&floor_label(&cut_epoch_floor), 4);
    assert!(
        downgrade_the_recipient(&mut fx).is_err(),
        "the cut set did not publish"
    );
    fx.owner_device.floor_store.heal_floors();
    fx.world.record_store.heal_put_for(root.as_str());
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    let _ = events_so_far(&mut fx._events);

    fx.world
        .scheduler
        .advance_to(swept_at(&fx.engine, deadline));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(fx.link_entries(), 0, "the expired link is cut");
    assert_eq!(
        abandoned(&mut fx._events),
        vec![(fx.folder, "owed-cut-replaced".to_owned())]
    );
}

/// ADR 0068 D1 as amended: the read cut lands, the wave stops at its
/// re-point, and the revokee then publishes a root whose head block no source
/// holds. The revoke run again re-drives the cut from the last copy at once,
/// and ends in one pass.
#[test]
fn a_rerun_over_a_head_block_plant_after_the_cut_stands_ends_in_one_pass() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let folder = fx.folder;
    owe_the_wave(&mut fx, folder);
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the wave is owed");
    let old_root = derive_write_name(&revokee_seed, &fx.folder.0);
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    plant_root_served_at(&fx, &revokee_seed, fx.folder, sequence, false);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    let events = events_so_far(&mut fx._events);
    assert!(
        root_refusals(&fx, &events, sequence) > 0,
        "the drop is reported"
    );
    assert_eq!(owed_or_abandoned(&events, fx.folder), (false, false));
    assert_eq!(fx.granted_scope_repoint().write_epoch, 3, "the wave landed");
    assert_the_revokee_is_cut(&fx, &revokee_seed);
}

/// ADR 0068 as amended: the read cut lands, the wave stops at its re-point,
/// and the revokee then plants at the root. The boundary walk refuses the
/// planted root, and the sync pass still re-drives the owed wave from the last
/// copy, with no command.
#[test]
fn a_sync_pass_redrives_an_owed_cut_while_a_root_plant_stands() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    let folder = fx.folder;
    owe_the_wave(&mut fx, folder);
    assert_eq!(fx.owed_scopes(), vec![fx.folder], "the wave is owed");
    let old_root = derive_write_name(&revokee_seed, &fx.folder.0);
    let sequence = sequence_at(&fx.world, &old_root) + 1;
    plant_root_at(&fx, &revokee_seed, sequence);

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let events = events_so_far(&mut fx._events);
    assert!(root_refusals(&fx, &events, sequence) > 0);
    assert_eq!(fx.granted_scope_repoint().write_epoch, 3, "the wave landed");
    assert_the_revokee_is_cut(&fx, &revokee_seed);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(fx.owed_scopes().is_empty(), "no work stays owed");
}

// ---------------------------------------------------------------------------
// A lagging endpoint while another endpoint fails (ADR 0071)
// ---------------------------------------------------------------------------

/// A grant, then a file created under `parent` while endpoint B refuses PUTs:
/// B serves the record at `parent` one sequence below A. Returns (A, B).
fn lag_one_endpoint(fx: &mut GrantScenario, parent: NodeId) -> (EndpointId, EndpointId) {
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    let endpoints = fx.world.record_store.endpoints();
    let (a, b) = (endpoints[0].clone(), endpoints[1].clone());
    fx.world.record_store.fail_put_endpoint(&b);
    block_on(fx.engine.command(Command::Create {
        parent,
        name: "upload.bin".into(),
        kind: NodeKind::File,
    }))
    .expect("a create stages");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    fx.world.record_store.heal_put_endpoint(&b);
    let name = write_name(parent);
    assert_eq!(
        sequence_served_by(&fx.world, &b, &name) + 1,
        sequence_served_by(&fx.world, &a, &name),
        "B lags A by one sequence"
    );
    (a, b)
}

fn sequence_served_by(world: &FakeWorld, endpoint: &EndpointId, name: &IpnsName) -> u64 {
    let bytes = world
        .record_store
        .record_at(endpoint, name.as_str())
        .expect("the endpoint holds a record");
    IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(name))
        .expect("the record verifies")
        .sequence
}

fn revoke_recipient(fx: &mut GrantScenario) -> Result<CommandOutcome, EngineError> {
    fx.revoke_person(&recipient_identity().verifying_key().to_sec1())
}

/// The cached last-known-good copy and the durable sequence floor of `node`'s
/// record name on the owner device.
fn cache_and_floor(fx: &GrantScenario, node: NodeId) -> (Option<Vec<u8>>, Option<u64>) {
    let key = write_name(node);
    let key = key.as_str().as_bytes();
    (
        block_on(fx.owner_device.snapshot_cache.get(key)).expect("the cache reads"),
        block_on(floor::sequence_floor(&fx.owner_device.floor_store, key)).expect("floor read"),
    )
}

fn assert_revoke_unavailable_while_a_fails(parent_of: fn(&GrantScenario) -> NodeId) {
    assert_revoke_unavailable_while(parent_of, |store, a| store.fail_endpoint(a));
}

/// [`assert_revoke_unavailable_while_a_fails`], with A failed by `fail`.
fn assert_revoke_unavailable_while(
    parent_of: fn(&GrantScenario) -> NodeId,
    fail: fn(&InMemoryRecordStore, &EndpointId),
) {
    let mut fx = GrantScenario::new();
    let parent = parent_of(&fx);
    let (a, _) = lag_one_endpoint(&mut fx, parent);
    events_so_far(&mut fx._events);
    let before = cache_and_floor(&fx, parent);
    fail(&fx.world.record_store, &a);

    let outcome = revoke_recipient(&mut fx);
    assert!(
        matches!(outcome, Err(EngineError::Seam { .. })),
        "a below-floor pick while an endpoint fails is unavailable: {outcome:?}"
    );
    assert_eq!(abuse_events(&mut fx._events), 0, "no trust event");
    assert_eq!(cache_and_floor(&fx, parent), before, "nothing is adopted");

    fx.world.record_store.heal_endpoint(&a);
    assert_eq!(revoke_recipient(&mut fx), Ok(CommandOutcome::Done));
}

/// A 429 states nothing about the name, so it is a failed endpoint.
#[test]
fn a_revoke_over_a_lagging_granted_root_while_an_endpoint_answers_429_is_unavailable() {
    assert_revoke_unavailable_while(|fx| fx.folder, |store, a| store.answer_get_at(a, 429));
}

#[test]
fn a_revoke_over_a_lagging_granted_root_while_an_endpoint_fails_is_unavailable() {
    assert_revoke_unavailable_while_a_fails(|fx| fx.folder);
}

#[test]
fn a_revoke_over_a_lagging_vault_root_while_an_endpoint_fails_is_unavailable() {
    assert_revoke_unavailable_while_a_fails(|_| ROOT);
}

#[test]
fn a_revoke_over_a_lagging_endpoint_with_every_endpoint_up_finishes() {
    let mut fx = GrantScenario::new();
    let folder = fx.folder;
    lag_one_endpoint(&mut fx, folder);
    assert_eq!(revoke_recipient(&mut fx), Ok(CommandOutcome::Done));
}

/// What endpoint A answers while B serves the old record.
#[derive(Clone, Copy)]
enum AAnswers {
    /// A serves B's old record too.
    TheOldRecord,
    /// A answers 403: an answer, not a failed endpoint (ADR 0071 D2).
    Forbidden,
}

/// [`lag_one_endpoint`], then A answers as `answer`: every endpoint answers,
/// and the freshest record is below the floor.
fn every_endpoint_answers_below_floor(
    parent_of: fn(&GrantScenario) -> NodeId,
    answer: AAnswers,
) -> GrantScenario {
    let mut fx = GrantScenario::new();
    let parent = parent_of(&fx);
    let (a, b) = lag_one_endpoint(&mut fx, parent);
    match answer {
        AAnswers::TheOldRecord => {
            let name = write_name(parent);
            let old = fx
                .world
                .record_store
                .record_at(&b, name.as_str())
                .expect("B holds the old record");
            fx.world.record_store.seed_record(&a, name.as_str(), old);
        }
        AAnswers::Forbidden => fx.world.record_store.answer_get_at(&a, 403),
    }
    events_so_far(&mut fx._events);
    fx
}

#[test]
fn a_revoke_over_a_below_floor_record_from_every_endpoint_stays_a_trust_violation() {
    for answer in [AAnswers::TheOldRecord, AAnswers::Forbidden] {
        let mut fx = every_endpoint_answers_below_floor(|fx| fx.folder, answer);
        let outcome = revoke_recipient(&mut fx);
        assert!(
            matches!(outcome, Err(EngineError::TrustViolation { .. })),
            "every endpoint answered, so the below-floor pick is a rollback: {outcome:?}"
        );
        // The owner cut reads the root from its last copy, which sends one
        // trust event, and a read revoke keeps the stop (ADR 0068 D1, D3).
        assert_eq!(abuse_events(&mut fx._events), 1);
    }
}

#[test]
fn a_tick_read_of_a_below_floor_vault_root_from_every_endpoint_sends_one_gate_event() {
    for answer in [AAnswers::TheOldRecord, AAnswers::Forbidden] {
        let mut fx = every_endpoint_answers_below_floor(|_| ROOT, answer);
        tick(&fx.world, &fx.engine, &mut fx._tasks);
        let abuse: Vec<String> = events_so_far(&mut fx._events)
            .into_iter()
            .filter_map(|event| match event {
                Event::AttributableAbuse { description } => Some(description),
                _ => None,
            })
            .collect();
        // The vault-root resolve reports the sequence stage once; the link
        // sweep's own read of the root reports its refusal apart.
        assert_eq!(
            abuse
                .iter()
                .filter(|description| description.contains("stage [sequence]"))
                .count(),
            1,
            "{abuse:?}"
        );
    }
}

#[test]
fn a_focus_read_of_a_below_floor_granted_root_from_every_endpoint_stays_abuse() {
    let mut fx = every_endpoint_answers_below_floor(|fx| fx.folder, AAnswers::TheOldRecord);
    let folder = fx.folder;
    block_on(fx.engine.command(Command::SetFocus { node: Some(folder) })).expect("the focus moves");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert!(abuse_events(&mut fx._events) > 0, "a trust event");
}

fn assert_read_stale_while_a_fails(parent_of: fn(&GrantScenario) -> NodeId) {
    let mut fx = GrantScenario::new();
    let parent = parent_of(&fx);
    let (a, _) = lag_one_endpoint(&mut fx, parent);
    let children = |fx: &GrantScenario| {
        block_on(fx.engine.view())
            .expect("a rendered view")
            .children(parent)
            .len()
    };
    let before = (children(&fx), cache_and_floor(&fx, parent));
    events_so_far(&mut fx._events);
    fx.world.record_store.fail_endpoint(&a);

    block_on(fx.engine.command(Command::SetFocus { node: Some(parent) })).expect("the focus moves");
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(abuse_events(&mut fx._events), 0, "no trust event");
    assert_eq!(
        (children(&fx), cache_and_floor(&fx, parent)),
        before,
        "last-known-good stays, and no floor moves"
    );
}

#[test]
fn a_focus_read_of_a_lagging_granted_root_while_an_endpoint_fails_is_stale_not_abuse() {
    assert_read_stale_while_a_fails(|fx| fx.folder);
}

#[test]
fn a_tick_read_of_a_lagging_vault_root_while_an_endpoint_fails_is_stale_not_abuse() {
    assert_read_stale_while_a_fails(|_| ROOT);
}

/// ADR 0071 D3: a queued op does not dead-letter on the lag. It stays queued,
/// and lands when the failed endpoint recovers.
#[test]
fn a_queued_create_under_a_lagging_root_while_an_endpoint_fails_waits_and_lands() {
    let mut fx = GrantScenario::new();
    let folder = fx.folder;
    let (a, b) = lag_one_endpoint(&mut fx, folder);
    let name = write_name(folder);
    let served = |fx: &GrantScenario| {
        (
            sequence_served_by(&fx.world, &a, &name),
            sequence_served_by(&fx.world, &b, &name),
        )
    };
    let before = (served(&fx), cache_and_floor(&fx, folder));
    events_so_far(&mut fx._events);
    fx.world.record_store.fail_endpoint(&a);

    block_on(fx.engine.command(Command::Create {
        parent: folder,
        name: "queued.bin".into(),
        kind: NodeKind::File,
    }))
    .expect("a create stages");
    let queued = queued_ops(&fx.owner_device);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(queued_ops(&fx.owner_device), queued, "the op stays queued");
    assert_eq!(
        (served(&fx), cache_and_floor(&fx, folder)),
        before,
        "the drain writes nothing"
    );
    assert_eq!(abuse_events(&mut fx._events), 0, "no trust event");

    fx.world.record_store.heal_endpoint(&a);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(queued_ops(&fx.owner_device), 0, "the op lands");
    assert!(
        block_on(fx.engine.view())
            .expect("a rendered view")
            .children(folder)
            .iter()
            .any(|child| child.name == "queued.bin")
    );
}

/// ADR 0068 D5: the owed wave's cut set keeps the bystander, and the revokee
/// plants at the root. The last copy cannot prove that the bystander still
/// holds a grant, so a sync pass that re-drives the wave from it keeps no row
/// and seals the new seed to nobody.
#[test]
fn a_redrive_from_the_last_copy_keeps_no_grant_row() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let folder = fx.folder;
    owe_the_wave(&mut fx, folder);
    let old_root = derive_write_name(&revokee_seed, &folder.0);
    plant_root_at(&fx, &revokee_seed, sequence_at(&fx.world, &old_root) + 1);

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(moved, old_root, "the wave moved the root");
    assert_no_grant_at(&fx, &moved);
}

/// ADR 0068 D5: a revoke while a wave is owed runs the owed cut first. Its
/// read falls back to the last copy, so the cut it runs keeps no row.
#[test]
fn a_revoke_over_an_owed_wave_and_a_planted_root_keeps_no_grant_row() {
    let mut fx = GrantScenario::new();
    let (_, _, revokee_seed) = write_granted_nested_subtree(&mut fx);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let folder = fx.folder;
    owe_the_wave(&mut fx, folder);
    let old_root = derive_write_name(&revokee_seed, &folder.0);
    plant_root_at(&fx, &revokee_seed, sequence_at(&fx.world, &old_root) + 1);

    assert_eq!(revoke_the_recipient(&mut fx), Ok(CommandOutcome::Done));

    assert_the_revokee_is_cut(&fx, &revokee_seed);
    assert_no_grant_at(&fx, &fx.granted_scope_repoint().current_root);
}

/// ADR 0068 D5: a downgrade over a write scope whose wave a stranded share
/// owes, at a planted root. The re-drive that the command runs first cuts
/// every row from the last copy, so the grantee holds no row to downgrade.
#[test]
fn a_downgrade_over_a_stranded_write_scope_at_a_planted_root_keeps_no_grant_row() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);
    plant_root_served_at(
        &fx,
        &WRITE_SCOPE_SEED,
        fx.folder,
        sequence_at(&fx.world, &stalled) + 1,
        true,
    );

    let outcome = downgrade_the_recipient(&mut fx);

    assert_eq!(
        outcome,
        Err(EngineError::MalformedInput {
            check: "grant-recipient-not-granted"
        })
    );
    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(moved, stalled, "a wave moved the root");
    assert_no_grant_at(&fx, &moved);
}

/// ADR 0068 D1 as amended: a read revoke whose root head block no source
/// holds runs on the last copy and keeps the stop. The check that the cut set
/// landed reads the root as the command does, finds the set did not land, and
/// leaves no work owed.
#[test]
fn a_read_revoke_that_stops_at_an_absent_root_head_block_owes_nothing() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let root = write_name(fx.folder);
    plant_root_served_at(
        &fx,
        &WRITE_SCOPE_SEED,
        fx.folder,
        sequence_at(&fx.world, &root) + 1,
        false,
    );
    let _ = events_so_far(&mut fx._events);

    assert!(revoke_the_recipient(&mut fx).is_err(), "the read cut stops");
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let events = events_so_far(&mut fx._events);
    assert_eq!(
        owed_or_abandoned(&events, fx.folder),
        (false, false),
        "no entry stays for a pass to re-drive"
    );
}

/// Each re-drive decides again whether a cut never landed. One pass reads a
/// replayed pre-cut root and marks the owed wave as a cut that never landed.
/// The next pass reads the cut set again, and the wave still stops. A link
/// expiry after that does not replace the owed wave.
#[test]
fn a_link_expiry_does_not_replace_an_owed_wave_whose_cut_landed() {
    let mut fx = GrantScenario::new();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let deadline = fx.an_hour_from_now();
    fx.mint_link_until(Permission::Read, deadline);
    let granted = fx.granted_scope_repoint();
    let section = published_grant_section_at(&fx.world, &fx.blocks, &granted.current_root)
        .expect("the granted root");
    let writer_seed = grantee_write_scope_seed(&section, &granted.current_root, &fx.folder.0, 1);
    let pre_cut = published_value(&fx.world, &granted.current_root);
    let pointer = scope_pointer_name(kdf::owner_pointer_seed(&SECRET).as_bytes(), &fx.folder.0);
    let mut cut_epoch_floor = fx.folder.0.to_vec();
    cut_epoch_floor.extend_from_slice(b"/cut-epoch");
    fx.world.record_store.fail_put_for(pointer.as_str());
    fx.owner_device
        .floor_store
        .fail_floor_raises_for(&floor_label(&cut_epoch_floor));
    assert_eq!(
        downgrade_the_recipient(&mut fx),
        Ok(CommandOutcome::Done),
        "the cut set lands, and the wave stops at its re-point"
    );
    fx.owner_device.floor_store.heal_floors();
    let cut_set = published_value(&fx.world, &granted.current_root);
    let _ = events_so_far(&mut fx._events);
    publish_value_under(&fx.world, &writer_seed, fx.folder, &pre_cut);
    tick(&fx.world, &fx.engine, &mut fx._tasks);
    assert_eq!(
        owed_reports(&mut fx._events)
            .into_iter()
            .map(|(_, detail, ..)| detail)
            .collect::<Vec<_>>(),
        vec!["owed-cut-never-landed".to_owned()],
        "the pass reads the replay as a cut that never landed"
    );
    publish_value_under(&fx.world, &writer_seed, fx.folder, &cut_set);
    for _ in 0..8 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }
    assert_eq!(
        fx.owed_scopes().first(),
        Some(&fx.folder),
        "the wave stops again"
    );

    fx.world
        .scheduler
        .advance_to(swept_at(&fx.engine, deadline));
    tick(&fx.world, &fx.engine, &mut fx._tasks);

    assert_eq!(
        abandoned(&mut fx._events),
        Vec::new(),
        "nothing is replaced"
    );
    assert_eq!(fx.link_entries(), 1, "the sweep waits for the owed wave");
}

/// ADR 0068 D5: the owed wave of a new write share re-drives from the last
/// copy of a planted root. The cut removes the new grantee's row and the
/// delivery, and the host learns it once.
#[test]
fn a_redrive_that_drops_a_new_share_from_the_last_copy_tells_the_host_once() {
    let mut fx = GrantScenario::new();
    fx.strand_the_owed_wave();
    let stalled = write_name(fx.folder);
    plant_root_served_at(
        &fx,
        &WRITE_SCOPE_SEED,
        fx.folder,
        sequence_at(&fx.world, &stalled) + 1,
        true,
    );

    for _ in 0..3 {
        tick(&fx.world, &fx.engine, &mut fx._tasks);
    }

    assert_eq!(
        abandoned(&mut fx._events),
        vec![(fx.folder, "owed-grants-dropped-from-last-copy".to_owned())]
    );
}

/// ADR 0068 D5: device A holds no owed entry and reads a planted root from
/// its last copy, at a name that its write seed does not derive. The downgrade
/// does not settle the scope on that copy; its own cut keeps no row.
#[test]
fn a_downgrade_with_no_owed_entry_at_a_planted_root_keeps_no_grant_row() {
    let mut fx = GrantScenario::new();
    let (mut other, _other_events, mut other_tasks) = fx.second_owner_device();
    fx.strand_the_owed_wave();
    tick(&fx.world, &other, &mut other_tasks);
    let stalled = write_name(fx.folder);
    plant_root_served_at(
        &fx,
        &WRITE_SCOPE_SEED,
        fx.folder,
        sequence_at(&fx.world, &stalled) + 1,
        true,
    );

    let outcome = command_on(
        &fx,
        &mut other,
        Command::ChangePermission {
            node: fx.folder,
            recipient_identity_public_key: recipient_identity().verifying_key().to_sec1().to_vec(),
            permission: Permission::Read,
        },
    );

    assert_eq!(outcome, Some(Ok(CommandOutcome::Done)));
    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(moved, stalled, "the downgrade moved the root");
    assert_no_grant_at(&fx, &moved);
}

/// ADR 0068 D5: device A owes the wave of a cut whose set keeps the
/// bystander. Device B then revokes the bystander, and the write grantee
/// plants at the root. A sync pass on A re-drives the wave from its last copy,
/// which still keeps the bystander, and the root it moves to keeps no row.
#[test]
fn a_redrive_after_another_device_revoked_keeps_no_grant_row() {
    let mut fx = GrantScenario::new();
    let (mut other, _other_events, _other_tasks) = fx.second_owner_device();
    assert_eq!(
        fx.grant_folder_at(Permission::Write),
        Ok(CommandOutcome::Done)
    );
    let granted = fx.granted_scope_repoint().current_root;
    let section =
        published_grant_section_at(&fx.world, &fx.blocks, &granted).expect("the granted root");
    let writer_seed = grantee_write_scope_seed(&section, &granted, &fx.folder.0, 1);
    assert_eq!(
        fx.grant_bystander(Permission::Read),
        Ok(CommandOutcome::Done)
    );
    let folder = fx.folder;
    owe_the_wave(&mut fx, folder);
    assert_eq!(
        command_on(
            &fx,
            &mut other,
            Command::Revoke {
                node: folder,
                recipient_identity_public_key: bystander_identity(),
            },
        ),
        Some(Ok(CommandOutcome::Done)),
        "device B revokes the bystander"
    );
    let old_root = derive_write_name(&writer_seed, &folder.0);
    plant_root_at(&fx, &writer_seed, sequence_at(&fx.world, &old_root) + 1);

    tick(&fx.world, &fx.engine, &mut fx._tasks);

    let moved = fx.granted_scope_repoint().current_root;
    assert_ne!(moved, old_root, "the wave moved the root");
    assert_no_grant_at(&fx, &moved);
}

/// Run `command` on `engine` across the retries of its bounded steps.
fn command_on(
    fx: &GrantScenario,
    engine: &mut Engine<FakeSeamTypes>,
    command: Command,
) -> Option<Result<CommandOutcome, EngineError>> {
    let cadence = engine.profile().poll_cadence;
    let mut future = pin!(engine.command(command));
    let mut cx = Context::from_waker(Waker::noop());
    (0..64).find_map(|_| match future.as_mut().poll(&mut cx) {
        Poll::Ready(outcome) => Some(outcome),
        Poll::Pending => {
            fx.world.scheduler.advance(cadence);
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Rotation progress: the name wave and the sweep report on the engine clock
// ---------------------------------------------------------------------------

/// A write revoke reports its name wave: one start, one progress event per
/// node with the root last, and one end, each at the virtual clock's time.
#[test]
fn a_write_revoke_reports_each_node_of_its_name_wave_and_the_end() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    events_so_far(&mut fx._events);
    fx.world.scheduler.advance(Duration::from_secs(5));
    let at = fx.world.scheduler.now();

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );

    let wave: Vec<Event> = events_so_far(&mut fx._events)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                Event::NameWaveStarted { .. }
                    | Event::NameWaveProgress { .. }
                    | Event::NameWaveEnded { .. }
            )
        })
        .collect();
    let scope_root = fx.folder;
    let progress = |moved| Event::NameWaveProgress {
        scope_root,
        moved,
        total: 3,
        at,
    };
    assert_eq!(
        wave,
        vec![
            Event::NameWaveStarted { scope_root, at },
            progress(1),
            progress(2),
            progress(3),
            Event::NameWaveEnded {
                scope_root,
                interior_nodes: 2,
                dropped: 0,
                at,
            },
        ]
    );
}

/// A read revoke cuts the scope's read epoch, and the sweep it enqueues
/// re-seals the interior nodes: the run reports no node left at the old
/// epoch, with the cut time and the re-seal time on the virtual clock.
#[test]
fn the_sweep_a_read_revoke_enqueues_reports_no_node_left_at_the_old_epoch() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    nested_subtree(&mut fx);
    events_so_far(&mut fx._events);
    let cut_at = fx.world.scheduler.now();

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );
    settle_filed_sweeps(&fx);

    let reports: Vec<Event> = events_so_far(&mut fx._events)
        .into_iter()
        .filter(|event| matches!(event, Event::SweepConvergence { .. }))
        .collect();
    let [
        Event::SweepConvergence {
            scope_root,
            read_epoch,
            old_epoch_nodes,
            cut_at: reported_cut,
            last_reseal_at,
            at,
        },
    ] = reports.as_slice()
    else {
        panic!("one sweep run reports, not {reports:?}");
    };
    assert_eq!(*scope_root, fx.folder);
    assert_eq!(*read_epoch, 2, "the run gated the root at the cut epoch");
    assert_eq!(*old_epoch_nodes, 0, "no interior node is left behind");
    assert_eq!(*reported_cut, Some(cut_at));
    assert_eq!(*last_reseal_at, Some(*at), "this run re-sealed the nodes");
    assert!(*at >= cut_at);
}

/// A write wave that stops sends its start and no end: the owed work is its
/// terminal event.
#[test]
fn a_write_wave_that_stops_sends_no_end_and_reports_the_work_owed() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    events_so_far(&mut fx._events);
    fx.world
        .record_store
        .fail_put_for(folder_pointer(&fx).as_str());
    let folder = fx.folder;

    assert_eq!(
        command_across_retries(
            &mut fx,
            Command::Revoke {
                node: folder,
                recipient_identity_public_key: recipient_identity()
                    .verifying_key()
                    .to_sec1()
                    .to_vec(),
            }
        ),
        Ok(CommandOutcome::Done)
    );

    let terminal: Vec<&str> = events_so_far(&mut fx._events)
        .iter()
        .filter_map(|event| match event {
            Event::NameWaveStarted { scope_root, .. } if *scope_root == folder => Some("started"),
            Event::NameWaveEnded { .. } => Some("ended"),
            Event::RotationWorkOwed { scope_root, .. } if *scope_root == folder => Some("owed"),
            _ => None,
        })
        .collect();
    assert_eq!(terminal, vec!["started", "owed"]);
}

/// The sweep runs this pass reports, with the cut time and the last re-seal
/// time of each.
fn sweep_reports(
    events: &mut EventStream,
) -> Vec<(NodeId, Option<UnixMillis>, Option<UnixMillis>)> {
    events_so_far(events)
        .into_iter()
        .filter_map(|event| match event {
            Event::SweepConvergence {
                scope_root,
                cut_at,
                last_reseal_at,
                ..
            } => Some((scope_root, cut_at, last_reseal_at)),
            _ => None,
        })
        .collect()
}

/// A stalled link mint spawns the sweep of the parent, which no cut moved: the
/// parent's run reports no cut time.
#[test]
fn the_sweep_a_stalled_mint_spawns_reports_no_cut_of_the_parent() {
    let mut fx = GrantScenario::new();
    fx.world
        .record_store
        .fail_put_for(write_name(ROOT).as_str());
    fx.mint_link();
    fx.world
        .record_store
        .heal_put_for(write_name(ROOT).as_str());
    settle_filed_sweeps(&fx);

    let parent: Vec<_> = sweep_reports(&mut fx._events)
        .into_iter()
        .filter(|(scope, _, _)| *scope == ROOT)
        .collect();
    assert!(!parent.is_empty(), "the parent's sweep reports");
    assert!(
        parent.iter().all(|(_, cut_at, _)| cut_at.is_none()),
        "no cut of the parent occurred"
    );
}

/// A manual rotation cuts the scope's read epoch: the sweep it enqueues
/// reports the cut time and the new epoch.
#[test]
fn the_sweep_a_rotate_now_enqueues_reports_its_cut_time_and_new_epoch() {
    let mut fx = GrantScenario::new();
    assert_eq!(fx.grant_folder_to_recipient(), Ok(CommandOutcome::Done));
    nested_subtree(&mut fx);
    events_so_far(&mut fx._events);
    let cut_at = fx.world.scheduler.now();

    assert_eq!(
        block_on(fx.engine.command(Command::RotateNow { node: fx.folder })),
        Ok(CommandOutcome::Done)
    );
    settle_filed_sweeps(&fx);

    let reports: Vec<(u64, Option<UnixMillis>)> = events_so_far(&mut fx._events)
        .into_iter()
        .filter_map(|event| match event {
            Event::SweepConvergence {
                scope_root,
                read_epoch,
                cut_at,
                ..
            } if scope_root == fx.folder => Some((read_epoch, cut_at)),
            _ => None,
        })
        .collect();
    assert_eq!(reports, vec![(2, Some(cut_at))]);
}

/// The sweep a write revoke enqueues reads the root at the name the cascade
/// saw, and the name wave then moves the root. The sweep follows the root the
/// scope pointer vouches and reports, with no wait for the idle job.
#[test]
fn the_sweep_a_write_revoke_enqueues_follows_the_moved_root() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    events_so_far(&mut fx._events);
    let cut_at = fx.world.scheduler.now();

    assert_eq!(
        fx.revoke_person(&recipient_identity().verifying_key().to_sec1()),
        Ok(CommandOutcome::Done)
    );
    settle_filed_sweeps(&fx);

    let reports: Vec<(u64, u32, Option<UnixMillis>)> = events_so_far(&mut fx._events)
        .into_iter()
        .filter_map(|event| match event {
            Event::SweepConvergence {
                scope_root,
                read_epoch,
                old_epoch_nodes,
                cut_at,
                ..
            } if scope_root == fx.folder => Some((read_epoch, old_epoch_nodes, cut_at)),
            _ => None,
        })
        .collect();
    assert_eq!(
        reports,
        vec![(2, 0, Some(cut_at))],
        "one converged report at the cut epoch, with its cut time"
    );
}

/// A sweep enqueued before a write cut moves the root still reads the current
/// root: it follows the root the scope pointer vouches.
#[test]
fn a_sweep_enqueued_before_a_write_cut_reads_the_current_root() {
    let mut fx = GrantScenario::new();
    write_granted_nested_subtree(&mut fx);
    let folder = fx.folder;
    assert_eq!(
        block_on(fx.engine.command(Command::RotateNow { node: folder })),
        Ok(CommandOutcome::Done)
    );
    let before = fx.granted_scope_repoint().current_root;
    assert_eq!(
        command_across_retries(&mut fx, Command::RotateWriteNow { node: folder }),
        Ok(CommandOutcome::Done)
    );
    assert_ne!(
        fx.granted_scope_repoint().current_root,
        before,
        "the write cut moved the root after the sweep was enqueued"
    );
    events_so_far(&mut fx._events);
    settle_filed_sweeps(&fx);

    let reports: Vec<u32> = events_so_far(&mut fx._events)
        .into_iter()
        .filter_map(|event| match event {
            Event::SweepConvergence {
                scope_root,
                old_epoch_nodes,
                ..
            } if scope_root == folder => Some(old_epoch_nodes),
            _ => None,
        })
        .collect();
    assert!(!reports.is_empty(), "the enqueued sweep reports");
    assert!(reports.iter().all(|nodes| *nodes == 0), "and converges");
}
