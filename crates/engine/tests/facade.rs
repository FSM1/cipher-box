//! Facade skeleton surface: lifecycle law, typed unimplemented commands,
//! and event-stream plumbing over a fully faked seam set.

use cipherbox_engine::testkit::{FakeDevice, FakeSeamTypes, FakeWorld, SeededEntropy, block_on};
use cipherbox_engine::{
    Command, Engine, EngineError, EventStream, LoginSecret, NodeId, NodeKind, Permission,
    PlaintextContent, SyncTimingProfile,
};

fn new_engine(device: &FakeDevice) -> (Engine<FakeSeamTypes>, EventStream) {
    Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(42)),
        SyncTimingProfile::CI,
    )
}

fn secret() -> LoginSecret {
    LoginSecret::new(vec![7u8; 32])
}

fn all_commands() -> Vec<(Command, &'static str)> {
    let node = NodeId([1; 16]);
    let parent = NodeId([2; 16]);
    vec![
        (
            Command::Create {
                parent,
                name: "notes.txt".into(),
                kind: NodeKind::File,
                content: Some(PlaintextContent(b"hello".to_vec())),
            },
            "create",
        ),
        (Command::Delete { node }, "delete"),
        (
            Command::Rename {
                node,
                new_name: "renamed.txt".into(),
            },
            "rename",
        ),
        (
            Command::Relink {
                node,
                new_parent: parent,
            },
            "relink",
        ),
        (
            Command::UpdateContent {
                node,
                content: PlaintextContent(b"v2".to_vec()),
            },
            "updateContent",
        ),
        (Command::SetFocus { node: Some(node) }, "setFocus"),
        (Command::ManualRefresh, "manualRefresh"),
        (
            Command::ImportContact {
                contact_code: b"contact-bundle".to_vec(),
            },
            "importContact",
        ),
        (
            Command::Grant {
                node,
                recipient_identity_public_key: b"bob-pk".to_vec(),
                permission: Permission::Read,
            },
            "grant",
        ),
        (
            Command::Revoke {
                node,
                recipient_identity_public_key: b"bob-pk".to_vec(),
            },
            "revoke",
        ),
        (
            Command::Downgrade {
                node,
                recipient_identity_public_key: b"bob-pk".to_vec(),
            },
            "downgrade",
        ),
        (
            Command::CreateInviteLink {
                node,
                permission: Permission::Write,
            },
            "createInviteLink",
        ),
        (
            Command::AcceptShare {
                sealed_share_pointer: b"sealed-pointer".to_vec(),
            },
            "acceptShare",
        ),
        (Command::RotateNow { node }, "rotateNow"),
        (
            Command::SiweLogin {
                message: "siwe message".into(),
                signature: b"wallet-sig".to_vec(),
            },
            "siweLogin",
        ),
        (Command::Logout, "logout"),
    ]
}

#[test]
fn commands_before_start_are_rejected_not_started() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);

    let result = block_on(engine.command(Command::ManualRefresh));
    assert_eq!(result, Err(EngineError::NotStarted));
}

#[test]
fn start_succeeds_once_and_only_once() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);

    assert_eq!(block_on(engine.start(secret())), Ok(()));
    assert_eq!(
        block_on(engine.start(secret())),
        Err(EngineError::AlreadyStarted),
        "one live instance is the single writer — no second start"
    );
}

#[test]
fn an_empty_secret_is_rejected() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);

    assert_eq!(
        block_on(engine.start(LoginSecret::new(Vec::new()))),
        Err(EngineError::InvalidSecret)
    );
    // A rejected start does not consume the lifecycle.
    assert_eq!(block_on(engine.start(secret())), Ok(()));
}

#[test]
fn every_command_returns_its_typed_unimplemented_error() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();

    for (command, expected_name) in all_commands() {
        let result = block_on(engine.command(command));
        assert_eq!(
            result,
            Err(EngineError::Unimplemented {
                command: expected_name
            }),
            "scaffold facade: `{expected_name}` must reject as typed-unimplemented"
        );
    }
}

#[test]
fn the_event_stream_ends_when_the_engine_drops() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, mut events) = new_engine(&device);

    drop(engine);
    assert_eq!(block_on(events.next()), None);
}

#[test]
fn the_engine_runs_under_the_injected_profile() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events) = new_engine(&device);

    assert_eq!(engine.profile(), &SyncTimingProfile::CI);
}

#[test]
fn two_devices_on_one_world_share_network_and_clock() {
    let world = FakeWorld::new();
    let alice = world.device(b"alice-pk");
    let bob = world.device(b"bob-pk");

    // Shared clock.
    use cipherbox_engine::seams::Scheduler;
    world
        .scheduler
        .advance(core::time::Duration::from_millis(250));
    assert_eq!(alice.scheduler.now(), bob.scheduler.now());

    // Shared record store, per-device floors.
    use cipherbox_engine::seams::RecordTransport;
    let endpoint = &world.record_store.endpoints()[0];
    alice
        .record_store
        .seed_record(endpoint, "shared-name", b"record".to_vec());
    assert_eq!(
        bob.record_store.record_at(endpoint, "shared-name"),
        Some(b"record".to_vec())
    );
}
