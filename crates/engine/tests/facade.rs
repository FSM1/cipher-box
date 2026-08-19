//! Facade skeleton surface: lifecycle law, typed unimplemented commands,
//! and event-stream plumbing over a fully faked seam set.

use core::cell::RefCell;

use cipherbox_core::kdf;
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_engine::grants::{ContactStore, StagingContactStore, resolve_recipient};
use cipherbox_engine::net::RE_PUT_INTERVAL;
use cipherbox_engine::seams::{HttpResponse, Scheduler, UnixMillis};
use cipherbox_engine::testkit::{FakeDevice, FakeSeamTypes, FakeWorld, SeededEntropy, block_on};
use cipherbox_engine::{
    ApiBaseUrl, Command, CommandOutcome, ContentProfile, Engine, EngineError, EventStream,
    GatewayConfig, LoginSecret, MAX_CONTACT_CODE_BYTES, NodeId, Permission, StoragePolicy,
    SyncTimingProfile,
};

fn new_engine(device: &FakeDevice) -> (Engine<FakeSeamTypes>, EventStream) {
    Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(42)),
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy::CI,
        ApiBaseUrl::offline(),
        GatewayConfig::disabled(),
    )
}

/// The login secret every test in this file starts the engine with. The staging
/// stores the tests reach into directly derive their keys from it, so the two
/// stay in step.
const SECRET: [u8; 32] = [7u8; 32];

fn secret() -> LoginSecret {
    LoginSecret::new(SECRET.to_vec())
}

/// Commands whose pipeline slice has not landed: the still-unimplemented
/// surface. The metadata intent ops (delete/rename/relink and create) are wired
/// and covered by the inline facade tests.
fn unimplemented_commands() -> Vec<(Command, &'static str)> {
    let node = NodeId([1; 16]);
    vec![
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
            Command::AcceptShare {
                sealed_share_pointer: b"sealed-pointer".to_vec(),
            },
            "acceptShare",
        ),
        (Command::RotateNow { node }, "rotateNow"),
        (Command::Logout, "logout"),
    ]
}

#[test]
fn a_manual_refresh_with_no_sync_loop_reports_a_failed_refresh() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();

    // No vault pointer resolved a root, so no tick loop is running to force a
    // pass: the refresh must fail rather than park or silently succeed.
    assert!(matches!(
        block_on(engine.command(Command::ManualRefresh)),
        Err(EngineError::RefreshFailed { .. })
    ));
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
fn a_siwe_challenge_before_start_is_rejected_not_started() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events) = new_engine(&device);

    assert_eq!(
        block_on(engine.siwe_challenge()),
        Err(EngineError::NotStarted)
    );
}

#[test]
fn a_started_engine_serves_the_nonce_from_its_api_client() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).expect("start");

    device.http.enqueue_response(HttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: br#"{"nonce":"a1b2c3d4e5f60718","expiresAt":"2026-01-01T00:00:00Z"}"#.to_vec(),
    });

    assert_eq!(
        block_on(engine.siwe_challenge()),
        Ok("a1b2c3d4e5f60718".to_owned())
    );
    let request = device.http.requests().pop().expect("one request");
    assert!(request.url.ends_with("/auth/siwe/challenge"), "{request:?}");
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
fn unimplemented_commands_return_their_typed_error() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();

    for (command, expected_name) in unimplemented_commands() {
        let result = block_on(engine.command(command));
        assert_eq!(
            result,
            Err(EngineError::Unimplemented {
                command: expected_name
            }),
            "`{expected_name}` must reject as typed-unimplemented until its slice lands"
        );
    }
}

/// The invite mint is wired, so it refuses with its own verdict rather than
/// falling through the catch-all — and it refuses a node that names no scope
/// root before it reaches any key material.
#[test]
fn minting_an_invite_link_refuses_a_node_that_names_no_scope_root() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();

    assert_eq!(
        block_on(engine.command(Command::CreateInviteLink {
            node: NodeId([1; 16]),
            permission: Permission::Read,
        })),
        Err(EngineError::UnsupportedTarget {
            check: "invite-target-is-not-a-scope-root"
        }),
    );
}

/// The vault root passes the target check, so an offline engine stops at the
/// scope material it has not resolved — availability, never the catch-all.
#[test]
fn minting_an_invite_link_on_an_unresolved_vault_root_reports_availability() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();
    let root = block_on(engine.view()).expect("view").root();

    assert!(matches!(
        block_on(engine.command(Command::CreateInviteLink {
            node: root,
            permission: Permission::Read,
        })),
        Err(EngineError::Seam { .. }),
    ));
}

/// A contact code the peer signed itself: the bundle a real import receives
/// out of band.
fn contact_code(scalar: [u8; 32]) -> Vec<u8> {
    let identity = EcdsaSigner::from_scalar(&scalar).expect("valid identity scalar");
    ContactCode::create(&identity, kdf::enc_subkey(&scalar).public()).encode()
}

#[test]
fn importing_a_contact_returns_the_bound_public_keys() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();
    let scalar = [3u8; 32];

    let outcome = block_on(engine.command(Command::ImportContact {
        contact_code: contact_code(scalar),
    }));

    let CommandOutcome::ContactImported(contact) = outcome.expect("the code imports") else {
        panic!("importing a contact answers with the contact");
    };
    let identity = EcdsaSigner::from_scalar(&scalar).expect("valid identity scalar");
    assert_eq!(contact.identity_pk(), identity.verifying_key());
    assert_eq!(contact.enc_subkey(), kdf::enc_subkey(&scalar).public());
}

/// An import that only lived in the command's return value would leave a later
/// grant with an identity key and no subkey to seal to, so the contact must come
/// back from the durable book on the next session.
#[test]
fn an_imported_contact_survives_a_session_restart() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();
    let scalar = [3u8; 32];
    block_on(engine.command(Command::ImportContact {
        contact_code: contact_code(scalar),
    }))
    .expect("the code imports");
    drop(engine);

    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let book = StagingContactStore::new(&device.staging_store, &enc_subkey, &entropy);
    let identity = EcdsaSigner::from_scalar(&scalar).expect("valid identity scalar");
    let resolved = block_on(resolve_recipient(
        &book,
        &identity.verifying_key().to_sec1(),
    ))
    .expect("the recorded contact resolves by identity key");
    assert_eq!(
        resolved.enc_subkey(),
        kdf::enc_subkey(&scalar).public(),
        "the subkey a later grant seals to is the one the import verified"
    );
}

/// A durable book that cannot take the write must fail the command: a host told
/// the contact imported would offer it as a grant recipient the next session
/// cannot resolve.
#[test]
fn an_import_the_book_cannot_take_is_not_reported_as_imported() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();

    let enc_subkey = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(7));
    let book = StagingContactStore::new(&device.staging_store, &enc_subkey, &entropy);
    device
        .staging_store
        .interrupt_staged_write_after(book.staging_key(), 0);

    let result = block_on(engine.command(Command::ImportContact {
        contact_code: contact_code([3u8; 32]),
    }));
    assert!(
        matches!(result, Err(EngineError::Seam { .. })),
        "a lost durable write fails the import: {result:?}"
    );
    assert!(
        block_on(book.contacts()).expect("load").is_empty(),
        "nothing was recorded"
    );
}

/// The binding signature is the only thing tying the encryption subkey to the
/// identity key, so a code that fails it is refused outright — never a
/// degraded import that hands back an unbound subkey (#34 D6).
#[test]
fn a_contact_code_that_fails_its_binding_is_refused() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();
    let mut code = contact_code([3u8; 32]);
    let honest = kdf::enc_subkey(&[3u8; 32]).public().to_bytes();
    let forged = kdf::enc_subkey(&[4u8; 32]).public().to_bytes();
    let at = code
        .windows(honest.len())
        .position(|window| window == honest)
        .expect("the encoded code carries the subkey it bound");
    code[at..at + forged.len()].copy_from_slice(&forged);

    assert_eq!(
        block_on(engine.command(Command::ImportContact { contact_code: code })),
        Err(EngineError::TrustViolation {
            message: "contact code rejected: subkey-binding-invalid".to_owned(),
        }),
    );
}

/// A bundle that does not decode is refused too, but as bad input — a host
/// told a garbled scan came from a forger would accuse the wrong party.
#[test]
fn a_malformed_contact_code_is_refused_without_a_trust_verdict() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();

    let result = block_on(engine.command(Command::ImportContact {
        contact_code: b"not a contact bundle".to_vec(),
    }));

    assert!(
        matches!(result, Err(EngineError::MalformedInput { .. })),
        "an undecodable bundle is refused, never imported: {result:?}"
    );
}

/// The bundle is three fixed-width keys, and the bytes are an unbounded host
/// paste: an over-cap payload never reaches the decoder.
#[test]
fn an_oversized_contact_code_is_refused_before_it_is_decoded() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();

    assert_eq!(
        block_on(engine.command(Command::ImportContact {
            contact_code: vec![0x80; MAX_CONTACT_CODE_BYTES + 1],
        })),
        Err(EngineError::MalformedInput {
            check: "contact-code-too-large",
        }),
    );
}

/// The lifecycle check outranks the trust decision: a valid code still yields
/// no contact before `start`.
#[test]
fn a_contact_import_before_start_never_verifies() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);

    assert_eq!(
        block_on(engine.command(Command::ImportContact {
            contact_code: contact_code([3u8; 32]),
        })),
        Err(EngineError::NotStarted),
    );
}

/// Focus is recorded whatever the window resolves to: a node absent from
/// gate-passing state has nothing to descend into, which is not an error.
#[test]
fn set_focus_records_a_window_with_nothing_to_resolve() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = new_engine(&device);
    block_on(engine.start(secret())).unwrap();

    assert_eq!(
        block_on(engine.command(Command::SetFocus {
            node: Some(NodeId([1; 16]))
        })),
        Ok(CommandOutcome::Done)
    );
    assert_eq!(
        block_on(engine.command(Command::SetFocus { node: None })),
        Ok(CommandOutcome::Done)
    );
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
fn cold_start_spawns_exactly_the_hourly_liveness_loop() {
    let world = FakeWorld::new();
    // Auto-advance so the spawned loop's sleep resolves without a manual driver;
    // every clone shares this one inner clock.
    let scheduler = world.scheduler.clone().with_auto_advance();
    let device = world.device(b"me");
    let (mut engine, _events) = new_engine(&device);

    assert!(
        scheduler.take_spawned_tasks().is_empty(),
        "no background loop is spawned before start"
    );

    block_on(engine.start(secret())).unwrap();
    let tasks = scheduler.take_spawned_tasks();
    assert_eq!(
        tasks.len(),
        1,
        "cold-start spawns exactly the liveness loop"
    );

    // Dropping the engine clears the alive latch, so the loop stops at its next
    // wake instead of re-PUTting forever after the session is gone.
    drop(engine);
    for task in tasks {
        block_on(task);
    }
    assert_eq!(
        scheduler.now(),
        UnixMillis(u64::try_from(RE_PUT_INTERVAL.as_millis()).unwrap()),
        "the loop slept one hourly interval before the drop latch stopped it"
    );
}

#[test]
fn a_rejected_start_spawns_no_liveness_loop() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let (mut engine, _events) = new_engine(&device);

    assert_eq!(
        block_on(engine.start(LoginSecret::new(Vec::new()))),
        Err(EngineError::InvalidSecret)
    );
    assert!(
        device.scheduler.take_spawned_tasks().is_empty(),
        "a rejected start wires no background work"
    );
}

#[test]
fn the_engine_runs_under_the_injected_profile() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events) = new_engine(&device);

    assert_eq!(engine.profile(), &SyncTimingProfile::CI);
    assert_eq!(
        engine.storage_policy(),
        &StoragePolicy::CI,
        "the measured storage split is injected whole, not derived at use"
    );
}

#[test]
fn two_devices_on_one_world_share_network_and_clock() {
    let world = FakeWorld::new();
    let alice = world.device(b"alice-pk");
    let bob = world.device(b"bob-pk");

    // Shared clock.
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
