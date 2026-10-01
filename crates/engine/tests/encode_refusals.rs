//! Encode-side refusals of the engine's own formats, and of the produce-side
//! gate every record publish passes (AGENTS.md rule 8). CI also runs this file
//! under `--release`, where `debug_assert!` is compiled out, so a refusal that
//! leans on one fails there.

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_engine::SyncTimingProfile;
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
use cipherbox_engine::seams::{FloorStore, HttpResponse, RecordTransport, UnixMillis};
use cipherbox_engine::testkit::{FakeDevice, FakeWorld, block_on};

/// A publish basis at `name` with no record read there.
fn fresh(name: &IpnsName) -> Observed {
    Observed::gated(name, 0, ENVELOPE_V).expect("this build's envelope version")
}

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
            publish_under(&device, &signer, &fresh(&name), Some(bar)),
            Err(PublishError::BelowBar { floor, at, epoch }),
        );
        assert!(nothing_reached_the_transport(&device, &name));
    }
    let signer = Ed25519Signer::from_seed([0x44; 32]);
    let name = name_of(&signer);
    assert_eq!(
        publish_under(&device, &signer, &fresh(&name), Some(root_bar(5, 4, 3))),
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
