//! The reject families of every engine plane outside rotation: one refusal per
//! fail-closed check those planes publish, each produced by driving the live
//! entry point (`testkit::reject` holds the shape).
//!
//! A variant whose verdict is another surface's, carried verbatim, is pinned by
//! that type's order test in `crates/engine/tests/kat_checks.rs` instead of
//! appearing here — a family only ever names its own surface.

use zeroize::Zeroizing;

use cipherbox_core::codec::Value;
use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_core::hex::lower as hex_lower;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSection, GrantSetCommitment, GrantSetEntry, Permission,
    PreservedFields, ReadBody, encode_grant_section, sign_grant_set,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::{
    EcdsaSignature, EcdsaSigner, IDENTITY_PUBLIC_LEN, SIGNATURE_LEN as ECDSA_SIG_LEN,
};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::X25519Secret;

use crate::content::provider::place_block;
use crate::content::{
    ByoBearer, ByoIpfsConfig, ByoKind, PinMode, ProviderError, test_connection, validate_byo_config,
};
use crate::deadlines::DeadlinePolicy;
use crate::devices::{
    ApprovalDecision, RelayedAnswerRefused, adopt_factor, approval_response_payload,
    rendezvous_public_key, seal_factor,
};
use crate::gate::floor::{Strictness, check as floor_check};
use crate::gate::{GateError, GateRejection};
use crate::grants::contact::import_contact;
use crate::grants::ledger::enforce_committed_ledger;
use crate::grants::owner_entry::{AbuseEvent, OwnerEntry, cross_check};
use crate::grants::{
    AckedClaim, AuthorityViolation, CLAIM_ID_LEN, CommittedScope, CreateGrantError,
    EphemeralInvitee, GrantRecipient, GrantRow, GranteeScopePlan, InviteClaim, InviteError,
    InviteFragment, LinkTerms, MAX_INVITE_FRAGMENT_BYTES, MAX_INVITE_NAME_BYTES, OwnerAuthority,
    OwnerGrantKeys, convert_invite_claim, mint_invite_grant, post_share_pointer,
};

use crate::name::MAX_NODE_NAME_BYTES;
use crate::net::author::{
    AuthorError, EnvelopeAuthoring, author_child_envelope, author_scope_root_envelope,
};
use crate::record_plane::DefaultsReason;
use crate::rotation::derive_write_name;
use crate::seams::{HttpResponse, Mailbox, SeamError, SeamResult, UnixMillis};
use crate::settings::{
    PlacementRefusal, SettingsLoad, VaultSettings, decide_placement, placement_of,
    resolve_kept_bearer,
};
use crate::testkit::fakes::{InMemoryFloorStore, ScriptedHttp};
use crate::testkit::reject::{RejectFamily, family, refusal};
use crate::testkit::{
    OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY, OwnerRootSpec, SeededEntropy, block_on,
    owner_root_fixture, owner_root_pseudonym,
};

/// Every non-rotation reject family, in a fixed order. Deterministic: two calls
/// give byte-identical output.
pub fn reject_families() -> Vec<RejectFamily> {
    vec![
        author_family(),
        create_family(),
        devices_family(),
        gate_family(),
        invite_family(),
        ledger_family(),
        owner_entry_family(),
        placement_family(),
        provider_family(),
    ]
}

// --- provider ---------------------------------------------------------------

/// A config whose every field is acceptable, so one mutation at a time isolates
/// the check it trips.
fn honest_provider(kind: ByoKind) -> ByoIpfsConfig {
    ByoIpfsConfig {
        endpoint: "https://ipfs.member.test".to_owned(),
        kind,
        access_token: ByoBearer::Set(Zeroizing::new("member-bearer".to_owned())),
    }
}

fn provider_family() -> RejectFamily {
    let refused = |name, config: &ByoIpfsConfig| {
        refusal!(
            name,
            validate_byo_config(config)
                .err()
                .unwrap_or_else(|| panic!("{name}: the config must fail closed")),
        )
    };
    let endpoint = |value: &str| ByoIpfsConfig {
        endpoint: value.to_owned(),
        ..honest_provider(ByoKind::Psa)
    };
    let bearer = |value: ByoBearer| ByoIpfsConfig {
        access_token: value,
        ..honest_provider(ByoKind::Psa)
    };

    let mut vectors = vec![
        refused("endpoint-without-a-scheme", &endpoint("ipfs.member.test")),
        refused(
            "plaintext-http-to-a-public-host",
            &endpoint("http://ipfs.member.test"),
        ),
        refused(
            "endpoint-naming-the-cloud-metadata-service",
            &endpoint("http://169.254.169.254"),
        ),
        refused(
            "bearer-carrying-a-header-separator",
            &bearer(ByoBearer::Set(Zeroizing::new(
                "tok\r\nX-Injected: 1".to_owned(),
            ))),
        ),
        refused("bearer-left-as-keep", &bearer(ByoBearer::Keep)),
    ];

    // The two kept-bearer verdicts: a save that asks to keep what this session
    // does not hold, and one that asks to carry it to another provider.
    let keeping = VaultSettings {
        pin_mode: PinMode::Dual,
        byo: Some(bearer(ByoBearer::Keep)),
        ..VaultSettings::default()
    };
    let elsewhere = ByoIpfsConfig {
        endpoint: "https://other.member.test".to_owned(),
        ..honest_provider(ByoKind::Psa)
    };
    let kept = |name, held: Option<&ByoIpfsConfig>| {
        refusal!(
            name,
            resolve_kept_bearer(&keeping, held)
                .err()
                .unwrap_or_else(|| panic!("{name}: keeping must fail closed")),
        )
    };
    vectors.push(kept("keep-with-no-bearer-in-this-session", None));
    vectors.push(kept("keep-carried-to-another-endpoint", Some(&elsewhere)));

    // The seam answers: what the provider said, and what it failed to say.
    let probed = |name, http: &ScriptedHttp| {
        refusal!(
            name,
            block_on(test_connection(
                &honest_provider(ByoKind::Psa),
                http,
                &DeadlinePolicy::default(),
            ))
            .err()
            .unwrap_or_else(|| panic!("{name}: the probe must fail closed")),
        )
    };
    let unreachable = ScriptedHttp::default();
    unreachable.enqueue_error(SeamError::new("the provider did not answer"));
    vectors.push(probed("provider-that-never-answered", &unreachable));

    let rejected = ScriptedHttp::default();
    rejected.enqueue_response(HttpResponse {
        status: 401,
        headers: Vec::new(),
        body: Vec::new(),
    });
    vectors.push(probed("provider-that-refused-the-bearer", &rejected));

    let flooding = ScriptedHttp::default();
    flooding.enqueue_response(HttpResponse {
        status: 200,
        headers: Vec::new(),
        // Past the provider-response cap, so the probe reads no verdict at all.
        body: vec![b'{'; 64 * 1024 + 1],
    });
    vectors.push(probed("answer-past-the-provider-response-cap", &flooding));

    // The two block-placement verdicts, on the Kubo leg that names an address
    // back.
    let kubo = honest_provider(ByoKind::Kubo);
    let block = b"one sealed leaf".to_vec();
    let cid = compute_cid(CONTENT_CID_CODEC, &block);
    let placed = |name, address: &[u8], http: &ScriptedHttp| {
        refusal!(
            name,
            block_on(place_block(
                &kubo,
                address,
                &block,
                http,
                &DeadlinePolicy::default(),
            ))
            .err()
            .unwrap_or_else(|| panic!("{name}: the placement must fail closed")),
        )
    };
    let unused = ScriptedHttp::default();
    vectors.push(placed("block-address-off-the-frozen-shapes", &[], &unused));
    assert!(
        unused.requests().is_empty(),
        "an unaddressable block reaches no provider"
    );

    let mismatched = ScriptedHttp::default();
    let stored = compute_cid(CONTENT_CID_CODEC, b"some other block");
    mismatched.enqueue_response(HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: format!("{{\"Key\":\"{}\"}}", encode_content_cid_str(&stored)).into_bytes(),
    });
    vectors.push(placed(
        "provider-that-stored-another-address",
        &cid,
        &mismatched,
    ));

    family("provider", ProviderError::CHECKS, vectors)
}

// --- placement --------------------------------------------------------------

fn placement_family() -> RejectFamily {
    let refused = |name, settings: VaultSettings| {
        refusal!(
            name,
            placement_of(&settings)
                .err()
                .unwrap_or_else(|| panic!("{name}: the placement must fail closed")),
        )
    };
    let external = |byo| VaultSettings {
        pin_mode: PinMode::External,
        byo,
        ..VaultSettings::default()
    };

    let degraded = decide_placement(&SettingsLoad::Defaults(DefaultsReason::Suppressed));
    let vectors = vec![
        refused("external-only-with-no-provider-configured", external(None)),
        refused(
            "external-only-over-a-pin-by-cid-provider",
            external(Some(honest_provider(ByoKind::Pinata))),
        ),
        refusal!(
            "settings-load-degraded-past-a-first-run",
            degraded
                .decision
                .expect_err("a suppressed load authenticates no placement"),
        ),
    ];

    family("placement", PlacementRefusal::CHECKS, vectors)
}

// --- gate -------------------------------------------------------------------

/// Drive the floor law with the floors a previous adoption durably raised.
fn gate_family() -> RejectFamily {
    const NAME: &[u8] = b"k51qzi5uqu5dgate";
    const SCOPE: [u8; 16] = [0x9a; 16];

    let refused = |name, floors: &InMemoryFloorStore, sequence, epoch| {
        let error = block_on(floor_check(
            floors,
            NAME,
            &SCOPE,
            sequence,
            epoch,
            Strictness::StrictlyNewer,
        ))
        .err()
        .unwrap_or_else(|| panic!("{name}: the floor law must fail closed"));
        let rejection = match error {
            GateError::Rejected(rejection) => rejection,
            GateError::Seam(seam) => panic!("{name}: an in-memory floor store answered: {seam}"),
        };
        refusal!(name, rejection)
    };

    let floors = InMemoryFloorStore::default();
    block_on(raise_floors(&floors, NAME, &SCOPE));
    let vectors = vec![
        refused("record-replayed-below-the-sequence-floor", &floors, 4, 9),
        refused("record-from-an-epoch-a-revocation-cut", &floors, 9, 4),
    ];

    family("gate", GateRejection::CHECKS, vectors)
}

async fn raise_floors(floors: &InMemoryFloorStore, name: &[u8], scope_id: &[u8; 16]) {
    use crate::seams::FloorStore;
    floors
        .raise_sequence_floor(name, 5)
        .await
        .expect("an in-memory floor store raises");
    floors
        .raise_epoch_floor(scope_id, 5)
        .await
        .expect("an in-memory floor store raises");
}

// --- ledger and owner entry -------------------------------------------------

const POINTER_READ_KEY: [u8; SECRET_LEN] = [0x66; SECRET_LEN];

fn ledger_family() -> RejectFamily {
    let commitment = GrantSetCommitment {
        ipns_name: b"k51qzi5uqu5dledger".to_vec(),
        owner_pseudonym_pk: [0x88; 32],
        cut_epoch: 0,
        entries: vec![GrantSetEntry::new(
            &POINTER_READ_KEY,
            [0x21; 32],
            [0x61; 32],
            Permission::Read,
            [0x02; 32],
        )],
        unknown: PreservedFields::new(),
    };
    let row = |tag: [u8; 32], permission| {
        GrantLedgerEntry::new(
            [0x02; IDENTITY_PUBLIC_LEN],
            [0x61; 32],
            permission,
            tag,
            [0u8; ECDSA_SIG_LEN],
        )
    };
    let refused = |name, ledger: &[GrantLedgerEntry]| {
        refusal!(
            name,
            enforce_committed_ledger(&commitment, ledger)
                .err()
                .unwrap_or_else(|| panic!("{name}: the divergence must fail closed")),
        )
    };

    let vectors = vec![refused(
        "ledger-row-the-owner-never-committed",
        &[
            row([0x21; 32], Permission::Read),
            row([0x77; 32], Permission::Write),
        ],
    )];

    family("ledger", AuthorityViolation::CHECKS, vectors)
}

fn owner_entry_family() -> RejectFamily {
    const SEED: [u8; 32] = [0x66; 32];
    const OTHER: [u8; 32] = [0x99; 32];

    let refused = |name, owner_blob: &[u8; 32], ascent: Option<&[u8; 32]>| match cross_check(
        owner_blob, ascent, &SEED, 4,
    ) {
        OwnerEntry::Abuse(event) => refusal!(name, event),
        OwnerEntry::Confirmed { .. } => panic!("{name}: a disagreement must raise abuse"),
    };

    let vectors = vec![refused(
        "owner-blob-seed-that-did-not-unseal-the-body",
        &OTHER,
        None,
    )];

    family("owner_entry", AbuseEvent::CHECKS, vectors)
}

// --- devices ----------------------------------------------------------------

fn devices_family() -> RejectFamily {
    const DEVICE: &str = "cd11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    const REQUEST: &str = "1b3d4c1a-0000-4000-8000-000000000001";

    let scalar = [4u8; SECRET_LEN];
    let ephemeral = rendezvous_public_key(&scalar).expect("a valid rendezvous scalar");
    let sealed = seal_factor(
        &ephemeral,
        REQUEST,
        DEVICE,
        &[9u8; SECRET_LEN],
        b"the recovery factor",
    )
    .expect("the factor seals to the rendezvous key");
    let approver = Ed25519Signer::from_seed([21u8; SECRET_LEN]);
    let approver_pk = hex_lower(&approver.verifying_key().to_bytes());

    // A well-formed answer, re-signed for another request id: every field the
    // approving device answered with is intact, only the binding is not.
    let payload = approval_response_payload(
        &approver_pk,
        "1b3d4c1a-0000-4000-8000-000000000002",
        ApprovalDecision::Approve,
        &ephemeral,
        &sealed,
    )
    .expect("the payload encodes");
    let signature = hex_lower(&approver.sign(&payload).to_bytes());

    let vectors = vec![refusal!(
        "answer-signed-for-another-request",
        adopt_factor(&sealed, REQUEST, DEVICE, &approver_pk, &signature, &scalar)
            .expect_err("an unbound answer must fail closed"),
    )];

    family("devices", RelayedAnswerRefused::CHECKS, vectors)
}

// --- invite -----------------------------------------------------------------

const INVITE_SCOPE: [u8; 16] = [0x5c; 16];
const INVITE_DEADLINE: UnixMillis = UnixMillis(1_700_000_000_000);
const INVITE_WRITE_SCOPE_SEED: [u8; SECRET_LEN] = [0x55; SECRET_LEN];
const INVITE_LINK_SECRET: u8 = 0x4e;

/// The scope pointer name a claim on the fixture's link names.
fn invite_pointer_name() -> IpnsName {
    IpnsName::from_public_key(&Ed25519Signer::from_seed([0x5d; 32]).verifying_key())
}

/// One owner, one minted link, one committed set: the state a conversion runs
/// against, so each vector mutates exactly one input away from it.
struct InviteFixture {
    identity: EcdsaSigner,
    enc: X25519Secret,
    scope: ChildScopeRef,
    link_row: GrantRow,
    commitment: GrantSetCommitment,
    commitment_sig: EcdsaSignature,
    ledger: Vec<GrantLedgerEntry>,
}

impl InviteFixture {
    fn new() -> Self {
        Self::capped(5)
    }

    /// A link that admits `admission_cap` people.
    fn capped(admission_cap: u64) -> Self {
        let identity = EcdsaSigner::from_scalar(&[0x33; 32]).expect("a valid owner scalar");
        let enc = X25519Secret::from_scalar([0x11; 32]);
        let pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let name = derive_write_name(&INVITE_WRITE_SCOPE_SEED, &INVITE_SCOPE)
            .as_str()
            .as_bytes()
            .to_vec();
        let link_row = mint_invite_grant(
            &identity,
            &enc,
            &POINTER_READ_KEY,
            &EphemeralInvitee::from_secret(&[INVITE_LINK_SECRET; SECRET_LEN])
                .expect("a valid invite secret"),
            &INVITE_SCOPE,
            &INVITE_WRITE_SCOPE_SEED,
            &LinkTerms {
                deadline: INVITE_DEADLINE,
                conversion_permission: Permission::Read,
                admission_cap,
            },
        )
        .expect("the owner mints its own link");
        let (commitment, commitment_sig, ledger) =
            owner_signed_set(&identity, &pseudonym, name.clone(), &[&link_row]);
        Self {
            identity,
            enc,
            scope: ChildScopeRef::new(INVITE_SCOPE, name),
            link_row,
            commitment,
            commitment_sig,
            ledger,
        }
    }

    fn authority(&self) -> OwnerAuthority<'_> {
        OwnerAuthority {
            identity_signer: &self.identity,
            enc_secret: &self.enc,
        }
    }

    fn committed(&self) -> CommittedScope<'_> {
        CommittedScope::bind(
            &self.scope,
            &self.commitment,
            &self.commitment_sig,
            &self.ledger,
        )
        .expect("the gated reference names the scope root the set carries")
    }
}

fn owner_signed_set(
    identity: &EcdsaSigner,
    pseudonym: &Ed25519Signer,
    ipns_name: Vec<u8>,
    rows: &[&GrantRow],
) -> (GrantSetCommitment, EcdsaSignature, Vec<GrantLedgerEntry>) {
    let commitment = GrantSetCommitment {
        ipns_name,
        owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
        cut_epoch: 0,
        entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
        unknown: PreservedFields::new(),
    };
    let sig = sign_grant_set(identity, &commitment).expect("the owner signs its own set");
    let ledger = rows.iter().map(|r| r.ledger_entry.clone()).collect();
    (commitment, sig, ledger)
}

/// A claim as the owner acked it: sender-authenticated already.
fn claim_item(
    sender: &EcdsaSigner,
    contact_code: Vec<u8>,
    scope_pointer_name: IpnsName,
) -> AckedClaim {
    AckedClaim {
        sender: sender.verifying_key().to_sec1(),
        payload: InviteClaim {
            claim_id: [0x99; CLAIM_ID_LEN],
            scope_pointer_name,
            contact_code,
            name: String::new(),
        }
        .encode()
        .expect("an honest claim encodes"),
        acked_at: UnixMillis(0),
    }
}

fn contact_code(identity: &EcdsaSigner, enc: &X25519Secret) -> Vec<u8> {
    ContactCode::create(identity, enc.public()).encode()
}

/// A fragment the owner signed, one field away from a bound.
fn invite_fragment(owner: &EcdsaSigner, folder_name: String) -> InviteFragment {
    let mut fragment = InviteFragment {
        invite_secret: SecretBytes::new([INVITE_LINK_SECRET; SECRET_LEN]),
        owner_contact_code: contact_code(owner, &X25519Secret::from_scalar([0x11; 32])),
        scope_id: INVITE_SCOPE,
        scope_pointer_name: invite_pointer_name(),
        pointer_read_key: SecretBytes::new(POINTER_READ_KEY),
        owner_name: "Ada".to_owned(),
        folder_name,
        names_sig: [0; ECDSA_SIG_LEN],
    };
    fragment.sign_names(owner);
    fragment
}

/// An invite fragment the live encoder produced, beside the fields it carries,
/// hex where they are bytes. The owner is the fixture's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteFragmentVector {
    /// The vector's name.
    pub name: String,
    /// The fragment text, as a URL carries it.
    pub fragment: String,
    /// The invite secret.
    pub invite_secret: String,
    /// The owner contact code.
    pub owner_contact_code: String,
    /// The scope id.
    pub scope_id: String,
    /// The scope pointer name.
    pub scope_pointer_name: String,
    /// The pointer read key.
    pub pointer_read_key: String,
    /// The owner name.
    pub owner_name: String,
    /// The folder name.
    pub folder_name: String,
    /// The owner signature over the names.
    pub names_sig: String,
    /// Whether the names verify under the owner identity.
    pub names_verify: bool,
}

/// The owner identity every [`invite_fragment_accept`] vector is signed under.
pub fn invite_fragment_owner() -> EcdsaSigner {
    InviteFixture::new().identity
}

/// The invite fragments whose bytes the KAT pins: a signed fragment, one with
/// no owner name, and one whose names a forwarder changed under the signature.
/// A changed name still decodes; only its signature fails.
pub fn invite_fragment_accept() -> Vec<InviteFragmentVector> {
    let owner = invite_fragment_owner();
    let signed = invite_fragment(&owner, "Photos".to_owned());
    let mut unnamed = signed.clone();
    unnamed.owner_name = String::new();
    unnamed.sign_names(&owner);
    let mut relabelled = signed.clone();
    relabelled.owner_name = "Eve".to_owned();
    [
        ("signed-names", signed),
        ("no-owner-name", unnamed),
        ("names-a-forwarder-changed", relabelled),
    ]
    .into_iter()
    .map(|(name, fragment)| InviteFragmentVector {
        name: name.to_owned(),
        fragment: fragment
            .encode()
            .expect("a fixture fragment is inside its bound")
            .to_string(),
        invite_secret: hex_lower(fragment.invite_secret.as_bytes()),
        owner_contact_code: hex_lower(&fragment.owner_contact_code),
        scope_id: hex_lower(&fragment.scope_id),
        scope_pointer_name: fragment.scope_pointer_name.as_str().to_owned(),
        pointer_read_key: hex_lower(fragment.pointer_read_key.as_bytes()),
        owner_name: fragment.owner_name.clone(),
        folder_name: fragment.folder_name.clone(),
        names_sig: hex_lower(&fragment.names_sig),
        names_verify: fragment.verified_names(&owner.verifying_key()).is_some(),
    })
    .collect()
}

fn invite_family() -> RejectFamily {
    let fx = InviteFixture::new();
    let link_signer =
        EcdsaSigner::from_scalar(&[INVITE_LINK_SECRET; 32]).expect("a valid ephemeral scalar");
    let claimant_identity = EcdsaSigner::from_scalar(&[0x67; 32]).expect("a valid claimant scalar");
    let claimant_enc = X25519Secret::from_scalar([0x98; 32]);
    let claimant = contact_code(&claimant_identity, &claimant_enc);

    // One honest conversion, varied one input at a time.
    let convert = |name: &'static str, scope: &CommittedScope<'_>, item: &AckedClaim| {
        refusal!(
            name,
            convert_invite_claim(
                &fx.authority(),
                scope,
                &invite_pointer_name(),
                &POINTER_READ_KEY,
                item,
            )
            .err()
            .unwrap_or_else(|| panic!("{name}: the conversion must fail closed")),
        )
    };
    let honest_item = claim_item(&link_signer, claimant.clone(), invite_pointer_name());

    let mut vectors = vec![
        refusal!(
            "invite-secret-outside-the-group",
            EphemeralInvitee::from_secret(&[0u8; SECRET_LEN])
                .expect_err("an all-zero secret is not a scalar"),
        ),
        refusal!(
            "fragment-that-is-not-this-build-encoding",
            InviteFragment::decode("not a fragment!!")
                .expect_err("a malformed fragment is refused"),
        ),
        refusal!(
            "fragment-past-the-invite-link-bound",
            InviteFragment::decode(&"A".repeat(MAX_INVITE_FRAGMENT_BYTES * 2))
                .expect_err("an oversized fragment is refused"),
        ),
        refusal!(
            "fragment-folder-name-past-its-bound",
            invite_fragment(&fx.identity, "n".repeat(MAX_INVITE_NAME_BYTES + 1))
                .encode()
                .expect_err("a name past its bound is refused at encode"),
        ),
        refusal!(
            "claim-name-no-ledger-row-can-carry",
            InviteClaim {
                claim_id: [0x99; CLAIM_ID_LEN],
                scope_pointer_name: invite_pointer_name(),
                contact_code: claimant.clone(),
                name: "a\nb".to_owned(),
            }
            .encode()
            .expect_err("a name with a control character is refused at encode"),
        ),
        refusal!(
            "gated-reference-to-a-scope-the-set-does-not-name",
            CommittedScope::bind(
                &ChildScopeRef::new(INVITE_SCOPE, b"k51qzi5uqu5delsewhere".to_vec()),
                &fx.commitment,
                &fx.commitment_sig,
                &fx.ledger,
            )
            .err()
            .unwrap_or_else(|| panic!("a commitment bound elsewhere is refused")),
        ),
    ];

    let stranger = EcdsaSigner::from_scalar(&[0x34; 32]).expect("a valid stranger scalar");
    let stranger_enc = X25519Secret::from_scalar([0x35; 32]);
    vectors.push(refusal!(
        "conversion-presented-by-a-stranger",
        convert_invite_claim(
            &OwnerAuthority {
                identity_signer: &stranger,
                enc_secret: &stranger_enc,
            },
            &fx.committed(),
            &invite_pointer_name(),
            &POINTER_READ_KEY,
            &honest_item,
        )
        .expect_err("only the owner converts a claim"),
    ));

    vectors.push(convert(
        "claim-payload-that-did-not-decode",
        &fx.committed(),
        &AckedClaim {
            payload: b"not det-cbor".to_vec(),
            ..honest_item.clone()
        },
    ));
    vectors.push(convert(
        "claim-naming-another-scope-pointer",
        &fx.committed(),
        &claim_item(
            &link_signer,
            claimant.clone(),
            IpnsName::from_public_key(&Ed25519Signer::from_seed([0x5e; 32]).verifying_key()),
        ),
    ));
    vectors.push(convert(
        "claim-signed-by-no-link-on-the-set",
        &fx.committed(),
        &claim_item(&stranger, claimant.clone(), invite_pointer_name()),
    ));

    vectors.push(refusal!(
        "claim-on-a-link-past-its-deadline",
        convert_invite_claim(
            &fx.authority(),
            &fx.committed(),
            &invite_pointer_name(),
            &POINTER_READ_KEY,
            &AckedClaim {
                acked_at: INVITE_DEADLINE,
                ..honest_item.clone()
            },
        )
        .expect_err("a link past its deadline admits nobody"),
    ));
    let full = InviteFixture::capped(0);
    vectors.push(refusal!(
        "claim-on-a-link-at-its-admission-cap",
        convert_invite_claim(
            &full.authority(),
            &full.committed(),
            &invite_pointer_name(),
            &POINTER_READ_KEY,
            &honest_item,
        )
        .expect_err("a link at its cap admits nobody"),
    ));

    let mut torn = claimant.clone();
    *torn.last_mut().expect("a contact code has bytes") ^= 0xff;
    vectors.push(convert(
        "claimant-contact-code-that-fails-its-binding-verify",
        &fx.committed(),
        &claim_item(&link_signer, torn, invite_pointer_name()),
    ));
    vectors.push(convert(
        "claimant-anchored-back-to-the-links-own-identity",
        &fx.committed(),
        &claim_item(
            &link_signer,
            contact_code(&link_signer, &claimant_enc),
            invite_pointer_name(),
        ),
    ));
    vectors.push(convert(
        "claimant-handing-back-the-owners-own-contact",
        &fx.committed(),
        &claim_item(
            &link_signer,
            contact_code(&claimant_identity, &fx.enc),
            invite_pointer_name(),
        ),
    ));

    // The produced set would file two rows under one tag — the shape core's own
    // decoder refuses, so the conversion refuses before it is signed.
    let doubled = vec![fx.link_row.ledger_entry.clone(); 2];
    let doubled_scope =
        CommittedScope::bind(&fx.scope, &fx.commitment, &fx.commitment_sig, &doubled)
            .expect("the reference still names the scope root");
    vectors.push(convert(
        "ledger-filing-two-rows-under-one-tag",
        &doubled_scope,
        &honest_item,
    ));

    family("invite", InviteError::CHECKS, vectors)
}

// --- author -----------------------------------------------------------------

const AUTHOR_NODE: [u8; 16] = [0x1b; 16];
const AUTHOR_SCOPE: [u8; 16] = [0x2a; 16];
const AUTHOR_READ_KEY: [u8; 32] = [0x9d; 32];
const AUTHOR_NONCE: [u8; 24] = [0x5e; 24];

fn empty_folder() -> ReadBody {
    ReadBody::Folder {
        created_at: 1,
        modified_at: 2,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    }
}

fn authoring(body: &ReadBody, carried: PreservedFields) -> EnvelopeAuthoring<'_> {
    EnvelopeAuthoring {
        node_id: AUTHOR_NODE,
        scope_id: AUTHOR_SCOPE,
        epoch: OWNER_ROOT_EPOCH,
        read_key: &AUTHOR_READ_KEY,
        nonce: &AUTHOR_NONCE,
        body,
        carried_unknown: carried,
        carried_epoch_tag_unknown: PreservedFields::new(),
    }
}

fn carried_section(section: &GrantSection) -> PreservedFields {
    [(
        "grantSection".to_owned(),
        Value::Bytes(encode_grant_section(section).expect("the section encodes")),
    )]
    .into_iter()
    .collect()
}

fn author_family() -> RejectFamily {
    let owner_identity = EcdsaSigner::from_scalar(&[0x11; 32]).expect("a valid owner scalar");
    let owner = owner_identity.verifying_key();
    let fixture = owner_root_fixture(OwnerRootSpec {
        writer_pseudonym: &owner_root_pseudonym(),
        pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
        owner_identity: &owner_identity,
        owner_enc: &kdf::enc_subkey(&[0x3c; 32]).public(),
        scope_id: AUTHOR_SCOPE,
        root_id: AUTHOR_NODE,
        children: Vec::new(),
        child_scope_index: Vec::new(),
        parent_node_seed: None,
        owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
        write_history_link: Vec::new(),
        grants: Vec::new(),
    });
    let folder = empty_folder();
    let root = |carried: PreservedFields, name: &IpnsName, owes: bool| {
        author_scope_root_envelope(authoring(&folder, carried), name, &owner, owes)
    };
    let elsewhere = derive_write_name(&[0x7c; 32], &AUTHOR_SCOPE);

    let mut unsigned = fixture.grant_section.clone();
    unsigned.commitment_sig = [0u8; 64];

    let vectors = vec![
        refusal!(
            "child-envelope-carrying-the-scope-root-marker",
            author_child_envelope(authoring(
                &folder,
                [("grantSection".to_owned(), Value::Bytes(b"section".to_vec()))]
                    .into_iter()
                    .collect(),
            ))
            .expect_err("a child may never carry a grant section"),
        ),
        refusal!(
            "scope-root-without-the-marker-every-root-adoption-requires",
            root(PreservedFields::new(), &fixture.name, false)
                .expect_err("a scope root carries a grant section"),
        ),
        refusal!(
            "scope-root-whose-carried-section-does-not-decode",
            root(
                [("grantSection".to_owned(), Value::Bytes(b"section".to_vec()))]
                    .into_iter()
                    .collect(),
                &fixture.name,
                false,
            )
            .expect_err("a section this build cannot read is never published"),
        ),
        refusal!(
            "commitment-naming-another-scope-root",
            root(carried_section(&fixture.grant_section), &elsewhere, false,)
                .expect_err("the commitment binds the name it publishes at"),
        ),
        refusal!(
            "commitment-the-anchored-owner-did-not-sign",
            root(carried_section(&unsigned), &fixture.name, false)
                .expect_err("an unsigned commitment is never published"),
        ),
        refusal!(
            "interior-scope-root-carrying-no-ascent-link",
            root(carried_section(&fixture.grant_section), &fixture.name, true,)
                .expect_err("an interior root owes its ascent link"),
        ),
    ];

    family("author", AuthorError::CHECKS, vectors)
}

// --- create -----------------------------------------------------------------

/// One fixed stream per driven call: a KAT corpus may not sample entropy.
const CREATE_ENTROPY_SEED: u64 = 0xc7_ea_7e_5d;

/// A mailbox that refuses every post — the leg that leaves a grantee unaware of
/// a scope that already exists.
struct RefusingMailbox;

impl Mailbox for RefusingMailbox {
    async fn post(&self, _recipient: &[u8], _payload: &[u8], _key: &str) -> SeamResult<()> {
        Err(SeamError::new("the mailbox did not accept the pointer"))
    }

    async fn poll(&self) -> SeamResult<Vec<crate::seams::MailboxItem>> {
        Ok(Vec::new())
    }

    async fn ack(&self, _item_id: &str) -> SeamResult<bool> {
        Ok(false)
    }
}

fn create_family() -> RejectFamily {
    let owner_identity = EcdsaSigner::from_scalar(&[0x33; 32]).expect("a valid owner scalar");
    let owner_enc = X25519Secret::from_scalar([0x11; 32]);
    let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
    let owner = OwnerGrantKeys {
        enc_secret: &owner_enc,
        identity_signer: &owner_identity,
        pseudonym_signer: &owner_pseudonym,
    };
    let recipient_identity = EcdsaSigner::from_scalar(&[0x45; 32]).expect("a valid recipient key");
    let recipient_enc = X25519Secret::from_scalar([0x44; 32]);
    let contact =
        import_contact(&ContactCode::create(&recipient_identity, recipient_enc.public()).encode())
            .expect("a freshly created code verifies");
    let owner_enc_pub = owner_enc.public();
    let parent_node_seed = [0x44; SECRET_LEN];
    let write_scope_seed = [0x55; SECRET_LEN];
    let grantee = GranteeScopePlan {
        v: 2,
        scope_id: INVITE_SCOPE,
        parent_node_seed: &parent_node_seed,
        owner_enc_pub: &owner_enc_pub,
        write_scope_seed: &write_scope_seed,
        write_cut: None,
        pointer_read_key: &POINTER_READ_KEY,
        subtree_child_index: &[],
    };
    let name = derive_write_name(&write_scope_seed, &INVITE_SCOPE);

    // The label bound is checked before the post, so one refusing mailbox
    // serves both vectors: the first never reaches it.
    let post = |name_of: &'static str, display_name: String| {
        let recipient = GrantRecipient {
            contact: &contact,
            display_name,
            grantee_name: None,
        };
        refusal!(
            name_of,
            block_on(post_share_pointer(
                &mut SeededEntropy::new(CREATE_ENTROPY_SEED),
                &RefusingMailbox,
                &owner,
                &grantee,
                &recipient,
                &name,
            ))
            .err()
            .unwrap_or_else(|| panic!("{name_of}: the post must fail closed")),
        )
    };

    let vectors = vec![
        post(
            "courtesy-label-past-the-recipients-own-bound",
            "a".repeat(MAX_NODE_NAME_BYTES + 1),
        ),
        post(
            "mailbox-that-did-not-accept-the-pointer",
            "Shared".to_owned(),
        ),
    ];

    family("create", CreateGrantError::CHECKS, vectors)
}
