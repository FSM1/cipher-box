//! The check-surface suite: every engine error type a host branches on, pinned
//! against its own `CHECKS` in variant declaration order, plus the one table
//! that proves a check name is owned by exactly one surface, plus the frozen
//! reject vectors of every plane outside rotation.
//!
//! A new variant that inherits a neighbour's check name, or is appended out of
//! order, fails here rather than reaching a reject vector unnamed. A verdict
//! that quietly changes class fails against the committed corpus.
//!
//! `crates/engine/kat` is written only by
//! `cargo run -p cipherbox-engine --example kat_gen`.

mod reject_corpus;

use std::collections::BTreeMap;

use cipherbox_core::error::{CodecError, Malformed, TrustViolation};
use cipherbox_core::hex::lower as hex_lower;
use cipherbox_engine::RelayedAnswerRefused;
use cipherbox_engine::content::{ByoKind, DagError, ProviderError};
use cipherbox_engine::entropy::EntropyError;
use cipherbox_engine::gate::{GateRejection, GateStage, RejectionReason};
use cipherbox_engine::grants::InviteFragment;
use cipherbox_engine::grants::accept::TooLong;
use cipherbox_engine::grants::{
    AbuseEvent, AuthorityViolation, CreateGrantError, GrantEditError, InviteError,
};
use cipherbox_engine::net::author::AuthorError;
use cipherbox_engine::record_plane::DefaultsReason;
use cipherbox_engine::rotation::{
    CascadeError, ResealError, ResolveFailure, RevokeError, RotateError, RotateOnCutError,
    RotationPublishError, SweepError, SweepResolveFailure, WriteRotateError,
};
use cipherbox_engine::seams::SeamError;
use cipherbox_engine::settings::{PlacementRefusal, SettingsRefusal};
use cipherbox_engine::testkit::checks::{
    InviteFragmentVector, invite_fragment_accept, invite_fragment_owner, reject_families,
};
use reject_corpus::Corpus;

const MANIFEST: &str = include_str!("../kat/checks/manifest.json");

/// Every vector file the manifest may reference, keyed manifest-relative
/// (relative to `kat/checks/`).
const FIXTURES: &[(&str, &str)] = &[
    (
        "vectors/author_reject.json",
        include_str!("../kat/checks/vectors/author_reject.json"),
    ),
    (
        "vectors/create_reject.json",
        include_str!("../kat/checks/vectors/create_reject.json"),
    ),
    (
        "vectors/devices_reject.json",
        include_str!("../kat/checks/vectors/devices_reject.json"),
    ),
    (
        "vectors/gate_reject.json",
        include_str!("../kat/checks/vectors/gate_reject.json"),
    ),
    (
        "vectors/invite_reject.json",
        include_str!("../kat/checks/vectors/invite_reject.json"),
    ),
    (
        "vectors/ledger_reject.json",
        include_str!("../kat/checks/vectors/ledger_reject.json"),
    ),
    (
        "vectors/owner_entry_reject.json",
        include_str!("../kat/checks/vectors/owner_entry_reject.json"),
    ),
    (
        "vectors/placement_reject.json",
        include_str!("../kat/checks/vectors/placement_reject.json"),
    ),
    (
        "vectors/provider_reject.json",
        include_str!("../kat/checks/vectors/provider_reject.json"),
    ),
];

fn corpus() -> Corpus {
    Corpus::new(MANIFEST, FIXTURES, reject_families())
}

#[test]
fn manifest_header_names_the_check_surface_profile() {
    corpus().header_names("cipherbox/v2 engine check surfaces");
}

#[test]
fn every_embedded_fixture_is_referenced_and_every_reference_embedded() {
    corpus().every_fixture_is_referenced_and_every_reference_embedded();
}

#[test]
fn the_committed_families_are_exactly_the_driven_ones() {
    corpus().the_committed_families_are_exactly_the_driven_ones();
}

#[test]
fn re_driving_the_planes_reproduces_the_committed_vectors() {
    corpus().re_driving_reproduces_the_committed_vectors();
}

#[test]
fn manifest_counts_and_checks_agree_with_the_vector_files() {
    corpus().counts_and_checks_agree_with_the_vector_files();
}

#[test]
fn every_committed_check_sits_on_its_own_surface() {
    corpus().every_committed_check_sits_on_its_own_surface();
}

#[test]
fn vector_names_are_unique_within_each_family() {
    corpus().vector_names_are_unique_within_each_family();
}

#[test]
fn every_class_is_an_axis_or_a_delegated_label() {
    corpus().every_class_is_an_axis_or_a_delegated_label();
}

// --- the one collision table ------------------------------------------------

/// Every surface the engine and core publish. A name owned by two of them
/// leaves a reject vector unable to say where it came from — which is why a
/// variant that means another surface's check delegates to it rather than
/// repeating the string.
fn surfaces() -> [(&'static str, &'static [&'static str]); 21] {
    [
        ("core-trust", TrustViolation::CHECKS),
        ("core-malformed", Malformed::CHECKS),
        ("entropy", EntropyError::CHECKS),
        ("content-dag", DagError::CHECKS),
        ("reseal", ResealError::CHECKS),
        ("revoke", RevokeError::CHECKS),
        ("read_rotate", RotateError::CHECKS),
        ("cascade", CascadeError::CHECKS),
        ("write_rotate", WriteRotateError::CHECKS),
        ("sweep", SweepError::CHECKS),
        ("cut", RotateOnCutError::CHECKS),
        ("author", AuthorError::CHECKS),
        ("create", CreateGrantError::CHECKS),
        ("devices", RelayedAnswerRefused::CHECKS),
        ("gate", GateRejection::CHECKS),
        ("grant_edit", GrantEditError::CHECKS),
        ("invite", InviteError::CHECKS),
        ("ledger", AuthorityViolation::CHECKS),
        ("owner_entry", AbuseEvent::CHECKS),
        ("placement", PlacementRefusal::CHECKS),
        ("provider", ProviderError::CHECKS),
    ]
}

#[test]
fn no_check_name_is_shared_across_surfaces() {
    let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, checks) in surfaces() {
        for check in checks {
            if let Some(previous) = owner.insert(check, name) {
                panic!("{check} is published by both {previous} and {name}");
            }
        }
    }
}

#[test]
fn the_collision_table_covers_every_driven_plane() {
    let mut planes: Vec<&str> = reject_families().iter().map(|f| f.plane).collect();
    planes.extend(
        cipherbox_engine::testkit::rotation::reject_families()
            .iter()
            .map(|f| f.plane),
    );
    for plane in planes {
        assert!(
            surfaces().iter().any(|(name, _)| *name == plane),
            "{plane}: the collision table must cover every driven plane"
        );
    }
}

/// A surface whose every variant delegates owns no name at all, so its empty
/// `CHECKS` is the claim the collision table rests on.
#[test]
fn a_settings_hold_carries_the_verdict_of_the_rule_that_refused() {
    assert!(SettingsRefusal::CHECKS.is_empty());
    let byo = SettingsRefusal::Byo(ProviderError::InsecureTransport);
    assert_eq!(byo.check(), ProviderError::InsecureTransport.check());
    assert_eq!(byo.class(), ProviderError::InsecureTransport.class());

    let placement = SettingsRefusal::Placement(PlacementRefusal::NoProvider);
    assert_eq!(placement.check(), PlacementRefusal::NoProvider.check());
    assert_eq!(placement.class(), PlacementRefusal::NoProvider.class());
}

// --- the surface order tests ------------------------------------------------

/// The names `named` carries that are on `surface`, in the order the variants
/// declare them, and the ones that are not. A delegated variant must appear in
/// the second list by name, so wiring a new variant to another surface's check
/// fails here too.
fn split<'a>(named: &[&'a str], surface: &[&str]) -> (Vec<&'a str>, Vec<&'a str>) {
    named.iter().copied().partition(|c| surface.contains(c))
}

fn seam() -> SeamError {
    SeamError::new("the seam answered nothing")
}

fn codec() -> CodecError {
    CodecError::Malformed(Malformed::WipedMap)
}

#[test]
fn the_provider_check_surface_matches_the_variants_in_order() {
    let named: Vec<&str> = [
        ProviderError::InvalidEndpoint,
        ProviderError::InsecureTransport,
        ProviderError::BlockedAddress,
        ProviderError::InvalidCredential,
        ProviderError::UnresolvedCredential,
        ProviderError::NoStoredCredential,
        ProviderError::RepointedCredential,
        ProviderError::Unreachable,
        ProviderError::NoVerdict,
        ProviderError::Rejected { status: 503 },
        ProviderError::MalformedBlockAddress,
        ProviderError::AddressMismatch,
    ]
    .iter()
    .map(ProviderError::check)
    .collect();
    assert_eq!(named, ProviderError::CHECKS);
}

#[test]
fn the_placement_check_surface_matches_the_variants_in_order() {
    let named: Vec<&str> = [
        PlacementRefusal::SettingsUnavailable(DefaultsReason::Suppressed),
        PlacementRefusal::NoProvider,
        PlacementRefusal::NoExternalIngress(ByoKind::Psa),
    ]
    .iter()
    .map(PlacementRefusal::check)
    .collect();
    assert_eq!(named, PlacementRefusal::CHECKS);
}

#[test]
fn the_gate_check_surface_matches_the_variants_in_order() {
    let rejection = |reason| GateRejection {
        stage: GateStage::Epoch,
        reason,
    };
    let named: Vec<&str> = [
        rejection(RejectionReason::Trust(codec())),
        rejection(RejectionReason::SequenceNotNewer {
            floor: 5,
            sequence: 4,
        }),
        rejection(RejectionReason::EpochBelowFloor { floor: 5, epoch: 4 }),
        rejection(RejectionReason::ScopeRootNotResealable { size: 9, limit: 8 }),
    ]
    .iter()
    .map(GateRejection::check)
    .collect();
    let (owned, delegated) = split(&named, GateRejection::CHECKS);
    assert_eq!(owned, GateRejection::CHECKS);
    assert_eq!(delegated, [codec().check()]);
}

#[test]
fn the_author_check_surface_matches_the_variants_in_order() {
    let named: Vec<&str> = [
        AuthorError::GrantSectionOnChild,
        AuthorError::MissingGrantSection,
        AuthorError::InvalidGrantSection,
        AuthorError::CommitmentNameMismatch,
        AuthorError::CommitmentSignatureInvalid,
        AuthorError::SectionSignatureInvalid,
        AuthorError::MissingAscentLink,
        AuthorError::Seal(codec()),
        AuthorError::HeadTooLarge {
            field: "readSealed",
            size: 9,
            limit: 8,
        },
        AuthorError::ScopeRootNotResealable { size: 9, limit: 8 },
        AuthorError::GrantSectionTooLarge,
    ]
    .iter()
    .map(AuthorError::check)
    .collect();
    let (owned, delegated) = split(&named, AuthorError::CHECKS);
    assert_eq!(owned, AuthorError::CHECKS);
    assert_eq!(
        delegated,
        [
            TrustViolation::StructureSignatureInvalid.check(),
            codec().check(),
            GateRejection::SCOPE_ROOT_NOT_RESEALABLE,
        ]
    );
}

#[test]
fn the_devices_check_surface_matches_the_variants_in_order() {
    let named: Vec<&str> = [
        RelayedAnswerRefused::Unsigned,
        RelayedAnswerRefused::Sealed(TrustViolation::EciesOpenFailed),
    ]
    .iter()
    .map(RelayedAnswerRefused::check)
    .collect();
    let (owned, delegated) = split(&named, RelayedAnswerRefused::CHECKS);
    assert_eq!(owned, RelayedAnswerRefused::CHECKS);
    assert_eq!(delegated, [TrustViolation::EciesOpenFailed.check()]);
}

#[test]
fn the_ledger_and_owner_entry_surfaces_carry_one_check_each() {
    let violation = AuthorityViolation {
        description: "a ledger row the owner never committed".to_owned(),
    };
    assert_eq!(vec![violation.check()], AuthorityViolation::CHECKS);
    assert_eq!(violation.class(), "trust");

    let event = AbuseEvent {
        description: "a seed that did not unseal the body".to_owned(),
    };
    assert_eq!(vec![event.check()], AbuseEvent::CHECKS);
    assert_eq!(event.class(), "trust");
}

#[test]
fn the_entropy_surface_carries_one_check() {
    let error = EntropyError::new("the seam produced nothing");
    assert_eq!(vec![error.check()], EntropyError::CHECKS);
    assert_eq!(error.class(), "availability");
}

#[test]
fn the_invite_check_surface_matches_the_variants_in_order() {
    let violation = AuthorityViolation {
        description: "a ledger row the owner never committed".to_owned(),
    };
    let named: Vec<&str> = [
        InviteError::Entropy(EntropyError::new("no entropy")),
        InviteError::InvalidSecret,
        InviteError::UnusableInviteeKey,
        InviteError::InvalidExpiry,
        InviteError::MalformedClaim(codec()),
        InviteError::MalformedFragment,
        InviteError::FragmentTooLarge,
        InviteError::NameTooLong,
        InviteError::ScopeMismatch,
        InviteError::ScopeUnbound,
        InviteError::NotOwner,
        InviteError::LinkNotCommitted,
        InviteError::LinkExpired,
        InviteError::ClaimantContact(codec()),
        InviteError::ClaimantIsTheEphemeralHalf,
        InviteError::ClaimantIsTheOwner,
        InviteError::GrantSetFull,
        InviteError::UnusableClaimantKey,
        InviteError::DuplicateTag,
        InviteError::Authority(violation.clone()),
    ]
    .iter()
    .map(InviteError::check)
    .collect();
    let (owned, delegated) = split(&named, InviteError::CHECKS);
    assert_eq!(owned, InviteError::CHECKS);
    assert_eq!(
        delegated,
        [
            EntropyError::CHECKS[0],
            Malformed::InvalidDeadline.check(),
            violation.check(),
        ]
    );
}

#[test]
fn the_grant_edit_check_surface_matches_the_variants_in_order() {
    let named: Vec<&str> = [
        GrantEditError::SamePermission,
        GrantEditError::NotGranted,
        GrantEditError::LinkRow,
        GrantEditError::Invite(InviteError::NotOwner),
        GrantEditError::Sign(codec()),
    ]
    .iter()
    .map(GrantEditError::check)
    .collect();
    let (owned, delegated) = split(&named, GrantEditError::CHECKS);
    assert_eq!(owned, GrantEditError::CHECKS);
    assert_eq!(delegated, [InviteError::NotOwner.check(), codec().check()]);
}

#[test]
fn the_create_check_surface_matches_the_variants_in_order() {
    let node_id = [1u8; 16];
    let named: Vec<&str> = [
        CreateGrantError::Converge(SweepError::Publish {
            node_id,
            error: RotationPublishError::NotPublished,
        }),
        CreateGrantError::SubtreeNotConverged {
            unconverged: Vec::new(),
        },
        CreateGrantError::SubtreeBoundaryDiverged {
            planned_not_met: Vec::new(),
            met_not_planned: Vec::new(),
        },
        CreateGrantError::UnusableRecipientKey,
        CreateGrantError::RecipientIsTheOwner,
        CreateGrantError::DisplayNameTooLong(TooLong {
            field: "displayName",
            len: 9,
            limit: 8,
        }),
        CreateGrantError::CommitmentEncode(codec()),
        CreateGrantError::Entropy(EntropyError::new("no entropy")),
        CreateGrantError::Mint(ResealError::SignerNotCommitted),
        CreateGrantError::Publish(RotationPublishError::NotPublished),
        CreateGrantError::Resume(ResolveFailure::Rejected),
        CreateGrantError::ResumeNotThisGrant,
        CreateGrantError::ParentScopeSuperseded,
        CreateGrantError::TargetIndexLostARoot,
        CreateGrantError::DescendantResolve {
            scope_id: node_id,
            reason: ResolveFailure::Rejected,
        },
        CreateGrantError::InteriorResolve {
            node_id,
            reason: SweepResolveFailure::Rejected,
        },
        CreateGrantError::InteriorNotConverged { node_id },
        CreateGrantError::InteriorEpochRegressed { node_id },
        CreateGrantError::InteriorPublish {
            node_id,
            error: RotationPublishError::NotPublished,
        },
        CreateGrantError::DescendantMint {
            scope_id: node_id,
            error: ResealError::SignerNotCommitted,
        },
        CreateGrantError::DescendantPublish {
            scope_id: node_id,
            error: RotationPublishError::NotPublished,
        },
        CreateGrantError::ParentMint(ResealError::SignerNotCommitted),
        CreateGrantError::ParentPublish(RotationPublishError::NotPublished),
        CreateGrantError::VouchScope(RotationPublishError::NotPublished),
        CreateGrantError::Mailbox(seam()),
    ]
    .iter()
    .map(CreateGrantError::check)
    .collect();
    let (owned, delegated) = split(&named, CreateGrantError::CHECKS);
    assert_eq!(owned, CreateGrantError::CHECKS);
    assert_eq!(delegated, [EntropyError::CHECKS[0]]);
}

// --- invite fragment bytes ---------------------------------------------------

const INVITE_FRAGMENT_ACCEPT: &str =
    include_str!("../kat/checks/vectors/invite_fragment_accept.json");

/// The fragment bytes an invite link carries are pinned: each committed
/// fragment decodes to the fields beside it, re-encodes to the same text, and
/// its names verify under the owner exactly when the vector says so.
#[test]
fn every_pinned_invite_fragment_decodes_to_its_fields_and_re_encodes() {
    let vectors: Vec<InviteFragmentVector> =
        serde_json::from_str(INVITE_FRAGMENT_ACCEPT).expect("the fragment vectors parse");
    assert!(
        vectors == invite_fragment_accept(),
        "the live encoder drifted from the pinned fragment bytes"
    );
    let owner = invite_fragment_owner().verifying_key();
    for v in &vectors {
        let fragment = InviteFragment::decode(&v.fragment)
            .unwrap_or_else(|e| panic!("{}: the pinned fragment decodes ({e})", v.name));
        let fields = [
            (
                "inviteSecret",
                hex_lower(fragment.invite_secret.as_bytes()),
                &v.invite_secret,
            ),
            (
                "ownerContactCode",
                hex_lower(&fragment.owner_contact_code),
                &v.owner_contact_code,
            ),
            ("scopeId", hex_lower(&fragment.scope_id), &v.scope_id),
            (
                "scopePointerName",
                fragment.scope_pointer_name.as_str().to_owned(),
                &v.scope_pointer_name,
            ),
            (
                "pointerReadKey",
                hex_lower(fragment.pointer_read_key.as_bytes()),
                &v.pointer_read_key,
            ),
            ("ownerName", fragment.owner_name.clone(), &v.owner_name),
            ("folderName", fragment.folder_name.clone(), &v.folder_name),
            ("namesSig", hex_lower(&fragment.names_sig), &v.names_sig),
        ];
        for (field, decoded, pinned) in fields {
            assert!(decoded == *pinned, "{}: {field} drifted", v.name);
        }
        assert!(
            fragment
                .encode()
                .expect("a pinned fragment re-encodes")
                .as_str()
                == v.fragment,
            "{}: the fragment does not re-encode to its own bytes",
            v.name
        );
        assert_eq!(
            fragment.verified_names(&owner).is_some(),
            v.names_verify,
            "{}: names verdict",
            v.name
        );
    }
}
