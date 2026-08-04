//! The adoption-gate simulation harness: N engine instances on one fake record
//! store, virtual time, and adversarial replay/transplant/re-sign, plus the
//! six-stage matrix and the floor-law scenarios hard-asserted 1:1 against the
//! design tables in blueprint/engine.md ("Adoption gate and floors").
//!
//! Every record is hand-fed: the IPNS record plane rides the shared fake record
//! store and the metadata is built directly with `crates/core`'s crypto. The
//! gate composes only core's verify/unseal functions, so the reject rows assert
//! core's exact named `TrustViolation` error, never an engine reinvention.

use std::collections::BTreeSet;

use cipherbox_core::codec::{Map, Value, encode};
use cipherbox_core::error::TrustViolation;
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::payload::{RepointObject, open_pointer_payload, seal_pointer_payload};
use cipherbox_core::seal::{
    AadContext, Envelope, GrantBlobPayload, GrantSection, GrantSetCommitment, OverrideSeedPayload,
    OwnerWriteBlobPayload, PreservedFields, ReadBody, STRUCT_TAG_ASCENT_LINK,
    STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_HISTORY_LINK, STRUCT_TAG_OWNER_BLOB,
    STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_READ_BODY, STRUCT_TAG_WRITE_BODY, SignedAscentLink,
    SignedGrantBlob, SignedOwnerBlob, SignedOwnerWriteBlob, SignedSealed, StructureSigInput,
    WriteBody, encode_write_body, open_grant_blob, seal, seal_ascent_link, seal_grant_blob,
    seal_owner_blob, seal_owner_write_blob, seal_read_body, sign_grant_set, sign_structure,
};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;

use cipherbox_engine::SyncTimingProfile;
use cipherbox_engine::gate::floor::{
    advance_write_epoch_on_sight, cold_seed, read_epoch_floor, sequence_floor, write_epoch_floor,
};
use cipherbox_engine::gate::{
    Adopted, Candidate, FLOOR_VERDICTS, GateError, GateStage, ReaderContext, SeedBlob, adopt,
};
use cipherbox_engine::net::MAX_RECORD_BYTES;
use cipherbox_engine::rotation::{
    CommittedSet, PrevEpochSeed, ResealSeeds, ScopeRootIdentity, reseal_scope_root,
};
use cipherbox_engine::seams::{FloorStore, RecordTransport, Scheduler};
use cipherbox_engine::testkit::fakes::InMemoryFloorStore;
use cipherbox_engine::testkit::{FakeWorld, SeededEntropy, block_on};

// Format version, injected TTL/EOL, and the fixed nonces/ephemeral scalars the
// fixture seals under (test crypto: deterministic, KAT-style injected entropy).
const V: u64 = 1;
const TTL_NANOS: u64 = 2_000_000_000;
const EOL: &str = "2027-01-01T00:00:00Z";
const RECORD_VALUE: &[u8] = b"/ipfs/AAAAAAAAAA";
const NONCE_READ_BODY: [u8; 24] = [11u8; 24];
const NONCE_WRITE_BODY: [u8; 24] = [22u8; 24];
const NONCE_POINTER: [u8; 24] = [33u8; 24];
const EPH_OWNER: [u8; 32] = [3u8; 32];
const EPH_ASCENT: [u8; 32] = [4u8; 32];
const EPH_GRANT: [u8; 32] = [5u8; 32];

/// A fully valid scope-root fixture: every key/seed and the derived valid
/// [`Candidate`] parts. Each test builds a fresh fixture and mutates one aspect
/// to exercise exactly one gate stage.
struct Fixture {
    // Identities.
    owner_identity: EcdsaSigner,
    owner_identity_verifier: EcdsaVerifier,
    owner_pseudonym: Ed25519Signer,
    owner_enc: X25519Secret,
    // Scope shape.
    scope_id: [u8; 16],
    root_id: [u8; 16],
    scope_seed: [u8; 32],
    epoch: u64,
    // Derived record/metadata.
    read_key: [u8; 32],
    ipns_signer: Ed25519Signer,
    name: IpnsName,
    owner_blob_enc: [u8; 32],
    owner_blob_ct: Vec<u8>,
    owner_blob_aad: AadContext,
    /// The record's grant section — the commitment, owner blob, and write-body
    /// with real detached structure signatures. The gate enumerates and
    /// recomputes over this (#687).
    grant_section: GrantSection,
    valid_envelope: Envelope,
}

impl Fixture {
    fn new() -> Self {
        let owner_identity = EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid scalar");
        let owner_identity_verifier = owner_identity.verifying_key();
        let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let owner_enc = X25519Secret::from_scalar([0x33; 32]);

        let scope_id = [0x44; 16];
        let root_id = [0x55; 16];
        let scope_seed = [0x66; 32];
        let write_scope_seed = [0x77; 32];
        let epoch = 1;

        // Read plane: read key from the node seed.
        let node_seed = kdf::node_seed(&scope_seed, &root_id);
        let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();

        // Write plane: the IPNS keypair and the write-body key.
        let write_seed = kdf::write_seed(&write_scope_seed, &root_id);
        let ipns_signer = kdf::ipns_keypair(write_seed.as_bytes());
        let name = IpnsName::from_public_key(&ipns_signer.verifying_key());
        let write_key = kdf::write_key(write_seed.as_bytes());

        // Owner blob (a seed-bearing structure AND the owner's seed source).
        let override_payload = OverrideSeedPayload::new(scope_seed, epoch);
        let owner_blob_aad = AadContext {
            v: V,
            id: root_id,
            scope: scope_id,
            epoch,
            struct_tag: STRUCT_TAG_OWNER_BLOB,
        };
        let owner_blob = seal_owner_blob(
            &owner_enc.public(),
            &EPH_OWNER,
            &owner_blob_aad,
            &override_payload,
        )
        .unwrap();
        let owner_blob_ct = owner_blob.ciphertext.clone();
        let owner_blob_enc = owner_blob.enc;
        // Sign a seed-bearing structure's ciphertext with the owner pseudonym —
        // the detached structure signature the gate recomputes and verifies.
        let sign = |tag: u8, recipient: Option<[u8; 32]>, ct: &[u8]| -> [u8; 64] {
            let input = StructureSigInput::over_ciphertext(scope_id, epoch, tag, recipient, ct);
            sign_structure(&owner_pseudonym, &input).to_bytes()
        };
        let signed_owner_blob = SignedOwnerBlob {
            enc: owner_blob_enc,
            ciphertext: owner_blob_ct.clone(),
            signature: sign(STRUCT_TAG_OWNER_BLOB, None, &owner_blob_ct),
            unknown: PreservedFields::new(),
        };

        // Write-body (a second seed-bearing structure, to exercise the loop).
        let write_body = WriteBody {
            grant_ledger: Vec::new(),
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let write_body_aad = AadContext {
            v: V,
            id: root_id,
            scope: scope_id,
            epoch,
            struct_tag: STRUCT_TAG_WRITE_BODY,
        };
        let write_body_sealed = seal(
            write_key.as_bytes(),
            &NONCE_WRITE_BODY,
            &write_body_aad,
            &encode_write_body(&write_body).expect("encodes"),
        );
        let signed_write_body = SignedSealed {
            signature: sign(STRUCT_TAG_WRITE_BODY, None, &write_body_sealed),
            sealed: write_body_sealed,
            unknown: PreservedFields::new(),
        };

        // Owner-write-blob (the write-plane mirror of the owner blob): its AAD
        // binds the write epoch, its structure signature the (here-equal) epoch
        // the gate recomputes from the envelope.
        let owner_write_payload = OwnerWriteBlobPayload::new(write_scope_seed, epoch);
        let owner_write_aad = AadContext {
            v: V,
            id: root_id,
            scope: scope_id,
            epoch,
            struct_tag: STRUCT_TAG_OWNER_WRITE_BLOB,
        };
        let owner_write = seal_owner_write_blob(
            &owner_enc.public(),
            &EPH_OWNER,
            &owner_write_aad,
            &owner_write_payload,
        )
        .unwrap();
        let signed_owner_write_blob = SignedOwnerWriteBlob {
            signature: sign(STRUCT_TAG_OWNER_WRITE_BLOB, None, &owner_write.ciphertext),
            enc: owner_write.enc,
            ciphertext: owner_write.ciphertext,
            unknown: PreservedFields::new(),
        };

        // Grant-set commitment (grant-less scope: the owner pseudonym is the
        // sole committed writer).
        let commitment = GrantSetCommitment {
            ipns_name: name.as_str().as_bytes().to_vec(),
            owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
            entries: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let commitment_sig = sign_grant_set(&owner_identity, &commitment)
            .expect("signs")
            .to_compact();
        let grant_section = GrantSection {
            commitment: commitment.clone(),
            commitment_sig,
            grant_blobs: Vec::new(),
            owner_blob: signed_owner_blob,
            owner_write_blob: Some(signed_owner_write_blob),
            ascent_link: None,
            history_links: Vec::new(),
            write_body: signed_write_body,
            unknown: PreservedFields::new(),
        };

        // Valid empty-folder read-body sealed into the envelope.
        let folder = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let valid_envelope = seal_read_body(
            &read_key,
            &NONCE_READ_BODY,
            V,
            root_id,
            scope_id,
            epoch,
            &folder,
        )
        .expect("valid folder seals");

        Self {
            owner_identity,
            owner_identity_verifier,
            owner_pseudonym,
            owner_enc,
            scope_id,
            root_id,
            scope_seed,
            epoch,
            read_key,
            ipns_signer,
            name,
            owner_blob_enc,
            owner_blob_ct,
            owner_blob_aad,
            grant_section,
            valid_envelope,
        }
    }

    fn record_bytes(&self, sequence: u64) -> Vec<u8> {
        IpnsRecord::create_v2(&self.ipns_signer, RECORD_VALUE, sequence, TTL_NANOS, EOL).marshal()
    }

    fn read_body_aad(&self) -> AadContext {
        AadContext {
            v: V,
            id: self.root_id,
            scope: self.scope_id,
            epoch: self.epoch,
            struct_tag: STRUCT_TAG_READ_BODY,
        }
    }

    /// Seal an arbitrary read-body plaintext under the scope read key — used to
    /// stage a duplicate-child body built at the codec level (bypassing
    /// `encode_read_body`'s uniqueness guard, exactly as a hostile peer would).
    fn seal_read_plaintext(&self, plaintext: &[u8]) -> Vec<u8> {
        seal(
            &self.read_key,
            &NONCE_READ_BODY,
            &self.read_body_aad(),
            plaintext,
        )
    }

    fn envelope_with_read_sealed(&self, read_sealed: Vec<u8>) -> Envelope {
        Envelope {
            v: V,
            id: self.root_id,
            scope: self.scope_id,
            epoch: self.epoch,
            read_sealed,
            unknown: PreservedFields::new(),
            epoch_tag_unknown: PreservedFields::new(),
        }
    }

    fn candidate_with_record(&self, record_bytes: Vec<u8>) -> Candidate {
        Candidate {
            name: self.name.clone(),
            record_bytes,
            grant_section: self.grant_section.clone(),
            envelope: self.valid_envelope.clone(),
        }
    }

    fn candidate(&self, sequence: u64) -> Candidate {
        self.candidate_with_record(self.record_bytes(sequence))
    }

    fn owner_seed_blob(&self, tampered: bool) -> SeedBlob<'_> {
        let mut ciphertext = self.owner_blob_ct.clone();
        if tampered {
            ciphertext[0] ^= 0xFF;
        }
        SeedBlob::Owner {
            enc_secret: &self.owner_enc,
            enc: self.owner_blob_enc,
            ciphertext,
            aad: self.owner_blob_aad,
        }
    }

    fn reader(&self) -> ReaderContext<'_> {
        ReaderContext {
            owner_identity: &self.owner_identity_verifier,
            scope_id: self.scope_id,
            read_key: &self.read_key,
            parent_node_seed: None,
            seed_blob: Some(self.owner_seed_blob(false)),
        }
    }

    /// A well-formed published ascent link sealed under `parent_node_seed` with a
    /// valid owner-pseudonym structure signature. The stage-3 verdict hinges on
    /// whether the *reader's* `parent_node_seed` re-derives this keypair, so a
    /// mismatched reader seed is a natural `ascent-link-mismatch`.
    fn ascent_link_under(&self, parent_node_seed: &[u8; 32]) -> SignedAscentLink {
        self.ascent_link_under_aad(parent_node_seed, self.ascent_aad())
    }

    /// An ascent link sealed under `parent_node_seed` with a caller-chosen AAD,
    /// carrying this scope's real override seed — lets a test seal under an AAD
    /// that does not bind to the envelope (the gate rebuilds the AAD from the
    /// envelope, so such a link fails the HPKE open).
    fn ascent_link_under_aad(
        &self,
        parent_node_seed: &[u8; 32],
        aad: AadContext,
    ) -> SignedAscentLink {
        self.ascent_link_full(
            parent_node_seed,
            aad,
            OverrideSeedPayload::new(self.scope_seed, self.epoch),
        )
    }

    /// An ascent link sealed under `parent_node_seed`/`aad` carrying a
    /// caller-chosen `OverrideSeedPayload` — lets a test seal a rogue or
    /// stale-epoch seed to the published ascent public key. The structure
    /// signature is always valid (over the real ciphertext at the fixture
    /// scope/epoch), so the derive-and-verify half is what a test exercises.
    fn ascent_link_full(
        &self,
        parent_node_seed: &[u8; 32],
        aad: AadContext,
        payload: OverrideSeedPayload,
    ) -> SignedAscentLink {
        let link = seal_ascent_link(parent_node_seed, &EPH_ASCENT, &aad, &payload).unwrap();
        let input = StructureSigInput::over_ciphertext(
            self.scope_id,
            self.epoch,
            STRUCT_TAG_ASCENT_LINK,
            None,
            &link.ciphertext,
        );
        SignedAscentLink {
            ascent_public: link.ascent_public,
            enc: link.enc,
            ciphertext: link.ciphertext,
            signature: sign_structure(&self.owner_pseudonym, &input).to_bytes(),
            unknown: PreservedFields::new(),
        }
    }

    /// The envelope-matching ascent AAD (the honest ascent context for the
    /// fixture's scope root).
    fn ascent_aad(&self) -> AadContext {
        AadContext {
            v: V,
            id: self.root_id,
            scope: self.scope_id,
            epoch: self.epoch,
            struct_tag: STRUCT_TAG_ASCENT_LINK,
        }
    }

    /// An owner seed blob whose sealed AAD is overridden (e.g. a foreign scope)
    /// while still HPKE-wrapped to the reader's real enc subkey — a transplant
    /// that opens but must fail the envelope cross-check.
    fn owner_seed_blob_with_aad(&self, aad: AadContext) -> SeedBlob<'_> {
        let payload = OverrideSeedPayload::new(self.scope_seed, self.epoch);
        let blob = seal_owner_blob(&self.owner_enc.public(), &EPH_OWNER, &aad, &payload).unwrap();
        SeedBlob::Owner {
            enc_secret: &self.owner_enc,
            enc: blob.enc,
            ciphertext: blob.ciphertext,
            aad,
        }
    }

    /// An owner seed blob carrying a *wrong* scope seed: it opens cleanly (real
    /// AAD, real enc subkey) yet cannot derive the reader's read key.
    fn owner_seed_blob_wrong_seed(&self, wrong_seed: [u8; 32]) -> SeedBlob<'_> {
        let payload = OverrideSeedPayload::new(wrong_seed, self.epoch);
        let blob = seal_owner_blob(
            &self.owner_enc.public(),
            &EPH_OWNER,
            &self.owner_blob_aad,
            &payload,
        )
        .unwrap();
        SeedBlob::Owner {
            enc_secret: &self.owner_enc,
            enc: blob.enc,
            ciphertext: blob.ciphertext,
            aad: self.owner_blob_aad,
        }
    }
}

/// One folder child as a raw det-CBOR map (so a duplicate listing can be built
/// below the `encode_read_body` uniqueness guard).
fn raw_child(id: [u8; 16], name: &str, ipns: &[u8]) -> Value {
    let mut m = Map::new();
    m.insert("id", Value::Bytes(id.to_vec()));
    m.insert("name", Value::Text(name.to_string()));
    m.insert("ipnsName", Value::Bytes(ipns.to_vec()));
    m.insert("kind", Value::Text("file".to_string()));
    m.insert("linkCounter", Value::Unsigned(0));
    Value::Map(m)
}

/// A folder read-body plaintext built directly through the codec.
fn raw_folder_plaintext(children: Vec<Value>) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("kind", Value::Text("folder".to_string()));
    m.insert("children", Value::Array(children));
    m.insert("createdAt", Value::Unsigned(0));
    m.insert("modifiedAt", Value::Unsigned(0));
    encode(&Value::Map(m)).unwrap()
}

fn duplicate_id_plaintext() -> Vec<u8> {
    raw_folder_plaintext(vec![
        raw_child([1; 16], "a", b"ipns-a"),
        raw_child([1; 16], "b", b"ipns-b"),
    ])
}

fn duplicate_ipns_name_plaintext() -> Vec<u8> {
    raw_folder_plaintext(vec![
        raw_child([1; 16], "a", b"ipns-same"),
        raw_child([2; 16], "b", b"ipns-same"),
    ])
}

/// Overwrite the top-level `value` protobuf field (field 1, emitted first) with
/// a same-length payload, leaving the signed `data` field untouched — so the
/// signature still verifies but the data/value consistency check fires.
fn tamper_top_value(mut bytes: Vec<u8>, new_value: &[u8]) -> Vec<u8> {
    assert_eq!(bytes[0], 0x0A, "IPNS field-1 (value) length-delimited tag");
    let len = bytes[1] as usize;
    assert_eq!(
        len,
        new_value.len(),
        "same-length overwrite keeps the signed data field intact"
    );
    bytes[2..2 + len].copy_from_slice(new_value);
    bytes
}

// ---------------------------------------------------------------------------
// The six-stage matrix — mirrored 1:1 from blueprint/engine.md.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Expect {
    Accept,
    Reject(GateStage, &'static str),
}

/// The design table: the acceptance row plus every reject class, each pinned to
/// the stage it fires at and its exact named error.
const MATRIX: &[(&str, Expect)] = &[
    ("accept", Expect::Accept),
    (
        "record-verify:ipns-signature-invalid",
        Expect::Reject(GateStage::RecordVerify, "ipns-signature-invalid"),
    ),
    (
        "record-verify:ipns-value-mismatch",
        Expect::Reject(GateStage::RecordVerify, "ipns-value-mismatch"),
    ),
    (
        "commitment-verify:commitment-invalid",
        Expect::Reject(GateStage::CommitmentVerify, "commitment-invalid"),
    ),
    (
        "grant-section:structure-signature-invalid",
        Expect::Reject(GateStage::GrantSection, "structure-signature-invalid"),
    ),
    (
        "grant-section:ascent-link-mismatch",
        Expect::Reject(GateStage::GrantSection, "ascent-link-mismatch"),
    ),
    (
        "sequence:sequence-not-newer",
        Expect::Reject(GateStage::Sequence, "sequence-not-newer"),
    ),
    (
        "epoch:epoch-below-floor",
        Expect::Reject(GateStage::Epoch, "epoch-below-floor"),
    ),
    (
        "unseal:seal-open-failed",
        Expect::Reject(GateStage::Unseal, "seal-open-failed"),
    ),
    (
        "unseal:hpke-open-failed",
        Expect::Reject(GateStage::Unseal, "hpke-open-failed"),
    ),
    (
        "unseal:duplicate-id",
        Expect::Reject(GateStage::Unseal, "duplicate-id"),
    ),
    (
        "unseal:duplicate-ipns-name",
        Expect::Reject(GateStage::Unseal, "duplicate-ipns-name"),
    ),
];

/// The exact reject surface the six-stage matrix must exercise: nine composed
/// core `TrustViolation` checks plus the two engine floor-law verdicts.
const MATRIX_REJECT_SURFACE: &[&str] = &[
    "ipns-signature-invalid",
    "ipns-value-mismatch",
    "commitment-invalid",
    "structure-signature-invalid",
    "ascent-link-mismatch",
    "sequence-not-newer",
    "epoch-below-floor",
    "seal-open-failed",
    "hpke-open-failed",
    "duplicate-id",
    "duplicate-ipns-name",
];

/// Build a fresh fixture, apply the named mutation, and run the gate to a
/// verdict. Each call owns its fixture/floors for the whole adopt.
fn run_matrix_case(name: &str) -> Result<Adopted, GateError> {
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let mut candidate = fx.candidate(1);
    let mut tamper_seed_blob = false;
    let mut reader_parent_seed: Option<[u8; 32]> = None;

    match name {
        "accept" => {}
        "record-verify:ipns-signature-invalid" => {
            let last = candidate.record_bytes.len() - 1;
            candidate.record_bytes[last] ^= 0x01;
        }
        "record-verify:ipns-value-mismatch" => {
            candidate.record_bytes = tamper_top_value(candidate.record_bytes, b"/ipfs/BBBBBBBBBB");
        }
        "commitment-verify:commitment-invalid" => {
            let foreign = EcdsaSigner::from_scalar(&[0x5A; 32]).expect("valid scalar");
            candidate.grant_section.commitment_sig =
                sign_grant_set(&foreign, &candidate.grant_section.commitment)
                    .expect("signs")
                    .to_compact();
        }
        "grant-section:structure-signature-invalid" => {
            candidate.grant_section.owner_blob.signature[0] ^= 0xFF;
        }
        "grant-section:ascent-link-mismatch" => {
            // The link is sealed under one parent seed; the reader supplies a
            // DIFFERENT real ancestor seed, so the reader-derived keypair
            // mismatches the link's public half — a natural ascent-link-mismatch.
            candidate.grant_section.ascent_link = Some(fx.ascent_link_under(&[0xA1; 32]));
            reader_parent_seed = Some([0xB2; 32]);
        }
        "sequence:sequence-not-newer" => {
            block_on(floors.raise_sequence_floor(fx.name.as_str().as_bytes(), 5)).unwrap();
        }
        "epoch:epoch-below-floor" => {
            block_on(floors.raise_epoch_floor(&fx.scope_id, 5)).unwrap();
        }
        "unseal:seal-open-failed" => {
            let last = candidate.envelope.read_sealed.len() - 1;
            candidate.envelope.read_sealed[last] ^= 0x01;
        }
        "unseal:hpke-open-failed" => {
            tamper_seed_blob = true;
        }
        "unseal:duplicate-id" => {
            candidate.envelope =
                fx.envelope_with_read_sealed(fx.seal_read_plaintext(&duplicate_id_plaintext()));
        }
        "unseal:duplicate-ipns-name" => {
            candidate.envelope = fx.envelope_with_read_sealed(
                fx.seal_read_plaintext(&duplicate_ipns_name_plaintext()),
            );
        }
        other => panic!("unknown matrix row: {other}"),
    }

    let reader = ReaderContext {
        owner_identity: &fx.owner_identity_verifier,
        scope_id: fx.scope_id,
        read_key: &fx.read_key,
        parent_node_seed: reader_parent_seed.as_ref(),
        seed_blob: Some(fx.owner_seed_blob(tamper_seed_blob)),
    };
    // The matrix asserts only the adoption verdict.
    block_on(adopt(&floors, &reader, &candidate)).map(|(adopted, _)| adopted)
}

#[test]
fn six_stage_matrix_matches_the_design_table() {
    let mut observed: BTreeSet<String> = BTreeSet::new();
    for (name, expect) in MATRIX {
        let result = run_matrix_case(name);
        match expect {
            Expect::Accept => {
                let adopted = result
                    .unwrap_or_else(|e| panic!("row `{name}` must accept, got rejection: {e}"));
                assert_eq!(adopted.sequence, 1, "row `{name}`");
                assert_eq!(adopted.epoch, 1, "row `{name}`");
            }
            Expect::Reject(stage, check) => {
                let err = result.expect_err(&format!("row `{name}` must reject"));
                let rejection = err.rejection().unwrap_or_else(|| {
                    panic!("row `{name}` must be a trust rejection, not a seam error")
                });
                assert_eq!(rejection.stage, *stage, "row `{name}` stage");
                assert_eq!(rejection.check(), *check, "row `{name}` named error");
                observed.insert(rejection.check().to_string());
            }
        }
    }

    // Anti-vacuity: the run exercised exactly the reject surface — every row
    // ran (or the loop would have panicked) and no check is missing or extra.
    let expected: BTreeSet<String> = MATRIX_REJECT_SURFACE
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        observed, expected,
        "the matrix run must exercise exactly the design reject surface"
    );
}

#[test]
fn every_gate_stage_is_pinned_by_a_matrix_reject_row() {
    let stages: BTreeSet<&str> = MATRIX
        .iter()
        .filter_map(|(_, e)| match e {
            Expect::Reject(stage, _) => Some(stage.name()),
            Expect::Accept => None,
        })
        .collect();
    let all: BTreeSet<&str> = GateStage::ALL.iter().map(|s| s.name()).collect();
    assert_eq!(
        stages, all,
        "each of the six stages must have at least one reject row"
    );
}

#[test]
fn matrix_table_and_reject_surface_mirror_one_to_one() {
    let from_table: BTreeSet<&str> = MATRIX
        .iter()
        .filter_map(|(_, e)| match e {
            Expect::Reject(_, check) => Some(*check),
            Expect::Accept => None,
        })
        .collect();
    let surface: BTreeSet<&str> = MATRIX_REJECT_SURFACE.iter().copied().collect();
    assert_eq!(
        from_table, surface,
        "the matrix table's reject checks must mirror the reject surface 1:1"
    );
}

#[test]
fn foreign_scope_label_rejected_at_stage_six_binding() {
    // Resolver binding (#745/#756): the record is a fully valid scope root sealed
    // for its own scope and the reader's read_key opens it (the scope UUID is not
    // in the read-key KDF) — only the reader's `scope_id`, the trusted parent-index
    // label, is foreign. Adopting under it would dedup/rotate the WRONG scope key,
    // a silent revocation hole, so stage 6 binds `envelope.scope` to
    // `reader.scope_id` and fails closed.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let candidate = fx.candidate(1);

    let foreign_scope = [0xEE; 16];
    assert_ne!(foreign_scope, fx.scope_id, "the label must actually differ");
    let reader = ReaderContext {
        owner_identity: &fx.owner_identity_verifier,
        scope_id: foreign_scope,
        read_key: &fx.read_key,
        parent_node_seed: None,
        seed_blob: Some(fx.owner_seed_blob(false)),
    };

    let err = block_on(adopt(&floors, &reader, &candidate))
        .expect_err("a foreign scope label must be rejected");
    let rejection = err
        .rejection()
        .expect("a trust rejection, not a seam error");
    assert_eq!(rejection.stage, GateStage::Unseal, "stage-6 binding");
    assert_eq!(rejection.check(), "seal-open-failed");
}

#[test]
fn no_reject_check_is_an_engine_invented_crypto_code() {
    let core: BTreeSet<&str> = TrustViolation::CHECKS.iter().copied().collect();
    let floor: BTreeSet<&str> = FLOOR_VERDICTS.iter().copied().collect();
    for check in MATRIX_REJECT_SURFACE {
        assert!(
            core.contains(check) || floor.contains(check),
            "`{check}` must be a core TrustViolation or an engine floor verdict — never an engine-invented crypto code"
        );
    }
    // The only non-core checks are exactly the two floor verdicts.
    let non_core: BTreeSet<&str> = MATRIX_REJECT_SURFACE
        .iter()
        .copied()
        .filter(|c| !core.contains(c))
        .collect();
    assert_eq!(
        non_core, floor,
        "the only engine-domain reject checks are the two floor verdicts"
    );
}

// ---------------------------------------------------------------------------
// The floor-law scenarios — mirrored 1:1 from the floor law (#39 D4 / #38 D4).
// ---------------------------------------------------------------------------

/// The five floor-law rules, each exercised by [`run_floor_scenario`].
const FLOOR_LAW_RULES: &[&str] = &[
    "advance-only-on-aad-confirmed-unseal",
    "cold-seed-from-repoint",
    "pointer-write-epoch-advances-on-sight",
    "grant-blob-epoch-advisory-only",
    "floorstore-regression-fail-closed",
];

fn run_floor_scenario(rule: &str) {
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let name_bytes = fx.name.as_str().as_bytes();

    match rule {
        "advance-only-on-aad-confirmed-unseal" => {
            // A confirmed adopt advances both floors.
            block_on(adopt(&floors, &fx.reader(), &fx.candidate(1))).expect("adopts");
            assert_eq!(
                block_on(sequence_floor(&floors, name_bytes)).unwrap(),
                Some(1)
            );
            assert_eq!(
                block_on(read_epoch_floor(&floors, &fx.scope_id)).unwrap(),
                Some(1)
            );

            // A newer record whose body does NOT unseal must move no floor.
            let mut broken = fx.candidate(2);
            let last = broken.envelope.read_sealed.len() - 1;
            broken.envelope.read_sealed[last] ^= 0x01;
            let err = block_on(adopt(&floors, &fx.reader(), &broken)).unwrap_err();
            assert_eq!(err.rejection().unwrap().check(), "seal-open-failed");
            assert_eq!(
                block_on(sequence_floor(&floors, name_bytes)).unwrap(),
                Some(1),
                "a failed unseal must not advance the sequence floor despite a newer sequence"
            );
            assert_eq!(
                block_on(read_epoch_floor(&floors, &fx.scope_id)).unwrap(),
                Some(1)
            );
        }
        "cold-seed-from-repoint" => {
            let pointer_read_key = [0x8A; 32];
            let repoint = RepointObject {
                scope_id: fx.scope_id,
                current_root: fx.name.clone(),
                write_epoch: 7,
                min_read_epoch: 3,
                prev_root: None,
            };
            let sealed = seal_pointer_payload(
                &pointer_read_key,
                &NONCE_POINTER,
                V,
                &fx.owner_identity,
                &repoint,
            );

            // Owner-vouched: opens under the owner identity, then seeds.
            let opened = open_pointer_payload(
                &pointer_read_key,
                V,
                &fx.scope_id,
                &fx.owner_identity_verifier,
                &sealed,
            )
            .expect("owner-signed re-point opens");
            block_on(cold_seed(&floors, &opened)).unwrap();
            assert_eq!(
                block_on(read_epoch_floor(&floors, &fx.scope_id)).unwrap(),
                Some(3),
                "read-epoch floor cold-seeds from minReadEpoch"
            );
            assert_eq!(
                block_on(write_epoch_floor(&floors, &fx.scope_id)).unwrap(),
                Some(7),
                "write-epoch floor cold-seeds from writeEpoch"
            );

            // Fail-closed: a non-owner re-point never authenticates, so nothing
            // seeds (identity-signature-invalid, floors untouched).
            let untouched = InMemoryFloorStore::default();
            let foreign = EcdsaSigner::from_scalar(&[0x1D; 32]).unwrap();
            let err = open_pointer_payload(
                &pointer_read_key,
                V,
                &fx.scope_id,
                &foreign.verifying_key(),
                &sealed,
            )
            .expect_err("a non-owner re-point must fail closed");
            assert_eq!(err.check(), "identity-signature-invalid");
            assert_eq!(
                block_on(read_epoch_floor(&untouched, &fx.scope_id)).unwrap(),
                None,
                "a rejected re-point moves no floor"
            );
        }
        "pointer-write-epoch-advances-on-sight" => {
            assert_eq!(
                block_on(advance_write_epoch_on_sight(&floors, &fx.scope_id, 5)).unwrap(),
                5
            );
            assert_eq!(
                block_on(advance_write_epoch_on_sight(&floors, &fx.scope_id, 3)).unwrap(),
                5,
                "a writeEpoch at or below the durable floor is a monotonic no-op"
            );
            assert_eq!(
                block_on(advance_write_epoch_on_sight(&floors, &fx.scope_id, 9)).unwrap(),
                9
            );
        }
        "grant-blob-epoch-advisory-only" => {
            // A grant blob claims epoch 99, but the record's AAD-confirmed
            // envelope epoch is 1 — the floor advances to 1, never to 99.
            let recipient_tag = [0x7A; 32];
            let grant_aad = AadContext {
                v: V,
                id: fx.root_id,
                scope: fx.scope_id,
                epoch: fx.epoch,
                struct_tag: STRUCT_TAG_GRANT_BLOB,
            };
            let payload = GrantBlobPayload::new(fx.scope_seed, None, 99, [0x7B; 32]);
            let blob =
                seal_grant_blob(&fx.owner_enc.public(), &EPH_GRANT, &grant_aad, &payload).unwrap();
            let input = StructureSigInput::over_ciphertext(
                fx.scope_id,
                fx.epoch,
                STRUCT_TAG_GRANT_BLOB,
                Some(recipient_tag),
                &blob.ciphertext,
            );
            let signed_blob = SignedGrantBlob {
                tag: recipient_tag,
                enc: blob.enc,
                ciphertext: blob.ciphertext.clone(),
                signature: sign_structure(&fx.owner_pseudonym, &input).to_bytes(),
                unknown: PreservedFields::new(),
            };
            let mut candidate = fx.candidate(1);
            candidate.grant_section.grant_blobs.push(signed_blob);

            block_on(adopt(&floors, &fx.reader(), &candidate)).expect("adopts");
            assert_eq!(
                block_on(read_epoch_floor(&floors, &fx.scope_id)).unwrap(),
                Some(1),
                "the floor advances to the AAD-confirmed envelope epoch, not the grant blob's claim"
            );
            let opened =
                open_grant_blob(&fx.owner_enc, &blob.enc, &grant_aad, &blob.ciphertext).unwrap();
            assert_eq!(
                opened.epoch, 99,
                "the grant blob really carried epoch 99 — advisory, and it moved no floor"
            );
        }
        "floorstore-regression-fail-closed" => {
            // Seed the read-epoch floor high, then prove a below-floor record is
            // rejected AND the durable floor never regresses.
            block_on(floors.raise_epoch_floor(&fx.scope_id, 5)).unwrap();
            let err = block_on(adopt(&floors, &fx.reader(), &fx.candidate(1))).unwrap_err();
            let rejection = err.rejection().unwrap();
            assert_eq!(rejection.stage, GateStage::Epoch);
            assert_eq!(rejection.check(), "epoch-below-floor");
            assert_eq!(
                block_on(floors.raise_epoch_floor(&fx.scope_id, 2)).unwrap(),
                5,
                "a raise below the stored floor is a fail-closed no-op keeping the max"
            );
            assert_eq!(
                block_on(read_epoch_floor(&floors, &fx.scope_id)).unwrap(),
                Some(5)
            );
        }
        other => panic!("unknown floor-law rule: {other}"),
    }
}

#[test]
fn floor_law_scenarios_match_the_design_table() {
    for rule in FLOOR_LAW_RULES {
        run_floor_scenario(rule);
    }
}

#[test]
fn every_floor_law_rule_is_named_and_covered() {
    // The scenario runner recognizes exactly the design's rule set — any rule
    // added to the table without an arm panics, any arm without a table entry
    // is never covered.
    let rules: BTreeSet<&str> = FLOOR_LAW_RULES.iter().copied().collect();
    assert_eq!(
        rules.len(),
        FLOOR_LAW_RULES.len(),
        "no duplicate rule names"
    );
    assert_eq!(
        FLOOR_LAW_RULES.len(),
        5,
        "the floor law has exactly five rules: advance-on-unseal, cold-seed, writeEpoch-on-sight, blob-epoch-advisory, regression-fail-closed"
    );
}

// ---------------------------------------------------------------------------
// The simulation harness — N engines on one fake record store, virtual time,
// adversarial replay / transplant / re-sign.
// ---------------------------------------------------------------------------

#[test]
fn simulation_n_engines_one_record_store_adversarial() {
    let world = FakeWorld::new();
    let owner_device = world.device(b"owner-pk");
    let reader_device = world.device(b"reader-pk");
    let fx = Fixture::new();
    let endpoint = world.record_store.endpoints()[0].clone();
    let routing_key = fx.name.as_str().to_string();

    // A valid seq-1 record on the shared network adopts on every device.
    world
        .record_store
        .seed_record(&endpoint, &routing_key, fx.record_bytes(1));
    for device in [&owner_device, &reader_device] {
        let bytes = block_on(device.record_store.get_record(
            &endpoint,
            &routing_key,
            MAX_RECORD_BYTES,
        ))
        .unwrap()
        .expect("record present on the shared store");
        let candidate = fx.candidate_with_record(bytes);
        let (adopted, _) = block_on(adopt(&device.floor_store, &fx.reader(), &candidate))
            .expect("a shared valid record adopts on every device");
        assert_eq!(adopted.sequence, 1);
    }

    // Virtual time is one shared timeline.
    world.scheduler.advance(SyncTimingProfile::CI.poll_cadence);
    assert_eq!(owner_device.scheduler.now(), reader_device.scheduler.now());

    // Replay: adopt a newer record, then the adversary re-seeds the old one.
    world
        .record_store
        .seed_record(&endpoint, &routing_key, fx.record_bytes(2));
    let newer = block_on(owner_device.record_store.get_record(
        &endpoint,
        &routing_key,
        MAX_RECORD_BYTES,
    ))
    .unwrap()
    .unwrap();
    block_on(adopt(
        &owner_device.floor_store,
        &fx.reader(),
        &fx.candidate_with_record(newer),
    ))
    .expect("the newer record adopts");

    world
        .record_store
        .seed_record(&endpoint, &routing_key, fx.record_bytes(1));
    let replayed = block_on(owner_device.record_store.get_record(
        &endpoint,
        &routing_key,
        MAX_RECORD_BYTES,
    ))
    .unwrap()
    .unwrap();
    let err = block_on(adopt(
        &owner_device.floor_store,
        &fx.reader(),
        &fx.candidate_with_record(replayed),
    ))
    .unwrap_err();
    assert_eq!(
        err.rejection().unwrap().check(),
        "sequence-not-newer",
        "a replayed older record is a fail-closed rejection, never a silent no-op"
    );

    // Re-sign: a fresh device cold-seeds its read floor from an owner re-point
    // at minReadEpoch 2; a revokee re-signs a valid old-epoch(1) record.
    let victim = world.device(b"victim-pk");
    let pointer_read_key = [0x8A; 32];
    let repoint = RepointObject {
        scope_id: fx.scope_id,
        current_root: fx.name.clone(),
        write_epoch: 2,
        min_read_epoch: 2,
        prev_root: None,
    };
    let sealed = seal_pointer_payload(
        &pointer_read_key,
        &NONCE_POINTER,
        V,
        &fx.owner_identity,
        &repoint,
    );
    let opened = open_pointer_payload(
        &pointer_read_key,
        V,
        &fx.scope_id,
        &fx.owner_identity_verifier,
        &sealed,
    )
    .unwrap();
    block_on(cold_seed(&victim.floor_store, &opened)).unwrap();
    let err = block_on(adopt(&victim.floor_store, &fx.reader(), &fx.candidate(3))).unwrap_err();
    assert_eq!(
        err.rejection().unwrap().check(),
        "epoch-below-floor",
        "a revokee's validly re-signed old-epoch record fails the advanced floor"
    );

    // Transplant: a signature made over the history-link tag, planted in the
    // owner-blob slot. The gate recomputes the owner-blob preimage (fixed tag by
    // enumeration position) and the transplanted signature fails.
    let mut transplanted = fx.candidate(1);
    let history_tag_sig = sign_structure(
        &fx.owner_pseudonym,
        &StructureSigInput::over_ciphertext(
            fx.scope_id,
            fx.epoch,
            STRUCT_TAG_HISTORY_LINK,
            None,
            &fx.owner_blob_ct,
        ),
    )
    .to_bytes();
    transplanted.grant_section.owner_blob.signature = history_tag_sig;
    let err = block_on(adopt(
        &reader_device.floor_store,
        &fx.reader(),
        &transplanted,
    ))
    .unwrap_err();
    assert_eq!(
        err.rejection().unwrap().check(),
        "structure-signature-invalid",
        "a transplanted structure signature is rejected by core's tag-bound preimage"
    );
}

#[test]
fn non_empty_history_link_authenticates_and_rejects_tamper_and_replay() {
    // Every other fixture leaves history_links empty, so the STRUCT_TAG_HISTORY_LINK
    // recompute-and-verify loop is exercised here over a populated list (#687).
    let fx = Fixture::new();
    let sealed = b"prior-write-epoch-history-link".to_vec();
    let sign_link = |epoch: u64, bytes: &[u8]| -> [u8; 64] {
        sign_structure(
            &fx.owner_pseudonym,
            &StructureSigInput::over_ciphertext(
                fx.scope_id,
                epoch,
                STRUCT_TAG_HISTORY_LINK,
                None,
                bytes,
            ),
        )
        .to_bytes()
    };

    // Valid link signed over the envelope epoch passes through the loop.
    let mut candidate = fx.candidate(1);
    candidate.grant_section.history_links.push(SignedSealed {
        sealed: sealed.clone(),
        signature: sign_link(fx.epoch, &sealed),
        unknown: PreservedFields::new(),
    });
    block_on(adopt(
        &InMemoryFloorStore::default(),
        &fx.reader(),
        &candidate,
    ))
    .expect("valid non-empty history link adopts");

    // Tamper: mutate the sealed bytes but keep the old signature.
    let mut tampered = fx.candidate(1);
    let mut bad = sealed.clone();
    bad[0] ^= 0xFF;
    tampered.grant_section.history_links.push(SignedSealed {
        sealed: bad,
        signature: sign_link(fx.epoch, &sealed),
        unknown: PreservedFields::new(),
    });
    let rej = block_on(adopt(
        &InMemoryFloorStore::default(),
        &fx.reader(),
        &tampered,
    ))
    .unwrap_err();
    let rej = rej.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "structure-signature-invalid");

    // Cross-epoch replay: a link validly signed for a neighbouring epoch fails the
    // gate's recompute at the authenticated envelope epoch.
    let mut replayed = fx.candidate(1);
    replayed.grant_section.history_links.push(SignedSealed {
        sealed: sealed.clone(),
        signature: sign_link(fx.epoch + 1, &sealed),
        unknown: PreservedFields::new(),
    });
    let rej = block_on(adopt(
        &InMemoryFloorStore::default(),
        &fx.reader(),
        &replayed,
    ))
    .unwrap_err();
    let rej = rej.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "structure-signature-invalid");
}

// ---------------------------------------------------------------------------
// Trust-boundary hardening: ascent authority, cross-epoch structure replay, and
// seed-blob envelope binding + read-key cross-check (blueprint/engine.md §405-408).
// ---------------------------------------------------------------------------

#[test]
fn ascent_authority_is_reader_derived_not_candidate_supplied() {
    // The attacker seals a well-formed ascent link from a seed IT chose; the
    // reader's real ancestor seed is different. The gate re-derives the expected
    // keypair from reader state (not the candidate), so the check mismatches —
    // the vacuous "producer picks its own seed and passes" is closed.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let mut candidate = fx.candidate(1);
    candidate.grant_section.ascent_link = Some(fx.ascent_link_under(&[0xAB; 32]));
    let mut reader = fx.reader();
    let wrong_seed = [0xCD; 32];
    reader.parent_node_seed = Some(&wrong_seed);
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "ascent-link-mismatch");
}

#[test]
fn ascent_present_without_reader_seed_fails_closed() {
    // An ascent link present with no reader ancestor seed cannot be verified —
    // fail closed, never adopt on an unverifiable link.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let mut candidate = fx.candidate(1);
    candidate.grant_section.ascent_link = Some(fx.ascent_link_under(&[0xAB; 32]));
    let reader = fx.reader();
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "ascent-link-mismatch");
}

#[test]
fn an_unsigned_ascent_link_is_a_signature_verdict_before_it_is_an_authority_one() {
    // The ascent link is doubly checked, and the signature half runs first: an
    // unsigned link is `structure-signature-invalid` even when the reader also
    // has no ancestor seed to derive authority from.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let mut candidate = fx.candidate(1);
    let mut link = fx.ascent_link_under(&[0xAB; 32]);
    link.signature[0] ^= 0xFF;
    candidate.grant_section.ascent_link = Some(link);
    let err = block_on(adopt(&floors, &fx.reader(), &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "structure-signature-invalid");
}

#[test]
fn ascent_adopts_when_reader_seed_matches_sealed_link() {
    // Positive: the reader's ancestor seed re-derives the sealed keypair, so the
    // link verifies and the record adopts.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let parent_seed = [0xAB; 32];
    let mut candidate = fx.candidate(1);
    candidate.grant_section.ascent_link = Some(fx.ascent_link_under(&parent_seed));
    let mut reader = fx.reader();
    reader.parent_node_seed = Some(&parent_seed);
    let (adopted, _) = block_on(adopt(&floors, &reader, &candidate)).expect("valid ascent adopts");
    assert_eq!(adopted.sequence, 1);
}

#[test]
fn ascent_link_aad_must_bind_to_the_envelope() {
    // The link's public half derives from the reader's real parent seed (the
    // derive half passes) and its structure signature is valid, but it was
    // HPKE-sealed under a foreign-epoch AAD. The gate rebuilds the AAD from the
    // authenticated envelope, so the HPKE open fails the tag — fail closed.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let parent_seed = [0xAB; 32];
    let foreign_aad = AadContext {
        v: V,
        id: fx.root_id,
        scope: fx.scope_id,
        epoch: fx.epoch + 1,
        struct_tag: STRUCT_TAG_ASCENT_LINK,
    };
    let mut candidate = fx.candidate(1);
    candidate.grant_section.ascent_link = Some(fx.ascent_link_under_aad(&parent_seed, foreign_aad));
    let mut reader = fx.reader();
    reader.parent_node_seed = Some(&parent_seed);
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "hpke-open-failed");
}

#[test]
fn ascent_link_rogue_seed_fails_read_key_cross_check() {
    // The link opens cleanly (real parent seed, envelope-matching AAD) but a
    // rogue override seed was sealed to the PUBLISHED ascent public key — it does
    // not derive this scope root's read key. Attributable abuse, not adoption.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let parent_seed = [0xAB; 32];
    let rogue = OverrideSeedPayload::new([0xEE; 32], fx.epoch);
    let mut candidate = fx.candidate(1);
    candidate.grant_section.ascent_link =
        Some(fx.ascent_link_full(&parent_seed, fx.ascent_aad(), rogue));
    let mut reader = fx.reader();
    reader.parent_node_seed = Some(&parent_seed);
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "ascent-link-mismatch");
}

#[test]
fn ascent_link_stale_epoch_payload_rejected() {
    // The link opens and carries the real scope seed (so the read-key derive
    // matches), but its payload epoch is stale vs the envelope — a cross-epoch
    // ascent seed. The epoch bind rejects it.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let parent_seed = [0xAB; 32];
    let stale = OverrideSeedPayload::new(fx.scope_seed, fx.epoch + 1);
    let mut candidate = fx.candidate(1);
    candidate.grant_section.ascent_link =
        Some(fx.ascent_link_full(&parent_seed, fx.ascent_aad(), stale));
    let mut reader = fx.reader();
    reader.parent_node_seed = Some(&parent_seed);
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "ascent-link-mismatch");
}

#[test]
fn cross_epoch_structure_replay_rejected_at_grant_section() {
    // A new record at epoch 2 carrying an authentic owner-signed structure from
    // the OLD epoch 1 (same scope, same pseudonym): the signature verifies, so
    // only the envelope-binding cross-check rejects the cross-epoch replay.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let folder = ReadBody::Folder {
        created_at: 0,
        modified_at: 0,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let envelope_e2 = seal_read_body(
        &fx.read_key,
        &NONCE_READ_BODY,
        V,
        fx.root_id,
        fx.scope_id,
        2,
        &folder,
    )
    .expect("epoch-2 folder seals");
    // The gate recomputes each preimage at the envelope's epoch, so there is no
    // caller-asserted epoch to trust (#687).
    let mut candidate = fx.candidate(1);
    candidate.envelope = envelope_e2;
    let err = block_on(adopt(&floors, &fx.reader(), &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "structure-signature-invalid");
}

#[test]
fn swapped_structure_ciphertext_rejected_at_grant_section() {
    // #687: the owner-blob signature is authentically the committed owner
    // pseudonym's, over the ORIGINAL ciphertext at the correct scope/epoch — but
    // the grant section presents a DIFFERENT ciphertext. The gate recomputes
    // `H(ciphertext)` from the actual bytes, so the signed hash no longer
    // matches. (Before the fix the gate trusted a caller-supplied hash and this
    // swap adopted.)
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let mut candidate = fx.candidate(1);
    candidate.grant_section.owner_blob.ciphertext[0] ^= 0xFF;
    let err = block_on(adopt(&floors, &fx.reader(), &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(
        rej.check(),
        "structure-signature-invalid",
        "a swapped ciphertext must fail the recomputed structure-signature hash"
    );
}

#[test]
fn tampered_owner_write_blob_signature_rejected_at_grant_section() {
    // A present owner-write-blob with a broken structure signature is a
    // whole-record trust violation, never staleness — the gate authenticates it
    // beside the owner blob.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let mut candidate = fx.candidate(1);
    candidate
        .grant_section
        .owner_write_blob
        .as_mut()
        .expect("fixture authors an owner-write-blob")
        .signature[0] ^= 0xFF;
    let err = block_on(adopt(&floors, &fx.reader(), &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::GrantSection);
    assert_eq!(rej.check(), "structure-signature-invalid");
}

#[test]
fn absent_owner_write_blob_still_adopts() {
    // The field is optional (additive wire evolution): a record predating the tag
    // carries `None` and adopts on its other structures unchanged.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let mut candidate = fx.candidate(1);
    candidate.grant_section.owner_write_blob = None;
    let (adopted, _) =
        block_on(adopt(&floors, &fx.reader(), &candidate)).expect("adopts without it");
    assert_eq!(adopted.sequence, 1);
}

#[test]
fn seed_blob_foreign_scope_aad_rejected_at_unseal() {
    // The seed blob is HPKE-wrapped to the reader's real enc subkey but sealed
    // under a foreign scope AAD — it would open, yet it is not this envelope's
    // seed source. Fail closed on the AAD cross-check.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let foreign_aad = AadContext {
        v: V,
        id: fx.root_id,
        scope: [0xEE; 16],
        epoch: fx.epoch,
        struct_tag: STRUCT_TAG_OWNER_BLOB,
    };
    let mut reader = fx.reader();
    reader.seed_blob = Some(fx.owner_seed_blob_with_aad(foreign_aad));
    let candidate = fx.candidate(1);
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::Unseal);
    assert_eq!(rej.check(), "hpke-open-failed");
}

#[test]
fn seed_blob_wrong_seed_fails_read_key_cross_check() {
    // The blob opens cleanly (real AAD, real enc subkey) but carries a wrong
    // scope seed that does not derive the reader's read key — an attributable
    // seed disagreement, not silent staleness.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let mut reader = fx.reader();
    reader.seed_blob = Some(fx.owner_seed_blob_wrong_seed([0xAB; 32]));
    let candidate = fx.candidate(1);
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::Unseal);
    assert_eq!(rej.check(), "seal-open-failed");
}

#[test]
fn seed_blob_correct_seed_derives_read_key_and_adopts() {
    // Positive: the default owner blob carries the real scope seed under the real
    // scope/epoch/v AAD — the cross-check passes and the record adopts.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let (adopted, _) = block_on(adopt(&floors, &fx.reader(), &fx.candidate(1))).expect("adopts");
    assert_eq!(adopted.sequence, 1);
    assert_eq!(adopted.epoch, 1);
}

#[test]
fn envelope_scope_must_equal_reader_scope() {
    // The read body is sealed under a FOREIGN scope with the reader's real read
    // key (the scope UUID is not in the read-key KDF, so it still opens), and the
    // envelope is labeled that foreign scope — while the reader is scope A. The
    // grant section's structures are re-signed at the foreign scope so stage 3
    // passes and the stage-6 reader-scope precondition is the sole rejection.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let foreign_scope = [0xEE; 16];
    let folder = ReadBody::Folder {
        created_at: 0,
        modified_at: 0,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let envelope_b = seal_read_body(
        &fx.read_key,
        &NONCE_READ_BODY,
        V,
        fx.root_id,
        foreign_scope,
        fx.epoch,
        &folder,
    )
    .expect("foreign-scope folder seals under the reader's read key");
    let mut candidate = fx.candidate(1);
    candidate.envelope = envelope_b;
    let resign = |tag: u8, ct: &[u8]| {
        sign_structure(
            &fx.owner_pseudonym,
            &StructureSigInput::over_ciphertext(foreign_scope, fx.epoch, tag, None, ct),
        )
        .to_bytes()
    };
    let owner_ct = candidate.grant_section.owner_blob.ciphertext.clone();
    candidate.grant_section.owner_blob.signature = resign(STRUCT_TAG_OWNER_BLOB, &owner_ct);
    let owner_write = candidate
        .grant_section
        .owner_write_blob
        .as_mut()
        .expect("fixture authors an owner-write-blob");
    owner_write.signature = resign(STRUCT_TAG_OWNER_WRITE_BLOB, &owner_write.ciphertext.clone());
    let wb_sealed = candidate.grant_section.write_body.sealed.clone();
    candidate.grant_section.write_body.signature = resign(STRUCT_TAG_WRITE_BODY, &wb_sealed);
    let err = block_on(adopt(&floors, &fx.reader(), &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::Unseal);
    assert_eq!(rej.check(), "seal-open-failed");
}

#[test]
fn seed_blob_aad_id_must_equal_envelope_id() {
    // The blob is wrapped to the reader's real enc subkey with the right
    // scope/epoch/v, but names a different node id than the envelope — a
    // wrong-node transplant, fail-closed.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let wrong_id_aad = AadContext {
        v: V,
        id: [0xDD; 16],
        scope: fx.scope_id,
        epoch: fx.epoch,
        struct_tag: STRUCT_TAG_OWNER_BLOB,
    };
    let mut reader = fx.reader();
    reader.seed_blob = Some(fx.owner_seed_blob_with_aad(wrong_id_aad));
    let candidate = fx.candidate(1);
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::Unseal);
    assert_eq!(rej.check(), "hpke-open-failed");
}

#[test]
fn seed_blob_aad_struct_tag_must_match_blob_type() {
    // An owner blob whose AAD carries the grant-blob tag: domain separation is
    // broken, fail-closed even though it is wrapped to the reader's enc subkey.
    let fx = Fixture::new();
    let floors = InMemoryFloorStore::default();
    let wrong_tag_aad = AadContext {
        v: V,
        id: fx.root_id,
        scope: fx.scope_id,
        epoch: fx.epoch,
        struct_tag: STRUCT_TAG_GRANT_BLOB,
    };
    let mut reader = fx.reader();
    reader.seed_blob = Some(fx.owner_seed_blob_with_aad(wrong_tag_aad));
    let candidate = fx.candidate(1);
    let err = block_on(adopt(&floors, &reader, &candidate)).unwrap_err();
    let rej = err.rejection().unwrap();
    assert_eq!(rej.stage, GateStage::Unseal);
    assert_eq!(rej.check(), "hpke-open-failed");
}

// ---------------------------------------------------------------------------
// reseal → adopt, with the two planes' clocks apart.
//
// A read-only rotation advances the read epoch and leaves the write epoch
// standing (the write KDF takes no epoch), so a real scope root's structures
// sit under three clocks: the envelope's read epoch, the write plane's own, and
// each carried history link's minting epoch. The gate recomputes every
// structure signature at the envelope epoch.
// ---------------------------------------------------------------------------

const RESEAL_READ_EPOCH: u64 = 5;
const RESEAL_WRITE_EPOCH: u64 = 1;
const RESEAL_PREV_EPOCH: u64 = 4;
const RESEAL_OLDEST_EPOCH: u64 = 3;
const RESEAL_WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];

/// The scope root a twice-rotated scope publishes: `reseal_scope_root`'s own
/// output at read epoch 5 over a write plane still at epoch 1, carrying the
/// history link the previous cut minted at read epoch 4.
struct ResealedFixture {
    owner_identity: EcdsaSigner,
    owner_pseudonym: Ed25519Signer,
    owner_enc: X25519Secret,
    scope_id: [u8; 16],
    read_key: [u8; 32],
    ipns_signer: Ed25519Signer,
    name: IpnsName,
    section: GrantSection,
    envelope: Envelope,
}

impl ResealedFixture {
    fn new() -> Self {
        let owner_identity = EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid scalar");
        let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let owner_enc = X25519Secret::from_scalar([0x33; 32]);
        // A scope root's node id IS its scope id — what every AAD here binds.
        let scope_id = [0x44; 16];
        let pointer_read_key = [0x88; 32];
        let epoch_three_seed = [0x63; 32];
        let epoch_four_seed = [0x64; 32];
        let epoch_five_seed = [0x65; 32];

        // The write KDF takes no epoch — which is why the write plane's clock is
        // free to stand still under a read rotation.
        let write_seed = kdf::write_seed(&RESEAL_WRITE_SCOPE_SEED, &scope_id);
        let ipns_signer = kdf::ipns_keypair(write_seed.as_bytes());
        let name = IpnsName::from_public_key(&ipns_signer.verifying_key());
        let commitment = GrantSetCommitment {
            ipns_name: name.as_str().as_bytes().to_vec(),
            owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
            entries: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let commitment_sig = sign_grant_set(&owner_identity, &commitment)
            .expect("signs")
            .to_compact();

        let owner_enc_pub = owner_enc.public();
        let identity = ScopeRootIdentity {
            v: V,
            scope_id,
            ipns_name: name.as_str().as_bytes(),
            owner_enc_pub: &owner_enc_pub,
            parent_node_seed: None,
            pseudonym_signer: &owner_pseudonym,
        };
        let committed = CommittedSet {
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &[],
            write_history_link: b"",
            direct_child_scope_index: &[],
        };
        let reseal = |read_epoch: u64,
                      override_seed: &[u8; 32],
                      prev: PrevEpochSeed<'_>,
                      carried: &[SignedSealed]| {
            reseal_scope_root(
                &mut SeededEntropy::new(read_epoch),
                &identity,
                &ResealSeeds {
                    override_seed,
                    read_epoch,
                    prev: Some(prev),
                    write_scope_seed: &RESEAL_WRITE_SCOPE_SEED,
                    write_epoch: RESEAL_WRITE_EPOCH,
                    pointer_read_key: &pointer_read_key,
                },
                &committed,
                carried,
            )
            .expect("re-seals")
        };

        let prior = reseal(
            RESEAL_PREV_EPOCH,
            &epoch_four_seed,
            PrevEpochSeed {
                seed: &epoch_three_seed,
                epoch: RESEAL_OLDEST_EPOCH,
            },
            &[],
        );
        let section = reseal(
            RESEAL_READ_EPOCH,
            &epoch_five_seed,
            PrevEpochSeed {
                seed: &epoch_four_seed,
                epoch: RESEAL_PREV_EPOCH,
            },
            &prior.history_links,
        );

        let node_seed = kdf::node_seed(&epoch_five_seed, &scope_id);
        let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
        let folder = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let envelope = seal_read_body(
            &read_key,
            &NONCE_READ_BODY,
            V,
            scope_id,
            scope_id,
            RESEAL_READ_EPOCH,
            &folder,
        )
        .expect("the root body seals");

        Self {
            owner_identity,
            owner_pseudonym,
            owner_enc,
            scope_id,
            read_key,
            ipns_signer,
            name,
            section,
            envelope,
        }
    }

    fn candidate(&self) -> Candidate {
        Candidate {
            name: self.name.clone(),
            record_bytes: IpnsRecord::create_v2(&self.ipns_signer, RECORD_VALUE, 1, TTL_NANOS, EOL)
                .marshal(),
            grant_section: self.section.clone(),
            envelope: self.envelope.clone(),
        }
    }

    /// The owner's seed source, taken from the re-sealed section's own owner
    /// blob under the AAD the re-seal bound it at.
    fn seed_blob(&self) -> SeedBlob<'_> {
        SeedBlob::Owner {
            enc_secret: &self.owner_enc,
            enc: self.section.owner_blob.enc,
            ciphertext: self.section.owner_blob.ciphertext.clone(),
            aad: AadContext {
                v: V,
                id: self.scope_id,
                scope: self.scope_id,
                epoch: RESEAL_READ_EPOCH,
                struct_tag: STRUCT_TAG_OWNER_BLOB,
            },
        }
    }

    /// A detached structure signature over `ct` at `epoch` — the preimage a
    /// producer that bound the wrong clock would have signed.
    fn sign_at(&self, epoch: u64, tag: u8, ct: &[u8]) -> [u8; 64] {
        sign_structure(
            &self.owner_pseudonym,
            &StructureSigInput::over_ciphertext(self.scope_id, epoch, tag, None, ct),
        )
        .to_bytes()
    }

    fn adopt(&self, candidate: &Candidate) -> Result<Adopted, GateError> {
        let floors = InMemoryFloorStore::default();
        let owner = self.owner_identity.verifying_key();
        let reader = ReaderContext {
            owner_identity: &owner,
            scope_id: self.scope_id,
            read_key: &self.read_key,
            parent_node_seed: None,
            seed_blob: Some(self.seed_blob()),
        };
        block_on(adopt(&floors, &reader, candidate)).map(|(adopted, _)| adopted)
    }
}

#[test]
fn a_resealed_root_adopts_with_the_read_and_write_epochs_apart() {
    let fx = ResealedFixture::new();
    assert_ne!(
        RESEAL_READ_EPOCH, RESEAL_WRITE_EPOCH,
        "a read-only rotation is exactly where the two planes' clocks diverge"
    );
    assert_eq!(
        fx.section.history_links.len(),
        2,
        "a twice-rotated scope carries a link minted at an earlier epoch"
    );
    let adopted = fx
        .adopt(&fx.candidate())
        .expect("the re-sealed root adopts");
    assert_eq!(adopted.epoch, RESEAL_READ_EPOCH);
    assert_eq!(adopted.sequence, 1);
}

/// Assert `candidate` is a whole-record stage-3 trust violation.
fn assert_structure_signature_invalid(fx: &ResealedFixture, candidate: &Candidate) {
    let err = fx.adopt(candidate).expect_err("a wrong-clock signature");
    let rejection = err
        .rejection()
        .expect("a trust rejection, not a seam error");
    assert_eq!(rejection.stage, GateStage::GrantSection);
    assert_eq!(rejection.check(), "structure-signature-invalid");
}

#[test]
fn a_write_body_signed_at_the_write_epoch_is_a_whole_record_rejection() {
    let fx = ResealedFixture::new();
    let mut candidate = fx.candidate();
    let sealed = candidate.grant_section.write_body.sealed.clone();
    candidate.grant_section.write_body.signature =
        fx.sign_at(RESEAL_WRITE_EPOCH, STRUCT_TAG_WRITE_BODY, &sealed);
    assert_structure_signature_invalid(&fx, &candidate);
}

#[test]
fn an_owner_write_blob_signed_at_the_write_epoch_is_a_whole_record_rejection() {
    // The other dual-clock structure: its sealed AAD binds the write epoch, its
    // signature the read epoch.
    let fx = ResealedFixture::new();
    let mut candidate = fx.candidate();
    let blob = candidate
        .grant_section
        .owner_write_blob
        .as_mut()
        .expect("the re-seal authors one");
    let ciphertext = blob.ciphertext.clone();
    blob.signature = fx.sign_at(RESEAL_WRITE_EPOCH, STRUCT_TAG_OWNER_WRITE_BLOB, &ciphertext);
    assert_structure_signature_invalid(&fx, &candidate);
}

#[test]
fn a_carried_history_link_left_at_its_minting_epoch_is_a_whole_record_rejection() {
    let fx = ResealedFixture::new();
    let mut candidate = fx.candidate();
    let carried = candidate.grant_section.history_links[0].sealed.clone();
    candidate.grant_section.history_links[0].signature =
        fx.sign_at(RESEAL_PREV_EPOCH, STRUCT_TAG_HISTORY_LINK, &carried);
    assert_structure_signature_invalid(&fx, &candidate);
}
