//! The production [`Adopter`]: cold-start content-plane assembly (blueprint/
//! engine.md "Resolve/publish pipeline", "Adoption gate and floors").
//!
//! The resolve pipeline routes every fetched record through [`Adopter::adopt`];
//! this is the concrete owner-arm implementation for the vault's own root. It
//! assembles the content-plane [`Candidate`] — recover the head CID anchor from
//! the signed record, fetch the head block fail-closed on a CID mismatch, decode
//! the envelope and its grant section — then builds the owner's [`ReaderContext`]
//! and calls [`gate::adopt`](crate::gate::adopt). The adopter adds **no** trust
//! logic: it only assembles inputs; every trust decision (commitment, structure
//! signatures, seed cross-checks, read-body unseal, floor law) stays in the gate.
//!
//! Cold-start scope (#789): read-plane assembly plus owner cold-start
//! write-plane recovery (E8) — the owner-write-blob hands the owner the
//! write-scope seed it cannot re-derive. The owner-seed-cache tri-way abuse
//! cross-check is a later slice; a tampered owner blob still fails closed here at
//! the grant-section structure signature and the read-body unseal.

use cipherbox_core::content::decode_content_cid_str;
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, Envelope, STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_OWNER_WRITE_BLOB, SignedOwnerWriteBlob,
    decode_envelope, decode_grant_section, grant_section_bytes, open_owner_blob,
    open_owner_write_blob,
};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use super::publish::head_cid_from_value;
use super::resolve::{AdoptOutcome, Adopter};
use crate::content::{ContentPlane, Gateway, ReadError, read_block};
use crate::gate::{
    Candidate, GateError, GateRejection, GateStage, ReaderContext, RejectionReason, SeedBlob,
    adopt, floor,
};
use crate::seams::{FloorStore, Http, SeamError};

/// The cold-start owner-root [`Adopter`]. Borrows the content-plane seams and
/// the owner's identity/sealing material from the live session; the vault owner
/// is the terminal owner of its own key material, so nothing is zeroized here.
pub struct RootAdopter<'a, H, F> {
    /// Content read sources (accelerator + public fallbacks).
    gateway: &'a Gateway,
    /// The HTTP seam the content fetch rides.
    http: &'a H,
    /// The durable floor store the gate reads and advances.
    floors: &'a F,
    /// The owner's X25519 encryption secret — opens the root owner blob to
    /// recover the scope seed.
    owner_enc_secret: &'a X25519Secret,
    /// The contact-anchored owner identity verifier (the gate's stage-2 anchor).
    owner_identity: &'a EcdsaVerifier,
    /// The vault root scope id (the AAD scope binding and the read-epoch floor
    /// key). A resolved root whose envelope scope disagrees is a scope transplant
    /// the gate rejects fail-closed.
    root_scope_id: [u8; 16],
}

impl<'a, H, F> RootAdopter<'a, H, F> {
    /// Assemble the cold-start owner-root adopter over the borrowed seams and the
    /// session's owner material.
    pub fn new(
        gateway: &'a Gateway,
        http: &'a H,
        floors: &'a F,
        owner_enc_secret: &'a X25519Secret,
        owner_identity: &'a EcdsaVerifier,
        root_scope_id: [u8; 16],
    ) -> Self {
        Self {
            gateway,
            http,
            floors,
            owner_enc_secret,
            owner_identity,
            root_scope_id,
        }
    }
}

impl<H: Http, F: FloorStore> RootAdopter<'_, H, F> {
    /// Steps 1-5: turn a fetched record into a content-plane [`Candidate`].
    /// Verifies the record only to read its signed head anchor (the gate
    /// re-verifies from scratch); fetches the head block fail-closed on a CID
    /// mismatch; decodes the envelope and its grant section.
    async fn assemble_candidate(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<Candidate, GateError> {
        // Step 1 — verify to read the signed `/ipfs/<cid>` value (the head
        // anchor). Trust is the gate's; this only extracts the anchor.
        let verified = IpnsRecord::unmarshal(record_bytes)
            .and_then(|record| record.verify(name))
            .map_err(assembly_reject)?;

        // Step 2/3 — recover the head CID string and the binary CIDv1 anchor.
        let cid_str = head_cid_from_value(&verified.value)
            .ok_or_else(|| assembly_reject(Malformed::ContentCidStrMalformed.into()))?;
        let expected_cid = decode_content_cid_str(&cid_str).map_err(assembly_reject)?;

        // Step 4 — fetch the head block (dag-cbor root), fail-closed on mismatch.
        let block = read_block(
            self.gateway,
            self.http,
            &cid_str,
            &expected_cid,
            ContentPlane::Root,
        )
        .await
        .map_err(map_read_error)?;

        // Step 5 — decode the envelope and its grant section.
        let envelope = decode_envelope(&block).map_err(assembly_reject)?;
        let section_bytes = grant_section_bytes(&envelope).ok_or_else(|| {
            assembly_reject(
                Malformed::MissingField {
                    field: "grantSection",
                }
                .into(),
            )
        })?;
        let grant_section = decode_grant_section(section_bytes).map_err(assembly_reject)?;

        Ok(Candidate {
            name: name.clone(),
            record_bytes: record_bytes.to_vec(),
            grant_section,
            envelope,
        })
    }
}

impl<H: Http, F: FloorStore> Adopter for RootAdopter<'_, H, F> {
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<AdoptOutcome, GateError> {
        let candidate = self.assemble_candidate(name, record_bytes).await?;

        // Step 6 — owner-blob ReaderContext. The vault owner recovers its own root
        // scope seed from the record's owner blob (the read-plane seed source) and
        // derives the read key; the gate re-opens the same blob, cross-checks the
        // seed derives this key, and unseals the read-body.
        let env = &candidate.envelope;
        let owner_blob = &candidate.grant_section.owner_blob;
        let owner_blob_aad = AadContext {
            v: env.v,
            id: env.id,
            scope: env.scope,
            epoch: env.epoch,
            struct_tag: STRUCT_TAG_OWNER_BLOB,
        };
        let payload = open_owner_blob(
            self.owner_enc_secret,
            &owner_blob.enc,
            &owner_blob_aad,
            &owner_blob.ciphertext,
        )
        .map_err(|e| reject(GateStage::Unseal, e))?;

        // The derived read key is secret; this fn is its terminal owner, so it
        // zeroizes on drop (the gate borrows it and never zeroizes a caller buffer).
        let node_seed = kdf::node_seed(payload.override_seed(), &env.id);
        let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());

        let reader = ReaderContext {
            owner_identity: self.owner_identity,
            scope_id: self.root_scope_id,
            read_key: &read_key,
            parent_node_seed: None,
            seed_blob: Some(SeedBlob::Owner {
                enc_secret: self.owner_enc_secret,
                enc: owner_blob.enc,
                ciphertext: owner_blob.ciphertext.clone(),
                aad: owner_blob_aad,
            }),
        };

        // Step 7 — the gate owns all trust; the owner reader surfaces no gate write
        // seed (that arm is the write-grantee's). The owner's own write-scope seed
        // is recovered from the owner-write-blob below for cold-start self-renewal.
        let (adopted, _) = adopt(self.floors, &reader, &candidate).await?;

        let write_scope_seed = match &candidate.grant_section.owner_write_blob {
            // Re-authorable, NOT a trust failure — held keyless.
            None => None,
            Some(owb) => self.recover_write_scope_seed(env, owb).await?,
        };
        Ok(AdoptOutcome {
            adopted,
            write_scope_seed,
            node_id: env.id,
        })
    }
}

impl<H: Http, F: FloorStore> RootAdopter<'_, H, F> {
    /// Recover the owner's write-scope seed (a KDF non-edge the owner cannot
    /// re-derive) from the record's owner-write-blob for cold-start write-plane
    /// self-renewal (blueprint/core.md "Grant section").
    ///
    /// The AAD binds the durable, monotonic write-epoch floor — cold-seeded from
    /// the owner-vouched pointer before `resolve` runs (`sync/boot.rs`). A stale
    /// owner-write-blob authored below the floor cannot open under the newer
    /// floor's AAD, so an older write epoch can never be replayed (#752 rollback
    /// defense). No known write floor, an open failure, or an epoch mismatch ⇒
    /// re-authorable, held keyless — never a `Rejected` verdict, no abuse event.
    /// The gate independently authenticates this blob's structure signature at the
    /// read epoch (`gate/adoption.rs`); this only reads the seed it wraps.
    async fn recover_write_scope_seed(
        &self,
        env: &Envelope,
        owb: &SignedOwnerWriteBlob,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError> {
        let Some(wf) = floor::write_epoch_floor(self.floors, &self.root_scope_id)
            .await
            .map_err(GateError::Seam)?
        else {
            return Ok(None);
        };
        let aad = AadContext {
            v: env.v,
            id: env.id,
            scope: env.scope,
            epoch: wf,
            struct_tag: STRUCT_TAG_OWNER_WRITE_BLOB,
        };
        let Ok(payload) =
            open_owner_write_blob(self.owner_enc_secret, &owb.enc, &aad, &owb.ciphertext)
        else {
            return Ok(None);
        };
        // Belt-and-suspenders: the HPKE AAD already binds `epoch == wf`, so a
        // successful open implies equality; a mismatch means something is off —
        // treat as re-authorable, never adopt the seed.
        if payload.write_epoch != wf {
            return Ok(None);
        }
        Ok(Some(Zeroizing::new(*payload.write_scope_seed())))
    }
}

/// A fail-closed content-plane assembly failure: the head the signed record
/// anchors is malformed or tampered, so the record's content anchor is
/// untrustworthy. Assembly runs before the gate's six stages, so it surfaces as
/// a `RecordVerify` rejection carrying the verbatim core check (the check name
/// carries the real detail).
fn assembly_reject(e: CodecError) -> GateError {
    reject(GateStage::RecordVerify, e)
}

fn reject(stage: GateStage, e: CodecError) -> GateError {
    GateError::Rejected(GateRejection {
        stage,
        reason: RejectionReason::Trust(e),
    })
}

/// Map a content-read failure: a CID mismatch/tamper is a fail-closed trust
/// violation surfaced verbatim; no source or an over-cap body is availability (a
/// retryable seam), never a trust verdict (`content/read.rs`).
fn map_read_error(e: ReadError) -> GateError {
    match e {
        ReadError::TrustViolation(codec) => assembly_reject(codec),
        ReadError::Unavailable => GateError::Seam(SeamError::new("head block unavailable")),
        ReadError::TooLarge { size, limit } => GateError::Seam(SeamError::new(format!(
            "head block exceeds the content cap ({size} > {limit})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::codec::Value;
    use cipherbox_core::content::{compute_cid, encode_content_cid_str};
    use cipherbox_core::seal::{
        Envelope, GrantSection, GrantSetCommitment, OverrideSeedPayload, OwnerWriteBlobPayload,
        ReadBody, STRUCT_TAG_WRITE_BODY, SignedOwnerBlob, SignedSealed, StructureSigInput,
        WriteBody, encode_envelope, encode_grant_section, encode_write_body, seal, seal_owner_blob,
        seal_owner_write_blob, seal_read_body, sign_grant_set, sign_structure,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use crate::content::{DAG_ROOT_CODEC, GatewaySource};
    use crate::seams::HttpResponse;
    use crate::session::SessionIdentity;
    use crate::testkit::block_on;
    use crate::testkit::fakes::{InMemoryFloorStore, ScriptedHttp};

    const V: u64 = 1;
    const TTL_NANOS: u64 = 2_000_000_000;
    const EOL: &str = "2099-01-01T00:00:00Z";
    const NONCE_READ_BODY: [u8; 24] = [11u8; 24];
    const NONCE_WRITE_BODY: [u8; 24] = [22u8; 24];
    const EPH_OWNER: [u8; 32] = [3u8; 32];
    const EPH_OWNER_WRITE: [u8; 32] = [4u8; 32];
    /// The write-scope seed the fixture's owner-write-blob wraps (matches the seed
    /// that derives the record's IPNS name).
    const WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
    /// The write epoch the fixture authors its owner-write-blob at.
    const OWB_WRITE_EPOCH: u64 = 3;

    /// A valid owner-root scope fixture: the owner keys plus the head block (an
    /// envelope carrying its grant section) the record anchors.
    struct Fixture {
        owner_identity_verifier: EcdsaVerifier,
        owner_enc: X25519Secret,
        scope_id: [u8; 16],
        root_id: [u8; 16],
        name: IpnsName,
        grant_section: GrantSection,
        envelope: Envelope,
        head_block: Vec<u8>,
        head_cid_str: String,
    }

    impl Fixture {
        fn new() -> Self {
            Self::build(None)
        }

        /// Build the fixture, optionally authoring a real owner-write-blob at
        /// `owb_write_epoch` (the write plane's own clock; its AAD binds that
        /// epoch, its structure signature the read epoch — mirrors reseal).
        fn build(owb_write_epoch: Option<u64>) -> Self {
            let owner_identity = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
            let owner_identity_verifier = owner_identity.verifying_key();
            let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
            let owner_enc = X25519Secret::from_scalar([0x33; 32]);

            let scope_id = [0x44; 16];
            let root_id = [0x55; 16];
            let scope_seed = [0x66; 32];
            let write_scope_seed = [0x77; 32];
            let epoch = 1;

            let node_seed = kdf::node_seed(&scope_seed, &root_id);
            let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
            let write_seed = kdf::write_seed(&write_scope_seed, &root_id);
            let ipns_signer = kdf::ipns_keypair(write_seed.as_bytes());
            let name = IpnsName::from_public_key(&ipns_signer.verifying_key());
            let write_key = kdf::write_key(write_seed.as_bytes());

            let sign = |tag: u8, ct: &[u8]| -> [u8; 64] {
                let input = StructureSigInput::over_ciphertext(scope_id, epoch, tag, None, ct);
                sign_structure(&owner_pseudonym, &input).to_bytes()
            };

            // Owner blob — the seed-bearing structure AND the owner's seed source.
            let override_payload = OverrideSeedPayload::new(scope_seed, epoch);
            let owner_blob_aad = AadContext {
                v: V,
                id: root_id,
                scope: scope_id,
                epoch,
                struct_tag: STRUCT_TAG_OWNER_BLOB,
            };
            let sealed_owner = seal_owner_blob(
                &owner_enc.public(),
                &EPH_OWNER,
                &owner_blob_aad,
                &override_payload,
            );
            let owner_blob = SignedOwnerBlob {
                signature: sign(STRUCT_TAG_OWNER_BLOB, &sealed_owner.ciphertext),
                enc: sealed_owner.enc,
                ciphertext: sealed_owner.ciphertext.clone(),
                unknown: Vec::new(),
            };

            // Write body — a second seed-bearing structure the gate authenticates.
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
                &encode_write_body(&WriteBody {
                    grant_ledger: Vec::new(),
                    write_history_link: Vec::new(),
                    direct_child_scope_index: Vec::new(),
                    unknown: Vec::new(),
                })
                .unwrap(),
            );
            let write_body = SignedSealed {
                signature: sign(STRUCT_TAG_WRITE_BODY, &write_body_sealed),
                sealed: write_body_sealed,
                unknown: Vec::new(),
            };

            // Owner-write-blob — the write-scope seed sealed to the owner. AAD
            // binds the WRITE epoch; the structure signature binds the read epoch.
            let owner_write_blob = owb_write_epoch.map(|we| {
                let payload = OwnerWriteBlobPayload::new(write_scope_seed, we);
                let owb_aad = AadContext {
                    v: V,
                    id: root_id,
                    scope: scope_id,
                    epoch: we,
                    struct_tag: STRUCT_TAG_OWNER_WRITE_BLOB,
                };
                let sealed = seal_owner_write_blob(
                    &owner_enc.public(),
                    &EPH_OWNER_WRITE,
                    &owb_aad,
                    &payload,
                );
                SignedOwnerWriteBlob {
                    signature: sign(STRUCT_TAG_OWNER_WRITE_BLOB, &sealed.ciphertext),
                    enc: sealed.enc,
                    ciphertext: sealed.ciphertext,
                    unknown: Vec::new(),
                }
            });

            let commitment = GrantSetCommitment {
                ipns_name: name.as_str().as_bytes().to_vec(),
                owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
                entries: Vec::new(),
                unknown: Vec::new(),
            };
            let commitment_sig = sign_grant_set(&owner_identity, &commitment)
                .unwrap()
                .to_compact();
            let grant_section = GrantSection {
                commitment,
                commitment_sig,
                grant_blobs: Vec::new(),
                owner_blob,
                owner_write_blob,
                ascent_link: None,
                history_links: Vec::new(),
                write_body,
                unknown: Vec::new(),
            };

            let folder = ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children: Vec::new(),
                unknown: Vec::new(),
            };
            let mut envelope = seal_read_body(
                &read_key,
                &NONCE_READ_BODY,
                V,
                root_id,
                scope_id,
                epoch,
                &folder,
            )
            .unwrap();
            envelope.unknown.push((
                "grantSection".to_string(),
                Value::Bytes(encode_grant_section(&grant_section).unwrap()),
            ));

            let head_block = encode_envelope(&envelope);
            let head_cid_str = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));

            Self {
                owner_identity_verifier,
                owner_enc,
                scope_id,
                root_id,
                name,
                grant_section,
                envelope,
                head_block,
                head_cid_str,
            }
        }

        fn record(&self, sequence: u64) -> Vec<u8> {
            let value = format!("/ipfs/{}", self.head_cid_str);
            let signer = {
                let write_seed = kdf::write_seed(&[0x77; 32], &self.root_id);
                kdf::ipns_keypair(write_seed.as_bytes())
            };
            IpnsRecord::create_v2(&signer, value.as_bytes(), sequence, TTL_NANOS, EOL).marshal()
        }

        fn adopter<'a>(
            &'a self,
            http: &'a ScriptedHttp,
            floors: &'a InMemoryFloorStore,
            owner_identity: &'a EcdsaVerifier,
            gateway: &'a Gateway,
        ) -> RootAdopter<'a, ScriptedHttp, InMemoryFloorStore> {
            RootAdopter::new(
                gateway,
                http,
                floors,
                &self.owner_enc,
                owner_identity,
                self.scope_id,
            )
        }
    }

    fn gateway() -> Gateway {
        Gateway {
            accelerator: Some(GatewaySource {
                base_url: "https://gw.test".into(),
                bearer: None,
            }),
            public_fallbacks: Vec::new(),
        }
    }

    fn ok_response(body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body,
        }
    }

    #[test]
    fn assembles_the_expected_candidate_from_a_fixture_head_block() {
        let fx = Fixture::new();
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let candidate = block_on(adopter.assemble_candidate(&fx.name, &fx.record(1)))
            .expect("assembles a candidate");
        assert_eq!(candidate.name, fx.name);
        assert_eq!(candidate.envelope, fx.envelope);
        assert_eq!(candidate.grant_section, fx.grant_section);
        // The head block was fetched at its canonical content-CID address.
        assert!(http.requests()[0].url.contains(&fx.head_cid_str));
    }

    #[test]
    fn a_tampered_head_block_fails_closed_at_assembly() {
        let fx = Fixture::new();
        let http = ScriptedHttp::default();
        // A block that does not content-address to the record's head CID: the
        // fetch verify fails closed before any decode.
        let mut tampered = fx.head_block.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        http.enqueue_response(ok_response(tampered));
        let floors = InMemoryFloorStore::default();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        match block_on(adopter.assemble_candidate(&fx.name, &fx.record(1))) {
            Ok(_) => panic!("a tampered head block must fail closed"),
            Err(GateError::Rejected(r)) => assert_eq!(r.check(), "content-cid-mismatch"),
            Err(GateError::Seam(e)) => panic!("expected a rejection, got seam {e}"),
        }
    }

    #[test]
    fn a_gate_passing_owner_root_adopts_through_the_production_adopter() {
        let fx = Fixture::new();
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let outcome =
            block_on(adopter.adopt(&fx.name, &fx.record(1))).expect("the owner root adopts");
        assert_eq!(outcome.adopted.sequence, 1);
        assert_eq!(outcome.adopted.epoch, 1);
        assert_eq!(
            outcome.node_id, fx.root_id,
            "the scope-root id rides the outcome"
        );
        assert!(
            outcome.write_scope_seed.is_none(),
            "the owner arm surfaces no write seed (held keyless)"
        );
    }

    #[test]
    fn a_wrong_owner_identity_is_rejected_by_the_gate() {
        let fx = Fixture::new();
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        let gw = gateway();
        // A different owner identity than the one that signed the commitment: the
        // gate rejects fail-closed at commitment-verify.
        let rogue = EcdsaSigner::from_scalar(&[0x99; 32])
            .unwrap()
            .verifying_key();
        let adopter = fx.adopter(&http, &floors, &rogue, &gw);

        match block_on(adopter.adopt(&fx.name, &fx.record(1))) {
            Ok(_) => panic!("a wrong owner identity must be rejected"),
            Err(GateError::Rejected(r)) => {
                assert_eq!(r.stage, GateStage::CommitmentVerify);
                assert_eq!(r.check(), "commitment-invalid");
            }
            Err(GateError::Seam(e)) => panic!("expected a gate rejection, got seam {e}"),
        }
    }

    /// Seed the write-epoch floor to `epoch` (the cold-start seeding `sync/boot`
    /// does from the owner-vouched pointer before `resolve`).
    fn seed_write_floor(floors: &InMemoryFloorStore, scope_id: &[u8; 16], epoch: u64) {
        block_on(floor::advance_write_epoch_on_sight(floors, scope_id, epoch)).unwrap();
    }

    #[test]
    fn owner_root_with_owner_write_blob_recovers_the_write_scope_seed() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let outcome = block_on(adopter.adopt(&fx.name, &fx.record(1))).expect("adopts");
        let seed = outcome
            .write_scope_seed
            .expect("the owner recovers its write-scope seed from the owner-write-blob");
        assert_eq!(*seed, WRITE_SCOPE_SEED);
        // The recovered seed reproduces the record's IPNS routing name.
        let signer = SessionIdentity::write_name_signer(&seed, &fx.root_id);
        assert_eq!(IpnsName::from_public_key(&signer.verifying_key()), fx.name);
    }

    #[test]
    fn missing_owner_write_blob_is_held_keyless_not_a_trust_failure() {
        let fx = Fixture::new(); // owner_write_blob: None
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let outcome = block_on(adopter.adopt(&fx.name, &fx.record(1)))
            .expect("a record without an owner-write-blob still adopts");
        assert!(
            outcome.write_scope_seed.is_none(),
            "no owner-write-blob ⇒ held keyless, never a trust failure"
        );
    }

    #[test]
    fn stale_owner_write_blob_below_the_write_floor_is_ignored() {
        // Blob authored one write epoch below the durable floor: its AAD under the
        // newer floor cannot open it (#752 rollback defense) — a stale owner-write
        // -blob is re-authorable, not a rejection. This invariant holds in release.
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH - 1));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let outcome = block_on(adopter.adopt(&fx.name, &fx.record(1)))
            .expect("a stale owner-write-blob is re-authorable, never a rejection");
        assert!(
            outcome.write_scope_seed.is_none(),
            "a stale owner-write-blob below the floor yields no seed"
        );
    }

    #[test]
    fn owner_write_blob_transplanted_across_write_epoch_fails_open() {
        // The floor names a different write epoch than the blob was sealed under:
        // the recomputed AAD never opens it (adopter-layer mirror of the core
        // transplant test) ⇒ Ok(None), no rejection, no abuse event.
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH + 1);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let outcome = block_on(adopter.adopt(&fx.name, &fx.record(1)))
            .expect("a write-epoch-transplanted owner-write-blob fails open, not closed");
        assert!(
            outcome.write_scope_seed.is_none(),
            "a transplanted owner-write-blob yields no seed"
        );
    }
}
