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

use core::cell::RefCell;

use cipherbox_core::content::{decode_content_cid_str, verify_cid};
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
    /// The candidate a rejected [`Adopter::adopt`] assembled, kept so the
    /// equal-floor `Current` recovery ([`Adopter::recover_own_write_seed`])
    /// reuses it instead of re-fetching the same head block per resolve tick.
    assembled: RefCell<Option<Candidate>>,
    /// A head block the caller already holds ([`Self::hold_local_head`]).
    local_head: RefCell<Option<LocalHead>>,
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
            assembled: RefCell::new(None),
            local_head: RefCell::new(None),
        }
    }

    /// Supply a head block the caller already holds, so a self-adopt of our own
    /// just-published record skips the fetch. The CID the signed record anchors
    /// still decides: a block that does not match it is ignored.
    pub fn hold_local_head(&self, head: LocalHead) {
        *self.local_head.borrow_mut() = Some(head);
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
        // Steps 1-4 are the shared head-envelope assembly; the sequence is
        // discarded — the gate re-verifies the record from scratch.
        let local = self.local_head.borrow().clone();
        let (_sequence, envelope) =
            assemble_head_envelope(self.gateway, self.http, name, record_bytes, local.as_ref())
                .await?;

        // Step 5 — decode the grant section.
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
        // The recovered scope read seed rides the outcome on a gate pass — the
        // engine's per-scope seed cell feeds the child read pipeline from it.
        let read_scope_seed = Zeroizing::new(*payload.override_seed());
        let node_seed = kdf::node_seed(&read_scope_seed, &env.id);
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
        let (adopted, _) = match adopt(self.floors, &reader, &candidate).await {
            Ok(pass) => pass,
            Err(err) => {
                // Keep the candidate for the equal-floor recovery path — it
                // re-resolves the same head CID otherwise.
                *self.assembled.borrow_mut() = Some(candidate);
                return Err(err);
            }
        };

        let write_scope_seed = match &candidate.grant_section.owner_write_blob {
            // Re-authorable, NOT a trust failure — held keyless.
            None => None,
            Some(owb) => self.recover_write_scope_seed(env, owb).await?,
        };
        Ok(AdoptOutcome {
            adopted,
            write_scope_seed,
            node_id: env.id,
            read_scope_seed: Some(read_scope_seed),
        })
    }

    async fn recover_own_write_seed(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<Option<([u8; 16], Zeroizing<[u8; 32]>)>, SeamError> {
        // Recovery is fail-open, never a trust verdict: an unopenable/absent blob
        // yields `Ok(None)`, held keyless (#752 F3: a Current never hardens).
        // Reuse the candidate the rejected `adopt` assembled for these same
        // bytes; assembling again re-fetches the head block.
        let cached = self
            .assembled
            .borrow_mut()
            .take()
            .filter(|c| c.name == *name && c.record_bytes == record_bytes);
        let candidate = match cached {
            Some(candidate) => candidate,
            None => match self.assemble_candidate(name, record_bytes).await {
                Ok(candidate) => candidate,
                Err(GateError::Seam(seam)) => return Err(seam),
                Err(GateError::Rejected(_)) => return Ok(None),
            },
        };
        let Some(owb) = &candidate.grant_section.owner_write_blob else {
            return Ok(None);
        };
        // Map a recovery seam to availability, never a trust verdict.
        let seed = match self
            .recover_write_scope_seed(&candidate.envelope, owb)
            .await
        {
            Ok(seed) => seed,
            Err(GateError::Seam(seam)) => return Err(seam),
            Err(GateError::Rejected(_)) => return Ok(None),
        };
        Ok(seed.map(|seed| (candidate.envelope.id, seed)))
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

/// A head block the caller already holds — the write path's own just-uploaded
/// block. Supplying it lets a self-adopt skip the fetch (never the gate): the
/// block is still checked against the CID the signed record anchors, so a
/// mismatched local head falls back to the network rather than being trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHead {
    /// The block's content CID, as the record `Value` spells it.
    pub cid: String,
    /// The head block bytes.
    pub block: Vec<u8>,
}

/// The head-envelope assembly shared by both adopters: verify the record to
/// read its signed `/ipfs/<cid>` head anchor (trust is the gate's — this only
/// extracts the anchor), take the head block fail-closed on a CID mismatch, and
/// decode the envelope. Returns the verified record sequence alongside it.
pub(crate) async fn assemble_head_envelope<H: Http>(
    gateway: &Gateway,
    http: &H,
    name: &IpnsName,
    record_bytes: &[u8],
    local: Option<&LocalHead>,
) -> Result<(u64, Envelope), GateError> {
    let verified = IpnsRecord::unmarshal(record_bytes)
        .and_then(|record| record.verify(name))
        .map_err(assembly_reject)?;

    let cid_str = head_cid_from_value(&verified.value)
        .ok_or_else(|| assembly_reject(Malformed::ContentCidStrMalformed.into()))?;
    let expected_cid = decode_content_cid_str(&cid_str).map_err(assembly_reject)?;

    let block = match local.filter(|held| held.cid == cid_str) {
        Some(held) => {
            verify_cid(&expected_cid, &held.block).map_err(assembly_reject)?;
            held.block.clone()
        }
        None => read_block(gateway, http, &cid_str, &expected_cid, ContentPlane::Root)
            .await
            .map_err(map_read_error)?,
    };

    let envelope = decode_envelope(&block).map_err(assembly_reject)?;
    Ok((verified.sequence, envelope))
}

/// A fail-closed content-plane assembly failure: the head the signed record
/// anchors is malformed or tampered, so the record's content anchor is
/// untrustworthy. Assembly runs before the gate's six stages, so it surfaces as
/// a `RecordVerify` rejection carrying the verbatim core check (the check name
/// carries the real detail).
pub(super) fn assembly_reject(e: CodecError) -> GateError {
    reject(GateStage::RecordVerify, e)
}

pub(super) fn reject(stage: GateStage, e: CodecError) -> GateError {
    GateError::Rejected(GateRejection {
        stage,
        reason: RejectionReason::Trust(e),
    })
}

/// Map a content-read failure: a CID mismatch/tamper is a fail-closed trust
/// violation surfaced verbatim; no source or an over-cap body is availability (a
/// retryable seam), never a trust verdict (`content/read.rs`).
pub(super) fn map_read_error(e: ReadError) -> GateError {
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

    use cipherbox_core::seal::{Envelope, GrantSection};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::content::GatewaySource;
    use crate::seams::HttpResponse;
    use crate::session::SessionIdentity;
    use crate::testkit::fakes::{InMemoryFloorStore, ScriptedHttp};
    use crate::testkit::{
        OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootFixture, OwnerRootSpec, block_on, owner_root_fixture,
    };

    const TTL_NANOS: u64 = 2_000_000_000;
    const EOL: &str = "2099-01-01T00:00:00Z";
    /// The write epoch the fixture authors its owner-write-blob at.
    const OWB_WRITE_EPOCH: u64 = 3;

    /// A valid owner-root scope fixture: standalone owner keys (no session
    /// derives them) plus the head block the record anchors.
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
        /// `owb_write_epoch` (the write plane's own clock).
        fn build(owb_write_epoch: Option<u64>) -> Self {
            let owner_identity = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
            // Distinct recipient key per authored write epoch — the owner-write-blob's
            // HPKE key derives from `owner_enc` alone under a fixed ephemeral
            // ([`OwnerRootSpec`]), so one key across epochs reuses the keystream.
            let mut enc_scalar = [0x33u8; 32];
            enc_scalar[0] = enc_scalar[0]
                .wrapping_add(u8::try_from(owb_write_epoch.unwrap_or(0)).unwrap_or(u8::MAX));
            let owner_enc = X25519Secret::from_scalar(enc_scalar);
            let scope_id = [0x44; 16];
            let root_id = [0x55; 16];

            let OwnerRootFixture {
                name,
                grant_section,
                envelope,
                head_block,
                head_cid_str,
            } = owner_root_fixture(OwnerRootSpec {
                owner_identity: &owner_identity,
                owner_enc: &owner_enc.public(),
                scope_id,
                root_id,
                children: Vec::new(),
                owner_write_blob_epoch: owb_write_epoch,
            });

            Self {
                owner_identity_verifier: owner_identity.verifying_key(),
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
            let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &self.root_id);
            let signer = kdf::ipns_keypair(write_seed.as_bytes());
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
        assert_eq!(
            outcome.read_scope_seed.as_deref(),
            Some(&[0x66u8; 32]),
            "a gate pass surfaces the owner-blob scope read seed"
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
        assert_eq!(*seed, OWNER_ROOT_WRITE_SCOPE_SEED);
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

    #[test]
    fn recover_own_write_seed_returns_the_seed_for_our_own_current_root() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let (node_id, seed) = block_on(adopter.recover_own_write_seed(&fx.name, &fx.record(1)))
            .expect("recovery is fail-open, never an error")
            .expect("the owner recovers its own write seed on the Current path");
        assert_eq!(node_id, fx.root_id, "keyed by the envelope id");
        assert_eq!(*seed, OWNER_ROOT_WRITE_SCOPE_SEED);
        // The recovered seed reproduces the record's IPNS routing name.
        let signer = SessionIdentity::write_name_signer(&seed, &fx.root_id);
        assert_eq!(IpnsName::from_public_key(&signer.verifying_key()), fx.name);
    }

    #[test]
    fn equal_floor_recovery_reuses_the_candidate_adopt_assembled() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        // Steady state: the durable sequence floor already sits at the record's
        // sequence, so adopt rejects equal-floor and recovery runs next.
        block_on(floors.raise_sequence_floor(fx.name.as_str().as_bytes(), 1)).unwrap();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let record = fx.record(1);
        match block_on(adopter.adopt(&fx.name, &record)) {
            Err(GateError::Rejected(r)) => assert_eq!(r.check(), "sequence-not-newer"),
            Ok(_) => panic!("an equal-floor record must reject at the sequence stage"),
            Err(GateError::Seam(e)) => panic!("expected a rejection, got seam {e}"),
        }
        let (_, seed) = block_on(adopter.recover_own_write_seed(&fx.name, &record))
            .expect("recovery is fail-open, never an error")
            .expect("the owner recovers its write seed from the reused candidate");
        assert_eq!(*seed, OWNER_ROOT_WRITE_SCOPE_SEED);
        assert_eq!(
            http.requests().len(),
            1,
            "the head block is fetched once; recovery reuses adopt's candidate"
        );
    }

    #[test]
    fn recover_own_write_seed_is_none_when_the_blob_is_absent_stale_or_transplanted() {
        // Missing owner-write-blob → held keyless, never a seed.
        let fx = Fixture::new();
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        assert!(
            block_on(adopter.recover_own_write_seed(&fx.name, &fx.record(1)))
                .expect("fail-open")
                .is_none(),
            "no owner-write-blob ⇒ no recovered seed"
        );

        // Stale blob one write epoch below the floor → won't open → None.
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH - 1));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        assert!(
            block_on(adopter.recover_own_write_seed(&fx.name, &fx.record(1)))
                .expect("fail-open")
                .is_none(),
            "a stale owner-write-blob below the floor recovers no seed"
        );

        // Transplanted: the floor names a different write epoch than the blob was
        // sealed under → the recomputed AAD never opens it → None.
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH + 1);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        assert!(
            block_on(adopter.recover_own_write_seed(&fx.name, &fx.record(1)))
                .expect("fail-open")
                .is_none(),
            "a transplanted owner-write-blob recovers no seed"
        );
    }
}
