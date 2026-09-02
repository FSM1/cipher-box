//! The production [`Adopter`]: cold-start content-plane assembly (blueprint/
//! engine.md "Resolve/publish pipeline", "Adoption gate and floors").
//!
//! The resolve pipeline routes every fetched record through [`Adopter::adopt`];
//! this is the concrete implementation for a scope root, on either entry arm
//! ([`SeedSource`]). It assembles the
//! content-plane [`Candidate`] — recover the head CID anchor from the signed
//! record, fetch the head block fail-closed on a CID mismatch, decode the
//! envelope and its grant section — then builds the reader's [`ReaderContext`]
//! and calls [`gate::adopt`](crate::gate::adopt). The adopter adds **no** trust
//! logic: it only assembles inputs; every trust decision (commitment, structure
//! signatures, seed cross-checks, read-body unseal, floor law) stays in the gate.
//!
//! Cold-start scope: read-plane assembly plus owner cold-start write-plane
//! recovery (E8) — the owner-write-blob hands the owner the write-scope seed it
//! cannot re-derive. The owner-seed-cache tri-way abuse cross-check is a later
//! slice; a tampered owner blob still fails closed here at the grant-section
//! structure signature and the read-body unseal.

use core::cell::RefCell;

use cipherbox_core::content::{decode_content_cid_str, verify_cid};
use cipherbox_core::error::{CodecError, Malformed, TrustViolation};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, Envelope, GrantSection, Permission, ReadBody, STRUCT_TAG_GRANT_BLOB,
    STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_OWNER_WRITE_BLOB, SignedOwnerWriteBlob, decode_envelope,
    decode_grant_section, grant_section_bytes, open_grant_blob, open_owner_blob,
    open_owner_write_blob, open_read_body,
};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use zeroize::Zeroizing;

use super::publish::head_cid_from_value;
use super::resolve::{AdoptOutcome, Adopter, OwnScopeMaterial};
use crate::content::limits::{MAX_RESEALABLE_ROOT_REST_BYTES, scope_root_rest_bytes};
use crate::content::{ContentPlane, Gateway, ReadError, is_plane_anchor, read_block};
use crate::gate::{
    Adopted, Candidate, GateError, GateRejection, GateStage, ReaderContext, RejectionReason,
    SeedBlob, adopt, floor,
};
use crate::grants::{recipient_blinded_tag, self_locate_signed};
use crate::seams::{FloorStore, Http, SeamError};

/// Where a reader's copy of a scope root's read seed lives in the record it is
/// gating — the one axis the owner arm and the grantee arm differ on. The
/// reader is the terminal owner of the secret each arm borrows.
enum SeedSource<'a> {
    /// The vault owner: the record's owner blob, plus its owner-write-blob for
    /// cold-start write-plane recovery.
    Owner(&'a X25519Secret),
    /// A grantee: the one grant blob filed under the blinded tag this device
    /// re-derives from its pairwise ECDH with the **verified contact's**
    /// encryption subkey — never a key the record supplies (`grants/ledger.rs`
    /// self-location). A write grant's blob also conveys the write scope seed.
    Grantee {
        /// The grantee's own X25519 encryption secret.
        enc_secret: &'a X25519Secret,
        /// The verified contact's encryption subkey: the blinded-tag ECDH peer.
        owner_enc_pub: &'a X25519Public,
    },
}

/// The cold-start scope-root [`Adopter`]. Borrows the content-plane seams and
/// the reader's identity/sealing material from the live session; a reader is the
/// terminal owner of its own key material, so nothing is zeroized here.
pub struct RootAdopter<'a, H, F> {
    /// Content read sources (accelerator + public fallbacks).
    gateway: &'a Gateway,
    /// The HTTP seam the content fetch rides.
    http: &'a H,
    /// The durable floor store the gate reads and advances.
    floors: &'a F,
    /// Where this reader's copy of the scope read seed lives in the record.
    seeds: SeedSource<'a>,
    /// The contact-anchored owner identity verifier (the gate's stage-2 anchor).
    owner_identity: &'a EcdsaVerifier,
    /// The vault root scope id (the AAD scope binding and the read-epoch floor
    /// key). A resolved root whose envelope scope disagrees is a scope transplant
    /// the gate rejects fail-closed.
    root_scope_id: [u8; 16],
    /// The candidate a rejected [`Adopter::adopt`] assembled, kept so the
    /// equal-floor `Current` recovery ([`Adopter::recover_own_scope_material`])
    /// reuses it instead of re-fetching the same head block per resolve tick.
    assembled: RefCell<Option<Candidate>>,
    /// A head block the caller already holds ([`Self::hold_local_head`]).
    local_head: RefCell<Option<LocalHead>>,
    /// The reader's own ancestor node seed for this scope root, required
    /// whenever the resolved record carries an ascent link — every interior
    /// scope root does ([`Self::under_parent_node_seed`]).
    parent_node_seed: Option<Zeroizing<[u8; 32]>>,
    /// Record bytes the caller already holds with the scope material recovered
    /// from them ([`Self::holding`]).
    held_current: Option<Vec<u8>>,
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
        Self::over(
            gateway,
            http,
            floors,
            SeedSource::Owner(owner_enc_secret),
            owner_identity,
            root_scope_id,
        )
    }

    /// The same adopter for a **grantee**: the seed comes from this device's own
    /// grant blob, and `owner_identity` stays the contact-anchored owner the
    /// gate's stage 2 verifies the commitment under.
    pub fn for_grantee(
        gateway: &'a Gateway,
        http: &'a H,
        floors: &'a F,
        enc_secret: &'a X25519Secret,
        owner_enc_pub: &'a X25519Public,
        owner_identity: &'a EcdsaVerifier,
        root_scope_id: [u8; 16],
    ) -> Self {
        Self::over(
            gateway,
            http,
            floors,
            SeedSource::Grantee {
                enc_secret,
                owner_enc_pub,
            },
            owner_identity,
            root_scope_id,
        )
    }

    fn over(
        gateway: &'a Gateway,
        http: &'a H,
        floors: &'a F,
        seeds: SeedSource<'a>,
        owner_identity: &'a EcdsaVerifier,
        root_scope_id: [u8; 16],
    ) -> Self {
        Self {
            gateway,
            http,
            floors,
            seeds,
            owner_identity,
            root_scope_id,
            assembled: RefCell::new(None),
            local_head: RefCell::new(None),
            parent_node_seed: None,
            held_current: None,
        }
    }

    /// Declare the record bytes the caller already holds for this name, with the
    /// scope material it recovered from them still in hand. An equal-floor
    /// `Current` re-resolve of exactly those bytes then recovers nothing — the
    /// record signs its head CID, so identical bytes address the identical head
    /// block and can only reproduce the seeds already held, at the cost of two
    /// HPKE opens every poll on an idle vault. `None` disables the skip.
    #[must_use]
    pub(crate) fn holding(mut self, record_bytes: Option<Vec<u8>>) -> Self {
        self.held_current = record_bytes;
        self
    }

    /// Supply the reader's ancestor node seed, `nodeSeed(parentOverrideSeed,
    /// scopeId)`. The vault root carries no ascent link and needs none; every
    /// interior scope root carries one, and the gate fails closed without the
    /// seed it derives the expected ascent keypair from.
    pub(crate) fn under_parent_node_seed(mut self, seed: Zeroizing<[u8; 32]>) -> Self {
        self.parent_node_seed = Some(seed);
        self
    }

    /// Supply a head block the caller already holds, so a self-adopt of our own
    /// just-published record skips the fetch. The CID the signed record anchors
    /// still decides: a block that does not match it is ignored.
    pub fn hold_local_head(&self, head: LocalHead) {
        *self.local_head.borrow_mut() = Some(head);
    }
}

impl<H: Http, F: FloorStore> RootAdopter<'_, H, F> {
    /// [`assemble_candidate`] over this adopter's own gateway, HTTP seam, and
    /// held local head.
    async fn assemble_candidate(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<Candidate, GateError> {
        let local = self.local_head.borrow().clone();
        assemble_candidate(self.gateway, self.http, name, record_bytes, local.as_ref()).await
    }
}

/// Steps 1-5: turn a fetched record into a content-plane [`Candidate`].
/// Verifies the record only to read its signed head anchor (the gate re-verifies
/// from scratch); fetches the head block fail-closed on a CID mismatch; decodes
/// the envelope and its grant section; and holds the root to the re-seal
/// reservation this engine's own author side enforces.
///
/// Free-standing because the accept flow assembles a candidate for a **sharer's**
/// scope root, which no reader context of this device's own anchors.
pub(crate) async fn assemble_candidate<H: Http>(
    gateway: &Gateway,
    http: &H,
    name: &IpnsName,
    record_bytes: &[u8],
    local: Option<&LocalHead>,
) -> Result<Candidate, GateError> {
    // Steps 1-4; the sequence is discarded — the gate re-verifies the record
    // from scratch. Only the block's length outlives the decode, so the buffer
    // is released rather than held beside the envelope it decoded into.
    let (_sequence, envelope, block_len) =
        assemble_head_envelope(gateway, http, name, record_bytes, local).await?;

    // Step 5 — decode the grant section.
    let section_bytes = grant_section_bytes(&envelope).ok_or_else(|| {
        assembly_reject(
            Malformed::MissingField {
                field: "grantSection",
            }
            .into(),
        )
    })?;
    let rest = scope_root_rest_bytes(block_len, section_bytes.len());
    if rest > MAX_RESEALABLE_ROOT_REST_BYTES {
        return Err(GateError::Rejected(GateRejection {
            stage: GateStage::RecordVerify,
            reason: RejectionReason::ScopeRootNotResealable {
                size: rest,
                limit: MAX_RESEALABLE_ROOT_REST_BYTES,
            },
        }));
    }
    let grant_section = decode_grant_section(section_bytes).map_err(assembly_reject)?;

    Ok(Candidate {
        name: name.clone(),
        record_bytes: record_bytes.to_vec(),
        grant_section,
        envelope,
    })
}

impl<H: Http, F: FloorStore> Adopter for RootAdopter<'_, H, F> {
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<AdoptOutcome, GateError> {
        self.adopt_root(name, record_bytes)
            .await
            .map(|(_, outcome)| outcome)
    }

    async fn recover_own_scope_material(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<Option<OwnScopeMaterial>, SeamError> {
        Ok(self
            .recover_own_scope_root(name, record_bytes)
            .await?
            .map(|root| OwnScopeMaterial {
                node_id: root.envelope.id,
                read_scope_seed: root.read_scope_seed,
                write_scope_seed: root.write_scope_seed,
                at_floor: Adopted {
                    read_body: root.read_body,
                    sequence: root.sequence,
                    epoch: root.envelope.epoch,
                },
            }))
    }
}

/// The owner's own scope root as recovered at exactly the durable sequence
/// floor: what a gate pass surfaces, off the candidate the rejected adopt
/// authenticated. Terminal owner of the recovered seeds — they zeroize on drop.
pub(crate) struct RecoveredScopeRoot {
    /// The record's envelope.
    pub(crate) envelope: Envelope,
    /// The sequence the recovery re-verified and re-imposed the floor at.
    pub(crate) sequence: u64,
    /// Its grant section, authenticated by the gate's stages 1-3.
    pub(crate) grant_section: GrantSection,
    /// The read-body the recovery re-unsealed under the recovered seed.
    pub(crate) read_body: ReadBody,
    /// The scope read seed this record's own owner blob wraps.
    pub(crate) read_scope_seed: Zeroizing<[u8; 32]>,
    /// The scope write seed, `None` when the root is held keyless.
    pub(crate) write_scope_seed: Option<Zeroizing<[u8; 32]>>,
}

impl<H: Http, F: FloorStore> RootAdopter<'_, H, F> {
    /// Recover the owner's own scope root from a record the gate rejected at
    /// **exactly** the durable sequence floor. The caller establishes that
    /// equality from the rejection ([`RejectionReason::SequenceNotNewer`] with
    /// `sequence == floor`); a strictly lower sequence is a replay and never
    /// reaches here.
    ///
    /// Fail-OPEN, never a trust verdict: anything unproved yields `Ok(None)`
    /// (a `Current` never hardens — [`Adopter::recover_own_scope_material`]).
    pub(crate) async fn recover_own_scope_root(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<Option<RecoveredScopeRoot>, SeamError> {
        // Steady state — see [`Self::holding`].
        if self.held_current.as_deref() == Some(record_bytes) {
            return Ok(None);
        }
        // Only the candidate the rejected [`Adopter::adopt`] cached for these
        // exact bytes is eligible. Nothing but a sequence-stage verdict is ever
        // cached, so the gate's stages 1-3 authenticated the grant section it
        // carries; re-assembling here would run none of them.
        let Some(candidate) = self
            .assembled
            .borrow_mut()
            .take()
            .filter(|c| c.name == *name && c.record_bytes == record_bytes)
        else {
            return Ok(None);
        };
        // Stages 4/5 did NOT run: `floor::check` returns `SequenceNotNewer`
        // before it reads the epoch floor. Re-impose both here rather than
        // trusting the caller's reading of the rejection — `AtFloor` admits only
        // the exact sequence floor, so a replay below it recovers nothing, and
        // the read-epoch floor still bars a forgery-window writer re-serving a
        // pre-rotation section at the floor.
        let Ok(sequence) = IpnsRecord::unmarshal(&candidate.record_bytes)
            .and_then(|record| record.verify(name))
            .map(|verified| verified.sequence)
        else {
            return Ok(None);
        };
        let env = &candidate.envelope;
        if let Err(rejected) = floor::check(
            self.floors,
            name.as_str().as_bytes(),
            &self.root_scope_id,
            sequence,
            env.epoch,
            floor::Strictness::AtFloor,
        )
        .await
        {
            return match rejected {
                GateError::Seam(seam) => Err(seam),
                GateError::Rejected(_) => Ok(None),
            };
        }
        // Stage 6's reader-scope binding, which did not run either.
        if env.scope != self.root_scope_id {
            return Ok(None);
        }
        let Ok(opened) = self.open_seeds(env, &candidate.grant_section, name) else {
            return Ok(None);
        };
        let OpenedSeeds {
            read_scope_seed,
            grant_write_scope_seed,
            ..
        } = opened;
        // Unseal-confirm the seed, exactly as stage 6 does for an adopt: a seed
        // that does not derive the key this record's own body opens under is not
        // this scope's seed.
        let node_seed = kdf::node_seed(&read_scope_seed, &env.id);
        let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());
        let Ok(read_body) = open_read_body(env, &read_key) else {
            return Ok(None);
        };
        // Map a recovery seam to availability, never a trust verdict.
        let write_scope_seed = match self
            .write_scope_seed(env, &candidate.grant_section, grant_write_scope_seed)
            .await
        {
            Ok(seed) => seed,
            Err(GateError::Seam(seam)) => return Err(seam),
            Err(GateError::Rejected(_)) => return Ok(None),
        };
        Ok(Some(RecoveredScopeRoot {
            envelope: candidate.envelope,
            sequence,
            grant_section: candidate.grant_section,
            read_body,
            read_scope_seed,
            write_scope_seed,
        }))
    }
}

impl<H: Http, F: FloorStore> RootAdopter<'_, H, F> {
    /// The gate pass **plus** the candidate it authenticated, for the callers
    /// that need the record's own grant section (the rotation seams' gated
    /// scope-root read) rather than only the read-body outcome.
    pub(crate) async fn adopt_root(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<(Candidate, AdoptOutcome), GateError> {
        let candidate = self.assemble_candidate(name, record_bytes).await?;

        // Step 6 — the reader's own seed source. Whichever arm supplies it, the
        // recovered seed derives the read key and the gate re-opens the same
        // blob, cross-checks the seed derives that key, and unseals the
        // read-body.
        let env = &candidate.envelope;
        let OpenedSeeds {
            blob,
            read_scope_seed,
            grant_write_scope_seed,
        } = self
            .open_seeds(env, &candidate.grant_section, name)
            .map_err(|e| reject(GateStage::Unseal, e))?;

        // The derived read key is secret; this fn is its terminal owner, so it
        // zeroizes on drop (the gate borrows it and never zeroizes a caller buffer).
        // The recovered scope read seed rides the outcome on a gate pass — the
        // engine's per-scope seed cell feeds the child read pipeline from it.
        let node_seed = kdf::node_seed(&read_scope_seed, &env.id);
        let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());

        let reader = ReaderContext {
            owner_identity: self.owner_identity,
            scope_id: self.root_scope_id,
            read_key: &read_key,
            parent_node_seed: self.parent_node_seed.as_deref(),
            seed_blob: Some(blob),
        };

        // Step 7 — the gate owns all trust. The write seed it surfaces for a
        // write grantee, and the owner-write-blob recovery below, are the same
        // capability reached through each arm's own material.
        let (adopted, _) = match adopt(self.floors, &reader, &candidate).await {
            Ok(pass) => pass,
            Err(err) => {
                // Keep the candidate for the equal-floor recovery path — it
                // re-resolves the same head CID otherwise. Only a sequence-stage
                // verdict is kept: that is the one rejection reached with stages
                // 1-3 already passed, and the recovery reads seeds straight out
                // of the grant section those stages authenticate. Caching a
                // stage-1/2/3 rejection would let a forged section reach it.
                if matches!(
                    err,
                    GateError::Rejected(GateRejection {
                        stage: GateStage::Sequence,
                        ..
                    })
                ) {
                    *self.assembled.borrow_mut() = Some(candidate);
                }
                return Err(err);
            }
        };

        let write_scope_seed = self
            .write_scope_seed(env, &candidate.grant_section, grant_write_scope_seed)
            .await?;
        let node_id = env.id;
        Ok((
            candidate,
            AdoptOutcome {
                adopted,
                write_scope_seed,
                node_id,
                read_scope_seed: Some(read_scope_seed),
            },
        ))
    }
}

/// The reader's own seed source inside one record: the blob the gate re-opens,
/// the read scope seed it wraps, and — for a write grant — the write scope seed
/// it also conveys. Terminal owner of both seeds: they zeroize on drop.
struct OpenedSeeds<'a> {
    blob: SeedBlob<'a>,
    read_scope_seed: Zeroizing<[u8; 32]>,
    /// `None` on the owner arm (whose write seed comes from the owner-write
    /// blob) and for a read-only grant.
    grant_write_scope_seed: Option<Zeroizing<[u8; 32]>>,
}

impl<H: Http, F: FloorStore> RootAdopter<'_, H, F> {
    /// Open this reader's seed source in `section` and take the seeds it wraps.
    ///
    /// A grantee locates its blob by the tag its own pairwise ECDH derives at
    /// `name`, so a section carrying no blob for this device is unopenable —
    /// the definitive revocation signal (`grants/revocation.rs`), and here a
    /// fail-closed refusal rather than a stall.
    fn open_seeds(
        &self,
        env: &Envelope,
        section: &GrantSection,
        name: &IpnsName,
    ) -> Result<OpenedSeeds<'_>, CodecError> {
        match &self.seeds {
            SeedSource::Owner(enc_secret) => {
                let blob = &section.owner_blob;
                let aad = blob_aad(env, STRUCT_TAG_OWNER_BLOB);
                let payload = open_owner_blob(enc_secret, &blob.enc, &aad, &blob.ciphertext)?;
                Ok(OpenedSeeds {
                    read_scope_seed: Zeroizing::new(*payload.override_seed()),
                    grant_write_scope_seed: None,
                    blob: SeedBlob::Owner {
                        enc_secret,
                        enc: blob.enc,
                        ciphertext: blob.ciphertext.clone(),
                        aad,
                    },
                })
            }
            SeedSource::Grantee {
                enc_secret,
                owner_enc_pub,
            } => {
                let tag =
                    recipient_blinded_tag(enc_secret, owner_enc_pub, name.as_str().as_bytes())
                        .ok_or(TrustViolation::HpkeNonContributory)?;
                // A blob at your tag is not enough: the tag must be in the
                // owner-signed commitment, whose permission — not the blob's own
                // contents — is authority (CONTEXT.md "Grant blob"; the same
                // check `grants/accept.rs` makes on first entry). Stage 2 anchors
                // that commitment to the owner identity a beat later, and a
                // record failing either is rejected whole.
                let committed = section
                    .commitment
                    .entries
                    .iter()
                    .find(|entry| entry.tag == tag)
                    .ok_or(TrustViolation::CommitmentInvalid)?;
                let blob = self_locate_signed(&section.grant_blobs, &tag)
                    .ok_or(TrustViolation::HpkeOpenFailed)?;
                let aad = blob_aad(env, STRUCT_TAG_GRANT_BLOB);
                let payload = open_grant_blob(enc_secret, &blob.enc, &aad, &blob.ciphertext)?;
                Ok(OpenedSeeds {
                    read_scope_seed: Zeroizing::new(*payload.read_scope_seed()),
                    grant_write_scope_seed: match committed.permission {
                        Permission::Write => {
                            payload.write_scope_seed().map(|seed| Zeroizing::new(*seed))
                        }
                        Permission::Read => None,
                    },
                    blob: SeedBlob::Grantee {
                        enc_secret,
                        enc: blob.enc,
                        ciphertext: blob.ciphertext.clone(),
                        aad,
                    },
                })
            }
        }
    }

    /// Recover the owner's write-scope seed (a KDF non-edge the owner cannot
    /// re-derive) from the record's owner-write-blob for cold-start write-plane
    /// self-renewal (blueprint/core.md "Grant section").
    ///
    /// The AAD binds the durable, monotonic write-epoch floor — cold-seeded from
    /// the owner-vouched pointer before `resolve` runs (`sync/boot.rs`). A stale
    /// owner-write-blob authored below the floor cannot open under the newer
    /// floor's AAD, so an older write epoch can never be replayed (rollback
    /// defense). No known write floor, an open failure, or an epoch mismatch ⇒
    /// re-authorable, held keyless — never a `Rejected` verdict, no abuse event.
    /// The gate independently authenticates this blob's structure signature at the
    /// read epoch (`gate/adoption.rs`); this only reads the seed it wraps.
    async fn recover_write_scope_seed(
        &self,
        enc_secret: &X25519Secret,
        env: &Envelope,
        owb: &SignedOwnerWriteBlob,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError> {
        let Some(wf) = floor::write_epoch_floor(self.floors, &self.root_scope_id)
            .await
            .map_err(GateError::Seam)?
        else {
            return Ok(None);
        };
        Ok(open_write_scope_seed_at(enc_secret, env, owb, wf))
    }

    /// The scope write seed this reader is entitled to: the owner recovers it
    /// from the record's owner-write-blob (a KDF non-edge it cannot re-derive),
    /// a write grantee reads it straight out of its own grant blob.
    async fn write_scope_seed(
        &self,
        env: &Envelope,
        section: &GrantSection,
        grant_write_scope_seed: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError> {
        match (&self.seeds, &section.owner_write_blob) {
            (SeedSource::Owner(enc_secret), Some(owb)) => {
                self.recover_write_scope_seed(enc_secret, env, owb).await
            }
            // Re-authorable, NOT a trust failure — held keyless.
            (SeedSource::Owner(_), None) => Ok(None),
            (SeedSource::Grantee { .. }, _) => Ok(grant_write_scope_seed),
        }
    }
}

/// Open `owb` at `write_epoch` and hand back the write scope seed it wraps, or
/// `None` when it does not open there.
///
/// `write_epoch` is the caller's authority on the write plane's clock: the
/// durable floor for a cold-start adopt, the owner-signed re-point object for a
/// resumed name wave (`net/rotation.rs`).
pub(crate) fn open_write_scope_seed_at(
    owner_enc_secret: &X25519Secret,
    env: &Envelope,
    owb: &SignedOwnerWriteBlob,
    write_epoch: u64,
) -> Option<Zeroizing<[u8; 32]>> {
    let aad = AadContext {
        v: env.v,
        id: env.id,
        scope: env.scope,
        epoch: write_epoch,
        struct_tag: STRUCT_TAG_OWNER_WRITE_BLOB,
    };
    let payload = open_owner_write_blob(owner_enc_secret, &owb.enc, &aad, &owb.ciphertext).ok()?;
    // Belt-and-suspenders: the HPKE AAD already binds the epoch, so a successful
    // open implies equality; a mismatch means something is off.
    (payload.write_epoch == write_epoch).then(|| Zeroizing::new(*payload.write_scope_seed()))
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

/// Take the head block a record anchors: verify the record to read its signed
/// `/ipfs/<cid>` anchor (trust is the gate's — this only extracts the anchor),
/// then take the block fail-closed on a CID mismatch. Returns the verified
/// record sequence alongside it. Every record family reaches its head block
/// through here, so the anchor rule has one home.
pub(crate) async fn fetch_head_block<H: Http>(
    gateway: &Gateway,
    http: &H,
    name: &IpnsName,
    record_bytes: &[u8],
    local: Option<&LocalHead>,
) -> Result<(u64, Vec<u8>), GateError> {
    let verified = IpnsRecord::unmarshal(record_bytes)
        .and_then(|record| record.verify(name))
        .map_err(assembly_reject)?;

    let cid_str = head_cid_from_value(&verified.value)
        .ok_or_else(|| assembly_reject(Malformed::ContentCidStrMalformed.into()))?;
    let expected_cid = decode_content_cid_str(&cid_str).map_err(assembly_reject)?;

    let block = match local.filter(|held| held.cid == cid_str) {
        Some(held) => {
            // A locally-held block clears the same bar as a fetched one: the
            // plane's anchor check, then the content address itself.
            if !is_plane_anchor(&cid_str, &expected_cid, ContentPlane::Root) {
                return Err(assembly_reject(TrustViolation::ContentCidMismatch.into()));
            }
            verify_cid(&expected_cid, &held.block).map_err(assembly_reject)?;
            held.block.clone()
        }
        None => read_block(gateway, http, &cid_str, &expected_cid, ContentPlane::Root)
            .await
            .map_err(map_read_error)?,
    };
    Ok((verified.sequence, block))
}

/// The head-envelope assembly shared by both adopters: [`fetch_head_block`],
/// then decode the envelope. The block's length rides out beside it, because a
/// scope root is measured against it; the buffer itself is dropped here.
pub(crate) async fn assemble_head_envelope<H: Http>(
    gateway: &Gateway,
    http: &H,
    name: &IpnsName,
    record_bytes: &[u8],
    local: Option<&LocalHead>,
) -> Result<(u64, Envelope, usize), GateError> {
    let (sequence, block) = fetch_head_block(gateway, http, name, record_bytes, local).await?;
    let envelope = decode_envelope(&block).map_err(assembly_reject)?;
    Ok((sequence, envelope, block.len()))
}

/// The structured AAD a seed-bearing structure of `env` is sealed under.
fn blob_aad(env: &Envelope, struct_tag: u8) -> AadContext {
    AadContext {
        v: env.v,
        id: env.id,
        scope: env.scope,
        epoch: env.epoch,
        struct_tag,
    }
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

    use cipherbox_core::seal::{Envelope, GrantSection, encode_envelope};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::content::root_block_cid;

    use crate::content::GatewaySource;
    use crate::seams::HttpResponse;
    use crate::session::SessionIdentity;
    use crate::testkit::fakes::{InMemoryFloorStore, ScriptedHttp};
    use crate::testkit::{
        OWNER_ROOT_EPOCH, OWNER_ROOT_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootFixture,
        OwnerRootSpec, block_on, owner_root_fixture, padding,
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
                child_scope_index: Vec::new(),
                parent_node_seed: None,
                owner_write_blob_epoch: owb_write_epoch,
                write_history_link: Vec::new(),
                grants: Vec::new(),
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
            self.record_over(&self.head_cid_str, sequence)
        }

        fn record_over(&self, cid: &str, sequence: u64) -> Vec<u8> {
            let value = format!("/ipfs/{cid}");
            let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &self.root_id);
            let signer = kdf::ipns_keypair(write_seed.as_bytes());
            IpnsRecord::create_v2(&signer, value.as_bytes(), sequence, TTL_NANOS, EOL).marshal()
        }

        /// The same scope root re-encoded with `pad` bytes of carried,
        /// cuttable unknown outside its grant section — what a foreign client
        /// this engine's own author side would refuse can publish.
        fn padded(&self, pad: usize) -> (Vec<u8>, String) {
            let mut envelope = self.envelope.clone();
            // Appended, never replaced: the grant section itself rides in
            // `unknown` under its own key.
            envelope.unknown = envelope
                .unknown
                .entries()
                .iter()
                .cloned()
                .chain(padding(pad).entries().iter().cloned())
                .collect();
            let block = encode_envelope(&envelope).expect("the padded envelope encodes");
            let cid = root_block_cid(&block);
            (block, cid)
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
            accelerator: Some(GatewaySource::public("https://gw.test")),
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
    fn a_scope_root_with_no_room_for_its_own_re_seal_is_refused_at_adoption() {
        // The produce side holds every root it authors to this budget
        // (`net/author.rs::encode_scope_root`). Adopting a foreign root over it
        // would leave the owner's own re-key refusing on that scope for ever —
        // the encode/decode asymmetry AGENTS.md rule 8 forbids.
        let fx = Fixture::new();
        let (block, cid) = fx.padded(MAX_RESEALABLE_ROOT_REST_BYTES);
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(block));
        let floors = InMemoryFloorStore::default();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let Err(GateError::Rejected(rejection)) =
            block_on(adopter.assemble_candidate(&fx.name, &fx.record_over(&cid, 1)))
        else {
            panic!("an un-resealable root must be refused as a rejection");
        };
        assert_eq!(rejection.check(), "scope-root-not-resealable");
    }

    #[test]
    fn a_scope_root_inside_the_re_seal_reservation_still_adopts() {
        // The anti-vacuity half: the budget must not refuse an ordinary root.
        let fx = Fixture::new();
        let (block, cid) = fx.padded(1024);
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(block));
        let floors = InMemoryFloorStore::default();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        assert!(
            block_on(adopter.assemble_candidate(&fx.name, &fx.record_over(&cid, 1))).is_ok(),
            "a root with room to spare must still assemble"
        );
    }

    #[test]
    fn a_held_local_head_serves_the_assembly_without_a_fetch() {
        let fx = Fixture::new();
        // No scripted response at all: a fetch here would fail the assembly.
        let http = ScriptedHttp::default();
        let floors = InMemoryFloorStore::default();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        adopter.hold_local_head(LocalHead {
            cid: fx.head_cid_str.clone(),
            block: fx.head_block.clone(),
        });

        let candidate = block_on(adopter.assemble_candidate(&fx.name, &fx.record(1)))
            .expect("the held block stands in for the fetch");
        assert_eq!(candidate.envelope, fx.envelope);
        assert!(http.requests().is_empty(), "the write path skips the fetch");
    }

    #[test]
    fn a_held_local_head_that_is_not_the_records_own_block_is_never_trusted() {
        let fx = Fixture::new();
        let http = ScriptedHttp::default();
        let floors = InMemoryFloorStore::default();
        let gw = gateway();

        // Right address, wrong bytes: the content-address check refuses them
        // exactly as it refuses a tampered fetched block.
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        adopter.hold_local_head(LocalHead {
            cid: fx.head_cid_str.clone(),
            block: b"not the block this record anchors".to_vec(),
        });
        match block_on(adopter.assemble_candidate(&fx.name, &fx.record(1))) {
            Err(GateError::Rejected(r)) => assert_eq!(r.check(), "content-cid-mismatch"),
            Err(GateError::Seam(e)) => panic!("expected a rejection, got seam {e}"),
            Ok(_) => panic!("a mis-addressed local head must fail closed"),
        }

        // A held block for some other record is simply not this record's head:
        // the assembly falls back to the network for the one it does anchor.
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        adopter.hold_local_head(LocalHead {
            cid: "bafkreiotherblockaddress".to_owned(),
            block: b"another record's head".to_vec(),
        });
        assert_eq!(
            block_on(adopter.assemble_candidate(&fx.name, &fx.record(1)))
                .expect("falls back to the fetch")
                .envelope,
            fx.envelope
        );
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
        // newer floor cannot open it (rollback defense) — a stale owner-write-blob
        // is re-authorable, not a rejection. This invariant holds in release.
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

    /// Drive the real equal-floor `Current` sequence: the durable floor already
    /// sits at the record's sequence, so `adopt` rejects at the sequence stage
    /// and caches its candidate, and recovery runs off that.
    async fn recover_at_floor(
        adopter: &RootAdopter<'_, ScriptedHttp, InMemoryFloorStore>,
        floors: &InMemoryFloorStore,
        fx: &Fixture,
    ) -> Result<Option<OwnScopeMaterial>, SeamError> {
        floors
            .raise_sequence_floor(fx.name.as_str().as_bytes(), 1)
            .await
            .expect("seed the floor");
        let record = fx.record(1);
        assert!(
            adopter.adopt(&fx.name, &record).await.is_err(),
            "an equal-floor record must reject at the sequence stage"
        );
        adopter.recover_own_scope_material(&fx.name, &record).await
    }

    #[test]
    fn recovery_returns_both_scope_seeds_for_our_own_current_root() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        let material = block_on(recover_at_floor(&adopter, &floors, &fx))
            .expect("recovery is fail-open, never an error")
            .expect("the owner recovers its own scope seeds on the Current path");
        assert_eq!(material.node_id, fx.root_id, "keyed by the envelope id");
        assert_eq!(
            *material.read_scope_seed, OWNER_ROOT_SCOPE_SEED,
            "the read seed the write plane seals under survives a session that adopts nothing",
        );
        let seed = material
            .write_scope_seed
            .expect("the write seed is recovered");
        assert_eq!(*seed, OWNER_ROOT_WRITE_SCOPE_SEED);
        // The recovered seed reproduces the record's IPNS routing name.
        let signer = SessionIdentity::write_name_signer(&seed, &fx.root_id);
        assert_eq!(IpnsName::from_public_key(&signer.verifying_key()), fx.name);
    }

    /// The equal-floor recovery re-unseals the very body the gate's stage 6
    /// produces, so a caller that republishes our own current record (the
    /// rotation's gated read) carries it forward byte-for-byte.
    #[test]
    fn recovery_returns_the_read_body_the_gate_would_have_unsealed() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let gw = gateway();

        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let adopted = block_on(
            fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw)
                .adopt(&fx.name, &fx.record(1)),
        )
        .expect("a record above the floor adopts")
        .adopted
        .read_body;

        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        block_on(floors.raise_sequence_floor(fx.name.as_str().as_bytes(), 1)).unwrap();
        let record = fx.record(1);
        assert!(
            block_on(adopter.adopt(&fx.name, &record)).is_err(),
            "an equal-floor record must reject at the sequence stage"
        );

        let recovered = block_on(adopter.recover_own_scope_root(&fx.name, &record))
            .expect("recovery is fail-open, never an error")
            .expect("our own current root recovers");
        assert_eq!(recovered.read_body, adopted);
    }

    /// The recovery enforces its own equal-floor precondition rather than
    /// trusting the caller's reading of the rejection: a record strictly below
    /// the sequence floor is a replay and recovers no seed.
    #[test]
    fn equal_floor_recovery_refuses_a_record_below_the_sequence_floor() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        block_on(floors.raise_sequence_floor(fx.name.as_str().as_bytes(), 9)).unwrap();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        let record = fx.record(1);
        assert!(block_on(adopter.adopt(&fx.name, &record)).is_err());
        assert!(
            block_on(adopter.recover_own_scope_root(&fx.name, &record))
                .expect("fail-open")
                .is_none(),
            "a replay below the floor is not our own current record",
        );
    }

    /// The candidate cache is the recovery's whole claim to stages 1-3, so only
    /// a sequence-stage verdict may populate it. A record rejected earlier — here
    /// an unrecognised owner identity, gate stage 2 — must leave nothing behind,
    /// or a forged grant section would reach the seed recovery unauthenticated.
    #[test]
    fn a_pre_floor_rejection_caches_no_candidate_for_the_recovery() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let impostor = EcdsaSigner::from_scalar(&[0x22; 32])
            .expect("valid scalar")
            .verifying_key();
        let adopter = fx.adopter(&http, &floors, &impostor, &gw);

        let record = fx.record(1);
        match block_on(adopter.adopt(&fx.name, &record)) {
            Err(GateError::Rejected(r)) => assert_eq!(r.stage, GateStage::CommitmentVerify),
            Err(GateError::Seam(e)) => panic!("expected a commitment rejection, got seam {e}"),
            Ok(_) => panic!("an unrecognised owner identity must be rejected"),
        }
        assert!(
            block_on(adopter.recover_own_scope_root(&fx.name, &record))
                .expect("fail-open")
                .is_none(),
            "a candidate that never cleared the commitment stage is not recoverable",
        );
    }

    #[test]
    fn equal_floor_recovery_refuses_a_record_below_the_read_epoch_floor() {
        // Stages 4/5 never ran for a `Current`, so recovery re-imposes the
        // read-epoch floor itself: a forgery-window writer re-serving a
        // pre-rotation section at the floor must not hand back the revoked
        // epoch's read seed.
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        block_on(floors.raise_epoch_floor(&fx.scope_id, OWNER_ROOT_EPOCH + 1)).unwrap();
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);

        assert!(
            block_on(recover_at_floor(&adopter, &floors, &fx))
                .expect("fail-open")
                .is_none(),
            "a record below the read-epoch floor recovers no seed"
        );
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
        let seed = block_on(adopter.recover_own_scope_material(&fx.name, &record))
            .expect("recovery is fail-open, never an error")
            .expect("the owner recovers its seeds from the reused candidate")
            .write_scope_seed
            .expect("the write seed is recovered");
        assert_eq!(*seed, OWNER_ROOT_WRITE_SCOPE_SEED);
        assert_eq!(
            http.requests().len(),
            1,
            "the head block is fetched once; recovery reuses adopt's candidate"
        );
    }

    #[test]
    fn bytes_already_held_short_circuit_the_equal_floor_recovery() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx
            .adopter(&http, &floors, &fx.owner_identity_verifier, &gw)
            .holding(Some(fx.record(1)));

        assert!(
            block_on(recover_at_floor(&adopter, &floors, &fx))
                .expect("recovery is fail-open, never an error")
                .is_none(),
            "the caller already holds these bytes and the material behind them",
        );
    }

    #[test]
    fn a_hold_of_other_bytes_never_short_circuits_the_recovery() {
        let fx = Fixture::build(Some(OWB_WRITE_EPOCH));
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        // A hold on a different record of the same name: the fetched bytes are
        // not the held ones, so the skip must not fire.
        let adopter = fx
            .adopter(&http, &floors, &fx.owner_identity_verifier, &gw)
            .holding(Some(fx.record(2)));

        assert_eq!(
            block_on(recover_at_floor(&adopter, &floors, &fx))
                .expect("fail-open")
                .and_then(|material| material.write_scope_seed)
                .as_deref(),
            Some(&OWNER_ROOT_WRITE_SCOPE_SEED),
        );
    }

    #[test]
    fn no_write_seed_is_recovered_when_the_blob_is_absent_stale_or_transplanted() {
        // Missing owner-write-blob → held keyless, never a seed.
        let fx = Fixture::new();
        let http = ScriptedHttp::default();
        http.enqueue_response(ok_response(fx.head_block.clone()));
        let floors = InMemoryFloorStore::default();
        seed_write_floor(&floors, &fx.scope_id, OWB_WRITE_EPOCH);
        let gw = gateway();
        let adopter = fx.adopter(&http, &floors, &fx.owner_identity_verifier, &gw);
        assert!(
            block_on(recover_at_floor(&adopter, &floors, &fx))
                .expect("fail-open")
                .expect("the read seed still recovers")
                .write_scope_seed
                .is_none(),
            "no owner-write-blob ⇒ held keyless"
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
            block_on(recover_at_floor(&adopter, &floors, &fx))
                .expect("fail-open")
                .expect("the read seed still recovers")
                .write_scope_seed
                .is_none(),
            "a stale owner-write-blob below the floor recovers no write seed"
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
            block_on(recover_at_floor(&adopter, &floors, &fx))
                .expect("fail-open")
                .expect("the read seed still recovers")
                .write_scope_seed
                .is_none(),
            "a transplanted owner-write-blob recovers no write seed"
        );
    }
}
