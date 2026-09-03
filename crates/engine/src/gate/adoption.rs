//! The adoption gate — the six-stage trust pipeline every resolved record
//! passes before it touches the snapshot (blueprint/engine.md "Adoption gate
//! and floors"; CONTEXT.md "Adoption gate"). It composes the #33 pipeline with
//! the #39 D3 seal-auth stage and the D4 floor law. The six stages are
//! enumerated on [`GateStage`] and documented at each stage below.
//!
//! The gate is a **pure composition of `crates/core`'s verify/unseal
//! functions** plus the engine's durable floors: no crypto, no codec, and no
//! cryptographic error code of its own. Every cryptographic verdict is a core
//! [`CodecError`] surfaced verbatim through [`RejectionReason::Trust`]; the only
//! engine-domain verdicts are the two floor comparisons (stages 4 and 5), the
//! [`FloorStore`] seam's territory.
//!
//! Every failure is fail-closed and whole-record: the caller pins last-known-
//! good and never renders the rejected record. Floors advance (via
//! [`floor::advance_on_unseal`]) **only** after stage 6 succeeds — the
//! AAD-confirmed-unseal rule of the floor law.

use core::fmt;
use std::collections::BTreeSet;

use cipherbox_core::error::{CodecError, TrustViolation};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, AscentLink, Envelope, GrantSection, GrantSetCommitment, Permission,
    PreservedFields, ReadBody, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB,
    STRUCT_TAG_HISTORY_LINK, STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_OWNER_WRITE_BLOB,
    STRUCT_TAG_WRITE_BODY, StructureSigInput, open_ascent_link, open_grant_blob, open_owner_blob,
    open_read_body, refuse_stale_cut_epoch, verify_grant_set_bound, verify_structure,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier};
use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Verifier};
use cipherbox_core::suite::secret::{SecretBytes, ct_eq};
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::gate::floor;
use crate::seams::{FloorStore, SeamError, SeamResult};

/// The six ordered stages of the adoption gate. The stage a rejection names is
/// the first stage that failed; earlier stages all passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStage {
    /// Stage 1: core's IPNS record verify chain.
    RecordVerify,
    /// Stage 2: the owner-signed grant-set commitment.
    CommitmentVerify,
    /// Stage 3: seed-bearing structure signatures under committed pseudonyms.
    GrantSection,
    /// Stage 4: strictly-newer sequence vs the durable per-name floor.
    Sequence,
    /// Stage 5: epoch tag at or above the scope's durable read-epoch floor.
    Epoch,
    /// Stage 6: HPKE seed source and symmetric read-body unseal.
    Unseal,
}

impl GateStage {
    /// Every stage, in pipeline order — the anti-vacuity anchor for the
    /// six-stage matrix.
    pub const ALL: &'static [GateStage] = &[
        GateStage::RecordVerify,
        GateStage::CommitmentVerify,
        GateStage::GrantSection,
        GateStage::Sequence,
        GateStage::Epoch,
        GateStage::Unseal,
    ];

    /// The stable kebab-case name of the stage.
    pub fn name(&self) -> &'static str {
        match self {
            GateStage::RecordVerify => "record-verify",
            GateStage::CommitmentVerify => "commitment-verify",
            GateStage::GrantSection => "grant-section",
            GateStage::Sequence => "sequence",
            GateStage::Epoch => "epoch",
            GateStage::Unseal => "unseal",
        }
    }
}

/// The engine floor-law verdict names — the two adoption-gate rejections that
/// are engine domain (a durable-floor comparison), not a composed core check.
/// Every *other* gate rejection carries a core `TrustViolation`/`Malformed`
/// check name verbatim.
pub const FLOOR_VERDICTS: &[&str] = &["sequence-not-newer", "epoch-below-floor"];

/// Why the gate rejected a record. Fail-closed in every arm: a rejection is a
/// trust violation, never mere staleness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    /// A composed `crates/core` cryptographic/codec check fired — surfaced
    /// verbatim, never reclassified. Covers stages 1–3 and 6.
    Trust(CodecError),
    /// Stage 4: the record's sequence is not strictly newer than the durable
    /// per-name sequence floor — a replay/rollback, fail-closed.
    SequenceNotNewer {
        /// The durable per-name sequence floor.
        floor: u64,
        /// The rejected record's sequence.
        sequence: u64,
    },
    /// Stage 5: the envelope epoch tag is below the scope's durable read-epoch
    /// floor — an old-epoch record past a revocation boundary, fail-closed.
    EpochBelowFloor {
        /// The durable read-epoch floor.
        floor: u64,
        /// The rejected record's epoch tag.
        epoch: u64,
    },
    /// A scope root leaves no room for its own re-seal: its bytes outside the
    /// grant section are over
    /// [`resealable_root_rest_bytes`](crate::content::limits::resealable_root_rest_bytes).
    ///
    /// This engine never authors one (`net/author.rs::encode_scope_root`), so
    /// adopting one from any other client would leave the owner's own re-key
    /// refusing on it for ever. The read-side half of that produce-side bound
    /// (AGENTS.md rule 8). Cache-first keeps the previously adopted head, so
    /// the scope stays readable.
    ScopeRootNotResealable {
        /// The record's byte count outside its grant section.
        size: usize,
        /// The budget that count must stay under.
        limit: usize,
    },
}

/// A fail-closed adoption-gate rejection: the stage that fired and its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRejection {
    /// The first stage that failed.
    pub stage: GateStage,
    /// Why it failed.
    pub reason: RejectionReason,
}

impl GateRejection {
    /// The stable named error for this rejection: the composed core check name
    /// for a cryptographic/codec stage, or the engine floor-law verdict name
    /// for a floor stage. This is the string the six-stage matrix asserts 1:1
    /// against the design tables.
    pub fn check(&self) -> &'static str {
        match &self.reason {
            RejectionReason::Trust(e) => e.check(),
            RejectionReason::SequenceNotNewer { .. } => "sequence-not-newer",
            RejectionReason::EpochBelowFloor { .. } => "epoch-below-floor",
            RejectionReason::ScopeRootNotResealable { .. } => "scope-root-not-resealable",
        }
    }
}

impl fmt::Display for GateRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "adoption gate rejected at stage [{}]: [{}]",
            self.stage.name(),
            self.check()
        )
    }
}

impl std::error::Error for GateRejection {}

/// The result of running the gate: a fail-closed [`GateRejection`], or a host
/// seam I/O failure — availability, never a trust decision. Only
/// [`GateError::Rejected`] means the record was untrustworthy; a
/// [`GateError::Seam`] is a retryable read of the durable floors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// A fail-closed gate rejection.
    Rejected(GateRejection),
    /// A [`FloorStore`] seam failure — host I/O, not a trust verdict.
    Seam(SeamError),
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::Rejected(r) => write!(f, "{r}"),
            GateError::Seam(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GateError {}

impl GateError {
    /// The rejection, if this was a fail-closed trust verdict (not a seam I/O
    /// failure). Convenience for tests and hosts that classify verdicts.
    pub fn rejection(&self) -> Option<&GateRejection> {
        match self {
            GateError::Rejected(r) => Some(r),
            GateError::Seam(_) => None,
        }
    }
}

/// The reader's HPKE seed source, opened at the unseal stage to prove the
/// reader can obtain the scope seed (`hpke-open-failed` on tamper). The public
/// `enc`/`ciphertext` are the envelope grant-section blob addressed to this
/// reader; the secret is the reader's own. A holder that already possesses the
/// scope read key passes no seed blob.
pub enum SeedBlob<'a> {
    /// The vault owner's own-scope owner blob (HPKE to the owner enc subkey).
    Owner {
        /// The owner's X25519 encryption secret.
        enc_secret: &'a X25519Secret,
        /// The HPKE encapsulated key.
        enc: [u8; 32],
        /// The HPKE ciphertext.
        ciphertext: Vec<u8>,
        /// The structured AAD the blob was sealed under.
        aad: AadContext,
    },
    /// A grantee's grant blob (HPKE to the recipient enc subkey).
    Grantee {
        /// The grantee's X25519 encryption secret.
        enc_secret: &'a X25519Secret,
        /// The HPKE encapsulated key.
        enc: [u8; 32],
        /// The HPKE ciphertext.
        ciphertext: Vec<u8>,
        /// The structured AAD the blob was sealed under.
        aad: AadContext,
    },
}

/// The hand-fed resolved record the gate adopts — the public bytes a resolve
/// would assemble off the record/content plane. This slice does not resolve;
/// tests feed candidates directly (blueprint/engine.md: "records are
/// hand-fed").
pub struct Candidate {
    /// The IPNS name the record was fetched under — the verify chain's sole
    /// trust anchor.
    pub name: IpnsName,
    /// The raw IPNS record protobuf bytes.
    pub record_bytes: Vec<u8>,
    /// The scope root's grant section — the commitment (+ its owner signature)
    /// and every seed-bearing structure with its detached structure signature.
    /// The gate enumerates its structures for stage-3 authentication **from this
    /// record's own bytes**, recomputing each `H(ciphertext)`, so
    /// completeness is gate-enforced and never caller-asserted.
    pub grant_section: GrantSection,
    /// The scope root's envelope (carries the plaintext epoch tag and the
    /// sealed read-body).
    pub envelope: Envelope,
}

/// The reader's private context for adoption. The gate borrows every field and
/// zeroizes none of it — the reader is the terminal owner of its own key
/// material.
pub struct ReaderContext<'a> {
    /// The contact-code-anchored owner identity (stage-2 verification anchor).
    pub owner_identity: &'a EcdsaVerifier,
    /// The scope id (the read-epoch floor key and the AAD scope binding). The
    /// caller supplies floors already namespaced to the authority it reads under
    /// ([`SharerScopedFloorStore`](crate::seams::SharerScopedFloorStore)).
    pub scope_id: [u8; 16],
    /// The reader's own derived scope read key for the read-body unseal.
    pub read_key: &'a [u8; 32],
    /// The reader's cached ancestor node seed — the trusted secret the expected
    /// ascent keypair re-derives from. Required whenever
    /// `candidate.grant_section.ascent_link` is `Some`; a `None` here against a
    /// present ascent link is fail-closed (cannot verify). The one exception is
    /// a reader entering by its own grant blob, which descends from nobody.
    pub parent_node_seed: Option<&'a [u8; 32]>,
    /// The reader's HPKE seed source, opened at the unseal stage; `None` for a
    /// holder that already possesses the read key.
    pub seed_blob: Option<SeedBlob<'a>>,
}

/// A record that passed all six gate stages: the unsealed read-body and the
/// authenticated sequence/epoch the floor law advanced to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adopted {
    /// The unsealed, uniqueness-checked read-body.
    pub read_body: ReadBody,
    /// The authenticated record sequence (the new per-name floor).
    pub sequence: u64,
    /// The authenticated epoch tag (the new read-epoch floor).
    pub epoch: u64,
}

/// A gate pass whose floor-law advance is **deferred**: all six stages
/// succeeded and the read-body unsealed, but the durable floors have not moved
/// yet. A caller that must durably persist accepted state (the accept flow's
/// received-shares bookmark) persists first, then calls [`commit`] — so a
/// persist failure leaves the floors untouched and the record re-adopts cleanly
/// on redelivery instead of being stranded below an already-advanced sequence
/// floor. The durability of the floor advance is thus gated on the durability
/// of the accepted state.
///
/// [`commit`]: PendingAdoption::commit
#[must_use = "the deferred floor advance must be committed once the accepted state is durable"]
pub struct PendingAdoption {
    adopted: Adopted,
    scope_id: [u8; 16],
    ipns_name: Vec<u8>,
    cut_epoch: u64,
}

/// Suffix that keeps the cut-epoch floor apart from the other floors under one
/// scope id, on the convention `gate::floor` sets for the write-epoch floor.
pub(crate) const CUT_EPOCH_SUFFIX: &[u8] = b"/cut-epoch";

/// The floor key carrying the newest cut epoch this device has adopted at
/// `scope_id`.
fn cut_epoch_floor_key(scope_id: &[u8; 16]) -> Vec<u8> {
    [scope_id.as_slice(), CUT_EPOCH_SUFFIX].concat()
}

/// Stage 2 of the gate, whole: the grant-set commitment verifies under the
/// contact-anchored `owner_identity`, binds `ipns_name` — the name is inside the
/// signed preimage, so a commitment for another scope root is invalid here — and
/// is not a set `cut_epoch_floor` has already superseded.
///
/// A commitment carries no read epoch, so a pre-cut set the owner really did
/// sign verifies for ever, and any committed write grantee can republish a root
/// that carries it; the cut epoch this device already adopted is what tells the
/// replay apart from the set in force (blueprint/engine.md "Adoption gate and
/// floors"). The classification path a `/shared` row renders holds a record to
/// this same bar without unsealing it, so the two never disagree.
pub(crate) fn verify_commitment_in_force(
    owner_identity: &EcdsaVerifier,
    section: &GrantSection,
    ipns_name: &[u8],
    cut_epoch_floor: u64,
) -> Result<(), CodecError> {
    let commitment_sig = EcdsaSignature::from_compact(&section.commitment_sig)
        .ok_or(CodecError::from(TrustViolation::CommitmentInvalid))?;
    verify_grant_set_bound(
        owner_identity,
        &section.commitment,
        &commitment_sig,
        ipns_name,
    )?;
    refuse_stale_cut_epoch(&section.commitment, cut_epoch_floor)
}

/// `scope_id`'s cut-epoch floor, zero where this device recorded none — the bar
/// [`refuse_stale_cut_epoch`] holds a commitment to.
pub(crate) async fn read_cut_epoch_floor<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
) -> SeamResult<u64> {
    Ok(floors
        .epoch_floor(&cut_epoch_floor_key(scope_id))
        .await?
        .unwrap_or(0))
}

/// Raise `scope_id`'s cut-epoch floor to `cut_epoch` — a maximum against the
/// stored value, like every other floor advance.
///
/// Three paths reach one bar, which is what makes a rollback refusable
/// everywhere. The cutting device raises it from the cut it just published; the
/// gate raises it at the commit of an adoption; and the `/shared` classification
/// path raises it from any commitment that clears stage 2
/// ([ADR 0014](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0014-a-verified-commitments-cut-epoch-raises-the-floor-without-an-unseal.md)).
///
/// Without the cutting device's own raise the owner keeps accepting the set it
/// just cut until its next resolve of that scope — long enough for the revokee
/// to republish the pre-cut root and have the next cut sign off that base. Call
/// it **after** the cut publishes: a raise ahead of the publish would leave the
/// device refusing the record the scope still carries, with the fresh set
/// nowhere on the network to replace it.
pub async fn record_cut_epoch_floor<F: FloorStore>(
    floors: &F,
    scope_id: &[u8; 16],
    cut_epoch: u64,
) -> Result<u64, SeamError> {
    floors
        .raise_epoch_floor(&cut_epoch_floor_key(scope_id), cut_epoch)
        .await
}

impl PendingAdoption {
    /// Commit the deferred floor-law advance (the AAD-confirmed-unseal rule),
    /// then yield the [`Adopted`] result. Call only after the accepted state is
    /// durably persisted.
    ///
    /// The stage-4/5 floor reads and this advance are deliberately not a CAS
    /// pair: the engine is the single writer (blueprint/engine.md "Facade"), and
    /// cross-writer contention is resolved on the publish plane, never on the
    /// local floor read.
    pub async fn commit<F: FloorStore>(self, floors: &F) -> Result<Adopted, GateError> {
        // The restrictive floor goes first, so an interrupt between the two
        // leaves this device refusing a pre-cut set it would otherwise
        // re-adopt, never the reverse. A scope the owner never cut carries
        // zero, which an absent key already reads as, so it files nothing.
        if self.cut_epoch > 0 {
            floors
                .raise_epoch_floor(&cut_epoch_floor_key(&self.scope_id), self.cut_epoch)
                .await
                .map_err(GateError::Seam)?;
        }
        floor::advance_on_unseal(
            floors,
            &self.scope_id,
            &self.ipns_name,
            self.adopted.sequence,
            self.adopted.epoch,
        )
        .await
        .map_err(GateError::Seam)?;
        Ok(self.adopted)
    }
}

/// The committed write-capable pseudonym keys of a scope root: the owner
/// pseudonym plus every write-permission entry's. Read-only entries never
/// authorize a seed-bearing structure.
///
/// Deduplicated: only a tag is unique across committed entries, so one pseudonym
/// may be named by many. A repeat authenticates nothing the first copy did not,
/// and each copy would cost another trial verification.
///
/// Left compressed. A commitment may name 1024 writers while the pin means at
/// most one is ever used, so decompressing eagerly would reinstate an
/// O(pseudonyms) cost the scan itself no longer pays.
#[doc(hidden)]
pub fn committed_write_pseudonyms(commitment: &GrantSetCommitment) -> Vec<[u8; 32]> {
    let writers = commitment
        .entries
        .iter()
        .filter(|e| e.permission == Permission::Write)
        .map(|e| e.pseudonym_pk);
    let mut seen = BTreeSet::new();
    core::iter::once(commitment.owner_pseudonym_pk)
        .chain(writers)
        .filter(|pk| seen.insert(*pk))
        .collect()
}

/// Whether `pseudonym_pk` is one of a scope root's committed write-capable
/// pseudonyms — [`committed_write_pseudonyms`]'s membership test, without
/// materialising the set. The set the gate authenticates a section against, so a
/// re-seal can bind its own signer to exactly it (fail-closed symmetry).
pub fn is_committed_write_pseudonym(
    commitment: &GrantSetCommitment,
    pseudonym_pk: &[u8; 32],
) -> bool {
    commitment.owner_pseudonym_pk == *pseudonym_pk
        || commitment
            .entries
            .iter()
            .any(|e| e.permission == Permission::Write && e.pseudonym_pk == *pseudonym_pk)
}

/// Trial-verifier over a section's committed write-capable pseudonyms, pinning
/// the one that authenticated the section's first structure — the **one
/// section, one signer** rule (blueprint/engine.md "Adoption gate and floors").
/// The scan therefore runs at most once per record, so worst-case work is
/// `pseudonyms + structures` rather than their product.
struct StructureAuthenticator {
    committed: Vec<[u8; 32]>,
    pinned: Option<Ed25519Verifier>,
}

impl StructureAuthenticator {
    /// Authenticate one seed-bearing structure against the committed write-capable
    /// pseudonyms, recomputing the signed input **from the record's actual sealed
    /// bytes**: the `ciphertext_hash` is `H(ciphertext)` over `ciphertext`,
    /// and `scope`/`epoch` come from the authenticated envelope — never a
    /// caller-supplied [`StructureSigInput`]. A signature therefore proves "the
    /// committed writer signed *these* bytes at *this* scope/epoch", not merely
    /// "the writer once signed some hash".
    ///
    /// The first structure is trusted iff the recomputed input verifies under at
    /// least one committed pseudonym, which pins that pseudonym as the section's
    /// signer; every later structure must verify under **that** key alone. Any
    /// other outcome is a `structure-signature-invalid` trust violation over the
    /// whole record.
    fn authenticate(
        &mut self,
        scope: [u8; 16],
        epoch: u64,
        struct_tag: u8,
        recipient_tag: Option<[u8; 32]>,
        ciphertext: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CodecError> {
        let input =
            StructureSigInput::over_ciphertext(scope, epoch, struct_tag, recipient_tag, ciphertext);
        let sig = Ed25519Signature::from_bytes(*signature);
        if let Some(pinned) = &self.pinned {
            return verify_structure(pinned, &input, &sig);
        }
        // A pseudonym that is not a valid point verifies nothing, so a failed
        // decompression falls through exactly as a failed signature does.
        for pseudonym in self
            .committed
            .iter()
            .filter_map(|pk| Ed25519Verifier::from_bytes(*pk))
        {
            if verify_structure(&pseudonym, &input, &sig).is_ok() {
                self.pinned = Some(pseudonym);
                return Ok(());
            }
        }
        Err(TrustViolation::StructureSignatureInvalid.into())
    }
}

/// Visit every seed-bearing structure `section` carries — its `structTag`,
/// recipient tag, signed-over bytes and detached signature — short-circuit on
/// the first `Err`. The single definition of *what* stage 3 authenticates, so a
/// new structure kind cannot reach the wire covered by only some of the passes
/// that walk one. The signed-over bytes are the structure's ciphertext, except
/// for the ascent link ([`ascent_link_sig_body`]).
#[doc(hidden)]
pub fn for_each_structure<E>(
    section: &GrantSection,
    mut visit: impl FnMut(u8, Option<[u8; 32]>, &[u8], &[u8; 64]) -> Result<(), E>,
) -> Result<(), E> {
    let owner = &section.owner_blob;
    visit(
        STRUCT_TAG_OWNER_BLOB,
        None,
        &owner.ciphertext,
        &owner.signature,
    )?;
    if let Some(b) = &section.owner_write_blob {
        visit(
            STRUCT_TAG_OWNER_WRITE_BLOB,
            None,
            &b.ciphertext,
            &b.signature,
        )?;
    }
    for b in &section.grant_blobs {
        visit(
            STRUCT_TAG_GRANT_BLOB,
            Some(b.tag),
            &b.ciphertext,
            &b.signature,
        )?;
    }
    for l in &section.history_links {
        visit(STRUCT_TAG_HISTORY_LINK, None, &l.sealed, &l.signature)?;
    }
    let body = &section.write_body;
    visit(STRUCT_TAG_WRITE_BODY, None, &body.sealed, &body.signature)?;
    if let Some(a) = &section.ascent_link {
        visit(STRUCT_TAG_ASCENT_LINK, None, &a.sig_body(), &a.signature)?;
    }
    Ok(())
}

/// The gate's stage-3 predicate: authenticate every structure signature
/// `section` carries against **one** of the pseudonyms its own commitment names,
/// recomputed at `envelope`'s scope and epoch — whatever epoch a structure's own
/// sealed AAD binds (blueprint/core.md "Structure signatures"). The single
/// signer is pinned by the first structure ([`StructureAuthenticator`]).
///
/// Stage 3 only: the pseudonyms come from the section's own commitment, which
/// [`verify_grant_set`] anchors to the owner identity at stage 2.
///
/// Also run release-active on the produce side (`net/author.rs`), so a scope
/// root this build's own gate would reject is never signed (AGENTS.md rule 8).
#[doc(hidden)]
pub fn authenticate_section_structures(
    section: &GrantSection,
    envelope: &Envelope,
) -> Result<(), CodecError> {
    let (scope, epoch) = (envelope.scope, envelope.epoch);
    let mut auth = StructureAuthenticator {
        committed: committed_write_pseudonyms(&section.commitment),
        pinned: None,
    };
    for_each_structure(section, |tag, recipient, ct, sig| {
        auth.authenticate(scope, epoch, tag, recipient, ct, sig)
    })
}

impl SeedBlob<'_> {
    /// The structured AAD the blob claims to be sealed under — cross-checked
    /// against the envelope before it is trusted.
    fn aad(&self) -> &AadContext {
        match self {
            SeedBlob::Owner { aad, .. } | SeedBlob::Grantee { aad, .. } => aad,
        }
    }

    /// The domain-separation tag this blob variant must carry — the AAD's
    /// `structTag` is pinned to it so an owner blob can never present as a grant
    /// blob (or any other structure).
    fn struct_tag(&self) -> u8 {
        match self {
            SeedBlob::Owner { .. } => STRUCT_TAG_OWNER_BLOB,
            SeedBlob::Grantee { .. } => STRUCT_TAG_GRANT_BLOB,
        }
    }
}

/// The two seeds a seed blob yields: the recovered read scope seed (always) and,
/// for a write-grantee, the scope write seed the held set derives its renewal
/// signer from (`None` for a read-only grant and the owner arm). Both zeroize on
/// drop.
type UnsealedSeeds = (SecretBytes, Option<Zeroizing<[u8; 32]>>);

/// Open the reader's HPKE seed source, returning the recovered read scope seed
/// (for the gate's read-key cross-check) and, for a write-grantee, the write
/// scope seed. The write seed is consumed by the resolve/gate driver that keeps
/// a write-capable scope alive (blueprint/engine.md "Liveness").
fn open_seed_blob(blob: &SeedBlob<'_>) -> Result<UnsealedSeeds, CodecError> {
    match blob {
        SeedBlob::Owner {
            enc_secret,
            enc,
            ciphertext,
            aad,
        } => {
            let payload = open_owner_blob(enc_secret, enc, aad, ciphertext)?;
            Ok((SecretBytes::new(*payload.override_seed()), None))
        }
        SeedBlob::Grantee {
            enc_secret,
            enc,
            ciphertext,
            aad,
        } => {
            let payload = open_grant_blob(enc_secret, enc, aad, ciphertext)?;
            let write_scope_seed = payload.write_scope_seed().copied().map(Zeroizing::new);
            Ok((
                SecretBytes::new(*payload.read_scope_seed()),
                write_scope_seed,
            ))
        }
    }
}

/// Run the adoption gate over one hand-fed [`Candidate`] for one
/// [`ReaderContext`], **deferring** the floor-law advance. On success all six
/// stages passed and the read-body unsealed, but the durable floors have not
/// moved: the caller persists any accepted state, then calls
/// [`PendingAdoption::commit`] to advance them. On failure nothing durable
/// changed and the caller pins last-known-good. Use [`adopt`] for the eager
/// path that has no accepted state to persist first.
pub async fn adopt_deferred<F: FloorStore>(
    floors: &F,
    reader: &ReaderContext<'_>,
    candidate: &Candidate,
) -> Result<(PendingAdoption, Option<Zeroizing<[u8; 32]>>), GateError> {
    // Stage 1 — record verify (Ed25519 key from the name itself).
    let verified = IpnsRecord::unmarshal(&candidate.record_bytes)
        .and_then(|record| record.verify(&candidate.name))
        .map_err(|e| reject(GateStage::RecordVerify, RejectionReason::Trust(e)))?;

    // Stage 2.
    let section = &candidate.grant_section;
    let cut_epoch_floor = read_cut_epoch_floor(floors, &reader.scope_id)
        .await
        .map_err(GateError::Seam)?;
    verify_commitment_in_force(
        reader.owner_identity,
        section,
        candidate.name.as_str().as_bytes(),
        cut_epoch_floor,
    )
    .map_err(|e| reject(GateStage::CommitmentVerify, RejectionReason::Trust(e)))?;

    // Stage 3 — grant-section authentication under `authenticate_structure`'s
    // recompute contract. Any failure rejects the whole record (#39 D3).
    let epoch = candidate.envelope.epoch;
    authenticate_section_structures(section, &candidate.envelope)
        .map_err(|e| reject(GateStage::GrantSection, RejectionReason::Trust(e)))?;
    // A reader entering by its own grant blob descends from nobody, and stage 6
    // cross-checks the seed that blob wraps against this record's read key — the
    // same binding this check makes for a descending reader. A reader that does
    // hold an ancestor seed still verifies under it, so the two fields cannot
    // disagree into a skipped check.
    let by_grant_alone = reader.parent_node_seed.is_none()
        && matches!(reader.seed_blob, Some(SeedBlob::Grantee { .. }));
    if let Some(ascent) = section.ascent_link.as_ref().filter(|_| !by_grant_alone) {
        // The ascent link is doubly checked: its structure signature (above)
        // proves the committed writer authored it, and this derive-and-verify
        // proves the sealed seed is *this* scope root's.
        //
        // Ascent authority is reader-derived: the expected keypair comes from the
        // reader's cached ancestor node seed, never the network-supplied record
        // (blueprint/engine.md: "Ancestor readers derive the expected ascent
        // keypair from the parent node seed"). No reader seed ⇒ cannot verify ⇒
        // fail closed. The AAD is rebuilt from the authenticated envelope, so a
        // link sealed under a foreign context fails the HPKE tag on open.
        let parent_node_seed = reader.parent_node_seed.ok_or_else(|| {
            reject(
                GateStage::GrantSection,
                RejectionReason::Trust(TrustViolation::AscentLinkMismatch.into()),
            )
        })?;
        let aad = AadContext {
            v: candidate.envelope.v,
            id: candidate.envelope.id,
            scope: candidate.envelope.scope,
            epoch: candidate.envelope.epoch,
            struct_tag: STRUCT_TAG_ASCENT_LINK,
        };
        let link = AscentLink {
            ascent_public: ascent.ascent_public,
            enc: ascent.enc,
            ciphertext: ascent.ciphertext.clone(),
            unknown: PreservedFields::new(),
        };
        // Cross-check the recovered override seed: the ascent public key is
        // published, so anyone can seal a rogue payload to it. The seed the link
        // carries is this scope root's current override seed (CONTEXT.md "Ascent
        // link"/"Override seed"), so it must belong to this epoch and derive this
        // node's read key — the ascent-link half of engine.md:406-408.
        let payload = open_ascent_link(parent_node_seed, &aad, &link)
            .map_err(|e| reject(GateStage::GrantSection, RejectionReason::Trust(e)))?;
        let node_seed = kdf::node_seed(payload.override_seed(), &candidate.envelope.id);
        let derived_read_key = kdf::read_key(node_seed.as_bytes());
        if payload.epoch != candidate.envelope.epoch
            || !ct_eq(derived_read_key.as_bytes(), reader.read_key)
        {
            return Err(reject(
                GateStage::GrantSection,
                RejectionReason::Trust(TrustViolation::AscentLinkMismatch.into()),
            ));
        }
    }

    // Stages 4/5 — the durable floor law ([`floor::check`]): strictly-newer
    // sequence vs the per-name floor, epoch tag at or above the scope's
    // read-epoch floor.
    let name_bytes = candidate.name.as_str().as_bytes();
    floor::check(
        floors,
        name_bytes,
        &reader.scope_id,
        verified.sequence,
        epoch,
        floor::Strictness::StrictlyNewer,
    )
    .await?;

    // Stage 6 — unseal success required (AAD-confirmed). The HPKE seed source
    // (if any) opens first, then the symmetric read-body; the read-body decode
    // enforces child id/ipnsName uniqueness fail-closed.
    //
    // Reader-scope precondition: the scope UUID is not in the read-key KDF, so a
    // read body sealed under a foreign scope still opens under this reader's key.
    // Bind the envelope's scope to the reader's own scope so it joins the same
    // equivalence class as every AAD/structure scope — a foreign-scope envelope
    // is a scope transplant, fail-closed (blueprint/engine.md cross-check).
    if candidate.envelope.scope != reader.scope_id {
        return Err(reject(
            GateStage::Unseal,
            RejectionReason::Trust(TrustViolation::SealOpenFailed.into()),
        ));
    }
    // A write-grantee's blob also carries the scope write seed the held set
    // derives its per-name renewal signer from; `None` for a read-only grant,
    // the owner arm, or a holder that passes no seed blob.
    let mut write_scope_seed = None;
    if let Some(blob) = &reader.seed_blob {
        // Bind the blob to THIS envelope: a seed blob sealed under a different
        // scope/epoch/version is a transplant, not this record's seed source.
        // Fail closed before opening (blueprint/engine.md cross-check discipline).
        let aad = blob.aad();
        if aad.scope != reader.scope_id
            || aad.id != candidate.envelope.id
            || aad.epoch != candidate.envelope.epoch
            || aad.v != candidate.envelope.v
            || aad.struct_tag != blob.struct_tag()
        {
            return Err(reject(
                GateStage::Unseal,
                RejectionReason::Trust(TrustViolation::HpkeOpenFailed.into()),
            ));
        }
        // Cross-check: the recovered seed must derive the reader's read key, or
        // the blob-seed and the actual-unseal key disagree — an attributable
        // abuse event (blueprint/engine.md), never a silent staleness.
        let (seed, ws) = open_seed_blob(blob)
            .map_err(|e| reject(GateStage::Unseal, RejectionReason::Trust(e)))?;
        let node_seed = kdf::node_seed(seed.as_bytes(), &candidate.envelope.id);
        let derived_read_key = kdf::read_key(node_seed.as_bytes());
        if !ct_eq(derived_read_key.as_bytes(), reader.read_key) {
            return Err(reject(
                GateStage::Unseal,
                RejectionReason::Trust(TrustViolation::SealOpenFailed.into()),
            ));
        }
        write_scope_seed = ws;
    }
    let read_body = open_read_body(&candidate.envelope, reader.read_key)
        .map_err(|e| reject(GateStage::Unseal, RejectionReason::Trust(e)))?;

    // All six stages passed; the floor-law advance is DEFERRED to
    // [`PendingAdoption::commit`] (see that type's contract).
    Ok((
        PendingAdoption {
            adopted: Adopted {
                read_body,
                sequence: verified.sequence,
                epoch,
            },
            scope_id: reader.scope_id,
            ipns_name: name_bytes.to_vec(),
            cut_epoch: section.commitment.cut_epoch,
        },
        write_scope_seed,
    ))
}

/// Run the adoption gate and, on success, immediately advance the floor law
/// (the AAD-confirmed-unseal rule). The eager path for callers that hold no
/// accepted state to persist first (e.g. a plain resolve); a caller that must
/// make the floor advance atomic with a durable write uses [`adopt_deferred`]
/// plus [`PendingAdoption::commit`]. Returns the adopted state and, for a
/// write-grantee, the transient scope write seed the held set derives its
/// renewal signer from (`None` for a read-only holder and the owner arm).
pub async fn adopt<F: FloorStore>(
    floors: &F,
    reader: &ReaderContext<'_>,
    candidate: &Candidate,
) -> Result<(Adopted, Option<Zeroizing<[u8; 32]>>), GateError> {
    let (pending, write_scope_seed) = adopt_deferred(floors, reader, candidate).await?;
    let adopted = pending.commit(floors).await?;
    Ok((adopted, write_scope_seed))
}

/// Build a `GateError::Rejected` from a stage and reason.
fn reject(stage: GateStage, reason: RejectionReason) -> GateError {
    GateError::Rejected(GateRejection { stage, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::seal::sign_structure;
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    #[test]
    fn stage_names_are_stable_and_complete() {
        assert_eq!(GateStage::ALL.len(), 6, "the gate has exactly six stages");
        let names: Vec<&str> = GateStage::ALL.iter().map(GateStage::name).collect();
        assert_eq!(
            names,
            [
                "record-verify",
                "commitment-verify",
                "grant-section",
                "sequence",
                "epoch",
                "unseal"
            ]
        );
    }

    #[test]
    fn rejection_check_names_the_error() {
        let seq = GateRejection {
            stage: GateStage::Sequence,
            reason: RejectionReason::SequenceNotNewer {
                floor: 5,
                sequence: 3,
            },
        };
        assert_eq!(seq.check(), "sequence-not-newer");

        let epoch = GateRejection {
            stage: GateStage::Epoch,
            reason: RejectionReason::EpochBelowFloor { floor: 4, epoch: 2 },
        };
        assert_eq!(epoch.check(), "epoch-below-floor");

        let trust = GateRejection {
            stage: GateStage::RecordVerify,
            reason: RejectionReason::Trust(TrustViolation::IpnsSignatureInvalid.into()),
        };
        assert_eq!(trust.check(), "ipns-signature-invalid");
    }

    #[test]
    fn floor_verdicts_are_the_two_engine_domain_names() {
        assert_eq!(FLOOR_VERDICTS, &["sequence-not-newer", "epoch-below-floor"]);
    }

    const SCOPE: [u8; 16] = [0x11; 16];
    const EPOCH: u64 = 7;

    fn committed_signers() -> Vec<Ed25519Signer> {
        (0u8..4)
            .map(|i| Ed25519Signer::from_seed([i; 32]))
            .collect()
    }

    fn authenticator(signers: &[Ed25519Signer]) -> StructureAuthenticator {
        StructureAuthenticator {
            committed: signers
                .iter()
                .map(|s| s.verifying_key().to_bytes())
                .collect(),
            pinned: None,
        }
    }

    /// Sign `ciphertext` as an owner blob at the fixture scope/epoch.
    fn signed(signer: &Ed25519Signer, ciphertext: &[u8]) -> [u8; 64] {
        let input = StructureSigInput::over_ciphertext(
            SCOPE,
            EPOCH,
            STRUCT_TAG_OWNER_BLOB,
            None,
            ciphertext,
        );
        sign_structure(signer, &input).to_bytes()
    }

    fn authenticate(
        auth: &mut StructureAuthenticator,
        ciphertext: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CodecError> {
        auth.authenticate(
            SCOPE,
            EPOCH,
            STRUCT_TAG_OWNER_BLOB,
            None,
            ciphertext,
            signature,
        )
    }

    #[test]
    fn any_committed_pseudonym_can_pin_the_sections_signer() {
        // Pinning must not narrow *who* may sign a section — only how many
        // signers one section may have. Every committed pseudonym, at whatever
        // index, still authenticates a section of its own.
        let signers = committed_signers();
        for signer in &signers {
            let mut auth = authenticator(&signers);
            for structure in [&b"first"[..], b"second", b"third"] {
                authenticate(&mut auth, structure, &signed(signer, structure))
                    .expect("one committed pseudonym signs the whole section");
            }
        }
    }

    #[test]
    fn a_section_signed_by_two_committed_pseudonyms_is_unadoptable() {
        let signers = committed_signers();
        let mut auth = authenticator(&signers);
        authenticate(&mut auth, b"first", &signed(&signers[0], b"first")).expect("pins signer 0");
        assert_eq!(
            authenticate(&mut auth, b"second", &signed(&signers[1], b"second"))
                .unwrap_err()
                .check(),
            "structure-signature-invalid",
            "a second committed signer must not authenticate the same section"
        );
    }

    #[test]
    fn a_commitment_naming_no_usable_write_pseudonym_authenticates_nothing() {
        // Zero candidates: nothing can pin, so nothing adopts.
        let signer = Ed25519Signer::from_seed([1; 32]);
        let mut auth = authenticator(&[]);
        assert_eq!(
            authenticate(&mut auth, b"first", &signed(&signer, b"first"))
                .unwrap_err()
                .check(),
            "structure-signature-invalid"
        );
    }

    #[test]
    fn a_signature_from_no_committed_pseudonym_is_rejected_pinned_or_not() {
        let signers = committed_signers();
        let outsider = Ed25519Signer::from_seed([0x99; 32]);
        let mut fresh = authenticator(&signers);
        let mut pinned = authenticator(&signers);
        authenticate(&mut pinned, b"first", &signed(&signers[2], b"first")).expect("pins signer 2");
        for auth in [&mut fresh, &mut pinned] {
            assert_eq!(
                authenticate(auth, b"forged", &signed(&outsider, b"forged"))
                    .unwrap_err()
                    .check(),
                "structure-signature-invalid"
            );
        }
    }
}
