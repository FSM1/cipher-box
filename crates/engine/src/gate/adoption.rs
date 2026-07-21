//! The adoption gate — the six-stage trust pipeline every resolved record
//! passes before it touches the snapshot (blueprint/engine.md "Adoption gate
//! and floors"; CONTEXT.md "Adoption gate").
//!
//! The gate is a **pure composition of `crates/core`'s verify/unseal
//! functions** plus the engine's durable floors. It defines no crypto, no
//! codec, and no cryptographic error code of its own: every cryptographic
//! verdict is a core [`CodecError`] surfaced verbatim through
//! [`RejectionReason::Trust`]. The only engine-domain verdicts are the two
//! floor comparisons (stages 4 and 5), which are the [`FloorStore`] seam's
//! territory by construction.
//!
//! Stage order (composes the #33 pipeline with the #39 D3 seal-auth stage and
//! the D4 floor law):
//!
//! 1. **Record verify** — core's full IPNS chain: the Ed25519 key is taken from
//!    the [`IpnsName`] itself, `signatureV2` verifies, and the signed
//!    `data.Value` must equal the top-level value. Yields the authenticated
//!    sequence/epoch/EOL.
//! 2. **Commitment verify** — the owner-signed grant-set commitment against the
//!    contact-code-anchored owner identity, and its binding to this record's
//!    name.
//! 3. **Grant-section authentication** — every seed-bearing structure verifies
//!    under a *committed write-capable pseudonym*; an ancestor reader also
//!    derives-and-verifies the ascent link. Any failure rejects the **whole
//!    record**.
//! 4. **Sequence** — strictly newer than the durable per-name sequence floor.
//! 5. **Epoch** — the envelope epoch tag at or above the scope's durable
//!    read-epoch floor.
//! 6. **Unseal** — the reader's HPKE seed source (if any) and the symmetric
//!    read-body must open; the read-body decode also enforces child
//!    id/`ipnsName` uniqueness fail-closed.
//!
//! Every failure is fail-closed and whole-record: the caller pins last-known-
//! good and never renders the rejected record. Floors advance (via
//! [`floor::advance_on_unseal`]) **only** after stage 6 succeeds — the
//! AAD-confirmed-unseal rule of the floor law.

use core::fmt;

use cipherbox_core::error::{CodecError, TrustViolation};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, AscentLink, Envelope, GrantSetCommitment, Permission, ReadBody,
    STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_OWNER_BLOB, StructureSigInput,
    open_ascent_link, open_grant_blob, open_owner_blob, open_read_body, verify_grant_set,
    verify_structure,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier};
use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Verifier};
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::gate::floor;
use crate::seams::{FloorStore, SeamError};

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

/// One seed-bearing structure presented for stage-3 authentication: the exact
/// [`StructureSigInput`] it was detached-signed over and the signature. It
/// carries **no** trusted author — the gate authenticates it against the
/// committed writer-pseudonym set, so a signature under a non-committed key is
/// rejected.
#[derive(Clone)]
pub struct SignedStructure {
    /// The signed input `{scope, epoch, structTag, recipientTag?, H(ciphertext)}`.
    pub input: StructureSigInput,
    /// The detached pseudonym signature over [`structure_sig_preimage`] of the
    /// input.
    ///
    /// [`structure_sig_preimage`]: cipherbox_core::seal::structure_sig_preimage
    pub signature: Ed25519Signature,
}

/// A network-supplied ascent link presented for the stage-3 derive-and-verify
/// (`ascent-link-mismatch`). Present only when the reader descends through the
/// link from an ancestor scope; a same-scope holder passes `None`. The seed the
/// expected keypair re-derives from is **reader state**
/// ([`ReaderContext::parent_node_seed`]), never carried here — the candidate
/// producer must not supply its own verification key (blueprint/engine.md:
/// "Ancestor readers derive the expected ascent keypair from the parent node
/// seed").
#[derive(Clone)]
pub struct AscentCheck {
    /// The published ascent link (plaintext public half + HPKE-sealed seed).
    pub link: AscentLink,
    /// The structured AAD the link was sealed under.
    pub aad: AadContext,
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
    /// The scope root's grant-set commitment.
    pub commitment: GrantSetCommitment,
    /// The owner's identity signature over the commitment.
    pub commitment_sig: EcdsaSignature,
    /// The seed-bearing structures presented for stage-3 authentication.
    pub structures: Vec<SignedStructure>,
    /// The ascent link derive-and-verify, for an ancestor reader.
    pub ascent: Option<AscentCheck>,
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
    /// The scope id (the read-epoch floor key and the AAD scope binding).
    pub scope_id: [u8; 16],
    /// The reader's own derived scope read key for the read-body unseal.
    pub read_key: &'a [u8; 32],
    /// The reader's cached ancestor node seed — the trusted secret the expected
    /// ascent keypair re-derives from. Required whenever `candidate.ascent` is
    /// `Some`; a `None` here against a present ascent link is fail-closed
    /// (cannot verify).
    pub parent_node_seed: Option<[u8; 32]>,
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

/// The committed write-capable pseudonyms of a scope root: the owner pseudonym
/// plus every write-permission entry's pseudonym. Read-only entries never
/// authorize a seed-bearing structure.
fn committed_write_pseudonyms(commitment: &GrantSetCommitment) -> Vec<Ed25519Verifier> {
    let mut set = Vec::new();
    if let Some(owner) = Ed25519Verifier::from_bytes(commitment.owner_pseudonym_pk) {
        set.push(owner);
    }
    for entry in &commitment.entries {
        if entry.permission == Permission::Write {
            if let Some(pk) = Ed25519Verifier::from_bytes(entry.pseudonym_pk) {
                set.push(pk);
            }
        }
    }
    set
}

/// Authenticate one seed-bearing structure against the committed write-capable
/// pseudonyms. The structure is trusted iff its signature verifies under at
/// least one committed pseudonym; otherwise the whole record is a
/// `structure-signature-invalid` trust violation.
fn authenticate_structure(
    committed: &[Ed25519Verifier],
    structure: &SignedStructure,
) -> Result<(), CodecError> {
    for pseudonym in committed {
        if verify_structure(pseudonym, &structure.input, &structure.signature).is_ok() {
            return Ok(());
        }
    }
    Err(TrustViolation::StructureSignatureInvalid.into())
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

/// Open the reader's HPKE seed source, returning the recovered scope seed so the
/// gate can cross-check it derives the reader's read key. The returned
/// [`SecretBytes`] zeroizes on drop at the gate (the terminal owner).
fn open_seed_blob(blob: &SeedBlob<'_>) -> Result<SecretBytes, CodecError> {
    match blob {
        SeedBlob::Owner {
            enc_secret,
            enc,
            ciphertext,
            aad,
        } => {
            let payload = open_owner_blob(enc_secret, enc, aad, ciphertext)?;
            Ok(SecretBytes::new(*payload.override_seed()))
        }
        SeedBlob::Grantee {
            enc_secret,
            enc,
            ciphertext,
            aad,
        } => {
            let payload = open_grant_blob(enc_secret, enc, aad, ciphertext)?;
            Ok(SecretBytes::new(*payload.read_scope_seed()))
        }
    }
}

/// Constant-time 32-byte equality: no data-dependent early exit, so a mismatch
/// between a candidate-derived key and the caller-owned read key is never a
/// timing oracle over the reader's secret.
fn ct_eq_secret(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

/// Run the adoption gate over one hand-fed [`Candidate`] for one
/// [`ReaderContext`]. On success the floor law has advanced (per the
/// AAD-confirmed-unseal rule) and the unsealed read-body is returned; on
/// failure nothing durable changed and the caller pins last-known-good.
pub async fn adopt<F: FloorStore>(
    floors: &F,
    reader: &ReaderContext<'_>,
    candidate: &Candidate,
) -> Result<Adopted, GateError> {
    // Stage 1 — record verify (Ed25519 key from the name itself).
    let verified = IpnsRecord::unmarshal(&candidate.record_bytes)
        .and_then(|record| record.verify(&candidate.name))
        .map_err(|e| reject(GateStage::RecordVerify, RejectionReason::Trust(e)))?;

    // Stage 2 — commitment verify against the contact-anchored owner identity,
    // and its binding to this record's name (the name is inside the signed
    // commitment preimage; a commitment for a different scope root is invalid
    // here).
    verify_grant_set(
        reader.owner_identity,
        &candidate.commitment,
        &candidate.commitment_sig,
    )
    .map_err(|e| reject(GateStage::CommitmentVerify, RejectionReason::Trust(e)))?;
    if candidate.commitment.ipns_name != candidate.name.as_str().as_bytes() {
        return Err(reject(
            GateStage::CommitmentVerify,
            RejectionReason::Trust(TrustViolation::CommitmentInvalid.into()),
        ));
    }

    // Stage 3 — grant-section authentication under committed write pseudonyms.
    let committed = committed_write_pseudonyms(&candidate.commitment);
    for structure in &candidate.structures {
        // Bind every structure to THIS envelope: an authentically-signed
        // structure from another scope/epoch is a cross-epoch replay, not
        // adoption material, and any grant-section failure rejects the whole
        // record (blueprint/engine.md §"Adoption gate and floors", #39 D3).
        // TODO(grant-section): recompute ciphertext_hash from record bytes, don't trust structure.input
        if structure.input.scope_id != candidate.envelope.scope
            || structure.input.epoch != candidate.envelope.epoch
        {
            return Err(reject(
                GateStage::GrantSection,
                RejectionReason::Trust(TrustViolation::StructureSignatureInvalid.into()),
            ));
        }
        authenticate_structure(&committed, structure)
            .map_err(|e| reject(GateStage::GrantSection, RejectionReason::Trust(e)))?;
    }
    if let Some(ascent) = &candidate.ascent {
        // Ascent authority is reader-derived: the expected keypair comes from
        // the reader's cached ancestor node seed, never the network-supplied
        // candidate (blueprint/engine.md: "Ancestor readers derive the expected
        // ascent keypair from the parent node seed"). No reader seed ⇒ cannot
        // verify ⇒ fail closed.
        let parent_node_seed = reader.parent_node_seed.ok_or_else(|| {
            reject(
                GateStage::GrantSection,
                RejectionReason::Trust(TrustViolation::AscentLinkMismatch.into()),
            )
        })?;
        // Bind the link's AAD to THIS envelope: a link valid under the same
        // parent seed for another node/scope/epoch/version is a replay, not this
        // record's ascent (blueprint/engine.md:405-406 — derive-and-verify
        // against the current node). Fail closed before opening.
        if ascent.aad.scope != reader.scope_id
            || ascent.aad.id != candidate.envelope.id
            || ascent.aad.epoch != candidate.envelope.epoch
            || ascent.aad.v != candidate.envelope.v
            || ascent.aad.struct_tag != STRUCT_TAG_ASCENT_LINK
        {
            return Err(reject(
                GateStage::GrantSection,
                RejectionReason::Trust(TrustViolation::AscentLinkMismatch.into()),
            ));
        }
        // Cross-check the recovered override seed: the ascent public key is
        // published, so anyone can seal a rogue payload to it. The seed the link
        // carries is this scope root's current override seed (CONTEXT.md "Ascent
        // link"/"Override seed"), so it must belong to this epoch and derive this
        // node's read key — the ascent-link half of engine.md:406-408 (owner-blob
        // seed vs ascent-link seed vs actual unseal; any disagreement is
        // attributable abuse). The recovered `OverrideSeedPayload` and derived
        // `SecretBytes` are gate-owned and zeroize on drop; `reader.read_key` is
        // caller-owned and never zeroized.
        let payload = open_ascent_link(&parent_node_seed, &ascent.aad, &ascent.link)
            .map_err(|e| reject(GateStage::GrantSection, RejectionReason::Trust(e)))?;
        let node_seed = kdf::node_seed(payload.override_seed(), &candidate.envelope.id);
        let derived_read_key = kdf::read_key(node_seed.as_bytes());
        if payload.epoch != candidate.envelope.epoch
            || !ct_eq_secret(derived_read_key.as_bytes(), reader.read_key)
        {
            return Err(reject(
                GateStage::GrantSection,
                RejectionReason::Trust(TrustViolation::AscentLinkMismatch.into()),
            ));
        }
    }

    // Stage 4 — strictly newer than the durable per-name sequence floor.
    let name_bytes = candidate.name.as_str().as_bytes();
    let sequence_floor = floors
        .sequence_floor(name_bytes)
        .await
        .map_err(GateError::Seam)?
        .unwrap_or(0);
    if verified.sequence <= sequence_floor {
        return Err(reject(
            GateStage::Sequence,
            RejectionReason::SequenceNotNewer {
                floor: sequence_floor,
                sequence: verified.sequence,
            },
        ));
    }

    // Stage 5 — epoch tag at or above the scope's durable read-epoch floor.
    let epoch = candidate.envelope.epoch;
    let epoch_floor = floor::read_epoch_floor(floors, &reader.scope_id)
        .await
        .map_err(GateError::Seam)?
        .unwrap_or(0);
    if epoch < epoch_floor {
        return Err(reject(
            GateStage::Epoch,
            RejectionReason::EpochBelowFloor {
                floor: epoch_floor,
                epoch,
            },
        ));
    }

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
        // abuse event (blueprint/engine.md), never a silent staleness. The
        // derived `SecretBytes` are gate-owned and zeroize on drop here;
        // `reader.read_key` is caller-owned and never zeroized.
        let seed = open_seed_blob(blob)
            .map_err(|e| reject(GateStage::Unseal, RejectionReason::Trust(e)))?;
        let node_seed = kdf::node_seed(seed.as_bytes(), &candidate.envelope.id);
        let derived_read_key = kdf::read_key(node_seed.as_bytes());
        if !ct_eq_secret(derived_read_key.as_bytes(), reader.read_key) {
            return Err(reject(
                GateStage::Unseal,
                RejectionReason::Trust(TrustViolation::SealOpenFailed.into()),
            ));
        }
    }
    let read_body = open_read_body(&candidate.envelope, reader.read_key)
        .map_err(|e| reject(GateStage::Unseal, RejectionReason::Trust(e)))?;

    // Floor law — advance ONLY now, after the AAD-confirmed unseal.
    //
    // The stage-4/5 reads above and this advance are not a CAS pair, and they
    // do not need to be: the engine is the single writer (blueprint/engine.md
    // "Facade" — one live instance), so no concurrent adopt races this device's
    // floors between the read and the advance. Cross-writer contention is
    // resolved on the publish/RecordTransport plane (CAS), never on the local
    // floor read. `advance_on_unseal` itself orders its two raises fail-safe.
    floor::advance_on_unseal(
        floors,
        &reader.scope_id,
        name_bytes,
        verified.sequence,
        epoch,
    )
    .await
    .map_err(GateError::Seam)?;

    Ok(Adopted {
        read_body,
        sequence: verified.sequence,
        epoch,
    })
}

/// Build a `GateError::Rejected` from a stage and reason.
fn reject(stage: GateStage, reason: RejectionReason) -> GateError {
    GateError::Rejected(GateRejection { stage, reason })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
