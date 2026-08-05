//! The shared scope-root re-seal helper (blueprint/engine.md "Rotation
//! primitives: rotateScope", "sweep"; CONTEXT.md "Grant section").
//!
//! [`reseal_scope_root`] assembles a scope root's signed [`GrantSection`] — its
//! grant blobs (re-wrapped for the committed set), owner blob, owner-write-blob
//! (the write-plane mirror, authored beside the write-body), ascent link,
//! per-epoch history links, and sealed write-body — each detached-signed by the
//! rotator's writer pseudonym. It is a **pure composition** of `crates/core`'s
//! seal primitives: no crypto of its own, it samples no entropy (the injected
//! [`Entropy`] seam supplies every HPKE ephemeral scalar and seal nonce), and
//! reads no clock. Its [`ResealSeeds`] source is the axis both callers share:
//!
//! - **`rotateScope`** passes a fresh random override seed at a new read epoch
//!   plus the prior seed for a fresh history link — the read-plane root cut.
//! - **the sweep** passes the scope's *existing* seed at the *current* epoch with
//!   `prev = None` — a metadata-only catch-up minting no new seed or history link
//!   (blueprint/engine.md "Sweeps re-seal metadata only").
//!
//! # Revocation completeness is the point
//!
//! A grant blob is re-wrapped for **exactly** the committed set: one blob per
//! grant-ledger entry, and the ledger MUST equal the owner-signed commitment
//! (`(tag → permission)`), enforced fail-closed up front via
//! [`enforce_committed_ledger`] — the encode-side mirror of the adoption gate's
//! resolve check (AGENTS.md rule 8). A grantee removed from the commitment and
//! ledger by the read-revoke trigger is therefore **absent** from the re-wrapped
//! blobs — that absence is the revocation; a divergent ledger is rejected here,
//! never sealed.

use zeroize::{Zeroize, Zeroizing};

use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, AscentLink, GrantBlobPayload, GrantLedgerEntry, GrantSection, GrantSetCommitment,
    HistoryLinkPayload, MAX_HISTORY_LINKS, OverrideSeedPayload, OwnerWriteBlobPayload, Permission,
    PreservedFields, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_HISTORY_LINK,
    STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_WRITE_BODY, SignedAscentLink,
    SignedGrantBlob, SignedOwnerBlob, SignedOwnerWriteBlob, SignedSealed, StructureSigInput,
    WriteBody, encode_write_body, open_ascent_link, open_history_link, seal, seal_ascent_link,
    seal_grant_blob, seal_history_link, seal_owner_blob, seal_owner_write_blob, sign_structure,
};
use cipherbox_core::suite::aead;
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN as ECDSA_SIG_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, ct_eq};
use cipherbox_core::suite::x25519::X25519Public;

use crate::entropy::{Entropy, EntropyError};
use crate::grants::enforce_committed_ledger;

/// How many history links a re-seal carries forward — the ratchet's retained
/// window, in rotations (blueprint/core.md "History-link retention"). The window
/// is the deepest epoch lag a backward walk can cover; a node past it is
/// re-sealed forward by the next sweep rather than lost.
const MAX_RETAINED_HISTORY_LINKS: usize = 64;

// Under the decode bound, or a re-seal mints sections the decoder refuses; at
// least one, or `keep` below underflows and disables the prune in release.
const _: () = assert!(MAX_RETAINED_HISTORY_LINKS >= 1);
const _: () = assert!(MAX_RETAINED_HISTORY_LINKS <= MAX_HISTORY_LINKS);

/// The identity, recipients, and signing capability of one scope root — the
/// context-that-does-not-change-across-epochs half of a re-seal.
pub struct ScopeRootIdentity<'a> {
    /// The envelope format+suite version.
    pub v: u64,
    /// The scope-root node id (== scope id; `id` and `scope` in every AAD).
    pub scope_id: [u8; 16],
    /// The scope root's opaque `ipnsName` bytes (the commitment's anchor).
    pub ipns_name: &'a [u8],
    /// The vault owner's X25519 encryption-subkey public — the owner-blob
    /// recipient (the owner is an implicit, unrevokable grantee of every scope).
    pub owner_enc_pub: &'a X25519Public,
    /// The parent node seed the ascent link derives its keypair from; `None` at
    /// the vault root, which carries no ascent link.
    pub parent_node_seed: Option<&'a [u8; SECRET_LEN]>,
    /// The rotator's writer-pseudonym signer — detached-signs every structure.
    pub pseudonym_signer: &'a Ed25519Signer,
}

/// The previous epoch's read seed, sealed into a fresh history link under the
/// new epoch's structure key (the key-regression ratchet).
pub struct PrevEpochSeed<'a> {
    /// The previous epoch's override (read scope) seed.
    pub seed: &'a [u8; SECRET_LEN],
    /// The previous epoch it belongs to.
    pub epoch: u64,
}

/// The seed source of a re-seal — the axis that distinguishes a rotation cut
/// (fresh seed, new epoch, `prev = Some`) from a sweep catch-up (existing seed,
/// current epoch, `prev = None`).
pub struct ResealSeeds<'a> {
    /// The scope's read-plane override (read scope) seed sealed into the owner
    /// blob, ascent link, and every grant blob's `readScopeSeed`.
    pub override_seed: &'a [u8; SECRET_LEN],
    /// The read epoch this re-seal publishes at.
    pub read_epoch: u64,
    /// The prior epoch's seed for a fresh history link, or `None` when this
    /// re-seal introduces no new epoch (sweep catch-up).
    pub prev: Option<PrevEpochSeed<'a>>,
    /// The write-plane scope seed — unchanged by a read rotation — used to derive
    /// the write key/seed and sealed into write grants' `writeScopeSeed`.
    pub write_scope_seed: &'a [u8; SECRET_LEN],
    /// The write epoch the write-body publishes at (unchanged by a read rotation).
    pub write_epoch: u64,
    /// The stable per-scope pointer read key carried in every grant blob.
    pub pointer_read_key: &'a [u8; SECRET_LEN],
}

/// The owner-committed grant set plus the write-body content a re-seal carries.
pub struct CommittedSet<'a> {
    /// The owner-signed, epoch-free commitment (reused verbatim on a grantee
    /// rotation; owner-re-signed by the read-revoke trigger before it reaches
    /// here).
    pub commitment: &'a GrantSetCommitment,
    /// The 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: &'a [u8; ECDSA_SIG_LEN],
    /// The authoritative grant ledger — one grant blob is re-wrapped per entry.
    /// MUST equal `commitment` as a `(tag → permission)` set (enforced closed).
    pub grant_ledger: &'a [GrantLedgerEntry],
    /// The opaque write-plane history-link blob (carried through a read rotation).
    pub write_history_link: &'a [u8],
    /// The directly-descendant scope roots (the F-4 cascade index, #38 D6).
    pub direct_child_scope_index: &'a [cipherbox_core::seal::ChildScopeRef],
}

/// A fail-closed re-seal failure. Every variant leaves nothing published — the
/// caller ([`rotate_scope`](super::rotate::rotate_scope)) never advances a floor
/// on any of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResealError {
    /// The grant ledger to re-wrap does not match the owner-signed committed set
    /// (a write-grantee tried to add, drop, or re-permission a tag). The same
    /// invariant the adoption gate rejects on resolve, enforced here so a re-seal
    /// never seals a section the gate would refuse (fail-closed symmetry).
    LedgerDivergesFromCommitment,
    /// The rotator's pseudonym signer is not the owner-committed pseudonym key.
    /// Detach-signing every structure under an uncommitted key mints a scope root
    /// the adoption gate always rejects (an unopenable root); the same
    /// signer-binding invariant the gate checks on resolve, enforced here so a
    /// re-seal never signs a section the gate would refuse (fail-closed symmetry).
    SignerNotCommitted,
    /// A grant-ledger entry's recipient encryption key is unusable (malformed or
    /// low-order X25519). A grant can never be wrapped to an unopenable key.
    UnusableRecipientKey,
    /// The freshly sealed ascent link does not reopen as this epoch's override
    /// seed — bytes the gate's stage 3 rejects whole-record
    /// ([`verify_ascent_link`]).
    AscentLinkMismatch,
    /// Entropy acquisition failed; no seal proceeds without fresh randomness.
    Entropy(EntropyError),
    /// More carried history links than the codec's frozen bound admits — a set
    /// that could only ever produce a section this build's own encoder rejects.
    TooManyHistoryLinks,
    /// A re-sealed structure could not be encoded — a duplicate ledger tag, or
    /// nesting past the codec's `MAX_DEPTH`.
    Encode(cipherbox_core::error::CodecError),
}

impl core::fmt::Display for ResealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResealError::LedgerDivergesFromCommitment => {
                f.write_str("grant ledger diverges from the owner-signed committed set")
            }
            ResealError::SignerNotCommitted => {
                f.write_str("rotator signer is not the owner-committed pseudonym key")
            }
            ResealError::UnusableRecipientKey => {
                f.write_str("grant-ledger recipient encryption key is unusable")
            }
            ResealError::AscentLinkMismatch => {
                f.write_str("sealed ascent link does not reopen as this scope root's override seed")
            }
            ResealError::Entropy(e) => write!(f, "entropy error: {e}"),
            ResealError::TooManyHistoryLinks => {
                f.write_str("carried history links exceed the codec's frozen bound")
            }
            ResealError::Encode(e) => write!(f, "structure encode failed: {}", e.check()),
        }
    }
}

impl std::error::Error for ResealError {}

impl ResealError {
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            ResealError::LedgerDivergesFromCommitment => "ledger-diverges-from-commitment",
            ResealError::SignerNotCommitted => "signer-not-committed",
            ResealError::UnusableRecipientKey => "unusable-recipient-key",
            ResealError::AscentLinkMismatch => "ascent-link-mismatch",
            ResealError::Entropy(_) => "entropy-error",
            ResealError::TooManyHistoryLinks => "too-many-history-links",
            ResealError::Encode(_) => "structure-encode-failed",
        }
    }
}

/// The index of the oldest link in `carried` that still walks as this scope's
/// ratchet from `head`, newest first — everything older than the first link that
/// fails to open is dropped rather than published, since no reader could walk
/// past that break either (blueprint/core.md "History-link retention").
///
/// Truncating rather than refusing is deliberate: the carried set is
/// attacker-influenced — the adoption gate authenticates each link's signature
/// but nothing about their order — so failing the re-seal would let a committed
/// write-grantee permanently block the very rotation that revokes them.
fn walkable_chain_start(
    v: u64,
    scope_id: [u8; 16],
    head: &PrevEpochSeed<'_>,
    carried: &[SignedSealed],
) -> usize {
    let mut seed = Zeroizing::new(*head.seed);
    let mut epoch = head.epoch;
    for (i, link) in carried.iter().enumerate().rev() {
        let key = kdf::structure_key(&seed, STRUCT_TAG_HISTORY_LINK);
        let ctx = ctx_for(v, scope_id, epoch, STRUCT_TAG_HISTORY_LINK);
        let Ok(payload) = open_history_link(key.as_bytes(), &ctx, &link.sealed) else {
            return i + 1;
        };
        // The ratchet only ever steps backward; a flat or rising epoch is a
        // chain that cannot terminate.
        if payload.prev_epoch >= epoch {
            return i + 1;
        }
        seed = Zeroizing::new(*payload.prev_seed());
        epoch = payload.prev_epoch;
    }
    0
}

/// Fill an `N`-byte array from the entropy seam, fail-closed.
fn fill<const N: usize, E: Entropy>(entropy: &mut E) -> Result<[u8; N], ResealError> {
    let mut buf = [0u8; N];
    entropy.fill(&mut buf).map_err(ResealError::Entropy)?;
    Ok(buf)
}

/// Assemble one scope root's signed [`GrantSection`] at the epoch and seed the
/// `seeds` source dictates, re-wrapping grant blobs for exactly the committed
/// set. Pure composition of core seal primitives; the injected `entropy`
/// supplies every HPKE ephemeral scalar and seal nonce.
///
/// `carried_history_links` keep their sealed bytes verbatim — each stays
/// openable under the epoch key that minted it — but are re-signed at this
/// re-seal's read epoch, the one the gate recomputes every structure at. When
/// `seeds.prev` is `Some`, one freshly-minted link (the prior seed under the new
/// epoch's structure key) is appended, and the wire order is **oldest epoch
/// first**.
///
/// A rotation keeps the retained window's walkable suffix
/// ([`walkable_chain_start`]), so the prune to the newest
/// [`MAX_RETAINED_HISTORY_LINKS`] provably drops the oldest end rather than an
/// assumed one. A sweep publishes at the floor epoch without minting a link, so
/// the record's epoch label can outrun the newest link's minting epoch — the
/// AAD a walk needs, which [`ResealSeeds`] does not carry — leaving it unable to
/// walk or safely prune; it appends nothing, so the set cannot grow there.
/// Callers MUST still source the set from a gate-passed section.
///
/// Fails closed — see [`ResealError`] — before sealing anything on a divergent
/// ledger or an unusable recipient key, so a partial or unopenable section is
/// never produced. Terminal-owner rule: this function owns only the transient
/// seal plaintexts (zeroized by the core seal primitives); every borrowed seed
/// stays the caller's to zero.
pub fn reseal_scope_root<E: Entropy>(
    entropy: &mut E,
    identity: &ScopeRootIdentity<'_>,
    seeds: &ResealSeeds<'_>,
    committed: &CommittedSet<'_>,
    carried_history_links: &[SignedSealed],
) -> Result<GrantSection, ResealError> {
    // Fail-closed BEFORE any seal (see `ResealError::SignerNotCommitted`). The
    // pseudonym pubkey is public, so a plain byte compare is correct.
    if identity.pseudonym_signer.verifying_key().to_bytes()
        != committed.commitment.owner_pseudonym_pk
    {
        return Err(ResealError::SignerNotCommitted);
    }

    // Fail-closed BEFORE any seal (see `ResealError::LedgerDivergesFromCommitment`
    // and the module's revocation-completeness rule). Reseal trusts each entry's
    // `recipient_enc_pk` verbatim from the committed ledger; the tag<->enc_pk
    // binding is enforced at resolve time.
    enforce_committed_ledger(committed.commitment, committed.grant_ledger)
        .map_err(|_| ResealError::LedgerDivergesFromCommitment)?;

    // Fail-closed BEFORE any seal: the produce-side mirror of the codec's own
    // bound (AGENTS.md rule 8), so a sweep — which prunes nothing — can never
    // spend a section's worth of signatures on a set the encoder then refuses.
    if carried_history_links.len() > MAX_HISTORY_LINKS {
        return Err(ResealError::TooManyHistoryLinks);
    }

    let scope_id = identity.scope_id;
    let read_epoch = seeds.read_epoch;
    let signer = identity.pseudonym_signer;

    // Every structure signature binds the READ epoch, whatever epoch its own AAD
    // seals under: the gate recomputes each preimage from the authenticated
    // envelope, whose epoch tag is the read epoch (gate/adoption.rs stage 3).
    let sign_over = |struct_tag: u8, recipient_tag: Option<[u8; SECRET_LEN]>, bytes: &[u8]| {
        let input = StructureSigInput::over_ciphertext(
            scope_id,
            read_epoch,
            struct_tag,
            recipient_tag,
            bytes,
        );
        sign_structure(signer, &input).to_bytes()
    };

    // --- Grant blobs: one per committed grantee, sorted by tag for a stable
    // wire order that leaks no ledger ordering. ---
    let mut grant_blobs: Vec<SignedGrantBlob> = Vec::with_capacity(committed.grant_ledger.len());
    for entry in committed.grant_ledger {
        let recipient_pub = X25519Public::from_bytes(entry.recipient_enc_pk)
            .ok_or(ResealError::UnusableRecipientKey)?;
        let mut write_seed = match entry.permission {
            Permission::Write => Some(*seeds.write_scope_seed),
            Permission::Read => None,
        };
        let payload = GrantBlobPayload::new(
            *seeds.override_seed,
            write_seed,
            read_epoch,
            *seeds.pointer_read_key,
        );
        // Terminal-owner cleanup: the payload owns its own zeroizing copy, so wipe
        // this local write-seed copy before the next iteration.
        write_seed.zeroize();
        let mut ephemeral = fill::<32, E>(entropy)?;
        let ctx = ctx_for(identity.v, scope_id, read_epoch, STRUCT_TAG_GRANT_BLOB);
        let sealed = seal_grant_blob(&recipient_pub, &ephemeral, &ctx, &payload);
        ephemeral.zeroize();
        let sealed = sealed.map_err(ResealError::Encode)?;
        let signature = sign_over(STRUCT_TAG_GRANT_BLOB, Some(entry.tag), &sealed.ciphertext);
        grant_blobs.push(SignedGrantBlob {
            tag: entry.tag,
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
            signature,
            unknown: PreservedFields::new(),
        });
    }
    grant_blobs.sort_by(|a, b| a.tag.cmp(&b.tag));

    // --- Owner blob: the override seed wrapped to the owner. ---
    let owner_blob = {
        let payload = OverrideSeedPayload::new(*seeds.override_seed, read_epoch);
        let mut ephemeral = fill::<32, E>(entropy)?;
        let ctx = ctx_for(identity.v, scope_id, read_epoch, STRUCT_TAG_OWNER_BLOB);
        let sealed = seal_owner_blob(identity.owner_enc_pub, &ephemeral, &ctx, &payload);
        ephemeral.zeroize();
        let sealed = sealed.map_err(ResealError::Encode)?;
        let signature = sign_over(STRUCT_TAG_OWNER_BLOB, None, &sealed.ciphertext);
        SignedOwnerBlob {
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
            signature,
            unknown: PreservedFields::new(),
        }
    };

    // --- Owner-write-blob: the write-scope seed wrapped to the owner (the
    // write-plane mirror of the owner blob), authored wherever the write-body
    // lives. Its AAD binds the write epoch — the write plane's own clock. ---
    let owner_write_blob = {
        let payload = OwnerWriteBlobPayload::new(*seeds.write_scope_seed, seeds.write_epoch);
        let mut ephemeral = fill::<32, E>(entropy)?;
        let ctx = ctx_for(
            identity.v,
            scope_id,
            seeds.write_epoch,
            STRUCT_TAG_OWNER_WRITE_BLOB,
        );
        let sealed = seal_owner_write_blob(identity.owner_enc_pub, &ephemeral, &ctx, &payload);
        ephemeral.zeroize();
        let sealed = sealed.map_err(ResealError::Encode)?;
        let signature = sign_over(STRUCT_TAG_OWNER_WRITE_BLOB, None, &sealed.ciphertext);
        Some(SignedOwnerWriteBlob {
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
            signature,
            unknown: PreservedFields::new(),
        })
    };

    // --- Ascent link: the override seed sealed to the parent-derived keypair
    // (interior scope roots only). ---
    let ascent_link = match identity.parent_node_seed {
        Some(parent_node_seed) => {
            let payload = OverrideSeedPayload::new(*seeds.override_seed, read_epoch);
            let mut ephemeral = fill::<32, E>(entropy)?;
            let ctx = ctx_for(identity.v, scope_id, read_epoch, STRUCT_TAG_ASCENT_LINK);
            let link = seal_ascent_link(parent_node_seed, &ephemeral, &ctx, &payload);
            ephemeral.zeroize();
            let link = link.map_err(ResealError::Encode)?;
            verify_ascent_link(parent_node_seed, &ctx, seeds.override_seed, &link)?;
            let signature = sign_over(STRUCT_TAG_ASCENT_LINK, None, &link.ciphertext);
            Some(SignedAscentLink {
                ascent_public: link.ascent_public,
                enc: link.enc,
                ciphertext: link.ciphertext,
                signature,
                unknown: PreservedFields::new(),
            })
        }
        None => None,
    };

    // --- History links: a rotation keeps the retained window's walkable suffix
    // and appends one fresh link; a sweep carries what it has. ---
    let oldest_kept = match &seeds.prev {
        Some(prev) => {
            let window = carried_history_links
                .len()
                .saturating_sub(MAX_RETAINED_HISTORY_LINKS - 1);
            window
                + walkable_chain_start(identity.v, scope_id, prev, &carried_history_links[window..])
        }
        None => 0,
    };
    let mut history_links: Vec<SignedSealed> = carried_history_links[oldest_kept..]
        .iter()
        .map(|link| SignedSealed {
            signature: sign_over(STRUCT_TAG_HISTORY_LINK, None, &link.sealed),
            sealed: link.sealed.clone(),
            unknown: link.unknown.clone(),
        })
        .collect();
    if let Some(prev) = &seeds.prev {
        let structure_key = kdf::structure_key(seeds.override_seed, STRUCT_TAG_HISTORY_LINK);
        let nonce = fill::<{ aead::NONCE_LEN }, E>(entropy)?;
        let ctx = ctx_for(identity.v, scope_id, read_epoch, STRUCT_TAG_HISTORY_LINK);
        let payload = HistoryLinkPayload::new(*prev.seed, prev.epoch);
        let sealed = seal_history_link(structure_key.as_bytes(), &nonce, &ctx, &payload)
            .map_err(ResealError::Encode)?;
        let signature = sign_over(STRUCT_TAG_HISTORY_LINK, None, &sealed);
        history_links.push(SignedSealed {
            sealed,
            signature,
            unknown: PreservedFields::new(),
        });
    }

    // --- Write-body: sealed under the write key at the write epoch. ---
    let write_body = {
        let wb = WriteBody {
            grant_ledger: committed.grant_ledger.to_vec(),
            write_history_link: committed.write_history_link.to_vec(),
            direct_child_scope_index: committed.direct_child_scope_index.to_vec(),
            unknown: PreservedFields::new(),
        };
        let mut plaintext = encode_write_body(&wb).map_err(ResealError::Encode)?;
        let write_seed = kdf::write_seed(seeds.write_scope_seed, &scope_id);
        let write_key = kdf::write_key(write_seed.as_bytes());
        let nonce = fill::<{ aead::NONCE_LEN }, E>(entropy)?;
        let ctx = ctx_for(
            identity.v,
            scope_id,
            seeds.write_epoch,
            STRUCT_TAG_WRITE_BODY,
        );
        let sealed = seal(write_key.as_bytes(), &nonce, &ctx, &plaintext);
        plaintext.zeroize();
        let signature = sign_over(STRUCT_TAG_WRITE_BODY, None, &sealed);
        SignedSealed {
            sealed,
            signature,
            unknown: PreservedFields::new(),
        }
    };

    Ok(GrantSection {
        commitment: committed.commitment.clone(),
        commitment_sig: *committed.commitment_sig,
        grant_blobs,
        owner_blob,
        owner_write_blob,
        ascent_link,
        history_links,
        write_body,
        unknown: PreservedFields::new(),
    })
}

/// The produce-side half of the gate's stage-3 ascent-link cross-check
/// (`gate/adoption.rs`), release-active per AGENTS.md rule 8: reopen the link as
/// an ancestor reader does and confirm it carries the seed and epoch this
/// re-seal publishes at. The expected pair comes from [`ResealSeeds`], never
/// from the payload under test, so a link minted off the wrong local — the prior
/// epoch's seed, a stale epoch — fails here rather than at every ancestor
/// reader. Nothing downstream can catch it: the publisher holds no ancestor
/// seed, so the link stays unopenable until it reaches one.
///
/// The gate compares the read key the recovered seed derives; comparing the seed
/// is the same predicate one derivation earlier.
fn verify_ascent_link(
    parent_node_seed: &[u8; SECRET_LEN],
    ctx: &AadContext,
    override_seed: &[u8; SECRET_LEN],
    link: &AscentLink,
) -> Result<(), ResealError> {
    let payload = open_ascent_link(parent_node_seed, ctx, link)
        .map_err(|_| ResealError::AscentLinkMismatch)?;
    if payload.epoch != ctx.epoch || !ct_eq(payload.override_seed(), override_seed) {
        return Err(ResealError::AscentLinkMismatch);
    }
    Ok(())
}

/// The AAD context for a scope-root structure: `id == scope == scope_id` (a
/// scope root's node id is its scope id).
fn ctx_for(v: u64, scope_id: [u8; 16], epoch: u64, struct_tag: u8) -> AadContext {
    AadContext {
        v,
        id: scope_id,
        scope: scope_id,
        epoch,
        struct_tag,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::SeededEntropy;
    use cipherbox_core::seal::{
        GrantSetEntry, encode_grant_section, open_ascent_link, open_grant_blob, open_history_link,
        open_owner_blob, open_owner_write_blob, sign_grant_set, verify_structure,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Verifier};
    use cipherbox_core::suite::secret::ct_eq;
    use cipherbox_core::suite::x25519::X25519Secret;

    const V: u64 = 2;
    const SCOPE: [u8; 16] = [0x5c; 16];

    struct Fixture {
        owner_enc: X25519Secret,
        pseudonym: Ed25519Signer,
        owner_ecdsa: EcdsaSigner,
        parent_node_seed: [u8; 32],
        write_scope_seed: [u8; 32],
        pointer_read_key: [u8; 32],
        read_grantee: X25519Secret,
        write_grantee: X25519Secret,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                owner_enc: X25519Secret::from_scalar([0x11; 32]),
                pseudonym: Ed25519Signer::from_seed([0x22; 32]),
                owner_ecdsa: EcdsaSigner::from_scalar(&[0x33; 32]).unwrap(),
                parent_node_seed: [0x44; 32],
                write_scope_seed: [0x55; 32],
                pointer_read_key: [0x66; 32],
                read_grantee: X25519Secret::from_scalar([0x77; 32]),
                write_grantee: X25519Secret::from_scalar([0x88; 32]),
            }
        }

        fn read_tag() -> [u8; 32] {
            [0xa1; 32]
        }
        fn write_tag() -> [u8; 32] {
            [0xb2; 32]
        }

        /// A commitment + matching ledger for a read grantee and a write grantee.
        fn committed(
            &self,
        ) -> (
            GrantSetCommitment,
            [u8; ECDSA_SIG_LEN],
            Vec<GrantLedgerEntry>,
        ) {
            let entries = vec![
                GrantSetEntry::new(Self::read_tag(), Permission::Read, [0x02; 32]),
                GrantSetEntry::new(Self::write_tag(), Permission::Write, [0x03; 32]),
            ];
            let commitment = GrantSetCommitment {
                ipns_name: b"scope-root-name".to_vec(),
                owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
                entries,
                unknown: PreservedFields::new(),
            };
            let sig = sign_grant_set(&self.owner_ecdsa, &commitment)
                .unwrap()
                .to_compact();
            let ledger = vec![
                GrantLedgerEntry::new(
                    [0x02; 33],
                    self.read_grantee.public().to_bytes(),
                    Permission::Read,
                    Self::read_tag(),
                ),
                GrantLedgerEntry::new(
                    [0x03; 33],
                    self.write_grantee.public().to_bytes(),
                    Permission::Write,
                    Self::write_tag(),
                ),
            ];
            (commitment, sig, ledger)
        }
    }

    // `owner_enc_pub` needs a `&X25519Public`; hold it in a local so the borrow
    // outlives the call.
    fn identity<'a>(
        fx: &'a Fixture,
        owner_pub: &'a X25519Public,
        ipns_name: &'a [u8],
        parent: Option<&'a [u8; 32]>,
    ) -> ScopeRootIdentity<'a> {
        ScopeRootIdentity {
            v: V,
            scope_id: SCOPE,
            ipns_name,
            owner_enc_pub: owner_pub,
            parent_node_seed: parent,
            pseudonym_signer: &fx.pseudonym,
        }
    }

    fn seeds<'a>(
        override_seed: &'a [u8; 32],
        read_epoch: u64,
        prev: Option<PrevEpochSeed<'a>>,
        write_scope_seed: &'a [u8; 32],
        pointer_read_key: &'a [u8; 32],
    ) -> ResealSeeds<'a> {
        ResealSeeds {
            override_seed,
            read_epoch,
            prev,
            write_scope_seed,
            write_epoch: 1,
            pointer_read_key,
        }
    }

    fn committed_set<'a>(
        commitment: &'a GrantSetCommitment,
        sig: &'a [u8; ECDSA_SIG_LEN],
        ledger: &'a [GrantLedgerEntry],
    ) -> CommittedSet<'a> {
        CommittedSet {
            commitment,
            commitment_sig: sig,
            grant_ledger: ledger,
            write_history_link: b"",
            direct_child_scope_index: &[],
        }
    }

    fn verifier(fx: &Fixture) -> Ed25519Verifier {
        fx.pseudonym.verifying_key()
    }

    fn blob_sig(sig: &[u8; 64]) -> Ed25519Signature {
        Ed25519Signature::from_bytes(*sig)
    }

    #[test]
    fn reseal_round_trips_and_every_structure_is_pseudonym_signed() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let ipns = b"scope-root-name";
        let id = identity(&fx, &owner_pub, ipns, Some(&fx.parent_node_seed));

        let override_seed = [0x99; 32];
        let prev_seed = [0x9a; 32];
        let s = seeds(
            &override_seed,
            5,
            Some(PrevEpochSeed {
                seed: &prev_seed,
                epoch: 4,
            }),
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);

        let mut e = SeededEntropy::new(1);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");

        let ver = verifier(&fx);

        // Grant blobs: sorted by tag; read grantee opens read seed only, write
        // grantee opens both — all at the new epoch, all pseudonym-signed.
        assert_eq!(section.grant_blobs.len(), 2);
        for gb in &section.grant_blobs {
            let input = StructureSigInput::over_ciphertext(
                SCOPE,
                5,
                STRUCT_TAG_GRANT_BLOB,
                Some(gb.tag),
                &gb.ciphertext,
            );
            verify_structure(&ver, &input, &blob_sig(&gb.signature)).expect("grant blob signed");
        }

        let read_gb = section
            .grant_blobs
            .iter()
            .find(|b| b.tag == Fixture::read_tag())
            .unwrap();
        let ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_GRANT_BLOB);
        let read_payload =
            open_grant_blob(&fx.read_grantee, &read_gb.enc, &ctx, &read_gb.ciphertext).unwrap();
        assert!(ct_eq(read_payload.read_scope_seed(), &override_seed));
        assert!(
            read_payload.write_scope_seed().is_none(),
            "read grant, no write seed"
        );
        assert_eq!(read_payload.epoch, 5);
        assert!(ct_eq(read_payload.pointer_read_key(), &fx.pointer_read_key));

        let write_gb = section
            .grant_blobs
            .iter()
            .find(|b| b.tag == Fixture::write_tag())
            .unwrap();
        let write_payload =
            open_grant_blob(&fx.write_grantee, &write_gb.enc, &ctx, &write_gb.ciphertext).unwrap();
        assert!(ct_eq(write_payload.read_scope_seed(), &override_seed));
        assert!(
            ct_eq(
                write_payload.write_scope_seed().unwrap(),
                &fx.write_scope_seed
            ),
            "write grant carries the write scope seed"
        );

        // Owner blob → override seed.
        let owner_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_OWNER_BLOB);
        let owner_payload = open_owner_blob(
            &fx.owner_enc,
            &section.owner_blob.enc,
            &owner_ctx,
            &section.owner_blob.ciphertext,
        )
        .unwrap();
        assert!(ct_eq(owner_payload.override_seed(), &override_seed));

        // Owner-write-blob → write scope seed, AAD bound to the WRITE epoch (1),
        // structure signature bound to the READ epoch (5, the envelope's).
        let owb = section
            .owner_write_blob
            .as_ref()
            .expect("owner-write-blob authored beside the write-body");
        let owb_ctx = ctx_for(V, SCOPE, 1, STRUCT_TAG_OWNER_WRITE_BLOB);
        let owb_payload =
            open_owner_write_blob(&fx.owner_enc, &owb.enc, &owb_ctx, &owb.ciphertext).unwrap();
        assert!(ct_eq(owb_payload.write_scope_seed(), &fx.write_scope_seed));
        assert_eq!(owb_payload.write_epoch, 1);
        let owb_sig_input = StructureSigInput::over_ciphertext(
            SCOPE,
            5,
            STRUCT_TAG_OWNER_WRITE_BLOB,
            None,
            &owb.ciphertext,
        );
        verify_structure(&ver, &owb_sig_input, &blob_sig(&owb.signature))
            .expect("owner-write-blob signed at the read epoch");

        // Ascent link → override seed, opened with the parent seed.
        let ascent = section
            .ascent_link
            .as_ref()
            .expect("interior root has ascent");
        let ascent_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_ASCENT_LINK);
        let ascent_link = cipherbox_core::seal::AscentLink {
            ascent_public: ascent.ascent_public,
            enc: ascent.enc,
            ciphertext: ascent.ciphertext.clone(),
            unknown: PreservedFields::new(),
        };
        let ascent_payload =
            open_ascent_link(&fx.parent_node_seed, &ascent_ctx, &ascent_link).unwrap();
        assert!(ct_eq(ascent_payload.override_seed(), &override_seed));

        // History link → prev seed under the new epoch's structure key.
        assert_eq!(section.history_links.len(), 1);
        let hl_key = kdf::structure_key(&override_seed, STRUCT_TAG_HISTORY_LINK);
        let hl_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_HISTORY_LINK);
        let hl = open_history_link(hl_key.as_bytes(), &hl_ctx, &section.history_links[0].sealed)
            .unwrap();
        assert!(ct_eq(hl.prev_seed(), &prev_seed));
        assert_eq!(hl.prev_epoch, 4);

        // The whole section encodes (the release-active dup-tag guard passes).
        encode_grant_section(&section).expect("section encodes");
    }

    /// Release-active (rule 8): the guard returns `Err`, so a `--release` build
    /// refuses exactly the links a debug build does. Every reject row is a link
    /// an ancestor reader rejects whole-record.
    #[test]
    fn an_ascent_link_the_gate_would_reject_is_never_signed() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let parent_node_seed = fx.parent_node_seed;
        let override_seed = [0x99; 32];
        let ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_ASCENT_LINK);

        // The link a real re-seal mints passes its own guard.
        let id = identity(&fx, &owner_pub, b"scope-root-name", Some(&parent_node_seed));
        let s = seeds(
            &override_seed,
            ctx.epoch,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        let minted = reseal_scope_root(&mut SeededEntropy::new(13), &id, &s, &cs, &[])
            .expect("reseal")
            .ascent_link
            .expect("interior root has ascent");
        verify_ascent_link(
            &parent_node_seed,
            &ctx,
            &override_seed,
            &AscentLink {
                ascent_public: minted.ascent_public,
                enc: minted.enc,
                ciphertext: minted.ciphertext,
                unknown: PreservedFields::new(),
            },
        )
        .expect("a minted link is the one an ancestor reader opens");

        let sealed = |seed: &[u8; 32], carried: [u8; 32], epoch: u64| {
            seal_ascent_link(
                seed,
                &[0x07; 32],
                &ctx,
                &OverrideSeedPayload::new(carried, epoch),
            )
            .expect("seals")
        };
        for link in [
            // Sealed to a keypair no ancestor of this node derives.
            sealed(&[0x45; 32], override_seed, ctx.epoch),
            // Carries a seed that does not derive this node's read key.
            sealed(&parent_node_seed, [0x9a; 32], ctx.epoch),
            // Carries an epoch the record does not publish at.
            sealed(&parent_node_seed, override_seed, ctx.epoch + 1),
        ] {
            assert_eq!(
                verify_ascent_link(&parent_node_seed, &ctx, &override_seed, &link),
                Err(ResealError::AscentLinkMismatch),
            );
        }
        assert_eq!(
            ResealError::AscentLinkMismatch.check(),
            "ascent-link-mismatch"
        );
    }

    #[test]
    fn vault_root_omits_ascent_link() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let id = identity(&fx, &owner_pub, b"root", None);
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(2);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");
        assert!(
            section.ascent_link.is_none(),
            "vault root has no ascent link"
        );
        assert!(section.history_links.is_empty(), "no prev, no history link");
    }

    #[test]
    fn sweep_seed_source_mints_no_new_history_link() {
        // prev = None (sweep catch-up): no fresh link, carried sealed bytes kept
        // and re-signed at this read epoch.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let id = identity(&fx, &owner_pub, b"n", Some(&fx.parent_node_seed));
        let seed = [0x0e; 32];
        let s = seeds(&seed, 7, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let carried = vec![SignedSealed {
            sealed: b"prior-epoch-link".to_vec(),
            signature: [0x01; 64],
            unknown: PreservedFields::new(),
        }];
        let mut e = SeededEntropy::new(3);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &carried).expect("reseal");
        assert_eq!(section.history_links.len(), 1, "no fresh link minted");
        assert_eq!(
            section.history_links[0].sealed, carried[0].sealed,
            "the sealed link stays openable under the epoch key that minted it"
        );
        let input = StructureSigInput::over_ciphertext(
            SCOPE,
            7,
            STRUCT_TAG_HISTORY_LINK,
            None,
            &carried[0].sealed,
        );
        verify_structure(
            &verifier(&fx),
            &input,
            &blob_sig(&section.history_links[0].signature),
        )
        .expect("the carried link is re-signed at the epoch the gate recomputes at");
    }

    /// The synthetic chain's override seed for epoch `e`.
    fn chain_seed(e: u64) -> [u8; 32] {
        let mut seed = [0x40; 32];
        seed[..8].copy_from_slice(&e.to_be_bytes());
        seed
    }

    /// A real ratchet: links for epochs `2..=newest`, oldest first, each sealed
    /// under its own epoch's structure key and naming the epoch before it —
    /// exactly what `reseal_scope_root` mints, so the walk accepts it.
    fn real_chain(newest: u64) -> Vec<SignedSealed> {
        (2..=newest)
            .map(|e| {
                let key = kdf::structure_key(&chain_seed(e), STRUCT_TAG_HISTORY_LINK);
                let ctx = ctx_for(V, SCOPE, e, STRUCT_TAG_HISTORY_LINK);
                let payload = HistoryLinkPayload::new(chain_seed(e - 1), e - 1);
                SignedSealed {
                    sealed: seal_history_link(key.as_bytes(), &[0x5a; 24], &ctx, &payload).unwrap(),
                    signature: [0x01; 64],
                    unknown: PreservedFields::new(),
                }
            })
            .collect()
    }

    /// Re-seal at `newest + 1`, carrying `carried`.
    fn reseal_over_chain(
        fx: &Fixture,
        newest: u64,
        carried: &[SignedSealed],
    ) -> Result<GrantSection, ResealError> {
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let id = identity(fx, &owner_pub, b"n", None);
        let head = chain_seed(newest);
        let fresh = chain_seed(newest + 1);
        let s = seeds(
            &fresh,
            newest + 1,
            Some(PrevEpochSeed {
                seed: &head,
                epoch: newest,
            }),
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        reseal_scope_root(&mut SeededEntropy::new(11), &id, &s, &cs, carried)
    }

    #[test]
    fn retention_keeps_the_newest_window_and_drops_the_oldest() {
        // The ratchet is a contiguous chain, so only the oldest end may be
        // dropped — a hole would strand every epoch beyond it.
        let fx = Fixture::new();
        let newest = MAX_RETAINED_HISTORY_LINKS as u64 + 8;
        let carried = real_chain(newest);
        let section = reseal_over_chain(&fx, newest, &carried).expect("reseal");

        assert_eq!(
            section.history_links.len(),
            MAX_RETAINED_HISTORY_LINKS,
            "the fresh link rides inside the retained window, never past it"
        );
        let kept: Vec<&Vec<u8>> = section.history_links[..MAX_RETAINED_HISTORY_LINKS - 1]
            .iter()
            .map(|l| &l.sealed)
            .collect();
        let newest_carried: Vec<&Vec<u8>> = carried
            [carried.len() - (MAX_RETAINED_HISTORY_LINKS - 1)..]
            .iter()
            .map(|l| &l.sealed)
            .collect();
        assert_eq!(kept, newest_carried, "newest carried links kept, in order");
        let fresh = &section.history_links[MAX_RETAINED_HISTORY_LINKS - 1].sealed;
        assert!(
            !carried.iter().any(|l| &l.sealed == fresh),
            "the freshly minted link is appended last, keeping the wire order oldest-first"
        );
        // Retention is what holds a re-seal inside the codec's frozen bound.
        encode_grant_section(&section).expect("a retained section always encodes");
    }

    /// A mutation that breaks the carried chain inside the retained window, so
    /// the damage is not merely pruned away.
    type ChainBreak = fn(&mut Vec<SignedSealed>);

    #[test]
    fn a_chain_that_does_not_walk_is_truncated_never_refused() {
        // The carried set is attacker-influenced: the gate authenticates each
        // link's signature and nothing about their order. Refusing would let a
        // committed write-grantee block the rotation that revokes them, so the
        // unwalkable remainder is dropped and the cut still lands.
        let cases: [(&str, ChainBreak); 4] = [
            ("reversed", |c| c.reverse()),
            ("gapped", |c| {
                c.remove(c.len() - 3);
            }),
            ("tampered", |c| c.last_mut().unwrap().sealed[30] ^= 0xFF),
            ("interior swap", |c| {
                let n = c.len();
                c.swap(n - 2, n - 3);
            }),
        ];
        let fx = Fixture::new();
        for (name, break_chain) in cases {
            let mut carried = real_chain(12);
            break_chain(&mut carried);
            let section = reseal_over_chain(&fx, 12, &carried)
                .unwrap_or_else(|e| panic!("{name}: a broken chain must not block the cut: {e}"));
            assert!(
                section.history_links.len() < carried.len() + 1,
                "{name}: the unwalkable remainder must be dropped, not carried"
            );
            encode_grant_section(&section).unwrap_or_else(|e| panic!("{name}: encodes: {e}"));
        }
    }

    #[test]
    fn a_link_minted_for_another_scope_is_never_re_signed() {
        // The AAD binds the scope, so a genuine link lifted from another scope
        // opens under no seed this walk reaches — transplant, not tamper.
        let fx = Fixture::new();
        let mut carried = real_chain(12);
        let key = kdf::structure_key(&chain_seed(12), STRUCT_TAG_HISTORY_LINK);
        let ctx = ctx_for(V, [0xee; 16], 12, STRUCT_TAG_HISTORY_LINK);
        let payload = HistoryLinkPayload::new(chain_seed(11), 11);
        carried.last_mut().unwrap().sealed =
            seal_history_link(key.as_bytes(), &[0x5a; 24], &ctx, &payload).unwrap();

        let section = reseal_over_chain(&fx, 12, &carried).expect("the cut still lands");
        assert_eq!(
            section.history_links.len(),
            1,
            "nothing older than the transplant survives; only the fresh link remains"
        );
    }

    #[test]
    fn a_carried_set_past_the_codec_bound_fails_closed_before_any_seal() {
        // Release-active mirror of the codec's own bound: a set this big could
        // only ever produce a section this build's own encoder rejects.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(9);
        let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let carried = real_chain(MAX_HISTORY_LINKS as u64 + 3);
        let err = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &carried)
            .expect_err("past the bound");
        assert_eq!(err.check(), "too-many-history-links");
    }

    #[test]
    fn a_sweep_carries_its_chain_through_unpruned() {
        // A sweep mints no link, so the record's epoch label can outrun the
        // newest link's minting epoch — the AAD a walk needs. It neither walks
        // nor prunes; appending nothing, it cannot grow the set either.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = chain_seed(9);
        let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        // Past the retained window, so a reinstated sweep prune would show up.
        let carried = real_chain(MAX_RETAINED_HISTORY_LINKS as u64 + 8);
        let section = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &carried)
            .expect("a sweep re-seals whatever it carries");
        let sealed: Vec<&Vec<u8>> = section.history_links.iter().map(|l| &l.sealed).collect();
        let carried_sealed: Vec<&Vec<u8>> = carried.iter().map(|l| &l.sealed).collect();
        assert_eq!(
            sealed, carried_sealed,
            "carried through, in order, unpruned"
        );
    }

    #[test]
    fn revoked_grantee_is_absent_survivors_present_at_new_epoch() {
        // The revocation crown jewel: three grantees, revoke the middle one by
        // removing it from BOTH the commitment and the ledger, re-seal, and prove
        // the revokee has no blob while survivors decrypt to the fresh seed.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let revoked = X25519Secret::from_scalar([0xcc; 32]);
        let revoked_tag = [0xc3; 32];

        let entries = vec![
            GrantSetEntry::new(Fixture::read_tag(), Permission::Read, [0x02; 32]),
            GrantSetEntry::new(revoked_tag, Permission::Read, [0x04; 32]),
            GrantSetEntry::new(Fixture::write_tag(), Permission::Write, [0x03; 32]),
        ];
        let commitment = GrantSetCommitment {
            ipns_name: b"n".to_vec(),
            owner_pseudonym_pk: fx.pseudonym.verifying_key().to_bytes(),
            entries,
            unknown: PreservedFields::new(),
        };
        let ledger = vec![
            GrantLedgerEntry::new(
                [0x02; 33],
                fx.read_grantee.public().to_bytes(),
                Permission::Read,
                Fixture::read_tag(),
            ),
            GrantLedgerEntry::new(
                [0x04; 33],
                revoked.public().to_bytes(),
                Permission::Read,
                revoked_tag,
            ),
            GrantLedgerEntry::new(
                [0x03; 33],
                fx.write_grantee.public().to_bytes(),
                Permission::Write,
                Fixture::write_tag(),
            ),
        ];

        // Revoke: the read-revoke trigger's committed-set cut.
        let commitment_sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
            .unwrap()
            .to_compact();
        let cut = super::super::trigger::revoke_read_grant(
            &commitment,
            &commitment_sig,
            &ledger,
            &revoked_tag,
            &fx.owner_ecdsa,
        )
        .expect("revoke");
        assert!(
            !cut.grant_ledger.iter().any(|e| e.tag == revoked_tag),
            "revokee gone from ledger"
        );
        assert!(
            !cut.commitment.entries.iter().any(|e| e.tag == revoked_tag),
            "revokee gone from commitment"
        );

        let id = identity(&fx, &owner_pub, b"n", None);
        let new_seed = [0xef; 32];
        let s = seeds(
            &new_seed,
            2,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = CommittedSet {
            commitment: &cut.commitment,
            commitment_sig: &cut.commitment_sig,
            grant_ledger: &cut.grant_ledger,
            write_history_link: b"",
            direct_child_scope_index: &[],
        };
        let mut e = SeededEntropy::new(4);
        let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");

        // The revokee has NO grant blob.
        assert!(
            !section.grant_blobs.iter().any(|b| b.tag == revoked_tag),
            "revoked party's blob is absent — this is the revocation"
        );
        assert_eq!(
            section.grant_blobs.len(),
            2,
            "only survivors are re-wrapped"
        );
        // And the revokee cannot open any survivor's blob (fresh seed).
        let ctx = ctx_for(V, SCOPE, 2, STRUCT_TAG_GRANT_BLOB);
        for b in &section.grant_blobs {
            assert!(
                open_grant_blob(&revoked, &b.enc, &ctx, &b.ciphertext).is_err(),
                "revokee cannot open a survivor's blob"
            );
        }
        // Survivor opens the fresh seed.
        let read_gb = section
            .grant_blobs
            .iter()
            .find(|b| b.tag == Fixture::read_tag())
            .unwrap();
        let payload =
            open_grant_blob(&fx.read_grantee, &read_gb.enc, &ctx, &read_gb.ciphertext).unwrap();
        assert!(ct_eq(payload.read_scope_seed(), &new_seed));
    }

    #[test]
    fn diverging_ledger_fails_closed_release_active() {
        // A write-grantee adds a ledger row the owner never committed. The re-seal
        // rejects it with a runtime `Err` (not a debug_assert) — so a release
        // build never seals a section the gate would reject. This test is active
        // in release.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, mut ledger) = fx.committed();
        ledger.push(GrantLedgerEntry::new(
            [0x09; 33],
            X25519Secret::from_scalar([0x0f; 32]).public().to_bytes(),
            Permission::Write,
            [0xff; 32], // uncommitted tag
        ));
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(5);
        let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("diverging ledger");
        assert_eq!(err.check(), "ledger-diverges-from-commitment");
    }

    #[test]
    fn signer_not_committed_fails_closed_release_active() {
        // The rotator's pseudonym signer differs from the owner-committed pseudonym
        // key. The re-seal rejects it with a runtime `Err` (not a debug_assert) — so
        // a release build never signs a scope root the gate would reject as
        // signer-mismatched (an unopenable root). This test is active in release.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let wrong_signer = Ed25519Signer::from_seed([0x99; 32]);
        let id = ScopeRootIdentity {
            v: V,
            scope_id: SCOPE,
            ipns_name: b"scope-root-name",
            owner_enc_pub: &owner_pub,
            parent_node_seed: None,
            pseudonym_signer: &wrong_signer,
        };
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(7);
        let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("signer mismatch");
        assert_eq!(err.check(), "signer-not-committed");
    }

    #[test]
    fn unusable_recipient_key_fails_closed() {
        // A low-order (all-zero) recipient encryption key cannot receive a grant.
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let commitment = GrantSetCommitment {
            ipns_name: b"n".to_vec(),
            owner_pseudonym_pk: fx.pseudonym.verifying_key().to_bytes(),
            entries: vec![GrantSetEntry::new(
                Fixture::read_tag(),
                Permission::Read,
                [0x02; 32],
            )],
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
            .unwrap()
            .to_compact();
        let ledger = vec![GrantLedgerEntry::new(
            [0x02; 33],
            [0u8; 32], // low-order X25519 → from_bytes rejects
            Permission::Read,
            Fixture::read_tag(),
        )];
        let id = identity(&fx, &owner_pub, b"n", None);
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(6);
        let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("bad key");
        assert_eq!(err.check(), "unusable-recipient-key");
    }

    #[test]
    fn determinism_same_entropy_same_bytes() {
        let fx = Fixture::new();
        let owner_pub = fx.owner_enc.public();
        let (commitment, sig, ledger) = fx.committed();
        let id = identity(&fx, &owner_pub, b"n", Some(&fx.parent_node_seed));
        let seed = [0x01; 32];
        let prev = [0x02; 32];
        let build = || {
            let s = seeds(
                &seed,
                3,
                Some(PrevEpochSeed {
                    seed: &prev,
                    epoch: 2,
                }),
                &fx.write_scope_seed,
                &fx.pointer_read_key,
            );
            let cs = committed_set(&commitment, &sig, &ledger);
            let mut e = SeededEntropy::new(42);
            encode_grant_section(&reseal_scope_root(&mut e, &id, &s, &cs, &[]).unwrap()).unwrap()
        };
        assert_eq!(
            build(),
            build(),
            "same entropy seed → byte-identical section"
        );
    }
}
