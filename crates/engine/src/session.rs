//! Cold-start session identity — the seed-derived signing and sealing identity
//! assembled once at [`Engine::start`](crate::facade::Engine::start).
//!
//! The cold-start sequence begins by deriving, as a pure function of the login
//! secret, the owner-plane identity that needs no network: the encryption
//! subkey, the owner pointer seed, and the vault-pointer signer chain
//! (blueprint/engine.md "Pointer planes"; CONTEXT.md "Vault pointer", "Scope
//! pointer", "Encryption subkey"). Per-scope read/write material and the
//! per-name write-plane signers layer on top through the factory methods here,
//! fed the scope seeds the resolve/gate path unseals — this module owns the
//! derivation edges, its callers own the inputs.
//!
//! Every derivation composes `crates/core`'s frozen KDF edge catalog
//! ([`cipherbox_core::kdf`]); nothing here derives a key of its own. The whole
//! type is a pure function of the injected secret — no clock, no RNG — so the
//! same secret always yields the same identity (the determinism a cold-start
//! test pins). Secret material lives in zeroizing owners and is redacted from
//! `Debug`; the login secret is retained in engine memory only, because the
//! vault-pointer chain is index-probed at runtime (cold start and per tick,
//! CONTEXT.md "Vault pointer") and cannot be fully pre-derived.

use core::cell::{Cell, RefCell};
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use zeroize::Zeroizing;

use crate::bin_index::BinIndexKeys;
use crate::facade::{
    ClaimCounts, EngineError, LoginSecret, NodeId, RetainedDeadLetters, ScopeSeeds, SweepKeys,
    SweepTaskFactory, SyncStatus,
};
use crate::grants::accept::ReceivedSharesLock;
use crate::grants::grafted::{
    BookmarkedPermissions, BookmarkedScopeRoots, ClaimRecord, GraftedSharers,
};
use crate::grants::received_status::ReceivedVerdicts;
use crate::net::HeldRecords;
use crate::net::retire::{OrphanHeads, ReclaimStall};
use crate::net::rotation::OnAccessMisses;
use crate::rotation::WalkedReadEpochs;
use crate::seams::UnixMillis;
use crate::settings::{SessionPlacement, VaultSettingsSummary};
use crate::sync::cancel::UploadCancels;
use crate::sync::drain::{BookkeepingCursors, QueueHold};
use crate::sync::model::Snapshot;
use crate::sync::project::UnlinkedChild;
use crate::sync::rebase::QueueScanMemo;
use crate::sync::render::BaseSnapshot;
use crate::sync::staging::LiveBlocks;
use crate::sync::tick::FocusWindow;

/// The session's seed-derived identity — the single place derived key material
/// lives once the engine is live.
///
/// Constructed by [`SessionIdentity::derive`] at cold start and held by the
/// engine for the session's lifetime. Public-key accessors are `pub`; the
/// signer/seal factories that return secret-bearing material are `pub(crate)`,
/// reachable only by the in-crate pipeline (resolve, publish, rotation, the
/// liveness loop) — hosts wrap the facade and never hold signers.
// Not every derivation factory has a live caller yet.
#[allow(dead_code)]
pub(crate) struct SessionIdentity {
    /// The login secret, retained for the runtime vault-pointer index probe.
    /// Engine memory only: never persisted, never logged, zeroized on drop.
    login_secret: Zeroizing<Vec<u8>>,
    /// The user's X25519 encryption subkey (`enc-subkey` edge). Seals, and —
    /// as the op record's HPKE static sender — authenticates authorship of a
    /// queued op; the identity key signs. Zeroizes on drop.
    enc_subkey: X25519Secret,
    /// The owner pointer seed (`owner-pointer-seed` edge). Per-scope pointer
    /// signers and pointer read keys derive from it lazily. Zeroizes on drop.
    owner_pointer_seed: SecretBytes,
    /// The owner pseudonym seed (`owner-pseudonym-seed` edge) — the owner's
    /// `pseudonym-sign` input, kept off the encryption and pointer planes
    /// (ADR 0005). Zeroizes on drop.
    owner_pseudonym_seed: SecretBytes,
    /// The contact-label seed (`contact-label-seed` edge) — what a contact
    /// identity is labelled under before it keys durable local state
    /// ([`ContactLabel`](crate::seams::ContactLabel)). Zeroizes on drop.
    contact_label_seed: SecretBytes,
    /// The owner ECDSA identity: the login-secret scalar adopted directly (v1
    /// Web3Auth TSS export is the secp256k1 identity key), not a catalog edge.
    /// Signs the login challenge and structure commitments; its verifier is the
    /// owner-trust anchor the adoption gate checks. Zeroizes on drop.
    identity: EcdsaSigner,
}

#[allow(dead_code)]
impl SessionIdentity {
    /// Derive the cold-start identity from the login secret — a pure function
    /// of the secret bytes (no clock, no RNG), composing only frozen catalog
    /// edges. Same secret in, same identity out.
    ///
    /// Fails closed ([`EngineError::InvalidSecret`]) when the secret is not a
    /// 32-byte scalar in range: the owner identity is the scalar adopted
    /// directly, so a wrong-length or out-of-range secret has no valid identity
    /// and must never derive a silent default (a real Web3Auth key is always
    /// valid, so this is a guard, not a live path).
    pub(crate) fn derive(secret: &LoginSecret) -> Result<Self, EngineError> {
        let bytes = secret.expose();
        let scalar: Zeroizing<[u8; SECRET_LEN]> =
            Zeroizing::new(bytes.try_into().map_err(|_| EngineError::InvalidSecret)?);
        let identity = EcdsaSigner::from_scalar(&scalar).ok_or(EngineError::InvalidSecret)?;
        Ok(Self {
            login_secret: Zeroizing::new(bytes.to_vec()),
            enc_subkey: kdf::enc_subkey(bytes),
            owner_pointer_seed: kdf::owner_pointer_seed(bytes),
            owner_pseudonym_seed: kdf::owner_pseudonym_seed(bytes),
            contact_label_seed: kdf::contact_label_seed(bytes),
            identity,
        })
    }

    /// The public half of the encryption subkey — the sealing identity peers
    /// address. Non-secret; safe to publish and to compare in tests.
    pub fn enc_subkey_public(&self) -> X25519Public {
        self.enc_subkey.public()
    }

    /// The owner ECDSA identity signer — the login-challenge and structure
    /// commitment signer. Secret-bearing, so in-crate only.
    pub(crate) fn identity(&self) -> &EcdsaSigner {
        &self.identity
    }

    /// The owner identity verifier — the owner-trust anchor a resolved record
    /// is gated against. Public material.
    pub fn owner_identity(&self) -> EcdsaVerifier {
        self.identity.verifying_key()
    }

    /// The retained login secret, for the runtime vault-pointer index probe
    /// (cold start and per tick). Owner-plane name/read-key derivation happens
    /// inside the pointer walk, which needs the raw secret; secret-bearing, so
    /// in-crate only.
    pub(crate) fn login_secret(&self) -> &[u8] {
        &self.login_secret
    }

    /// The encryption subkey itself — the sealing key the grant/mailbox paths
    /// use. Secret-bearing, so in-crate only.
    pub(crate) fn enc_subkey(&self) -> &X25519Secret {
        &self.enc_subkey
    }

    /// This member's own contact code: the self-authenticating
    /// `{identityPk, encSubkey, bindingSig}` bundle a peer imports. Public
    /// material — the binding signature is over two public keys, and nothing
    /// here is secret-bearing.
    pub(crate) fn contact_code(&self) -> Vec<u8> {
        ContactCode::create(&self.identity, self.enc_subkey.public()).encode()
    }

    /// The `i`-th vault-pointer signer (`vault-pointer-index` edge): the
    /// per-name Ed25519 signer for the indexed owner re-point chain, index 0
    /// the default. Probed one past the highest known on cold start and per
    /// tick (CONTEXT.md "Vault pointer"), so it derives on demand.
    pub(crate) fn vault_pointer_signer(&self, index: u64) -> Ed25519Signer {
        kdf::vault_pointer_index(&self.login_secret, index)
    }

    /// The per-scope pointer signer (`scope-pointer` edge): the owner-keyed
    /// stable IPNS name a shared scope carries, from the owner pointer seed
    /// and the scope id.
    pub(crate) fn scope_pointer_signer(&self, scope_id: &[u8; 16]) -> Ed25519Signer {
        kdf::scope_pointer(self.owner_pointer_seed.as_bytes(), scope_id)
    }

    /// The per-scope pointer **name** — [`Self::scope_pointer_signer`]'s public
    /// half, and the whole capability a consult needs.
    pub(crate) fn scope_pointer_name(&self, scope_id: &[u8; 16]) -> IpnsName {
        IpnsName::from_public_key(&self.scope_pointer_signer(scope_id).verifying_key())
    }

    /// The stable per-scope pointer read key (`pointer-read-key` edge) that
    /// seals a scope's re-point object.
    pub(crate) fn pointer_read_key(&self, scope_id: &[u8; 16]) -> SecretBytes {
        kdf::pointer_read_key(self.owner_pointer_seed.as_bytes(), scope_id)
    }

    /// The owner pointer seed itself — the write wave seals its re-point object
    /// under a key derived from it, and the sweep's pointer consult derives the
    /// name it reads. Broader than [`Self::pointer_read_key`] (it also derives
    /// the pointer **signing** key), so in-crate and used only where both halves
    /// are needed.
    pub(crate) fn owner_pointer_seed(&self) -> SecretBytes {
        SecretBytes::new(*self.owner_pointer_seed.as_bytes())
    }

    /// The owner pseudonym seed (`owner-pseudonym-seed` edge) — the input to
    /// every per-scope `pseudonym-sign`. Copied out only for a spawned task that
    /// outlives a borrow of this session ([`crate::owner_keys::OwnerSeedKeys`]).
    pub(crate) fn owner_pseudonym_seed(&self) -> SecretBytes {
        SecretBytes::new(*self.owner_pseudonym_seed.as_bytes())
    }

    /// The contact-label seed (`contact-label-seed` edge) — the input every
    /// [`ContactLabel`](crate::seams::ContactLabel) derives under.
    pub(crate) fn contact_label_seed(&self) -> &SecretBytes {
        &self.contact_label_seed
    }

    /// The genesis scope read (override) seed (`genesis-read-scope-seed` edge).
    /// Derived, not drawn, so two mint attempts by one account reproduce one
    /// vault (ADR 0007 D1); every later read seed is drawn at its rotation.
    pub(crate) fn genesis_read_scope_seed(&self) -> SecretBytes {
        kdf::genesis_read_scope_seed(&self.login_secret)
    }

    /// The genesis `writeScopeSeed` (`genesis-write-scope-seed` edge) — see
    /// [`Self::genesis_read_scope_seed`].
    pub(crate) fn genesis_write_scope_seed(&self) -> SecretBytes {
        kdf::genesis_write_scope_seed(&self.login_secret)
    }

    /// The per-name write-plane IPNS signer for a node: `writeSeed(node) =
    /// KDF(writeScopeSeed, node.id)` then the `ipns-keypair` edge. This is the
    /// per-name `Ed25519Signer` the held set stores for its sub-EOL `seq+1`
    /// renewal — the resolve/gate path supplies the unsealed `write_scope_seed`.
    /// Keyed solely by its arguments (no session field), so it is an associated
    /// function the held-set insert can call directly.
    pub(crate) fn write_name_signer(
        write_scope_seed: &[u8; 32],
        node_id: &[u8; 16],
    ) -> Ed25519Signer {
        let write_seed = kdf::write_seed(write_scope_seed, node_id);
        kdf::ipns_keypair(write_seed.as_bytes())
    }

    /// The owner's writer-pseudonym signer for a scope: the `pseudonym-sign`
    /// edge over the session's `ownerPseudonymSeed`.
    ///
    /// Takes only the scope id, so the owner's pairwise input cannot be
    /// supplied — and mis-supplied — by a caller. A provisioned
    /// `ownerPseudonymPk` is committed epoch-free and never revised, so wrong
    /// bytes here are a permanent `SignerNotCommitted` on every later rotation.
    pub(crate) fn owner_writer_pseudonym_signer(&self, scope_id: &[u8; 16]) -> Ed25519Signer {
        kdf::pseudonym_sign(self.owner_pseudonym_seed.as_bytes(), scope_id)
    }

    /// A **grantee's** writer-pseudonym signer (`pseudonym-sign` edge): the
    /// per-(scope, writer) signing keypair a re-sealed structure is
    /// detach-signed under, from the grant's pairwise ECDH secret and the scope
    /// id. That secret already fully encodes the writer's identity, so — unlike
    /// every sibling factory — this one consults no stored session field, and is
    /// therefore an associated function. The owner arm is
    /// [`Self::owner_writer_pseudonym_signer`].
    pub(crate) fn grantee_writer_pseudonym_signer(
        grant_ecdh: &[u8; 32],
        scope_id: &[u8; 16],
    ) -> Ed25519Signer {
        kdf::pseudonym_sign(grant_ecdh, scope_id)
    }
}

impl fmt::Debug for SessionIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionIdentity(redacted)")
    }
}

/// The session cells the command path and the tick loop share. Each cell keeps
/// its own `Rc`, so a spawned task can still hold one cell alone.
pub(crate) struct SessionState {
    /// The staging keys the live write handles hold — orphan GC's live set, shared with
    /// the tick loop that sweeps after each drain pass.
    pub(crate) live_blocks: Rc<RefCell<LiveBlocks>>,
    /// The upload-cancel interlock, shared with the drain the tick loop runs.
    pub(crate) cancels: Rc<RefCell<UploadCancels>>,
    /// The last-known-good gate-passing base snapshot (state law's left
    /// operand). Seeded at the anchored root; cold-start/resolve replace it
    /// with the resolved remote state. Reads render this ⊕ the pending-op
    /// overlay; commands never mutate it — only the op queue diverges locally.
    /// Behind an [`Rc`] so the resolve-tick loop shares the one cell and
    /// repaints it in place from a gate-passing live resolve. Every repaint
    /// bumps the cell's generation, which is half of what
    /// [`render_memo`](crate::facade::Engine::render_memo) is keyed on.
    pub(crate) snapshot: Rc<BaseSnapshot>,
    /// The session's live held-record set — see [`HeldRecords`] for what enters
    /// it. The liveness loop this session spawns keyless re-PUTs its values on
    /// the hourly cadence.
    pub(crate) held_records: Rc<RefCell<HeldRecords>>,
    /// Scope roots this session owes a scope-exit cut for, driven by the drain.
    /// Session-lived, like the orphan-head set.
    pub(crate) pending_scope_exits: Rc<RefCell<BTreeSet<NodeId>>>,
    /// Staleness bookkeeping shared with the resolve-tick loop: it stamps
    /// successes and reports rung changes; [`snapshot`](crate::facade::Engine::snapshot)
    /// classifies at read time off the same cell.
    pub(crate) sync_status: Rc<RefCell<SyncStatus>>,
    /// Per-scope read seeds recovered by gate-passing adopts (the owner-blob
    /// override seed), keyed by scope id. In-memory only — never persisted,
    /// never crossing the facade (security rules 1/3); the child read pipeline
    /// derives per-node read keys from them (`node-seed` → `read-key`).
    ///
    /// Every key is the vault root scope id, a scope root below it this vault
    /// owns, or a grafted scope id. The eviction pass reads that as an
    /// invariant: it drops a seed under any other key,
    /// because no floor namespace answers for one
    /// ([`evict_grafted_read_seeds`](crate::grants::grafted::evict_grafted_read_seeds)).
    pub(crate) scope_read_seeds: Rc<RefCell<ScopeSeeds>>,
    /// Per-scope write seeds recovered by gate-passing adopts (the
    /// owner-write-blob seed), keyed by scope id. In-memory only, exactly like
    /// [`scope_read_seeds`](Self::scope_read_seeds); the drain derives each new
    /// node's `ipnsName` and its narrow per-name signer from them.
    pub(crate) scope_write_seeds: Rc<RefCell<ScopeSeeds>>,
    /// The scope roots below the vault root that a gated descent proved this
    /// session holds
    /// ([`ScopeWalk::descendant_scope_roots`](crate::net::ScopeWalk::descendant_scope_roots)).
    /// In-memory only, grow-only within a session
    /// (`install_descendant_scopes`); the read legs group focus targets against
    /// it ([`scope_root_of`](crate::sync::tick::scope_root_of)).
    pub(crate) descendant_scope_roots: Rc<RefCell<BTreeSet<NodeId>>>,
    /// Scope roots the same walk named but proved no material for: a folder
    /// publishing under a name its parent scope's write seed does not derive is
    /// a scope root of its own, whether or not the parent's child-scope index
    /// still names it
    /// ([`ScopeWalk::descendant_scope_roots`](crate::net::ScopeWalk::descendant_scope_roots)).
    /// Grows within a session until a walk proves the root
    /// (`install_unproved_scopes`). A boundary with no material still splits
    /// the focus window (`focus_scope_roots`) and still names a crossing a
    /// relocation is classified against
    /// ([`relocation_scope_roots`](crate::facade::Engine::relocation_scope_roots)).
    pub(crate) unproved_scope_roots: Rc<RefCell<BTreeSet<NodeId>>>,
    /// Whether the last boundary walk to reach a verdict met a trust rejection.
    /// While it stands the session refuses every relocation, because a walk
    /// that could not gate a descendant scope root names no boundary below it,
    /// and every move out of that scope would read intra-scope. Only a later
    /// walk that proves its whole boundary set lifts it; an availability
    /// failure neither raises nor lifts it.
    pub(crate) boundary_walk_rejected: Rc<Cell<bool>>,
    /// Whether the last boundary walk proved every scope root it named. Until
    /// one has, a scope root can be missing from the known set.
    pub(crate) scope_roots_walked: Rc<Cell<bool>>,
    /// The read epoch the same walk proved each of them at, which no seed cache
    /// carries ([`crate::rotation::scope_material`]). Replaced per walk, unlike
    /// the set above.
    pub(crate) walked_read_epochs: Rc<RefCell<WalkedReadEpochs>>,
    /// The `ipnsName` the vault root scope currently publishes under: adopted at
    /// cold start, minted by a first run, moved by a write wave this session
    /// drove, and re-read from the vault pointer on every consult. `None` until
    /// one of those lands.
    ///
    /// A write wave moves the root and leaves the predecessor name **dead to
    /// survivors but live to the revokee**, who still holds its write-name key
    /// (blueprint/engine.md "Residuals"). The cached write scope seed lags the
    /// wave until an adopt re-deposits it, so an owner action that re-derived
    /// its target would name the dead root. This cell is what the derivation is
    /// proved against ([`vault_root_scope`](crate::facade::Engine::vault_root_scope)).
    pub(crate) current_root_name: Rc<RefCell<Option<IpnsName>>>,
    /// The open focus window
    /// ([`Command::SetFocus`](crate::facade::Command::SetFocus)): the folder
    /// the host has open, whose record and whole ancestor chain every resolve
    /// tick refreshes. Shared with the tick loop, which reads it on each pass.
    pub(crate) focus: Rc<RefCell<FocusWindow>>,
    /// When each focus folder was last refreshed, so a navigation inside the
    /// staleness threshold renders state already held instead of re-probing the
    /// record plane (blueprint/engine.md: refresh on access past the threshold).
    pub(crate) focus_refreshed: Rc<RefCell<BTreeMap<NodeId, UnixMillis>>>,
    /// When each scope's pointer was last consulted, so the polled consult runs
    /// at
    /// [`SyncTimingProfile::pointer_consult_interval`](crate::profile::SyncTimingProfile::pointer_consult_interval)
    /// rather than at the poll cadence. In-memory: a floor only ever moves up,
    /// so a restart's first tick re-consults and re-derives it.
    pub(crate) pointer_consulted: Rc<RefCell<BTreeMap<NodeId, UnixMillis>>>,
    /// The owner accesses' scope-pointer consult misses ([`OnAccessMisses`]).
    pub(crate) on_access_misses: OnAccessMisses,
    /// The verdict the tick's last pass reached for each bookmarked shared
    /// scope. In-memory: a verdict is what a live resolve found, so a restart
    /// re-earns it rather than rendering one nothing observed this session.
    pub(crate) received_verdicts: Rc<RefCell<ReceivedVerdicts>>,
    /// Held across every load, change and persist of the received-shares list,
    /// so the join, the accept and the refresh never overwrite each other.
    pub(crate) received_shares_lock: Rc<ReceivedSharesLock>,
    /// Rebuilt by the received-share pass, like
    /// [`received_verdicts`](Self::received_verdicts).
    pub(crate) grafted_sharers: Rc<RefCell<GraftedSharers>>,
    /// Rebuilt by the same pass: the cross-plane rule the focus window's folder
    /// leg applies below a grafted root
    /// ([`GraftedPlane`](crate::grants::grafted::GraftedPlane)).
    pub(crate) bookmarked_scope_roots: Rc<RefCell<BookmarkedScopeRoots>>,
    /// Rebuilt by the same pass: what each bookmarked scope's accepted grant
    /// permits this vault to do, which is what [`snapshot`](crate::facade::Engine::snapshot)
    /// reports so a host can refuse a write at the gesture.
    pub(crate) bookmarked_permissions: Rc<RefCell<BookmarkedPermissions>>,
    /// The grafted roots the last tick built a drain pass for, which is every
    /// fact a write below one needs (`grafted_write_passes`).
    pub(crate) grafted_write_roots: Rc<RefCell<BTreeSet<NodeId>>>,
    /// Folded by the same pass: what each renderable grafted scope's body
    /// named, which decides the ids no plane may render.
    pub(crate) grafted_claims: Rc<RefCell<ClaimRecord>>,
    /// The folders this session's own grants promoted into scope roots. The
    /// mint is the one moment a session proves it promoted a folder, so it is
    /// the only writer; read by
    /// [`relocation_scope_roots`](crate::facade::Engine::relocation_scope_roots).
    pub(crate) minted_scope_roots: Rc<RefCell<BTreeSet<NodeId>>>,
    /// The conversion entries the last conversion pass counted.
    pub(crate) pending_invite_claims: Rc<RefCell<ClaimCounts>>,
    /// Set while a conversion pass runs (`ConversionPass::running`).
    pub(crate) conversion_running: Rc<Cell<bool>>,
    /// Retained dead-lettered ops. Feeds
    /// [`SnapshotView`](crate::facade::SnapshotView)'s dead-letter surface (#33
    /// D6: dead letters are retained, never silent).
    pub(crate) dead_letters: Rc<RefCell<RetainedDeadLetters>>,
    /// Memo of the durable queue scan every read renders through
    /// ([`scan_queue`](crate::facade::Engine::scan_queue)).
    pub(crate) queue_scan: Rc<RefCell<QueueScanMemo>>,
    /// The drain's held queue head, written by the drain tick and read by
    /// [`snapshot`](crate::facade::Engine::snapshot). In-memory: a restart re-derives it from the
    /// next drain attempt's own verdict rather than trusting a stale one.
    pub(crate) queue_hold: Rc<RefCell<Option<QueueHold>>>,
    /// Pinned bytes a published prune still owes the registry, written by the
    /// drain tick and read by
    /// [`pending_reclaim_bytes`](crate::facade::Engine::pending_reclaim_bytes).
    /// In-memory: the durable record is the retire ledger, which every pass re-reads.
    pub(crate) pending_reclaim: Rc<Cell<u64>>,
    /// Why the debts the last reclaim pass could not settle did not settle,
    /// written by the drain tick and read by
    /// [`reclaim_stalls`](crate::facade::Engine::reclaim_stalls). In-memory for the same reason
    /// [`pending_reclaim`](Self::pending_reclaim) is: every pass re-derives it
    /// from the retire ledger.
    pub(crate) reclaim_stalls: Rc<RefCell<Vec<ReclaimStall>>>,
    /// Where each bounded bookkeeping loop stopped, and whether the reclaim
    /// figure prices the whole owed set ([`BookkeepingCursors`]).
    pub(crate) bookkeeping: Rc<RefCell<BookkeepingCursors>>,
    /// Head blocks the drain uploaded for a publish that never reached the
    /// record transport, pending retirement. Session-lived so a retire the
    /// registry refused goes out again on a later pass.
    pub(crate) orphan_heads: Rc<OrphanHeads>,
    /// Whether a poll tick has reconciled the record plane since this session
    /// started. The drain holds a replayed quarantine until it is set
    /// (blueprint/engine.md "Retirement").
    pub(crate) converged_tick: Rc<Cell<bool>>,
    /// Builds the sweep task every rotation arm enqueues. Built at
    /// [`start`](crate::facade::Engine::start) for the same reason the tick loop is: a spawned
    /// task is `'static`, and the command path's seam bounds are narrower.
    pub(crate) sweep_tasks: Rc<RefCell<Option<SweepTaskFactory>>>,
    /// Where this session's bytes go, decided at [`start`](crate::facade::Engine::start) from the
    /// vault settings load and re-decided by a settings save, and shared with
    /// the drain. Carries its own provenance, because an assumed placement must
    /// never latch account-scoped state. `None` until start, and emptied on drop
    /// like [`tick_enc_subkey`](SessionSecrets::tick_enc_subkey) — the config it holds
    /// carries the member's provider bearer.
    pub(crate) placement: Rc<RefCell<Option<SessionPlacement>>>,
    /// The host-visible summary of the settings this session loaded, refreshed
    /// by a confirmed save and by the tick's re-decide. Redacted at
    /// construction
    /// ([`VaultSettings::summary`](crate::settings::VaultSettings::summary)),
    /// so the provider bearer never enters it. Shared with the tick loop, which
    /// must never move the placement without moving what the host is told the
    /// session writes under.
    pub(crate) settings_summary: Rc<RefCell<Option<VaultSettingsSummary>>>,
    /// Unlinks a read leg observed and this device did not author. The drain
    /// adopts them into the bin and clears only what it settles, so a capture
    /// the merge already dropped from the base is not lost on a failed pass
    /// (ADR 0010 item 5).
    pub(crate) observed_unlinks: Rc<RefCell<Vec<UnlinkedChild>>>,
    /// Whether this session has already held the account's `byo` flag to the
    /// vaulted mode. Latched per placement decision, not per write: the flag is
    /// account-wide, so re-deriving it on every write would let two devices flap
    /// it — a settings change this session adopts is the one event that re-arms
    /// it, whether the member saved it here or on another device.
    pub(crate) byo_reconciled: Rc<Cell<bool>>,
}

impl SessionState {
    pub(crate) fn new() -> Self {
        Self {
            live_blocks: Rc::new(RefCell::new(LiveBlocks::default())),
            cancels: Rc::new(RefCell::new(UploadCancels::default())),
            // The anchored all-zero root until cold-start/resolve replaces
            // the base snapshot; children come from the pending-op overlay.
            // Shared by every account on purpose: a well-known anchor, never
            // an account discriminator — separation lives in the KDFs and in
            // the per-identity seam views that consume it.
            snapshot: Rc::new(BaseSnapshot::new(Snapshot::new(NodeId::VAULT_ROOT))),
            held_records: Rc::new(RefCell::new(HeldRecords::new())),
            pending_scope_exits: Rc::new(RefCell::new(BTreeSet::new())),
            sync_status: Rc::new(RefCell::new(SyncStatus::default())),
            scope_read_seeds: Rc::new(RefCell::new(BTreeMap::new())),
            scope_write_seeds: Rc::new(RefCell::new(BTreeMap::new())),
            descendant_scope_roots: Rc::new(RefCell::new(BTreeSet::new())),
            unproved_scope_roots: Rc::new(RefCell::new(BTreeSet::new())),
            boundary_walk_rejected: Rc::new(Cell::new(false)),
            scope_roots_walked: Rc::new(Cell::new(false)),
            walked_read_epochs: Rc::new(RefCell::new(WalkedReadEpochs::new())),
            current_root_name: Rc::new(RefCell::new(None)),
            focus: Rc::new(RefCell::new(FocusWindow::default())),
            focus_refreshed: Rc::new(RefCell::new(BTreeMap::new())),
            pointer_consulted: Rc::new(RefCell::new(BTreeMap::new())),
            on_access_misses: OnAccessMisses::default(),
            received_verdicts: Rc::new(RefCell::new(ReceivedVerdicts::new())),
            received_shares_lock: Rc::new(ReceivedSharesLock::new(())),
            grafted_sharers: Rc::new(RefCell::new(GraftedSharers::new())),
            bookmarked_scope_roots: Rc::new(RefCell::new(BookmarkedScopeRoots::new())),
            bookmarked_permissions: Rc::new(RefCell::new(BookmarkedPermissions::new())),
            grafted_write_roots: Rc::new(RefCell::new(BTreeSet::new())),
            grafted_claims: Rc::new(RefCell::new(ClaimRecord::default())),
            minted_scope_roots: Rc::new(RefCell::new(BTreeSet::new())),
            pending_invite_claims: Rc::new(RefCell::new(ClaimCounts::default())),
            conversion_running: Rc::new(Cell::new(false)),
            dead_letters: Rc::new(RefCell::new(BTreeMap::new())),
            queue_scan: Rc::new(RefCell::new(QueueScanMemo::default())),
            queue_hold: Rc::new(RefCell::new(None)),
            pending_reclaim: Rc::new(Cell::new(0)),
            reclaim_stalls: Rc::new(RefCell::new(Vec::new())),
            bookkeeping: Rc::new(RefCell::new(BookkeepingCursors::default())),
            orphan_heads: Rc::new(OrphanHeads::default()),
            converged_tick: Rc::new(Cell::new(false)),
            sweep_tasks: Rc::new(RefCell::new(None)),
            placement: Rc::new(RefCell::new(None)),
            settings_summary: Rc::new(RefCell::new(None)),
            observed_unlinks: Rc::new(RefCell::new(Vec::new())),
            byo_reconciled: Rc::new(Cell::new(false)),
        }
    }
}

/// The session secrets the tick loop gates on, in cells that teardown empties.
#[derive(Default)]
pub(crate) struct SessionSecrets {
    /// The one piece of session secret the resolve-tick loop needs — the
    /// encryption subkey it opens owner blobs and op records with — in a cell
    /// the engine empties on drop. A parked task is not polled until its next
    /// scheduler wake, so anything the loop captured outright would stay
    /// resident for up to that wake past the engine (security rules 1/7); every
    /// shared cell of either group that carries key material is cleared the same way.
    pub(crate) tick_enc_subkey: Rc<RefCell<Option<X25519Secret>>>,
    /// The bin index's own signer and seal key, derived at
    /// [`start`](crate::facade::Engine::start) and shared with the drain on the same terms as
    /// [`tick_enc_subkey`](Self::tick_enc_subkey): a spawned task holds the two
    /// edges the bin index needs, never the login secret they came from.
    pub(crate) tick_bin_keys: Rc<RefCell<Option<Rc<BinIndexKeys>>>>,
    /// The settings record's own signer, shared with the tick's settings
    /// recheck on the same terms as [`tick_bin_keys`](Self::tick_bin_keys). The
    /// recheck enrols what it resolved, and the renewal re-signs with this.
    pub(crate) tick_settings_signer: Rc<RefCell<Option<Rc<Ed25519Signer>>>>,
    /// The owner identity signer, shared with the tick's conversion pass on
    /// the same terms as [`tick_settings_signer`](Self::tick_settings_signer):
    /// a conversion on the tick re-signs the commitment, each minted row and
    /// each share pointer (ADR 0023 D4).
    pub(crate) tick_owner_signer: Rc<RefCell<Option<Rc<EcdsaSigner>>>>,
    /// The received-share leg's: the contact-label seed that leg's
    /// sharer-scoped floor reads are keyed under
    /// ([`ContactLabel`](crate::seams::ContactLabel)). Same cell discipline as
    /// [`tick_enc_subkey`](Self::tick_enc_subkey).
    pub(crate) tick_contact_label_seed: Rc<RefCell<Option<SecretBytes>>>,
    /// What a spawned sweep opens and signs with, shared with every task it
    /// produces and emptied on drop — the tasks read through this cell, so
    /// teardown revokes the material instead of waiting out the last pass. The
    /// tick's polled pointer consult reads the same cell rather than holding a
    /// second copy of the two owner seeds.
    pub(crate) sweep_keys: Rc<RefCell<Option<Rc<SweepKeys>>>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::suite::secret::ct_eq;

    fn identity(secret: &[u8]) -> SessionIdentity {
        SessionIdentity::derive(&LoginSecret::new(secret.to_vec())).expect("valid identity")
    }

    #[test]
    fn derivation_is_a_pure_function_of_the_secret() {
        let a = identity(&[7u8; 32]);
        let b = identity(&[7u8; 32]);
        let scope = [3u8; 16];
        let node = [4u8; 16];
        let write_scope_seed = [5u8; 32];

        assert_eq!(
            a.enc_subkey_public().to_bytes(),
            b.enc_subkey_public().to_bytes(),
            "same secret must yield the same enc subkey"
        );
        assert_eq!(
            a.vault_pointer_signer(0).verifying_key().to_bytes(),
            b.vault_pointer_signer(0).verifying_key().to_bytes(),
            "same secret must yield the same vault-pointer signer"
        );
        assert_eq!(
            a.scope_pointer_signer(&scope).verifying_key().to_bytes(),
            b.scope_pointer_signer(&scope).verifying_key().to_bytes(),
        );
        assert!(
            ct_eq(
                a.pointer_read_key(&scope).as_bytes(),
                b.pointer_read_key(&scope).as_bytes(),
            ),
            "same secret must yield the same pointer read key",
        );
        assert_eq!(
            SessionIdentity::write_name_signer(&write_scope_seed, &node)
                .verifying_key()
                .to_bytes(),
            SessionIdentity::write_name_signer(&write_scope_seed, &node)
                .verifying_key()
                .to_bytes(),
            "the per-name write signer is a pure function of seed + node id",
        );
    }

    #[test]
    fn a_different_secret_yields_a_different_identity() {
        let a = identity(&[7u8; 32]);
        let b = identity(&[8u8; 32]);

        assert_ne!(
            a.enc_subkey_public().to_bytes(),
            b.enc_subkey_public().to_bytes(),
        );
        assert_ne!(
            a.vault_pointer_signer(0).verifying_key().to_bytes(),
            b.vault_pointer_signer(0).verifying_key().to_bytes(),
        );
        assert_ne!(
            a.scope_pointer_signer(&[3u8; 16])
                .verifying_key()
                .to_bytes(),
            b.scope_pointer_signer(&[3u8; 16])
                .verifying_key()
                .to_bytes(),
            "the owner-plane scope pointer is keyed off the login secret",
        );
    }

    #[test]
    fn the_vault_pointer_chain_is_indexed() {
        let id = identity(&[7u8; 32]);
        assert_ne!(
            id.vault_pointer_signer(0).verifying_key().to_bytes(),
            id.vault_pointer_signer(1).verifying_key().to_bytes(),
            "each index is a distinct name in the chain",
        );
    }

    #[test]
    fn per_name_write_signers_bind_scope_seed_and_node_id() {
        let base = SessionIdentity::write_name_signer(&[5u8; 32], &[4u8; 16])
            .verifying_key()
            .to_bytes();
        assert_ne!(
            base,
            SessionIdentity::write_name_signer(&[6u8; 32], &[4u8; 16])
                .verifying_key()
                .to_bytes(),
            "a different write scope seed is a different name",
        );
        assert_ne!(
            base,
            SessionIdentity::write_name_signer(&[5u8; 32], &[9u8; 16])
                .verifying_key()
                .to_bytes(),
            "a different node id is a different name",
        );
    }

    #[test]
    fn grantee_writer_pseudonym_signer_binds_pairwise_material_and_scope() {
        let pairwise = [2u8; 32];
        let scope = [3u8; 16];
        let base = SessionIdentity::grantee_writer_pseudonym_signer(&pairwise, &scope)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            base,
            SessionIdentity::grantee_writer_pseudonym_signer(&pairwise, &scope)
                .verifying_key()
                .to_bytes(),
            "same pairwise material and scope must yield the same pseudonym signer",
        );
        assert_ne!(
            base,
            SessionIdentity::grantee_writer_pseudonym_signer(&[9u8; 32], &scope)
                .verifying_key()
                .to_bytes(),
            "different pairwise material is a different pseudonym",
        );
        assert_ne!(
            base,
            SessionIdentity::grantee_writer_pseudonym_signer(&pairwise, &[4u8; 16])
                .verifying_key()
                .to_bytes(),
            "a different scope is a different pseudonym",
        );
    }

    #[test]
    fn the_owner_verifier_is_the_identity_signers_public_key() {
        let id = identity(&[7u8; 32]);
        assert_eq!(
            id.identity().verifying_key().to_sec1(),
            id.owner_identity().to_sec1(),
            "owner_identity() exposes the identity signer's verifier",
        );
    }

    #[test]
    fn a_signature_by_identity_verifies_under_the_owner_verifier() {
        let id = identity(&[7u8; 32]);
        let msg = b"cipherbox-login:v2:deadbeef";
        let sig = id.identity().sign_detcbor(msg);
        assert!(
            id.owner_identity().verify_detcbor(msg, &sig),
            "the owner verifier accepts the identity signer's signature",
        );
    }

    #[test]
    fn derive_fails_closed_on_a_wrong_length_secret() {
        assert_eq!(
            SessionIdentity::derive(&LoginSecret::new(vec![7u8; 31])).unwrap_err(),
            EngineError::InvalidSecret,
            "a non-32-byte secret has no valid identity scalar",
        );
    }

    #[test]
    fn derive_fails_closed_on_a_zero_scalar() {
        assert_eq!(
            SessionIdentity::derive(&LoginSecret::new(vec![0u8; 32])).unwrap_err(),
            EngineError::InvalidSecret,
            "the zero scalar is not a valid secp256k1 key",
        );
    }

    #[test]
    fn debug_is_redacted() {
        assert_eq!(
            format!("{:?}", identity(&[7u8; 32])),
            "SessionIdentity(redacted)"
        );
    }
}
