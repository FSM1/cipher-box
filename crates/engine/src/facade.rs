//! The facade — the engine's single async command-and-event surface
//! (blueprint/engine.md "Facade").
//!
//! Designed to be wrapped, not extended: desktop calls it directly in the
//! Tauri process; web wraps it via `crates/wasm` inside a dedicated worker,
//! with the RPC layer and tab leadership owned by `packages/client`
//! (#28 D3/D4). The engine's contract is only this: one live instance is
//! the single writer, and every trust decision already happened below the
//! facade — hosts render, they never decide.
//!
//! This is the skeleton slice: the surface shape (constructor over the
//! whole seam set, `start(secret)`, the [`Command`] enum, the [`Event`]
//! stream) is real and frozen; command execution is not — every command
//! resolves to [`EngineError::Unimplemented`] until the pipeline slices
//! land.

use core::cell::{Cell, RefCell};
use core::fmt;
use core::pin::Pin;
use std::rc::Rc;

use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use futures_channel::mpsc;
use futures_core::Stream;
use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::net::{
    Adopter, HeldRecord, LivenessControl, RE_PUT_INTERVAL, keyless_re_put, run_liveness_loop,
};
use crate::profile::SyncTimingProfile;
use crate::seams::{OpId, Scheduler, SeamSet, SeamTypes, StagingStore};
use crate::session::SessionIdentity;
use crate::sync::boot::{ColdStartError, ColdStartOutcome, ColdStartParams, cold_start};
use crate::sync::pointer::PointerFetch;
use crate::sync::rebase::decode_queue;

/// The stable 16-byte node identifier (`id16`, blueprint/core.md). Public,
/// non-secret, and location-independent — routes and commands key on it,
/// never on rotating `ipnsName`s.
///
/// `Ord` orders by the raw id bytes: a non-secret, location-independent total
/// order that keeps the sync core's snapshot maps and dead-letter reporting
/// deterministic across platforms.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct NodeId(pub [u8; 16]);

/// Plaintext file content crossing the facade.
///
/// A newtype rather than bare `Vec<u8>` so `Debug` is structurally
/// redacted: plaintext user bytes must never reach a log site (security
/// rule 2), including through a derived `{:?}` on a containing [`Command`].
#[derive(Clone, PartialEq, Eq)]
pub struct PlaintextContent(pub Vec<u8>);

impl fmt::Debug for PlaintextContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlaintextContent(<{} bytes>)", self.0.len())
    }
}

/// What a created node is. Kind is sealed inside the read-body on the wire;
/// at the facade it is plain intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeKind {
    /// A file node.
    File,
    /// A folder node.
    Folder,
}

/// Grant permission level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read grant: read seed only.
    Read,
    /// Write grant: read and write seeds.
    Write,
}

/// The staleness ladder (#33 D4): fresh → reconciling → stale → offline.
/// Availability staleness keeps cached views usable indefinitely; trust
/// violations are never staleness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staleness {
    /// View is within the freshness window.
    Fresh,
    /// A background reconcile is in flight (quiet indicator).
    Reconciling,
    /// Past the profile threshold: stale badge, "last synced X ago".
    Stale,
    /// Offline banner.
    Offline,
}

/// The login secret handed to [`Engine::start`], and nowhere else.
///
/// Zeroized on drop. The engine derives everything else in-crate via core's
/// KDF catalog; the secret never leaves engine memory, is never logged, and
/// has no `Clone`.
pub struct LoginSecret(Zeroizing<Vec<u8>>);

impl LoginSecret {
    /// Wraps the raw login secret bytes. The caller should not retain a
    /// copy (web transfers the buffer and zeroes its own).
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Whether the secret is empty (always a caller bug).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the raw secret bytes for in-crate cold-start derivation only.
    /// `pub(crate)` so the secret never leaves engine memory; the only caller
    /// is [`SessionIdentity::derive`](crate::session::SessionIdentity::derive).
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for LoginSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginSecret(redacted)")
    }
}

/// Every command a host can issue — the intent ops, grant/rotation/share
/// actions, auth, and manual refresh (blueprint/engine.md "Facade").
///
/// Payloads are scaffold-minimal and harden with the pipeline slices; the
/// variant set is the surface hosts build against.
///
/// `Debug` is hand-written and prints only the variant name: payloads
/// carry private user data (plaintext content, names, contact bundles),
/// and a derived `{:?}` at any diagnostic site would leak it into logs.
#[derive(Clone, PartialEq, Eq)]
pub enum Command {
    // --- intent ops (#33 D6: every mutation rides the durable op queue) ---
    /// Create a node under a parent.
    Create {
        /// Parent folder.
        parent: NodeId,
        /// Name as entered (uniqueness uses the strict comparator).
        name: String,
        /// File or folder.
        kind: NodeKind,
        /// Initial content for file creates.
        content: Option<PlaintextContent>,
    },
    /// Delete a node (conditional delete semantics on rebase).
    Delete {
        /// Target node.
        node: NodeId,
    },
    /// Rename a node in place.
    Rename {
        /// Target node.
        node: NodeId,
        /// New name as entered.
        new_name: String,
    },
    /// Move a node to a new parent. Intra-scope this is a pure relink;
    /// cross-scope it re-seals the subtree and may trigger a scope-exit
    /// rotation for the source (#26 D1/D7).
    Relink {
        /// Node being moved.
        node: NodeId,
        /// Destination parent.
        new_parent: NodeId,
    },
    /// Write new content to a file node (fresh per-version content key).
    UpdateContent {
        /// Target file node.
        node: NodeId,
        /// New content bytes.
        content: PlaintextContent,
    },

    // --- focus and refresh ---
    /// Set the open folder driving the focus window; `None` when no folder
    /// is open.
    SetFocus {
        /// The open folder, if any.
        node: Option<NodeId>,
    },
    /// Manual refresh with nocache semantics everywhere (#33 D4).
    ManualRefresh,

    // --- grants, shares, rotation (owner/grant actions per engine.md) ---
    /// Import a contact code; binding-signature verification is mandatory
    /// and fail-closed (#34 D6).
    ImportContact {
        /// The self-authenticating contact bundle bytes.
        contact_code: Vec<u8>,
    },
    /// Grant a node to an imported contact (owner-only).
    Grant {
        /// Node to grant (folder or file — files are first-class targets).
        node: NodeId,
        /// Recipient's identity public key, as imported.
        recipient_identity_public_key: Vec<u8>,
        /// Read or write.
        permission: Permission,
    },
    /// Revoke a grant (owner-only; read revoke = immediate cut).
    Revoke {
        /// Granted node.
        node: NodeId,
        /// Recipient's identity public key.
        recipient_identity_public_key: Vec<u8>,
    },
    /// Downgrade a write grant to read (owner-only; triggers write
    /// rotation).
    Downgrade {
        /// Granted node.
        node: NodeId,
        /// Recipient's identity public key.
        recipient_identity_public_key: Vec<u8>,
    },
    /// Mint an invite link for a node (#25 D6). The returned URL fragment
    /// carries the ephemeral secret; response payloads land with the grants
    /// slice.
    CreateInviteLink {
        /// Node to invite to.
        node: NodeId,
        /// Read or write.
        permission: Permission,
    },
    /// Accept a share from a polled mailbox pointer or claimed invite.
    AcceptShare {
        /// The sealed share pointer payload.
        sealed_share_pointer: Vec<u8>,
    },
    /// Manual hygiene rotate-now for a scope (same primitives as every
    /// rotation trigger).
    RotateNow {
        /// The scope root to rotate.
        node: NodeId,
    },

    // --- auth ---
    /// Exchange a host-collected SIWE wallet signature (secondary method;
    /// the engine performs the exchange through its API client).
    SiweLogin {
        /// The signed SIWE message.
        message: String,
        /// The wallet signature bytes.
        signature: Vec<u8>,
    },
    /// Log out: zeroize engine state; durable seams survive by design.
    Logout,
}

impl Command {
    /// Stable command name for diagnostics and typed unimplemented errors.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Create { .. } => "create",
            Command::Delete { .. } => "delete",
            Command::Rename { .. } => "rename",
            Command::Relink { .. } => "relink",
            Command::UpdateContent { .. } => "updateContent",
            Command::SetFocus { .. } => "setFocus",
            Command::ManualRefresh => "manualRefresh",
            Command::ImportContact { .. } => "importContact",
            Command::Grant { .. } => "grant",
            Command::Revoke { .. } => "revoke",
            Command::Downgrade { .. } => "downgrade",
            Command::CreateInviteLink { .. } => "createInviteLink",
            Command::AcceptShare { .. } => "acceptShare",
            Command::RotateNow { .. } => "rotateNow",
            Command::SiweLogin { .. } => "siweLogin",
            Command::Logout => "logout",
        }
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Command({})", self.name())
    }
}

/// Events the engine emits on the one-way stream out
/// (blueprint/engine.md "Facade"). Payloads are scaffold-minimal and harden
/// with the pipeline slices; the variant set is the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A new gate-passing snapshot (with pending-op overlay applied) is
    /// available.
    SnapshotUpdated,
    /// Staleness-ladder transition.
    StalenessChanged {
        /// The new level.
        level: Staleness,
    },
    /// Withheld-update escalation on a shared scope (#33 D7).
    WithheldUpdateEscalation {
        /// The pinned name, as opaque bytes.
        ipns_name: Vec<u8>,
    },
    /// A queued op terminally failed rebase; staged bytes are preserved
    /// (#33 D6).
    DeadLetter {
        /// The dead-lettered op.
        op_id: OpId,
    },
    /// Attributable abuse: owner-blob / ascent-link / unseal cross-check
    /// disagreement (#39 D6) — never a silent failure.
    AttributableAbuse {
        /// Human-readable classification (no key material).
        description: String,
    },
}

/// Errors returned by facade calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// A command was issued before [`Engine::start`].
    NotStarted,
    /// [`Engine::start`] was called on an already-started engine (one live
    /// instance is the single writer).
    AlreadyStarted,
    /// The login secret was empty.
    InvalidSecret,
    /// The command's pipeline slice has not landed yet (scaffold state).
    Unimplemented {
        /// [`Command::name`] of the rejected command.
        command: &'static str,
    },
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::NotStarted => f.write_str("engine not started"),
            EngineError::AlreadyStarted => f.write_str("engine already started"),
            EngineError::InvalidSecret => f.write_str("login secret must not be empty"),
            EngineError::Unimplemented { command } => {
                write!(f, "command not implemented yet: {command}")
            }
        }
    }
}

impl std::error::Error for EngineError {}

/// The receiving side of the engine's one-way event stream.
///
/// Runtime-agnostic: an unbounded in-process channel, awaitable on any
/// executor, native or WASM. Ends (`None`) when the engine is dropped.
pub struct EventStream {
    receiver: mpsc::UnboundedReceiver<Event>,
}

impl EventStream {
    /// Waits for the next event; `None` once the engine is gone.
    pub async fn next(&mut self) -> Option<Event> {
        core::future::poll_fn(|cx| Pin::new(&mut self.receiver).poll_next(cx)).await
    }
}

/// The engine — the single stateful brain behind the facade.
///
/// Constructed over the whole seam set (missing seam = compile error), an
/// injected entropy source, and an explicit sync timing profile. Generic
/// over the host's [`SeamTypes`] family: fully statically dispatched, no
/// `Send` requirement, so one implementation links natively on desktop and
/// compiles to worker-hosted WASM on web.
pub struct Engine<T: SeamTypes> {
    seams: SeamSet<T>,
    /// Wired by the pipeline slices (seeds, nonces, jitter).
    #[allow(dead_code)]
    entropy: Box<dyn Entropy>,
    profile: SyncTimingProfile,
    #[allow(dead_code)]
    events: mpsc::UnboundedSender<Event>,
    /// The session's live held-record set: the resolve slice pushes each
    /// gate-passing record here, and the cold-start liveness loop keyless
    /// re-PUTs the set on the hourly cadence. Empty until resolve lands.
    held_records: Rc<RefCell<Vec<HeldRecord>>>,
    /// Session-alive latch: cleared on drop so the spawned liveness loop
    /// stops at its next wake instead of re-PUTting after the engine is gone.
    alive: Rc<Cell<bool>>,
    /// The cold-start session identity, derived from the login secret at
    /// [`start`](Self::start). `None` until then; the single place derived key
    /// material lives once the engine is live. The resolve/publish/rotation
    /// slices and the liveness loop read every signer from here.
    session: Option<SessionIdentity>,
    started: bool,
}

impl<T: SeamTypes> Engine<T> {
    /// Builds an engine over the whole seam set and hands back the paired
    /// event stream.
    pub fn new(
        seams: SeamSet<T>,
        entropy: Box<dyn Entropy>,
        profile: SyncTimingProfile,
    ) -> (Self, EventStream) {
        let (events, receiver) = mpsc::unbounded();
        (
            Self {
                seams,
                entropy,
                profile,
                events,
                held_records: Rc::new(RefCell::new(Vec::new())),
                alive: Rc::new(Cell::new(true)),
                session: None,
                started: false,
            },
            EventStream { receiver },
        )
    }

    /// Start of secret: consumes the login secret and brings the engine up.
    ///
    /// Derives the cold-start [`SessionIdentity`] from the secret — the
    /// owner-plane identity that needs no network (enc subkey, owner pointer
    /// seed, vault-pointer signer chain), plus the per-scope/per-name signer
    /// factories the pipeline layers scope material onto. The remaining
    /// cold-start steps (vault-pointer resolve, floor cold-seed, root
    /// adoption, first snapshot event) land with the resolve/gate slices,
    /// which read their key material from the session assembled here.
    ///
    /// The lifecycle contract holds: exactly one successful `start` per
    /// instance, and the secret is zeroized on consumption — derivation is the
    /// only reader, and the secret is dropped at its terminal owner the moment
    /// the identity is built.
    pub async fn start(&mut self, secret: LoginSecret) -> Result<(), EngineError>
    where
        T::Scheduler: Clone + 'static,
        T::RecordTransport: Clone + 'static,
    {
        if self.started {
            return Err(EngineError::AlreadyStarted);
        }
        if secret.is_empty() {
            return Err(EngineError::InvalidSecret);
        }
        // Pure derivation from the injected secret — no clock, no RNG — then
        // the secret zeroizes on drop here, at its terminal owner.
        self.session = Some(SessionIdentity::derive(&secret));
        drop(secret);
        self.spawn_liveness_loop();
        self.started = true;
        Ok(())
    }

    /// The live session identity, once [`start`](Self::start) has derived it.
    /// `pub(crate)`: the in-crate pipeline (resolve, publish, rotation, the
    /// liveness loop) reads its signers here; hosts wrap the facade and never
    /// hold key material.
    // Read by the pipeline slices that consume the session (resolve #745/#746,
    // liveness composition #750/#751); the hook is live now, its callers land next.
    #[allow(dead_code)]
    pub(crate) fn session(&self) -> Option<&SessionIdentity> {
        self.session.as_ref()
    }

    /// Run the cold-start live-session data path — the ordered chain composed on
    /// top of the derived [`SessionIdentity`] (blueprint/engine.md cold-start
    /// sequence): vault-pointer resolve → floor cold-seed (fail-closed on
    /// regression) → current root name adoption through the gate → first
    /// [`Event::SnapshotUpdated`] with the pending-op overlay, cache-first from
    /// the snapshot cache. Any queue entry that fails to decode is surfaced as
    /// an [`Event::DeadLetter`] and dropped from the durable queue before the
    /// chain runs, so a corrupt entry is not re-emitted on the next boot.
    ///
    /// Reads every seam from the engine, the login secret from
    /// [`session`](Self::session), and the pending ops from the durable staging
    /// store; emits no clock/RNG-derived value, so the whole chain is
    /// deterministic off the injected seams. The record-plane fetchers enter as
    /// the two seam traits the resolver slices (#745/#746) implement:
    /// [`PointerFetch`] for the pointer block and [`Adopter`] for the root record.
    ///
    /// `owner_identity` is the auth-provided contact-code-anchored identity that
    /// signs the re-point object — the vault-pointer walk's fail-closed anchor.
    // Live composition consumed by the facade cold-start test; the resolver slice
    // (#745/#746) supplies the concrete `PointerFetch`/`Adopter` at the `start`
    // call site.
    #[allow(dead_code)]
    pub(crate) async fn cold_start_data_path<Pf, Ad>(
        &mut self,
        pointer_fetch: &Pf,
        adopter: &Ad,
        owner_identity: &EcdsaVerifier,
        root_scope_id: [u8; 16],
        payload_version: u64,
        root: NodeId,
    ) -> Result<ColdStartOutcome, ColdStartError>
    where
        Pf: PointerFetch,
        Ad: Adopter,
    {
        // Precondition guard fails fast before any seam I/O, so an unstarted
        // engine returns `NotStarted` rather than misclassifying a staging-store
        // failure as retryable `Seam`.
        let session = self.session.as_ref().ok_or(ColdStartError::NotStarted)?;
        let raw = self
            .seams
            .staging_store
            .queued_ops()
            .await
            .map_err(ColdStartError::Seam)?;
        let (decoded, undecodable) = decode_queue(&raw);
        let pending: Vec<_> = decoded.into_iter().map(|(_id, op)| op).collect();

        // Surface every undecodable queue entry as `Event::DeadLetter` and drop
        // its op record from the durable queue so a corrupt/forward-version
        // entry is not re-decoded and re-emitted on every boot (#768). Staged
        // upload bytes live in a separate plane keyed by staging keys — never
        // touched here, so they are retained per the dead-letter contract
        // (blueprint/engine.md #33 D6).
        //
        // `DeadLetter` delivery is best-effort over a non-durable in-process
        // channel, so hosts MUST dedup by `op_id`. Gate the durable removal on a
        // successful send: a receiver dropped mid-teardown must not silently
        // purge an unsurfaced entry — preserved, the next boot re-surfaces it.
        for (op_id, _reason) in &undecodable {
            if self
                .events
                .unbounded_send(Event::DeadLetter { op_id: *op_id })
                .is_ok()
            {
                self.seams
                    .staging_store
                    .remove_op(*op_id)
                    .await
                    .map_err(ColdStartError::Seam)?;
            }
        }

        let params = ColdStartParams {
            login_secret: session.login_secret(),
            owner_identity,
            root_scope_id,
            payload_version,
            root,
            pending_ops: &pending,
        };
        let events = self.events.clone();
        let mut emit = |event: Event| {
            let _ = events.unbounded_send(event);
        };
        cold_start(
            pointer_fetch,
            adopter,
            &self.seams.floor_store,
            &self.seams.record_transport,
            &self.seams.snapshot_cache,
            &params,
            &mut emit,
        )
        .await
    }

    /// Spawn the ~hourly keyless re-PUT loop (blueprint/engine.md "Liveness"):
    /// actively-used vaults keep their own records alive off the injected
    /// scheduler, so no client depends on the API republisher. The task holds
    /// only `Rc`/seam-handle clones, so the engine may drop while it is parked;
    /// the alive latch then stops it. The sub-EOL seq+1 renewal joins this same
    /// loop once cold-start derives the per-name signers it needs.
    fn spawn_liveness_loop(&self)
    where
        T::Scheduler: Clone + 'static,
        T::RecordTransport: Clone + 'static,
    {
        let scheduler = self.seams.scheduler.clone();
        let transport = self.seams.record_transport.clone();
        let held = self.held_records.clone();
        let alive = self.alive.clone();
        self.seams.scheduler.spawn(Box::pin(async move {
            run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
                if !alive.get() {
                    return LivenessControl::Stop;
                }
                let records = held.borrow().clone();
                keyless_re_put(&transport, &records).await;
                LivenessControl::Continue
            })
            .await;
        }));
    }

    /// Executes one command. The single write entry point: every mutation,
    /// share action, auth call, and manual refresh comes through here.
    pub async fn command(&mut self, command: Command) -> Result<(), EngineError> {
        if !self.started {
            return Err(EngineError::NotStarted);
        }
        Err(EngineError::Unimplemented {
            command: command.name(),
        })
    }

    /// The sync timing profile this engine runs under.
    pub fn profile(&self) -> &SyncTimingProfile {
        &self.profile
    }
}

impl<T: SeamTypes> Drop for Engine<T> {
    fn drop(&mut self) {
        // Signal the spawned liveness loop to stop; it holds only `Rc` clones,
        // so it outlives the engine unless the latch is cleared here.
        self.alive.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::seams::UnixMillis;
    use crate::testkit::{FakeSeamTypes, FakeWorld, SeededEntropy, block_on};

    fn new_engine() -> (Engine<FakeSeamTypes>, EventStream) {
        let device = FakeWorld::new().device(b"alice-pk");
        Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
        )
    }

    /// Starts an engine whose virtual clock sits at `clock` before `start`, so
    /// tests can prove derivation is independent of the wall time at boot.
    fn started_engine_at(secret_byte: u8, clock: UnixMillis) -> Engine<FakeSeamTypes> {
        let world = FakeWorld::new();
        world.scheduler.advance_to(clock);
        let device = world.device(b"alice-pk");
        let (mut engine, _events) = Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
        );
        block_on(engine.start(LoginSecret::new(vec![secret_byte; 32]))).unwrap();
        engine
    }

    #[test]
    fn login_secret_debug_is_redacted() {
        let secret = LoginSecret::new(vec![0xAA; 32]);
        assert_eq!(format!("{secret:?}"), "LoginSecret(redacted)");
    }

    #[test]
    fn cold_start_derives_and_wires_the_session_identity() {
        let (mut engine, _events) = new_engine();
        assert!(engine.session().is_none(), "no identity before start");

        block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).unwrap();
        let session = engine
            .session()
            .expect("start derives the session identity");

        // The per-name signers #750/#751 need are reachable and match the pure
        // derivation from the same secret — start invents no key material.
        let expected = SessionIdentity::derive(&LoginSecret::new(vec![7u8; 32]));
        assert_eq!(
            session.vault_pointer_signer(0).verifying_key().to_bytes(),
            expected.vault_pointer_signer(0).verifying_key().to_bytes(),
        );
        assert_eq!(
            session
                .write_name_signer(&[5u8; 32], &[4u8; 16])
                .verifying_key()
                .to_bytes(),
            expected
                .write_name_signer(&[5u8; 32], &[4u8; 16])
                .verifying_key()
                .to_bytes(),
        );
    }

    #[test]
    fn cold_start_derivation_is_deterministic_and_clock_independent() {
        // Two engines whose virtual clocks sit at different instants derive the
        // same identity from the same secret: `start` reads no clock or RNG,
        // only the seed.
        let a = started_engine_at(7, UnixMillis(0));
        let b = started_engine_at(7, UnixMillis(1_000_000));
        assert_eq!(
            a.session().unwrap().enc_subkey_public().to_bytes(),
            b.session().unwrap().enc_subkey_public().to_bytes(),
        );
        let c = started_engine_at(8, UnixMillis(2_000_000));
        assert_ne!(
            a.session().unwrap().enc_subkey_public().to_bytes(),
            c.session().unwrap().enc_subkey_public().to_bytes(),
            "a different secret is a different identity",
        );
    }

    #[test]
    fn command_names_are_stable() {
        assert_eq!(Command::ManualRefresh.name(), "manualRefresh");
        assert_eq!(Command::Logout.name(), "logout");
        assert_eq!(
            Command::Delete {
                node: NodeId([0; 16])
            }
            .name(),
            "delete"
        );
    }

    #[test]
    fn command_debug_prints_only_the_variant_name() {
        let command = Command::Create {
            parent: NodeId([0; 16]),
            name: "vacation-plans.txt".into(),
            kind: NodeKind::File,
            content: Some(PlaintextContent(b"top-secret-plaintext".to_vec())),
        };
        let debug = format!("{command:?}");
        assert_eq!(debug, "Command(create)", "payloads must never leak");
    }

    #[test]
    fn plaintext_content_debug_is_redacted() {
        let content = PlaintextContent(b"top-secret-plaintext".to_vec());
        assert_eq!(format!("{content:?}"), "PlaintextContent(<20 bytes>)");
    }

    #[test]
    fn engine_error_displays() {
        assert_eq!(
            EngineError::Unimplemented { command: "create" }.to_string(),
            "command not implemented yet: create"
        );
        assert_eq!(EngineError::NotStarted.to_string(), "engine not started");
    }

    // --- cold-start data path composition ---

    mod cold_start {
        use super::*;

        use std::sync::{Arc, Mutex};

        use cipherbox_core::ipns::{IpnsName, IpnsRecord};
        use cipherbox_core::kdf;
        use cipherbox_core::payload::RepointObject;
        use cipherbox_core::seal::ReadBody;
        use cipherbox_core::suite::ecdsa::EcdsaSigner;
        use cipherbox_core::suite::ed25519::Ed25519Signer;

        use crate::gate::Adopted;
        use crate::seams::{EndpointId, OpId, SeamResult, StagingStore};
        use crate::sync::boot::RootResolve;
        use crate::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};
        use crate::testkit::FakeDevice;

        const SECRET: &[u8] = b"facade-cold-start-secret-fixture";
        const ROOT_SCOPE: [u8; 16] = [0u8; 16];
        const VERSION: u64 = 1;

        fn owner() -> EcdsaSigner {
            EcdsaSigner::from_scalar(&[3u8; 32]).expect("valid scalar")
        }

        fn root_signer() -> Ed25519Signer {
            kdf::ipns_keypair(&[9u8; 32])
        }

        fn root_name() -> IpnsName {
            IpnsName::from_public_key(&root_signer().verifying_key())
        }

        /// A scripted vault-pointer network keyed by the login secret's indexed
        /// names.
        #[derive(Clone, Default)]
        struct ScriptedPointers {
            blocks: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>>,
        }

        impl ScriptedPointers {
            fn seal_index(&self, index: u64, min_read_epoch: u64, write_epoch: u64) {
                let read_key =
                    kdf::pointer_read_key(kdf::owner_pointer_seed(SECRET).as_bytes(), &ROOT_SCOPE);
                let object = RepointObject {
                    scope_id: ROOT_SCOPE,
                    current_root: root_name(),
                    write_epoch,
                    min_read_epoch,
                    prev_root: None,
                };
                let mut entropy = SeededEntropy::new(index);
                let block = seal_repoint(
                    SessionRole::Owner,
                    &mut entropy,
                    read_key.as_bytes(),
                    VERSION,
                    &owner(),
                    &object,
                )
                .unwrap();
                self.blocks
                    .lock()
                    .unwrap()
                    .insert(vault_pointer_name(SECRET, index).as_str().to_owned(), block);
            }
        }

        impl PointerFetch for ScriptedPointers {
            async fn fetch(&self, name: &IpnsName) -> SeamResult<Option<Vec<u8>>> {
                Ok(self.blocks.lock().unwrap().get(name.as_str()).cloned())
            }
        }

        #[derive(Clone)]
        struct AdoptingAdopter;

        impl Adopter for AdoptingAdopter {
            async fn adopt(
                &self,
                _name: &IpnsName,
                _record_bytes: &[u8],
            ) -> Result<Adopted, crate::gate::GateError> {
                Ok(Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: Vec::new(),
                    },
                    sequence: 1,
                    epoch: 1,
                })
            }
        }

        /// Seed a valid signed IPNS record at the root name across the device's
        /// endpoints so the gated resolve fetches a record to adopt.
        fn seed_root_record(device: &FakeDevice) {
            let record = IpnsRecord::create_v2(
                &root_signer(),
                b"/ipfs/bafyrootmeta",
                1,
                0,
                "2099-01-01T00:00:00Z",
            )
            .marshal();
            for endpoint in [
                EndpointId::new("fake:someguy"),
                EndpointId::new("fake:public-routing"),
            ] {
                device
                    .record_store
                    .seed_record(&endpoint, root_name().as_str(), record.clone());
            }
        }

        /// A started engine on a world whose clock sits at `clock`, with a valid
        /// vault pointer and root record already published.
        fn started_at(clock: UnixMillis) -> (Engine<FakeSeamTypes>, EventStream, ScriptedPointers) {
            let world = FakeWorld::new();
            world.scheduler.advance_to(clock);
            let device = world.device(b"alice-pk");
            seed_root_record(&device);
            let (mut engine, events) = Engine::new(
                device.seam_set(),
                Box::new(SeededEntropy::new(42)),
                SyncTimingProfile::CI,
            );
            block_on(engine.start(LoginSecret::new(SECRET.to_vec()))).unwrap();
            let pointers = ScriptedPointers::default();
            pointers.seal_index(0, 1, 1);
            pointers.seal_index(1, 3, 2);
            (engine, events, pointers)
        }

        fn drive(
            engine: &mut Engine<FakeSeamTypes>,
            pointers: &ScriptedPointers,
        ) -> ColdStartOutcome {
            block_on(engine.cold_start_data_path(
                pointers,
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ))
            .unwrap()
        }

        #[test]
        fn runs_the_full_sequence_and_emits_on_the_event_stream() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            let outcome = drive(&mut engine, &pointers);

            assert_eq!(
                outcome.vault_pointer.unwrap().index,
                1,
                "highest valid index"
            );
            assert_eq!(outcome.root_resolve, Some(RootResolve::Adopted));
            // Floors seeded from the owner-vouched re-point.
            assert_eq!(
                block_on(crate::gate::floor::read_epoch_floor(
                    &engine.seams.floor_store,
                    &ROOT_SCOPE
                ))
                .unwrap(),
                Some(3)
            );
            // The first snapshot event reached the host's stream.
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));
        }

        #[test]
        fn reads_no_clock_two_engines_on_independent_clocks_agree() {
            let (mut a, _ea, pa) = started_at(UnixMillis(0));
            let (mut b, _eb, pb) = started_at(UnixMillis(5_000_000));
            // The data path is a pure function of the seams + session: the two
            // outcomes match despite the engines' clocks sitting far apart.
            assert_eq!(drive(&mut a, &pa), drive(&mut b, &pb));
        }

        #[test]
        fn before_start_returns_not_started_not_panic() {
            let (mut engine, _events) = new_engine();
            assert!(engine.session().is_none(), "no identity before start");
            let out = block_on(engine.cold_start_data_path(
                &ScriptedPointers::default(),
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ));
            assert_eq!(out, Err(ColdStartError::NotStarted));
        }

        #[test]
        fn unstarted_engine_reports_not_started_even_when_staging_store_fails() {
            // Precondition guard must run before the staging read, so a failing
            // seam on an unstarted engine still classifies as `NotStarted`, not
            // a retryable `Seam`.
            let world = FakeWorld::new();
            let device = world.device(b"alice-pk");
            device.staging_store.fail_queued_ops();
            let (mut engine, _events) = Engine::new(
                device.seam_set(),
                Box::new(SeededEntropy::new(42)),
                SyncTimingProfile::CI,
            );
            assert!(engine.session().is_none(), "no identity before start");
            let out = block_on(engine.cold_start_data_path(
                &ScriptedPointers::default(),
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ));
            assert_eq!(out, Err(ColdStartError::NotStarted));
        }

        #[test]
        fn undecodable_queue_entry_surfaces_as_dead_letter_on_cold_start() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            // A corrupt op record that `Op::decode` rejects.
            let op_id = block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op"))
                .expect("enqueue");
            assert_eq!(op_id, OpId(1));

            drive(&mut engine, &pointers);

            // The dead-letter surfaces on the host stream ahead of the first paint.
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter { op_id: OpId(1) })
            );
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));
            // The op record was dropped from the durable queue.
            assert!(
                block_on(engine.seams.staging_store.queued_ops())
                    .unwrap()
                    .is_empty(),
                "the dead-lettered op is removed from the durable queue"
            );
        }

        #[test]
        fn dead_lettered_entry_is_not_re_emitted_on_a_second_boot() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op")).expect("enqueue");

            // First boot: surfaces the dead-letter, then paints.
            drive(&mut engine, &pointers);
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter { op_id: OpId(1) })
            );
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));

            // Second boot over the same durable store: the corrupt entry is gone,
            // so only the paint event fires — no re-emitted dead-letter.
            drive(&mut engine, &pointers);
            assert_eq!(block_on(events.next()), Some(Event::SnapshotUpdated));
        }

        #[test]
        fn dropped_receiver_preserves_unsurfaced_dead_letter_across_a_boot() {
            let (mut engine, events, pointers) = started_at(UnixMillis(123_456));
            block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op")).expect("enqueue");
            // Receiver gone mid-teardown: the `DeadLetter` send fails, so the
            // durable removal is gated off and the entry survives for next boot.
            drop(events);

            drive(&mut engine, &pointers);

            assert_eq!(
                block_on(engine.seams.staging_store.queued_ops())
                    .unwrap()
                    .len(),
                1,
                "an unsurfaced dead-letter is retained when the send fails"
            );
        }

        #[test]
        fn remove_op_failure_after_send_re_surfaces_the_dead_letter_next_boot() {
            let (mut engine, mut events, pointers) = started_at(UnixMillis(123_456));
            block_on(engine.seams.staging_store.enqueue_op(b"not-a-valid-op")).expect("enqueue");
            // Send lands in the buffer but the durable removal fails: the gated
            // `?` aborts cold-start with `Seam` before the paint, leaving the op
            // queued. The receiver stays alive, so the `DeadLetter` is observable.
            engine.seams.staging_store.fail_remove_op();

            let first = block_on(engine.cold_start_data_path(
                &pointers,
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ));
            assert!(
                matches!(first, Err(ColdStartError::Seam(_))),
                "a failed durable removal aborts cold-start as a retryable Seam error"
            );
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter { op_id: OpId(1) })
            );
            assert_eq!(
                block_on(engine.seams.staging_store.queued_ops())
                    .unwrap()
                    .len(),
                1,
                "a removal failure after a successful send retains the op"
            );

            // Next boot re-surfaces the same op_id — hosts dedup by it — proving
            // the best-effort contract holds under a partial seam failure.
            let second = block_on(engine.cold_start_data_path(
                &pointers,
                &AdoptingAdopter,
                &owner().verifying_key(),
                ROOT_SCOPE,
                VERSION,
                NodeId([0xAB; 16]),
            ));
            assert!(matches!(second, Err(ColdStartError::Seam(_))));
            assert_eq!(
                block_on(events.next()),
                Some(Event::DeadLetter { op_id: OpId(1) })
            );
        }
    }
}
