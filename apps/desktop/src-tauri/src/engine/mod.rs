//! The engine's native host (blueprint/desktop.md "Engine wiring").
//!
//! One engine per running app, hosted on a thread of its own. The engine is
//! `!Send` — it is the single writer, pinned to one execution context — and
//! Tauri commands run on a pool, so the engine cannot be shared behind a lock
//! the way a `Send` value could. It therefore lives on a dedicated thread
//! running a current-thread runtime inside a `LocalSet` (the shape
//! `TokioScheduler::spawn` requires), and every command reaches it as a message
//! over a channel with a reply channel of its own: serialized by construction,
//! and no webview call ever blocks on another's.
//!
//! The login secret crosses this boundary once, into
//! [`Engine::start`](cipherbox_engine::facade::Engine::start), and is zeroized
//! whether the start succeeded or failed. Nothing key-shaped comes back: the
//! only value this module returns to the webview is [`VaultStatus`].

mod config;
mod seams;

use std::collections::VecDeque;
use std::fs;
use std::mem;
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread::JoinHandle;

use cipherbox_desktop_seams::{KeyringCredentialStore, account_data_dir, measured_storage_policy};
use cipherbox_engine::facade::{Command, Engine, Event, EventStream, LoginSecret};
use cipherbox_engine::seams::CredentialStore;
use cipherbox_engine::{ChallengeSigner, ContentProfile, IdentityChallengeSigner, Staleness};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::mount::{FromMount, MountStatus, Projection};

pub use config::EngineConfig;
pub use seams::DesktopSeamTypes;
use seams::OsEntropy;

/// The secp256k1 scalar length `crates/engine/src/session.rs` requires.
pub const LOGIN_SECRET_LEN: usize = 32;

/// The refusal both length checks answer with — the IPC edge's and the
/// account-naming derivation's.
pub const NOT_A_SCALAR: &str = "the login secret is not a 32-byte scalar";

const INVALID_SECRET: &str = "the login secret is not a valid identity scalar";
const NO_SESSION: &str = "no session is live on this device";
const ALREADY_LIVE: &str = "a session is already live on this device";
const POISONED: &str = "the session state is unreadable; restart CipherBox";

/// The most warnings retained at once. An identical warning dedupes rather than
/// accumulating, so this bounds distinct kind-and-detail pairs, not tick count.
const MAX_WARNINGS: usize = 8;

/// What the shell renders of a live vault. Key-free by construction: counts, a
/// rung, and the engine's own key-material-free classifications — never a name
/// the engine holds keys for.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    /// Items directly under the vault root.
    pub items: usize,
    /// The staleness rung at read time.
    pub staleness: &'static str,
    /// Retained dead-lettered ops — work this device holds that will not
    /// publish, and must never be silent.
    pub dead_letters: usize,
    /// Whether this session holds the material a publish needs. False means
    /// nothing will publish until a refresh or a later start mints the vault —
    /// read rather than retained from its event, so it clears when it stops
    /// being true.
    pub provisioned: bool,
    /// Conditions the engine raised that no snapshot carries.
    pub warnings: Vec<VaultWarning>,
    /// Whether the vault is also projected as a filesystem, and where.
    pub mount: MountStatus,
}

/// A condition the engine emits once and never repeats, retained by the host
/// because the window renders state and a state nobody kept is a state nobody
/// sees (blueprint/engine.md: never a silent failure).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultWarning {
    /// The stable class the window renders its line from.
    pub kind: &'static str,
    /// The engine's own key-material-free classification, where the event
    /// carries one that names no record. The window says what happened, never
    /// which record it happened to: an IPNS name resolves for anyone who reads
    /// it off this window, and links a member to one object's write history.
    pub detail: Option<String>,
}

/// What the tray renders. Off [`Engine::status`] rather than a rendered
/// snapshot: the tray is a status line, and the snapshot's overlay rebuild has
/// no place on the path the mount is served from.
#[derive(Debug)]
pub enum TrayState {
    /// No session is live on this device.
    SignedOut,
    /// A live session.
    Live {
        /// The staleness rung at read time.
        staleness: Staleness,
        /// Whether the vault is also projected as a filesystem, and where. A
        /// mount failure never fails the session, and the tray is the surface
        /// that is up when the window is not (blueprint/desktop.md
        /// "Lifecycle").
        mount: MountStatus,
        /// Queued changes that will never publish — the parked writes.
        parked: usize,
        /// Whether `parked` rose past what the member has already been told,
        /// which is the edge the notification fires on.
        newly_parked: bool,
        /// Conditions the engine raised. A warning is a state of its own and
        /// never a rung on the staleness ladder.
        warnings: Vec<VaultWarning>,
    },
    /// A live session whose state could not be read. Never rendered as a
    /// healthy one: a tray still reading "Synced" is worse than one saying it
    /// does not know.
    Unreadable(String),
}

/// The parked-writes anti-spam watermark: what the member has been told.
#[derive(Default)]
struct ParkedWrites(usize);

impl ParkedWrites {
    /// Whether `parked` is news. A count that holds or falls is not — and a
    /// fall re-arms the notification, so the next parked write is announced
    /// (blueprint/desktop.md "Conflicts, dead letters, and rotation").
    fn rose_to(&mut self, parked: usize) -> bool {
        let news = parked > self.0;
        self.0 = parked;
        news
    }
}

/// The warnings this session has raised, newest last.
#[derive(Default)]
struct Warnings(VecDeque<VaultWarning>);

impl Warnings {
    /// Classifies one event, retaining the classes no read reports. Staleness,
    /// dead letters, op progress and provisioning are absent on purpose — a
    /// read answers all four, and a retained copy could not clear when they do.
    ///
    /// Each `kind` is the event's stable name, the spelling `crates/wasm` gives
    /// the same event, so both hosts say one word for one condition.
    fn record(&mut self, event: &Event) {
        let warning = match event {
            // The description is `"{routing_key}: {rejection}"`
            // (`emit_trust_violation`), so the whole string goes rather than
            // the record's name with it. The class is the signal here; which
            // record failed the gate is not something this window can act on.
            Event::AttributableAbuse { .. } => VaultWarning {
                kind: "attributableAbuse",
                detail: None,
            },
            Event::WithheldUpdateEscalation { .. } => VaultWarning {
                kind: "withheldUpdateEscalation",
                detail: None,
            },
            Event::RenewalFailed { detail, .. } => VaultWarning {
                kind: "renewalFailed",
                detail: Some(detail.clone()),
            },
            _ => return,
        };
        // A condition that keeps firing must not evict the others.
        if self.0.contains(&warning) {
            return;
        }
        if self.0.len() == MAX_WARNINGS {
            self.0.pop_front();
        }
        self.0.push_back(warning);
    }

    fn list(&self) -> Vec<VaultWarning> {
        self.0.iter().cloned().collect()
    }
}

/// The rung's stable name, the spelling the wasm host uses for the same ladder
/// so both shells say one word for one state.
fn rung(staleness: Staleness) -> &'static str {
    match staleness {
        Staleness::Fresh => "fresh",
        Staleness::Reconciling => "reconciling",
        Staleness::Stale => "stale",
        Staleness::Offline => "offline",
    }
}

/// What the host asks of the engine thread. Ending the session is not one of
/// them: closing the channel is what ends it.
enum Request {
    /// Read the vault's status, and answer here.
    Status(oneshot::Sender<Result<VaultStatus, String>>),
    /// Force a refresh with nocache semantics — the tray's "Sync Now".
    Refresh(oneshot::Sender<Result<(), String>>),
    /// Delete this device's stored refresh token. A logout is not a quit: the
    /// durable stores survive both, but the credential survives only the quit
    /// (blueprint/desktop.md, "Lifecycle").
    ForgetCredentials,
    /// The same, plus the last-account id — the one datum of this account the
    /// keyring holds outside the account directory a forget removes.
    ForgetCredentialsAndAccount,
}

/// The live session: the channel into its engine thread, the thread itself, and
/// where the durable stores it opened live — a logout keeps those, and only an
/// explicit forget sweeps them.
struct Live {
    requests: mpsc::UnboundedSender<Request>,
    thread: JoinHandle<()>,
    account_dir: PathBuf,
}

/// Where the running app's one engine lives.
#[derive(Default)]
pub struct EngineHost {
    live: Mutex<Option<Live>>,
}

impl EngineHost {
    /// Builds the engine for `secret` and starts it, resolving once cold start
    /// has landed or refusing with why it did not.
    pub async fn start(
        &self,
        secret: Zeroizing<Vec<u8>>,
        session: SessionEnv,
    ) -> Result<(), String> {
        let started = self.spawn_engine(secret, session)?;
        let outcome = started
            .await
            .unwrap_or_else(|_| Err("the engine stopped before it started".to_owned()));
        // A thread that ended itself still holds the slot; the join in `stop` is
        // what frees it for the next attempt.
        if outcome.is_err() {
            self.stop();
        }
        outcome
    }

    /// Logs out: deletes this device's stored refresh token, then ends the
    /// session as [`stop`](Self::stop) does. The durable stores survive by
    /// design; an explicit "forget this device" is what sweeps them.
    ///
    /// The token is deleted here rather than revoked at the API: this shell ends
    /// a session by closing the channel to the engine thread, so nothing on this
    /// path reaches the facade.
    ///
    /// Idempotent — the login flow calls it on paths where no session is live.
    pub fn log_out(&self) {
        self.end_session(Request::ForgetCredentials);
    }

    /// Hands the engine thread its last request and ends the session.
    fn end_session(&self, last: Request) {
        if let Ok(live) = self.live.lock()
            && let Some(live) = live.as_ref()
        {
            // Not awaited: the join in `stop` is what proves the thread reached
            // it, and a closed channel means it never will.
            let _ = live.requests.send(last);
        }
        self.stop();
    }

    /// Forgets this device: the session ends as a logout does, and then the
    /// durable stores a logout preserves are swept
    /// (blueprint/desktop.md "Lifecycle").
    ///
    /// The sweep is last: the engine's stores are open files until its thread
    /// has joined, and a directory removed under a running engine would be
    /// rebuilt by the next write.
    pub fn forget_device(&self) -> Result<(), String> {
        let account_dir = self
            .live
            .lock()
            .map_err(|_| POISONED)?
            .as_ref()
            .map(|live| live.account_dir.clone());
        self.end_session(Request::ForgetCredentialsAndAccount);
        let Some(account_dir) = account_dir else {
            return Err(NO_SESSION.to_owned());
        };
        match fs::remove_dir_all(&account_dir) {
            Ok(()) => Ok(()),
            // Nothing to forget is the state a forget was asking for.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "this device's stored vault data is still here: {error}"
            )),
        }
    }

    /// Ends the session: the engine drops (zeroizing what it holds and stopping
    /// its loops) and its thread joins. Idempotent.
    pub fn stop(&self) {
        let live = match self.live.lock() {
            Ok(mut live) => live.take(),
            // The slot holds an `Option`, which a panic elsewhere cannot leave
            // half-written — and a session that cannot be taken is a session
            // that cannot be stopped.
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(live) = live {
            // Closing the request channel is the stop signal: the serve loop
            // ends, the engine drops, and the thread returns.
            drop(live.requests);
            let _ = live.thread.join();
        }
    }

    /// Reads the live vault's status.
    pub async fn status(&self) -> Result<VaultStatus, String> {
        self.ask(Request::Status)?.await.map_err(|_| NO_SESSION)?
    }

    /// Forces a refresh with nocache semantics — the tray's "Sync Now"
    /// (blueprint/desktop.md "Tray").
    pub async fn refresh(&self) -> Result<(), String> {
        self.ask(Request::Refresh)?.await.map_err(|_| NO_SESSION)?
    }

    /// Files one request with the live session and hands back where its answer
    /// will arrive, or refuses because there is no session to ask.
    fn ask<T>(
        &self,
        request: impl FnOnce(oneshot::Sender<T>) -> Request,
    ) -> Result<oneshot::Receiver<T>, String> {
        let (reply, answer) = oneshot::channel();
        let live = self.live.lock().map_err(|_| POISONED)?;
        live.as_ref()
            .ok_or(NO_SESSION)?
            .requests
            .send(request(reply))
            .map_err(|_| NO_SESSION)?;
        Ok(answer)
    }

    /// Claims the one engine slot and spawns its thread, handing back where the
    /// start verdict will arrive. The slot is taken before the thread spawns, so
    /// a second caller is refused rather than building a second engine.
    fn spawn_engine(
        &self,
        secret: Zeroizing<Vec<u8>>,
        session: SessionEnv,
    ) -> Result<oneshot::Receiver<Result<(), String>>, String> {
        let mut live = self.live.lock().map_err(|_| POISONED)?;
        if live.is_some() {
            return Err(ALREADY_LIVE.to_owned());
        }
        // Past the slot check: naming the account is a scalar multiplication,
        // and a refused second start has no account to name.
        let account_dir = account_data_dir(&session.data_local_dir, &account_id(&secret)?)
            .map_err(|error| error.to_string())?;

        let (requests, inbox) = mpsc::unbounded_channel();
        let (verdict, started) = oneshot::channel();
        let thread = {
            let account_dir = account_dir.clone();
            std::thread::Builder::new()
                .name("cipherbox-engine".to_owned())
                .spawn(move || host_engine(secret, session, account_dir, inbox, verdict))
                .map_err(|error| format!("the engine thread could not start: {error}"))?
        };

        *live = Some(Live {
            requests,
            thread,
            account_dir,
        });
        Ok(started)
    }
}

/// Where this session's stores live and what tells the shell to repaint.
pub struct SessionEnv {
    /// This build's engine configuration.
    pub config: EngineConfig,
    /// `<data_local_dir>` — the account directory is composed under it.
    pub data_local_dir: PathBuf,
    /// The member's home directory — the mount point is composed under it.
    /// `None` on a device that reports none, which refuses the mount and not
    /// the session (blueprint/desktop.md "Lifecycle").
    pub home_dir: Option<PathBuf>,
    /// The OS keyring service name holding the rotating refresh token.
    pub keyring_service: String,
    /// What the session paints when its state moves.
    pub shell: Shell,
}

/// The two surfaces a session paints: the window, which re-reads what it
/// renders, and the tray, which is handed the state directly.
pub struct Shell {
    /// Called when the engine emits, so the window re-reads what it renders.
    pub changed: Box<dyn Fn() + Send>,
    /// Called with the tray's state whenever it moves.
    pub tray: Box<dyn Fn(TrayState) + Send>,
}

/// One repaint for a whole burst of events: repainting each one would cost a
/// snapshot rebuild on the very engine the mount is served from.
async fn repaint(
    shell: &Shell,
    projection: &mut Projection,
    warnings: &Warnings,
    parked: &mut ParkedWrites,
) {
    (shell.changed)();
    let mount = projection.status();
    (shell.tray)(match projection.engine_mut().status().await {
        Ok(status) => {
            let count = status.dead_letters.len();
            TrayState::Live {
                staleness: status.staleness,
                mount,
                parked: count,
                newly_parked: parked.rose_to(count),
                warnings: warnings.list(),
            }
        }
        Err(error) => TrayState::Unreadable(error.to_string()),
    });
}

/// The API's own account identifier for this login secret: the compressed SEC1
/// identity public key, lowercase hex. Public material — every login presents
/// it — and one path component, so it names the account's store directory
/// (blueprint/desktop.md "Engine wiring").
fn account_id(secret: &[u8]) -> Result<String, String> {
    let scalar: Zeroizing<[u8; LOGIN_SECRET_LEN]> =
        Zeroizing::new(secret.try_into().map_err(|_| NOT_A_SCALAR)?);
    IdentityChallengeSigner::from_scalar(&scalar)
        .map(|signer| signer.public_key_hex())
        .ok_or_else(|| INVALID_SECRET.to_owned())
}

/// The engine thread: build, start, mount, then serve until the request channel
/// closes.
fn host_engine(
    secret: Zeroizing<Vec<u8>>,
    session: SessionEnv,
    account_dir: PathBuf,
    inbox: mpsc::UnboundedReceiver<Request>,
    verdict: oneshot::Sender<Result<(), String>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = verdict.send(Err(format!("the engine runtime could not start: {error}")));
            return;
        }
    };

    // The engine's background loops are spawned with `spawn_local`, so the
    // whole session runs inside this LocalSet.
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let (engine, events, credentials) = match start_engine(secret, &session, &account_dir).await
        {
            Ok(started) => started,
            Err(refusal) => {
                let _ = verdict.send(Err(refusal));
                return;
            }
        };
        // Settled before the mount is attempted: that is what leaves a mount
        // failure no way to fail the session it reports itself in.
        let _ = verdict.send(Ok(()));

        let projection = Projection::open(engine, session.home_dir.as_deref(), &account_dir);
        serve(projection, credentials, inbox, events, session.shell).await;
    });
}

/// Constructs the engine over the desktop seam set and consumes the secret. The
/// credential store comes back out because logout deletes what the engine's
/// login put in it, and the seam set itself is the engine's from here on.
async fn start_engine(
    secret: Zeroizing<Vec<u8>>,
    session: &SessionEnv,
    account_dir: &std::path::Path,
) -> Result<
    (
        Engine<DesktopSeamTypes>,
        EventStream,
        KeyringCredentialStore,
    ),
    String,
> {
    let seams = seams::seam_set(&session.config, account_dir, &session.keyring_service)
        .map_err(|error| error.to_string())?;
    let credentials = seams.credential_store.clone();
    // After the stores have opened: the split is measured on the volume the
    // staged bytes actually land on.
    let storage_policy = session
        .config
        .pinned_storage_policy
        .unwrap_or_else(|| measured_storage_policy(account_dir));

    let (mut engine, events) = Engine::new(
        seams,
        Box::new(OsEntropy),
        session.config.profile,
        // The framing is frozen and pins the wire format, so every host writes
        // the shipped profile.
        ContentProfile::PRODUCTION,
        storage_policy,
        session.config.api_base_url.clone(),
        session.config.gateway.clone(),
    );

    // The engine copies the secret into its own zeroizing store; this frame's
    // owner scrubs on drop, whichever way the start goes.
    engine
        .start(LoginSecret::new(secret.to_vec()))
        .await
        .map_err(|error| error.to_string())?;
    Ok((engine, events, credentials))
}

/// What woke the session loop. One loop and one owner: the projection holds the
/// engine, so a status read, an engine event and a kernel operation are served
/// in turn rather than contending for it. The mount is a wake source of its own
/// so that making it never becomes something the loop waits out.
enum Woke {
    /// The host asked for something, or closed the channel — logout or quit.
    Request(Option<Request>),
    /// The engine emitted, or dropped its stream.
    Event(Option<Event>),
    /// The mount woke the session: an operation, its end, or its verdict.
    Mount(FromMount),
}

/// Serves the session until the host closes the request channel (logout or
/// quit), then tears the projection down: quiesce, unmount, stop the engine.
async fn serve(
    mut projection: Projection,
    credentials: KeyringCredentialStore,
    mut inbox: mpsc::UnboundedReceiver<Request>,
    mut events: EventStream,
    shell: Shell,
) {
    let mut warnings = Warnings::default();
    let mut parked = ParkedWrites::default();
    repaint(&shell, &mut projection, &warnings, &mut parked).await;
    loop {
        let woke = tokio::select! {
            request = inbox.recv() => Woke::Request(request),
            event = events.next() => Woke::Event(event),
            woken = projection.next() => Woke::Mount(woken),
        };
        match woke {
            // The engine only stops emitting by dropping, and this loop is what
            // holds it.
            Woke::Request(None) | Woke::Event(None) => break,
            Woke::Request(Some(Request::Status(reply))) => {
                let _ = reply.send(status(&mut projection, &warnings).await);
            }
            // The pass is filed here and awaited elsewhere: its network legs
            // are the one thing a host may not serve a kernel behind
            // (blueprint/desktop.md "the never-block law"). The mint that
            // answers a refresh on a vault-less account is not a pass and has
            // no filed form.
            Woke::Request(Some(Request::Refresh(reply))) => {
                match projection.engine_mut().file_forced_pass() {
                    Ok(Some(pass)) => {
                        tokio::task::spawn_local(async move {
                            let _ = reply.send(pass.landed().await.map_err(|e| e.to_string()));
                        });
                    }
                    Ok(None) => {
                        let minted = projection
                            .engine_mut()
                            .command(Command::ManualRefresh)
                            .await
                            .map(|_| ())
                            .map_err(|error| error.to_string());
                        let _ = reply.send(minted);
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error.to_string()));
                    }
                }
            }
            // A keyring that refuses the delete is reported to no one: the
            // session is ending either way, and there is no surface left to
            // tell. It is the next login's `store` that overwrites it.
            Woke::Request(Some(Request::ForgetCredentials)) => {
                let _ = credentials.clear_refresh_token().await;
            }
            Woke::Request(Some(Request::ForgetCredentialsAndAccount)) => {
                let _ = credentials.clear_refresh_token().await;
                let _ = credentials.clear_last_account_id().await;
            }
            Woke::Event(Some(event)) => {
                if absorb_burst(&mut projection, &mut warnings, &mut events, event).await {
                    repaint(&shell, &mut projection, &warnings, &mut parked).await;
                }
            }
            Woke::Mount(FromMount::Op(op)) => projection.answer(op).await,
            Woke::Mount(FromMount::Ended) => {
                repaint(&shell, &mut projection, &warnings, &mut parked).await;
            }
            Woke::Mount(FromMount::Landed(landed)) => {
                projection = projection.settled(landed);
                repaint(&shell, &mut projection, &warnings, &mut parked).await;
            }
        }
    }
    (shell.tray)(TrayState::SignedOut);
    projection.tear_down().await;
}

/// The most events one wake folds together. The loop must return to its other
/// wake sources: the kernel is served from here too, and it may not wait out an
/// engine that keeps emitting. Anything past the cap wakes this arm again.
const MAX_BURST: usize = 64;

/// Fold `event` and what is already queued behind it into the warnings and the
/// kernel's caches, and report whether any of it moved what a host renders.
///
/// One push invalidation per run of one kind: the render a later event of that
/// kind drives subsumes what its predecessors would have pushed, so the run's
/// last is the one worth folding in.
async fn absorb_burst(
    projection: &mut Projection,
    warnings: &mut Warnings,
    events: &mut EventStream,
    event: Event,
) -> bool {
    let mut moved = false;
    let mut current = event;
    for folded in 1..=MAX_BURST {
        warnings.record(&current);
        moved |= moves_the_status(&current);
        // Nothing is taken off the stream past the cap: an event taken and not
        // folded in would be an invalidation the kernel never hears about.
        let next = (folded < MAX_BURST).then(|| events.try_next()).flatten();
        if next.as_ref().map(mem::discriminant) != Some(mem::discriminant(&current)) {
            projection.absorb(&current).await;
        }
        let Some(next) = next else { break };
        current = next;
    }
    moved
}

async fn status(projection: &mut Projection, warnings: &Warnings) -> Result<VaultStatus, String> {
    let mount = projection.status();
    let engine = projection.engine_mut();
    let view = engine
        .snapshot(engine.root())
        .await
        .map_err(|error| error.to_string())?;
    Ok(VaultStatus {
        items: view.children.len(),
        staleness: rung(view.staleness),
        dead_letters: view.dead_letters.len(),
        provisioned: engine.is_provisioned(),
        warnings: warnings.list(),
        mount,
    })
}

/// Whether an event can change what [`VaultStatus`] reports. A transfer's
/// per-block progress cannot, and it is the one event that arrives in bursts —
/// repainting on it would cost a snapshot build per chunk.
fn moves_the_status(event: &Event) -> bool {
    !matches!(event, Event::OpProgress { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_engine::facade::{NodeId, OpPhase};
    use cipherbox_engine::seams::OpId;
    use cipherbox_engine::sync::DeadLetterReason;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A session loop under a counting repaint seam: `painted` rises once per
    /// rebuild the window is asked for.
    struct Counted {
        shell: Shell,
        painted: Arc<AtomicUsize>,
        credentials: KeyringCredentialStore,
        requests: mpsc::UnboundedSender<Request>,
        inbox: mpsc::UnboundedReceiver<Request>,
    }

    fn counted(session: &SessionEnv) -> Counted {
        let painted = Arc::new(AtomicUsize::new(0));
        let counting = painted.clone();
        let (requests, inbox) = mpsc::unbounded_channel();
        Counted {
            shell: Shell {
                changed: Box::new(move || {
                    counting.fetch_add(1, Ordering::Relaxed);
                }),
                tray: Box::new(|_| {}),
            },
            painted,
            credentials: KeyringCredentialStore::new(&session.keyring_service)
                .expect("a credential store"),
            requests,
            inbox,
        }
    }

    fn account_dir(data_local_dir: &Path, secret: &[u8]) -> Result<PathBuf, String> {
        account_data_dir(data_local_dir, &account_id(secret)?).map_err(|error| error.to_string())
    }

    fn scalar() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![7u8; LOGIN_SECRET_LEN])
    }

    fn session_env(data_local_dir: &Path) -> SessionEnv {
        SessionEnv {
            config: EngineConfig::parse(&config::BuildEnv {
                api_base_url: Some("http://127.0.0.1:1/api"),
                routing_endpoints: Some("http://127.0.0.1:1"),
                read_accelerator_url: None,
                public_gateways: None,
                environment: Some("ci"),
            })
            .expect("a configured build parses"),
            data_local_dir: data_local_dir.to_path_buf(),
            home_dir: Some(data_local_dir.join("home")),
            keyring_service: "com.cipherbox.desktop.test".to_owned(),
            shell: Shell {
                changed: Box::new(|| {}),
                tray: Box::new(|_| {}),
            },
        }
    }

    /// An engine built over the desktop seam set but never started — enough to
    /// be held, which is all a mount refusal has to leave behind.
    fn unstarted_engine(session: &SessionEnv, account_dir: &Path) -> Engine<DesktopSeamTypes> {
        let seams = seams::seam_set(&session.config, account_dir, &session.keyring_service)
            .expect("the desktop stores open under a temp root");
        Engine::new(
            seams,
            Box::new(OsEntropy),
            session.config.profile,
            ContentProfile::PRODUCTION,
            session
                .config
                .pinned_storage_policy
                .expect("the ci build pins a budget"),
            session.config.api_base_url.clone(),
            session.config.gateway.clone(),
        )
        .0
    }

    /// The account directory is named by the identity the API knows this
    /// account by, so two accounts on one machine never share a store — and the
    /// same account lands on the same directory every sign-in.
    #[test]
    fn the_account_directory_is_the_identity_public_key() {
        let dir = account_dir(Path::new("/var/lib"), &scalar()).expect("a valid scalar");
        let again = account_dir(Path::new("/var/lib"), &scalar()).expect("a valid scalar");
        assert_eq!(dir, again);

        let name = dir
            .file_name()
            .expect("a named directory")
            .to_str()
            .unwrap();
        assert_eq!(name.len(), 66, "compressed SEC1 identity key, hex");
        assert!(name.starts_with("02") || name.starts_with("03"));
        assert_eq!(dir.parent().unwrap(), Path::new("/var/lib/cipherbox"));

        let other =
            account_dir(Path::new("/var/lib"), &[9u8; LOGIN_SECRET_LEN]).expect("a valid scalar");
        assert_ne!(dir, other, "two accounts never share a store directory");
    }

    /// The same fail-closed edge the engine's own derivation holds: a secret
    /// with no valid identity has no account, so nothing is opened for it.
    #[test]
    fn a_secret_with_no_valid_identity_names_no_account() {
        for secret in [
            vec![0u8; LOGIN_SECRET_LEN],
            vec![0xffu8; LOGIN_SECRET_LEN],
            vec![7u8; 31],
            Vec::new(),
        ] {
            assert!(account_dir(Path::new("/var/lib"), &secret).is_err());
        }
    }

    /// One engine per running app: the second caller is refused at the slot,
    /// before any construction, rather than building a second engine.
    #[test]
    fn a_second_start_is_refused_rather_than_building_a_second_engine() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let host = EngineHost::default();

        let first = host.spawn_engine(scalar(), session_env(dir.path()));
        assert!(first.is_ok());
        let second = host.spawn_engine(scalar(), session_env(dir.path()));
        assert_eq!(second.err().as_deref(), Some(ALREADY_LIVE));

        host.stop();

        // …and the device takes a new session once the first has ended.
        assert!(host.spawn_engine(scalar(), session_env(dir.path())).is_ok());
        host.stop();
    }

    #[test]
    fn ending_a_session_that_was_never_live_is_a_no_op() {
        let host = EngineHost::default();
        host.stop();
        host.stop();
        host.log_out();
        host.log_out();
    }

    /// The session outlives a mount it could not make: the engine is still
    /// this session's to read from, and the refusal is reported beside the
    /// vault rather than instead of it (blueprint/desktop.md "Lifecycle").
    #[tokio::test]
    async fn a_mount_that_cannot_be_made_leaves_the_session_standing() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let session = session_env(dir.path());
        let home = session.home_dir.clone().expect("the test env names a home");
        // A home directory that is a file: no mount point can be made under
        // one, whatever the mount point is called.
        std::fs::write(&home, b"not a home directory").expect("no home to mount under");

        // …and a device that reports no home directory at all is the same
        // refusal, not a refused session.
        for home_dir in [Some(home.as_path()), None] {
            let account_dir = dir.path().join("account");
            let engine = unstarted_engine(&session, &account_dir);
            let mut projection = Projection::open(engine, home_dir, &account_dir);
            if projection.status() == MountStatus::Opening {
                let FromMount::Landed(landed) = projection.next().await else {
                    panic!("a mount being made lands, whichever way it goes");
                };
                projection = projection.settled(landed);
            }

            assert!(
                matches!(projection.status(), MountStatus::Refused { .. }),
                "a session with no mount says why",
            );
            assert_eq!(
                projection.engine_mut().profile(),
                &session.config.profile,
                "the session's engine is still here to serve reads",
            );
            projection.tear_down().await;
        }
    }

    /// A logout keeps this device's durable stores — the ops a mount acked and
    /// never published are in them, and the next mount drains them — while an
    /// explicit forget is what sweeps them (blueprint/desktop.md "Lifecycle").
    #[tokio::test]
    async fn a_logout_keeps_the_durable_stores_and_a_forget_sweeps_them() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let account = account_dir(dir.path(), &scalar()).expect("a valid scalar");

        for forget in [false, true] {
            let host = EngineHost::default();
            let started = host
                .spawn_engine(scalar(), session_env(dir.path()))
                .expect("the slot is free");
            // An op this device acked to the kernel and has not published.
            std::fs::create_dir_all(&account).expect("an account store");
            let acked = account.join("acked-op");
            std::fs::write(&acked, b"journaled, unpublished").expect("a queued op");
            let _ = started.await;

            if forget {
                host.forget_device()
                    .expect("a live session can be forgotten");
                assert!(!account.exists(), "a forget leaves nothing of this account");
            } else {
                host.log_out();
                assert!(acked.exists(), "a logout keeps what the next mount drains");
            }
        }
    }

    /// The keyring holds one datum outside the account directory a forget
    /// removes — the last-account id — so only a forget asks the engine thread
    /// to drop it. A logout must not: it is what names the account directory on
    /// the next launch.
    #[test]
    fn only_a_forget_asks_the_engine_thread_to_drop_the_last_account_id() {
        let dir = tempfile::tempdir().expect("a temp dir");
        for forget in [false, true] {
            let (requests, mut inbox) = mpsc::unbounded_channel();
            let host = EngineHost {
                live: Mutex::new(Some(Live {
                    requests,
                    thread: std::thread::spawn(|| {}),
                    account_dir: dir.path().join("account"),
                })),
            };

            if forget {
                host.forget_device().expect("a live session is forgettable");
            } else {
                host.log_out();
            }

            let asked = inbox.try_recv().expect("the last request was sent");
            assert!(
                match asked {
                    Request::ForgetCredentialsAndAccount => forget,
                    Request::ForgetCredentials => !forget,
                    _ => false,
                },
                "a forget drops the account id and a logout keeps it"
            );
        }
    }

    /// Forgetting needs a session to name the account whose stores go: without
    /// one there is nothing to sweep and nothing that could be found to sweep.
    #[test]
    fn forgetting_a_device_with_no_session_is_refused() {
        assert_eq!(
            EngineHost::default().forget_device().err().as_deref(),
            Some(NO_SESSION)
        );
    }

    #[tokio::test]
    async fn status_without_a_session_is_refused() {
        let host = EngineHost::default();
        assert_eq!(host.status().await.err().as_deref(), Some(NO_SESSION));
    }

    fn warned(events: &[Event]) -> Vec<VaultWarning> {
        let mut warnings = Warnings::default();
        for event in events {
            warnings.record(event);
        }
        warnings.list()
    }

    /// The classes no read reports. Dropping them would render a withheld
    /// update as an ordinary, up-to-date vault. Each kind is the event's own
    /// stable name, so this window and the web one say one word for one thing.
    #[test]
    fn the_engines_never_silent_events_are_retained_under_their_stable_names() {
        let retained = warned(&[
            Event::AttributableAbuse {
                description: "gate rejection".to_owned(),
            },
            Event::WithheldUpdateEscalation {
                ipns_name: b"a-pinned-name".to_vec(),
            },
            Event::RenewalFailed {
                routing_key: "a-routing-key".to_owned(),
                detail: "the CAS race was lost".to_owned(),
            },
        ]);

        assert_eq!(
            retained.iter().map(|w| w.kind).collect::<Vec<_>>(),
            [
                "attributableAbuse",
                "withheldUpdateEscalation",
                "renewalFailed"
            ],
        );
    }

    /// Provisioning is a state a read answers, so retaining its event would
    /// leave the window showing an unprovisioned vault after one was minted.
    #[test]
    fn the_unprovisioned_event_is_read_rather_than_retained() {
        assert!(
            warned(&[Event::VaultUnprovisioned {
                retryable: true,
                detail: "the mint did not land".to_owned(),
            }])
            .is_empty()
        );
    }

    /// A warning says what happened, never which record it happened to: an
    /// IPNS name resolves for whoever reads it off the window. Every arm that
    /// could carry one is here — a trust violation's description arrives with
    /// the routing key already spliced into it, so dropping a field is not
    /// enough for that one.
    #[test]
    fn a_warning_carries_no_record_identifier() {
        const NAME: &str = "k51qzi5uqu5dexampleexamplename";

        let retained = warned(&[
            Event::WithheldUpdateEscalation {
                ipns_name: NAME.as_bytes().to_vec(),
            },
            Event::RenewalFailed {
                routing_key: NAME.to_owned(),
                detail: "the CAS race was lost".to_owned(),
            },
            Event::AttributableAbuse {
                description: format!("{NAME}: content-cid-mismatch"),
            },
        ]);

        assert_eq!(retained.len(), 3, "every arm is retained");
        for warning in &retained {
            let detail = warning.detail.clone().unwrap_or_default();
            assert!(!detail.contains(NAME), "{}: {detail}", warning.kind);
        }
    }

    /// The snapshot already carries these three, and a warning beside them
    /// would be the conflation the staleness ladder exists to prevent.
    #[test]
    fn what_a_snapshot_already_reports_raises_no_warning() {
        assert!(
            warned(&[
                Event::SnapshotUpdated,
                Event::StalenessChanged {
                    level: Staleness::Offline,
                },
                Event::DeadLetter {
                    op_id: OpId(1),
                    reason: DeadLetterReason::Undecodable,
                },
                Event::OpProgress {
                    op_id: None,
                    node: NodeId([0u8; 16]),
                    phase: OpPhase::DownloadFailed,
                    progress: None,
                    error: Some("unavailable".to_owned()),
                },
            ])
            .is_empty()
        );
    }

    /// A condition that keeps firing must not push the others out of a bounded
    /// list — the oldest *distinct* warning is the one that goes.
    #[test]
    fn a_repeating_condition_neither_accumulates_nor_evicts() {
        let renewal = |detail: &str| Event::RenewalFailed {
            routing_key: "a-routing-key".to_owned(),
            detail: detail.to_owned(),
        };

        let mut warnings = Warnings::default();
        for _ in 0..MAX_WARNINGS * 2 {
            warnings.record(&renewal("the CAS race was lost"));
        }
        assert_eq!(warnings.list().len(), 1);

        for index in 0..MAX_WARNINGS * 2 {
            warnings.record(&renewal(&format!("refusal {index}")));
        }
        let retained = warnings.list();
        assert_eq!(retained.len(), MAX_WARNINGS);
        assert_eq!(
            retained.last().and_then(|w| w.detail.clone()),
            Some(format!("refusal {}", MAX_WARNINGS * 2 - 1)),
            "the newest warning is always retained",
        );
    }

    /// A transfer's per-block progress moves nothing the window shows, and it
    /// is the one event that arrives per chunk — repainting on it would cost a
    /// snapshot build per block of every upload and download.
    #[test]
    fn per_block_progress_raises_no_repaint() {
        assert!(!moves_the_status(&Event::OpProgress {
            op_id: None,
            node: NodeId([0u8; 16]),
            phase: OpPhase::UploadProgress,
            progress: None,
            error: None,
        }));
        assert!(moves_the_status(&Event::SnapshotUpdated));
        assert!(moves_the_status(&Event::StalenessChanged {
            level: Staleness::Stale,
        }));
    }

    /// A burst of status-moving events costs the window one rebuild, not one
    /// per event: every rebuild is a snapshot render on the engine the mount is
    /// served from.
    #[tokio::test]
    async fn a_burst_of_events_costs_one_repaint_whatever_its_size() {
        for burst in [1usize, 8, 64] {
            let dir = tempfile::tempdir().expect("a temp dir");
            let session = session_env(dir.path());
            let account_dir = dir.path().join("account");
            // No home: the engine stands alone, so the burst is the only thing
            // this loop is answering.
            let projection =
                Projection::open(unstarted_engine(&session, &account_dir), None, &account_dir);
            let Counted {
                shell,
                painted,
                credentials,
                // Held open, so the loop ends on the event stream rather than
                // on a closed inbox.
                requests: _requests,
                inbox,
            } = counted(&session);

            let (sink, events) = EventStream::piped();
            for _ in 0..burst {
                sink.send(Event::SnapshotUpdated);
            }
            // Closing the stream ends the loop once the burst has drained.
            drop(sink);

            tokio::task::LocalSet::new()
                .run_until(serve(projection, credentials, inbox, events, shell))
                .await;

            assert_eq!(
                painted.load(Ordering::Relaxed),
                2,
                "{burst} events: one paint on start, one for the burst",
            );
        }
    }

    /// The mount is a wake source of its own, so a mount that takes seconds is
    /// a mount point that is not there yet rather than a session that has
    /// stopped answering.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn a_status_read_lands_while_the_mount_is_still_being_made() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let session = session_env(dir.path());
        let account_dir = dir.path().join("account");
        // A mount that does not land until this test lets it.
        let (release, held) = std::sync::mpsc::channel::<()>();
        let projection = Projection::Opening {
            engine: Box::new(unstarted_engine(&session, &account_dir)),
            spill: cipherbox_fuse::SpillArea::production(&account_dir).expect("a spill area"),
            at: dir.path().join("CipherBox"),
            landing: tokio::task::spawn_blocking(move || {
                let _ = held.recv();
                Err("the test released the mount".to_owned())
            }),
        };
        assert_eq!(projection.status(), MountStatus::Opening);

        let Counted {
            shell,
            credentials,
            requests,
            inbox,
            ..
        } = counted(&session);
        let (_sink, events) = EventStream::piped();

        tokio::task::LocalSet::new()
            .run_until(async move {
                let serving =
                    tokio::task::spawn_local(serve(projection, credentials, inbox, events, shell));
                let (reply, answer) = oneshot::channel();
                requests
                    .send(Request::Status(reply))
                    .expect("the session is serving");
                assert!(
                    answer.await.is_ok(),
                    "the session answers while the mount is outstanding",
                );
                // Ending the session is what stops the loop; the mount never
                // did. The tear-down waits the mount out, so it is released
                // here rather than left for the shutdown bound to expire on.
                drop(requests);
                drop(release);
                serving.await.expect("the session loop ends cleanly");
            })
            .await;
    }

    /// A dead letter that keeps re-reporting is announced once: the watermark is
    /// what the member has already been told, and only more than that is news.
    #[test]
    fn parked_writes_are_announced_on_the_rise_and_not_on_every_report() {
        let mut parked = ParkedWrites::default();
        assert!(!parked.rose_to(0), "an empty queue is not news");
        assert!(parked.rose_to(1));
        for _ in 0..8 {
            assert!(
                !parked.rose_to(1),
                "the same parked write is announced once"
            );
        }
        assert!(parked.rose_to(3), "more parked work is news again");
        assert!(!parked.rose_to(2));
        // …and once some of it clears, the next arrival is news once more.
        assert!(parked.rose_to(3));
    }

    /// Hosts render the rung, so each one crosses as its stable name.
    #[test]
    fn each_staleness_rung_crosses_as_its_stable_name() {
        for (level, name) in [
            (Staleness::Fresh, "fresh"),
            (Staleness::Reconciling, "reconciling"),
            (Staleness::Stale, "stale"),
            (Staleness::Offline, "offline"),
        ] {
            assert_eq!(rung(level), name);
        }
    }
}
