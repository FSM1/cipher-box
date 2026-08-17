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
mod mailbox;
mod seams;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;
use std::thread::JoinHandle;

use cipherbox_desktop_seams::{KeyringCredentialStore, account_data_dir};
use cipherbox_engine::facade::{ApiBaseUrl, Engine, Event, EventStream, LoginSecret};
use cipherbox_engine::seams::CredentialStore;
use cipherbox_engine::{ChallengeSigner, ContentProfile, IdentityChallengeSigner, Staleness};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

pub use config::EngineConfig;
use seams::{DesktopSeamTypes, OsEntropy};

/// The secp256k1 scalar length `crates/engine/src/session.rs` requires.
pub const LOGIN_SECRET_LEN: usize = 32;

const INVALID_SECRET: &str = "the login secret is not a valid identity scalar";
const NO_SESSION: &str = "no session is live on this device";
const ALREADY_LIVE: &str = "a session is already live on this device";
const POISONED: &str = "the session state is unreadable; restart CipherBox";

/// The most warnings retained at once. A repeating condition dedupes rather
/// than accumulating, so this bounds distinct classes, not tick count.
const MAX_WARNINGS: usize = 8;

/// What the shell renders of a live vault. Key-free by construction: counts, a
/// rung, and the engine's own key-material-free classifications — never a name
/// the engine holds keys for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    /// Items directly under the vault root.
    pub items: usize,
    /// The staleness rung at read time.
    pub staleness: &'static str,
    /// Retained dead-lettered ops — work this device holds that will not
    /// publish, and must never be silent.
    pub dead_letters: usize,
    /// Durable queue entries this session holds but cannot read.
    pub retained_records: usize,
    /// Conditions the engine raised that no snapshot carries.
    pub warnings: Vec<VaultWarning>,
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
    /// carries one. Record names and routing keys are deliberately left
    /// behind: the window says what happened, never which record it happened
    /// to.
    pub detail: Option<String>,
}

/// The warnings this session has raised, newest last.
#[derive(Default)]
struct Warnings(VecDeque<VaultWarning>);

impl Warnings {
    /// Classifies one event, retaining the classes a snapshot cannot report.
    /// Staleness, dead letters, and op progress are absent on purpose — the
    /// snapshot carries all three, and a warning that duplicated them would be
    /// the conflation the ladder exists to prevent.
    fn record(&mut self, event: &Event) {
        let warning = match event {
            Event::VaultUnprovisioned { detail, .. } => VaultWarning {
                kind: "unprovisioned",
                detail: Some(detail.clone()),
            },
            Event::AttributableAbuse { description } => VaultWarning {
                kind: "trustViolation",
                detail: Some(description.clone()),
            },
            Event::WithheldUpdateEscalation { .. } => VaultWarning {
                kind: "withheldUpdate",
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

impl VaultStatus {
    /// The rung's stable name, the spelling the wasm host uses for the same
    /// ladder so both shells say one word for one state.
    fn rung(staleness: Staleness) -> &'static str {
        match staleness {
            Staleness::Fresh => "fresh",
            Staleness::Reconciling => "reconciling",
            Staleness::Stale => "stale",
            Staleness::Offline => "offline",
        }
    }
}

/// What the host asks of the engine thread. Ending the session is not one of
/// them: closing the channel is what ends it.
enum Request {
    /// Read the vault's status, and answer here.
    Status(oneshot::Sender<Result<VaultStatus, String>>),
    /// Delete this device's stored refresh token. A logout is not a quit: the
    /// durable stores survive both, but the credential survives only the quit
    /// (blueprint/desktop.md, "Lifecycle").
    ForgetCredentials,
}

/// The live session: the channel into its engine thread, and the thread itself.
struct Live {
    requests: mpsc::UnboundedSender<Request>,
    thread: JoinHandle<()>,
}

/// Where the running app's one engine lives.
#[derive(Default)]
pub struct EngineHost {
    live: Mutex<Option<Live>>,
}

impl EngineHost {
    /// Builds the engine for `secret` and starts it, resolving once cold start
    /// has landed or refusing with why it did not.
    ///
    /// A second call while a session is live is refused rather than building a
    /// second engine: the slot is taken before the thread spawns, so the losing
    /// caller never reaches construction.
    pub async fn start(
        &self,
        secret: Zeroizing<Vec<u8>>,
        session: SessionEnv,
    ) -> Result<(), String> {
        let started = self.spawn_engine(secret, session)?;
        match started.await {
            Ok(Ok(())) => Ok(()),
            // The thread ends itself on a failed start; joining it here is what
            // frees the slot for the next attempt.
            Ok(Err(refusal)) => {
                self.stop();
                Err(refusal)
            }
            Err(_) => {
                self.stop();
                Err("the engine stopped before it started".to_owned())
            }
        }
    }

    /// Logs out: deletes this device's stored refresh token, then ends the
    /// session as [`stop`](Self::stop) does. The durable stores survive by
    /// design; an explicit "forget this device" is what sweeps them.
    ///
    /// Idempotent — the login flow calls it on paths where no session is live.
    pub fn log_out(&self) {
        if let Ok(live) = self.live.lock() {
            if let Some(live) = live.as_ref() {
                // Not awaited: the join in `stop` is what proves the thread
                // reached it, and a closed channel means it never will.
                let _ = live.requests.send(Request::ForgetCredentials);
            }
        }
        self.stop();
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
        let (reply, answer) = oneshot::channel();
        {
            let live = self.live.lock().map_err(|_| POISONED)?;
            let live = live.as_ref().ok_or(NO_SESSION)?;
            live.requests
                .send(Request::Status(reply))
                .map_err(|_| NO_SESSION)?;
        }
        answer.await.map_err(|_| NO_SESSION)?
    }

    /// Claims the one engine slot and spawns its thread, handing back where the
    /// start verdict will arrive.
    fn spawn_engine(
        &self,
        secret: Zeroizing<Vec<u8>>,
        session: SessionEnv,
    ) -> Result<oneshot::Receiver<Result<(), String>>, String> {
        let mut live = self.live.lock().map_err(|_| POISONED)?;
        if live.is_some() {
            return Err(ALREADY_LIVE.to_owned());
        }

        let (requests, inbox) = mpsc::unbounded_channel();
        let (verdict, started) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("cipherbox-engine".to_owned())
            .spawn(move || host_engine(secret, session, inbox, verdict))
            .map_err(|error| format!("the engine thread could not start: {error}"))?;

        *live = Some(Live { requests, thread });
        Ok(started)
    }
}

/// Where this session's stores live and what tells the shell to repaint.
pub struct SessionEnv {
    /// This build's engine configuration.
    pub config: EngineConfig,
    /// `<data_local_dir>` — the account directory is composed under it.
    pub data_local_dir: PathBuf,
    /// The OS keyring service name holding the rotating refresh token.
    pub keyring_service: String,
    /// Called when the engine emits, so the shell re-reads what it renders.
    pub changed: Box<dyn Fn() + Send>,
}

/// The API's own account identifier for this login secret: the compressed SEC1
/// identity public key, lowercase hex. Public material — every login presents
/// it — and one path component, so it names the account's store directory
/// (blueprint/desktop.md "Engine wiring").
fn account_id(secret: &[u8]) -> Result<String, String> {
    let scalar: Zeroizing<[u8; LOGIN_SECRET_LEN]> = Zeroizing::new(
        secret
            .try_into()
            .map_err(|_| "the login secret is not a 32-byte scalar")?,
    );
    IdentityChallengeSigner::from_scalar(&scalar)
        .map(|signer| signer.public_key_hex())
        .ok_or_else(|| INVALID_SECRET.to_owned())
}

/// The engine thread: build, start, then serve until the request channel closes.
fn host_engine(
    secret: Zeroizing<Vec<u8>>,
    session: SessionEnv,
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
        let (engine, events, credentials) = match start_engine(secret, &session).await {
            Ok(started) => started,
            Err(refusal) => {
                let _ = verdict.send(Err(refusal));
                return;
            }
        };
        let _ = verdict.send(Ok(()));

        // Shared with the drain rather than owned by it: both run on this one
        // thread, and the status read is what carries them to the window.
        let warnings = Rc::new(RefCell::new(Warnings::default()));
        tokio::task::spawn_local(repaint_on_events(
            events,
            Rc::clone(&warnings),
            session.changed,
        ));
        serve(engine, credentials, warnings, inbox).await;
    });
}

/// Constructs the engine over the desktop seam set and consumes the secret. The
/// credential store comes back out because logout deletes what the engine's
/// login put in it, and the seam set itself is the engine's from here on.
async fn start_engine(
    secret: Zeroizing<Vec<u8>>,
    session: &SessionEnv,
) -> Result<
    (
        Engine<DesktopSeamTypes>,
        EventStream,
        KeyringCredentialStore,
    ),
    String,
> {
    let account_dir = account_data_dir(&session.data_local_dir, &account_id(&secret)?)
        .map_err(|error| error.to_string())?;
    let seams = seams::seam_set(&session.config, &account_dir, &session.keyring_service)?;
    let credentials = seams.credential_store.clone();

    let (mut engine, events) = Engine::new(
        seams,
        Box::new(OsEntropy),
        session.config.profile,
        // The framing is frozen and pins the wire format, so every host writes
        // the shipped profile.
        ContentProfile::PRODUCTION,
        session.config.storage_policy,
        ApiBaseUrl::parse(&session.config.api_base_url).map_err(|error| error.to_string())?,
        session.config.gateway.clone(),
    );

    // The engine copies the secret into its own zeroizing store; this frame's
    // copy dies here, on the failure path as much as the success one.
    let started = engine.start(LoginSecret::new(secret.to_vec())).await;
    drop(secret);
    started.map_err(|error| error.to_string())?;
    Ok((engine, events, credentials))
}

/// Serves requests until the host closes the channel (logout or quit), at which
/// point the engine drops — stopping its loops and zeroizing what it holds.
async fn serve(
    engine: Engine<DesktopSeamTypes>,
    credentials: KeyringCredentialStore,
    warnings: Rc<RefCell<Warnings>>,
    mut inbox: mpsc::UnboundedReceiver<Request>,
) {
    while let Some(request) = inbox.recv().await {
        match request {
            Request::Status(reply) => {
                let _ = reply.send(status(&engine, &warnings).await);
            }
            // A keyring that refuses the delete is reported to no one: the
            // session is ending either way, and there is no surface left to
            // tell. It is the next login's `store` that overwrites it.
            Request::ForgetCredentials => {
                let _ = credentials.clear_refresh_token().await;
            }
        }
    }
}

async fn status(
    engine: &Engine<DesktopSeamTypes>,
    warnings: &RefCell<Warnings>,
) -> Result<VaultStatus, String> {
    let view = engine
        .snapshot(engine.root())
        .await
        .map_err(|error| error.to_string())?;
    Ok(VaultStatus {
        items: view.children.len(),
        staleness: VaultStatus::rung(view.staleness),
        dead_letters: view.dead_letters.len(),
        retained_records: view.retained_records,
        warnings: warnings.borrow().list(),
    })
}

/// Drains the engine's event stream, retaining what no snapshot reports and
/// telling the shell to re-read the rest. Draining is not optional — an unread
/// stream grows for as long as the session lives.
async fn repaint_on_events(
    mut events: EventStream,
    warnings: Rc<RefCell<Warnings>>,
    changed: Box<dyn Fn() + Send>,
) {
    while let Some(event) = events.next().await {
        warnings.borrow_mut().record(&event);
        changed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_engine::facade::{NodeId, OpPhase};
    use cipherbox_engine::seams::OpId;
    use cipherbox_engine::sync::DeadLetterReason;
    use std::path::Path;

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
            keyring_service: "com.cipherbox.desktop.test".to_owned(),
            changed: Box::new(|| {}),
        }
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

    /// The classes no snapshot carries. Dropping them would render a withheld
    /// update or a vault that was never minted as an empty, synced vault.
    #[test]
    fn the_engines_never_silent_events_are_retained() {
        let retained = warned(&[
            Event::VaultUnprovisioned {
                retryable: true,
                detail: "the mint did not land".to_owned(),
            },
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
                "unprovisioned",
                "trustViolation",
                "withheldUpdate",
                "renewalFailed"
            ],
        );
    }

    /// A warning says what happened, never which record it happened to: a
    /// pinned name and a routing key both identify a record to whoever reads
    /// the window.
    #[test]
    fn a_warning_carries_no_record_identifier() {
        let retained = warned(&[
            Event::WithheldUpdateEscalation {
                ipns_name: b"a-pinned-name".to_vec(),
            },
            Event::RenewalFailed {
                routing_key: "a-routing-key".to_owned(),
                detail: "the CAS race was lost".to_owned(),
            },
        ]);

        for warning in &retained {
            let detail = warning.detail.clone().unwrap_or_default();
            assert!(!detail.contains("a-pinned-name"), "{detail}");
            assert!(!detail.contains("a-routing-key"), "{detail}");
        }
        assert_eq!(retained[0].detail, None, "an escalation names no record");
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
        let repeated = Event::AttributableAbuse {
            description: "gate rejection".to_owned(),
        };
        let mut warnings = Warnings::default();
        for _ in 0..MAX_WARNINGS * 2 {
            warnings.record(&repeated);
        }
        assert_eq!(warnings.list().len(), 1);

        for index in 0..MAX_WARNINGS * 2 {
            warnings.record(&Event::AttributableAbuse {
                description: format!("rejection {index}"),
            });
        }
        let retained = warnings.list();
        assert_eq!(retained.len(), MAX_WARNINGS);
        assert_eq!(
            retained.last().and_then(|w| w.detail.clone()),
            Some(format!("rejection {}", MAX_WARNINGS * 2 - 1)),
            "the newest warning is always retained",
        );
    }

    /// Hosts render the rung, so each one crosses as its stable name.
    #[test]
    fn each_staleness_rung_crosses_as_its_stable_name() {
        for (rung, name) in [
            (Staleness::Fresh, "fresh"),
            (Staleness::Reconciling, "reconciling"),
            (Staleness::Stale, "stale"),
            (Staleness::Offline, "offline"),
        ] {
            assert_eq!(VaultStatus::rung(rung), name);
        }
    }
}
