//! The `rotation-wave` scenario: one whole engine per account, over the
//! desktop production seams, rotates a folder of `--nodes` subfolders.
//!
//! The read cut runs first and the write cut second: a sweep filed after a
//! write cut must follow the moved root, and the measured sweep is the one the
//! read cut files. Both measured spans come from the engine's own events, on
//! the engine's `Scheduler` clock (blueprint/engine.md "Triggers").

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cipherbox_desktop_seams::{
    FileFloorStore, FileSnapshotCache, FileStagingStore, ReqwestHttp, ReqwestRecordTransport,
    TokioScheduler, measured_storage_policy,
};
use cipherbox_engine::facade::PendingClass;
use cipherbox_engine::{
    ApiBaseUrl, Command, CommandOutcome, ContentProfile, Engine, Event, EventStream, GatewayConfig,
    LoginSecret, NodeId, NodeKind, OsEntropy, OwnerScopedFloorStore, Permission,
    QueueGenerationStore, SeamSet, SeamTypes, SyncTimingProfile,
};
use zeroize::Zeroizing;

use crate::metrics::{Collector, Outcome, Sample};
use crate::plan::RunPlan;
use crate::runner::random_token;
use crate::seams::MemoryCredentialStore;

/// How long the subtree may take to reach the network before the run gives up.
const POPULATE_BUDGET: Duration = Duration::from_secs(300);
/// How long the read cut's sweep may take to report convergence: a sweep the
/// cut files gives up after three passes and leaves the rest to the idle job.
pub(crate) const CONVERGE_BUDGET: Duration =
    Duration::from_secs(SyncTimingProfile::PRODUCTION.sweep_cadence.as_secs() + 300);
/// The API's per-account content bucket refills over this window. Each phase
/// starts on a full bucket, so the burst that built the subtree does not
/// throttle the cut that follows it.
const THROTTLE_WINDOW: Duration = Duration::from_secs(61);
/// Subfolders created per bucket: each publishes a record and re-seals its
/// parent, and the bucket holds 60 uploads.
const POPULATE_CHUNK: u32 = 20;
const FOLDER_NAME: &str = "rotation-wave";

struct LoadSeamTypes;

impl SeamTypes for LoadSeamTypes {
    type FloorStore = FileFloorStore;
    type RecordTransport = ReqwestRecordTransport;
    type Http = ReqwestHttp;
    type Scheduler = TokioScheduler;
    type StagingStore = FileStagingStore;
    type SnapshotCache = FileSnapshotCache;
    type CredentialStore = MemoryCredentialStore;
}

/// One name wave, on the engine clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wave {
    /// From the wave start to its end.
    pub(crate) total_ms: u64,
    /// The time each node took to land, from the previous node or the start.
    pub(crate) node_ms: Vec<u64>,
    pub(crate) interior_nodes: u32,
    pub(crate) dropped: u32,
}

/// Shape the name wave of `scope_root` out of an event run. A wave with no end
/// stopped, and measured nothing.
pub(crate) fn name_wave(events: &[Event], scope_root: NodeId) -> Result<Wave, String> {
    let mut start = None;
    let mut previous = 0;
    let mut landed = 0;
    let mut node_ms = Vec::new();
    for event in events {
        match event {
            Event::NameWaveStarted {
                scope_root: root,
                at,
            } if *root == scope_root => {
                if start.is_none() {
                    start = Some(at.0);
                    previous = at.0;
                }
            }
            // A retry counts again from one: a node counts once, at the first
            // event that shows it moved.
            Event::NameWaveProgress {
                scope_root: root,
                moved,
                at,
                ..
            } if *root == scope_root && start.is_some() && *moved > landed => {
                node_ms.push(at.0.saturating_sub(previous));
                previous = at.0;
                landed = *moved;
            }
            Event::NameWaveEnded {
                scope_root: root,
                interior_nodes,
                dropped,
                at,
            } if *root == scope_root => {
                let start = start.ok_or("the name wave ended with no start")?;
                return Ok(Wave {
                    total_ms: at.0.saturating_sub(start),
                    node_ms,
                    interior_nodes: *interior_nodes,
                    dropped: *dropped,
                });
            }
            _ => {}
        }
    }
    Err(match start {
        Some(_) => "the name wave started and sent no end".to_owned(),
        None => "the write cut sent no name wave".to_owned(),
    })
}

/// Whether `event` reports that `scope_root` holds no node at the old epoch.
fn converged(event: &Event, scope_root: NodeId) -> bool {
    matches!(
        event,
        Event::SweepConvergence { scope_root: root, old_epoch_nodes: 0, .. } if *root == scope_root
    )
}

/// Two spans from the read cut of `scope_root`, out of the first report that
/// says it converged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Convergence {
    /// To the end of the run that proved no node at the old epoch: the bound
    /// on the window the old read key still opens a node.
    pub(crate) confirmed_ms: u64,
    /// To the end of the last run that re-sealed a node. A node re-sealed by
    /// another path, such as owed rotation work, does not move it.
    pub(crate) last_reseal_ms: u64,
}

pub(crate) fn sweep_convergence(
    events: &[Event],
    scope_root: NodeId,
) -> Result<Convergence, String> {
    let Some(Event::SweepConvergence {
        cut_at,
        last_reseal_at,
        at,
        ..
    }) = events.iter().find(|event| converged(event, scope_root))
    else {
        return Err("no sweep run reported the scope converged".to_owned());
    };
    match (cut_at, last_reseal_at) {
        (Some(cut), Some(reseal)) => Ok(Convergence {
            confirmed_ms: at.0.saturating_sub(cut.0),
            last_reseal_ms: reseal.0.saturating_sub(cut.0),
        }),
        (None, _) => Err("the converged report carries no cut time".to_owned()),
        (_, None) => Err("the converged report carries no re-seal time".to_owned()),
    }
}

/// Run one engine per account, each in its own state directory.
pub(crate) async fn run(plan: &RunPlan) -> Result<(Collector, f64), String> {
    let run_id = random_token(6);
    let started = Instant::now();
    let mut tasks = Vec::new();
    for index in 0..plan.clients {
        let plan = plan.clone();
        let dir = Path::new(&plan.report_dir).join(format!("state-{run_id}-{index}"));
        tasks.push(tokio::task::spawn_local(async move {
            if plan.ramp_ms > 0 {
                tokio::time::sleep(Duration::from_millis(plan.ramp_ms * u64::from(index))).await;
            }
            let mut collector = Collector::default();
            if let Err(error) = one_account(&plan, &dir, &mut collector).await {
                collector
                    .record(Sample::new("rotation-run", Outcome::Failed, 0.0).with_detail(error));
            }
            let _ = std::fs::remove_dir_all(&dir);
            collector
        }));
    }
    let mut collector = Collector::default();
    for task in tasks {
        let samples = task
            .await
            .map_err(|error| format!("an engine did not finish: {error}"))?;
        collector.absorb(samples);
    }
    Ok((collector, started.elapsed().as_secs_f64() * 1_000.0))
}

fn seam_set(plan: &RunPlan, dir: &Path) -> Result<SeamSet<LoadSeamTypes>, String> {
    let seam = |error: cipherbox_engine::seams::SeamError| error.to_string();
    Ok(SeamSet::<LoadSeamTypes> {
        floor_store: OwnerScopedFloorStore::new(
            FileFloorStore::open(dir.join("floors")).map_err(seam)?,
        ),
        record_transport: ReqwestRecordTransport::new(plan.routing_endpoints.clone(), None)
            .map_err(seam)?,
        http: ReqwestHttp::new().map_err(seam)?,
        scheduler: TokioScheduler::new(),
        staging_store: QueueGenerationStore::new(
            FileStagingStore::open(dir.join("staging")).map_err(seam)?,
        ),
        snapshot_cache: FileSnapshotCache::open(dir.join("cache")).map_err(seam)?,
        credential_store: MemoryCredentialStore::default(),
    })
}

/// A fresh identity: the API creates the account at its first login.
fn fresh_secret() -> Result<LoginSecret, String> {
    let mut secret = Zeroizing::new(vec![0u8; 32]);
    getrandom::getrandom(&mut secret).map_err(|error| format!("draw a login secret: {error}"))?;
    Ok(LoginSecret::new(std::mem::take(&mut *secret)))
}

fn elapsed_ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1_000.0
}

async fn one_account(
    plan: &RunPlan,
    dir: &PathBuf,
    collector: &mut Collector,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|error| format!("create {}: {error}", dir.display()))?;
    let seams = seam_set(plan, dir)?;
    let api_base_url = ApiBaseUrl::parse(&plan.api_url).map_err(|error| error.to_string())?;
    let (mut engine, mut events) = Engine::new(
        seams,
        Box::new(OsEntropy),
        SyncTimingProfile::PRODUCTION,
        ContentProfile::PRODUCTION,
        measured_storage_policy(dir),
        api_base_url,
        GatewayConfig {
            accelerator: plan.gateway_url.clone(),
            public_fallbacks: Vec::new(),
        },
    );

    let since = Instant::now();
    engine
        .start(fresh_secret()?, None)
        .await
        .map_err(|error| format!("engine start: {error}"))?;
    collector.record(Sample::new("engine-start", Outcome::Ok, elapsed_ms(since)));

    let since = Instant::now();
    let folder = populate(&mut engine, &mut events, plan.nodes).await?;
    collector.record(Sample::new("populate", Outcome::Ok, elapsed_ms(since)));

    let since = Instant::now();
    match engine
        .command(Command::CreateInviteLink {
            node: folder,
            permission: Permission::Read,
            expires_at: None,
            owner_name: String::new(),
            admission_cap: None,
        })
        .await
    {
        Ok(CommandOutcome::InviteLinkMinted(_)) => {}
        Ok(other) => return Err(format!("the link mint answered {other:?}")),
        Err(error) => return Err(format!("the link mint failed: {error}")),
    }
    collector.record(Sample::new("link-mint", Outcome::Ok, elapsed_ms(since)));

    tokio::time::sleep(THROTTLE_WINDOW).await;
    drain(&mut events);
    let since = Instant::now();
    engine
        .command(Command::RotateNow { node: folder })
        .await
        .map_err(|error| format!("the read cut failed: {error}"))?;
    collector.record(Sample::new("read-cut", Outcome::Ok, elapsed_ms(since)));
    let reports = until_converged(&mut events, folder).await;
    match sweep_convergence(&reports, folder) {
        Ok(spans) => {
            collector.record(Sample::new(
                "sweep-converge",
                Outcome::Ok,
                spans.confirmed_ms as f64,
            ));
            collector.record(Sample::new(
                "sweep-last-reseal",
                Outcome::Ok,
                spans.last_reseal_ms as f64,
            ));
        }
        Err(error) => {
            collector.record(Sample::new("sweep-converge", Outcome::Failed, 0.0).with_detail(error))
        }
    }

    tokio::time::sleep(THROTTLE_WINDOW).await;
    drain(&mut events);
    let since = Instant::now();
    engine
        .command(Command::RotateWriteNow { node: folder })
        .await
        .map_err(|error| format!("the write cut failed: {error}"))?;
    collector.record(Sample::new("write-cut", Outcome::Ok, elapsed_ms(since)));
    match name_wave(&drain(&mut events), folder) {
        Ok(wave) => record_wave(collector, &wave, plan.nodes),
        Err(error) => {
            collector.record(Sample::new("name-wave", Outcome::Failed, 0.0).with_detail(error));
        }
    }

    // Best effort: the measurement already holds every sample.
    let _ = engine.command(Command::Logout).await;
    Ok(())
}

fn record_wave(collector: &mut Collector, wave: &Wave, nodes: u32) {
    let sample = Sample::new("name-wave", Outcome::Ok, wave.total_ms as f64);
    collector.record(if wave.interior_nodes == nodes && wave.dropped == 0 {
        sample
    } else {
        Sample::new("name-wave", Outcome::Failed, wave.total_ms as f64).with_detail(format!(
            "the wave covered {} interior nodes of {nodes} and dropped {}",
            wave.interior_nodes, wave.dropped
        ))
    });
    for ms in &wave.node_ms {
        collector.record(Sample::new("name-wave-node", Outcome::Ok, *ms as f64));
    }
}

/// Create the folder and its subfolders, then refresh until the queue has
/// published every one of them.
async fn populate(
    engine: &mut Engine<LoadSeamTypes>,
    events: &mut EventStream,
    nodes: u32,
) -> Result<NodeId, String> {
    let root = engine.root();
    create_folder(engine, root, FOLDER_NAME).await?;
    let folder = child_named(engine, root, FOLDER_NAME).await?;
    await_published(engine, events, &[(root, 1)]).await?;
    let mut created = 0;
    while created < nodes {
        if created > 0 {
            tokio::time::sleep(THROTTLE_WINDOW).await;
        }
        let chunk = (nodes - created).min(POPULATE_CHUNK);
        for index in created..created + chunk {
            create_folder(engine, folder, &format!("node-{index}")).await?;
        }
        created += chunk;
        await_published(engine, events, &[(folder, created)]).await?;
    }
    Ok(folder)
}

/// Refresh until each folder lists its count of children with none queued.
async fn await_published(
    engine: &mut Engine<LoadSeamTypes>,
    events: &mut EventStream,
    folders: &[(NodeId, u32)],
) -> Result<(), String> {
    let deadline = Instant::now() + POPULATE_BUDGET;
    loop {
        engine
            .command(Command::ManualRefresh)
            .await
            .map_err(|error| format!("refresh: {error}"))?;
        drain(events);
        let mut done = true;
        for (folder, count) in folders {
            done &= published(engine, *folder, *count).await?;
        }
        if done {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "the subtree did not publish within {}s",
                POPULATE_BUDGET.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn create_folder(
    engine: &mut Engine<LoadSeamTypes>,
    parent: NodeId,
    name: &str,
) -> Result<(), String> {
    engine
        .command(Command::Create {
            parent,
            name: name.to_owned(),
            kind: NodeKind::Folder,
        })
        .await
        .map(|_| ())
        .map_err(|error| format!("create a folder: {error}"))
}

async fn child_named(
    engine: &Engine<LoadSeamTypes>,
    parent: NodeId,
    name: &str,
) -> Result<NodeId, String> {
    let view = engine
        .snapshot(parent)
        .await
        .map_err(|error| format!("snapshot: {error}"))?;
    view.children
        .iter()
        .find(|child| child.name == name)
        .map(|child| child.id)
        .ok_or_else(|| format!("the folder `{name}` is not in its parent"))
}

/// Whether `folder` lists `count` children and the queue holds none of them.
async fn published(
    engine: &Engine<LoadSeamTypes>,
    folder: NodeId,
    count: u32,
) -> Result<bool, String> {
    let view = engine
        .snapshot(folder)
        .await
        .map_err(|error| format!("snapshot: {error}"))?;
    if let Some(dead) = view.dead_letters.first() {
        return Err(format!("an op dead-lettered: {:?}", dead.reason));
    }
    Ok(view.children.len() == count as usize
        && view
            .children
            .iter()
            .all(|child| child.pending == PendingClass::None))
}

fn drain(events: &mut EventStream) -> Vec<Event> {
    std::iter::from_fn(|| events.try_next()).collect()
}

/// Collect events until a sweep report says `scope_root` converged, or the
/// budget runs out.
async fn until_converged(events: &mut EventStream, scope_root: NodeId) -> Vec<Event> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + CONVERGE_BUDGET;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await {
        let done = converged(&event, scope_root);
        seen.push(event);
        if done {
            break;
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_engine::seams::UnixMillis;

    const SCOPE: NodeId = NodeId([7; 16]);
    const OTHER: NodeId = NodeId([9; 16]);

    fn started(scope_root: NodeId, at: u64) -> Event {
        Event::NameWaveStarted {
            scope_root,
            at: UnixMillis(at),
        }
    }

    fn progress(scope_root: NodeId, moved: u32, at: u64) -> Event {
        Event::NameWaveProgress {
            scope_root,
            moved,
            total: 3,
            at: UnixMillis(at),
        }
    }

    fn ended(scope_root: NodeId, at: u64) -> Event {
        Event::NameWaveEnded {
            scope_root,
            interior_nodes: 2,
            dropped: 0,
            at: UnixMillis(at),
        }
    }

    fn report(
        scope_root: NodeId,
        old_epoch_nodes: u32,
        cut_at: Option<u64>,
        last_reseal_at: Option<u64>,
    ) -> Event {
        Event::SweepConvergence {
            scope_root,
            read_epoch: 2,
            old_epoch_nodes,
            cut_at: cut_at.map(UnixMillis),
            last_reseal_at: last_reseal_at.map(UnixMillis),
            at: UnixMillis(5_000),
        }
    }

    #[test]
    fn a_wave_measures_each_node_from_the_one_before_and_the_whole_from_its_start() {
        let events = [
            started(SCOPE, 1_000),
            progress(OTHER, 1, 1_050),
            progress(SCOPE, 1, 1_100),
            progress(SCOPE, 2, 1_250),
            progress(SCOPE, 3, 1_300),
            ended(SCOPE, 1_320),
        ];
        assert_eq!(
            name_wave(&events, SCOPE),
            Ok(Wave {
                total_ms: 320,
                node_ms: vec![100, 150, 50],
                interior_nodes: 2,
                dropped: 0,
            })
        );
    }

    #[test]
    fn a_retried_wave_counts_each_node_once() {
        let events = [
            started(SCOPE, 1_000),
            progress(SCOPE, 1, 1_100),
            progress(SCOPE, 2, 1_200),
            progress(SCOPE, 1, 1_300),
            progress(SCOPE, 2, 1_400),
            progress(SCOPE, 3, 1_500),
            ended(SCOPE, 1_520),
        ];
        let wave = name_wave(&events, SCOPE).expect("a wave");
        assert_eq!(wave.node_ms, vec![100, 100, 300]);
        assert_eq!(wave.total_ms, 520);
    }

    #[test]
    fn a_wave_with_no_end_measures_nothing() {
        let stopped = [started(SCOPE, 1_000), progress(SCOPE, 1, 1_100)];
        assert!(name_wave(&stopped, SCOPE).is_err());
        assert!(name_wave(&[ended(OTHER, 1_000)], SCOPE).is_err());
        assert!(name_wave(&[ended(SCOPE, 1_000)], SCOPE).is_err());
    }

    #[test]
    fn convergence_runs_from_the_cut_to_the_run_that_converged() {
        let events = [
            report(OTHER, 0, Some(100), Some(200)),
            report(SCOPE, 3, Some(1_000), Some(1_400)),
            report(SCOPE, 0, Some(1_000), Some(2_500)),
            report(SCOPE, 0, Some(1_000), Some(9_000)),
        ];
        assert_eq!(
            sweep_convergence(&events, SCOPE),
            Ok(Convergence {
                confirmed_ms: 4_000,
                last_reseal_ms: 1_500,
            })
        );
    }

    #[test]
    fn convergence_needs_a_converged_report_with_both_times() {
        assert!(sweep_convergence(&[report(SCOPE, 1, Some(1), Some(2))], SCOPE).is_err());
        assert!(sweep_convergence(&[report(SCOPE, 0, None, Some(2))], SCOPE).is_err());
        assert!(sweep_convergence(&[report(SCOPE, 0, Some(1), None)], SCOPE).is_err());
    }

    #[test]
    fn a_wave_that_drops_a_node_or_misses_the_subtree_is_a_failed_sample() {
        let mut collector = Collector::default();
        let wave = Wave {
            total_ms: 10,
            node_ms: vec![5, 5],
            interior_nodes: 2,
            dropped: 1,
        };
        record_wave(&mut collector, &wave, 2);
        record_wave(&mut collector, &Wave { dropped: 0, ..wave }, 3);
        let summary = collector.summarize(1.0);
        let row = summary
            .iter()
            .find(|row| row.op == "name-wave")
            .expect("a name-wave row");
        assert_eq!((row.count, row.failed), (2, 2));
    }
}
