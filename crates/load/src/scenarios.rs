//! The five scenarios, each aimed at one v2 API surface. Sustained and spike
//! profiles are `--ops-per-client` and `--ramp-ms` on these, not scenarios of
//! their own (crates/load/README.md).

use cipherbox_engine::api::NameRegistration;
use cipherbox_engine::seams::Http;

use crate::metrics::Collector;
use crate::plan::{RunPlan, Scenario};
use crate::runner::{
    VirtualClient, gateway_get, leaf_cid, measure, measure_served, pace, random_bytes,
    random_token, synthetic_ipns_names,
};

/// How many batches of registered targets may sit pending before the run
/// retires them, so a long wave's memory tracks the batch size rather than the
/// run length.
const RETIRE_DRAIN_BATCHES: usize = 4;

/// Entropy behind each advisory CID, drawn one batch at a time so a large
/// `--batch-size` does not spend the run's wall clock in per-row OS reads.
const ADVISORY_CID_BYTES: usize = 64;

pub(crate) async fn drive<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    http: &H,
    collector: &mut Collector,
) {
    match plan.scenario {
        Scenario::ContentIngest => content_ingest(virtual_client, plan, collector).await,
        Scenario::GatewayRead => gateway_read(virtual_client, plan, http, collector).await,
        Scenario::NameWave => name_wave(virtual_client, plan, collector).await,
        Scenario::Mixed => mixed(virtual_client, plan, collector).await,
        Scenario::ByoAdvisory => byo_advisory(virtual_client, plan, collector).await,
    }
}

/// Upload one caller-addressed block, returning its content address.
async fn upload_block<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    collector: &mut Collector,
) -> Option<String> {
    let block = random_bytes(plan.block_bytes as usize);
    let cid = leaf_cid(&block);
    measure(
        collector,
        "content-upload",
        u64::from(plan.block_bytes),
        virtual_client.client.upload(&cid, &block),
    )
    .await
    .map(|_| cid)
}

/// Hosted content ingress: one request, one caller-addressed block.
async fn content_ingest<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    collector: &mut Collector,
) {
    let mut pinned = Vec::new();
    for _ in 0..plan.ops_per_client {
        if let Some(cid) = upload_block(virtual_client, plan, collector).await {
            pinned.push(cid);
        }
        drain_if_full(virtual_client, plan, collector, &mut pinned).await;
        pace(plan).await;
    }
    retire(virtual_client, plan, collector, pinned).await;
}

/// Read-accelerator throughput, over a small set of blocks the run seeds.
async fn gateway_read<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    http: &H,
    collector: &mut Collector,
) {
    let gateway = plan.gateway_url.as_deref().unwrap_or_default();
    let mut seeded = Vec::new();
    for _ in 0..plan.ops_per_client.min(4) {
        if let Some(cid) = upload_block(virtual_client, plan, collector).await {
            seeded.push(cid);
        }
        pace(plan).await;
    }
    if seeded.is_empty() {
        return;
    }

    for index in 0..plan.ops_per_client {
        let cid = &seeded[index as usize % seeded.len()];
        let url = format!("{gateway}/ipfs/{cid}?format=raw");
        measure_served(
            collector,
            "gateway-read",
            gateway_get(http, &url, plan.gateway_token.as_deref()),
        )
        .await;
        pace(plan).await;
    }
    retire(virtual_client, plan, collector, seeded).await;
}

/// Registry cadence under a name wave: bulk registration of freshly derived
/// names, then the sweep that retires them.
async fn name_wave<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    collector: &mut Collector,
) {
    let mut names = Vec::new();
    for _ in 0..plan.ops_per_client {
        let batch: Vec<NameRegistration> = synthetic_ipns_names(plan.batch_size)
            .into_iter()
            .map(|ipns_name| NameRegistration {
                ipns_name,
                head_cid: None,
                content_cids: Vec::new(),
            })
            .collect();
        if register(virtual_client, collector, &batch).await {
            names.extend(batch.into_iter().map(|entry| entry.ipns_name));
        }
        drain_if_full(virtual_client, plan, collector, &mut names).await;
        pace(plan).await;
    }
    retire(virtual_client, plan, collector, names).await;
}

/// The interleaved profile: ingest, registration, quota, and a mailbox
/// round-trip on one account.
async fn mixed<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    collector: &mut Collector,
) {
    let mut targets = Vec::new();
    for _ in 0..plan.ops_per_client {
        if let Some(cid) = upload_block(virtual_client, plan, collector).await {
            let batch = [NameRegistration {
                ipns_name: synthetic_ipns_names(1).remove(0),
                head_cid: None,
                content_cids: vec![cid],
            }];
            if register(virtual_client, collector, &batch).await {
                let [entry] = batch;
                targets.push(entry.ipns_name);
                targets.extend(entry.content_cids);
            }
        }

        measure(collector, "account-quota", 0, virtual_client.client.quota()).await;

        let blob = random_bytes(256);
        let posted = measure(
            collector,
            "mailbox-post",
            blob.len() as u64,
            virtual_client.client.mailbox_post(
                &virtual_client.public_key,
                &blob,
                &random_token(24),
            ),
        )
        .await;
        measure(
            collector,
            "mailbox-poll",
            0,
            virtual_client.client.mailbox_poll(),
        )
        .await;
        if let Some(id) = posted {
            measure(
                collector,
                "mailbox-ack",
                0,
                virtual_client.client.mailbox_ack(&id),
            )
            .await;
        }
        drain_if_full(virtual_client, plan, collector, &mut targets).await;
        pace(plan).await;
    }
    retire(virtual_client, plan, collector, targets).await;
}

/// A BYO account's registry path: its bytes never touch the API, so it only
/// registers advisory pin rows, which count for liveness and never gate.
async fn byo_advisory<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    collector: &mut Collector,
) {
    if measure(
        collector,
        "account-byo",
        0,
        virtual_client.client.set_byo(true),
    )
    .await
    .is_none()
    {
        return;
    }

    let mut targets = Vec::new();
    for _ in 0..plan.ops_per_client {
        let seed = random_bytes(ADVISORY_CID_BYTES * plan.batch_size as usize);
        let batch: Vec<NameRegistration> = synthetic_ipns_names(plan.batch_size)
            .into_iter()
            .zip(seed.chunks(ADVISORY_CID_BYTES))
            .map(|(ipns_name, block)| NameRegistration {
                ipns_name,
                head_cid: None,
                content_cids: vec![leaf_cid(block)],
            })
            .collect();
        if register(virtual_client, collector, &batch).await {
            for entry in batch {
                targets.push(entry.ipns_name);
                targets.extend(entry.content_cids);
            }
        }
        measure(collector, "account-quota", 0, virtual_client.client.quota()).await;
        drain_if_full(virtual_client, plan, collector, &mut targets).await;
        pace(plan).await;
    }
    retire(virtual_client, plan, collector, targets).await;
}

async fn register<H: Http>(
    virtual_client: &VirtualClient<H>,
    collector: &mut Collector,
    batch: &[NameRegistration],
) -> bool {
    measure(
        collector,
        "registry-register",
        0,
        virtual_client.client.register(batch),
    )
    .await
    .is_some()
}

async fn drain_if_full<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    collector: &mut Collector,
    targets: &mut Vec<String>,
) {
    if targets.len() >= plan.batch_size as usize * RETIRE_DRAIN_BATCHES {
        retire(virtual_client, plan, collector, std::mem::take(targets)).await;
    }
}

/// Retire what the run registered, in batches the registry accepts.
async fn retire<H: Http>(
    virtual_client: &VirtualClient<H>,
    plan: &RunPlan,
    collector: &mut Collector,
    targets: Vec<String>,
) {
    for chunk in targets.chunks(plan.batch_size as usize) {
        measure(
            collector,
            "registry-retire",
            0,
            virtual_client.client.retire(chunk),
        )
        .await;
        pace(plan).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_engine::seams::HttpMethod;

    use crate::plan::Target;
    use crate::runner::provision;
    use crate::stub_http::StubHttp;

    fn plan(scenario: Scenario, ops_per_client: u32, batch_size: u32) -> RunPlan {
        RunPlan {
            scenario,
            target: Target::Local,
            api_url: "http://localhost:3000".to_owned(),
            gateway_url: Some("http://localhost:8080".to_owned()),
            gateway_token: None,
            test_login_secret: "stub-secret".to_owned(),
            clients: 1,
            ops_per_client,
            block_bytes: 128,
            batch_size,
            pace_ms: 0,
            ramp_ms: 0,
            report_dir: String::new(),
        }
    }

    /// Drive one scenario over `http`, returning the samples it filed. The
    /// client is minted through the harness's own `provision`, and its traffic
    /// dropped, so the recording is the scenario's own call sequence.
    fn drive_over(plan: &RunPlan, http: &StubHttp) -> Collector {
        let mut collector = Collector::default();
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
            .block_on(async {
                let mut clients = provision(plan, http, "stub", &mut Collector::default()).await;
                let virtual_client = clients.pop().expect("the stub authenticates one client");
                http.clear_calls();
                drive(&virtual_client, plan, http, &mut collector).await;
            });
        collector
    }

    fn drive_against_stub(plan: &RunPlan) -> StubHttp {
        let http = StubHttp::default();
        drive_over(plan, &http);
        http
    }

    /// The content addresses a run uploaded, recomputed from the bytes it sent.
    fn uploaded_cids(http: &StubHttp) -> Vec<String> {
        http.bodies_for("/content/upload")
            .iter()
            .map(|block| leaf_cid(block))
            .collect()
    }

    fn sorted(mut values: Vec<String>) -> Vec<String> {
        values.sort();
        values
    }

    /// A scenario must outlive nothing it registered: every target it created
    /// comes back in a retire body before it returns.
    fn assert_retires(http: &StubHttp, expected: Vec<String>) {
        assert_eq!(sorted(http.retired()), sorted(expected));
    }

    /// The `(method, path)` shape of the run, in send order.
    fn shape(http: &StubHttp) -> Vec<(HttpMethod, String)> {
        http.calls()
            .into_iter()
            .map(|call| (call.method, call.path))
            .collect()
    }

    fn posts(paths: &[&str]) -> Vec<(HttpMethod, String)> {
        paths
            .iter()
            .map(|path| (HttpMethod::Post, (*path).to_owned()))
            .collect()
    }

    #[test]
    fn content_ingest_uploads_then_retires_every_block_it_pinned() {
        let http = drive_against_stub(&plan(Scenario::ContentIngest, 3, 8));

        assert_eq!(
            shape(&http),
            posts(&[
                "/content/upload",
                "/content/upload",
                "/content/upload",
                "/registry/retire",
            ])
        );
        assert_retires(&http, uploaded_cids(&http));
    }

    #[test]
    fn gateway_read_seeds_blocks_reads_them_back_and_retires_the_seed() {
        let http = drive_against_stub(&plan(Scenario::GatewayRead, 2, 8));

        let paths = http.paths();
        assert_eq!(&paths[..2], ["/content/upload", "/content/upload"]);
        assert!(
            paths[2..4].iter().all(|path| path.starts_with("/ipfs/")),
            "{paths:?}"
        );
        assert_eq!(paths[4], "/registry/retire");
        assert_retires(&http, uploaded_cids(&http));
    }

    #[test]
    fn a_name_wave_retires_every_name_it_registered() {
        let http = drive_against_stub(&plan(Scenario::NameWave, 2, 3));

        assert_eq!(
            shape(&http),
            posts(&[
                "/registry/register",
                "/registry/register",
                "/registry/retire",
                "/registry/retire",
            ])
        );
        assert_eq!(http.registered_names().len(), 6);
        assert_retires(&http, http.registered_targets());
    }

    // The drain keeps a long wave's memory on the batch size rather than the
    // run length; it must retire what it drops, not leak it.
    #[test]
    fn the_drain_path_retires_mid_run_and_still_leaves_nothing_behind() {
        let http = drive_against_stub(&plan(Scenario::NameWave, 5, 1));

        let paths = http.paths();
        let first_retire = paths
            .iter()
            .position(|path| path == "/registry/retire")
            .expect("the drain retired mid-run");
        let last_register = paths
            .iter()
            .rposition(|path| path == "/registry/register")
            .expect("registered");
        assert!(first_retire < last_register, "{paths:?}");

        assert_eq!(http.registered_names().len(), 5);
        assert_retires(&http, http.registered_targets());
    }

    #[test]
    fn the_mixed_profile_interleaves_ingest_registry_quota_and_a_mailbox_round_trip() {
        let http = drive_against_stub(&plan(Scenario::Mixed, 1, 8));

        assert_eq!(
            shape(&http),
            [
                (HttpMethod::Post, "/content/upload".to_owned()),
                (HttpMethod::Post, "/registry/register".to_owned()),
                (HttpMethod::Get, "/account/quota".to_owned()),
                (HttpMethod::Post, "/mailbox/messages".to_owned()),
                (HttpMethod::Get, "/mailbox/messages".to_owned()),
                // The ack can only name the id the post came back with.
                (HttpMethod::Delete, "/mailbox/messages/msg-1".to_owned()),
                (HttpMethod::Post, "/registry/retire".to_owned()),
            ]
        );

        // The block it ingested is the CID it registered, so retiring the
        // registration's targets retires the pin it created.
        assert!(http.registered_targets().contains(&uploaded_cids(&http)[0]));
        assert_retires(&http, http.registered_targets());
    }

    #[test]
    fn byo_advisory_flips_the_account_then_retires_its_advisory_rows() {
        let http = drive_against_stub(&plan(Scenario::ByoAdvisory, 1, 2));

        assert_eq!(
            shape(&http),
            [
                (HttpMethod::Patch, "/account/byo".to_owned()),
                (HttpMethod::Post, "/registry/register".to_owned()),
                (HttpMethod::Get, "/account/quota".to_owned()),
                (HttpMethod::Post, "/registry/retire".to_owned()),
                (HttpMethod::Post, "/registry/retire".to_owned()),
            ]
        );

        // A BYO account's bytes never reach the ingress — it registers advisory
        // pin rows only, and owes every one of them back.
        assert!(http.bodies_for("/content/upload").is_empty());
        assert_eq!(http.registered_names().len(), 2);
        assert_retires(&http, http.registered_targets());
    }

    // A 429 is the API keeping its throttling promise, so it must file apart
    // from a genuine failure end to end, not just at the sample level.
    #[test]
    fn a_throttled_upload_is_filed_as_throttled_and_leaves_nothing_to_retire() {
        let http = StubHttp::default();
        http.throttle("/content/upload");
        let collector = drive_over(&plan(Scenario::ContentIngest, 2, 8), &http);

        let upload = collector
            .summarize(1_000.0)
            .into_iter()
            .find(|summary| summary.op == "content-upload")
            .expect("the upload op was measured");
        assert_eq!((upload.ok, upload.throttled, upload.failed), (0, 2, 0));
        assert!(
            !http.paths().iter().any(|path| path == "/registry/retire"),
            "a throttled upload pinned nothing, so there is nothing to retire"
        );
    }
}
