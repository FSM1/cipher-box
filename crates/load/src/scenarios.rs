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
    use cipherbox_engine::api::ApiClient;
    use cipherbox_engine::seams::HttpMethod;

    use crate::plan::Target;
    use crate::seams::MemoryCredentialStore;
    use crate::stub_http::StubHttp;

    const API_URL: &str = "http://localhost:3000";
    const GATEWAY_URL: &str = "http://localhost:8080";

    fn plan(scenario: Scenario, ops_per_client: u32, batch_size: u32) -> RunPlan {
        RunPlan {
            scenario,
            target: Target::Local,
            api_url: API_URL.to_owned(),
            gateway_url: Some(GATEWAY_URL.to_owned()),
            gateway_token: None,
            test_login_secret: "stub-secret".to_owned(),
            clients: 1,
            ops_per_client,
            block_bytes: 128,
            batch_size,
            // Zero pace keeps the run off the timer wheel, so the stubbed
            // sequence is the whole of what the scenario does.
            pace_ms: 0,
            ramp_ms: 0,
            report_dir: String::new(),
        }
    }

    /// Drive one scenario against a stub API, returning the stub and the
    /// samples the run filed. Provisioning traffic is discarded first, so the
    /// recording is the scenario's own call sequence.
    fn drive_against_stub(
        plan: &RunPlan,
        arrange: impl FnOnce(&StubHttp),
    ) -> (StubHttp, Collector) {
        let http = StubHttp::default();
        let mut collector = Collector::default();
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(async {
                let client =
                    ApiClient::new(http.clone(), MemoryCredentialStore::default(), API_URL);
                let outcome = client
                    .test_login("load-stub", &plan.test_login_secret)
                    .await
                    .expect("the stub authenticates");
                let virtual_client = VirtualClient {
                    client,
                    public_key: outcome.public_key,
                };
                http.take_calls();
                arrange(&http);
                drive(&virtual_client, plan, &http, &mut collector).await;
            });
        (http, collector)
    }

    /// The content addresses a run uploaded, recomputed from the bytes it sent.
    fn uploaded_cids(http: &StubHttp) -> Vec<String> {
        http.calls()
            .iter()
            .filter(|call| call.path == "/content/upload")
            .map(|call| leaf_cid(&call.body))
            .collect()
    }

    /// The names a run registered, read back out of the register bodies.
    fn registered_names(http: &StubHttp) -> Vec<String> {
        http.calls()
            .iter()
            .filter(|call| call.path == "/registry/register")
            .flat_map(|call| {
                serde_json::from_slice::<Vec<serde_json::Value>>(&call.body)
                    .expect("register body is a JSON array")
            })
            .map(|entry| entry["ipnsName"].as_str().expect("ipnsName").to_owned())
            .collect()
    }

    fn sorted(mut values: Vec<String>) -> Vec<String> {
        values.sort();
        values
    }

    #[test]
    fn content_ingest_uploads_then_retires_every_block_it_pinned() {
        let plan = plan(Scenario::ContentIngest, 3, 8);
        let (http, _) = drive_against_stub(&plan, |_| {});

        assert_eq!(
            http.paths(),
            [
                "/content/upload",
                "/content/upload",
                "/content/upload",
                "/registry/retire",
            ]
        );
        assert_eq!(sorted(http.retired()), sorted(uploaded_cids(&http)));
    }

    #[test]
    fn gateway_read_seeds_blocks_reads_them_back_and_retires_the_seed() {
        let plan = plan(Scenario::GatewayRead, 2, 8);
        let (http, _) = drive_against_stub(&plan, |_| {});

        let paths = http.paths();
        assert_eq!(&paths[..2], ["/content/upload", "/content/upload"]);
        assert!(
            paths[2..4].iter().all(|path| path.starts_with("/ipfs/")),
            "{paths:?}"
        );
        assert_eq!(paths[4], "/registry/retire");
        assert_eq!(sorted(http.retired()), sorted(uploaded_cids(&http)));
    }

    #[test]
    fn a_name_wave_retires_every_name_it_registered() {
        let plan = plan(Scenario::NameWave, 2, 3);
        let (http, _) = drive_against_stub(&plan, |_| {});

        assert_eq!(
            http.paths(),
            [
                "/registry/register",
                "/registry/register",
                "/registry/retire",
                "/registry/retire",
            ]
        );
        let registered = registered_names(&http);
        assert_eq!(registered.len(), 6);
        assert_eq!(sorted(http.retired()), sorted(registered));
    }

    // The drain keeps a long wave's memory on the batch size rather than the
    // run length; it must retire what it drops, not leak it.
    #[test]
    fn the_drain_path_retires_mid_run_and_still_leaves_nothing_behind() {
        let plan = plan(Scenario::NameWave, 5, 1);
        let (http, _) = drive_against_stub(&plan, |_| {});

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

        let registered = registered_names(&http);
        assert_eq!(registered.len(), 5);
        assert_eq!(sorted(http.retired()), sorted(registered));
    }

    #[test]
    fn the_mixed_profile_interleaves_ingest_registry_quota_and_a_mailbox_round_trip() {
        let plan = plan(Scenario::Mixed, 1, 8);
        let (http, _) = drive_against_stub(&plan, |_| {});

        let calls = http.calls();
        let shape: Vec<_> = calls
            .iter()
            .map(|call| (call.method, call.path.as_str()))
            .collect();
        assert_eq!(
            shape,
            [
                (HttpMethod::Post, "/content/upload"),
                (HttpMethod::Post, "/registry/register"),
                (HttpMethod::Get, "/account/quota"),
                (HttpMethod::Post, "/mailbox/messages"),
                (HttpMethod::Get, "/mailbox/messages"),
                (HttpMethod::Delete, "/mailbox/messages/msg-1"),
                (HttpMethod::Post, "/registry/retire"),
            ]
        );

        let mut expected = registered_names(&http);
        expected.extend(uploaded_cids(&http));
        assert_eq!(sorted(http.retired()), sorted(expected));
    }

    #[test]
    fn byo_advisory_flips_the_account_then_retires_its_advisory_rows() {
        let plan = plan(Scenario::ByoAdvisory, 1, 2);
        let (http, _) = drive_against_stub(&plan, |_| {});

        let calls = http.calls();
        assert_eq!(calls[0].method, HttpMethod::Patch);
        assert_eq!(calls[0].path, "/account/byo");
        assert_eq!(http.paths()[1..3], ["/registry/register", "/account/quota"]);
        // Two names and their two advisory CIDs, retired in batch-size chunks.
        let registered = registered_names(&http);
        assert_eq!(registered.len(), 2);
        assert_eq!(http.retired().len(), 4);
        assert!(registered.iter().all(|name| http.retired().contains(name)));
    }

    // A 429 is the API keeping its throttling promise, so it must file apart
    // from a genuine failure end to end, not just at the sample level.
    #[test]
    fn a_throttled_upload_is_filed_as_throttled_and_leaves_nothing_to_retire() {
        let plan = plan(Scenario::ContentIngest, 2, 8);
        let (http, collector) = drive_against_stub(&plan, |http| http.throttle("/content/upload"));

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
