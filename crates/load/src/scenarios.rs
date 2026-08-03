//! The five scenarios, each aimed at one v2 API surface. Sustained and spike
//! profiles are `--ops-per-client` and `--ramp-ms` on these, not scenarios of
//! their own (crates/load/README.md).

use cipherbox_desktop_seams::ReqwestHttp;
use cipherbox_engine::api::NameRegistration;

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

pub(crate) async fn drive(
    virtual_client: &VirtualClient,
    plan: &RunPlan,
    http: &ReqwestHttp,
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
async fn upload_block(
    virtual_client: &VirtualClient,
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
async fn content_ingest(virtual_client: &VirtualClient, plan: &RunPlan, collector: &mut Collector) {
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
async fn gateway_read(
    virtual_client: &VirtualClient,
    plan: &RunPlan,
    http: &ReqwestHttp,
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
async fn name_wave(virtual_client: &VirtualClient, plan: &RunPlan, collector: &mut Collector) {
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
async fn mixed(virtual_client: &VirtualClient, plan: &RunPlan, collector: &mut Collector) {
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
async fn byo_advisory(virtual_client: &VirtualClient, plan: &RunPlan, collector: &mut Collector) {
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

async fn register(
    virtual_client: &VirtualClient,
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

async fn drain_if_full(
    virtual_client: &VirtualClient,
    plan: &RunPlan,
    collector: &mut Collector,
    targets: &mut Vec<String>,
) {
    if targets.len() >= plan.batch_size as usize * RETIRE_DRAIN_BATCHES {
        retire(virtual_client, plan, collector, std::mem::take(targets)).await;
    }
}

/// Retire what the run registered, in batches the registry accepts.
async fn retire(
    virtual_client: &VirtualClient,
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
