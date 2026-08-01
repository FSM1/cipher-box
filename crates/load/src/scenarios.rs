//! The five scenarios, each aimed at one v2 API surface.
//!
//! v1's `upload-throughput`, `ipns-publish-storm`, `mixed-workload`,
//! `sustained-load`, `spike-test` and the `byo-*` family do not map across
//! one-for-one: v2 moved publish/resolve off the API entirely (clients PUT
//! `/routing/v1` themselves) and reads off the API process onto the read
//! accelerator. What ports is the shape of the load — bulk name registration,
//! block ingest, block reads, an interleaved mix, and a BYO account's advisory
//! rows. Sustained and spike runs are `--ops-per-client` and `--ramp-ms` on
//! those scenarios rather than scenarios of their own.

use cipherbox_engine::api::NameRegistration;

use crate::metrics::Collector;
use crate::plan::{RunPlan, Scenario};
use crate::runner::{
    VirtualClient, leaf_cid, measure, measure_http, pace, random_bytes, random_token,
    synthetic_ipns_name,
};
use crate::seams::LoadHttp;

pub async fn drive(
    virtual_client: &VirtualClient,
    plan: &RunPlan,
    http: &LoadHttp,
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

/// Hosted content ingress: one request, one caller-addressed block.
async fn content_ingest(virtual_client: &VirtualClient, plan: &RunPlan, collector: &mut Collector) {
    let mut pinned = Vec::new();
    for _ in 0..plan.ops_per_client {
        let block = random_bytes(plan.block_bytes as usize);
        let cid = leaf_cid(&block);
        let uploaded = measure(
            collector,
            "content-upload",
            u64::from(plan.block_bytes),
            virtual_client.client.upload(&cid, &block),
        )
        .await;
        if uploaded.is_some() {
            pinned.push(cid);
        }
        pace(plan).await;
    }
    retire_all(virtual_client, plan, collector, pinned).await;
}

/// Read-accelerator throughput. The API process serves no bytes in v2, so the
/// read leg goes straight to the trustless gateway.
async fn gateway_read(
    virtual_client: &VirtualClient,
    plan: &RunPlan,
    http: &LoadHttp,
    collector: &mut Collector,
) {
    let Some(gateway) = plan.gateway_url.as_deref() else {
        return;
    };
    let seed_count = plan.ops_per_client.min(4);
    let mut seeded = Vec::new();
    for _ in 0..seed_count {
        let block = random_bytes(plan.block_bytes as usize);
        let cid = leaf_cid(&block);
        if measure(
            collector,
            "content-upload",
            u64::from(plan.block_bytes),
            virtual_client.client.upload(&cid, &block),
        )
        .await
        .is_some()
        {
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
        measure_http(
            collector,
            "gateway-read",
            http.get(&url, plan.gateway_token.as_deref()),
        )
        .await;
        pace(plan).await;
    }
    retire_all(virtual_client, plan, collector, seeded).await;
}

/// Registry cadence under a name wave: bulk registration of freshly derived
/// names, then the sweep that retires them.
async fn name_wave(virtual_client: &VirtualClient, plan: &RunPlan, collector: &mut Collector) {
    let mut names = Vec::new();
    for _ in 0..plan.ops_per_client {
        let batch: Vec<NameRegistration> = (0..plan.batch_size)
            .map(|_| NameRegistration {
                ipns_name: synthetic_ipns_name(),
                head_cid: None,
                content_cids: Vec::new(),
            })
            .collect();
        if measure(
            collector,
            "registry-register",
            0,
            virtual_client.client.register(&batch),
        )
        .await
        .is_some()
        {
            names.extend(batch.into_iter().map(|entry| entry.ipns_name));
        }
        pace(plan).await;
    }
    retire_all(virtual_client, plan, collector, names).await;
}

/// The interleaved profile: ingest, register-first, quota, and a mailbox
/// round-trip on one account.
async fn mixed(virtual_client: &VirtualClient, plan: &RunPlan, collector: &mut Collector) {
    let mut targets = Vec::new();
    for _ in 0..plan.ops_per_client {
        let block = random_bytes(plan.block_bytes as usize);
        let cid = leaf_cid(&block);
        let uploaded = measure(
            collector,
            "content-upload",
            u64::from(plan.block_bytes),
            virtual_client.client.upload(&cid, &block),
        )
        .await;

        if uploaded.is_some() {
            let name = synthetic_ipns_name();
            let batch = [NameRegistration {
                ipns_name: name.clone(),
                head_cid: None,
                content_cids: vec![cid.clone()],
            }];
            if measure(
                collector,
                "registry-register",
                0,
                virtual_client.client.register(&batch),
            )
            .await
            .is_some()
            {
                targets.push(name);
                targets.push(cid);
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
        pace(plan).await;
    }
    retire_all(virtual_client, plan, collector, targets).await;
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
        let batch: Vec<NameRegistration> = (0..plan.batch_size)
            .map(|_| NameRegistration {
                ipns_name: synthetic_ipns_name(),
                head_cid: None,
                content_cids: vec![leaf_cid(&random_bytes(64))],
            })
            .collect();
        if measure(
            collector,
            "registry-register",
            0,
            virtual_client.client.register(&batch),
        )
        .await
        .is_some()
        {
            for entry in batch {
                targets.push(entry.ipns_name);
                targets.extend(entry.content_cids);
            }
        }
        measure(collector, "account-quota", 0, virtual_client.client.quota()).await;
        pace(plan).await;
    }
    retire_all(virtual_client, plan, collector, targets).await;
}

/// Retire everything the run registered, in batches the registry accepts.
async fn retire_all(
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
