//! Virtual clients and the run loop.
//!
//! `ApiClient` holds its session in a `RefCell`, so it is `!Sync` and its
//! futures are `!Send`: virtual clients run as `spawn_local` tasks on one
//! current-thread runtime, each owning its own client and session.

use std::future::Future;
use std::time::{Duration, Instant};

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_engine::api::{ApiClient, ApiError};

use crate::metrics::{Collector, Outcome, Sample};
use crate::plan::RunPlan;
use crate::scenarios;
use crate::seams::{LoadHttp, MemoryCredentialStore};

pub type Client = ApiClient<LoadHttp, MemoryCredentialStore>;

/// One authenticated account driving load.
pub struct VirtualClient {
    pub index: u32,
    pub client: Client,
    /// The account's identity `publicKey` — its own mailbox address.
    pub public_key: String,
}

/// The HTTP status an error carries, where the client kept one.
pub fn status_of(error: &ApiError) -> Option<u16> {
    match error {
        ApiError::Status { status, .. } => Some(*status),
        ApiError::Unauthorized => Some(401),
        ApiError::Forbidden => Some(403),
        _ => None,
    }
}

/// Time one operation and file it under `op`. Returns `None` on any failure so
/// a scenario can skip the rest of an iteration without unwinding the run.
pub async fn measure<T>(
    collector: &mut Collector,
    op: &'static str,
    bytes: u64,
    call: impl Future<Output = Result<T, ApiError>>,
) -> Option<T> {
    let started = Instant::now();
    let result = call.await;
    let latency_ms = started.elapsed().as_secs_f64() * 1_000.0;
    match result {
        Ok(value) => {
            collector.record(Sample::new(op, Outcome::Ok, latency_ms).with_bytes(bytes));
            Some(value)
        }
        Err(error) => {
            let outcome = if status_of(&error) == Some(429) {
                Outcome::Throttled
            } else {
                Outcome::Failed
            };
            collector.record(Sample::new(op, outcome, latency_ms).with_detail(error.to_string()));
            None
        }
    }
}

/// Time one direct HTTP call — the read accelerator, which is not on the API
/// client — and file it under `op`.
pub async fn measure_http(
    collector: &mut Collector,
    op: &'static str,
    call: impl Future<Output = Result<(u16, Vec<u8>), String>>,
) -> Option<Vec<u8>> {
    let started = Instant::now();
    let result = call.await;
    let latency_ms = started.elapsed().as_secs_f64() * 1_000.0;
    match result {
        Ok((status, body)) if (200..300).contains(&status) => {
            let bytes = body.len() as u64;
            collector.record(Sample::new(op, Outcome::Ok, latency_ms).with_bytes(bytes));
            Some(body)
        }
        Ok((status, _)) => {
            let outcome = if status == 429 {
                Outcome::Throttled
            } else {
                Outcome::Failed
            };
            collector.record(
                Sample::new(op, outcome, latency_ms).with_detail(format!("status {status}")),
            );
            None
        }
        Err(detail) => {
            collector.record(Sample::new(op, Outcome::Failed, latency_ms).with_detail(detail));
            None
        }
    }
}

pub async fn pace(plan: &RunPlan) {
    if plan.pace_ms > 0 {
        tokio::time::sleep(Duration::from_millis(plan.pace_ms)).await;
    }
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out).expect("os rng");
    out
}

const BASE36: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// A random lowercase-alphanumeric token — the shape the registry's
/// `CID_OR_NAME` guard accepts.
pub fn random_token(len: usize) -> String {
    random_bytes(len)
        .into_iter()
        .map(|byte| BASE36[usize::from(byte) % BASE36.len()] as char)
        .collect()
}

/// A synthetic name for the inventory. It never resolves — the registry is
/// zero-knowledge about the encoding and only guards column width — and the run
/// retires every name it registers.
pub fn synthetic_ipns_name() -> String {
    format!("k51{}", random_token(59))
}

/// The engine's content address for a sealed leaf: the `raw` codec core fixes
/// for content blocks.
pub fn leaf_cid(bytes: &[u8]) -> String {
    encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, bytes))
}

/// Mint `count` accounts through test-login. Handles carry a per-run token so a
/// crashed run never leaves a later one sharing its accounts and quota.
async fn provision(
    plan: &RunPlan,
    http: &LoadHttp,
    run_id: &str,
    collector: &mut Collector,
) -> Vec<VirtualClient> {
    let mut clients = Vec::new();
    for index in 0..plan.clients {
        let client = ApiClient::new(
            http.clone(),
            MemoryCredentialStore::default(),
            plan.api_url.clone(),
        );
        let handle = format!("load-{}-{run_id}-{index}", plan.scenario.as_str());
        let outcome = measure(
            collector,
            "auth-test-login",
            0,
            client.test_login(&handle, &plan.test_login_secret),
        )
        .await;
        if let Some(outcome) = outcome {
            clients.push(VirtualClient {
                index,
                client,
                public_key: outcome.public_key,
            });
        }
    }
    clients
}

async fn teardown(clients: Vec<VirtualClient>, collector: &mut Collector) {
    for virtual_client in clients {
        measure(
            collector,
            "account-delete",
            0,
            virtual_client.client.delete_account(),
        )
        .await;
    }
}

/// Run the plan and return every sample it produced plus the wall-clock time
/// the whole run took. Provisioning and teardown sit inside that window: they
/// are API surface the run exercised, so throughput is the honest whole-run
/// rate rather than a load-phase rate divided by a shorter clock.
pub async fn run(plan: &RunPlan) -> Result<(Collector, f64), String> {
    let http = LoadHttp::new()?;
    let run_id = random_token(6);
    let mut collector = Collector::default();
    let started = Instant::now();

    let clients = provision(plan, &http, &run_id, &mut collector).await;
    if clients.is_empty() {
        return Err(format!(
            "no virtual client could authenticate against {}: {}",
            plan.api_url,
            collector.first_failure().unwrap_or("no detail")
        ));
    }
    println!(
        "provisioned {}/{} accounts against {}",
        clients.len(),
        plan.clients,
        plan.api_url
    );

    let mut tasks = Vec::new();
    for virtual_client in clients {
        let plan = plan.clone();
        let http = http.clone();
        tasks.push(tokio::task::spawn_local(async move {
            if plan.ramp_ms > 0 {
                tokio::time::sleep(Duration::from_millis(
                    plan.ramp_ms * u64::from(virtual_client.index),
                ))
                .await;
            }
            let mut collector = Collector::default();
            scenarios::drive(&virtual_client, &plan, &http, &mut collector).await;
            (virtual_client, collector)
        }));
    }

    let mut clients = Vec::new();
    for task in tasks {
        let (virtual_client, samples) = task.await.map_err(|error| error.to_string())?;
        collector.absorb(samples);
        clients.push(virtual_client);
    }

    teardown(clients, &mut collector).await;
    Ok((collector, started.elapsed().as_secs_f64() * 1_000.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::content::decode_content_cid_str;
    use cipherbox_engine::seams::SeamError;

    #[test]
    fn a_synthetic_name_satisfies_the_registry_name_guard() {
        let name = synthetic_ipns_name();
        assert!(name.len() <= 128);
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric()), "{name}");
    }

    #[test]
    fn synthetic_names_do_not_repeat() {
        let first = synthetic_ipns_name();
        assert_ne!(first, synthetic_ipns_name());
    }

    #[test]
    fn a_leaf_cid_decodes_under_the_raw_content_codec() {
        let decoded = decode_content_cid_str(&leaf_cid(b"load block")).expect("decode");
        assert_eq!(decoded[1], CONTENT_CID_CODEC);
    }

    #[test]
    fn a_leaf_cid_is_a_bare_alphanumeric_token() {
        let cid = leaf_cid(&random_bytes(1024));
        assert!(cid.chars().all(|c| c.is_ascii_alphanumeric()), "{cid}");
        assert!(cid.len() <= 256);
    }

    #[test]
    fn rate_limiting_is_the_only_status_the_run_loop_treats_apart() {
        assert_eq!(
            status_of(&ApiError::Status {
                status: 429,
                message: None,
                code: None
            }),
            Some(429)
        );
        assert_eq!(status_of(&ApiError::Unauthorized), Some(401));
        assert_eq!(status_of(&ApiError::Forbidden), Some(403));
        assert_eq!(
            status_of(&ApiError::Transport(SeamError::new("down"))),
            None
        );
    }

    #[test]
    fn a_throttled_call_is_filed_apart_from_a_failed_one() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut collector = Collector::default();
        runtime.block_on(async {
            let throttled: Result<(), ApiError> = Err(ApiError::Status {
                status: 429,
                message: None,
                code: None,
            });
            measure(&mut collector, "upload", 0, async { throttled }).await;
            let failed: Result<(), ApiError> = Err(ApiError::Status {
                status: 500,
                message: None,
                code: None,
            });
            measure(&mut collector, "upload", 0, async { failed }).await;
            measure(&mut collector, "upload", 32, async {
                Ok::<_, ApiError>(())
            })
            .await;
        });

        let upload = &collector.summarize(1_000.0)[0];
        assert_eq!((upload.ok, upload.throttled, upload.failed), (1, 1, 1));
        assert_eq!(upload.bytes, 32, "only successful bytes are counted");
    }
}
