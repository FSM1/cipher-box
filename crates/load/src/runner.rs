//! Virtual clients and the run loop.
//!
//! `ApiClient` holds its session in a `RefCell`, so it is `!Sync` and its
//! futures are `!Send`: virtual clients run as `spawn_local` tasks on one
//! current-thread runtime, each owning its own client and session.

use std::future::Future;
use std::time::{Duration, Instant};

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_engine::api::{ApiClient, ApiError};
use cipherbox_engine::seams::{
    Http, HttpCredentials, HttpMethod, HttpRequest, SeamError, bearer_header,
};

use crate::metrics::{Collector, Outcome, Sample};
use crate::plan::{MAX_BLOCK_BYTES, RunPlan};
use crate::scenarios;
use crate::seams::{MemoryCredentialStore, build_http};

pub(crate) type Client<H> = ApiClient<H, MemoryCredentialStore>;

/// One authenticated account driving load. Generic over the transport so a
/// scenario can be driven over a stub seam without a live stack; a run always
/// binds it to the desktop [`ReqwestHttp`].
pub(crate) struct VirtualClient<H: Http> {
    pub(crate) client: Client<H>,
    /// The account's identity `publicKey` — its own mailbox address.
    pub(crate) public_key: String,
}

/// The HTTP status an error carries, where the client kept one.
fn status_of(error: &ApiError) -> Option<u16> {
    match error {
        ApiError::Status { status, .. } => Some(*status),
        ApiError::Unauthorized => Some(401),
        ApiError::Forbidden => Some(403),
        _ => None,
    }
}

/// Rate limiting is the one failure a load run expects: v2 has no throttle
/// bypass, so a 429 is the API keeping its promise, not a defect.
fn outcome_of(error: &ApiError) -> Outcome {
    if status_of(error) == Some(429) {
        Outcome::Throttled
    } else {
        Outcome::Failed
    }
}

/// Time one operation and file it under `op`. Returns `None` on any failure so
/// a scenario can skip the rest of an iteration without unwinding the run.
pub(crate) async fn measure<T>(
    collector: &mut Collector,
    op: &'static str,
    bytes: u64,
    call: impl Future<Output = Result<T, ApiError>>,
) -> Option<T> {
    let started = Instant::now();
    let result = call.await;
    let latency_ms = started.elapsed().as_secs_f64() * 1_000.0;
    collector.record(match &result {
        Ok(_) => Sample::new(op, Outcome::Ok, latency_ms).with_bytes(bytes),
        Err(error) => Sample::new(op, outcome_of(error), latency_ms).with_detail(error.to_string()),
    });
    result.ok()
}

/// Like [`measure`], but the call itself reports how many bytes it moved.
pub(crate) async fn measure_served(
    collector: &mut Collector,
    op: &'static str,
    call: impl Future<Output = Result<u64, ApiError>>,
) -> Option<u64> {
    let started = Instant::now();
    let result = call.await;
    let latency_ms = started.elapsed().as_secs_f64() * 1_000.0;
    collector.record(match &result {
        Ok(bytes) => Sample::new(op, Outcome::Ok, latency_ms).with_bytes(*bytes),
        Err(error) => Sample::new(op, outcome_of(error), latency_ms).with_detail(error.to_string()),
    });
    result.ok()
}

/// Fetch one block off the read accelerator, returning the bytes served. Reads
/// go straight to the gateway: the API process serves no bytes in v2.
pub(crate) async fn gateway_get<H: Http>(
    http: &H,
    url: &str,
    token: Option<&str>,
) -> Result<u64, ApiError> {
    let headers = match token {
        Some(token) => vec![
            bearer_header(token)
                .map_err(|_| ApiError::Transport(SeamError::new("gateway bearer is unusable")))?,
        ],
        None => Vec::new(),
    };
    let request = HttpRequest {
        method: HttpMethod::Get,
        url: url.to_owned(),
        headers,
        body: None,
        credentials: HttpCredentials::Omit,
        timeout_ms: Some(30_000),
    };
    // A block is bounded by the API's own ceiling, so a gateway that answers
    // with something larger is refused rather than buffered.
    let response = http
        .send_capped(request, MAX_BLOCK_BYTES as usize)
        .await
        .map_err(|error| ApiError::Decode(format!("gateway fetch: {error:?}")))?;
    if !(200..300).contains(&response.status) {
        return Err(ApiError::Status {
            status: response.status,
            message: None,
            code: None,
        });
    }
    Ok(response.body.len() as u64)
}

pub(crate) async fn pace(plan: &RunPlan) {
    if plan.pace_ms > 0 {
        tokio::time::sleep(Duration::from_millis(plan.pace_ms)).await;
    }
}

pub(crate) fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out).expect("os rng");
    out
}

const BASE36: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn to_base36(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| BASE36[usize::from(*byte) % BASE36.len()] as char)
        .collect()
}

/// A random lowercase-alphanumeric token — the shape the registry's
/// `CID_OR_NAME` guard accepts.
pub(crate) fn random_token(len: usize) -> String {
    to_base36(&random_bytes(len))
}

/// The suffix length that puts a synthetic name in the shape of a libp2p-key
/// CID while staying inside the registry's 128-character column.
const NAME_SUFFIX_LEN: usize = 59;

/// Synthetic names for the inventory, drawn from one entropy read. They never
/// resolve — the registry is zero-knowledge about the encoding and only guards
/// column width — and a run retires every name it registers.
pub(crate) fn synthetic_ipns_names(count: u32) -> Vec<String> {
    random_bytes(NAME_SUFFIX_LEN * count as usize)
        .chunks(NAME_SUFFIX_LEN)
        .map(|chunk| format!("k51{}", to_base36(chunk)))
        .collect()
}

/// The engine's content address for a sealed leaf: the `raw` codec core fixes
/// for content blocks.
pub(crate) fn leaf_cid(bytes: &[u8]) -> String {
    encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, bytes))
}

/// Mint `count` accounts through test-login. Handles carry a per-run token so a
/// crashed run never leaves a later one sharing its accounts and quota.
async fn provision<H: Http + Clone>(
    plan: &RunPlan,
    http: &H,
    run_id: &str,
    collector: &mut Collector,
) -> Vec<VirtualClient<H>> {
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
                client,
                public_key: outcome.public_key,
            });
        }
    }
    clients
}

async fn teardown<H: Http>(clients: Vec<VirtualClient<H>>, collector: &mut Collector) {
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

/// Run the plan, returning every sample it produced and the wall-clock time the
/// whole run took — provisioning and teardown included, since they are API
/// surface the run exercised.
pub async fn run(plan: &RunPlan) -> Result<(Collector, f64), String> {
    let http = build_http()?;
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
    for (index, virtual_client) in clients.into_iter().enumerate() {
        let plan = plan.clone();
        let http = http.clone();
        tasks.push(tokio::task::spawn_local(async move {
            if plan.ramp_ms > 0 {
                tokio::time::sleep(Duration::from_millis(plan.ramp_ms * index as u64)).await;
            }
            let mut collector = Collector::default();
            scenarios::drive(&virtual_client, &plan, &http, &mut collector).await;
            (virtual_client, collector)
        }));
    }

    // A virtual client that panics must not skip teardown, or the run strands
    // its provisioned accounts and their quota on a shared target. Record the
    // join failure, tear down every client that came back, then report.
    let mut clients = Vec::new();
    let mut join_error = None;
    for task in tasks {
        match task.await {
            Ok((virtual_client, samples)) => {
                collector.absorb(samples);
                clients.push(virtual_client);
            }
            Err(error) => {
                join_error.get_or_insert_with(|| error.to_string());
            }
        }
    }

    teardown(clients, &mut collector).await;
    if let Some(error) = join_error {
        return Err(format!("a virtual client did not finish: {error}"));
    }
    Ok((collector, started.elapsed().as_secs_f64() * 1_000.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::content::decode_content_cid_str;
    use cipherbox_engine::seams::SeamError;

    #[test]
    fn synthetic_names_satisfy_the_registry_name_guard_and_do_not_repeat() {
        let names = synthetic_ipns_names(8);
        assert_eq!(names.len(), 8);
        for name in &names {
            assert!(name.len() <= 128);
            assert!(name.chars().all(|c| c.is_ascii_alphanumeric()), "{name}");
        }
        assert_ne!(names[0], names[1]);
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
