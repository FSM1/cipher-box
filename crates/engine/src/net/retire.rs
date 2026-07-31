//! Retirement (blueprint/engine.md "Resolve/publish pipeline: Retirement",
//! #34 D4).
//!
//! Retire = remove my registry rows; the timing is engine policy. Interior old
//! names batch-retire at name-wave completion (immediate, [`retire`]); the old
//! scope-root name lingers serving the tombstone until the migration window
//! closes ([`root_retire_ready`], stubbed — see below).

use crate::api::{ApiClient, ApiError};
use crate::seams::{CredentialStore, Http};

/// The server's retire batch cap, which refuses a larger array fail-closed
/// (blueprint/api.md "Batch bounds").
const RETIRE_BATCH_MAX: usize = 1000;

/// Batch-retire registry rows for `targets` (`ipnsName`s or CIDs). Idempotent
/// server-side (blueprint/api.md), so a replayed batch — a resumed name wave, or
/// a chunk a failed pass already sent — is a no-op, never an error. This is the
/// interior-name path: it retires the moment the caller says a name is dead.
///
/// Chunked to [`RETIRE_BATCH_MAX`]; a failing chunk leaves the earlier ones
/// retired and returns `Err`.
pub async fn retire<H, C>(api: &ApiClient<H, C>, targets: &[String]) -> Result<(), ApiError>
where
    H: Http,
    C: CredentialStore,
{
    for chunk in targets.chunks(RETIRE_BATCH_MAX) {
        api.retire(chunk).await?;
    }
    Ok(())
}

/// Whether the old scope-root name may be retired yet. **Stubbed to `false`**:
/// the migration window that bounds how long the old root lingers serving the
/// tombstone is an open edge (blueprint/engine.md "Open edges: Migration-window
/// closure"; #38 fixed the channel architecture but not the window). Until it
/// lands the root never auto-retires, so a revokee or a lagging reader can
/// always chase the tombstone to the new root.
pub fn root_retire_ready() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::{HttpMethod, HttpResponse};
    use crate::testkit::block_on;
    use crate::testkit::fakes::{InMemoryCredentialStore, ScriptedHttp};

    fn client() -> (
        ScriptedHttp,
        ApiClient<ScriptedHttp, InMemoryCredentialStore>,
    ) {
        let http = ScriptedHttp::default();
        let client = ApiClient::new(
            http.clone(),
            InMemoryCredentialStore::default(),
            "http://api.test",
        );
        (http, client)
    }

    #[test]
    fn empty_retire_is_a_no_op_with_no_request() {
        let (http, client) = client();
        block_on(retire(&client, &[])).expect("empty retire");
        assert!(http.requests().is_empty(), "no targets means no API call");
    }

    #[test]
    fn retire_posts_the_batch_to_the_registry() {
        let (http, client) = client();
        http.enqueue_response(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        });
        block_on(retire(&client, &["k51interior".to_owned()])).expect("retire");
        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert!(requests[0].url.ends_with("/registry/retire"));
    }

    #[test]
    fn an_oversize_batch_splits_into_chunks_the_server_accepts() {
        let (http, client) = client();
        let targets: Vec<String> = (0..RETIRE_BATCH_MAX + 1)
            .map(|i| format!("cid{i}"))
            .collect();
        for _ in 0..2 {
            http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        block_on(retire(&client, &targets)).expect("retire");

        let requests = http.requests();
        assert_eq!(requests.len(), 2, "the batch splits at the server's cap");
        let sent: Vec<String> = requests
            .iter()
            .flat_map(|request| {
                let body = request.body.as_deref().expect("a retire call has a body");
                serde_json::from_slice::<Vec<String>>(body).expect("a retire body is a JSON array")
            })
            .collect();
        assert_eq!(
            sent, targets,
            "every target still reaches the registry once"
        );
    }

    #[test]
    fn root_never_auto_retires_pending_the_migration_window() {
        assert!(
            !root_retire_ready(),
            "the old root lingers until the migration-window constant lands"
        );
    }
}
