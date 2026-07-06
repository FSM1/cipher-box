//! IPNS publish coordination: queue entries, sequence tracking, and replay helpers.

use std::collections::HashMap;
use std::sync::Arc;

/// Entry in the debounced publish queue.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct PublishQueueEntry {
    pub first_dirty: std::time::Instant,
    pub pending_uploads: usize,
}

pub fn next_file_publish_sequence(
    is_first_publish: bool,
    current_sequence: Option<u64>,
) -> Result<u64, String> {
    if is_first_publish {
        return Ok(1);
    }

    current_sequence
        .ok_or_else(|| "Missing current sequence for existing file IPNS record".to_string())
        .and_then(|seq| {
            seq.checked_add(1)
                .ok_or_else(|| "IPNS sequence number overflow".to_string())
        })
}

/// Classifies an IPNS resolve result into a typed [`crate::error::IpnsResolveOutcome`].
///
/// Wraps [`PublishCoordinator::resolve_sequence`] and maps:
/// - `Ok(seq)` → `Found(seq)`
/// - `Err(e)` where `e` signals 404 / "not found" → `NotFound`
/// - `Err(e)` otherwise → `Error(e)` (non-404; entry should be retained)
///
/// Centralises the brittle substring match (#19) so `replay_upload_entry` matches
/// on the typed enum rather than calling `.to_lowercase().contains("not found")` inline.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) async fn resolve_ipns_for_replay(
    coordinator: &PublishCoordinator,
    api: &cipherbox_api_client::ApiClient,
    ipns_name: &str,
) -> crate::error::IpnsResolveOutcome {
    classify_resolve_outcome(coordinator.resolve_sequence_strict(api, ipns_name).await)
}

/// Pure classification of a `resolve_sequence` result into an [`crate::error::IpnsResolveOutcome`].
///
/// Split out from [`resolve_ipns_for_replay`] so the brittle "not found" / "404"
/// substring contract (#19) is unit-testable without a live API client:
/// - `Ok(seq)` → `Found(seq)`
/// - `Err(e)` whose text signals 404 / "not found" → `NotFound`
/// - any other `Err(e)` → `Error(e)` (entry retained on replay)
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) fn classify_resolve_outcome(
    result: Result<u64, String>,
) -> crate::error::IpnsResolveOutcome {
    use crate::error::IpnsResolveOutcome;
    match result {
        Ok(seq) => IpnsResolveOutcome::Found(seq),
        Err(e) if e.to_lowercase().contains("not found") || e.contains("404") => {
            IpnsResolveOutcome::NotFound
        }
        Err(e) => IpnsResolveOutcome::Error(e),
    }
}

/// Coordinates IPNS publish operations to prevent sequence number races.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct PublishCoordinator {
    seq_cache: std::sync::Mutex<HashMap<String, u64>>,
    publish_locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl PublishCoordinator {
    pub fn new() -> Self {
        Self {
            seq_cache: std::sync::Mutex::new(HashMap::new()),
            publish_locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn get_lock(&self, ipns_name: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.publish_locks.lock().unwrap();
        locks
            .entry(ipns_name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub async fn resolve_sequence(
        &self,
        api: &cipherbox_api_client::ApiClient,
        ipns_name: &str,
    ) -> Result<u64, String> {
        // D-01: route through the verified chokepoint.
        match cipherbox_api_client::ipns::resolve_ipns_verified(api, ipns_name).await {
            // sc6-allow: replay-path resolve (resolve_ipns_for_replay), not a node/v3 read
            Ok(verified) => {
                // D-08: use sequence from signed CBOR data.
                let resolved = verified.sequence_number;
                let cached = self.get_cached(ipns_name).unwrap_or(0);
                let seq = std::cmp::max(resolved, cached);
                self.update_cache(ipns_name, seq);
                Ok(seq)
            }
            // D-04: Legacy variant removed — all-absent sig fields fail closed (strict cutover).
            // Callers fall through to the Invalid arm.
            Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
                // D-02: verify failure on soft resolve — fall back to cache (never wedge).
                log::warn!(
                    "resolve_sequence: IPNS {} verify failed: {} — falling back to cache (D-02)",
                    ipns_name,
                    msg
                );
                match self.get_cached(ipns_name) {
                    Some(cached) => Ok(cached),
                    None => Err(format!(
                        "IPNS verify failed and no cached sequence for {}: {}",
                        ipns_name, msg
                    )),
                }
            }
            Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
                match self.get_cached(ipns_name) {
                    Some(cached) => {
                        log::warn!(
                            "IPNS resolve failed for {}, using cached seq {}: {}",
                            ipns_name,
                            cached,
                            e
                        );
                        Ok(cached)
                    }
                    None => Err(format!(
                        "IPNS resolve failed and no cached sequence for {}: {}",
                        ipns_name, e
                    )),
                }
            }
        }
    }

    /// Strict resolve for replay classification: returns Err on ANY resolve failure,
    /// never falling back to the cache. A genuine success still updates+returns the
    /// max(resolved, cached) sequence so a subsequent confirmed publish advances correctly.
    pub async fn resolve_sequence_strict(
        &self,
        api: &cipherbox_api_client::ApiClient,
        ipns_name: &str,
    ) -> Result<u64, String> {
        // D-01: route through the verified chokepoint.
        match cipherbox_api_client::ipns::resolve_ipns_verified(api, ipns_name).await {
            // sc6-allow: replay-path resolve (resolve_ipns_for_replay), not a node/v3 read
            Ok(verified) => {
                // D-08: use sequence from signed CBOR data.
                let cached = self.get_cached(ipns_name).unwrap_or(0);
                let seq = std::cmp::max(verified.sequence_number, cached);
                self.update_cache(ipns_name, seq);
                Ok(seq)
            }
            // D-04: Legacy variant removed — all-absent sig fields fail closed (strict cutover).
            Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
                // Strict: verify failure → Err.
                Err(format!("IPNS {} verify failed: {}", ipns_name, msg))
            }
            Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
                Err(format!("IPNS resolve failed for {}: {}", ipns_name, e))
            }
        }
    }

    pub fn record_publish(&self, ipns_name: &str, published_seq: u64) {
        self.update_cache(ipns_name, published_seq);
    }

    fn get_cached(&self, ipns_name: &str) -> Option<u64> {
        self.seq_cache.lock().unwrap().get(ipns_name).copied()
    }

    fn update_cache(&self, ipns_name: &str, seq: u64) {
        let mut cache = self.seq_cache.lock().unwrap();
        let entry = cache.entry(ipns_name.to_string()).or_insert(0);
        if seq > *entry {
            *entry = seq;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::next_file_publish_sequence;

    #[test]
    fn next_file_publish_sequence_starts_new_records_at_one() {
        // First-publish embeds sequence 1 (matching the TS SDK `file/index.ts` which embeds 1n
        // and the API comment at ipns.service.ts:357 that assumes clients compute 0+1=1).
        assert_eq!(next_file_publish_sequence(true, None).unwrap(), 1);
        assert_eq!(next_file_publish_sequence(true, Some(99)).unwrap(), 1);
    }

    #[test]
    fn next_file_publish_sequence_increments_existing_records() {
        assert_eq!(next_file_publish_sequence(false, Some(0)).unwrap(), 1);
        assert_eq!(next_file_publish_sequence(false, Some(7)).unwrap(), 8);
    }

    #[test]
    fn next_file_publish_sequence_rejects_missing_existing_sequence() {
        assert!(next_file_publish_sequence(false, None).is_err());
    }

    #[test]
    fn next_file_publish_sequence_normal_increment_unchanged() {
        assert_eq!(next_file_publish_sequence(false, Some(5)).unwrap(), 6);
    }

    #[test]
    fn next_file_publish_sequence_overflow_returns_err() {
        let result = next_file_publish_sequence(false, Some(u64::MAX));
        assert!(result.is_err(), "expected Err on u64::MAX overflow, got Ok");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("overflow"),
            "error message must contain 'overflow', got: {msg:?}"
        );
    }

    #[test]
    fn next_file_publish_sequence_missing_sequence_error_preserved() {
        let result = next_file_publish_sequence(false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing current sequence"));
    }

    // T-45-05b: classify_resolve_outcome pins the #19 substring contract directly
    // (the not-found / 404 classification that drives first-publish vs retain),
    // exercising the predicate without a live API client.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[test]
    fn classify_resolve_outcome_maps_resolve_results() {
        use super::classify_resolve_outcome;
        use crate::error::IpnsResolveOutcome;

        // Successful resolve -> Found(seq)
        assert!(matches!(
            classify_resolve_outcome(Ok(7)),
            IpnsResolveOutcome::Found(7)
        ));

        // not-found / 404 signals (case-insensitive) -> NotFound (drives first publish)
        for msg in [
            "record not found",
            "IPNS NOT FOUND",
            "HTTP 404 Not Found",
            "server returned 404",
        ] {
            assert!(
                matches!(
                    classify_resolve_outcome(Err(msg.to_string())),
                    IpnsResolveOutcome::NotFound
                ),
                "{msg:?} must classify as NotFound"
            );
        }

        // transient / other errors -> Error (entry retained, NOT a first publish)
        for msg in ["connection timeout", "500 internal server error"] {
            assert!(
                matches!(
                    classify_resolve_outcome(Err(msg.to_string())),
                    IpnsResolveOutcome::Error(_)
                ),
                "{msg:?} must classify as Error"
            );
        }
    }
}
