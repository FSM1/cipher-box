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
        return Ok(0);
    }

    current_sequence
        .map(|seq| seq + 1)
        .ok_or_else(|| "Missing current sequence for existing file IPNS record".to_string())
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
pub(crate) fn classify_resolve_outcome(result: Result<u64, String>) -> crate::error::IpnsResolveOutcome {
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
        match cipherbox_api_client::ipns::resolve_ipns(api, ipns_name).await {
            Ok(resp) => {
                let resolved = resp.sequence_number.parse::<u64>().unwrap_or_else(|e| {
                    log::warn!(
                        "Failed to parse IPNS sequence '{}' for {}: {}",
                        resp.sequence_number,
                        ipns_name,
                        e
                    );
                    0
                });
                let cached = self.get_cached(ipns_name).unwrap_or(0);
                let seq = std::cmp::max(resolved, cached);
                self.update_cache(ipns_name, seq);
                Ok(seq)
            }
            Err(e) => match self.get_cached(ipns_name) {
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
            },
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
        let resp = cipherbox_api_client::ipns::resolve_ipns(api, ipns_name)
            .await
            .map_err(|e| format!("IPNS resolve failed for {}: {}", ipns_name, e))?;
        let resolved = resp.sequence_number.parse::<u64>().map_err(|e| {
            format!(
                "Invalid IPNS sequence '{}' for {}: {}",
                resp.sequence_number, ipns_name, e
            )
        })?;
        let cached = self.get_cached(ipns_name).unwrap_or(0);
        let seq = std::cmp::max(resolved, cached);
        self.update_cache(ipns_name, seq);
        Ok(seq)
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
    fn next_file_publish_sequence_starts_new_records_at_zero() {
        assert_eq!(next_file_publish_sequence(true, None).unwrap(), 0);
        assert_eq!(next_file_publish_sequence(true, Some(99)).unwrap(), 0);
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
