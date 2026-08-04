//! The fake `/routing/v1` record store — an in-memory [`RecordTransport`].

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::seams::{EndpointId, RecordTransport, SeamError, SeamResult};

/// Records held by one endpoint, keyed by routing key.
type EndpointRecords = HashMap<String, Vec<u8>>;

/// In-memory fake of the `/routing/v1` endpoint set: one map of opaque
/// record bytes per configured endpoint.
///
/// Shared by design — every engine in a scenario clones the same store, so
/// N instances see one "network". Direct [`seed_record`] /
/// [`record_at`] access lets tests stage adversarial records and observe
/// publishes without a transport round-trip; [`fail_endpoint`] /
/// [`heal_endpoint`] model an endpoint that is transiently unreachable, so the
/// simulation harness can exercise any-ack success and the background re-PUT.
///
/// [`seed_record`]: InMemoryRecordStore::seed_record
/// [`record_at`]: InMemoryRecordStore::record_at
/// [`fail_endpoint`]: InMemoryRecordStore::fail_endpoint
/// [`heal_endpoint`]: InMemoryRecordStore::heal_endpoint
#[derive(Clone)]
pub struct InMemoryRecordStore {
    endpoints: Vec<EndpointId>,
    inner: Arc<Mutex<HashMap<EndpointId, EndpointRecords>>>,
    /// Endpoints currently returning a transport error (unreachable). Empty by
    /// default, so a store's behavior is unchanged until a test injects a fault.
    failing: Arc<Mutex<HashSet<EndpointId>>>,
    /// Endpoints that reject a PUT but still serve GET — models an endpoint that
    /// already holds a strictly-newer record (IPNS higher-sequence-wins) and so
    /// ignores our stale write while still serving the winner. Lets the harness
    /// drive a lost CAS race.
    put_failing: Arc<Mutex<HashSet<EndpointId>>>,
}

impl InMemoryRecordStore {
    /// A store serving the given endpoint set.
    ///
    /// # Panics
    /// Panics on an empty endpoint set — the transport contract requires at
    /// least one endpoint.
    pub fn new(endpoints: Vec<EndpointId>) -> Self {
        assert!(!endpoints.is_empty(), "endpoint set must not be empty");
        let inner = endpoints
            .iter()
            .cloned()
            .map(|endpoint| (endpoint, HashMap::new()))
            .collect();
        Self {
            endpoints,
            inner: Arc::new(Mutex::new(inner)),
            failing: Arc::new(Mutex::new(HashSet::new())),
            put_failing: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Test-side write, bypassing the seam (adversarial staging).
    pub fn seed_record(&self, endpoint: &EndpointId, routing_key: &str, record: Vec<u8>) {
        self.inner
            .lock()
            .expect("lock")
            .get_mut(endpoint)
            .expect("known endpoint")
            .insert(routing_key.to_owned(), record);
    }

    /// Test-side read, bypassing the seam (publish observation).
    pub fn record_at(&self, endpoint: &EndpointId, routing_key: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .expect("lock")
            .get(endpoint)
            .and_then(|records| records.get(routing_key).cloned())
    }

    /// Make `endpoint` return a transport error on every GET/PUT until
    /// [`heal_endpoint`](Self::heal_endpoint) clears it.
    pub fn fail_endpoint(&self, endpoint: &EndpointId) {
        self.failing.lock().expect("lock").insert(endpoint.clone());
    }

    /// Restore `endpoint` to normal operation.
    pub fn heal_endpoint(&self, endpoint: &EndpointId) {
        self.failing.lock().expect("lock").remove(endpoint);
    }

    /// Make `endpoint` reject PUTs while still serving GETs — an endpoint that
    /// already holds a strictly-newer record and ignores our stale write.
    pub fn fail_put_endpoint(&self, endpoint: &EndpointId) {
        self.put_failing
            .lock()
            .expect("lock")
            .insert(endpoint.clone());
    }

    /// Restore `endpoint`'s PUT path.
    pub fn heal_put_endpoint(&self, endpoint: &EndpointId) {
        self.put_failing.lock().expect("lock").remove(endpoint);
    }

    /// Whether `endpoint`'s GET path is currently injected to fail.
    fn get_failing(&self, endpoint: &EndpointId) -> bool {
        self.failing.lock().expect("lock").contains(endpoint)
    }

    /// Whether `endpoint`'s PUT path is currently injected to fail (a full fault
    /// fails PUT too).
    fn put_failing(&self, endpoint: &EndpointId) -> bool {
        self.get_failing(endpoint) || self.put_failing.lock().expect("lock").contains(endpoint)
    }
}

impl RecordTransport for InMemoryRecordStore {
    fn endpoints(&self) -> Vec<EndpointId> {
        self.endpoints.clone()
    }

    async fn get_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        max_bytes: usize,
    ) -> SeamResult<Option<Vec<u8>>> {
        if self.get_failing(endpoint) {
            return Err(SeamError::new(format!(
                "endpoint unreachable: {}",
                endpoint.0
            )));
        }
        let record = self
            .inner
            .lock()
            .expect("lock")
            .get(endpoint)
            .map(|records| records.get(routing_key).cloned())
            .ok_or_else(|| SeamError::new(format!("unknown endpoint: {}", endpoint.0)))?;
        match record {
            Some(bytes) if bytes.len() > max_bytes => Err(SeamError::new(format!(
                "record over cap: {} > {max_bytes}",
                bytes.len()
            ))),
            other => Ok(other),
        }
    }

    async fn put_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        record: &[u8],
    ) -> SeamResult<()> {
        if self.put_failing(endpoint) {
            return Err(SeamError::new(format!(
                "endpoint unreachable: {}",
                endpoint.0
            )));
        }
        self.inner
            .lock()
            .expect("lock")
            .get_mut(endpoint)
            .map(|records| {
                records.insert(routing_key.to_owned(), record.to_vec());
            })
            .ok_or_else(|| SeamError::new(format!("unknown endpoint: {}", endpoint.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;

    #[test]
    fn unknown_endpoint_is_a_seam_error() {
        let store = InMemoryRecordStore::new(vec![EndpointId::new("a")]);
        let missing = EndpointId::new("nope");
        assert!(block_on(store.get_record(&missing, "k", 1024)).is_err());
        assert!(block_on(store.put_record(&missing, "k", b"r")).is_err());
    }

    #[test]
    fn seed_and_inspect_bypass_the_seam() {
        let endpoint = EndpointId::new("a");
        let store = InMemoryRecordStore::new(vec![endpoint.clone()]);
        store.seed_record(&endpoint, "name", b"forged".to_vec());
        assert_eq!(
            block_on(store.get_record(&endpoint, "name", 1024)).unwrap(),
            Some(b"forged".to_vec())
        );
        block_on(store.put_record(&endpoint, "name", b"published")).unwrap();
        assert_eq!(
            store.record_at(&endpoint, "name"),
            Some(b"published".to_vec())
        );
    }
}
