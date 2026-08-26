//! The fake `/routing/v1` record store — an in-memory [`RecordTransport`].

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use cipherbox_core::ipns::{IpnsName, IpnsRecord};

use crate::seams::{EndpointId, RecordTransport, SeamError, SeamResult};

/// Records held by one endpoint, keyed by routing key.
type EndpointRecords = HashMap<String, Vec<u8>>;

/// In-memory fake of the `/routing/v1` endpoint set: one map of opaque
/// record bytes per configured endpoint, holding the **highest sequence** at
/// each routing key as a real endpoint does ([`supersedes`]).
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
    /// Endpoints that reject a PUT but still serve GET, so the harness can drive
    /// a lost CAS race from the transport rather than from the record.
    put_failing: Arc<Mutex<HashSet<EndpointId>>>,
    /// Routing keys whose PUT is refused at every endpoint, so one record of a
    /// multi-record plan can fail while the rest of the plan publishes.
    put_failing_keys: Arc<Mutex<HashSet<String>>>,
    /// Routing keys whose GET is refused at every endpoint, so one node of a
    /// tree can be unresolvable while the rest of it reads normally.
    get_failing_keys: Arc<Mutex<HashSet<String>>>,
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
            put_failing_keys: Arc::new(Mutex::new(HashSet::new())),
            get_failing_keys: Arc::new(Mutex::new(HashSet::new())),
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

    /// Make `endpoint` reject PUTs while still serving GETs, driving a lost CAS
    /// race from the transport rather than from the record.
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

    /// Refuse every PUT under `routing_key` while the rest of the name space
    /// publishes normally, until [`heal_put_for`](Self::heal_put_for) clears it.
    pub fn fail_put_for(&self, routing_key: &str) {
        self.put_failing_keys
            .lock()
            .expect("lock")
            .insert(routing_key.to_owned());
    }

    /// Restore `routing_key`'s PUT path.
    pub fn heal_put_for(&self, routing_key: &str) {
        self.put_failing_keys
            .lock()
            .expect("lock")
            .remove(routing_key);
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

    /// Whether `routing_key`'s PUT is currently injected to fail everywhere.
    fn put_failing_key(&self, routing_key: &str) -> bool {
        self.put_failing_keys
            .lock()
            .expect("lock")
            .contains(routing_key)
    }

    /// Refuse every GET under `routing_key` while the rest of the name space
    /// resolves normally, until [`heal_get_for`](Self::heal_get_for) clears it —
    /// one node of a tree that no source will serve.
    pub fn fail_get_for(&self, routing_key: &str) {
        self.get_failing_keys
            .lock()
            .expect("lock")
            .insert(routing_key.to_owned());
    }

    /// Restore `routing_key`'s GET path.
    pub fn heal_get_for(&self, routing_key: &str) {
        self.get_failing_keys
            .lock()
            .expect("lock")
            .remove(routing_key);
    }

    /// Whether `routing_key`'s GET is currently injected to fail everywhere.
    fn get_failing_key(&self, routing_key: &str) -> bool {
        self.get_failing_keys
            .lock()
            .expect("lock")
            .contains(routing_key)
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
        if self.get_failing_key(routing_key) {
            return Err(SeamError::new(format!("get refused for {routing_key}")));
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
        if self.put_failing_key(routing_key) {
            return Err(SeamError::new(format!("put refused for {routing_key}")));
        }
        self.inner
            .lock()
            .expect("lock")
            .get_mut(endpoint)
            .map(|records| {
                if let Some(held) = records.get(routing_key)
                    && supersedes(routing_key, held, record)
                {
                    return;
                }
                records.insert(routing_key.to_owned(), record.to_vec());
            })
            .ok_or_else(|| SeamError::new(format!("unknown endpoint: {}", endpoint.0)))
    }
}

/// Whether the record already held under `routing_key` beats the incoming one on
/// IPNS higher-sequence-wins, so the endpoint keeps it and the stale PUT is a
/// silent no-op — a real endpoint acks the write either way.
///
/// The routing key is the record's `ipnsName`, so both sequences are read from
/// the verify chain rather than from unsigned bytes. A pair this fake cannot
/// verify has no sequence to compare and is written through, so a test may still
/// stage opaque bytes through the seam.
fn supersedes(routing_key: &str, held: &[u8], incoming: &[u8]) -> bool {
    let Ok(name) = IpnsName::parse(routing_key) else {
        return false;
    };
    let sequence = |bytes: &[u8]| {
        IpnsRecord::unmarshal(bytes)
            .ok()
            .and_then(|record| record.verify(&name).ok())
            .map(|verified| verified.sequence)
    };
    sequence(held)
        .zip(sequence(incoming))
        .is_some_and(|(held, incoming)| held > incoming)
}

#[cfg(test)]
mod tests {
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use super::*;
    use crate::testkit::account::{EOL, TTL_NANOS};
    use crate::testkit::block_on;

    /// A real signed record at `sequence`, under the name its own signer mints.
    fn signed_value(signer: &Ed25519Signer, sequence: u64, value: &[u8]) -> Vec<u8> {
        IpnsRecord::create_v2(signer, value, sequence, TTL_NANOS, EOL).marshal()
    }

    fn signed(signer: &Ed25519Signer, sequence: u64) -> Vec<u8> {
        signed_value(signer, sequence, b"/ipfs/bafyvalue")
    }

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

    #[test]
    fn a_stale_put_is_acked_and_loses_to_the_held_sequence() {
        let endpoint = EndpointId::new("a");
        let store = InMemoryRecordStore::new(vec![endpoint.clone()]);
        let signer = Ed25519Signer::from_seed([3u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());

        block_on(store.put_record(&endpoint, name.as_str(), &signed(&signer, 5))).expect("put 5");
        block_on(store.put_record(&endpoint, name.as_str(), &signed(&signer, 4)))
            .expect("a stale put is acked, as a real endpoint acks it");
        assert_eq!(
            store.record_at(&endpoint, name.as_str()),
            Some(signed(&signer, 5)),
            "the endpoint keeps the highest sequence"
        );

        block_on(store.put_record(&endpoint, name.as_str(), &signed(&signer, 6))).expect("put 6");
        assert_eq!(
            store.record_at(&endpoint, name.as_str()),
            Some(signed(&signer, 6)),
            "a newer sequence wins"
        );
        // Same sequence, so neither supersedes: the later write stands, which is
        // what lets a re-PUT refresh an EOL at an unchanged sequence.
        let refreshed = signed_value(&signer, 6, b"/ipfs/bafyrefreshed");
        block_on(store.put_record(&endpoint, name.as_str(), &refreshed)).expect("put");
        assert_eq!(store.record_at(&endpoint, name.as_str()), Some(refreshed));
    }

    #[test]
    fn seeding_a_stale_record_still_bypasses_the_seam() {
        let endpoint = EndpointId::new("a");
        let store = InMemoryRecordStore::new(vec![endpoint.clone()]);
        let signer = Ed25519Signer::from_seed([4u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());

        block_on(store.put_record(&endpoint, name.as_str(), &signed(&signer, 9))).expect("put 9");
        store.seed_record(&endpoint, name.as_str(), signed(&signer, 2));
        assert_eq!(
            store.record_at(&endpoint, name.as_str()),
            Some(signed(&signer, 2)),
            "adversarial staging is not a publish and answers to no sequence rule"
        );
    }

    #[test]
    fn a_key_scoped_get_fault_leaves_every_other_key_serving() {
        let endpoint = EndpointId::new("a");
        let store = InMemoryRecordStore::new(vec![endpoint.clone()]);
        store.seed_record(&endpoint, "hidden", b"r".to_vec());
        store.seed_record(&endpoint, "served", b"r".to_vec());

        store.fail_get_for("hidden");
        assert!(block_on(store.get_record(&endpoint, "hidden", 1024)).is_err());
        assert!(block_on(store.get_record(&endpoint, "served", 1024)).is_ok());

        store.heal_get_for("hidden");
        assert!(block_on(store.get_record(&endpoint, "hidden", 1024)).is_ok());
    }
}
