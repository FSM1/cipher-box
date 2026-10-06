//! The fake `/routing/v1` record store — an in-memory [`RecordTransport`].

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use cipherbox_core::ipns::{IpnsName, IpnsRecord};

use crate::net::{HeldKey, HeldRecord, HeldRecords};
use crate::seams::{EndpointId, RecordTransport, SeamError, SeamResult};

/// Records held by one endpoint, keyed by routing key.
type EndpointRecords = HashMap<String, Vec<u8>>;

/// Records waiting on a PUT at the routing key they are filed under, each with
/// the routing key it is to be served at and the one endpoint that serves it
/// (`None` for every endpoint).
type DeferredRecords = HashMap<String, Vec<(String, Vec<u8>, Option<EndpointId>)>>;

/// For each routing key: the GETs still to answer from the store, the GETs then
/// to answer with the record (`None` for no record), and the record.
type SwappedRecords = HashMap<String, (usize, usize, Option<Vec<u8>>)>;

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
    /// Routing keys whose PUT an endpoint answers with an HTTP status and does
    /// not store, keyed by routing key and endpoint.
    put_answers: Arc<Mutex<HashMap<(String, EndpointId), u16>>>,
    /// Endpoints that answer every GET with an HTTP status
    /// ([`answer_get_at`](InMemoryRecordStore::answer_get_at)).
    get_answers: Arc<Mutex<HashMap<EndpointId, u16>>>,
    /// Routing keys whose GET is refused at every endpoint, so one node of a
    /// tree can be unresolvable while the rest of it reads normally.
    get_failing_keys: Arc<Mutex<HashSet<String>>>,
    /// (endpoint, routing key) pairs whose GET is refused at that endpoint only.
    get_failing_at: Arc<Mutex<HashSet<(EndpointId, String)>>>,
    /// GETs served per routing key, so a test can count what a pass spends on
    /// one name rather than inferring it from what the pass published.
    gets: Arc<Mutex<HashMap<String, usize>>>,
    /// PUTs asked for per routing key, whatever fault is injected.
    puts: Arc<Mutex<HashMap<String, usize>>>,
    /// Records held back until a PUT lands
    /// ([`seed_record_after_put`](InMemoryRecordStore::seed_record_after_put)).
    deferred: Arc<Mutex<DeferredRecords>>,
    /// Whether every PUT is acked and discarded
    /// ([`drop_puts`](InMemoryRecordStore::drop_puts)).
    dropping_puts: Arc<AtomicBool>,
    /// Whether every GET parks for ever
    /// ([`stall_gets`](InMemoryRecordStore::stall_gets)).
    stalling_gets: Arc<AtomicBool>,
    /// ([`stall_gets_for_after`](InMemoryRecordStore::stall_gets_for_after)).
    stalling_keys: Arc<Mutex<HashMap<String, usize>>>,
    /// ([`serve_gets_for_after`](InMemoryRecordStore::serve_gets_for_after)).
    swapped_keys: Arc<Mutex<SwappedRecords>>,
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
            put_answers: Arc::default(),
            get_answers: Arc::default(),
            get_failing_keys: Arc::new(Mutex::new(HashSet::new())),
            get_failing_at: Arc::default(),
            gets: Arc::new(Mutex::new(HashMap::new())),
            puts: Arc::new(Mutex::new(HashMap::new())),
            deferred: Arc::new(Mutex::new(HashMap::new())),
            dropping_puts: Arc::new(AtomicBool::new(false)),
            stalling_gets: Arc::new(AtomicBool::new(false)),
            stalling_keys: Arc::default(),
            swapped_keys: Arc::default(),
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

    /// Serve `record` at `routing_key` from every endpoint once a PUT lands at
    /// `after_put_at`, and not before — another device that published while the
    /// pass under test was mid-flight, staged without a wall clock.
    pub fn seed_record_after_put(&self, after_put_at: &str, routing_key: &str, record: Vec<u8>) {
        self.defer(after_put_at, routing_key, record, None);
    }

    /// [`seed_record_after_put`](Self::seed_record_after_put) at `endpoint`
    /// alone: the endpoint set split between two records.
    pub fn seed_record_after_put_at(
        &self,
        endpoint: &EndpointId,
        after_put_at: &str,
        routing_key: &str,
        record: Vec<u8>,
    ) {
        self.defer(after_put_at, routing_key, record, Some(endpoint.clone()));
    }

    fn defer(
        &self,
        after_put_at: &str,
        routing_key: &str,
        record: Vec<u8>,
        endpoint: Option<EndpointId>,
    ) {
        self.deferred
            .lock()
            .expect("lock")
            .entry(after_put_at.to_owned())
            .or_default()
            .push((routing_key.to_owned(), record, endpoint));
    }

    /// Install whatever [`seed_record_after_put`](Self::seed_record_after_put)
    /// filed under `routing_key`.
    fn release_deferred(&self, routing_key: &str) {
        let released = self.deferred.lock().expect("lock").remove(routing_key);
        for (key, record, only) in released.unwrap_or_default() {
            for endpoint in &self.endpoints {
                if only.as_ref().is_none_or(|only| only == endpoint) {
                    self.seed_record(endpoint, &key, record.clone());
                }
            }
        }
    }

    /// Test-side read, bypassing the seam (publish observation).
    pub fn record_at(&self, endpoint: &EndpointId, routing_key: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .expect("lock")
            .get(endpoint)
            .and_then(|records| records.get(routing_key).cloned())
    }

    /// Every record each endpoint holds, by endpoint and routing key.
    pub(crate) fn contents(&self) -> BTreeMap<(EndpointId, String), Vec<u8>> {
        self.inner
            .lock()
            .expect("lock")
            .iter()
            .flat_map(|(endpoint, records)| {
                records
                    .iter()
                    .map(|(key, record)| ((endpoint.clone(), key.clone()), record.clone()))
            })
            .collect()
    }

    /// Every routing key `endpoint` holds a record at, sorted.
    pub fn routing_keys(&self, endpoint: &EndpointId) -> Vec<String> {
        let mut keys: Vec<String> = self
            .inner
            .lock()
            .expect("lock")
            .get(endpoint)
            .map(|records| records.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        keys
    }

    /// Make `endpoint` return a transport error on every GET/PUT until
    /// [`heal_endpoint`](Self::heal_endpoint) clears it.
    pub fn fail_endpoint(&self, endpoint: &EndpointId) {
        self.failing.lock().expect("lock").insert(endpoint.clone());
    }

    /// Restore `endpoint` to normal operation.
    pub fn heal_endpoint(&self, endpoint: &EndpointId) {
        self.failing.lock().expect("lock").remove(endpoint);
        self.get_answers.lock().expect("lock").remove(endpoint);
    }

    /// Answer every GET at `endpoint` with `status` until
    /// [`heal_endpoint`](Self::heal_endpoint) clears it.
    pub fn answer_get_at(&self, endpoint: &EndpointId, status: u16) {
        self.get_answers
            .lock()
            .expect("lock")
            .insert(endpoint.clone(), status);
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

    /// Answer every PUT under `routing_key` at `endpoint` with `status`, and
    /// store nothing, until [`heal_put_for`](Self::heal_put_for) clears it.
    pub fn answer_put_for_at(&self, endpoint: &EndpointId, routing_key: &str, status: u16) {
        self.put_answers
            .lock()
            .expect("lock")
            .insert((routing_key.to_owned(), endpoint.clone()), status);
    }

    /// Restore `routing_key`'s PUT path.
    pub fn heal_put_for(&self, routing_key: &str) {
        self.put_answers
            .lock()
            .expect("lock")
            .retain(|(key, _), _| key != routing_key);
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

    /// Refuse every GET under `routing_key` at `endpoint` alone, while other
    /// endpoints and other names answer normally.
    pub fn fail_get_at_for(&self, endpoint: &EndpointId, routing_key: &str) {
        self.get_failing_at
            .lock()
            .expect("lock")
            .insert((endpoint.clone(), routing_key.to_owned()));
    }

    /// Restore `routing_key`'s GET path.
    pub fn heal_get_for(&self, routing_key: &str) {
        self.get_failing_keys
            .lock()
            .expect("lock")
            .remove(routing_key);
    }

    /// How many GETs this store has been asked for at `routing_key`, across
    /// every endpoint and whatever fault is injected.
    pub fn get_count(&self, routing_key: &str) -> usize {
        self.gets
            .lock()
            .expect("lock")
            .get(routing_key)
            .copied()
            .unwrap_or(0)
    }

    /// How many PUTs this store has been asked for at `routing_key`, across
    /// every endpoint and whatever fault is injected.
    pub fn put_count(&self, routing_key: &str) -> usize {
        self.puts
            .lock()
            .expect("lock")
            .get(routing_key)
            .copied()
            .unwrap_or(0)
    }

    /// Ack every PUT and retain nothing, so a confirm re-resolve reads no
    /// record at all — an endpoint that answers 200 and stores nothing.
    pub fn drop_puts(&self) {
        self.dropping_puts.store(true, Ordering::SeqCst);
    }

    /// Retain PUTs again after [`drop_puts`](Self::drop_puts).
    pub fn keep_puts(&self) {
        self.dropping_puts.store(false, Ordering::SeqCst);
    }

    /// Park every GET under `routing_key` once `budget` more of them have
    /// answered, until [`release_gets_for`](Self::release_gets_for), so a test
    /// can hold one caller mid-read.
    pub fn stall_gets_for_after(&self, routing_key: &str, budget: usize) {
        self.stalling_keys
            .lock()
            .expect("lock")
            .insert(routing_key.to_owned(), budget);
    }

    /// Answer the `count` GETs under `routing_key` that come after `answered`
    /// more of them with `record` (`None` serves no record), then answer from
    /// the store again, so one read of a name sees other bytes between two that
    /// do not.
    pub fn serve_gets_for_after(
        &self,
        routing_key: &str,
        answered: usize,
        count: usize,
        record: Option<Vec<u8>>,
    ) {
        self.swapped_keys
            .lock()
            .expect("lock")
            .insert(routing_key.to_owned(), (answered, count, record));
    }

    /// The bytes [`serve_gets_for_after`](Self::serve_gets_for_after) answers
    /// this GET under `routing_key` with, if any.
    fn swapped(&self, routing_key: &str) -> Option<Option<Vec<u8>>> {
        let mut keys = self.swapped_keys.lock().expect("lock");
        let (answered, count, record) = keys.get_mut(routing_key)?;
        if let Some(left) = answered.checked_sub(1) {
            *answered = left;
            return None;
        }
        *count = count.checked_sub(1)?;
        Some(record.clone())
    }

    /// Park every GET for ever — the shape of a name no source answers for.
    /// The future stays `Pending`, so a deterministic executor parks on it
    /// rather than spinning.
    pub fn stall_gets(&self) {
        self.stalling_gets.store(true, Ordering::SeqCst);
    }

    /// Answer every GET [`stall_gets_for_after`](Self::stall_gets_for_after)
    /// parked under `routing_key`, and stop stalling it.
    pub fn release_gets_for(&self, routing_key: &str) {
        self.stalling_keys.lock().expect("lock").remove(routing_key);
    }

    /// Whether `routing_key`'s stall budget is spent.
    fn stalls(&self, routing_key: &str) -> bool {
        self.stalling_keys.lock().expect("lock").get(routing_key) == Some(&0)
    }

    /// Whether `routing_key`'s GET is currently injected to fail everywhere.
    fn get_failing_key(&self, routing_key: &str) -> bool {
        self.get_failing_keys
            .lock()
            .expect("lock")
            .contains(routing_key)
    }

    fn get_failing_at(&self, endpoint: &EndpointId, routing_key: &str) -> bool {
        self.get_failing_at
            .lock()
            .expect("lock")
            .contains(&(endpoint.clone(), routing_key.to_owned()))
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
        _bearer: Option<&str>,
    ) -> SeamResult<Option<Vec<u8>>> {
        *self
            .gets
            .lock()
            .expect("lock")
            .entry(routing_key.to_owned())
            .or_default() += 1;
        let parked = self
            .stalling_keys
            .lock()
            .expect("lock")
            .get_mut(routing_key)
            .is_some_and(|budget| match budget.checked_sub(1) {
                Some(left) => {
                    *budget = left;
                    false
                }
                None => true,
            });
        if self.stalling_gets.load(Ordering::SeqCst) {
            return core::future::poll_fn(|_| core::task::Poll::Pending).await;
        }
        if parked {
            core::future::poll_fn(|_| {
                if self.stalls(routing_key) {
                    core::task::Poll::Pending
                } else {
                    core::task::Poll::Ready(())
                }
            })
            .await;
        }
        if self.get_failing(endpoint) {
            return Err(SeamError::new(format!(
                "endpoint unreachable: {}",
                endpoint.0
            )));
        }
        if let Some(status) = self.get_answers.lock().expect("lock").get(endpoint) {
            return Err(SeamError::http_status(
                format!("get answered {status}"),
                *status,
            ));
        }
        if self.get_failing_key(routing_key) || self.get_failing_at(endpoint, routing_key) {
            return Err(SeamError::new(format!("get refused for {routing_key}")));
        }
        let record = match self.swapped(routing_key) {
            Some(record) => record,
            None => self
                .inner
                .lock()
                .expect("lock")
                .get(endpoint)
                .map(|records| records.get(routing_key).cloned())
                .ok_or_else(|| SeamError::new(format!("unknown endpoint: {}", endpoint.0)))?,
        };
        match record {
            Some(bytes) if bytes.len() > max_bytes => Err(SeamError::over_cap(format!(
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
        *self
            .puts
            .lock()
            .expect("lock")
            .entry(routing_key.to_owned())
            .or_default() += 1;
        if self.put_failing(endpoint) {
            return Err(SeamError::new(format!(
                "endpoint unreachable: {}",
                endpoint.0
            )));
        }
        if self.put_failing_key(routing_key) {
            return Err(SeamError::new(format!("put refused for {routing_key}")));
        }
        let answer = self
            .put_answers
            .lock()
            .expect("lock")
            .get(&(routing_key.to_owned(), endpoint.clone()))
            .copied();
        if let Some(status) = answer {
            return Err(SeamError::http_status(
                format!("put answered {status} for {routing_key}"),
                status,
            ));
        }
        if self.dropping_puts.load(Ordering::SeqCst) {
            return Ok(());
        }
        let known = self
            .inner
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
            .is_some();
        if !known {
            return Err(SeamError::new(format!("unknown endpoint: {}", endpoint.0)));
        }
        self.release_deferred(routing_key);
        Ok(())
    }
}

/// A transport that lands `record` at `key` in the renewal set before it
/// delegates each GET — the interleaving a single-threaded executor allows at
/// any `.await`, where a publish confirms and enrols its record while a load is
/// still in flight.
pub struct SlotFillingRecordStore {
    inner: InMemoryRecordStore,
    held: Rc<RefCell<HeldRecords>>,
    key: HeldKey,
    record: HeldRecord,
}

impl SlotFillingRecordStore {
    /// Delegate to `inner`, enrolling `record` at `key` on every GET.
    pub fn new(
        inner: InMemoryRecordStore,
        held: Rc<RefCell<HeldRecords>>,
        key: HeldKey,
        record: HeldRecord,
    ) -> Self {
        Self {
            inner,
            held,
            key,
            record,
        }
    }
}

impl RecordTransport for SlotFillingRecordStore {
    fn endpoints(&self) -> Vec<EndpointId> {
        self.inner.endpoints()
    }

    async fn get_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        max_bytes: usize,
        bearer: Option<&str>,
    ) -> SeamResult<Option<Vec<u8>>> {
        self.held.borrow_mut().insert(self.key, self.record.clone());
        self.inner
            .get_record(endpoint, routing_key, max_bytes, bearer)
            .await
    }

    async fn put_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        record: &[u8],
    ) -> SeamResult<()> {
        self.inner.put_record(endpoint, routing_key, record).await
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
        assert!(block_on(store.get_record(&missing, "k", 1024, None)).is_err());
        assert!(block_on(store.put_record(&missing, "k", b"r")).is_err());
    }

    /// A served record keeps the read's cap, as a stored one does.
    #[test]
    fn a_served_record_over_the_cap_is_refused() {
        let endpoint = EndpointId::new("a");
        let store = InMemoryRecordStore::new(vec![endpoint.clone()]);
        store.serve_gets_for_after("name", 0, 2, Some(vec![0; 8]));
        assert!(block_on(store.get_record(&endpoint, "name", 4, None)).is_err());
        assert_eq!(
            block_on(store.get_record(&endpoint, "name", 8, None)).unwrap(),
            Some(vec![0; 8])
        );
    }

    #[test]
    fn seed_and_inspect_bypass_the_seam() {
        let endpoint = EndpointId::new("a");
        let store = InMemoryRecordStore::new(vec![endpoint.clone()]);
        store.seed_record(&endpoint, "name", b"forged".to_vec());
        assert_eq!(
            block_on(store.get_record(&endpoint, "name", 1024, None)).unwrap(),
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
        assert!(block_on(store.get_record(&endpoint, "hidden", 1024, None)).is_err());
        assert!(block_on(store.get_record(&endpoint, "served", 1024, None)).is_ok());

        store.heal_get_for("hidden");
        assert!(block_on(store.get_record(&endpoint, "hidden", 1024, None)).is_ok());
    }
}
