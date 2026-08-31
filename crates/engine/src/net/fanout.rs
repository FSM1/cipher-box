//! Endpoint-set fan-out primitives shared by the resolve, publish, and liveness
//! paths (blueprint/engine.md "Resolve/publish pipeline").
//!
//! The engine owns IPNS end-to-end over dumb `/routing/v1` transports (#28 D2):
//! core signs and verifies, the [`RecordTransport`] seam only moves bytes, and
//! every decision — which endpoint's copy is freshest, when a PUT has succeeded,
//! which endpoints still need a retry — lives here.

use core::future::poll_fn;
use core::task::Poll;

use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};

use crate::seams::{EndpointId, RecordTransport};

/// Hard ceiling on one signed IPNS record fetched from a `/routing/v1`
/// endpoint. The IPNS spec caps a record at 10 KiB, and the endpoint set
/// includes at least one untrusted public endpoint — anything larger is a
/// hostile or broken endpoint whose bytes are never adoptable.
pub const MAX_RECORD_BYTES: usize = 10 * 1024;

/// The outcome of a parallel PUT across the endpoint set.
pub struct Fanout {
    /// Endpoints that acknowledged the PUT.
    pub acked: Vec<EndpointId>,
    /// Endpoints that failed or had not answered when the first ack returned —
    /// the set a background retry re-PUTs (blueprint: "remaining PUTs retry in
    /// the background").
    pub not_acked: Vec<EndpointId>,
}

impl Fanout {
    /// Whether any endpoint acknowledged: the publish success condition
    /// (blueprint: "success = any ack").
    pub fn any_acked(&self) -> bool {
        !self.acked.is_empty()
    }
}

/// PUT `bytes` for `key` to every endpoint concurrently, returning as soon as
/// one endpoint acknowledges — the remaining endpoints (failed or still
/// in-flight) come back in [`Fanout::not_acked`] for a background retry. When
/// every endpoint settles with no ack, `acked` is empty and the caller fails
/// closed.
pub async fn fanout_put<T: RecordTransport>(transport: &T, key: &str, bytes: &[u8]) -> Fanout {
    let endpoints = transport.endpoints();
    let mut futs: Vec<_> = endpoints
        .iter()
        .map(|endpoint| Box::pin(transport.put_record(endpoint, key, bytes)))
        .collect();
    // Per-endpoint settle state: `Some(true)` acked, `Some(false)` failed,
    // `None` still pending.
    let mut status: Vec<Option<bool>> = vec![None; futs.len()];

    poll_fn(|cx| {
        let mut all_settled = true;
        for (index, fut) in futs.iter_mut().enumerate() {
            if status[index].is_some() {
                continue;
            }
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => status[index] = Some(true),
                Poll::Ready(Err(_)) => status[index] = Some(false),
                Poll::Pending => all_settled = false,
            }
        }
        // Return the instant one endpoint acks, or once every endpoint settled.
        if status.contains(&Some(true)) || all_settled {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;

    let mut acked = Vec::new();
    let mut not_acked = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        if status[index] == Some(true) {
            acked.push(endpoint.clone());
        } else {
            not_acked.push(endpoint.clone());
        }
    }
    Fanout { acked, not_acked }
}

/// What a fan-out GET found at a name, on rule 6's axis: [`Absent`] is a
/// statement about the name, [`Unavailable`] is a statement about the endpoints.
///
/// `Absent` needs the endpoint set to be **unanimous**: every endpoint answered,
/// and every answer was "no record". One endpoint's word against a set of
/// failures is not evidence about a name, and treating it as such is how a
/// single hostile accelerator truncates a chain. Even unanimity is not proof —
/// endpoints can be wrong together — so a caller that must not be steered by an
/// absence still needs a durable bar of its own.
///
/// [`Absent`]: FanoutRecord::Absent
/// [`Unavailable`]: FanoutRecord::Unavailable
pub enum FanoutRecord {
    /// The freshest verifiable record an endpoint served, with its bytes.
    Found(VerifiedRecord, Vec<u8>),
    /// Every endpoint answered, and every answer was "no record".
    Absent,
    /// No endpoint served a verifiable record and the set did not agree the
    /// name is vacant: one errored, broke the size cap, or served unverifiable
    /// bytes. Availability, never a verdict about the name.
    Unavailable,
}

/// Fan-out GET across the endpoint set and core-verify each returned record
/// against `name`, returning the freshest `(VerifiedRecord, record_bytes)` or
/// `None` when no endpoint serves a verifiable record. A malformed or
/// signature-invalid copy at one endpoint is ignored (an accelerator can serve
/// stale garbage); a per-endpoint transport error is tolerated as availability
/// staleness — only genuine host failure is surfaced.
///
/// This is the record-plane verify step (core's Ed25519-from-the-name chain);
/// the full adoption gate runs downstream on the chosen bytes. The
/// [`VerifiedRecord`] rides out so no caller re-verifies the same signature.
///
/// Callers that must not read an unreadable plane as an empty one take
/// [`fanout_get_classified`] instead.
pub async fn fanout_get_verify<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
) -> Option<(VerifiedRecord, Vec<u8>)> {
    match fanout_get_classified(transport, name).await {
        FanoutRecord::Found(verified, bytes) => Some((verified, bytes)),
        FanoutRecord::Absent | FanoutRecord::Unavailable => None,
    }
}

/// [`fanout_get_verify`] with the two answers it collapses kept apart
/// ([`FanoutRecord`]).
///
/// An empty endpoint set falls out as `Unavailable` for the same reason:
/// zero answers is silence, not vacancy.
pub async fn fanout_get_classified<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
) -> FanoutRecord {
    let key = name.as_str();
    let mut best: Option<(VerifiedRecord, Vec<u8>)> = None;
    let mut vacant = 0usize;
    let mut asked = 0usize;
    for endpoint in transport.endpoints() {
        asked += 1;
        let bytes = match transport.get_record(&endpoint, key, MAX_RECORD_BYTES).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                vacant += 1;
                continue;
            }
            Err(_) => continue,
        };
        // Release-active backstop: a transport that ignores its cap must not
        // talk the engine past it (mirrors the WASM bridge's `send_capped`).
        if bytes.len() > MAX_RECORD_BYTES {
            continue;
        }
        let Ok(record) = IpnsRecord::unmarshal(&bytes) else {
            continue;
        };
        let Ok(verified) = record.verify(name) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(current, _)| verified.sequence > current.sequence)
        {
            best = Some((verified, bytes));
        }
    }
    match best {
        Some((verified, bytes)) => FanoutRecord::Found(verified, bytes),
        None if asked > 0 && vacant == asked => FanoutRecord::Absent,
        None => FanoutRecord::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use super::*;
    use crate::seams::{SeamError, SeamResult};
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryRecordStore;

    /// A transport that ignores `max_bytes` and serves whatever it was seeded,
    /// recording the cap the engine handed it.
    struct IgnoresTheCap {
        bytes: Vec<u8>,
        seen_cap: Cell<Option<usize>>,
    }

    impl RecordTransport for IgnoresTheCap {
        fn endpoints(&self) -> Vec<EndpointId> {
            vec![EndpointId::new("ignores-cap")]
        }

        async fn get_record(
            &self,
            _endpoint: &EndpointId,
            _routing_key: &str,
            max_bytes: usize,
        ) -> SeamResult<Option<Vec<u8>>> {
            self.seen_cap.set(Some(max_bytes));
            Ok(Some(self.bytes.clone()))
        }

        async fn put_record(
            &self,
            _endpoint: &EndpointId,
            _routing_key: &str,
            _record: &[u8],
        ) -> SeamResult<()> {
            Err(SeamError::new("put unused by this fake"))
        }
    }

    #[test]
    fn get_verify_caps_the_read_and_skips_a_transport_that_ignores_it() {
        let name = IpnsName::from_public_key(&Ed25519Signer::from_seed([7u8; 32]).verifying_key());
        let transport = IgnoresTheCap {
            bytes: vec![0u8; MAX_RECORD_BYTES + 1],
            seen_cap: Cell::new(None),
        };

        assert!(block_on(fanout_get_verify(&transport, &name)).is_none());
        assert_eq!(
            transport.seen_cap.get(),
            Some(MAX_RECORD_BYTES),
            "the engine, not the transport, chooses the record cap"
        );
    }

    /// Bytes that exist but do not verify say nothing about vacancy: an
    /// over-cap answer is availability, never "this name has no record".
    #[test]
    fn unverifiable_bytes_classify_as_unavailable_not_absent() {
        let name = IpnsName::from_public_key(&Ed25519Signer::from_seed([7u8; 32]).verifying_key());
        let transport = IgnoresTheCap {
            bytes: vec![0u8; MAX_RECORD_BYTES + 1],
            seen_cap: Cell::new(None),
        };

        assert!(matches!(
            block_on(fanout_get_classified(&transport, &name)),
            FanoutRecord::Unavailable
        ));
    }

    #[test]
    fn an_unseeded_name_is_absent_and_an_unreachable_one_is_unavailable() {
        let name = IpnsName::from_public_key(&Ed25519Signer::from_seed([9u8; 32]).verifying_key());
        let eps = vec![EndpointId::new("a"), EndpointId::new("b")];
        let store = InMemoryRecordStore::new(eps.clone());

        assert!(
            matches!(
                block_on(fanout_get_classified(&store, &name)),
                FanoutRecord::Absent
            ),
            "every endpoint answers 'no record', so the name is absent"
        );

        for endpoint in &eps {
            store.fail_endpoint(endpoint);
        }
        assert!(
            matches!(
                block_on(fanout_get_classified(&store, &name)),
                FanoutRecord::Unavailable
            ),
            "no endpoint answered at all, so nothing is known about the name"
        );
    }

    /// One endpoint's "no record" against a set of failures is not evidence
    /// about a name. Reading it as one lets a single hostile accelerator
    /// truncate a chain while its peers are made to fail.
    #[test]
    fn one_vacant_answer_beside_a_failure_is_unavailable_not_absent() {
        let name = IpnsName::from_public_key(&Ed25519Signer::from_seed([5u8; 32]).verifying_key());
        let eps = vec![EndpointId::new("honest"), EndpointId::new("down")];
        let store = InMemoryRecordStore::new(eps.clone());
        store.fail_endpoint(&eps[1]);

        assert!(matches!(
            block_on(fanout_get_classified(&store, &name)),
            FanoutRecord::Unavailable
        ));

        store.heal_endpoint(&eps[1]);
        assert!(
            matches!(
                block_on(fanout_get_classified(&store, &name)),
                FanoutRecord::Absent
            ),
            "unanimity is what makes an absence an answer"
        );
    }
}
