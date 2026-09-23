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

/// Why one endpoint's answer to a fan-out GET counted for nothing. A class
/// only: the diagnostics that carry it hold no record bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointFailure {
    /// The transport returned an error: unreachable, refused, non-2xx, or late.
    Transport,
    /// The endpoint served more than [`MAX_RECORD_BYTES`].
    OverCap,
    /// The bytes did not decode as an IPNS record.
    Malformed,
    /// The record did not verify at the name.
    Unverified,
}

impl core::fmt::Display for EndpointFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Transport => "transport",
            Self::OverCap => "over-cap",
            Self::Malformed => "malformed",
            Self::Unverified => "unverified",
        })
    }
}

/// Every endpoint that failed one fan-out GET, in endpoint-set order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointFailures(pub Vec<(EndpointId, EndpointFailure)>);

impl core::fmt::Display for EndpointFailures {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("no endpoint answered");
        }
        for (index, (endpoint, failure)) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{} {failure}", endpoint.0)?;
        }
        Ok(())
    }
}

/// Which fan-out answers read as "the name is vacant" (ADR 0022).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VacancyRule {
    /// Every endpoint answered, and every answer was "no record".
    Unanimous,
    /// At least one endpoint answered "no record", and every other one failed.
    /// Only for a vault-pointer name the registry confirmed this account never
    /// registered: register-first means no record at it can exist to overwrite.
    FirstRun,
}

impl VacancyRule {
    /// [`FirstRun`](Self::FirstRun) at the one name the registry confirmed
    /// unregistered, [`Unanimous`](Self::Unanimous) at every other name.
    pub fn at(first_run_name: Option<&IpnsName>, name: &IpnsName) -> Self {
        if first_run_name == Some(name) {
            Self::FirstRun
        } else {
            Self::Unanimous
        }
    }
}

/// What a fan-out GET found at a name, on rule 6's axis: [`Absent`] is a
/// statement about the name, [`Unavailable`] is a statement about the endpoints.
///
/// Under [`VacancyRule::Unanimous`], `Absent` needs every endpoint to answer,
/// and every answer to be "no record". One endpoint's word against a set of
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
    /// The endpoints agree the name carries no record, by the read's
    /// [`VacancyRule`].
    Absent,
    /// No endpoint served a verifiable record and the vacancy rule did not
    /// hold. Availability, never a verdict about the name.
    Unavailable(EndpointFailures),
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
        FanoutRecord::Absent | FanoutRecord::Unavailable(_) => None,
    }
}

/// [`fanout_get_verify`] with the two answers it collapses kept apart
/// ([`FanoutRecord`]), under [`VacancyRule::Unanimous`].
///
/// An empty endpoint set falls out as `Unavailable` for the same reason:
/// zero answers is silence, not vacancy.
pub async fn fanout_get_classified<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
) -> FanoutRecord {
    fanout_get_under(transport, name, VacancyRule::Unanimous).await
}

/// [`fanout_get_classified`] under `rule`, which decides only between `Absent`
/// and `Unavailable`: a `Found` is the same verified record under either rule.
pub async fn fanout_get_under<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
    rule: VacancyRule,
) -> FanoutRecord {
    let key = name.as_str();
    let mut best: Option<(VerifiedRecord, Vec<u8>)> = None;
    let mut vacant = 0usize;
    let mut failures = Vec::new();
    for endpoint in transport.endpoints() {
        let bytes = match transport
            .get_record(&endpoint, key, MAX_RECORD_BYTES, None)
            .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                vacant += 1;
                continue;
            }
            Err(_) => {
                failures.push((endpoint, EndpointFailure::Transport));
                continue;
            }
        };
        // Release-active backstop: a transport that ignores its cap must not
        // talk the engine past it (mirrors the WASM bridge's `send_capped`).
        if bytes.len() > MAX_RECORD_BYTES {
            failures.push((endpoint, EndpointFailure::OverCap));
            continue;
        }
        let Ok(record) = IpnsRecord::unmarshal(&bytes) else {
            failures.push((endpoint, EndpointFailure::Malformed));
            continue;
        };
        let Ok(verified) = record.verify(name) else {
            failures.push((endpoint, EndpointFailure::Unverified));
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(current, _)| verified.sequence > current.sequence)
        {
            best = Some((verified, bytes));
        }
    }
    if let Some((verified, bytes)) = best {
        return FanoutRecord::Found(verified, bytes);
    }
    if vacant > 0 && (rule == VacancyRule::FirstRun || failures.is_empty()) {
        FanoutRecord::Absent
    } else {
        FanoutRecord::Unavailable(EndpointFailures(failures))
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
            _bearer: Option<&str>,
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
            FanoutRecord::Unavailable(_)
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
                FanoutRecord::Unavailable(_)
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
            FanoutRecord::Unavailable(_)
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

    /// ADR 0022 D2: at a name the registry confirmed unregistered, one vacant
    /// answer beside failures is an absence, and failures alone still are not.
    #[test]
    fn first_run_reads_one_vacant_answer_beside_a_failure_as_absent() {
        let name = IpnsName::from_public_key(&Ed25519Signer::from_seed([5u8; 32]).verifying_key());
        let eps = vec![EndpointId::new("front"), EndpointId::new("public")];
        let store = InMemoryRecordStore::new(eps.clone());
        store.fail_endpoint(&eps[1]);

        assert!(matches!(
            block_on(fanout_get_under(&store, &name, VacancyRule::FirstRun)),
            FanoutRecord::Absent
        ));

        store.fail_endpoint(&eps[0]);
        assert!(
            matches!(
                block_on(fanout_get_under(&store, &name, VacancyRule::FirstRun)),
                FanoutRecord::Unavailable(_)
            ),
            "with no vacant answer there is nothing to read as an absence"
        );
    }

    /// ADR 0022 D3: the first-run rule changes only the vacancy verdict. A
    /// record still has to verify at the name, and one that does is `Found`.
    #[test]
    fn first_run_still_verifies_every_record_it_is_served() {
        let signer = Ed25519Signer::from_seed([5u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let eps = vec![
            EndpointId::new("front"),
            EndpointId::new("public"),
            EndpointId::new("down"),
        ];
        let store = InMemoryRecordStore::new(eps.clone());
        store.fail_endpoint(&eps[2]);
        let forged = IpnsRecord::create_v2(
            &Ed25519Signer::from_seed([6u8; 32]),
            b"forged",
            9,
            1,
            "2099-01-01T00:00:00Z",
        )
        .marshal();
        store.seed_record(&eps[1], name.as_str(), forged);

        assert!(
            matches!(
                block_on(fanout_get_under(&store, &name, VacancyRule::FirstRun)),
                FanoutRecord::Absent
            ),
            "a record that does not verify at the name is a failure, never a find"
        );

        let genuine =
            IpnsRecord::create_v2(&signer, b"genuine", 1, 1, "2099-01-01T00:00:00Z").marshal();
        store.seed_record(&eps[0], name.as_str(), genuine);
        let FanoutRecord::Found(verified, _) =
            block_on(fanout_get_under(&store, &name, VacancyRule::FirstRun))
        else {
            panic!("a record that verifies at the name is found under either rule");
        };
        assert_eq!(verified.value, b"genuine");
    }

    #[test]
    fn an_unavailable_read_names_every_failed_endpoint_and_its_class() {
        let name = IpnsName::from_public_key(&Ed25519Signer::from_seed([5u8; 32]).verifying_key());
        let eps = vec![EndpointId::new("front"), EndpointId::new("public")];
        let store = InMemoryRecordStore::new(eps.clone());
        store.fail_endpoint(&eps[0]);
        store.seed_record(&eps[1], name.as_str(), b"not a record".to_vec());

        let FanoutRecord::Unavailable(failures) = block_on(fanout_get_classified(&store, &name))
        else {
            panic!("no endpoint answered usefully");
        };
        assert_eq!(failures.to_string(), "front transport; public malformed");
    }

    #[test]
    fn a_vacancy_rule_is_first_run_only_at_the_confirmed_name() {
        let confirmed =
            IpnsName::from_public_key(&Ed25519Signer::from_seed([1u8; 32]).verifying_key());
        let other = IpnsName::from_public_key(&Ed25519Signer::from_seed([2u8; 32]).verifying_key());

        assert_eq!(
            VacancyRule::at(Some(&confirmed), &confirmed),
            VacancyRule::FirstRun
        );
        assert_eq!(
            VacancyRule::at(Some(&confirmed), &other),
            VacancyRule::Unanimous
        );
        assert_eq!(VacancyRule::at(None, &confirmed), VacancyRule::Unanimous);
    }
}
