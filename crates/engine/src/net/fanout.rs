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

use super::eol::ranks_above;
use super::fork::verified;
use crate::seams::{EndpointId, RecordTransport, SeamError};

/// Hard ceiling on one signed IPNS record fetched from a `/routing/v1`
/// endpoint. The IPNS spec caps a record at 10 KiB, and the endpoint set
/// includes at least one untrusted public endpoint — anything larger is a
/// hostile or broken endpoint whose bytes are never adoptable.
pub const MAX_RECORD_BYTES: usize = 10 * 1024;

/// What one endpoint's PUT answer states about the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// A 2xx answer.
    Accepted,
    /// A 4xx answer: the hop that answered did not act on the request, so the
    /// record did not leave through this endpoint.
    Refused,
    /// No answer, or an answer that states nothing about the record: a 5xx can
    /// follow a partial routing put, and a 1xx or 3xx settles nothing.
    Unknown,
}

impl PutOutcome {
    fn of(result: &Result<(), SeamError>) -> Self {
        match result {
            Ok(()) => Self::Accepted,
            Err(error) => match error.status() {
                Some(400..=499) => Self::Refused,
                _ => Self::Unknown,
            },
        }
    }
}

/// The outcome of a parallel PUT across the endpoint set.
pub struct Fanout {
    /// Endpoints that acknowledged the PUT.
    pub acked: Vec<EndpointId>,
    /// Endpoints that failed or had not answered when the first ack returned —
    /// the set a background retry re-PUTs (blueprint: "remaining PUTs retry in
    /// the background").
    pub not_acked: Vec<EndpointId>,
    /// Whether every endpoint settled with a stated refusal.
    pub all_refused: bool,
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
    let mut status: Vec<Option<PutOutcome>> = vec![None; futs.len()];

    poll_fn(|cx| {
        let mut all_settled = true;
        for (index, fut) in futs.iter_mut().enumerate() {
            if status[index].is_some() {
                continue;
            }
            match fut.as_mut().poll(cx) {
                Poll::Ready(result) => status[index] = Some(PutOutcome::of(&result)),
                Poll::Pending => all_settled = false,
            }
        }
        // Return the instant one endpoint acks, or once every endpoint settled.
        if status.contains(&Some(PutOutcome::Accepted)) || all_settled {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;

    let mut acked = Vec::new();
    let mut not_acked = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        if status[index] == Some(PutOutcome::Accepted) {
            acked.push(endpoint.clone());
        } else {
            not_acked.push(endpoint.clone());
        }
    }
    let all_refused = !status.is_empty() && status.iter().all(|s| *s == Some(PutOutcome::Refused));
    Fanout {
        acked,
        not_acked,
        all_refused,
    }
}

/// A class, never bytes: the diagnostics that carry it must hold no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointFailure {
    /// No HTTP answer, a 5xx, or late: the endpoint said nothing about the
    /// name (ADR 0071 D2).
    Transport,
    /// An HTTP answer other than 2xx, 404 or 5xx.
    Status,
    /// The endpoint served more than the byte cap.
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
            Self::Status => "status",
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
    /// The registry's answer covers `first_run_name` and no other name.
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

/// [`fanout_get_classified`] under `rule`, which never touches a `Found`
/// (ADR 0022 D3).
pub async fn fanout_get_under<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
    rule: VacancyRule,
) -> FanoutRecord {
    scan(transport, name).await.classify(rule)
}

/// [`fanout_get_classified`], whether an endpoint answered for the name (with
/// no record, or with bytes that it served; a transport failure or a status
/// answer is no answer), and [`TiedFetch::endpoint_failed`].
pub(crate) async fn fanout_get_answered<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
) -> (FanoutRecord, bool, bool) {
    let scan = scan(transport, name).await;
    let answered = scan.vacant > 0
        || scan.failures.iter().any(|(_, failure)| {
            !matches!(
                failure,
                EndpointFailure::Transport | EndpointFailure::Status
            )
        });
    let endpoint_failed = scan.endpoint_failed();
    (
        scan.classify(VacancyRule::Unanimous),
        answered,
        endpoint_failed,
    )
}

/// The freshest verified record, and every other record another endpoint
/// served at its sequence. The freshest pick takes the record that ranks
/// above the others at a tie ([`ranks_above`]), so without the ties a
/// sibling's record hides behind it.
/// The ties are record-verified only; a caller gates one before it builds on
/// it.
pub(crate) async fn fanout_get_tied<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
) -> Option<(VerifiedRecord, Vec<u8>, Vec<Vec<u8>>)> {
    fanout_get_tied_classified(transport, name).await.pick
}

/// What [`fanout_get_tied_classified`] read at a name.
pub(crate) struct TiedFetch {
    /// [`fanout_get_tied`]'s answer.
    pub(crate) pick: Option<(VerifiedRecord, Vec<u8>, Vec<Vec<u8>>)>,
    /// No endpoint served a record, and the endpoints agree the name holds
    /// none, under [`VacancyRule::Unanimous`].
    pub(crate) absent: bool,
    /// An endpoint gave no answer about the name, so a below-floor pick is
    /// unavailable, not a rollback (ADR 0071 D1, D2).
    pub(crate) endpoint_failed: bool,
}

/// [`fanout_get_tied`], and what the endpoints said beside the pick.
pub(crate) async fn fanout_get_tied_classified<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
) -> TiedFetch {
    let scan = scan(transport, name).await;
    let absent = scan.absent(VacancyRule::Unanimous);
    let endpoint_failed = scan.endpoint_failed();
    let Scan { best, tied, .. } = scan;
    TiedFetch {
        pick: best.map(|(verified, bytes)| (verified, bytes, tied)),
        absent,
        endpoint_failed,
    }
}

/// Every endpoint's answer to one fan-out GET, before a caller reads it.
struct Scan {
    /// The freshest verifiable record. At one sequence the record that
    /// [`ranks_above`] the others wins.
    best: Option<(VerifiedRecord, Vec<u8>)>,
    /// The other distinct verifiable records at `best`'s sequence, one per
    /// endpoint at most.
    tied: Vec<Vec<u8>>,
    vacant: usize,
    failures: Vec<(EndpointId, EndpointFailure)>,
}

impl Scan {
    /// Whether an endpoint gave no answer about the name (ADR 0071 D2).
    fn endpoint_failed(&self) -> bool {
        self.failures
            .iter()
            .any(|(_, failure)| *failure == EndpointFailure::Transport)
    }

    /// Whether the endpoints agree the name holds no record, by `rule`.
    fn absent(&self, rule: VacancyRule) -> bool {
        self.best.is_none()
            && self.vacant > 0
            && (rule == VacancyRule::FirstRun || self.failures.is_empty())
    }

    fn classify(self, rule: VacancyRule) -> FanoutRecord {
        let absent = self.absent(rule);
        let Self { best, failures, .. } = self;
        if let Some((verified, bytes)) = best {
            return FanoutRecord::Found(verified, bytes);
        }
        if absent {
            FanoutRecord::Absent
        } else {
            FanoutRecord::Unavailable(EndpointFailures(failures))
        }
    }
}

async fn scan<T: RecordTransport>(transport: &T, name: &IpnsName) -> Scan {
    let key = name.as_str();
    let mut scan = Scan {
        best: None,
        tied: Vec::new(),
        vacant: 0,
        failures: Vec::new(),
    };
    for endpoint in transport.endpoints() {
        let bytes = match transport
            .get_record(&endpoint, key, MAX_RECORD_BYTES, None)
            .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                scan.vacant += 1;
                continue;
            }
            Err(error) => {
                scan.failures.push((endpoint, get_failure(&error)));
                continue;
            }
        };
        // Release-active backstop: a transport that ignores its cap must not
        // talk the engine past it (mirrors the WASM bridge's `send_capped`).
        if bytes.len() > MAX_RECORD_BYTES {
            scan.failures.push((endpoint, EndpointFailure::OverCap));
            continue;
        }
        let Ok(record) = IpnsRecord::unmarshal(&bytes) else {
            scan.failures.push((endpoint, EndpointFailure::Malformed));
            continue;
        };
        let Ok(verified) = record.verify(name) else {
            scan.failures.push((endpoint, EndpointFailure::Unverified));
            continue;
        };
        match &scan.best {
            Some((current, _)) if verified.sequence == current.sequence => {
                let seen =
                    |bytes: &[u8]| signed_data(name, bytes).as_deref() == Some(&verified.data[..]);
                if verified.data == current.data || scan.tied.iter().any(|tie| seen(tie)) {
                    continue;
                }
                if ranks_above(
                    (&verified.validity, &verified.data),
                    (&current.validity, &current.data),
                ) {
                    if let Some((_, displaced)) = scan.best.replace((verified, bytes)) {
                        scan.tied.push(displaced);
                    }
                } else {
                    scan.tied.push(bytes);
                }
            }
            Some((current, _)) if verified.sequence < current.sequence => {}
            _ => {
                scan.best = Some((verified, bytes));
                scan.tied.clear();
            }
        }
    }
    scan
}

/// The class of a failed GET. Only an endpoint that gave no answer about the
/// name is a [`EndpointFailure::Transport`] failure (ADR 0071 D2).
fn get_failure(error: &SeamError) -> EndpointFailure {
    if error.is_over_cap() {
        return EndpointFailure::OverCap;
    }
    match error.status() {
        None | Some(500..=599) => EndpointFailure::Transport,
        Some(_) => EndpointFailure::Status,
    }
}

/// The signed `data` of `record_bytes`, when it verifies under `name`.
fn signed_data(name: &IpnsName, record_bytes: &[u8]) -> Option<Vec<u8>> {
    verified(name, record_bytes).map(|record| record.data)
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use super::*;
    use crate::seams::{SeamError, SeamResult};
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryRecordStore;

    fn scan_of(vacant: usize, failures: usize) -> Scan {
        Scan {
            best: None,
            tied: Vec::new(),
            vacant,
            failures: (0..failures)
                .map(|at| {
                    (
                        EndpointId::new(format!("e{at}")),
                        EndpointFailure::Transport,
                    )
                })
                .collect(),
        }
    }

    /// Under the unanimous rule, only every endpoint answering "no record" is
    /// an absence: one failure, or no endpoint at all, is not.
    #[test]
    fn the_unanimous_rule_needs_every_endpoint_to_answer_no_record() {
        assert!(!scan_of(1, 1).absent(VacancyRule::Unanimous), "one failure");
        assert!(
            scan_of(2, 0).absent(VacancyRule::Unanimous),
            "every endpoint"
        );
        assert!(!scan_of(0, 0).absent(VacancyRule::Unanimous), "no endpoint");
    }

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

    /// A renewal signs one day short of a real write's EOL, so at one sequence
    /// the real write is the one every reader takes, on whichever endpoint it
    /// sits (ADR 0061 D3 step 7).
    #[test]
    fn at_one_sequence_the_later_eol_wins_on_any_endpoint() {
        use crate::net::eol::{eol_from, renewal_eol_from};
        use crate::seams::UnixMillis;

        let signer = Ed25519Signer::from_seed([3u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let now = UnixMillis(5_000_000);
        let renewal =
            IpnsRecord::create_v2(&signer, b"/ipfs/renewed", 4, 1, &renewal_eol_from(now))
                .marshal();
        let write =
            IpnsRecord::create_v2(&signer, b"/ipfs/written", 4, 1, &eol_from(now)).marshal();
        for order in [[&renewal, &write], [&write, &renewal]] {
            let eps = vec![EndpointId::new("a"), EndpointId::new("b")];
            let store = InMemoryRecordStore::new(eps.clone());
            store.seed_record(&eps[0], name.as_str(), order[0].clone());
            store.seed_record(&eps[1], name.as_str(), order[1].clone());

            let (_, best, tied) = block_on(fanout_get_tied(&store, &name)).expect("a record");
            assert_eq!(best, write, "the real write wins the tie");
            assert_eq!(
                tied,
                vec![renewal.clone()],
                "the renewal is the tied record"
            );
        }
    }

    /// At one sequence and one EOL, every reader takes the record with the
    /// higher signed `data`, whatever endpoint serves it (ADR 0066 D2).
    #[test]
    fn at_one_sequence_and_one_eol_the_higher_signed_data_wins_on_any_endpoint() {
        use crate::net::eol::eol_from;
        use crate::seams::UnixMillis;

        let signer = Ed25519Signer::from_seed([3u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let eol = eol_from(UnixMillis(5_000_000));
        let mut records = [
            IpnsRecord::create_v2(&signer, b"/ipfs/one", 4, 1, &eol).marshal(),
            IpnsRecord::create_v2(&signer, b"/ipfs/two", 4, 1, &eol).marshal(),
        ];
        records.sort_by_key(|record| signed_data(&name, record));
        let [lower, higher] = records;
        for order in [[&lower, &higher], [&higher, &lower]] {
            let eps = vec![EndpointId::new("a"), EndpointId::new("b")];
            let store = InMemoryRecordStore::new(eps.clone());
            store.seed_record(&eps[0], name.as_str(), order[0].clone());
            store.seed_record(&eps[1], name.as_str(), order[1].clone());

            let (_, best, tied) = block_on(fanout_get_tied(&store, &name)).expect("a record");
            assert_eq!(best, higher, "the higher signed data wins the tie");
            assert_eq!(tied, vec![lower.clone()]);
        }
    }

    /// A copy of the record with an unsigned field added carries the same
    /// signed `data`: it is the same record, not a tie, on either endpoint.
    #[test]
    fn a_copy_with_an_unsigned_field_added_is_the_same_record() {
        let signer = Ed25519Signer::from_seed([3u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let record =
            IpnsRecord::create_v2(&signer, b"/ipfs/one", 4, 1, "2099-01-01T00:00:00Z").marshal();
        let copy = crate::net::fork::with_unsigned_field(&record);
        assert_ne!(copy, record);

        for order in [[&record, &copy], [&copy, &record]] {
            let eps = vec![EndpointId::new("a"), EndpointId::new("b")];
            let store = InMemoryRecordStore::new(eps.clone());
            store.seed_record(&eps[0], name.as_str(), order[0].clone());
            store.seed_record(&eps[1], name.as_str(), order[1].clone());

            let (best, _, tied) = block_on(fanout_get_tied(&store, &name)).expect("a record");
            assert_eq!(Some(best.data), signed_data(&name, &record));
            assert!(tied.is_empty());
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

    /// ADR 0071 D2: a "no record" answer is an answer, and only a transport
    /// failure is an endpoint that failed.
    #[test]
    fn only_a_transport_failure_beside_a_pick_is_a_failed_endpoint() {
        use crate::net::eol::eol_from;
        use crate::seams::UnixMillis;

        let signer = Ed25519Signer::from_seed([4u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let record = IpnsRecord::create_v2(
            &signer,
            b"/ipfs/old",
            2,
            1,
            &eol_from(UnixMillis(5_000_000)),
        )
        .marshal();
        let eps = vec![EndpointId::new("lagging"), EndpointId::new("other")];
        let store = InMemoryRecordStore::new(eps.clone());
        store.seed_record(&eps[0], name.as_str(), record);

        let fetch = block_on(fanout_get_tied_classified(&store, &name));
        assert!(fetch.pick.is_some());
        assert!(!fetch.endpoint_failed, "a 404 is an answer");

        for (status, failed) in [(403, false), (429, false), (500, true), (503, true)] {
            store.answer_get_at(&eps[1], status);
            let fetch = block_on(fanout_get_tied_classified(&store, &name));
            assert!(fetch.pick.is_some());
            assert_eq!(fetch.endpoint_failed, failed, "status {status}");
        }

        store.heal_endpoint(&eps[1]);
        store.fail_endpoint(&eps[1]);
        let fetch = block_on(fanout_get_tied_classified(&store, &name));
        assert!(fetch.pick.is_some());
        assert!(fetch.endpoint_failed, "no answer at all");
    }

    #[test]
    fn a_seam_over_cap_body_is_an_answer() {
        assert_eq!(
            get_failure(&SeamError::over_cap("too large")),
            EndpointFailure::OverCap
        );
        assert_eq!(
            get_failure(&SeamError::new("offline")),
            EndpointFailure::Transport
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

    /// ADR 0060 D1: a 4xx is a stated refusal, and every other failure is an
    /// unknown outcome, a status the engine cannot place included.
    #[test]
    fn only_a_4xx_answer_is_a_stated_refusal() {
        assert_eq!(PutOutcome::of(&Ok(())), PutOutcome::Accepted);
        for status in [400, 404, 408, 429, 499] {
            assert_eq!(
                PutOutcome::of(&Err(SeamError::http_status("answer", status))),
                PutOutcome::Refused,
                "{status}",
            );
        }
        for status in [100, 200, 302, 399, 500, 502, 504, 599, 600, 0] {
            assert_eq!(
                PutOutcome::of(&Err(SeamError::http_status("answer", status))),
                PutOutcome::Unknown,
                "{status}",
            );
        }
        assert_eq!(
            PutOutcome::of(&Err(SeamError::new("no answer"))),
            PutOutcome::Unknown,
        );
    }

    /// ADR 0060 D2: only a refusal at every endpoint is `all_refused`.
    #[test]
    fn a_put_is_all_refused_only_when_every_endpoint_refused_it() {
        let eps = vec![EndpointId::new("front"), EndpointId::new("public")];
        let key = "k51-put";
        let run = |answers: [Option<u16>; 2], down: bool| {
            let store = InMemoryRecordStore::new(eps.clone());
            for (endpoint, answer) in eps.iter().zip(answers) {
                if let Some(status) = answer {
                    store.answer_put_for_at(endpoint, key, status);
                }
            }
            if down {
                store.fail_endpoint(&eps[1]);
            }
            block_on(fanout_put(&store, key, b"record"))
        };

        let refused = run([Some(400), Some(403)], false);
        assert!(refused.all_refused && !refused.any_acked());
        for (answers, down) in [
            ([Some(400), Some(503)], false),
            ([Some(400), None], true),
            ([Some(400), None], false),
        ] {
            let fanout = run(answers, down);
            assert!(!fanout.all_refused, "{answers:?} down={down}");
        }
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
