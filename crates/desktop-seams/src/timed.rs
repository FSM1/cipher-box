//! A transport seam that reports each request slower than a threshold, for the
//! headless e2e host's diagnostics.
//!
//! The privacy rule for that log: a report names the request kind, the endpoint
//! host, the duration and the outcome class. It never carries a path, a routing
//! key, a CID, a header or an error message, because each of those can carry a
//! name or a token.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cipherbox_engine::seams::{
    CappedFetchError, EndpointId, Http, HttpRequest, HttpResponse, RecordTransport, SeamError,
    SeamResult,
};

/// The host a report names when the URL does not parse.
const UNPARSED: &str = "unparsed";

/// One request that took at least the threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowRequest {
    /// `record-get`, `record-put`, `http` or `http-capped`.
    pub kind: &'static str,
    /// The endpoint host as the URL parser reads it, or `unparsed`.
    pub host: String,
    /// How long the request took.
    pub millis: u64,
    /// `ok`, `absent`, `status <code>`, `over-cap` or `error`.
    pub outcome: String,
}

/// Where a [`Timed`] seam sends its reports.
pub type SlowRequestSink = Arc<dyn Fn(&SlowRequest) + Send + Sync>;

/// `inner`, with every request that takes `threshold` or more reported.
#[derive(Clone)]
pub struct Timed<S> {
    inner: S,
    threshold: Duration,
    report: SlowRequestSink,
}

impl<S> Timed<S> {
    /// Wraps `inner`.
    pub fn new(inner: S, threshold: Duration, report: SlowRequestSink) -> Self {
        Self {
            inner,
            threshold,
            report,
        }
    }

    async fn timed<R>(
        &self,
        kind: &'static str,
        url: &str,
        call: impl Future<Output = R>,
        outcome: impl FnOnce(&R) -> String,
    ) -> R {
        let started = Instant::now();
        let result = call.await;
        let elapsed = started.elapsed();
        if elapsed >= self.threshold {
            (self.report)(&SlowRequest {
                kind,
                host: host_of(url),
                millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                outcome: outcome(&result),
            });
        }
        result
    }
}

/// The host of `url` as `reqwest` would reach it: a backslash ends the host,
/// and an IPv6 host keeps its brackets.
fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| UNPARSED.to_owned())
}

fn status_class(status: u16) -> String {
    if (200..300).contains(&status) {
        "ok".to_owned()
    } else {
        format!("status {status}")
    }
}

fn error_class(error: &SeamError) -> String {
    if error.is_over_cap() {
        return "over-cap".to_owned();
    }
    error
        .status()
        .map_or_else(|| "error".to_owned(), status_class)
}

impl<S: RecordTransport> RecordTransport for Timed<S> {
    fn endpoints(&self) -> Vec<EndpointId> {
        self.inner.endpoints()
    }

    fn accelerator(&self) -> Option<EndpointId> {
        self.inner.accelerator()
    }

    async fn get_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        max_bytes: usize,
        bearer: Option<&str>,
    ) -> SeamResult<Option<Vec<u8>>> {
        self.timed(
            "record-get",
            &endpoint.0,
            self.inner
                .get_record(endpoint, routing_key, max_bytes, bearer),
            |got| match got {
                Ok(Some(_)) => "ok".to_owned(),
                Ok(None) => "absent".to_owned(),
                Err(error) => error_class(error),
            },
        )
        .await
    }

    async fn put_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        record: &[u8],
    ) -> SeamResult<()> {
        self.timed(
            "record-put",
            &endpoint.0,
            self.inner.put_record(endpoint, routing_key, record),
            |put| match put {
                Ok(()) => "ok".to_owned(),
                Err(error) => error_class(error),
            },
        )
        .await
    }
}

impl<S: Http> Http for Timed<S> {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let url = request.url.clone();
        self.timed("http", &url, self.inner.send(request), |sent| match sent {
            Ok(response) => status_class(response.status),
            Err(error) => error_class(error),
        })
        .await
    }

    async fn send_capped(
        &self,
        request: HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, CappedFetchError> {
        let url = request.url.clone();
        self.timed(
            "http-capped",
            &url,
            self.inner.send_capped(request, max_bytes),
            |sent| match sent {
                Ok(response) => status_class(response.status),
                Err(CappedFetchError::BodyTooLarge { .. }) => "over-cap".to_owned(),
                Err(CappedFetchError::Transport(error)) => error_class(error),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use cipherbox_engine::seams::{HttpCredentials, HttpMethod};
    use cipherbox_engine::testkit::block_on;
    use zeroize::Zeroizing;

    use super::*;

    const ROUTING_KEY: &str = "k51qzi5uqu5dsecretroutingkey";
    const BEARER: &str = "pseudonym-token";
    const CID: &str = "bafkreisecretcid";
    const ACCELERATOR: &str = "https://routing.test";

    /// Which fixed answer [`Canned`] gives. Each error message holds every
    /// planted secret.
    #[derive(Clone, Copy)]
    enum Answer {
        /// A status, or an error with no status.
        Refuse,
        /// A body over the cap.
        OverCap,
        /// A capped fetch that failed in transport.
        Transport,
        /// Each call succeeds; a record GET serves a record.
        Serve,
        /// A record GET finds no record.
        Vacant,
    }

    /// Answers each call at once with its [`Answer`].
    #[derive(Clone)]
    struct Canned {
        answer: Answer,
    }

    fn planted() -> String {
        format!("failed for {ROUTING_KEY} under {BEARER} at {CID}")
    }

    impl RecordTransport for Canned {
        fn endpoints(&self) -> Vec<EndpointId> {
            vec![EndpointId::new("https://user:pw@delegated.test:8443/base")]
        }

        fn accelerator(&self) -> Option<EndpointId> {
            Some(EndpointId::new(ACCELERATOR))
        }

        async fn get_record(
            &self,
            _endpoint: &EndpointId,
            _routing_key: &str,
            _max_bytes: usize,
            _bearer: Option<&str>,
        ) -> SeamResult<Option<Vec<u8>>> {
            match self.answer {
                Answer::Refuse | Answer::Transport => Err(SeamError::http_status(planted(), 429)),
                Answer::OverCap => Err(SeamError::over_cap(planted())),
                Answer::Serve => Ok(Some(planted().into_bytes())),
                Answer::Vacant => Ok(None),
            }
        }

        async fn put_record(
            &self,
            _endpoint: &EndpointId,
            _routing_key: &str,
            _record: &[u8],
        ) -> SeamResult<()> {
            match self.answer {
                Answer::Serve => Ok(()),
                _ => Err(SeamError::new(planted())),
            }
        }
    }

    impl Http for Canned {
        async fn send(&self, _request: HttpRequest) -> SeamResult<HttpResponse> {
            match self.answer {
                Answer::Serve => Ok(answered(200)),
                _ => Err(SeamError::new(planted())),
            }
        }

        async fn send_capped(
            &self,
            _request: HttpRequest,
            max_bytes: usize,
        ) -> Result<HttpResponse, CappedFetchError> {
            match self.answer {
                Answer::OverCap => Err(CappedFetchError::BodyTooLarge {
                    observed: max_bytes + 1,
                    limit: max_bytes,
                }),
                Answer::Transport => Err(CappedFetchError::Transport(SeamError::new(planted()))),
                Answer::Serve => Ok(answered(200)),
                Answer::Refuse | Answer::Vacant => Ok(answered(404)),
            }
        }
    }

    fn answered(status: u16) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("Set-Cookie".to_owned(), planted())],
            body: Zeroizing::new(planted().into_bytes()),
        }
    }

    fn collecting(
        threshold: Duration,
        answer: Answer,
    ) -> (Timed<Canned>, Arc<Mutex<Vec<SlowRequest>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let timed = Timed::new(
            Canned { answer },
            threshold,
            Arc::new(move |slow: &SlowRequest| sink.lock().unwrap().push(slow.clone())),
        );
        (timed, seen)
    }

    fn request_to(url: String) -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            url,
            headers: vec![(
                "Authorization".to_owned(),
                Zeroizing::new(format!("Bearer {BEARER}")),
            )],
            body: None,
            credentials: HttpCredentials::Omit,
            timeout_ms: None,
        }
    }

    fn report(kind: &'static str, host: &str, outcome: &str) -> SlowRequest {
        SlowRequest {
            kind,
            host: host.to_owned(),
            millis: 0,
            outcome: outcome.to_owned(),
        }
    }

    /// The reports with their durations set to zero: a canned answer takes no
    /// measurable time, and the duration is not what these tests prove.
    fn reports(seen: &Mutex<Vec<SlowRequest>>) -> Vec<SlowRequest> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|slow| {
                assert!(slow.millis < 60_000, "a canned answer took {}", slow.millis);
                SlowRequest {
                    millis: 0,
                    ..slow.clone()
                }
            })
            .collect()
    }

    fn carries_no_secret(seen: &[SlowRequest]) {
        let text = format!("{seen:?}");
        for secret in [
            ROUTING_KEY,
            BEARER,
            CID,
            "user",
            "pw",
            "/base",
            "8443",
            "ipfs",
        ] {
            assert!(!text.contains(secret), "a report carries {secret:?}");
        }
    }

    #[test]
    fn each_slow_request_reports_its_kind_host_and_outcome_and_nothing_it_addressed() {
        let (timed, seen) = collecting(Duration::ZERO, Answer::Refuse);
        let endpoint = timed.endpoints().remove(0);
        let _ = block_on(timed.get_record(&endpoint, ROUTING_KEY, 1024, Some(BEARER)));
        let _ = block_on(timed.put_record(&endpoint, ROUTING_KEY, b"record"));
        let _ = block_on(timed.send(request_to(format!(
            "https://[2001:db8::1]:8443/ipfs/{CID}?token={BEARER}"
        ))));
        let _ = block_on(timed.send_capped(
            request_to(format!("https://gateway.test/ipfs/{CID}#{BEARER}")),
            1024,
        ));

        let seen = reports(&seen);
        assert_eq!(
            seen,
            [
                report("record-get", "delegated.test", "status 429"),
                report("record-put", "delegated.test", "error"),
                report("http", "[2001:db8::1]", "error"),
                report("http-capped", "gateway.test", "status 404"),
            ]
        );
        carries_no_secret(&seen);
    }

    #[test]
    fn a_backslash_path_or_an_unparsed_url_reports_no_part_of_the_path() {
        let (timed, seen) = collecting(Duration::ZERO, Answer::OverCap);
        let _ = block_on(timed.send_capped(
            request_to(format!("https://gateway.test\\ipfs\\{CID}")),
            1024,
        ));
        let _ = block_on(timed.send(request_to(format!("gateway.test/ipfs/{CID}"))));

        let seen = reports(&seen);
        assert_eq!(
            seen,
            [
                report("http-capped", "gateway.test", "over-cap"),
                report("http", UNPARSED, "error"),
            ]
        );
        carries_no_secret(&seen);
    }

    #[test]
    fn every_other_outcome_class_reports_its_class_and_no_planted_secret() {
        let mut seen = Vec::new();
        for answer in [
            Answer::OverCap,
            Answer::Transport,
            Answer::Serve,
            Answer::Vacant,
        ] {
            let (timed, reported) = collecting(Duration::ZERO, answer);
            let endpoint = timed.endpoints().remove(0);
            let _ = block_on(timed.get_record(&endpoint, ROUTING_KEY, 1024, Some(BEARER)));
            let _ = block_on(
                timed.send_capped(request_to(format!("https://gateway.test/ipfs/{CID}")), 1024),
            );
            seen.extend(reports(&reported));
        }

        assert_eq!(
            seen,
            [
                report("record-get", "delegated.test", "over-cap"),
                report("http-capped", "gateway.test", "over-cap"),
                report("record-get", "delegated.test", "status 429"),
                report("http-capped", "gateway.test", "error"),
                report("record-get", "delegated.test", "ok"),
                report("http-capped", "gateway.test", "ok"),
                report("record-get", "delegated.test", "absent"),
                report("http-capped", "gateway.test", "status 404"),
            ]
        );
        carries_no_secret(&seen);
    }

    #[test]
    fn the_wrapper_forwards_the_accelerator() {
        let (timed, _seen) = collecting(Duration::ZERO, Answer::Refuse);
        assert_eq!(timed.accelerator(), Some(EndpointId::new(ACCELERATOR)));
    }

    #[test]
    fn a_request_under_the_threshold_reports_nothing() {
        let (timed, seen) = collecting(Duration::from_secs(3600), Answer::Refuse);
        let endpoint = timed.endpoints().remove(0);
        let _ = block_on(timed.get_record(&endpoint, ROUTING_KEY, 1024, None));
        let _ = block_on(timed.put_record(&endpoint, ROUTING_KEY, b"record"));
        let _ = block_on(timed.send(request_to(format!("https://gateway.test/ipfs/{CID}"))));

        assert!(seen.lock().unwrap().is_empty());
    }
}
