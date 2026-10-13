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

    fn observe(
        &self,
        kind: &'static str,
        url: &str,
        started: Instant,
        outcome: impl FnOnce() -> String,
    ) {
        let elapsed = started.elapsed();
        if elapsed < self.threshold {
            return;
        }
        (self.report)(&SlowRequest {
            kind,
            host: host_of(url),
            millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            outcome: outcome(),
        });
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
        let started = Instant::now();
        let got = self
            .inner
            .get_record(endpoint, routing_key, max_bytes, bearer)
            .await;
        self.observe("record-get", &endpoint.0, started, || match &got {
            Ok(Some(_)) => "ok".to_owned(),
            Ok(None) => "absent".to_owned(),
            Err(error) => error_class(error),
        });
        got
    }

    async fn put_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        record: &[u8],
    ) -> SeamResult<()> {
        let started = Instant::now();
        let put = self.inner.put_record(endpoint, routing_key, record).await;
        self.observe("record-put", &endpoint.0, started, || match &put {
            Ok(()) => "ok".to_owned(),
            Err(error) => error_class(error),
        });
        put
    }
}

impl<S: Http> Http for Timed<S> {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let url = request.url.clone();
        let started = Instant::now();
        let sent = self.inner.send(request).await;
        self.observe("http", &url, started, || match &sent {
            Ok(response) => status_class(response.status),
            Err(error) => error_class(error),
        });
        sent
    }

    async fn send_capped(
        &self,
        request: HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, CappedFetchError> {
        let url = request.url.clone();
        let started = Instant::now();
        let sent = self.inner.send_capped(request, max_bytes).await;
        self.observe("http-capped", &url, started, || match &sent {
            Ok(response) => status_class(response.status),
            Err(CappedFetchError::BodyTooLarge { .. }) => "over-cap".to_owned(),
            Err(CappedFetchError::Transport(error)) => error_class(error),
        });
        sent
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use cipherbox_engine::seams::{HttpCredentials, HttpMethod};
    use zeroize::Zeroizing;

    use super::*;

    const ROUTING_KEY: &str = "k51qzi5uqu5dsecretroutingkey";
    const BEARER: &str = "pseudonym-token";
    const CID: &str = "bafkreisecretcid";
    const ACCELERATOR: &str = "https://routing.test";

    /// Answers each call at once with a fixed result whose error message holds
    /// every planted secret.
    #[derive(Clone)]
    struct Canned {
        capped_over_cap: bool,
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
            Err(SeamError::http_status(planted(), 429))
        }

        async fn put_record(
            &self,
            _endpoint: &EndpointId,
            _routing_key: &str,
            _record: &[u8],
        ) -> SeamResult<()> {
            Err(SeamError::new(planted()))
        }
    }

    impl Http for Canned {
        async fn send(&self, _request: HttpRequest) -> SeamResult<HttpResponse> {
            Err(SeamError::new(planted()))
        }

        async fn send_capped(
            &self,
            _request: HttpRequest,
            max_bytes: usize,
        ) -> Result<HttpResponse, CappedFetchError> {
            if self.capped_over_cap {
                return Err(CappedFetchError::BodyTooLarge {
                    observed: max_bytes + 1,
                    limit: max_bytes,
                });
            }
            Ok(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Zeroizing::new(Vec::new()),
            })
        }
    }

    fn collecting(
        threshold: Duration,
        capped_over_cap: bool,
    ) -> (Timed<Canned>, Arc<Mutex<Vec<SlowRequest>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let timed = Timed::new(
            Canned { capped_over_cap },
            threshold,
            Arc::new(move |slow: &SlowRequest| sink.lock().unwrap().push(slow.clone())),
        );
        (timed, seen)
    }

    fn run<F: core::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime")
            .block_on(future)
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
        let (timed, seen) = collecting(Duration::ZERO, false);
        let endpoint = timed.endpoints().remove(0);
        let _ = run(timed.get_record(&endpoint, ROUTING_KEY, 1024, Some(BEARER)));
        let _ = run(timed.put_record(&endpoint, ROUTING_KEY, b"record"));
        let _ = run(timed.send(request_to(format!(
            "https://[2001:db8::1]:8443/ipfs/{CID}?token={BEARER}"
        ))));
        let _ = run(timed.send_capped(
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
        let (timed, seen) = collecting(Duration::ZERO, true);
        let _ = run(timed.send_capped(
            request_to(format!("https://gateway.test\\ipfs\\{CID}")),
            1024,
        ));
        let _ = run(timed.send(request_to(format!("gateway.test/ipfs/{CID}"))));

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
    fn the_wrapper_forwards_the_accelerator() {
        let (timed, _seen) = collecting(Duration::ZERO, false);
        assert_eq!(timed.accelerator(), Some(EndpointId::new(ACCELERATOR)));
    }

    #[test]
    fn a_request_under_the_threshold_reports_nothing() {
        let (timed, seen) = collecting(Duration::from_secs(3600), false);
        let endpoint = timed.endpoints().remove(0);
        let _ = run(timed.get_record(&endpoint, ROUTING_KEY, 1024, None));
        let _ = run(timed.put_record(&endpoint, ROUTING_KEY, b"record"));
        let _ = run(timed.send(request_to(format!("https://gateway.test/ipfs/{CID}"))));

        assert!(seen.lock().unwrap().is_empty());
    }
}
