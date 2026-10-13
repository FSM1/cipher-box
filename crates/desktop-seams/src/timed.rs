//! A transport seam that reports each request slower than a threshold, for the
//! headless e2e host's diagnostics.
//!
//! A report names the request kind, the endpoint host, the duration and the
//! outcome class. It never carries a path, a routing key, a CID, a header or
//! an error message, because each of those can carry a name or a token.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cipherbox_engine::seams::{
    CappedFetchError, EndpointId, Http, HttpRequest, HttpResponse, RecordTransport, SeamResult,
};

/// One request that took at least the threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowRequest {
    /// `record-get`, `record-put`, `http` or `http-capped`.
    pub kind: &'static str,
    /// The endpoint host, with no scheme, user info, port, path or query.
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
            host: host_of(url).to_owned(),
            millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            outcome: outcome(),
        });
    }
}

/// The host of `url`: past the scheme and any user info, before the port,
/// path, query or fragment.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host.split(':').next().unwrap_or_default()
}

fn status_class(status: u16) -> String {
    if (200..300).contains(&status) {
        "ok".to_owned()
    } else {
        format!("status {status}")
    }
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
            Err(error) => error
                .status()
                .map_or_else(|| "error".to_owned(), status_class),
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
            Err(error) => error
                .status()
                .map_or_else(|| "error".to_owned(), status_class),
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
            Err(_) => "error".to_owned(),
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
            Err(CappedFetchError::Transport(_)) => "error".to_owned(),
        });
        sent
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use cipherbox_engine::seams::{HttpCredentials, HttpMethod, SeamError};
    use zeroize::Zeroizing;

    use super::*;

    const ROUTING_KEY: &str = "k51qzi5uqu5dsecretroutingkey";
    const BEARER: &str = "pseudonym-token";

    /// Answers every request at once with a fixed result.
    #[derive(Clone)]
    struct Refusing;

    impl RecordTransport for Refusing {
        fn endpoints(&self) -> Vec<EndpointId> {
            vec![EndpointId::new("https://user:pw@delegated.test:8443/base")]
        }

        async fn get_record(
            &self,
            _endpoint: &EndpointId,
            _routing_key: &str,
            _max_bytes: usize,
            _bearer: Option<&str>,
        ) -> SeamResult<Option<Vec<u8>>> {
            Err(SeamError::http_status(
                format!("record_transport get: status 429 for {ROUTING_KEY}"),
                429,
            ))
        }

        async fn put_record(
            &self,
            _endpoint: &EndpointId,
            _routing_key: &str,
            _record: &[u8],
        ) -> SeamResult<()> {
            Ok(())
        }
    }

    impl Http for Refusing {
        async fn send(&self, _request: HttpRequest) -> SeamResult<HttpResponse> {
            Ok(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Zeroizing::new(Vec::new()),
            })
        }
    }

    fn collecting(threshold: Duration) -> (Timed<Refusing>, Arc<Mutex<Vec<SlowRequest>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let timed = Timed::new(
            Refusing,
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

    fn block_request() -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            url: format!("https://gateway.test/ipfs/bafkreisecretcid?format=raw#{BEARER}"),
            headers: vec![(
                "Authorization".to_owned(),
                Zeroizing::new(format!("Bearer {BEARER}")),
            )],
            body: None,
            credentials: HttpCredentials::Omit,
            timeout_ms: None,
        }
    }

    #[test]
    fn a_slow_request_reports_its_kind_host_and_outcome_and_nothing_it_addressed() {
        let (timed, seen) = collecting(Duration::ZERO);
        let endpoint = timed.endpoints().remove(0);
        let _ = run(timed.get_record(&endpoint, ROUTING_KEY, 1024, Some(BEARER)));
        let _ = run(timed.send_capped(block_request(), 1024));

        let seen = seen.lock().unwrap();
        let reported: Vec<(&str, &str, &str)> = seen
            .iter()
            .map(|slow| (slow.kind, slow.host.as_str(), slow.outcome.as_str()))
            .collect();
        assert_eq!(
            reported,
            [
                ("record-get", "delegated.test", "status 429"),
                ("http-capped", "gateway.test", "status 404"),
            ]
        );
        let text = format!("{seen:?}");
        for secret in [
            ROUTING_KEY,
            BEARER,
            "bafkreisecretcid",
            "user",
            "pw",
            "/base",
            "8443",
        ] {
            assert!(!text.contains(secret), "a report carries {secret:?}");
        }
    }

    #[test]
    fn a_request_under_the_threshold_reports_nothing() {
        let (timed, seen) = collecting(Duration::from_secs(3600));
        let endpoint = timed.endpoints().remove(0);
        let _ = run(timed.get_record(&endpoint, ROUTING_KEY, 1024, None));
        let _ = run(timed.put_record(&endpoint, ROUTING_KEY, b"record"));
        let _ = run(timed.send(block_request()));

        assert!(seen.lock().unwrap().is_empty());
    }
}
