//! Scripted [`Http`] fake.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::seams::{Http, HttpRequest, HttpResponse, SeamError, SeamResult};

/// A reply computed from the request it answers.
type DerivedReply = Box<dyn FnOnce(&HttpRequest) -> SeamResult<HttpResponse> + Send>;

/// A queued reply: either fixed bytes or a reply derived from the request.
enum Reply {
    Fixed(SeamResult<HttpResponse>),
    Derived(DerivedReply),
}

#[derive(Default)]
struct Inner {
    responses: VecDeque<Reply>,
    requests: Vec<HttpRequest>,
}

/// Scripted HTTP: responses are queued by the test and returned in order;
/// every request is recorded for assertion. An unscripted request is a
/// seam error — a test that hits the network unexpectedly should fail
/// loudly.
#[derive(Clone, Default)]
pub struct ScriptedHttp {
    inner: Arc<Mutex<Inner>>,
}

impl ScriptedHttp {
    /// Queues a successful response.
    pub fn enqueue_response(&self, response: HttpResponse) {
        self.enqueue(Reply::Fixed(Ok(response)));
    }

    /// Queues a transport-level failure.
    pub fn enqueue_error(&self, error: SeamError) {
        self.enqueue(Reply::Fixed(Err(error)));
    }

    /// Queues a reply computed from the request — for an endpoint whose answer
    /// is a function of what was sent (a content upload echoing the CID of the
    /// bytes it received, say).
    pub fn enqueue_derived(
        &self,
        reply: impl FnOnce(&HttpRequest) -> SeamResult<HttpResponse> + Send + 'static,
    ) {
        self.enqueue(Reply::Derived(Box::new(reply)));
    }

    fn enqueue(&self, reply: Reply) {
        self.inner.lock().expect("lock").responses.push_back(reply);
    }

    /// Every request sent so far, in order.
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.inner.lock().expect("lock").requests.clone()
    }
}

impl Http for ScriptedHttp {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let mut inner = self.inner.lock().expect("lock");
        let reply = inner.responses.pop_front();
        inner.requests.push(request);
        let request = inner.requests.last().expect("just pushed");
        match reply {
            Some(Reply::Fixed(response)) => response,
            Some(Reply::Derived(reply)) => reply(request),
            None => Err(SeamError::new("ScriptedHttp: no scripted response left")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::HttpMethod;
    use crate::testkit::block_on;

    fn request(url: &str) -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            url: url.to_owned(),
            headers: Vec::new(),
            body: None,
        }
    }

    #[test]
    fn returns_scripted_responses_in_order_and_records_requests() {
        let http = ScriptedHttp::default();
        http.enqueue_response(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"first".to_vec(),
        });

        let response = block_on(http.send(request("https://api.test/a"))).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"first");

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://api.test/a");
    }

    #[test]
    fn unscripted_request_fails_loudly() {
        let http = ScriptedHttp::default();
        assert!(block_on(http.send(request("https://api.test/oops"))).is_err());
    }

    #[test]
    fn send_capped_rejects_an_over_cap_body_and_admits_one_at_the_cap() {
        use crate::seams::CappedFetchError;

        let body = |len: usize| HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: vec![0u8; len],
        };
        let http = ScriptedHttp::default();
        http.enqueue_response(body(9)); // over the cap
        http.enqueue_response(body(8)); // exactly at the cap

        let err = block_on(http.send_capped(request("https://api.test/big"), 8)).unwrap_err();
        assert_eq!(
            err,
            CappedFetchError::BodyTooLarge {
                observed: 9,
                limit: 8
            }
        );
        let ok = block_on(http.send_capped(request("https://api.test/ok"), 8)).unwrap();
        assert_eq!(ok.body.len(), 8, "a body exactly at the cap is admitted");
    }
}
