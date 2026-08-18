//! A canned-response [`Http`] seam for the scenario tests.
//!
//! `Http` is a seam, so the scenario bodies — the call sequence they issue and
//! the targets they retire — are assertable without a live stack.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use cipherbox_engine::seams::{Http, HttpMethod, HttpRequest, HttpResponse, SeamResult};

/// One request the harness issued, keyed the way a test wants to read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Call {
    pub(crate) method: HttpMethod,
    pub(crate) path: String,
    pub(crate) body: Vec<u8>,
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    /// Paths answered 429 instead of their canned response.
    throttled: HashSet<String>,
    next_message_id: u64,
}

/// A stub API and gateway. Cheap to clone; clones share one recording.
#[derive(Clone, Default)]
pub(crate) struct StubHttp {
    state: Rc<RefCell<State>>,
}

impl StubHttp {
    /// Answer every request for `path` with 429, the one failure a load run
    /// files apart from an outright failure.
    pub(crate) fn throttle(&self, path: &str) {
        self.state.borrow_mut().throttled.insert(path.to_owned());
    }

    /// Every call so far, in send order.
    pub(crate) fn calls(&self) -> Vec<Call> {
        self.state.borrow().calls.clone()
    }

    /// Every call so far, clearing the recording — so a test can discard the
    /// provisioning traffic before driving a scenario.
    pub(crate) fn take_calls(&self) -> Vec<Call> {
        std::mem::take(&mut self.state.borrow_mut().calls)
    }

    /// The paths of every call so far, in send order.
    pub(crate) fn paths(&self) -> Vec<String> {
        self.calls().into_iter().map(|call| call.path).collect()
    }

    /// Every target named in a `/registry/retire` body, in retire order.
    pub(crate) fn retired(&self) -> Vec<String> {
        self.calls()
            .iter()
            .filter(|call| call.path == "/registry/retire")
            .flat_map(|call| {
                serde_json::from_slice::<Vec<String>>(&call.body)
                    .expect("retire body is a JSON array of targets")
            })
            .collect()
    }
}

/// The path portion of an absolute URL, query string included.
fn path_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    match rest.find('/') {
        Some(index) => rest[index..].to_owned(),
        None => "/".to_owned(),
    }
}

fn json(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: body.as_bytes().to_vec(),
    }
}

fn empty(status: u16) -> HttpResponse {
    HttpResponse {
        status,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

impl Http for StubHttp {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let path = path_of(&request.url);
        let body = request.body.unwrap_or_default();
        let mut state = self.state.borrow_mut();
        state.calls.push(Call {
            method: request.method,
            path: path.clone(),
            body: body.clone(),
        });
        if state.throttled.contains(&path) {
            return Ok(json(
                429,
                r#"{"statusCode":429,"message":"Too Many Requests"}"#,
            ));
        }

        let response = match (request.method, path.as_str()) {
            (HttpMethod::Post, "/auth/test-login") => json(
                201,
                r#"{"accessToken":"stub-access","refreshToken":"stub-refresh","isNewUser":true,"publicKey":"stub-public-key","privateKey":"00"}"#,
            ),
            (HttpMethod::Post, "/content/upload") => {
                json(201, &format!(r#"{{"cid":"stub","size":{}}}"#, body.len()))
            }
            (HttpMethod::Post, "/registry/register") => empty(201),
            (HttpMethod::Post, "/registry/retire") => {
                let retired =
                    serde_json::from_slice::<Vec<String>>(&body).map_or(0, |targets| targets.len());
                json(200, &format!(r#"{{"retired":{retired},"unpinned":0}}"#))
            }
            (HttpMethod::Get, "/account/quota") => json(
                200,
                r#"{"usedBytes":0,"limitBytes":1073741824,"advisory":false}"#,
            ),
            (HttpMethod::Patch, "/account/byo") => empty(200),
            (HttpMethod::Delete, "/account") => empty(200),
            (HttpMethod::Post, "/mailbox/messages") => {
                state.next_message_id += 1;
                json(201, &format!(r#"{{"id":"msg-{}"}}"#, state.next_message_id))
            }
            (HttpMethod::Get, "/mailbox/messages") => json(200, r#"{"messages":[]}"#),
            (HttpMethod::Delete, path) if path.starts_with("/mailbox/messages/") => empty(200),
            (HttpMethod::Get, path) if path.starts_with("/ipfs/") => HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: vec![0u8; 64],
            },
            _ => json(404, r#"{"statusCode":404,"message":"stub has no route"}"#),
        };
        Ok(response)
    }
}
