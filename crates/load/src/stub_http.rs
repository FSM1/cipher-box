//! A canned-response [`Http`] seam for the scenario tests.
//!
//! `Http` is a seam, so the scenario bodies — the call sequence they issue and
//! the targets they retire — are assertable without a live stack.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use cipherbox_engine::seams::{Http, HttpMethod, HttpRequest, HttpResponse, SeamResult};

/// One request the harness issued, keyed the way a test wants to read it.
#[derive(Debug, Clone)]
pub(crate) struct Call {
    pub(crate) method: HttpMethod,
    pub(crate) path: String,
    pub(crate) body: Vec<u8>,
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    throttled: HashSet<String>,
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

    /// Drop the recording, so a test can discard provisioning traffic before
    /// driving a scenario.
    pub(crate) fn clear_calls(&self) {
        self.state.borrow_mut().calls.clear();
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.state.borrow().calls.clone()
    }

    pub(crate) fn paths(&self) -> Vec<String> {
        self.state
            .borrow()
            .calls
            .iter()
            .map(|call| call.path.clone())
            .collect()
    }

    pub(crate) fn bodies_for(&self, path: &str) -> Vec<Vec<u8>> {
        self.state
            .borrow()
            .calls
            .iter()
            .filter(|call| call.path == path)
            .map(|call| call.body.clone())
            .collect()
    }

    pub(crate) fn registered_names(&self) -> Vec<String> {
        self.registrations()
            .map(|entry| entry["ipnsName"].as_str().expect("ipnsName").to_owned())
            .collect()
    }

    /// Exactly the set a scenario owes the registry back: every name it
    /// registered plus every content CID under it.
    pub(crate) fn registered_targets(&self) -> Vec<String> {
        self.registrations()
            .flat_map(|entry| {
                let mut targets = vec![entry["ipnsName"].as_str().expect("ipnsName").to_owned()];
                targets.extend(
                    entry["contentCids"]
                        .as_array()
                        .expect("contentCids")
                        .iter()
                        .map(|cid| cid.as_str().expect("a cid").to_owned()),
                );
                targets
            })
            .collect()
    }

    fn registrations(&self) -> impl Iterator<Item = serde_json::Value> {
        self.bodies_for("/registry/register")
            .into_iter()
            .flat_map(|body| {
                serde_json::from_slice::<Vec<serde_json::Value>>(&body)
                    .expect("a register body is a JSON array of registrations")
            })
    }

    pub(crate) fn retired(&self) -> Vec<String> {
        self.bodies_for("/registry/retire")
            .iter()
            .flat_map(|body| {
                serde_json::from_slice::<Vec<String>>(body)
                    .expect("a retire body is a JSON array of targets")
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

fn route(method: HttpMethod, path: &str, body: &[u8]) -> HttpResponse {
    match (method, path) {
        (HttpMethod::Post, "/auth/test-login") => json(
            201,
            r#"{"accessToken":"stub-access","refreshToken":"stub-refresh","acceleratorToken":"stub-gateway","isNewUser":true,"publicKey":"stub-public-key","privateKey":"00"}"#,
        ),
        (HttpMethod::Post, "/content/upload") => {
            json(201, &format!(r#"{{"cid":"stub","size":{}}}"#, body.len()))
        }
        (HttpMethod::Post, "/registry/register") => empty(201),
        (HttpMethod::Post, "/registry/retire") => {
            let retired = serde_json::from_slice::<Vec<String>>(body).map_or(0, |t| t.len());
            json(200, &format!(r#"{{"retired":{retired},"unpinned":0}}"#))
        }
        (HttpMethod::Get, "/account/quota") => json(
            200,
            r#"{"usedBytes":0,"limitBytes":1073741824,"advisory":false}"#,
        ),
        (HttpMethod::Patch, "/account/byo") => empty(200),
        (HttpMethod::Post, "/mailbox/messages") => json(201, r#"{"id":"msg-1"}"#),
        (HttpMethod::Get, "/mailbox/messages") => json(200, r#"{"messages":[]}"#),
        (HttpMethod::Delete, path) if path.starts_with("/mailbox/messages/") => empty(200),
        (HttpMethod::Get, path) if path.starts_with("/ipfs/") => HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: vec![0u8; 64],
        },
        _ => json(404, r#"{"statusCode":404,"message":"stub has no route"}"#),
    }
}

impl Http for StubHttp {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let path = path_of(&request.url);
        let body = request.body.unwrap_or_default();
        let throttled = self.state.borrow().throttled.contains(&path);
        let response = if throttled {
            json(429, r#"{"statusCode":429,"message":"Too Many Requests"}"#)
        } else {
            route(request.method, &path, &body)
        };
        self.state.borrow_mut().calls.push(Call {
            method: request.method,
            path,
            body,
        });
        Ok(response)
    }
}
