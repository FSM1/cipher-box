//! The fake API's per-name registration query (`GET /registry/names/:ipnsName`,
//! ADR 0022 D1), served as a standing route beside the mailbox so it spends no
//! scripted HTTP entry.

use std::sync::{Arc, Mutex};

use crate::seams::{HttpMethod, HttpRequest, HttpResponse, SeamResult};

const NAMES_PATH: &str = "/registry/names/";

/// A scripted `(status, body)`.
type Reply = (u16, Vec<u8>);

/// The registry's answer to every registration query on one device. Unscripted,
/// it answers 503: a registry outage, which keeps the unanimity rule.
#[derive(Clone, Default)]
pub struct InMemoryNameRegistry {
    reply: Arc<Mutex<Option<Reply>>>,
    queries: Arc<Mutex<Vec<String>>>,
}

impl InMemoryNameRegistry {
    /// Answer every query with `status` and `body` verbatim. Only
    /// `200 {"registered": <bool>}` is the registry's answer.
    pub fn reply(&self, status: u16, body: Vec<u8>) {
        *self.reply.lock().expect("lock") = Some((status, body));
    }

    /// Every name a query asked about, in order.
    pub fn queries(&self) -> Vec<String> {
        self.queries.lock().expect("lock").clone()
    }

    /// Answer `request` when it is a registration query, else `None`.
    pub fn serve(&self, request: &HttpRequest) -> Option<SeamResult<HttpResponse>> {
        if request.method != HttpMethod::Get {
            return None;
        }
        let name = request.url.split_once(NAMES_PATH)?.1;
        self.queries.lock().expect("lock").push(name.to_owned());
        let (status, body) = self
            .reply
            .lock()
            .expect("lock")
            .clone()
            .unwrap_or((503, Vec::new()));
        Some(Ok(HttpResponse {
            status,
            headers: Vec::new(),
            body,
        }))
    }
}
