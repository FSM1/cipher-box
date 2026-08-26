//! In-memory mailbox hub and per-recipient [`Mailbox`] fake.
//!
//! The hub doubles as the fake API's mailbox routes ([`InMemoryMailbox::serve`]),
//! because the engine reaches its inbox through its own API client: a device's
//! scripted HTTP answers `/mailbox/messages` from the same hub its handle reads,
//! so an engine's post and a test's out-of-band poll see one inbox.
//!
//! It serves the wire shape, not the JWT guard the real routes carry: that the
//! engine presents a bearer on every mailbox call is asserted where the token
//! lives (`api/client.rs`) and against the live API (the contract suite).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cipherbox_core::hex::lower as hex_lower;
use serde_json::{Value, json};

use crate::seams::{
    HttpMethod, HttpRequest, HttpResponse, Mailbox, MailboxItem, SeamError, SeamResult,
};

const MESSAGES_PATH: &str = "/mailbox/messages";

/// A fixed `receivedAt`: the fake serves the wire shape, not a clock.
const RECEIVED_AT: &str = "1970-01-01T00:00:00.000Z";

/// Inboxes are keyed by the recipient's lowercase-hex address — the spelling
/// the API routes on — so the seam handle and the HTTP route reach one queue.
#[derive(Default)]
struct HubInner {
    next_id: u64,
    queues: HashMap<String, Vec<MailboxItem>>,
    /// `(recipient, idempotency key)` → the id the first post assigned, so a
    /// replay answers with the original id the way the API does.
    seen_idempotency_keys: HashMap<(String, String), String>,
}

/// The shared mailbox "server": routes posts between recipients so N
/// engines in a scenario exchange sealed blobs through one hub.
#[derive(Clone, Default)]
pub struct InMemoryMailboxHub {
    inner: Arc<Mutex<HubInner>>,
}

impl InMemoryMailboxHub {
    /// A [`Mailbox`] seam handle bound to one recipient's inbox.
    pub fn mailbox_for(&self, recipient_public_key: &[u8]) -> InMemoryMailbox {
        InMemoryMailbox {
            hub: self.clone(),
            address: hex_lower(recipient_public_key),
            ack_failing: Arc::new(Mutex::new(false)),
        }
    }

    /// Route one sealed payload and answer the id the recipient will ack by.
    /// A replay of a `(recipient, idempotency key)` pair answers the original.
    fn post_item(&self, address: &str, sealed_payload: &[u8], key: &str) -> String {
        let mut inner = self.inner.lock().expect("lock");
        let dedupe_key = (address.to_owned(), key.to_owned());
        if let Some(id) = inner.seen_idempotency_keys.get(&dedupe_key) {
            return id.clone();
        }
        inner.next_id += 1;
        let item_id = format!("item-{}", inner.next_id);
        inner
            .seen_idempotency_keys
            .insert(dedupe_key, item_id.clone());
        inner
            .queues
            .entry(address.to_owned())
            .or_default()
            .push(MailboxItem {
                item_id: item_id.clone(),
                sealed_payload: sealed_payload.to_vec(),
            });
        item_id
    }
}

/// One account's view of the hub: posts route anywhere, polls and acks
/// operate on the bound recipient's own queue.
#[derive(Clone)]
pub struct InMemoryMailbox {
    hub: InMemoryMailboxHub,
    address: String,
    /// When set, every `ack` fails — models a transient ack outage so a test can
    /// prove a redelivered accept takes the idempotent ack-only path. Shared
    /// across clones so a toggle on one handle affects the borrowed handle.
    ack_failing: Arc<Mutex<bool>>,
}

impl InMemoryMailbox {
    /// Make every `ack` fail, or clear the failure.
    pub fn set_ack_failing(&self, failing: bool) {
        *self.ack_failing.lock().expect("lock") = failing;
    }

    /// This inbox as a standing [`ScriptedHttp`](super::ScriptedHttp) route.
    pub fn http_route(
        &self,
    ) -> impl Fn(&HttpRequest) -> Option<SeamResult<HttpResponse>> + Send + Sync + use<> {
        let inbox = self.clone();
        move |request| inbox.serve(request)
    }

    /// Answer one API mailbox request against this handle's inbox, or `None`
    /// when the URL names no mailbox route.
    ///
    /// The wire shape is the API's (`apps/api/src/mailbox/dto/mailbox.dto.ts`):
    /// hex recipient, base64 blob, `{ messages: [...] }`, ack by path segment.
    fn serve(&self, request: &HttpRequest) -> Option<SeamResult<HttpResponse>> {
        let tail = request
            .url
            .split_once(MESSAGES_PATH)?
            .1
            .trim_start_matches('/');
        Some(match (request.method, tail) {
            (HttpMethod::Post, "") => Ok(self.serve_post(request.body.as_deref())),
            (HttpMethod::Get, "") => Ok(self.serve_poll()),
            (HttpMethod::Delete, id) if !id.is_empty() => self.serve_ack(id),
            _ => Ok(json(
                404,
                br#"{"message":"no such mailbox route"}"#.to_vec(),
            )),
        })
    }

    fn serve_post(&self, body: Option<&[u8]>) -> HttpResponse {
        let posted = body
            .and_then(|body| serde_json::from_slice::<Value>(body).ok())
            .and_then(|wire| {
                let address = wire["recipientPublicKey"].as_str()?;
                if !is_lowercase_hex(address) {
                    return None;
                }
                let blob = BASE64.decode(wire["blob"].as_str()?).ok()?;
                let key = wire["idempotencyKey"].as_str()?.to_owned();
                Some(self.hub.post_item(address, &blob, &key))
            });
        match posted {
            Some(id) => json(201, format!(r#"{{"id":"{id}"}}"#).into_bytes()),
            None => json(400, br#"{"message":"malformed post body"}"#.to_vec()),
        }
    }

    fn serve_poll(&self) -> HttpResponse {
        let messages: Vec<Value> = self
            .items()
            .into_iter()
            .map(|item| {
                json!({
                    "id": item.item_id,
                    "receivedAt": RECEIVED_AT,
                    "blob": BASE64.encode(&item.sealed_payload),
                })
            })
            .collect();
        json(
            200,
            serde_json::to_vec(&json!({ "messages": messages })).expect("serializes"),
        )
    }

    fn serve_ack(&self, item_id: &str) -> SeamResult<HttpResponse> {
        self.remove(item_id)?;
        Ok(json(200, br#"{"success":true}"#.to_vec()))
    }

    fn items(&self) -> Vec<MailboxItem> {
        self.hub
            .inner
            .lock()
            .expect("lock")
            .queues
            .get(&self.address)
            .cloned()
            .unwrap_or_default()
    }

    fn remove(&self, item_id: &str) -> SeamResult<()> {
        if *self.ack_failing.lock().expect("lock") {
            return Err(SeamError::new("mailbox ack transient outage"));
        }
        if let Some(queue) = self
            .hub
            .inner
            .lock()
            .expect("lock")
            .queues
            .get_mut(&self.address)
        {
            queue.retain(|item| item.item_id != item_id);
        }
        Ok(())
    }
}

impl Mailbox for InMemoryMailbox {
    async fn post(
        &self,
        recipient_public_key: &[u8],
        sealed_payload: &[u8],
        idempotency_key: &str,
    ) -> SeamResult<()> {
        self.hub.post_item(
            &hex_lower(recipient_public_key),
            sealed_payload,
            idempotency_key,
        );
        Ok(())
    }

    async fn poll(&self) -> SeamResult<Vec<MailboxItem>> {
        Ok(self.items())
    }

    async fn ack(&self, item_id: &str) -> SeamResult<()> {
        self.remove(item_id)
    }
}

fn json(status: u16, body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body,
    }
}

fn is_lowercase_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() && b <= b'f')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;

    #[test]
    fn hub_routes_between_recipients_and_isolates_inboxes() {
        let hub = InMemoryMailboxHub::default();
        let alice = hub.mailbox_for(b"alice-pk");
        let bob = hub.mailbox_for(b"bob-pk");

        block_on(alice.post(b"bob-pk", b"sealed-for-bob", "k1")).unwrap();

        let bob_items = block_on(bob.poll()).unwrap();
        assert_eq!(bob_items.len(), 1);
        assert_eq!(bob_items[0].sealed_payload, b"sealed-for-bob");
        assert!(block_on(alice.poll()).unwrap().is_empty());
    }
}
