//! The `Mailbox` seam over the API's mailbox routes (blueprint/api.md
//! "Mailbox"), via the [`Http`] seam — the host's implementation on this
//! platform exactly as `packages/client/src/seams/mailbox.ts` is on web, with
//! nothing desktop-specific in it.
//!
//! A pure byte mover: it addresses the recipient and moves the opaque sealed
//! payload. The engine seals, unseals, and authenticates every item, so a
//! transport that lies can withhold or replay but never forge.
//!
//! The routes are bearer-authenticated and this seam carries no bearer: the
//! session token lives inside the engine's own API client, which the facade
//! hands no host. Delivery therefore lands with the slice that gives a host
//! seam a session credential.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cipherbox_desktop_seams::ReqwestHttp;
use cipherbox_engine::seams::{
    Http, HttpCredentials, HttpMethod, HttpRequest, Mailbox, MailboxItem, SeamError, SeamResult,
};
use serde::Deserialize;

/// Control-plane deadline: a mailbox round trip must not park a UI flow.
const CONTROL_TIMEOUT_MS: u64 = 10_000;

/// The mailbox transport for one account's inbox.
pub struct HttpMailbox {
    http: ReqwestHttp,
    messages_url: String,
}

/// The API's poll envelope. An unreadable one is a failure, never an empty
/// inbox (fail-closed: a missed grant is not the same as no grant).
#[derive(Deserialize)]
struct PollWire {
    messages: Vec<MessageWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageWire {
    id: String,
    blob: String,
}

impl HttpMailbox {
    /// A mailbox over `http`, addressing the API at `api_base_url`.
    pub fn new(http: ReqwestHttp, api_base_url: &str) -> Self {
        Self {
            http,
            messages_url: format!("{}/mailbox/messages", api_base_url.trim_end_matches('/')),
        }
    }

    async fn send(&self, request: HttpRequest, op: &str) -> SeamResult<Vec<u8>> {
        let response = self
            .http
            .send(request)
            .await
            .map_err(|error| SeamError::new(format!("mailbox {op}: {error}")))?;
        if response.status >= 300 {
            return Err(SeamError::new(format!(
                "mailbox {op} failed: {}",
                response.status
            )));
        }
        Ok(response.body)
    }

    fn request(&self, method: HttpMethod, url: String, body: Option<Vec<u8>>) -> HttpRequest {
        let headers = if body.is_some() {
            vec![("Content-Type".to_owned(), "application/json".to_owned())]
        } else {
            Vec::new()
        };
        HttpRequest {
            method,
            url,
            headers,
            body,
            credentials: HttpCredentials::Omit,
            timeout_ms: Some(CONTROL_TIMEOUT_MS),
        }
    }
}

impl Mailbox for HttpMailbox {
    async fn post(
        &self,
        recipient_public_key: &[u8],
        sealed_payload: &[u8],
        idempotency_key: &str,
    ) -> SeamResult<()> {
        let body = serde_json::json!({
            "recipientPublicKey": hex_lower(recipient_public_key),
            "blob": BASE64.encode(sealed_payload),
            "idempotencyKey": idempotency_key,
        });
        let body = serde_json::to_vec(&body)
            .map_err(|error| SeamError::new(format!("mailbox post body: {error}")))?;
        self.send(
            self.request(HttpMethod::Post, self.messages_url.clone(), Some(body)),
            "post",
        )
        .await
        .map(|_| ())
    }

    async fn poll(&self) -> SeamResult<Vec<MailboxItem>> {
        let body = self
            .send(
                self.request(HttpMethod::Get, self.messages_url.clone(), None),
                "poll",
            )
            .await?;
        let wire: PollWire = serde_json::from_slice(&body)
            .map_err(|error| SeamError::new(format!("mailbox poll envelope: {error}")))?;
        wire.messages
            .into_iter()
            .map(|message| {
                Ok(MailboxItem {
                    item_id: message.id,
                    sealed_payload: BASE64.decode(message.blob).map_err(|error| {
                        SeamError::new(format!("mailbox poll payload: {error}"))
                    })?,
                })
            })
            .collect()
    }

    async fn ack(&self, item_id: &str) -> SeamResult<()> {
        // The API's ack is idempotent — an unknown id answers 200 — so a 404
        // here means the route is wrong, not that the item was already acked.
        let url = format!("{}/{}", self.messages_url, encode_path_segment(item_id));
        self.send(self.request(HttpMethod::Delete, url, None), "ack")
            .await
            .map(|_| ())
    }
}

/// Lowercase hex, the spelling the API's `recipientPublicKey` field takes.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut hex, byte| {
        hex.push_str(&format!("{byte:02x}"));
        hex
    })
}

/// Percent-encodes everything outside RFC 3986's unreserved set, so an item id
/// the transport did not mint cannot carry the request onto another route.
fn encode_path_segment(segment: &str) -> String {
    segment
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_two_digits_per_byte() {
        assert_eq!(hex_lower(&[0x02, 0xab, 0x00, 0xff]), "02ab00ff");
    }

    /// A traversal in an item id would otherwise address a different route
    /// with the caller's authority.
    #[test]
    fn an_item_id_cannot_escape_its_path_segment() {
        assert_eq!(encode_path_segment("../quota"), "..%2Fquota");
        assert_eq!(encode_path_segment("a b?c#d"), "a%20b%3Fc%23d");
        assert_eq!(encode_path_segment("Az0-._~"), "Az0-._~");
    }

    #[test]
    fn the_messages_url_takes_one_slash_however_the_base_is_spelled() {
        for base in [
            "https://api.test",
            "https://api.test/",
            "https://api.test//",
        ] {
            let mailbox = HttpMailbox::new(ReqwestHttp::new().unwrap(), base);
            assert_eq!(mailbox.messages_url, "https://api.test/mailbox/messages");
        }
    }

    /// An envelope the transport cannot read is a failure, never an empty
    /// inbox: a silently-empty poll drops a grant nobody hears about again.
    #[test]
    fn a_malformed_poll_envelope_fails_closed() {
        for body in [
            &br#"{}"#[..],
            &br#"{"messages":[{"id":"a"}]}"#[..],
            &br#"{"messages":[{"id":1,"blob":"AA=="}]}"#[..],
            &br#"not json"#[..],
        ] {
            assert!(
                serde_json::from_slice::<PollWire>(body).is_err(),
                "{body:?}"
            );
        }
    }
}
