//! [`Mailbox`] over the engine's own API client (blueprint/engine.md "Host
//! seams").
//!
//! The mailbox is not a host seam: its routes are `@UseGuards(JwtAuthGuard)`
//! API routes, so a host implementation would need the access bearer, and the
//! bearer never leaves the engine. Riding [`ApiClient`] gives the mailbox the
//! same single-flight refresh and one-retry-on-401 as every other authed call,
//! from the one token store there is.

use cipherbox_core::hex::lower as hex_lower;

use super::ApiClient;
use crate::seams::{CredentialStore, Http, Mailbox, MailboxItem, SeamError, SeamResult};

impl<H: Http, C: CredentialStore> Mailbox for ApiClient<H, C> {
    async fn post(
        &self,
        recipient_public_key: &[u8],
        sealed_payload: &[u8],
        idempotency_key: &str,
    ) -> SeamResult<()> {
        self.mailbox_post(
            &hex_lower(recipient_public_key),
            sealed_payload,
            idempotency_key,
        )
        .await
        .map(drop)
        .map_err(|error| SeamError::new(format!("mailbox post: {error}")))
    }

    async fn poll(&self) -> SeamResult<Vec<MailboxItem>> {
        Ok(self
            .mailbox_poll()
            .await
            .map_err(|error| SeamError::new(format!("mailbox poll: {error}")))?
            .into_iter()
            .map(|item| MailboxItem {
                item_id: item.id,
                sealed_payload: item.blob,
            })
            .collect())
    }

    async fn ack(&self, item_id: &str) -> SeamResult<()> {
        self.mailbox_ack(item_id)
            .await
            .map_err(|error| SeamError::new(format!("mailbox ack: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::{AUTHORIZATION, HttpMethod, HttpResponse};
    use crate::testkit::block_on;
    use crate::testkit::fakes::{InMemoryCredentialStore, ScriptedHttp};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use serde_json::json;

    const ACCESS: &str = "access-token";

    fn client(http: &ScriptedHttp) -> ApiClient<ScriptedHttp, InMemoryCredentialStore> {
        let client = ApiClient::new(
            http.clone(),
            InMemoryCredentialStore::default(),
            "https://api.test",
        );
        block_on(client.test_login("mailbox-seam", "secret")).expect("login");
        client
    }

    fn login_response() -> HttpResponse {
        json_response(
            200,
            json!({
                "accessToken": ACCESS,
                "refreshToken": "refresh-token",
                "gatewayToken": "gateway-token",
                "publicKey": "02".to_owned() + &"ab".repeat(32),
                "privateKey": "ab".repeat(32),
            }),
        )
    }

    fn token_response() -> HttpResponse {
        json_response(
            200,
            json!({
                "accessToken": ACCESS,
                "refreshToken": "refresh-token",
                "gatewayToken": "gateway-token",
            }),
        )
    }

    fn json_response(status: u16, body: serde_json::Value) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    fn bearer(http: &ScriptedHttp, index: usize) -> Option<String> {
        http.requests()[index]
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(AUTHORIZATION))
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn every_mailbox_call_carries_the_engine_held_bearer() {
        let http = ScriptedHttp::default();
        http.enqueue_response(login_response());
        let client = client(&http);

        http.enqueue_response(json_response(201, json!({ "id": "m1" })));
        http.enqueue_response(json_response(200, json!({ "messages": [] })));
        http.enqueue_response(json_response(200, json!({ "success": true })));

        block_on(client.post(&[0x02; 33], b"sealed", "idem")).expect("post");
        block_on(Mailbox::poll(&client)).expect("poll");
        block_on(client.ack("m1")).expect("ack");

        for index in 1..=3 {
            assert_eq!(
                bearer(&http, index).as_deref(),
                Some(format!("Bearer {ACCESS}").as_str()),
                "mailbox request {index} must present the session bearer"
            );
        }
    }

    #[test]
    fn a_401_refreshes_once_and_retries() {
        let http = ScriptedHttp::default();
        http.enqueue_response(login_response());
        let client = client(&http);

        http.enqueue_response(json_response(401, json!({ "message": "expired" })));
        http.enqueue_response(token_response()); // /auth/refresh
        http.enqueue_response(json_response(
            200,
            json!({ "messages": [{ "id": "m1", "receivedAt": "t", "blob": BASE64.encode(b"sealed") }] }),
        ));

        let items = block_on(Mailbox::poll(&client)).expect("poll after refresh");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].sealed_payload, b"sealed");
        let urls: Vec<_> = http.requests().iter().map(|r| r.url.clone()).collect();
        assert_eq!(
            urls[1..],
            [
                "https://api.test/mailbox/messages",
                "https://api.test/auth/refresh",
                "https://api.test/mailbox/messages",
            ],
            "one refresh, then one retry of the same route"
        );
    }

    #[test]
    fn post_addresses_the_recipient_as_lowercase_hex() {
        let http = ScriptedHttp::default();
        http.enqueue_response(login_response());
        let client = client(&http);
        http.enqueue_response(json_response(201, json!({ "id": "m1" })));

        block_on(client.post(&[0x02; 33], b"sealed", "idem")).expect("post");

        let body: serde_json::Value =
            serde_json::from_slice(http.requests()[1].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["recipientPublicKey"], "02".repeat(33));
        assert_eq!(body["blob"], BASE64.encode(b"sealed"));
    }

    #[test]
    fn an_item_id_the_transport_could_steer_a_route_with_is_refused() {
        let http = ScriptedHttp::default();
        http.enqueue_response(login_response());
        let client = client(&http);

        for hostile in ["../../account", "m1/../account", "m 1", "m1?x=1", ""] {
            assert!(
                block_on(client.ack(hostile)).is_err(),
                "{hostile:?} must not reach the transport"
            );
        }
        assert_eq!(
            http.requests().len(),
            1,
            "a refused ack sends nothing beyond the login"
        );
    }

    #[test]
    fn ack_sends_the_item_id_the_poll_handed_back() {
        let http = ScriptedHttp::default();
        http.enqueue_response(login_response());
        let client = client(&http);
        http.enqueue_response(json_response(200, json!({ "success": true })));

        block_on(client.ack("0b7f5a2e-1c3d-4e5f-8a9b-0c1d2e3f4a5b")).expect("ack");

        assert_eq!(
            http.requests()[1].url,
            "https://api.test/mailbox/messages/0b7f5a2e-1c3d-4e5f-8a9b-0c1d2e3f4a5b"
        );
        assert_eq!(http.requests()[1].method, HttpMethod::Delete);
    }
}
