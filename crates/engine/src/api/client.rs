//! The hand-written API client (blueprint/engine.md "API client").
//!
//! One client, shared by web and desktop, over the [`Http`] seam — no
//! generated clients anywhere (#28 D5). It owns the token lifecycle: the
//! short-lived access JWT lives in engine memory (never persisted), the
//! rotating refresh token persists per platform through [`CredentialStore`]
//! (HTTP-only cookie on web via the Http seam, OS keychain on desktop).
//! Refresh is single-flight with one retry-then-fail on 401.

use core::cell::RefCell;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures_channel::oneshot;
use serde::Serialize;
use zeroize::Zeroizing;

use super::error::ApiError;
use super::signer::ChallengeSigner;
use super::types::{
    ChallengeRequest, ChallengeResponse, ErrorBody, LoginOutcome, LoginRequest, MailboxItem,
    MailboxItemWire, NameRegistration, Quota, RefreshRequest, SiweChallengeResponse,
    SiweLoginRequest, SiweNonce, TestLoginOutcome, TestLoginRequest, TestLoginResponse,
    TokenResponse, UploadResult,
};
use crate::seams::{CredentialStore, Http, HttpMethod, HttpRequest, HttpResponse};

const CONTENT_TYPE: &str = "Content-Type";
const AUTHORIZATION: &str = "Authorization";
const APPLICATION_JSON: &str = "application/json";
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";

/// Mutable client state, single-owner behind a [`RefCell`]: the engine is the
/// single writer (blueprint/engine.md Facade), so interior mutability with no
/// borrow held across an `await` is sufficient — no lock is needed.
struct State {
    /// The short-lived access JWT, in memory only. Zeroized on replacement/drop.
    access_token: Option<Zeroizing<String>>,
    /// Waiters coalesced behind the one in-flight refresh (single-flight).
    /// `Some(vec)` means a refresh is in progress; the leader owns the vec and
    /// notifies every waiter with a clone of the result when it finishes.
    refresh_waiters: Option<Vec<oneshot::Sender<Result<(), ApiError>>>>,
}

/// The engine's single API client. Generic over the two seams it drives so the
/// contract suite can point it at a real HTTP stack while unit tests drive it
/// with the scripted fake.
pub struct ApiClient<H: Http, C: CredentialStore> {
    http: H,
    credentials: C,
    base_url: String,
    state: RefCell<State>,
}

impl<H: Http, C: CredentialStore> ApiClient<H, C> {
    /// Builds a client over the Http and CredentialStore seams against an API
    /// base URL (any trailing slash is trimmed).
    pub fn new(http: H, credentials: C, base_url: impl Into<String>) -> Self {
        let mut base = base_url.into();
        while base.ends_with('/') {
            base.pop();
        }
        Self {
            http,
            credentials,
            base_url: base,
            state: RefCell::new(State {
                access_token: None,
                refresh_waiters: None,
            }),
        }
    }

    /// The API base URL, without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Whether an access token is currently held in memory.
    pub fn is_authenticated(&self) -> bool {
        self.state.borrow().access_token.is_some()
    }

    // --- auth: identity, SIWE, test-login, refresh, logout ---

    /// Engine-native challenge-signature login: request a challenge for the
    /// signer's identity key, sign it, and exchange it for tokens. Creates the
    /// account implicitly at first login (`is_new_user`).
    pub async fn login_identity(
        &self,
        signer: &impl ChallengeSigner,
    ) -> Result<LoginOutcome, ApiError> {
        let public_key = signer.public_key_hex();
        let challenge = {
            let response = self
                .post_json(
                    "/auth/challenge",
                    &ChallengeRequest {
                        public_key: &public_key,
                    },
                )
                .await?;
            let response = ok_or_err(response)?;
            let body: ChallengeResponse = decode(&response)?;
            body.challenge
        };
        let signature = signer.sign_challenge(&challenge);
        let response = self
            .post_json(
                "/auth/login",
                &LoginRequest {
                    public_key: &public_key,
                    challenge: &challenge,
                    signature: &signature,
                },
            )
            .await?;
        let response = ok_or_err(response)?;
        let tokens: TokenResponse = decode(&response)?;
        let is_new_user = tokens.is_new_user.unwrap_or(false);
        self.store_tokens(tokens.access_token, tokens.refresh_token)
            .await?;
        Ok(LoginOutcome { is_new_user })
    }

    /// Issue a single-use SIWE nonce to embed in an EIP-4361 message.
    pub async fn siwe_challenge(&self) -> Result<SiweNonce, ApiError> {
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: self.url("/auth/siwe/challenge"),
            headers: Vec::new(),
            body: None,
        };
        let response = ok_or_err(self.http.send(request).await?)?;
        let body: SiweChallengeResponse = decode(&response)?;
        Ok(SiweNonce {
            nonce: body.nonce,
            expires_at: body.expires_at,
        })
    }

    /// SIWE wallet login (secondary method). The host collects the wallet
    /// signature and the engine exchanges it here; the wallet must already be
    /// linked to an account.
    pub async fn siwe_login(
        &self,
        message: &str,
        signature: &str,
    ) -> Result<LoginOutcome, ApiError> {
        let response = self
            .post_json("/auth/siwe/login", &SiweLoginRequest { message, signature })
            .await?;
        let response = ok_or_err(response)?;
        let tokens: TokenResponse = decode(&response)?;
        let is_new_user = tokens.is_new_user.unwrap_or(false);
        self.store_tokens(tokens.access_token, tokens.refresh_token)
            .await?;
        Ok(LoginOutcome { is_new_user })
    }

    /// Link a SIWE wallet to the authenticated account (owner-authenticated).
    pub async fn siwe_link(&self, message: &str, signature: &str) -> Result<(), ApiError> {
        let body = to_json(&SiweLoginRequest { message, signature });
        let response = self
            .request_authed(
                HttpMethod::Post,
                "/auth/siwe/link",
                Some(APPLICATION_JSON),
                Some(body),
            )
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Staging-gated deterministic login for e2e. The API hard-blocks this in
    /// production and when `TEST_LOGIN_SECRET` is unset; those surface as
    /// [`ApiError::Forbidden`], a wrong secret as [`ApiError::Unauthorized`].
    pub async fn test_login(
        &self,
        handle: &str,
        secret: &str,
    ) -> Result<TestLoginOutcome, ApiError> {
        let response = self
            .post_json("/auth/test-login", &TestLoginRequest { handle, secret })
            .await?;
        let response = ok_or_err(response)?;
        let body: TestLoginResponse = decode(&response)?;
        let outcome = TestLoginOutcome {
            is_new_user: body.is_new_user.unwrap_or(false),
            public_key: body.public_key,
            private_key: Zeroizing::new(body.private_key),
        };
        self.store_tokens(body.access_token, body.refresh_token)
            .await?;
        Ok(outcome)
    }

    /// Rotate the refresh token. Single-flight: a concurrent caller awaits the
    /// in-flight rotation instead of spending its own (already-invalidated)
    /// token. On failure the local session is torn down.
    pub async fn refresh(&self) -> Result<(), ApiError> {
        let receiver = {
            let mut state = self.state.borrow_mut();
            match state.refresh_waiters.as_mut() {
                // A refresh is already running: enqueue and await its result.
                Some(waiters) => {
                    let (tx, rx) = oneshot::channel();
                    waiters.push(tx);
                    Some(rx)
                }
                // We are the leader: mark a refresh in progress and run it.
                None => {
                    state.refresh_waiters = Some(Vec::new());
                    None
                }
            }
        };

        if let Some(rx) = receiver {
            return match rx.await {
                Ok(result) => result,
                Err(oneshot::Canceled) => Err(ApiError::Unauthorized),
            };
        }

        let result = self.do_refresh().await;
        let waiters = self
            .state
            .borrow_mut()
            .refresh_waiters
            .take()
            .unwrap_or_default();
        for tx in waiters {
            let _ = tx.send(result.clone());
        }
        result
    }

    /// Revoke every refresh token server-side and tear down the local session.
    pub async fn logout(&self) -> Result<(), ApiError> {
        let response = self
            .request_authed(HttpMethod::Post, "/auth/logout", None, None)
            .await?;
        let result = ok_or_err(response).map(drop);
        self.clear_session().await?;
        result
    }

    // --- pin/name registry, quota, content, mailbox, recovery, account ---
    // Provisional until the matching API slices land (see types.rs).

    /// Batch register names (`[{ipnsName, headCid?, contentCids[]}]`).
    /// Register-first ordering is the publish pipeline's concern, not the
    /// caller's; this is the raw endpoint.
    pub async fn register(&self, names: &[NameRegistration]) -> Result<(), ApiError> {
        let body = to_json(names);
        let response = self
            .request_authed(
                HttpMethod::Post,
                "/registry/register",
                Some(APPLICATION_JSON),
                Some(body),
            )
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Batch retire names or CIDs (`[ipnsName | cid]`).
    pub async fn retire(&self, targets: &[String]) -> Result<(), ApiError> {
        let body = to_json(targets);
        let response = self
            .request_authed(
                HttpMethod::Post,
                "/registry/retire",
                Some(APPLICATION_JSON),
                Some(body),
            )
            .await?;
        ok_or_err(response).map(drop)
    }

    /// The per-account quota (advisory for BYO accounts).
    pub async fn quota(&self) -> Result<Quota, ApiError> {
        let response = self
            .request_authed(HttpMethod::Get, "/account/quota", None, None)
            .await?;
        let response = ok_or_err(response)?;
        decode(&response)
    }

    /// Upload content bytes to the hosted pin store.
    pub async fn upload(&self, content: &[u8]) -> Result<UploadResult, ApiError> {
        let response = self
            .request_authed(
                HttpMethod::Post,
                "/content/upload",
                Some(APPLICATION_OCTET_STREAM),
                Some(content.to_vec()),
            )
            .await?;
        let response = ok_or_err(response)?;
        decode(&response)
    }

    /// Post a sealed blob to a recipient's mailbox with an idempotency key.
    pub async fn mailbox_post(
        &self,
        recipient_public_key: &str,
        blob: &[u8],
        idempotency_key: &str,
    ) -> Result<(), ApiError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            recipient_public_key: &'a str,
            blob: String,
            idempotency_key: &'a str,
        }
        let body = to_json(&Body {
            recipient_public_key,
            blob: BASE64.encode(blob),
            idempotency_key,
        });
        let response = self
            .request_authed(
                HttpMethod::Post,
                "/mailbox",
                Some(APPLICATION_JSON),
                Some(body),
            )
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Poll pending mailbox items, decoding each sealed blob from base64.
    pub async fn mailbox_poll(&self) -> Result<Vec<MailboxItem>, ApiError> {
        let response = self
            .request_authed(HttpMethod::Get, "/mailbox", None, None)
            .await?;
        let response = ok_or_err(response)?;
        let wire: Vec<MailboxItemWire> = decode(&response)?;
        wire.into_iter()
            .map(|item| {
                let blob = BASE64
                    .decode(item.blob.as_bytes())
                    .map_err(|error| ApiError::Decode(format!("mailbox blob base64: {error}")))?;
                Ok(MailboxItem {
                    id: item.id,
                    received_at: item.received_at,
                    blob,
                })
            })
            .collect()
    }

    /// Ack (delete) a mailbox item by id.
    pub async fn mailbox_ack(&self, id: &str) -> Result<(), ApiError> {
        let response = self
            .request_authed(HttpMethod::Delete, &format!("/mailbox/{id}"), None, None)
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Fetch cached (possibly expired) record bytes for a name — the revival
    /// aid after a >EOL lapse. Returns the raw record bytes.
    pub async fn recovery_fetch(&self, ipns_name: &str) -> Result<Vec<u8>, ApiError> {
        let response = self
            .request_authed(
                HttpMethod::Get,
                &format!("/recovery/{ipns_name}"),
                None,
                None,
            )
            .await?;
        let response = ok_or_err(response)?;
        Ok(response.body)
    }

    /// Toggle the account's BYO (bring-your-own IPFS) flag.
    pub async fn set_byo(&self, enabled: bool) -> Result<(), ApiError> {
        #[derive(Serialize)]
        struct Body {
            byo: bool,
        }
        let body = to_json(&Body { byo: enabled });
        let response = self
            .request_authed(
                HttpMethod::Patch,
                "/account/byo",
                Some(APPLICATION_JSON),
                Some(body),
            )
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Immediate account hard-delete, then tear down the local session.
    pub async fn delete_account(&self) -> Result<(), ApiError> {
        let response = self
            .request_authed(HttpMethod::Delete, "/account", None, None)
            .await?;
        let result = ok_or_err(response).map(drop);
        self.clear_session().await?;
        result
    }

    // --- internals ---

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// POST a JSON body without authentication (the challenge/login/refresh
    /// surface).
    async fn post_json<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<HttpResponse, ApiError> {
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: self.url(path),
            headers: vec![(CONTENT_TYPE.to_owned(), APPLICATION_JSON.to_owned())],
            body: Some(to_json(body)),
        };
        Ok(self.http.send(request).await?)
    }

    /// Send an authenticated request with one refresh-then-retry on 401.
    async fn request_authed(
        &self,
        method: HttpMethod,
        path: &str,
        content_type: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, ApiError> {
        let first = self
            .send_with_token(method, path, content_type, body.clone())
            .await?;
        if first.status != 401 {
            return Ok(first);
        }
        // One refresh, then one retry; a second 401 is terminal (the caller
        // maps it via `ok_or_err`).
        self.refresh().await?;
        self.send_with_token(method, path, content_type, body).await
    }

    /// Send a request, attaching the in-memory access token as a bearer when
    /// one is held. When none is held the request goes out unauthenticated —
    /// the server's 401 then drives the refresh path (which covers a web
    /// reload where only the HTTP-only cookie survives).
    async fn send_with_token(
        &self,
        method: HttpMethod,
        path: &str,
        content_type: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(content_type) = content_type {
            headers.push((CONTENT_TYPE.to_owned(), content_type.to_owned()));
        }
        // Scope the borrow so it never crosses the await below.
        if let Some(token) = self.state.borrow().access_token.as_ref() {
            headers.push((
                AUTHORIZATION.to_owned(),
                format!("Bearer {}", token.as_str()),
            ));
        }
        let request = HttpRequest {
            method,
            url: self.url(path),
            headers,
            body,
        };
        Ok(self.http.send(request).await?)
    }

    /// The refresh rotation itself (only the single-flight leader runs this).
    async fn do_refresh(&self) -> Result<(), ApiError> {
        let stored = self.credentials.load_refresh_token().await?;
        let refresh_token = match stored {
            Some(bytes) => Some(
                String::from_utf8(bytes)
                    .map_err(|_| ApiError::Decode("stored refresh token is not utf-8".into()))?,
            ),
            // Web: no stored token — the HTTP-only cookie rides the Http seam.
            None => None,
        };
        let response = self
            .post_json("/auth/refresh", &RefreshRequest { refresh_token })
            .await?;
        if !is_success(response.status) {
            // Session is dead: drop the stale access + refresh material so it
            // is never replayed.
            self.clear_session().await?;
            return Err(error_from_response(&response));
        }
        let tokens: TokenResponse = decode(&response)?;
        self.store_tokens(tokens.access_token, tokens.refresh_token)
            .await
    }

    /// Persist the refresh token and hold the access token in memory. The
    /// refresh string is zeroized once handed to the store.
    async fn store_tokens(
        &self,
        access_token: String,
        refresh_token: String,
    ) -> Result<(), ApiError> {
        let refresh_token = Zeroizing::new(refresh_token);
        self.credentials
            .store_refresh_token(refresh_token.as_bytes())
            .await?;
        self.state.borrow_mut().access_token = Some(Zeroizing::new(access_token));
        Ok(())
    }

    /// Drop the in-memory access token and any persisted refresh token.
    async fn clear_session(&self) -> Result<(), ApiError> {
        self.state.borrow_mut().access_token = None;
        self.credentials.clear_refresh_token().await?;
        Ok(())
    }
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Serialize a request body. The client's own request types are always
/// serializable, so a failure is a programmer error, not a runtime condition.
fn to_json<B: Serialize + ?Sized>(body: &B) -> Vec<u8> {
    serde_json::to_vec(body).expect("api request bodies always serialize")
}

fn ok_or_err(response: HttpResponse) -> Result<HttpResponse, ApiError> {
    if is_success(response.status) {
        Ok(response)
    } else {
        Err(error_from_response(&response))
    }
}

fn error_from_response(response: &HttpResponse) -> ApiError {
    match response.status {
        401 => ApiError::Unauthorized,
        403 => ApiError::Forbidden,
        status => {
            let message = serde_json::from_slice::<ErrorBody>(&response.body)
                .ok()
                .and_then(|body| body.message_string());
            ApiError::Status { status, message }
        }
    }
}

fn decode<T: serde::de::DeserializeOwned>(response: &HttpResponse) -> Result<T, ApiError> {
    serde_json::from_slice(&response.body).map_err(|error| ApiError::Decode(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;
    use crate::testkit::fakes::{InMemoryCredentialStore, ScriptedHttp};
    use serde_json::{Value, json};
    use std::future::Future;
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    struct StubSigner;

    impl ChallengeSigner for StubSigner {
        fn public_key_hex(&self) -> String {
            "02".to_owned() + &"ab".repeat(32)
        }
        fn sign_challenge(&self, challenge: &str) -> String {
            format!("sig-for-{challenge}")
        }
    }

    fn json_response(status: u16, body: Value) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![(CONTENT_TYPE.to_owned(), APPLICATION_JSON.to_owned())],
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    fn body_json(request: &HttpRequest) -> Value {
        serde_json::from_slice(request.body.as_ref().expect("request has a body")).unwrap()
    }

    fn has_bearer(request: &HttpRequest) -> bool {
        request
            .headers
            .iter()
            .any(|(name, value)| name == AUTHORIZATION && value.starts_with("Bearer "))
    }

    type Fakes = (
        ScriptedHttp,
        InMemoryCredentialStore,
        ApiClient<ScriptedHttp, InMemoryCredentialStore>,
    );

    fn fakes() -> Fakes {
        let http = ScriptedHttp::default();
        let creds = InMemoryCredentialStore::default();
        let client = ApiClient::new(http.clone(), creds.clone(), "http://api.test/");
        (http, creds, client)
    }

    /// Log in so the client holds an access token and a stored refresh token.
    fn login(http: &ScriptedHttp, client: &ApiClient<ScriptedHttp, InMemoryCredentialStore>) {
        http.enqueue_response(json_response(
            200,
            json!({ "challenge": "cipherbox-login:v2:abc", "expiresAt": "2026-01-01T00:00:00Z" }),
        ));
        http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-1", "refreshToken": "a".repeat(64), "isNewUser": true }),
        ));
        block_on(client.login_identity(&StubSigner)).expect("login");
    }

    #[test]
    fn base_url_trailing_slash_is_trimmed() {
        let (_http, _creds, client) = fakes();
        assert_eq!(client.base_url(), "http://api.test");
    }

    #[test]
    fn identity_login_signs_the_challenge_and_persists_tokens() {
        let (http, creds, client) = fakes();
        login(&http, &client);

        assert!(client.is_authenticated());
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert_eq!(requests[0].url, "http://api.test/auth/challenge");
        assert_eq!(
            body_json(&requests[0])["publicKey"],
            StubSigner.public_key_hex()
        );
        assert_eq!(requests[1].url, "http://api.test/auth/login");
        let login_body = body_json(&requests[1]);
        assert_eq!(login_body["challenge"], "cipherbox-login:v2:abc");
        assert_eq!(login_body["signature"], "sig-for-cipherbox-login:v2:abc");

        let stored = block_on(creds.load_refresh_token()).unwrap().unwrap();
        assert_eq!(stored, "a".repeat(64).as_bytes());
    }

    #[test]
    fn identity_login_bad_signature_is_unauthorized() {
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            200,
            json!({ "challenge": "c", "expiresAt": "2026-01-01T00:00:00Z" }),
        ));
        http.enqueue_response(json_response(
            401,
            json!({ "message": "Invalid challenge signature" }),
        ));
        assert_eq!(
            block_on(client.login_identity(&StubSigner)).unwrap_err(),
            ApiError::Unauthorized
        );
        assert!(!client.is_authenticated());
    }

    #[test]
    fn refresh_sends_the_stored_token_and_rotates() {
        let (http, creds, client) = fakes();
        block_on(creds.store_refresh_token(b"seed-refresh-token")).unwrap();
        http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-2", "refreshToken": "b".repeat(64) }),
        ));

        block_on(client.refresh()).expect("refresh");

        let requests = http.requests();
        assert_eq!(requests[0].url, "http://api.test/auth/refresh");
        assert_eq!(
            body_json(&requests[0])["refreshToken"],
            "seed-refresh-token"
        );
        assert!(client.is_authenticated());
        let stored = block_on(creds.load_refresh_token()).unwrap().unwrap();
        assert_eq!(stored, "b".repeat(64).as_bytes());
    }

    #[test]
    fn refresh_without_a_stored_token_omits_the_field() {
        // The web platform keeps no stored token: the HTTP-only cookie rides
        // the Http seam, so the body must carry no refreshToken field.
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt", "refreshToken": "c".repeat(64) }),
        ));
        block_on(client.refresh()).expect("refresh via cookie");
        assert_eq!(body_json(&http.requests()[0]), json!({}));
    }

    #[test]
    fn refresh_failure_clears_the_session() {
        let (http, creds, client) = fakes();
        login(&http, &client);
        http.enqueue_response(json_response(
            401,
            json!({ "message": "Invalid refresh token" }),
        ));

        assert_eq!(
            block_on(client.refresh()).unwrap_err(),
            ApiError::Unauthorized
        );
        assert!(!client.is_authenticated());
        assert!(block_on(creds.load_refresh_token()).unwrap().is_none());
    }

    #[test]
    fn expired_access_triggers_one_refresh_then_retry() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        // First logout attempt 401 → refresh 200 → retry 200.
        http.enqueue_response(json_response(401, json!({ "message": "jwt expired" })));
        http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-2", "refreshToken": "d".repeat(64) }),
        ));
        http.enqueue_response(json_response(200, json!({ "success": true })));

        block_on(client.logout()).expect("logout after refresh");

        let urls: Vec<_> = http.requests().iter().map(|r| r.url.clone()).collect();
        assert_eq!(
            &urls[2..],
            &[
                "http://api.test/auth/logout",
                "http://api.test/auth/refresh",
                "http://api.test/auth/logout",
            ]
        );
    }

    #[test]
    fn terminal_401_after_refresh_is_unauthorized() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        http.enqueue_response(json_response(401, json!({ "message": "expired" }))); // quota attempt
        http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-2", "refreshToken": "d".repeat(64) }),
        )); // refresh ok
        http.enqueue_response(json_response(401, json!({ "message": "still bad" }))); // retry 401

        assert_eq!(
            block_on(client.quota()).unwrap_err(),
            ApiError::Unauthorized
        );
    }

    #[test]
    fn test_login_returns_the_keypair_and_redacts_the_private_key() {
        let (http, _creds, client) = fakes();
        let private_key = "11".repeat(32);
        http.enqueue_response(json_response(
            200,
            json!({
                "accessToken": "jwt",
                "refreshToken": "e".repeat(64),
                "isNewUser": true,
                "publicKey": "02cafe",
                "privateKey": private_key,
            }),
        ));

        let outcome = block_on(client.test_login("alice@test", "the-secret")).expect("test login");
        assert!(outcome.is_new_user);
        assert_eq!(outcome.public_key, "02cafe");
        assert_eq!(&*outcome.private_key, &private_key);
        assert!(client.is_authenticated());

        let body = body_json(&http.requests()[0]);
        assert_eq!(body["handle"], "alice@test");
        assert_eq!(body["secret"], "the-secret");

        let debug = format!("{outcome:?}");
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains(&private_key),
            "private key must never render"
        );
    }

    #[test]
    fn test_login_disabled_is_forbidden() {
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            403,
            json!({ "message": "Test login is not enabled" }),
        ));
        assert_eq!(
            block_on(client.test_login("h", "wrong")).unwrap_err(),
            ApiError::Forbidden
        );
    }

    #[test]
    fn siwe_challenge_returns_a_nonce_with_no_request_body() {
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            200,
            json!({ "nonce": "nonce-123", "expiresAt": "2026-01-01T00:00:00Z" }),
        ));
        let nonce = block_on(client.siwe_challenge()).expect("nonce");
        assert_eq!(nonce.nonce, "nonce-123");
        let request = &http.requests()[0];
        assert_eq!(request.url, "http://api.test/auth/siwe/challenge");
        assert!(request.body.is_none());
    }

    #[test]
    fn siwe_login_unlinked_wallet_is_unauthorized() {
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            401,
            json!({ "message": "Wallet is not linked to an account" }),
        ));
        assert_eq!(
            block_on(client.siwe_login("message", "0xsig")).unwrap_err(),
            ApiError::Unauthorized
        );
    }

    #[test]
    fn register_builds_the_batch_body_with_a_bearer() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        http.enqueue_response(json_response(200, json!({})));

        let names = vec![NameRegistration {
            ipns_name: "k51abc".into(),
            head_cid: Some("bafyhead".into()),
            content_cids: vec!["bafyc1".into(), "bafyc2".into()],
        }];
        block_on(client.register(&names)).expect("register");

        let request = http.requests().pop().unwrap();
        assert_eq!(request.url, "http://api.test/registry/register");
        assert!(has_bearer(&request));
        let body = body_json(&request);
        assert_eq!(body[0]["ipnsName"], "k51abc");
        assert_eq!(body[0]["headCid"], "bafyhead");
        assert_eq!(body[0]["contentCids"], json!(["bafyc1", "bafyc2"]));
    }

    #[test]
    fn mailbox_poll_decodes_base64_blobs() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        let blob = b"sealed-payload-bytes";
        http.enqueue_response(json_response(
            200,
            json!([{ "id": "m1", "receivedAt": "2026-01-01T00:00:00Z", "blob": BASE64.encode(blob) }]),
        ));

        let items = block_on(client.mailbox_poll()).expect("poll");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "m1");
        assert_eq!(items[0].blob, blob);
    }

    #[test]
    fn status_error_carries_the_server_message() {
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            500,
            json!({ "statusCode": 500, "message": "internal boom" }),
        ));
        assert_eq!(
            block_on(client.siwe_challenge()).unwrap_err(),
            ApiError::Status {
                status: 500,
                message: Some("internal boom".into())
            }
        );
    }

    // --- single-flight: two concurrent refreshes issue exactly one request ---

    #[derive(Clone, Default)]
    struct GatedHttp {
        inner: Arc<Mutex<GateInner>>,
    }

    #[derive(Default)]
    struct GateInner {
        requests: usize,
        response: Option<HttpResponse>,
        wakers: Vec<Waker>,
    }

    impl GatedHttp {
        fn request_count(&self) -> usize {
            self.inner.lock().unwrap().requests
        }
        fn release(&self, response: HttpResponse) {
            let mut inner = self.inner.lock().unwrap();
            inner.response = Some(response);
            for waker in inner.wakers.drain(..) {
                waker.wake();
            }
        }
    }

    impl Http for GatedHttp {
        async fn send(&self, _request: HttpRequest) -> crate::seams::SeamResult<HttpResponse> {
            self.inner.lock().unwrap().requests += 1;
            GateFuture {
                inner: self.inner.clone(),
            }
            .await
        }
    }

    struct GateFuture {
        inner: Arc<Mutex<GateInner>>,
    }

    impl Future for GateFuture {
        type Output = crate::seams::SeamResult<HttpResponse>;
        fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut inner = self.inner.lock().unwrap();
            match &inner.response {
                Some(response) => Poll::Ready(Ok(response.clone())),
                None => {
                    inner.wakers.push(cx.waker().clone());
                    Poll::Pending
                }
            }
        }
    }

    #[test]
    fn concurrent_refreshes_are_single_flight() {
        let http = GatedHttp::default();
        let creds = InMemoryCredentialStore::default();
        block_on(creds.store_refresh_token(b"seed-refresh-token")).unwrap();
        let client = ApiClient::new(http.clone(), creds, "http://api.test");

        let mut first = pin!(client.refresh());
        let mut second = pin!(client.refresh());
        let mut cx = Context::from_waker(Waker::noop());

        // Leader polls first: one /auth/refresh goes out, then it parks.
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert_eq!(http.request_count(), 1);
        // Waiter polls: it coalesces behind the leader — no second request.
        assert!(second.as_mut().poll(&mut cx).is_pending());
        assert_eq!(http.request_count(), 1);

        http.release(json_response(
            200,
            json!({ "accessToken": "jwt", "refreshToken": "f".repeat(64) }),
        ));

        assert!(matches!(first.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(http.request_count(), 1, "one refresh served both callers");
        assert!(client.is_authenticated());
    }
}
