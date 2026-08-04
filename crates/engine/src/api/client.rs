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
use cipherbox_core::content::{CONTENT_CID_CODEC, decode_content_cid_str};
use futures_channel::oneshot;
use serde::Serialize;
use zeroize::Zeroizing;

use super::error::ApiError;
use super::signer::ChallengeSigner;
use super::types::{
    ChallengeRequest, ChallengeResponse, ErrorBody, LoginOutcome, LoginRequest, MailboxItem,
    MailboxPollWire, MailboxPostWire, NameRegistration, Quota, RefreshRequest,
    SiweChallengeResponse, SiweLoginRequest, SiweNonce, TestLoginOutcome, TestLoginRequest,
    TestLoginResponse, TokenResponse, UploadResult,
};
use crate::content::DAG_ROOT_CODEC;
use crate::seams::{CredentialStore, Http, HttpMethod, HttpRequest, HttpResponse};

const CONTENT_TYPE: &str = "Content-Type";
const AUTHORIZATION: &str = "Authorization";
const APPLICATION_JSON: &str = "application/json";
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
/// Carries an upload's declared content address. A header, not a query
/// parameter: content addresses correlate across accounts and edge proxies log
/// URLs (blueprint/api.md, Accepted exposure).
const CONTENT_CID: &str = "X-Content-Cid";
/// Byte offset of the multicodec in the frozen CIDv1 framing.
const CID_CODEC_INDEX: usize = 1;

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
        if !is_eip4361_nonce(&body.nonce) {
            return Err(ApiError::Decode("unusable siwe nonce".into()));
        }
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
        let response = self
            .json_authed(
                HttpMethod::Post,
                "/auth/siwe/link",
                &SiweLoginRequest { message, signature },
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
            .request_authed(HttpMethod::Post, "/auth/logout")
            .await?;
        let result = ok_or_err(response).map(drop);
        self.clear_session().await?;
        result
    }

    // --- pin/name registry, quota, content, mailbox, recovery, account ---

    /// Batch register names (`[{ipnsName, headCid?, contentCids[]}]`).
    /// Register-first ordering is the publish pipeline's concern, not the
    /// caller's; this is the raw endpoint.
    pub async fn register(&self, names: &[NameRegistration]) -> Result<(), ApiError> {
        let response = self
            .json_authed(HttpMethod::Post, "/registry/register", names)
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Batch retire names or CIDs (`[ipnsName | cid]`).
    pub async fn retire(&self, targets: &[String]) -> Result<(), ApiError> {
        let response = self
            .json_authed(HttpMethod::Post, "/registry/retire", targets)
            .await?;
        ok_or_err(response).map(drop)
    }

    /// The per-account quota (advisory for BYO accounts).
    pub async fn quota(&self) -> Result<Quota, ApiError> {
        let response = self
            .request_authed(HttpMethod::Get, "/account/quota")
            .await?;
        let response = ok_or_err(response)?;
        decode(&response)
    }

    /// Upload content bytes to the hosted pin store under `cid`, the caller's
    /// own content address for them. The API pins under exactly that address
    /// and refuses bytes that do not hash to it, so the block the network
    /// serves is the block the engine authored (blueprint/api.md, Ingress).
    ///
    /// Refused fail-closed unless `cid` is a canonical content-plane address
    /// under one of the two codecs the ingress accepts — matching the API's
    /// own set, so a wider one breaks here rather than as a 400 in production.
    pub async fn upload(&self, cid: &str, content: &[u8]) -> Result<UploadResult, ApiError> {
        let decoded = decode_content_cid_str(cid).map_err(|_| ApiError::MalformedContentCid)?;
        if !matches!(decoded[CID_CODEC_INDEX], CONTENT_CID_CODEC | DAG_ROOT_CODEC) {
            return Err(ApiError::MalformedContentCid);
        }
        let response = self
            .request_authed_with(
                HttpMethod::Post,
                "/content/upload",
                Some(APPLICATION_OCTET_STREAM),
                &[(CONTENT_CID, cid)],
                Some(content.to_vec()),
            )
            .await?;
        let response = ok_or_err(response)?;
        decode(&response)
    }

    /// Post a sealed blob to a recipient's mailbox with an idempotency key,
    /// returning the server-assigned message id (a replay of the same key
    /// returns the original id).
    pub async fn mailbox_post(
        &self,
        recipient_public_key: &str,
        blob: &[u8],
        idempotency_key: &str,
    ) -> Result<String, ApiError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            recipient_public_key: &'a str,
            blob: String,
            idempotency_key: &'a str,
        }
        let response = self
            .json_authed(
                HttpMethod::Post,
                "/mailbox/messages",
                &Body {
                    recipient_public_key,
                    blob: BASE64.encode(blob),
                    idempotency_key,
                },
            )
            .await?;
        let response = ok_or_err(response)?;
        let wire: MailboxPostWire = decode(&response)?;
        Ok(wire.id)
    }

    /// Poll pending mailbox items, decoding each sealed blob from base64.
    pub async fn mailbox_poll(&self) -> Result<Vec<MailboxItem>, ApiError> {
        let response = self
            .request_authed(HttpMethod::Get, "/mailbox/messages")
            .await?;
        let response = ok_or_err(response)?;
        let wire: MailboxPollWire = decode(&response)?;
        wire.messages
            .into_iter()
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
            .request_authed(HttpMethod::Delete, &format!("/mailbox/messages/{id}"))
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Fetch cached (possibly expired) record bytes for a name — the revival
    /// aid after a >EOL lapse. Returns the raw record bytes.
    pub async fn recovery_fetch(&self, ipns_name: &str) -> Result<Vec<u8>, ApiError> {
        let response = self
            .request_authed(HttpMethod::Get, &format!("/recovery/{ipns_name}"))
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
        let response = self
            .json_authed(HttpMethod::Patch, "/account/byo", &Body { byo: enabled })
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Immediate account hard-delete, then tear down the local session.
    pub async fn delete_account(&self) -> Result<(), ApiError> {
        let response = self.request_authed(HttpMethod::Delete, "/account").await?;
        let result = ok_or_err(response).map(drop);
        self.clear_session().await?;
        result
    }

    // --- internals ---

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// POST a JSON body without authentication (the challenge/login surface;
    /// refresh builds its request inline to zeroize the secret-bearing body).
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

    /// [`Self::request_authed`] carrying a JSON body, so the serialize and the
    /// `Content-Type` that must accompany it are never stated apart.
    async fn json_authed<B: Serialize + ?Sized>(
        &self,
        method: HttpMethod,
        path: &str,
        body: &B,
    ) -> Result<HttpResponse, ApiError> {
        self.request_authed_with(
            method,
            path,
            Some(APPLICATION_JSON),
            &[],
            Some(to_json(body)),
        )
        .await
    }

    /// Send a bodyless authenticated request with one refresh-then-retry on 401.
    async fn request_authed(
        &self,
        method: HttpMethod,
        path: &str,
    ) -> Result<HttpResponse, ApiError> {
        self.request_authed_with(method, path, None, &[], None)
            .await
    }

    /// [`Self::request_authed`], plus a body and request-specific headers.
    async fn request_authed_with(
        &self,
        method: HttpMethod,
        path: &str,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, ApiError> {
        let first = self
            .send_with_token(method, path, content_type, extra_headers, body.clone())
            .await?;
        if first.status != 401 {
            return Ok(first);
        }
        // One refresh, then one retry; a second 401 is terminal (the caller
        // maps it via `ok_or_err`).
        self.refresh().await?;
        self.send_with_token(method, path, content_type, extra_headers, body)
            .await
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
        extra_headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(content_type) = content_type {
            headers.push((CONTENT_TYPE.to_owned(), content_type.to_owned()));
        }
        for (name, value) in extra_headers {
            headers.push(((*name).to_owned(), (*value).to_owned()));
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
            // Wrap the decoded secret so its allocation is cleared at this
            // terminal owner (mirrors `store_tokens`); `from_utf8` reuses the
            // stored bytes' buffer, so this also clears them.
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(token) => Some(Zeroizing::new(token)),
                // Corrupted stored credential: self-heal by clearing the dead
                // session, else every authed call loops 401 → refresh → Decode
                // → 401. Mirrors the refresh-failure path below.
                Err(_) => {
                    self.clear_session().await?;
                    return Err(ApiError::Decode("stored refresh token is not utf-8".into()));
                }
            },
            // Web: no stored token — the HTTP-only cookie rides the Http seam.
            None => None,
        };
        // Serialize once into a zeroizing buffer so the secret-bearing body is
        // cleared on every exit path (success, error, network failure).
        let body = Zeroizing::new(to_json(&RefreshRequest {
            refresh_token: refresh_token.as_ref().map(|token| token.to_string()),
        }));
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: self.url("/auth/refresh"),
            headers: vec![(CONTENT_TYPE.to_owned(), APPLICATION_JSON.to_owned())],
            body: Some(body.to_vec()),
        };
        let response = self.http.send(request).await?;
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

/// EIP-4361 fixes the nonce at 8+ alphanumerics. The check is fail-closed
/// rather than cosmetic: the nonce is interpolated verbatim into the text a
/// wallet signs, so anything outside that class lets a hostile challenge
/// response inject extra fields into the signed message.
fn is_eip4361_nonce(nonce: &str) -> bool {
    (8..=128).contains(&nonce.len()) && nonce.chars().all(|c| c.is_ascii_alphanumeric())
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
            let body = serde_json::from_slice::<ErrorBody>(&response.body).ok();
            ApiError::Status {
                status,
                message: body.as_ref().and_then(ErrorBody::message_string),
                code: body.and_then(|body| body.code),
            }
        }
    }
}

fn decode<T: serde::de::DeserializeOwned>(response: &HttpResponse) -> Result<T, ApiError> {
    serde_json::from_slice(&response.body).map_err(|error| ApiError::Decode(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};

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
            json!({ "nonce": "a1b2c3d4e5f60718", "expiresAt": "2026-01-01T00:00:00Z" }),
        ));
        let nonce = block_on(client.siwe_challenge()).expect("nonce");
        assert_eq!(nonce.nonce, "a1b2c3d4e5f60718");
        let request = &http.requests()[0];
        assert_eq!(request.url, "http://api.test/auth/siwe/challenge");
        assert!(request.body.is_none());
    }

    #[test]
    fn siwe_challenge_refuses_a_nonce_outside_the_eip4361_class() {
        for unusable in [
            "short7",
            "has-a-hyphen-in-it",
            "line\nbreak12345",
            "spaced out nonce",
            "",
            "1234567",
            &"a".repeat(129),
            // `char::is_alphanumeric` would accept both; the ASCII class must
            // not — a confusable nonce is one a wallet renders unreadably.
            "١٢٣٤٥٦٧٨",
            "ＡＢＣＤＥＦＧＨ",
        ] {
            let (http, _creds, client) = fakes();
            http.enqueue_response(json_response(
                200,
                json!({ "nonce": unusable, "expiresAt": "2026-01-01T00:00:00Z" }),
            ));
            let error = block_on(client.siwe_challenge()).unwrap_err();
            assert_eq!(
                error,
                ApiError::Decode("unusable siwe nonce".into()),
                "accepted {unusable:?}"
            );
            assert!(
                unusable.is_empty() || !error.to_string().contains(unusable),
                "the refusal echoed the offending nonce"
            );
        }
    }

    #[test]
    fn siwe_challenge_accepts_the_class_boundaries() {
        for usable in ["12345678", &"a".repeat(128)] {
            let (http, _creds, client) = fakes();
            http.enqueue_response(json_response(
                200,
                json!({ "nonce": usable, "expiresAt": "2026-01-01T00:00:00Z" }),
            ));
            assert_eq!(
                block_on(client.siwe_challenge()).expect("nonce").nonce,
                usable
            );
        }
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
            json!({ "messages": [
                { "id": "m1", "receivedAt": "2026-01-01T00:00:00Z", "blob": BASE64.encode(blob) },
            ] }),
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
                message: Some("internal boom".into()),
                code: None,
            }
        );
    }

    /// One status covers unrelated causes on the upload endpoint, so the
    /// machine discriminator has to survive the client — prose does not.
    #[test]
    fn status_error_carries_the_server_code_when_the_body_has_one() {
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            413,
            json!({ "statusCode": 413, "message": "over quota", "code": "QUOTA_EXCEEDED" }),
        ));
        assert_eq!(
            block_on(client.siwe_challenge()).unwrap_err(),
            ApiError::Status {
                status: 413,
                message: Some("over quota".into()),
                code: Some("QUOTA_EXCEEDED".into()),
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

    #[test]
    fn upload_declares_the_block_address_on_the_wire() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        let block = b"sealed-block".to_vec();
        let cid = encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, &block));
        http.enqueue_response(json_response(
            201,
            json!({ "cid": cid, "size": block.len() }),
        ));

        let result = block_on(client.upload(&cid, &block)).expect("upload");

        assert_eq!(result.cid, cid);
        let request = http.requests().pop().expect("upload request");
        assert_eq!(
            request.url, "http://api.test/content/upload",
            "the address rides a header, never the URL"
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| name == CONTENT_CID && *value == cid),
            "the declared address is sent"
        );
        assert_eq!(request.body.as_deref(), Some(&block[..]));
    }

    #[test]
    fn upload_refuses_a_non_canonical_content_cid_before_the_wire() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        let sent_after_login = http.requests().len();

        let error = block_on(client.upload("not-a-canonical-cid", b"bytes")).expect_err("refused");

        assert!(matches!(error, ApiError::MalformedContentCid));
        assert_eq!(
            http.requests().len(),
            sent_after_login,
            "no request left the client"
        );
    }

    #[test]
    fn upload_refuses_a_codec_the_ingress_does_not_accept() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        let sent_after_login = http.requests().len();

        // Canonically framed, but `dag-pb` (0x70) is outside the frozen
        // content-plane set the ingress routes.
        let cid = encode_content_cid_str(&compute_cid(0x70, b"block"));
        let error = block_on(client.upload(&cid, b"block")).expect_err("refused");

        assert!(matches!(error, ApiError::MalformedContentCid));
        assert_eq!(
            http.requests().len(),
            sent_after_login,
            "no request left the client"
        );
    }
}
