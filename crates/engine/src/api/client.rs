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
    AuthMethod, ChallengeRequest, ChallengeResponse, ErrorBody, LoginOutcome, LoginRequest,
    MailboxItem, MailboxPollWire, MailboxPostWire, NameRegistration, Quota, RefreshRequest,
    RetireResult, SiweChallengeResponse, SiweLinkRequest, SiweLoginRequest, SiweNonce,
    TestLoginOutcome, TestLoginRequest, TestLoginResponse, TokenResponse, UnlinkMethodRequest,
    UploadResult,
};
use crate::content::{DAG_ROOT_CODEC, SessionBearer};
use crate::seams::{
    CredentialStore, Http, HttpCredentials, HttpMethod, HttpRequest, HttpResponse, SeamError,
    bearer_header, item_id_is_legal,
};

/// Control-plane deadline: small JSON round trips must not park a UI flow.
const CONTROL_TIMEOUT_MS: u64 = 10_000;
/// Upload deadline: a content block legitimately moves megabytes on a slow
/// uplink, so it cannot share the control-plane bound.
const TRANSFER_TIMEOUT_MS: u64 = 120_000;

const CONTENT_TYPE: &str = "Content-Type";
const APPLICATION_JSON: &str = "application/json";
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
/// Carries an upload's declared content address. A header, not a query
/// parameter: content addresses correlate across accounts and edge proxies log
/// URLs (blueprint/api.md, Accepted exposure).
const CONTENT_CID: &str = "X-Content-Cid";
/// Byte offset of the multicodec in the frozen CIDv1 framing.
const CID_CODEC_INDEX: usize = 1;

/// Waiters coalesced behind the one in-flight refresh (single-flight). `Some`
/// means a refresh is in progress; the leader owns the vec and notifies every
/// waiter with a clone of the result when it finishes.
///
/// Single-owner behind a [`RefCell`]: the engine is the single writer
/// (blueprint/engine.md Facade), so interior mutability with no borrow held
/// across an `await` is sufficient — no lock is needed.
type RefreshWaiters = RefCell<Option<Vec<oneshot::Sender<Result<(), ApiError>>>>>;

/// Holds single-flight leadership for one rotation and releases it on `Drop`,
/// so a leader cancelled while parked on the network cannot leave the slot
/// occupied by senders nothing will ever fire.
struct RefreshLead<'a> {
    waiters: &'a RefreshWaiters,
}

impl RefreshLead<'_> {
    /// Takes the waiters to notify, leaving the slot for `Drop` to release.
    fn waiters(&self) -> Vec<oneshot::Sender<Result<(), ApiError>>> {
        self.waiters.borrow_mut().take().unwrap_or_default()
    }
}

impl Drop for RefreshLead<'_> {
    fn drop(&mut self) {
        *self.waiters.borrow_mut() = None;
    }
}

/// The engine's single API client. Generic over the two seams it drives so the
/// contract suite can point it at a real HTTP stack while unit tests drive it
/// with the scripted fake.
pub struct ApiClient<H: Http, C: CredentialStore> {
    http: H,
    credentials: C,
    base_url: String,
    /// The short-lived access JWT, in memory only. Zeroized on replacement/drop.
    session: SessionBearer,
    /// The read accelerator's pseudonym, in its own cell so the API leg and the
    /// gateway leg cannot present each other's credential.
    accelerator: SessionBearer,
    refresh_waiters: RefreshWaiters,
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
            session: SessionBearer::default(),
            accelerator: SessionBearer::default(),
            refresh_waiters: RefCell::new(None),
        }
    }

    /// Hold this session's credentials in the caller's cells rather than
    /// private ones, so a reader sharing them sees every rotation. Replaces
    /// both cells outright: call it on a fresh client, before login.
    pub fn with_session_bearers(
        mut self,
        session: SessionBearer,
        accelerator: SessionBearer,
    ) -> Self {
        self.session = session;
        self.accelerator = accelerator;
        self
    }

    /// The API base URL, without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Whether an access token is currently held in memory.
    pub fn is_authenticated(&self) -> bool {
        self.session.is_held()
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
        let challenge = self.identity_challenge(&public_key).await?;
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
        self.store_tokens(tokens).await?;
        Ok(LoginOutcome { is_new_user })
    }

    /// Issue a single-use SIWE nonce to embed in an EIP-4361 message.
    pub async fn siwe_challenge(&self) -> Result<SiweNonce, ApiError> {
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: self.url("/auth/siwe/challenge"),
            headers: Vec::new(),
            body: None,
            credentials: HttpCredentials::Include,
            timeout_ms: Some(CONTROL_TIMEOUT_MS),
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
        self.store_tokens(tokens).await?;
        Ok(LoginOutcome { is_new_user })
    }

    /// Fetch a challenge for `public_key`, refusing one the API could not have
    /// issued before it reaches the identity key ([`is_identity_challenge`]).
    async fn identity_challenge(&self, public_key: &str) -> Result<String, ApiError> {
        let response = self
            .post_json("/auth/challenge", &ChallengeRequest { public_key })
            .await?;
        let response = ok_or_err(response)?;
        let body: ChallengeResponse = decode(&response)?;
        if !is_identity_challenge(&body.challenge) {
            return Err(ApiError::Decode("unusable login challenge".into()));
        }
        Ok(body.challenge)
    }

    /// The login methods on the authenticated account (owner-authenticated).
    pub async fn auth_methods(&self) -> Result<Vec<AuthMethod>, ApiError> {
        let response = self
            .request_authed(HttpMethod::Get, "/auth/methods")
            .await?;
        let response = ok_or_err(response)?;
        decode(&response)
    }

    /// Unlink one login method, re-proving the account identity key first: a
    /// stolen access token alone must not strip an account's other methods.
    pub async fn unlink_auth_method(
        &self,
        method_id: &str,
        signer: &impl ChallengeSigner,
    ) -> Result<(), ApiError> {
        let challenge = self.identity_challenge(&signer.public_key_hex()).await?;
        let signature = signer.sign_challenge(&challenge);
        let response = self
            .json_authed(
                HttpMethod::Post,
                "/auth/unlink",
                &UnlinkMethodRequest {
                    method_id,
                    challenge: &challenge,
                    signature: &signature,
                },
            )
            .await?;
        ok_or_err(response).map(drop)
    }

    /// Link a SIWE wallet to the authenticated account, re-proving the account
    /// identity key first: a link is a change to which keys open the account,
    /// so it carries the same live-possession proof [`Self::unlink_auth_method`]
    /// demands.
    pub async fn siwe_link(
        &self,
        message: &str,
        signature: &str,
        signer: &impl ChallengeSigner,
    ) -> Result<(), ApiError> {
        let challenge = self.identity_challenge(&signer.public_key_hex()).await?;
        let challenge_signature = signer.sign_challenge(&challenge);
        let response = self
            .json_authed(
                HttpMethod::Post,
                "/auth/siwe/link",
                &SiweLinkRequest {
                    message,
                    signature,
                    challenge: &challenge,
                    challenge_signature: &challenge_signature,
                },
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
        self.store_tokens(TokenResponse {
            access_token: body.access_token,
            refresh_token: body.refresh_token,
            accelerator_token: body.accelerator_token,
            is_new_user: body.is_new_user,
        })
        .await?;
        Ok(outcome)
    }

    /// Rotate the refresh token. Single-flight: a concurrent caller awaits the
    /// in-flight rotation instead of spending its own (already-invalidated)
    /// token. On failure the local session is torn down.
    pub async fn refresh(&self) -> Result<(), ApiError> {
        let receiver = {
            let mut slot = self.refresh_waiters.borrow_mut();
            match slot.as_mut() {
                // A refresh is already running: enqueue and await its result.
                Some(waiters) => {
                    let (tx, rx) = oneshot::channel();
                    waiters.push(tx);
                    Some(rx)
                }
                // We are the leader: mark a refresh in progress and run it.
                None => {
                    *slot = Some(Vec::new());
                    None
                }
            }
        };

        if let Some(rx) = receiver {
            return match rx.await {
                Ok(result) => result,
                // A cancelled leader is availability, not a dead session — the
                // caller must not be told to re-login.
                Err(oneshot::Canceled) => Err(ApiError::Transport(SeamError::new(
                    "refresh was cancelled before it completed",
                ))),
            };
        }

        let lead = RefreshLead {
            waiters: &self.refresh_waiters,
        };
        let result = self.do_refresh().await;
        for tx in lead.waiters() {
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

    /// Batch retire names or CIDs (`[ipnsName | cid]`), reporting what the
    /// registry deleted for this account.
    pub async fn retire(&self, targets: &[String]) -> Result<RetireResult, ApiError> {
        let response = self
            .json_authed(HttpMethod::Post, "/registry/retire", targets)
            .await?;
        let response = ok_or_err(response)?;
        decode(&response)
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
                TRANSFER_TIMEOUT_MS,
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
    ///
    /// The id comes from an integrity-untrusted transport and lands in this
    /// authenticated request's path, so an id the seam contract does not admit
    /// ([`item_id_is_legal`]) is refused before a request is built.
    pub async fn mailbox_ack(&self, id: &str) -> Result<(), ApiError> {
        if !item_id_is_legal(id) {
            return Err(ApiError::Decode("illegal mailbox item id".into()));
        }
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
            credentials: HttpCredentials::Include,
            timeout_ms: Some(CONTROL_TIMEOUT_MS),
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
            CONTROL_TIMEOUT_MS,
        )
        .await
    }

    /// Send a bodyless authenticated request with one refresh-then-retry on 401.
    async fn request_authed(
        &self,
        method: HttpMethod,
        path: &str,
    ) -> Result<HttpResponse, ApiError> {
        self.request_authed_with(method, path, None, &[], None, CONTROL_TIMEOUT_MS)
            .await
    }

    /// [`Self::request_authed`], plus a body, request-specific headers, and an
    /// explicit per-request-class deadline.
    async fn request_authed_with(
        &self,
        method: HttpMethod,
        path: &str,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
        timeout_ms: u64,
    ) -> Result<HttpResponse, ApiError> {
        let first = self
            .send_with_token(
                method,
                path,
                content_type,
                extra_headers,
                body.clone(),
                timeout_ms,
            )
            .await?;
        if first.status != 401 {
            return Ok(first);
        }
        // One refresh, then one retry; a second 401 is terminal (the caller
        // maps it via `ok_or_err`).
        self.refresh().await?;
        self.send_with_token(method, path, content_type, extra_headers, body, timeout_ms)
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
        timeout_ms: u64,
    ) -> Result<HttpResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(content_type) = content_type {
            headers.push((CONTENT_TYPE.to_owned(), content_type.to_owned()));
        }
        for (name, value) in extra_headers {
            headers.push(((*name).to_owned(), (*value).to_owned()));
        }
        let bearer = match self.session.peek().map(|t| bearer_header(t.as_str())) {
            Some(Ok(header)) => Some(header),
            // Drop a token that can never be a header value instead of
            // refusing every later call while still holding it: the next
            // call then goes out unauthenticated and its 401 drives one
            // refresh. The refresh credential is a separate secret and
            // stays, so a malformed response cannot end the session.
            Some(Err(_)) => {
                self.session.clear();
                return Err(ApiError::Decode("unusable access token".into()));
            }
            None => None,
        };
        if let Some(header) = bearer {
            headers.push(header);
        }
        let request = HttpRequest {
            method,
            url: self.url(path),
            headers,
            body,
            credentials: HttpCredentials::Include,
            timeout_ms: Some(timeout_ms),
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
            credentials: HttpCredentials::Include,
            timeout_ms: Some(CONTROL_TIMEOUT_MS),
        };
        let response = self.http.send(request).await?;
        if !is_success(response.status) {
            // A refusal means the session is dead: drop the stale access +
            // refresh material so it is never replayed. Anything else — the
            // API's contended-resource 503, a gateway error — left the token
            // unspent, so discarding it would turn a retryable blip into a
            // forced re-login.
            if is_session_refusal(response.status) {
                self.clear_session().await?;
            }
            return Err(error_from_response(&response));
        }
        // A 2xx spent the presented token whatever the body says — the API
        // commits the rotation before answering. Keeping it would replay a used
        // token into reuse detection, which revokes the whole family.
        let tokens: TokenResponse = match decode(&response) {
            Ok(tokens) => tokens,
            Err(error) => {
                self.clear_session().await?;
                return Err(error);
            }
        };
        self.store_tokens(tokens).await
    }

    /// Persist the refresh token and hold the two in-memory bearers. The
    /// refresh string is zeroized once handed to the store.
    async fn store_tokens(&self, tokens: TokenResponse) -> Result<(), ApiError> {
        let refresh_token = Zeroizing::new(tokens.refresh_token);
        self.credentials
            .store_refresh_token(refresh_token.as_bytes())
            .await?;
        self.session.set(tokens.access_token);
        self.accelerator.set(tokens.accelerator_token);
        Ok(())
    }

    /// Drop both in-memory bearers and any persisted refresh token.
    async fn clear_session(&self) -> Result<(), ApiError> {
        self.session.clear();
        self.accelerator.clear();
        self.credentials.clear_refresh_token().await?;
        Ok(())
    }
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// A refusal of the credential itself, as opposed to a transport or capacity
/// failure that says nothing about whether the session is still good.
fn is_session_refusal(status: u16) -> bool {
    status == 401 || status == 403
}

/// The domain tag the API stamps on an identity login challenge
/// (`apps/api/src/auth/services/challenge.service.ts`). Versioned, so a format
/// change bumps it rather than silently widening what this key will sign.
const IDENTITY_CHALLENGE_PREFIX: &str = "cipherbox-login:v2:";
/// The challenge's random tail: 32 bytes rendered lowercase hex.
const IDENTITY_CHALLENGE_NONCE_LEN: usize = 64;

/// Whether the server's answer is a challenge this key may sign: the login
/// domain tag followed by exactly the API's random tail.
///
/// The signer hands `sha256(utf8(challenge))` to the secp256k1 identity key,
/// so an unchecked challenge makes that key a signing oracle for any UTF-8
/// preimage. Pinning the whole shape — not just the tag — leaves a hostile
/// responder no steerable byte outside the hex alphabet the API renders.
fn is_identity_challenge(challenge: &str) -> bool {
    challenge
        .strip_prefix(IDENTITY_CHALLENGE_PREFIX)
        .is_some_and(|nonce| {
            nonce.len() == IDENTITY_CHALLENGE_NONCE_LEN
                && nonce
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
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

    use super::super::types::{AuthMethodKind, login_response, new_user_login_response};

    use crate::seams::{AUTHORIZATION, Mailbox};
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

    fn bearer_value(request: &HttpRequest) -> Option<&str> {
        request
            .headers
            .iter()
            .find(|(name, _)| name == AUTHORIZATION)
            .map(|(_, value)| value.as_str())
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

    /// A challenge shaped exactly as the API issues one: the login domain tag
    /// plus 32 random bytes in lowercase hex.
    fn challenge() -> String {
        IDENTITY_CHALLENGE_PREFIX.to_owned() + &"0123456789abcdef".repeat(4)
    }

    /// Log in so the client holds an access token and a stored refresh token.
    fn login(http: &ScriptedHttp, client: &ApiClient<ScriptedHttp, InMemoryCredentialStore>) {
        http.enqueue_response(json_response(
            200,
            json!({ "challenge": challenge(), "expiresAt": "2026-01-01T00:00:00Z" }),
        ));
        http.enqueue_response(json_response(
            200,
            new_user_login_response("jwt-1", &"a".repeat(64), "gw-a"),
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
        assert_eq!(login_body["challenge"], challenge());
        assert_eq!(login_body["signature"], format!("sig-for-{}", challenge()));

        let stored = block_on(creds.load_refresh_token()).unwrap().unwrap();
        assert_eq!(stored, "a".repeat(64).as_bytes());
    }

    /// Every shape the API could not have issued. Each breaks a different part
    /// of the pin, so none is subsumed by another.
    fn hostile_challenges() -> Vec<String> {
        let hex64 = "0123456789abcdef".repeat(4);
        vec![
            String::new(),
            // The tag with no tail at all.
            IDENTITY_CHALLENGE_PREFIX.to_owned(),
            // No domain tag: an arbitrary preimage of the responder's choosing.
            hex64.clone(),
            // Another protocol's tag, and an older version of this one.
            format!("cipherbox-grant:v2:{hex64}"),
            format!("cipherbox-login:v1:{hex64}"),
            // The tag as a suffix, not a prefix — guards a `contains` regression.
            format!("{hex64}{IDENTITY_CHALLENGE_PREFIX}"),
            // Right tag and alphabet, wrong width — short, then long.
            format!("{IDENTITY_CHALLENGE_PREFIX}{}", &hex64[..63]),
            format!("{IDENTITY_CHALLENGE_PREFIX}{hex64}0"),
            // Right width, outside the hex alphabet: all-caps, one uppercase
            // digit among 64, then a wholly attacker-chosen tail.
            format!(
                "{IDENTITY_CHALLENGE_PREFIX}{}",
                "0123456789ABCDEF".repeat(4)
            ),
            format!("{IDENTITY_CHALLENGE_PREFIX}{}A", &hex64[..63]),
            format!("{IDENTITY_CHALLENGE_PREFIX}{:_<64}", "sign anything"),
            // 64 chars but 65 bytes, then 64 bytes with a multi-byte tail: the
            // width check counts bytes, and the alphabet catches what it misses.
            format!("{IDENTITY_CHALLENGE_PREFIX}{}\u{e9}", &hex64[..63]),
            format!("{IDENTITY_CHALLENGE_PREFIX}{}\u{e9}", &hex64[..62]),
            // An interior control character; the tail is echoed to /auth/login.
            format!("{IDENTITY_CHALLENGE_PREFIX}{}\0", &hex64[..63]),
        ]
    }

    /// The accept side of the pin: every tail the API's hex renderer can emit
    /// is admitted, so a tightening that would break a real login fails here
    /// rather than in staging.
    #[test]
    fn the_shape_the_api_issues_is_accepted_at_the_class_boundaries() {
        for tail in ["0".repeat(64), "f".repeat(64), "0123456789abcdef".repeat(4)] {
            assert!(is_identity_challenge(&format!(
                "{IDENTITY_CHALLENGE_PREFIX}{tail}"
            )));
        }
    }

    /// The guard is "never signs", not merely "never sends": a refused
    /// challenge must not reach the identity key at all.
    #[test]
    fn a_challenge_the_api_could_not_have_issued_is_never_signed() {
        struct PanickingSigner;

        impl ChallengeSigner for PanickingSigner {
            fn public_key_hex(&self) -> String {
                "02".to_owned() + &"ab".repeat(32)
            }
            fn sign_challenge(&self, challenge: &str) -> String {
                panic!("the identity key signed a refused challenge: {challenge:?}");
            }
        }

        for challenge in hostile_challenges() {
            let (http, _creds, client) = fakes();
            http.enqueue_response(json_response(
                200,
                json!({ "challenge": challenge, "expiresAt": "2026-01-01T00:00:00Z" }),
            ));
            assert_eq!(
                block_on(client.login_identity(&PanickingSigner)).unwrap_err(),
                ApiError::Decode("unusable login challenge".into()),
                "challenge {challenge:?} must be refused"
            );
            let requests = http.requests();
            assert_eq!(requests.len(), 1, "only /auth/challenge for {challenge:?}");
            assert_eq!(requests[0].url, "http://api.test/auth/challenge");
            assert!(!client.is_authenticated());
        }
    }

    #[test]
    fn identity_login_bad_signature_is_unauthorized() {
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            200,
            json!({ "challenge": challenge(), "expiresAt": "2026-01-01T00:00:00Z" }),
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

    /// The two bearers are separate capabilities: the API leg presents the
    /// session JWT, the gateway leg the read-scoped pseudonym.
    #[test]
    fn the_api_leg_presents_the_access_jwt_while_the_accelerator_holds_the_pseudonym() {
        let (http, _creds, client) = fakes();
        let accelerator = SessionBearer::default();
        let client = client.with_session_bearers(SessionBearer::default(), accelerator.clone());
        login(&http, &client);

        http.enqueue_response(json_response(200, json!({})));
        block_on(client.register(&[])).expect("register");

        let request = http.requests().pop().unwrap();
        assert_eq!(bearer_value(&request), Some("Bearer jwt-1"));
        assert_eq!(
            accelerator.peek().as_deref().map(String::as_str),
            Some("gw-a"),
            "the gateway leg reads the pseudonym from its own cell"
        );
    }

    #[test]
    fn rotation_replaces_the_pseudonym_the_accelerator_presents() {
        let (http, _creds, client) = fakes();
        let accelerator = SessionBearer::default();
        let client = client.with_session_bearers(SessionBearer::default(), accelerator.clone());
        login(&http, &client);

        http.enqueue_response(json_response(
            200,
            login_response("jwt-2", &"b".repeat(64), "gw-b"),
        ));
        block_on(client.refresh()).expect("refresh");

        assert_eq!(
            accelerator.peek().as_deref().map(String::as_str),
            Some("gw-b")
        );
    }

    #[test]
    fn a_dead_session_drops_the_pseudonym_too() {
        let (http, _creds, client) = fakes();
        let accelerator = SessionBearer::default();
        let client = client.with_session_bearers(SessionBearer::default(), accelerator.clone());
        login(&http, &client);
        http.enqueue_response(json_response(
            401,
            json!({ "message": "Invalid refresh token" }),
        ));

        assert_eq!(
            block_on(client.refresh()).unwrap_err(),
            ApiError::Unauthorized
        );
        assert!(!accelerator.is_held(), "gateway reads die with the session");
    }

    #[test]
    fn a_contended_refresh_keeps_the_token_it_could_not_spend() {
        // The API serializes an account's rotation and answers a wait past its
        // bound with 503, having spent nothing. Discarding the credential here
        // would turn that retryable blip into a forced re-login.
        let (http, creds, client) = fakes();
        block_on(creds.store_refresh_token(b"seed-refresh-token")).unwrap();
        http.enqueue_response(json_response(
            503,
            json!({ "message": "Contended resource; retry shortly" }),
        ));

        assert!(block_on(client.refresh()).is_err());

        let stored = block_on(creds.load_refresh_token()).unwrap().unwrap();
        assert_eq!(stored, b"seed-refresh-token");
    }

    #[test]
    fn a_login_body_without_the_accelerator_token_fails_closed() {
        // The accelerator bearer must never fall back to the session JWT: the
        // gateway tier would then see an identity-bearing credential. The 2xx
        // spent the presented token, so the dead session goes with it.
        let (http, creds, client) = fakes();
        let accelerator = SessionBearer::default();
        let client = client.with_session_bearers(SessionBearer::default(), accelerator.clone());
        login(&http, &client);
        http.enqueue_response(json_response(
            200,
            json!({ "accessToken": "jwt-2", "refreshToken": "b".repeat(64) }),
        ));

        assert!(matches!(
            block_on(client.refresh()).unwrap_err(),
            ApiError::Decode(_)
        ));
        assert!(!accelerator.is_held());
        assert!(!client.is_authenticated());
        assert!(block_on(creds.load_refresh_token()).unwrap().is_none());
    }

    #[test]
    fn refresh_sends_the_stored_token_and_rotates() {
        let (http, creds, client) = fakes();
        block_on(creds.store_refresh_token(b"seed-refresh-token")).unwrap();
        http.enqueue_response(json_response(
            200,
            login_response("jwt-2", &"b".repeat(64), "gw-b"),
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
            login_response("jwt", &"c".repeat(64), "gw-c"),
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
            login_response("jwt-2", &"d".repeat(64), "gw-d"),
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
            login_response("jwt-2", &"d".repeat(64), "gw-d"),
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
        let mut body = new_user_login_response("jwt", &"e".repeat(64), "gw-e");
        body["publicKey"] = json!("02cafe");
        body["privateKey"] = json!(private_key);
        http.enqueue_response(json_response(200, body));

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

    /// The defect this client's `Mailbox` impl exists to fix: the browser seam
    /// it replaced sent no bearer, so every mailbox route 401'd.
    #[test]
    fn every_mailbox_seam_call_carries_the_session_bearer() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        http.enqueue_response(json_response(201, json!({ "id": "m1" })));
        http.enqueue_response(json_response(200, json!({ "messages": [] })));
        http.enqueue_response(json_response(200, json!({ "success": true })));

        block_on(Mailbox::post(&client, &[0x02; 33], b"sealed", "idem")).expect("post");
        block_on(Mailbox::poll(&client)).expect("poll");
        block_on(Mailbox::ack(&client, "m1")).expect("ack");

        let requests = http.requests();
        for request in &requests[2..] {
            assert_eq!(
                bearer_value(request),
                Some("Bearer jwt-1"),
                "{} must present the session bearer",
                request.url
            );
        }
    }

    /// The defect's other half: the browser seam had no 401-refresh-retry, so
    /// an expired token wedged it permanently.
    #[test]
    fn a_mailbox_401_refreshes_once_and_retries() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        http.enqueue_response(json_response(401, json!({ "message": "expired" })));
        http.enqueue_response(json_response(
            200,
            login_response("jwt-2", &"b".repeat(64), "gw-b"),
        ));
        http.enqueue_response(json_response(200, json!({ "messages": [] })));

        block_on(Mailbox::poll(&client)).expect("poll after refresh");

        let urls: Vec<_> = http.requests().iter().map(|r| r.url.clone()).collect();
        assert_eq!(
            urls[2..],
            [
                "http://api.test/mailbox/messages",
                "http://api.test/auth/refresh",
                "http://api.test/mailbox/messages",
            ],
            "one refresh, then one retry of the same route"
        );
    }

    /// Routing addresses the recipient's identity key as the API's lowercase-hex
    /// `recipientPublicKey`.
    #[test]
    fn the_mailbox_seam_posts_a_lowercase_hex_recipient() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        http.enqueue_response(json_response(201, json!({ "id": "m1" })));

        block_on(Mailbox::post(&client, &[0x02; 33], b"sealed", "idem")).expect("post");

        let body = body_json(&http.requests()[2]);
        assert_eq!(body["recipientPublicKey"], "02".repeat(33));
        assert_eq!(body["blob"], BASE64.encode(b"sealed"));
    }

    /// The item id is transport-supplied and lands in this request's path, so
    /// an id that could move the ack elsewhere never reaches the wire. `.` and
    /// `..` are in the unreserved alphabet but resolve away in a URL.
    #[test]
    fn an_item_id_that_could_steer_the_ack_route_is_refused() {
        let (http, _creds, client) = fakes();
        login(&http, &client);

        for hostile in [
            "..",
            ".",
            "../../account",
            "m1/../account",
            "m 1",
            "m1?x=1",
            "",
        ] {
            assert!(
                block_on(client.mailbox_ack(hostile)).is_err(),
                "{hostile:?} must not reach the transport"
            );
        }
        assert_eq!(
            http.requests().len(),
            2,
            "a refused ack sends nothing beyond the login"
        );
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
            login_response("jwt", &"f".repeat(64), "gw-f"),
        ));

        assert!(matches!(first.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(http.request_count(), 1, "one refresh served both callers");
        assert!(client.is_authenticated());
    }

    /// A leader dropped while parked on the network must hand leadership back,
    /// or every later caller enqueues behind a rotation that will never finish.
    #[test]
    fn a_cancelled_refresh_leader_lets_the_next_caller_lead() {
        let http = GatedHttp::default();
        let creds = InMemoryCredentialStore::default();
        block_on(creds.store_refresh_token(b"seed-refresh-token")).unwrap();
        let client = ApiClient::new(http.clone(), creds, "http://api.test");
        let mut cx = Context::from_waker(Waker::noop());

        {
            let mut leader = pin!(client.refresh());
            assert!(leader.as_mut().poll(&mut cx).is_pending());
            assert_eq!(http.request_count(), 1);
        } // The leader's future is dropped mid-flight.

        // The next caller leads a fresh rotation rather than parking.
        let mut next = pin!(client.refresh());
        assert!(next.as_mut().poll(&mut cx).is_pending());
        assert_eq!(http.request_count(), 2, "the slot was handed back");

        http.release(json_response(
            200,
            login_response("jwt", &"f".repeat(64), "gw-f"),
        ));
        assert!(matches!(next.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        assert!(client.is_authenticated());
    }

    /// A waiter behind a cancelled leader is woken, and told it was an
    /// availability failure — not that its session is dead.
    #[test]
    fn a_waiter_behind_a_cancelled_leader_is_woken_not_parked() {
        let http = GatedHttp::default();
        let creds = InMemoryCredentialStore::default();
        block_on(creds.store_refresh_token(b"seed-refresh-token")).unwrap();
        let client = ApiClient::new(http.clone(), creds, "http://api.test");
        let mut cx = Context::from_waker(Waker::noop());

        let mut waiter = pin!(client.refresh());
        {
            let mut leader = pin!(client.refresh());
            assert!(leader.as_mut().poll(&mut cx).is_pending());
            assert!(waiter.as_mut().poll(&mut cx).is_pending());
            assert_eq!(http.request_count(), 1, "the waiter coalesced");
        }

        match waiter.as_mut().poll(&mut cx) {
            Poll::Ready(Err(ApiError::Transport(_))) => {}
            other => panic!("a cancelled leader is availability, got {other:?}"),
        }
    }

    /// The access token is the API's bytes, so it meets the seam's header-value
    /// rule like any other bearer: an unusable one fails closed rather than
    /// reaching the transport.
    #[test]
    fn an_access_token_that_cannot_be_a_header_value_is_refused() {
        let (http, _creds, client) = fakes();
        http.enqueue_response(json_response(
            200,
            json!({ "challenge": challenge(), "expiresAt": "2026-01-01T00:00:00Z" }),
        ));
        http.enqueue_response(json_response(
            200,
            login_response("jwt-1\r\nX-Injected: yes", &"a".repeat(64), "gw-a"),
        ));
        block_on(client.login_identity(&StubSigner)).expect("login");

        assert_eq!(
            block_on(client.quota()).unwrap_err(),
            ApiError::Decode("unusable access token".into())
        );
        assert_eq!(http.requests().len(), 2, "no request carried the token");
        assert!(!client.is_authenticated(), "the unusable token was dropped");

        // Self-heal: the next call goes out unauthenticated, and its 401 buys
        // one rotation off the still-held refresh credential.
        http.enqueue_response(json_response(401, json!({ "message": "no bearer" })));
        http.enqueue_response(json_response(
            200,
            login_response("jwt-2", &"b".repeat(64), "gw-b"),
        ));
        http.enqueue_response(json_response(
            200,
            json!({ "usedBytes": 1, "limitBytes": 2, "advisory": false }),
        ));

        block_on(client.quota()).expect("the session recovered");
        let requests = http.requests();
        assert!(!has_bearer(&requests[2]), "the dropped token was not sent");
        assert_eq!(requests[3].url, "http://api.test/auth/refresh");
        assert!(has_bearer(&requests[4]), "the retry carried the new token");
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

    // --- login methods: list and unlink ---

    /// A kind this build does not know still renders: the row is a display
    /// fact, so refusing the whole read would blank a pane over a server the
    /// account can still log in through.
    #[test]
    fn auth_methods_decodes_display_rows_including_an_unknown_kind() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        let sent_after_login = http.requests().len();
        http.enqueue_response(json_response(
            200,
            json!([
                {
                    "id": "row-1",
                    "kind": "identity",
                    "identifierDisplay": "0x1234\u{2026}abcd",
                    "createdAt": "2026-08-27T10:00:00.000Z",
                    "lastUsedAt": "2026-08-27T11:00:00.000Z",
                },
                {
                    "id": "row-2",
                    "kind": "wallet",
                    "identifierDisplay": null,
                    "createdAt": "2026-08-27T09:00:00.000Z",
                },
                { "id": "row-3", "kind": "passkey", "createdAt": "2026-08-27T08:00:00.000Z" },
            ]),
        ));

        let methods = block_on(client.auth_methods()).expect("auth methods");

        assert_eq!(
            methods,
            vec![
                AuthMethod {
                    id: "row-1".to_owned(),
                    kind: AuthMethodKind::Identity,
                    identifier_display: Some("0x1234\u{2026}abcd".to_owned()),
                    created_at: "2026-08-27T10:00:00.000Z".to_owned(),
                    last_used_at: Some("2026-08-27T11:00:00.000Z".to_owned()),
                },
                AuthMethod {
                    id: "row-2".to_owned(),
                    kind: AuthMethodKind::Wallet,
                    identifier_display: None,
                    created_at: "2026-08-27T09:00:00.000Z".to_owned(),
                    last_used_at: None,
                },
                AuthMethod {
                    id: "row-3".to_owned(),
                    kind: AuthMethodKind::Unknown,
                    identifier_display: None,
                    created_at: "2026-08-27T08:00:00.000Z".to_owned(),
                    last_used_at: None,
                },
            ],
        );
        let requests = http.requests();
        assert_eq!(requests.len(), sent_after_login + 1);
        let read = requests.last().expect("the read was sent");
        assert_eq!(read.method, HttpMethod::Get);
        assert_eq!(read.url, "http://api.test/auth/methods");
        assert!(has_bearer(read), "the read is owner-authenticated");
    }

    /// A stolen access token alone must not strip an account's other login
    /// methods, so the unlink re-proves live possession of the identity key.
    #[test]
    fn unlink_auth_method_reproves_the_identity_key_before_deleting() {
        let (http, _creds, client) = fakes();
        login(&http, &client);
        let sent_after_login = http.requests().len();
        http.enqueue_response(json_response(200, json!({ "challenge": challenge() })));
        http.enqueue_response(json_response(200, json!({ "success": true })));

        block_on(client.unlink_auth_method("method-1", &StubSigner)).expect("unlink");

        let requests = http.requests();
        let sent = &requests[sent_after_login..];
        assert_eq!(sent.len(), 2, "one challenge, then one unlink");
        assert_eq!(sent[0].url, "http://api.test/auth/challenge");
        assert_eq!(
            body_json(&sent[0])["publicKey"],
            StubSigner.public_key_hex()
        );
        assert_eq!(sent[1].method, HttpMethod::Post);
        assert_eq!(sent[1].url, "http://api.test/auth/unlink");
        assert!(has_bearer(&sent[1]));
        let body = body_json(&sent[1]);
        assert_eq!(body["methodId"], "method-1");
        assert_eq!(body["challenge"], challenge());
        assert_eq!(body["signature"], format!("sig-for-{}", challenge()));
        assert!(
            body.get("publicKey").is_none(),
            "the server reads the key off the token, never the body"
        );
    }

    /// The unlink challenge clears the same pin the login one does — it goes
    /// to the same signing key, so an unchecked one is the same oracle.
    #[test]
    fn an_unlink_challenge_the_api_could_not_have_issued_is_never_signed() {
        struct PanickingSigner;

        impl ChallengeSigner for PanickingSigner {
            fn public_key_hex(&self) -> String {
                "02".to_owned() + &"ab".repeat(32)
            }
            fn sign_challenge(&self, challenge: &str) -> String {
                panic!("the identity key signed a refused challenge: {challenge:?}");
            }
        }

        for challenge in hostile_challenges() {
            let (http, _creds, client) = fakes();
            http.enqueue_response(json_response(
                200,
                json!({ "challenge": challenge.clone() }),
            ));
            assert_eq!(
                block_on(client.unlink_auth_method("method-1", &PanickingSigner)).unwrap_err(),
                ApiError::Decode("unusable login challenge".into()),
                "challenge {challenge:?} must be refused"
            );
            let requests = http.requests();
            assert_eq!(requests.len(), 1, "only /auth/challenge for {challenge:?}");
            assert_eq!(requests[0].url, "http://api.test/auth/challenge");
        }
    }
}
