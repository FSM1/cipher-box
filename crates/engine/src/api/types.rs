//! Wire DTOs and the public outcome types for the [`super::ApiClient`].
//!
//! Field names mirror the NestJS API's camelCase JSON verbatim (AGENTS.md:
//! camelCase for API fields). The token-bearing request/response structs are
//! crate-internal and deliberately implement no `Debug` — tokens and
//! signatures must never reach a log site (security rule 2). Public outcome
//! types expose only non-secret data, except the test-login private key which
//! is zeroized and redacted.

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// --- auth requests (serialized to JSON bodies) ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChallengeRequest<'a> {
    pub public_key: &'a str,
}

/// An account-management operation that re-proves the identity key. The API
/// mints one challenge pool per operation and refuses a cross-operation spend.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StepUpOperation {
    Link,
    Unlink,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StepUpChallengeRequest<'a> {
    pub operation: StepUpOperation,
    /// The row an unlink challenge may remove; omitted for every other
    /// operation, which the API refuses to bind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_id: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginRequest<'a> {
    pub public_key: &'a str,
    pub challenge: &'a str,
    pub signature: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshRequest {
    /// Omitted entirely on web, where the HTTP-only refresh cookie rides the
    /// Http seam instead of a body field (blueprint/engine.md CredentialStore).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SiweLoginRequest<'a> {
    pub message: &'a str,
    pub signature: &'a str,
}

/// The link body for [`ApiClient::siwe_link`](super::ApiClient::siwe_link): the
/// SIWE pair plus the identity re-proof, whose signature is named apart from the
/// wallet's.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SiweLinkRequest<'a> {
    pub message: &'a str,
    pub signature: &'a str,
    pub challenge: &'a str,
    pub challenge_signature: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TestLoginRequest<'a> {
    pub handle: &'a str,
    pub secret: &'a str,
}

/// The unlink body for
/// [`ApiClient::unlink_auth_method`](super::ApiClient::unlink_auth_method).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnlinkMethodRequest<'a> {
    pub method_id: &'a str,
    pub challenge: &'a str,
    pub signature: &'a str,
}

// --- auth responses (deserialized from JSON bodies) ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    /// The read accelerator's opaque pseudonym (CONTEXT.md, Accelerator token).
    pub accelerator_token: String,
    #[serde(default)]
    pub is_new_user: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SiweChallengeResponse {
    pub nonce: String,
    pub expires_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TestLoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub accelerator_token: String,
    #[serde(default)]
    pub is_new_user: Option<bool>,
    pub public_key: String,
    pub private_key: String,
}

/// The login/refresh response body the auth tests enqueue — one home for its
/// field names, so a wire rename touches this literal rather than every test.
#[cfg(test)]
pub(crate) fn login_response(
    access_token: &str,
    refresh_token: &str,
    accelerator_token: &str,
) -> serde_json::Value {
    serde_json::json!({
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "acceleratorToken": accelerator_token,
    })
}

/// [`login_response`] for a login that implicitly created the account.
#[cfg(test)]
pub(crate) fn new_user_login_response(
    access_token: &str,
    refresh_token: &str,
    accelerator_token: &str,
) -> serde_json::Value {
    let mut body = login_response(access_token, refresh_token, accelerator_token);
    body["isNewUser"] = serde_json::json!(true);
    body
}

/// A NestJS error envelope: `{ statusCode, message, error, code? }`. `message`
/// is a string or an array of strings (validation failures); both are accepted.
/// `code` is the stable machine discriminator the API stamps where one status
/// covers unrelated causes (blueprint/api.md; the two upload 413s).
#[derive(Deserialize)]
pub(crate) struct ErrorBody {
    #[serde(default)]
    pub message: serde_json::Value,
    #[serde(default)]
    pub code: Option<String>,
}

impl ErrorBody {
    /// The server's message as a flat string, or `None` when absent.
    pub fn message_string(&self) -> Option<String> {
        match &self.message {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Array(items) => {
                let joined = items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                (!joined.is_empty()).then_some(joined)
            }
            _ => None,
        }
    }
}

// --- public outcome types (returned across the client boundary) ---

/// The result of a successful identity or SIWE login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginOutcome {
    /// True when this login implicitly created the account (first login).
    pub is_new_user: bool,
}

/// One login method on the account, as `/auth/methods` serves it. Display form
/// only: the identifier hash never crosses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethod {
    /// The row id, which [`ApiClient::unlink_auth_method`](super::ApiClient::unlink_auth_method)
    /// names.
    pub id: String,
    /// Which login surface this row admits.
    pub kind: AuthMethodKind,
    /// A truncated, human-readable form of the identifier, when there is one.
    #[serde(default)]
    pub identifier_display: Option<String>,
    /// When the row was created, ISO 8601.
    pub created_at: String,
    /// When the row last logged in, ISO 8601, or absent if it never has.
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// Which login surface an [`AuthMethod`] admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethodKind {
    /// The account identity key (challenge-signature login).
    Identity,
    /// A linked SIWE wallet.
    Wallet,
    /// The staging-gated test login.
    Test,
    /// A kind this client does not know. Rendered as-is rather than refused —
    /// the row is a display fact, not a trust decision.
    #[serde(other)]
    Unknown,
}

/// A freshly issued SIWE nonce to embed in an EIP-4361 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiweNonce {
    /// The single-use nonce.
    pub nonce: String,
    /// Nonce expiry, ISO 8601.
    pub expires_at: String,
}

/// The result of the staging-gated test-login: the deterministic keypair plus
/// whether the account was created. `Debug` redacts the private key.
#[derive(Clone)]
pub struct TestLoginOutcome {
    /// True when this login implicitly created the account.
    pub is_new_user: bool,
    /// The deterministic compressed secp256k1 public key, lowercase hex.
    pub public_key: String,
    /// The deterministic secp256k1 private key, hex — a test hook only.
    /// Zeroized on drop and never logged.
    pub private_key: Zeroizing<String>,
}

impl fmt::Debug for TestLoginOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestLoginOutcome")
            .field("is_new_user", &self.is_new_user)
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

// --- pin/name registry, quota, content, mailbox, recovery ---
//
// The wire shapes below follow blueprint/api.md and are bound to the live API
// by the contract suite (`crates/contract`); the client methods are also
// unit-tested for request construction against the scripted Http fake.

/// One entry of a batch name registration
/// (`[{ipnsName, headCid?, contentCids[]}]`, blueprint/api.md).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NameRegistration {
    /// The IPNS name being registered.
    pub ipns_name: String,
    /// The head (metadata) CID, when publishing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_cid: Option<String>,
    /// The content CIDs to pin/count under this name.
    pub content_cids: Vec<String>,
}

/// A per-account quota response. Hosted rows are authoritative; a BYO account's
/// rows are advisory (`advisory: true`, quota always allows) — blueprint/api.md.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Quota {
    /// Bytes currently counted against the account.
    pub used_bytes: u64,
    /// The account's limit (env default plus any override).
    pub limit_bytes: u64,
    /// True for BYO accounts, whose rows never gate uploads.
    pub advisory: bool,
}

/// What a batch retire deleted for the caller's account.
///
/// `retired: 0` is the registry's own done-signal, not a failure: the rows are
/// gone, whether this call deleted them or a lost-response replay of it did. It
/// is not evidence they were *this* account's — the endpoint only ever deletes
/// the caller's rows, so another account's targets answer 0 too.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RetireResult {
    /// Inventory and pin rows deleted for the account.
    pub retired: u64,
    /// Rows whose global refcount reached zero, so the block physically
    /// unpinned.
    pub unpinned: u64,
}

/// The result of a hosted upload.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UploadResult {
    /// The content CID Kubo pinned.
    pub cid: String,
    /// The pinned size in bytes.
    pub size: u64,
}

/// One polled mailbox item. The blob is the HPKE-sealed payload bytes; no
/// sender metadata is exposed in the clear (blueprint/api.md Mailbox).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxItem {
    /// The item id (used to ack).
    pub id: String,
    /// When the item was received, ISO 8601.
    pub received_at: String,
    /// The sealed payload bytes.
    pub blob: Vec<u8>,
}

/// The mailbox item as it rides the wire: the blob is base64.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MailboxItemWire {
    pub id: String,
    pub received_at: String,
    pub blob: String,
}

/// The poll response envelope.
#[derive(Deserialize)]
pub(crate) struct MailboxPollWire {
    pub messages: Vec<MailboxItemWire>,
}

/// The post response: the server-assigned message id.
#[derive(Deserialize)]
pub(crate) struct MailboxPostWire {
    pub id: String,
}
