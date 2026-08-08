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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TestLoginRequest<'a> {
    pub handle: &'a str,
    pub secret: &'a str,
}

// --- auth responses (deserialized from JSON bodies) ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
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
    #[serde(default)]
    pub is_new_user: Option<bool>,
    pub public_key: String,
    pub private_key: String,
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
