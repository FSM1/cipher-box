//! The hand-written API client and token lifecycle (blueprint/engine.md
//! "API client").
//!
//! One client for both hosts, over the [`crate::seams::Http`] and
//! [`crate::seams::CredentialStore`] seams — no generated clients anywhere
//! (#28 D5). The NestJS API keeps emitting its OpenAPI spec as a docs
//! artifact; enforcement is the live contract-test suite (`crates/contract`),
//! not codegen.

mod client;
mod error;
mod mailbox;
mod signer;
mod types;

pub use client::ApiClient;
pub use error::{ApiError, QUOTA_EXCEEDED, REGISTRY_BATCH_REFUSED, UPLOAD_TOO_LARGE};
pub use signer::{ChallengeSigner, IdentityChallengeSigner};
pub use types::{
    LoginOutcome, MailboxItem, NameRegistration, Quota, RetireResult, SiweNonce, TestLoginOutcome,
    UploadResult,
};
#[cfg(test)]
pub(crate) use types::{login_response, new_user_login_response};
