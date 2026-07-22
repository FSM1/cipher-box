//! The hand-written API client and token lifecycle (blueprint/engine.md
//! "API client").
//!
//! One client for both hosts, over the [`crate::seams::Http`] and
//! [`crate::seams::CredentialStore`] seams — no generated clients anywhere
//! (#28 D5). The NestJS API keeps emitting its OpenAPI spec as a docs
//! artifact; enforcement is the live contract-test suite (`crates/contract`),
//! not codegen. Only the auth/token surface is implemented server-side today
//! (#624); the registry/content/mailbox/recovery/account methods here follow
//! blueprint/api.md and are provisional until those API slices land, when the
//! contract suite binds them live.

mod client;
mod error;
mod signer;
mod types;

pub use client::ApiClient;
pub use error::ApiError;
pub use signer::{ChallengeSigner, IdentityChallengeSigner};
pub use types::{
    LoginOutcome, MailboxItem, NameRegistration, Quota, SiweNonce, TestLoginOutcome, UploadResult,
};
