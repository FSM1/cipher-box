//! Typed HTTP client for CipherBox API.
//!
//! Provides async functions for all CipherBox API endpoints
//! used by the desktop app: auth, IPFS, IPNS, vault operations.
//! Mirrors @cipherbox/api-client TypeScript package.

pub mod auth;
pub mod client;
pub mod error;
pub mod ipfs;
pub mod ipns;
pub mod types;

pub use client::ApiClient;
pub use error::ApiError;
pub use types::*;
