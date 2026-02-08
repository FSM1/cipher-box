//! API client module for CipherBox Desktop.
//!
//! Provides HTTP client with auth header injection, Keychain token storage,
//! IPFS/IPNS operations, and request/response types matching the CipherBox backend API.

pub mod auth;
pub mod client;
pub mod ipfs;
pub mod ipns;
pub mod types;
