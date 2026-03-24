//! HTTP client re-export from `cipherbox_api_client`.
//!
//! The desktop app used to have its own `ApiClient` implementation.
//! Now it re-exports `cipherbox_api_client::ApiClient` so all desktop code
//! (`crate::api::ipfs`, `crate::api::ipns`, etc.) uses the same type
//! as the SDK's `KeyState.api`.

pub use cipherbox_api_client::ApiClient;
