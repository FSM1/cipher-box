//! Request and response types for the CipherBox backend API.
//!
//! All structs use camelCase serialization to match the API's JSON format.
//! Auth DTOs use manual Debug impls to redact sensitive fields (M-11).

use std::fmt;

use serde::{Deserialize, Serialize};

/// Login request body sent to POST /auth/login.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub id_token: String,
    pub public_key: String,
    pub login_type: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("id_token", &"[REDACTED]")
            .field("public_key", &"[REDACTED]")
            .field("login_type", &self.login_type)
            .finish()
    }
}

/// Login response from POST /auth/login (desktop client receives refreshToken in body).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub is_new_user: bool,
}

impl fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("is_new_user", &self.is_new_user)
            .finish()
    }
}

/// Refresh request body sent to POST /auth/refresh.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

/// Refresh response from POST /auth/refresh (desktop client receives refreshToken in body).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
}

impl fmt::Debug for RefreshResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

/// TEE public keys included in vault response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeeKeysResponse {
    pub current_epoch: u32,
    pub current_public_key: String,
    pub previous_epoch: Option<u32>,
    pub previous_public_key: Option<String>,
}

/// Request body for POST /vault/init (new user vault initialization).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitVaultRequest {
    pub owner_public_key: String,
    pub root_ipns_name: String,
}

impl fmt::Debug for InitVaultRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitVaultRequest")
            .field("owner_public_key", &"[REDACTED]")
            .field("root_ipns_name", &self.root_ipns_name)
            .finish()
    }
}

/// Vault response from GET /vault.
///
/// The rootFolderKey lives exclusively in the IPFS vault blob v2 header.
/// The IPNS key is HKDF-derived client-side.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultResponse {
    pub root_ipns_name: String,
    pub tee_keys: Option<TeeKeysResponse>,
}

impl fmt::Debug for VaultResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultResponse")
            .field("root_ipns_name", &self.root_ipns_name)
            .field("tee_keys", &self.tee_keys)
            .finish()
    }
}
