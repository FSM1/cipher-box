//! Request and response types for the CipherBox backend API.
//!
//! All structs use camelCase serialization to match the API's JSON format.

use serde::{Deserialize, Serialize};

/// Login request body sent to POST /auth/login.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub id_token: String,
    pub public_key: String,
    pub login_type: String,
}

/// Login response from POST /auth/login (desktop client receives refreshToken in body).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub is_new_user: bool,
}

/// Refresh request body sent to POST /auth/refresh.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Refresh response from POST /auth/refresh (desktop client receives refreshToken in body).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
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

/// Vault response from GET /vault.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultResponse {
    pub encrypted_root_folder_key: String,
    pub root_ipns_name: String,
    pub encrypted_root_ipns_private_key: String,
    pub root_ipns_public_key: String,
    pub tee_keys: Option<TeeKeysResponse>,
}
