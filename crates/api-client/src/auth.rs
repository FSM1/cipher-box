//! Authentication operations via the CipherBox backend API.
//!
//! Provides login, refresh, logout, and vault operations.

use crate::client::ApiClient;
use crate::error::ApiError;
use crate::types::*;

/// Log in to the CipherBox backend.
///
/// POST /auth/login with Web3Auth id_token and secp256k1 public key.
/// Returns access and refresh tokens.
pub async fn login(client: &ApiClient, request: &LoginRequest) -> Result<LoginResponse, ApiError> {
    let resp = client.post("/auth/login", request).await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::AuthFailed(format!(
            "Login failed ({}): {}",
            status, body
        )));
    }

    resp.json::<LoginResponse>()
        .await
        .map_err(|e| ApiError::DeserializationFailed(format!("Login response: {}", e)))
}

/// Refresh the access token using a refresh token.
///
/// POST /auth/refresh with the current refresh token.
/// Returns new access and refresh tokens (rotation).
pub async fn refresh(
    client: &ApiClient,
    request: &RefreshRequest,
) -> Result<RefreshResponse, ApiError> {
    let resp = client.post("/auth/refresh", request).await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::AuthFailed(format!(
            "Refresh failed ({}): {}",
            status, body
        )));
    }

    resp.json::<RefreshResponse>()
        .await
        .map_err(|e| ApiError::DeserializationFailed(format!("Refresh response: {}", e)))
}

/// Log out from the CipherBox backend.
///
/// POST /auth/logout (authenticated). Best-effort -- errors are logged
/// but not propagated (matches web app pattern).
pub async fn logout(client: &ApiClient) -> Result<(), ApiError> {
    let resp = client.authenticated_post("/auth/logout", &()).await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        log::warn!("Logout returned non-success ({}): {}", status, body);
    }

    Ok(())
}

/// Fetch the current user's vault.
///
/// GET /vault returns the root IPNS name and TEE keys.
pub async fn get_vault(client: &ApiClient) -> Result<VaultResponse, ApiError> {
    let resp = client.authenticated_get("/vault").await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse {
            status,
            message: format!("Get vault failed: {}", body),
        });
    }

    resp.json::<VaultResponse>()
        .await
        .map_err(|e| ApiError::DeserializationFailed(format!("Vault response: {}", e)))
}

/// Initialize a new user's vault.
///
/// POST /vault/init with the owner's public key and root IPNS name.
pub async fn init_vault(
    client: &ApiClient,
    request: &InitVaultRequest,
) -> Result<(), ApiError> {
    let resp = client.authenticated_post("/vault/init", request).await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse {
            status,
            message: format!("Init vault failed: {}", body),
        });
    }

    Ok(())
}
