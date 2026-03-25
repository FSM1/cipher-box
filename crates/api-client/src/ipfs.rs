//! IPFS content operations via the CipherBox backend API.
//!
//! Provides fetching encrypted file content, uploading encrypted files,
//! and unpinning content. Content is always encrypted -- the backend
//! never sees plaintext.

use crate::client::ApiClient;
use crate::error::ApiError;
use crate::types::{UnpinRequest, UploadResponse};

/// Fetch encrypted file content from IPFS via the backend.
///
/// GET /ipfs/{cid} returns raw encrypted bytes (application/octet-stream).
pub async fn fetch_content(client: &ApiClient, cid: &str) -> Result<Vec<u8>, ApiError> {
    let resp = client
        .authenticated_get(&format!("/ipfs/{}", cid))
        .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse {
            status,
            message: format!("IPFS fetch failed: {}", body),
        });
    }

    let bytes = resp.bytes().await.map_err(|e| {
        ApiError::RequestFailed(e)
    })?;
    Ok(bytes.to_vec())
}

/// Upload encrypted file content to IPFS via the backend.
///
/// POST /ipfs/upload with multipart form data. Returns CID string.
pub async fn upload_content(client: &ApiClient, data: &[u8]) -> Result<String, ApiError> {
    use reqwest::multipart;

    let part = multipart::Part::bytes(data.to_vec())
        .file_name("encrypted")
        .mime_str("application/octet-stream")
        .map_err(ApiError::RequestFailed)?;

    let form = multipart::Form::new().part("file", part);

    let resp = client
        .authenticated_multipart_post("/ipfs/upload", form)
        .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse {
            status,
            message: format!("IPFS upload failed: {}", body),
        });
    }

    let upload_resp: UploadResponse = resp.json().await.map_err(|e| {
        ApiError::DeserializationFailed(format!("Failed to parse upload response: {}", e))
    })?;

    Ok(upload_resp.cid)
}

/// Unpin content from IPFS via the backend.
///
/// POST /ipfs/unpin with `{ cid }`. Fire-and-forget on delete
/// (matches web app pattern -- 404 treated as success).
pub async fn unpin_content(client: &ApiClient, cid: &str) -> Result<(), ApiError> {
    let resp = client
        .authenticated_post("/ipfs/unpin", &UnpinRequest { cid })
        .await?;

    // 404 is success (already unpinned -- idempotent behavior)
    if resp.status().as_u16() == 404 || resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Err(ApiError::ApiResponse {
            status,
            message: format!("IPFS unpin failed: {}", body),
        })
    }
}
