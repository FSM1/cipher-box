//! IPFS content operations via the CipherBox backend API.
//!
//! Provides fetching encrypted file content and uploading encrypted files.
//! Content is always encrypted -- the backend never sees plaintext.

use super::client::ApiClient;

/// Fetch encrypted file content from IPFS via the backend.
///
/// GET /ipfs/{cid} returns raw encrypted bytes (application/octet-stream).
pub async fn fetch_content(client: &ApiClient, cid: &str) -> Result<Vec<u8>, String> {
    let resp = client
        .authenticated_get(&format!("/ipfs/{}", cid))
        .await
        .map_err(|e| format!("IPFS fetch failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("IPFS fetch failed ({}): {}", status, body));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read IPFS response: {}", e))?;
    Ok(bytes.to_vec())
}

/// Upload encrypted file content to IPFS via the backend.
///
/// POST /ipfs/upload with multipart form data. Returns CID string.
/// Used by write operations in plan 09-06.
pub async fn upload_content(client: &ApiClient, data: &[u8]) -> Result<String, String> {
    use reqwest::multipart;

    let part = multipart::Part::bytes(data.to_vec())
        .file_name("encrypted")
        .mime_str("application/octet-stream")
        .map_err(|e| format!("Failed to create multipart part: {}", e))?;

    let form = multipart::Form::new().part("file", part);

    // We need a raw request for multipart -- use authenticated_multipart_post
    // For now, use the client's underlying reqwest client via get_bytes pattern
    // The upload endpoint is /ipfs/upload
    let resp = client
        .authenticated_multipart_post("/ipfs/upload", form)
        .await
        .map_err(|e| format!("IPFS upload failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("IPFS upload failed ({}): {}", status, body));
    }

    #[derive(serde::Deserialize)]
    struct UploadResponse {
        cid: String,
    }

    let upload_resp: UploadResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse upload response: {}", e))?;

    Ok(upload_resp.cid)
}
