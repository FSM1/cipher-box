//! IPNS resolution via the CipherBox backend API.
//!
//! Resolves IPNS names to their current CID and sequence number.

use serde::Deserialize;

use super::client::ApiClient;

/// Response from GET /ipns/resolve.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveResponse {
    /// Whether the resolution succeeded.
    pub success: bool,
    /// CID that the IPNS name currently points to.
    pub cid: String,
    /// Current sequence number as a string (bigint from backend).
    pub sequence_number: String,
}

/// Resolve an IPNS name to its current CID via the backend.
///
/// GET /ipns/resolve?ipnsName={name}
/// Returns the CID and sequence number of the current IPNS record.
pub async fn resolve_ipns(
    client: &ApiClient,
    ipns_name: &str,
) -> Result<IpnsResolveResponse, String> {
    let path = format!("/ipns/resolve?ipnsName={}", urlencoding::encode(ipns_name));
    let resp = client
        .authenticated_get(&path)
        .await
        .map_err(|e| format!("IPNS resolve failed: {}", e))?;

    if resp.status().as_u16() == 404 {
        return Err("IPNS name not found".to_string());
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("IPNS resolve failed ({}): {}", status, body));
    }

    let resolve_resp: IpnsResolveResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse IPNS resolve response: {}", e))?;

    Ok(resolve_resp)
}

/// IPNS publish request body matching the backend PublishIpnsDto.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsPublishRequest {
    /// IPNS name (k51... CIDv1 format).
    pub ipns_name: String,
    /// Base64-encoded marshaled IPNS record (protobuf bytes).
    pub record: String,
    /// CID of the encrypted metadata this record points to.
    pub metadata_cid: String,
    /// Hex-encoded ECIES-wrapped Ed25519 private key for TEE republishing
    /// (only required on first publish for a new folder).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_ipns_private_key: Option<String>,
    /// TEE key epoch (required with encrypted_ipns_private_key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_epoch: Option<u32>,
}

/// Publish a signed IPNS record via the backend.
///
/// POST /ipns/publish with the signed record. The backend relays
/// to delegated-ipfs.dev and tracks the folder for TEE republishing.
pub async fn publish_ipns(
    client: &ApiClient,
    request: &IpnsPublishRequest,
) -> Result<(), String> {
    let resp = client
        .authenticated_post("/ipns/publish", request)
        .await
        .map_err(|e| format!("IPNS publish failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("IPNS publish failed ({}): {}", status, body));
    }

    Ok(())
}
