//! IPNS resolution and publishing via the CipherBox backend API.
//!
//! Resolves IPNS names to their current CID and sequence number,
//! and publishes signed IPNS records.

use crate::client::ApiClient;
use crate::error::ApiError;
use crate::types::{IpnsPublishRequest, IpnsResolveResponse, PublishResult};

/// Resolve an IPNS name to its current CID via the backend.
///
/// GET /ipns/resolve?ipnsName={name}
/// Returns the CID and sequence number of the current IPNS record.
pub async fn resolve_ipns(
    client: &ApiClient,
    ipns_name: &str,
) -> Result<IpnsResolveResponse, ApiError> {
    let path = format!(
        "/ipns/resolve?ipnsName={}",
        urlencoding::encode(ipns_name)
    );
    let resp = client.authenticated_get(&path).await?;

    if resp.status().as_u16() == 404 {
        return Err(ApiError::IpnsNotFound(ipns_name.to_string()));
    }

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse {
            status,
            message: format!("IPNS resolve failed: {}", body),
        });
    }

    resp.json::<IpnsResolveResponse>()
        .await
        .map_err(|e| ApiError::DeserializationFailed(format!("IPNS resolve response: {}", e)))
}

/// Publish a signed IPNS record via the backend.
///
/// POST /ipns/publish with the signed record. The backend relays
/// to the delegated routing service and tracks the folder for TEE republishing.
///
/// Returns `PublishResult::Success` on 2xx, `PublishResult::Conflict`
/// on 409 (another device published a higher sequence), or `Err` on
/// other errors.
pub async fn publish_ipns(
    client: &ApiClient,
    request: &IpnsPublishRequest,
) -> Result<PublishResult, ApiError> {
    let resp = client
        .authenticated_post("/ipns/publish", request)
        .await?;

    if resp.status().as_u16() == 409 {
        // Parse conflict response body: { currentSequenceNumber: "..." }
        let body: serde_json::Value = resp.json().await.map_err(|e| {
            ApiError::DeserializationFailed(format!("409 Conflict but failed to parse body: {}", e))
        })?;
        let current_seq = body["currentSequenceNumber"]
            .as_str()
            .ok_or_else(|| {
                ApiError::DeserializationFailed(format!(
                    "409 Conflict but missing currentSequenceNumber in response: {}",
                    body
                ))
            })?
            .to_string();
        return Ok(PublishResult::Conflict {
            current_sequence_number: current_seq,
        });
    }

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse {
            status,
            message: format!("IPNS publish failed: {}", body),
        });
    }

    Ok(PublishResult::Success)
}
