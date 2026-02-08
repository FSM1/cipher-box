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
    let path = format!("/ipns/resolve?ipnsName={}", ipns_name);
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
