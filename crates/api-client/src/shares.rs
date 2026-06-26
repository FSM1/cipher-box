//! Share revocation endpoints for the CipherBox API.
//!
//! Mirrors the TypeScript `@cipherbox/api-client` share-revocation contract used
//! by the web/SDK delete path. The desktop FUSE mount calls
//! [`revoke_shares_for_items`] before destructively removing a deleted node so
//! that any active Share/ShareInvite rows for that node are hard-revoked BEFORE
//! the eventual unpin can orphan a sharee.

use serde::Serialize;

use crate::client::ApiClient;
use crate::error::ApiError;

/// Maximum number of IPNS names accepted by `POST /shares/revoke-for-items`
/// in a single request. Mirrors the server-side `@ArrayMaxSize(5000)` guard on
/// `RevokeForItemsDto`. The desktop delete path only ever sends a single name
/// (FUSE deletes bottom-up), so this is a defensive cap rather than a chunking
/// driver.
pub const REVOKE_FOR_ITEMS_MAX: usize = 5000;

/// Request body for `POST /shares/revoke-for-items`.
///
/// The server DTO field is camelCase `ipnsNames`, so the Rust field is renamed
/// via serde to match.
#[derive(Debug, Serialize)]
struct RevokeForItemsRequest {
    #[serde(rename = "ipnsNames")]
    ipns_names: Vec<String>,
}

/// Hard-revoke every share/invite the authenticated user created for any of the
/// listed IPNS names.
///
/// `POST /shares/revoke-for-items` is idempotent: names that were never shared
/// are simply ignored by the server. The endpoint returns HTTP 200 on success.
///
/// An empty `ipns_names` slice is a no-op (the server DTO rejects empty arrays,
/// so we short-circuit to `Ok(())` without a round-trip — there is nothing to
/// revoke). A slice larger than [`REVOKE_FOR_ITEMS_MAX`] is rejected locally as
/// an [`ApiError::ApiResponse`] with status 400 to mirror the server guard.
pub async fn revoke_shares_for_items(
    client: &ApiClient,
    ipns_names: &[String],
) -> Result<(), ApiError> {
    if ipns_names.is_empty() {
        return Ok(());
    }
    if ipns_names.len() > REVOKE_FOR_ITEMS_MAX {
        return Err(ApiError::ApiResponse {
            status: 400,
            message: format!(
                "too many ipnsNames: {} exceeds max {}",
                ipns_names.len(),
                REVOKE_FOR_ITEMS_MAX
            ),
        });
    }

    let request = RevokeForItemsRequest {
        ipns_names: ipns_names.to_vec(),
    };

    let resp = client
        .authenticated_post("/shares/revoke-for-items", &request)
        .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse {
            status,
            message: format!("share revocation failed: {}", body),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request body must serialize to `{"ipnsNames":[...]}` (serde rename),
    /// matching the server DTO field name exactly.
    #[test]
    fn request_serializes_camel_case_ipns_names() {
        let req = RevokeForItemsRequest {
            ipns_names: vec!["k51one".to_string(), "k51two".to_string()],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"ipnsNames":["k51one","k51two"]}"#);
    }

    /// A single-name request (the desktop delete path) still uses the camelCase
    /// key and a JSON array.
    #[test]
    fn request_single_name_is_array() {
        let req = RevokeForItemsRequest {
            ipns_names: vec!["k51only".to_string()],
        };
        let value: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert!(value["ipnsNames"].is_array());
        assert_eq!(value["ipnsNames"][0], "k51only");
    }

    /// An empty slice is a no-op and never touches the network.
    #[tokio::test]
    async fn empty_slice_is_ok_no_request() {
        // Unreachable base URL: if this made a request it would error, proving
        // the empty short-circuit fires before any network I/O.
        let client = ApiClient::new("http://127.0.0.1:1");
        let result = revoke_shares_for_items(&client, &[]).await;
        assert!(result.is_ok());
    }

    /// A slice larger than the cap is rejected locally as a 400 without a
    /// network round-trip.
    #[tokio::test]
    async fn oversized_slice_is_local_400() {
        let client = ApiClient::new("http://127.0.0.1:1");
        let names: Vec<String> = (0..(REVOKE_FOR_ITEMS_MAX + 1))
            .map(|i| format!("k51name{}", i))
            .collect();
        let err = revoke_shares_for_items(&client, &names)
            .await
            .expect_err("oversized slice must be rejected");
        match err {
            ApiError::ApiResponse { status, .. } => assert_eq!(status, 400),
            other => panic!("expected ApiResponse 400, got {:?}", other),
        }
    }
}
