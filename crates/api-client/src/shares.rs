//! Share revocation and sent-share listing endpoints for the CipherBox API.
//!
//! Mirrors the TypeScript `@cipherbox/api-client` share contract used by the
//! web/SDK delete and grant-awareness paths. The desktop FUSE mount calls
//! [`revoke_shares_for_items`] before destructively removing a deleted node so
//! that any active Share/ShareInvite rows for that node are hard-revoked BEFORE
//! the eventual unpin can orphan a sharee. [`collect_sent_shares`] is the
//! client-side source of `activeGrantRootIpnsNames` (the set of root IPNS
//! names the authenticated user has actively shared out), mirroring the web
//! client's `GET /shares/sent` call that populates `useShareStore.sentShares`.

use serde::{Deserialize, Serialize};

use crate::client::ApiClient;
use crate::error::ApiError;

/// Page size used by [`collect_sent_shares`] when walking `GET /shares/sent`.
/// Mirrors the server-side `PaginationQueryDto` default (`limit: number = 50`).
const SENT_SHARES_PAGE_LIMIT: u32 = 50;

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

/// A single row from `GET /shares/sent` — mirrors the server's
/// `SentShareResponseDto` (`apps/api/src/shares/dto/share-response.dto.ts`)
/// field-for-field. `share_root_ipns_name` is the value consumed downstream
/// to build `activeGrantRootIpnsNames`.
///
/// Note: unlike some domain rows, revoked shares are hard-deleted server-side
/// (see `revoke_shares_for_items`), so there is no `revoked`/status field on
/// the wire — every row returned by this endpoint is, by construction, an
/// active grant.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentShareResponse {
    /// UUID of the share row.
    pub share_id: String,
    /// Recipient secp256k1 public key (0x04...).
    pub recipient_public_key: String,
    /// Hex-encoded ECIES encrypted key for read access.
    pub encrypted_read_key: String,
    /// Hex-encoded ECIES encrypted key for write access, or `None` for
    /// read-only shares.
    pub encrypted_write_key: Option<String>,
    /// UUID of the root shared node.
    pub root_node_id: String,
    /// IPNS name (k51...) of the root shared node — the grant root.
    pub share_root_ipns_name: String,
    /// Generation of the root node at share creation (numeric string).
    pub root_generation: String,
    /// Hex-encoded ECIES ciphertext of the display name, or `None` if not
    /// provided.
    pub item_name_encrypted: Option<String>,
    /// ISO-8601 creation timestamp, kept as an opaque string (no client-side
    /// date parsing is required for grant-root awareness).
    pub created_at: String,
}

/// A page of `GET /shares/sent` — mirrors the server's
/// `PaginatedSentSharesDto`.
#[derive(Debug, Clone, Deserialize)]
pub struct SentSharesPage {
    /// The rows in this page.
    pub shares: Vec<SentShareResponse>,
    /// Total number of matching rows across all pages (not just this page).
    pub total: u32,
}

/// Fetch a single page of the authenticated user's sent shares.
///
/// `GET /shares/sent?limit={limit}&offset={offset}` — mirrors
/// `revoke_shares_for_items`'s authenticated-GET/error-handling shape. An
/// empty result set (e.g. a user who has never shared anything) is returned
/// as `Ok(SentSharesPage { shares: vec![], total: 0 })`, not an error.
pub async fn list_sent_shares(
    client: &ApiClient,
    limit: u32,
    offset: u32,
) -> Result<SentSharesPage, ApiError> {
    let path = format!("/shares/sent?limit={}&offset={}", limit, offset);
    let resp = client.authenticated_get(&path).await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse {
            status,
            message: format!("list sent shares failed: {}", body),
        });
    }

    resp.json()
        .await
        .map_err(|e| ApiError::DeserializationFailed(format!("sent shares response: {}", e)))
}

/// Pure pagination-termination decision, extracted so the loop in
/// [`collect_sent_shares`] is unit-testable without a live HTTP server.
///
/// Fetch another page only if the page just fetched was non-empty AND fewer
/// rows have been collected so far than the server-reported `total`. The
/// non-empty check guards against a server that reports a stale/incorrect
/// `total` — an empty page always halts pagination regardless of `total`, so
/// the loop cannot spin forever.
fn should_fetch_next_page(last_page_len: usize, collected_len: usize, total: u32) -> bool {
    last_page_len > 0 && (collected_len as u32) < total
}

/// Page through `GET /shares/sent` until every sent-share row has been
/// collected, returning the full grant-root set client-side (the source of
/// `activeGrantRootIpnsNames` — RESEARCH Pitfall 2 / Open Question 2).
///
/// A user with no sent shares gets back an empty `Vec`, not an error.
pub async fn collect_sent_shares(client: &ApiClient) -> Result<Vec<SentShareResponse>, ApiError> {
    let mut collected: Vec<SentShareResponse> = Vec::new();
    let mut offset: u32 = 0;

    loop {
        let page = list_sent_shares(client, SENT_SHARES_PAGE_LIMIT, offset).await?;
        let page_len = page.shares.len();
        collected.extend(page.shares);

        if !should_fetch_next_page(page_len, collected.len(), page.total) {
            break;
        }

        offset += SENT_SHARES_PAGE_LIMIT;
    }

    Ok(collected)
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

    /// `SentShareResponse` deserializes from the exact camelCase wire shape
    /// produced by `SentShareResponseDto`, including the two nullable fields.
    #[test]
    fn sent_share_response_deserializes_camel_case() {
        let json = r#"{
            "shareId": "share-1",
            "recipientPublicKey": "0x04abc",
            "encryptedReadKey": "deadbeef",
            "encryptedWriteKey": null,
            "rootNodeId": "node-1",
            "shareRootIpnsName": "k51one",
            "rootGeneration": "3",
            "itemNameEncrypted": null,
            "createdAt": "2026-01-01T00:00:00.000Z"
        }"#;
        let share: SentShareResponse = serde_json::from_str(json).unwrap();
        assert_eq!(share.share_id, "share-1");
        assert_eq!(share.share_root_ipns_name, "k51one");
        assert_eq!(share.encrypted_write_key, None);
        assert_eq!(share.item_name_encrypted, None);
    }

    /// `SentSharesPage` deserializes the `{ shares, total }` envelope
    /// (`PaginatedSentSharesDto`), including an empty-result page.
    #[test]
    fn sent_shares_page_deserializes_including_empty() {
        let json = r#"{"shares":[],"total":0}"#;
        let page: SentSharesPage = serde_json::from_str(json).unwrap();
        assert!(page.shares.is_empty());
        assert_eq!(page.total, 0);
    }

    /// Pagination continues while a non-empty page was returned and fewer
    /// rows have been collected than the reported total.
    #[test]
    fn should_fetch_next_page_continues_when_more_remain() {
        assert!(should_fetch_next_page(50, 50, 120));
        assert!(should_fetch_next_page(50, 100, 120));
    }

    /// Pagination halts once the collected count reaches the reported total.
    #[test]
    fn should_fetch_next_page_stops_when_total_reached() {
        assert!(!should_fetch_next_page(20, 120, 120));
        assert!(!should_fetch_next_page(0, 120, 120));
    }

    /// An empty page halts pagination immediately even if the server
    /// (incorrectly) still reports a higher total — this is what prevents an
    /// infinite loop against a misbehaving/lagging server.
    #[test]
    fn should_fetch_next_page_stops_on_empty_page_regardless_of_total() {
        assert!(!should_fetch_next_page(0, 0, 999));
    }

    /// `list_sent_shares` against an unreachable host surfaces the transport
    /// error via `ApiError::RequestFailed` (through `authenticated_get`'s
    /// `?`), mirroring the revoke path's network-error handling.
    #[tokio::test]
    async fn list_sent_shares_against_unreachable_host_errors() {
        let client = ApiClient::new("http://127.0.0.1:1");
        let result = list_sent_shares(&client, 50, 0).await;
        assert!(result.is_err());
    }

    // -- update_grant / revoke_share wire-function tests -------------------
    //
    // No mock-HTTP crate (wiremock/mockito) is a dependency of this crate, so
    // these tests use a minimal raw-TCP one-shot mock server mirroring the
    // established project pattern in
    // `crates/fuse/src/write_ops/implementation/delete.rs`
    // (`spawn_mock_rotation_server`), adapted to CAPTURE the inbound
    // method/path/body (via an `mpsc` channel back to the async test) rather
    // than dispatch a fixture response by path — these tests assert on the
    // exact request CipherBox's real `ApiClient` sends, not just on a canned
    // response.

    /// One HTTP/1.1 request captured by [`spawn_capturing_mock_server`].
    struct CapturedRequest {
        method: String,
        path: String,
        body: String,
    }

    /// Spawn a background thread that accepts exactly one HTTP/1.1
    /// connection, captures its method/path/body, replies with
    /// `status_line`/`response_body`, and sends the captured request back
    /// over the returned channel. Returns the mock server's base URL
    /// (`http://127.0.0.1:<port>`) suitable for `ApiClient::new`.
    fn spawn_capturing_mock_server(
        status_line: &'static str,
        response_body: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<CapturedRequest>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server local_addr");
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };

            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let headers_end = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    return; // peer closed before a full request arrived
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                if buf.len() > 1_000_000 {
                    return; // safety cap against a malformed/oversized request
                }
            };

            let content_length = {
                let headers = String::from_utf8_lossy(&buf[..headers_end]);
                headers
                    .split("\r\n")
                    .find_map(|line| {
                        let (k, v) = line.split_once(':')?;
                        k.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().to_string())
                    })
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0)
            };
            let have = buf.len() - headers_end;
            if have < content_length {
                let mut remaining = vec![0u8; content_length - have];
                if stream.read_exact(&mut remaining).is_err() {
                    return;
                }
                buf.extend_from_slice(&remaining);
            }

            let request_line = buf
                .split(|&b| b == b'\n')
                .next()
                .map(|l| String::from_utf8_lossy(l).trim().to_string())
                .unwrap_or_default();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();
            let body = String::from_utf8_lossy(&buf[headers_end..]).to_string();

            let header = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status_line,
                response_body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(response_body.as_bytes());
            let _ = stream.flush();

            let _ = tx.send(CapturedRequest { method, path, body });
        });

        (format!("http://{}", addr), rx)
    }

    /// `update_grant` PATCHes `/shares/{shareId}/grant` with a body carrying
    /// ONLY `encryptedReadKey` + `rootGeneration` (write-key fields absent),
    /// and treats 204 as success.
    #[tokio::test]
    async fn update_grant_patches_grant_path_with_read_key_only_body() {
        let (base_url, rx) = spawn_capturing_mock_server("204 No Content", "");
        let client = ApiClient::new(&base_url);

        let result = update_grant(&client, "share-1", "deadbeef", 3).await;
        assert!(result.is_ok(), "expected Ok, got {:?}", result);

        let captured = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("mock server captured a request");
        assert_eq!(captured.method, "PATCH");
        assert_eq!(captured.path, "/shares/share-1/grant");

        let value: serde_json::Value =
            serde_json::from_str(&captured.body).expect("body is valid JSON");
        assert_eq!(value["encryptedReadKey"], "deadbeef");
        assert_eq!(value["rootGeneration"], "3");
        assert!(
            value.get("encryptedWriteKey").is_none(),
            "encryptedWriteKey must be absent from a read-key-rotation-only body"
        );
        assert!(
            value.get("clearEncryptedWriteKey").is_none(),
            "clearEncryptedWriteKey must be absent from a read-key-rotation-only body"
        );
    }

    /// `update_grant` maps a non-2xx response (400) to
    /// `ApiError::ApiResponse` with a message mentioning the operation.
    #[tokio::test]
    async fn update_grant_non_2xx_maps_to_api_response_error() {
        let (base_url, _rx) = spawn_capturing_mock_server("400 Bad Request", "bad request");
        let client = ApiClient::new(&base_url);

        let err = update_grant(&client, "share-1", "deadbeef", 3)
            .await
            .expect_err("non-2xx must be an error");
        match err {
            ApiError::ApiResponse { status, message } => {
                assert_eq!(status, 400);
                assert!(
                    message.contains("update_grant"),
                    "message should mention update_grant: {}",
                    message
                );
            }
            other => panic!("expected ApiResponse, got {:?}", other),
        }
    }

    /// `revoke_share` DELETEs `/shares/{shareId}` and treats 204 as success.
    #[tokio::test]
    async fn revoke_share_deletes_share_path() {
        let (base_url, rx) = spawn_capturing_mock_server("204 No Content", "");
        let client = ApiClient::new(&base_url);

        let result = revoke_share(&client, "share-1").await;
        assert!(result.is_ok(), "expected Ok, got {:?}", result);

        let captured = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("mock server captured a request");
        assert_eq!(captured.method, "DELETE");
        assert_eq!(captured.path, "/shares/share-1");
    }

    /// `revoke_share` maps a non-2xx response (404) to
    /// `ApiError::ApiResponse` with a message mentioning the operation.
    #[tokio::test]
    async fn revoke_share_non_2xx_maps_to_api_response_error() {
        let (base_url, _rx) = spawn_capturing_mock_server("404 Not Found", "not found");
        let client = ApiClient::new(&base_url);

        let err = revoke_share(&client, "share-1")
            .await
            .expect_err("non-2xx must be an error");
        match err {
            ApiError::ApiResponse { status, message } => {
                assert_eq!(status, 404);
                assert!(
                    message.contains("revoke_share"),
                    "message should mention revoke_share: {}",
                    message
                );
            }
            other => panic!("expected ApiResponse, got {:?}", other),
        }
    }

    /// `revoke_share` also maps a 500 to `ApiError::ApiResponse` (not just
    /// 404) — mirrors the plan's "404/500 -> Err" behavior requirement.
    #[tokio::test]
    async fn revoke_share_500_maps_to_api_response_error() {
        let (base_url, _rx) = spawn_capturing_mock_server("500 Internal Server Error", "boom");
        let client = ApiClient::new(&base_url);

        let err = revoke_share(&client, "share-1")
            .await
            .expect_err("non-2xx must be an error");
        match err {
            ApiError::ApiResponse { status, .. } => assert_eq!(status, 500),
            other => panic!("expected ApiResponse, got {:?}", other),
        }
    }
}
