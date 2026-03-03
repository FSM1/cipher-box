//! IPNS resolution via the CipherBox backend API.
//!
//! Resolves IPNS names to their current CID and sequence number.

use serde::Deserialize;

use super::client::ApiClient;

/// Result of an IPNS publish attempt.
#[derive(Debug)]
pub enum PublishResult {
    /// Publish succeeded.
    Success,
    /// Server returned 409 Conflict -- another device published since our last sync.
    Conflict {
        /// The server's current sequence number (string, bigint).
        current_sequence_number: String,
    },
}

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
    /// Expected sequence number for optimistic concurrency control.
    /// If set, the server returns 409 Conflict if the current sequence
    /// does not match. Omit to perform an unconditional publish.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sequence_number: Option<String>,
}

/// Publish a signed IPNS record via the backend.
///
/// POST /ipns/publish with the signed record. The backend relays
/// to delegated-ipfs.dev and tracks the folder for TEE republishing.
///
/// Returns `PublishResult::Success` on 2xx, `PublishResult::Conflict`
/// on 409 (another device published a higher sequence), or `Err` on
/// other errors.
pub async fn publish_ipns(
    client: &ApiClient,
    request: &IpnsPublishRequest,
) -> Result<PublishResult, String> {
    let resp = client
        .authenticated_post("/ipns/publish", request)
        .await
        .map_err(|e| format!("IPNS publish failed: {}", e))?;

    if resp.status().as_u16() == 409 {
        // Parse conflict response body: { currentSequenceNumber: "..." }
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let current_seq = body["currentSequenceNumber"]
            .as_str()
            .unwrap_or("0")
            .to_string();
        return Ok(PublishResult::Conflict {
            current_sequence_number: current_seq,
        });
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("IPNS publish failed ({}): {}", status, body));
    }

    Ok(PublishResult::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_request_serialization_with_expected_sequence() {
        let req = IpnsPublishRequest {
            ipns_name: "k51test".to_string(),
            record: "base64record".to_string(),
            metadata_cid: "bafytest".to_string(),
            encrypted_ipns_private_key: None,
            key_epoch: None,
            expected_sequence_number: Some("42".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["ipnsName"], "k51test");
        assert_eq!(json["record"], "base64record");
        assert_eq!(json["metadataCid"], "bafytest");
        assert_eq!(json["expectedSequenceNumber"], "42");
        // Optional fields omitted when None
        assert!(json.get("encryptedIpnsPrivateKey").is_none());
        assert!(json.get("keyEpoch").is_none());
    }

    #[test]
    fn publish_request_serialization_without_expected_sequence() {
        let req = IpnsPublishRequest {
            ipns_name: "k51test".to_string(),
            record: "base64record".to_string(),
            metadata_cid: "bafytest".to_string(),
            encrypted_ipns_private_key: None,
            key_epoch: None,
            expected_sequence_number: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("expectedSequenceNumber").is_none(),
            "omitting expected_sequence_number should skip the field entirely");
    }

    #[test]
    fn publish_request_serialization_with_tee_fields() {
        let req = IpnsPublishRequest {
            ipns_name: "k51test".to_string(),
            record: "base64record".to_string(),
            metadata_cid: "bafytest".to_string(),
            encrypted_ipns_private_key: Some("ecies-wrapped-key-hex".to_string()),
            key_epoch: Some(3),
            expected_sequence_number: Some("1".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["encryptedIpnsPrivateKey"], "ecies-wrapped-key-hex");
        assert_eq!(json["keyEpoch"], 3);
        assert_eq!(json["expectedSequenceNumber"], "1");
    }

    #[test]
    fn publish_request_camel_case_field_names() {
        let req = IpnsPublishRequest {
            ipns_name: "k51test".to_string(),
            record: "rec".to_string(),
            metadata_cid: "cid".to_string(),
            encrypted_ipns_private_key: Some("key".to_string()),
            key_epoch: Some(1),
            expected_sequence_number: Some("5".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        // Verify camelCase (not snake_case) in serialized output
        assert!(json.contains("ipnsName"), "should use camelCase");
        assert!(json.contains("metadataCid"), "should use camelCase");
        assert!(json.contains("encryptedIpnsPrivateKey"), "should use camelCase");
        assert!(json.contains("keyEpoch"), "should use camelCase");
        assert!(json.contains("expectedSequenceNumber"), "should use camelCase");
        assert!(!json.contains("ipns_name"), "should NOT use snake_case");
    }

    #[test]
    fn publish_result_debug_format() {
        // Verify Debug derives work (used in log::warn! calls)
        let success = PublishResult::Success;
        let conflict = PublishResult::Conflict {
            current_sequence_number: "99".to_string(),
        };
        let success_dbg = format!("{:?}", success);
        let conflict_dbg = format!("{:?}", conflict);
        assert!(success_dbg.contains("Success"));
        assert!(conflict_dbg.contains("Conflict"));
        assert!(conflict_dbg.contains("99"));
    }

    #[test]
    fn resolve_response_deserialization() {
        let json = r#"{"success":true,"cid":"bafybeig","sequenceNumber":"42"}"#;
        let resp: IpnsResolveResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.cid, "bafybeig");
        assert_eq!(resp.sequence_number, "42");
    }

    #[test]
    fn resolve_response_camel_case_deserialization() {
        // Verify camelCase deserialization (backend sends camelCase)
        let json = r#"{"success":false,"cid":"","sequenceNumber":"0"}"#;
        let resp: IpnsResolveResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.sequence_number, "0");
    }
}
