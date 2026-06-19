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

    let status = resp.status().as_u16();
    let body: IpnsResolveResponse = resp
        .json()
        .await
        .map_err(|e| ApiError::DeserializationFailed(format!("IPNS resolve response: {}", e)))?;

    if !body.success || body.cid.is_empty() {
        return Err(ApiError::ApiResponse {
            status,
            message: format!(
                "IPNS resolve unsuccessful: success={}, cid='{}'",
                body.success, body.cid
            ),
        });
    }

    Ok(body)
}

/// Verify an IPNS resolve response signature.
///
/// Implements D-03 (absent fields → None, allow+warn), D-02 (invalid → Some(false)),
/// and D-04 (valid + name binding → Some(true)).
///
/// Returns:
/// - `Ok(None)` when any signature field is absent (legacy record, backward-compat).
/// - `Ok(Some(false))` when signature fields are present but verification fails or
///   the derived IPNS name does not match `ipns_name`.
/// - `Ok(Some(true))` when the signature is valid and the public key derives to `ipns_name`.
/// - `Err` when base64 decoding or IPNS name derivation fails on present fields.
pub fn verify_ipns_resolve_signature(
    _resp: &crate::types::IpnsResolveResponse,
    _ipns_name: &str,
) -> Result<Option<bool>, crate::error::ApiError> {
    unimplemented!("verify_ipns_resolve_signature is not yet implemented")
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

#[cfg(test)]
mod tests {
    use super::verify_ipns_resolve_signature;
    use crate::types::IpnsResolveResponse;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    fn make_resolve_response_no_sig() -> IpnsResolveResponse {
        IpnsResolveResponse {
            success: true,
            cid: "bafytest".to_string(),
            sequence_number: "1".to_string(),
            signature_v2: None,
            data: None,
            pub_key: None,
        }
    }

    fn make_resolve_response_with_sig(
        signature_v2: &str,
        data: &str,
        pub_key: &str,
    ) -> IpnsResolveResponse {
        IpnsResolveResponse {
            success: true,
            cid: "bafytest".to_string(),
            sequence_number: "1".to_string(),
            signature_v2: Some(signature_v2.to_string()),
            data: Some(data.to_string()),
            pub_key: Some(pub_key.to_string()),
        }
    }

    /// Test 1: serde deserialization of optional sig fields.
    #[test]
    fn deserialize_with_sig_fields() {
        let json = r#"{
            "success": true,
            "cid": "bafytest",
            "sequenceNumber": "1",
            "signatureV2": "AAAA",
            "data": "BBBB",
            "pubKey": "CCCC"
        }"#;
        let resp: IpnsResolveResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.signature_v2, Some("AAAA".to_string()));
        assert_eq!(resp.data, Some("BBBB".to_string()));
        assert_eq!(resp.pub_key, Some("CCCC".to_string()));
    }

    /// Test 1b: serde deserialization without sig fields.
    #[test]
    fn deserialize_without_sig_fields() {
        let json = r#"{"success": true, "cid": "bafytest", "sequenceNumber": "1"}"#;
        let resp: IpnsResolveResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.signature_v2, None);
        assert_eq!(resp.data, None);
        assert_eq!(resp.pub_key, None);
    }

    /// Test 2: absent sig fields → Ok(None) — D-03 allow+flag.
    #[test]
    fn absent_fields_returns_none() {
        let resp = make_resolve_response_no_sig();
        let result = verify_ipns_resolve_signature(&resp, "k51anyname");
        assert_eq!(result.unwrap(), None);
    }

    /// Test 3: invalid Ed25519 signature → Ok(Some(false)) — D-02.
    #[test]
    fn invalid_signature_returns_some_false() {
        let (pub_key_bytes, private_key) = cipherbox_crypto::generate_ed25519_keypair();
        let data_bytes = b"some-cbor-data";
        // Sign DIFFERENT bytes (wrong data) to create an invalid signature.
        let wrong_message = b"wrong-message";
        let sig_bytes = cipherbox_crypto::sign_ed25519(wrong_message, &private_key).unwrap();

        let resp = make_resolve_response_with_sig(
            &STANDARD.encode(&sig_bytes),
            &STANDARD.encode(data_bytes),
            &STANDARD.encode(&pub_key_bytes),
        );
        let ipns_name = cipherbox_crypto::derive_ipns_name(
            pub_key_bytes.as_slice().try_into().unwrap()
        ).unwrap();
        let result = verify_ipns_resolve_signature(&resp, &ipns_name);
        assert_eq!(result.unwrap(), Some(false));
    }

    /// Test 4: valid signature and matching derived IPNS name → Ok(Some(true)) — D-04.
    #[test]
    fn valid_signature_matching_name_returns_some_true() {
        let (pub_key_bytes, private_key) = cipherbox_crypto::generate_ed25519_keypair();
        let data_bytes = b"some-cbor-data";

        // Build signed_data exactly as verify_ipns_resolve_signature expects.
        let mut signed_data = b"ipns-signature:".to_vec();
        signed_data.extend_from_slice(data_bytes);
        let sig_bytes = cipherbox_crypto::sign_ed25519(&signed_data, &private_key).unwrap();

        let pubkey_arr: [u8; 32] = pub_key_bytes.as_slice().try_into().unwrap();
        let ipns_name = cipherbox_crypto::derive_ipns_name(&pubkey_arr).unwrap();

        let resp = make_resolve_response_with_sig(
            &STANDARD.encode(&sig_bytes),
            &STANDARD.encode(data_bytes),
            &STANDARD.encode(&pub_key_bytes),
        );
        let result = verify_ipns_resolve_signature(&resp, &ipns_name);
        assert_eq!(result.unwrap(), Some(true));
    }

    /// Test 5: valid signature but IPNS name doesn't match derived name → Ok(Some(false)).
    #[test]
    fn valid_signature_wrong_name_returns_some_false() {
        let (pub_key_bytes, private_key) = cipherbox_crypto::generate_ed25519_keypair();
        let data_bytes = b"some-cbor-data";

        let mut signed_data = b"ipns-signature:".to_vec();
        signed_data.extend_from_slice(data_bytes);
        let sig_bytes = cipherbox_crypto::sign_ed25519(&signed_data, &private_key).unwrap();

        let resp = make_resolve_response_with_sig(
            &STANDARD.encode(&sig_bytes),
            &STANDARD.encode(data_bytes),
            &STANDARD.encode(&pub_key_bytes),
        );
        // Pass a deliberately wrong IPNS name.
        let result = verify_ipns_resolve_signature(&resp, "k51wrongname123");
        assert_eq!(result.unwrap(), Some(false));
    }
}
