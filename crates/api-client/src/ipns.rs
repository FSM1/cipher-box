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
    let path = format!("/ipns/resolve?ipnsName={}", urlencoding::encode(ipns_name));
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
/// Implements D-03 (all fields absent → None, allow+warn), D-02 (invalid → Some(false)),
/// and D-04 (valid + name binding → Some(true)).
///
/// Returns:
/// - `Ok(None)` ONLY when ALL THREE signature fields (signatureV2, data, pubKey) are
///   absent — a true legacy record (backward-compat allow path).
/// - `Ok(Some(false))` when SOME but not all three fields are present (partial/downgrade
///   record — fail closed), when signature verification fails, or when the derived IPNS
///   name does not match `ipns_name`.
/// - `Ok(Some(true))` when the signature is valid and the public key derives to `ipns_name`.
/// - `Err` when base64 decoding or IPNS name derivation fails on present fields.
pub fn verify_ipns_resolve_signature(
    resp: &crate::types::IpnsResolveResponse,
    ipns_name: &str,
) -> Result<Option<bool>, crate::error::ApiError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let sig_present = resp.signature_v2.is_some();
    let data_present = resp.data.is_some();
    let pub_key_present = resp.pub_key.is_some();

    // D-03: ALL fields absent → true legacy record, allow + flag (caller warns and continues).
    if !sig_present && !data_present && !pub_key_present {
        return Ok(None);
    }

    // Partial fields (some but not all present) → fail closed. A record carrying 1 or 2
    // of the 3 fields is a downgrade vector, not a legacy record.
    let (Some(sig_b64), Some(data_b64), Some(pub_key_b64)) = (
        resp.signature_v2.as_ref(),
        resp.data.as_ref(),
        resp.pub_key.as_ref(),
    ) else {
        return Ok(Some(false));
    };

    let decode_field = |label: &str, s: &str| -> Result<Vec<u8>, crate::error::ApiError> {
        STANDARD.decode(s).map_err(|e| {
            crate::error::ApiError::DeserializationFailed(format!(
                "IPNS {} base64 decode failed: {}",
                label, e
            ))
        })
    };
    let sig = decode_field("signatureV2", sig_b64)?;
    let cbor_data = decode_field("data", data_b64)?;
    let pub_key = decode_field("pubKey", pub_key_b64)?;

    // Build signed bytes: "ipns-signature:" prefix || CBOR data.
    let mut signed_data = b"ipns-signature:".to_vec();
    signed_data.extend_from_slice(&cbor_data);

    // D-02: invalid signature → fail closed.
    if !cipherbox_crypto::verify_ed25519(&signed_data, &sig, &pub_key) {
        return Ok(Some(false));
    }

    // Convert decoded pub_key to fixed 32-byte array; wrong length → treat as invalid.
    let pubkey_arr: [u8; 32] = match pub_key.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return Ok(Some(false)),
    };

    // Derive IPNS name and check it binds to the resolved name.
    let derived_name = cipherbox_crypto::derive_ipns_name(&pubkey_arr).map_err(|e| {
        crate::error::ApiError::DeserializationFailed(format!("IPNS name derivation failed: {}", e))
    })?;

    Ok(Some(derived_name == ipns_name))
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
    let resp = client.authenticated_post("/ipns/publish", request).await?;

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
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

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

    /// Test 2: all sig fields absent → Ok(Some(false)) — D-04 fail closed (was Ok(None) / legacy allow).
    /// After the Phase 60 strict cutover the all-absent branch falls through to Some(false).
    #[test]
    fn absent_fields_returns_some_false() {
        let resp = make_resolve_response_no_sig();
        let result = verify_ipns_resolve_signature(&resp, "k51anyname");
        assert_eq!(result.unwrap(), Some(false));
    }

    /// Test 2 (legacy name kept for grep-ability): same assertion as absent_fields_returns_some_false.
    #[test]
    fn absent_fields_returns_none_is_now_some_false() {
        // Confirms the D-04 semantic: the old None path is gone; all-absent → Some(false).
        let resp = make_resolve_response_no_sig();
        assert_eq!(verify_ipns_resolve_signature(&resp, "k51anyname").unwrap(), Some(false));
    }

    /// Test 2b: only signatureV2 present (1 of 3) → Ok(Some(false)) — fail closed on partial.
    #[test]
    fn partial_fields_only_signature_returns_some_false() {
        let mut resp = make_resolve_response_no_sig();
        resp.signature_v2 = Some("AAAA".to_string());
        let result = verify_ipns_resolve_signature(&resp, "k51anyname");
        assert_eq!(result.unwrap(), Some(false));
    }

    /// Test 2c: two of three fields present (signatureV2 + data, no pubKey) →
    /// Ok(Some(false)) — fail closed on partial/downgrade record.
    #[test]
    fn partial_fields_two_of_three_returns_some_false() {
        let mut resp = make_resolve_response_no_sig();
        resp.signature_v2 = Some("AAAA".to_string());
        resp.data = Some("BBBB".to_string());
        // pub_key intentionally left None.
        let result = verify_ipns_resolve_signature(&resp, "k51anyname");
        assert_eq!(result.unwrap(), Some(false));
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
        let ipns_name =
            cipherbox_crypto::derive_ipns_name(pub_key_bytes.as_slice().try_into().unwrap())
                .unwrap();
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

    // ---- Phase 60 Plan 01: bind_verified tests (Task 1 RED) ----
    // These tests reference `bind_verified` and `VerifyError` / `VerifiedResolve`
    // which will be relocated from crates/fuse/src/verify.rs in the GREEN step.

    use super::{VerifyError, VerifiedResolve, bind_verified};
    use ciborium::Value as CborValue;

    /// Helper: build CBOR bytes for value and sequence, matching the build_cbor_data layout.
    fn make_cbor_data(value: &str, seq: u64) -> Vec<u8> {
        let cbor_map = CborValue::Map(vec![
            (CborValue::Text("TTL".to_string()), CborValue::Integer((300_000_000_000u64).into())),
            (CborValue::Text("Value".to_string()), CborValue::Bytes(value.as_bytes().to_vec())),
            (CborValue::Text("Sequence".to_string()), CborValue::Integer(seq.into())),
            (CborValue::Text("Validity".to_string()), CborValue::Bytes(b"2099-01-01T00:00:00.000000000Z".to_vec())),
            (CborValue::Text("ValidityType".to_string()), CborValue::Integer(0u64.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        buf
    }

    /// Helper: construct IpnsResolveResponse with CBOR data encoding /ipfs/<cid> + seq.
    fn make_resp_with_cbor(cid: &str, seq: u64, resp_cid: &str, resp_seq: u64) -> IpnsResolveResponse {
        let cbor = make_cbor_data(&format!("/ipfs/{}", cid), seq);
        let data_b64 = STANDARD.encode(&cbor);
        IpnsResolveResponse {
            success: true,
            cid: resp_cid.to_string(),
            sequence_number: resp_seq.to_string(),
            signature_v2: Some("fakesig".to_string()),
            data: Some(data_b64),
            pub_key: Some("fakepubkey".to_string()),
        }
    }

    #[test]
    fn bind_verified_valid_returns_ok_with_embedded_cid() {
        // Valid signature verdict, cid and seq match — returns VerifiedResolve.
        // The cid in VerifiedResolve must be the embedded value with "/ipfs/" stripped (D-08).
        let resp = make_resp_with_cbor("bafyREAL", 5, "bafyREAL", 5);
        let result = bind_verified(&resp, Some(true)).unwrap();
        assert_eq!(result.cid, "bafyREAL");
        assert_eq!(result.sequence_number, 5);
    }

    #[test]
    fn bind_verified_cid_swap_returns_invalid() {
        // Valid signature verdict but embedded cid differs from response cid — Invalid.
        let resp = make_resp_with_cbor("bafyREAL", 5, "bafyDIFFERENT", 5);
        let err = bind_verified(&resp, Some(true)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(ref msg) if msg.contains("cid binding mismatch")),
            "expected cid binding mismatch, got: {:?}", err
        );
    }

    #[test]
    fn bind_verified_seq_mismatch_returns_invalid() {
        // Valid signature verdict, cid matches, but embedded seq != response seq — Invalid.
        let resp = make_resp_with_cbor("bafyCID", 99, "bafyCID", 5);
        let err = bind_verified(&resp, Some(true)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(ref msg) if msg.contains("sequence binding mismatch")),
            "expected sequence binding mismatch, got: {:?}", err
        );
    }

    /// D-04: first-publish skew (embedded=0, resp_seq=1) is now REJECTED under strict equality.
    /// The skew disjunct `(resp_seq == 1 && embedded_seq == 0)` has been removed.
    #[test]
    fn bind_verified_first_publish_seq_skew_now_invalid() {
        let resp = make_resp_with_cbor("bafyFIRST", 0, "bafyFIRST", 1);
        let err = bind_verified(&resp, Some(true)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(_)),
            "expected VerifyError::Invalid for seq skew, got: {:?}", err
        );
    }

    /// D-04: None verdict (all signature fields absent) → VerifyError::Invalid.
    /// The Legacy variant has been removed; absent fields fail closed.
    #[test]
    fn bind_verified_absent_fields_returns_invalid() {
        let resp = IpnsResolveResponse {
            success: true,
            cid: "bafyABSENT".to_string(),
            sequence_number: "1".to_string(),
            signature_v2: None,
            data: None,
            pub_key: None,
        };
        let err = bind_verified(&resp, None).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(_)),
            "expected VerifyError::Invalid for absent fields, got: {:?}", err
        );
    }

    #[test]
    fn bind_verified_invalid_sig_returns_invalid() {
        // Some(false) verdict → Invalid.
        let resp = IpnsResolveResponse {
            success: true,
            cid: "bafyINVALID".to_string(),
            sequence_number: "1".to_string(),
            signature_v2: Some("badsig".to_string()),
            data: Some(STANDARD.encode(b"garbage")),
            pub_key: Some("key".to_string()),
        };
        let err = bind_verified(&resp, Some(false)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(ref msg) if msg.contains("signature verification failed")),
            "expected signature verification failed, got: {:?}", err
        );
    }
}
