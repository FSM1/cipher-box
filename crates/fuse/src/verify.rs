//! IPNS resolve + verify chokepoint.
//!
//! `resolve_ipns_verified` is the single entry point for all FUSE resolve sites.
//! It resolves, signature-verifies, and CBOR-binds the cid/sequence in one call.
//!
//! # Failure posture
//!
//! - `VerifyError::Legacy` — all three signature fields absent (D-04); callers warn and proceed.
//! - `VerifyError::Invalid` — invalid/partial signature or CBOR binding mismatch (D-02/D-07);
//!   callers fail the operation (not the whole mount).
//! - `VerifyError::Api` — API-level error; callers propagate as-is.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Error returned by `resolve_ipns_verified`.
#[derive(Debug)]
pub enum VerifyError {
    /// API-level error (network failure, 404, etc.).
    Api(cipherbox_api_client::error::ApiError),
    /// All three signature fields absent — legacy record (D-04).
    /// Carries the already-resolved `cid` and `sequence_number` so callers need not
    /// issue a second `resolve_ipns` call (eliminates the TOCTOU race window, T-59-04).
    Legacy { cid: String, sequence_number: String },
    /// Invalid/partial signature or CBOR cid/sequence binding mismatch (D-02/D-07).
    /// Callers should fail the operation (not the whole mount).
    Invalid(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(e) => write!(f, "API error: {}", e),
            Self::Legacy { cid, sequence_number } => write!(
                f,
                "legacy record: all signature fields absent (cid={cid}, seq={sequence_number})"
            ),
            Self::Invalid(msg) => write!(f, "verification failed: {}", msg),
        }
    }
}

/// A fully-verified IPNS resolve result with authoritative signed values (D-08).
#[derive(Debug, Clone)]
pub struct VerifiedResolve {
    /// CID from the signed CBOR data (authoritative; D-08 — embedded value is the source of truth).
    pub cid: String,
    /// Sequence number from the signed CBOR data (authoritative; D-08).
    pub sequence_number: u64,
}

/// Pure helper that classifies a resolve response given the signature verdict.
///
/// Separated from `resolve_ipns_verified` so that unit tests can drive it
/// with constructed `IpnsResolveResponse` values without hitting the network.
///
/// # Arguments
///
/// * `resp`         — the raw resolve response from the API
/// * `sig_verdict`  — the output of `verify_ipns_resolve_signature`
///   - `None`       → legacy (all fields absent)
///   - `Some(true)` → signature valid; proceed to CBOR binding
///   - `Some(false)` → invalid/partial
pub(crate) fn bind_verified(
    resp: &cipherbox_api_client::types::IpnsResolveResponse,
    sig_verdict: Option<bool>,
) -> Result<VerifiedResolve, VerifyError> {
    match sig_verdict {
        None => Err(VerifyError::Legacy {
            cid: resp.cid.clone(),
            sequence_number: resp.sequence_number.clone(),
        }),
        Some(false) => Err(VerifyError::Invalid("signature verification failed".to_string())),
        Some(true) => {
            // Signature is valid. Now decode the CBOR `data` and bind the embedded
            // cid/sequence back to the response fields (D-07/D-08).
            let data_b64 = resp
                .data
                .as_deref()
                .ok_or_else(|| VerifyError::Invalid(
                    "sig_verdict=Some(true) but resp.data is None — contract violation".to_string(),
                ))?;
            let data_bytes = STANDARD
                .decode(data_b64)
                .map_err(|e| VerifyError::Invalid(format!("base64 decode of CBOR data failed: {}", e)))?;

            let (embedded_value, embedded_seq) =
                cipherbox_core::ipns::decode_ipns_cbor_data(&data_bytes)
                    .map_err(|e| VerifyError::Invalid(format!("CBOR decode failed: {}", e)))?;

            // D-08: embedded value is "/ipfs/<cid>" — compare to response cid.
            let expected_value = format!("/ipfs/{}", resp.cid);
            if embedded_value != expected_value {
                return Err(VerifyError::Invalid(format!(
                    "IPNS cid binding mismatch: embedded={}, response cid={}",
                    embedded_value, resp.cid
                )));
            }

            // D-07: embedded sequence must match response sequence_number (strict equality).
            //
            // The historical first-publish skew allowance (resp_seq == 1 && embedded_seq == 0)
            // is removed as of Phase 59 Finding F: FUSE now embeds 1 on first publish
            // (next_file_publish_sequence returns 1; replay.rs child-folder first-publish also
            // embeds 1), matching the TS SDK convention. All clients now embed 1 on first
            // publish, so the skew window no longer exists. Strict equality tightens the
            // anti-rollback check (T-59-10).
            let resp_seq = resp
                .sequence_number
                .parse::<u64>()
                .map_err(|e| VerifyError::Invalid(format!("parse response sequence_number: {}", e)))?;
            let seq_ok = embedded_seq == resp_seq;
            if !seq_ok {
                return Err(VerifyError::Invalid(format!(
                    "IPNS sequence binding mismatch: embedded={}, response seq={}",
                    embedded_seq, resp_seq
                )));
            }

            // D-08: use the signed/embedded cid (strip "/ipfs/" prefix).
            let cid = embedded_value
                .strip_prefix("/ipfs/")
                .unwrap_or(&embedded_value)
                .to_string();

            // Return the DB-authoritative sequence (resp_seq): downstream sequence math
            // (resolve_sequence → next publish = seq + 1) keys off the API's DB counter, and
            // the binding above guarantees resp_seq == embedded_seq except for the benign
            // first-publish skew, where resp_seq (1) is the correct forward base.
            Ok(VerifiedResolve {
                cid,
                sequence_number: resp_seq,
            })
        }
    }
}

/// Resolve an IPNS name, verify the signature, and bind the embedded cid/sequence.
///
/// This is the single verified chokepoint for all FUSE resolve sites (D-01).
///
/// # Returns
///
/// - `Ok(VerifiedResolve)` — signature valid, CBOR binding succeeded; `.cid` and
///   `.sequence_number` are from the signed CBOR data (D-08 authoritative).
/// - `Err(VerifyError::Legacy)` — all three signature fields absent; caller warns
///   and proceeds with the raw `resp.cid` (D-04).
/// - `Err(VerifyError::Invalid(_))` — invalid/partial signature or binding mismatch;
///   caller fails the operation (D-02 scoped fail-closed).
/// - `Err(VerifyError::Api(_))` — API-level error; caller propagates.
pub async fn resolve_ipns_verified(
    api: &cipherbox_api_client::client::ApiClient,
    ipns_name: &str,
) -> Result<VerifiedResolve, VerifyError> {
    let resp = cipherbox_api_client::ipns::resolve_ipns(api, ipns_name)
        .await
        .map_err(VerifyError::Api)?;

    let verdict = cipherbox_api_client::ipns::verify_ipns_resolve_signature(&resp, ipns_name)
        .map_err(|e| VerifyError::Invalid(format!("signature verification error: {}", e)))?;

    bind_verified(&resp, verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_api_client::types::IpnsResolveResponse;
    use ciborium::Value as CborValue;

    /// Helper: build CBOR bytes for value and sequence, matching the build_cbor_data layout.
    fn make_cbor_data(value: &str, seq: u64) -> Vec<u8> {
        let cbor_map = CborValue::Map(vec![
            (CborValue::Text("TTL".to_string()), CborValue::Integer((300_000_000_000u64).into())),
            (CborValue::Text("Value".to_string()), CborValue::Bytes(value.as_bytes().to_vec())),
            (CborValue::Text("Sequence".to_string()), CborValue::Integer(seq.into())),
            (CborValue::Text("Validity".to_string()), CborValue::Bytes(b"2024-01-01T00:00:00.000000000Z".to_vec())),
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

    #[test]
    fn bind_verified_legacy_returns_legacy() {
        // None verdict → Legacy { cid, sequence_number } carrying the input response fields.
        let resp = IpnsResolveResponse {
            success: true,
            cid: "bafyLEGACY".to_string(),
            sequence_number: "7".to_string(),
            signature_v2: None,
            data: None,
            pub_key: None,
        };
        let err = bind_verified(&resp, None).unwrap_err();
        match err {
            VerifyError::Legacy { cid, sequence_number } => {
                assert_eq!(cid, resp.cid, "Legacy must carry resp.cid");
                assert_eq!(sequence_number, resp.sequence_number, "Legacy must carry resp.sequence_number");
            }
            other => panic!("expected VerifyError::Legacy, got {:?}", other),
        }
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
