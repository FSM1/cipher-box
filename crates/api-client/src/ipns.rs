//! IPNS resolution and publishing via the CipherBox backend API.
//!
//! Resolves IPNS names to their current CID and sequence number,
//! and publishes signed IPNS records.
//!
//! This module also hosts the verified-resolve chokepoint (`resolve_ipns_verified`)
//! relocated from `crates/fuse/src/verify.rs` so all Rust consumers (sdk, fuse, desktop)
//! share one implementation (D-08). The `crates/fuse/src/verify.rs` file is reduced to
//! a thin re-export of the public symbols here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use crate::client::ApiClient;
use crate::error::ApiError;
use crate::types::{IpnsPublishRequest, IpnsResolveResponse, PublishResult};

// ---------------------------------------------------------------------------
// Verified-resolve chokepoint — relocated from crates/fuse/src/verify.rs
// Applies D-04 (no Legacy variant, strict seq equality) and D-08 (shared wrapper).
// ---------------------------------------------------------------------------

/// Error returned by `resolve_ipns_verified`.
#[derive(Debug)]
pub enum VerifyError {
    /// API-level error (network failure, 404, etc.).
    Api(ApiError),
    /// Invalid/partial signature, CBOR cid/sequence binding mismatch, or all signature
    /// fields absent (fail-closed, D-04 — Legacy variant removed).
    Invalid(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(e) => write!(f, "API error: {}", e),
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
///   - `Some(true)` → signature valid; proceed to CBOR binding + expiry
///   - `Some(false)` → invalid / partial / all-absent → `Err(VerifyError::Invalid(...))`
///   - `None`       → defensive arm: post-D-04 `verify_ipns_resolve_signature` never
///     returns `None` (all-absent now arrives as `Some(false)`, logged at the detection
///     site), so this arm is unreachable from the production resolve path. It is retained
///     for exhaustive `Option<bool>` matching, is exercised directly by unit tests, and
///     also fails closed.
pub(crate) fn bind_verified(
    resp: &IpnsResolveResponse,
    sig_verdict: Option<bool>,
) -> Result<VerifiedResolve, VerifyError> {
    match sig_verdict {
        // Defensive arm (see doc above): unreachable from the production resolve path
        // post-D-04 since all-absent arrives as Some(false); kept for total matching and
        // fails closed.
        None => Err(VerifyError::Invalid("all signature fields absent — fail closed".to_string())),
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

            // D-04: strict sequence equality — skew disjunct removed.
            // Previously allowed (resp_seq == 1 && embedded_seq == 0) as a first-publish skew.
            // Phase 60 removes all embedded-0 producers (D-02) and wipes staging so no such
            // records exist when strict verify goes live (D-12 lockstep invariant).
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

            // D-07: resolve-side EOL/expiry enforcement with 5-minute clock-skew buffer.
            // Fail-closed: missing or unparseable Validity is treated as expired.
            let (validity_bytes, _validity_type) =
                cipherbox_core::ipns::decode_ipns_cbor_validity(&data_bytes)
                    .map_err(|e| VerifyError::Invalid(format!("CBOR Validity decode failed: {}", e)))?;
            let validity_bytes = validity_bytes
                .ok_or_else(|| VerifyError::Invalid("IPNS record has no Validity field — fail closed".to_string()))?;

            let validity_str = std::str::from_utf8(&validity_bytes)
                .map_err(|_| VerifyError::Invalid("IPNS Validity is not valid UTF-8".to_string()))?;

            let expiry_secs = parse_rfc3339_to_unix_secs(validity_str)
                .ok_or_else(|| VerifyError::Invalid(format!("IPNS Validity parse failed: {}", validity_str)))?;

            // 5-minute skew buffer: reject when expiry < now - 300s.
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            const SKEW_BUFFER_SECS: u64 = 300;
            if expiry_secs < now_secs.saturating_sub(SKEW_BUFFER_SECS) {
                return Err(VerifyError::Invalid(format!(
                    "IPNS record expired: validity={}, now={}",
                    validity_str, now_secs
                )));
            }

            // D-08: use the signed/embedded cid (strip "/ipfs/" prefix).
            let cid = embedded_value
                .strip_prefix("/ipfs/")
                .unwrap_or(&embedded_value)
                .to_string();

            Ok(VerifiedResolve {
                cid,
                sequence_number: resp_seq,
            })
        }
    }
}

/// Resolve an IPNS name, verify the signature, and bind the embedded cid/sequence.
///
/// This is the single verified chokepoint for all Rust consumers (D-08, D-01).
///
/// # Returns
///
/// - `Ok(VerifiedResolve)` — signature valid, CBOR binding succeeded; `.cid` and
///   `.sequence_number` are from the signed CBOR data (D-08 authoritative).
/// - `Err(VerifyError::Invalid(_))` — any verification failure (invalid/partial signature,
///   binding mismatch, or all fields absent — D-04 fail-closed, no Legacy tolerance).
/// - `Err(VerifyError::Api(_))` — API-level error; caller propagates.
pub async fn resolve_ipns_verified(
    api: &ApiClient,
    ipns_name: &str,
) -> Result<VerifiedResolve, VerifyError> {
    let resp = resolve_ipns(api, ipns_name)
        .await
        .map_err(VerifyError::Api)?;

    let verdict = verify_ipns_resolve_signature(&resp, ipns_name)
        .map_err(|e| VerifyError::Invalid(format!("signature verification error: {}", e)))?;

    bind_verified(&resp, verdict)
}

/// Parse a fixed-format RFC3339 timestamp string to Unix seconds.
///
/// The IPNS Validity field uses the format produced by `format_validity_timestamp` in
/// `crates/core/src/ipns.rs`: `"YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ"` (nanoseconds, UTC).
///
/// Returns `None` if the string cannot be parsed; caller should treat this as fail-closed.
/// This is a manual parse to avoid adding a chrono dependency to `crates/api-client`.
fn parse_rfc3339_to_unix_secs(s: &str) -> Option<u64> {
    // Expected format: "2026-01-01T00:00:00.000000000Z" (29 chars minimum, ends with Z).
    // Tolerate missing nanoseconds: "2026-01-01T00:00:00Z" also valid.
    let s = s.strip_suffix('Z')?;
    let (date_part, time_part) = s.split_once('T')?;

    let mut date_parts = date_part.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    // Reject trailing date components (e.g. "2026-01-01-99").
    if date_parts.next().is_some() {
        return None;
    }

    // Split off nanoseconds if present; a present fractional part must be non-empty and
    // all ASCII digits (reject junk like "00:00:00." or extra separators).
    let mut dot = time_part.splitn(2, '.');
    let time_no_nanos = dot.next()?;
    if let Some(frac) = dot.next() {
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    let mut time_parts = time_no_nanos.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let minute: u64 = time_parts.next()?.parse().ok()?;
    let second: u64 = time_parts.next()?.parse().ok()?;
    // Reject trailing time components (e.g. "00:00:00:99").
    if time_parts.next().is_some() {
        return None;
    }

    // Range + leap-aware day-of-month validation. The Hinnant civil_from_days algorithm
    // silently rolls an impossible date (e.g. 2026-02-31) into the following month, which
    // would EXTEND the record's validity — the opposite of fail-closed — so reject it here.
    if month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if day > days_in_month {
        return None;
    }

    // Compute days since Unix epoch using the Hinnant civil_from_days algorithm (inverted).
    // days_from_civil: given (year, month, day) → days since 1970-01-01.
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = (era * 146097) as i64 + doe as i64 - 719468;

    if days_since_epoch < 0 {
        return None; // Pre-epoch timestamp — treat as expired.
    }

    let total_secs = days_since_epoch as u64 * 86400 + hour * 3600 + minute * 60 + second;
    Some(total_secs)
}

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
/// Implements D-04 strict path: all-absent fields → `Ok(Some(false))` (fail-closed, no legacy
/// tolerance). The old `Ok(None)` all-absent branch has been removed per Phase 60 D-04.
///
/// Returns:
/// - `Ok(Some(false))` when ALL THREE signature fields are absent (D-04 — was `Ok(None)` before
///   Phase 60 strict cutover), when SOME but not all three fields are present (partial/downgrade
///   record — fail closed), when signature verification fails, or when the derived IPNS
///   name does not match `ipns_name`.
/// - `Ok(Some(true))` when the signature is valid and the public key derives to `ipns_name`.
/// - `Err` when base64 decoding or IPNS name derivation fails on present fields.
///
/// Note: `None` is no longer produced. The return type `Option<bool>` is kept for API compatibility
/// with `bind_verified`'s match on `sig_verdict`; callers that previously matched `None` (Legacy)
/// should now see `Some(false)` (Invalid) per D-04.
pub fn verify_ipns_resolve_signature(
    resp: &crate::types::IpnsResolveResponse,
    ipns_name: &str,
) -> Result<Option<bool>, crate::error::ApiError> {
    // D-04: ALL fields absent no longer produces Ok(None) (legacy allow).
    // The missing-fields case falls through to the partial-field pattern below,
    // returning Ok(Some(false)) — fail closed.
    // (The old `if !sig && !data && !pub_key { return Ok(None); }` has been deleted.)

    // Partial fields (some but not all present) → fail closed. A record carrying 1 or 2
    // of the 3 fields is a downgrade vector, not a legacy record. All-absent also falls here.
    let (Some(sig_b64), Some(data_b64), Some(pub_key_b64)) = (
        resp.signature_v2.as_ref(),
        resp.data.as_ref(),
        resp.pub_key.as_ref(),
    ) else {
        // Both all-absent and partial records fail closed (D-04), but log the distinct
        // root cause so an operator debugging (e.g. a pre-cutover row on a non-wiped
        // environment) can tell "all three fields absent" apart from a partial downgrade.
        // bind_verified only sees Some(false) and cannot make this distinction, so the
        // signal belongs here at the detection site.
        match (
            resp.signature_v2.is_some(),
            resp.data.is_some(),
            resp.pub_key.is_some(),
        ) {
            (false, false, false) => log::warn!(
                "IPNS resolve verify: all three signature fields absent (signatureV2/data/pubKey) — failing closed (D-04)"
            ),
            (sig, data, pk) => log::warn!(
                "IPNS resolve verify: partial signature fields (signatureV2={sig}, data={data}, pubKey={pk}) — downgrade, failing closed (D-04)"
            ),
        }
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

    // ---- Phase 60 Plan 01: bind_verified tests ----

    use super::{VerifyError, bind_verified, parse_rfc3339_to_unix_secs};
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

    // ---- Task 2 RED: EOL/expiry enforcement tests (D-07) ----
    // These tests will fail until bind_verified checks the Validity field.

    /// Build CBOR data with an explicit validity timestamp (for expiry tests).
    fn make_cbor_data_with_validity(value: &str, seq: u64, validity: &str) -> Vec<u8> {
        let cbor_map = CborValue::Map(vec![
            (CborValue::Text("TTL".to_string()), CborValue::Integer((300_000_000_000u64).into())),
            (CborValue::Text("Value".to_string()), CborValue::Bytes(value.as_bytes().to_vec())),
            (CborValue::Text("Sequence".to_string()), CborValue::Integer(seq.into())),
            (CborValue::Text("Validity".to_string()), CborValue::Bytes(validity.as_bytes().to_vec())),
            (CborValue::Text("ValidityType".to_string()), CborValue::Integer(0u64.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).unwrap();
        buf
    }

    fn make_resp_with_validity(cid: &str, seq: u64, validity: &str) -> IpnsResolveResponse {
        let cbor = make_cbor_data_with_validity(&format!("/ipfs/{}", cid), seq, validity);
        let data_b64 = STANDARD.encode(&cbor);
        IpnsResolveResponse {
            success: true,
            cid: cid.to_string(),
            sequence_number: seq.to_string(),
            signature_v2: Some("fakesig".to_string()),
            data: Some(data_b64),
            pub_key: Some("fakepubkey".to_string()),
        }
    }

    /// D-07: A record with Validity timestamp 1 hour in the past (beyond 5-min skew buffer)
    /// must be rejected with VerifyError::Invalid containing "expired".
    #[test]
    fn bind_verified_expired_record_returns_invalid() {
        // 2020-01-01T00:00:00.000000000Z — well in the past.
        let resp = make_resp_with_validity("bafyEXPIRED", 1, "2020-01-01T00:00:00.000000000Z");
        let err = bind_verified(&resp, Some(true)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(ref msg) if msg.contains("expired")),
            "expected 'expired' in error message, got: {:?}", err
        );
    }

    /// D-07: A record with Validity timestamp 24 hours in the future must be accepted.
    #[test]
    fn bind_verified_future_validity_returns_ok() {
        // 2099-12-31T00:00:00.000000000Z — far in the future.
        let resp = make_resp_with_validity("bafyFUTURE", 1, "2099-12-31T00:00:00.000000000Z");
        let result = bind_verified(&resp, Some(true)).unwrap();
        assert_eq!(result.cid, "bafyFUTURE");
    }

    fn now_unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Test-only inverse of `parse_rfc3339_to_unix_secs`: render unix seconds as
    /// "YYYY-MM-DDTHH:MM:SSZ" via Howard Hinnant's civil_from_days algorithm, so the
    /// skew-boundary tests build a `now`-relative timestamp that round-trips through the
    /// real production parser + verify path. The round-trip is what makes the assertions
    /// meaningful (a wrong rendering would fail the parser, not silently pass).
    fn secs_to_rfc3339(secs: u64) -> String {
        let days = (secs / 86400) as i64;
        let rem = secs % 86400;
        let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = (z - era * 146097) as u64; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let year = if month <= 2 { y + 1 } else { y };
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    /// D-07: a Validity 2 minutes in the past — inside the 5-minute (300s) skew buffer —
    /// must be ACCEPTED. Pins the buffer's existence: if the buffer were removed, `now-120s`
    /// would read as expired and this test would fail. (Generous 180s margin from the edge.)
    #[test]
    fn bind_verified_within_skew_buffer_returns_ok() {
        let validity = secs_to_rfc3339(now_unix_secs() - 120);
        let resp = make_resp_with_validity("bafySKEW", 3, &validity);
        let result = bind_verified(&resp, Some(true)).unwrap();
        assert_eq!(result.cid, "bafySKEW");
    }

    /// D-07: a Validity just beyond the 300s buffer (`now-301s`) must be REJECTED as expired.
    /// Pins the upper edge so the buffer cannot be silently widened. Safe to assert exactly:
    /// production reads `now` no earlier than this test does, so `now-301` is always < `now_prod-300`.
    #[test]
    fn bind_verified_just_past_skew_buffer_returns_invalid() {
        let validity = secs_to_rfc3339(now_unix_secs() - 301);
        let resp = make_resp_with_validity("bafySKEWPAST", 3, &validity);
        let err = bind_verified(&resp, Some(true)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(ref msg) if msg.contains("expired")),
            "expected an 'expired' error just past the skew buffer, got: {err:?}"
        );
    }

    /// D-07: the RFC3339 parser must fail closed (None) on malformed timestamps. Impossible
    /// calendar dates must NOT silently roll into a later month (which would EXTEND validity).
    #[test]
    fn parse_rfc3339_rejects_malformed_timestamps() {
        // Well-formed cases parse.
        assert!(parse_rfc3339_to_unix_secs("2026-01-01T00:00:00.000000000Z").is_some());
        assert!(parse_rfc3339_to_unix_secs("2026-01-01T00:00:00Z").is_some());
        assert!(parse_rfc3339_to_unix_secs("2024-02-29T00:00:00.000000000Z").is_some()); // leap day

        // Impossible / out-of-range dates fail closed.
        assert!(parse_rfc3339_to_unix_secs("2026-02-31T00:00:00.000000000Z").is_none());
        assert!(parse_rfc3339_to_unix_secs("2025-02-29T00:00:00.000000000Z").is_none()); // not leap
        assert!(parse_rfc3339_to_unix_secs("2026-04-31T00:00:00.000000000Z").is_none());
        assert!(parse_rfc3339_to_unix_secs("2026-13-01T00:00:00.000000000Z").is_none());
        assert!(parse_rfc3339_to_unix_secs("2026-01-01T24:00:00.000000000Z").is_none());

        // Trailing / junk components fail closed.
        assert!(parse_rfc3339_to_unix_secs("2026-01-01-99T00:00:00.000000000Z").is_none());
        assert!(parse_rfc3339_to_unix_secs("2026-01-01T00:00:00:99.000000000Z").is_none());
        assert!(parse_rfc3339_to_unix_secs("2026-01-01T00:00:00.abcZ").is_none());
    }

    // ---- Task 2 (Phase 75): ValidityType == 0 EOL gate tests ----

    /// Build CBOR data with an explicit ValidityType (or its absence) for gate tests.
    fn make_cbor_data_with_validity_type(
        value: &str,
        seq: u64,
        validity: &str,
        validity_type: Option<i64>,
    ) -> Vec<u8> {
        let mut entries = vec![
            (CborValue::Text("TTL".to_string()), CborValue::Integer((300_000_000_000u64).into())),
            (CborValue::Text("Value".to_string()), CborValue::Bytes(value.as_bytes().to_vec())),
            (CborValue::Text("Sequence".to_string()), CborValue::Integer(seq.into())),
            (CborValue::Text("Validity".to_string()), CborValue::Bytes(validity.as_bytes().to_vec())),
        ];
        if let Some(vt) = validity_type {
            entries.push((CborValue::Text("ValidityType".to_string()), CborValue::Integer(vt.into())));
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(entries), &mut buf).unwrap();
        buf
    }

    fn make_resp_with_validity_type(
        cid: &str,
        seq: u64,
        validity: &str,
        validity_type: Option<i64>,
    ) -> IpnsResolveResponse {
        let cbor = make_cbor_data_with_validity_type(&format!("/ipfs/{}", cid), seq, validity, validity_type);
        let data_b64 = STANDARD.encode(&cbor);
        IpnsResolveResponse {
            success: true,
            cid: cid.to_string(),
            sequence_number: seq.to_string(),
            signature_v2: Some("fakesig".to_string()),
            data: Some(data_b64),
            pub_key: Some("fakepubkey".to_string()),
        }
    }

    /// A record whose ValidityType is absent (None) must be rejected — fail closed.
    #[test]
    fn bind_verified_missing_validity_type_returns_invalid() {
        let resp = make_resp_with_validity_type(
            "bafyNOTYPE",
            1,
            "2099-01-01T00:00:00.000000000Z",
            None,
        );
        let err = bind_verified(&resp, Some(true)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(_)),
            "expected VerifyError::Invalid for missing ValidityType, got: {:?}", err
        );
    }

    /// A record whose ValidityType is a non-zero integer must be rejected.
    #[test]
    fn bind_verified_non_zero_validity_type_returns_invalid() {
        let resp = make_resp_with_validity_type(
            "bafyNONEOL",
            1,
            "2099-01-01T00:00:00.000000000Z",
            Some(1),
        );
        let err = bind_verified(&resp, Some(true)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(_)),
            "expected VerifyError::Invalid for non-zero ValidityType, got: {:?}", err
        );
    }

    /// A valid, in-date record with ValidityType 0 still returns Ok(VerifiedResolve).
    #[test]
    fn bind_verified_validity_type_zero_in_date_returns_ok() {
        let resp = make_resp_with_validity_type(
            "bafyEOL0",
            1,
            "2099-01-01T00:00:00.000000000Z",
            Some(0),
        );
        let result = bind_verified(&resp, Some(true)).unwrap();
        assert_eq!(result.cid, "bafyEOL0");
    }

    /// An expired record with ValidityType 0 is still rejected (existing D-07 leg unchanged).
    #[test]
    fn bind_verified_validity_type_zero_expired_returns_invalid() {
        let resp = make_resp_with_validity_type(
            "bafyEOL0EXPIRED",
            1,
            "2020-01-01T00:00:00.000000000Z",
            Some(0),
        );
        let err = bind_verified(&resp, Some(true)).unwrap_err();
        assert!(
            matches!(err, VerifyError::Invalid(ref msg) if msg.contains("expired")),
            "expected 'expired' error, got: {:?}", err
        );
    }
}
