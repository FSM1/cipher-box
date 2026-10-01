//! CipherBox wasm — wasm-bindgen bindings over the engine facade
//! (`cipherbox-engine`, which links `cipherbox-core`), loaded as one ES module
//! inside the engine worker by `packages/client`.
//!
//! Normative design: blueprint/web-client.md ("WASM packaging and the type
//! boundary"). This crate is bindings only — it holds no vault logic, no
//! crypto, and no codec of its own; every trust decision already happened
//! below the facade (blueprint/engine.md). Core is linked *inside*: nothing
//! from `cipherbox-core` is exported directly to JS.
//!
//! The wasm-bindgen-generated `.d.ts` is the single boundary contract that
//! `packages/client` re-exports — there is no hand-maintained TS mirror of
//! engine structures. The facade commands, their outcomes, the events and the
//! views cross as the engine's own types, typed by tsify ([`boundary`]).
//! Boundary hygiene is structural: `u64`s cross as `bigint`, binary payloads as
//! `Uint8Array`, and the command surface exposes only intent while the event
//! and read surfaces carry key-free view state and decrypted user content.
//!
//! One secret crosses out, and only because handing it over *is* the feature:
//! an invite link's bearer capability (the `inviteLinkMinted` outcome), which
//! the host puts in a URL fragment and reads nothing out of. It crosses as the
//! fragment text rather than as bytes so the host composes and parses no link
//! material. Residual: a JS string is immutable, so the host cannot scrub the
//! copy it holds — inherent to a capability that has to reach a URL.

// wasm-bindgen's macro-generated glue is unsafe by nature and exempt; this
// forbids only unsafe we would hand-write (there is none).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use cipherbox_engine::facade;
use wasm_bindgen::prelude::*;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod seams_bridge;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod host;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub mod boundary;

// Test-only: the production artifact never pulls the engine test kit or these
// bindings.
#[cfg(all(feature = "conformance", target_family = "wasm", target_os = "unknown"))]
mod conformance;

// ---------------------------------------------------------------------------
// Boundary value types.
// ---------------------------------------------------------------------------

/// The stable 16-byte node identifier (`id16`). Routes and commands key on it,
/// never on rotating `ipnsName`s.
#[wasm_bindgen]
pub struct NodeId {
    inner: facade::NodeId,
}

#[wasm_bindgen]
impl NodeId {
    /// Builds a node id from its 16 raw bytes; throws if the length is wrong.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<NodeId, JsError> {
        let inner: [u8; 16] = bytes
            .try_into()
            .map_err(|_| JsError::new("nodeId must be exactly 16 bytes"))?;
        Ok(Self {
            inner: facade::NodeId(inner),
        })
    }

    /// The 16 raw bytes of this node id.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.0.to_vec()
    }
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
impl NodeId {
    fn facade(&self) -> facade::NodeId {
        self.inner
    }
}

/// A freshly opened read stream and the plaintext size of the version it
/// pinned (`Engine::stream_size`).
#[wasm_bindgen]
pub struct OpenedStream {
    handle: u64,
    size: f64,
}

#[wasm_bindgen]
impl OpenedStream {
    /// The handle every window of this stream is read against.
    #[wasm_bindgen(getter)]
    pub fn handle(&self) -> u64 {
        self.handle
    }

    /// The pinned version's plaintext size in bytes. A JS number, not a
    /// `bigint`, so it pairs with the whole-number offsets `readStream` takes.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> f64 {
        self.size
    }
}

impl OpenedStream {
    /// Pairs a minted handle with its pinned version's size.
    pub fn new(handle: u64, size: f64) -> Self {
        Self { handle, size }
    }
}

/// The short fingerprint of a 33-byte compressed identity key, the value both
/// hosts show beside a grantee name (ADR 0027 D7). Throws on bytes that are
/// not an identity key.
#[wasm_bindgen(js_name = identityFingerprint)]
pub fn identity_fingerprint(identity_public_key: &[u8]) -> Result<String, JsError> {
    cipherbox_engine::fingerprint_identity_key(identity_public_key)
        .ok_or_else(|| JsError::new("invalid identity public key"))
}

/// A signed IPNS record's sequence and EOL, verified under the name it was
/// fetched for.
#[cfg(feature = "observer")]
#[wasm_bindgen]
pub struct IpnsRecordReading {
    inner: cipherbox_engine::net::eol::RecordReading,
}

#[cfg(feature = "observer")]
#[wasm_bindgen]
impl IpnsRecordReading {
    /// The record sequence number.
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    /// The signed RFC3339 EOL text.
    #[wasm_bindgen(getter)]
    pub fn validity(&self) -> String {
        self.inner.validity.clone()
    }

    /// The EOL as Unix millis, or `undefined` where the text does not parse.
    #[wasm_bindgen(getter, js_name = validUntil)]
    pub fn valid_until(&self) -> Option<u64> {
        self.inner.valid_until
    }
}

/// Reads the sequence and EOL of the signed `record` a routing endpoint
/// returned for `ipnsName`. Throws the check name of a record that is
/// malformed or that the name's key did not sign.
#[cfg(feature = "observer")]
#[wasm_bindgen(js_name = readIpnsRecord)]
pub fn read_ipns_record(ipns_name: &str, record: &[u8]) -> Result<IpnsRecordReading, JsError> {
    cipherbox_engine::net::eol::verify_record_outside_session(ipns_name, record)
        .map(|inner| IpnsRecordReading { inner })
        .map_err(|error| JsError::new(error.check()))
}

// ---------------------------------------------------------------------------
// The device-approval rendezvous (ADR 0009). Pure functions of the exchange
// transcript, exported free rather than as engine commands: a device that asks
// to be approved has no session to issue a command through.
// ---------------------------------------------------------------------------

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod rendezvous {
    use super::*;
    use zeroize::Zeroizing;

    /// What a requester needs to open a rendezvous: the key it offers, the bytes it
    /// must sign over that key, and the digits its screen shows.
    #[wasm_bindgen]
    pub struct DeviceRendezvous {
        ephemeral_public_key: String,
        request_payload: Vec<u8>,
        comparison_value: String,
    }

    #[wasm_bindgen]
    impl DeviceRendezvous {
        /// The compressed secp256k1 key a factor must be sealed to.
        #[wasm_bindgen(getter, js_name = ephemeralPublicKey)]
        pub fn ephemeral_public_key(&self) -> String {
            self.ephemeral_public_key.clone()
        }

        /// The bytes the requesting device signs.
        #[wasm_bindgen(getter, js_name = requestPayload)]
        pub fn request_payload(&self) -> Vec<u8> {
            self.request_payload.clone()
        }

        /// The digits this screen shows, for the member to compare with the
        /// approver's. Both sides derive them from the same two requester fields.
        #[wasm_bindgen(getter, js_name = comparisonValue)]
        pub fn comparison_value(&self) -> String {
            self.comparison_value.clone()
        }
    }

    /// What an approver sends: the sealed factor, if it approved, and the bytes it
    /// must sign over its whole answer.
    #[wasm_bindgen]
    pub struct DeviceApprovalResponse {
        sealed_factor: Option<String>,
        payload: Vec<u8>,
    }

    #[wasm_bindgen]
    impl DeviceApprovalResponse {
        /// The sealed fresh factor, base64; absent on a denial.
        #[wasm_bindgen(getter, js_name = sealedFactor)]
        pub fn sealed_factor(&self) -> Option<String> {
            self.sealed_factor.clone()
        }

        /// The bytes the approving device signs.
        #[wasm_bindgen(getter)]
        pub fn payload(&self) -> Vec<u8> {
            self.payload.clone()
        }
    }

    /// Open a rendezvous from 32 fresh random bytes. The scalar stays with the
    /// caller: it is what opens the factor an approver seals back.
    #[wasm_bindgen(js_name = openDeviceRendezvous)]
    pub fn open_device_rendezvous(
        device_public_key: &str,
        rendezvous_scalar: Vec<u8>,
    ) -> Result<DeviceRendezvous, JsError> {
        let ephemeral_public_key =
            cipherbox_engine::rendezvous_public_key(&*scalar32(rendezvous_scalar)?)
                .map_err(malformed_device_field)?;
        let request_payload =
            cipherbox_engine::approval_request_payload(device_public_key, &ephemeral_public_key)
                .map_err(malformed_device_field)?;
        let comparison_value =
            cipherbox_engine::comparison_value(device_public_key, &ephemeral_public_key)
                .map_err(malformed_device_field)?;
        Ok(DeviceRendezvous {
            ephemeral_public_key,
            request_payload,
            comparison_value,
        })
    }

    /// Seal a fresh factor to the requester and build the answer to sign.
    /// `seal_scalar` must be 32 fresh random bytes on every call.
    #[wasm_bindgen(js_name = approveDeviceRendezvous)]
    pub fn approve_device_rendezvous(
        device_public_key: &str,
        request_id: &str,
        requester_device_public_key: &str,
        ephemeral_public_key: &str,
        seal_scalar: Vec<u8>,
        factor_key: Vec<u8>,
    ) -> Result<DeviceApprovalResponse, JsError> {
        let factor_key = Zeroizing::new(factor_key);
        let sealed_factor = cipherbox_engine::seal_factor(
            ephemeral_public_key,
            request_id,
            requester_device_public_key,
            &*scalar32(seal_scalar)?,
            &factor_key,
        )
        .map_err(malformed_device_field)?;
        let payload = cipherbox_engine::approval_response_payload(
            device_public_key,
            request_id,
            cipherbox_engine::ApprovalDecision::Approve,
            ephemeral_public_key,
            &sealed_factor,
        )
        .map_err(malformed_device_field)?;
        Ok(DeviceApprovalResponse {
            sealed_factor: Some(sealed_factor),
            payload,
        })
    }

    /// Build the denial to sign. A denial seals nothing.
    #[wasm_bindgen(js_name = denyDeviceRendezvous)]
    pub fn deny_device_rendezvous(
        device_public_key: &str,
        request_id: &str,
        ephemeral_public_key: &str,
    ) -> Result<DeviceApprovalResponse, JsError> {
        let payload = cipherbox_engine::approval_response_payload(
            device_public_key,
            request_id,
            cipherbox_engine::ApprovalDecision::Deny,
            ephemeral_public_key,
            "",
        )
        .map_err(malformed_device_field)?;
        Ok(DeviceApprovalResponse {
            sealed_factor: None,
            payload,
        })
    }

    /// Adopt the factor an approver sealed, with the scalar that opened the
    /// rendezvous. The approver's signature over the answer is verified first,
    /// so a relayed envelope nobody signed for is never opened (D4).
    ///
    /// The plaintext crosses into JS from the borrowed slice while its zeroizing
    /// owner is still alive: a `Vec` return would hand wasm-bindgen a buffer it
    /// frees without clearing, leaving the factor in linear memory for the life of
    /// the tab.
    #[wasm_bindgen(js_name = openDeviceFactor)]
    pub fn open_device_factor(
        sealed_factor: &str,
        request_id: &str,
        requester_device_public_key: &str,
        responder_device_public_key: &str,
        response_signature: &str,
        rendezvous_scalar: Vec<u8>,
    ) -> Result<js_sys::Uint8Array, JsError> {
        let opened = cipherbox_engine::adopt_factor(
            sealed_factor,
            request_id,
            requester_device_public_key,
            responder_device_public_key,
            response_signature,
            &*scalar32(rendezvous_scalar)?,
        )
        .map_err(|refusal| JsError::new(refusal.check()))?;
        Ok(js_sys::Uint8Array::from(opened.as_slice()))
    }

    /// Adopt a scalar the host handed in. Taken by value and held zeroizing, so the
    /// copy wasm-bindgen makes in linear memory does not outlive the call.
    fn scalar32(bytes: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, JsError> {
        let bytes = Zeroizing::new(bytes);
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| JsError::new("a rendezvous scalar is 32 bytes"))
    }

    fn malformed_device_field(refusal: cipherbox_engine::MalformedDeviceField) -> JsError {
        JsError::new(refusal.check())
    }
}

// ---------------------------------------------------------------------------
// Native-only tests. The browser-shaped boundary behaviour lives in `tests/`
// under wasm-bindgen-test.
//
// Gated off wasm32-unknown-unknown (the exact complement of `boundary.rs`):
// that target has no libtest harness, so a plain `#[test]` there compiles to a
// silent no-op. Native and wasm32-wasip1 run these unchanged.
// ---------------------------------------------------------------------------

#[cfg(all(test, not(all(target_family = "wasm", target_os = "unknown"))))]
mod tests {
    use super::*;

    // The wrong-length rejection builds a `JsError` (wasm-only) — see
    // `tests/boundary.rs`.
    #[test]
    fn node_id_accepts_16_bytes_and_round_trips() {
        assert!(NodeId::from_bytes(&[0u8; 16]).is_ok());
        assert_eq!(
            NodeId::from_bytes(&[7u8; 16]).unwrap().bytes(),
            vec![7u8; 16]
        );
    }
}
