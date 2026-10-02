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
/// pinned (`Engine::stream_size`). It crosses as plain data, so a host can
/// hand it to another realm.
#[derive(serde::Serialize, tsify::Tsify)]
#[tsify(large_number_types_as_bigints)]
pub struct OpenedStream {
    /// The handle every window of this stream is read against.
    handle: u64,
    /// The pinned version's plaintext size in bytes. A JS number, not a
    /// `bigint`, so it pairs with the whole-number offsets `readStream` takes.
    size: f64,
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

/// The device-approval rendezvous steps and what each produces.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub mod rendezvous {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
    use tsify::Ts;
    use zeroize::Zeroizing;

    use crate::boundary::{decode_rendezvous_step, encode_view};

    /// A scalar or a factor key the host handed in.
    pub type Secret = Zeroizing<Vec<u8>>;

    const SCALAR: &str = "scalar";
    const SEAL_SCALAR: &str = "sealScalar";
    const FACTOR_KEY: &str = "factorKey";

    /// The JS name of every secret field on any step. [`decode_rendezvous_step`]
    /// puts the empty placeholder in each before serde reads the step.
    pub(crate) const SECRET_FIELDS: [&str; 3] = [SCALAR, SEAL_SCALAR, FACTOR_KEY];

    /// Refuses real bytes. Serde has buffered them unwiped by the time this
    /// runs, so a secret field left off [`SECRET_FIELDS`] fails every decode
    /// rather than passing silently.
    fn secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
        let placeholder = Zeroizing::new(cipherbox_engine::wire::bytes::deserialize(deserializer)?);
        if !placeholder.is_empty() {
            return Err(de::Error::custom("a secret field skipped its placeholder"));
        }
        Ok(placeholder)
    }

    fn as_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    /// One step of the rendezvous. Every step is a pure function of the
    /// exchange transcript; the engine holds no state for it.
    #[derive(Deserialize, tsify::Tsify)]
    #[serde(
        tag = "kind",
        rename_all = "camelCase",
        rename_all_fields = "camelCase",
        deny_unknown_fields
    )]
    pub enum DeviceRendezvousStep {
        /// Open a rendezvous from 32 fresh random bytes. The scalar stays with
        /// the caller: it is what opens the factor an approver seals back.
        Open {
            /// The requesting device's key.
            device_public_key: String,
            /// The rendezvous scalar.
            #[serde(deserialize_with = "secret")]
            #[tsify(type = "Uint8Array")]
            scalar: Secret,
        },
        /// Seal a fresh factor to the requester and build the answer to sign.
        Approve {
            /// The approving device's key.
            device_public_key: String,
            /// The rendezvous being answered.
            request_id: String,
            /// The requesting device's key.
            requester_device_public_key: String,
            /// The key the requester offered.
            ephemeral_public_key: String,
            /// 32 fresh random bytes on every call.
            #[serde(deserialize_with = "secret")]
            #[tsify(type = "Uint8Array")]
            seal_scalar: Secret,
            /// The factor the requester adopts.
            #[serde(deserialize_with = "secret")]
            #[tsify(type = "Uint8Array")]
            factor_key: Secret,
        },
        /// Build the denial to sign. A denial seals nothing.
        Deny {
            /// The denying device's key.
            device_public_key: String,
            /// The rendezvous being answered.
            request_id: String,
            /// The key the requester offered.
            ephemeral_public_key: String,
        },
        /// Adopt the factor an approver sealed, with the scalar that opened the
        /// rendezvous.
        OpenFactor {
            /// The sealed factor, base64.
            sealed_factor: String,
            /// The rendezvous it answers.
            request_id: String,
            /// This device's key.
            requester_device_public_key: String,
            /// The approving device (D4).
            responder_device_public_key: String,
            /// The approver's signature over its whole answer (D4).
            response_signature: String,
            /// The scalar that opened the rendezvous.
            #[serde(deserialize_with = "secret")]
            #[tsify(type = "Uint8Array")]
            scalar: Secret,
        },
    }

    impl DeviceRendezvousStep {
        /// Each secret slot of this step, by its JS field name.
        pub(crate) fn secrets_mut(&mut self) -> Vec<(&'static str, &mut Secret)> {
            match self {
                Self::Open { scalar, .. } | Self::OpenFactor { scalar, .. } => {
                    vec![(SCALAR, scalar)]
                }
                Self::Approve {
                    seal_scalar,
                    factor_key,
                    ..
                } => vec![(SEAL_SCALAR, seal_scalar), (FACTOR_KEY, factor_key)],
                Self::Deny { .. } => Vec::new(),
            }
        }
    }

    /// What one rendezvous step produced.
    #[derive(Serialize, tsify::Tsify)]
    #[serde(
        tag = "kind",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )]
    #[tsify(missing_as_null)]
    pub enum DeviceRendezvousResult {
        /// What a requester offers and must sign, and the digits its screen
        /// shows.
        Opened {
            /// The compressed secp256k1 key a factor must be sealed to.
            ephemeral_public_key: String,
            /// The bytes the requesting device signs.
            #[serde(serialize_with = "as_bytes")]
            #[tsify(type = "Uint8Array")]
            request_payload: Vec<u8>,
            /// The digits this screen shows, for the member to compare with
            /// the approver's.
            comparison_value: String,
        },
        /// What an approver sends and must sign.
        Response {
            /// The sealed fresh factor, base64; `null` on a denial.
            sealed_factor: Option<String>,
            /// The bytes the approving device signs.
            #[serde(serialize_with = "as_bytes")]
            #[tsify(type = "Uint8Array")]
            payload: Vec<u8>,
        },
        /// The opened factor. The encode copies it into JS straight from this
        /// zeroizing owner, so no unwiped copy stays in linear memory.
        Factor {
            /// The factor key.
            #[serde(serialize_with = "as_bytes")]
            #[tsify(type = "Uint8Array")]
            factor_key: Secret,
        },
    }

    /// Runs one rendezvous step. Throws the check name of a malformed field or
    /// a refused answer, and a refusal for a step that does not decode.
    #[wasm_bindgen(js_name = deviceRendezvous, unchecked_return_type = "DeviceRendezvousResult")]
    pub fn device_rendezvous(step: Ts<DeviceRendezvousStep>) -> Result<JsValue, JsError> {
        encode_view(&run(decode_rendezvous_step(&step.js_value())?)?)
    }

    fn run(step: DeviceRendezvousStep) -> Result<DeviceRendezvousResult, JsError> {
        match step {
            DeviceRendezvousStep::Open {
                device_public_key,
                scalar,
            } => {
                let ephemeral_public_key =
                    cipherbox_engine::rendezvous_public_key(&*scalar32(&scalar)?)
                        .map_err(malformed_device_field)?;
                let request_payload = cipherbox_engine::approval_request_payload(
                    &device_public_key,
                    &ephemeral_public_key,
                )
                .map_err(malformed_device_field)?;
                let comparison_value =
                    cipherbox_engine::comparison_value(&device_public_key, &ephemeral_public_key)
                        .map_err(malformed_device_field)?;
                Ok(DeviceRendezvousResult::Opened {
                    ephemeral_public_key,
                    request_payload,
                    comparison_value,
                })
            }
            DeviceRendezvousStep::Approve {
                device_public_key,
                request_id,
                requester_device_public_key,
                ephemeral_public_key,
                seal_scalar,
                factor_key,
            } => {
                let sealed_factor = cipherbox_engine::seal_factor(
                    &ephemeral_public_key,
                    &request_id,
                    &requester_device_public_key,
                    &*scalar32(&seal_scalar)?,
                    &factor_key,
                )
                .map_err(malformed_device_field)?;
                let payload = cipherbox_engine::approval_response_payload(
                    &device_public_key,
                    &request_id,
                    cipherbox_engine::ApprovalDecision::Approve,
                    &ephemeral_public_key,
                    &sealed_factor,
                )
                .map_err(malformed_device_field)?;
                Ok(DeviceRendezvousResult::Response {
                    sealed_factor: Some(sealed_factor),
                    payload,
                })
            }
            DeviceRendezvousStep::Deny {
                device_public_key,
                request_id,
                ephemeral_public_key,
            } => {
                let payload = cipherbox_engine::approval_response_payload(
                    &device_public_key,
                    &request_id,
                    cipherbox_engine::ApprovalDecision::Deny,
                    &ephemeral_public_key,
                    "",
                )
                .map_err(malformed_device_field)?;
                Ok(DeviceRendezvousResult::Response {
                    sealed_factor: None,
                    payload,
                })
            }
            // The approver's signature over the answer is verified first, so a
            // relayed envelope nobody signed for is never opened (D4).
            DeviceRendezvousStep::OpenFactor {
                sealed_factor,
                request_id,
                requester_device_public_key,
                responder_device_public_key,
                response_signature,
                scalar,
            } => {
                let factor_key = cipherbox_engine::adopt_factor(
                    &sealed_factor,
                    &request_id,
                    &requester_device_public_key,
                    &responder_device_public_key,
                    &response_signature,
                    &*scalar32(&scalar)?,
                )
                .map_err(|refusal| JsError::new(refusal.check()))?;
                Ok(DeviceRendezvousResult::Factor { factor_key })
            }
        }
    }

    fn scalar32(bytes: &Secret) -> Result<Zeroizing<[u8; 32]>, JsError> {
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
