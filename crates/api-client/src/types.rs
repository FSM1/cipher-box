//! Request and response types for the CipherBox backend API.
//!
//! All structs use camelCase serialization to match the API's JSON format.
//! Auth DTOs use manual Debug impls to redact sensitive fields.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Login request body sent to POST /auth/login.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub id_token: String,
    pub public_key: String,
    pub login_type: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("id_token", &"[REDACTED]")
            .field("public_key", &"[REDACTED]")
            .field("login_type", &self.login_type)
            .finish()
    }
}

/// Login response from POST /auth/login (desktop client receives refreshToken in body).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub is_new_user: bool,
}

impl fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("is_new_user", &self.is_new_user)
            .finish()
    }
}

/// Refresh request body sent to POST /auth/refresh.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

/// Refresh response from POST /auth/refresh (desktop client receives refreshToken in body).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
}

impl fmt::Debug for RefreshResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

/// TEE public keys included in vault response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeeKeysResponse {
    pub current_epoch: u32,
    pub current_public_key: String,
    pub previous_epoch: Option<u32>,
    pub previous_public_key: Option<String>,
}

/// Request body for POST /vault/init (new user vault initialization).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitVaultRequest {
    pub owner_public_key: String,
    pub root_ipns_name: String,
}

impl fmt::Debug for InitVaultRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitVaultRequest")
            .field("owner_public_key", &"[REDACTED]")
            .field("root_ipns_name", &self.root_ipns_name)
            .finish()
    }
}

/// Vault response from GET /vault.
///
/// The rootFolderKey lives exclusively in the IPFS vault blob v2 header.
/// The IPNS key is HKDF-derived client-side.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultResponse {
    pub root_ipns_name: String,
    pub tee_keys: Option<TeeKeysResponse>,
}

impl fmt::Debug for VaultResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultResponse")
            .field("root_ipns_name", &self.root_ipns_name)
            .field("tee_keys", &self.tee_keys)
            .finish()
    }
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
    /// Base64-encoded Ed25519 signature over "ipns-signature:" || data (optional, absent on legacy records).
    pub signature_v2: Option<String>,
    /// Base64-encoded CBOR-encoded IPNS record data that was signed (optional).
    pub data: Option<String>,
    /// Base64-encoded Ed25519 public key that produced the signature (optional).
    pub pub_key: Option<String>,
}

/// IPNS publish request body matching the backend PublishIpnsDto.
#[derive(Serialize)]
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

impl std::fmt::Debug for IpnsPublishRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpnsPublishRequest")
            .field("ipns_name", &self.ipns_name)
            .field("metadata_cid", &self.metadata_cid)
            .field("record", &"[REDACTED]")
            .field("encrypted_ipns_private_key", &self.encrypted_ipns_private_key.as_ref().map(|_| "[REDACTED]"))
            .field("key_epoch", &self.key_epoch)
            .field("expected_sequence_number", &self.expected_sequence_number)
            .finish()
    }
}

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

/// Response from POST /ipfs/upload.
#[derive(Debug, Deserialize)]
pub struct UploadResponse {
    /// CID of the uploaded content.
    pub cid: String,
}

/// Request body for POST /ipfs/unpin.
#[derive(Debug, Serialize)]
pub struct UnpinRequest<'a> {
    /// CID to unpin.
    pub cid: &'a str,
}
