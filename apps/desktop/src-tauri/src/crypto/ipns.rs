//! IPNS record creation, marshaling, and name derivation.
//!
//! Produces IPNS records compatible with the TypeScript `ipns` npm package output.
//! Full implementation in Task 2.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpnsError {
    #[error("IPNS record creation failed")]
    CreationFailed,
    #[error("IPNS record marshaling failed")]
    MarshalingFailed,
    #[error("IPNS name derivation failed")]
    DerivationFailed,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
}

/// IPNS record structure matching the TypeScript IPNSRecord type.
#[derive(Debug, Clone)]
pub struct IpnsRecord {
    /// IPFS path value (e.g., "/ipfs/bafy...").
    pub value: String,
    /// RFC3339 validity timestamp.
    pub validity: String,
    /// Validity type (0 = EOL).
    pub validity_type: u32,
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// TTL in nanoseconds.
    pub ttl: u64,
    /// 64-byte Ed25519 V1 signature.
    pub signature_v1: Vec<u8>,
    /// 64-byte Ed25519 V2 signature.
    pub signature_v2: Vec<u8>,
    /// CBOR-encoded record data.
    pub data: Vec<u8>,
    /// 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
}

/// Create an IPNS record signed with the given Ed25519 private key.
///
/// Stub -- full implementation in Task 2.
pub fn create_ipns_record(
    _ed25519_private_key: &[u8; 32],
    _value: &str,
    _sequence_number: u64,
    _lifetime_ms: u64,
) -> Result<IpnsRecord, IpnsError> {
    Err(IpnsError::CreationFailed)
}

/// Marshal an IPNS record to protobuf bytes.
///
/// Stub -- full implementation in Task 2.
pub fn marshal_ipns_record(_record: &IpnsRecord) -> Result<Vec<u8>, IpnsError> {
    Err(IpnsError::MarshalingFailed)
}

/// Derive the IPNS name (CIDv1 base36) from an Ed25519 public key.
///
/// Stub -- full implementation in Task 2.
pub fn derive_ipns_name(_ed25519_public_key: &[u8; 32]) -> Result<String, IpnsError> {
    Err(IpnsError::DerivationFailed)
}
