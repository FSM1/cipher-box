//! Device registry types matching the web app's TypeScript definitions.
//!
//! These types are serialized/deserialized as camelCase JSON to ensure
//! cross-platform compatibility with the web app's device registry.

use serde::{Deserialize, Serialize};

/// Authorization status for a device in the registry.
///
/// Matches TypeScript: `'pending' | 'authorized' | 'revoked'`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceAuthStatus {
    Pending,
    Authorized,
    Revoked,
}

/// Platform identifier for a device.
///
/// Matches TypeScript: `'web' | 'macos' | 'linux' | 'windows'`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DevicePlatform {
    Web,
    Macos,
    Linux,
    Windows,
}

/// Individual device entry in the registry.
///
/// Each entry represents a physical device that has authenticated
/// with the user's CipherBox account. Matches the TypeScript `DeviceEntry` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEntry {
    /// SHA-256 hash of device's Ed25519 public key (hex).
    pub device_id: String,
    /// Device's Ed25519 public key (hex) - for future key exchange.
    pub public_key: String,
    /// Human-readable device name (e.g., "MacBook Pro").
    pub name: String,
    /// Platform identifier.
    pub platform: DevicePlatform,
    /// App version string (e.g., "0.1.0").
    pub app_version: String,
    /// Device model or OS version.
    pub device_model: String,
    /// SHA-256 hash of IP address at registration (hex, privacy-preserving).
    pub ip_hash: String,
    /// Authorization status.
    pub status: DeviceAuthStatus,
    /// When device was first registered (Unix ms).
    pub created_at: u64,
    /// Last time device synced with registry (Unix ms).
    pub last_seen_at: u64,
    /// When device was revoked (Unix ms, null if not revoked).
    pub revoked_at: Option<u64>,
    /// Device ID of the device that performed revocation (null if not revoked).
    pub revoked_by: Option<String>,
}

/// The full device registry.
///
/// Encrypted as a single JSON blob with the user's publicKey via ECIES,
/// then stored on IPFS and referenced by a dedicated IPNS name.
/// Matches the TypeScript `DeviceRegistry` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegistry {
    /// Schema version for future migrations.
    pub version: String,
    /// Monotonically increasing update counter.
    pub sequence_number: u64,
    /// Array of all device entries (including revoked, for audit trail).
    pub devices: Vec<DeviceEntry>,
}
