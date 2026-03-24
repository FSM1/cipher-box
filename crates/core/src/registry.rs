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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device_entry() -> DeviceEntry {
        DeviceEntry {
            device_id: "sha256-hash-hex".to_string(),
            public_key: "ed25519-pubkey-hex".to_string(),
            name: "MacBook Pro".to_string(),
            platform: DevicePlatform::Macos,
            app_version: "0.1.0".to_string(),
            device_model: "MacBookPro18,1".to_string(),
            ip_hash: "ip-hash-hex".to_string(),
            status: DeviceAuthStatus::Authorized,
            created_at: 1700000000000,
            last_seen_at: 1700000001000,
            revoked_at: None,
            revoked_by: None,
        }
    }

    #[test]
    fn device_registry_serde_round_trip() {
        let registry = DeviceRegistry {
            version: "v1".to_string(),
            sequence_number: 7,
            devices: vec![sample_device_entry()],
        };

        let json = serde_json::to_string(&registry).unwrap();
        let deserialized: DeviceRegistry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, "v1");
        assert_eq!(deserialized.sequence_number, 7);
        assert_eq!(deserialized.devices.len(), 1);
        assert_eq!(deserialized.devices[0].device_id, "sha256-hash-hex");
        assert_eq!(deserialized.devices[0].name, "MacBook Pro");
    }

    #[test]
    fn camel_case_field_names_in_json() {
        let registry = DeviceRegistry {
            version: "v1".to_string(),
            sequence_number: 1,
            devices: vec![sample_device_entry()],
        };

        let json = serde_json::to_string(&registry).unwrap();

        // Registry-level camelCase
        assert!(json.contains("\"sequenceNumber\""));
        assert!(!json.contains("\"sequence_number\""));

        // DeviceEntry-level camelCase
        assert!(json.contains("\"deviceId\""));
        assert!(!json.contains("\"device_id\""));
        assert!(json.contains("\"publicKey\""));
        assert!(!json.contains("\"public_key\""));
        assert!(json.contains("\"appVersion\""));
        assert!(!json.contains("\"app_version\""));
        assert!(json.contains("\"deviceModel\""));
        assert!(!json.contains("\"device_model\""));
        assert!(json.contains("\"ipHash\""));
        assert!(!json.contains("\"ip_hash\""));
        assert!(json.contains("\"authStatus\"") || json.contains("\"status\""));
        assert!(json.contains("\"createdAt\""));
        assert!(json.contains("\"lastSeenAt\""));
    }

    #[test]
    fn device_auth_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&DeviceAuthStatus::Pending).unwrap(),
            r#""pending""#
        );
        assert_eq!(
            serde_json::to_string(&DeviceAuthStatus::Authorized).unwrap(),
            r#""authorized""#
        );
        assert_eq!(
            serde_json::to_string(&DeviceAuthStatus::Revoked).unwrap(),
            r#""revoked""#
        );
    }

    #[test]
    fn platform_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Web).unwrap(),
            r#""web""#
        );
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Macos).unwrap(),
            r#""macos""#
        );
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Linux).unwrap(),
            r#""linux""#
        );
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Windows).unwrap(),
            r#""windows""#
        );
    }

    #[test]
    fn optional_fields_serialize_as_null_when_none() {
        let entry = sample_device_entry();
        let json = serde_json::to_string(&entry).unwrap();

        // revoked_at and revoked_by are None, should appear as null in JSON
        // (serde serializes Option::None as null by default, not skipped)
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.get("revokedAt").unwrap(), &serde_json::Value::Null);
        assert_eq!(value.get("revokedBy").unwrap(), &serde_json::Value::Null);
    }

    #[test]
    fn optional_fields_present_when_some() {
        let mut entry = sample_device_entry();
        entry.status = DeviceAuthStatus::Revoked;
        entry.revoked_at = Some(1700000002000);
        entry.revoked_by = Some("other-device-id".to_string());

        let json = serde_json::to_string(&entry).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["revokedAt"], 1700000002000u64);
        assert_eq!(value["revokedBy"], "other-device-id");
    }

    #[test]
    fn empty_devices_registry_round_trip() {
        let registry = DeviceRegistry {
            version: "v1".to_string(),
            sequence_number: 0,
            devices: vec![],
        };
        let json = serde_json::to_string(&registry).unwrap();
        let deserialized: DeviceRegistry = serde_json::from_str(&json).unwrap();
        assert!(deserialized.devices.is_empty());
    }

    #[test]
    fn platform_deserializes_from_lowercase() {
        let p: DevicePlatform = serde_json::from_str(r#""macos""#).unwrap();
        assert_eq!(p, DevicePlatform::Macos);
        let p: DevicePlatform = serde_json::from_str(r#""windows""#).unwrap();
        assert_eq!(p, DevicePlatform::Windows);
    }

    #[test]
    fn auth_status_deserializes_from_lowercase() {
        let s: DeviceAuthStatus = serde_json::from_str(r#""pending""#).unwrap();
        assert_eq!(s, DeviceAuthStatus::Pending);
        let s: DeviceAuthStatus = serde_json::from_str(r#""revoked""#).unwrap();
        assert_eq!(s, DeviceAuthStatus::Revoked);
    }
}
