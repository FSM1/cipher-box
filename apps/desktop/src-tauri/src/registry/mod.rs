//! Desktop device registry client.
//!
//! Delegates encrypted device registry operations to `cipherbox_sdk::registry`.
//! OS-specific operations (keyring for device ID, hostname) stay here.
//!
//! IMPORTANT: Registry operations must NEVER block login.
//! All errors are caught and logged by the caller (tokio::spawn wrapper).

use std::sync::Arc;

use cipherbox_api_client::ApiClient;
use cipherbox_sdk::registry::DeviceInfo;

/// Register this desktop device in the encrypted device registry.
///
/// Gathers OS-specific device info (hostname, keyring device ID) and delegates
/// the actual registration to `cipherbox_sdk::registry::register_device`.
///
/// This function should be called via `tokio::spawn` so failures never block login.
pub async fn register_device(
    api: &Arc<ApiClient>,
    private_key: &[u8; 32],
    public_key: &[u8],
    _user_id: &str,
) -> Result<(), String> {
    let device_info = DeviceInfo {
        device_id: get_or_create_device_id(),
        name: cipherbox_sdk::registry::get_device_name(),
        platform: cipherbox_sdk::registry::get_device_platform(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        device_model: cipherbox_sdk::registry::get_device_model(),
    };

    cipherbox_sdk::registry::register_device(api, private_key, public_key, device_info)
        .await
        .map_err(|e| e.to_string())
}

/// Get or create a persistent device ID stored in macOS Keychain.
///
/// Uses the `keyring` crate with service "cipherbox-desktop" and key "device-id".
/// If no device ID exists, generates a UUID v4 and stores it.
///
/// In debug builds, skips Keychain entirely and uses an ephemeral UUID.
/// This avoids macOS Keychain permission prompts that fire on every rebuild
/// (each build produces a new binary signature).
fn get_or_create_device_id() -> String {
    #[cfg(debug_assertions)]
    {
        use cipherbox_crypto::utils::generate_uuid_v4;
        log::info!("Debug mode: using ephemeral device ID (no Keychain access)");
        return generate_uuid_v4();
    }

    #[cfg(not(debug_assertions))]
    {
        use cipherbox_crypto::utils::generate_uuid_v4;
        let entry = match keyring::Entry::new("cipherbox-desktop", "device-id") {
            Ok(e) => e,
            Err(e) => {
                log::warn!("Keychain entry creation failed: {}. Using ephemeral ID.", e);
                return generate_uuid_v4();
            }
        };

        match entry.get_password() {
            Ok(id) if !id.is_empty() => id,
            _ => {
                let uuid = generate_uuid_v4();

                let _ = entry.delete_credential();
                if let Err(e) = entry.set_password(&uuid) {
                    log::warn!(
                        "Failed to store device ID in Keychain: {}. Using ephemeral ID.",
                        e
                    );
                }
                uuid
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use cipherbox_core::registry::{DeviceAuthStatus, DeviceEntry, DevicePlatform, DeviceRegistry};

    #[test]
    fn test_device_registry_serialization() {
        let registry = DeviceRegistry {
            version: "v1".to_string(),
            sequence_number: 1,
            devices: vec![DeviceEntry {
                device_id: "abc123".to_string(),
                public_key: "deadbeef".to_string(),
                name: "Test Device".to_string(),
                platform: DevicePlatform::Macos,
                app_version: "0.1.0".to_string(),
                device_model: "macOS Desktop".to_string(),
                ip_hash: "".to_string(),
                status: DeviceAuthStatus::Authorized,
                created_at: 1700000000000,
                last_seen_at: 1700000000000,
                revoked_at: None,
                revoked_by: None,
            }],
        };

        let json = serde_json::to_string(&registry).unwrap();

        // Verify camelCase serialization
        assert!(json.contains("\"sequenceNumber\":1"));
        assert!(json.contains("\"deviceId\":\"abc123\""));
        assert!(json.contains("\"publicKey\":\"deadbeef\""));
        assert!(json.contains("\"appVersion\":\"0.1.0\""));
        assert!(json.contains("\"deviceModel\":\"macOS Desktop\""));
        assert!(json.contains("\"ipHash\":\"\""));
        assert!(json.contains("\"status\":\"authorized\""));
        assert!(json.contains("\"createdAt\":1700000000000"));
        assert!(json.contains("\"lastSeenAt\":1700000000000"));
        assert!(json.contains("\"revokedAt\":null"));
        assert!(json.contains("\"revokedBy\":null"));
        assert!(json.contains("\"platform\":\"macos\""));
    }

    #[test]
    fn test_device_registry_deserialization() {
        let json = r#"{
            "version": "v1",
            "sequenceNumber": 3,
            "devices": [{
                "deviceId": "dev-001",
                "publicKey": "aabbcc",
                "name": "Chrome on macOS",
                "platform": "web",
                "appVersion": "0.2.0",
                "deviceModel": "macOS 15.2",
                "ipHash": "def456",
                "status": "pending",
                "createdAt": 1700000000000,
                "lastSeenAt": 1700000001000,
                "revokedAt": null,
                "revokedBy": null
            }]
        }"#;

        let registry: DeviceRegistry = serde_json::from_str(json).unwrap();
        assert_eq!(registry.version, "v1");
        assert_eq!(registry.sequence_number, 3);
        assert_eq!(registry.devices.len(), 1);
        assert_eq!(registry.devices[0].device_id, "dev-001");
        assert_eq!(registry.devices[0].platform, DevicePlatform::Web);
        assert_eq!(registry.devices[0].status, DeviceAuthStatus::Pending);
    }

    #[test]
    fn test_device_entry_status_variants() {
        // Verify all status values serialize correctly
        let authorized: DeviceAuthStatus =
            serde_json::from_str("\"authorized\"").unwrap();
        assert_eq!(authorized, DeviceAuthStatus::Authorized);

        let pending: DeviceAuthStatus =
            serde_json::from_str("\"pending\"").unwrap();
        assert_eq!(pending, DeviceAuthStatus::Pending);

        let revoked: DeviceAuthStatus =
            serde_json::from_str("\"revoked\"").unwrap();
        assert_eq!(revoked, DeviceAuthStatus::Revoked);
    }

    #[test]
    fn test_device_platform_variants() {
        // Verify all platform values serialize correctly
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Web).unwrap(),
            "\"web\""
        );
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Macos).unwrap(),
            "\"macos\""
        );
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Linux).unwrap(),
            "\"linux\""
        );
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Windows).unwrap(),
            "\"windows\""
        );
    }
}
