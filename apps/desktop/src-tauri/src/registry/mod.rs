//! Encrypted device registry client.
//!
//! Manages registration of the desktop device in the ECIES-encrypted
//! device registry stored on IPFS/IPNS. The registry enables cross-device
//! awareness: the web app can see the desktop as a known device, and the
//! desktop can participate in device approval flows.
//!
//! IMPORTANT: Registry operations must NEVER block login.
//! All errors are caught and logged by the caller (tokio::spawn wrapper).

pub mod types;

use std::sync::Arc;

use base64::Engine;

use crate::api::client::ApiClient;
use crate::api::ipns::IpnsPublishRequest;
use crate::crypto;
use types::{DeviceAuthStatus, DeviceEntry, DevicePlatform, DeviceRegistry};

/// Register this desktop device in the encrypted device registry.
///
/// Steps:
/// 1. Derive registry IPNS keypair via HKDF
/// 2. Try to resolve existing registry from IPNS
/// 3. Build device entry for this desktop
/// 4. Update or create registry with the device entry
/// 5. Encrypt registry with user's public key (ECIES)
/// 6. Upload to IPFS and publish IPNS record
///
/// This function should be called via `tokio::spawn` so failures never block login.
pub async fn register_device(
    api: &Arc<ApiClient>,
    private_key: &[u8; 32],
    public_key: &[u8],
    _user_id: &str,
) -> Result<(), String> {
    // 1. Derive registry IPNS keypair via HKDF
    let (reg_ipns_priv, _reg_ipns_pub, reg_ipns_name) =
        crypto::hkdf::derive_registry_ipns_keypair(private_key)
            .map_err(|e| format!("Registry IPNS derivation failed: {}", e))?;

    // 2. Try to resolve existing registry from IPNS
    let existing_registry = match fetch_and_decrypt_registry(api, &reg_ipns_name, private_key).await
    {
        Ok(reg) => Some(reg),
        Err(_) => None, // No registry exists yet (first device)
    };

    // 3. Build device entry for this desktop
    let device_id = get_or_create_device_id();
    let device_entry = DeviceEntry {
        device_id: device_id.clone(),
        public_key: hex::encode(public_key),
        name: get_device_name(),
        platform: DevicePlatform::Macos,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        device_model: get_device_model(),
        ip_hash: String::new(), // Not tracked for desktop
        status: if existing_registry.is_none() {
            DeviceAuthStatus::Authorized // First device auto-authorized
        } else {
            DeviceAuthStatus::Pending
        },
        created_at: now_ms(),
        last_seen_at: now_ms(),
        revoked_at: None,
        revoked_by: None,
    };

    // 4. Build updated registry
    let mut registry = existing_registry.unwrap_or(DeviceRegistry {
        version: "v1".to_string(),
        sequence_number: 0,
        devices: vec![],
    });

    // Update existing device entry or add new one
    if let Some(existing) = registry
        .devices
        .iter_mut()
        .find(|d| d.device_id == device_id)
    {
        existing.last_seen_at = now_ms();
        existing.app_version = env!("CARGO_PKG_VERSION").to_string();
    } else {
        registry.devices.push(device_entry);
    }
    registry.sequence_number += 1;

    // 5. Encrypt registry with user's public key (ECIES)
    let registry_json = serde_json::to_vec(&registry)
        .map_err(|e| format!("Registry serialization failed: {}", e))?;
    let encrypted = crypto::ecies::wrap_key(&registry_json, public_key)
        .map_err(|e| format!("Registry encryption failed: {}", e))?;

    // 6. Upload encrypted registry to IPFS
    let cid = crate::api::ipfs::upload_content(api, &encrypted).await?;

    // 7. Create and publish IPNS record
    let reg_ipns_priv_arr: [u8; 32] = reg_ipns_priv
        .try_into()
        .map_err(|_| "Invalid registry IPNS key length".to_string())?;
    let value = format!("/ipfs/{}", cid);
    let record =
        crypto::ipns::create_ipns_record(&reg_ipns_priv_arr, &value, registry.sequence_number, 86_400_000)
            .map_err(|e| format!("IPNS record creation failed: {}", e))?;
    let marshaled = crypto::ipns::marshal_ipns_record(&record)
        .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
    let record_base64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

    let publish_req = IpnsPublishRequest {
        ipns_name: reg_ipns_name,
        record: record_base64,
        metadata_cid: cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
    };
    crate::api::ipns::publish_ipns(api, &publish_req).await?;

    log::info!(
        "Device registered in encrypted registry (device_id: {})",
        device_id
    );
    Ok(())
}

/// Fetch and decrypt existing registry from IPNS.
async fn fetch_and_decrypt_registry(
    api: &ApiClient,
    ipns_name: &str,
    private_key: &[u8; 32],
) -> Result<DeviceRegistry, String> {
    let resolve = crate::api::ipns::resolve_ipns(api, ipns_name).await?;
    let encrypted = crate::api::ipfs::fetch_content(api, &resolve.cid).await?;
    let decrypted = crypto::ecies::unwrap_key(&encrypted, private_key)
        .map_err(|e| format!("Registry decryption failed: {}", e))?;
    serde_json::from_slice(&decrypted).map_err(|e| format!("Registry parse failed: {}", e))
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
        let bytes = crypto::utils::generate_random_bytes(16);
        let uuid = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6] & 0x0f, bytes[7],
            (bytes[8] & 0x3f) | 0x80, bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        );
        log::info!("Debug mode: using ephemeral device ID (no Keychain access)");
        return uuid;
    }

    #[cfg(not(debug_assertions))]
    {
        let entry = keyring::Entry::new("cipherbox-desktop", "device-id")
            .unwrap_or_else(|e| {
                log::warn!("Keychain entry creation failed: {}", e);
                panic!("Cannot create keyring entry: {}", e);
            });

        match entry.get_password() {
            Ok(id) if !id.is_empty() => id,
            _ => {
                let bytes = crypto::utils::generate_random_bytes(16);
                let uuid = format!(
                    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5],
                    bytes[6] & 0x0f, bytes[7],
                    (bytes[8] & 0x3f) | 0x80, bytes[9],
                    bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
                );

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

/// Get the device name from the system hostname.
fn get_device_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "CipherBox Desktop".to_string())
}

/// Get a device model string.
///
/// Returns a generic "macOS Desktop" string. Could be enhanced with
/// `sysinfo` crate for specific model names (e.g., "MacBook Pro").
fn get_device_model() -> String {
    "macOS Desktop".to_string()
}

/// Get the current time in milliseconds since Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_get_device_name() {
        let name = get_device_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_get_device_model() {
        let model = get_device_model();
        assert_eq!(model, "macOS Desktop");
    }

    #[test]
    fn test_now_ms() {
        let ts = now_ms();
        // Should be a reasonable timestamp (after 2024-01-01)
        assert!(ts > 1704067200000);
    }
}
