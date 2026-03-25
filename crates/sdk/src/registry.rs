//! Encrypted device registry operations.
//!
//! Manages registration of devices in the ECIES-encrypted device registry
//! stored on IPFS/IPNS. The registry enables cross-device awareness.
//!
//! OS-specific operations (keyring, hostname) are NOT here -- the desktop
//! app gathers device info and passes it as parameters.
//!
//! IMPORTANT: Registry operations must NEVER block login.
//! All errors are caught and logged by the caller (tokio::spawn wrapper).

use std::sync::Arc;

use base64::Engine;

use cipherbox_api_client::ApiClient;
use cipherbox_core::registry::{DeviceAuthStatus, DeviceEntry, DevicePlatform, DeviceRegistry};

use crate::error::SdkError;

/// Information about a device, gathered by the platform-specific caller.
///
/// The SDK does not gather this information itself -- the desktop app
/// provides it (hostname, platform, version, device model come from
/// platform-specific APIs like keyring and hostname crate).
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Unique device ID (from keyring or ephemeral UUID).
    pub device_id: String,
    /// Human-readable device name (from hostname).
    pub name: String,
    /// Device platform.
    pub platform: DevicePlatform,
    /// App version string (e.g., "0.1.0").
    pub app_version: String,
    /// Device model or OS version string.
    pub device_model: String,
}

/// Register a device in the encrypted device registry.
///
/// Steps:
/// 1. Derive registry IPNS keypair via HKDF
/// 2. Try to resolve existing registry from IPNS
/// 3. Build device entry from the provided DeviceInfo
/// 4. Update or create registry with the device entry
/// 5. Encrypt registry with user's public key (ECIES)
/// 6. Upload to IPFS and publish IPNS record
///
/// This function should be called via `tokio::spawn` so failures never block login.
pub async fn register_device(
    api: &Arc<ApiClient>,
    private_key: &[u8; 32],
    public_key: &[u8],
    device_info: DeviceInfo,
) -> Result<(), SdkError> {
    // 1. Derive registry IPNS keypair via HKDF
    let (reg_ipns_priv, _reg_ipns_pub, reg_ipns_name) =
        cipherbox_crypto::hkdf::derive_registry_ipns_keypair(private_key)?;

    // 2. Try to resolve existing registry from IPNS
    let existing_registry =
        match fetch_and_decrypt_registry(api, &reg_ipns_name, private_key).await {
            Ok(reg) => Some(reg),
            Err(_) => None, // No registry exists yet (first device)
        };

    // 3. Build device entry
    let update_app_version = device_info.app_version.clone();
    let update_device_model = device_info.device_model.clone();
    let device_entry = DeviceEntry {
        device_id: device_info.device_id.clone(),
        public_key: hex::encode(public_key),
        name: device_info.name,
        platform: device_info.platform,
        app_version: device_info.app_version,
        device_model: device_info.device_model,
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
        .find(|d| d.device_id == device_info.device_id)
    {
        existing.last_seen_at = now_ms();
        existing.app_version = update_app_version;
        existing.device_model = update_device_model;
    } else {
        registry.devices.push(device_entry);
    }
    registry.sequence_number += 1;

    // 5. Encrypt registry with user's public key (ECIES)
    let registry_json = serde_json::to_vec(&registry).map_err(|e| {
        SdkError::RegistryError(format!("Registry serialization failed: {}", e))
    })?;
    let encrypted = cipherbox_crypto::ecies::wrap_key(&registry_json, public_key)?;

    // 6. Upload encrypted registry to IPFS
    let cid = cipherbox_api_client::ipfs::upload_content(api, &encrypted)
        .await
        .map_err(SdkError::Api)?;

    // 7. Create and publish IPNS record
    let reg_ipns_priv_arr: [u8; 32] = reg_ipns_priv.as_slice().try_into().map_err(|_| {
        SdkError::RegistryError("Invalid registry IPNS key length".to_string())
    })?;
    let value = format!("/ipfs/{}", cid);
    let record = cipherbox_core::ipns::create_ipns_record(
        &reg_ipns_priv_arr,
        &value,
        registry.sequence_number,
        86_400_000,
    )?;
    let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)?;
    let record_base64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

    // Device registry publishes do not use conflict detection -- the registry
    // IPNS namespace is separate from folder metadata, and the registry write
    // is already serialized by the caller.
    let publish_req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: reg_ipns_name,
        record: record_base64,
        metadata_cid: cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(api, &publish_req)
        .await
        .map_err(SdkError::Api)?
    {
        cipherbox_api_client::PublishResult::Success => {}
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on device registry publish");
        }
    }

    log::info!(
        "Device registered in encrypted registry (device_id: {})",
        device_info.device_id
    );
    Ok(())
}

/// Fetch and decrypt existing registry from IPNS.
async fn fetch_and_decrypt_registry(
    api: &ApiClient,
    ipns_name: &str,
    private_key: &[u8; 32],
) -> Result<DeviceRegistry, SdkError> {
    let resolve = cipherbox_api_client::ipns::resolve_ipns(api, ipns_name)
        .await
        .map_err(SdkError::Api)?;
    let encrypted = cipherbox_api_client::ipfs::fetch_content(api, &resolve.cid)
        .await
        .map_err(SdkError::Api)?;
    let decrypted = cipherbox_crypto::ecies::unwrap_key(&encrypted, private_key)?;
    serde_json::from_slice(&decrypted).map_err(|e| {
        SdkError::RegistryError(format!("Registry parse failed: {}", e))
    })
}

/// Get the device name from the system hostname.
///
/// Convenience function for callers that don't want to handle hostname
/// resolution themselves. Returns "CipherBox Desktop" on error.
pub fn get_device_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "CipherBox Desktop".to_string())
}

/// Get the device platform enum for the current OS.
pub fn get_device_platform() -> DevicePlatform {
    #[cfg(target_os = "macos")]
    {
        DevicePlatform::Macos
    }
    #[cfg(target_os = "windows")]
    {
        DevicePlatform::Windows
    }
    #[cfg(target_os = "linux")]
    {
        DevicePlatform::Linux
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        DevicePlatform::Web
    }
}

/// Get a device model string for the current platform.
pub fn get_device_model() -> String {
    #[cfg(target_os = "macos")]
    {
        "macOS Desktop".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "Windows Desktop".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "Linux Desktop".to_string()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        "Desktop".to_string()
    }
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
    use cipherbox_core::registry::{DeviceAuthStatus, DeviceEntry, DevicePlatform, DeviceRegistry};

    #[test]
    fn device_info_construction_and_field_access() {
        let info = DeviceInfo {
            device_id: "dev-001".to_string(),
            name: "My Laptop".to_string(),
            platform: DevicePlatform::Macos,
            app_version: "1.2.3".to_string(),
            device_model: "macOS Desktop".to_string(),
        };

        assert_eq!(info.device_id, "dev-001");
        assert_eq!(info.name, "My Laptop");
        assert_eq!(info.platform, DevicePlatform::Macos);
        assert_eq!(info.app_version, "1.2.3");
        assert_eq!(info.device_model, "macOS Desktop");
    }

    #[test]
    fn device_info_clone() {
        let info = DeviceInfo {
            device_id: "dev-002".to_string(),
            name: "Work PC".to_string(),
            platform: DevicePlatform::Windows,
            app_version: "0.5.0".to_string(),
            device_model: "Windows Desktop".to_string(),
        };
        let cloned = info.clone();
        assert_eq!(cloned.device_id, info.device_id);
        assert_eq!(cloned.name, info.name);
    }

    #[test]
    fn device_platform_enum_variants() {
        // Verify all platform variants exist and are distinct.
        let web = DevicePlatform::Web;
        let macos = DevicePlatform::Macos;
        let linux = DevicePlatform::Linux;
        let windows = DevicePlatform::Windows;

        assert_eq!(web, DevicePlatform::Web);
        assert_eq!(macos, DevicePlatform::Macos);
        assert_eq!(linux, DevicePlatform::Linux);
        assert_eq!(windows, DevicePlatform::Windows);
        assert_ne!(macos, linux);
        assert_ne!(web, windows);
    }

    #[test]
    fn device_auth_status_variants() {
        let pending = DeviceAuthStatus::Pending;
        let authorized = DeviceAuthStatus::Authorized;
        let revoked = DeviceAuthStatus::Revoked;

        assert_eq!(pending, DeviceAuthStatus::Pending);
        assert_eq!(authorized, DeviceAuthStatus::Authorized);
        assert_eq!(revoked, DeviceAuthStatus::Revoked);
        assert_ne!(pending, authorized);
        assert_ne!(authorized, revoked);
    }

    #[test]
    fn get_device_platform_returns_valid_variant() {
        let platform = get_device_platform();
        // Should be one of the known variants on any supported platform.
        assert!(
            platform == DevicePlatform::Macos
                || platform == DevicePlatform::Windows
                || platform == DevicePlatform::Linux
                || platform == DevicePlatform::Web
        );
    }

    #[test]
    fn get_device_model_returns_non_empty_string() {
        let model = get_device_model();
        assert!(!model.is_empty());
    }

    #[test]
    fn get_device_name_returns_non_empty_string() {
        let name = get_device_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn device_auth_status_serde_roundtrip() {
        let statuses = vec![
            DeviceAuthStatus::Pending,
            DeviceAuthStatus::Authorized,
            DeviceAuthStatus::Revoked,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let parsed: DeviceAuthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, parsed);
        }
    }

    #[test]
    fn device_platform_serde_roundtrip() {
        let platforms = vec![
            DevicePlatform::Web,
            DevicePlatform::Macos,
            DevicePlatform::Linux,
            DevicePlatform::Windows,
        ];
        for platform in &platforms {
            let json = serde_json::to_string(platform).unwrap();
            let parsed: DevicePlatform = serde_json::from_str(&json).unwrap();
            assert_eq!(*platform, parsed);
        }
    }

    #[test]
    fn device_platform_serde_uses_lowercase() {
        assert_eq!(serde_json::to_string(&DevicePlatform::Macos).unwrap(), "\"macos\"");
        assert_eq!(serde_json::to_string(&DevicePlatform::Web).unwrap(), "\"web\"");
        assert_eq!(serde_json::to_string(&DevicePlatform::Linux).unwrap(), "\"linux\"");
        assert_eq!(serde_json::to_string(&DevicePlatform::Windows).unwrap(), "\"windows\"");
    }

    #[test]
    fn device_auth_status_serde_uses_lowercase() {
        assert_eq!(serde_json::to_string(&DeviceAuthStatus::Pending).unwrap(), "\"pending\"");
        assert_eq!(serde_json::to_string(&DeviceAuthStatus::Authorized).unwrap(), "\"authorized\"");
        assert_eq!(serde_json::to_string(&DeviceAuthStatus::Revoked).unwrap(), "\"revoked\"");
    }

    #[test]
    fn device_registry_serde_roundtrip() {
        let registry = DeviceRegistry {
            version: "v1".to_string(),
            sequence_number: 42,
            devices: vec![DeviceEntry {
                device_id: "dev-123".to_string(),
                public_key: "abcdef".to_string(),
                name: "Test Device".to_string(),
                platform: DevicePlatform::Linux,
                app_version: "0.1.0".to_string(),
                device_model: "Linux Desktop".to_string(),
                ip_hash: String::new(),
                status: DeviceAuthStatus::Authorized,
                created_at: 1700000000000,
                last_seen_at: 1700000001000,
                revoked_at: None,
                revoked_by: None,
            }],
        };

        let json = serde_json::to_string(&registry).unwrap();
        let parsed: DeviceRegistry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, "v1");
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.devices.len(), 1);
        assert_eq!(parsed.devices[0].device_id, "dev-123");
        assert_eq!(parsed.devices[0].platform, DevicePlatform::Linux);
        assert_eq!(parsed.devices[0].status, DeviceAuthStatus::Authorized);
    }

    #[test]
    fn now_ms_returns_reasonable_timestamp() {
        let ts = now_ms();
        // Should be after 2020-01-01 (1577836800000 ms) and non-zero.
        assert!(ts > 1_577_836_800_000);
    }
}
