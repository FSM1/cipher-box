//! User-configurable vault settings.
//!
//! Settings are stored as ECIES-encrypted JSON in an IPNS entry.
//! The server never sees plaintext settings (zero-knowledge).
//! Mirrors @cipherbox/core VaultSettings TypeScript type.

use serde::{Deserialize, Serialize};

/// Delete behavior for vault files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum DeleteBehavior {
    Bin,
    Permanent,
}

/// User-configurable vault settings.
///
/// JSON field names use camelCase to match TypeScript serialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettings {
    /// Schema version for future migrations.
    pub version: String,
    /// Recycle bin retention period in days (0-365; 0 = immediate purge).
    pub recycle_bin_retention_days: u32,
    /// Delete behavior: Bin = soft delete, Permanent = immediate hard delete.
    pub delete_behavior: DeleteBehavior,
    /// Maximum number of past versions retained per file (0-100).
    pub max_versions_per_file: u32,
    /// Cooldown period for version creation in minutes (0-1440).
    pub version_cooldown_minutes: u32,
}

/// Returns the default vault settings matching current hardcoded behavior.
pub fn default_vault_settings() -> VaultSettings {
    VaultSettings {
        version: "v1".to_string(),
        recycle_bin_retention_days: 30,
        delete_behavior: DeleteBehavior::Bin,
        max_versions_per_file: 10,
        version_cooldown_minutes: 15,
    }
}

/// Validate and sanitize vault settings from parsed JSON.
///
/// Clamps out-of-range numeric values to valid bounds.
/// Returns default settings for corrupt or non-object input.
/// Returns default settings if version is not "v1" (unknown version guard).
pub fn validate_vault_settings(input: &serde_json::Value) -> VaultSettings {
    let defaults = default_vault_settings();

    let obj = match input.as_object() {
        Some(o) => o,
        None => return defaults,
    };

    // Unknown version guard
    if let Some(version) = obj.get("version") {
        if version.as_str() != Some("v1") {
            return defaults;
        }
    }

    let recycle_bin_retention_days = obj
        .get("recycleBinRetentionDays")
        .and_then(|v| v.as_u64())
        .map(|v| (v as u32).clamp(0, 365))
        .unwrap_or(defaults.recycle_bin_retention_days);

    let delete_behavior = obj
        .get("deleteBehavior")
        .and_then(|v| v.as_str())
        .and_then(|s| match s {
            "bin" => Some(DeleteBehavior::Bin),
            "permanent" => Some(DeleteBehavior::Permanent),
            _ => None,
        })
        .unwrap_or(defaults.delete_behavior);

    let max_versions_per_file = obj
        .get("maxVersionsPerFile")
        .and_then(|v| v.as_u64())
        .map(|v| (v as u32).clamp(0, 100))
        .unwrap_or(defaults.max_versions_per_file);

    let version_cooldown_minutes = obj
        .get("versionCooldownMinutes")
        .and_then(|v| v.as_u64())
        .map(|v| (v as u32).clamp(0, 1440))
        .unwrap_or(defaults.version_cooldown_minutes);

    VaultSettings {
        version: "v1".to_string(),
        recycle_bin_retention_days,
        delete_behavior,
        max_versions_per_file,
        version_cooldown_minutes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_vault_settings_has_correct_values() {
        let defaults = default_vault_settings();
        assert_eq!(defaults.version, "v1");
        assert_eq!(defaults.recycle_bin_retention_days, 30);
        assert_eq!(defaults.delete_behavior, DeleteBehavior::Bin);
        assert_eq!(defaults.max_versions_per_file, 10);
        assert_eq!(defaults.version_cooldown_minutes, 15);
    }

    #[test]
    fn validate_with_valid_json_returns_correct_settings() {
        let input = json!({
            "version": "v1",
            "recycleBinRetentionDays": 60,
            "deleteBehavior": "permanent",
            "maxVersionsPerFile": 20,
            "versionCooldownMinutes": 30
        });
        let result = validate_vault_settings(&input);
        assert_eq!(result.version, "v1");
        assert_eq!(result.recycle_bin_retention_days, 60);
        assert_eq!(result.delete_behavior, DeleteBehavior::Permanent);
        assert_eq!(result.max_versions_per_file, 20);
        assert_eq!(result.version_cooldown_minutes, 30);
    }

    #[test]
    fn validate_clamps_retention_days_above_365() {
        let input = json!({
            "version": "v1",
            "recycleBinRetentionDays": 500
        });
        let result = validate_vault_settings(&input);
        assert_eq!(result.recycle_bin_retention_days, 365);
    }

    #[test]
    fn validate_clamps_retention_days_below_0() {
        // JSON u64 can't be negative, so test with missing field
        // For negative values, serde_json::as_u64() returns None -> default
        let input = json!({
            "version": "v1",
            "recycleBinRetentionDays": -5
        });
        let result = validate_vault_settings(&input);
        // Negative value fails as_u64(), falls back to default 30
        assert_eq!(result.recycle_bin_retention_days, 30);
    }

    #[test]
    fn validate_retention_days_zero_is_valid() {
        let input = json!({
            "version": "v1",
            "recycleBinRetentionDays": 0
        });
        let result = validate_vault_settings(&input);
        assert_eq!(result.recycle_bin_retention_days, 0);
    }

    #[test]
    fn validate_clamps_max_versions_above_100() {
        let input = json!({
            "version": "v1",
            "maxVersionsPerFile": 200
        });
        let result = validate_vault_settings(&input);
        assert_eq!(result.max_versions_per_file, 100);
    }

    #[test]
    fn validate_clamps_cooldown_above_1440() {
        let input = json!({
            "version": "v1",
            "versionCooldownMinutes": 2000
        });
        let result = validate_vault_settings(&input);
        assert_eq!(result.version_cooldown_minutes, 1440);
    }

    #[test]
    fn validate_returns_defaults_for_null_input() {
        let input = json!(null);
        let result = validate_vault_settings(&input);
        assert_eq!(result, default_vault_settings());
    }

    #[test]
    fn validate_returns_defaults_for_non_object_input() {
        let input = json!("not an object");
        let result = validate_vault_settings(&input);
        assert_eq!(result, default_vault_settings());

        let input = json!(42);
        let result = validate_vault_settings(&input);
        assert_eq!(result, default_vault_settings());

        let input = json!([1, 2, 3]);
        let result = validate_vault_settings(&input);
        assert_eq!(result, default_vault_settings());
    }

    #[test]
    fn validate_returns_defaults_for_unknown_version() {
        let input = json!({
            "version": "v99",
            "recycleBinRetentionDays": 60
        });
        let result = validate_vault_settings(&input);
        assert_eq!(result, default_vault_settings());
    }

    #[test]
    fn serde_round_trip_uses_camel_case() {
        let settings = VaultSettings {
            version: "v1".to_string(),
            recycle_bin_retention_days: 45,
            delete_behavior: DeleteBehavior::Permanent,
            max_versions_per_file: 25,
            version_cooldown_minutes: 60,
        };

        let json_str = serde_json::to_string(&settings).unwrap();
        assert!(json_str.contains("\"maxVersionsPerFile\""));
        assert!(json_str.contains("\"recycleBinRetentionDays\""));
        assert!(json_str.contains("\"deleteBehavior\""));
        assert!(json_str.contains("\"versionCooldownMinutes\""));
        // Verify no snake_case in output
        assert!(!json_str.contains("max_versions_per_file"));
        assert!(!json_str.contains("recycle_bin_retention_days"));

        // Deserialize back
        let parsed: VaultSettings = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed, settings);
    }

    #[test]
    fn deserialize_from_camel_case_json() {
        let json_str = r#"{"version":"v1","recycleBinRetentionDays":30,"deleteBehavior":"bin","maxVersionsPerFile":10,"versionCooldownMinutes":15}"#;
        let settings: VaultSettings = serde_json::from_str(json_str).unwrap();
        assert_eq!(settings, default_vault_settings());
    }

    #[test]
    fn validate_with_missing_fields_uses_defaults() {
        let input = json!({
            "version": "v1"
        });
        let result = validate_vault_settings(&input);
        assert_eq!(result.version, "v1");
        assert_eq!(result.recycle_bin_retention_days, 30);
        assert_eq!(result.delete_behavior, DeleteBehavior::Bin);
        assert_eq!(result.max_versions_per_file, 10);
        assert_eq!(result.version_cooldown_minutes, 15);
    }
}
