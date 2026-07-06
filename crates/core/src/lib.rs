//! CipherBox domain types, metadata schemas, IPNS records, and vault blob.
//!
//! Contains everything that "knows about CipherBox's data model."
//! Depends on cipherbox-crypto for cryptographic primitives.
//! Mirrors @cipherbox/core TypeScript package.

pub mod bin;
pub mod error;
pub mod file;
pub mod folder;
pub mod ipns;
pub mod node;
pub mod registry;
pub mod vault_blob;
pub mod vault_settings;

// Re-export primary types and functions
pub use bin::{
    decrypt_bin_metadata, empty_bin_metadata, encrypt_bin_metadata, BinEntry, BinItemType,
    RecycleBinMetadata,
};
pub use error::CoreError;
pub use folder::VersionEntry;
pub use ipns::{create_ipns_record, marshal_ipns_record, IpnsRecord};
pub use registry::{DeviceAuthStatus, DeviceEntry, DevicePlatform, DeviceRegistry};
pub use vault_blob::{deserialize_vault_blob_v2, detect_blob_version, serialize_vault_blob_v2};
pub use vault_settings::{
    default_vault_settings, validate_vault_settings, DeleteBehavior, VaultSettings,
};
