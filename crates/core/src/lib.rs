//! CipherBox domain types, metadata schemas, IPNS records, and vault blob.
//!
//! Contains everything that "knows about CipherBox's data model."
//! Depends on cipherbox-crypto for cryptographic primitives.
//! Mirrors @cipherbox/core TypeScript package.

pub mod folder;
pub mod file;
pub mod registry;
pub mod bin;
pub mod vault_blob;
pub mod ipns;
pub mod decrypt;
pub mod vault_settings;
pub mod error;

// Re-export primary types and functions
pub use folder::{FolderMetadata, FolderChild, FolderEntry, encrypt_folder_metadata, decrypt_folder_metadata};
pub use file::{FileMetadata, FilePointer, VersionEntry};
pub use registry::{DeviceRegistry, DeviceEntry, DeviceAuthStatus, DevicePlatform};
pub use bin::{RecycleBinMetadata, BinEntry, BinItemType, encrypt_bin_metadata, decrypt_bin_metadata, empty_bin_metadata};
pub use vault_blob::{serialize_vault_blob_v2, deserialize_vault_blob_v2, detect_blob_version};
pub use ipns::{IpnsRecord, create_ipns_record, marshal_ipns_record};
pub use decrypt::{decrypt_metadata_from_ipfs_public, decrypt_file_metadata_from_ipfs_public};
pub use vault_settings::{VaultSettings, DeleteBehavior, default_vault_settings, validate_vault_settings};
pub use error::CoreError;
