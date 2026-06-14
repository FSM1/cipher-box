//! Shared journal-entry builders for the CipherBox FUSE filesystem.
//!
//! This module provides `build_upload_journal_entry` and
//! `build_mkdir_journal_entry` as inherent methods on [`CipherBoxFS`], so both
//! the fuser (macOS/Linux) and WinFsp (Windows) write paths share a single
//! implementation of the encrypt → ECIES-wrap → resolve-parent-IPNS →
//! build-`JournalEntry` steps.
//!
//! Each platform keeps its own reply/return machinery, in-memory inode
//! mutations, and background spawn — only the entry-build steps live here.
//!
//! ## Security invariants
//!
//! - `UploadJournalResult` carries `ciphertext` only; plaintext is never
//!   stored in the result struct.
//! - Each key is ECIES-wrapped exactly once.  The caller must not re-wrap.
//! - `is_first_publish` is threaded through to the caller so the per-file
//!   IPNS sequence number is computed correctly (§Pitfall 4 in 45-RESEARCH.md).

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::inode::{InodeKind, ROOT_INO};

/// Result returned by [`CipherBoxFS::build_upload_journal_entry`].
///
/// Carries the built [`cipherbox_sdk::JournalEntry`] and every field the
/// caller's inode-mutation and spawn block needs.  The `ciphertext` field
/// holds the AES-256-GCM encrypted file content; plaintext is never stored.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct UploadJournalResult {
    /// The fully-built journal entry ready for `journal.put`.
    pub entry: cipherbox_sdk::JournalEntry,
    /// AES-256-GCM encrypted file content.
    pub ciphertext: Vec<u8>,
    /// Decrypted plaintext — used to populate `pending_content` in the
    /// in-memory cache so reads after write return the correct bytes without a
    /// network round-trip.
    pub plaintext: Vec<u8>,
    /// The `FileMetadata` struct ready for the per-file IPNS publish.
    pub file_meta: cipherbox_core::folder::FileMetadata,
    /// Raw Ed25519 private key for the per-file IPNS record (if present).
    /// Zeroized on drop.
    pub file_ipns_private_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// IPNS name for the per-file metadata record (if present).
    pub file_meta_ipns_name: Option<String>,
    /// Folder key used to encrypt the per-file IPNS record (if present).
    pub folder_key_for_file_meta: Option<Vec<u8>>,
    /// ECIES-hex-encoded file key, as stored in the inode and journal.
    pub encrypted_file_key_hex: String,
    /// Hex-encoded AES-GCM IV.
    pub iv_hex: String,
    /// Plaintext size in bytes (after encryption).
    pub file_size: u64,
    /// Versioning history for the new file metadata entry.
    pub versions_for_meta: Option<Vec<cipherbox_core::folder::VersionEntry>>,
    /// Inode number of the parent folder.
    pub parent_ino: u64,
    /// CID of the previous version of this file (for unpin after upload).
    pub old_file_cid: Option<String>,
    /// CIDs of versions pruned by the versioning policy (to be unpinned).
    pub pruned_cids: Vec<String>,
    /// Write generation at the time the helper was called (before any inode
    /// mutation by the caller).
    pub write_gen: u64,
    /// Whether this is the first publish for the per-file IPNS record.
    /// Passed to `publish_file_metadata` so the sequence number starts at 0.
    pub is_first_publish: bool,
}

/// Result returned by [`CipherBoxFS::build_mkdir_journal_entry`].
///
/// Carries the built [`cipherbox_sdk::JournalEntry`] and every field the
/// caller's spawn block needs to upload the initial folder metadata and
/// publish the new child + parent IPNS records.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct MkdirJournalResult {
    /// The fully-built journal entry ready for `journal.put`.
    pub entry: cipherbox_sdk::JournalEntry,
    /// Encrypted initial folder metadata bytes ready for IPFS upload.
    pub json_bytes: Vec<u8>,
    /// Raw Ed25519 private key for the new child folder IPNS record.
    /// Zeroized on drop.
    pub ipns_private_key: zeroize::Zeroizing<Vec<u8>>,
    /// TEE-ECIES-wrapped child IPNS private key (for key rotation / TEE
    /// republishing).  `None` if no TEE public key is configured.
    pub encrypted_ipns_for_tee: Option<String>,
    /// Current TEE key epoch (forwarded verbatim from `CipherBoxFS`).
    pub tee_key_epoch: Option<u32>,
    /// IPNS name for the newly created child folder.
    pub ipns_name: String,
    /// Parent folder metadata snapshot (with the new child already appended)
    /// ready for the parent IPNS publish.
    pub parent_metadata: cipherbox_core::folder::FolderMetadata,
    /// Raw parent folder encryption key.
    pub parent_folder_key: Vec<u8>,
    /// Raw Ed25519 private key for the parent folder IPNS record.
    pub parent_ipns_key: Vec<u8>,
    /// IPNS name of the parent folder.
    pub parent_ipns_name: String,
    /// CID of the parent folder's previous metadata blob (for unpin on
    /// successful publish).
    pub parent_old_cid: Option<String>,
    /// Inode number assigned to the new child folder.
    pub ino: u64,
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl crate::CipherBoxFS {
    /// Build a [`JournalEntry`] for an upload (file write) without writing the
    /// entry to disk, mutating inodes, or spawning.
    ///
    /// Performs:
    /// 1. Read plaintext from the temp file handle.
    /// 2. AES-256-GCM encrypt + ECIES-wrap the file key.
    /// 3. Extract previous file metadata from the inode table.
    /// 4. Apply versioning policy.
    /// 5. Resolve `parent_folder_ipns_name` and ECIES-wrap the parent IPNS key.
    /// 6. ECIES-wrap the per-file IPNS key (if present).
    /// 7. Build and return a [`JournalOp::UploadFile`] entry.
    ///
    /// # Security
    ///
    /// Keys are wrapped exactly once.  The returned `UploadJournalResult`
    /// carries ciphertext only; the file key is cleared before return.
    pub fn build_upload_journal_entry(
        &self,
        ino: u64,
        handle: &crate::file_handle::OpenFileHandle,
        is_new_file: bool,
    ) -> Result<UploadJournalResult, String> {
        let plaintext = handle.read_all()?;

        let mut file_key = cipherbox_crypto::utils::generate_file_key();
        let iv = cipherbox_crypto::utils::generate_iv();

        let ciphertext = cipherbox_crypto::aes::encrypt_aes_gcm(&plaintext, &file_key, &iv)
            .map_err(|e| format!("File encryption failed: {}", e))?;

        let wrapped_key = cipherbox_crypto::ecies::wrap_key(&file_key, &self.public_key)
            .map_err(|e| format!("Key wrapping failed: {}", e))?;

        // Zeroize raw file key before any fallible path can return.
        cipherbox_crypto::utils::clear_bytes(&mut file_key);

        let (
            old_file_cid,
            old_encrypted_key,
            old_iv,
            old_size,
            old_mode,
            existing_versions,
            file_ipns_private_key,
            file_meta_ipns_name,
        ) = self
            .inodes
            .get(ino)
            .map(|inode| match &inode.kind {
                InodeKind::File {
                    cid,
                    encrypted_file_key,
                    iv,
                    size,
                    encryption_mode,
                    versions,
                    file_ipns_private_key,
                    file_meta_ipns_name,
                    ..
                } => (
                    if cid.is_empty() {
                        None
                    } else {
                        Some(cid.clone())
                    },
                    encrypted_file_key.clone(),
                    iv.clone(),
                    *size,
                    encryption_mode.clone(),
                    versions.clone(),
                    file_ipns_private_key.clone(),
                    file_meta_ipns_name.clone(),
                ),
                _ => (
                    None,
                    String::new(),
                    String::new(),
                    0,
                    "GCM".to_string(),
                    None,
                    None,
                    None,
                ),
            })
            .unwrap_or((
                None,
                String::new(),
                String::new(),
                0,
                "GCM".to_string(),
                None,
                None,
                None,
            ));

        let encrypted_file_key_hex = hex::encode(&wrapped_key);
        let iv_hex = hex::encode(&iv);
        let file_size = plaintext.len() as u64;

        let file_name = self
            .inodes
            .get(ino)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        let mime_type = crate::helpers::mime_from_extension(&file_name);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let (new_versions, pruned_cids) = crate::helpers::apply_versioning(
            existing_versions,
            &old_file_cid,
            &old_encrypted_key,
            &old_iv,
            old_size,
            &old_mode,
            now_ms,
            self.max_versions_per_file,
            self.version_cooldown_ms,
            ino,
        );

        let versions_for_meta = new_versions.as_ref().filter(|v| !v.is_empty()).cloned();

        let write_gen = self
            .inodes
            .get(ino)
            .map(|i| i.write_generation)
            .unwrap_or(0);

        let parent_ino = self
            .inodes
            .get(ino)
            .map(|i| i.parent_ino)
            .unwrap_or(ROOT_INO);

        let folder_key_for_file_meta = self.get_folder_key(parent_ino);

        // Resolve parent IPNS name for stable journal entry (D-02).
        let parent_folder_ipns_name = self
            .inodes
            .get(parent_ino)
            .and_then(|inode| match &inode.kind {
                InodeKind::Root { ipns_name, .. } => ipns_name.clone(),
                InodeKind::Folder { ipns_name, .. } => Some(ipns_name.clone()),
                _ => None,
            })
            .unwrap_or_else(|| self.root_ipns_name.clone());

        // CR-01: journal the user-ECIES-wrapped parent IPNS key so replay can
        // sign and publish the parent IPNS record at crash-recovery time.
        let parent_ipns_key_hex_for_journal = self
            .inodes
            .get(parent_ino)
            .and_then(|inode| match &inode.kind {
                InodeKind::Root {
                    ipns_private_key, ..
                } => ipns_private_key.as_deref(),
                InodeKind::Folder {
                    ipns_private_key, ..
                } => ipns_private_key.as_deref(),
                _ => None,
            })
            .and_then(|raw_key| {
                cipherbox_crypto::wrap_key(raw_key, &self.public_key)
                    .map(|w| hex::encode(&w))
                    .map_err(|e| {
                        log::warn!("Failed to wrap parent IPNS key for journal: {}", e);
                        e
                    })
                    .ok()
            })
            .unwrap_or_default();

        // Build journal entry referencing ciphertext only — no plaintext (D-05).
        use base64::Engine;
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
        let wrapped_key_hex = encrypted_file_key_hex.clone();

        // ECIES-wrap the per-file IPNS key exactly once (CR-01, no double-wrap).
        let file_ipns_key_hex = file_meta_ipns_name.as_ref().and_then(|_| {
            file_ipns_private_key
                .as_ref()
                .map(|k| {
                    cipherbox_crypto::ecies::wrap_key(k, &self.public_key)
                        .map(|w| hex::encode(&w))
                        .unwrap_or_else(|e| {
                            log::warn!("Failed to wrap file IPNS key for journal: {}", e);
                            String::new()
                        })
                })
                .or_else(|| {
                    self.inodes.get(ino).and_then(|i| match &i.kind {
                        InodeKind::File {
                            file_ipns_key_encrypted_hex,
                            ..
                        } => file_ipns_key_encrypted_hex.clone(),
                        _ => None,
                    })
                })
        });

        let entry = cipherbox_sdk::JournalEntry {
            id: hex::encode(cipherbox_crypto::utils::generate_random_bytes(16)),
            vault_root_ipns: self.root_ipns_name.clone(),
            op: cipherbox_sdk::JournalOp::UploadFile {
                ciphertext_b64,
                wrapped_key_hex,
                iv_hex: iv_hex.clone(),
                file_meta_ipns_name: file_meta_ipns_name.clone(),
                file_ipns_key_hex,
                parent_folder_ipns_name,
                parent_ipns_key_hex: parent_ipns_key_hex_for_journal,
                filename: file_name,
                size: file_size,
                created_at_ms: now_ms,
            },
            retries: 0,
            status: cipherbox_sdk::JournalEntryStatus::Pending,
        };

        let file_meta = cipherbox_core::folder::FileMetadata {
            version: "v1".to_string(),
            cid: String::new(),
            file_key_encrypted: encrypted_file_key_hex.clone(),
            file_iv: iv_hex.clone(),
            size: file_size,
            mime_type,
            encryption_mode: "GCM".to_string(),
            created_at: now_ms,
            modified_at: now_ms,
            versions: versions_for_meta.clone(),
        };

        Ok(UploadJournalResult {
            entry,
            ciphertext,
            plaintext,
            file_meta,
            file_ipns_private_key,
            file_meta_ipns_name,
            folder_key_for_file_meta,
            encrypted_file_key_hex,
            iv_hex,
            file_size,
            versions_for_meta,
            parent_ino,
            old_file_cid,
            pruned_cids,
            write_gen,
            is_first_publish: is_new_file,
        })
    }

    /// Build a [`JournalEntry`] for a directory creation (mkdir) without
    /// writing the entry to disk, mutating inodes, or spawning.
    ///
    /// The caller is expected to have already:
    /// - Allocated `ino` via `fs.inodes.allocate_ino()`
    /// - Inserted the new child inode
    /// - Updated the parent inode's children + timestamps
    ///
    /// Performs:
    /// 1. Generate the initial encrypted folder metadata bytes.
    /// 2. Optionally ECIES-wrap the child IPNS key for the TEE.
    /// 3. Build the parent folder metadata snapshot via `build_folder_metadata`.
    /// 4. ECIES-wrap parent + child IPNS private keys (user key).
    /// 5. Build and return a [`JournalOp::MkdirPublish`] entry.
    ///
    /// # Security
    ///
    /// Each key is wrapped exactly once.  The TEE-wrapped key is stored
    /// separately from the user-ECIES-wrapped key in the result struct.
    pub fn build_mkdir_journal_entry(
        &self,
        parent_ino: u64,
        child_ino: u64,
        name: &str,
        folder_key: &[u8],
        ipns_name: &str,
        ipns_private_key: zeroize::Zeroizing<Vec<u8>>,
        encrypted_folder_key_hex: &str,
    ) -> Result<MkdirJournalResult, String> {
        let metadata = cipherbox_core::folder::FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        };

        let json_bytes = crate::encrypt_metadata_to_json(&metadata, folder_key)?;

        // TEE-wrap the child IPNS private key for republishing (if TEE configured).
        let encrypted_ipns_for_tee = if let Some(ref tee_key) = self.tee_public_key {
            let wrapped = cipherbox_crypto::wrap_key(&ipns_private_key, tee_key)
                .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
            Some(hex::encode(&wrapped))
        } else {
            None
        };
        let tee_key_epoch = self.tee_key_epoch;

        let (parent_metadata, parent_folder_key, parent_ipns_key, parent_ipns_name, parent_old_cid) =
            self.build_folder_metadata(parent_ino)?;

        let mkdir_created_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // CR-01: journal the user-ECIES-wrapped parent IPNS key for replay signing.
        let parent_ipns_key_hex_for_journal =
            cipherbox_crypto::wrap_key(&parent_ipns_key, &self.public_key)
                .map(|w| hex::encode(&w))
                .unwrap_or_else(|e| {
                    // An empty string parks the entry on replay rather than
                    // persisting a degraded key silently.
                    log::warn!("Failed to wrap parent IPNS key for journal: {}", e);
                    String::new()
                });

        // CR-03: journal the user-ECIES-wrapped child IPNS key (not TEE-wrapped).
        let child_ipns_key_hex_user_wrapped =
            cipherbox_crypto::wrap_key(&ipns_private_key, &self.public_key)
                .map(|w| hex::encode(&w))
                .unwrap_or_else(|e| {
                    // CR-03: never fall back to the TEE-wrapped key here — replay
                    // writes this into FolderEntry.ipns_private_key_encrypted which
                    // must be user-ECIES-wrapped.  An empty string makes replay park
                    // the entry rather than brick the folder with an unusable key.
                    log::warn!("Failed to wrap child IPNS key for journal: {}", e);
                    String::new()
                });

        let entry = cipherbox_sdk::JournalEntry {
            id: hex::encode(cipherbox_crypto::utils::generate_random_bytes(16)),
            vault_root_ipns: self.root_ipns_name.clone(),
            op: cipherbox_sdk::JournalOp::MkdirPublish {
                child_ipns_name: ipns_name.to_string(),
                child_folder_key_hex: encrypted_folder_key_hex.to_string(),
                child_ipns_key_hex: child_ipns_key_hex_user_wrapped,
                parent_folder_ipns_name: parent_ipns_name.clone(),
                parent_ipns_key_hex: parent_ipns_key_hex_for_journal,
                name: name.to_string(),
                created_at_ms: mkdir_created_at_ms,
            },
            retries: 0,
            status: cipherbox_sdk::JournalEntryStatus::Pending,
        };

        Ok(MkdirJournalResult {
            entry,
            json_bytes,
            ipns_private_key,
            encrypted_ipns_for_tee,
            tee_key_epoch,
            ipns_name: ipns_name.to_string(),
            parent_metadata,
            parent_folder_key,
            parent_ipns_key,
            parent_ipns_name,
            parent_old_cid,
            ino: child_ino,
        })
    }
}

#[cfg(test)]
mod tests {
    // Unit tests for journal_helpers live in crates/fuse/src/lib.rs (alongside
    // the existing characterization tests) and in crates/sdk/src/queue.rs
    // (journal round-trip tests).  This module intentionally has no runtime
    // network dependencies so there are no tests that require a live
    // CipherBoxFS instance here.
}
