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
//! - The built `JournalEntry` references `ciphertext` only — plaintext is
//!   never written to the journal or to disk.  `UploadJournalResult` carries
//!   the plaintext transiently in memory (for the `pending_content`
//!   read-after-write cache); it is never persisted.
//! - Each key is ECIES-wrapped exactly once.  The caller must not re-wrap.
//! - `is_first_publish` is threaded through to the caller so the per-file
//!   IPNS sequence number is computed correctly (§Pitfall 4 in 45-RESEARCH.md).

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::inode::{InodeKind, ROOT_INO};

/// Result returned by [`CipherBoxFS::build_upload_journal_entry`].
///
/// Carries the built [`cipherbox_sdk::JournalEntry`] and every field the
/// caller's inode-mutation and spawn block needs.  The `ciphertext` field
/// holds the AES-256-GCM encrypted file content; the `plaintext` field is
/// transient in-memory data for the read-after-write cache and is never
/// written to the journal or disk.
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
    /// Zeroized on drop (S3/D-05).
    pub folder_key_for_file_meta: Option<zeroize::Zeroizing<Vec<u8>>>,
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
        // D-01 (WR-06): reject oversized files BEFORE reading the temp file into memory so the
        // release path replies EIO instead of allocating a multi-GB buffer and stalling the
        // shared FS thread. The size is read from the temp file's on-disk metadata — checking
        // after `read_all()` would defeat the guard (the allocation already happened).
        let size_on_disk = handle.get_size()?;
        if size_on_disk > cipherbox_sdk::MAX_JOURNAL_PAYLOAD_BYTES {
            return Err(format!(
                "File too large for journal ({} bytes > {} byte cap); refusing to write",
                size_on_disk,
                cipherbox_sdk::MAX_JOURNAL_PAYLOAD_BYTES
            ));
        }

        let plaintext = handle.read_all()?;
        let file_size = plaintext.len() as u64;

        let mut file_key = cipherbox_crypto::utils::generate_file_key();
        let iv = cipherbox_crypto::utils::generate_iv();

        // Zeroize the raw file key on every fallible path — `generate_file_key`
        // returns a plain `[u8; 32]` with no zeroize-on-drop, so an early `?`
        // return here would otherwise leave the key in memory.
        let ciphertext = match cipherbox_crypto::aes::encrypt_aes_gcm(&plaintext, &file_key, &iv) {
            Ok(ct) => ct,
            Err(e) => {
                cipherbox_crypto::utils::clear_bytes(&mut file_key);
                return Err(format!("File encryption failed: {}", e));
            }
        };

        let wrapped_key = match cipherbox_crypto::ecies::wrap_key(&file_key, &self.public_key) {
            Ok(wk) => wk,
            Err(e) => {
                cipherbox_crypto::utils::clear_bytes(&mut file_key);
                return Err(format!("Key wrapping failed: {}", e));
            }
        };

        // Zeroize raw file key on the success path.
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

        let file_name = self
            .inodes
            .get(ino)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        let mime_type = crate::helpers::mime_from_extension(&file_name);

        let now_ms = current_unix_ms();

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

        let (write_gen, parent_ino) = self
            .inodes
            .get(ino)
            .map(|i| (i.write_generation, i.parent_ino))
            .unwrap_or((0, ROOT_INO));

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
            .map(|raw_key| wrap_key_to_hex(raw_key, &self.public_key, "parent IPNS key"))
            .unwrap_or_default();

        // D-01: ciphertext goes to a sidecar `<id>.bin`, not into the JSON. Compute the
        // sidecar path + SHA-256 now so the entry references exactly what put_with_sidecar
        // will write; the in-memory `ciphertext` is still returned for the live upload thread.
        let entry_id = generate_entry_id();
        let sidecar_path = self.journal.sidecar_path_for(&entry_id);
        let sidecar_sha256 = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&ciphertext);
            hex::encode(hasher.finalize())
        };

        // D-04 (IN-03): ECIES-encrypt the filename at rest — no plaintext name persists.
        // Unlike key wrapping (where an empty-string fallback is acceptable), a failed
        // filename encryption must fail the write so we never silently lose the name.
        let filename_encrypted_hex = hex::encode(
            cipherbox_crypto::ecies::wrap_key(file_name.as_bytes(), &self.public_key)
                .map_err(|e| format!("filename encryption failed: {}", e))?,
        );

        // ECIES-wrap the per-file IPNS key exactly once (CR-01, no double-wrap).
        // Only journalled when there's an IPNS name to publish.
        let file_ipns_key_hex = if file_meta_ipns_name.is_none() {
            None
        } else {
            file_ipns_private_key
                .as_ref()
                .map(|k| wrap_key_to_hex(k, &self.public_key, "file IPNS key"))
                .or_else(|| {
                    self.inodes.get(ino).and_then(|i| match &i.kind {
                        InodeKind::File {
                            file_ipns_key_encrypted_hex,
                            ..
                        } => file_ipns_key_encrypted_hex.clone(),
                        _ => None,
                    })
                })
        };

        let entry = cipherbox_sdk::JournalEntry {
            id: entry_id,
            vault_root_ipns: self.root_ipns_name.clone(),
            op: cipherbox_sdk::JournalOp::UploadFile {
                sidecar_path,
                sidecar_sha256,
                // Compat-only field; new entries always use the sidecar, never inline ciphertext.
                legacy_ciphertext_b64: String::new(),
                wrapped_key_hex: encrypted_file_key_hex.clone(),
                iv_hex: iv_hex.clone(),
                file_meta_ipns_name: file_meta_ipns_name.clone(),
                file_ipns_key_hex,
                parent_folder_ipns_name,
                parent_ipns_key_hex: parent_ipns_key_hex_for_journal,
                filename_encrypted_hex,
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

        let mkdir_created_at_ms = current_unix_ms();

        // CR-01: journal the user-ECIES-wrapped parent IPNS key for replay signing.
        // An empty string (on wrap failure) parks the entry on replay rather than
        // persisting a degraded key silently.
        let parent_ipns_key_hex_for_journal =
            wrap_key_to_hex(&parent_ipns_key, &self.public_key, "parent IPNS key");

        // CR-03: journal the user-ECIES-wrapped child IPNS key (NOT TEE-wrapped) —
        // replay writes this into FolderEntry.ipns_private_key_encrypted, which must
        // be user-ECIES-wrapped.  An empty string parks the entry rather than
        // bricking the folder with an unusable key.
        let child_ipns_key_hex_user_wrapped =
            wrap_key_to_hex(&ipns_private_key, &self.public_key, "child IPNS key");

        // D-04 (IN-03): ECIES-encrypt the directory name at rest. A failed encryption
        // fails the write rather than persisting a plaintext or empty name.
        let name_encrypted_hex = hex::encode(
            cipherbox_crypto::ecies::wrap_key(name.as_bytes(), &self.public_key)
                .map_err(|e| format!("directory name encryption failed: {}", e))?,
        );

        let entry = cipherbox_sdk::JournalEntry {
            id: generate_entry_id(),
            vault_root_ipns: self.root_ipns_name.clone(),
            op: cipherbox_sdk::JournalOp::MkdirPublish {
                child_ipns_name: ipns_name.to_string(),
                child_folder_key_hex: encrypted_folder_key_hex.to_string(),
                child_ipns_key_hex: child_ipns_key_hex_user_wrapped,
                parent_folder_ipns_name: parent_ipns_name.clone(),
                parent_ipns_key_hex: parent_ipns_key_hex_for_journal,
                name_encrypted_hex,
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

/// Current Unix time in milliseconds (saturating to 0 if the clock predates the epoch).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Generate a fresh journal-entry id: hex-encoded 16 random bytes.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn generate_entry_id() -> String {
    hex::encode(cipherbox_crypto::utils::generate_random_bytes(16))
}

/// ECIES-wrap `raw_key` for `public_key` and hex-encode it for journalling.
///
/// On wrap failure, logs a warning and returns an empty string — an empty key
/// field makes replay park the entry rather than persist a degraded key
/// (CR-01 / CR-03).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn wrap_key_to_hex(raw_key: &[u8], public_key: &[u8], label: &str) -> String {
    cipherbox_crypto::wrap_key(raw_key, public_key)
        .map(|w| hex::encode(&w))
        .unwrap_or_else(|e| {
            log::warn!("Failed to wrap {} for journal: {}", label, e);
            String::new()
        })
}

// REQ-6: builder round-trip tests. Gated on `feature = "fuse"` because they use
// the `crate::test_support` harness (itself fuse-feature-gated) and a real EC
// keypair so `wrap_key` ECIES-wraps key material (Threat T-46-02). Network-free.
#[cfg(all(test, feature = "fuse"))]
mod tests {
    use crate::test_support::{make_isolated_journal_dir, make_test_fs_with_keypair};
    use zeroize::Zeroizing;

    /// Generate a real secp256k1 keypair (33-byte compressed pubkey, 32-byte
    /// secret) via the `ecies` dev-dep. A zero vec is NOT a valid curve point.
    fn real_keypair() -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (
            Zeroizing::new(sk.serialize().to_vec()),
            Zeroizing::new(pk.serialize().to_vec()),
        )
    }

    #[tokio::test]
    async fn build_upload_journal_entry_round_trips() {
        let (private_key, public_key) = real_keypair();
        let fs = make_test_fs_with_keypair(private_key, public_key);

        // A fresh write handle backed by a temp file with real content.
        // Isolated per-test dir keyed by process id + counter so parallel test
        // binaries never collide on a shared path (T-46-04).
        let temp_dir = make_isolated_journal_dir();
        let ino = 4242u64; // not present in inodes → treated as a brand-new file
        let mut handle =
            crate::file_handle::OpenFileHandle::new_write(ino, &temp_dir, None).unwrap();
        let plaintext = b"hello cipherbox upload round trip";
        handle.write_at(0, plaintext).unwrap();

        let result = fs
            .build_upload_journal_entry(ino, &handle, /* is_new_file */ true)
            .expect("upload builder must succeed with a real keypair");

        match &result.entry.op {
            cipherbox_sdk::JournalOp::UploadFile {
                sidecar_path,
                sidecar_sha256,
                wrapped_key_hex,
                filename_encrypted_hex,
                ..
            } => {
                // D-01: ciphertext lives in a sidecar, not in the JSON entry.
                assert!(
                    sidecar_path.to_string_lossy().ends_with(".bin"),
                    "sidecar_path must point at a .bin file, got {:?}",
                    sidecar_path
                );
                // The in-memory ciphertext is carried transiently for the live upload.
                assert!(
                    !result.ciphertext.is_empty(),
                    "in-memory ciphertext must be non-empty"
                );
                assert_ne!(
                    result.ciphertext.as_slice(),
                    plaintext.as_slice(),
                    "journalled bytes must be ciphertext, never plaintext (T-46-01)"
                );
                // sidecar_sha256 must be the SHA-256 of the in-memory ciphertext.
                let expected = {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(&result.ciphertext);
                    hex::encode(h.finalize())
                };
                assert_eq!(
                    sidecar_sha256, &expected,
                    "sidecar_sha256 must match SHA-256 of the ciphertext"
                );
                // D-04: the filename is ECIES-encrypted hex, never the plaintext name.
                assert!(
                    !filename_encrypted_hex.is_empty()
                        && hex::decode(filename_encrypted_hex).is_ok(),
                    "filename_encrypted_hex must be valid ECIES hex (T-52-09 / IN-03)"
                );
                // The file key is ECIES-wrapped (present, hex-encoded), never raw.
                assert!(
                    !wrapped_key_hex.is_empty(),
                    "wrapped_key_hex must be present and ECIES-wrapped (T-46-02)"
                );
                assert!(
                    hex::decode(wrapped_key_hex).is_ok(),
                    "wrapped_key_hex must be valid hex"
                );
            }
            other => panic!("expected UploadFile op, got {:?}", other),
        }

        // Plaintext is carried transiently in memory only, never in the entry.
        assert_eq!(result.plaintext, plaintext);
    }

    #[tokio::test]
    async fn build_mkdir_journal_entry_round_trips() {
        let (private_key, public_key) = real_keypair();
        let fs = make_test_fs_with_keypair(private_key, public_key);

        let parent_ino = crate::inode::ROOT_INO;
        let child_ino = 9001u64;
        let child_ipns_private_key = Zeroizing::new(vec![3u8; 32]);

        let result = fs
            .build_mkdir_journal_entry(
                parent_ino,
                child_ino,
                "newdir",
                &[5u8; 32],        // folder_key
                "k51child-newdir", // child ipns name
                child_ipns_private_key,
                "deadbeef", // encrypted_folder_key_hex
            )
            .expect("mkdir builder must succeed against the root parent");

        assert_eq!(result.ino, child_ino, "result must reference the new child");
        match &result.entry.op {
            cipherbox_sdk::JournalOp::MkdirPublish {
                child_ipns_name,
                name_encrypted_hex,
                child_ipns_key_hex,
                parent_ipns_key_hex,
                ..
            } => {
                assert_eq!(child_ipns_name, "k51child-newdir");
                // D-04: directory name is ECIES-encrypted hex, never the plaintext "newdir".
                assert!(
                    !name_encrypted_hex.is_empty() && hex::decode(name_encrypted_hex).is_ok(),
                    "name_encrypted_hex must be valid ECIES hex (IN-03)"
                );
                assert_ne!(
                    name_encrypted_hex, "newdir",
                    "directory name must not be persisted as plaintext"
                );
                // Both IPNS keys are ECIES-wrapped (non-empty hex), never raw.
                assert!(
                    !child_ipns_key_hex.is_empty() && hex::decode(child_ipns_key_hex).is_ok(),
                    "child IPNS key must be ECIES-wrapped hex (T-46-02)"
                );
                assert!(
                    !parent_ipns_key_hex.is_empty() && hex::decode(parent_ipns_key_hex).is_ok(),
                    "parent IPNS key must be ECIES-wrapped hex (T-46-02)"
                );
            }
            other => panic!("expected MkdirPublish op, got {:?}", other),
        }
    }

    /// D-01 (WR-06): a file larger than `MAX_JOURNAL_PAYLOAD_BYTES` must cause
    /// `build_upload_journal_entry` to return `Err` (so the release path replies EIO)
    /// rather than encrypting + streaming a multi-GB sidecar and stalling the FS thread.
    ///
    /// This drives the *real* helper against an oversized handle so the guard's
    /// ordering (it must run BEFORE `read_all()`) is actually covered: a regression
    /// that moved the check after the read, or removed it, would fail here. We avoid
    /// allocating real bytes by `set_len`-ing the temp file to a sparse logical size
    /// past the cap — `get_size()` reads `fs::metadata().len()`, so the guard fires
    /// on the logical length without any multi-GB allocation. The at/under-cap path
    /// is covered by `build_upload_journal_entry_round_trips` (a small file succeeds).
    ///
    /// Async only because `make_test_fs_with_keypair` captures `Handle::current()`; the
    /// helper under test is synchronous and the guard runs before any `.await`.
    #[tokio::test]
    async fn payload_size_cap_returns_err() {
        let (private_key, public_key) = real_keypair();
        let fs = make_test_fs_with_keypair(private_key, public_key);

        // A fresh write handle backed by a temp file. ino is deliberately absent
        // from the inode table so the helper treats it as a brand-new file.
        let temp_dir = make_isolated_journal_dir();
        let ino = 9999u64;
        let handle =
            crate::file_handle::OpenFileHandle::new_write(ino, &temp_dir, None).unwrap();

        // Make the temp file sparse and one byte past the cap. No real allocation:
        // set_len produces a logical size that get_size() reports verbatim.
        handle
            .truncate(cipherbox_sdk::MAX_JOURNAL_PAYLOAD_BYTES + 1)
            .expect("truncate to oversize must succeed (sparse file)");

        // The real helper must reject before reading the file into memory.
        // `UploadJournalResult` does not derive Debug, so match instead of `expect_err`.
        let err = match fs.build_upload_journal_entry(ino, &handle, /* is_new_file */ true) {
            Ok(_) => panic!("over-cap file must be rejected by the real helper"),
            Err(e) => e,
        };
        assert!(
            err.contains("too large for journal"),
            "error must explain the cap rejection, got: {}",
            err
        );
    }
}
