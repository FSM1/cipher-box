//! Shared journal-entry builders for the CipherBox FUSE filesystem.
//!
//! This module provides `build_upload_journal_entry` and
//! `build_mkdir_journal_entry` as inherent methods on [`CipherBoxFS`], so both
//! the fuser (macOS/Linux) and WinFsp (Windows) write paths share a single
//! implementation of the encrypt → seal-node → build-`JournalEntry` steps.
//!
//! Each platform keeps its own reply/return machinery, in-memory inode
//! mutations, and background spawn — only the entry-build steps live here.
//!
//! ## node/v3 write emission (69-09 Slice 3)
//!
//! The write path emits a fresh sealed `PublishedNode` for the child
//! (`emit.rs`/`seal_published_node`) and the D-07 dual read/write splices for
//! the parent (`cipherbox_sdk::build_child_refs`): a read-plane
//! [`SealedChildRef`] keyed by ipnsName and a write-plane [`WriteChildRef`]
//! keyed by `child_id = uuid_from_ino(child_ino)`. The child node is sealed
//! with the SAME `uuid_from_ino` id, so a reader recovering `child_id` from the
//! resolved node round-trips the AAD. Node-to-node keys live ONLY inside the
//! symmetric seals — the former per-key ECIES-under-user-key hops are gone.
//!
//! ## Security invariants
//!
//! - The built `JournalEntry` references `ciphertext` only via a sidecar —
//!   plaintext is never written to the journal or to disk. `UploadJournalResult`
//!   carries the plaintext transiently in memory (read-after-write cache).
//! - Keys are minted/derived once; caller-owned buffers are never zeroed here
//!   (D-09 terminal-owner discipline — the freshly minted keys are moved out).
//! - The ONLY retained ECIES is the TEE-pubkey wrap of the child ipnsPrivateKey
//!   (CLAUDE.md rule #7) — never a node-to-node key hop.

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::inode::{InodeKind, ROOT_INO};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use base64::Engine as _;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use cipherbox_core::node::{
    encode_published_node, seal::seal_published_node, Node, NodeContent, NodeKind, NodeWriteBody,
};

/// Result returned by [`CipherBoxFS::build_upload_journal_entry`].
///
/// Carries the built [`cipherbox_sdk::JournalEntry`] plus the node/v3 file
/// identity + content the caller's live publish (`publish_file_metadata`) needs
/// to seal + publish the file node once the content CID is known. The
/// `ciphertext`/`plaintext` fields are transient in-memory data (read-after-write
/// cache); they are never written to the journal or disk.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct UploadJournalResult {
    /// The fully-built journal entry ready for `journal.put`.
    pub entry: cipherbox_sdk::JournalEntry,
    /// AES-256-GCM encrypted file content (transient — for the live upload).
    pub ciphertext: Vec<u8>,
    /// Decrypted plaintext — used to populate `pending_content` so reads after
    /// write return the correct bytes without a network round-trip.
    pub plaintext: Vec<u8>,
    /// The file node's own symmetric readKey (node/v3). Terminal-owned here.
    pub file_read_key: zeroize::Zeroizing<[u8; 32]>,
    /// The file node's own symmetric writeKey (node/v3).
    pub file_write_key: zeroize::Zeroizing<[u8; 32]>,
    /// The file node's Ed25519 signing seed (per-file IPNS record).
    pub file_ipns_private_key: zeroize::Zeroizing<Vec<u8>>,
    /// The file node's per-file IPNS name (stable across overwrites, D-02).
    pub file_ipns_name: String,
    /// Raw 32-byte AES content key — sealed inside `NodeContent.file_key`
    /// (NOT ECIES-wrapped; node/v3 stores it raw inside the sealed read-body).
    pub file_key: zeroize::Zeroizing<Vec<u8>>,
    /// Hex-encoded AES-GCM IV (NodeContent.file_iv is HEX — content_ops decodes
    /// it via `hex::decode`).
    pub iv_hex: String,
    /// MIME type derived from the file name.
    pub mime_type: String,
    /// Encryption mode ("GCM").
    pub encryption_mode: String,
    /// TEE-ECIES-wrapped file ipnsPrivateKey (rule #7), or `None` if no TEE key.
    pub encrypted_ipns_for_tee: Option<String>,
    /// Current TEE key epoch (forwarded verbatim from `CipherBoxFS`).
    pub tee_key_epoch: Option<u32>,
    /// Plaintext size in bytes.
    pub file_size: u64,
    /// Inode number of the parent folder.
    pub parent_ino: u64,
    /// CID of the previous version of this file (for unpin after upload).
    pub old_file_cid: Option<String>,
    /// CIDs of versions pruned by the versioning policy (to be unpinned).
    pub pruned_cids: Vec<String>,
    /// Write generation at the time the helper was called.
    pub write_gen: u64,
    /// Whether this is the first publish for the per-file IPNS record.
    pub is_first_publish: bool,
}

/// Result returned by [`CipherBoxFS::build_mkdir_journal_entry`].
///
/// Carries the built [`cipherbox_sdk::JournalEntry`] plus the freshly sealed
/// child `PublishedNode` bytes and the re-sealed parent `PublishedNode` bytes
/// (with the new child spliced into BOTH planes), ready for the caller's
/// background upload + IPNS publish.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct MkdirJournalResult {
    /// The fully-built journal entry ready for `journal.put`.
    pub entry: cipherbox_sdk::JournalEntry,
    /// Encoded sealed child folder `PublishedNode` bytes ready for IPFS upload.
    pub child_published_node: Vec<u8>,
    /// Raw Ed25519 signing seed for the new child folder IPNS record.
    pub child_ipns_private_key: zeroize::Zeroizing<Vec<u8>>,
    /// TEE-ECIES-wrapped child IPNS private key (rule #7). `None` if no TEE key.
    pub encrypted_ipns_for_tee: Option<String>,
    /// Current TEE key epoch (forwarded verbatim from `CipherBoxFS`).
    pub tee_key_epoch: Option<u32>,
    /// IPNS name for the newly created child folder.
    pub child_ipns_name: String,
    /// Re-sealed parent `PublishedNode` bytes (child spliced) for the parent
    /// IPNS publish.
    pub parent_published_node: Vec<u8>,
    /// Raw Ed25519 signing seed for the parent folder IPNS record.
    pub parent_ipns_private_key: Vec<u8>,
    /// IPNS name of the parent folder.
    pub parent_ipns_name: String,
    /// CID of the parent folder's previous metadata blob (for unpin on publish).
    pub parent_old_cid: Option<String>,
    /// Inode number assigned to the new child folder.
    pub ino: u64,
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl crate::CipherBoxFS {
    /// Extract a parent folder/root node's symmetric keys + identity from the
    /// inode table (node/v3). Returns `(read_key, write_key, ipns_private_key,
    /// ipns_name)`.
    fn parent_node_keys(
        &self,
        parent_ino: u64,
    ) -> Result<([u8; 32], [u8; 32], Vec<u8>, String), String> {
        let inode = self
            .inodes
            .get(parent_ino)
            .ok_or_else(|| format!("Parent inode {} not found", parent_ino))?;
        match &inode.kind {
            InodeKind::Root {
                read_key,
                write_key,
                ipns_private_key,
                ipns_name,
            } => Ok((
                **read_key,
                **write_key,
                ipns_private_key.to_vec(),
                if ipns_name.is_empty() {
                    self.root_ipns_name.clone()
                } else {
                    ipns_name.clone()
                },
            )),
            InodeKind::Folder {
                read_key,
                write_key,
                ipns_private_key,
                ipns_name,
                ..
            } => Ok((
                **read_key,
                **write_key,
                ipns_private_key.to_vec(),
                ipns_name.clone(),
            )),
            _ => Err(format!("Parent inode {} is not a folder", parent_ino)),
        }
    }

    /// Build a [`JournalEntry`] for an upload (file write) without writing the
    /// entry to disk, mutating inodes, or spawning.
    ///
    /// node/v3: seals a fresh file `PublishedNode` (content CID filled at
    /// publish time by the live path / replay) + the D-07 dual parent splices,
    /// and constructs the reshaped [`cipherbox_sdk::JournalOp::UploadFile`].
    ///
    /// # Security
    ///
    /// The raw AES content key is moved into `NodeContent.file_key` (sealed
    /// inside the node's read-body) and returned to the caller for the live
    /// re-seal — it is never ECIES-wrapped and never journaled in the clear.
    pub fn build_upload_journal_entry(
        &self,
        ino: u64,
        handle: &crate::file_handle::OpenFileHandle,
        is_new_file: bool,
    ) -> Result<UploadJournalResult, String> {
        // D-01 (WR-06): reject oversized files BEFORE reading the temp file into
        // memory so the release path replies EIO instead of allocating a
        // multi-GB buffer and stalling the shared FS thread.
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

        // Zeroize the raw file key on every fallible path.
        let ciphertext = match cipherbox_crypto::aes::encrypt_aes_gcm(&plaintext, &file_key, &iv) {
            Ok(ct) => ct,
            Err(e) => {
                cipherbox_crypto::utils::clear_bytes(&mut file_key);
                return Err(format!("File encryption failed: {}", e));
            }
        };

        let iv_hex = hex::encode(iv);

        // node/v3: recover the file node's own identity (read/write keys, signing
        // seed, ipns name) from the inode. handle_create minted these for a fresh
        // file; populate_folder filled them for an existing (overwrite) file.
        let (
            file_read_key,
            file_write_key,
            file_ipns_private_key,
            file_ipns_name,
            old_file_cid,
            existing_mode,
        ) = self
            .inodes
            .get(ino)
            .and_then(|inode| match &inode.kind {
                InodeKind::File {
                    ipns_name,
                    cid,
                    encryption_mode,
                    read_key,
                    write_key,
                    ipns_private_key,
                    ..
                } => Some((
                    read_key.clone(),
                    write_key.clone(),
                    ipns_private_key.clone(),
                    ipns_name.clone(),
                    if cid.is_empty() {
                        None
                    } else {
                        Some(cid.clone())
                    },
                    encryption_mode.clone(),
                )),
                _ => None,
            })
            .ok_or_else(|| {
                cipherbox_crypto::utils::clear_bytes(&mut file_key);
                format!("Upload target inode {} is not a node/v3 file", ino)
            })?;

        let encryption_mode = if existing_mode.is_empty() {
            "GCM".to_string()
        } else {
            existing_mode
        };

        let (write_gen, parent_ino) = self
            .inodes
            .get(ino)
            .map(|i| (i.write_generation, i.parent_ino))
            .unwrap_or((0, ROOT_INO));

        let file_name = self
            .inodes
            .get(ino)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        let mime_type = crate::helpers::mime_from_extension(&file_name);

        let now_ms = current_unix_ms();

        // Build the file NodeContent. The content CID is filled at publish time
        // (live path / replay re-upload) — the journal-time seal uses an empty
        // CID placeholder. `file_iv` is HEX (content_ops decodes via hex::decode);
        // `file_key` is the RAW 32-byte AES key (sealed inside the read-body).
        // Versioning history is not reconstructed here (InodeKind dropped
        // `versions` in Slice 1 — see the file-versioning E2E flag).
        let node_content = NodeContent {
            cid: String::new(),
            file_iv: iv_hex.clone(),
            size: file_size,
            mime_type: mime_type.clone(),
            encryption_mode: encryption_mode.clone(),
            file_key: file_key.to_vec(),
            versions: Vec::new(),
        };

        // Raw file key is now owned by NodeContent + the returned result; clear
        // the stack copy.
        cipherbox_crypto::utils::clear_bytes(&mut file_key);

        // D-07: the file node's stable id is the inode's STORED node_id (its real
        // published.id), NOT uuid_from_ino(ino). A file materialized from a remote
        // listing then written keeps its creator's id; both the file-node seal and
        // the parent D-07 splices below must use it so replay re-publishes an
        // envelope whose id still pairs with the parent's WriteChildRef.child_id.
        let child_id = self
            .inodes
            .get(ino)
            .map(|i| i.node_id.clone())
            .unwrap_or_else(|| crate::fs::uuid_from_ino(ino));
        let file_node = Node::File {
            id: child_id.clone(),
            generation: 0,
            created_at: now_ms,
            modified_at: now_ms,
            content: node_content.clone(),
        };
        let write_body = NodeWriteBody {
            ipns_private_key: file_ipns_private_key.to_vec(),
            write_children: Vec::new(),
        };
        let published = seal_published_node(
            &file_node,
            &file_read_key,
            &file_write_key,
            Some(&write_body),
        )
        .map_err(|e| format!("File node seal failed: {}", e))?;
        let child_published_node = encode_published_node(&published)
            .map_err(|e| format!("File node encode failed: {}", e))?;
        let child_published_node_b64 =
            base64::engine::general_purpose::STANDARD.encode(&child_published_node);

        // D-01: ciphertext goes to a sidecar `<id>.bin`, not into the JSON.
        let entry_id = generate_entry_id();
        let sidecar_path = self.journal.sidecar_path_for(&entry_id);
        let sidecar_sha256 = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&ciphertext);
            hex::encode(hasher.finalize())
        };

        // Parent read/write keys for the D-07 dual splice.
        let (parent_read_key, parent_write_key, _parent_ipns_key, parent_folder_ipns_name) =
            self.parent_node_keys(parent_ino)?;

        let (parent_child_ref, parent_write_child_ref) = cipherbox_sdk::build_child_refs(
            &file_read_key,
            &file_write_key,
            &parent_read_key,
            &parent_write_key,
            &child_id,
            &file_ipns_name,
            &file_name,
            NodeKind::File,
            0,
            0,
        )
        .map_err(|e| format!("build_child_refs (file) failed: {}", e))?;

        // TEE-wrap the file ipnsPrivateKey for republishing (rule #7).
        let (encrypted_ipns_for_tee, tee_key_epoch) = match &self.tee_public_key {
            Some(tee_key) => {
                let wrapped = cipherbox_crypto::wrap_key(&file_ipns_private_key, tee_key)
                    .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
                (Some(hex::encode(&wrapped)), self.tee_key_epoch)
            }
            None => (None, None),
        };

        let entry = cipherbox_sdk::JournalEntry {
            id: entry_id,
            vault_root_ipns: self.root_ipns_name.clone(),
            op: cipherbox_sdk::JournalOp::UploadFile {
                sidecar_path,
                sidecar_sha256,
                legacy_ciphertext_b64: String::new(),
                child_published_node: child_published_node_b64,
                parent_child_ref,
                parent_write_child_ref,
                file_meta_ipns_name: Some(file_ipns_name.clone()),
                parent_folder_ipns_name,
                size: file_size,
                created_at_ms: now_ms,
            },
            retries: 0,
            status: cipherbox_sdk::JournalEntryStatus::Pending,
        };

        Ok(UploadJournalResult {
            entry,
            ciphertext,
            plaintext,
            file_read_key,
            file_write_key,
            file_ipns_private_key,
            file_ipns_name,
            file_key: zeroize::Zeroizing::new(node_content.file_key),
            iv_hex,
            mime_type,
            encryption_mode,
            encrypted_ipns_for_tee,
            tee_key_epoch,
            file_size,
            parent_ino,
            old_file_cid,
            pruned_cids: Vec::new(),
            write_gen,
            is_first_publish: is_new_file,
        })
    }

    /// Build a [`JournalEntry`] for a directory creation (mkdir) without
    /// writing the entry to disk, mutating inodes, or spawning.
    ///
    /// node/v3: seals a fresh child folder `PublishedNode`, re-seals the parent
    /// with the child spliced into BOTH planes (via `build_folder_metadata`),
    /// and constructs the reshaped [`cipherbox_sdk::JournalOp::MkdirPublish`].
    ///
    /// The caller is expected to have already allocated `child_ino`, inserted
    /// the new child inode (with these read/write keys + ipns identity), and
    /// updated the parent's children list, so `build_folder_metadata` sees it.
    pub fn build_mkdir_journal_entry(
        &self,
        parent_ino: u64,
        child_ino: u64,
        name: &str,
        child_read_key: &[u8; 32],
        child_write_key: &[u8; 32],
        child_ipns_name: &str,
        child_ipns_private_key: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<MkdirJournalResult, String> {
        let child_id = crate::fs::uuid_from_ino(child_ino);
        let now_ms = current_unix_ms();

        // Seal the fresh (empty) child folder node under its OWN read/write keys.
        let child_node = Node::Folder {
            id: child_id.clone(),
            generation: 0,
            created_at: now_ms,
            modified_at: now_ms,
            children: Vec::new(),
        };
        let child_write_body = NodeWriteBody {
            ipns_private_key: child_ipns_private_key.to_vec(),
            write_children: Vec::new(),
        };
        let child_published = seal_published_node(
            &child_node,
            child_read_key,
            child_write_key,
            Some(&child_write_body),
        )
        .map_err(|e| format!("Child folder seal failed: {}", e))?;
        let child_published_node = encode_published_node(&child_published)
            .map_err(|e| format!("Child folder encode failed: {}", e))?;
        let child_published_node_b64 =
            base64::engine::general_purpose::STANDARD.encode(&child_published_node);

        // TEE-wrap the child IPNS private key for republishing (rule #7).
        let (encrypted_ipns_for_tee, tee_key_epoch) = match &self.tee_public_key {
            Some(tee_key) => {
                let wrapped = cipherbox_crypto::wrap_key(&child_ipns_private_key, tee_key)
                    .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
                (Some(hex::encode(&wrapped)), self.tee_key_epoch)
            }
            None => (None, None),
        };

        // Parent read/write keys for the D-07 dual splice.
        let (parent_read_key, parent_write_key, _parent_ipns_key, _parent_ipns_name) =
            self.parent_node_keys(parent_ino)?;

        let (parent_child_ref, parent_write_child_ref) = cipherbox_sdk::build_child_refs(
            child_read_key,
            child_write_key,
            &parent_read_key,
            &parent_write_key,
            &child_id,
            child_ipns_name,
            name,
            NodeKind::Folder,
            0,
            0,
        )
        .map_err(|e| format!("build_child_refs (folder) failed: {}", e))?;

        // Re-seal the parent with the new child spliced into BOTH planes. The
        // child inode is already inserted, so build_folder_metadata includes it.
        let (parent_published_node, parent_ipns_private_key, parent_ipns_name, parent_old_cid) =
            self.build_folder_metadata(parent_ino)?;

        let entry = cipherbox_sdk::JournalEntry {
            id: generate_entry_id(),
            vault_root_ipns: self.root_ipns_name.clone(),
            op: cipherbox_sdk::JournalOp::MkdirPublish {
                child_ipns_name: child_ipns_name.to_string(),
                child_published_node: child_published_node_b64,
                parent_child_ref,
                parent_write_child_ref,
                parent_folder_ipns_name: parent_ipns_name.clone(),
                created_at_ms: now_ms,
            },
            retries: 0,
            status: cipherbox_sdk::JournalEntryStatus::Pending,
        };

        Ok(MkdirJournalResult {
            entry,
            child_published_node,
            child_ipns_private_key,
            encrypted_ipns_for_tee,
            tee_key_epoch,
            child_ipns_name: child_ipns_name.to_string(),
            parent_published_node,
            parent_ipns_private_key,
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

// REQ-6: builder round-trip tests. Gated on `feature = "fuse"` because they use
// the `crate::test_support` harness. Network-free.
#[cfg(all(test, feature = "fuse"))]
mod tests {
    use crate::test_support::{make_isolated_journal_dir, make_test_fs_with_keypair};
    // node/v3: the base64 `Engine` trait must be in scope for `.decode(...)`.
    use base64::Engine;
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

    /// node/v3: mkdir builds a MkdirPublish op carrying the sealed child
    /// PublishedNode + the D-07 dual parent splices (never legacy hex-ECIES keys).
    #[tokio::test]
    async fn build_mkdir_journal_entry_emits_node_v3() {
        let (private_key, public_key) = real_keypair();
        let fs = make_test_fs_with_keypair(private_key, public_key);

        let parent_ino = crate::inode::ROOT_INO;
        let child_ino = 9001u64;
        let child_ipns_private_key = Zeroizing::new(vec![3u8; 32]);
        let child_read_key = [5u8; 32];
        let child_write_key = [6u8; 32];

        let result = fs
            .build_mkdir_journal_entry(
                parent_ino,
                child_ino,
                "newdir",
                &child_read_key,
                &child_write_key,
                "k51child-newdir",
                child_ipns_private_key,
            )
            .expect("mkdir builder must succeed against the root parent");

        assert_eq!(result.ino, child_ino, "result must reference the new child");
        assert!(
            !result.child_published_node.is_empty(),
            "child PublishedNode bytes must be present"
        );
        match &result.entry.op {
            cipherbox_sdk::JournalOp::MkdirPublish {
                child_ipns_name,
                child_published_node,
                parent_child_ref,
                parent_write_child_ref,
                ..
            } => {
                assert_eq!(child_ipns_name, "k51child-newdir");
                // The child PublishedNode is base64 of a sealed node/v3 envelope.
                assert!(
                    !child_published_node.is_empty()
                        && base64::engine::general_purpose::STANDARD
                            .decode(child_published_node.as_bytes())
                            .is_ok(),
                    "child_published_node must be valid base64 of the sealed node"
                );
                // Read plane keyed by ipnsName; write plane keyed by childId UUID
                // (D-07) — never conflated.
                assert_eq!(parent_child_ref.ipns_name, "k51child-newdir");
                assert_eq!(
                    parent_write_child_ref.child_id,
                    crate::fs::uuid_from_ino(child_ino),
                    "WriteChildRef must be keyed by the child UUID (uuid_from_ino)"
                );
                assert_ne!(
                    parent_write_child_ref.child_id, parent_child_ref.ipns_name,
                    "write-plane childId must never equal the read-plane ipnsName"
                );
                assert!(
                    !parent_child_ref.read_key_sealed.is_empty(),
                    "read_key_sealed (symmetric seal under parent readKey) must be present"
                );
                assert!(
                    !parent_write_child_ref.write_key_sealed.is_empty(),
                    "write_key_sealed (symmetric seal under parent writeKey) must be present"
                );
            }
            other => panic!("expected MkdirPublish op, got {:?}", other),
        }
    }

    /// D-01 (WR-06): a file larger than `MAX_JOURNAL_PAYLOAD_BYTES` must cause
    /// `build_upload_journal_entry` to return `Err` before reading the file.
    #[tokio::test]
    async fn payload_size_cap_returns_err() {
        let (private_key, public_key) = real_keypair();
        let fs = make_test_fs_with_keypair(private_key, public_key);

        let temp_dir = make_isolated_journal_dir();
        let ino = 9999u64;
        let handle = crate::file_handle::OpenFileHandle::new_write(ino, &temp_dir, None).unwrap();

        handle
            .truncate(cipherbox_sdk::MAX_JOURNAL_PAYLOAD_BYTES + 1)
            .expect("truncate to oversize must succeed (sparse file)");

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
