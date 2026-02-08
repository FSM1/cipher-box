//! Inode table mapping inode numbers to folder/file metadata.
//!
//! The inode table is rebuilt on mount from IPNS metadata. Folders are loaded
//! lazily: children are populated on first readdir/lookup, not upfront.
//! Each folder inode stores its decrypted IPNS private key for write operations.

#[cfg(feature = "fuse")]
use fuser::FileAttr;

#[cfg(feature = "fuse")]
use fuser::FileType;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto;
use crate::crypto::folder::{FolderChild, FolderMetadata};

/// Root inode number (standard FUSE convention).
pub const ROOT_INO: u64 = 1;

/// Default block size for statfs reporting.
pub const BLOCK_SIZE: u32 = 4096;

// ── InodeKind ─────────────────────────────────────────────────────────────────

/// Type of inode, carrying type-specific data.
#[derive(Debug, Clone)]
pub enum InodeKind {
    /// Root directory of the mounted vault.
    Root {
        /// Decrypted Ed25519 IPNS private key for signing root folder metadata.
        /// Populated from AppState.root_ipns_private_key during init.
        ipns_private_key: Option<Vec<u8>>,
        /// Root folder IPNS name for metadata resolution.
        ipns_name: Option<String>,
    },

    /// Subfolder within the vault.
    Folder {
        /// IPNS name for this subfolder (k51... format).
        ipns_name: String,
        /// Hex-encoded ECIES-wrapped AES key for this folder's metadata.
        encrypted_folder_key: String,
        /// Decrypted 32-byte AES folder key for metadata encryption/decryption.
        folder_key: Vec<u8>,
        /// Decrypted Ed25519 IPNS private key for signing this folder's IPNS records.
        /// Critical for write operations (plan 09-06).
        ipns_private_key: Option<Vec<u8>>,
        /// Whether children have been loaded from IPNS metadata.
        children_loaded: bool,
    },

    /// File within the vault.
    File {
        /// IPFS CID of the encrypted file content.
        cid: String,
        /// Hex-encoded ECIES-wrapped AES key for this file.
        encrypted_file_key: String,
        /// Hex-encoded IV used for file encryption.
        iv: String,
        /// Original file size in bytes (before encryption).
        size: u64,
        /// Encryption mode (always "GCM" for v1.0).
        encryption_mode: String,
    },
}

// ── InodeData ─────────────────────────────────────────────────────────────────

/// Complete data for a single inode.
#[derive(Debug, Clone)]
pub struct InodeData {
    /// Inode number.
    pub ino: u64,
    /// Parent inode number.
    pub parent_ino: u64,
    /// Decrypted entry name.
    pub name: String,
    /// Type-specific data (Root/Folder/File).
    pub kind: InodeKind,
    /// FUSE file attributes (size, timestamps, permissions).
    #[cfg(feature = "fuse")]
    pub attr: FileAttr,
    /// Child inode numbers (for directories only).
    pub children: Option<Vec<u64>>,
}

// ── InodeTable ────────────────────────────────────────────────────────────────

/// Maps inode numbers to metadata and provides lookup by parent+name.
///
/// Inode numbers are allocated sequentially starting at 2 (1 is root).
/// The table is rebuilt on mount from IPNS metadata.
pub struct InodeTable {
    /// Map from inode number to inode data.
    pub inodes: HashMap<u64, InodeData>,
    /// Lookup index: (parent_ino, name) -> child_ino.
    name_to_ino: HashMap<(u64, String), u64>,
    /// Atomic counter for allocating new inode numbers.
    next_ino: AtomicU64,
}

impl InodeTable {
    /// Create a new inode table with a root inode (ino=1).
    #[cfg(feature = "fuse")]
    pub fn new() -> Self {
        let now = SystemTime::now();
        let root_attr = FileAttr {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        };

        let root = InodeData {
            ino: ROOT_INO,
            parent_ino: ROOT_INO, // root is its own parent
            name: String::new(),
            kind: InodeKind::Root {
                ipns_private_key: None,
                ipns_name: None,
            },
            attr: root_attr,
            children: Some(vec![]),
        };

        let mut inodes = HashMap::new();
        inodes.insert(ROOT_INO, root);

        Self {
            inodes,
            name_to_ino: HashMap::new(),
            next_ino: AtomicU64::new(2),
        }
    }

    /// Allocate a new unique inode number.
    pub fn allocate_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::SeqCst)
    }

    /// Insert an inode into the table and update the name lookup index.
    pub fn insert(&mut self, data: InodeData) {
        let key = (data.parent_ino, data.name.clone());
        self.name_to_ino.insert(key, data.ino);
        self.inodes.insert(data.ino, data);
    }

    /// Look up an inode by number.
    pub fn get(&self, ino: u64) -> Option<&InodeData> {
        self.inodes.get(&ino)
    }

    /// Mutable lookup by inode number.
    pub fn get_mut(&mut self, ino: u64) -> Option<&mut InodeData> {
        self.inodes.get_mut(&ino)
    }

    /// Find a child inode by parent inode + child name.
    pub fn find_child(&self, parent_ino: u64, name: &str) -> Option<u64> {
        self.name_to_ino
            .get(&(parent_ino, name.to_string()))
            .copied()
    }

    /// Remove an inode from the table and clean up the name lookup.
    #[allow(dead_code)]
    pub fn remove(&mut self, ino: u64) {
        if let Some(data) = self.inodes.remove(&ino) {
            self.name_to_ino
                .remove(&(data.parent_ino, data.name.clone()));
            // Also remove from parent's children list
            if let Some(parent) = self.inodes.get_mut(&data.parent_ino) {
                if let Some(ref mut children) = parent.children {
                    children.retain(|&c| c != ino);
                }
            }
        }
    }

    /// Populate a folder's children from decrypted folder metadata.
    ///
    /// For each child:
    /// - **Subfolder:** Decrypts `folder_key_encrypted` and `ipns_private_key_encrypted`
    ///   using the user's secp256k1 private key (ECIES unwrap).
    /// - **File:** Stores CID, encrypted file key, IV, size, and encryption mode.
    ///
    /// The `private_key` parameter is the user's secp256k1 private key for ECIES decryption.
    #[cfg(feature = "fuse")]
    pub fn populate_folder(
        &mut self,
        parent_ino: u64,
        metadata: &FolderMetadata,
        private_key: &[u8],
    ) -> Result<(), String> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let mut child_inos = Vec::new();

        for child in &metadata.children {
            match child {
                FolderChild::Folder(folder) => {
                    let ino = self.allocate_ino();

                    // Decrypt folder key (ECIES unwrap)
                    let encrypted_folder_key_bytes =
                        hex::decode(&folder.folder_key_encrypted)
                            .map_err(|_| format!(
                                "Invalid folderKeyEncrypted hex for folder '{}'",
                                folder.name
                            ))?;
                    let folder_key =
                        crypto::ecies::unwrap_key(&encrypted_folder_key_bytes, private_key)
                            .map_err(|e| format!(
                                "Failed to decrypt folder key for '{}': {}",
                                folder.name, e
                            ))?;

                    // Decrypt IPNS private key (ECIES unwrap)
                    let encrypted_ipns_key_bytes =
                        hex::decode(&folder.ipns_private_key_encrypted)
                            .map_err(|_| format!(
                                "Invalid ipnsPrivateKeyEncrypted hex for folder '{}'",
                                folder.name
                            ))?;
                    let ipns_private_key =
                        crypto::ecies::unwrap_key(&encrypted_ipns_key_bytes, private_key)
                            .map_err(|e| format!(
                                "Failed to decrypt IPNS private key for '{}': {}",
                                folder.name, e
                            ))?;

                    let now = SystemTime::now();
                    let created = UNIX_EPOCH
                        + Duration::from_millis(folder.created_at);
                    let modified = UNIX_EPOCH
                        + Duration::from_millis(folder.modified_at);

                    let attr = FileAttr {
                        ino,
                        size: 0,
                        blocks: 0,
                        atime: modified,
                        mtime: modified,
                        ctime: modified,
                        crtime: created,
                        kind: FileType::Directory,
                        perm: 0o755,
                        nlink: 2,
                        uid,
                        gid,
                        rdev: 0,
                        blksize: BLOCK_SIZE,
                        flags: 0,
                    };

                    let inode = InodeData {
                        ino,
                        parent_ino,
                        name: folder.name.clone(),
                        kind: InodeKind::Folder {
                            ipns_name: folder.ipns_name.clone(),
                            encrypted_folder_key: folder.folder_key_encrypted.clone(),
                            folder_key,
                            ipns_private_key: Some(ipns_private_key),
                            children_loaded: false,
                        },
                        attr,
                        children: Some(vec![]),
                    };

                    self.insert(inode);
                    child_inos.push(ino);
                }
                FolderChild::File(file) => {
                    let ino = self.allocate_ino();

                    let created = UNIX_EPOCH
                        + Duration::from_millis(file.created_at);
                    let modified = UNIX_EPOCH
                        + Duration::from_millis(file.modified_at);

                    let attr = FileAttr {
                        ino,
                        size: file.size,
                        blocks: (file.size + 511) / 512,
                        atime: modified,
                        mtime: modified,
                        ctime: modified,
                        crtime: created,
                        kind: FileType::RegularFile,
                        perm: 0o644,
                        nlink: 1,
                        uid,
                        gid,
                        rdev: 0,
                        blksize: BLOCK_SIZE,
                        flags: 0,
                    };

                    let inode = InodeData {
                        ino,
                        parent_ino,
                        name: file.name.clone(),
                        kind: InodeKind::File {
                            cid: file.cid.clone(),
                            encrypted_file_key: file.file_key_encrypted.clone(),
                            iv: file.file_iv.clone(),
                            size: file.size,
                            encryption_mode: file.encryption_mode.clone(),
                        },
                        attr,
                        children: None,
                    };

                    self.insert(inode);
                    child_inos.push(ino);
                }
            }
        }

        // Set parent's children list
        if let Some(parent) = self.inodes.get_mut(&parent_ino) {
            parent.children = Some(child_inos);
            // Mark folder as loaded
            match &mut parent.kind {
                InodeKind::Root { .. } => {
                    // Root is always "loaded" after populate
                }
                InodeKind::Folder {
                    children_loaded, ..
                } => {
                    *children_loaded = true;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "fuse"))]
mod tests {
    use super::*;

    #[test]
    fn test_inode_table_new_has_root() {
        let table = InodeTable::new();
        let root = table.get(ROOT_INO);
        assert!(root.is_some());
        let root = root.unwrap();
        assert_eq!(root.ino, ROOT_INO);
        assert_eq!(root.parent_ino, ROOT_INO);
        assert!(matches!(root.kind, InodeKind::Root { .. }));
        assert!(root.children.is_some());
    }

    #[test]
    fn test_allocate_ino_sequential() {
        let table = InodeTable::new();
        assert_eq!(table.allocate_ino(), 2);
        assert_eq!(table.allocate_ino(), 3);
        assert_eq!(table.allocate_ino(), 4);
    }

    #[test]
    fn test_insert_and_find_child() {
        let mut table = InodeTable::new();
        let ino = table.allocate_ino();

        let now = SystemTime::now();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let data = InodeData {
            ino,
            parent_ino: ROOT_INO,
            name: "documents".to_string(),
            kind: InodeKind::Folder {
                ipns_name: "k51test".to_string(),
                encrypted_folder_key: "deadbeef".to_string(),
                folder_key: vec![0u8; 32],
                ipns_private_key: Some(vec![0u8; 32]),
                children_loaded: false,
            },
            attr: FileAttr {
                ino,
                size: 0,
                blocks: 0,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                kind: FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid,
                gid,
                rdev: 0,
                blksize: BLOCK_SIZE,
                flags: 0,
            },
            children: Some(vec![]),
        };

        table.insert(data);

        // Find by parent + name
        let found = table.find_child(ROOT_INO, "documents");
        assert_eq!(found, Some(ino));

        // Lookup by ino
        let inode = table.get(ino);
        assert!(inode.is_some());
        assert_eq!(inode.unwrap().name, "documents");
    }

    #[test]
    fn test_find_child_not_found() {
        let table = InodeTable::new();
        assert_eq!(table.find_child(ROOT_INO, "nonexistent"), None);
    }

    #[test]
    fn test_remove_inode() {
        let mut table = InodeTable::new();
        let ino = table.allocate_ino();

        let now = SystemTime::now();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Add child to root's children
        if let Some(root) = table.get_mut(ROOT_INO) {
            if let Some(ref mut children) = root.children {
                children.push(ino);
            }
        }

        let data = InodeData {
            ino,
            parent_ino: ROOT_INO,
            name: "test.txt".to_string(),
            kind: InodeKind::File {
                cid: "bafytest".to_string(),
                encrypted_file_key: "aabb".to_string(),
                iv: "ccdd".to_string(),
                size: 1024,
                encryption_mode: "GCM".to_string(),
            },
            attr: FileAttr {
                ino,
                size: 1024,
                blocks: 2,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                kind: FileType::RegularFile,
                perm: 0o644,
                nlink: 1,
                uid,
                gid,
                rdev: 0,
                blksize: BLOCK_SIZE,
                flags: 0,
            },
            children: None,
        };

        table.insert(data);
        assert!(table.get(ino).is_some());
        assert!(table.find_child(ROOT_INO, "test.txt").is_some());

        table.remove(ino);
        assert!(table.get(ino).is_none());
        assert!(table.find_child(ROOT_INO, "test.txt").is_none());
    }

    #[test]
    fn test_inode_kind_folder_has_ipns_private_key() {
        let kind = InodeKind::Folder {
            ipns_name: "k51test".to_string(),
            encrypted_folder_key: "deadbeef".to_string(),
            folder_key: vec![0u8; 32],
            ipns_private_key: Some(vec![42u8; 32]),
            children_loaded: false,
        };

        match kind {
            InodeKind::Folder {
                ipns_private_key, ..
            } => {
                assert!(ipns_private_key.is_some());
                assert_eq!(ipns_private_key.unwrap().len(), 32);
            }
            _ => panic!("Expected Folder kind"),
        }
    }

    #[test]
    fn test_inode_kind_root_has_ipns_private_key() {
        let kind = InodeKind::Root {
            ipns_private_key: Some(vec![42u8; 32]),
            ipns_name: Some("k51root".to_string()),
        };

        match kind {
            InodeKind::Root {
                ipns_private_key,
                ipns_name,
            } => {
                assert!(ipns_private_key.is_some());
                assert!(ipns_name.is_some());
            }
            _ => panic!("Expected Root kind"),
        }
    }

    #[test]
    fn test_inode_kind_file_has_encryption_mode() {
        let kind = InodeKind::File {
            cid: "bafytest".to_string(),
            encrypted_file_key: "aabb".to_string(),
            iv: "ccdd".to_string(),
            size: 1024,
            encryption_mode: "GCM".to_string(),
        };

        match kind {
            InodeKind::File {
                encryption_mode, ..
            } => {
                assert_eq!(encryption_mode, "GCM");
            }
            _ => panic!("Expected File kind"),
        }
    }

    #[test]
    fn test_populate_folder_with_files() {
        let mut table = InodeTable::new();

        let metadata = FolderMetadata {
            version: "v1".to_string(),
            children: vec![
                FolderChild::File(crate::crypto::folder::FileEntry {
                    id: "file-1".to_string(),
                    name: "hello.txt".to_string(),
                    cid: "bafyfile1".to_string(),
                    file_key_encrypted: "aa".to_string(),
                    file_iv: "bb".to_string(),
                    size: 100,
                    created_at: 1700000000000,
                    modified_at: 1700000000000,
                    encryption_mode: "GCM".to_string(),
                }),
            ],
        };

        // For files, populate_folder doesn't need ECIES decryption
        let private_key = vec![0u8; 32]; // unused for files
        let result = table.populate_folder(ROOT_INO, &metadata, &private_key);
        assert!(result.is_ok());

        // Root should have 1 child
        let root = table.get(ROOT_INO).unwrap();
        assert_eq!(root.children.as_ref().unwrap().len(), 1);

        let child_ino = root.children.as_ref().unwrap()[0];
        let child = table.get(child_ino).unwrap();
        assert_eq!(child.name, "hello.txt");
        assert!(matches!(child.kind, InodeKind::File { .. }));
    }
}
