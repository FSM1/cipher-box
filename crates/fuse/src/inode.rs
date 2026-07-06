//! Inode table mapping inode numbers to folder/file metadata.
//!
//! The inode table is rebuilt on mount from IPNS metadata. Folders are loaded
//! lazily: children are populated on first readdir/lookup, not upfront.
//! Each folder inode stores its decrypted IPNS private key for write operations.

#[cfg(feature = "fuse")]
use fuser::FileType;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

// node/v3 read materialization (69-09 Slice 2): the owned listing carrier and
// the symmetric NodeKind discriminator. The legacy `FolderMetadata`/`FolderChild`
// types are no longer consumed by the prod read path — only the #[cfg(test)]
// fixtures below still reference them (kept RED for the final green boundary).
use cipherbox_core::node::NodeKind;
use cipherbox_sdk::ResolvedOwnedChild;

#[cfg(all(test, any(feature = "fuse", feature = "winfsp")))]
use cipherbox_core::folder::{FolderChild, FolderMetadata};

/// Normalize a filename to NFC (composed) form for consistent HashMap lookups.
/// macOS NFS client may send names in either NFC or NFD form; FUSE-T's go-nfsv4
/// may also re-normalize. By normalizing to NFC on both storage and lookup,
/// we avoid mismatches with accented characters (e.g., `e` vs `e` + combining grave).
///
/// On Windows, WinFsp sends callbacks with arbitrary casing (often uppercased)
/// for case-insensitive volumes. We fold to lowercase for consistent HashMap
/// key matching while preserving original casing in InodeData.name.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) fn normalize_name(name: &str) -> String {
    // unicode-normalization is a dependency of the fuse feature.
    // On Windows (winfsp feature), fold to lowercase for case-insensitive matching.
    // WinFsp's case-insensitive lookup is the user-mode filesystem's responsibility.
    #[cfg(feature = "fuse")]
    {
        use unicode_normalization::UnicodeNormalization;
        name.nfc().collect()
    }
    #[cfg(all(feature = "winfsp", not(feature = "fuse")))]
    {
        name.to_lowercase()
    }
}

/// Root inode number (standard FUSE convention).
pub const ROOT_INO: u64 = 1;

/// Default block size for statfs reporting.
pub const BLOCK_SIZE: u32 = 4096;

// -- FileAttrs ---------------------------------------------------------------

/// Platform-agnostic file attributes.
/// Converted to `fuser::FileAttr` on macOS and `winfsp::filesystem::FileInfo` on Windows
/// at the operations layer boundary.
#[derive(Debug, Clone)]
pub struct FileAttrs {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub crtime: SystemTime,
    pub is_dir: bool,
    pub perm: u16,
    pub nlink: u32,
}

#[cfg(feature = "fuse")]
impl FileAttrs {
    /// Convert to fuser::FileAttr for macOS FUSE replies.
    /// uid/gid are injected from the operations layer (libc::getuid()/getgid()).
    pub fn to_fuse_attr(&self, uid: u32, gid: u32) -> fuser::FileAttr {
        fuser::FileAttr {
            ino: self.ino,
            size: self.size,
            blocks: self.blocks,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
            crtime: self.crtime,
            kind: if self.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: self.perm,
            nlink: self.nlink,
            uid,
            gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }
}

// -- InodeKind ---------------------------------------------------------------

/// Type of inode, carrying type-specific data.
///
/// node/v3 owner state (69-09): each variant carries the raw symmetric
/// `read_key`/`write_key` pair plus the Ed25519 signing seed
/// (`ipns_private_key`), sourced from `cipherbox_sdk::ResolvedOwnedChild`
/// (`{ read_key, write_key, ipns_private_key }`). The mount is the terminal
/// owner of these `Zeroizing` keys — they are moved in, never borrowed-then-
/// zeroed. The legacy node-to-node hex key fields (`encrypted_folder_key`,
/// `encrypted_file_key`, `folder_key`) are gone: `read_key` replaces them.
#[derive(Debug, Clone)]
pub enum InodeKind {
    /// Root directory of the mounted vault.
    ///
    /// The mount holds the root's read/write keys and signing seed sourced
    /// from `AppState` at init. `InodeTable::new` installs empty placeholder
    /// values that the root-population glue overwrites before first use
    /// (69-09 Slice 5).
    Root {
        /// Root folder IPNS name for metadata resolution.
        ipns_name: String,
        /// Raw 32-byte symmetric readKey for this folder's node/v3 metadata.
        read_key: Zeroizing<[u8; 32]>,
        /// Raw 32-byte symmetric writeKey — needed to build child WriteChildRefs.
        write_key: Zeroizing<[u8; 32]>,
        /// Decrypted Ed25519 IPNS private key (signing seed) for this folder.
        /// Wrapped in `Zeroizing` for automatic zeroization on drop.
        ipns_private_key: Zeroizing<Vec<u8>>,
    },

    /// Subfolder within the vault.
    Folder {
        /// IPNS name for this subfolder (k51... format).
        ipns_name: String,
        /// Raw 32-byte symmetric readKey for this folder's node/v3 metadata.
        read_key: Zeroizing<[u8; 32]>,
        /// Raw 32-byte symmetric writeKey — needed to build child WriteChildRefs.
        write_key: Zeroizing<[u8; 32]>,
        /// Decrypted Ed25519 IPNS private key for signing this folder's records.
        /// Wrapped in `Zeroizing` for automatic zeroization on drop.
        ipns_private_key: Zeroizing<Vec<u8>>,
        /// Whether children have been loaded from node/v3 metadata.
        children_loaded: bool,
    },

    /// File within the vault.
    File {
        /// Per-file IPNS name (k51... format) for this file's node/v3 record.
        ipns_name: String,
        /// IPFS CID of the encrypted file content.
        cid: String,
        /// Original file size in bytes (before encryption).
        size: u64,
        /// Encryption mode ("GCM" for v1/standard, "CTR" for streaming media).
        encryption_mode: String,
        /// Hex-encoded IV used for file encryption.
        iv: String,
        /// Raw 32-byte symmetric readKey for this file's node/v3 record.
        read_key: Zeroizing<[u8; 32]>,
        /// Raw 32-byte symmetric writeKey for this file's node/v3 record.
        write_key: Zeroizing<[u8; 32]>,
        /// Decrypted Ed25519 IPNS private key for signing this file's record.
        /// Wrapped in `Zeroizing` for automatic zeroization on drop.
        ipns_private_key: Zeroizing<Vec<u8>>,
    },
}

// -- InodeData ---------------------------------------------------------------

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
    /// Platform-agnostic file attributes (size, timestamps, permissions).
    pub attr: FileAttrs,
    /// Child inode numbers (for directories only).
    pub children: Option<Vec<u64>>,
    /// Write generation counter. Incremented on each truncate/overwrite cycle.
    /// Upload completions carry this value and are only applied if it matches,
    /// preventing stale uploads from overwriting newer content state.
    pub write_generation: u64,
}

// -- InodeTable --------------------------------------------------------------

/// Maps inode numbers to metadata and provides lookup by parent+name.
///
/// Inode numbers are allocated sequentially starting at 2 (1 is root).
/// The table is rebuilt on mount from IPNS metadata.
pub struct InodeTable {
    /// Map from inode number to inode data.
    pub inodes: HashMap<u64, InodeData>,
    /// Lookup index: (parent_ino, name) -> child_ino.
    pub name_to_ino: HashMap<(u64, String), u64>,
    /// Atomic counter for allocating new inode numbers.
    next_ino: AtomicU64,
}

impl InodeTable {
    /// Create a new inode table with a root inode (ino=1).
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn new() -> Self {
        let now = SystemTime::now();
        let root_attr = FileAttrs {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            is_dir: true,
            perm: 0o777,
            nlink: 2,
        };

        let root = InodeData {
            ino: ROOT_INO,
            parent_ino: ROOT_INO, // root is its own parent
            name: String::new(),
            kind: InodeKind::Root {
                ipns_name: String::new(),
                read_key: Zeroizing::new([0u8; 32]),
                write_key: Zeroizing::new([0u8; 32]),
                ipns_private_key: Zeroizing::new(Vec::new()),
            },
            attr: root_attr,
            children: Some(vec![]),
            write_generation: 0,
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
    /// Name is normalized to NFC for consistent lookup across Unicode forms.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn insert(&mut self, data: InodeData) {
        let key = (data.parent_ino, normalize_name(&data.name));
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
    /// Name is normalized to NFC for consistent lookup across Unicode forms.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn find_child(&self, parent_ino: u64, name: &str) -> Option<u64> {
        self.name_to_ino
            .get(&(parent_ino, normalize_name(name)))
            .copied()
    }

    /// Remove an inode from the table and clean up the name lookup.
    #[allow(dead_code)]
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn remove(&mut self, ino: u64) {
        if let Some(data) = self.inodes.remove(&ino) {
            self.name_to_ino
                .remove(&(data.parent_ino, normalize_name(&data.name)));
            // Also remove from parent's children list
            if let Some(parent) = self.inodes.get_mut(&data.parent_ino) {
                if let Some(ref mut children) = parent.children {
                    children.retain(|&c| c != ino);
                }
            }
        }
    }

    /// Populate a folder's children from the gated node/v3 owned materialization
    /// `cipherbox_sdk::list_folder_owned` (69-17, SC#1/SC#6).
    ///
    /// The mount is a WRITE-OWNER: each child `InodeKind` is filled with the
    /// recovered `{ read_key, write_key, ipns_private_key }` MOVED straight out
    /// of the returned `ResolvedOwnedChild`. Per D-09 terminal-owner discipline
    /// the mount is the terminal owner of those `Zeroizing` keys — they are
    /// moved in, NEVER zeroed here (and `parent_read_key`/`parent_write_key`
    /// are caller-owned borrows that are likewise never zeroed). No node-to-node
    /// ECIES unwrap remains: `list_folder_owned` recovers every child key via
    /// the symmetric `unseal_child_read_key`/`unseal_child_write_key`/
    /// `unseal_node` chain internally.
    ///
    /// File children are materialized with `{ipns_name, size, read_key,
    /// write_key, ipns_private_key}`; the content descriptors (`cid`/`iv`/
    /// `encryption_mode`) live inside the file node's OWN sealed read-body and
    /// are filled later by [`resolve_file_pointer`] once the mount unseals it
    /// (they are placeholders here — an empty `cid` means "unresolved", surfaced
    /// by [`get_unresolved_file_pointers`]/`..._for_parent`).
    ///
    /// SIGNATURE CHANGE (69-09 Slice 5 caller note): this method now takes the
    /// parent's `ipns_name` + its symmetric `parent_read_key`/`parent_write_key`
    /// (from the parent `InodeKind`) plus the `api`/`high_water` threaded from
    /// the `CipherBoxFS` caller (InodeTable holds neither). It is now `async`.
    /// The former `(&FolderMetadata, private_key, public_key)` params are gone.
    /// When `merge_only` is true (background refresh) existing children absent
    /// from the remote listing are preserved; when false (initial mount) they
    /// are removed (matched by stable `ipns_name`).
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[allow(clippy::too_many_arguments)]
    pub async fn populate_folder(
        &mut self,
        parent_ino: u64,
        ipns_name: &str,
        parent_read_key: &[u8; 32],
        parent_write_key: &[u8; 32],
        api: &cipherbox_api_client::ApiClient,
        high_water: &cipherbox_sdk::RotationHighWater<cipherbox_sdk::JsonSidecarFloorStore>,
        merge_only: bool,
    ) -> Result<(), String> {
        // Route the read strictly through the single gated owned entrypoint
        // (SC#6). The fetcher is a borrow adapter constructed inline per call
        // (69-09 Slice 1 carry-forward).
        let fetcher = cipherbox_sdk::ApiNodeFetcher { api };
        let resolved = cipherbox_sdk::list_folder_owned(
            &fetcher,
            high_water,
            ipns_name,
            parent_read_key,
            parent_write_key,
        )
        .await
        .map_err(|e| format!("list_folder_owned failed for {}: {}", ipns_name, e))?;

        self.apply_owned_children(parent_ino, resolved, merge_only);
        Ok(())
    }

    /// Sync-apply half of the node/v3 refresh pipeline (69-09 Slice 5b(d)).
    ///
    /// Splits [`populate_folder`] into an async fetch ([`cipherbox_sdk::list_folder_owned`])
    /// and this synchronous apply so the FUSE callback thread's
    /// `drain_refresh_completions` can apply a `Vec<ResolvedOwnedChild>` that a
    /// background task already fetched — the mount never awaits on the callback
    /// thread. Applies the same stable-ipns_name ino-reuse, rename-by-ipns, and
    /// `merge_only` preservation semantics `populate_folder` had inline. The mount
    /// is the terminal owner of each child's moved-in `Zeroizing` keys (D-09).
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn apply_owned_children(
        &mut self,
        parent_ino: u64,
        resolved: Vec<ResolvedOwnedChild>,
        merge_only: bool,
    ) {
        let old_child_inos: Vec<u64> = self
            .inodes
            .get(&parent_ino)
            .and_then(|p| p.children.as_ref())
            .cloned()
            .unwrap_or_default();

        // Stable-ID index of existing children by ipns_name (read plane, D-07)
        // for NFS-stable ino reuse across renames.
        let mut ipns_to_ino: HashMap<String, u64> = HashMap::new();
        for &child_ino in &old_child_inos {
            if let Some(child) = self.inodes.get(&child_ino) {
                match &child.kind {
                    InodeKind::Folder { ipns_name, .. } | InodeKind::File { ipns_name, .. } => {
                        ipns_to_ino.insert(ipns_name.clone(), child_ino);
                    }
                    InodeKind::Root { .. } => {}
                }
            }
        }

        // Remote ipns_names to distinguish true removals from renames.
        let new_ipns_names: std::collections::HashSet<String> =
            resolved.iter().map(|c| c.child.ipns_name.clone()).collect();

        // Remove children not in the remote listing (initial mount only), matched
        // by stable ipns_name so a rename (new name, same ipns_name) is not dropped.
        if !merge_only {
            for old_ino in &old_child_inos {
                if let Some(old_child) = self.inodes.get(old_ino) {
                    let stable_id = match &old_child.kind {
                        InodeKind::Folder { ipns_name, .. } | InodeKind::File { ipns_name, .. } => {
                            Some(ipns_name.clone())
                        }
                        InodeKind::Root { .. } => None,
                    };
                    let in_remote = stable_id
                        .as_ref()
                        .map(|id| new_ipns_names.contains(id))
                        .unwrap_or(false);
                    if !in_remote {
                        let name = old_child.name.clone();
                        self.inodes.remove(old_ino);
                        self.name_to_ino
                            .remove(&(parent_ino, normalize_name(&name)));
                    }
                }
            }
        }

        let mut child_inos = Vec::new();

        for owned in resolved {
            let ResolvedOwnedChild {
                child,
                read_key,
                write_key,
                ipns_private_key,
            } = owned;

            // Reuse existing ino: prefer stable ipns_name, fall back to display name.
            let matched_by_stable_id = ipns_to_ino.contains_key(&child.ipns_name);
            let existing_ino = ipns_to_ino
                .get(&child.ipns_name)
                .copied()
                .or_else(|| self.find_child(parent_ino, &child.name));

            // Rename detected via ipns match (not name): drop the stale name index.
            if let Some(matched_ino) = existing_ino {
                if self.find_child(parent_ino, &child.name).is_none() {
                    if let Some(old_inode) = self.inodes.get(&matched_ino) {
                        let old_name = old_inode.name.clone();
                        self.name_to_ino
                            .remove(&(parent_ino, normalize_name(&old_name)));
                        log::debug!(
                            "Child rename detected via IPNS match (ipns={})",
                            child.ipns_name
                        );
                    }
                }
            }

            let ino = existing_ino.unwrap_or_else(|| self.allocate_ino());
            let modified = UNIX_EPOCH + Duration::from_millis(child.modified_at);

            match child.kind {
                NodeKind::Folder | NodeKind::Root => {
                    // Preserve children list + loaded state only on a stable-ID
                    // match (D-11): a display-name-only fallback means identity
                    // changed, so force a fresh load.
                    let (existing_children, was_loaded) = if existing_ino.is_some()
                        && matched_by_stable_id
                    {
                        let old = self.inodes.get(&ino);
                        let ch = old.and_then(|o| o.children.clone());
                        let loaded = old
                            .map(|o| {
                                matches!(
                                    &o.kind,
                                    InodeKind::Folder {
                                        children_loaded: true,
                                        ..
                                    }
                                )
                            })
                            .unwrap_or(false);
                        (ch, loaded)
                    } else {
                        if existing_ino.is_some() {
                            log::info!(
                                    "Folder '{}': stable-ID mismatch on fallback match, clearing loaded state (D-11)",
                                    child.name
                                );
                        }
                        (Some(vec![]), false)
                    };

                    let attr = FileAttrs {
                        ino,
                        size: 0,
                        blocks: 0,
                        atime: modified,
                        mtime: modified,
                        ctime: modified,
                        crtime: modified,
                        is_dir: true,
                        perm: 0o777,
                        nlink: 2,
                    };
                    let inode = InodeData {
                        ino,
                        parent_ino,
                        name: child.name.clone(),
                        kind: InodeKind::Folder {
                            ipns_name: child.ipns_name.clone(),
                            read_key,
                            write_key,
                            ipns_private_key,
                            children_loaded: was_loaded,
                        },
                        attr,
                        children: existing_children,
                        write_generation: 0,
                    };
                    self.insert(inode);
                    child_inos.push(ino);
                }
                NodeKind::File => {
                    let size = child.size.unwrap_or(0);
                    let attr = FileAttrs {
                        ino,
                        size,
                        blocks: (size + 511) / 512,
                        atime: modified,
                        mtime: modified,
                        ctime: modified,
                        crtime: modified,
                        is_dir: false,
                        perm: 0o666,
                        nlink: 1,
                    };
                    let inode = InodeData {
                        ino,
                        parent_ino,
                        name: child.name.clone(),
                        // Content descriptors (cid/iv/encryption_mode) live in the
                        // file node's sealed read-body and are filled by
                        // resolve_file_pointer once unsealed. Empty cid ==
                        // unresolved.
                        kind: InodeKind::File {
                            ipns_name: child.ipns_name.clone(),
                            cid: String::new(),
                            size,
                            encryption_mode: "GCM".to_string(),
                            iv: String::new(),
                            read_key,
                            write_key,
                            ipns_private_key,
                        },
                        attr,
                        children: None,
                        write_generation: 0,
                    };
                    self.insert(inode);
                    child_inos.push(ino);
                }
            }
        }

        // merge_only: preserve existing children absent from the remote listing.
        if merge_only {
            for &old_ino in &old_child_inos {
                if !child_inos.contains(&old_ino) {
                    child_inos.push(old_ino);
                }
            }
        }

        // Set parent's children list + mark loaded.
        if let Some(parent) = self.inodes.get_mut(&parent_ino) {
            let old_children = parent.children.as_ref().cloned().unwrap_or_default();
            let children_changed =
                old_children.len() != child_inos.len() || old_children != child_inos;
            if children_changed {
                let now = SystemTime::now();
                parent.attr.mtime = now;
                parent.attr.ctime = now;
            }

            parent.children = Some(child_inos);
            match &mut parent.kind {
                InodeKind::Root { .. } => {}
                InodeKind::Folder {
                    children_loaded, ..
                } => {
                    *children_loaded = true;
                }
                InodeKind::File { .. } => {}
            }
        }
    }

    /// Fill a File inode's node/v3 content descriptors (CID, IV, size,
    /// encryption mode) after the mount unseals the file node's read-body.
    ///
    /// SIGNATURE CHANGE (69-09 Slice 5 caller note): the former
    /// `encrypted_file_key` (ECIES hex) and `versions` params are gone — the
    /// file_key is now recovered at read time from the sealed body (content_ops)
    /// and is never stored in the inode. This updates the descriptors in place,
    /// PRESERVING the moved-in `read_key`/`write_key`/`ipns_private_key` and
    /// `ipns_name` (no key clone, D-09).
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn resolve_file_pointer(
        &mut self,
        ino: u64,
        cid: String,
        iv: String,
        size: u64,
        encryption_mode: String,
    ) {
        if let Some(inode) = self.inodes.get_mut(&ino) {
            if let InodeKind::File {
                cid: cid_slot,
                iv: iv_slot,
                size: size_slot,
                encryption_mode: mode_slot,
                ..
            } = &mut inode.kind
            {
                *cid_slot = cid;
                *iv_slot = iv;
                *size_slot = size;
                *mode_slot = encryption_mode;
            }
            // Update attr size for GETATTR/READDIR.
            inode.attr.size = size;
            inode.attr.blocks = (size + 511) / 512;
        }
    }

    /// Get all unresolved File inodes (empty `cid` — content descriptors not yet
    /// recovered). Returns Vec of `(ino, ipns_name)`.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn get_unresolved_file_pointers(&self) -> Vec<(u64, String)> {
        self.inodes
            .values()
            .filter_map(|inode| match &inode.kind {
                InodeKind::File { ipns_name, cid, .. } if cid.is_empty() => {
                    Some((inode.ino, ipns_name.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Get unresolved File inodes scoped to a specific parent folder.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn get_unresolved_file_pointers_for_parent(&self, parent_ino: u64) -> Vec<(u64, String)> {
        self.inodes
            .values()
            .filter_map(|inode| {
                if inode.parent_ino != parent_ino {
                    return None;
                }
                match &inode.kind {
                    InodeKind::File { ipns_name, cid, .. } if cid.is_empty() => {
                        Some((inode.ino, ipns_name.clone()))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// Mark *genuine remote file edits* for re-resolution WITHOUT rebuilding
    /// folder structure or clobbering pending local mutations.
    ///
    /// SIGNATURE CHANGE (69-09 Slice 5 caller note): the input is now the gated
    /// `&[ResolvedOwnedChild]` listing (from `list_folder_owned`) instead of the
    /// legacy `&FolderMetadata`. For each remote File child mapping to an
    /// already-resolved local inode (non-empty `cid`) under the SAME identity
    /// (same `ipns_name`, same display name) whose remote `modified_at` is
    /// STRICTLY newer than the local mtime, the content descriptors are cleared
    /// (marking it unresolved) while the moved-in keys are PRESERVED. "Local
    /// wins" on ties/behind-clock skew (the deliberate `>`), so a pending local
    /// mutation is never overwritten. It returns `()`: the caller MUST still
    /// call `get_unresolved_file_pointers_for_parent` to drive the resolution
    /// spawn (that re-scan covers the files flipped here plus any already
    /// unresolved).
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    pub fn mark_remotely_edited_files_unresolved(
        &mut self,
        parent_ino: u64,
        resolved: &[ResolvedOwnedChild],
    ) {
        for owned in resolved {
            let child = &owned.child;
            if child.kind != NodeKind::File {
                continue;
            }
            // Match strictly by current display name: a rename is a structural
            // change deliberately left to the full populate_folder path.
            let Some(existing_ino) = self.find_child(parent_ino, &child.name) else {
                continue;
            };
            let modified = UNIX_EPOCH + Duration::from_millis(child.modified_at);
            let Some(inode) = self.inodes.get_mut(&existing_ino) else {
                continue;
            };
            // Only flip an already-resolved (non-empty cid) file under the SAME
            // identity whose remote timestamp is strictly newer than the local copy.
            let should_mark = matches!(
                &inode.kind,
                InodeKind::File { ipns_name, cid, .. }
                    if *ipns_name == child.ipns_name && !cid.is_empty()
            ) && modified > inode.attr.mtime;
            if !should_mark {
                continue;
            }
            log::info!(
                "File '{}': remote edit detected while folder ino {} is locally publishing -- marking for re-resolution without clobbering local state",
                child.name,
                parent_ino
            );
            // Clear content descriptors (mark unresolved); PRESERVE the keys.
            if let InodeKind::File { cid, iv, size, .. } = &mut inode.kind {
                cid.clear();
                iv.clear();
                *size = 0;
            }
            inode.attr.size = 0;
            inode.attr.blocks = 0;
            // Adopt the remote timestamp so the next refresh does not re-mark.
            inode.attr.atime = modified;
            inode.attr.mtime = modified;
            inode.attr.ctime = modified;
        }
    }
}

#[cfg(all(test, any(feature = "fuse", feature = "winfsp")))]
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

        let data = InodeData {
            ino,
            parent_ino: ROOT_INO,
            name: "documents".to_string(),
            kind: InodeKind::Folder {
                ipns_name: "k51test".to_string(),
                encrypted_folder_key: "deadbeef".to_string(),
                folder_key: Zeroizing::new(vec![0u8; 32]),
                ipns_private_key: Some(Zeroizing::new(vec![0u8; 32])),
                children_loaded: false,
            },
            attr: FileAttrs {
                ino,
                size: 0,
                blocks: 0,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                is_dir: true,
                perm: 0o777,
                nlink: 2,
            },
            children: Some(vec![]),
            write_generation: 0,
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
                file_meta_ipns_name: None,
                file_meta_resolved: true,
                file_ipns_private_key: None,
                file_ipns_key_encrypted_hex: None,
                versions: None,
            },
            attr: FileAttrs {
                ino,
                size: 1024,
                blocks: 2,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                is_dir: false,
                perm: 0o666,
                nlink: 1,
            },
            children: None,
            write_generation: 0,
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
            folder_key: Zeroizing::new(vec![0u8; 32]),
            ipns_private_key: Some(Zeroizing::new(vec![42u8; 32])),
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
            ipns_private_key: Some(Zeroizing::new(vec![42u8; 32])),
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
            file_meta_ipns_name: None,
            file_meta_resolved: true,
            file_ipns_private_key: None,
            file_ipns_key_encrypted_hex: None,
            versions: None,
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
    fn test_populate_folder_with_file_pointers() {
        let mut table = InodeTable::new();

        let metadata = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "file-1".to_string(),
                name: "hello.txt".to_string(),
                file_meta_ipns_name:
                    "k51qzi5uqu5dljtg5upm7x7ugan9lql3ewyknv4r4mhhkwzn8n7cnbd1unfwgx".to_string(),
                ipns_private_key_encrypted: None,
                created_at: 1700000000000,
                modified_at: 1700000000000,
            })],
        };

        // For FilePointer children without ipnsPrivateKeyEncrypted, HKDF derivation
        // is used. Public key is needed for wrapping during lazy migration.
        let private_key = vec![0u8; 32];
        let public_key = vec![0u8; 33]; // dummy compressed public key
        let result = table.populate_folder(ROOT_INO, &metadata, &private_key, &public_key, false);
        assert!(result.is_ok());

        // Root should have 1 child
        let root = table.get(ROOT_INO).unwrap();
        assert_eq!(root.children.as_ref().unwrap().len(), 1);

        let child_ino = root.children.as_ref().unwrap()[0];
        let child = table.get(child_ino).unwrap();
        assert_eq!(child.name, "hello.txt");
        match &child.kind {
            InodeKind::File {
                file_meta_ipns_name,
                file_meta_resolved,
                file_ipns_key_encrypted_hex,
                file_ipns_private_key,
                ..
            } => {
                assert_eq!(
                    file_meta_ipns_name.as_deref(),
                    Some("k51qzi5uqu5dljtg5upm7x7ugan9lql3ewyknv4r4mhhkwzn8n7cnbd1unfwgx")
                );
                assert!(
                    !file_meta_resolved,
                    "FilePointer should not be resolved yet"
                );
                assert!(
                    file_ipns_key_encrypted_hex.is_none(),
                    "Legacy FilePointer should have no cached encrypted hex"
                );
                assert!(
                    file_ipns_private_key.is_none(),
                    "Legacy FilePointer with zeroed key should have no derived private key"
                );
            }
            _ => panic!("Expected File kind"),
        }
    }

    /// Helper to generate a secp256k1 keypair for ECIES operations in tests.
    fn generate_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (sk.serialize().to_vec(), pk.serialize().to_vec())
    }

    #[test]
    fn test_populate_folder_matches_renamed_folder_by_ipns_name() {
        let mut table = InodeTable::new();

        // Generate a real secp256k1 keypair for ECIES operations
        let (private_key, public_key) = generate_test_keypair();

        // Create a 32-byte folder key and wrap it with ECIES
        let folder_key_raw = vec![42u8; 32];
        let folder_key_encrypted_hex =
            hex::encode(cipherbox_crypto::ecies::wrap_key(&folder_key_raw, &public_key).unwrap());

        // Create a 32-byte IPNS private key and wrap it
        let ipns_key_raw = vec![7u8; 32];
        let ipns_key_encrypted_hex =
            hex::encode(cipherbox_crypto::ecies::wrap_key(&ipns_key_raw, &public_key).unwrap());

        let ipns_name = "k51qzi5uqu5dFOLDERipnsNAMEstableAcross_renames";

        // Initial population: folder named "OldName"
        let metadata_v1 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                id: "folder-1".to_string(),
                name: "OldName".to_string(),
                ipns_name: ipns_name.to_string(),
                folder_key_encrypted: folder_key_encrypted_hex.clone(),
                ipns_private_key_encrypted: ipns_key_encrypted_hex.clone(),
                created_at: 1700000000000,
                modified_at: 1700000000000,
            })],
        };

        table
            .populate_folder(ROOT_INO, &metadata_v1, &private_key, &public_key, false)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        assert_eq!(root.children.as_ref().unwrap().len(), 1);
        let original_ino = root.children.as_ref().unwrap()[0];
        let child = table.get(original_ino).unwrap();
        assert_eq!(child.name, "OldName");

        // Now rename folder in remote metadata: same ipns_name, new name
        let metadata_v2 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                id: "folder-1".to_string(),
                name: "NewName".to_string(),
                ipns_name: ipns_name.to_string(),
                folder_key_encrypted: folder_key_encrypted_hex.clone(),
                ipns_private_key_encrypted: ipns_key_encrypted_hex.clone(),
                created_at: 1700000000000,
                modified_at: 1700001000000,
            })],
        };

        // merge_only=true (background sync)
        table
            .populate_folder(ROOT_INO, &metadata_v2, &private_key, &public_key, true)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        // Should have exactly 1 child, not 2 (the old folder should be reused, not duplicated)
        assert_eq!(
            root.children.as_ref().unwrap().len(),
            1,
            "Renamed folder should not create duplicate -- expected 1 child, got {}",
            root.children.as_ref().unwrap().len()
        );

        // The ino should be reused
        let child_ino = root.children.as_ref().unwrap()[0];
        assert_eq!(
            child_ino, original_ino,
            "Inode should be reused after rename"
        );

        // Name should be updated
        let child = table.get(child_ino).unwrap();
        assert_eq!(
            child.name, "NewName",
            "Folder name should be updated to new name"
        );

        // Old name should NOT be findable
        assert!(
            table.find_child(ROOT_INO, "OldName").is_none(),
            "Old name should not be findable"
        );

        // New name should be findable
        assert_eq!(
            table.find_child(ROOT_INO, "NewName"),
            Some(original_ino),
            "New name should map to same ino"
        );

        // IPNS name should be unchanged
        match &child.kind {
            InodeKind::Folder {
                ipns_name: stored_ipns,
                ..
            } => {
                assert_eq!(stored_ipns, ipns_name, "IPNS name should be preserved");
            }
            _ => panic!("Expected Folder kind"),
        }
    }

    #[test]
    fn test_populate_folder_matches_renamed_folder_initial_mount() {
        let mut table = InodeTable::new();

        let (private_key, public_key) = generate_test_keypair();
        let folder_key_raw = vec![42u8; 32];
        let folder_key_encrypted_hex =
            hex::encode(cipherbox_crypto::ecies::wrap_key(&folder_key_raw, &public_key).unwrap());
        let ipns_key_raw = vec![7u8; 32];
        let ipns_key_encrypted_hex =
            hex::encode(cipherbox_crypto::ecies::wrap_key(&ipns_key_raw, &public_key).unwrap());

        let ipns_name = "k51qzi5uqu5dFOLDERstableID";

        // Initial: folder named "Alpha"
        let metadata_v1 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                id: "folder-1".to_string(),
                name: "Alpha".to_string(),
                ipns_name: ipns_name.to_string(),
                folder_key_encrypted: folder_key_encrypted_hex.clone(),
                ipns_private_key_encrypted: ipns_key_encrypted_hex.clone(),
                created_at: 1700000000000,
                modified_at: 1700000000000,
            })],
        };

        table
            .populate_folder(ROOT_INO, &metadata_v1, &private_key, &public_key, false)
            .unwrap();
        let original_ino = table.get(ROOT_INO).unwrap().children.as_ref().unwrap()[0];

        // Non-merge (initial mount) with renamed folder
        let metadata_v2 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                id: "folder-1".to_string(),
                name: "Beta".to_string(),
                ipns_name: ipns_name.to_string(),
                folder_key_encrypted: folder_key_encrypted_hex.clone(),
                ipns_private_key_encrypted: ipns_key_encrypted_hex.clone(),
                created_at: 1700000000000,
                modified_at: 1700001000000,
            })],
        };

        // merge_only=false (initial mount / full refresh)
        table
            .populate_folder(ROOT_INO, &metadata_v2, &private_key, &public_key, false)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        assert_eq!(
            root.children.as_ref().unwrap().len(),
            1,
            "Should have exactly 1 child"
        );

        let child_ino = root.children.as_ref().unwrap()[0];
        assert_eq!(
            child_ino, original_ino,
            "Inode should be reused after rename"
        );

        let child = table.get(child_ino).unwrap();
        assert_eq!(child.name, "Beta", "Name should be updated");
        assert!(
            table.find_child(ROOT_INO, "Alpha").is_none(),
            "Old name should not exist"
        );
        assert_eq!(table.find_child(ROOT_INO, "Beta"), Some(original_ino));
    }

    /// Build a folder with one resolved file (cid="bafyOLDcid", keys set) at the
    /// given `modified_at`, returning the table and the file's inode number.
    #[cfg(test)]
    fn table_with_resolved_file(ipns_name: &str, modified_at: u64) -> (InodeTable, u64) {
        let mut table = InodeTable::new();
        let metadata = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "file-1".to_string(),
                name: "hello.txt".to_string(),
                file_meta_ipns_name: ipns_name.to_string(),
                ipns_private_key_encrypted: None,
                created_at: 1700000000000,
                modified_at,
            })],
        };
        let private_key = vec![0u8; 32];
        let public_key = vec![0u8; 33];
        table
            .populate_folder(ROOT_INO, &metadata, &private_key, &public_key, false)
            .unwrap();
        let child_ino = table.get(ROOT_INO).unwrap().children.as_ref().unwrap()[0];
        table.resolve_file_pointer(
            child_ino,
            "bafyOLDcid".to_string(),
            "enckey".to_string(),
            "iv123".to_string(),
            42,
            "GCM".to_string(),
            None,
        );
        if let Some(inode) = table.inodes.get_mut(&child_ino) {
            if let InodeKind::File {
                ref mut file_ipns_private_key,
                ref mut file_ipns_key_encrypted_hex,
                ..
            } = inode.kind
            {
                *file_ipns_private_key = Some(Zeroizing::new(vec![1u8; 32]));
                *file_ipns_key_encrypted_hex = Some("abcdef1234".to_string());
            }
        }
        (table, child_ino)
    }

    #[test]
    fn test_mark_remotely_edited_marks_newer_same_pointer() {
        let ipns_name = "k51qzi5uqu5dljtg5upm7x7ugan9lql3ewyknv4r4mhhkwzn8n7cnbd1unfwgx";
        let (mut table, child_ino) = table_with_resolved_file(ipns_name, 1700000000000);

        // Remote edit: same pointer + name, strictly newer modified_at.
        let metadata = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "file-1".to_string(),
                name: "hello.txt".to_string(),
                file_meta_ipns_name: ipns_name.to_string(),
                ipns_private_key_encrypted: None,
                created_at: 1700000000000,
                modified_at: 1700001000000, // 1000s later
            })],
        };

        // The remote-newer same-pointer file is flipped to unresolved in place (the
        // function returns ()); the assertions below verify the flip.
        table.mark_remotely_edited_files_unresolved(ROOT_INO, &metadata);

        let child = table.get(child_ino).unwrap();
        let expected_mtime = UNIX_EPOCH + Duration::from_millis(1700001000000);
        assert_eq!(
            child.attr.mtime, expected_mtime,
            "mtime adopts remote value"
        );
        assert_eq!(child.attr.size, 0, "stale resolved size cleared");
        assert_eq!(child.attr.blocks, 0, "stale resolved blocks cleared");
        match &child.kind {
            InodeKind::File {
                file_meta_resolved,
                cid,
                file_meta_ipns_name,
                file_ipns_private_key,
                file_ipns_key_encrypted_hex,
                ..
            } => {
                assert!(!file_meta_resolved, "should be unresolved");
                assert!(cid.is_empty(), "cid cleared for re-resolution");
                assert_eq!(file_meta_ipns_name.as_deref(), Some(ipns_name));
                assert!(
                    file_ipns_private_key.is_some(),
                    "IPNS key preserved (same pointer)"
                );
                assert_eq!(file_ipns_key_encrypted_hex.as_deref(), Some("abcdef1234"));
            }
            _ => panic!("Expected File"),
        }

        // Idempotent: now that it is unresolved, a second pass is a no-op (the guard
        // requires file_meta_resolved: true), leaving the inode untouched --
        // get_unresolved... drives the actual re-spawn instead.
        table.mark_remotely_edited_files_unresolved(ROOT_INO, &metadata);
        let child = table.get(child_ino).unwrap();
        assert_eq!(
            child.attr.mtime, expected_mtime,
            "second pass must not change the already-unresolved inode"
        );
        assert!(
            matches!(
                &child.kind,
                InodeKind::File {
                    file_meta_resolved: false,
                    ..
                }
            ),
            "still unresolved after second pass"
        );
    }

    #[test]
    fn test_mark_remotely_edited_preserves_local_mutations() {
        let ipns_name = "k51qzi5uqu5dljtg5upm7x7ugan9lql3ewyknv4r4mhhkwzn8n7cnbd1unfwgx";

        // Local inode sits at t=1700001000000 (a pending local mutation). Remote
        // metadata is OLDER (1700000000000) -- it must NOT clobber local state.
        let (mut table, child_ino) = table_with_resolved_file(ipns_name, 1700001000000);
        let stale_remote = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "file-1".to_string(),
                name: "hello.txt".to_string(),
                file_meta_ipns_name: ipns_name.to_string(),
                ipns_private_key_encrypted: None,
                created_at: 1700000000000,
                modified_at: 1700000000000, // older than local
            })],
        };
        // Older remote must NOT touch the local mutation -- the inode stays resolved.
        table.mark_remotely_edited_files_unresolved(ROOT_INO, &stale_remote);
        match &table.get(child_ino).unwrap().kind {
            InodeKind::File {
                file_meta_resolved,
                cid,
                ..
            } => {
                assert!(file_meta_resolved, "local state stays resolved");
                assert_eq!(cid, "bafyOLDcid", "local cid untouched");
            }
            _ => panic!("Expected File"),
        }

        // Equal modified_at is also a no-op (local wins on ties).
        let equal_remote = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "file-1".to_string(),
                name: "hello.txt".to_string(),
                file_meta_ipns_name: ipns_name.to_string(),
                ipns_private_key_encrypted: None,
                created_at: 1700000000000,
                modified_at: 1700001000000,
            })],
        };
        // Equal modified_at is also a no-op (local wins on ties): inode stays resolved.
        table.mark_remotely_edited_files_unresolved(ROOT_INO, &equal_remote);
        assert!(
            matches!(
                &table.get(child_ino).unwrap().kind,
                InodeKind::File {
                    file_meta_resolved: true,
                    ..
                }
            ),
            "equal modified_at is a no-op -- inode stays resolved"
        );
    }

    #[test]
    fn test_mark_remotely_edited_ignores_structural_changes() {
        let ipns_name = "k51qzi5uqu5dljtg5upm7x7ugan9lql3ewyknv4r4mhhkwzn8n7cnbd1unfwgx";
        let (mut table, _child_ino) = table_with_resolved_file(ipns_name, 1700000000000);
        let inode_count_before = table.inodes.len();

        // A brand-new remote file (no local inode) plus a folder child: neither is a
        // content edit of an existing resolved file, so nothing is marked and -- the
        // point of this path -- no structural inode is added while locally mutating.
        let metadata = FolderMetadata {
            version: "v2".to_string(),
            children: vec![
                FolderChild::File(cipherbox_core::folder::FilePointer {
                    id: "file-2".to_string(),
                    name: "brand-new.txt".to_string(),
                    file_meta_ipns_name: "k51qzi5uqu5dNEWfileADDEDremotelyABC123".to_string(),
                    ipns_private_key_encrypted: None,
                    created_at: 1700002000000,
                    modified_at: 1700002000000,
                }),
                FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                    id: "folder-1".to_string(),
                    name: "subfolder".to_string(),
                    ipns_name: "k51qzi5uqu5dSUBFOLDERref456".to_string(),
                    folder_key_encrypted: "00".to_string(),
                    ipns_private_key_encrypted: "00".to_string(),
                    created_at: 1700002000000,
                    modified_at: 1700002000000,
                }),
            ],
        };
        // Structural changes (new file, folder) are not content edits of an existing
        // resolved file, so nothing is flipped and -- the point of this path -- no
        // structural inode is added while locally mutating.
        table.mark_remotely_edited_files_unresolved(ROOT_INO, &metadata);
        assert_eq!(
            table.inodes.len(),
            inode_count_before,
            "no inodes added/removed by the content-only re-resolution path"
        );
    }

    #[test]
    fn test_populate_folder_resets_resolved_file_on_modified_at_change() {
        let mut table = InodeTable::new();

        let ipns_name = "k51qzi5uqu5dljtg5upm7x7ugan9lql3ewyknv4r4mhhkwzn8n7cnbd1unfwgx";

        // Initial population with a FilePointer
        let metadata_v1 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "file-1".to_string(),
                name: "hello.txt".to_string(),
                file_meta_ipns_name: ipns_name.to_string(),
                ipns_private_key_encrypted: None,
                created_at: 1700000000000,
                modified_at: 1700000000000,
            })],
        };

        let private_key = vec![0u8; 32];
        let public_key = vec![0u8; 33];
        table
            .populate_folder(ROOT_INO, &metadata_v1, &private_key, &public_key, false)
            .unwrap();

        let child_ino = table.get(ROOT_INO).unwrap().children.as_ref().unwrap()[0];

        // Simulate resolution: mark file as resolved with a CID
        table.resolve_file_pointer(
            child_ino,
            "bafyOLDcid".to_string(),
            "enckey".to_string(),
            "iv123".to_string(),
            42,
            "GCM".to_string(),
            None,
        );

        // Pre-populate IPNS key material on the resolved inode so we can
        // verify it is preserved (or cleared) after re-population.
        if let Some(inode) = table.inodes.get_mut(&child_ino) {
            if let InodeKind::File {
                ref mut file_ipns_private_key,
                ref mut file_ipns_key_encrypted_hex,
                ..
            } = inode.kind
            {
                *file_ipns_private_key = Some(Zeroizing::new(vec![1u8; 32]));
                *file_ipns_key_encrypted_hex = Some("abcdef1234".to_string());
            }
        }

        // Verify it's resolved with keys
        let child = table.get(child_ino).unwrap();
        match &child.kind {
            InodeKind::File {
                file_meta_resolved,
                cid,
                file_ipns_private_key,
                file_ipns_key_encrypted_hex,
                ..
            } => {
                assert!(file_meta_resolved);
                assert_eq!(cid, "bafyOLDcid");
                assert!(
                    file_ipns_private_key.is_some(),
                    "IPNS private key should be set"
                );
                assert_eq!(file_ipns_key_encrypted_hex.as_deref(), Some("abcdef1234"));
            }
            _ => panic!("Expected File kind"),
        }

        // Now re-populate with SAME modified_at -- should keep existing resolved data
        table
            .populate_folder(ROOT_INO, &metadata_v1, &private_key, &public_key, true)
            .unwrap();

        let child = table.get(child_ino).unwrap();
        match &child.kind {
            InodeKind::File {
                file_meta_resolved,
                cid,
                ..
            } => {
                assert!(
                    file_meta_resolved,
                    "File should remain resolved when modified_at unchanged"
                );
                assert_eq!(cid, "bafyOLDcid", "CID should be unchanged");
            }
            _ => panic!("Expected File kind"),
        }

        // Now re-populate with NEWER modified_at (same IPNS name) -- should reset
        // to unresolved but preserve IPNS keys since it's the same file pointer.
        let metadata_v2 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "file-1".to_string(),
                name: "hello.txt".to_string(),
                file_meta_ipns_name: ipns_name.to_string(),
                ipns_private_key_encrypted: None,
                created_at: 1700000000000,
                modified_at: 1700001000000, // 1000s later
            })],
        };

        table
            .populate_folder(ROOT_INO, &metadata_v2, &private_key, &public_key, true)
            .unwrap();

        let child = table.get(child_ino).unwrap();
        match &child.kind {
            InodeKind::File {
                file_meta_resolved,
                cid,
                file_meta_ipns_name,
                file_ipns_private_key,
                file_ipns_key_encrypted_hex,
                ..
            } => {
                assert!(
                    !file_meta_resolved,
                    "File should be unresolved after modified_at change"
                );
                assert!(cid.is_empty(), "CID should be cleared for re-resolution");
                assert_eq!(
                    file_meta_ipns_name.as_deref(),
                    Some(ipns_name),
                    "IPNS name should be preserved for re-resolution"
                );
                assert!(
                    file_ipns_private_key.is_some(),
                    "IPNS private key should be preserved for same pointer"
                );
                assert_eq!(
                    file_ipns_key_encrypted_hex.as_deref(),
                    Some("abcdef1234"),
                    "IPNS encrypted key hex should be preserved for same pointer"
                );
            }
            _ => panic!("Expected File kind"),
        }

        // Now simulate a file replacement: same name but different IPNS name.
        // IPNS keys should be cleared since this is a different file.
        let new_ipns_name = "k51qzi5uqu5dREPLACEDfileDIFFERENTipnsNAMEabcdef123456789";
        let metadata_v3 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "file-2".to_string(),
                name: "hello.txt".to_string(),
                file_meta_ipns_name: new_ipns_name.to_string(),
                ipns_private_key_encrypted: Some("newencryptedkey".to_string()),
                created_at: 1700000000000,
                modified_at: 1700002000000, // even later
            })],
        };

        // First resolve the inode again so we enter the was_resolved path
        table.resolve_file_pointer(
            child_ino,
            "bafyRESOLVED".to_string(),
            "enckey2".to_string(),
            "iv456".to_string(),
            99,
            "GCM".to_string(),
            None,
        );

        table
            .populate_folder(ROOT_INO, &metadata_v3, &private_key, &public_key, true)
            .unwrap();

        let child = table.get(child_ino).unwrap();
        match &child.kind {
            InodeKind::File {
                file_meta_resolved,
                file_meta_ipns_name,
                file_ipns_private_key,
                file_ipns_key_encrypted_hex,
                ..
            } => {
                assert!(
                    !file_meta_resolved,
                    "File should be unresolved after pointer replacement"
                );
                assert_eq!(
                    file_meta_ipns_name.as_deref(),
                    Some(new_ipns_name),
                    "IPNS name should be updated to new pointer's name"
                );
                assert!(
                    file_ipns_private_key.is_none(),
                    "IPNS private key should be cleared for different pointer"
                );
                assert_eq!(
                    file_ipns_key_encrypted_hex.as_deref(),
                    Some("newencryptedkey"),
                    "IPNS encrypted key should come from new FilePointer"
                );
            }
            _ => panic!("Expected File kind"),
        }
    }

    // --- D-11: inode stable-ID identity reset tests ---
    //
    // These tests verify that populate_folder distinguishes a stable-ID match
    // (ipns_to_ino lookup) from a display-name-only fallback (find_child), and
    // that a fallback-only match clears loaded state and forces re-resolution.

    // Test 1: stable-ID match preserves loaded state.
    // Seed a folder registered in ipns_to_ino (same ipns_name); on refresh the
    // children + children_loaded state must be preserved.
    #[test]
    fn d11_stable_id_match_preserves_children_loaded_state() {
        let (private_key, public_key) = generate_test_keypair();

        let folder_key_raw = vec![42u8; 32];
        let folder_key_encrypted_hex =
            hex::encode(cipherbox_crypto::ecies::wrap_key(&folder_key_raw, &public_key).unwrap());
        let ipns_key_raw = vec![7u8; 32];
        let ipns_key_encrypted_hex =
            hex::encode(cipherbox_crypto::ecies::wrap_key(&ipns_key_raw, &public_key).unwrap());

        let folder_ipns = "k51stable-id-test-folder";

        let mut table = InodeTable::new();

        // Initial population
        let meta_v1 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                id: "f1".to_string(),
                name: "MyFolder".to_string(),
                ipns_name: folder_ipns.to_string(),
                folder_key_encrypted: folder_key_encrypted_hex.clone(),
                ipns_private_key_encrypted: ipns_key_encrypted_hex.clone(),
                created_at: 1000,
                modified_at: 1000,
            })],
        };
        table
            .populate_folder(ROOT_INO, &meta_v1, &private_key, &public_key, false)
            .unwrap();

        let child_ino = {
            let root = table.get(ROOT_INO).unwrap();
            root.children.as_ref().unwrap()[0]
        };

        // Manually mark the folder as having children loaded with a child
        let child_ino_2 = table.allocate_ino();
        {
            let folder = table.get_mut(child_ino).unwrap();
            folder.children = Some(vec![child_ino_2]);
            if let InodeKind::Folder {
                ref mut children_loaded,
                ..
            } = folder.kind
            {
                *children_loaded = true;
            }
        }

        // Refresh with same ipns_name (stable-ID match) — same folder, different modified_at
        let meta_v2 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                id: "f1".to_string(),
                name: "MyFolder".to_string(),
                ipns_name: folder_ipns.to_string(), // SAME stable ID
                folder_key_encrypted: folder_key_encrypted_hex.clone(),
                ipns_private_key_encrypted: ipns_key_encrypted_hex.clone(),
                created_at: 1000,
                modified_at: 2000, // updated timestamp
            })],
        };
        table
            .populate_folder(ROOT_INO, &meta_v2, &private_key, &public_key, true)
            .unwrap();

        let refreshed = table.get(child_ino).unwrap();
        // D-11: stable-ID match MUST preserve children_loaded and children
        match &refreshed.kind {
            InodeKind::Folder {
                children_loaded, ..
            } => {
                assert!(
                    *children_loaded,
                    "D-11: stable-ID match must preserve children_loaded=true"
                );
            }
            _ => panic!("Expected Folder kind"),
        }
        assert_eq!(
            refreshed.children.as_ref().map(|v| v.len()),
            Some(1),
            "D-11: stable-ID match must preserve children list"
        );
    }

    // Test 2: display-name fallback resets loaded state.
    // Seed a folder reachable only via find_child (NOT in ipns_to_ino under the
    // incoming ipns_name) — matched_by_stable_id == false — so children must be
    // cleared to Some(vec![]) and children_loaded forced to false.
    #[test]
    fn d11_display_name_fallback_clears_loaded_state() {
        let (private_key, public_key) = generate_test_keypair();

        let folder_key_raw = vec![42u8; 32];
        let folder_key_encrypted_hex =
            hex::encode(cipherbox_crypto::ecies::wrap_key(&folder_key_raw, &public_key).unwrap());
        let ipns_key_raw = vec![7u8; 32];
        let ipns_key_encrypted_hex =
            hex::encode(cipherbox_crypto::ecies::wrap_key(&ipns_key_raw, &public_key).unwrap());

        let old_ipns = "k51old-ipns-name";
        let new_ipns = "k51new-ipns-name-different"; // different IPNS name = display-name fallback

        let mut table = InodeTable::new();

        // Seed with old_ipns — this puts the folder in ipns_to_ino under old_ipns
        let meta_v1 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                id: "f1".to_string(),
                name: "SharedFolder".to_string(),
                ipns_name: old_ipns.to_string(),
                folder_key_encrypted: folder_key_encrypted_hex.clone(),
                ipns_private_key_encrypted: ipns_key_encrypted_hex.clone(),
                created_at: 1000,
                modified_at: 1000,
            })],
        };
        table
            .populate_folder(ROOT_INO, &meta_v1, &private_key, &public_key, false)
            .unwrap();

        let child_ino = {
            let root = table.get(ROOT_INO).unwrap();
            root.children.as_ref().unwrap()[0]
        };

        // Manually mark the folder as children_loaded with some children
        let dummy_child_ino = table.allocate_ino();
        {
            let folder = table.get_mut(child_ino).unwrap();
            folder.children = Some(vec![dummy_child_ino]);
            if let InodeKind::Folder {
                ref mut children_loaded,
                ..
            } = folder.kind
            {
                *children_loaded = true;
            }
        }

        // Refresh with a DIFFERENT ipns_name but SAME display name "SharedFolder"
        // → ipns_to_ino lookup misses (new_ipns not registered), find_child hits by name
        // → matched_by_stable_id == false → identity changed → must clear loaded state
        let meta_v2 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::Folder(cipherbox_core::folder::FolderEntry {
                id: "f2".to_string(),
                name: "SharedFolder".to_string(), // same display name
                ipns_name: new_ipns.to_string(),  // DIFFERENT IPNS → display-name fallback
                folder_key_encrypted: folder_key_encrypted_hex.clone(),
                ipns_private_key_encrypted: ipns_key_encrypted_hex.clone(),
                created_at: 1000,
                modified_at: 2000,
            })],
        };
        table
            .populate_folder(ROOT_INO, &meta_v2, &private_key, &public_key, true)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        let refreshed_ino = root.children.as_ref().unwrap()[0];
        let refreshed = table.get(refreshed_ino).unwrap();

        // D-11: display-name fallback must clear children_loaded and children
        match &refreshed.kind {
            InodeKind::Folder {
                children_loaded, ..
            } => {
                assert!(
                    !*children_loaded,
                    "D-11: display-name fallback must clear children_loaded (force re-load)"
                );
            }
            _ => panic!("Expected Folder kind"),
        }
        assert_eq!(
            refreshed.children.as_ref().map(|v| v.len()),
            Some(0),
            "D-11: display-name fallback must clear children to empty vec"
        );
    }

    // Test 3: file pointer — display-name fallback forces same_pointer = false.
    // When the incoming FilePointer has a DIFFERENT file_meta_ipns_name than what
    // the inode holds, the inode should be treated as a different file and re-resolved.
    // Additionally, when matched only by display name (not by file_ipns_to_ino stable id),
    // same_pointer must be false regardless of IPNS name string comparison.
    #[test]
    fn d11_file_display_name_fallback_forces_re_resolution() {
        let mut table = InodeTable::new();

        let old_file_ipns = "k51old-file-ipns";
        let new_file_ipns = "k51new-file-ipns-different"; // different IPNS → pointer changed

        // Seed with old_file_ipns and simulate a resolved file state
        let meta_v1 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "fp1".to_string(),
                name: "document.txt".to_string(),
                file_meta_ipns_name: old_file_ipns.to_string(),
                ipns_private_key_encrypted: None,
                created_at: 1000,
                modified_at: 1000,
            })],
        };

        let private_key = vec![0u8; 32];
        let public_key = vec![0u8; 33];
        table
            .populate_folder(ROOT_INO, &meta_v1, &private_key, &public_key, false)
            .unwrap();

        let file_ino = {
            let root = table.get(ROOT_INO).unwrap();
            root.children.as_ref().unwrap()[0]
        };

        // Manually resolve the file and set a modified_at timestamp
        {
            let file = table.get_mut(file_ino).unwrap();
            file.attr.mtime = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1000);
            file.kind = InodeKind::File {
                cid: "bafyold".to_string(),
                encrypted_file_key: "oldkey".to_string(),
                iv: "oldiv".to_string(),
                size: 100,
                encryption_mode: "GCM".to_string(),
                file_meta_ipns_name: Some(old_file_ipns.to_string()),
                file_meta_resolved: true,
                file_ipns_private_key: Some(Zeroizing::new(vec![1u8; 32])),
                file_ipns_key_encrypted_hex: Some("oldencryptedkey".to_string()),
                versions: None,
            };
        }

        // Refresh with a DIFFERENT file_meta_ipns_name AND a modified_at that triggers
        // the re-resolution path (modified_at changed). Since the new IPNS name is
        // different, this is NOT in file_ipns_to_ino → display-name fallback.
        // D-11: the different file_meta_ipns_name must force same_pointer = false
        // → IPNS private key NOT preserved (it belongs to the old IPNS identity).
        let meta_v2 = FolderMetadata {
            version: "v2".to_string(),
            children: vec![FolderChild::File(cipherbox_core::folder::FilePointer {
                id: "fp2".to_string(),
                name: "document.txt".to_string(), // same display name
                file_meta_ipns_name: new_file_ipns.to_string(), // DIFFERENT IPNS → fallback
                ipns_private_key_encrypted: Some("newencryptedkey".to_string()),
                created_at: 1000,
                modified_at: 2000, // changed → triggers re-resolution path
            })],
        };

        table
            .populate_folder(ROOT_INO, &meta_v2, &private_key, &public_key, true)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        let refreshed_ino = root.children.as_ref().unwrap()[0];
        let refreshed = table.get(refreshed_ino).unwrap();

        match &refreshed.kind {
            InodeKind::File {
                file_meta_ipns_name,
                file_meta_resolved,
                file_ipns_private_key,
                ..
            } => {
                // D-11: file_meta_ipns_name must be the new pointer's IPNS name
                assert_eq!(
                    file_meta_ipns_name.as_deref(),
                    Some(new_file_ipns),
                    "D-11: new IPNS name must be set on display-name fallback"
                );
                assert!(
                    !*file_meta_resolved,
                    "D-11: file must be unresolved after identity reset (display-name fallback)"
                );
                // D-11: IPNS private key must NOT be preserved from the old identity
                // (same_pointer = false means we use the new FilePointer's encrypted key,
                //  not the old private key from the stale identity)
                assert!(
                    file_ipns_private_key.is_none(),
                    "D-11: IPNS private key from old identity must NOT be preserved on fallback"
                );
            }
            _ => panic!("Expected File kind"),
        }
    }

    // ---- Finding B / T-59-02: file_meta_ipns_name change forces re-resolution ----
    //
    // These tests verify that when a resolved file's `file_meta_ipns_name` changes
    // (same mtime), `populate_folder` marks it unresolved instead of carrying over
    // the stale CID/keys.  The mtime-change path is also regression-guarded.

    /// Helper: seed a resolved file inode in the table under root and return
    /// the file's ino.
    fn seed_resolved_file(table: &mut InodeTable, ipns_name: &str, mtime_ms: u64) -> u64 {
        // Initial population with a placeholder FilePointer
        let meta = cipherbox_core::FolderMetadata {
            version: "v2".to_string(),
            children: vec![cipherbox_core::FolderChild::File(
                cipherbox_core::folder::FilePointer {
                    id: "fp-seed".to_string(),
                    name: "report.txt".to_string(),
                    file_meta_ipns_name: ipns_name.to_string(),
                    ipns_private_key_encrypted: None,
                    created_at: 1000,
                    modified_at: mtime_ms,
                },
            )],
        };
        let private_key = vec![0u8; 32];
        let public_key = vec![0u8; 33];
        table
            .populate_folder(ROOT_INO, &meta, &private_key, &public_key, false)
            .unwrap();

        let file_ino = {
            let root = table.get(ROOT_INO).unwrap();
            root.children.as_ref().unwrap()[0]
        };

        // Manually mark as resolved with the stable ipns_name
        {
            let file = table.get_mut(file_ino).unwrap();
            file.attr.mtime = std::time::UNIX_EPOCH + std::time::Duration::from_millis(mtime_ms);
            file.kind = InodeKind::File {
                cid: "bafyoriginal".to_string(),
                encrypted_file_key: "originalkey".to_string(),
                iv: "originaliv".to_string(),
                size: 42,
                encryption_mode: "GCM".to_string(),
                file_meta_ipns_name: Some(ipns_name.to_string()),
                file_meta_resolved: true,
                file_ipns_private_key: Some(Zeroizing::new(vec![9u8; 32])),
                file_ipns_key_encrypted_hex: Some("enckeyhex".to_string()),
                versions: None,
            };
        }
        file_ino
    }

    /// Test 1 (RED): A resolved file with the SAME mtime but a DIFFERENT
    /// `file_meta_ipns_name` (incoming pointer is a different identity) MUST be
    /// marked `file_meta_resolved: false` so stale CID/keys are not carried over.
    ///
    /// This test is RED under the broken code (which only checks mtime) and GREEN
    /// after the fix (which also checks pointer identity).
    #[test]
    fn upsert_children_file_same_mtime_different_ipns_name_marks_unresolved() {
        let mut table = InodeTable::new();
        let old_ipns = "k51old-file-ipns";
        let new_ipns = "k51new-file-different";
        let mtime_ms = 5000u64;

        let _file_ino = seed_resolved_file(&mut table, old_ipns, mtime_ms);

        // Refresh with a DIFFERENT ipns_name but the SAME mtime.
        // Bug: the current code returns (true, Some(existing.kind.clone())) here,
        // carrying over stale resolved state.  Fix: must return (true, None) when
        // file_meta_ipns_name differs.
        let meta_v2 = cipherbox_core::FolderMetadata {
            version: "v2".to_string(),
            children: vec![cipherbox_core::FolderChild::File(
                cipherbox_core::folder::FilePointer {
                    id: "fp-v2".to_string(),
                    name: "report.txt".to_string(),
                    file_meta_ipns_name: new_ipns.to_string(), // DIFFERENT pointer identity
                    ipns_private_key_encrypted: None,
                    created_at: 1000,
                    modified_at: mtime_ms, // SAME mtime — only name changed
                },
            )],
        };
        let private_key = vec![0u8; 32];
        let public_key = vec![0u8; 33];
        table
            .populate_folder(ROOT_INO, &meta_v2, &private_key, &public_key, true)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        let refreshed_ino = root.children.as_ref().unwrap()[0];
        let refreshed = table.get(refreshed_ino).unwrap();
        match &refreshed.kind {
            InodeKind::File {
                file_meta_resolved,
                file_meta_ipns_name,
                ..
            } => {
                assert!(
                    !*file_meta_resolved,
                    "Finding B: file with changed file_meta_ipns_name (same mtime) MUST be \
                     marked file_meta_resolved=false; got true (stale state carried over)"
                );
                assert_eq!(
                    file_meta_ipns_name.as_deref(),
                    Some(new_ipns),
                    "Finding B: new ipns name must be set after pointer-identity change"
                );
            }
            _ => panic!("Expected File kind"),
        }
    }

    /// Test 2: A resolved file with the SAME mtime AND the SAME `file_meta_ipns_name`
    /// keeps `file_meta_resolved: true` (no spurious re-resolution when the pointer
    /// is unchanged).
    #[test]
    fn upsert_children_file_same_mtime_same_ipns_name_stays_resolved() {
        let mut table = InodeTable::new();
        let ipns = "k51same-file-ipns";
        let mtime_ms = 5000u64;

        let _file_ino = seed_resolved_file(&mut table, ipns, mtime_ms);

        // Refresh with the SAME ipns_name AND same mtime — no re-resolution needed.
        let meta_v2 = cipherbox_core::FolderMetadata {
            version: "v2".to_string(),
            children: vec![cipherbox_core::FolderChild::File(
                cipherbox_core::folder::FilePointer {
                    id: "fp-v2".to_string(),
                    name: "report.txt".to_string(),
                    file_meta_ipns_name: ipns.to_string(), // SAME pointer identity
                    ipns_private_key_encrypted: None,
                    created_at: 1000,
                    modified_at: mtime_ms, // SAME mtime
                },
            )],
        };
        let private_key = vec![0u8; 32];
        let public_key = vec![0u8; 33];
        table
            .populate_folder(ROOT_INO, &meta_v2, &private_key, &public_key, true)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        let refreshed_ino = root.children.as_ref().unwrap()[0];
        let refreshed = table.get(refreshed_ino).unwrap();
        match &refreshed.kind {
            InodeKind::File {
                file_meta_resolved, ..
            } => {
                assert!(
                    *file_meta_resolved,
                    "Finding B: file with same mtime and same ipns_name MUST stay resolved"
                );
            }
            _ => panic!("Expected File kind"),
        }
    }

    /// Test 3 (regression guard): A file with a CHANGED mtime still triggers
    /// re-resolution regardless of ipns_name (the existing mtime path is unchanged).
    #[test]
    fn upsert_children_file_changed_mtime_marks_unresolved_regression_guard() {
        let mut table = InodeTable::new();
        let ipns = "k51unchanged-file-ipns";
        let mtime_ms = 5000u64;

        let _file_ino = seed_resolved_file(&mut table, ipns, mtime_ms);

        // Refresh with CHANGED mtime → must force re-resolution (existing behavior).
        let meta_v2 = cipherbox_core::FolderMetadata {
            version: "v2".to_string(),
            children: vec![cipherbox_core::FolderChild::File(
                cipherbox_core::folder::FilePointer {
                    id: "fp-v2".to_string(),
                    name: "report.txt".to_string(),
                    file_meta_ipns_name: ipns.to_string(), // same name
                    ipns_private_key_encrypted: None,
                    created_at: 1000,
                    modified_at: mtime_ms + 1000, // CHANGED mtime
                },
            )],
        };
        let private_key = vec![0u8; 32];
        let public_key = vec![0u8; 33];
        table
            .populate_folder(ROOT_INO, &meta_v2, &private_key, &public_key, true)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        let refreshed_ino = root.children.as_ref().unwrap()[0];
        let refreshed = table.get(refreshed_ino).unwrap();
        match &refreshed.kind {
            InodeKind::File {
                file_meta_resolved, ..
            } => {
                assert!(
                    !*file_meta_resolved,
                    "Regression guard: changed mtime must still force re-resolution"
                );
            }
            _ => panic!("Expected File kind"),
        }
    }

    /// CR-553 (PR #553 CodeRabbit Major, workflow-verified real bug): a pointer swap
    /// must hydrate the NEW pointer's raw IPNS signing key from its
    /// `ipns_private_key_encrypted`, not leave `file_ipns_private_key: None`. With None,
    /// `resolve_file_pointer` carries None forward (file_meta_resolved flips to true while
    /// the raw key stays None), so the swapped file can be read but never publishes per-file
    /// IPNS updates and is skipped on cross-folder-move re-encryption (both read the raw key
    /// directly from this inode field).
    #[test]
    fn upsert_children_pointer_swap_hydrates_new_ipns_signing_key() {
        // Real ECIES keypair so wrap/unwrap round-trips (a zero key is not a valid point).
        let (sk, pk) = ecies::utils::generate_keypair();
        let private_key = sk.serialize().to_vec(); // 32 bytes
        let public_key = pk.serialize().to_vec(); // 33 bytes (compressed)

        let mut table = InodeTable::new();
        let old_ipns = "k51old-swap-file";
        let new_ipns = "k51new-swap-file";
        let mtime_ms = 7000u64;
        let _file_ino = seed_resolved_file(&mut table, old_ipns, mtime_ms);

        // The NEW pointer's per-file IPNS private key, wrapped to public_key.
        let new_file_ipns_key = vec![3u8; 32];
        let wrapped = cipherbox_crypto::ecies::wrap_key(&new_file_ipns_key, &public_key).unwrap();
        let encrypted_hex = hex::encode(&wrapped);

        // Refresh with a DIFFERENT ipns_name (pointer swap) under the SAME mtime,
        // carrying the new pointer's encrypted IPNS key.
        let meta_v2 = cipherbox_core::FolderMetadata {
            version: "v2".to_string(),
            children: vec![cipherbox_core::FolderChild::File(
                cipherbox_core::folder::FilePointer {
                    id: "fp-swap".to_string(),
                    name: "report.txt".to_string(),
                    file_meta_ipns_name: new_ipns.to_string(),
                    ipns_private_key_encrypted: Some(encrypted_hex),
                    created_at: 1000,
                    modified_at: mtime_ms, // SAME mtime — only pointer identity changed
                },
            )],
        };
        table
            .populate_folder(ROOT_INO, &meta_v2, &private_key, &public_key, true)
            .unwrap();

        let root = table.get(ROOT_INO).unwrap();
        let refreshed_ino = root.children.as_ref().unwrap()[0];
        let refreshed = table.get(refreshed_ino).unwrap();
        match &refreshed.kind {
            InodeKind::File {
                file_meta_resolved,
                file_meta_ipns_name,
                file_ipns_private_key,
                ..
            } => {
                assert!(
                    !*file_meta_resolved,
                    "pointer swap must mark the file unresolved for re-resolution"
                );
                assert_eq!(
                    file_meta_ipns_name.as_deref(),
                    Some(new_ipns),
                    "the new pointer identity must be recorded"
                );
                let raw = file_ipns_private_key.as_ref().expect(
                    "CR-553: swapped pointer's raw IPNS signing key must be hydrated, not None",
                );
                assert_eq!(
                    raw.as_slice(),
                    new_file_ipns_key.as_slice(),
                    "hydrated key must equal the unwrapped new-pointer key"
                );
            }
            _ => panic!("Expected File kind"),
        }
    }
}
