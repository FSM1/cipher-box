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
// the symmetric NodeKind discriminator. The legacy
// `cipherbox_core::folder::{FolderMetadata, FolderChild}` types are no longer
// consumed anywhere in this module — the inode table now materializes children
// exclusively from `cipherbox_sdk::ResolvedOwnedChild` (69-09 Slice 5c).
use cipherbox_core::node::NodeKind;
use cipherbox_sdk::ResolvedOwnedChild;

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
    /// The node's STABLE own id (`PublishedNode.id` == the D-07
    /// `WriteChildRef.child_id` == the seal AAD).
    ///
    /// This is the child-identity key the parent's write plane pairs on. It is
    /// assigned ONCE and never re-derived from the (client-local, non-portable)
    /// inode number: `uuid_from_ino(ino)` at creation, or the child's remote
    /// `published.id` when materialized from a listing
    /// (`apply_owned_children`). Publish paths (`build_folder_metadata`, the
    /// per-file publish, the upload journal) MUST use this value, NOT
    /// `uuid_from_ino(local_ino)` — otherwise a parent re-published after a
    /// re-materialization keys the child's `WriteChildRef` by a fresh local ino
    /// that no longer matches the child node's real id, and `list_folder_owned`
    /// fails the D-07 read/write pairing.
    pub node_id: String,
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
            // Root's stable id preserves the pre-node_id behavior exactly:
            // build_folder_metadata sealed the root under uuid_from_ino(ROOT_INO).
            node_id: crate::fs::uuid_from_ino(ROOT_INO),
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
                node_id,
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
                        // D-07: persist the child's REAL id, not uuid_from_ino(ino)
                        // (this materialized ino may differ from the creator's).
                        node_id: node_id.clone(),
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
                        // D-07: persist the child's REAL id, not uuid_from_ino(ino)
                        // (this materialized ino may differ from the creator's).
                        node_id: node_id.clone(),
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

    // ── node/v3 test fixtures ───────────────────────────────────────────────
    //
    // 69-09 Slice 5c: the legacy-model inode tests (5-arg `populate_folder`
    // taking `&FolderMetadata`, `resolve_file_pointer` with the removed
    // `encrypted_file_key`/`versions` args, and the ECIES-keypair
    // `mark_remotely_edited` round-trips) were DELETED — they asserted the
    // intentionally-removed pre-node/v3 crypto model and porting them risks
    // false-green. Deep node-to-node crypto correctness is covered by the SDK
    // listing/seal vectors and the later sdk-e2e/desktop-e2e gate. The tests
    // below KEEP the non-crypto inode-table MECHANICS (id allocation, insert/
    // find/remove, NFC name handling) and ADD node/v3 `apply_owned_children`
    // fake-materialization smoke tests exercising the sync-apply half of the
    // refresh pipeline (stable-ipns-name ino reuse, children_loaded marking,
    // file placeholder + `resolve_file_pointer` fill).

    /// Build a node/v3 `ResolvedOwnedChild` fixture with deterministic keys.
    fn owned_child(
        ipns: &str,
        name: &str,
        kind: NodeKind,
        size: Option<u64>,
    ) -> ResolvedOwnedChild {
        ResolvedOwnedChild {
            child: cipherbox_sdk::ResolvedChild {
                ipns_name: ipns.to_string(),
                name: name.to_string(),
                kind,
                size,
                modified_at: 1000,
                sequence: 1,
            },
            // A materialized child carries a REAL remote id distinct from any
            // uuid_from_ino(local_ino) — derive a stable fixture id from the ipns.
            node_id: format!("nodeid-{ipns}"),
            read_key: Zeroizing::new([0x11u8; 32]),
            write_key: Zeroizing::new([0x22u8; 32]),
            ipns_private_key: Zeroizing::new(vec![0x33u8; 32]),
        }
    }

    /// Construct a `Folder` InodeData with node/v3 key material (mechanics tests).
    fn folder_inode(table: &InodeTable, parent: u64, name: &str, ipns: &str) -> InodeData {
        let ino = table.allocate_ino();
        let now = SystemTime::now();
        InodeData {
            ino,
            node_id: crate::fs::uuid_from_ino(ino),
            parent_ino: parent,
            name: name.to_string(),
            kind: InodeKind::Folder {
                ipns_name: ipns.to_string(),
                read_key: Zeroizing::new([0u8; 32]),
                write_key: Zeroizing::new([0u8; 32]),
                ipns_private_key: Zeroizing::new(vec![0u8; 32]),
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
        }
    }

    // ── mechanics: table construction / id allocation ───────────────────────

    #[test]
    fn test_inode_table_new_has_root() {
        let table = InodeTable::new();
        let root = table.get(ROOT_INO).expect("root exists");
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

    // ── mechanics: insert / find / remove / name handling ───────────────────

    #[test]
    fn test_insert_and_find_child() {
        let mut table = InodeTable::new();
        let data = folder_inode(&table, ROOT_INO, "documents", "k51test");
        let ino = data.ino;
        table.insert(data);

        assert_eq!(table.find_child(ROOT_INO, "documents"), Some(ino));
        assert_eq!(table.get(ino).unwrap().name, "documents");
    }

    #[test]
    fn test_find_child_not_found() {
        let table = InodeTable::new();
        assert_eq!(table.find_child(ROOT_INO, "nonexistent"), None);
    }

    #[test]
    fn test_remove_inode_clears_name_index() {
        let mut table = InodeTable::new();
        let data = folder_inode(&table, ROOT_INO, "gone", "k51gone");
        let ino = data.ino;
        table.insert(data);
        assert!(table.find_child(ROOT_INO, "gone").is_some());

        table.remove(ino);
        assert!(table.get(ino).is_none());
        assert_eq!(table.find_child(ROOT_INO, "gone"), None);
    }

    #[test]
    fn test_find_child_nfc_normalizes_unicode() {
        let mut table = InodeTable::new();
        // Composed 'é' (U+00E9) stored; decomposed 'e' + combining acute looked up.
        let data = folder_inode(&table, ROOT_INO, "caf\u{00e9}", "k51nfc");
        let ino = data.ino;
        table.insert(data);
        // NFD form must resolve to the same inode via NFC normalization.
        assert_eq!(table.find_child(ROOT_INO, "cafe\u{0301}"), Some(ino));
    }

    // ── node/v3 apply_owned_children (sync-apply refresh half) ──────────────

    #[test]
    fn apply_owned_children_populates_and_marks_loaded() {
        let mut table = InodeTable::new();
        let resolved = vec![
            owned_child("k51folderA", "folderA", NodeKind::Folder, None),
            owned_child("k51fileB", "fileB.txt", NodeKind::File, Some(1024)),
        ];
        table.apply_owned_children(ROOT_INO, resolved, false);

        // Both children linked under root.
        let folder_ino = table
            .find_child(ROOT_INO, "folderA")
            .expect("folder linked");
        let file_ino = table
            .find_child(ROOT_INO, "fileB.txt")
            .expect("file linked");

        // Folder carries moved-in node/v3 keys.
        match &table.get(folder_ino).unwrap().kind {
            InodeKind::Folder {
                read_key,
                write_key,
                ..
            } => {
                assert_eq!(**read_key, [0x11u8; 32]);
                assert_eq!(**write_key, [0x22u8; 32]);
            }
            other => panic!("expected Folder, got {:?}", other),
        }

        // File is materialized as a placeholder (empty cid == unresolved).
        match &table.get(file_ino).unwrap().kind {
            InodeKind::File { cid, size, .. } => {
                assert!(cid.is_empty(), "fresh file must be unresolved (empty cid)");
                assert_eq!(*size, 1024);
            }
            other => panic!("expected File, got {:?}", other),
        }

        // Parent root marked as having loaded children.
        assert_eq!(
            table
                .get(ROOT_INO)
                .unwrap()
                .children
                .as_ref()
                .map(|c| c.len()),
            Some(2)
        );
        // The freshly-populated file surfaces as unresolved.
        let unresolved = table.get_unresolved_file_pointers_for_parent(ROOT_INO);
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].0, file_ino);
    }

    #[test]
    fn apply_owned_children_reuses_ino_on_rename_by_ipns_name() {
        let mut table = InodeTable::new();
        table.apply_owned_children(
            ROOT_INO,
            vec![owned_child("k51stable", "old-name", NodeKind::Folder, None)],
            false,
        );
        let first_ino = table.find_child(ROOT_INO, "old-name").expect("linked");

        // Same ipns_name, new display name => rename, ino must be reused (NFS-stable).
        table.apply_owned_children(
            ROOT_INO,
            vec![owned_child("k51stable", "new-name", NodeKind::Folder, None)],
            false,
        );
        let renamed_ino = table
            .find_child(ROOT_INO, "new-name")
            .expect("renamed linked");
        assert_eq!(
            first_ino, renamed_ino,
            "ino reused across rename by ipns_name"
        );
        // Stale display-name index dropped.
        assert_eq!(table.find_child(ROOT_INO, "old-name"), None);
    }

    #[test]
    fn apply_owned_children_merge_only_preserves_absent_children() {
        let mut table = InodeTable::new();
        table.apply_owned_children(
            ROOT_INO,
            vec![
                owned_child("k51keep", "keep", NodeKind::Folder, None),
                owned_child("k51local", "local-only", NodeKind::Folder, None),
            ],
            false,
        );
        // A refresh that only re-lists "keep" must NOT drop "local-only" under merge_only.
        table.apply_owned_children(
            ROOT_INO,
            vec![owned_child("k51keep", "keep", NodeKind::Folder, None)],
            true,
        );
        assert!(table.find_child(ROOT_INO, "keep").is_some());
        assert!(
            table.find_child(ROOT_INO, "local-only").is_some(),
            "merge_only must preserve children absent from the remote listing"
        );
    }

    #[test]
    fn resolve_file_pointer_fills_descriptors() {
        let mut table = InodeTable::new();
        table.apply_owned_children(
            ROOT_INO,
            vec![owned_child("k51file", "doc.pdf", NodeKind::File, Some(10))],
            false,
        );
        let ino = table.find_child(ROOT_INO, "doc.pdf").unwrap();

        table.resolve_file_pointer(
            ino,
            "bafyCID".to_string(),
            "abcd".to_string(),
            42,
            "GCM".to_string(),
        );

        match &table.get(ino).unwrap().kind {
            InodeKind::File {
                cid,
                iv,
                size,
                encryption_mode,
                ..
            } => {
                assert_eq!(cid, "bafyCID");
                assert_eq!(iv, "abcd");
                assert_eq!(*size, 42);
                assert_eq!(encryption_mode, "GCM");
            }
            other => panic!("expected File, got {:?}", other),
        }
        // Now resolved: no longer surfaced as an unresolved pointer.
        assert!(table
            .get_unresolved_file_pointers_for_parent(ROOT_INO)
            .is_empty());
    }
}
