//! WinFsp FileSystemContext implementation for CipherBoxFS.
//!
//! Delegates to category-specific modules:
//! - `read_ops`: get_volume_info, get_security_by_name, open, close, read, get_file_info, get_security, flush
//! - `write_ops`: create, write, overwrite, cleanup, set_basic_info, set_file_size, set_delete, rename
//! - `dir_ops`: read_directory
//!
//! Uses `Arc<Mutex<CipherBoxFS>>` for interior mutability (WinFsp callbacks
//! receive `&self`, not `&mut self`, because the driver invokes callbacks on
//! any thread).
//!
//! Path resolution: WinFsp is path-based (receives `\folder\file.txt`), while
//! the inode table uses parent_ino + name lookups. `resolve_path()` bridges
//! this by walking the inode table component-by-component from the root.

#[cfg(feature = "winfsp")]
pub mod implementation {
    use std::ffi::c_void;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use widestring::U16CStr;
    use winfsp::filesystem::{DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo};
    use winfsp::FspError;

    use crate::inode::{FileAttrs, ROOT_INO};
    use crate::CipherBoxFS;

    // Re-export is_windows_special so sub-modules can import from here
    pub use crate::helpers::is_windows_special;

    // ── NTSTATUS error helpers ─────────────────────────────────────────
    // FspError::IO cannot be used in const context since ErrorKind may not be
    // const-constructible, so we use inline functions.
    pub fn status_object_name_not_found() -> FspError {
        FspError::NTSTATUS(0xC0000034_u32 as i32)
    }
    pub fn status_invalid_parameter() -> FspError {
        FspError::NTSTATUS(0xC000000D_u32 as i32)
    }
    pub fn status_object_name_collision() -> FspError {
        FspError::NTSTATUS(0xC0000035_u32 as i32)
    }
    pub fn status_directory_not_empty() -> FspError {
        FspError::NTSTATUS(0xC0000101_u32 as i32)
    }
    pub fn status_invalid_handle() -> FspError {
        FspError::NTSTATUS(0xC0000008_u32 as i32)
    }
    pub fn status_io_device_error() -> FspError {
        FspError::IO(std::io::ErrorKind::Other)
    }
    pub fn status_device_not_ready() -> FspError {
        FspError::NTSTATUS(0xC00000A3_u32 as i32)
    }
    pub fn status_access_denied() -> FspError {
        FspError::NTSTATUS(0xC0000022_u32 as i32)
    }

    /// Permissive self-relative security descriptor granting FILE_ALL_ACCESS
    /// to Everyone (S-1-1-0). CipherBox is single-user; encryption is the real
    /// access control, so we grant full NTFS permissions.
    ///
    /// Layout: 20-byte header, 28-byte DACL (one ACE), 12-byte Owner, 12-byte Group.
    ///
    /// Without a valid descriptor, WinFsp's `FspFileSystemOpenCheck()` strips
    /// DELETE access from `GrantedAccess` when `SecurityDescriptorSize == 0`,
    /// which prevents directory deletion via `Remove-Item` / `RemoveDirectory()`.
    pub static PERMISSIVE_SD: [u8; 72] = [
        // ── SECURITY_DESCRIPTOR header (20 bytes) ──
        0x01, // Revision
        0x00, // Sbz1
        0x04, 0x80, // Control: SE_SELF_RELATIVE | SE_DACL_PRESENT
        0x30, 0x00, 0x00, 0x00, // OwnerOffset = 48
        0x3C, 0x00, 0x00, 0x00, // GroupOffset = 60
        0x00, 0x00, 0x00, 0x00, // SaclOffset = 0 (none)
        0x14, 0x00, 0x00, 0x00, // DaclOffset = 20
        // ── ACL header (8 bytes) ──
        0x02, // AclRevision
        0x00, // Sbz1
        0x1C, 0x00, // AclSize = 28
        0x01, 0x00, // AceCount = 1
        0x00, 0x00, // Sbz2
        // ── ACCESS_ALLOWED_ACE (20 bytes) ──
        0x00, // AceType = ACCESS_ALLOWED
        0x00, // AceFlags
        0x14, 0x00, // AceSize = 20
        0xFF, 0x01, 0x1F, 0x00, // Mask = FILE_ALL_ACCESS (0x001F01FF)
        // SID: S-1-1-0 (Everyone)
        0x01, 0x01, // Revision, SubAuthorityCount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IdentifierAuthority
        0x00, 0x00, 0x00, 0x00, // SubAuthority[0]
        // ── Owner SID: S-1-1-0 (12 bytes) ──
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // ── Group SID: S-1-1-0 (12 bytes) ──
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    // ── WinFsp Context Types ───────────────────────────────────────────────

    /// WinFsp filesystem context wrapping the shared CipherBoxFS.
    ///
    /// All callbacks receive `&self`, so we use `Arc<Mutex<CipherBoxFS>>` for
    /// interior mutability. The tokio runtime handle is used for blocking on
    /// async operations from WinFsp's synchronous callback threads.
    pub struct WinFspContext {
        pub inner: Arc<Mutex<CipherBoxFS>>,
        pub rt: tokio::runtime::Handle,
    }

    /// Lightweight file context returned from open/create.
    /// References into CipherBoxFS.open_files via file handle ID.
    pub struct WinFspFileContext {
        pub fh: u64,
        pub ino: u64,
        pub is_dir: bool,
    }

    // ── Path Resolution ────────────────────────────────────────────────────

    /// Resolve a Windows-style path (`\folder\subfolder\file.txt`) to (ino, parent_ino).
    /// Returns None if any component is not found.
    pub fn resolve_path(fs: &CipherBoxFS, path: &str) -> Option<(u64, u64)> {
        let path = path.trim_start_matches('\\');
        if path.is_empty() {
            return Some((ROOT_INO, ROOT_INO));
        }
        let mut current_ino = ROOT_INO;
        let mut parent_ino = ROOT_INO;
        for component in path.split('\\').filter(|c| !c.is_empty()) {
            parent_ino = current_ino;
            match fs.inodes.find_child(current_ino, component) {
                Some(child_ino) => current_ino = child_ino,
                None => return None,
            }
        }
        Some((current_ino, parent_ino))
    }

    /// Split a Windows path into (parent_path, file_name).
    /// e.g. `\Documents\hello.txt` -> (`\Documents`, `hello.txt`)
    /// Root path `\` or `\hello.txt` -> (`\`, `hello.txt`)
    pub fn split_path(path: &str) -> (&str, &str) {
        match path.rfind('\\') {
            Some(pos) => {
                let parent = if pos == 0 { "\\" } else { &path[..pos] };
                let name = &path[pos + 1..];
                (parent, name)
            }
            None => ("\\", path),
        }
    }

    // ── FileInfo Conversion ────────────────────────────────────────────────

    /// Convert a SystemTime to Windows FILETIME (100-nanosecond intervals
    /// since 1601-01-01). Returns 0 if the time is before the Unix epoch.
    pub fn systemtime_to_filetime(t: SystemTime) -> u64 {
        // Windows FILETIME epoch: 1601-01-01 00:00:00 UTC
        // Unix epoch: 1970-01-01 00:00:00 UTC
        // Difference: 11644473600 seconds = 116444736000000000 in 100ns intervals
        const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => {
                let hundred_ns = d.as_secs() * 10_000_000 + d.subsec_nanos() as u64 / 100;
                hundred_ns + EPOCH_DIFF
            }
            Err(_) => 0,
        }
    }

    /// Convert Windows FILETIME to SystemTime. Returns UNIX_EPOCH if invalid.
    pub fn filetime_to_systemtime(ft: u64) -> SystemTime {
        const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
        if ft < EPOCH_DIFF {
            return UNIX_EPOCH;
        }
        let hundred_ns = ft - EPOCH_DIFF;
        let secs = hundred_ns / 10_000_000;
        let nanos = (hundred_ns % 10_000_000) * 100;
        UNIX_EPOCH + Duration::new(secs, nanos as u32)
    }

    /// Populate a WinFsp FileInfo from our platform-agnostic FileAttrs.
    pub fn fill_file_info(attrs: &FileAttrs) -> FileInfo {
        let mut info = FileInfo::default();
        info.file_attributes = if attrs.is_dir {
            0x10 // FILE_ATTRIBUTE_DIRECTORY
        } else {
            0x80 // FILE_ATTRIBUTE_NORMAL
        };
        info.file_size = attrs.size;
        info.allocation_size = (attrs.size + 4095) & !4095; // round up to 4K
        info.creation_time = systemtime_to_filetime(attrs.crtime);
        info.last_access_time = systemtime_to_filetime(attrs.atime);
        info.last_write_time = systemtime_to_filetime(attrs.mtime);
        info.change_time = systemtime_to_filetime(attrs.ctime);
        info
    }

    // ── Helper functions ───────────────────────────────────────────────────

    /// Synchronous (WinFsp-callback-thread) node/v3 content fetch + decrypt.
    ///
    /// SC#1 (69-14): the former node-to-node ECIES file-content-key unwrap is
    /// GONE. node/v3 recovers the content descriptors + file_key by SYMMETRIC
    /// unseal of the file node's OWN read-body — this now takes the file's
    /// `ipns_name` + its `read_key` and resolves the node through the gated
    /// [`cipherbox_sdk::fetch_node_gated`] wrapper (SC#6) via
    /// `crate::content_ops::fetch_node_and_decrypt_content`. `read_key` is a
    /// caller-owned borrow (D-09). Bounded by the Windows 10s
    /// `crate::block_with_timeout` (A2 scope narrowing — the macOS FUSE path
    /// keeps its own private 3s timeout copy in operations.rs).
    pub fn fetch_and_decrypt_file_content(
        fs: &CipherBoxFS,
        ipns_name: &str,
        read_key: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let api = fs.api.clone();
        let high_water = fs.high_water.clone();
        let ipns_owned = ipns_name.to_string();
        let read_key_owned = *read_key;
        let rt = fs.rt.clone();

        crate::block_with_timeout(&rt, async move {
            crate::content_ops::fetch_node_and_decrypt_content(
                &api,
                &high_water,
                &ipns_owned,
                &read_key_owned,
            )
            .await
        })
    }

    // Re-export shared async helpers from content_ops (Tier-2 dedup, Plan 55-03).
    // fetch_node_and_decrypt_content and publish_file_node are identical between
    // macOS and Windows; they are now in the shared content_ops module.
    // fetch_and_decrypt_file_content (sync wrapper, uses crate::block_with_timeout
    // with 10s timeout) stays defined locally here; the macOS path uses its own
    // 3s timeout copy in operations.rs (A2 scope narrowing). publish_file_metadata
    // (the legacy per-file publish) is gone — publish_file_node is the single
    // per-file node/v3 publish path on both platforms (SC#2/SC#1, 69-14).
    pub use crate::content_ops::{fetch_node_and_decrypt_content, publish_file_node};

    // ── FileSystemContext Implementation (delegates to sub-modules) ──────

    impl FileSystemContext for WinFspContext {
        type FileContext = WinFspFileContext;

        fn get_volume_info(
            &self,
            volume_info: &mut winfsp::filesystem::VolumeInfo,
        ) -> Result<(), FspError> {
            super::super::read_ops::implementation::handle_get_volume_info(self, volume_info)
        }

        fn get_security_by_name(
            &self,
            file_name: &U16CStr,
            security_descriptor: Option<&mut [c_void]>,
            _find_reparse_point: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
        ) -> Result<FileSecurity, FspError> {
            super::super::read_ops::implementation::handle_get_security_by_name(
                self,
                file_name,
                security_descriptor,
            )
        }

        fn open(
            &self,
            file_name: &U16CStr,
            create_options: u32,
            granted_access: u32,
            file_info: &mut OpenFileInfo,
        ) -> Result<Self::FileContext, FspError> {
            super::super::read_ops::implementation::handle_open(
                self,
                file_name,
                create_options,
                granted_access,
                file_info,
            )
        }

        fn overwrite(
            &self,
            context: &Self::FileContext,
            _file_attributes: u32,
            _replace_file_attributes: bool,
            _allocation_size: u64,
            _extra_buffer: Option<&[u8]>,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::super::write_ops::implementation::handle_overwrite(self, context, file_info)
        }

        fn close(&self, context: Self::FileContext) {
            super::super::read_ops::implementation::handle_close(self, context);
        }

        fn read(
            &self,
            context: &Self::FileContext,
            buffer: &mut [u8],
            offset: u64,
        ) -> Result<u32, FspError> {
            super::super::read_ops::implementation::handle_read(self, context, buffer, offset)
        }

        fn write(
            &self,
            context: &Self::FileContext,
            buffer: &[u8],
            offset: u64,
            write_to_end_of_file: bool,
            _constrained_io: bool,
            file_info: &mut FileInfo,
        ) -> Result<u32, FspError> {
            super::super::write_ops::implementation::handle_write(
                self,
                context,
                buffer,
                offset,
                write_to_end_of_file,
                file_info,
            )
        }

        fn flush(
            &self,
            _context: Option<&Self::FileContext>,
            _file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::super::read_ops::implementation::handle_flush()
        }

        fn get_file_info(
            &self,
            context: &Self::FileContext,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::super::read_ops::implementation::handle_get_file_info(self, context, file_info)
        }

        fn get_security(
            &self,
            _context: &Self::FileContext,
            security_descriptor: Option<&mut [c_void]>,
        ) -> Result<u64, FspError> {
            super::super::read_ops::implementation::handle_get_security(security_descriptor)
        }

        fn set_basic_info(
            &self,
            context: &Self::FileContext,
            _file_attributes: u32,
            creation_time: u64,
            last_access_time: u64,
            last_write_time: u64,
            change_time: u64,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::super::write_ops::implementation::handle_set_basic_info(
                self,
                context,
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                file_info,
            )
        }

        fn set_file_size(
            &self,
            context: &Self::FileContext,
            new_size: u64,
            set_allocation_size: bool,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::super::write_ops::implementation::handle_set_file_size(
                self,
                context,
                new_size,
                set_allocation_size,
                file_info,
            )
        }

        fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
            super::super::write_ops::implementation::handle_cleanup(self, context, flags);
        }

        fn read_directory(
            &self,
            context: &Self::FileContext,
            _pattern: Option<&U16CStr>,
            marker: DirMarker,
            buffer: &mut [u8],
        ) -> Result<u32, FspError> {
            super::super::dir_ops::implementation::handle_read_directory(
                self, context, marker, buffer,
            )
        }

        fn create(
            &self,
            file_name: &U16CStr,
            create_options: u32,
            granted_access: u32,
            _file_attributes: u32,
            _security_descriptor: Option<&[c_void]>,
            _allocation_size: u64,
            _extra_buffer: Option<&[u8]>,
            _extra_buffer_is_reparse_point: bool,
            file_info: &mut OpenFileInfo,
        ) -> Result<Self::FileContext, FspError> {
            super::super::write_ops::implementation::handle_create(
                self,
                file_name,
                create_options,
                granted_access,
                _file_attributes,
                _security_descriptor,
                _allocation_size,
                _extra_buffer,
                _extra_buffer_is_reparse_point,
                file_info,
            )
        }

        fn rename(
            &self,
            _context: &Self::FileContext,
            file_name: &U16CStr,
            new_file_name: &U16CStr,
            replace_if_exists: bool,
        ) -> Result<(), FspError> {
            super::super::write_ops::implementation::handle_rename(
                self,
                file_name,
                new_file_name,
                replace_if_exists,
            )
        }

        fn set_delete(
            &self,
            context: &Self::FileContext,
            file_name: &U16CStr,
            delete_file: bool,
        ) -> Result<(), FspError> {
            super::super::write_ops::implementation::handle_set_delete(
                self,
                context,
                file_name,
                delete_file,
            )
        }
    }
}
