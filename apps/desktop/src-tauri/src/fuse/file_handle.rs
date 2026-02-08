//! Open file handle with temp file write buffering.
//!
//! Implements the "temp-file commit model": writes buffer to a local temp file,
//! then encrypt + upload on file close (release). This avoids uploading on
//! every write() call and ensures atomic file content updates.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Open file handle tracking active reads and writes.
///
/// For read-only opens, only `cached_content` is populated.
/// For writable opens, a temp file is created for buffering writes.
/// On release, if dirty, the temp file content is encrypted and uploaded.
pub struct OpenFileHandle {
    /// Inode number of the open file.
    pub ino: u64,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR).
    pub flags: i32,
    /// Path to temp file used for write buffering (None for read-only opens).
    pub temp_path: Option<PathBuf>,
    /// Whether the file has been modified since open.
    pub dirty: bool,
    /// Pre-fetched decrypted content for reads (populated on first read).
    pub cached_content: Option<Vec<u8>>,
    /// Original file size before modifications.
    pub original_size: u64,
}

impl OpenFileHandle {
    /// Create a read-only file handle. No temp file, not dirty.
    pub fn new_read(ino: u64, flags: i32) -> Self {
        Self {
            ino,
            flags,
            temp_path: None,
            dirty: false,
            cached_content: None,
            original_size: 0,
        }
    }

    /// Create a writable file handle with a temp file.
    ///
    /// If `existing_content` is provided (editing an existing file),
    /// the temp file is pre-populated with the decrypted content.
    pub fn new_write(
        ino: u64,
        flags: i32,
        temp_dir: &Path,
        existing_content: Option<&[u8]>,
    ) -> Result<Self, String> {
        // Ensure temp directory exists
        fs::create_dir_all(temp_dir)
            .map_err(|e| format!("Failed to create temp dir: {}", e))?;

        // Generate unique temp file name
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_path = temp_dir.join(format!("cb-write-{}-{}", ino, timestamp));

        // Create temp file and optionally pre-populate
        let original_size = if let Some(content) = existing_content {
            fs::write(&temp_path, content)
                .map_err(|e| format!("Failed to write temp file: {}", e))?;
            content.len() as u64
        } else {
            // Create empty temp file
            fs::File::create(&temp_path)
                .map_err(|e| format!("Failed to create temp file: {}", e))?;
            0
        };

        Ok(Self {
            ino,
            flags,
            temp_path: Some(temp_path),
            dirty: false,
            cached_content: None,
            original_size,
        })
    }

    /// Write data to the temp file at the given offset. Marks the handle as dirty.
    pub fn write_at(&mut self, offset: i64, data: &[u8]) -> Result<usize, String> {
        let temp_path = self
            .temp_path
            .as_ref()
            .ok_or("No temp file for write")?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(temp_path)
            .map_err(|e| format!("Failed to open temp file for write: {}", e))?;

        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|e| format!("Failed to seek temp file: {}", e))?;

        file.write_all(data)
            .map_err(|e| format!("Failed to write to temp file: {}", e))?;

        self.dirty = true;
        Ok(data.len())
    }

    /// Read data from the temp file at the given offset.
    ///
    /// Used for files opened for write that also need reading (O_RDWR).
    pub fn read_at(&self, offset: i64, size: u32) -> Result<Vec<u8>, String> {
        let temp_path = self
            .temp_path
            .as_ref()
            .ok_or("No temp file for read")?;

        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(temp_path)
            .map_err(|e| format!("Failed to open temp file for read: {}", e))?;

        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|e| format!("Failed to seek temp file: {}", e))?;

        let mut buf = vec![0u8; size as usize];
        let bytes_read = file
            .read(&mut buf)
            .map_err(|e| format!("Failed to read from temp file: {}", e))?;

        buf.truncate(bytes_read);
        Ok(buf)
    }

    /// Get the current size of the temp file.
    pub fn get_size(&self) -> Result<u64, String> {
        let temp_path = self
            .temp_path
            .as_ref()
            .ok_or("No temp file")?;

        let metadata = fs::metadata(temp_path)
            .map_err(|e| format!("Failed to get temp file metadata: {}", e))?;

        Ok(metadata.len())
    }

    /// Read the entire temp file contents (used for encrypt + upload on close).
    pub fn read_all(&self) -> Result<Vec<u8>, String> {
        let temp_path = self
            .temp_path
            .as_ref()
            .ok_or("No temp file for read_all")?;

        fs::read(temp_path).map_err(|e| format!("Failed to read temp file: {}", e))
    }

    /// Truncate the temp file to the given size.
    pub fn truncate(&self, size: u64) -> Result<(), String> {
        let temp_path = self
            .temp_path
            .as_ref()
            .ok_or("No temp file for truncate")?;

        let file = fs::OpenOptions::new()
            .write(true)
            .open(temp_path)
            .map_err(|e| format!("Failed to open temp file for truncate: {}", e))?;

        file.set_len(size)
            .map_err(|e| format!("Failed to truncate temp file: {}", e))
    }

    /// Delete the temp file. Called after upload or on error.
    pub fn cleanup(&self) {
        if let Some(ref temp_path) = self.temp_path {
            if temp_path.exists() {
                if let Err(e) = fs::remove_file(temp_path) {
                    log::warn!("Failed to cleanup temp file {:?}: {}", temp_path, e);
                }
            }
        }
    }
}

impl Drop for OpenFileHandle {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_read_handle() {
        let handle = OpenFileHandle::new_read(42, libc::O_RDONLY);
        assert_eq!(handle.ino, 42);
        assert!(!handle.dirty);
        assert!(handle.temp_path.is_none());
        assert!(handle.cached_content.is_none());
    }

    #[test]
    fn test_new_write_handle_empty() {
        let temp_dir = std::env::temp_dir().join("cipherbox-test-write-empty");
        let handle = OpenFileHandle::new_write(5, libc::O_WRONLY, &temp_dir, None).unwrap();

        assert_eq!(handle.ino, 5);
        assert!(!handle.dirty);
        assert!(handle.temp_path.is_some());
        assert_eq!(handle.original_size, 0);

        // Temp file should exist
        let temp_path = handle.temp_path.as_ref().unwrap();
        assert!(temp_path.exists());

        // Cleanup
        handle.cleanup();
        let _ = fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_new_write_handle_with_content() {
        let temp_dir = std::env::temp_dir().join("cipherbox-test-write-content");
        let content = b"Hello, CipherBox!";
        let handle =
            OpenFileHandle::new_write(10, libc::O_RDWR, &temp_dir, Some(content)).unwrap();

        assert_eq!(handle.original_size, content.len() as u64);

        // Read back should match
        let read_back = handle.read_all().unwrap();
        assert_eq!(read_back, content);

        handle.cleanup();
        let _ = fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_write_at_and_read_at() {
        let temp_dir = std::env::temp_dir().join("cipherbox-test-write-read");
        let mut handle = OpenFileHandle::new_write(
            15,
            libc::O_RDWR,
            &temp_dir,
            Some(b"Hello World"),
        )
        .unwrap();

        // Write at offset 6
        let written = handle.write_at(6, b"Rust!").unwrap();
        assert_eq!(written, 5);
        assert!(handle.dirty);

        // Read back full content
        let content = handle.read_all().unwrap();
        assert_eq!(&content, b"Hello Rust!");

        // Read at specific offset
        let partial = handle.read_at(6, 5).unwrap();
        assert_eq!(&partial, b"Rust!");

        handle.cleanup();
        let _ = fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_get_size() {
        let temp_dir = std::env::temp_dir().join("cipherbox-test-get-size");
        let content = b"12345678901234567890"; // 20 bytes
        let handle =
            OpenFileHandle::new_write(20, libc::O_WRONLY, &temp_dir, Some(content)).unwrap();

        assert_eq!(handle.get_size().unwrap(), 20);

        handle.cleanup();
        let _ = fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_truncate() {
        let temp_dir = std::env::temp_dir().join("cipherbox-test-truncate");
        let content = b"Hello World!";
        let handle =
            OpenFileHandle::new_write(25, libc::O_WRONLY, &temp_dir, Some(content)).unwrap();

        assert_eq!(handle.get_size().unwrap(), 12);

        handle.truncate(5).unwrap();
        assert_eq!(handle.get_size().unwrap(), 5);

        let truncated = handle.read_all().unwrap();
        assert_eq!(&truncated, b"Hello");

        handle.cleanup();
        let _ = fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_cleanup_removes_temp_file() {
        let temp_dir = std::env::temp_dir().join("cipherbox-test-cleanup");
        let handle =
            OpenFileHandle::new_write(30, libc::O_WRONLY, &temp_dir, Some(b"test")).unwrap();

        let temp_path = handle.temp_path.clone().unwrap();
        assert!(temp_path.exists());

        handle.cleanup();
        assert!(!temp_path.exists());

        let _ = fs::remove_dir(&temp_dir);
    }
}
