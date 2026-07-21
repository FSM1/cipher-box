//! Fsync-barrier file primitives shared by the durable desktop stores.
//!
//! The v1 high-water-store / write-journal durability discipline
//! (blueprint/desktop.md): a value is durable only after its bytes hit the
//! platter (`sync_all`) **and** the directory entry that names them is
//! itself fsynced. [`atomic_write`] and [`remove_file_durable`] are the two
//! barriers every store builds on.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cipherbox_engine::seams::SeamError;

/// Process-unique suffix source for in-flight temp files, so two atomic
/// writes never collide on a temp name even across different keys.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Prefix marking a store's in-flight temp file. Enumeration skips these,
/// and [`ensure_dir`] sweeps any left behind by a crash mid-write.
const TEMP_PREFIX: &str = ".cbtmp.";

/// Wraps an I/O error as an opaque [`SeamError`] with an operation label.
///
/// Deliberately carries only the operation and the OS error — never a value
/// or a token (security rule 2). Store keys are engine-chosen identifiers,
/// not secrets, but they are still left out to keep messages minimal.
pub(crate) fn seam_err(op: &str, err: &io::Error) -> SeamError {
    SeamError::new(format!("{op}: {err}"))
}

/// Ensures a directory exists and sweeps any stale temp files from a
/// previous crashed write. Idempotent.
pub(crate) fn ensure_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            // Best-effort: a racing writer is impossible (single-writer
            // engine), so a lingering temp is always crash debris.
            let _ = fs::remove_file(entry.path());
        }
    }
    fsync_dir(dir)
}

/// Durably writes `bytes` to `path`, replacing any existing file atomically.
///
/// Barrier order: write a fresh temp file in the same directory, `sync_all`
/// its contents, `rename` it over the target (atomic replace on Unix and on
/// Windows — Rust's `fs::rename` maps to `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`), then fsync the
/// directory so the rename itself is durable. A crash can only ever leave
/// the old value or the new value — never a torn one.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let tmp = temp_path(dir);
    // Scope the handle so it is closed before the rename.
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    match fs::rename(&tmp, path) {
        Ok(()) => {}
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
    }
    fsync_dir(dir)
}

/// Durably removes a file. Idempotent: a missing file is success. The
/// removal is barriered with a directory fsync so an ordered caller (e.g.
/// the StagingStore's op-before-sidecar removal) can rely on it having hit
/// the platter before the next removal begins.
pub(crate) fn remove_file_durable(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    }
    if let Some(dir) = path.parent() {
        fsync_dir(dir)?;
    }
    Ok(())
}

/// Reads a file whole, mapping a missing file to `None`.
pub(crate) fn read_file_opt(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match File::open(path) {
        Ok(mut file) => {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// The names of the non-temp files directly in `dir` (no recursion). Temp
/// files and subdirectories are skipped.
pub(crate) fn list_file_names(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(TEMP_PREFIX) {
            continue;
        }
        names.push(name);
    }
    Ok(names)
}

/// Fsyncs a directory so a create/rename/unlink inside it is durable.
///
/// Unix opens the directory and `sync_all`s it. Windows has no directory
/// fsync; `fs::rename`'s `MOVEFILE_WRITE_THROUGH` and NTFS metadata
/// journaling cover the same guarantee, so this is a no-op there.
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// A process-unique filename component (`<pid>.<seq>`), so two in-flight
/// records never collide on a name even across concurrent writers.
pub(crate) fn unique_component() -> String {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{}.{seq}", std::process::id())
}

/// A process-unique temp path inside `dir`.
fn temp_path(dir: &Path) -> PathBuf {
    dir.join(format!("{TEMP_PREFIX}{}", unique_component()))
}

/// Lowercase hex encoding of opaque key bytes for use as a filename.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a lowercase-hex filename back to the original key bytes; `None`
/// if the string is not valid hex (so enumeration can skip foreign files).
pub(crate) fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_arbitrary_bytes() {
        let bytes = [0x00u8, 0xff, 0x9f, 0x92, 0x10, 0xab];
        assert_eq!(from_hex(&to_hex(&bytes)), Some(bytes.to_vec()));
        assert_eq!(to_hex(&[]), "");
        assert_eq!(from_hex(""), Some(Vec::new()));
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("abc"), None); // odd length
    }

    #[test]
    fn atomic_write_replaces_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value");
        atomic_write(&path, b"first").unwrap();
        assert_eq!(read_file_opt(&path).unwrap(), Some(b"first".to_vec()));
        atomic_write(&path, b"second").unwrap();
        assert_eq!(read_file_opt(&path).unwrap(), Some(b"second".to_vec()));
        // No temp debris survives a successful write.
        assert_eq!(
            list_file_names(dir.path()).unwrap(),
            vec!["value".to_string()]
        );
    }

    #[test]
    fn remove_file_durable_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value");
        atomic_write(&path, b"x").unwrap();
        remove_file_durable(&path).unwrap();
        remove_file_durable(&path).unwrap();
        assert_eq!(read_file_opt(&path).unwrap(), None);
    }

    #[test]
    fn ensure_dir_sweeps_temp_debris() {
        let dir = tempfile::tempdir().unwrap();
        let debris = dir.path().join(format!("{TEMP_PREFIX}stale"));
        std::fs::write(&debris, b"crash").unwrap();
        ensure_dir(dir.path()).unwrap();
        assert!(!debris.exists(), "a crashed temp file must be swept");
    }
}
