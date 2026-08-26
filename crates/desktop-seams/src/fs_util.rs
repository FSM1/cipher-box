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
/// its contents, `rename` it over the target (an atomic replace on both Unix
/// and Windows), then [`fsync_dir`] so the rename itself is durable. A crash
/// can only ever leave the old value or the new value — never a torn one.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let tmp = write_synced_temp(dir, bytes)?;
    match fs::rename(&tmp, path) {
        Ok(()) => {}
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
    }
    fsync_dir(dir).map_err(|err| io::Error::new(err.kind(), format!("write barrier: {err}")))
}

/// Durably removes a file. Idempotent: a missing file is success. The
/// removal is followed by [`fsync_dir`] so an ordered caller (e.g. the
/// StagingStore's op-before-sidecar removal) can rely on it having hit the
/// platter before the next removal begins.
pub(crate) fn remove_file_durable(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    }
    if let Some(dir) = path.parent() {
        fsync_dir(dir)
            .map_err(|err| io::Error::new(err.kind(), format!("unlink barrier: {err}")))?;
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

/// Durably removes every file directly in `dir`, in-flight temps included
/// ("forget this device"). Subdirectories are left alone.
///
/// Unlike [`list_file_names`], this does not skip temps: a temp still holds the
/// bytes a store was in the middle of writing, so an erase that stepped over it
/// would leave that record behind. Every entry is attempted even after one
/// refuses ([`keep_first`]) — stopping there would strand records the caller
/// has no second exit for.
///
/// One barrier for the whole sweep, not one per file
/// ([`remove_file_durable`]'s): nothing here is ordered against anything else in
/// the same directory, so a crash mid-sweep strands an arbitrary subset either
/// way. The trailing barrier still gives a caller sweeping several directories
/// the ordering between them.
pub(crate) fn empty_dir(dir: &Path) -> io::Result<()> {
    let listing = match fs::read_dir(dir) {
        Ok(listing) => listing,
        // Already gone is the state an erase was asking for; reporting failure
        // would tell a member their forget did not land.
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let mut refusal = Ok(());
    // Collected first: removing during the walk mutates what it iterates.
    let mut names = Vec::new();
    for entry in listing {
        match entry.and_then(|entry| Ok((entry.file_type()?.is_file(), entry.file_name()))) {
            Ok((true, name)) => names.push(name),
            Ok((false, _)) => {}
            Err(err) => refusal = keep_first(refusal, Err(err)),
        }
    }
    for name in names {
        match fs::remove_file(dir.join(name)) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => refusal = keep_first(refusal, Err(err)),
        }
    }
    let barrier =
        fsync_dir(dir).map_err(|err| io::Error::new(err.kind(), format!("sweep barrier: {err}")));
    keep_first(refusal, barrier)
}

/// Sequences two erase legs that are independent of each other: both have
/// already run, and the first refusal is what the caller sees.
pub(crate) fn keep_first<E>(kept: Result<(), E>, next: Result<(), E>) -> Result<(), E> {
    kept.and(next)
}

/// Barriers a directory so a create/rename/unlink inside it is durable
/// before the next one is issued.
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(dir: &Path) -> io::Result<()> {
    metadata_log_barrier(dir)
}

/// The [`fsync_dir`] barrier where a directory handle cannot be fsynced.
///
/// NTFS journals metadata to a per-volume log flushed as an LSN-ordered
/// prefix, so `sync_all`ing a file created *after* an unlink or rename also
/// persists it. This covers both barriers, not just unlinks: std's Windows
/// `rename` passes `MOVEFILE_REPLACE_EXISTING` alone, never
/// `MOVEFILE_WRITE_THROUGH`. The temp carries [`TEMP_PREFIX`], so a crash
/// before its removal leaves debris [`ensure_dir`] sweeps on reopen.
#[cfg(any(not(unix), test))]
fn metadata_log_barrier(dir: &Path) -> io::Result<()> {
    // A byte of content makes the flush a data-and-metadata transaction
    // rather than a flush of an untouched handle.
    let path = write_synced_temp(dir, b"\0")?;
    let _ = fs::remove_file(&path);
    Ok(())
}

/// Writes `bytes` to a fresh temp file in `dir` and `sync_all`s it, returning
/// its path with the handle already closed.
fn write_synced_temp(dir: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    let path = temp_path(dir);
    let mut file = File::create(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(path)
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
    fn metadata_log_barrier_leaves_the_directory_as_it_found_it() {
        let dir = tempfile::tempdir().unwrap();
        atomic_write(&dir.path().join("value"), b"x").unwrap();
        metadata_log_barrier(dir.path()).unwrap();
        metadata_log_barrier(dir.path()).unwrap();
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "successive barriers must neither collide on a temp name nor accumulate debris"
        );
        assert_eq!(
            read_file_opt(&dir.path().join("value")).unwrap(),
            Some(b"x".to_vec())
        );
    }

    /// The barrier reports a failure rather than returning success without
    /// having established one — an unbarriered removal is a fail-closed error,
    /// never a fast path, because callers order two removals against it.
    #[test]
    fn metadata_log_barrier_fails_closed_when_it_cannot_be_established() {
        let dir = tempfile::tempdir().unwrap();
        assert!(metadata_log_barrier(&dir.path().join("absent")).is_err());
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
