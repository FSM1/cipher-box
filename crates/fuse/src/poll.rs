//! Shared IPNS FilePointer resolution polling for macOS FUSE and Windows WinFsp.
//!
//! Both `read_ops.rs` (macOS) and `platform/windows/read_ops.rs` (Windows) need
//! to poll for in-flight async FilePointer resolution to complete. This module
//! provides the `PollResult` enum and `poll_filepointer_resolution` function so
//! both paths can share the same logic.

/// Why did polling for a FilePointer resolution stop?
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) enum PollResult {
    Resolved,
    TimedOut,
    NotInFlight,
}

/// Poll for an in-flight async FilePointer resolution to complete.
///
/// Only blocks if an async resolution task is actually in-flight for `ino`.
/// Uses a 5-second total deadline with 100ms sleep intervals.
///
/// This is `pub(crate)` so `platform/windows/read_ops.rs` can also call it.
#[cfg(feature = "fuse")]
pub(crate) fn poll_filepointer_resolution(
    fs: &mut crate::CipherBoxFS,
    ino: u64,
) -> PollResult {
    use std::time::Duration;
    const FILEPOINTER_POLL_TIMEOUT: Duration = Duration::from_secs(5);
    const FILEPOINTER_POLL_INTERVAL: Duration = Duration::from_millis(100);

    if !fs.resolving_file_pointers.contains(&ino) {
        log::debug!(
            "poll_filepointer_resolution: ino={} has no in-flight resolution",
            ino
        );
        return PollResult::NotInFlight;
    }
    let deadline = std::time::Instant::now() + FILEPOINTER_POLL_TIMEOUT;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(FILEPOINTER_POLL_INTERVAL);
        fs.drain_filepointer_completions();
        // Break early if async task completed with Failure (ino removed from set)
        if !fs.resolving_file_pointers.contains(&ino) {
            if let Some(inode) = fs.inodes.get(ino) {
                if let crate::inode::InodeKind::File {
                    file_meta_resolved: true,
                    cid,
                    ..
                } = &inode.kind
                {
                    if !cid.is_empty() {
                        return PollResult::Resolved;
                    }
                }
            }
            log::debug!(
                "poll_filepointer_resolution: ino={} async task finished but resolution failed",
                ino
            );
            return PollResult::NotInFlight;
        }
        // Still in-flight -- check if resolved yet
        if let Some(inode) = fs.inodes.get(ino) {
            if let crate::inode::InodeKind::File {
                cid,
                file_meta_resolved: true,
                ..
            } = &inode.kind
            {
                if !cid.is_empty() {
                    return PollResult::Resolved;
                }
            }
        }
    }
    PollResult::TimedOut
}
