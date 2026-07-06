//! IPNS FilePointer resolution polling for the macOS FUSE read path.
//!
//! The macOS read path (`read_ops.rs`) polls for an in-flight async FilePointer
//! resolution to complete via `poll_filepointer_resolution`. The Windows/WinFsp
//! read path (`platform/windows/read_ops.rs`) has its own inline polling loop
//! (different mutex semantics) and does not use this function, so
//! `poll_filepointer_resolution` is gated `#[cfg(feature = "fuse")]`. The
//! `PollResult` enum is gated for both feature sets.

/// Why did polling for a FilePointer resolution stop?
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) enum PollResult {
    Resolved,
    TimedOut,
    NotInFlight,
}

/// Total deadline for polling an in-flight FilePointer resolution.
///
/// `pub(crate)` so the macOS read path (`read_ops.rs`) can report the timeout
/// duration in its log messages without re-hardcoding the value.
#[cfg(feature = "fuse")]
pub(crate) const FILEPOINTER_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Poll for an in-flight async FilePointer resolution to complete.
///
/// Only blocks if an async resolution task is actually in-flight for `ino`.
/// Uses a 5-second total deadline with 100ms sleep intervals.
///
/// This is `pub(crate)` so the macOS read path in `read_ops.rs` can call it
/// from a sibling module.
#[cfg(feature = "fuse")]
pub(crate) fn poll_filepointer_resolution(fs: &mut crate::CipherBoxFS, ino: u64) -> PollResult {
    use std::time::Duration;
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
                // node/v3: "resolved" == content descriptors filled (non-empty CID).
                if let crate::inode::InodeKind::File { cid, .. } = &inode.kind {
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
            if let crate::inode::InodeKind::File { cid, .. } = &inode.kind {
                if !cid.is_empty() {
                    return PollResult::Resolved;
                }
            }
        }
    }
    PollResult::TimedOut
}
