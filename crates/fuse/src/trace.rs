//! The per-handle mount trace the e2e harnesses keep in each instance log.
//!
//! Writes only in the `e2e-hook` build. A line carries inode numbers, handle
//! ids, byte counts and op kinds — never a name, a path, or content.

use std::time::{SystemTime, UNIX_EPOCH};

/// Whether this build writes the trace.
pub(crate) const ENABLED: bool = cfg!(feature = "e2e-hook");

/// Milliseconds since the unix epoch, for a line in a raw stderr log.
pub(crate) fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}

/// Write one trace line to stderr, stamped with the wall clock: the instance
/// log is the raw stream, with no time of its own.
pub(crate) fn line(what: core::fmt::Arguments<'_>) {
    if ENABLED {
        eprintln!("mount trace: {what} (unix {} ms)", unix_millis());
    }
}
