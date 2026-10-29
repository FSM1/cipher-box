//! The per-handle write trace the e2e harnesses keep in each instance log.
//!
//! Compiled into the `e2e-hook` build only. A line carries inode numbers,
//! handle ids, byte counts and op kinds — never a name, a path, or content.

use std::time::{SystemTime, UNIX_EPOCH};

/// Write one trace line to stderr, stamped with the wall clock: the instance
/// log is the raw stream, with no time of its own.
pub(crate) fn line(what: core::fmt::Arguments<'_>) {
    if cfg!(feature = "e2e-hook") {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis());
        eprintln!("mount trace: {what} (unix {wall} ms)");
    }
}
