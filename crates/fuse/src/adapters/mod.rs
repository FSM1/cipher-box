//! One adapter per mount technology, each a thin decoder over the shared
//! operation core.

use crate::ops::DirEntry;

#[cfg(windows)]
mod descriptor;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod fuse;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod stale;
#[cfg(windows)]
pub mod windows;

/// The capacity every mount advertises. Byte accounting does not reach the
/// facade, and a mount that answers zero free space is refused *before* the
/// write by clients that read it first; a write over a real budget is still
/// refused where it belongs, by the engine's `ENOSPC`/`EDQUOT` equivalents.
pub(crate) const ADVISORY_CAPACITY_BYTES: u64 = 1 << 40;

/// How many invalidations may queue for the thread that pushes them at the
/// kernel. A queue that overflows drops its oldest: a mount cannot make the
/// kernel wait, and the cache lifetimes are the backstop.
pub(crate) const NOTIFY_QUEUE_DEPTH: usize = 4096;

/// `.` and `..`, which a listing synthesizes ahead of the children the core
/// hands back. Both name the directory itself — every host resolves `..` by
/// opening the parent, never through the entry a listing reports.
pub(crate) const DOT_NAMES: [&str; 2] = [".", ".."];

pub(crate) const DOT_ENTRIES: usize = DOT_NAMES.len();

/// The core cursor a host's directory offset resumes at. A host counts the
/// synthesized [`DOT_NAMES`] ahead of the children; the core counts children
/// alone.
pub(crate) fn cursor_of(offset: usize) -> usize {
    offset.saturating_sub(DOT_ENTRIES)
}

/// One entry of a [`page`]: a synthesized dot name, or a child the core listed.
pub(crate) enum Listed<'a> {
    Dot(&'a str),
    Child(&'a DirEntry),
}

/// One page in a host's offset space: the dot entries `offset` has not passed,
/// then `entries`, which the core already resumed at
/// [`cursor_of(offset)`](cursor_of). Each carries the offset a continuation
/// resumes at, which is the one *after* it.
///
/// Shared because the off-by-one here is the difference between a repeated
/// directory entry and a missing file, and one wire proving it is not the
/// other wire proving it.
pub(crate) fn page(
    offset: usize,
    entries: &[DirEntry],
) -> impl Iterator<Item = (Listed<'_>, usize)> {
    let dots = DOT_NAMES
        .iter()
        .enumerate()
        .skip(offset.min(DOT_ENTRIES))
        .map(|(index, name)| (Listed::Dot(name), index + 1));
    let base = offset.max(DOT_ENTRIES);
    let children = entries
        .iter()
        .enumerate()
        .map(move |(step, child)| (Listed::Child(child), base + step + 1));
    dots.chain(children)
}
