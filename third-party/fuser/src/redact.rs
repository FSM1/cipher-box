//! Name redaction for every log line and `Display` render in this crate.

use std::ffi::OsStr;
use std::fmt;

/// A file, link or xattr name is user plaintext in a zero-knowledge vault, so no
/// log sink may receive one (AGENTS.md rule 2). This renders the byte length and
/// nothing else, and a re-vendor has one definition to re-apply.
pub(crate) struct RedactedName<'a>(&'a OsStr);

/// Wraps a name so `&OsStr` and `&Path` call sites read the same.
pub(crate) fn redacted(name: &(impl AsRef<OsStr> + ?Sized)) -> RedactedName<'_> {
    RedactedName(name.as_ref())
}

impl fmt::Display for RedactedName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

impl fmt::Debug for RedactedName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
