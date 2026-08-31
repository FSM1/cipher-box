//! Name redaction for every log line and `Display` render in this crate.

use std::ffi::OsStr;
use std::fmt;

/// A file, link or xattr name is user plaintext, so no log sink may receive one.
/// This renders the byte length and nothing else, and a re-vendor has one
/// definition to re-apply.
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

/// A request payload borrows the name straight out of the kernel buffer, so a
/// derived `Debug` prints it. These payloads render their type and nothing more;
/// the redacted `Display for Operation` is the render that carries the detail.
macro_rules! opaque_debug {
    ($($payload:ident),+ $(,)?) => {
        $(
            impl ::std::fmt::Debug for $payload<'_> {
                fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                    write!(f, concat!(stringify!($payload), " {{ .. }}"))
                }
            }
        )+
    };
}

pub(crate) use opaque_debug;
