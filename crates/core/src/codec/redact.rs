//! Redacted renderings.
//!
//! What a rendering withholds is decoded **user content** — a filename, a child
//! `ipnsName`, an application payload — which in a zero-knowledge system is
//! exactly what the server must never see, so a log line must not carry it
//! either (AGENTS.md rule 2). Public material renders in full: ciphertexts,
//! signatures, CIDs, epoch counters, and public keys, which carry their own
//! rendering policy at their type. Secret key material redacts at its type too
//! ([`crate::suite::secret::SecretBytes`]).
//!
//! A node id renders while its `ipnsName` does not: the name is a live handle
//! that resolves a record, whereas an id reaches one only through the write
//! scope seed.
//!
//! Lengths are kept: a rendering with no shape at all is useless for diagnosis.

use core::fmt;

use crate::error::DisplayKey;

/// A byte buffer rendered as its length alone.
pub(crate) struct RedactedBytes(usize);

impl RedactedBytes {
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self(bytes.len())
    }
}

impl fmt::Debug for RedactedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes redacted>", self.0)
    }
}

/// Text rendered as its character count alone.
pub(crate) struct RedactedText(usize);

impl RedactedText {
    pub(crate) fn of(s: &str) -> Self {
        Self(s.chars().count())
    }
}

impl fmt::Debug for RedactedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} chars redacted>", self.0)
    }
}

/// Render a preserved-field set as keys only, with the field names bounded the
/// way the error surface bounds writer-controlled keys. Shared by both
/// preserve-unknowns carriers so neither can grow a value into a log line.
pub(crate) fn fmt_redacted_keys<'a>(
    f: &mut fmt::Formatter<'_>,
    keys: impl Iterator<Item = &'a str>,
) -> fmt::Result {
    let mut m = f.debug_map();
    for key in keys {
        m.key(&DisplayKey(key)).value(&"<redacted>");
    }
    m.finish()
}
