//! Redacted renderings.
//!
//! Never log keys or seeds (AGENTS.md rule 2), and in a zero-knowledge system
//! sealed plaintext — a filename, a child `ipnsName`, a recipient's identity key
//! — is the very thing the server must never see, so it is redacted on the same
//! terms. Public wire artifacts (ciphertexts, signatures, CIDs, node ids, epoch
//! counters) render in full; only what a seal protects is withheld.
//!
//! Lengths are kept: a rendering with no shape at all is useless for diagnosis.

use core::fmt;

use crate::error::DisplayKey;

/// A byte buffer rendered as its length alone.
pub(crate) struct RedactedBytes(pub(crate) usize);

impl fmt::Debug for RedactedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes redacted>", self.0)
    }
}

/// Text rendered as its character count alone.
pub(crate) struct RedactedText(pub(crate) usize);

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
