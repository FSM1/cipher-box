//! CipherBox engine: the one stateful brain — sync, key lifecycle, and the
//! seam traits through which entropy, time, and policy are injected.
//!
//! Normative design: blueprint/engine.md

#![forbid(unsafe_code)]

/// Placeholder identity item; the real engine lands in later PRs.
pub const CRATE: &str = "cipherbox-engine";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(super::CRATE, "cipherbox-engine");
    }

    #[test]
    fn depends_on_core() {
        assert_eq!(cipherbox_core::CRATE, "cipherbox-core");
    }
}
