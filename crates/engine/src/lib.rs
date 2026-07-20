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
        use cipherbox_core::codec::{Value, decode, encode};
        let bytes = encode(&Value::Unsigned(1));
        assert_eq!(decode(&bytes).unwrap(), Value::Unsigned(1));
    }
}
