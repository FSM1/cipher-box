//! CipherBox core: wire formats, crypto primitives, and the frozen KDF edge
//! catalog. Pure, deterministic, no I/O — entropy and time are injected.
//!
//! Normative design: blueprint/core.md

#![forbid(unsafe_code)]

/// Placeholder identity item; real wire formats and crypto land in later PRs.
pub const CRATE: &str = "cipherbox-core";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(super::CRATE, "cipherbox-core");
    }
}
