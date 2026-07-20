//! CipherBox fuse: filesystem projection core over the engine, backing the
//! desktop mounts (FUSE-T SMB on macOS, libfuse3 on Linux, WinFsp on Windows).
//!
//! Normative design: blueprint/desktop.md

/// Placeholder identity item; the real FS projection lands in later PRs.
pub const CRATE: &str = "cipherbox-fuse";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(super::CRATE, "cipherbox-fuse");
    }

    #[test]
    fn depends_on_engine() {
        assert_eq!(cipherbox_engine::CRATE, "cipherbox-engine");
    }
}
