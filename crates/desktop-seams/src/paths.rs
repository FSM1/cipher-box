//! The on-disk home of every desktop engine store.

use std::path::{Path, PathBuf};

/// The per-account engine data directory: `<data_local_dir>/cipherbox/<accountId>/`
/// (blueprint/desktop.md "Engine wiring").
///
/// All desktop seam stores live under this root, ciphertext-only at rest.
/// The host supplies `data_local_dir` (Tauri's `data_local_dir()`); this
/// crate never resolves it, so it stays testable against a tempdir.
pub fn account_data_dir(data_local_dir: &Path, account_id: &str) -> PathBuf {
    data_local_dir.join("cipherbox").join(account_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_the_cipherbox_account_root() {
        let dir = account_data_dir(Path::new("/var/lib"), "acct-42");
        assert_eq!(dir, PathBuf::from("/var/lib/cipherbox/acct-42"));
    }
}
