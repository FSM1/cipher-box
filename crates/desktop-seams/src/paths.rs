//! The on-disk home of every desktop engine store.

use std::path::{Component, Path, PathBuf};

use cipherbox_engine::seams::{SeamError, SeamResult};

/// The per-account engine data directory: `<data_local_dir>/cipherbox/<accountId>/`
/// (blueprint/desktop.md "Engine wiring").
///
/// All desktop seam stores live under this root, ciphertext-only at rest.
/// The host supplies `data_local_dir` (Tauri's `data_local_dir()`); this
/// crate never resolves it, so it stays testable against a tempdir.
///
/// `account_id` is joined onto the storage root verbatim, so it must be a
/// single normal path component: a value carrying a separator, a `..`, or an
/// absolute/prefixed path would escape `<data_local_dir>/cipherbox/`. Such an
/// id is an identity-layer bug, rejected here fail-closed rather than silently
/// sanitized (sanitizing could collide two distinct ids onto one dir).
pub fn account_data_dir(data_local_dir: &Path, account_id: &str) -> SeamResult<PathBuf> {
    if !is_single_normal_component(account_id) {
        return Err(SeamError::new(
            "account_data_dir: account_id must be a single path component",
        ));
    }
    Ok(data_local_dir.join("cipherbox").join(account_id))
}

/// True only when `account_id` is exactly one `Normal` path component with no
/// embedded separator on any platform — so `..`, `.`, `/tmp`, `a/b`, `C:\tmp`,
/// and the empty string are all rejected.
fn is_single_normal_component(account_id: &str) -> bool {
    if account_id.is_empty() || account_id.contains(['/', '\\']) {
        return false;
    }
    let mut components = Path::new(account_id).components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_the_cipherbox_account_root() {
        let dir = account_data_dir(Path::new("/var/lib"), "acct-42").unwrap();
        assert_eq!(dir, PathBuf::from("/var/lib/cipherbox/acct-42"));
    }

    #[test]
    fn rejects_ids_that_would_escape_the_root() {
        let base = Path::new("/var/lib");
        for bad in ["", "..", ".", "../other", "/tmp", "a/b", "C:\\tmp", "a\\b"] {
            assert!(
                account_data_dir(base, bad).is_err(),
                "account_id {bad:?} must be rejected"
            );
        }
    }
}
