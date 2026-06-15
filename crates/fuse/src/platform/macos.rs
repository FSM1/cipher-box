//! macOS-specific FUSE mount/unmount using FUSE-T with SMB backend.

use crate::mount_point;
use std::path::Path;

/// Unmount the FUSE filesystem on macOS.
///
/// Calls `umount` first, then `diskutil unmount force` as fallback.
pub fn unmount_filesystem() -> Result<(), String> {
    let mount_path = mount_point();
    log::info!("Unmounting CipherBoxFS at {}", mount_path.display());

    let status = std::process::Command::new("umount")
        .arg(&mount_path)
        .status()
        .map_err(|e| format!("Failed to run umount: {}", e))?;

    if status.success() {
        log::info!("FUSE filesystem unmounted successfully");
        cleanup_temp_dir();
        Ok(())
    } else {
        log::info!("umount failed (likely busy), trying diskutil unmount force");
        let status = std::process::Command::new("diskutil")
            .arg("unmount")
            .arg("force")
            .arg(&mount_path)
            .status()
            .map_err(|e| format!("Failed to run diskutil unmount force: {}", e))?;

        if status.success() {
            log::info!("FUSE filesystem force-unmounted via diskutil");
            cleanup_temp_dir();
            Ok(())
        } else {
            Err(format!(
                "Failed to unmount {} -- close Finder windows and retry",
                mount_path.display()
            ))
        }
    }
}

fn cleanup_temp_dir() {
    let temp_dir = std::env::temp_dir().join("cipherbox");
    if temp_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&temp_dir) {
            log::warn!("Failed to clean temp directory: {}", e);
        }
    }
}

/// Returns true if `mount_path` appears as a mount point in the given
/// `mount(8)` output.
///
/// Pure function over the `mount` text + target path so it is unit-testable
/// without spawning `mount`. Each line has the form
/// `<source> on <mountpoint> (<type>, <opts>)`; the mount point is the text
/// between " on " and the trailing " (". macOS prints mount-point paths
/// literally (no octal escaping), so spaces are compared as-is.
pub(crate) fn mount_output_contains_mountpoint(mount_output: &str, mount_path: &Path) -> bool {
    for line in mount_output.lines() {
        if let Some((_, rest)) = line.split_once(" on ") {
            if let Some((mountpoint, _)) = rest.rsplit_once(" (") {
                if Path::new(mountpoint) == mount_path {
                    return true;
                }
            }
        }
    }
    false
}

/// Best-effort recovery of a stale FUSE-T (SMB) mount before (re)mounting at the
/// same path.
///
/// A crashed FUSE-T session can leave the mount path as a stale `smbfs` mount
/// backed by a now-dead in-process server, blocking remount until it is
/// force-unmounted (documented manual remedy: `diskutil unmount force`). We
/// consult `mount(8)` authoritatively; if the path is still mounted we clear it
/// (`umount`, then `diskutil unmount force` as a fallback for the stuck case).
///
/// macOS analog of `platform::linux::recover_stale_mount`. Best-effort: any
/// error (failure to run `mount`, failed unmount) is logged and the function
/// returns so the caller proceeds with its normal `exists()` / `create_dir_all`
/// / clean-stale logic.
pub fn recover_stale_mount(mount_path: &Path) {
    let output = match std::process::Command::new("mount").output() {
        Ok(o) => o,
        Err(e) => {
            log::info!("recover_stale_mount: could not run `mount` ({}); skipping", e);
            return;
        }
    };
    let mounts = String::from_utf8_lossy(&output.stdout);

    if !mount_output_contains_mountpoint(&mounts, mount_path) {
        // Not currently mounted; nothing to recover.
        return;
    }

    log::info!(
        "recover_stale_mount: stale mount detected at {}; unmounting",
        mount_path.display()
    );

    // Try a normal unmount first.
    if try_unmount("umount", &[], mount_path) {
        log::info!(
            "recover_stale_mount: unmounted stale mount via umount at {}",
            mount_path.display()
        );
        return;
    }
    log::info!("recover_stale_mount: umount failed; trying diskutil unmount force");

    // Force fallback for the stuck/disconnected case.
    if try_unmount("diskutil", &["unmount", "force"], mount_path) {
        log::info!(
            "recover_stale_mount: force-unmounted stale mount via diskutil at {}",
            mount_path.display()
        );
    } else {
        log::info!(
            "recover_stale_mount: diskutil unmount force also failed at {}; proceeding anyway",
            mount_path.display()
        );
    }
}

/// Run `<program> <pre_args> <mount_path>` and report whether it exited
/// successfully. Spawn/exec failures count as not-successful.
fn try_unmount(program: &str, pre_args: &[&str], mount_path: &Path) -> bool {
    matches!(
        std::process::Command::new(program)
            .args(pre_args)
            .arg(mount_path)
            .status(),
        Ok(s) if s.success()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn mount_output_detects_stale_smbfs() {
        let mount_output = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
//user@127.0.0.1/share on /Users/me/CipherBox (smbfs, nodev, nosuid, mounted by me)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)\n";
        assert!(mount_output_contains_mountpoint(mount_output, Path::new("/Users/me/CipherBox")));
        assert!(!mount_output_contains_mountpoint(mount_output, Path::new("/Users/me/NotMounted")));
    }

    #[test]
    fn mount_output_detects_stale_with_spaced_path() {
        // macOS prints mount-point paths literally (no octal escaping).
        let mount_output = "//user@127.0.0.1/share on /Users/me/My Vault (smbfs, nodev, nosuid)\n";
        assert!(mount_output_contains_mountpoint(mount_output, Path::new("/Users/me/My Vault")));
    }

    #[test]
    fn mount_output_ignores_substring_paths() {
        let mount_output = "//x on /Users/me/CipherBoxBackup (smbfs)\n";
        assert!(!mount_output_contains_mountpoint(mount_output, Path::new("/Users/me/CipherBox")));
    }
}
