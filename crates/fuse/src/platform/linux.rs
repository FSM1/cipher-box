//! Linux-specific FUSE mount/unmount using kernel FUSE.

use crate::mount_point;
use std::path::Path;

/// Unmount the FUSE filesystem on Linux.
///
/// Tries fusermount3, fusermount (FUSE 2), then umount as last resort.
pub fn unmount_filesystem() -> Result<(), String> {
    let mount_path = mount_point();
    log::info!("Unmounting CipherBoxFS at {}", mount_path.display());

    // Try fusermount3 first (preferred, doesn't require root)
    let status = std::process::Command::new("fusermount3")
        .arg("-u")
        .arg(&mount_path)
        .status();

    match status {
        Ok(s) if s.success() => {
            log::info!("FUSE filesystem unmounted via fusermount3");
            cleanup_temp_dir();
            return Ok(());
        }
        _ => {
            log::info!("fusermount3 failed, trying fusermount (FUSE 2 compat)");
        }
    }

    // Fallback to fusermount (FUSE 2 compat)
    let status = std::process::Command::new("fusermount")
        .arg("-u")
        .arg(&mount_path)
        .status();

    match status {
        Ok(s) if s.success() => {
            log::info!("FUSE filesystem unmounted via fusermount");
            cleanup_temp_dir();
            return Ok(());
        }
        _ => {
            log::info!("fusermount failed, trying umount (may need privileges)");
        }
    }

    // Last resort: umount
    let status = std::process::Command::new("umount")
        .arg(&mount_path)
        .status()
        .map_err(|e| format!("Failed to run umount: {}", e))?;

    if status.success() {
        log::info!("FUSE filesystem unmounted via umount");
        cleanup_temp_dir();
        Ok(())
    } else {
        Err(format!(
            "Failed to unmount {} -- close file managers and retry",
            mount_path.display()
        ))
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

/// Un-escape a `/proc/self/mountinfo` field.
///
/// mountinfo encodes whitespace and a few control characters as octal escapes
/// (`\NNN`), most notably space as `\040`. Decode them so a path comparison
/// against a real on-disk path matches.
fn unescape_mountinfo_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // A backslash followed by exactly three octal digits is an escape.
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let d0 = bytes[i + 1];
            let d1 = bytes[i + 2];
            let d2 = bytes[i + 3];
            if d0.is_ascii_digit()
                && d0 <= b'7'
                && d1.is_ascii_digit()
                && d1 <= b'7'
                && d2.is_ascii_digit()
                && d2 <= b'7'
            {
                let value = ((d0 - b'0') << 6) | ((d1 - b'0') << 3) | (d2 - b'0');
                out.push(value);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Returns true if `mount_path` appears as a mount point in the given
/// `/proc/self/mountinfo` content.
///
/// Pure function over the mountinfo text + target path so it is unit-testable
/// without reading `/proc`. The mount-point is field index 4 (0-based,
/// space-separated) of each line; mountinfo octal-escapes (e.g. `\040` for
/// space) are decoded before comparison.
pub(crate) fn mountinfo_contains_mountpoint(mountinfo: &str, mount_path: &Path) -> bool {
    for line in mountinfo.lines() {
        let mut fields = line.split(' ');
        // Field index 4 is the mount point.
        if let Some(raw_mountpoint) = fields.nth(4) {
            let decoded = unescape_mountinfo_field(raw_mountpoint);
            if Path::new(&decoded) == mount_path {
                return true;
            }
        }
    }
    false
}

/// Best-effort recovery of a stale/disconnected Linux FUSE mount before
/// (re)mounting at the same path.
///
/// A crashed FUSE session leaves the mount point in a disconnected state where
/// `stat()` returns ENOTCONN, so `Path::exists()` lies (returns false). We
/// instead consult `/proc/self/mountinfo` authoritatively; if the mount point
/// is still present we unmount it (`fusermount3 -u`, then lazy `fusermount3 -z
/// -u` as a fallback for the disconnected case).
///
/// This is best-effort: any error (failure to read mountinfo, failed unmount)
/// is logged and the function returns so the caller proceeds with its normal
/// `exists()` / `create_dir_all` / clean-stale logic.
pub fn recover_stale_mount(mount_path: &Path) {
    let mountinfo = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(contents) => contents,
        Err(e) => {
            log::info!(
                "recover_stale_mount: could not read /proc/self/mountinfo ({}); skipping",
                e
            );
            return;
        }
    };

    if !mountinfo_contains_mountpoint(&mountinfo, mount_path) {
        // Not currently mounted (or not stale); nothing to recover.
        return;
    }

    log::info!(
        "recover_stale_mount: stale mount detected at {}; unmounting",
        mount_path.display()
    );

    // Try a normal unmount first.
    if try_fusermount3_unmount(mount_path, &["-u"]) {
        log::info!(
            "recover_stale_mount: unmounted stale mount via fusermount3 -u at {}",
            mount_path.display()
        );
        return;
    }
    log::info!("recover_stale_mount: fusermount3 -u failed; trying lazy fusermount3 -z -u");

    // Lazy unmount fallback for the disconnected case. -z detaches the mount
    // now and cleans up references as they are released; acceptable since we
    // immediately mount a fresh session at the same path.
    if try_fusermount3_unmount(mount_path, &["-z", "-u"]) {
        log::info!(
            "recover_stale_mount: lazily unmounted stale mount via fusermount3 -z -u at {}",
            mount_path.display()
        );
    } else {
        log::info!(
            "recover_stale_mount: lazy fusermount3 -z -u also failed at {}; proceeding anyway",
            mount_path.display()
        );
    }
}

/// Run `fusermount3 <args> <mount_path>` and report whether it exited
/// successfully. Spawn/exec failures count as not-successful.
fn try_fusermount3_unmount(mount_path: &Path, args: &[&str]) -> bool {
    matches!(
        std::process::Command::new("fusermount3")
            .args(args)
            .arg(mount_path)
            .status(),
        Ok(s) if s.success()
    )
}

/// Pure decision helper: should a `create_dir_all` error trigger
/// recover-then-retry-once?
///
/// Returns true only for `ErrorKind::AlreadyExists` (EEXIST), which is the
/// symptom of a disconnected FUSE mount whose dirent still exists. Any other
/// error kind propagates to the caller unchanged.
pub(crate) fn should_recover_then_retry(err_kind: std::io::ErrorKind) -> bool {
    err_kind == std::io::ErrorKind::AlreadyExists
}

/// Create the mount-point directory, recovering once from a stale FUSE mount.
///
/// Belt-and-suspenders for the Linux stale-mount case: a disconnected FUSE
/// mount whose dirent still exists surfaces as EEXIST from `create_dir_all`
/// even though `Path::exists()` returned false. On that specific error we
/// recover the stale mount and retry once; any other error propagates.
pub fn create_mount_point_dir(mount_path: &Path) -> std::io::Result<()> {
    match std::fs::create_dir_all(mount_path) {
        Ok(()) => Ok(()),
        Err(e) if should_recover_then_retry(e.kind()) => {
            recover_stale_mount(mount_path);
            std::fs::create_dir_all(mount_path)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn mountinfo_detects_stale() {
        let mountinfo = "\
36 35 0:30 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 36 0:31 / /home/user/CipherBox rw,nosuid,nodev,relatime shared:2 - fuse.CipherBox CipherBox rw
41 36 0:32 / /home/user/other rw,relatime shared:3 - ext4 /dev/sdb1 rw\n";

        let target = Path::new("/home/user/CipherBox");
        assert!(
            mountinfo_contains_mountpoint(mountinfo, target),
            "expected the CipherBox mount point to be detected"
        );

        let absent = Path::new("/home/user/NotMounted");
        assert!(
            !mountinfo_contains_mountpoint(mountinfo, absent),
            "expected an unmounted path to be absent"
        );
    }

    #[test]
    fn mountinfo_detects_stale_with_spaced_path() {
        // mountinfo escapes the space in "My Vault" as \040.
        let mountinfo = "\
36 35 0:30 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 36 0:31 / /home/user/My\\040Vault rw,nosuid,nodev,relatime shared:2 - fuse.CipherBox CipherBox rw\n";

        let target = Path::new("/home/user/My Vault");
        assert!(
            mountinfo_contains_mountpoint(mountinfo, target),
            "expected a mount point with an escaped space (\\040) to be detected"
        );
    }

    #[test]
    fn eexist_triggers_recovery() {
        assert!(
            should_recover_then_retry(std::io::ErrorKind::AlreadyExists),
            "AlreadyExists (EEXIST) must trigger recover-then-retry"
        );
        assert!(
            !should_recover_then_retry(std::io::ErrorKind::NotFound),
            "NotFound must not trigger recovery"
        );
        assert!(
            !should_recover_then_retry(std::io::ErrorKind::PermissionDenied),
            "PermissionDenied must not trigger recovery"
        );
    }
}
