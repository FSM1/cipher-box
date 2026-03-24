//! Linux-specific FUSE mount/unmount using kernel FUSE.

use crate::mount_point;

/// Unmount the FUSE filesystem on Linux.
///
/// Tries fusermount3, fusermount (FUSE 2), then umount as last resort.
pub fn unmount_filesystem() -> Result<(), String> {
    let mount_path = mount_point();
    log::info!("Unmounting CipherBoxFS at {}", mount_path.display());

    let temp_dir = std::env::temp_dir().join("cipherbox");
    if temp_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&temp_dir) {
            log::warn!("Failed to clean temp directory: {}", e);
        }
    }

    let mount_str = mount_path.to_str().unwrap();

    // Try fusermount3 first (preferred, doesn't require root)
    let status = std::process::Command::new("fusermount3")
        .args(["-u", mount_str])
        .status();

    match status {
        Ok(s) if s.success() => {
            log::info!("FUSE filesystem unmounted via fusermount3");
            return Ok(());
        }
        _ => {
            log::info!("fusermount3 failed, trying fusermount (FUSE 2 compat)");
        }
    }

    // Fallback to fusermount (FUSE 2 compat)
    let status = std::process::Command::new("fusermount")
        .args(["-u", mount_str])
        .status();

    match status {
        Ok(s) if s.success() => {
            log::info!("FUSE filesystem unmounted via fusermount");
            return Ok(());
        }
        _ => {
            log::info!("fusermount failed, trying umount (may need privileges)");
        }
    }

    // Last resort: umount
    let status = std::process::Command::new("umount")
        .arg(mount_str)
        .status()
        .map_err(|e| format!("Failed to run umount: {}", e))?;

    if status.success() {
        log::info!("FUSE filesystem unmounted via umount");
        Ok(())
    } else {
        Err(format!(
            "Failed to unmount {} -- close file managers and retry",
            mount_path.display()
        ))
    }
}
