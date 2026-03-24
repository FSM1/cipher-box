//! macOS-specific FUSE mount/unmount using FUSE-T with SMB backend.

use crate::mount_point;

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
