//! Linux-specific FUSE mount/unmount using kernel FUSE.

use crate::mount_point;

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
