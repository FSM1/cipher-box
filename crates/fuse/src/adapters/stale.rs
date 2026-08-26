//! Clearing a mount point a dead CipherBox left in the kernel's mount table.
//!
//! A crash or a kill leaves the mount point pointing at a server that is gone:
//! the entry survives in the table, every access answers `ENOTCONN` (or hangs),
//! and the next mount lands on top of it and fails. v1 recovered this per
//! platform; the adapters inherit it here.
//!
//! Nothing in this module touches the mount itself except [`answers`], which is
//! bounded — the table is read from the kernel's own listing, so a mount point
//! with no server behind it cannot block the probe.

use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

/// How long a mount point has to answer before it is treated as dead. Only a
/// mount whose server is hung takes the whole wait, and it is paid on the
/// mounting thread rather than the session loop.
const ANSWERS_WITHIN: Duration = Duration::from_secs(2);

/// Clear `mountpoint` if a CipherBox that is gone still holds it, so the mount
/// about to be made can take it.
///
/// A mount point whose server still answers is left alone: that is a live
/// projection, and the mount that follows refuses rather than stealing it.
pub(crate) fn clear(mountpoint: &Path) -> io::Result<()> {
    if !is_mounted(mountpoint)? || answers(mountpoint) {
        return Ok(());
    }
    force_unmount(mountpoint);
    if is_mounted(mountpoint)? {
        return Err(io::Error::other(
            "a CipherBox that is gone still holds this mount point; unmount it and sign in again",
        ));
    }
    Ok(())
}

/// Whether the mount point answers a `stat` within [`ANSWERS_WITHIN`]. The
/// probe runs on a thread of its own, so a hung server holds that thread and
/// not this one.
fn answers(mountpoint: &Path) -> bool {
    let (reply, answer) = mpsc::channel();
    let probed = mountpoint.to_path_buf();
    std::thread::spawn(move || {
        let _ = reply.send(std::fs::symlink_metadata(&probed).is_ok());
    });
    answer.recv_timeout(ANSWERS_WITHIN).unwrap_or(false)
}

/// Run `program` over `mountpoint` and report whether it exited successfully.
/// A program that is not installed counts as one that did not unmount.
fn ran(program: &str, arguments: &[&str], mountpoint: &Path) -> bool {
    matches!(
        Command::new(program).args(arguments).arg(mountpoint).status(),
        Ok(status) if status.success()
    )
}

#[cfg(target_os = "linux")]
fn is_mounted(mountpoint: &Path) -> io::Result<bool> {
    Ok(mountinfo_lists(
        &std::fs::read_to_string("/proc/self/mountinfo")?,
        mountpoint,
    ))
}

/// Unmount, then unmount lazily: the lazy form detaches a mount point whose
/// server is gone, which the plain form refuses as busy.
#[cfg(target_os = "linux")]
fn force_unmount(mountpoint: &Path) {
    let _ = ran("fusermount3", &["-u"], mountpoint)
        || ran("fusermount3", &["-u", "-z"], mountpoint)
        || ran("umount", &["-l"], mountpoint);
}

/// Whether `mountpoint` appears in `/proc/self/mountinfo` content. The mount
/// point is field 4; mountinfo octal-escapes whitespace in it, so the field is
/// decoded before it is compared.
#[cfg(target_os = "linux")]
fn mountinfo_lists(mountinfo: &str, mountpoint: &Path) -> bool {
    mountinfo.lines().any(|line| {
        line.split(' ')
            .nth(4)
            .is_some_and(|field| Path::new(&unescape(field)) == mountpoint)
    })
}

/// Decode mountinfo's `\NNN` octal escapes (space is `\040`).
#[cfg(target_os = "linux")]
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let octal = bytes
            .get(at + 1..at + 4)
            .filter(|_| bytes[at] == b'\\')
            .and_then(|digits| {
                digits.iter().try_fold(0u8, |value, digit| match digit {
                    b'0'..=b'7' => Some(value * 8 + (digit - b'0')),
                    _ => None,
                })
            });
        match octal {
            Some(byte) => {
                out.push(byte);
                at += 4;
            }
            None => {
                out.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(target_os = "macos")]
fn is_mounted(mountpoint: &Path) -> io::Result<bool> {
    let listing = Command::new("mount").output()?;
    Ok(mount_lists(
        &String::from_utf8_lossy(&listing.stdout),
        mountpoint,
    ))
}

/// `umount` first, then the force that smbfs needs once its server is gone.
#[cfg(target_os = "macos")]
fn force_unmount(mountpoint: &Path) {
    let _ = ran("umount", &[], mountpoint)
        || ran("umount", &["-f"], mountpoint)
        || ran("diskutil", &["unmount", "force"], mountpoint);
}

/// Whether `mountpoint` appears in `mount(8)` output. Each line reads
/// `<source> on <mountpoint> (<type>, …)`, and macOS prints the path literally.
#[cfg(target_os = "macos")]
fn mount_lists(listing: &str, mountpoint: &Path) -> bool {
    listing.lines().any(|line| {
        line.split_once(" on ")
            .and_then(|(_, rest)| rest.rsplit_once(" ("))
            .is_some_and(|(found, _)| Path::new(found) == mountpoint)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount point nothing has mounted is left for `prepare` to make, and a
    /// probe that consults the kernel's listing is what says so without
    /// touching the path.
    #[test]
    fn an_unmounted_point_needs_no_recovery() {
        let dir = tempfile::tempdir().expect("a temp dir");
        clear(&dir.path().join("CipherBox")).expect("nothing to clear");
    }

    /// A live mount point answers, and answering is what keeps this from
    /// force-unmounting a projection that is still serving.
    #[test]
    fn a_directory_that_answers_is_not_touched() {
        let dir = tempfile::tempdir().expect("a temp dir");
        assert!(answers(dir.path()));
        assert!(
            !answers(&dir.path().join("absent")),
            "a stat that fails is not an answer"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mountinfo_names_the_mount_point_field() {
        let mountinfo = "\
25 30 0:23 / /proc rw,nosuid shared:5 - proc proc rw
41 30 0:39 / /home/me/CipherBox rw,nosuid - fuse cipherbox rw
42 30 0:40 / /home/me/CipherBox\\040Backup rw - fuse cipherbox rw\n";

        assert!(mountinfo_lists(mountinfo, Path::new("/home/me/CipherBox")));
        assert!(mountinfo_lists(
            mountinfo,
            Path::new("/home/me/CipherBox Backup")
        ));
        assert!(
            !mountinfo_lists(mountinfo, Path::new("/home/me/Cipher")),
            "a prefix of a mount point is not one"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mount_output_names_the_mount_point() {
        let listing = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
//me@127.0.0.1/share on /Users/me/CipherBox (smbfs, nodev, nosuid)
//me@127.0.0.1/other on /Users/me/My Vault (smbfs, nodev, nosuid)\n";

        assert!(mount_lists(listing, Path::new("/Users/me/CipherBox")));
        assert!(
            mount_lists(listing, Path::new("/Users/me/My Vault")),
            "a mount point with a space is printed literally"
        );
        assert!(
            !mount_lists(listing, Path::new("/Users/me/CipherBoxBackup")),
            "a longer path that starts the same is not this mount point"
        );
    }
}
