//! Clearing a mount point a dead CipherBox left in the kernel's mount table.
//!
//! A crash or a kill leaves the entry behind pointing at a server that is gone,
//! so the next mount lands on top of it and fails. v1 recovered this per
//! platform; the adapters inherit it here.
//!
//! Force-unmounting is destructive, so it takes two proofs and not one: the
//! kernel's own listing must say the mount is CipherBox's, and the mount point
//! must answer with the errno a departed FUSE server leaves behind. A slow
//! answer is not a dead one — a live mount whose pump is busy would otherwise
//! lose every handle it holds to a sibling that started while it was working.

use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long the mount point has to answer before its silence is treated as
/// unknown — which refuses the mount rather than clearing it.
const ANSWERS_WITHIN: Duration = Duration::from_secs(2);

/// Shown when the mount point is held by a CipherBox that is still serving.
const STILL_SERVING: &str = "CipherBox is already mounted here; quit the other CipherBox first";

/// Shown when something that is not CipherBox's is mounted on the mount point.
const NOT_OURS: &str = "something else is mounted on this mount point";

/// Shown when the mount point is held by something this app cannot classify or
/// clear — the member has to unmount it.
const UNCLEARED: &str =
    "this mount point is held by a mount CipherBox cannot clear; unmount it and sign in again";

/// Clear `mountpoint` if a CipherBox that is gone still holds it, so the mount
/// about to be made can take it. Anything else mounted there is a refusal.
pub(crate) fn clear(mountpoint: &Path) -> io::Result<()> {
    if !is_ours(mountpoint)? {
        return match is_mounted(mountpoint)? {
            true => Err(io::Error::other(NOT_OURS)),
            false => Ok(()),
        };
    }
    match probe(mountpoint) {
        Answer::Serving => return Err(io::Error::other(STILL_SERVING)),
        Answer::Unknown => return Err(io::Error::other(UNCLEARED)),
        Answer::ServerGone => {}
    }
    force_unmount(mountpoint);
    match is_mounted(mountpoint)? {
        true => Err(io::Error::other(UNCLEARED)),
        false => Ok(()),
    }
}

/// What the mount point said when asked.
enum Answer {
    /// It answered: a server is behind it.
    Serving,
    /// It answered with the errno a FUSE mount whose server has departed
    /// returns, which is the one proof this module force-unmounts on.
    ServerGone,
    /// It refused for another reason, or did not answer within
    /// [`ANSWERS_WITHIN`]. Slow is not dead.
    Unknown,
}

/// Ask the mount point for its metadata, on a thread of its own so a server
/// that never answers holds that thread and not this one.
fn probe(mountpoint: &Path) -> Answer {
    let (reply, answer) = mpsc::channel();
    let probed = mountpoint.to_path_buf();
    std::thread::spawn(move || {
        let _ = reply.send(match std::fs::symlink_metadata(&probed) {
            Ok(_) => Answer::Serving,
            Err(error) if departed(&error) => Answer::ServerGone,
            Err(_) => Answer::Unknown,
        });
    });
    answer
        .recv_timeout(ANSWERS_WITHIN)
        .unwrap_or(Answer::Unknown)
}

/// Whether `error` is what the kernel answers for a mount whose server is gone.
fn departed(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOTCONN | libc::ENXIO | libc::ETIMEDOUT | libc::EHOSTDOWN)
    )
}

/// Run `program` over `mountpoint` and report whether it exited successfully.
/// Resolved absolutely: a mount is not something to hand to whatever `PATH`
/// names. Its diagnostics carry the mount path, so they go nowhere.
fn ran(candidates: &[&str], arguments: &[&str], mountpoint: &Path) -> bool {
    candidates.iter().any(|program| {
        matches!(
            Command::new(program)
                .args(arguments)
                .arg(mountpoint)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
            Ok(status) if status.success()
        )
    })
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    const FUSERMOUNT: &[&str] = &["/usr/bin/fusermount3", "/bin/fusermount3"];
    const UMOUNT: &[&str] = &["/usr/bin/umount", "/bin/umount", "/sbin/umount"];

    /// The mount table this kernel keeps for this process.
    pub(super) fn table() -> io::Result<String> {
        std::fs::read_to_string("/proc/self/mountinfo")
    }

    /// Unmount, then unmount lazily: the lazy form detaches a mount point whose
    /// server is gone, which the plain form refuses as busy.
    pub(super) fn force_unmount(mountpoint: &Path) {
        let _ = ran(FUSERMOUNT, &["-u"], mountpoint)
            || ran(FUSERMOUNT, &["-u", "-z"], mountpoint)
            || ran(UMOUNT, &["-l"], mountpoint);
    }

    /// Whether `mountpoint` is listed, and whether the entry is a FUSE mount
    /// this app made — `mount_options`' `FSName("cipherbox")` is the source, so
    /// the listing itself says whose the mount is.
    pub(super) fn entry(table: &str, mountpoint: &Path) -> Option<bool> {
        table.lines().find_map(|line| {
            let (before, after) = line.split_once(" - ")?;
            (Path::new(&unescape(before.split(' ').nth(4)?)) == mountpoint).then(|| {
                let mut fields = after.split(' ');
                let kind = fields.next().unwrap_or_default();
                let source = fields.next().unwrap_or_default();
                kind.starts_with("fuse") && source == "cipherbox"
            })
        })
    }

    /// Decode the four escapes proc(5) emits in a mountinfo path. `\134` is
    /// decoded last, so a path that literally contains `\040` stays one.
    fn unescape(field: &str) -> String {
        field
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    const UMOUNT: &[&str] = &["/sbin/umount", "/usr/sbin/umount"];
    const DISKUTIL: &[&str] = &["/usr/sbin/diskutil"];
    const MOUNT: &[&str] = &["/sbin/mount", "/usr/sbin/mount"];

    /// FUSE-T projects its mounts through the SMB client, so smbfs is the only
    /// filesystem type a CipherBox mount can appear under.
    const OURS: &str = "smbfs";

    pub(super) fn table() -> io::Result<String> {
        let listing = MOUNT
            .iter()
            .find_map(|program| Command::new(program).stderr(Stdio::null()).output().ok())
            .ok_or_else(|| io::Error::other("the mount table could not be read"))?;
        Ok(String::from_utf8_lossy(&listing.stdout).into_owned())
    }

    /// `umount` first, then the force smbfs needs once its server is gone.
    pub(super) fn force_unmount(mountpoint: &Path) {
        let _ = ran(UMOUNT, &[], mountpoint)
            || ran(UMOUNT, &["-f"], mountpoint)
            || ran(DISKUTIL, &["unmount", "force"], mountpoint);
    }

    /// Whether `mountpoint` is listed, and whether the entry is smbfs. Each
    /// line reads `<source> on <mountpoint> (<type>, …)`, and macOS prints the
    /// path literally.
    pub(super) fn entry(table: &str, mountpoint: &Path) -> Option<bool> {
        table.lines().find_map(|line| {
            let (_, rest) = line.split_once(" on ")?;
            let (found, kinds) = rest.rsplit_once(" (")?;
            (Path::new(found) == mountpoint)
                .then(|| kinds.split(',').next().unwrap_or_default().trim() == OURS)
        })
    }
}

use platform::force_unmount;

/// Whether anything at all is mounted on `mountpoint`.
fn is_mounted(mountpoint: &Path) -> io::Result<bool> {
    Ok(platform::entry(&platform::table()?, mountpoint).is_some())
}

/// Whether the mount on `mountpoint` is one this app made.
fn is_ours(mountpoint: &Path) -> io::Result<bool> {
    Ok(platform::entry(&platform::table()?, mountpoint).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount point nothing has mounted is left for `prepare` to make, and the
    /// kernel's listing is what says so without touching the path.
    #[test]
    fn an_unmounted_point_needs_no_recovery() {
        let dir = tempfile::tempdir().expect("a temp dir");
        clear(&dir.path().join("CipherBox")).expect("nothing to clear");
    }

    /// A path that answers is serving, and a path that is absent answers with
    /// an errno that is not a departed server's — neither is cleared.
    #[test]
    fn only_a_departed_servers_errno_is_read_as_death() {
        let dir = tempfile::tempdir().expect("a temp dir");
        assert!(matches!(probe(dir.path()), Answer::Serving));
        assert!(matches!(probe(&dir.path().join("absent")), Answer::Unknown));
        assert!(!departed(&io::Error::from_raw_os_error(libc::ENOENT)));
        assert!(departed(&io::Error::from_raw_os_error(libc::ENOTCONN)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_listing_says_whether_a_mount_point_is_this_apps() {
        let table = "\
25 30 0:23 / /proc rw,nosuid shared:5 - proc proc rw
41 30 0:39 / /home/me/CipherBox rw,nosuid - fuse cipherbox rw
42 30 0:40 / /home/me/CipherBox\\040Backup rw - fuse cipherbox rw
43 30 0:41 / /home/me/Elsewhere rw - fuse sshfs rw\n";

        assert_eq!(
            platform::entry(table, Path::new("/home/me/CipherBox")),
            Some(true)
        );
        assert_eq!(
            platform::entry(table, Path::new("/home/me/CipherBox Backup")),
            Some(true),
            "a mount point with an escaped space is decoded before it is compared"
        );
        assert_eq!(
            platform::entry(table, Path::new("/home/me/Elsewhere")),
            Some(false),
            "another FUSE filesystem is listed but is not this app's to unmount"
        );
        assert_eq!(
            platform::entry(table, Path::new("/home/me/Cipher")),
            None,
            "a prefix of a mount point is not one"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_listing_says_whether_a_mount_point_is_this_apps() {
        let table = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
//me@127.0.0.1/share on /Users/me/CipherBox (smbfs, nodev, nosuid)
//me@127.0.0.1/other on /Users/me/My Vault (smbfs, nodev, nosuid)
/dev/disk5s1 on /Users/me/Elsewhere (exfat, local, nodev)\n";

        assert_eq!(
            platform::entry(table, Path::new("/Users/me/CipherBox")),
            Some(true)
        );
        assert_eq!(
            platform::entry(table, Path::new("/Users/me/My Vault")),
            Some(true),
            "a mount point with a space is printed literally"
        );
        assert_eq!(
            platform::entry(table, Path::new("/Users/me/Elsewhere")),
            Some(false),
            "a volume the member mounted is not this app's to unmount"
        );
        assert_eq!(
            platform::entry(table, Path::new("/Users/me/CipherBoxBackup")),
            None,
            "a longer path that starts the same is not this mount point"
        );
    }
}
