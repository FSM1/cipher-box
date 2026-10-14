use std::ffi::{OsString, c_char, c_int};
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::ptr;

use crate::{Identity, Mounted};

/// Every filesystem the kernel has mounted now.
///
/// `MNT_NOWAIT` answers from the kernel's own table and asks no filesystem
/// for fresh statistics, so a volume that has stopped answering cannot hold
/// the read.
pub fn mounts() -> io::Result<Vec<Mounted>> {
    loop {
        // SAFETY: a null buffer with a zero size asks only for the count.
        let counted = unsafe { libc::getfsstat(ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        // One spare entry: a full buffer on the second call means a mount
        // landed in between, and the table is read again.
        let capacity = usize::try_from(counted).map_err(|_| io::Error::last_os_error())? + 1;
        let bytes = c_int::try_from(capacity * size_of::<libc::statfs>())
            .map_err(|_| io::Error::other("the mount table is too large to read"))?;
        let mut table: Vec<libc::statfs> = Vec::with_capacity(capacity);
        // SAFETY: `table` owns room for `capacity` entries and `bytes` is that
        // room exactly, so the kernel writes inside the allocation.
        let filled = unsafe { libc::getfsstat(table.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
        let filled = usize::try_from(filled).map_err(|_| io::Error::last_os_error())?;
        if filled >= capacity {
            continue;
        }
        // SAFETY: the kernel initialized the first `filled` entries.
        unsafe { table.set_len(filled) };
        return Ok(table.iter().map(mounted).collect());
    }
}

fn mounted(entry: &libc::statfs) -> Mounted {
    // SAFETY: `fsid_t` is two `i32`s with no padding, and its field is private.
    let fsid: [i32; 2] = unsafe { std::mem::transmute(entry.f_fsid) };
    Mounted {
        on: text_of(&entry.f_mntonname).into(),
        identity: Identity {
            fsid,
            fs_type: text_of(&entry.f_fstypename),
            from: text_of(&entry.f_mntfromname),
        },
    }
}

/// The NUL-terminated text the kernel wrote into a fixed field.
fn text_of(field: &[c_char]) -> OsString {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte as u8)
        .collect();
    OsString::from_vec(bytes)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn root(table: Vec<Mounted>) -> Mounted {
        table
            .into_iter()
            .find(|mounted| mounted.on == Path::new("/"))
            .expect("the root volume")
    }

    /// Every macOS host mounts its root volume, so a table that omits `/` was
    /// misread.
    #[test]
    fn the_table_lists_the_root_volume() {
        let root = root(mounts().expect("the mount table is readable"));
        assert!(!root.identity.fs_type.is_empty(), "{root:?}");
    }

    /// Two reads of one mount name it the same way.
    #[test]
    fn a_mount_keeps_its_identity_across_reads() {
        let first = root(mounts().expect("the mount table is readable"));
        let second = root(mounts().expect("the mount table is readable"));
        assert_eq!(first, second);
    }

    /// The field ends at its first NUL, whatever follows it.
    #[test]
    fn a_text_ends_at_its_terminator() {
        let mut field = [0 as c_char; 8];
        for (slot, byte) in field.iter_mut().zip(b"/a\0b") {
            *slot = *byte as c_char;
        }
        assert_eq!(text_of(&field), OsString::from("/a"));
    }
}
