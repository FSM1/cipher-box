use std::ffi::{OsStr, c_char, c_int};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

/// The mount point of every filesystem the kernel has mounted now.
///
/// `MNT_NOWAIT` answers from the kernel's own table and asks no filesystem
/// for fresh statistics, so a volume that has stopped answering cannot hold
/// the read.
pub fn mount_points() -> io::Result<Vec<PathBuf>> {
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
        return Ok(table
            .iter()
            .map(|entry| path_of(&entry.f_mntonname))
            .collect());
    }
}

/// The NUL-terminated path the kernel wrote into a fixed field.
fn path_of(field: &[c_char]) -> PathBuf {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte as u8)
        .collect();
    PathBuf::from(OsStr::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every macOS host mounts its root volume, so a table that omits `/` was
    /// misread.
    #[test]
    fn the_table_lists_the_root_volume() {
        let points = mount_points().expect("the mount table is readable");
        assert!(
            points.iter().any(|point| point == OsStr::new("/")),
            "{points:?}"
        );
    }

    /// The field ends at its first NUL, whatever follows it.
    #[test]
    fn a_path_ends_at_its_terminator() {
        let mut field = [0 as c_char; 8];
        for (slot, byte) in field.iter_mut().zip(b"/a\0b") {
            *slot = *byte as c_char;
        }
        assert_eq!(path_of(&field), PathBuf::from("/a"));
    }
}
