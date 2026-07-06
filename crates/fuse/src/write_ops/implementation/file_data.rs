use fuser::{ReplyAttr, ReplyCreate, ReplyWrite};
use std::sync::atomic::Ordering;
use std::time::SystemTime;

use crate::file_handle::OpenFileHandle;
use crate::helpers::is_platform_special;
use crate::inode::{FileAttrs, InodeData, InodeKind};
use crate::operations::implementation::{current_gid, current_uid, ttl_for_is_dir, FILE_TTL};
use crate::CipherBoxFS;

/// Set file attributes (handles truncate via size parameter).
pub fn handle_setattr(
    fs: &mut CipherBoxFS,
    ino: u64,
    size: Option<u64>,
    fh: Option<u64>,
    reply: ReplyAttr,
) {
    log::debug!("setattr: ino={} size={:?} fh={:?}", ino, size, fh);
    if let Some(new_size) = size {
        if let Some(fh_id) = fh {
            if let Some(handle) = fs.open_files.get_mut(&fh_id) {
                if handle.temp_path.is_some() {
                    if let Err(e) = handle.truncate(new_size) {
                        log::error!("Truncate failed for ino {}: {}", ino, e);
                        reply.error(libc::EIO);
                        return;
                    }
                    handle.dirty = true;
                }
            }
        } else {
            // No explicit fh -- find open writable handle for this inode
            let matching_fh: Option<u64> = fs
                .open_files
                .iter()
                .find(|(_, h)| h.ino == ino && h.temp_path.is_some())
                .map(|(id, _)| *id);
            if let Some(fh_id) = matching_fh {
                if let Some(handle) = fs.open_files.get_mut(&fh_id) {
                    if let Err(e) = handle.truncate(new_size) {
                        log::error!("Truncate (no-fh) failed for ino {}: {}", ino, e);
                        reply.error(libc::EIO);
                        return;
                    }
                    handle.dirty = true;
                }
            }
        }

        if let Some(inode) = fs.inodes.get_mut(ino) {
            inode.attr.size = new_size;
            inode.attr.blocks = (new_size + 511) / 512;
            inode.attr.mtime = SystemTime::now();

            if new_size == 0 {
                inode.write_generation += 1;
                if let InodeKind::File {
                    size: ref mut s,
                    cid: ref mut c,
                    ..
                } = inode.kind
                {
                    *s = 0;
                    *c = String::new();
                }
            } else {
                if let InodeKind::File {
                    size: ref mut s, ..
                } = inode.kind
                {
                    *s = new_size;
                }
            }

            reply.attr(
                &ttl_for_is_dir(inode.attr.is_dir),
                &inode.attr.to_fuse_attr(current_uid(), current_gid()),
            );
            return;
        }
    }

    if let Some(inode) = fs.inodes.get(ino) {
        reply.attr(
            &ttl_for_is_dir(inode.attr.is_dir),
            &inode.attr.to_fuse_attr(current_uid(), current_gid()),
        );
    } else {
        reply.error(libc::ENOENT);
    }
}

/// Write data to an open file.
pub fn handle_write(
    fs: &mut CipherBoxFS,
    ino: u64,
    fh: u64,
    offset: i64,
    data: &[u8],
    reply: ReplyWrite,
) {
    // D-05: reject negative offsets before write_at (EINVAL)
    if offset < 0 {
        reply.error(libc::EINVAL);
        return;
    }
    let offset_u64 = offset as u64;
    // D-05: guard offset+len overflow before write_at (EFBIG)
    let new_end = match offset_u64.checked_add(data.len() as u64) {
        Some(end) => end,
        None => {
            reply.error(libc::EFBIG);
            return;
        }
    };

    let handle = match fs.open_files.get_mut(&fh) {
        Some(h) => h,
        None => {
            reply.error(libc::EBADF);
            return;
        }
    };

    match handle.write_at(offset, data) {
        Ok(written) => {
            if let Some(inode) = fs.inodes.get_mut(ino) {
                if new_end > inode.attr.size {
                    inode.attr.size = new_end;
                    inode.attr.blocks = (new_end + 511) / 512;
                }
                inode.attr.mtime = SystemTime::now();
            }
            reply.written(written as u32);
        }
        Err(e) => {
            log::error!("Write failed for ino {} fh {}: {}", ino, fh, e);
            reply.error(libc::EIO);
        }
    }
}

/// Create a new file in a directory.
pub fn handle_create(
    fs: &mut CipherBoxFS,
    parent: u64,
    name: &std::ffi::OsStr,
    _flags: i32,
    reply: ReplyCreate,
) {
    let name_str = match name.to_str() {
        Some(n) => n,
        None => {
            reply.error(libc::EINVAL);
            return;
        }
    };

    if is_platform_special(name_str) {
        reply.error(libc::EACCES);
        return;
    }

    let parent_exists = fs.inodes.get(parent).map(|inode| {
        matches!(
            inode.kind,
            InodeKind::Root { .. } | InodeKind::Folder { .. }
        )
    });
    if parent_exists != Some(true) {
        reply.error(libc::ENOENT);
        return;
    }

    // D-06: reject duplicate child names before mutating the inode table (EEXIST)
    if fs.inodes.find_child(parent, name_str).is_some() {
        reply.error(libc::EEXIST);
        return;
    }

    let ino = fs.inodes.allocate_ino();
    let now = SystemTime::now();

    let attr = FileAttrs {
        ino,
        size: 0,
        blocks: 0,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        is_dir: false,
        perm: 0o666,
        nlink: 1,
    };
    let fuse_attr = attr.to_fuse_attr(current_uid(), current_gid());

    // Generate random Ed25519 IPNS keypair for this file
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let file_ipns_private_key = signing_key.to_bytes().to_vec();
    let file_ipns_public_key_bytes: [u8; 32] = verifying_key.to_bytes();
    let file_ipns_name = match cipherbox_core::ipns::derive_ipns_name(&file_ipns_public_key_bytes) {
        Ok(name) => name,
        Err(e) => {
            log::error!(
                "create: IPNS name derivation from random keypair failed: {}",
                e
            );
            reply.error(libc::EIO);
            return;
        }
    };

    // node/v3: mint the file node's OWN symmetric read/write keys. The file's
    // content key is minted per-write in build_upload_journal_entry; these keys
    // seal the file NODE (read-body / write-body). The former user-ECIES wrap of
    // the IPNS key is gone — the raw signing seed lives in the inode (zeroized
    // on drop) and is TEE-wrapped only at publish time (rule #7).
    let read_key = cipherbox_crypto::utils::generate_file_key();
    let write_key = cipherbox_crypto::utils::generate_file_key();

    let inode = InodeData {
        ino,
        parent_ino: parent,
        name: name_str.to_string(),
        kind: InodeKind::File {
            ipns_name: file_ipns_name,
            cid: String::new(),
            size: 0,
            encryption_mode: "GCM".to_string(),
            iv: String::new(),
            read_key: zeroize::Zeroizing::new(read_key),
            write_key: zeroize::Zeroizing::new(write_key),
            ipns_private_key: zeroize::Zeroizing::new(file_ipns_private_key),
        },
        attr,
        children: None,
        write_generation: 0,
    };

    fs.inodes.insert(inode);

    if let Some(parent_inode) = fs.inodes.get_mut(parent) {
        if let Some(ref mut children) = parent_inode.children {
            children.push(ino);
        }
        parent_inode.attr.mtime = SystemTime::now();
        parent_inode.attr.ctime = SystemTime::now();
    }

    let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
    match OpenFileHandle::new_write(ino, &fs.temp_dir, None) {
        Ok(handle) => {
            fs.open_files.insert(fh, handle);
        }
        Err(e) => {
            log::error!("Failed to create temp file for new file: {}", e);
            fs.inodes.remove(ino);
            if let Some(parent_inode) = fs.inodes.get_mut(parent) {
                if let Some(ref mut children) = parent_inode.children {
                    children.retain(|&child| child != ino);
                }
            }
            reply.error(libc::EIO);
            return;
        }
    }

    fs.mutated_folders.insert(parent, std::time::Instant::now());

    log::debug!(
        "create: {} in parent {} -> ino {} fh {}",
        name_str,
        parent,
        ino,
        fh
    );
    reply.created(&FILE_TTL, &fuse_attr, 0, fh, 0);
}

#[cfg(all(test, feature = "fuse"))]
mod tests {
    use super::*;
    use crate::inode::{FileAttrs, InodeData, InodeKind, ROOT_INO};
    use crate::test_support::{make_test_fs, reply_error_code, CaptureSender};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    // D-05 arithmetic: checked_add overflow predicate matches the guard logic
    #[test]
    fn d05_offset_overflow_predicate_at_boundary() {
        let offset_u64: u64 = u64::MAX;
        let len: u64 = 1;
        assert!(
            offset_u64.checked_add(len).is_none(),
            "u64::MAX + 1 must overflow"
        );
    }

    // D-05 arithmetic: no overflow within u64 range
    #[test]
    fn d05_offset_no_overflow_within_range() {
        let offset_u64: u64 = 100;
        let len: u64 = 200;
        assert_eq!(offset_u64.checked_add(len), Some(300));
    }

    // D-06 existence: find_child returns Some for a known duplicate name
    #[tokio::test]
    async fn d06_find_child_detects_duplicate() {
        let mut fs = make_test_fs();
        let now = SystemTime::now();

        // Insert a child folder under ROOT_INO
        let child_ino = fs.inodes.allocate_ino();
        let attr = FileAttrs {
            ino: child_ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            is_dir: true,
            perm: 0o777,
            nlink: 2,
        };
        let inode = InodeData {
            ino: child_ino,
            parent_ino: ROOT_INO,
            name: "dup".to_string(),
            kind: InodeKind::Folder {
                ipns_name: "k51test-dup".to_string(),
                read_key: zeroize::Zeroizing::new([0u8; 32]),
                write_key: zeroize::Zeroizing::new([0u8; 32]),
                ipns_private_key: zeroize::Zeroizing::new(vec![0u8; 32]),
                children_loaded: false,
            },
            attr,
            children: Some(vec![]),
            write_generation: 0,
        };
        fs.inodes.insert(inode);
        if let Some(root) = fs.inodes.get_mut(ROOT_INO) {
            if let Some(ref mut children) = root.children {
                children.push(child_ino);
            }
        }

        // Guard predicate: find_child returns Some for "dup" → guard path taken
        assert!(
            fs.inodes.find_child(ROOT_INO, "dup").is_some(),
            "find_child must return Some for existing child 'dup'"
        );

        // Guard predicate: find_child returns None for a non-existent name
        assert!(
            fs.inodes.find_child(ROOT_INO, "nonexistent").is_none(),
            "find_child must return None for 'nonexistent'"
        );
    }

    // D-05 end-to-end: handle_write returns EINVAL for negative offset
    #[tokio::test]
    async fn handle_write_rejects_negative_offset() {
        use fuser::Reply;
        let mut fs = make_test_fs();

        // The EINVAL guard fires before the open_files lookup, so no setup needed.
        let ino = 99u64;
        let fh = 42u64;
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sender = CaptureSender(buf.clone());
        let reply = <fuser::ReplyWrite as Reply>::new(1, sender);
        handle_write(&mut fs, ino, fh, -1i64, b"data", reply);
        assert_eq!(
            reply_error_code(&buf),
            -libc::EINVAL,
            "negative offset must return EINVAL"
        );
    }
}
