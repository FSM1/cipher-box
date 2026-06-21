use fuser::{ReplyAttr, ReplyCreate, ReplyWrite};
use std::sync::atomic::Ordering;
use std::time::SystemTime;

use crate::file_handle::OpenFileHandle;
use crate::helpers::is_platform_special;
use crate::inode::{FileAttrs, InodeData, InodeKind};
use crate::operations::implementation::{
    current_gid, current_uid, ttl_for_is_dir, FILE_TTL,
};
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
    let handle = match fs.open_files.get_mut(&fh) {
        Some(h) => h,
        None => {
            reply.error(libc::EBADF);
            return;
        }
    };

    match handle.write_at(offset, data) {
        Ok(written) => {
            let new_end = offset as u64 + data.len() as u64;
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
    let file_ipns_name =
        match cipherbox_core::ipns::derive_ipns_name(&file_ipns_public_key_bytes) {
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

    let ipns_key_encrypted_hex = match cipherbox_crypto::wrap_key(
        &file_ipns_private_key,
        &fs.public_key,
    ) {
        Ok(wrapped) => Some(hex::encode(&wrapped)),
        Err(e) => {
            log::error!("create: failed to ECIES-wrap IPNS key: {}. Cannot proceed without wrapped key.", e);
            reply.error(libc::EIO);
            return;
        }
    };

    let inode = InodeData {
        ino,
        parent_ino: parent,
        name: name_str.to_string(),
        kind: InodeKind::File {
            cid: String::new(),
            encrypted_file_key: String::new(),
            iv: String::new(),
            size: 0,
            encryption_mode: "GCM".to_string(),
            file_meta_ipns_name: Some(file_ipns_name),
            file_meta_resolved: true,
            file_ipns_private_key: Some(zeroize::Zeroizing::new(file_ipns_private_key)),
            file_ipns_key_encrypted_hex: ipns_key_encrypted_hex,
            versions: None,
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
