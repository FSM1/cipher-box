//! Write operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: write, create, setattr, rename, unlink, rmdir, mkdir.

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    use fuser::{
        ReplyAttr, ReplyCreate, ReplyEmpty, ReplyEntry, ReplyWrite,
    };
    use std::ffi::OsStr;
    use std::sync::atomic::Ordering;
    use std::time::SystemTime;

    use crate::fuse::CipherBoxFS;
    use crate::fuse::file_handle::OpenFileHandle;
    use crate::fuse::helpers::is_platform_special;
    use crate::fuse::inode::{FileAttrs, InodeData, InodeKind};
    use crate::fuse::operations::implementation::{
        ttl_for_is_dir, current_uid, current_gid, FILE_TTL, DIR_TTL,
    };

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
                let matching_fh: Option<u64> = fs.open_files.iter()
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
                    if let InodeKind::File { size: ref mut s, cid: ref mut c, .. } = inode.kind {
                        *s = 0;
                        *c = String::new();
                    }
                } else {
                    if let InodeKind::File { size: ref mut s, .. } = inode.kind {
                        *s = new_size;
                    }
                }

                reply.attr(&ttl_for_is_dir(inode.attr.is_dir), &inode.attr.to_fuse_attr(current_uid(), current_gid()));
                return;
            }
        }

        if let Some(inode) = fs.inodes.get(ino) {
            reply.attr(&ttl_for_is_dir(inode.attr.is_dir), &inode.attr.to_fuse_attr(current_uid(), current_gid()));
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
        name: &OsStr,
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
            matches!(inode.kind, InodeKind::Root { .. } | InodeKind::Folder { .. })
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
            perm: 0o644,
            nlink: 1,
        };
        let fuse_attr = attr.to_fuse_attr(current_uid(), current_gid());

        // Generate random Ed25519 IPNS keypair for this file
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let file_ipns_private_key = signing_key.to_bytes().to_vec();
        let file_ipns_public_key_bytes: [u8; 32] = verifying_key.to_bytes();
        let file_ipns_name = match crate::crypto::ipns::derive_ipns_name(&file_ipns_public_key_bytes) {
            Ok(name) => name,
            Err(e) => {
                log::error!("create: IPNS name derivation from random keypair failed: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        let ipns_key_encrypted_hex = match crate::crypto::ecies::wrap_key(&file_ipns_private_key, &fs.public_key) {
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

        log::debug!("create: {} in parent {} -> ino {} fh {}", name_str, parent, ino, fh);
        reply.created(&FILE_TTL, &fuse_attr, 0, fh, 0);
    }

    /// Delete a file from a directory.
    pub fn handle_unlink(
        fs: &mut CipherBoxFS,
        parent: u64,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let child_ino = match fs.inodes.find_child(parent, name_str) {
            Some(ino) => ino,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Capture data for bin entry before inode removal
        let bin_entry_data = match fs.inodes.get(child_ino) {
            Some(inode) => match &inode.kind {
                InodeKind::File {
                    file_meta_ipns_name,
                    file_ipns_key_encrypted_hex,
                    size,
                    cid,
                    versions,
                    ..
                } => {
                    let now_ms = SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let created_ms = inode.attr.crtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let meta_ipns = match file_meta_ipns_name {
                        Some(name) if !name.is_empty() => Some(name.clone()),
                        _ => {
                            // file_meta_ipns_name is optional for files loaded from
                            // remote metadata before IPNS resolve. Since bin publishing
                            // is best-effort, skip creating a bin entry when it's missing
                            // instead of failing the unlink.
                            log::warn!(
                                "unlink: missing file_meta_ipns_name for ino {}, skipping bin entry",
                                child_ino
                            );
                            None
                        }
                    };

                    if let Some(meta_ipns) = meta_ipns {
                        let file_pointer = crate::crypto::folder::FilePointer {
                            id: crate::crypto::utils::generate_uuid_v4(),
                            name: inode.name.clone(),
                            file_meta_ipns_name: meta_ipns,
                            ipns_private_key_encrypted: file_ipns_key_encrypted_hex.clone(),
                            created_at: if created_ms > 0 { created_ms } else { now_ms },
                            modified_at: now_ms,
                        };

                        let ver_cids = versions.as_ref().and_then(|items| {
                            let mapped: Vec<crate::crypto::bin::VersionCidEntry> = items
                                .iter()
                                .filter(|v| !v.cid.is_empty())
                                .map(|v| crate::crypto::bin::VersionCidEntry {
                                    cid: v.cid.clone(),
                                    size: v.size,
                                })
                                .collect();
                            if mapped.is_empty() { None } else { Some(mapped) }
                        });
                        Some((inode.name.clone(), *size, file_pointer, cid.clone(), ver_cids))
                    } else {
                        None
                    }
                }
                _ => {
                    reply.error(libc::EISDIR);
                    return;
                }
            },
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        log::debug!("unlink: {} from parent {}", name_str, parent);

        let now = SystemTime::now();

        fs.inodes.remove(child_ino);

        if let Some(parent_inode) = fs.inodes.get_mut(parent) {
            parent_inode.attr.mtime = now;
            parent_inode.attr.ctime = now;
        }

        if let Err(e) = fs.update_folder_metadata(parent) {
            log::error!("Failed to update folder metadata after unlink: {}", e);
        }

        // Create bin entry and publish to bin IPNS (fire-and-forget)
        if let Some((item_name, file_size, file_pointer, content_cid, ver_cids)) = bin_entry_data {
            let parent_ipns_name = fs.inodes.get(parent)
                .map(|p| match &p.kind {
                    InodeKind::Root { ipns_name, .. } => ipns_name.clone().unwrap_or_default(),
                    InodeKind::Folder { ipns_name, .. } => ipns_name.clone(),
                    _ => String::new(),
                })
                .unwrap_or_default();

            if parent_ipns_name.is_empty() {
                log::warn!(
                    "unlink: missing parent IPNS name for parent ino {}, skipping bin publish",
                    parent
                );
            } else {
                let parent_path = build_folder_path(fs, parent);

                let bin_entry = crate::crypto::bin::BinEntry {
                    id: crate::crypto::utils::generate_uuid_v4(),
                    item_type: crate::crypto::bin::BinItemType::File,
                    name: item_name.clone(),
                    original_parent_ipns_name: parent_ipns_name,
                    original_path: parent_path,
                    deleted_at: now
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    size: file_size,
                    mime_type: crate::crypto::utils::mime_from_extension(&item_name).to_string(),
                    content_cid: if content_cid.is_empty() { None } else { Some(content_cid) },
                    content_size: Some(file_size),
                    version_cids: ver_cids,
                    file_pointer: Some(file_pointer),
                    folder_entry: None,
                };

                crate::fuse::spawn_bin_entry_publish(
                    fs.api.clone(),
                    fs.rt.clone(),
                    bin_entry,
                    fs.private_key.clone(),
                    fs.public_key.to_vec(),
                    fs.publish_coordinator.clone(),
                );
            }
        }

        reply.ok();
    }

    /// Create a new directory.
    pub fn handle_mkdir(
        fs: &mut CipherBoxFS,
        parent: u64,
        name: &OsStr,
        reply: ReplyEntry,
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
            matches!(inode.kind, InodeKind::Root { .. } | InodeKind::Folder { .. })
        });
        if parent_exists != Some(true) {
            reply.error(libc::ENOENT);
            return;
        }

        log::debug!("mkdir: {} in parent {}", name_str, parent);

        let result = (|| -> Result<fuser::FileAttr, String> {
            let folder_key = crate::crypto::utils::generate_file_key();

            let (ipns_public_key, ipns_private_key) =
                crate::crypto::ed25519::generate_ed25519_keypair();

            let ipns_pub_arr: [u8; 32] = ipns_public_key.clone().try_into()
                .map_err(|_| "Invalid IPNS public key length".to_string())?;
            let ipns_name = crate::crypto::ipns::derive_ipns_name(&ipns_pub_arr)
                .map_err(|e| format!("Failed to derive IPNS name: {}", e))?;

            let wrapped_folder_key = crate::crypto::ecies::wrap_key(
                &folder_key, &fs.public_key,
            )
            .map_err(|e| format!("Folder key wrapping failed: {}", e))?;
            let encrypted_folder_key_hex = hex::encode(&wrapped_folder_key);

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
                is_dir: true,
                perm: 0o755,
                nlink: 2,
            };
            let fuse_attr = attr.to_fuse_attr(current_uid(), current_gid());

            let inode = InodeData {
                ino,
                parent_ino: parent,
                name: name_str.to_string(),
                kind: InodeKind::Folder {
                    ipns_name: ipns_name.clone(),
                    encrypted_folder_key: encrypted_folder_key_hex,
                    folder_key: zeroize::Zeroizing::new(folder_key.to_vec()),
                    ipns_private_key: Some(zeroize::Zeroizing::new(ipns_private_key.clone())),
                    children_loaded: true,
                },
                attr,
                children: Some(vec![]),
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

            let metadata = crate::crypto::folder::FolderMetadata {
                version: "v2".to_string(),
                children: vec![],
            };

            let json_bytes = crate::fuse::encrypt_metadata_to_json(
                &metadata, &folder_key,
            )?;

            let encrypted_ipns_for_tee = if let Some(ref tee_key) = fs.tee_public_key {
                let wrapped = crate::crypto::ecies::wrap_key(&ipns_private_key, tee_key)
                    .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
                Some(hex::encode(&wrapped))
            } else {
                None
            };
            let tee_key_epoch = fs.tee_key_epoch;

            let (parent_metadata, parent_folder_key, parent_ipns_key, parent_ipns_name, parent_old_cid) =
                fs.build_folder_metadata(parent)?;

            let api = fs.api.clone();
            let rt = fs.rt.clone();
            let ipns_name_clone = ipns_name.clone();
            let coordinator = fs.publish_coordinator.clone();

            std::thread::spawn(move || {
                let result = rt.block_on(async {
                    let initial_cid = crate::api::ipfs::upload_content(
                        &api, &json_bytes,
                    ).await?;

                    let ipns_key_arr: [u8; 32] = ipns_private_key.try_into()
                        .map_err(|_| "Invalid IPNS key length".to_string())?;
                    let value = format!("/ipfs/{}", initial_cid);
                    let record = crate::crypto::ipns::create_ipns_record(
                        &ipns_key_arr, &value, 0, 86_400_000,
                    ).map_err(|e| format!("IPNS record creation failed: {}", e))?;
                    let marshaled = crate::crypto::ipns::marshal_ipns_record(&record)
                        .map_err(|e| format!("IPNS marshal failed: {}", e))?;

                    use base64::Engine;
                    let record_b64 = base64::engine::general_purpose::STANDARD
                        .encode(&marshaled);

                    // New folder initial publish: sequence 0, no conflict check needed
                    let req = crate::api::ipns::IpnsPublishRequest {
                        ipns_name: ipns_name_clone.clone(),
                        record: record_b64,
                        metadata_cid: initial_cid,
                        encrypted_ipns_private_key: encrypted_ipns_for_tee,
                        key_epoch: tee_key_epoch,
                        expected_sequence_number: None,
                    };
                    match crate::api::ipns::publish_ipns(&api, &req).await? {
                        crate::api::ipns::PublishResult::Success => {
                            coordinator.record_publish(&ipns_name_clone, 0);
                            log::info!("New folder IPNS published: {}", ipns_name_clone);
                        }
                        crate::api::ipns::PublishResult::Conflict { .. } => {
                            // Sequence 0 should never conflict -- log and continue
                            log::warn!("Unexpected conflict on new folder IPNS publish for {}", ipns_name_clone);
                        }
                    }

                    let lock = coordinator.get_lock(&parent_ipns_name);
                    let _guard = lock.lock().await;

                    let parent_json = crate::fuse::encrypt_metadata_to_json(
                        &parent_metadata, &parent_folder_key,
                    )?;

                    let seq = coordinator.resolve_sequence(&api, &parent_ipns_name).await?;

                    let parent_meta_cid = crate::api::ipfs::upload_content(
                        &api, &parent_json,
                    ).await?;

                    let parent_key_arr: [u8; 32] = parent_ipns_key.try_into()
                        .map_err(|_| "Invalid parent IPNS key length".to_string())?;
                    let new_seq = seq + 1;
                    let parent_value = format!("/ipfs/{}", parent_meta_cid);
                    let parent_record = crate::crypto::ipns::create_ipns_record(
                        &parent_key_arr, &parent_value, new_seq, 86_400_000,
                    ).map_err(|e| format!("Parent IPNS record failed: {}", e))?;
                    let parent_marshaled = crate::crypto::ipns::marshal_ipns_record(
                        &parent_record,
                    ).map_err(|e| format!("Parent IPNS marshal failed: {}", e))?;
                    let parent_record_b64 = base64::engine::general_purpose::STANDARD
                        .encode(&parent_marshaled);

                    // Parent folder publish after mkdir includes conflict detection.
                    // On conflict, log a warning -- the debounced publish queue will
                    // retry the parent metadata on the next cycle.
                    // TODO: Add full re-fetch+merge+retry for parent mkdir publish (v2).
                    let parent_req = crate::api::ipns::IpnsPublishRequest {
                        ipns_name: parent_ipns_name.clone(),
                        record: parent_record_b64,
                        metadata_cid: parent_meta_cid,
                        encrypted_ipns_private_key: None,
                        key_epoch: None,
                        expected_sequence_number: Some(seq.to_string()),
                    };
                    match crate::api::ipns::publish_ipns(&api, &parent_req).await? {
                        crate::api::ipns::PublishResult::Success => {
                            coordinator.record_publish(&parent_ipns_name, new_seq);
                            // Only unpin old CID on successful publish
                            if let Some(old) = parent_old_cid {
                                let _ = crate::api::ipfs::unpin_content(&api, &old).await;
                            }
                            log::info!("Parent metadata published after mkdir");
                        }
                        crate::api::ipns::PublishResult::Conflict { current_sequence_number } => {
                            log::warn!(
                                "Conflict on parent publish after mkdir (expected seq {}, server has {}). \
                                Debounced publish will retry.",
                                seq, current_sequence_number
                            );
                            // Do not record_publish or unpin -- let the next debounced publish pick up fresh seq
                        }
                    }
                    Ok::<(), String>(())
                });

                if let Err(e) = result {
                    log::error!("Background mkdir publish failed: {}", e);
                }
            });

            Ok(fuse_attr)
        })();

        match result {
            Ok(fuse_attr) => {
                reply.entry(&DIR_TTL, &fuse_attr, 0);
            }
            Err(e) => {
                log::error!("mkdir failed: {}", e);
                reply.error(libc::EIO);
            }
        }
    }

    /// Remove an empty directory.
    pub fn handle_rmdir(
        fs: &mut CipherBoxFS,
        parent: u64,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let child_ino = match fs.inodes.find_child(parent, name_str) {
            Some(ino) => ino,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Capture folder data for bin entry before inode removal
        let bin_entry_data = match fs.inodes.get(child_ino) {
            Some(inode) => {
                match &inode.kind {
                    InodeKind::Folder {
                        ipns_name,
                        encrypted_folder_key,
                        ipns_private_key,
                        ..
                    } => {
                        // Check for non-empty folder (POSIX requirement)
                        if let Some(ref children) = inode.children {
                            if !children.is_empty() {
                                reply.error(libc::ENOTEMPTY);
                                return;
                            }
                        }

                        let now_ms = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let created_ms = inode.attr.crtime
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;

                        // Build the ECIES-wrapped IPNS private key for the FolderEntry
                        let ipns_key_encrypted = match ipns_private_key {
                            Some(key) => match crate::crypto::ecies::wrap_key(key, &fs.public_key) {
                                Ok(wrapped) => hex::encode(&wrapped),
                                Err(e) => {
                                    log::error!("rmdir: failed to wrap IPNS key for bin entry: {}", e);
                                    reply.error(libc::EIO);
                                    return;
                                }
                            },
                            None => {
                                log::error!("rmdir: missing folder IPNS private key for ino {}", child_ino);
                                reply.error(libc::EIO);
                                return;
                            }
                        };

                        let folder_entry = crate::crypto::folder::FolderEntry {
                            id: crate::crypto::utils::generate_uuid_v4(),
                            name: inode.name.clone(),
                            ipns_name: ipns_name.clone(),
                            folder_key_encrypted: encrypted_folder_key.clone(),
                            ipns_private_key_encrypted: ipns_key_encrypted,
                            created_at: if created_ms > 0 { created_ms } else { now_ms },
                            modified_at: now_ms,
                        };

                        Some((inode.name.clone(), folder_entry))
                    }
                    _ => {
                        reply.error(libc::ENOTDIR);
                        return;
                    }
                }
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        log::debug!("rmdir: {} from parent {}", name_str, parent);

        let now = SystemTime::now();

        fs.inodes.remove(child_ino);

        if let Some(parent_inode) = fs.inodes.get_mut(parent) {
            parent_inode.attr.mtime = now;
            parent_inode.attr.ctime = now;
        }

        if let Err(e) = fs.update_folder_metadata(parent) {
            log::error!("Failed to update folder metadata after rmdir: {}", e);
        }

        // Create bin entry and publish to bin IPNS (fire-and-forget)
        if let Some((item_name, folder_entry)) = bin_entry_data {
            let parent_ipns_name = fs.inodes.get(parent)
                .map(|p| match &p.kind {
                    InodeKind::Root { ipns_name, .. } => ipns_name.clone().unwrap_or_default(),
                    InodeKind::Folder { ipns_name, .. } => ipns_name.clone(),
                    _ => String::new(),
                })
                .unwrap_or_default();

            if parent_ipns_name.is_empty() {
                log::warn!(
                    "rmdir: missing parent IPNS name for parent ino {}, skipping bin publish",
                    parent
                );
            } else {
                let parent_path = build_folder_path(fs, parent);

                let bin_entry = crate::crypto::bin::BinEntry {
                    id: crate::crypto::utils::generate_uuid_v4(),
                    item_type: crate::crypto::bin::BinItemType::Folder,
                    name: item_name,
                    original_parent_ipns_name: parent_ipns_name,
                    original_path: parent_path,
                    deleted_at: now
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    size: 0,
                    mime_type: String::new(),
                    content_cid: None,
                    content_size: None,
                    version_cids: None,
                    file_pointer: None,
                    folder_entry: Some(folder_entry),
                };

                crate::fuse::spawn_bin_entry_publish(
                    fs.api.clone(),
                    fs.rt.clone(),
                    bin_entry,
                    fs.private_key.clone(),
                    fs.public_key.to_vec(),
                    fs.publish_coordinator.clone(),
                );
            }
        }

        reply.ok();
    }

    /// Rename or move a file/folder.
    pub fn handle_rename(
        fs: &mut CipherBoxFS,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEmpty,
    ) {
        log::debug!(
            "rename: {:?} (parent {}) -> {:?} (parent {})",
            name, parent, newname, newparent,
        );
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        let newname_str = match newname.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Find source inode (with FUSE-T truncated name fallback)
        let (source_ino, actual_name) = match fs.inodes.find_child(parent, name_str) {
            Some(ino) => (ino, name_str.to_string()),
            None => {
                let parent_inode = match fs.inodes.get(parent) {
                    Some(i) => i,
                    None => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                };
                let children = parent_inode.children.clone().unwrap_or_default();
                let mut matches: Vec<(u64, String)> = Vec::new();
                for &child_ino in &children {
                    if let Some(child) = fs.inodes.get(child_ino) {
                        if is_platform_special(&child.name) {
                            continue;
                        }
                        if child.name.ends_with(name_str) && child.name.len() > name_str.len() {
                            matches.push((child_ino, child.name.clone()));
                        }
                    }
                }
                if matches.len() == 1 {
                    log::debug!(
                        "rename suffix-match: truncated {:?} matched full name {:?}",
                        name_str, matches[0].1
                    );
                    (matches[0].0, matches[0].1.clone())
                } else {
                    log::debug!(
                        "rename failed: {:?} not found (suffix matches: {})",
                        name_str, matches.len()
                    );
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        let name_str = &actual_name;

        log::debug!(
            "rename: {} (ino {}) in parent {} -> {} in parent {}",
            name_str, source_ino, parent, newname_str, newparent,
        );

        // If destination exists, handle replacement
        if let Some(dest_ino) = fs.inodes.find_child(newparent, newname_str) {
            // Self-replace (rename "a" to "a" in same dir): no-op
            if dest_ino == source_ino {
                reply.ok();
                return;
            }

            if let Some(dest_inode) = fs.inodes.get(dest_ino) {
                // Validate kind compatibility (POSIX: can't replace file with dir or vice versa)
                let source_is_dir = fs.inodes.get(source_ino)
                    .map(|i| matches!(i.kind, InodeKind::Root { .. } | InodeKind::Folder { .. }))
                    .unwrap_or(false);
                let dest_is_dir = matches!(
                    dest_inode.kind,
                    InodeKind::Root { .. } | InodeKind::Folder { .. }
                );
                if source_is_dir && !dest_is_dir {
                    reply.error(libc::ENOTDIR);
                    return;
                }
                if !source_is_dir && dest_is_dir {
                    reply.error(libc::EISDIR);
                    return;
                }

                match &dest_inode.kind {
                    InodeKind::Folder { .. } => {
                        if let Some(ref children) = dest_inode.children {
                            if !children.is_empty() {
                                reply.error(libc::ENOTEMPTY);
                                return;
                            }
                        }
                    }
                    InodeKind::File { cid, .. } => {
                        if !cid.is_empty() {
                            let cid_clone = cid.clone();
                            let api = fs.api.clone();
                            fs.rt.spawn(async move {
                                let _ = crate::api::ipfs::unpin_content(
                                    &api, &cid_clone,
                                ).await;
                            });
                        }
                    }
                    _ => {}
                }
            }
            fs.inodes.remove(dest_ino);
        }

        // Remove source from old parent's name index (NFC-normalized)
        {
            use unicode_normalization::UnicodeNormalization;
            let nfc_key: String = name_str.nfc().collect();
            fs.inodes.name_to_ino.remove(&(parent, nfc_key));
        }

        // Update the source inode's name and parent
        if let Some(inode) = fs.inodes.get_mut(source_ino) {
            inode.name = newname_str.to_string();
            inode.parent_ino = newparent;
            inode.attr.ctime = SystemTime::now();
        }

        // Update the name lookup index for the new location (NFC-normalized)
        {
            use unicode_normalization::UnicodeNormalization;
            let nfc_key: String = newname_str.nfc().collect();
            fs.inodes.name_to_ino.insert(
                (newparent, nfc_key),
                source_ino,
            );
        }

        if parent != newparent {
            if let Some(old_parent) = fs.inodes.get_mut(parent) {
                if let Some(ref mut children) = old_parent.children {
                    children.retain(|&c| c != source_ino);
                }
                old_parent.attr.mtime = SystemTime::now();
                old_parent.attr.ctime = SystemTime::now();
            }
            if let Some(new_parent) = fs.inodes.get_mut(newparent) {
                if let Some(ref mut children) = new_parent.children {
                    children.push(source_ino);
                }
                new_parent.attr.mtime = SystemTime::now();
                new_parent.attr.ctime = SystemTime::now();
            }

            if let Err(e) = fs.update_folder_metadata(parent) {
                log::error!("Failed to update old parent metadata after rename: {}", e);
            }
            if let Err(e) = fs.update_folder_metadata(newparent) {
                log::error!("Failed to update new parent metadata after rename: {}", e);
            }
        } else {
            if let Some(parent_inode) = fs.inodes.get_mut(parent) {
                parent_inode.attr.mtime = SystemTime::now();
                parent_inode.attr.ctime = SystemTime::now();
            }
            if let Err(e) = fs.update_folder_metadata(parent) {
                log::error!("Failed to update parent metadata after rename: {}", e);
            }
        }

        reply.ok();
    }

    /// Build a human-readable breadcrumb path for a folder inode.
    /// Walks parent_ino upward to root, concatenating names with " / ".
    /// Example: "My Vault / Documents / Reports"
    fn build_folder_path(fs: &CipherBoxFS, folder_ino: u64) -> String {
        let mut parts = Vec::new();
        let mut current = folder_ino;
        for _ in 0..20 { // Safety limit to prevent infinite loops
            match fs.inodes.get(current) {
                Some(inode) => {
                    match &inode.kind {
                        InodeKind::Root { .. } => {
                            parts.push("My Vault".to_string());
                            break;
                        }
                        _ => {
                            parts.push(inode.name.clone());
                            current = inode.parent_ino;
                        }
                    }
                }
                None => break,
            }
        }
        parts.reverse();
        parts.join(" / ")
    }
}
