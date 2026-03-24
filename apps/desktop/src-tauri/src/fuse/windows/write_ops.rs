//! Write operations for Windows WinFsp filesystem.
//!
//! Contains handler logic for: create, write, overwrite, cleanup,
//! set_basic_info, set_file_size, set_delete, rename.

#[cfg(feature = "winfsp")]
pub(crate) mod implementation {
    use std::ffi::c_void;
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    use winfsp::filesystem::{FileInfo, OpenFileInfo};
    use widestring::U16CStr;
    use winfsp::FspError;

    use crate::fuse::constants::{MAX_VERSIONS_PER_FILE, VERSION_COOLDOWN_MS};
    use crate::fuse::file_handle::OpenFileHandle;
    use crate::fuse::helpers::mime_from_extension;
    use crate::fuse::inode::{FileAttrs, InodeData, InodeKind, ROOT_INO};
    use crate::fuse::windows::operations::implementation::{
        WinFspContext, WinFspFileContext,
        status_object_name_not_found, status_invalid_parameter,
        status_object_name_collision, status_directory_not_empty,
        status_invalid_handle, status_io_device_error,
        resolve_path, split_path, fill_file_info,
        filetime_to_systemtime, publish_file_metadata,
        is_windows_special,
    };

    /// create handler (files and directories)
    pub fn handle_create(
        ctx: &WinFspContext,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> Result<WinFspFileContext, FspError> {
        let path = file_name.to_string_lossy();
        log::info!(
            "create() path={} create_options=0x{:08X} granted_access=0x{:08X}",
            path, create_options, granted_access
        );
        let (parent_path, name) = split_path(&path);

        if name.is_empty() {
            return Err(status_invalid_parameter());
        }

        if is_windows_special(name) {
            return Err(status_object_name_not_found());
        }

        let mut fs = ctx.inner.lock().unwrap();

        let (parent_ino, _) = resolve_path(&fs, parent_path)
            .ok_or(status_object_name_not_found())?;

        let parent_is_dir = fs.inodes.get(parent_ino).map(|inode| {
            matches!(inode.kind, InodeKind::Root { .. } | InodeKind::Folder { .. })
        });
        if parent_is_dir != Some(true) {
            return Err(status_object_name_not_found());
        }

        // FILE_DIRECTORY_FILE = 0x00000001
        let is_dir = (create_options & 0x00000001) != 0;

        if is_dir {
            // Create directory
            let result = (|| -> Result<(FileAttrs, u64), String> {
                let folder_key = cipherbox_crypto::utils::generate_file_key();
                let (ipns_public_key, ipns_private_key) =
                    cipherbox_crypto::ed25519::generate_ed25519_keypair();
                let ipns_pub_arr: [u8; 32] = ipns_public_key.clone().try_into()
                    .map_err(|_| "Invalid IPNS public key length".to_string())?;
                let ipns_name = cipherbox_core::ipns::derive_ipns_name(&ipns_pub_arr)
                    .map_err(|e| format!("Failed to derive IPNS name: {}", e))?;
                let wrapped_folder_key = cipherbox_crypto::ecies::wrap_key(
                    &folder_key, &fs.public_key,
                )
                .map_err(|e| format!("Folder key wrapping failed: {}", e))?;
                let encrypted_folder_key_hex = hex::encode(&wrapped_folder_key);

                let ino = fs.inodes.allocate_ino();
                let now = SystemTime::now();

                let attr = FileAttrs {
                    ino, size: 0, blocks: 0,
                    atime: now, mtime: now, ctime: now, crtime: now,
                    is_dir: true, perm: 0o755, nlink: 2,
                };

                let inode = InodeData {
                    ino, parent_ino,
                    name: name.to_string(),
                    kind: InodeKind::Folder {
                        ipns_name: ipns_name.clone(),
                        encrypted_folder_key: encrypted_folder_key_hex,
                        folder_key: zeroize::Zeroizing::new(folder_key.to_vec()),
                        ipns_private_key: Some(zeroize::Zeroizing::new(ipns_private_key.clone())),
                        children_loaded: true,
                    },
                    attr: attr.clone(),
                    children: Some(vec![]),
                    write_generation: 0,
                };

                fs.inodes.insert(inode);
                if let Some(parent_inode) = fs.inodes.get_mut(parent_ino) {
                    if let Some(ref mut children) = parent_inode.children {
                        children.push(ino);
                    }
                    parent_inode.attr.mtime = SystemTime::now();
                    parent_inode.attr.ctime = SystemTime::now();
                }

                let metadata = cipherbox_core::folder::FolderMetadata {
                    version: "v2".to_string(),
                    children: vec![],
                };
                let json_bytes = crate::fuse::encrypt_metadata_to_json(&metadata, &folder_key)?;
                let encrypted_ipns_for_tee = if let Some(ref tee_key) = fs.tee_public_key {
                    let wrapped = cipherbox_crypto::ecies::wrap_key(&ipns_private_key, tee_key)
                        .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
                    Some(hex::encode(&wrapped))
                } else {
                    None
                };
                let tee_key_epoch = fs.tee_key_epoch;
                let (parent_metadata, parent_folder_key, parent_ipns_key, parent_ipns_name, parent_old_cid) =
                    fs.build_folder_metadata(parent_ino)?;

                let api = fs.api.clone();
                let rt = fs.rt.clone();
                let ipns_name_clone = ipns_name.clone();
                let coordinator = fs.publish_coordinator.clone();

                std::thread::spawn(move || {
                    let result = rt.block_on(async {
                        let initial_cid = cipherbox_api_client::ipfs::upload_content(&api, &json_bytes).await.map_err(|e| e.to_string())?;
                        let ipns_key_arr: [u8; 32] = ipns_private_key.try_into()
                            .map_err(|_| "Invalid IPNS key length".to_string())?;
                        let value = format!("/ipfs/{}", initial_cid);
                        let record = cipherbox_core::ipns::create_ipns_record(
                            &ipns_key_arr, &value, 0, 86_400_000,
                        ).map_err(|e| format!("IPNS record creation failed: {}", e))?;
                        let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
                            .map_err(|e| format!("IPNS marshal failed: {}", e))?;

                        use base64::Engine;
                        let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
                        // New folder initial publish: sequence 0, no conflict check needed
                        let req = cipherbox_api_client::IpnsPublishRequest {
                            ipns_name: ipns_name_clone.clone(),
                            record: record_b64,
                            metadata_cid: initial_cid,
                            encrypted_ipns_private_key: encrypted_ipns_for_tee,
                            key_epoch: tee_key_epoch,
                            expected_sequence_number: None,
                        };
                        match cipherbox_api_client::ipns::publish_ipns(&api, &req).await.map_err(|e| e.to_string())? {
                            cipherbox_api_client::PublishResult::Success => {
                                coordinator.record_publish(&ipns_name_clone, 0);
                            }
                            cipherbox_api_client::PublishResult::Conflict { .. } => {
                                log::warn!("Unexpected conflict on new folder IPNS publish for {}", ipns_name_clone);
                            }
                        }

                        let lock = coordinator.get_lock(&parent_ipns_name);
                        let _guard = lock.lock().await;
                        let parent_json = crate::fuse::encrypt_metadata_to_json(
                            &parent_metadata, &parent_folder_key,
                        )?;
                        let seq = coordinator.resolve_sequence(&api, &parent_ipns_name).await?;
                        let parent_meta_cid = cipherbox_api_client::ipfs::upload_content(&api, &parent_json).await.map_err(|e| e.to_string())?;
                        let parent_key_arr: [u8; 32] = parent_ipns_key.try_into()
                            .map_err(|_| "Invalid parent IPNS key length".to_string())?;
                        let new_seq = seq + 1;
                        let parent_value = format!("/ipfs/{}", parent_meta_cid);
                        let parent_record = cipherbox_core::ipns::create_ipns_record(
                            &parent_key_arr, &parent_value, new_seq, 86_400_000,
                        ).map_err(|e| format!("Parent IPNS record failed: {}", e))?;
                        let parent_marshaled = cipherbox_core::ipns::marshal_ipns_record(&parent_record)
                            .map_err(|e| format!("Parent IPNS marshal failed: {}", e))?;
                        let parent_record_b64 = base64::engine::general_purpose::STANDARD.encode(&parent_marshaled);
                        // Parent folder publish after mkdir includes conflict detection.
                        // On conflict, log a warning -- the debounced publish queue will retry.
                        // TODO: Add full re-fetch+merge+retry for parent mkdir publish (v2).
                        let parent_req = cipherbox_api_client::IpnsPublishRequest {
                            ipns_name: parent_ipns_name.clone(),
                            record: parent_record_b64,
                            metadata_cid: parent_meta_cid,
                            encrypted_ipns_private_key: None,
                            key_epoch: None,
                            expected_sequence_number: Some(seq.to_string()),
                        };
                        match cipherbox_api_client::ipns::publish_ipns(&api, &parent_req).await.map_err(|e| e.to_string())? {
                            cipherbox_api_client::PublishResult::Success => {
                                coordinator.record_publish(&parent_ipns_name, new_seq);
                                // Only unpin old CID on successful publish
                                if let Some(old) = parent_old_cid {
                                    let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                                }
                            }
                            cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
                                log::warn!(
                                    "Conflict on parent publish after mkdir (expected seq {}, server has {}). \
                                    Debounced publish will retry.",
                                    seq, current_sequence_number
                                );
                                // Do not unpin -- let the next debounced publish pick up fresh seq
                            }
                        }
                        Ok::<(), String>(())
                    });
                    if let Err(e) = result {
                        log::error!("Background mkdir publish failed: {}", e);
                    }
                });

                Ok((attr, ino))
            })();

            match result {
                Ok((attr, ino)) => {
                    *file_info.as_mut() = fill_file_info(&attr);
                    let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
                    Ok(WinFspFileContext { fh, ino, is_dir: true })
                }
                Err(e) => {
                    log::error!("create dir failed: {}", e);
                    Err(status_io_device_error())
                }
            }
        } else {
            // Create file
            let ino = fs.inodes.allocate_ino();
            let now = SystemTime::now();

            let attr = FileAttrs {
                ino, size: 0, blocks: 0,
                atime: now, mtime: now, ctime: now, crtime: now,
                is_dir: false, perm: 0o644, nlink: 1,
            };

            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let verifying_key = signing_key.verifying_key();
            let file_ipns_private_key = signing_key.to_bytes().to_vec();
            let file_ipns_public_key_bytes: [u8; 32] = verifying_key.to_bytes();
            let file_ipns_name = match cipherbox_core::ipns::derive_ipns_name(&file_ipns_public_key_bytes) {
                Ok(name) => name,
                Err(e) => {
                    log::error!("create: IPNS name derivation failed: {}", e);
                    return Err(status_io_device_error());
                }
            };

            let ipns_key_encrypted_hex = match cipherbox_crypto::ecies::wrap_key(
                &file_ipns_private_key, &fs.public_key,
            ) {
                Ok(wrapped) => Some(hex::encode(&wrapped)),
                Err(e) => {
                    log::error!("create: failed to ECIES-wrap IPNS key: {}", e);
                    return Err(status_io_device_error());
                }
            };

            let inode = InodeData {
                ino, parent_ino,
                name: name.to_string(),
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
                attr: attr.clone(),
                children: None,
                write_generation: 0,
            };

            fs.inodes.insert(inode);
            if let Some(parent_inode) = fs.inodes.get_mut(parent_ino) {
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
                    return Err(status_io_device_error());
                }
            }

            fs.mutated_folders.insert(parent_ino, std::time::Instant::now());

            *file_info.as_mut() = fill_file_info(&attr);
            Ok(WinFspFileContext { fh, ino, is_dir: false })
        }
    }

    /// write handler
    pub fn handle_write(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        buffer: &[u8],
        offset: u64,
        write_to_end_of_file: bool,
        file_info: &mut FileInfo,
    ) -> Result<u32, FspError> {
        let mut fs = ctx.inner.lock().unwrap();
        let fh = context.fh;
        let ino = context.ino;

        let current_file_size = fs.inodes.get(ino).map(|i| i.attr.size).unwrap_or(0);

        let actual_offset = if write_to_end_of_file {
            log::info!(
                "write() ino={} fh={} len={} write_to_end_of_file=true offset_param={} using file_size={}",
                ino, fh, buffer.len(), offset, current_file_size
            );
            current_file_size
        } else {
            log::info!(
                "write() ino={} fh={} len={} offset={} write_to_end_of_file=false",
                ino, fh, buffer.len(), offset
            );
            offset
        };

        let handle = match fs.open_files.get_mut(&fh) {
            Some(h) => h,
            None => return Err(status_invalid_handle()),
        };

        match handle.write_at(actual_offset as i64, buffer) {
            Ok(written) => {
                let new_end = actual_offset + buffer.len() as u64;
                if let Some(inode) = fs.inodes.get_mut(ino) {
                    if new_end > inode.attr.size {
                        inode.attr.size = new_end;
                        inode.attr.blocks = (new_end + 511) / 512;
                    }
                    inode.attr.mtime = SystemTime::now();
                    *file_info = fill_file_info(&inode.attr);
                }
                Ok(written as u32)
            }
            Err(e) => {
                log::error!("Write failed for ino {} fh {}: {}", ino, fh, e);
                Err(status_io_device_error())
            }
        }
    }

    /// overwrite handler
    pub fn handle_overwrite(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        log::info!("overwrite() called for ino={} fh={}", context.ino, context.fh);
        let mut fs = ctx.inner.lock().unwrap();

        if let Some(handle) = fs.open_files.get_mut(&context.fh) {
            let has_temp = handle.temp_path.is_some();
            log::info!("overwrite: handle found, has_temp_path={}", has_temp);
            if has_temp {
                handle.truncate(0).map_err(|_| status_io_device_error())?;
                handle.dirty = true;
                log::info!("overwrite: truncated to 0");
            }
        } else {
            log::warn!("overwrite: no handle found for fh={}", context.fh);
        }

        if let Some(inode) = fs.inodes.get_mut(context.ino) {
            inode.attr.size = 0;
            inode.attr.mtime = SystemTime::now();
            inode.attr.ctime = SystemTime::now();
            inode.write_generation += 1;
            if let InodeKind::File { size: ref mut s, cid: ref mut c, .. } = inode.kind {
                *s = 0;
                c.clear();
            }
            *file_info = fill_file_info(&inode.attr);
        }

        Ok(())
    }

    /// set_basic_info handler
    pub fn handle_set_basic_info(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        let mut fs = ctx.inner.lock().unwrap();
        if let Some(inode) = fs.inodes.get_mut(context.ino) {
            if creation_time != 0 {
                inode.attr.crtime = filetime_to_systemtime(creation_time);
            }
            if last_access_time != 0 {
                inode.attr.atime = filetime_to_systemtime(last_access_time);
            }
            if last_write_time != 0 {
                inode.attr.mtime = filetime_to_systemtime(last_write_time);
            }
            if change_time != 0 {
                inode.attr.ctime = filetime_to_systemtime(change_time);
            }
            *file_info = fill_file_info(&inode.attr);
        }
        Ok(())
    }

    /// set_file_size handler
    pub fn handle_set_file_size(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        log::info!(
            "set_file_size() ino={} fh={} new_size={} set_allocation_size={}",
            context.ino, context.fh, new_size, set_allocation_size
        );
        let mut fs = ctx.inner.lock().unwrap();

        let should_truncate = !set_allocation_size
            || (set_allocation_size && new_size == 0);

        if should_truncate {
            if let Some(handle) = fs.open_files.get_mut(&context.fh) {
                if handle.temp_path.is_some() {
                    handle.truncate(new_size).map_err(|_| status_io_device_error())?;
                    handle.dirty = true;
                    log::info!("set_file_size: truncated temp file to {} bytes", new_size);
                }
            }

            if let Some(inode) = fs.inodes.get_mut(context.ino) {
                inode.attr.size = new_size;
                inode.attr.blocks = (new_size + 511) / 512;
                inode.attr.mtime = SystemTime::now();
                if new_size == 0 {
                    inode.write_generation += 1;
                }
                if let InodeKind::File { size: ref mut s, cid: ref mut c, .. } = inode.kind {
                    *s = new_size;
                    if new_size == 0 {
                        c.clear();
                    }
                }
                *file_info = fill_file_info(&inode.attr);
            }
        }

        Ok(())
    }

    /// cleanup handler (IRP_MJ_CLEANUP -- immediate on handle close)
    pub fn handle_cleanup(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        flags: u32,
    ) {
        log::info!(
            "cleanup() ino={} fh={} flags=0x{:08X}",
            context.ino, context.fh, flags
        );
        let mut fs = ctx.inner.lock().unwrap();
        let ino = context.ino;
        let fh = context.fh;

        // FspCleanupDelete = 0x01
        if flags & 0x01 != 0 {
            let now = SystemTime::now();
            let now_ms = now
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            // Capture parent inode and bin entry data before inode removal
            let parent_ino = match fs.inodes.get(ino) {
                Some(inode) => inode.parent_ino,
                None => return,
            };

            // Capture bin entry data for file or folder before removal
            let bin_file_data: Option<(String, u64, cipherbox_core::folder::FilePointer, String, Option<Vec<cipherbox_core::bin::VersionCidEntry>>)> =
                match fs.inodes.get(ino) {
                    Some(inode) => match &inode.kind {
                        InodeKind::File {
                            file_meta_ipns_name,
                            file_ipns_key_encrypted_hex,
                            size,
                            cid,
                            versions,
                            ..
                        } => {
                            let created_ms = inode.attr.crtime
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;

                            match file_meta_ipns_name {
                                Some(name) if !name.is_empty() => {
                                    let file_pointer = cipherbox_core::folder::FilePointer {
                                        id: cipherbox_crypto::utils::generate_uuid_v4(),
                                        name: inode.name.clone(),
                                        file_meta_ipns_name: name.clone(),
                                        ipns_private_key_encrypted: file_ipns_key_encrypted_hex.clone(),
                                        created_at: if created_ms > 0 { created_ms } else { now_ms },
                                        modified_at: now_ms,
                                    };
                                    let ver_cids = crate::fuse::helpers::versions_to_bin_entries(versions);
                                    Some((inode.name.clone(), *size, file_pointer, cid.clone(), ver_cids))
                                }
                                _ => {
                                    log::warn!(
                                        "cleanup delete: missing file_meta_ipns_name for ino {}, skipping bin entry",
                                        ino
                                    );
                                    None
                                }
                            }
                        }
                        _ => None,
                    },
                    None => None,
                };

            let bin_folder_data: Option<(String, cipherbox_core::folder::FolderEntry)> =
                if bin_file_data.is_none() {
                    match fs.inodes.get(ino) {
                        Some(inode) => match &inode.kind {
                            InodeKind::Folder {
                                ipns_name,
                                encrypted_folder_key,
                                ipns_private_key,
                                ..
                            } => {
                                let created_ms = inode.attr.crtime
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64;

                                match ipns_private_key {
                                    Some(key) => {
                                        match cipherbox_crypto::ecies::wrap_key(key, &fs.public_key) {
                                            Ok(wrapped) => {
                                                let folder_entry = cipherbox_core::folder::FolderEntry {
                                                    id: cipherbox_crypto::utils::generate_uuid_v4(),
                                                    name: inode.name.clone(),
                                                    ipns_name: ipns_name.clone(),
                                                    folder_key_encrypted: encrypted_folder_key.clone(),
                                                    ipns_private_key_encrypted: hex::encode(&wrapped),
                                                    created_at: if created_ms > 0 { created_ms } else { now_ms },
                                                    modified_at: now_ms,
                                                };
                                                Some((inode.name.clone(), folder_entry))
                                            }
                                            Err(e) => {
                                                log::error!("cleanup delete: failed to wrap IPNS key: {}", e);
                                                None
                                            }
                                        }
                                    }
                                    None => {
                                        log::error!("cleanup delete: missing IPNS private key for ino {}", ino);
                                        None
                                    }
                                }
                            }
                            _ => None,
                        },
                        None => None,
                    }
                } else {
                    None
                };

            fs.inodes.remove(ino);

            if let Some(parent_inode) = fs.inodes.get_mut(parent_ino) {
                parent_inode.attr.mtime = now;
                parent_inode.attr.ctime = now;
            }

            if let Err(e) = fs.update_folder_metadata(parent_ino) {
                log::error!("Failed to update folder metadata after delete: {}", e);
            }

            // Create bin entry and publish (fire-and-forget) -- CIDs stay pinned for recovery
            let parent_ipns_name = fs.inodes.get(parent_ino)
                .map(|p| match &p.kind {
                    InodeKind::Root { ipns_name, .. } => ipns_name.clone().unwrap_or_default(),
                    InodeKind::Folder { ipns_name, .. } => ipns_name.clone(),
                    _ => String::new(),
                })
                .unwrap_or_default();

            if !parent_ipns_name.is_empty() {
                let parent_path = crate::fuse::helpers::build_folder_path(&fs, parent_ino);

                let bin_entry = if let Some((name, size, fp, cid, ver_cids)) = bin_file_data {
                    Some(cipherbox_core::bin::BinEntry {
                        id: cipherbox_crypto::utils::generate_uuid_v4(),
                        item_type: cipherbox_core::bin::BinItemType::File,
                        name: name.clone(),
                        original_parent_ipns_name: parent_ipns_name,
                        original_path: parent_path,
                        deleted_at: now_ms,
                        size,
                        mime_type: cipherbox_crypto::utils::mime_from_extension(&name).to_string(),
                        content_cid: if cid.is_empty() { None } else { Some(cid) },
                        content_size: Some(size),
                        version_cids: ver_cids,
                        file_pointer: Some(fp),
                        folder_entry: None,
                    })
                } else if let Some((name, fe)) = bin_folder_data {
                    Some(cipherbox_core::bin::BinEntry {
                        id: cipherbox_crypto::utils::generate_uuid_v4(),
                        item_type: cipherbox_core::bin::BinItemType::Folder,
                        name,
                        original_parent_ipns_name: parent_ipns_name,
                        original_path: parent_path,
                        deleted_at: now_ms,
                        size: 0,
                        mime_type: String::new(),
                        content_cid: None,
                        content_size: None,
                        version_cids: None,
                        file_pointer: None,
                        folder_entry: Some(fe),
                    })
                } else {
                    None
                };

                if let Some(entry) = bin_entry {
                    crate::fuse::spawn_bin_entry_publish(
                        fs.api.clone(),
                        fs.rt.clone(),
                        entry,
                        fs.private_key.clone(),
                        fs.public_key.to_vec(),
                        fs.publish_coordinator.clone(),
                    );
                }
            } else {
                log::warn!(
                    "cleanup delete: missing parent IPNS name for parent ino {}, skipping bin publish",
                    parent_ino
                );
            }
        } else {
            // Non-delete cleanup: flush dirty file handles
            fs.drain_upload_completions();

            let needs_flush = fs.open_files.get(&fh)
                .map(|h| {
                    let has_temp = h.temp_path.is_some();
                    let is_new = has_temp && fs.inodes.get(ino)
                        .map(|i| match &i.kind {
                            InodeKind::File { cid, .. } => cid.is_empty(),
                            _ => false,
                        })
                        .unwrap_or(false);
                    has_temp && (h.dirty || is_new)
                })
                .unwrap_or(false);

            if needs_flush {
                let handle = fs.open_files.remove(&fh).unwrap();

                let prepare_result = (|| -> Result<(), String> {
                    let plaintext = handle.read_all()?;
                    let mut file_key = cipherbox_crypto::utils::generate_file_key();
                    let iv = cipherbox_crypto::utils::generate_iv();
                    let ciphertext = cipherbox_crypto::aes::encrypt_aes_gcm(
                        &plaintext, &file_key, &iv,
                    )
                    .map_err(|e| format!("File encryption failed: {}", e))?;
                    let wrapped_key = cipherbox_crypto::ecies::wrap_key(&file_key, &fs.public_key)
                        .map_err(|e| format!("Key wrapping failed: {}", e))?;
                    cipherbox_crypto::utils::clear_bytes(&mut file_key);

                    let (old_file_cid, _old_encrypted_key, _old_iv, old_size, old_mode,
                         existing_versions, file_ipns_private_key, file_meta_ipns_name) =
                        fs.inodes.get(ino).map(|inode| match &inode.kind {
                            InodeKind::File {
                                cid, encrypted_file_key, iv, size, encryption_mode,
                                versions, file_ipns_private_key, file_meta_ipns_name, ..
                            } => (
                                if cid.is_empty() { None } else { Some(cid.clone()) },
                                encrypted_file_key.clone(), iv.clone(), *size,
                                encryption_mode.clone(), versions.clone(),
                                file_ipns_private_key.clone(), file_meta_ipns_name.clone(),
                            ),
                            _ => (None, String::new(), String::new(), 0, "GCM".to_string(), None, None, None),
                        }).unwrap_or((None, String::new(), String::new(), 0, "GCM".to_string(), None, None, None));

                    let encrypted_file_key_hex = hex::encode(&wrapped_key);
                    let iv_hex = hex::encode(&iv);
                    let file_size = plaintext.len() as u64;
                    let file_name = fs.inodes.get(ino).map(|i| i.name.clone()).unwrap_or_default();
                    let mime_type = mime_from_extension(&file_name);

                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let should_version = if let Some(ref versions) = existing_versions {
                        if let Some(newest) = versions.first() {
                            now_ms.saturating_sub(newest.timestamp) >= VERSION_COOLDOWN_MS
                        } else {
                            old_file_cid.as_ref().is_some_and(|c| !c.is_empty())
                        }
                    } else {
                        old_file_cid.as_ref().is_some_and(|c| !c.is_empty())
                    };

                    let (new_versions, pruned_cids) = if should_version {
                        if let Some(ref old_c) = old_file_cid {
                            if !old_c.is_empty() {
                                let version_entry = cipherbox_core::folder::VersionEntry {
                                    cid: old_c.clone(),
                                    file_key_encrypted: _old_encrypted_key.clone(),
                                    file_iv: _old_iv.clone(),
                                    size: old_size,
                                    timestamp: now_ms,
                                    encryption_mode: old_mode.clone(),
                                };
                                let mut versions = vec![version_entry];
                                versions.extend(existing_versions.unwrap_or_default());
                                let pruned: Vec<String> = if versions.len() > MAX_VERSIONS_PER_FILE {
                                    versions.split_off(MAX_VERSIONS_PER_FILE).into_iter().map(|v| v.cid).collect()
                                } else {
                                    vec![]
                                };
                                (Some(versions), pruned)
                            } else {
                                (existing_versions, vec![])
                            }
                        } else {
                            (existing_versions, vec![])
                        }
                    } else {
                        (existing_versions, vec![])
                    };

                    let versions_for_meta = new_versions.as_ref()
                        .filter(|v| !v.is_empty())
                        .cloned();

                    if let Some(inode) = fs.inodes.get_mut(ino) {
                        let cached_hex = match &inode.kind {
                            InodeKind::File { file_ipns_key_encrypted_hex, .. } => file_ipns_key_encrypted_hex.clone(),
                            _ => None,
                        };
                        inode.kind = InodeKind::File {
                            cid: String::new(),
                            encrypted_file_key: encrypted_file_key_hex.clone(),
                            iv: iv_hex.clone(),
                            size: file_size,
                            encryption_mode: "GCM".to_string(),
                            file_meta_ipns_name: file_meta_ipns_name.clone(),
                            file_meta_resolved: true,
                            file_ipns_private_key: file_ipns_private_key.clone(),
                            file_ipns_key_encrypted_hex: cached_hex,
                            versions: versions_for_meta.clone(),
                        };
                        // Bump generation so stale background uploads (from a
                        // prior truncate-to-zero flush) are rejected by
                        // drain_upload_completions.
                        inode.write_generation += 1;
                        inode.attr.size = file_size;
                        inode.attr.blocks = (file_size + 511) / 512;
                        inode.attr.mtime = SystemTime::now();
                    }

                    fs.pending_content.insert(ino, plaintext);

                    let write_gen = fs.inodes.get(ino)
                        .map(|i| i.write_generation)
                        .unwrap_or(0);
                    let parent_ino = fs.inodes.get(ino).map(|i| i.parent_ino).unwrap_or(ROOT_INO);
                    let folder_key_for_file_meta = fs.get_folder_key(parent_ino);
                    fs.queue_publish(parent_ino, true);

                    let api = fs.api.clone();
                    let rt = fs.rt.clone();
                    let upload_tx = fs.upload_tx.clone();
                    let coordinator = fs.publish_coordinator.clone();

                    let file_meta = cipherbox_core::folder::FileMetadata {
                        version: "v1".to_string(),
                        cid: String::new(),
                        file_key_encrypted: encrypted_file_key_hex,
                        file_iv: iv_hex,
                        size: file_size,
                        mime_type,
                        encryption_mode: "GCM".to_string(),
                        created_at: now_ms,
                        modified_at: now_ms,
                        versions: versions_for_meta,
                    };

                    std::thread::spawn(move || {
                        let result = rt.block_on(async {
                            let file_cid = cipherbox_api_client::ipfs::upload_content(&api, &ciphertext).await.map_err(|e| e.to_string())?;
                            log::info!("File uploaded: ino {} -> CID {}", ino, file_cid);

                            let _ = upload_tx.send(crate::fuse::UploadComplete {
                                ino,
                                new_cid: file_cid.clone(),
                                parent_ino,
                                old_file_cid,
                                pruned_cids,
                                write_generation: write_gen,
                            });

                            if let (Some(ipns_key), Some(ipns_name), Some(folder_key)) =
                                (&file_ipns_private_key, &file_meta_ipns_name, &folder_key_for_file_meta)
                            {
                                let mut file_meta_with_cid = file_meta;
                                file_meta_with_cid.cid = file_cid;
                                if let Err(e) = publish_file_metadata(
                                    &api, &file_meta_with_cid, folder_key, ipns_key, ipns_name, &coordinator,
                                ).await {
                                    log::warn!("Per-file IPNS publish failed for ino {}: {}", ino, e);
                                }
                            }

                            Ok::<(), String>(())
                        });

                        if let Err(e) = result {
                            log::error!("Background upload failed for ino {}: {}", ino, e);
                        }
                    });

                    Ok(())
                })();

                if let Err(e) = prepare_result {
                    log::error!("File upload preparation failed for ino {}: {}", ino, e);
                }

                handle.cleanup();
            }
        }
    }

    /// rename handler
    pub fn handle_rename(
        ctx: &WinFspContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), FspError> {
        let old_path = file_name.to_string_lossy();
        let new_path = new_file_name.to_string_lossy();

        let mut fs = ctx.inner.lock().unwrap();

        let (source_ino, old_parent_ino) = resolve_path(&fs, &old_path)
            .ok_or(status_object_name_not_found())?;

        let (new_parent_path, new_name) = split_path(&new_path);
        let (new_parent_ino, _) = resolve_path(&fs, new_parent_path)
            .ok_or(status_object_name_not_found())?;

        if let Some(dest_ino) = fs.inodes.find_child(new_parent_ino, new_name) {
            if !replace_if_exists {
                return Err(status_object_name_collision());
            }
            if let Some(dest_inode) = fs.inodes.get(dest_ino) {
                match &dest_inode.kind {
                    InodeKind::Folder { .. } => {
                        if let Some(ref children) = dest_inode.children {
                            if !children.is_empty() {
                                return Err(status_directory_not_empty());
                            }
                        }
                    }
                    InodeKind::File { cid, .. } => {
                        if !cid.is_empty() {
                            let cid_clone = cid.clone();
                            let api = fs.api.clone();
                            fs.rt.spawn(async move {
                                let _ = cipherbox_api_client::ipfs::unpin_content(&api, &cid_clone).await;
                            });
                        }
                    }
                    _ => {}
                }
            }
            fs.inodes.remove(dest_ino);
        }

        let old_name = fs.inodes.get(source_ino).map(|i| i.name.clone()).unwrap_or_default();
        fs.inodes.name_to_ino.remove(&(
            old_parent_ino,
            crate::fuse::inode::normalize_name(&old_name),
        ));

        if let Some(inode) = fs.inodes.get_mut(source_ino) {
            inode.name = new_name.to_string();
            inode.parent_ino = new_parent_ino;
            inode.attr.ctime = SystemTime::now();
        }

        fs.inodes.name_to_ino.insert(
            (new_parent_ino, crate::fuse::inode::normalize_name(new_name)),
            source_ino,
        );

        if old_parent_ino != new_parent_ino {
            if let Some(old_parent) = fs.inodes.get_mut(old_parent_ino) {
                if let Some(ref mut children) = old_parent.children {
                    children.retain(|&c| c != source_ino);
                }
                old_parent.attr.mtime = SystemTime::now();
                old_parent.attr.ctime = SystemTime::now();
            }
            if let Some(new_parent) = fs.inodes.get_mut(new_parent_ino) {
                if let Some(ref mut children) = new_parent.children {
                    children.push(source_ino);
                }
                new_parent.attr.mtime = SystemTime::now();
                new_parent.attr.ctime = SystemTime::now();
            }
            if let Err(e) = fs.update_folder_metadata(old_parent_ino) {
                log::error!("Failed to update old parent metadata after rename: {}", e);
            }
            if let Err(e) = fs.update_folder_metadata(new_parent_ino) {
                log::error!("Failed to update new parent metadata after rename: {}", e);
            }
        } else {
            if let Some(parent_inode) = fs.inodes.get_mut(old_parent_ino) {
                parent_inode.attr.mtime = SystemTime::now();
                parent_inode.attr.ctime = SystemTime::now();
            }
            if let Err(e) = fs.update_folder_metadata(old_parent_ino) {
                log::error!("Failed to update parent metadata after rename: {}", e);
            }
        }

        Ok(())
    }

    /// set_delete handler
    pub fn handle_set_delete(
        context: &WinFspFileContext,
        file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<(), FspError> {
        log::info!(
            "set_delete() ino={} fh={} path={} delete={}",
            context.ino, context.fh,
            file_name.to_string_lossy(),
            delete_file,
        );
        Ok(())
    }

}
