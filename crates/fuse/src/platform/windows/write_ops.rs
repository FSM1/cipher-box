//! Write operations for Windows WinFsp filesystem.
//!
//! Contains handler logic for: create, write, overwrite, cleanup,
//! set_basic_info, set_file_size, set_delete, rename.

#[cfg(feature = "winfsp")]
pub mod implementation {
    use std::ffi::c_void;
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    use winfsp::filesystem::{FileInfo, OpenFileInfo};
    use widestring::U16CStr;
    use winfsp::FspError;

    // Versioning constants now read from CipherBoxFS fields (user-configurable)
    use crate::file_handle::OpenFileHandle;
    use crate::helpers::mime_from_extension;
    use crate::inode::{FileAttrs, InodeData, InodeKind, ROOT_INO};
    use super::super::operations::implementation::{
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
                // Clone before the value is moved into InodeKind::Folder below (same
                // pattern as fuser plan deviation 4 fix).
                let encrypted_folder_key_hex_for_journal = encrypted_folder_key_hex.clone();

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
                        ipns_private_key: Some(ipns_private_key.clone()),
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
                let json_bytes = crate::encrypt_metadata_to_json(&metadata, &folder_key)?;
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

                // D-04: journal the MkdirPublish entry with an fsync barrier before
                // the directory entry is reported back to WinFsp (D-11b).
                let mkdir_created_at_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                // CR-01: journal the user-ECIES-wrapped parent IPNS key for replay signing.
                let parent_ipns_key_hex_for_journal = cipherbox_crypto::wrap_key(&parent_ipns_key, &fs.public_key)
                    .map(|w| hex::encode(&w))
                    .unwrap_or_default();
                // CR-03: journal the user-ECIES-wrapped child IPNS key (not TEE-wrapped).
                let child_ipns_key_hex_user_wrapped = cipherbox_crypto::wrap_key(&ipns_private_key, &fs.public_key)
                    .map(|w| hex::encode(&w))
                    .unwrap_or_else(|_| encrypted_ipns_for_tee.clone().unwrap_or_default());

                let mkdir_journal_entry = cipherbox_sdk::JournalEntry {
                    id: hex::encode(cipherbox_crypto::utils::generate_random_bytes(16)),
                    vault_root_ipns: fs.root_ipns_name.clone(),
                    op: cipherbox_sdk::JournalOp::MkdirPublish {
                        child_ipns_name: ipns_name.clone(),
                        child_folder_key_hex: encrypted_folder_key_hex_for_journal,
                        child_ipns_key_hex: child_ipns_key_hex_user_wrapped,
                        parent_folder_ipns_name: parent_ipns_name.clone(),
                        parent_ipns_key_hex: parent_ipns_key_hex_for_journal,
                        name: name.to_string(),
                        created_at_ms: mkdir_created_at_ms,
                    },
                    retries: 0,
                    status: cipherbox_sdk::JournalEntryStatus::Pending,
                };
                let mkdir_journal_entry_id = mkdir_journal_entry.id.clone();
                fs.journal.put(&mkdir_journal_entry)?;

                let api = fs.api.clone();
                let rt = fs.rt.clone();
                let ipns_name_clone = ipns_name.clone();
                let coordinator = fs.publish_coordinator.clone();
                let upload_tx = fs.upload_tx.clone();
                let journal_for_mkdir = fs.journal.clone();
                let parent_ino_for_conflict = parent_ino;

                std::thread::spawn(move || {
                    let result = rt.block_on(async {
                        let initial_cid = cipherbox_api_client::ipfs::upload_content(&api, &json_bytes).await.map_err(|e| e.to_string())?;
                        let ipns_key_arr: [u8; 32] = (*ipns_private_key).clone().try_into()
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
                        let parent_json = crate::encrypt_metadata_to_json(
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
                        // On conflict, signal the FS thread via upload_tx so the debounced
                        // publisher retries with a fresh sequence (D-11a).
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
                                // Remove journal entry now that parent publish is confirmed (D-11b).
                                let _ = journal_for_mkdir.remove(&mkdir_journal_entry_id);
                                log::info!("Parent metadata published after mkdir");
                            }
                            cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
                                // Signal the FS thread to re-arm the debounced publisher with a
                                // fresh sequence (D-11a). Journal entry stays until parent publish
                                // confirms (D-11b) — do NOT remove it here.
                                log::warn!(
                                    "Conflict on parent mkdir publish (expected seq {}, server has {}). Signalling retry.",
                                    seq, current_sequence_number
                                );
                                let _ = upload_tx.send(crate::FsEvent::MkdirConflict { parent_ino: parent_ino_for_conflict });
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
                                    let ver_cids = crate::helpers::versions_to_bin_entries(versions);
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

            fs.publish_queue.remove(&ino);
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
                let parent_path = crate::helpers::build_folder_path(&fs, parent_ino);

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
                    crate::spawn_bin_entry_publish(
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
                let is_new_file = fs.inodes.get(ino)
                    .map(|i| match &i.kind {
                        InodeKind::File { cid, .. } => cid.is_empty(),
                        _ => false,
                    })
                    .unwrap_or(false);
                let handle = fs.open_files.remove(&fh).unwrap();

                // Spawn params struct separates the prepare+journal phase from the spawn
                // phase so handle.cleanup() can run before the spawn (D-04, D-05).
                // CR-05: field types corrected to match CipherBoxFS fields.
                struct UploadSpawnParams {
                    api: std::sync::Arc<cipherbox_api_client::ApiClient>,
                    rt: tokio::runtime::Handle,
                    upload_tx: std::sync::mpsc::Sender<crate::FsEvent>,
                    coordinator: std::sync::Arc<crate::PublishCoordinator>,
                    tee_public_key: Option<Vec<u8>>,
                    tee_key_epoch: Option<u32>,
                    ciphertext: Vec<u8>,
                    file_meta: cipherbox_core::folder::FileMetadata,
                    file_ipns_private_key: Option<zeroize::Zeroizing<Vec<u8>>>,
                    file_meta_ipns_name: Option<String>,
                    folder_key_for_file_meta: Option<Vec<u8>>,
                    old_file_cid: Option<String>,
                    pruned_cids: Vec<String>,
                    write_gen: u64,
                    parent_ino: u64,
                    journal: cipherbox_sdk::WriteQueue,
                    // CR-07: carry full entry so record_failure can be called on failure.
                    journal_entry: cipherbox_sdk::JournalEntry,
                }

                let prepare_result = (|| -> Result<UploadSpawnParams, String> {
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

                    let (old_file_cid, old_encrypted_key, old_iv, old_size, old_mode,
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

                    let (new_versions, pruned_cids) = crate::helpers::apply_versioning(
                        existing_versions,
                        &old_file_cid,
                        &old_encrypted_key,
                        &old_iv,
                        old_size,
                        &old_mode,
                        now_ms,
                        fs.max_versions_per_file,
                        fs.version_cooldown_ms,
                        ino,
                    );

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

                    // Resolve parent IPNS name for stable journal entry (D-02).
                    let parent_folder_ipns_name = fs.inodes.get(parent_ino)
                        .and_then(|inode| match &inode.kind {
                            InodeKind::Root { ipns_name, .. } => ipns_name.clone(),
                            InodeKind::Folder { ipns_name, .. } => Some(ipns_name.clone()),
                            _ => None,
                        })
                        .unwrap_or_else(|| fs.root_ipns_name.clone());

                    // CR-01: journal the user-ECIES-wrapped parent IPNS key for replay signing.
                    let parent_ipns_key_hex_for_journal = fs.inodes.get(parent_ino)
                        .and_then(|inode| match &inode.kind {
                            InodeKind::Root { ipns_private_key, .. } => ipns_private_key.as_deref(),
                            InodeKind::Folder { ipns_private_key, .. } => ipns_private_key.as_deref(),
                            _ => None,
                        })
                        .and_then(|raw_key| {
                            cipherbox_crypto::wrap_key(raw_key, &fs.public_key)
                                .map(|w| hex::encode(&w))
                                .ok()
                        })
                        .unwrap_or_default();

                    let file_meta_ipns_name_str = file_meta_ipns_name
                        .clone()
                        .unwrap_or_default();

                    // Build journal entry referencing ciphertext only — no plaintext (D-05).
                    use base64::Engine;
                    let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
                    let wrapped_key_hex = encrypted_file_key_hex.clone();
                    let journal_entry = cipherbox_sdk::JournalEntry {
                        id: hex::encode(cipherbox_crypto::utils::generate_random_bytes(16)),
                        vault_root_ipns: fs.root_ipns_name.clone(),
                        op: cipherbox_sdk::JournalOp::UploadFile {
                            ciphertext_b64,
                            wrapped_key_hex,
                            iv_hex: iv_hex.clone(),
                            file_meta_ipns_name: file_meta_ipns_name_str,
                            file_ipns_key_hex: file_meta_ipns_name.as_ref().map(|_| {
                                file_ipns_private_key.as_ref()
                                    .map(|k| {
                                        cipherbox_crypto::ecies::wrap_key(k, &fs.public_key)
                                            .map(|w| hex::encode(&w))
                                            .unwrap_or_default()
                                    })
                                    .or_else(|| {
                                        fs.inodes.get(ino).and_then(|i| match &i.kind {
                                            InodeKind::File { file_ipns_key_encrypted_hex, .. } => file_ipns_key_encrypted_hex.clone(),
                                            _ => None,
                                        })
                                    })
                            }).flatten(),
                            parent_folder_ipns_name,
                            parent_ipns_key_hex: parent_ipns_key_hex_for_journal,
                            filename: file_name,
                            size: file_size,
                            created_at_ms: now_ms,
                        },
                        retries: 0,
                        status: cipherbox_sdk::JournalEntryStatus::Pending,
                    };
                    // D-04: fsync journal entry to disk BEFORE spawning the upload thread.
                    // WinFsp cleanup has no explicit reply — the implicit ack occurs after
                    // the callback returns, but the fsync barrier here still protects against
                    // crash-before-spawn data loss.
                    fs.journal.put(&journal_entry)?;

                    let api = fs.api.clone();
                    let rt = fs.rt.clone();
                    let upload_tx = fs.upload_tx.clone();
                    let coordinator = fs.publish_coordinator.clone();
                    let tee_public_key = fs.tee_public_key.clone();
                    let tee_key_epoch = fs.tee_key_epoch;
                    let journal_clone = fs.journal.clone();

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

                    Ok(UploadSpawnParams {
                        api,
                        rt,
                        upload_tx,
                        coordinator,
                        tee_public_key,
                        tee_key_epoch,
                        ciphertext,
                        file_meta,
                        file_ipns_private_key,
                        file_meta_ipns_name,
                        folder_key_for_file_meta,
                        old_file_cid,
                        pruned_cids,
                        write_gen,
                        parent_ino,
                        journal: journal_clone,
                        journal_entry,
                    })
                })();

                match prepare_result {
                    Ok(params) => {
                        // D-05: zeroize and delete plaintext temp file BEFORE spawning.
                        handle.cleanup();

                        // Spawn background upload AFTER journal fsync; entry stays in journal
                        // until success, preserving the write_generation stale-drain guard.
                        let UploadSpawnParams {
                            api, rt, upload_tx, coordinator, tee_public_key, tee_key_epoch,
                            ciphertext, file_meta, file_ipns_private_key, file_meta_ipns_name,
                            folder_key_for_file_meta, old_file_cid, pruned_cids, write_gen,
                            parent_ino, journal: spawn_journal, journal_entry: spawn_entry,
                        } = params;
                        std::thread::spawn(move || {
                            let result = rt.block_on(async {
                                let file_cid = cipherbox_api_client::ipfs::upload_content(&api, &ciphertext).await.map_err(|e| e.to_string())?;
                                log::info!("File uploaded: ino {} -> CID {}", ino, file_cid);

                                let _ = upload_tx.send(crate::FsEvent::UploadComplete(crate::UploadComplete {
                                    ino,
                                    new_cid: file_cid.clone(),
                                    parent_ino,
                                    old_file_cid,
                                    pruned_cids,
                                    write_generation: write_gen,
                                }));

                                // CR-08 mirror, mechanism b: the upload thread never removes
                                // the journal entry — files without per-file IPNS keys would
                                // otherwise be removed after upload_content alone, before the
                                // debounced parent-pointer publish, reopening the orphan
                                // window. Replay on next mount is the authoritative cleanup
                                // path (idempotent already_present check), matching the fuser
                                // path in read_ops.rs.
                                if let (Some(ipns_key), Some(ipns_name), Some(folder_key)) =
                                    (&file_ipns_private_key, &file_meta_ipns_name, &folder_key_for_file_meta)
                                {
                                    let mut file_meta_with_cid = file_meta;
                                    file_meta_with_cid.cid = file_cid;
                                    if let Err(e) = publish_file_metadata(
                                        &api, &file_meta_with_cid, folder_key, ipns_key, ipns_name, &coordinator,
                                        tee_public_key.as_deref(),
                                        tee_key_epoch,
                                        is_new_file,
                                    ).await {
                                        log::warn!("Per-file IPNS publish failed for ino {}: {}", ino, e);
                                    }
                                }

                                Ok::<(), String>(())
                            });

                            if let Err(e) = result {
                                // CR-07: call record_failure on background upload error so the
                                // retry/park pipeline has a production caller. Entry stays in
                                // journal for replay (D-09).
                                log::error!("Background upload failed for ino {}: {}", ino, e);
                                if let Err(re) = spawn_journal.record_failure(&spawn_entry, &e) {
                                    log::warn!("cleanup: record_failure failed for ino {}: {}", ino, re);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        // CR-04 mirror: WinFsp handle_cleanup returns () and cannot
                        // return a status code. However, the journal.put() that would
                        // have journaled the entry is inside the prepare closure, so
                        // on Err the entry is never written to disk — no success-implying
                        // state is committed. The OS receives an implicit success ack
                        // when the callback returns, but the in-memory inode state
                        // reflects the failed encryption (cid still empty), so any
                        // subsequent read returns stale or empty data, making the
                        // failure visible. This matches the fuser CR-04 constraint:
                        // WinFsp has no equivalent to reply.error(libc::EIO) here.
                        log::error!("File upload preparation failed for ino {}: {}", ino, e);
                        handle.cleanup();
                    }
                }
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
            fs.publish_queue.remove(&dest_ino);
            fs.inodes.remove(dest_ino);
        }

        let old_name = fs.inodes.get(source_ino).map(|i| i.name.clone()).unwrap_or_default();
        fs.inodes.name_to_ino.remove(&(
            old_parent_ino,
            crate::inode::normalize_name(&old_name),
        ));

        if let Some(inode) = fs.inodes.get_mut(source_ino) {
            inode.name = new_name.to_string();
            inode.parent_ino = new_parent_ino;
            inode.attr.ctime = SystemTime::now();
        }

        fs.inodes.name_to_ino.insert(
            (new_parent_ino, crate::inode::normalize_name(new_name)),
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
