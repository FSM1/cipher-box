//! Write operations for Windows WinFsp filesystem.
//!
//! Contains handler logic for: create, write, overwrite, cleanup,
//! set_basic_info, set_file_size, set_delete, rename.

#[cfg(feature = "winfsp")]
pub mod implementation {
    use std::ffi::c_void;
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    use widestring::U16CStr;
    use winfsp::filesystem::{FileInfo, OpenFileInfo};
    use winfsp::FspError;

    // Versioning constants now read from CipherBoxFS fields (user-configurable)
    use super::super::operations::implementation::{
        filetime_to_systemtime, fill_file_info, is_windows_special, publish_file_metadata,
        resolve_path, split_path, status_access_denied, status_directory_not_empty,
        status_invalid_handle, status_invalid_parameter, status_io_device_error,
        status_object_name_collision, status_object_name_not_found, WinFspContext,
        WinFspFileContext,
    };
    use crate::file_handle::OpenFileHandle;
    use crate::inode::{FileAttrs, InodeData, InodeKind};

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
            path,
            create_options,
            granted_access
        );
        let (parent_path, name) = split_path(&path);

        if name.is_empty() {
            return Err(status_invalid_parameter());
        }

        if is_windows_special(name) {
            return Err(status_object_name_not_found());
        }

        let mut fs = ctx.inner.lock().unwrap();

        let (parent_ino, _) =
            resolve_path(&fs, parent_path).ok_or(status_object_name_not_found())?;

        let parent_is_dir = fs.inodes.get(parent_ino).map(|inode| {
            matches!(
                inode.kind,
                InodeKind::Root { .. } | InodeKind::Folder { .. }
            )
        });
        if parent_is_dir != Some(true) {
            return Err(status_object_name_not_found());
        }

        // D-06: reject duplicate child names before any inode mutation (EEXIST equivalent)
        if fs.inodes.find_child(parent_ino, name).is_some() {
            return Err(status_object_name_collision());
        }

        // FILE_DIRECTORY_FILE = 0x00000001
        let is_dir = (create_options & 0x00000001) != 0;

        if is_dir {
            // Create directory
            let result = (|| -> Result<(FileAttrs, u64), String> {
                let folder_key = cipherbox_crypto::utils::generate_file_key();
                let (ipns_public_key, ipns_private_key) =
                    cipherbox_crypto::ed25519::generate_ed25519_keypair();
                let ipns_pub_arr: [u8; 32] = ipns_public_key
                    .clone()
                    .try_into()
                    .map_err(|_| "Invalid IPNS public key length".to_string())?;
                let ipns_name = cipherbox_core::ipns::derive_ipns_name(&ipns_pub_arr)
                    .map_err(|e| format!("Failed to derive IPNS name: {}", e))?;
                let wrapped_folder_key =
                    cipherbox_crypto::ecies::wrap_key(&folder_key, &fs.public_key)
                        .map_err(|e| format!("Folder key wrapping failed: {}", e))?;
                let encrypted_folder_key_hex = hex::encode(&wrapped_folder_key);
                // Clone before the value is moved into InodeKind::Folder below (same
                // pattern as fuser plan deviation 4 fix).
                let encrypted_folder_key_hex_for_journal = encrypted_folder_key_hex.clone();

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

                let inode = InodeData {
                    ino,
                    parent_ino,
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

                // Build the JournalEntry via the shared helper (journal_helpers.rs).
                // The helper handles: initial metadata encryption, TEE-wrap,
                // build_folder_metadata, ECIES-wrap of parent + child IPNS keys,
                // and JournalOp::MkdirPublish construction.
                // Roll back the in-memory inode insert + parent children/mtime update if the
                // journal entry can't be built or fsynced. Otherwise a failed mkdir returns an
                // error to WinFsp but leaves a ghost directory in the inode table with no
                // durable replay record. InodeTable::remove cleans the inode, name index, and
                // parent's children entry.
                let mkdir_result = match fs.build_mkdir_journal_entry(
                    parent_ino,
                    ino,
                    name,
                    &folder_key,
                    &ipns_name,
                    ipns_private_key.clone(),
                    &encrypted_folder_key_hex_for_journal,
                ) {
                    Ok(result) => result,
                    Err(e) => {
                        fs.inodes.remove(ino);
                        return Err(e);
                    }
                };

                let mkdir_journal_entry_id = mkdir_result.entry.id.clone();

                // D-04: fsync journal entry to disk BEFORE the directory entry is
                // reported back to WinFsp (D-11b).
                if let Err(e) = fs.journal.put(&mkdir_result.entry) {
                    fs.inodes.remove(ino);
                    return Err(e);
                }

                let crate::journal_helpers::MkdirJournalResult {
                    json_bytes,
                    ipns_private_key: ipns_private_key_zeroized,
                    encrypted_ipns_for_tee,
                    tee_key_epoch,
                    ipns_name: ipns_name_clone,
                    parent_metadata,
                    parent_folder_key,
                    parent_ipns_key,
                    parent_ipns_name,
                    parent_old_cid,
                    ..
                } = mkdir_result;

                let api = fs.api.clone();
                let rt = fs.rt.clone();
                let coordinator = fs.publish_coordinator.clone();
                let upload_tx = fs.upload_tx.clone();
                let journal_for_mkdir = fs.journal.clone();
                let parent_ino_for_conflict = parent_ino;

                std::thread::spawn(move || {
                    let result = rt.block_on(async {
                        let initial_cid = cipherbox_api_client::ipfs::upload_content(&api, &json_bytes).await.map_err(|e| e.to_string())?;
                        let ipns_key_arr: [u8; 32] = (*ipns_private_key_zeroized).clone().try_into()
                            .map_err(|_| "Invalid IPNS key length".to_string())?;
                        let value = format!("/ipfs/{}", initial_cid);
                        let record = cipherbox_core::ipns::create_ipns_record(
                            &ipns_key_arr, &value, 1, 86_400_000,
                        ).map_err(|e| format!("IPNS record creation failed: {}", e))?;
                        let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
                            .map_err(|e| format!("IPNS marshal failed: {}", e))?;

                        use base64::Engine;
                        let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
                        // New folder initial publish: sequence 1 (D-02), no conflict check needed
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
                                coordinator.record_publish(&ipns_name_clone, 1);
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
                    Ok(WinFspFileContext {
                        fh,
                        ino,
                        is_dir: true,
                    })
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

            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let verifying_key = signing_key.verifying_key();
            let file_ipns_private_key = signing_key.to_bytes().to_vec();
            let file_ipns_public_key_bytes: [u8; 32] = verifying_key.to_bytes();
            let file_ipns_name =
                match cipherbox_core::ipns::derive_ipns_name(&file_ipns_public_key_bytes) {
                    Ok(name) => name,
                    Err(e) => {
                        log::error!("create: IPNS name derivation failed: {}", e);
                        return Err(status_io_device_error());
                    }
                };

            let ipns_key_encrypted_hex =
                match cipherbox_crypto::ecies::wrap_key(&file_ipns_private_key, &fs.public_key) {
                    Ok(wrapped) => Some(hex::encode(&wrapped)),
                    Err(e) => {
                        log::error!("create: failed to ECIES-wrap IPNS key: {}", e);
                        return Err(status_io_device_error());
                    }
                };

            let inode = InodeData {
                ino,
                parent_ino,
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

            fs.mutated_folders
                .insert(parent_ino, std::time::Instant::now());

            *file_info.as_mut() = fill_file_info(&attr);
            Ok(WinFspFileContext {
                fh,
                ino,
                is_dir: false,
            })
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
                ino,
                fh,
                buffer.len(),
                offset
            );
            offset
        };

        // D-05: write_at takes an i64 offset; a u64 offset above i64::MAX would wrap to a
        // negative value. Reject it as an invalid parameter (mirrors the macOS EINVAL guard)
        // before the narrowing cast below.
        if actual_offset > i64::MAX as u64 {
            return Err(status_invalid_parameter());
        }

        // D-05: guard offset+len overflow before write_at (winfsp offset is u64, no <0 check)
        let new_end = match actual_offset.checked_add(buffer.len() as u64) {
            Some(end) => end,
            None => return Err(status_io_device_error()),
        };

        let handle = match fs.open_files.get_mut(&fh) {
            Some(h) => h,
            None => return Err(status_invalid_handle()),
        };

        match handle.write_at(actual_offset as i64, buffer) {
            Ok(written) => {
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
        log::info!(
            "overwrite() called for ino={} fh={}",
            context.ino,
            context.fh
        );
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
            if let InodeKind::File {
                size: ref mut s,
                cid: ref mut c,
                ..
            } = inode.kind
            {
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
            context.ino,
            context.fh,
            new_size,
            set_allocation_size
        );
        let mut fs = ctx.inner.lock().unwrap();

        let should_truncate = !set_allocation_size || (set_allocation_size && new_size == 0);

        if should_truncate {
            if let Some(handle) = fs.open_files.get_mut(&context.fh) {
                if handle.temp_path.is_some() {
                    handle
                        .truncate(new_size)
                        .map_err(|_| status_io_device_error())?;
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
                if let InodeKind::File {
                    size: ref mut s,
                    cid: ref mut c,
                    ..
                } = inode.kind
                {
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
    pub fn handle_cleanup(ctx: &WinFspContext, context: &WinFspFileContext, flags: u32) {
        log::info!(
            "cleanup() ino={} fh={} flags=0x{:08X}",
            context.ino,
            context.fh,
            flags
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

            // Capture the PARENT read/write keys (node/v3 D-07 dual-ref seal
            // material). Terminal-owner (D-09): copy the bytes, never zero the
            // inode-owned buffers.
            let parent_keys: Option<([u8; 32], [u8; 32])> =
                fs.inodes.get(parent_ino).and_then(|p| match &p.kind {
                    InodeKind::Root {
                        read_key,
                        write_key,
                        ..
                    }
                    | InodeKind::Folder {
                        read_key,
                        write_key,
                        ..
                    } => Some((**read_key, **write_key)),
                    _ => None,
                });

            // Capture the D-07 dual ref for a File or Folder child from its OWN
            // node/v3 keys, mirroring the FUSE handle_unlink/handle_rmdir path:
            // SealedChildRef.ipns_name (READ plane, a k51) and
            // WriteChildRef.child_id = uuid_from_ino(ino) (WRITE plane, a UUID)
            // — never conflated. Tuple: (name, size, item_type, content_cid,
            // child_ref, write_child_ref, child_published_node).
            let bin_capture: Option<(
                String,
                u64,
                cipherbox_core::bin::BinItemType,
                String,
                cipherbox_core::node::SealedChildRef,
                cipherbox_core::node::WriteChildRef,
                String,
            )> = match fs.inodes.get(ino) {
                Some(inode) => {
                    // WRITE plane is keyed by the child UUID (uuid_from_ino).
                    let child_id = crate::fs::uuid_from_ino(ino);
                    match &inode.kind {
                        InodeKind::File {
                            ipns_name,
                            read_key,
                            write_key,
                            size,
                            cid,
                            ..
                        } => {
                            if ipns_name.is_empty() {
                                log::warn!(
                                    "cleanup delete: missing ipns_name for ino {}, skipping bin entry",
                                    ino
                                );
                                None
                            } else if let Some((pr, pw)) = parent_keys {
                                // SECURITY-REVIEW: D-07 dual-keying — childId(UUID
                                // via uuid_from_ino) vs ipnsName must not be
                                // conflated.
                                cipherbox_sdk::build_child_refs(
                                    &**read_key,
                                    &**write_key,
                                    &pr,
                                    &pw,
                                    &child_id,
                                    ipns_name,
                                    &inode.name,
                                    cipherbox_core::node::NodeKind::File,
                                    0,
                                    0,
                                )
                                .ok()
                                .map(|(cr, wr)| {
                                    (
                                        inode.name.clone(),
                                        *size,
                                        cipherbox_core::bin::BinItemType::File,
                                        cid.clone(),
                                        cr,
                                        wr,
                                        String::new(),
                                    )
                                })
                            } else {
                                None
                            }
                        }
                        InodeKind::Folder {
                            ipns_name,
                            read_key,
                            write_key,
                            ..
                        } => {
                            if ipns_name.is_empty() {
                                None
                            } else if let Some((pr, pw)) = parent_keys {
                                // SECURITY-REVIEW: D-07 dual-keying — childId(UUID
                                // via uuid_from_ino) vs ipnsName must not be
                                // conflated.
                                cipherbox_sdk::build_child_refs(
                                    &**read_key,
                                    &**write_key,
                                    &pr,
                                    &pw,
                                    &child_id,
                                    ipns_name,
                                    &inode.name,
                                    cipherbox_core::node::NodeKind::Folder,
                                    0,
                                    0,
                                )
                                .ok()
                                .map(|(cr, wr)| {
                                    (
                                        inode.name.clone(),
                                        0u64,
                                        cipherbox_core::bin::BinItemType::Folder,
                                        String::new(),
                                        cr,
                                        wr,
                                        String::new(),
                                    )
                                })
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                }
                None => None,
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
            let parent_ipns_name = fs
                .inodes
                .get(parent_ino)
                .map(|p| match &p.kind {
                    InodeKind::Root { ipns_name, .. } => ipns_name.clone(),
                    InodeKind::Folder { ipns_name, .. } => ipns_name.clone(),
                    _ => String::new(),
                })
                .unwrap_or_default();

            if !parent_ipns_name.is_empty() {
                let parent_path = crate::helpers::build_folder_path(&fs, parent_ino);

                let bin_entry = if let Some((
                    name,
                    size,
                    item_type,
                    cid,
                    child_ref,
                    write_child_ref,
                    child_published_node,
                )) = bin_capture
                {
                    let (content_cid, content_size, mime_type) = match item_type {
                        cipherbox_core::bin::BinItemType::File => (
                            if cid.is_empty() { None } else { Some(cid) },
                            Some(size),
                            cipherbox_crypto::utils::mime_from_extension(&name).to_string(),
                        ),
                        cipherbox_core::bin::BinItemType::Folder => (None, None, String::new()),
                    };
                    Some(cipherbox_core::bin::BinEntry {
                        id: cipherbox_crypto::utils::generate_uuid_v4(),
                        item_type,
                        name,
                        original_parent_ipns_name: parent_ipns_name,
                        original_path: parent_path,
                        deleted_at: now_ms,
                        size,
                        mime_type,
                        content_cid,
                        content_size,
                        version_cids: None,
                        child_published_node,
                        child_ref,
                        write_child_ref,
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

            let needs_flush = fs
                .open_files
                .get(&fh)
                .map(|h| {
                    let has_temp = h.temp_path.is_some();
                    let is_new = has_temp
                        && fs
                            .inodes
                            .get(ino)
                            .map(|i| match &i.kind {
                                InodeKind::File { cid, .. } => cid.is_empty(),
                                _ => false,
                            })
                            .unwrap_or(false);
                    has_temp && (h.dirty || is_new)
                })
                .unwrap_or(false);

            if needs_flush {
                let is_new_file = fs
                    .inodes
                    .get(ino)
                    .map(|i| match &i.kind {
                        InodeKind::File { cid, .. } => cid.is_empty(),
                        _ => false,
                    })
                    .unwrap_or(false);
                let handle = fs.open_files.remove(&fh).unwrap();

                // Build the journal entry via the shared helper (journal_helpers.rs),
                // then fsync + apply in-memory mutations.
                //
                // CR-04: defer the in-memory write (inode kind/attr + generation bump,
                // pending_content, queued publish) until AFTER the journal fsync below, so a
                // prepare/journal failure mutates nothing. WinFsp Cleanup cannot signal an
                // error to the OS, so leaving no partial state on failure is the only safe
                // posture available on this path.
                let build_result =
                    (|| -> Result<crate::journal_helpers::UploadJournalResult, String> {
                        // Steps 1-7: encrypt, wrap, resolve parent IPNS, build JournalEntry.
                        let result = fs.build_upload_journal_entry(ino, &handle, is_new_file)?;

                        // D-04: fsync journal entry to disk BEFORE spawning the upload thread.
                        // WinFsp cleanup has no explicit reply — the implicit ack occurs after
                        // the callback returns, but the fsync barrier here still protects against
                        // crash-before-spawn data loss.
                        fs.journal.put(&result.entry)?;

                        // CR-04: journal durably committed — now apply the in-memory write.
                        if let Some(inode) = fs.inodes.get_mut(ino) {
                            let cached_hex = match &inode.kind {
                                InodeKind::File {
                                    file_ipns_key_encrypted_hex,
                                    ..
                                } => file_ipns_key_encrypted_hex.clone(),
                                _ => None,
                            };
                            inode.kind = InodeKind::File {
                                cid: String::new(),
                                encrypted_file_key: result.encrypted_file_key_hex.clone(),
                                iv: result.iv_hex.clone(),
                                size: result.file_size,
                                encryption_mode: "GCM".to_string(),
                                file_meta_ipns_name: result.file_meta_ipns_name.clone(),
                                file_meta_resolved: true,
                                file_ipns_private_key: result.file_ipns_private_key.clone(),
                                file_ipns_key_encrypted_hex: cached_hex,
                                versions: result.versions_for_meta.clone(),
                            };
                            // Bump generation so stale background uploads (from a
                            // prior truncate-to-zero flush) are rejected by
                            // drain_upload_completions.
                            inode.write_generation += 1;
                            inode.attr.size = result.file_size;
                            inode.attr.blocks = (result.file_size + 511) / 512;
                            inode.attr.mtime = SystemTime::now();
                        }

                        fs.pending_content.insert(ino, result.plaintext.clone());

                        fs.queue_publish(result.parent_ino, true);

                        Ok(result)
                    })();

                match build_result {
                    Ok(result) => {
                        // CR-07: snapshot for record_failure in spawn closure.
                        let spawn_entry = result.entry.clone();

                        // Read write_gen AFTER the inode mutation (write_generation bump)
                        // that happened inside the build_result closure above.
                        let write_gen = fs.inodes.get(ino).map(|i| i.write_generation).unwrap_or(0);

                        let crate::journal_helpers::UploadJournalResult {
                            ciphertext,
                            file_meta,
                            file_ipns_private_key,
                            file_meta_ipns_name,
                            folder_key_for_file_meta,
                            old_file_cid,
                            pruned_cids,
                            parent_ino,
                            ..
                        } = result;

                        let api = fs.api.clone();
                        let rt = fs.rt.clone();
                        let upload_tx = fs.upload_tx.clone();
                        let coordinator = fs.publish_coordinator.clone();
                        let tee_public_key = fs.tee_public_key.clone();
                        let tee_key_epoch = fs.tee_key_epoch;
                        let spawn_journal = fs.journal.clone();

                        // D-05: zeroize and delete plaintext temp file BEFORE spawning.
                        handle.cleanup();
                        std::thread::spawn(move || {
                            let result = rt.block_on(async {
                                let file_cid =
                                    cipherbox_api_client::ipfs::upload_content(&api, &ciphertext)
                                        .await
                                        .map_err(|e| e.to_string())?;
                                log::info!("File uploaded: ino {} -> CID {}", ino, file_cid);

                                let _ = upload_tx.send(crate::FsEvent::UploadComplete(
                                    crate::UploadComplete {
                                        ino,
                                        new_cid: file_cid.clone(),
                                        parent_ino,
                                        old_file_cid,
                                        pruned_cids,
                                        write_generation: write_gen,
                                    },
                                ));

                                // CR-08 mirror, mechanism b: the upload thread never removes
                                // the journal entry — files without per-file IPNS keys would
                                // otherwise be removed after upload_content alone, before the
                                // debounced parent-pointer publish, reopening the orphan
                                // window. Replay on next mount is the authoritative cleanup
                                // path (idempotent already_present check), matching the fuser
                                // path in read_ops.rs.
                                if let (Some(ipns_key), Some(ipns_name), Some(folder_key)) = (
                                    &file_ipns_private_key,
                                    &file_meta_ipns_name,
                                    &folder_key_for_file_meta,
                                ) {
                                    let mut file_meta_with_cid = file_meta;
                                    file_meta_with_cid.cid = file_cid;
                                    if let Err(e) = publish_file_metadata(
                                        &api,
                                        &file_meta_with_cid,
                                        folder_key,
                                        ipns_key,
                                        ipns_name,
                                        &coordinator,
                                        tee_public_key.as_deref(),
                                        tee_key_epoch,
                                        is_new_file,
                                    )
                                    .await
                                    {
                                        log::warn!(
                                            "Per-file IPNS publish failed for ino {}: {}",
                                            ino,
                                            e
                                        );
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
                                    log::warn!(
                                        "cleanup: record_failure failed for ino {}: {}",
                                        ino,
                                        re
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        // CR-04 mirror: WinFsp handle_cleanup returns () and cannot return a
                        // status code, so there is no equivalent to reply.error(libc::EIO).
                        // All in-memory mutations are deferred until after the journal fsync
                        // (inside the prepare closure), so on Err nothing was committed: no
                        // journal entry on disk, and the inode/pending_content/publish-queue
                        // state is unchanged from before the write. A subsequent read returns
                        // the original data — the failed write simply did not take effect.
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

        let (source_ino, old_parent_ino) =
            resolve_path(&fs, &old_path).ok_or(status_object_name_not_found())?;

        let (new_parent_path, new_name) = split_path(&new_path);
        let (new_parent_ino, _) =
            resolve_path(&fs, new_parent_path).ok_or(status_object_name_not_found())?;

        // Cross-folder FILE moves must re-encrypt the per-file FileMetadata to the
        // destination folderKey (it is sealed with the parent folderKey). Capture
        // the inputs before any inode mutation. See the FUSE handle_rename path for
        // the full rationale. Folder moves need nothing.
        let reencrypt_inputs: Option<(
            String,
            zeroize::Zeroizing<Vec<u8>>,
            zeroize::Zeroizing<Vec<u8>>,
            zeroize::Zeroizing<Vec<u8>>,
        )> = if old_parent_ino != new_parent_ino {
            match fs.inodes.get(source_ino).map(|i| &i.kind) {
                Some(InodeKind::File {
                    file_meta_ipns_name: Some(meta_ipns),
                    file_ipns_private_key: Some(key),
                    ..
                }) if !meta_ipns.is_empty() => {
                    match (
                        fs.get_folder_key(old_parent_ino),
                        fs.get_folder_key(new_parent_ino),
                    ) {
                        (Some(src_key), Some(dst_key)) => {
                            Some((meta_ipns.clone(), key.clone(), src_key, dst_key))
                        }
                        _ => {
                            log::warn!(
                                    "rename: cross-folder move missing folder key(s) for ino {}; skipping metadata re-encrypt",
                                    source_ino
                                );
                            None
                        }
                    }
                }
                Some(InodeKind::File { .. }) => {
                    log::warn!(
                            "rename: cross-folder file move for ino {} missing IPNS name/key; skipping metadata re-encrypt",
                            source_ino
                        );
                    None
                }
                _ => None,
            }
        } else {
            None
        };

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
                                let _ = cipherbox_api_client::ipfs::unpin_content(&api, &cid_clone)
                                    .await;
                            });
                        }
                    }
                    _ => {}
                }
            }
            fs.publish_queue.remove(&dest_ino);
            fs.inodes.remove(dest_ino);
        }

        let old_name = fs
            .inodes
            .get(source_ino)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        fs.inodes
            .name_to_ino
            .remove(&(old_parent_ino, crate::inode::normalize_name(&old_name)));

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

        // Re-encrypt the moved file's metadata to the destination folderKey
        // (fire-and-forget). Without this, every fresh resolve under the new
        // folder's key fails to decrypt.
        if let Some((meta_ipns, file_ipns_key, src_key, dst_key)) = reencrypt_inputs {
            crate::spawn_file_meta_reencrypt(
                fs.api.clone(),
                fs.rt.clone(),
                meta_ipns,
                file_ipns_key,
                src_key,
                dst_key,
                fs.publish_coordinator.clone(),
                fs.tee_public_key.clone(),
                fs.tee_key_epoch,
            );
        }

        Ok(())
    }

    /// set_delete handler.
    ///
    /// This is the Windows fail-closed share-revocation point. WinFsp calls
    /// `set_delete` BEFORE the actual delete-on-close runs in `handle_cleanup`
    /// (which returns `()` and cannot abort), and unlike cleanup this callback
    /// returns `Result<(), FspError>`, so returning `Err` rejects the delete.
    /// We mirror the unix `handle_unlink`/`handle_rmdir` contract: revoke any
    /// shares/invites for the node BEFORE it is destroyed, and on failure reject
    /// the delete (`STATUS_ACCESS_DENIED`) so the item stays put and no sharee is
    /// left with access to soon-to-be-orphaned content.
    ///
    /// When `delete_file` is `false` WinFsp is clearing a previously-set delete
    /// flag (an un-delete); there is nothing to revoke, so we accept it.
    ///
    /// Known gap (accepted): `set_delete(true)` followed by `set_delete(false)`
    /// (an application setting then cancelling `DELETE_ON_CLOSE`) revokes shares
    /// eagerly on the `true` call and does not restore them on the cancel — the
    /// node survives but its shares are gone. We accept this because `set_delete`
    /// is the only WinFsp callback that can *reject* a delete; deferring to
    /// `handle_cleanup` (the real deletion point) is impossible since cleanup
    /// returns `()` and cannot abort. The cancelled-delete window is rare, and
    /// the owner can always re-share; this trade favours TRUE fail-closed
    /// revocation (never leaving a sharee with access to deleted content) over
    /// avoiding the occasional spurious revoke on a cancelled delete.
    pub fn handle_set_delete(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<(), FspError> {
        log::info!(
            "set_delete() ino={} fh={} path={} delete={}",
            context.ino,
            context.fh,
            file_name.to_string_lossy(),
            delete_file,
        );

        if !delete_file {
            // Clearing the delete disposition — nothing is being destroyed.
            return Ok(());
        }

        // Resolve the node's own IPNS name under the lock, then drop the lock
        // BEFORE blocking on the network revoke so we never hold the FS mutex
        // across a (potentially 15s) round-trip. For a File this is the file's
        // file_meta_ipns_name; for a Folder it is the folder's own ipns_name.
        // Folder deletes only reach cleanup when empty, so the folder's own
        // ipns_name is complete coverage (no descendants to revoke).
        let (ipns_name, api, rt) = {
            let fs = ctx.inner.lock().unwrap();
            let ipns_name = match fs.inodes.get(context.ino) {
                Some(inode) => match &inode.kind {
                    InodeKind::File {
                        file_meta_ipns_name,
                        ..
                    } => file_meta_ipns_name.clone().unwrap_or_default(),
                    InodeKind::Folder { ipns_name, .. } => ipns_name.clone(),
                    // Root is never deleted; nothing to revoke.
                    _ => String::new(),
                },
                None => {
                    // Inode already gone — nothing to revoke; let the delete
                    // proceed (the cleanup path will no-op).
                    String::new()
                }
            };
            (ipns_name, fs.api.clone(), fs.rt.clone())
        };

        if crate::metadata::revoke_shares_blocking(&api, &rt, &ipns_name).is_err() {
            log::error!(
                "set_delete: share revocation failed for ino {} (rejecting delete)",
                context.ino
            );
            return Err(status_access_denied());
        }

        Ok(())
    }
}
