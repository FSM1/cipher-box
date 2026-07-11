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
        filetime_to_systemtime, fill_file_info, is_windows_special, publish_file_node,
        resolve_path, split_path, status_access_denied, status_directory_not_empty,
        status_file_is_a_directory, status_invalid_handle, status_invalid_parameter,
        status_io_device_error, status_not_a_directory, status_object_name_collision,
        status_object_name_not_found, WinFspContext,
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
            // Create directory. node/v3 (69-14, mirrors write_ops/implementation/
            // mkdir.rs): mint the child folder's OWN symmetric read/write keys +
            // Ed25519 IPNS signing seed. The former user-ECIES `folder_key` wrap
            // is gone — node-to-node keys are only sealed under the parent keys
            // (via build_mkdir_journal_entry's D-07 dual splice).
            let result = (|| -> Result<(FileAttrs, u64), String> {
                let read_key = cipherbox_crypto::utils::generate_file_key();
                let write_key = cipherbox_crypto::utils::generate_file_key();
                let (ipns_public_key, ipns_private_key) =
                    cipherbox_crypto::ed25519::generate_ed25519_keypair();
                let ipns_pub_arr: [u8; 32] = ipns_public_key
                    .clone()
                    .try_into()
                    .map_err(|_| "Invalid IPNS public key length".to_string())?;
                let ipns_name = cipherbox_core::ipns::derive_ipns_name(&ipns_pub_arr)
                    .map_err(|e| format!("Failed to derive IPNS name: {}", e))?;

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
                    // Fresh folder: its stable id is uuid_from_ino(ino); the child
                    // folder node is first published (mkdir journal) under this
                    // same id.
                    node_id: crate::fs::uuid_from_ino(ino),
                    parent_ino,
                    name: name.to_string(),
                    kind: InodeKind::Folder {
                        ipns_name: ipns_name.clone(),
                        read_key: zeroize::Zeroizing::new(read_key),
                        write_key: zeroize::Zeroizing::new(write_key),
                        ipns_private_key: zeroize::Zeroizing::new(ipns_private_key.to_vec()),
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
                // The helper handles: sealing the fresh child folder PublishedNode,
                // TEE-wrap of the child IPNS key, the D-07 dual parent splice (via
                // build_folder_metadata), and JournalOp::MkdirPublish construction.
                // Roll back the in-memory inode insert + parent children/mtime update if the
                // journal entry can't be built or fsynced. Otherwise a failed mkdir returns an
                // error to WinFsp but leaves a ghost directory in the inode table with no
                // durable replay record. InodeTable::remove cleans the inode, name index, and
                // parent's children entry.
                let mkdir_result = match fs.build_mkdir_journal_entry(
                    parent_ino,
                    ino,
                    name,
                    &read_key,
                    &write_key,
                    &ipns_name,
                    ipns_private_key.clone(),
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
                    child_published_node,
                    child_ipns_private_key: ipns_private_key_zeroized,
                    encrypted_ipns_for_tee,
                    tee_key_epoch,
                    child_ipns_name: ipns_name_clone,
                    parent_published_node,
                    parent_ipns_private_key,
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
                        let initial_cid = cipherbox_api_client::ipfs::upload_content(&api, &child_published_node).await.map_err(|e| e.to_string())?;
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
                        let seq = coordinator.resolve_sequence(&api, &parent_ipns_name).await?;
                        // node/v3: upload the re-sealed parent PublishedNode bytes
                        // verbatim (the new child is already spliced into BOTH
                        // planes by build_mkdir_journal_entry / build_folder_metadata).
                        let parent_meta_cid = cipherbox_api_client::ipfs::upload_content(&api, &parent_published_node).await.map_err(|e| e.to_string())?;
                        // SC2 item 4: MkdirJournalResult.parent_ipns_private_key is now
                        // a locally-owned Zeroizing seed; narrow into Zeroizing<[u8;32]>
                        // (scrubbed on drop) with no transient plaintext Vec.
                        let parent_key_arr: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
                            <[u8; 32]>::try_from(parent_ipns_private_key.as_slice())
                                .map_err(|_| "Invalid parent IPNS key length".to_string())?,
                        );
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

            // node/v3 (69-14, mirrors write_ops/implementation/file_data.rs
            // handle_create): mint the file node's OWN symmetric read/write
            // keys. The file's content key is minted per-write in
            // build_upload_journal_entry; these keys seal the file NODE
            // (read-body/write-body). The former user-ECIES wrap of the IPNS
            // key is gone — the raw signing seed lives in the inode (zeroized
            // on drop) and is TEE-wrapped only at publish time (rule #7).
            let read_key = cipherbox_crypto::utils::generate_file_key();
            let write_key = cipherbox_crypto::utils::generate_file_key();

            let inode = InodeData {
                ino,
                node_id: crate::fs::uuid_from_ino(ino),
                parent_ino,
                name: name.to_string(),
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

        // 70.1-13a: consume the coalescing hand-off from handle_set_delete. When
        // set (a shallow covered scope-exit), the rotation already republished
        // the grant-root with the post-delete child list, so the plain relink
        // below MUST be suppressed to avoid a redundant second publish (the
        // fuser path suppresses its relink inline in the same call). Always
        // removed so no stale entry leaks.
        let relink_suppressed = fs.coalesced_scope_exit_relink_suppressed.remove(&ino);

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
            // node/v3 keys, mirroring the FUSE handle_unlink/handle_rmdir path
            // (delete.rs:180/:419): SealedChildRef.ipns_name (READ plane, a k51)
            // and WriteChildRef.child_id = the inode's STORED node_id (WRITE
            // plane, a UUID) — never conflated. Tuple: (name, size, item_type,
            // content_cid, child_ref, write_child_ref, child_published_node).
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
                    // SECURITY-REVIEW: D-07 dual-keying — childId(UUID) vs ipnsName
                    // must not be conflated. childId is the inode's STORED node_id
                    // (its real published.id), NOT uuid_from_ino(ino): a
                    // materialized-then-deleted node keeps its creator's id, so the
                    // bin entry's WriteChildRef pairs correctly on restore. A
                    // never-materialized node has node_id == uuid_from_ino(ino)
                    // (seeded at creation), so the fresh-node case is unchanged.
                    let child_id = inode.node_id.clone();
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
                                // SECURITY-REVIEW: D-07 dual-keying — childId(UUID,
                                // the stored node_id) vs ipnsName must not be
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
                                // SECURITY-REVIEW: D-07 dual-keying — childId(UUID,
                                // the stored node_id) vs ipnsName must not be
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

            // 70.1-13a: suppress the plain relink when the covered scope-exit
            // rotation already republished the grant-root with the post-delete
            // child list (shallow scope-exit). Deep/private/non-covered deletes
            // still relink (now resealed under the Fix-A-refreshed key).
            if !relink_suppressed {
                if let Err(e) = fs.update_folder_metadata(parent_ino) {
                    log::error!("Failed to update folder metadata after delete: {}", e);
                }
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

                        // CR-04: journal durably committed — now apply the in-memory
                        // write. node/v3 (69-14, mirrors read_ops.rs handle_release):
                        // the file inode already owns its node identity (ipns_name +
                        // read/write keys + signing seed) from handle_create /
                        // populate_folder. Update ONLY the content descriptors in
                        // place, clearing the CID (filled by the live publish's
                        // UploadComplete), and PRESERVE the moved-in keys (D-09).
                        if let Some(inode) = fs.inodes.get_mut(ino) {
                            if let InodeKind::File {
                                cid,
                                iv,
                                size,
                                encryption_mode,
                                ..
                            } = &mut inode.kind
                            {
                                cid.clear();
                                *iv = result.iv_hex.clone();
                                *size = result.file_size;
                                *encryption_mode = result.encryption_mode.clone();
                            }
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

                        // node/v3 (69-14, mirrors read_ops.rs handle_release): the
                        // file node's canonical id (D-07), matching the parent's
                        // WriteChildRef.child_id + the read-body AAD. Sourced from
                        // the inode's STORED node_id (its real published.id) — NOT
                        // uuid_from_ino(ino): a file materialized from a remote
                        // listing then written via the mount keeps the id its
                        // creator published under.
                        let child_id = fs
                            .inodes
                            .get(ino)
                            .map(|i| i.node_id.clone())
                            .unwrap_or_else(|| crate::fs::uuid_from_ino(ino));

                        let crate::journal_helpers::UploadJournalResult {
                            ciphertext,
                            file_read_key,
                            file_write_key,
                            file_ipns_private_key,
                            file_ipns_name,
                            file_key,
                            iv_hex,
                            mime_type,
                            encryption_mode,
                            encrypted_ipns_for_tee,
                            tee_key_epoch,
                            file_size,
                            old_file_cid,
                            pruned_cids,
                            parent_ino,
                            is_first_publish,
                            ..
                        } = result;

                        let api = fs.api.clone();
                        let rt = fs.rt.clone();
                        let upload_tx = fs.upload_tx.clone();
                        let coordinator = fs.publish_coordinator.clone();
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
                                // the journal entry — the parent folder pointer is published
                                // by the debounced publisher AFTER this thread exits. Replay
                                // on next mount is the authoritative cleanup path (idempotent
                                // already_present check), matching the fuser path in
                                // read_ops.rs.
                                if !file_ipns_name.is_empty() {
                                    // Live per-file node/v3 publish: re-seal the file
                                    // node with the real content CID and publish its
                                    // per-file IPNS record (first-publish or CAS update).
                                    if let Err(e) = publish_file_node(
                                        &api,
                                        &file_ipns_name,
                                        &child_id,
                                        &file_cid,
                                        &file_key,
                                        &iv_hex,
                                        file_size,
                                        &mime_type,
                                        &encryption_mode,
                                        &file_read_key,
                                        &file_write_key,
                                        &file_ipns_private_key,
                                        &coordinator,
                                        encrypted_ipns_for_tee.as_deref(),
                                        tee_key_epoch,
                                        is_first_publish,
                                    )
                                    .await
                                    {
                                        log::warn!(
                                            "Per-file node publish failed for ino {}: {}",
                                            ino,
                                            e
                                        );
                                    }
                                } else {
                                    log::warn!(
                                        "cleanup: skipping per-file node publish for ino {} (missing file ipns_name)",
                                        ino
                                    );
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

        // D-15d (74-06, mirrors write_ops/implementation/rename.rs): the
        // replace_if_exists==false collision check is UNCONDITIONAL and stays
        // first — it can never be affected by scope-exit gating either way.
        //
        // Normalize a self-referential destination to `None`: for a same-path
        // or case-only rename `find_child` can return `source_ino`. Mirrors the
        // fuser reference (implementation/rename.rs, the `dest_ino ==
        // source_ino` self-replace guard). Without this the destination gate
        // and removal below would delete the source inode before its new name
        // mapping is created, leaving a dangling mapping / lost inode.
        let dest_ino = match fs.inodes.find_child(new_parent_ino, new_name) {
            Some(ino) if ino == source_ino => None,
            destination => destination,
        };
        if dest_ino.is_some() && !replace_if_exists {
            return Err(status_object_name_collision());
        }

        // D-15d: destination-REPLACEMENT POSIX-equivalent validation runs
        // BEFORE any scope-exit gate. A rename that will fail
        // STATUS_DIRECTORY_NOT_EMPTY must never trigger a rotation — validate
        // first, gate second, mutate third.
        if let Some(dest_ino) = dest_ino {
            if let Some(dest_inode) = fs.inodes.get(dest_ino) {
                // D-15d kind-compatibility (POSIX: a rename cannot replace a
                // file with a directory or vice versa). Mirrors the fuser
                // reference (write_ops/implementation/rename.rs ENOTDIR/EISDIR
                // guard) and must run BEFORE the non-empty check and BEFORE the
                // scope-exit gate — a kind-mismatched replace is a doomed
                // rename that must never trigger a rotation. Without this,
                // replace_if_exists could overwrite a file with a directory (or
                // an empty dir with a file), corrupting the namespace.
                let source_is_dir = fs
                    .inodes
                    .get(source_ino)
                    .map(|i| matches!(i.kind, InodeKind::Root { .. } | InodeKind::Folder { .. }))
                    .unwrap_or(false);
                let dest_is_dir = matches!(
                    dest_inode.kind,
                    InodeKind::Root { .. } | InodeKind::Folder { .. }
                );
                if source_is_dir && !dest_is_dir {
                    return Err(status_not_a_directory());
                }
                if !source_is_dir && dest_is_dir {
                    return Err(status_file_is_a_directory());
                }
                if let InodeKind::Folder { .. } = &dest_inode.kind {
                    if let Some(ref children) = dest_inode.children {
                        if !children.is_empty() {
                            return Err(status_directory_not_empty());
                        }
                    }
                }
            }
        }

        // SC#3 grant-scope gate (69-14, mirrors write_ops/implementation/rename.rs)
        // for a cross-folder move (a scope-exit for the source subtree). A
        // same-folder rename is NOT a scope exit — the node stays in place, so
        // no rotation. Computed on the SOURCE ancestry AFTER the
        // destination-replacement POSIX validation above (D-15d) but BEFORE
        // any inode mutation, so a fail-closed rotation aborts the move
        // cleanly (item stays put). Private move -> pure SealedChildRef relink
        // of both parents (ZERO rotation, D-08 unlink+bin-equivalent with no
        // cross-principal revoke); shared-scope exit -> rotate the read key
        // from the matched grant-root ancestor EXACTLY ONCE. D-07 dual-keying
        // is threaded inside the driver.
        //
        // SC#2: a cross-folder move is now a PURE SealedChildRef relink — each
        // node self-seals under its OWN readKey, so there is no per-file
        // metadata to re-encrypt on move (the legacy re-encrypt-on-move path is
        // dead by construction and deleted). The read-scope cut for a shared
        // move is handled by the grant-scope gates below (rotation), not by
        // re-keying the moved file.
        if old_parent_ino != new_parent_ino
            && crate::write_ops::grant_scope::run_scope_exit_gate(&mut fs, source_ino).is_err()
        {
            return Err(status_io_device_error());
        }

        // D-15d: gate the OVERWRITTEN destination's OWN scope-exit too.
        // Replacing a destination removes dest_ino outright — that is itself a
        // scope-exit for dest_ino's subtree whenever dest_ino is (or roots) a
        // shared node, regardless of whether the move is same-folder or
        // cross-folder. Runs AFTER the POSIX validation above (a doomed
        // rename never reaches here) and independently of the source gate
        // (two independent scope-exits). Uses the PLAIN (non-coalesced) gate
        // — matches the fuser rename.rs reference, which does not coalesce
        // either gate for rename.
        if let Some(dest_ino) = dest_ino {
            if crate::write_ops::grant_scope::run_scope_exit_gate(&mut fs, dest_ino).is_err() {
                return Err(status_access_denied());
            }
        }

        // Destination replacement mutation (validated + gated above): unpin
        // the replaced file's content (fire-and-forget) and remove its inode.
        if let Some(dest_ino) = dest_ino {
            if let Some(dest_inode) = fs.inodes.get(dest_ino) {
                if let InodeKind::File { cid, .. } = &dest_inode.kind {
                    if !cid.is_empty() {
                        let cid_clone = cid.clone();
                        let api = fs.api.clone();
                        fs.rt.spawn(async move {
                            let _ =
                                cipherbox_api_client::ipfs::unpin_content(&api, &cid_clone).await;
                        });
                    }
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

        // SC#2: no per-file metadata re-encrypt on move — each node self-seals
        // under its OWN readKey (the legacy re-encrypt-on-move helper is dead
        // by construction and deleted). See the grant-scope gate above.

        Ok(())
    }

    /// set_delete handler.
    ///
    /// This is the Windows fail-closed grant-scope gate point (SC#3, 69-14).
    /// WinFsp calls `set_delete` BEFORE the actual delete-on-close runs in
    /// `handle_cleanup` (which returns `()` and cannot abort), and unlike
    /// cleanup this callback returns `Result<(), FspError>`, so returning `Err`
    /// rejects the delete. We mirror the Unix `handle_unlink`/`handle_rmdir`
    /// contract: CONSUME the shared `crate::write_ops::grant_scope` module (69-07)
    /// BEFORE the node is destroyed — a private delete (no covering grant) is a
    /// pure relink with ZERO rotation; a shared-scope exit rotates the read key
    /// from the matched grant-root ancestor EXACTLY ONCE via
    /// `rotate_read_on_scope_exit` (69-08). On rotation failure the delete is
    /// rejected (`STATUS_ACCESS_DENIED`) so the item stays put and no sharee is
    /// left with access to soon-to-be-orphaned content (fail-closed).
    ///
    /// When `delete_file` is `false` WinFsp is clearing a previously-set delete
    /// flag (an un-delete); there is nothing to gate, so we accept it.
    ///
    /// Known gap (accepted): `set_delete(true)` followed by `set_delete(false)`
    /// (an application setting then cancelling `DELETE_ON_CLOSE`) runs the
    /// scope-exit gate (and any resulting rotation) eagerly on the `true` call
    /// and does not undo it on the cancel — the node survives but a shared-scope
    /// rotation already happened. We accept this because `set_delete` is the
    /// only WinFsp callback that can *reject* a delete; deferring to
    /// `handle_cleanup` (the real deletion point) is impossible since cleanup
    /// returns `()` and cannot abort. The cancelled-delete window is rare, and
    /// this trade favours TRUE fail-closed revocation (never leaving a removed
    /// reader with continued access) over avoiding an occasional spurious
    /// rotation on a cancelled delete.
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

        // SC#3 grant-scope gate (69-14, mirrors write_ops/implementation/delete.rs
        // handle_unlink/handle_rmdir): the unconditional `revoke_shares_blocking`
        // is REPLACED, not augmented. A private delete (no covering grant) is a
        // pure relink with ZERO rotation — the parent metadata republish (in
        // handle_cleanup) is the only durable effect. A shared-scope exit
        // rotates the read key from the matched grant-root ancestor EXACTLY
        // ONCE. Fail-closed: rotation failure rejects the delete
        // (STATUS_ACCESS_DENIED) so the item stays put and no sharee is left
        // with access to soon-to-be-orphaned content.
        let mut fs = ctx.inner.lock().unwrap();
        // 70.1-13a: the deleted node's DIRECT parent (child still present here).
        // A missing inode makes the ancestor walk inside the gate fail closed.
        let parent_ino = fs
            .inodes
            .get(context.ino)
            .map(|i| i.parent_ino)
            .unwrap_or(0);
        // Shared coalesced gate (identical logic to the fuser delete.rs path).
        // On a shallow covered scope-exit the rotation republishes the
        // grant-root with the post-delete child list as the SINGLE authoritative
        // publish; record the ino so handle_cleanup SKIPS its plain relink
        // (the WinFsp split's equivalent of the fuser path's local
        // `relink_suppressed`). Fail-closed → STATUS_ACCESS_DENIED.
        match crate::write_ops::grant_scope::run_scope_exit_gate_coalesced(
            &mut fs,
            context.ino,
            parent_ino,
        ) {
            Ok(true) => {
                fs.coalesced_scope_exit_relink_suppressed
                    .insert(context.ino);
            }
            Ok(false) => {
                // Private / deep / non-covered: clear any stale flag so cleanup
                // performs its normal relink.
                fs.coalesced_scope_exit_relink_suppressed
                    .remove(&context.ino);
            }
            Err(()) => {
                log::error!(
                    "set_delete: grant-scope gate failed for ino {} (rejecting delete)",
                    context.ino
                );
                return Err(status_access_denied());
            }
        }

        Ok(())
    }

    /// D-15d dest-gate tests (74-06), mirroring the fuser twins at
    /// `crates/fuse/src/write_ops/implementation/rename.rs`. This module only
    /// compiles under `feature = "winfsp"`, which does not build on
    /// macOS/Linux (no WinFsp SDK) — these tests are authored test-first and
    /// verified by the `Cargo Check & Test (Windows)` CI job, not locally.
    #[cfg(all(test, feature = "winfsp"))]
    mod tests {
        use super::*;
        use crate::inode::ROOT_INO;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, UNIX_EPOCH};
        use widestring::U16CString;
        use zeroize::Zeroizing;

        /// Real secp256k1 keypair — mirrors the fuser `rename.rs` test
        /// harness (`real_keypair`) so `wrap_key`'s ECIES calls succeed.
        fn real_keypair() -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
            let (sk, pk) = ecies::utils::generate_keypair();
            (
                Zeroizing::new(sk.serialize().to_vec()),
                Zeroizing::new(pk.serialize().to_vec()),
            )
        }

        /// Build a `WinFspContext` wrapping a fully-populated `CipherBoxFS`
        /// (via the shared, feature-agnostic `crate::test_support` harness)
        /// inside a live tokio runtime, so `run_scope_exit_gate`'s
        /// `rt.block_on` is valid when invoked from the TEST thread — mirrors
        /// the fuser `rename.rs` `fs_on_runtime` helper. The harness's
        /// `ApiClient` points at an unroutable host (127.0.0.1:1), so any
        /// GATED rotation attempt surfaces an error — the tests below use
        /// that as a positive proof the gate fired, not a live rotation
        /// success (matches the fuser twin's own documented proof strategy).
        fn ctx_on_runtime() -> (tokio::runtime::Runtime, WinFspContext) {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            let _guard = rt.enter();
            let (private_key, public_key) = real_keypair();
            let fs = crate::test_support::make_test_fs_with_keypair(private_key, public_key);
            let ctx = WinFspContext {
                inner: Arc::new(Mutex::new(fs)),
                rt: rt.handle().clone(),
            };
            (rt, ctx)
        }

        /// Seed the local sent-shares cache with a single AUTHORITATIVE grant
        /// rooted at `root_ipns_name` so a mutation whose ancestry contains
        /// that name is a SHARED-scope exit (covering grant present).
        fn seed_sent_share(ctx: &WinFspContext, root_ipns_name: &str) {
            use cipherbox_api_client::shares::SentShareResponse;
            let share = SentShareResponse {
                share_id: "s1".to_string(),
                recipient_public_key: "0x04".to_string(),
                encrypted_read_key: "ref".to_string(),
                encrypted_write_key: None,
                root_node_id: "n1".to_string(),
                share_root_ipns_name: root_ipns_name.to_string(),
                root_generation: "1".to_string(),
                item_name_encrypted: None,
                created_at: "2024-01-01T00:00:00Z".to_string(),
            };
            let fs = ctx.inner.lock().unwrap();
            *fs.sent_shares.write().expect("sent_shares lock poisoned") =
                crate::write_ops::grant_scope::SentSharesCache::from_sent_shares(&[share]);
        }

        /// Insert an EMPTY Folder child of `parent`.
        fn insert_empty_folder(
            ctx: &WinFspContext,
            parent: u64,
            name: &str,
            ipns_name: &str,
        ) -> u64 {
            let mut fs = ctx.inner.lock().unwrap();
            let ino = fs.inodes.allocate_ino();
            let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
            fs.inodes.insert(InodeData {
                ino,
                node_id: crate::fs::uuid_from_ino(ino),
                parent_ino: parent,
                name: name.to_string(),
                kind: InodeKind::Folder {
                    ipns_name: ipns_name.to_string(),
                    read_key: Zeroizing::new([1u8; 32]),
                    write_key: Zeroizing::new([6u8; 32]),
                    ipns_private_key: Zeroizing::new(vec![5u8; 32]),
                    children_loaded: true,
                },
                attr: FileAttrs {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: t,
                    mtime: t,
                    ctime: t,
                    crtime: t,
                    is_dir: true,
                    perm: 0o755,
                    nlink: 2,
                },
                children: Some(Vec::new()),
                write_generation: 0,
            });
            if let Some(p) = fs.inodes.get_mut(parent) {
                p.children.get_or_insert_with(Vec::new).push(ino);
            }
            ino
        }

        /// Insert a NON-empty Folder child (carries one dangling child ino so
        /// the STATUS_DIRECTORY_NOT_EMPTY-on-replace check fires; the
        /// dangling ino is never dereferenced by that check).
        fn insert_non_empty_folder(
            ctx: &WinFspContext,
            parent: u64,
            name: &str,
            ipns_name: &str,
        ) -> u64 {
            let ino = insert_empty_folder(ctx, parent, name, ipns_name);
            let mut fs = ctx.inner.lock().unwrap();
            if let Some(f) = fs.inodes.get_mut(ino) {
                f.children = Some(vec![999_999]);
            }
            ino
        }

        /// Insert a File child of `parent`.
        fn insert_file(ctx: &WinFspContext, parent: u64, name: &str, ipns_name: &str) -> u64 {
            let mut fs = ctx.inner.lock().unwrap();
            let ino = fs.inodes.allocate_ino();
            let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
            fs.inodes.insert(InodeData {
                ino,
                node_id: crate::fs::uuid_from_ino(ino),
                parent_ino: parent,
                name: name.to_string(),
                kind: InodeKind::File {
                    ipns_name: ipns_name.to_string(),
                    cid: String::new(),
                    size: 0,
                    encryption_mode: "GCM".to_string(),
                    iv: String::new(),
                    read_key: Zeroizing::new([2u8; 32]),
                    write_key: Zeroizing::new([4u8; 32]),
                    ipns_private_key: Zeroizing::new(vec![3u8; 32]),
                },
                attr: FileAttrs {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: t,
                    mtime: t,
                    ctime: t,
                    crtime: t,
                    is_dir: false,
                    perm: 0o644,
                    nlink: 1,
                },
                children: None,
                write_generation: 0,
            });
            if let Some(p) = fs.inodes.get_mut(parent) {
                p.children.get_or_insert_with(Vec::new).push(ino);
            }
            ino
        }

        /// Build a WinFsp-style absolute path (`\seg1\seg2`) from segments.
        fn winfsp_path(segments: &[&str]) -> U16CString {
            let joined = format!("\\{}", segments.join("\\"));
            U16CString::from_str(&joined).expect("test path must not contain NUL")
        }

        /// Assert `result` is `Err(FspError::NTSTATUS(expected))`, panicking
        /// with `msg` (and the actual result) otherwise. `FspError` has no
        /// `PartialEq` (upstream `winfsp` crate, `#[non_exhaustive]`), so this
        /// matches the wrapped NTSTATUS value directly instead.
        fn assert_ntstatus(result: &Result<(), FspError>, expected: i32, msg: &str) {
            match result {
                Err(FspError::NTSTATUS(code)) if *code == expected => {}
                other => panic!("{msg}; got {other:?}"),
            }
        }

        /// D-15d: a cross-folder rename whose SOURCE has an active covering
        /// grant (would trigger a rotation attempt if the gate ran) but whose
        /// destination replacement is POSIX-invalid (a non-empty folder,
        /// STATUS_DIRECTORY_NOT_EMPTY) must reject with
        /// STATUS_DIRECTORY_NOT_EMPTY WITHOUT ever invoking the scope-exit
        /// gate. Pre-fix, the gate ran BEFORE this validation, so a covered
        /// source surfaced STATUS_IO_DEVICE_ERROR (the rotation attempt
        /// failing against the harness's unroutable API) instead of the
        /// correct STATUS_DIRECTORY_NOT_EMPTY — a doomed rename must never
        /// attempt a rotation.
        #[test]
        fn rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt() {
            let (_rt, ctx) = ctx_on_runtime();

            // Source folder under the vault root, which IS a grant root: a
            // cross-folder move of this source is a covered scope-exit if
            // the gate is ever reached.
            let source = insert_empty_folder(&ctx, ROOT_INO, "shared-src", "k51shared-src");
            seed_sent_share(&ctx, "k51test-root");

            // A second folder to move INTO, containing a non-empty
            // destination folder occupying the target name
            // (STATUS_DIRECTORY_NOT_EMPTY on replace).
            let other_parent = insert_empty_folder(&ctx, ROOT_INO, "other", "k51other");
            insert_non_empty_folder(&ctx, other_parent, "dest", "k51dest");

            let old_path = winfsp_path(&["shared-src"]);
            let new_path = winfsp_path(&["other", "dest"]);
            let result = handle_rename(&ctx, old_path.as_ucstr(), new_path.as_ucstr(), true);

            assert_ntstatus(
                &result,
                0xC0000101_u32 as i32, // STATUS_DIRECTORY_NOT_EMPTY
                "POSIX destination validation must run BEFORE the scope-exit gate (D-15d) — a \
                 covered source must never attempt rotation on a doomed rename",
            );

            let fs = ctx.inner.lock().unwrap();
            assert!(
                fs.inodes.get(source).is_some(),
                "the source must remain untouched when the rename is rejected pre-gate"
            );
        }

        /// D-15d: renaming a private (uncovered) source OVER an existing
        /// destination that IS itself covered by a grant must gate the
        /// destination's OWN scope-exit before removing it — an ungated
        /// removal would be a silent revocation bypass. The harness's API
        /// points at an unroutable host, so a GATED (attempted) rotation
        /// surfaces STATUS_ACCESS_DENIED, proving the gate fired for
        /// `dest_ino` rather than silently succeeding.
        #[test]
        fn rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit() {
            let (_rt, ctx) = ctx_on_runtime();

            // Source: a private file with no covering grant.
            let source_parent = insert_empty_folder(&ctx, ROOT_INO, "srcdir", "k51srcdir");
            let source = insert_file(&ctx, source_parent, "a.txt", "k51a");

            // Destination: an existing file under a DIFFERENT folder that IS
            // a grant root — replacing it is itself a covered scope-exit.
            let dest_parent = insert_empty_folder(&ctx, ROOT_INO, "destdir", "k51destdir-shared");
            let dest = insert_file(&ctx, dest_parent, "b.txt", "k51b");
            seed_sent_share(&ctx, "k51destdir-shared");

            let old_path = winfsp_path(&["srcdir", "a.txt"]);
            let new_path = winfsp_path(&["destdir", "b.txt"]);
            let result = handle_rename(&ctx, old_path.as_ucstr(), new_path.as_ucstr(), true);

            assert_ntstatus(
                &result,
                0xC0000022_u32 as i32, // STATUS_ACCESS_DENIED
                "overwriting a covered destination must gate dest_ino's own scope-exit (D-15d) \
                 — the attempted rotation fails closed (STATUS_ACCESS_DENIED) against the \
                 unroutable test API, proving the gate fired rather than silently dropping \
                 dest_ino ungated",
            );

            let fs = ctx.inner.lock().unwrap();
            assert!(
                fs.inodes.get(dest).is_some(),
                "the covered destination must remain when its scope-exit rotation cannot complete"
            );
            assert!(
                fs.inodes.get(source).is_some(),
                "the source must remain untouched when the rename aborts on the dest gate"
            );
        }

        /// D-07 dual-keying parity with the shipped Unix fix (delete.rs
        /// `bin_dual_refs_are_restore_sufficient_and_d07_distinct`, commit
        /// c4d30e598). Ported for the Windows `cleanup()` bin-capture path,
        /// which now keys `WriteChildRef.child_id` by the inode's STORED
        /// `node_id` (`inode.node_id.clone()`), NOT `uuid_from_ino(ino)`.
        ///
        /// This asserts the MATERIALIZED-then-removed case: a node whose
        /// persisted `node_id` was assigned by its remote creator differs from
        /// `uuid_from_ino(local_ino)`. The bin entry must key by that stored
        /// node_id so it pairs correctly on restore. Pure `build_child_refs`
        /// round-trip (no live restore command exists) — the reachable proof.
        #[test]
        fn bin_child_id_keys_by_stored_node_id_not_local_ino_d07() {
            use base64::Engine as _;
            use cipherbox_core::node::{
                decode_node, decode_write_body,
                seal::{seal_published_node, unseal_node},
                Node, NodeKind, NodeWriteBody,
            };

            let parent_read_key = [7u8; 32];
            let parent_write_key = [9u8; 32];
            let child_read_key = [2u8; 32];
            let child_write_key = [4u8; 32];
            let child_ipns_name = "k51childfolder";

            // A MATERIALIZED node: its creator-assigned node_id is unrelated to
            // this session's local inode number. `cleanup()` sources child_id
            // from inode.node_id — mirror that here, NOT uuid_from_ino(local_ino).
            let local_ino = 42u64;
            let materialized_node_id = "remote-creator-node-uuid".to_string();
            assert_ne!(
                materialized_node_id,
                crate::fs::uuid_from_ino(local_ino),
                "precondition: a materialized node_id must differ from uuid_from_ino(local_ino)"
            );
            let child_id = materialized_node_id.clone();

            let (child_ref, write_child_ref) = cipherbox_sdk::build_child_refs(
                &child_read_key,
                &child_write_key,
                &parent_read_key,
                &parent_write_key,
                &child_id,
                child_ipns_name,
                "restore-me",
                NodeKind::Folder,
                0,
                0,
            )
            .expect("build_child_refs must succeed");

            // D-07: the two key spaces are structurally distinct, and the write
            // plane is keyed by the STORED node_id (not uuid_from_ino).
            assert_ne!(
                write_child_ref.child_id, child_ref.ipns_name,
                "D-07: WriteChildRef.child_id (UUID) must never equal SealedChildRef.ipns_name (k51)"
            );
            assert_eq!(
                write_child_ref.child_id, materialized_node_id,
                "write plane must be keyed by the inode's STORED node_id"
            );
            assert_ne!(
                write_child_ref.child_id,
                crate::fs::uuid_from_ino(local_ino),
                "regression: child_id must NOT fall back to uuid_from_ino(local_ino) for a materialized node"
            );
            assert_eq!(
                child_ref.ipns_name, child_ipns_name,
                "read plane keyed by ipnsName"
            );

            // Re-splice BOTH captured refs into a FRESH target parent node and
            // assert restore-sufficiency across both planes.
            let parent_id = crate::fs::uuid_from_ino(1);
            let parent_node = Node::Folder {
                id: parent_id.clone(),
                generation: 0,
                created_at: 0,
                modified_at: 0,
                children: vec![child_ref.clone()],
            };
            let write_body = NodeWriteBody {
                ipns_private_key: vec![0u8; 32],
                write_children: vec![write_child_ref.clone()],
            };
            let published = seal_published_node(
                &parent_node,
                &parent_read_key,
                &parent_write_key,
                Some(&write_body),
            )
            .expect("seal_published_node must succeed");

            // Read plane: unseal the parent read-body → child ipns_name present.
            let read_sealed = base64::engine::general_purpose::STANDARD
                .decode(&published.read_sealed)
                .expect("valid base64");
            let read_body =
                unseal_node(&read_sealed, &parent_read_key, &parent_id, NodeKind::Folder, 0)
                    .expect("unseal parent read-body");
            let recovered = decode_node(&read_body).expect("decode parent node");
            match recovered {
                Node::Folder { children, .. } => {
                    assert!(
                        children.iter().any(|c| c.ipns_name == child_ipns_name),
                        "the re-spliced child must be recovered in the parent read plane"
                    );
                }
                other => panic!("expected a recovered Folder node, got {:?}", other.kind()),
            }

            // Write plane: unseal the parent write-body → child keyed by node_id.
            let write_sealed_b64 = published.write_sealed.expect("write_sealed present");
            let write_sealed = base64::engine::general_purpose::STANDARD
                .decode(write_sealed_b64)
                .expect("valid base64");
            let wb_bytes =
                unseal_node(&write_sealed, &parent_write_key, &parent_id, NodeKind::Folder, 0)
                    .expect("unseal parent write-body");
            let recovered_wb = decode_write_body(&wb_bytes).expect("decode write body");
            assert!(
                recovered_wb
                    .write_children
                    .iter()
                    .any(|w| w.child_id == materialized_node_id),
                "the re-spliced child must be recovered in the parent write plane keyed by the stored node_id"
            );
        }
    }
}
