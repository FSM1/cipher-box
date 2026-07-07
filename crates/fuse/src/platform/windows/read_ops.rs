//! Read operations for Windows WinFsp filesystem.
//!
//! Contains handler logic for: get_volume_info, get_security_by_name, open,
//! close, read, get_file_info, get_security, flush.

#[cfg(feature = "winfsp")]
pub mod implementation {
    use std::ffi::c_void;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use winfsp::filesystem::{FileInfo, FileSecurity, OpenFileInfo};
    use widestring::U16CStr;
    use winfsp::FspError;

    use crate::file_handle::OpenFileHandle;
    use crate::inode::InodeKind;
    use super::super::operations::implementation::{
        WinFspContext, WinFspFileContext,
        status_object_name_not_found, status_invalid_parameter,
        status_invalid_handle, status_io_device_error,
        status_device_not_ready,
        resolve_path, fill_file_info, PERMISSIVE_SD,
        fetch_and_decrypt_file_content,
        is_windows_special,
    };
    use crate::constants::QUOTA_BYTES;
    use super::super::content_fetch::spawn_content_prefetch;

    /// get_volume_info handler
    pub fn handle_get_volume_info(
        ctx: &WinFspContext,
        volume_info: &mut winfsp::filesystem::VolumeInfo,
    ) -> Result<(), FspError> {
        let fs = ctx.inner.lock().unwrap();
        let used_bytes: u64 = fs
            .inodes
            .inodes
            .values()
            .filter_map(|inode| match &inode.kind {
                InodeKind::File { size, .. } => Some(*size),
                _ => None,
            })
            .sum();

        volume_info.total_size = QUOTA_BYTES;
        volume_info.free_size = QUOTA_BYTES.saturating_sub(used_bytes);
        Ok(())
    }

    /// get_security_by_name handler
    pub fn handle_get_security_by_name(
        ctx: &WinFspContext,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
    ) -> Result<FileSecurity, FspError> {
        let path = file_name.to_string_lossy();
        let fs = ctx.inner.lock().unwrap();

        let name_only = path.rsplit('\\').next().unwrap_or(&path);
        if is_windows_special(name_only) {
            return Err(status_object_name_not_found());
        }

        let (ino, _parent_ino) = resolve_path(&fs, &path)
            .ok_or(status_object_name_not_found())?;

        let inode = fs
            .inodes
            .get(ino)
            .ok_or(status_object_name_not_found())?;

        let info = fill_file_info(&inode.attr);

        if let Some(buf) = security_descriptor {
            if buf.len() >= PERMISSIVE_SD.len() {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        PERMISSIVE_SD.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        PERMISSIVE_SD.len(),
                    );
                }
            }
        }

        Ok(FileSecurity {
            attributes: info.file_attributes,
            reparse: false,
            sz_security_descriptor: PERMISSIVE_SD.len() as u64,
        })
    }

    /// open handler
    pub fn handle_open(
        ctx: &WinFspContext,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> Result<WinFspFileContext, FspError> {
        let path = file_name.to_string_lossy();
        log::info!(
            "open() path={} create_options=0x{:08X} granted_access=0x{:08X}",
            path, create_options, granted_access
        );
        let mut fs = ctx.inner.lock().unwrap();

        fs.drain_upload_completions();
        fs.drain_content_prefetches();
        fs.drain_refresh_completions();
        fs.drain_filepointer_completions();

        let (ino, parent_ino) = resolve_path(&fs, &path)
            .ok_or(status_object_name_not_found())?;

        // Check if parent folder metadata is stale and fire background refresh.
        // This mirrors read_directory's staleness check so that file opens also
        // trigger metadata refresh, not only directory listings.
        // node/v3 (69-14, mirrors 69-09 Slice 5b(d)): refresh needs the folder's
        // symmetric read_key + write_key for list_folder_owned (not a legacy
        // folder_key), and InodeKind::Root/Folder's `ipns_name` is a plain
        // `String` (empty == unset), not `Option<String>`.
        type RefreshTarget = (String, [u8; 32], [u8; 32]);
        let stale_info: Option<(u64, RefreshTarget)> = {
            if let Some(parent_inode) = fs.inodes.get(parent_ino) {
                match &parent_inode.kind {
                    InodeKind::Root { ipns_name, read_key, write_key, .. } => {
                        let name = if ipns_name.is_empty() {
                            fs.root_ipns_name.clone()
                        } else {
                            ipns_name.clone()
                        };
                        if !name.is_empty() && fs.metadata_cache.get(&name).is_none() {
                            Some((parent_ino, (name, **read_key, **write_key)))
                        } else {
                            None
                        }
                    }
                    InodeKind::Folder { ipns_name, read_key, write_key, .. } => {
                        if fs.metadata_cache.get(ipns_name).is_none() {
                            Some((parent_ino, (ipns_name.clone(), **read_key, **write_key)))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            } else {
                None
            }
        };

        if let Some((refresh_ino, (ipns_name, read_key, write_key))) =
            stale_info.filter(|(_, (n, _, _))| !fs.refreshing_metadata.contains(n))
        {
            fs.refreshing_metadata.insert(ipns_name.clone());
            crate::spawn_metadata_refresh(
                &fs.rt,
                fs.api.clone(),
                fs.refresh_tx.clone(),
                refresh_ino,
                ipns_name,
                read_key,
                write_key,
                fs.high_water.clone(),
            );
        }

        let inode = fs
            .inodes
            .get(ino)
            .ok_or(status_object_name_not_found())?;
        let is_dir = inode.attr.is_dir;

        *file_info.as_mut() = fill_file_info(&inode.attr);

        if is_dir {
            let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
            return Ok(WinFspFileContext { fh, ino, is_dir: true });
        }

        let is_write = (granted_access & 0x0006) != 0;

        if is_write {
            let (cid, ipns_name, read_key) = match &inode.kind {
                InodeKind::File {
                    cid,
                    ipns_name,
                    read_key,
                    ..
                } => (cid.clone(), ipns_name.clone(), **read_key),
                _ => return Err(status_invalid_parameter()),
            };

            let existing_content = if !cid.is_empty() {
                if let Some(cached) = fs.content_cache.get(&cid) {
                    Some(cached.to_vec())
                } else {
                    match fetch_and_decrypt_file_content(&fs, &ipns_name, &read_key) {
                        Ok(content) => Some(content),
                        Err(e) => {
                            log::error!("Failed to fetch content for write-open: {}", e);
                            return Err(status_io_device_error());
                        }
                    }
                }
            } else {
                None
            };

            let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
            match OpenFileHandle::new_write(ino, &fs.temp_dir, existing_content.as_deref()) {
                Ok(handle) => {
                    fs.open_files.insert(fh, handle);
                    Ok(WinFspFileContext { fh, ino, is_dir: false })
                }
                Err(e) => {
                    log::error!("Failed to create write handle: {}", e);
                    Err(status_io_device_error())
                }
            }
        } else {
            let (cid, ipns_name, read_key) = match &inode.kind {
                InodeKind::File {
                    cid,
                    ipns_name,
                    read_key,
                    ..
                } => (cid.clone(), ipns_name.clone(), **read_key),
                _ => return Err(status_invalid_parameter()),
            };

            if !cid.is_empty()
                && fs.content_cache.get(&cid).is_none()
                && !fs.prefetching.contains(&cid)
            {
                spawn_content_prefetch(
                    &mut fs,
                    cid.clone(),
                    ipns_name.clone(),
                    read_key,
                    "Prefetch failed",
                );
            }

            let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
            fs.open_files.insert(fh, OpenFileHandle::new_read(ino));
            Ok(WinFspFileContext { fh, ino, is_dir: false })
        }
    }

    /// close handler
    pub fn handle_close(ctx: &WinFspContext, context: WinFspFileContext) {
        log::info!("close() ino={} fh={}", context.ino, context.fh);
        let mut fs = ctx.inner.lock().unwrap();
        fs.drain_upload_completions();

        if let Some(handle) = fs.open_files.remove(&context.fh) {
            handle.cleanup();
        }
    }

    /// read handler
    pub fn handle_read(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<u32, FspError> {
        let mut fs = ctx.inner.lock().unwrap();
        fs.drain_upload_completions();
        fs.drain_content_prefetches();
        fs.drain_filepointer_completions();

        let fh = context.fh;
        let ino = context.ino;

        let has_temp = fs
            .open_files
            .get(&fh)
            .map(|h| h.temp_path.is_some())
            .unwrap_or(false);

        if has_temp {
            match fs.open_files.get(&fh) {
                Some(handle) => {
                    match handle.read_at(offset as i64, buffer.len() as u32) {
                        Ok(data) => {
                            let len = std::cmp::min(data.len(), buffer.len());
                            buffer[..len].copy_from_slice(&data[..len]);
                            return Ok(len as u32);
                        }
                        Err(e) => {
                            log::error!("Temp file read failed: {}", e);
                            return Err(status_io_device_error());
                        }
                    }
                }
                None => return Err(status_invalid_handle()),
            }
        }

        // node/v3 (69-14, mirrors 69-09 Slice 5b): the content descriptors
        // (encrypted_file_key/iv/encryption_mode) no longer live on the inode —
        // they are recovered lazily by unsealing the file node's own sealed
        // read-body. "Unresolved" == empty `cid`; the file's identity
        // `(ipns_name, read_key)` does not change across resolution, so it is
        // captured once here.
        let (mut cid, ipns_name, read_key) = {
            match fs.inodes.get(ino) {
                Some(inode) => match &inode.kind {
                    InodeKind::File {
                        cid,
                        ipns_name,
                        read_key,
                        ..
                    } => (cid.clone(), ipns_name.clone(), **read_key),
                    _ => return Err(status_invalid_parameter()),
                },
                None => return Err(status_object_name_not_found()),
            }
        };

        // --- FilePointer resolution poll (D-06) ---
        // If cid is empty and resolution is in-flight, wait up to 5s
        if cid.is_empty() && !fs.pending_content.contains_key(&ino) && fs.resolving_file_pointers.contains(&ino) {
            let poll_start = std::time::Instant::now();
            let max_wait = Duration::from_secs(5);
            loop {
                drop(fs);
                std::thread::sleep(Duration::from_millis(100));
                fs = ctx.inner.lock().unwrap();
                fs.drain_filepointer_completions();

                if let Some(inode) = fs.inodes.get(ino) {
                    if let InodeKind::File { cid: ref c, .. } = &inode.kind {
                        if !c.is_empty() {
                            cid = c.clone();
                            break;
                        }
                    }
                }
                // Early exit: resolution finished (failed) but inode still unresolved
                if !fs.resolving_file_pointers.contains(&ino) {
                    break;
                }
                if poll_start.elapsed() > max_wait {
                    log::warn!("FilePointer resolve poll timed out for ino {} after 5s", ino);
                    return Err(status_device_not_ready());
                }
            }
        }

        if cid.is_empty() {
            if let Some(content) = fs.pending_content.get(&ino) {
                let start = offset as usize;
                if start >= content.len() {
                    return Ok(0);
                }
                let end = std::cmp::min(start + buffer.len(), content.len());
                let len = end - start;
                buffer[..len].copy_from_slice(&content[start..end]);
                return Ok(len as u32);
            }
            return Ok(0);
        }

        if let Some(handle) = fs.open_files.get(&fh) {
            if let Some(ref content) = handle.cached_content {
                let start = offset as usize;
                if start >= content.len() {
                    return Ok(0);
                }
                let end = std::cmp::min(start + buffer.len(), content.len());
                let len = end - start;
                buffer[..len].copy_from_slice(&content[start..end]);
                return Ok(len as u32);
            }
        }

        let cached_owned = fs.content_cache.get(&cid).map(|c| c.to_vec());
        if let Some(cached_owned) = cached_owned {
            let start = offset as usize;
            if start >= cached_owned.len() {
                return Ok(0);
            }
            let end = std::cmp::min(start + buffer.len(), cached_owned.len());
            let len = end - start;
            buffer[..len].copy_from_slice(&cached_owned[start..end]);

            if let Some(handle) = fs.open_files.get_mut(&fh) {
                handle.cached_content = Some(cached_owned);
            }
            return Ok(len as u32);
        }

        // Content not cached: start prefetch and poll
        if !fs.prefetching.contains(&cid) {
            spawn_content_prefetch(
                &mut fs,
                cid.clone(),
                ipns_name.clone(),
                read_key,
                "Read prefetch failed",
            );
        }

        // Poll for content (up to 5s)
        let poll_start = std::time::Instant::now();
        let max_wait = Duration::from_secs(5);
        loop {
            drop(fs);
            std::thread::sleep(Duration::from_millis(100));
            fs = ctx.inner.lock().unwrap();
            fs.drain_content_prefetches();

            if let Some(cached) = fs.content_cache.get(&cid) {
                let start = offset as usize;
                if start >= cached.len() {
                    return Ok(0);
                }
                let end = std::cmp::min(start + buffer.len(), cached.len());
                let len = end - start;
                buffer[..len].copy_from_slice(&cached[start..end]);
                return Ok(len as u32);
            }
            if poll_start.elapsed() > max_wait {
                break;
            }
        }

        Err(status_io_device_error())
    }

    /// get_file_info handler
    pub fn handle_get_file_info(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        let fs = ctx.inner.lock().unwrap();
        let inode = fs
            .inodes
            .get(context.ino)
            .ok_or(status_object_name_not_found())?;
        *file_info = fill_file_info(&inode.attr);
        Ok(())
    }

    /// get_security handler
    pub fn handle_get_security(
        security_descriptor: Option<&mut [c_void]>,
    ) -> Result<u64, FspError> {
        if let Some(buf) = security_descriptor {
            if buf.len() >= PERMISSIVE_SD.len() {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        PERMISSIVE_SD.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        PERMISSIVE_SD.len(),
                    );
                }
            }
        }
        Ok(PERMISSIVE_SD.len() as u64)
    }

    /// flush handler
    pub fn handle_flush() -> Result<(), FspError> {
        Ok(())
    }
}
