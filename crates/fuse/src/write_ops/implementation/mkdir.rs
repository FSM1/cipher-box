use fuser::ReplyEntry;
use std::ffi::OsStr;
use std::time::SystemTime;

use crate::helpers::is_platform_special;
use crate::inode::{FileAttrs, InodeData, InodeKind};
use crate::operations::implementation::{current_gid, current_uid, DIR_TTL};
use crate::CipherBoxFS;

/// Create a new directory.
pub fn handle_mkdir(fs: &mut CipherBoxFS, parent: u64, name: &OsStr, reply: ReplyEntry) {
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

    // D-06: reject duplicate child names before mutating the inode table (EEXIST).
    // This guard is placed before the closure to return EEXIST (not EIO), since
    // the outer match maps all closure Err values to reply.error(libc::EIO).
    if fs.inodes.find_child(parent, name_str).is_some() {
        reply.error(libc::EEXIST);
        return;
    }

    log::debug!("mkdir: {} in parent {}", name_str, parent);

    let result = (|| -> Result<fuser::FileAttr, String> {
        // node/v3: mint the child folder's OWN symmetric read/write keys +
        // Ed25519 IPNS signing seed. The former user-ECIES `folder_key` wrap is
        // gone — node-to-node keys are only sealed under the parent keys.
        let read_key = cipherbox_crypto::utils::generate_file_key();
        let write_key = cipherbox_crypto::utils::generate_file_key();

        let (ipns_public_key, ipns_private_key) = cipherbox_crypto::generate_ed25519_keypair();

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
            perm: 0o777,
            nlink: 2,
        };
        let fuse_attr = attr.to_fuse_attr(current_uid(), current_gid());

        let inode = InodeData {
            ino,
            // Fresh folder: its stable id is uuid_from_ino(ino); the child folder
            // node is first published (mkdir journal) under this same id.
            node_id: crate::fs::uuid_from_ino(ino),
            parent_ino: parent,
            name: name_str.to_string(),
            kind: InodeKind::Folder {
                ipns_name: ipns_name.clone(),
                read_key: zeroize::Zeroizing::new(read_key),
                write_key: zeroize::Zeroizing::new(write_key),
                ipns_private_key: zeroize::Zeroizing::new(ipns_private_key.to_vec()),
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

        // Build the JournalEntry via the shared helper (journal_helpers.rs).
        // The helper handles: initial metadata encryption, TEE-wrap, build_folder_metadata,
        // ECIES-wrap of parent + child IPNS keys, and JournalOp::MkdirPublish construction.
        // D-04: the helper does NOT call journal.put — we do that here for the fsync barrier.
        // Roll back the in-memory inode insert + parent children/mtime update if the
        // journal entry can't be built or fsynced. Otherwise a failed mkdir returns an
        // error to the OS but leaves a ghost directory in the inode table with no durable
        // replay record. InodeTable::remove cleans the inode, name index, and parent's
        // children entry.
        let mkdir_result = match fs.build_mkdir_journal_entry(
            parent,
            ino,
            name_str,
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

        // D-04: fsync journal entry to disk BEFORE reply.entry().
        // This closes the crash-before-thread-runs window (T-43-07 / D-11b).
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
        let parent_ino = parent;

        std::thread::spawn(move || {
            let result = rt.block_on(async {
                let initial_cid = cipherbox_api_client::ipfs::upload_content(
                    &api, &child_published_node,
                ).await.map_err(|e| format!("{}", e))?;

                // SC2 item 4: the narrowed [u8;32] signing seed is a locally-owned
                // copy — wrap in Zeroizing so it is scrubbed on drop (incl. error
                // paths). try_from(as_slice()) copies straight into the array with no
                // transient plaintext Vec.
                let ipns_key_arr: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
                    <[u8; 32]>::try_from(ipns_private_key_zeroized.as_slice())
                        .map_err(|_| "Invalid IPNS key length".to_string())?,
                );
                let value = format!("/ipfs/{}", initial_cid);
                let record = cipherbox_core::ipns::create_ipns_record(
                    &ipns_key_arr, &value, 1, 86_400_000,
                ).map_err(|e| format!("IPNS record creation failed: {}", e))?;
                let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
                    .map_err(|e| format!("IPNS marshal failed: {}", e))?;

                use base64::Engine;
                let record_b64 = base64::engine::general_purpose::STANDARD
                    .encode(&marshaled);

                // New folder initial publish: sequence 1 (D-02), no conflict check needed
                let req = cipherbox_api_client::IpnsPublishRequest {
                    ipns_name: ipns_name_clone.clone(),
                    record: record_b64,
                    metadata_cid: initial_cid,
                    encrypted_ipns_private_key: encrypted_ipns_for_tee,
                    key_epoch: tee_key_epoch,
                    expected_sequence_number: None,
                };
                match cipherbox_api_client::ipns::publish_ipns(&api, &req).await.map_err(|e| format!("{}", e))? {
                    cipherbox_api_client::PublishResult::Success => {
                        coordinator.record_publish(&ipns_name_clone, 1);
                        log::info!("New folder IPNS published: {}", ipns_name_clone);
                    }
                    cipherbox_api_client::PublishResult::Conflict { .. } => {
                        // Sequence 0 should never conflict -- log and continue
                        log::warn!("Unexpected conflict on new folder IPNS publish for {}", ipns_name_clone);
                    }
                }

                let lock = coordinator.get_lock(&parent_ipns_name);
                let _guard = lock.lock().await;

                let seq = coordinator.resolve_sequence(&api, &parent_ipns_name).await?;

                // node/v3: upload the re-sealed parent PublishedNode bytes verbatim
                // (the new child is already spliced into BOTH planes).
                let parent_meta_cid = cipherbox_api_client::ipfs::upload_content(
                    &api, &parent_published_node,
                ).await.map_err(|e| format!("{}", e))?;

                // SC2 item 4: parent_ipns_private_key is a locally-owned Zeroizing
                // signing seed; narrow into a Zeroizing<[u8;32]> (scrubbed on drop,
                // incl. error paths) with no transient plaintext Vec.
                let parent_key_arr: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
                    <[u8; 32]>::try_from(parent_ipns_private_key.as_slice())
                        .map_err(|_| "Invalid parent IPNS key length".to_string())?,
                );
                let new_seq = seq + 1;
                let parent_value = format!("/ipfs/{}", parent_meta_cid);
                let parent_record = cipherbox_core::ipns::create_ipns_record(
                    &parent_key_arr, &parent_value, new_seq, 86_400_000,
                ).map_err(|e| format!("Parent IPNS record failed: {}", e))?;
                let parent_marshaled = cipherbox_core::ipns::marshal_ipns_record(
                    &parent_record,
                ).map_err(|e| format!("Parent IPNS marshal failed: {}", e))?;
                let parent_record_b64 = base64::engine::general_purpose::STANDARD
                    .encode(&parent_marshaled);

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
                match cipherbox_api_client::ipns::publish_ipns(&api, &parent_req).await.map_err(|e| format!("{}", e))? {
                    cipherbox_api_client::PublishResult::Success => {
                        coordinator.record_publish(&parent_ipns_name, new_seq);
                        // Only unpin old CID on successful publish
                        if let Some(old) = parent_old_cid {
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                        }
                        // Remove journal entry now that parent publish is confirmed (D-11b).
                        if let Err(e) = journal_for_mkdir.remove(&mkdir_journal_entry_id) {
                            log::warn!(
                                "mkdir parent-publish: failed to remove journal entry {} after success: {}; entry may replay again on next mount",
                                mkdir_journal_entry_id, e
                            );
                        }
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
                        let _ = upload_tx.send(crate::FsEvent::MkdirConflict { parent_ino });
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
