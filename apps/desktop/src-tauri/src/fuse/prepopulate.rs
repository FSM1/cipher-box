//! Shared IPNS prepopulate logic for macOS (fuse) and Windows (winfsp) mounts.
//!
//! Both `fuse/mod.rs` (macOS) and `fuse/windows/mod.rs` (Windows) contained a
//! ~255 LoC block that resolves the root IPNS record, decrypts root folder
//! metadata, pre-populates the inode table, and recursively pre-populates
//! immediate subfolders. This module normalizes those two structurally parallel
//! but non-byte-identical blocks into a single shared function.
//!
//! # A3 Note
//!
//! The two original blocks were NOT byte-identical:
//! - macOS used `cipherbox_core::decrypt_metadata_from_ipfs_public` (re-export path)
//!   and `if-let` chains for FilePointer resolution.
//! - Windows used `cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public`
//!   (submodule path), nested `match` arms, and
//!   `get_unresolved_file_pointers_for_parent` (scoped to a parent inode).
//!
//! The normalized function uses the direct re-export paths (which resolve on both
//! platforms) and `get_unresolved_file_pointers_for_parent` throughout (more
//! precise than the all-inodes variant used by macOS previously, and produces
//! the same result given that only the parent folder's children are present
//! when the call is made).

#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn prepopulate_filesystem(
    api: &std::sync::Arc<cipherbox_api_client::ApiClient>,
    inodes: &mut cipherbox_fuse::inode::InodeTable,
    metadata_cache: &mut cipherbox_fuse::cache::MetadataCache,
    root_ipns_name: &str,
    root_folder_key: &[u8],
    private_key: &[u8],
    public_key: &[u8],
) -> Vec<(String, u64)> {
    use zeroize::Zeroizing;

    let mut initial_sequences: Vec<(String, u64)> = Vec::new();

    // ── Fetch and decrypt root folder metadata ─────────────────────────────

    log::info!("Pre-populating root folder from IPNS...");
    let fetch_result: Result<(Vec<u8>, String, u64), String> = async {
        let resolve_resp =
            cipherbox_api_client::ipns::resolve_ipns(api, root_ipns_name)
                .await
                .map_err(|e| e.to_string())?;
        let encrypted_bytes =
            cipherbox_api_client::ipfs::fetch_content(api, &resolve_resp.cid)
                .await
                .map_err(|e| e.to_string())?;
        let seq = resolve_resp.sequence_number.parse::<u64>().unwrap_or_else(|e| {
            log::warn!(
                "Failed to parse root IPNS sequence '{}': {}",
                resolve_resp.sequence_number,
                e
            );
            0
        });
        Ok((encrypted_bytes, resolve_resp.cid, seq))
    }
    .await;

    match fetch_result {
        Err(e) => {
            log::warn!("Root folder fetch failed (mount will show empty): {}", e);
            return initial_sequences;
        }
        Ok((encrypted_bytes, cid, root_seq)) => {
            initial_sequences.push((root_ipns_name.to_string(), root_seq));

            let metadata =
                match cipherbox_core::decrypt_metadata_from_ipfs_public(&encrypted_bytes, root_folder_key) {
                    Ok(m) => m,
                    Err(e) => {
                        log::warn!("Root metadata decryption failed: {}", e);
                        return initial_sequences;
                    }
                };

            metadata_cache.set(root_ipns_name, metadata.clone(), cid);

            match inodes.populate_folder(
                cipherbox_fuse::inode::ROOT_INO,
                &metadata,
                private_key,
                public_key,
                false,
            ) {
                Err(e) => {
                    log::warn!("Root folder populate failed: {}", e);
                    return initial_sequences;
                }
                Ok(()) => {
                    log::info!("Root folder pre-populated successfully");
                }
            }

            // ── Resolve root-level FilePointers ────────────────────────────

            let root_unresolved = inodes
                .get_unresolved_file_pointers_for_parent(cipherbox_fuse::inode::ROOT_INO);

            if !root_unresolved.is_empty() {
                log::info!("Resolving {} root FilePointer(s)...", root_unresolved.len());
                let root_key_arr: Result<[u8; 32], _> = root_folder_key.try_into();
                if let Ok(fk) = root_key_arr {
                    let fk = Zeroizing::new(fk);
                    for (fp_ino, fp_ipns) in &root_unresolved {
                        let fp_result: Result<Vec<u8>, String> = async {
                            let resp =
                                cipherbox_api_client::ipns::resolve_ipns(api, fp_ipns)
                                    .await
                                    .map_err(|e| e.to_string())?;
                            cipherbox_api_client::ipfs::fetch_content(api, &resp.cid)
                                .await
                                .map_err(|e| e.to_string())
                        }
                        .await;
                        match fp_result {
                            Ok(enc_bytes) => {
                                match cipherbox_core::decrypt_file_metadata_from_ipfs_public(
                                    &enc_bytes, &fk,
                                ) {
                                    Ok(fm) => {
                                        inodes.resolve_file_pointer(
                                            *fp_ino,
                                            fm.cid,
                                            fm.file_key_encrypted,
                                            fm.file_iv,
                                            fm.size,
                                            fm.encryption_mode,
                                            fm.versions,
                                        );
                                    }
                                    Err(e) => log::warn!(
                                        "Root FilePointer decrypt failed for ino {}: {}",
                                        fp_ino,
                                        e
                                    ),
                                }
                            }
                            Err(e) => log::warn!(
                                "Root FilePointer resolve failed for ino {}: {}",
                                fp_ino,
                                e
                            ),
                        }
                    }
                }
            }

            // ── Pre-populate immediate subfolders ─────────────────────────

            let subfolder_infos: Vec<(u64, String, Zeroizing<Vec<u8>>)> = inodes
                .inodes
                .values()
                .filter_map(|inode| {
                    if inode.parent_ino != cipherbox_fuse::inode::ROOT_INO {
                        return None;
                    }
                    if let cipherbox_fuse::inode::InodeKind::Folder {
                        ref ipns_name,
                        ref folder_key,
                        ..
                    } = inode.kind
                    {
                        Some((inode.ino, ipns_name.clone(), folder_key.clone()))
                    } else {
                        None
                    }
                })
                .collect();

            for (sub_ino, sub_ipns, sub_key) in &subfolder_infos {
                log::info!("Pre-populating subfolder ino={} ipns={}", sub_ino, sub_ipns);
                let sub_result: Result<(Vec<u8>, String, u64), String> = async {
                    let resp =
                        cipherbox_api_client::ipns::resolve_ipns(api, sub_ipns)
                            .await
                            .map_err(|e| e.to_string())?;
                    let bytes =
                        cipherbox_api_client::ipfs::fetch_content(api, &resp.cid)
                            .await
                            .map_err(|e| e.to_string())?;
                    let seq = resp.sequence_number.parse::<u64>().unwrap_or_else(|e| {
                        log::warn!(
                            "Failed to parse subfolder IPNS sequence '{}' for {}: {}",
                            resp.sequence_number,
                            sub_ipns,
                            e
                        );
                        0
                    });
                    Ok((bytes, resp.cid, seq))
                }
                .await;

                match sub_result {
                    Err(e) => log::warn!("Subfolder ino={} fetch failed: {}", sub_ino, e),
                    Ok((enc_bytes, sub_cid, sub_seq)) => {
                        initial_sequences.push((sub_ipns.clone(), sub_seq));
                        match cipherbox_core::decrypt_metadata_from_ipfs_public(
                            &enc_bytes, sub_key,
                        ) {
                            Err(e) => log::warn!("Subfolder ino={} decrypt failed: {}", sub_ino, e),
                            Ok(sub_metadata) => {
                                metadata_cache.set(sub_ipns, sub_metadata.clone(), sub_cid);
                                match inodes.populate_folder(
                                    *sub_ino,
                                    &sub_metadata,
                                    private_key,
                                    public_key,
                                    false,
                                ) {
                                    Err(e) => log::warn!(
                                        "Subfolder ino={} populate failed: {}",
                                        sub_ino,
                                        e
                                    ),
                                    Ok(()) => {
                                        log::info!("Subfolder ino={} pre-populated", sub_ino);

                                        // Resolve subfolder FilePointers
                                        let sub_unresolved =
                                            inodes.get_unresolved_file_pointers_for_parent(
                                                *sub_ino,
                                            );
                                        if !sub_unresolved.is_empty() {
                                            let sk_arr: Result<[u8; 32], _> =
                                                sub_key.as_slice().try_into();
                                            if let Ok(sk) = sk_arr {
                                                let sk = Zeroizing::new(sk);
                                                for (fp_ino, fp_ipns) in &sub_unresolved {
                                                    let fp_result: Result<Vec<u8>, String> =
                                                        async {
                                                            let resp =
                                                                cipherbox_api_client::ipns::resolve_ipns(
                                                                    api, fp_ipns,
                                                                )
                                                                .await
                                                                .map_err(|e| e.to_string())?;
                                                            cipherbox_api_client::ipfs::fetch_content(
                                                                api, &resp.cid,
                                                            )
                                                            .await
                                                            .map_err(|e| e.to_string())
                                                        }
                                                        .await;
                                                    match fp_result {
                                                        Ok(fp_enc) => {
                                                            match cipherbox_core::decrypt_file_metadata_from_ipfs_public(
                                                                &fp_enc, &sk,
                                                            ) {
                                                                Ok(fm) => {
                                                                    inodes.resolve_file_pointer(
                                                                        *fp_ino,
                                                                        fm.cid,
                                                                        fm.file_key_encrypted,
                                                                        fm.file_iv,
                                                                        fm.size,
                                                                        fm.encryption_mode,
                                                                        fm.versions,
                                                                    );
                                                                }
                                                                Err(e) => log::warn!(
                                                                    "Sub FilePointer decrypt failed: {}",
                                                                    e
                                                                ),
                                                            }
                                                        }
                                                        Err(e) => log::warn!(
                                                            "Sub FilePointer resolve failed: {}",
                                                            e
                                                        ),
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    initial_sequences
}
