//! Shared content-prefetch helper for WinFsp read operations.
//!
//! Both `handle_open` (read path) and `handle_read` in `platform/windows/read_ops.rs`
//! contain the same content-prefetch spawn block. This module extracts that block
//! into a single function to eliminate the duplication.
//!
//! SC#1/SC#6 (69-14): node/v3 recovers the file content-key by SYMMETRIC unseal
//! of the file node's OWN sealed read-body — the former
//! `(encrypted_file_key, iv, encryption_mode)` triple is gone. The prefetch now
//! takes the file's `ipns_name` + its `read_key` and resolves the node through
//! the gated [`cipherbox_sdk::fetch_node_gated`] wrapper (via
//! `crate::content_ops::fetch_node_and_decrypt_content`) — mirroring the macOS
//! `spawn_content_prefetch_fuse` helper in `read_ops.rs`.

#[cfg(feature = "winfsp")]
pub(crate) fn spawn_content_prefetch(
    fs: &mut crate::CipherBoxFS,
    cid: String,
    ipns_name: String,
    read_key: [u8; 32],
    label: &'static str,
) {
    use crate::constants::CONTENT_DOWNLOAD_TIMEOUT;
    use crate::content_ops::fetch_node_and_decrypt_content;

    let api = fs.api.clone();
    let rt = fs.rt.clone();
    let tx = fs.content_tx.clone();
    let cid_clone = cid.clone();
    let ipns_clone = ipns_name;
    let read_key_owned = read_key;
    let high_water = fs.high_water.clone();
    fs.prefetching.insert(cid);

    rt.spawn(async move {
        let result = tokio::time::timeout(
            CONTENT_DOWNLOAD_TIMEOUT,
            fetch_node_and_decrypt_content(&api, &high_water, &ipns_clone, &read_key_owned),
        )
        .await;

        match result {
            Ok(Ok(plaintext)) => {
                let _ = tx.send(crate::PendingContent::Success {
                    cid: cid_clone,
                    data: plaintext,
                });
            }
            Ok(Err(e)) => {
                log::error!("{} for CID {}: {}", label, cid_clone, e);
                let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
            }
            Err(_) => {
                log::error!("{} timed out for CID {}", label, cid_clone);
                let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
            }
        }
    });
}
