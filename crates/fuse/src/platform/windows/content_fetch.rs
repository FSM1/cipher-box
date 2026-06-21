//! Shared content-prefetch helper for WinFsp read operations.
//!
//! Both `handle_open` (read path) and `handle_read` in `platform/windows/read_ops.rs`
//! contain the same content-prefetch spawn block. This module extracts that block
//! into a single function to eliminate the duplication.

#[cfg(feature = "winfsp")]
pub(crate) fn spawn_content_prefetch(
    fs: &mut crate::CipherBoxFS,
    cid: String,
    encrypted_file_key: String,
    iv: String,
    encryption_mode: String,
    label: &'static str,
) {
    use crate::constants::CONTENT_DOWNLOAD_TIMEOUT;
    use crate::content_ops::fetch_and_decrypt_content_async;

    let api = fs.api.clone();
    let rt = fs.rt.clone();
    let tx = fs.content_tx.clone();
    let cid_clone = cid.clone();
    let efk = encrypted_file_key;
    let iv_clone = iv;
    let enc_mode = encryption_mode;
    let pk = fs.private_key.clone();
    fs.prefetching.insert(cid);

    rt.spawn(async move {
        let result = tokio::time::timeout(
            CONTENT_DOWNLOAD_TIMEOUT,
            fetch_and_decrypt_content_async(
                &api, &cid_clone, &efk, &iv_clone, &enc_mode, &pk,
            ),
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
                log::error!(
                    "{} timed out for CID {}",
                    label,
                    cid_clone
                );
                let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
            }
        }
    });
}
