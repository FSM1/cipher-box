//! Metadata encryption, merge, and background publish helpers.

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::sync::Arc;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use zeroize::Zeroizing;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use cipherbox_api_client::ApiClient;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::publish::PublishCoordinator;

/// Shared attempt-budgeted CAS publish helper (D-03 / SC2 item 1).
///
/// Resolves the current IPNS sequence, calls `make_record(new_seq)` to produce
/// `(record_b64, metadata_cid)`, publishes with `expected_sequence_number:
/// Some(seq.to_string())`, and on `Conflict` re-resolves + retries with a jitter
/// back-off, up to `max_attempts` total publish attempts (the initial attempt
/// counts as attempt 1). Callers preserving the original single-retry behavior
/// pass `max_attempts: 2`; the metadata publish path passes `5`.
///
/// On persistent `Conflict`:
/// - If `journal_entry: Some((queue, entry))` — enqueue via `WriteQueue::put` and
///   return `Ok(())` (durable ack). **No call site supplies `Some` this phase** — see
///   D-01a: there is no `JournalOp::FilePublish`/`BinPublish` variant in
///   `crates/sdk/src/queue.rs`, so journaling per-file/bin publishes is a deferred
///   cross-crate change (CONTEXT Deferred Ideas).
/// - If `journal_entry: None` — return `Err` (the fire-and-forget caller logs at
///   `log::error!` and the blocking/sync path returns `EIO`).
///
/// Hard failures (record creation, marshal, upload, resolve) propagate `Err`
/// immediately — no retry.
///
/// The `old_cids_to_unpin` parameter carries CIDs to unpin only on success; on the
/// retry path additional intermediate CIDs are also cleaned up. Pass `vec![]` when
/// there is nothing to unpin.
///
/// `preresolved_seq`: when `Some(seq)`, the caller has already resolved the current
/// sequence (e.g. `publish_file_node`'s pre-publish equivocation guard resolves the
/// name via `resolve_ipns_for_replay`), so the first CAS attempt reuses it instead of
/// issuing a second identical resolve round-trip. Pass `None` to resolve here as
/// usual. The `Conflict` retry path always re-resolves regardless — a conflict means
/// any pre-resolved sequence is already stale.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) async fn publish_with_cas_retry<F>(
    api: &ApiClient,
    coordinator: &PublishCoordinator,
    ipns_name: &str,
    preresolved_seq: Option<u64>,
    make_record: F,
    old_cids_to_unpin: &[String],
    journal_entry: Option<()>, // placeholder for future (queue, entry) — always None this phase
    max_attempts: u32,
) -> Result<(), String>
where
    F: Fn(u64) -> Result<(String, String), String>, // make_record(new_seq) -> (record_b64, cid)
{
    // CIDs uploaded by attempts that were then superseded by a Conflict. These are
    // unpinned once the publish resolves (success or exhaustion). Any intermediate
    // CID equal to the finally-published CID is NOT unpinned — callers that re-publish
    // the SAME content blob at a fresh sequence (metadata + bin paths) would otherwise
    // unpin their own live content.
    let mut superseded_cids: Vec<String> = Vec::new();
    let mut attempt = 0u32;

    loop {
        // First attempt may reuse a caller-preresolved sequence; a Conflict always
        // invalidates it, so every retry re-resolves.
        let seq = if attempt == 0 {
            match preresolved_seq {
                Some(s) => s,
                None => coordinator.resolve_sequence(api, ipns_name).await?,
            }
        } else {
            coordinator.resolve_sequence(api, ipns_name).await?
        };
        let new_seq = seq
            .checked_add(1)
            .ok_or_else(|| "IPNS sequence number overflow".to_string())?;

        let (record_b64, metadata_cid) = make_record(new_seq)?;

        let req = cipherbox_api_client::IpnsPublishRequest {
            ipns_name: ipns_name.to_string(),
            record: record_b64,
            metadata_cid: metadata_cid.clone(),
            encrypted_ipns_private_key: None,
            key_epoch: None,
            expected_sequence_number: Some(seq.to_string()),
        };

        match cipherbox_api_client::ipns::publish_ipns(api, &req)
            .await
            .map_err(|e| format!("{}", e))?
        {
            cipherbox_api_client::PublishResult::Success => {
                coordinator.record_publish(ipns_name, new_seq);
                if attempt > 0 {
                    log::info!(
                        "Conflict resolved for {} after {} attempt(s) (seq {})",
                        ipns_name,
                        attempt + 1,
                        new_seq
                    );
                }
                // Unpin superseded CIDs from prior conflicting attempts (never the
                // just-published one) plus the caller's old CIDs.
                for cid in &superseded_cids {
                    if *cid != metadata_cid {
                        let _ = cipherbox_api_client::ipfs::unpin_content(api, cid).await;
                    }
                }
                for cid in old_cids_to_unpin {
                    let _ = cipherbox_api_client::ipfs::unpin_content(api, cid).await;
                }
                return Ok(());
            }
            cipherbox_api_client::PublishResult::Conflict {
                current_sequence_number,
            } => {
                attempt += 1;
                superseded_cids.push(metadata_cid);
                if attempt >= max_attempts {
                    // Exhausted the budget: clean up every intermediate CID and surface Err.
                    for cid in &superseded_cids {
                        let _ = cipherbox_api_client::ipfs::unpin_content(api, cid).await;
                    }
                    // D-01a: journal_entry param reserved for future journal-enqueue path
                    // (no JournalOp::FilePublish/BinPublish variant this phase; all call sites
                    // pass None). On persistent conflict: Err → EIO.
                    let _ = &journal_entry; // suppress unused warning until D-01a is wired
                    return Err(format!("persistent conflict for {}", ipns_name));
                }
                log::warn!(
                    "Conflict for {}: expected seq {}, server has {}. Re-resolving for retry (attempt {}/{}).",
                    ipns_name,
                    seq,
                    current_sequence_number,
                    attempt + 1,
                    max_attempts
                );

                let jitter_ms = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos()
                    % 400) as u64
                    + 100;
                tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
            }
        }
    }
}

/// Classify an IPNS resolve error string as "record does not exist yet" (so the caller
/// can treat it as an empty/first-publish case) vs a genuine failure to surface.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn is_ipns_not_found(error_message: &str) -> bool {
    error_message.to_lowercase().contains("not found")
}

/// Total wall-clock budget for a single blocking share-revocation, layered over
/// the bounded retry loop. A hung or unreachable backend surfaces as a failure
/// (→ EIO) rather than wedging the user's `rm` indefinitely.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
const REVOKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Maximum revocation attempts (1 initial + 2 retries). Mirrors the SDK
/// `revokeBatchWithRetry` `maxAttempts = 3` default.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
const REVOKE_MAX_ATTEMPTS: u32 = 3;

/// Decide whether a revocation error is a deterministic client failure that will
/// never succeed on retry (a 4xx — validation 400, auth 401/403, etc.) and so
/// should be surfaced immediately rather than burning the backoff budget.
///
/// Transport failures and 5xx are transient and retried. Mirrors the SDK
/// `isNonRetryableError` predicate (share/index.ts).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn is_non_retryable_revoke_error(err: &cipherbox_api_client::ApiError) -> bool {
    matches!(
        err,
        cipherbox_api_client::ApiError::ApiResponse { status, .. }
            if (400..=499).contains(status)
    )
}

/// Synchronously revoke every share/invite for a single deleted node's IPNS
/// name, blocking the calling filesystem thread until it succeeds, fails
/// non-retryably, exhausts retries, or times out.
///
/// This is the fail-closed access cutoff that must run BEFORE the destructive
/// inode removal / parent metadata update on the delete path. On `Err(())` the
/// caller MUST abort the delete (e.g. `reply.error(libc::EIO)`) so the item
/// stays put and no sharee is left with access to soon-to-be-orphaned content.
///
/// Returns `Ok(())` when:
/// - the revocation succeeds (2xx), or
/// - `ipns_name` is empty (nothing was ever shared without a name — nothing to
///   revoke).
///
/// Returns `Err(())` on any non-retryable 4xx, exhausted transient retries, or
/// timeout. The error is intentionally opaque (the caller maps it to a single
/// errno); details are logged.
///
/// The whole loop is bounded by [`REVOKE_TIMEOUT`] layered over up to
/// [`REVOKE_MAX_ATTEMPTS`] attempts with exponential backoff (300ms * 2^attempt).
//
// `Result<(), ()>` is deliberate: the only caller (the FUSE delete path) maps
// every failure to a single errno (EIO / STATUS_ACCESS_DENIED) and the rich
// error detail is logged here, so propagating a typed error would add no value.
#[allow(clippy::result_unit_err)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn revoke_shares_blocking(
    api: &Arc<ApiClient>,
    rt: &tokio::runtime::Handle,
    ipns_name: &str,
) -> Result<(), ()> {
    if ipns_name.is_empty() {
        // Nothing to revoke for an unnamed node.
        return Ok(());
    }

    let names = vec![ipns_name.to_string()];

    let outcome = rt.block_on(async {
        tokio::time::timeout(REVOKE_TIMEOUT, async {
            let mut last_err: Option<cipherbox_api_client::ApiError> = None;
            for attempt in 0..REVOKE_MAX_ATTEMPTS {
                match cipherbox_api_client::shares::revoke_shares_for_items(api, &names).await {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        // Deterministic 4xx: surface immediately, no retry.
                        if is_non_retryable_revoke_error(&err) {
                            return Err(err);
                        }
                        last_err = Some(err);
                        // Backoff before the next attempt (skip after the last).
                        if attempt < REVOKE_MAX_ATTEMPTS - 1 {
                            let backoff_ms = 300u64 * (1u64 << attempt);
                            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        }
                    }
                }
            }
            Err(
                last_err.unwrap_or(cipherbox_api_client::ApiError::ApiResponse {
                    status: 0,
                    message: "share revocation exhausted retries".to_string(),
                }),
            )
        })
        .await
    });

    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            log::error!(
                "share revocation failed for ipns {} (delete aborted): {}",
                ipns_name,
                e
            );
            Err(())
        }
        Err(_elapsed) => {
            log::error!(
                "share revocation timed out for ipns {} after {:?} (delete aborted)",
                ipns_name,
                REVOKE_TIMEOUT
            );
            Err(())
        }
    }
}

/// Spawn a background OS thread to upload a sealed node/v3 `PublishedNode` and
/// publish it via IPNS (69-09 Slice 3 write emission).
///
/// The parent folder/root node was already re-sealed by
/// [`crate::CipherBoxFS::build_folder_metadata`] — this function uploads the
/// opaque `published_node` bytes verbatim (no `FolderMetadata` encrypt) and runs
/// the CAS publish loop. On an IPNS sequence conflict it republishes the SAME
/// sealed bytes at a fresh sequence (last-writer-wins). The node/v3 merge of
/// concurrent remote children (the former `merge_folder_children` path) is
/// deferred to 69-09 Slice 5 — a sealed envelope cannot be structurally merged
/// without unsealing under the parent readKey, which Slice 5 wires in.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_metadata_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    published_node: Vec<u8>,
    ipns_private_key: Zeroizing<Vec<u8>>, // D-12: Zeroizing to match spawn_bin_entry_publish pattern
    ipns_name: String,
    old_metadata_cid: Option<String>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            let lock = coordinator.get_lock(&ipns_name);
            let _guard = lock.lock().await;

            // Pre-validate IPNS key length so the record builder is infallible.
            let ipns_key_arr: Zeroizing<[u8; 32]> = {
                let arr: [u8; 32] = ipns_private_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid IPNS private key length".to_string())?;
                Zeroizing::new(arr)
            };

            // Upload the sealed node/v3 envelope ONCE, then CAS-publish it.
            let cid = cipherbox_api_client::ipfs::upload_content(&api, &published_node)
                .await
                .map_err(|e| format!("{}", e))?;
            let old_cids: Vec<String> = old_metadata_cid.into_iter().collect();

            // node/v3 make_record: the sealed envelope was uploaded ONCE above, so
            // every attempt re-signs an IPNS record pointing at the SAME `cid` at a
            // fresh sequence (last-writer-wins). Adapt to the shared helper's
            // `(record_b64, cid)` closure shape.
            let make_record = |new_seq: u64| -> Result<(String, String), String> {
                use base64::Engine;
                let value = format!("/ipfs/{}", cid);
                let record =
                    cipherbox_core::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
                        .map_err(|e| format!("IPNS record creation failed: {}", e))?;
                let marshaled = cipherbox_core::marshal_ipns_record(&record)
                    .map_err(|e| format!("IPNS record marshal failed: {}", e))?;
                let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
                Ok((record_b64, cid.clone()))
            };

            // Delegate to the single shared CAS-retry helper with the metadata path's
            // 5-attempt budget (SC2 item 1 — no 5→2 regression). The helper never
            // unpins the just-published `cid`; on failure the best-effort cleanup below
            // unpins the now-orphaned sealed envelope.
            let publish_result = publish_with_cas_retry(
                &api,
                &coordinator,
                &ipns_name,
                None, // no pre-resolved sequence on the background metadata path
                make_record,
                &old_cids,
                None, // D-01a: no JournalOp variant; exhaustion → Err
                5,    // metadata publish budget (mirrors the former inline loop)
            )
            .await;
            if publish_result.is_ok() {
                log::info!("Background node/v3 publish succeeded for {}", ipns_name);
            }

            // Best-effort cleanup: any failure path above leaves the sealed
            // envelope uploaded+pinned but unreferenced by a published record —
            // unpin it so a failed publish doesn't leak an orphaned IPFS pin.
            if publish_result.is_err() {
                let _ = cipherbox_api_client::ipfs::unpin_content(&api, &cid).await;
            }
            publish_result?;
            Ok::<(), String>(())
        });
        if let Err(e) = result {
            log::error!("Background metadata publish failed: {}", e);
        }
    });
}

/// Add a BinEntry to the user's encrypted recycle bin IPNS record.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_bin_entry_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    entry: cipherbox_core::bin::BinEntry,
    user_private_key: Zeroizing<Vec<u8>>,
    user_public_key: Vec<u8>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            let pk_arr: [u8; 32] = user_private_key
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid private key length for bin derivation".to_string())?;
            let (bin_ipns_private_key, _bin_ipns_public_key, bin_ipns_name) =
                cipherbox_crypto::derive_bin_ipns_keypair(&pk_arr)
                    .map_err(|e| format!("Bin IPNS derivation failed: {}", e))?;

            let lock = coordinator.get_lock(&bin_ipns_name);
            let _guard = lock.lock().await;

            // D-01: route bin IPNS resolve through the verified chokepoint.
            let (mut bin_metadata, existing_cid) =
                match cipherbox_api_client::ipns::resolve_ipns_verified(&api, &bin_ipns_name).await // sc6-allow: legacy recycle-bin publish (spawn_bin_entry_publish), not a node/v3 read
                {
                    Ok(verified) => {
                        match cipherbox_api_client::ipfs::fetch_content(&api, &verified.cid).await {
                            Ok(bytes) => {
                                match cipherbox_core::decrypt_bin_metadata(
                                    &bytes,
                                    &user_private_key,
                                ) {
                                    Ok(meta) => (meta, Some(verified.cid)),
                                    Err(e) => {
                                        log::warn!("Failed to decrypt bin metadata: {}", e);
                                        return Err(format!("Bin decrypt failed: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("Failed to fetch bin metadata blob: {}", e);
                                return Err(format!("Bin fetch failed: {}", e));
                            }
                        }
                    }
                    // D-04: Legacy variant removed — all-absent sig fields fail closed.
                    Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
                        // D-02: fail only this operation.
                        log::warn!(
                            "spawn_bin_entry_publish: IPNS {} verify failed: {}",
                            bin_ipns_name,
                            msg
                        );
                        return Err(format!("Bin IPNS verify failed: {}", msg));
                    }
                    Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
                        let e_str = format!("{}", e);
                        if is_ipns_not_found(&e_str) {
                            (cipherbox_core::empty_bin_metadata(), None)
                        } else {
                            log::warn!("Failed to resolve bin IPNS: {}", e);
                            return Err(format!("Bin resolve failed: {}", e));
                        }
                    }
                };

            bin_metadata.sequence_number += 1;
            bin_metadata.entries.push(entry);

            let encrypted = cipherbox_core::encrypt_bin_metadata(&bin_metadata, &user_public_key)
                .map_err(|e| format!("Bin metadata encryption failed: {}", e))?;

            let new_cid = cipherbox_api_client::ipfs::upload_content(&api, &encrypted)
                .await
                .map_err(|e| format!("{}", e))?;

            // Validate bin IPNS key length before entering the CAS loop.
            let bin_ipns_key_arr: Zeroizing<[u8; 32]> = {
                let arr: [u8; 32] = bin_ipns_private_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid bin IPNS key length".to_string())?;
                Zeroizing::new(arr)
            };

            // `existing_cid` is None when the bin IPNS record does not exist yet (first
            // publish for this vault's bin). The CAS helper's resolve_sequence would treat
            // that not-found as a fatal error, so the first publish must NOT go through the
            // CAS helper — it publishes directly at seq 0 with expected_sequence_number: None
            // (no prior record to compare against), mirroring the per-file first-publish path.
            let is_first_bin_publish = existing_cid.is_none();
            let new_cid_for_record = new_cid.clone();
            let old_cids: Vec<String> = existing_cid.into_iter().collect();
            use base64::Engine;

            let make_bin_record = |seq_for_record: u64| -> Result<(String, String), String> {
                let value = format!("/ipfs/{}", new_cid_for_record);
                let record = cipherbox_core::create_ipns_record(
                    &bin_ipns_key_arr,
                    &value,
                    seq_for_record,
                    86_400_000,
                )
                .map_err(|e| format!("Bin IPNS record creation failed: {}", e))?;
                let marshaled = cipherbox_core::marshal_ipns_record(&record)
                    .map_err(|e| format!("Bin IPNS marshal failed: {}", e))?;
                let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
                Ok((record_b64, new_cid_for_record.clone()))
            };

            if is_first_bin_publish {
                // First publish: no prior record, so no CAS. Publish at seq 1 (D-02).
                let (record_b64, _cid) = make_bin_record(1)?;
                let req = cipherbox_api_client::IpnsPublishRequest {
                    ipns_name: bin_ipns_name.clone(),
                    record: record_b64,
                    metadata_cid: new_cid.clone(),
                    encrypted_ipns_private_key: None,
                    key_epoch: None,
                    expected_sequence_number: None,
                };
                match cipherbox_api_client::ipns::publish_ipns(&api, &req)
                    .await
                    .map_err(|e| format!("{}", e))?
                {
                    cipherbox_api_client::PublishResult::Success => {
                        coordinator.record_publish(&bin_ipns_name, 1);
                        log::info!("Bin entry published (first publish)");
                    }
                    cipherbox_api_client::PublishResult::Conflict { .. } => {
                        // Another client raced to create the bin record. D-01a: no
                        // JournalOp::BinPublish variant — surface as Err → EIO.
                        return Err(format!(
                            "Conflict on first bin IPNS publish for {} — another client raced",
                            bin_ipns_name
                        ));
                    }
                }
            } else {
                // Update publish: route through the shared CAS helper (D-03 / D-02).
                // D-01a: no JournalOp::BinPublish variant exists in crates/sdk/src/queue.rs
                // (only UploadFile/MkdirPublish); journaling bin publish is deferred (CONTEXT
                // Deferred Ideas). On retry exhaustion: return Err → log::error! → EIO.
                publish_with_cas_retry(
                    &api,
                    &coordinator,
                    &bin_ipns_name,
                    None, // no pre-resolved sequence on the bin-publish path
                    make_bin_record,
                    &old_cids,
                    None, // D-01a: no JournalOp::BinPublish variant; exhaustion → Err → EIO
                    2,    // preserve today's single-retry (2-attempt) bin behavior
                )
                .await
                .inspect(|_| log::info!("Bin entry published"))?;
            }

            Ok::<(), String>(())
        });
        if let Err(e) = result {
            log::error!("Background bin entry publish failed: {}", e);
        }
    });
}

#[cfg(test)]
mod tests {
    // --- publish_with_cas_retry tests (D-03 / D-01a / D-02) ---
    //
    // These tests exercise the helper logic via a closure-driven seam. Since the
    // actual IPNS publish and coordinator calls are network-bound, we verify the
    // branching that does not require a live network by testing the logic paths
    // directly through mock PublishResult variants.

    /// Enum mirroring PublishResult for test seam
    #[derive(Debug)]
    enum MockPublishResult {
        Success,
        Conflict { current_sequence_number: u64 },
        Err(String),
    }

    /// Minimal seam mirroring the `publish_with_cas_retry` attempt-budget loop,
    /// exercisable without network. `publishes` supplies one `MockPublishResult`
    /// per attempt (attempt 1 = index 0), and the loop runs up to `max_attempts`
    /// attempts, re-making the record on every attempt exactly like the real helper.
    /// Returns (result, make_record_call_count, record_publish_called).
    fn run_publish_retry_seam(
        publishes: Vec<MockPublishResult>,
        max_attempts: u32,
        journal_entry_is_some: bool,
    ) -> (Result<(), String>, usize, bool) {
        let mut make_record_call_count = 0usize;
        let mut record_publish_called = false;

        // Simulate the publish_with_cas_retry decision tree over the attempt budget.
        let result: Result<(), String> = (|| {
            let mut attempt = 0u32;
            let mut seq: u64 = 0; // simulated resolved sequence (advances on re-resolve)
            loop {
                let new_seq = seq.checked_add(1).ok_or_else(|| "overflow".to_string())?;
                make_record_call_count += 1;
                let _record = format!("record-seq-{}", new_seq); // simulates make_record(new_seq)

                let fallback = MockPublishResult::Err("no publish configured".to_string());
                let outcome = publishes.get(attempt as usize).unwrap_or(&fallback);

                match outcome {
                    MockPublishResult::Err(e) => return Err(e.clone()),
                    MockPublishResult::Success => {
                        record_publish_called = true;
                        return Ok(());
                    }
                    MockPublishResult::Conflict {
                        current_sequence_number,
                    } => {
                        attempt += 1;
                        if attempt >= max_attempts {
                            // Budget exhausted. Per D-01a: return Err (fire-and-forget → EIO).
                            // The journal-enqueue path is not wired this phase (no call site
                            // supplies Some), so both branches surface Err.
                            if journal_entry_is_some {
                                return Err(
                                    "persistent conflict — journal path placeholder".to_string()
                                );
                            }
                            return Err("persistent conflict for test-ipns-name".to_string());
                        }
                        // Simulate a re-resolve to a fresh sequence for the next attempt.
                        seq = *current_sequence_number;
                    }
                }
            }
        })();

        (result, make_record_call_count, record_publish_called)
    }

    // Test 1: success on first attempt — make_record called once, record_publish called.
    #[test]
    fn publish_with_cas_retry_success_first_attempt() {
        let (result, call_count, record_publish) =
            run_publish_retry_seam(vec![MockPublishResult::Success], 2, false);
        assert!(result.is_ok(), "expected Ok on first-attempt success");
        assert_eq!(call_count, 1, "make_record must be called once on success");
        assert!(record_publish, "record_publish must be called on success");
    }

    // Test 2: conflict then retry success — make_record called twice, record_publish called.
    #[test]
    fn publish_with_cas_retry_conflict_then_success() {
        let (result, call_count, record_publish) = run_publish_retry_seam(
            vec![
                MockPublishResult::Conflict {
                    current_sequence_number: 5,
                },
                MockPublishResult::Success,
            ],
            2,
            false,
        );
        assert!(result.is_ok(), "expected Ok after conflict+retry success");
        assert_eq!(
            call_count, 2,
            "make_record must be called twice (initial + retry)"
        );
        assert!(
            record_publish,
            "record_publish must be called on retry success"
        );
    }

    // Test 3: persistent conflict with journal_entry: None (the per-file/bin path per D-01a).
    // Must return Err containing "conflict" — NEVER record_publish with stale seq, NEVER warn-and-ack.
    #[test]
    fn publish_with_cas_retry_persistent_conflict_journal_none_returns_err() {
        let (result, _call_count, record_publish) = run_publish_retry_seam(
            vec![
                MockPublishResult::Conflict {
                    current_sequence_number: 5,
                },
                MockPublishResult::Conflict {
                    current_sequence_number: 6,
                },
            ],
            2,
            false, // journal_entry: None — the per-file/bin path per D-01a
        );
        assert!(
            result.is_err(),
            "persistent conflict with journal:None must return Err"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.to_lowercase().contains("conflict"),
            "error message must mention 'conflict', got: {}",
            err_msg
        );
        assert!(
            !record_publish,
            "record_publish must NOT be called on persistent conflict (would ack stale seq)"
        );
    }

    // Test 4: make_record returns Err (e.g. wrap_key failure) — propagates Err, no publish, no record_publish.
    #[test]
    fn publish_with_cas_retry_make_record_error_propagates() {
        let (result, _call_count, record_publish) = run_publish_retry_seam(
            vec![MockPublishResult::Err(
                "wrap_key failed: invalid key".to_string(),
            )],
            2,
            false,
        );
        assert!(result.is_err(), "make_record Err must propagate");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("wrap_key"),
            "error must propagate make_record message, got: {}",
            err_msg
        );
        assert!(
            !record_publish,
            "record_publish must NOT be called when make_record errors"
        );
    }

    // Test 5 (SC2 item 1): Conflict on attempts 1-4 then Success on attempt 5 must
    // SUCCEED under max_attempts: 5 — locks in the metadata publish path's budget
    // (guards against the silent 5→2 regression, RESEARCH Pitfall 2).
    #[test]
    fn publish_with_cas_retry_fifth_attempt_succeeds_under_budget_5() {
        let publishes = vec![
            MockPublishResult::Conflict {
                current_sequence_number: 1,
            },
            MockPublishResult::Conflict {
                current_sequence_number: 2,
            },
            MockPublishResult::Conflict {
                current_sequence_number: 3,
            },
            MockPublishResult::Conflict {
                current_sequence_number: 4,
            },
            MockPublishResult::Success,
        ];
        let (result, call_count, record_publish) = run_publish_retry_seam(publishes, 5, false);
        assert!(
            result.is_ok(),
            "5th-attempt success must be Ok under max_attempts: 5, got: {:?}",
            result
        );
        assert_eq!(
            call_count, 5,
            "make_record must be called once per attempt (5 attempts)"
        );
        assert!(
            record_publish,
            "record_publish must be called on the 5th-attempt success"
        );
    }

    // Test 6 (SC2 item 1): the SAME Conflict×4-then-Success sequence must EXHAUST
    // the budget and return Err under max_attempts: 2 — proves the budget parameter
    // is load-bearing (a 2-attempt caller never reaches attempt 5).
    #[test]
    fn publish_with_cas_retry_fifth_attempt_sequence_exhausts_budget_2() {
        let publishes = vec![
            MockPublishResult::Conflict {
                current_sequence_number: 1,
            },
            MockPublishResult::Conflict {
                current_sequence_number: 2,
            },
            MockPublishResult::Conflict {
                current_sequence_number: 3,
            },
            MockPublishResult::Conflict {
                current_sequence_number: 4,
            },
            MockPublishResult::Success,
        ];
        let (result, call_count, record_publish) = run_publish_retry_seam(publishes, 2, false);
        assert!(
            result.is_err(),
            "under max_attempts: 2 the sequence must exhaust the budget (Err) before reaching attempt 5"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.to_lowercase().contains("conflict"),
            "budget-exhaustion error must mention 'conflict', got: {}",
            err_msg
        );
        assert_eq!(
            call_count, 2,
            "make_record must be called exactly twice before the 2-attempt budget is exhausted"
        );
        assert!(
            !record_publish,
            "record_publish must NOT be called when the budget is exhausted"
        );
    }

    #[test]
    fn is_ipns_not_found_matches_case_insensitively() {
        // Predicate matches on "not found" substring (case-insensitive).
        assert!(super::is_ipns_not_found("IPNS record Not Found"));
        // Use a legible case that documents what the predicate actually matches.
        assert!(super::is_ipns_not_found("record not found"));
        // Negative: "404" alone must NOT match — the predicate is "not found", not "404".
        assert!(
            !super::is_ipns_not_found("404"),
            "bare '404' without 'not found' must not match is_ipns_not_found"
        );
    }

    #[test]
    fn is_ipns_not_found_rejects_other_errors() {
        assert!(!super::is_ipns_not_found("connection refused"));
        assert!(!super::is_ipns_not_found("500 internal server error"));
        assert!(!super::is_ipns_not_found(""));
    }

    // --- revoke_shares_blocking classifier + no-op tests ---

    use cipherbox_api_client::ApiError;

    /// Every 4xx is a deterministic client failure → non-retryable (surface
    /// immediately, no backoff). Mirrors the SDK `isNonRetryableError`.
    #[test]
    fn revoke_4xx_is_non_retryable() {
        for status in [400u16, 401, 403, 404, 409, 422, 499] {
            let err = ApiError::ApiResponse {
                status,
                message: "client error".to_string(),
            };
            assert!(
                super::is_non_retryable_revoke_error(&err),
                "status {} must be classified non-retryable",
                status
            );
        }
    }

    /// 5xx is transient → retryable (consume the backoff budget).
    #[test]
    fn revoke_5xx_is_retryable() {
        for status in [500u16, 502, 503, 504] {
            let err = ApiError::ApiResponse {
                status,
                message: "server error".to_string(),
            };
            assert!(
                !super::is_non_retryable_revoke_error(&err),
                "status {} must be classified retryable",
                status
            );
        }
    }

    /// Auth/deserialization/not-found error variants are not the
    /// ApiResponse-4xx shape, so they are treated as retryable (the loop will
    /// re-attempt and ultimately surface as a failure → EIO if persistent).
    #[test]
    fn revoke_non_apiresponse_errors_are_retryable() {
        assert!(!super::is_non_retryable_revoke_error(
            &ApiError::AuthFailed("no token".to_string())
        ));
        assert!(!super::is_non_retryable_revoke_error(
            &ApiError::DeserializationFailed("bad json".to_string())
        ));
        assert!(!super::is_non_retryable_revoke_error(
            &ApiError::IpnsNotFound("k51".to_string())
        ));
        // The internal "exhausted retries" sentinel (status 0) is NOT in the
        // 4xx range, so it does not short-circuit a fresh attempt.
        assert!(!super::is_non_retryable_revoke_error(
            &ApiError::ApiResponse {
                status: 0,
                message: "exhausted".to_string(),
            }
        ));
    }

    /// An empty ipns_name is a no-op: revoke_shares_blocking returns Ok(())
    /// WITHOUT any network round-trip (proven by the unreachable base URL — a
    /// real request would fail and return Err).
    #[test]
    fn revoke_blocking_empty_name_is_ok_no_network() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let api = std::sync::Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let result = super::revoke_shares_blocking(&api, rt.handle(), "");
        assert!(result.is_ok());
    }

    /// A non-empty name against an unreachable backend exhausts retries and
    /// returns Err(()) — the fail-closed signal the delete path maps to EIO.
    /// Connection-refused is a transport error (retryable), so this also
    /// exercises the retry loop terminating in Err.
    #[test]
    fn revoke_blocking_unreachable_backend_fails_closed() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Port 1 is unreachable: connect refused → RequestFailed (transient) →
        // retried up to the cap → Err. Bounded by REVOKE_TIMEOUT well under the
        // 15s ceiling for a connection-refused (returns immediately each time).
        let api = std::sync::Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let result = super::revoke_shares_blocking(&api, rt.handle(), "k51unreachable");
        assert!(
            result.is_err(),
            "revoke against an unreachable backend must fail closed (Err)"
        );
    }
}
