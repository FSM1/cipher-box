//! Background sync daemon for CipherBox SDK.
//!
//! Polls IPNS every 30 seconds for metadata changes, refreshes the inode table
//! when changes are detected, and processes queued offline writes.
//!
//! Uses sequence number comparison (not CID) per project decision from Phase 7.
//! Uses a generic status callback instead of Tauri AppHandle.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::queue::{JournalEntryStatus, WriteQueue};
use crate::state::{KeyState, SyncStatus};

/// Default polling interval for IPNS sync (30 seconds).
pub const SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// The background sync daemon.
///
/// Runs in a tokio task, polling IPNS for metadata changes at a regular interval.
/// Can be triggered manually via the `sync_now_tx` channel from the tray menu.
///
/// Uses a generic `status_callback` function instead of Tauri's AppHandle,
/// allowing the desktop app to bridge status updates to the tray icon while
/// keeping the daemon itself Tauri-free.
pub struct SyncDaemon {
    /// SDK key state (shared with the rest of the app).
    state: Arc<KeyState>,
    /// Generic callback for status updates (replaces Tauri tray integration).
    status_callback: Arc<dyn Fn(SyncStatus) + Send + Sync>,
    /// Poll interval (default 30s).
    poll_interval: Duration,
    /// Cached IPNS sequence numbers: ipns_name -> last known sequence_number.
    cached_sequence_numbers: HashMap<String, u64>,
    /// Channel receiver for manual sync triggers (from tray "Sync Now" button).
    sync_now_rx: mpsc::Receiver<()>,
    /// Whether the last poll attempt detected offline state.
    was_offline: bool,
    /// Durable write journal (cb-journal). Injected at construction so the daemon
    /// reads the same on-disk entries the FUSE layer writes (CR-07).
    write_queue: WriteQueue,
}

impl SyncDaemon {
    /// Create a new sync daemon.
    ///
    /// The `sync_now_rx` channel receives manual sync triggers from the tray menu.
    /// The `status_callback` is invoked on every status change, replacing the
    /// previous Tauri-specific `update_tray_status` calls.
    /// The `write_queue` must point at the same cb-journal directory the FUSE layer uses
    /// so the daemon can observe on-disk `Failed` entries and surface them via `WriteParked`
    /// (CR-07 — no `WriteQueue::default()` allowed; the `Default` impl was removed in 43-05).
    pub fn new(
        state: Arc<KeyState>,
        status_callback: Arc<dyn Fn(SyncStatus) + Send + Sync>,
        poll_interval: Duration,
        sync_now_rx: mpsc::Receiver<()>,
        write_queue: WriteQueue,
    ) -> Self {
        Self {
            state,
            status_callback,
            poll_interval,
            cached_sequence_numbers: HashMap::new(),
            sync_now_rx,
            was_offline: false,
            write_queue,
        }
    }

    /// Main run loop. Call from a spawned tokio task.
    ///
    /// Uses `tokio::select!` to wait on either the periodic tick or a manual trigger.
    /// On each tick: poll IPNS for changes, process write queue.
    pub async fn run(&mut self) {
        let mut ticker = tokio::time::interval(self.poll_interval);
        // The first tick fires immediately; skip it to let the app finish mounting.
        ticker.tick().await;

        log::info!(
            "Sync daemon started (interval: {}s)",
            self.poll_interval.as_secs()
        );

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.sync_cycle().await;
                }
                Some(()) = self.sync_now_rx.recv() => {
                    log::info!("Manual sync triggered");
                    self.sync_cycle().await;
                }
            }
        }
    }

    /// Execute one full sync cycle: poll + process write queue.
    async fn sync_cycle(&mut self) {
        // Check if authenticated
        if !*self.state.is_authenticated.read().await {
            return;
        }

        // Update status to Syncing
        (self.status_callback)(SyncStatus::Syncing);

        match self.poll().await {
            Ok(()) => {
                // Transitioned from offline to online
                if self.was_offline {
                    log::info!("Connectivity restored, resuming sync");
                    self.was_offline = false;
                }

                // Write queue drain is handled by the FUSE layer (Plan 43-02+).
                // The sync daemon observes journal counts and surfaces parked writes
                // to the user via the status_callback (CR-07).
                log::debug!("Sync cycle complete — checking journal for parked writes");

                // CR-07: read on-disk Failed counts from the cb-journal and emit
                // WriteParked when entries are permanently parked.
                //
                // Behavior:
                //   failed > 0  → emit WriteParked{pending, failed} (fires tray notification);
                //                 return immediately without also emitting Idle, so the parked
                //                 state remains the user-visible status for this cycle.
                //   failed == 0 → emit Idle to keep the tray clean.
                //                 pending-only state (transient retries) is silent — the
                //                 bridge in sync/mod.rs ignores WriteParked{failed:0} for
                //                 notifications, so emitting Idle avoids spurious status flap.
                let root_ipns_opt = self.state.root_ipns_name.read().await.clone();
                if let Some(root_ipns_name) = root_ipns_opt {
                    match self.write_queue.load_all_for_vault(&root_ipns_name) {
                        Ok(entries) => {
                            let failed = entries
                                .iter()
                                .filter(|e| matches!(e.status, JournalEntryStatus::Failed { .. }))
                                .count() as u32;
                            let pending = entries
                                .iter()
                                .filter(|e| {
                                    matches!(
                                        e.status,
                                        JournalEntryStatus::Pending | JournalEntryStatus::InProgress
                                    )
                                })
                                .count() as u32;
                            if failed > 0 {
                                (self.status_callback)(SyncStatus::WriteParked { pending, failed });
                                return;
                            }
                        }
                        Err(e) => {
                            log::warn!("Journal read failed during sync cycle: {} — proceeding to Idle", e);
                        }
                    }
                }

                (self.status_callback)(SyncStatus::Idle);
            }
            Err(e) => {
                log::warn!("Sync poll failed: {}", e);

                // Determine if this is a network error (offline) or API error
                if is_network_error(&e) {
                    if !self.was_offline {
                        log::info!("Network appears offline, pausing active sync");
                        self.was_offline = true;
                    }
                    (self.status_callback)(SyncStatus::Error("Offline".to_string()));
                } else {
                    (self.status_callback)(SyncStatus::Error(sanitize_error(&e)));
                }
            }
        }
    }

    /// Poll IPNS for all known folders and detect changes via sequence number comparison.
    ///
    /// For each folder:
    /// 1. Resolve IPNS name to get current sequence number
    /// 2. Compare with cached sequence number
    /// 3. If changed: log the change (metadata cache TTL handles refresh on next FUSE access)
    /// 4. Update cached sequence numbers
    async fn poll(&mut self) -> Result<(), String> {
        // Get root IPNS name
        let root_ipns_name = self
            .state
            .root_ipns_name
            .read()
            .await
            .clone()
            .ok_or_else(|| "Root IPNS name not available".to_string())?;

        // Resolve root folder IPNS
        let resolve_result =
            cipherbox_api_client::ipns::resolve_ipns(&self.state.api, &root_ipns_name)
                .await
                .map_err(|e| e.to_string())?;

        let new_seq = resolve_result
            .sequence_number
            .parse::<u64>()
            .unwrap_or(0);

        let cached_seq = self
            .cached_sequence_numbers
            .get(&root_ipns_name)
            .copied()
            .unwrap_or(0);

        if new_seq != cached_seq {
            log::info!(
                "IPNS change detected for root folder: seq {} -> {}",
                cached_seq,
                new_seq
            );
            self.cached_sequence_numbers
                .insert(root_ipns_name.clone(), new_seq);

            // The metadata cache has a 30s TTL, so the next FUSE readdir/lookup
            // will fetch and decrypt fresh metadata automatically.
            log::info!(
                "Root folder metadata changed (CID: {}). Cache will refresh on next access.",
                resolve_result.cid
            );
        }

        Ok(())
    }

}

/// Sanitize error messages before displaying in tray status or notifications.
///
/// Removes sensitive information that could leak implementation details:
/// - Truncates after first newline or at 80 chars (strips API response bodies)
/// - Replaces internal filesystem paths with `[path]`
/// - Replaces long hex strings (>40 chars) that may be tokens with `[token]`
fn sanitize_error(error: &str) -> String {
    // Truncate at first newline or 80 chars, whichever is shorter
    let truncated = error.split('\n').next().unwrap_or(error);
    let truncated = if truncated.len() > 80 {
        // Find the last char boundary at or before byte 80
        let mut boundary = 80;
        while boundary > 0 && !truncated.is_char_boundary(boundary) {
            boundary -= 1;
        }
        format!("{}...", &truncated[..boundary])
    } else {
        truncated.to_string()
    };

    // Remove internal filesystem paths
    let sanitized = regex_replace_paths(&truncated);

    // Remove token-like hex strings (>40 hex chars)
    regex_replace_tokens(&sanitized)
}

/// Replace filesystem paths like /Users/... or /home/... with [path].
fn regex_replace_paths(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        // Unix absolute paths (/Users, /home, /var, /tmp, /private) or Windows drive-letter
        // paths (C:\Users\ ...). Both are scrubbed to [path] by skipping to the next boundary.
        let is_path_start = (c == '/'
            && (input[i..].starts_with("/Users/")
                || input[i..].starts_with("/home/")
                || input[i..].starts_with("/var/")
                || input[i..].starts_with("/tmp/")
                || input[i..].starts_with("/private/")))
            || (c.is_ascii_uppercase()
                && i + 2 < input.len()
                && input[i + 1..].starts_with(":\\Users\\"));

        if is_path_start {
            result.push_str("[path]");
            // Skip until the next whitespace or quote boundary (or end of input).
            while let Some(&(_, next_c)) = chars.peek() {
                if next_c.is_whitespace() || next_c == '"' || next_c == '\'' {
                    break;
                }
                chars.next();
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Replace long hex strings (>40 chars) with [token].
fn regex_replace_tokens(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut hex_run = String::new();

    for c in input.chars() {
        if c.is_ascii_hexdigit() {
            hex_run.push(c);
        } else {
            if hex_run.len() > 40 {
                result.push_str("[token]");
            } else {
                result.push_str(&hex_run);
            }
            hex_run.clear();
            result.push(c);
        }
    }

    // Flush trailing hex run
    if hex_run.len() > 40 {
        result.push_str("[token]");
    } else {
        result.push_str(&hex_run);
    }

    result
}

/// Heuristic check for network-level errors vs application errors.
fn is_network_error(error: &str) -> bool {
    let network_patterns = [
        "dns error",
        "connect error",
        "connection refused",
        "network unreachable",
        "timed out",
        "timeout",
        "no route to host",
        "network is down",
        "couldn't resolve host",
    ];
    let lower = error.to_lowercase();
    network_patterns.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_error_extended_paths() {
        // Existing behavior preserved: /Users and /home are scrubbed.
        assert_eq!(
            sanitize_error("open /Users/alice/secret.txt failed"),
            "open [path] failed"
        );
        assert_eq!(sanitize_error("read /home/bob/x denied"), "read [path] denied");

        // New Unix prefixes (D-05).
        assert_eq!(
            sanitize_error("stat /var/folders/zz/foo nope"),
            "stat [path] nope"
        );
        assert_eq!(
            sanitize_error("write /tmp/cb-journal/abc oops"),
            "write [path] oops"
        );
        assert_eq!(
            sanitize_error("link /private/var/foo bad"),
            "link [path] bad"
        );

        // Windows drive-letter paths (any ASCII uppercase letter).
        assert_eq!(
            sanitize_error("open C:\\Users\\carol\\AppData\\file failed"),
            "open [path] failed"
        );
        assert_eq!(
            sanitize_error("open D:\\Users\\dave\\thing failed"),
            "open [path] failed"
        );

        // No path prefix → unchanged.
        assert_eq!(
            sanitize_error("generic error with no path"),
            "generic error with no path"
        );

        // Scrub stops at the first whitespace/quote boundary, not the whole message.
        assert_eq!(
            sanitize_error("a /Users/eve/x and /home/frank/y end"),
            "a [path] and [path] end"
        );
    }
}
