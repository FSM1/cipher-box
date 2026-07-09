//! Grant-root scope-computation building block, shared by BOTH platforms.
//!
//! This is the one piece of grant-root scope awareness with no TS analog: the
//! TS client never had a mounted filesystem tree to walk (design §3.9). It has
//! two halves:
//!
//! 1. **Ancestor walk (novel):** [`ancestor_ipns_chain`] computes a mutated
//!    inode's leaf-first ancestor IPNS-name chain by walking `parent_ino` up
//!    to `ROOT_INO` in the already-mounted [`crate::inode::InodeTable`] —
//!    O(depth), purely local, NO network call.
//! 2. **Grant-set source (Pitfall 2):** [`SentSharesCache`] is a local cache of
//!    the authenticated user's sent shares, refreshed out-of-band (mount init
//!    / periodic — see [`refresh_sent_shares`]) from
//!    `cipherbox_api_client::shares::collect_sent_shares` (69-03). It is never
//!    queried synchronously per-mutation (T-69-07-01).
//!
//! [`build_coverage_params`] and [`grant_root_for`] both WRAP
//! `cipherbox_sdk::rotation::scope::has_covering_grant` (69-05) — they do NOT
//! reimplement the coverage predicate (Pitfall 1).
//!
//! Hoisted here (rather than duplicated per platform) so BOTH the Unix write
//! handlers (69-11) and the Windows write handlers (69-14) consume the SAME
//! ancestor-walk + `has_covering_grant` call site (T-69-07-03).

use std::collections::HashSet;
use std::future::Future;

use cipherbox_api_client::shares::{collect_sent_shares, SentShareResponse};
use cipherbox_api_client::{ApiClient, ApiError};
use cipherbox_core::node::SealedChildRef;
use cipherbox_sdk::rotation::scope::{
    has_covering_grant, CoverageParams, LocalGrantRecord, ScopeExitResult,
};
use cipherbox_sdk::rotation::RotationError;
use cipherbox_sdk::RotateReadResult;

use crate::inode::{InodeKind, InodeTable, ROOT_INO};

// ---------------------------------------------------------------------------
// Ancestor walk — purely local, zero network calls
// ---------------------------------------------------------------------------

/// Compute the mutated node's leaf-first ancestor IPNS-name chain by walking
/// `parent_ino` from `start_ino` up to `ROOT_INO` in the already-mounted
/// `InodeTable`.
///
/// Leaf-first: the node itself is first (its own IPNS name, if any — a
/// `Folder`/`Root`'s `ipns_name` or a resolved `File`'s
/// `file_meta_ipns_name`), the vault root is last. O(depth) — a single pass
/// up the tree already held in memory. NO IPNS resolve / api-client / network
/// call (design §3.9; the anti-pattern this guards against is resolving
/// ancestry over the network).
pub fn ancestor_ipns_chain(inodes: &InodeTable, start_ino: u64) -> AncestorChain {
    let mut names = Vec::new();
    let mut visited = HashSet::new();
    let mut current_ino = start_ino;
    let mut reached_root = false;

    loop {
        // Cycle guard: a well-formed tree never revisits an inode, but this
        // keeps the walk O(depth)-bounded even over corrupt/synthetic state
        // rather than looping forever. A cycle means the walk did NOT reach
        // ROOT_INO cleanly (D-15b) — `reached_root` stays `false`.
        if !visited.insert(current_ino) {
            break;
        }

        // A missing inode (dangling `parent_ino`, corrupt/synthetic state)
        // also means the walk did NOT reach ROOT_INO cleanly (D-15b).
        let Some(inode) = inodes.get(current_ino) else {
            break;
        };

        match &inode.kind {
            // node/v3: Root/Folder/File all carry a plain `ipns_name: String`.
            // An empty string (Root pre-init, or a never-published File)
            // contributes nothing to the chain.
            InodeKind::Root { ipns_name, .. }
            | InodeKind::Folder { ipns_name, .. }
            | InodeKind::File { ipns_name, .. } => {
                if !ipns_name.is_empty() {
                    names.push(ipns_name.clone());
                }
            }
        }

        if current_ino == ROOT_INO {
            reached_root = true;
            break;
        }
        current_ino = inode.parent_ino;
    }

    AncestorChain {
        names,
        reached_root,
    }
}

/// Result of walking a mutated node's ancestor chain up to `ROOT_INO`.
///
/// `reached_root` distinguishes a CLEAN walk (terminated at `ROOT_INO`) from
/// one that broke early on a missing inode or a cycle. [`gate_scope_exit`]
/// treats `reached_root == false` as fail-closed (D-15b MAJOR) — a partial
/// chain must NEVER be treated as a clean "no grant found" walk, since it may
/// have omitted the true grant-root ancestor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorChain {
    /// Leaf-first IPNS-name chain: the mutated node itself first, the vault
    /// root last (when `reached_root` is `true`).
    pub names: Vec<String>,
    /// `true` only if the walk reached `ROOT_INO` cleanly — no missing
    /// inode, no cycle.
    pub reached_root: bool,
}

// ---------------------------------------------------------------------------
// SentSharesCache — local grant-set source (Pitfall 2)
// ---------------------------------------------------------------------------

/// Local, in-memory cache of the authenticated user's sent shares.
///
/// Refreshed out-of-band via [`refresh_sent_shares`] (mount init / periodic),
/// NEVER inline on the delete/rename hot path (T-69-07-01). Consumers read
/// this cache synchronously through [`build_coverage_params`].
#[derive(Debug, Clone, Default)]
pub struct SentSharesCache {
    root_ipns_names: HashSet<String>,
    /// D-15a (CRITICAL): `true` only after a successful `/shares/sent`
    /// refresh has completed this session ([`Self::from_sent_shares`]).
    /// `false` for [`Self::empty`] / [`Default::default`] — the
    /// pre-first-refresh (or failed-refresh) state.
    ///
    /// [`gate_scope_exit`] fails closed (`Err` -> EIO) while this is
    /// `false`, REGARDLESS of whether `root_ipns_names` happens to be
    /// empty (Pitfall 8: the trigger is authoritativeness, NOT emptiness —
    /// a naive "empty -> Err" would incorrectly block every private delete
    /// once the cache has legitimately refreshed to zero shares).
    is_authoritative: bool,
}

impl SentSharesCache {
    /// An empty, NON-authoritative cache — the state before the first
    /// refresh completes (or after a failed refresh). [`gate_scope_exit`]
    /// fails closed on this state (D-15a).
    pub fn empty() -> Self {
        Self {
            root_ipns_names: HashSet::new(),
            is_authoritative: false,
        }
    }

    /// Build a cache from a raw `collect_sent_shares` response. Pure and
    /// synchronous so it is unit-testable without a live HTTP server. A
    /// successful refresh is ALWAYS authoritative, even when `shares` is
    /// empty — a genuinely-empty refreshed cache still allows private
    /// deletes with zero rotation (D-15a / Pitfall 8).
    pub fn from_sent_shares(shares: &[SentShareResponse]) -> Self {
        Self {
            root_ipns_names: shares.iter().map(|s| s.root_ipns_name.clone()).collect(),
            is_authoritative: true,
        }
    }

    /// The set of root IPNS names this client has actively shared out.
    pub fn root_ipns_names(&self) -> &HashSet<String> {
        &self.root_ipns_names
    }
}

/// Refresh a [`SentSharesCache`] from the relay's `GET /shares/sent`
/// (paginated via `collect_sent_shares`, 69-03).
///
/// Intended call sites: mount init and a periodic background refresh (NOT a
/// per-mutation call — Pitfall 2 / T-69-07-01). The ancestor-walk +
/// `has_covering_grant` call site reads the resulting cache synchronously
/// via [`build_coverage_params`], never this function inline.
pub async fn refresh_sent_shares(api: &ApiClient) -> Result<SentSharesCache, ApiError> {
    let shares = collect_sent_shares(api).await?;
    Ok(SentSharesCache::from_sent_shares(&shares))
}

/// Cadence for the background sent-shares refresh (grant-root awareness).
/// Matches the app's 30s IPNS-poll rhythm: short enough that a folder shared
/// AFTER mount is covered by the scope-exit gate within one cycle (closing the
/// stale-cache fail-open window), without hammering `/shares/sent`.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub const SENT_SHARES_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Install a freshly-refreshed [`SentSharesCache`] into a shared slot,
/// recovering a poisoned lock (D-15c).
///
/// A successfully-refreshed AUTHORITATIVE cache is always safe to install
/// regardless of any prior poisoning, so recover the guard via `into_inner`
/// and clear the poison flag rather than panicking or leaving the gate
/// permanently failing closed until remount. Shared by
/// [`crate::CipherBoxFS::refresh_sent_shares`] and the periodic background
/// task ([`spawn_periodic_sent_shares_refresh`]) so both use identical
/// poison-recovery semantics.
pub fn install_sent_shares_cache(
    slot: &std::sync::RwLock<SentSharesCache>,
    cache: SentSharesCache,
) {
    match slot.write() {
        Ok(mut guard) => *guard = cache,
        Err(poisoned) => {
            log::error!(
                "install_sent_shares_cache: sent_shares RwLock was poisoned by a prior \
                 panicked holder — installing the freshly-refreshed authoritative cache \
                 and clearing the poison flag (D-15c)"
            );
            *poisoned.into_inner() = cache;
            slot.clear_poison();
        }
    }
}

/// Spawn the periodic background sent-shares refresh on `rt`.
///
/// Refreshes `sent_shares` every `interval` from `GET /shares/sent`, keeping
/// grant-root awareness fresh so a folder shared AFTER mount is still covered
/// by the scope-exit gate — closing the stale-cache fail-open window that a
/// one-shot mount-init refresh alone would leave. A failed refresh keeps the
/// prior cache (logged, non-fatal); this is NEVER the per-mutation hot path
/// (Pitfall 2 / T-69-07-01).
///
/// The first tick fires immediately (default `tokio::time::interval`
/// behavior), so the loop also RECOVERS a failed/timed-out mount-init refresh
/// promptly rather than waiting a full `interval`. Fire-and-forget: the task
/// lives for the mount's lifetime and is torn down when the runtime shuts
/// down at unmount.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_periodic_sent_shares_refresh(
    rt: &tokio::runtime::Handle,
    api: std::sync::Arc<ApiClient>,
    sent_shares: std::sync::Arc<std::sync::RwLock<SentSharesCache>>,
    interval: std::time::Duration,
) {
    rt.spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            match refresh_sent_shares(&api).await {
                Ok(cache) => install_sent_shares_cache(&sent_shares, cache),
                Err(e) => {
                    log::warn!(
                        "periodic sent-shares refresh failed (keeping prior cache): {}",
                        e
                    )
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Coverage-params builder + grant-root selection — wrap has_covering_grant
// ---------------------------------------------------------------------------

/// Build `cipherbox_sdk::rotation::scope::CoverageParams` from an ancestor
/// chain and the local sent-shares cache.
///
/// `active_grant_root_ipns_names` is the cache's full root-IPNS-name set (the
/// relay-supplied completeness aid, §3.9). `local_grant_record` mirrors the
/// shipped web/SDK pattern (`rotation-driver.service.ts` `getLocalGrantRecord`):
/// the first ancestor (leaf-first) that matches a cached grant root becomes
/// the client-authoritative anti-malicious-relay cross-check (T-63-17).
pub fn build_coverage_params(ancestors: &[String], sent_cache: &SentSharesCache) -> CoverageParams {
    let active_grant_root_ipns_names = sent_cache.root_ipns_names().clone();
    let local_grant_record = ancestors
        .iter()
        .find(|ancestor| active_grant_root_ipns_names.contains(*ancestor))
        .map(|ancestor| LocalGrantRecord {
            root_ipns_name: ancestor.clone(),
        });

    CoverageParams {
        node_ancestor_ipns_names: ancestors.to_vec(),
        active_grant_root_ipns_names,
        local_grant_record,
    }
}

/// Return the FIRST leaf-first ancestor that is a covering grant root — the
/// node to rotate FROM (a deep delete rotates from the shared-folder root,
/// not the leaf; Pattern 1(b)).
///
/// WRAPS `has_covering_grant` (69-05) per-ancestor rather than reimplementing
/// the membership/cross-check logic (Pitfall 1) — each candidate ancestor is
/// checked via a single-element `CoverageParams` reusing the same predicate.
pub fn grant_root_for(ancestors: &[String], params: &CoverageParams) -> Option<String> {
    for ancestor in ancestors {
        let candidate = CoverageParams {
            node_ancestor_ipns_names: vec![ancestor.clone()],
            active_grant_root_ipns_names: params.active_grant_root_ipns_names.clone(),
            local_grant_record: params.local_grant_record.clone(),
        };
        if has_covering_grant(&candidate) {
            return Some(ancestor.clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Scope-exit gate — the ONE rule, shared by every Unix delete/rename site
// ---------------------------------------------------------------------------

/// SC#3 / ROT-02 grant-scope gate for a delete/rename scope-exit.
///
/// Walks the mutated node's leaf-first ancestor IPNS chain
/// ([`ancestor_ipns_chain`]) and cross-checks it against the local sent-shares
/// cache ([`build_coverage_params`] → [`grant_root_for`], which WRAP
/// `cipherbox_sdk::rotation::scope::has_covering_grant`, 69-05). This gate
/// NEVER re-implements the coverage predicate (research landmine 10).
///
/// - **No covering grant (private):** returns [`ScopeExitResult::NoRotation`]
///   WITHOUT invoking `rotate`. The caller performs a PURE parent relink
///   (reseal the parent's `SealedChildRef` list, republish the PARENT ONLY) —
///   ZERO rotation, ZERO extra IPNS publishes (ROT-02 / SC#3 zero-rotation
///   invariant). This is also the D-08 (Q3 Model a) path: a write-recipient's
///   out-of-scope delete/move unlinks+bins ONLY — no cross-principal revoke is
///   ever issued here, and no new schema is introduced.
/// - **Covering grant (shared-scope exit):** invokes `rotate` EXACTLY ONCE,
///   passing the matched grant-root ipns_name (`grant_root_for` — the closest
///   leaf-first ancestor that is a grant root, i.e. the node to rotate FROM).
///
/// `rotate` is injectable so tests assert the call count with a spy (mirroring
/// the sdk `maybe_rotate_on_scope_exit` spy pattern). A `rotate` error
/// propagates as `Err` — fail-closed, never swallowed.
///
/// # Fail-closed gate-correctness (D-15a/b, CodeRabbit Phase 69 ship review)
/// Two conditions surface `Err` BEFORE the coverage check ever runs, so a
/// genuinely-uncertain state can never be silently mistaken for "no covering
/// grant":
/// - **D-15a:** `sent_cache` is NOT authoritative (no successful
///   `/shares/sent` refresh has completed this session, or the last one
///   failed) — an empty-looking cache in that state may just mean "not yet
///   refreshed", not "nothing is shared". A legitimately-empty
///   AUTHORITATIVE cache still proceeds to the coverage check (and yields
///   `NoRotation`) — the trigger is authoritativeness, never emptiness
///   (Pitfall 8).
/// - **D-15b:** the ancestor walk did NOT reach `ROOT_INO` cleanly (a
///   missing inode or a cycle) — a partial chain may have omitted the true
///   grant-root ancestor, so it is treated as unsafe rather than
///   `NoRotation`.
///
/// # Security
/// D-07 dual-keying: the grant-root passed to `rotate` is a READ-plane key
/// (`SealedChildRef.ipns_name`). The caller is responsible for threading the
/// WRITE-plane key (`WriteChildRef.child_id` = `uuid_from_ino`) separately —
/// the two key spaces MUST NOT be conflated (see [`rotate_read_on_scope_exit`]).
pub async fn gate_scope_exit<F, Fut>(
    inodes: &InodeTable,
    start_ino: u64,
    sent_cache: &SentSharesCache,
    rotate: F,
) -> Result<ScopeExitResult, RotationError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(), RotationError>>,
{
    match detect_scope_exit(inodes, start_ino, sent_cache)? {
        // ROT-02 / SC#3: no covering grant → zero rotation, zero extra
        // publishes. The caller's parent relink is the entire durable effect.
        None => Ok(ScopeExitResult::NoRotation),
        // Covered scope-exit: rotate the read key from the matched grant-root
        // ancestor EXACTLY ONCE. `detect_scope_exit`/`grant_root_for`
        // short-circuits at the first (closest, leaf-first) matching ancestor,
        // so this fires once per scope-exit regardless of how many ancestors
        // are grant roots.
        Some(grant_root_ipns_name) => {
            rotate(grant_root_ipns_name).await?;
            Ok(ScopeExitResult::Rotated)
        }
    }
}

/// The DETECTION half of the scope-exit gate (70.1-13a split): walks the
/// mutated node's leaf-first ancestor chain and cross-checks it against the
/// local sent-shares cache, returning the grant-root ipns to rotate FROM
/// (`Some`) or `None` for a private mutation. Fails closed (`Err`) on the
/// D-15a/D-15b conditions BEFORE any coverage decision.
///
/// Purely synchronous and side-effect-free (no rotation, no network) so it can
/// be run under an IMMUTABLE `&InodeTable` borrow, then dropped before the
/// caller takes a `&mut CipherBoxFS` borrow to perform the rotation +
/// post-rotation inode-key refresh ([`rotate_read_on_scope_exit`]). This split
/// is what makes the borrow-checker-safe `&mut` threading (and the coalescing
/// reorder) possible without weakening any gate check.
pub fn detect_scope_exit(
    inodes: &InodeTable,
    start_ino: u64,
    sent_cache: &SentSharesCache,
) -> Result<Option<String>, RotationError> {
    let chain = ancestor_ipns_chain(inodes, start_ino);

    // D-15b: an incomplete ancestor walk must never be treated as a clean
    // "no covering grant" result — it may have silently dropped the true
    // grant-root ancestor.
    if !chain.reached_root {
        return Err(RotationError::RotateFailed(format!(
            "scope-exit gate: ancestor walk from ino={start_ino} did not reach ROOT_INO \
             (missing inode or cycle) — failing closed rather than risking a silent \
             revocation bypass (D-15b)"
        )));
    }

    // D-15a: a non-authoritative sent-shares cache must never look like "no
    // shares -> private -> NoRotation". The gate fails closed until a
    // successful refresh has completed — NEVER gated on
    // `root_ipns_names().is_empty()` (Pitfall 8).
    if !sent_cache.is_authoritative {
        return Err(RotationError::RotateFailed(
            "scope-exit gate: sent-shares cache is not authoritative (no successful \
             refresh has completed yet, or the last refresh failed) — failing closed \
             rather than risking a silent revocation bypass (D-15a)"
                .to_string(),
        ));
    }

    let params = build_coverage_params(&chain.names, sent_cache);
    Ok(grant_root_for(&chain.names, &params))
}

/// Live read-key rotation for a shared-scope exit (SC#3): rotate the read key
/// from the matched grant-root node EXACTLY ONCE via
/// `cipherbox_sdk::rotation::engine::rotate_read_from_node` (69-08).
///
/// # Security — D-07 dual-keying (HARD CONSTRAINT)
/// `grant_root_ipns_name` is the READ-plane key (`SealedChildRef.ipns_name`);
/// `deleted_child_id` is the WRITE-plane key (`WriteChildRef.child_id` =
/// `crate::fs::uuid_from_ino`). They index two DISTINCT key spaces and must
/// NEVER be conflated — conflating them silently breaks `rotateWriteFromNode`
/// (project invariant). Both are threaded here as separate parameters.
/// `crates/fuse/src/write_ops/` is flagged for explicit security review.
///
/// # LIVE-WIRED (D-14, Plan 70.1-09)
/// Constructs the production `crate::write_ops::rotation_deps::
/// FuseRotationDeps` adapter (over `ApiClientTransport`) from `fs`, resolves
/// the grant-root's stable `node_id` + current `read_key` from the
/// locally-mounted inode table, and drives
/// `cipherbox_sdk::rotate_read_from_node`. A rotation failure (including the
/// grant-root not being found locally) still fails CLOSED here (`Err` → EIO
/// at the caller) — never a silent no-rotation, which would leave a removed
/// reader with continued access (the exact revocation-bypass this gate
/// exists to prevent). Private deletes never reach this seam.
/// # Coalescing + revocation-bypass fix (70.1-13a)
/// Takes `&mut CipherBoxFS` so that, after a successful rotation, the
/// grant-root inode's in-memory `read_key` is refreshed to the freshly-minted
/// post-rotation key (the caller contract `RotateReadResult` documents,
/// `engine.rs`). Without this refresh, a later local relink of that folder
/// reseals it under the STALE pre-rotation key, republishing a record the
/// revoked reader can still decrypt — the exact Bob-bypass this fixes.
///
/// `root_children_override`, when `Some`, is the grant-root's POST-delete
/// read-plane child list (a covered scope-exit delete where the grant-root IS
/// the deleted node's direct parent). The rotation then republishes the
/// grant-root already reflecting the deletion under the new key as the SINGLE
/// authoritative publish, so the caller SKIPS the separate parent relink
/// (no stale-key record, minimal publishes). `None` preserves the prior
/// behavior (rename / deep scope-exit / WinFsp), where the caller still runs
/// its own post-rotation relink (now correctly resealed under the refreshed
/// key).
pub async fn rotate_read_on_scope_exit(
    fs: &mut crate::CipherBoxFS,
    grant_root_ipns_name: &str,
    deleted_child_id: &str,
    root_children_override: Option<Vec<SealedChildRef>>,
) -> Result<(), RotationError> {
    // ipns_name (read plane) and child UUID (write plane) are PUBLIC
    // identifiers, not key material — safe to log (CLAUDE.md rule 2).
    let Some((root_node_id, root_read_key)) =
        crate::write_ops::rotation_deps::find_grant_root_state(&fs.inodes, grant_root_ipns_name)
    else {
        return Err(RotationError::RotateFailed(format!(
            "rotate_read_on_scope_exit: grant-root {grant_root_ipns_name} not found in the \
             local inode table (write-plane child_id={deleted_child_id})"
        )));
    };

    // Scope the immutable `deps` borrow of `fs` so it is dropped BEFORE the
    // post-rotation `&mut fs.inodes` refresh below (no overlapping borrows).
    let outcome = {
        let deps = crate::write_ops::rotation_deps::FuseRotationDeps::new(
            crate::write_ops::rotation_deps::ApiClientTransport {
                api: fs.api.as_ref(),
                inodes: &fs.inodes,
            },
            fs.public_key.to_vec(),
            fs.private_key.to_vec(),
            fs.rotation_checkpoint_store.clone(),
        );
        let mut job = cipherbox_sdk::RotationJobRecord::new(root_node_id.clone());
        match root_children_override {
            Some(children) => {
                cipherbox_sdk::rotate_read_from_node_with_root_children(
                    &deps,
                    &root_node_id,
                    grant_root_ipns_name,
                    root_read_key.as_slice(),
                    &mut job,
                    children,
                )
                .await
            }
            None => {
                cipherbox_sdk::rotate_read_from_node(
                    &deps,
                    &root_node_id,
                    grant_root_ipns_name,
                    root_read_key.as_slice(),
                    &mut job,
                )
                .await
            }
        }
    };

    match outcome {
        Ok(maybe_result) => {
            // 70.1-13a (revocation-bypass fix): refresh the grant-root inode's
            // in-memory read key so any subsequent local publish reseals under
            // the NEW key. `fresh_root` is `None` on a resume-skip; nothing to
            // refresh in that case.
            if let Some(result) = maybe_result {
                refresh_grant_root_read_key(&mut fs.inodes, grant_root_ipns_name, &result);
            }
            log::info!(
                "shared-scope-exit read-key rotation completed \
                 (read-plane grant_root ipns={}, write-plane child_id={})",
                grant_root_ipns_name,
                deleted_child_id,
            );
            Ok(())
        }
        Err(e) => {
            log::error!(
                "shared-scope-exit read-key rotation FAILED (read-plane grant_root ipns={}, \
                 write-plane child_id={}): {} — failing closed",
                grant_root_ipns_name,
                deleted_child_id,
                e,
            );
            Err(e)
        }
    }
}

/// 70.1-13a (revocation-bypass fix): overwrite the grant-root inode's in-memory
/// `read_key` with the freshly-minted post-rotation key. D-09 terminal-owner:
/// the inode owns its `Zeroizing` buffer; the 32 bytes are overwritten in place
/// (the old key is thereby discarded). `result.read_key` is NOT zeroed here —
/// `RotateReadResult` owns it and self-zeroes on drop. Key bytes are NEVER
/// logged.
fn refresh_grant_root_read_key(
    inodes: &mut InodeTable,
    grant_root_ipns_name: &str,
    result: &RotateReadResult,
) {
    for inode in inodes.inodes.values_mut() {
        match &mut inode.kind {
            InodeKind::Root {
                ipns_name,
                read_key,
                ..
            }
            | InodeKind::Folder {
                ipns_name,
                read_key,
                ..
            } if ipns_name.as_str() == grant_root_ipns_name => {
                read_key.copy_from_slice(result.read_key.as_slice());
                return;
            }
            _ => {}
        }
    }
}

/// Detection-only half of the scope-exit gate for a mutation of `ino`, run
/// under an immutable `&CipherBoxFS` borrow (70.1-13a). Returns the grant-root
/// ipns to rotate FROM (`Some`) or `None` for a private mutation; `Err(())`
/// on a poisoned cache (D-15c) or a fail-closed D-15a/D-15b condition. The
/// caller then takes a `&mut` borrow to perform the rotation
/// ([`rotate_read_on_scope_exit`]) — this split keeps the ancestor walk's
/// immutable borrow disjoint from the rotation's mutable inode-key refresh.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn detect_scope_exit_grant_root(
    fs: &crate::CipherBoxFS,
    ino: u64,
) -> Result<Option<String>, ()> {
    let sent_cache = match fs.sent_shares.read() {
        Ok(guard) => guard.clone(),
        Err(_poisoned) => {
            log::error!(
                "scope-exit gate: sent_shares RwLock is poisoned (a prior writer \
                 panicked while holding it) — failing closed (EIO) rather than \
                 panicking the fuser callback thread (D-15c)"
            );
            return Err(());
        }
    };
    detect_scope_exit(&fs.inodes, ino, &sent_cache).map_err(|e| {
        log::error!("scope-exit gate failed (fail-closed): {}", e);
    })
}

/// Drive the SC#3 scope-exit gate for a mutation of `ino` (unlink / rmdir /
/// cross-folder rename) against the live `CipherBoxFS` state — the single call
/// site shared by every Unix delete/rename handler (§3.8 "one rule, four call
/// sites").
///
/// Reads the local sent-shares cache synchronously (Pitfall 2 / T-69-07-01 —
/// NEVER a per-mutation network fetch) and blocks the fuser callback thread on
/// [`gate_scope_exit`] via `fs.rt.block_on` (the same pattern the replaced
/// `revoke_shares_blocking` used). Returns `Ok(())` on a private delete (zero
/// rotation) or a successfully-rotated shared-scope exit; `Err(())` on a
/// rotation failure — the caller maps that to EIO and aborts the destructive
/// removal (fail-closed).
///
/// SECURITY-REVIEW: D-07 dual-keying — the write plane is keyed by `child_id`
/// (`crate::fs::uuid_from_ino`, `WriteChildRef.child_id`) and the read plane by
/// `ipns_name` (`SealedChildRef.ipns_name` / the grant-root). The two key
/// spaces are threaded as SEPARATE values into [`rotate_read_on_scope_exit`]
/// and MUST NEVER be conflated. `crates/fuse/src/write_ops/` is flagged for
/// explicit security review.
///
/// # D-15c (MAJOR) — poisoned-lock handling
/// A poisoned `sent_shares` `RwLock` (a prior holder panicked while writing
/// it) returns `Err(())` here — NEVER `.expect(...)`-panics the calling
/// fuser callback thread, which would wedge the mount (a denial of service).
/// This is consistent with the surrounding `Result<(), ()>` flow: a poisoned
/// cache is treated the same as any other fail-closed gate outcome.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn run_scope_exit_gate(fs: &mut crate::CipherBoxFS, ino: u64) -> Result<(), ()> {
    // Write-plane key (D-07): the mutated node's stable id (its stored node_id ==
    // real published.id), kept DISTINCT from the read-plane grant-root ipns_name
    // threaded into the rotate seam below. Sourced from the inode, NOT
    // uuid_from_ino(ino), so a materialized shared node exits scope on its real
    // write-plane key. Falls back to uuid_from_ino only if the inode is missing.
    let child_id = fs
        .inodes
        .get(ino)
        .map(|i| i.node_id.clone())
        .unwrap_or_else(|| crate::fs::uuid_from_ino(ino));

    // 70.1-13a: detect coverage under an immutable borrow FIRST (D-15a/b/c
    // fail-closed preserved), then rotate under a `&mut` borrow so the
    // post-rotation inode-key refresh can run. `rt` is cloned so `block_on`
    // does not itself borrow `fs`, leaving the closure free to take `&mut fs`.
    let grant_root_ipns_name = match detect_scope_exit_grant_root(fs, ino)? {
        // Private mutation: zero rotation. The caller's own relink is the
        // entire durable effect (ROT-02 / SC#3 zero-rotation invariant).
        None => return Ok(()),
        Some(name) => name,
    };
    let rt = fs.rt.clone();
    rt.block_on(rotate_read_on_scope_exit(
        fs,
        &grant_root_ipns_name,
        &child_id,
        None,
    ))
    .map_err(|e| {
        log::error!("scope-exit gate failed (fail-closed): {}", e);
    })
}

/// 70.1-13a COALESCED scope-exit gate for a DELETE of `child_ino` whose direct
/// parent is `parent_ino` (unlink / rmdir / WinFsp set_delete). This is the
/// SINGLE shared implementation used by BOTH the fuser `delete.rs` handlers and
/// the WinFsp `write_ops.rs` handlers, so the coalescing logic cannot drift
/// between platforms.
///
/// Behaviour = [`run_scope_exit_gate`] plus coalescing: on a SHALLOW covered
/// scope-exit (the matched grant-root IS `parent_ino`), the rotation is driven
/// with the POST-delete child list ([`crate::CipherBoxFS::build_scope_exit_child_override`],
/// which mutates NO state — fail-closed until the rotation succeeds), so the
/// rotation republishes the grant-root as the SINGLE authoritative publish
/// (post-delete, new key) and the caller MUST suppress its own parent relink.
/// A deep scope-exit, a private delete, or a non-covered mutation returns
/// `Ok(false)` and the caller performs its normal relink (now resealed under
/// the Fix-A-refreshed key when a rotation ran).
///
/// Returns:
/// - `Ok(true)`  — shallow covered scope-exit coalesced; the caller MUST SKIP
///   its plain `update_folder_metadata(parent)` relink.
/// - `Ok(false)` — private / deep / non-covered; the caller relinks as normal.
/// - `Err(())`   — fail-closed (poisoned cache / D-15a / D-15b / rotation
///   failure); the caller maps this to EIO / STATUS_ACCESS_DENIED and aborts.
///
/// D-07 dual-keying and the D-15a/b/c fail-closed conditions are preserved
/// exactly as in [`run_scope_exit_gate`].
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn run_scope_exit_gate_coalesced(
    fs: &mut crate::CipherBoxFS,
    child_ino: u64,
    parent_ino: u64,
) -> Result<bool, ()> {
    // Write-plane key (D-07): the mutated node's stable id, kept DISTINCT from
    // the read-plane grant-root ipns_name.
    let child_id = fs
        .inodes
        .get(child_ino)
        .map(|i| i.node_id.clone())
        .unwrap_or_else(|| crate::fs::uuid_from_ino(child_ino));

    // Detect coverage under an immutable borrow FIRST (D-15a/b/c fail-closed).
    let grant_root_ipns_name = match detect_scope_exit_grant_root(fs, child_ino)? {
        None => return Ok(false),
        Some(name) => name,
    };

    // Shallow scope-exit? (the grant-root IS the deleted node's direct parent).
    // If so, build the post-delete child list WITHOUT mutating state (the child
    // inode is only removed after the rotation succeeds — fail-closed) and drive
    // the coalesced single publish.
    let parent_ipns = fs
        .inodes
        .get(parent_ino)
        .map(|p| match &p.kind {
            InodeKind::Root { ipns_name, .. } | InodeKind::Folder { ipns_name, .. } => {
                ipns_name.clone()
            }
            _ => String::new(),
        })
        .unwrap_or_default();
    let root_children_override = if !parent_ipns.is_empty() && parent_ipns == grant_root_ipns_name {
        // Fail closed: an incomplete override would drop children from the
        // grant-root's republished read plane (silent orphaning), so a build
        // failure aborts the whole scope-exit rather than publishing a short list.
        match fs.build_scope_exit_child_override(parent_ino, child_ino) {
            Ok(children) => Some(children),
            Err(e) => {
                log::error!("scope-exit coalesced child override failed (fail-closed): {}", e);
                return Err(());
            }
        }
    } else {
        None
    };
    let coalesced = root_children_override.is_some();

    let rt = fs.rt.clone();
    rt.block_on(rotate_read_on_scope_exit(
        fs,
        &grant_root_ipns_name,
        &child_id,
        root_children_override,
    ))
    .map(|()| coalesced)
    .map_err(|e| {
        log::error!("scope-exit gate failed (fail-closed): {}", e);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::{FileAttrs, InodeData};
    use std::time::SystemTime;
    use zeroize::Zeroizing;

    fn make_attrs(ino: u64, is_dir: bool) -> FileAttrs {
        let now = SystemTime::now();
        FileAttrs {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            is_dir,
            perm: if is_dir { 0o777 } else { 0o666 },
            nlink: if is_dir { 2 } else { 1 },
        }
    }

    fn insert_folder(
        table: &mut InodeTable,
        ino: u64,
        parent_ino: u64,
        name: &str,
        ipns_name: &str,
    ) {
        table.insert(InodeData {
            ino,
            node_id: crate::fs::uuid_from_ino(ino),
            parent_ino,
            name: name.to_string(),
            kind: InodeKind::Folder {
                ipns_name: ipns_name.to_string(),
                read_key: Zeroizing::new([0u8; 32]),
                write_key: Zeroizing::new([0u8; 32]),
                ipns_private_key: Zeroizing::new(vec![0u8; 32]),
                children_loaded: false,
            },
            attr: make_attrs(ino, true),
            children: Some(vec![]),
            write_generation: 0,
        });
    }

    fn insert_file(
        table: &mut InodeTable,
        ino: u64,
        parent_ino: u64,
        name: &str,
        file_meta_ipns_name: Option<&str>,
    ) {
        table.insert(InodeData {
            ino,
            node_id: crate::fs::uuid_from_ino(ino),
            parent_ino,
            name: name.to_string(),
            // node/v3: the file's IPNS identity is the plain `ipns_name` field
            // (empty == not-yet-published). Descriptors (cid/iv) stay empty here.
            kind: InodeKind::File {
                ipns_name: file_meta_ipns_name.unwrap_or_default().to_string(),
                cid: String::new(),
                size: 0,
                encryption_mode: "GCM".to_string(),
                iv: String::new(),
                read_key: Zeroizing::new([0u8; 32]),
                write_key: Zeroizing::new([0u8; 32]),
                ipns_private_key: Zeroizing::new(vec![0u8; 32]),
            },
            attr: make_attrs(ino, false),
            children: None,
            write_generation: 0,
        });
    }

    /// Root -> FolderA (shared-folder) -> FolderB -> FileC. The walk from the
    /// deepest file must return leaf-first: [fileC's ipns, folderB, folderA, root].
    fn build_nested_tree() -> (InodeTable, u64, u64, u64) {
        let mut table = InodeTable::new();
        if let Some(root) = table.get_mut(ROOT_INO) {
            root.kind = InodeKind::Root {
                ipns_name: "k51root".to_string(),
                read_key: Zeroizing::new([0u8; 32]),
                write_key: Zeroizing::new([0u8; 32]),
                ipns_private_key: Zeroizing::new(Vec::new()),
            };
        }
        let folder_a = table.allocate_ino();
        insert_folder(&mut table, folder_a, ROOT_INO, "FolderA", "k51folderA");
        let folder_b = table.allocate_ino();
        insert_folder(&mut table, folder_b, folder_a, "FolderB", "k51folderB");
        let file_c = table.allocate_ino();
        insert_file(&mut table, file_c, folder_b, "fileC.txt", Some("k51fileC"));
        (table, folder_a, folder_b, file_c)
    }

    #[test]
    fn ancestor_ipns_chain_is_leaf_first_over_a_synthetic_tree() {
        let (table, _folder_a, _folder_b, file_c) = build_nested_tree();

        let chain = ancestor_ipns_chain(&table, file_c);

        assert!(chain.reached_root, "a clean tree walk must reach ROOT_INO");
        assert_eq!(
            chain.names,
            vec![
                "k51fileC".to_string(),
                "k51folderB".to_string(),
                "k51folderA".to_string(),
                "k51root".to_string(),
            ],
            "chain must be leaf-first: node itself, then ancestors, vault root last"
        );
    }

    #[test]
    fn ancestor_ipns_chain_from_a_folder_starts_with_that_folder() {
        let (table, folder_a, folder_b, _file_c) = build_nested_tree();

        let chain = ancestor_ipns_chain(&table, folder_b);
        assert!(chain.reached_root);
        assert_eq!(
            chain.names,
            vec![
                "k51folderB".to_string(),
                "k51folderA".to_string(),
                "k51root".to_string()
            ]
        );

        let chain_a = ancestor_ipns_chain(&table, folder_a);
        assert!(chain_a.reached_root);
        assert_eq!(
            chain_a.names,
            vec!["k51folderA".to_string(), "k51root".to_string()]
        );
    }

    #[test]
    fn ancestor_ipns_chain_contains_no_network_call_and_is_purely_local() {
        // The walk over an in-memory InodeTable never touches the network:
        // this test asserting the return value is itself the proof — the
        // function signature takes no ApiClient/runtime handle at all.
        let (table, _a, _b, file_c) = build_nested_tree();
        let chain = ancestor_ipns_chain(&table, file_c);
        assert!(!chain.names.is_empty());
    }

    #[test]
    fn grant_root_for_selects_the_closest_ancestor_that_is_a_grant_root() {
        let (table, _folder_a, folder_b, file_c) = build_nested_tree();
        let ancestors = ancestor_ipns_chain(&table, file_c);

        // Both folderA (deepest match candidate excluded) and root are grant
        // roots in the relay set; folderB (the closest ancestor to file_c) is
        // ALSO a grant root here, so it must win over folderA/root.
        let cache = SentSharesCache {
            root_ipns_names: HashSet::from([
                "k51folderB".to_string(),
                "k51folderA".to_string(),
                "k51root".to_string(),
            ]),
            is_authoritative: true,
        };
        let params = build_coverage_params(&ancestors.names, &cache);

        let selected = grant_root_for(&ancestors.names, &params);
        assert_eq!(
            selected,
            Some("k51folderB".to_string()),
            "must select the leaf-first (closest) matching ancestor, not a deeper one"
        );

        // Sanity: dropping folderB from ancestors (walk from folder_b's own ino
        // gives FolderA as the closest match once FolderB is excluded).
        let ancestors_from_a = ancestor_ipns_chain(&table, _folder_a);
        let params_a = build_coverage_params(&ancestors_from_a.names, &cache);
        assert_eq!(
            grant_root_for(&ancestors_from_a.names, &params_a),
            Some("k51folderA".to_string())
        );
        let _ = folder_b;
    }

    #[test]
    fn grant_root_for_returns_none_when_no_ancestor_is_covered() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let ancestors = ancestor_ipns_chain(&table, file_c);
        let cache = SentSharesCache::empty();
        let params = build_coverage_params(&ancestors.names, &cache);

        assert_eq!(grant_root_for(&ancestors.names, &params), None);
        assert!(!has_covering_grant(&params));
    }

    #[test]
    fn build_coverage_params_populates_local_grant_record_from_the_cache() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let ancestors = ancestor_ipns_chain(&table, file_c);
        let cache = SentSharesCache::from_sent_shares(&[SentShareResponse {
            share_id: "share-1".to_string(),
            recipient_public_key: "0x04aa".to_string(),
            read_descriptor_ref: "deadbeef".to_string(),
            write_descriptor_ref: None,
            root_node_id: "node-1".to_string(),
            root_ipns_name: "k51folderA".to_string(),
            root_generation: "1".to_string(),
            item_name_encrypted: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        }]);

        let params = build_coverage_params(&ancestors.names, &cache);
        assert!(params.active_grant_root_ipns_names.contains("k51folderA"));
        assert_eq!(
            params.local_grant_record,
            Some(LocalGrantRecord {
                root_ipns_name: "k51folderA".to_string(),
            })
        );
        assert!(has_covering_grant(&params));
    }

    // -----------------------------------------------------------------
    // gate_scope_exit — the SC#3 / ROT-02 spy-based rotation-count gate
    // -----------------------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// SC#3 / ROT-02 zero-rotation invariant: a PRIVATE delete (no covering
    /// grant — an AUTHORITATIVE but genuinely-empty sent-shares cache)
    /// invokes the rotate spy ZERO times and returns `NoRotation`. This is
    /// the signature invariant of the phase. Uses `from_sent_shares(&[])`
    /// (authoritative-empty), NOT `SentSharesCache::empty()` (non-
    /// authoritative) — the latter now fails closed per D-15a; see
    /// `gate_scope_exit_non_authoritative_cache_fails_closed` below.
    #[tokio::test]
    async fn gate_scope_exit_private_delete_triggers_zero_rotations() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let cache = SentSharesCache::from_sent_shares(&[]);
        let spy = AtomicUsize::new(0);

        let result = gate_scope_exit(&table, file_c, &cache, |_grant_root| {
            let spy = &spy;
            async move {
                spy.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap();

        assert_eq!(
            spy.load(Ordering::SeqCst),
            0,
            "private delete must not rotate"
        );
        assert_eq!(result, ScopeExitResult::NoRotation);
    }

    /// A shared-scope exit (an ancestor is a grant root) invokes the rotate spy
    /// EXACTLY ONCE, rooted at `grant_root_for` (the closest leaf-first matching
    /// ancestor), and returns `Rotated`.
    #[tokio::test]
    async fn gate_scope_exit_shared_exit_rotates_exactly_once_at_grant_root() {
        let (table, _a, _b, file_c) = build_nested_tree();
        // FolderA (an ancestor of file_c) is a grant root; file_c's own ipns is
        // NOT, so the gate must rotate FROM folderA, not the leaf.
        let cache = SentSharesCache {
            root_ipns_names: HashSet::from(["k51folderA".to_string()]),
            is_authoritative: true,
        };
        let spy = AtomicUsize::new(0);
        let captured: Mutex<Option<String>> = Mutex::new(None);

        let result = gate_scope_exit(&table, file_c, &cache, |grant_root| {
            let spy = &spy;
            let captured = &captured;
            async move {
                spy.fetch_add(1, Ordering::SeqCst);
                *captured.lock().unwrap() = Some(grant_root);
                Ok(())
            }
        })
        .await
        .unwrap();

        assert_eq!(
            spy.load(Ordering::SeqCst),
            1,
            "shared exit rotates exactly once"
        );
        assert_eq!(result, ScopeExitResult::Rotated);
        assert_eq!(
            captured.into_inner().unwrap().as_deref(),
            Some("k51folderA"),
            "rotation must be rooted at the matched grant-root ancestor, not the leaf"
        );
    }

    /// Multiple grant-root ancestors still rotate EXACTLY ONCE (one rotation per
    /// scope-exit) — no over-rotation.
    #[tokio::test]
    async fn gate_scope_exit_multiple_grant_roots_rotate_once() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let cache = SentSharesCache {
            root_ipns_names: HashSet::from([
                "k51folderB".to_string(),
                "k51folderA".to_string(),
                "k51root".to_string(),
            ]),
            is_authoritative: true,
        };
        let spy = AtomicUsize::new(0);

        let result = gate_scope_exit(&table, file_c, &cache, |_grant_root| {
            let spy = &spy;
            async move {
                spy.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap();

        assert_eq!(spy.load(Ordering::SeqCst), 1);
        assert_eq!(result, ScopeExitResult::Rotated);
    }

    /// A rotate error propagates as `Err` (fail-closed), never swallowed — the
    /// caller maps it to EIO and aborts the destructive removal.
    #[tokio::test]
    async fn gate_scope_exit_rotate_error_propagates_and_is_not_swallowed() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let cache = SentSharesCache {
            root_ipns_names: HashSet::from(["k51folderA".to_string()]),
            is_authoritative: true,
        };

        let result = gate_scope_exit(&table, file_c, &cache, |_grant_root| async {
            Err(RotationError::RotateFailed("boom".to_string()))
        })
        .await;

        assert_eq!(
            result.unwrap_err(),
            RotationError::RotateFailed("boom".to_string())
        );
    }

    /// D-07 dual-keying: the READ-plane key surfaced to the rotate seam (the
    /// grant-root ipns_name) and the WRITE-plane key (`uuid_from_ino`) are
    /// DISTINCT values drawn from distinct key spaces — never interchangeable.
    #[test]
    fn d07_read_plane_grant_root_ipns_and_write_plane_child_id_are_distinct() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let ancestors = ancestor_ipns_chain(&table, file_c);
        let cache = SentSharesCache {
            root_ipns_names: HashSet::from(["k51folderA".to_string()]),
            is_authoritative: true,
        };
        let params = build_coverage_params(&ancestors.names, &cache);

        // Read plane: the grant-root IPNS name the rotation is rooted at.
        let read_plane = grant_root_for(&ancestors.names, &params).expect("covered");
        // Write plane: the mutated node's UUID (WriteChildRef.child_id).
        let write_plane = crate::fs::uuid_from_ino(file_c);

        assert_ne!(
            read_plane, write_plane,
            "D-07: read-plane ipns_name must never equal the write-plane child UUID"
        );
        assert!(
            read_plane.starts_with("k51"),
            "read plane is an IPNS k51 name"
        );
        assert!(
            !write_plane.starts_with("k51"),
            "write plane is a UUID, not an IPNS name"
        );
    }

    // -----------------------------------------------------------------
    // D-15a/b/c — gate-correctness fail-closed tests (CodeRabbit findings,
    // 2026-07-07-fuse-shared-scope-exit-rotation-live-wiring.md)
    // -----------------------------------------------------------------

    /// D-15a (CRITICAL): a NON-authoritative sent-shares cache (the state
    /// before the first `/shares/sent` refresh completes, or after a failed
    /// refresh) must NEVER look like "no shares -> private -> NoRotation" —
    /// the gate fails closed (`Err` -> EIO) instead, even though the raw
    /// `root_ipns_names` set happens to be empty (Pitfall 8: the trigger is
    /// authoritativeness, NOT emptiness).
    #[tokio::test]
    async fn gate_scope_exit_non_authoritative_cache_fails_closed() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let cache = SentSharesCache::empty(); // never refreshed -> not authoritative
        assert!(!cache.is_authoritative, "empty() must be non-authoritative");
        let spy = AtomicUsize::new(0);

        let result = gate_scope_exit(&table, file_c, &cache, |_grant_root| {
            let spy = &spy;
            async move {
                spy.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

        assert!(
            result.is_err(),
            "a non-authoritative cache must fail closed (EIO), never a silent NoRotation"
        );
        assert_eq!(
            spy.load(Ordering::SeqCst),
            0,
            "a fail-closed gate must never invoke rotate"
        );
    }

    /// D-15a: the flip side — a REFRESHED (authoritative) cache that is
    /// legitimately empty (the user has shared nothing) must still allow a
    /// private delete to succeed with ZERO rotation. Naively mapping
    /// "empty -> Err" would break every private delete once the client HAS
    /// refreshed and genuinely has no shares (Pitfall 8).
    #[tokio::test]
    async fn gate_scope_exit_authoritative_empty_cache_allows_private_delete() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let cache = SentSharesCache::from_sent_shares(&[]); // refreshed, genuinely empty
        assert!(
            cache.is_authoritative,
            "a completed refresh (even of zero shares) must be authoritative"
        );
        let spy = AtomicUsize::new(0);

        let result = gate_scope_exit(&table, file_c, &cache, |_grant_root| {
            let spy = &spy;
            async move {
                spy.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap();

        assert_eq!(result, ScopeExitResult::NoRotation);
        assert_eq!(
            spy.load(Ordering::SeqCst),
            0,
            "a legitimately-empty AUTHORITATIVE cache must not rotate"
        );
    }

    /// D-15b (MAJOR): an ancestor walk that does NOT reach `ROOT_INO`
    /// cleanly (a dangling `parent_ino` pointing at a missing inode) must
    /// fail closed — never be treated as a clean "no grant found" walk.
    #[tokio::test]
    async fn gate_scope_exit_incomplete_ancestor_walk_fails_closed() {
        let mut table = InodeTable::new();
        // A folder whose parent_ino points at an inode that was never
        // inserted (dangling/corrupt state) — the walk cannot reach ROOT_INO.
        let dangling_parent = 9_999;
        let orphan = table.allocate_ino();
        insert_folder(&mut table, orphan, dangling_parent, "orphan", "k51orphan");

        let chain = ancestor_ipns_chain(&table, orphan);
        assert!(
            !chain.reached_root,
            "a walk through a missing inode must not report reaching ROOT_INO"
        );

        let cache = SentSharesCache::from_sent_shares(&[]); // authoritative, irrelevant here
        let spy = AtomicUsize::new(0);

        let result = gate_scope_exit(&table, orphan, &cache, |_grant_root| {
            let spy = &spy;
            async move {
                spy.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

        assert!(
            result.is_err(),
            "an incomplete ancestor walk must fail closed (EIO), never NoRotation"
        );
        assert_eq!(spy.load(Ordering::SeqCst), 0);
    }

    /// D-15b: a cycle in the ancestor chain (corrupt/synthetic state) must
    /// also fail closed rather than being silently treated as a clean walk.
    #[tokio::test]
    async fn gate_scope_exit_cyclic_ancestor_walk_fails_closed() {
        let mut table = InodeTable::new();
        let ino_a = table.allocate_ino();
        let ino_b = table.allocate_ino();
        // ino_a's parent is ino_b, and ino_b's parent is ino_a: a cycle that
        // never reaches ROOT_INO.
        insert_folder(&mut table, ino_a, ino_b, "a", "k51a");
        insert_folder(&mut table, ino_b, ino_a, "b", "k51b");

        let chain = ancestor_ipns_chain(&table, ino_a);
        assert!(!chain.reached_root, "a cyclic walk must not reach ROOT_INO");

        let cache = SentSharesCache::from_sent_shares(&[]);
        let result = gate_scope_exit(&table, ino_a, &cache, |_grant_root| async { Ok(()) }).await;
        assert!(result.is_err(), "a cyclic ancestor walk must fail closed");
    }

    /// D-15c (MAJOR): a poisoned `sent_shares` `RwLock` must return
    /// `Err(())` (-> EIO) from `run_scope_exit_gate`, NEVER panic the fuser
    /// callback thread (a panic there would wedge the mount).
    #[test]
    fn run_scope_exit_gate_poisoned_lock_returns_err_not_panic() {
        let (_rt, mut fs) = fs_on_runtime_for_gate_test();
        let child = insert_root_file_child(&mut fs, "secret.txt");

        // Poison the lock: panic while holding the write guard, caught
        // locally so the test process itself does not abort.
        let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = fs.sent_shares.write().expect("acquire for poisoning");
            panic!("intentionally poisoning sent_shares for D-15c test");
        }));
        assert!(
            poison_result.is_err(),
            "the poisoning panic must have fired"
        );
        assert!(fs.sent_shares.is_poisoned(), "lock must now be poisoned");

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_scope_exit_gate(&mut fs, child)
        }));

        assert!(
            outcome.is_ok(),
            "run_scope_exit_gate must NOT panic on a poisoned lock (D-15c)"
        );
        assert_eq!(
            outcome.unwrap(),
            Err(()),
            "a poisoned lock must fail closed (EIO), not silently succeed"
        );
    }

    /// Real secp256k1 keypair so the fs harness matches production shape
    /// (mirrors `delete.rs`'s `real_keypair`).
    fn real_keypair_for_gate_test() -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (
            Zeroizing::new(sk.serialize().to_vec()),
            Zeroizing::new(pk.serialize().to_vec()),
        )
    }

    /// Build a multi-thread runtime and construct a `CipherBoxFS` inside its
    /// context (mirrors `delete.rs`'s `fs_on_runtime` harness) so
    /// `run_scope_exit_gate`'s `fs.rt.block_on` is valid when invoked from
    /// the TEST thread (not a runtime worker) — the same shape as the real
    /// fuser callback thread.
    fn fs_on_runtime_for_gate_test() -> (tokio::runtime::Runtime, crate::CipherBoxFS) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let (private_key, public_key) = real_keypair_for_gate_test();
        let fs = crate::test_support::make_test_fs_with_keypair(private_key, public_key);
        (rt, fs)
    }

    /// Insert a File child of ROOT_INO into an already-constructed `fs`'s
    /// inode table (mirrors `delete.rs`'s `insert_file_child`).
    fn insert_root_file_child(fs: &mut crate::CipherBoxFS, name: &str) -> u64 {
        let ino = fs.inodes.allocate_ino();
        insert_file(&mut fs.inodes, ino, ROOT_INO, name, Some("k51gatetest"));
        if let Some(root) = fs.inodes.get_mut(ROOT_INO) {
            root.children.get_or_insert_with(Vec::new).push(ino);
        }
        ino
    }
}
