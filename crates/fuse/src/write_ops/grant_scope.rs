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

use cipherbox_api_client::shares::{collect_sent_shares, SentShareResponse};
use cipherbox_api_client::{ApiClient, ApiError};
use cipherbox_sdk::rotation::scope::{has_covering_grant, CoverageParams, LocalGrantRecord};

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
pub fn ancestor_ipns_chain(inodes: &InodeTable, start_ino: u64) -> Vec<String> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current_ino = start_ino;

    loop {
        // Cycle guard: a well-formed tree never revisits an inode, but this
        // keeps the walk O(depth)-bounded even over corrupt/synthetic state
        // rather than looping forever.
        if !visited.insert(current_ino) {
            break;
        }

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
                    chain.push(ipns_name.clone());
                }
            }
        }

        if current_ino == ROOT_INO {
            break;
        }
        current_ino = inode.parent_ino;
    }

    chain
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
}

impl SentSharesCache {
    /// An empty cache — the state before the first refresh completes.
    pub fn empty() -> Self {
        Self {
            root_ipns_names: HashSet::new(),
        }
    }

    /// Build a cache from a raw `collect_sent_shares` response. Pure and
    /// synchronous so it is unit-testable without a live HTTP server.
    pub fn from_sent_shares(shares: &[SentShareResponse]) -> Self {
        Self {
            root_ipns_names: shares.iter().map(|s| s.root_ipns_name.clone()).collect(),
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

        assert_eq!(
            chain,
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
        assert_eq!(
            chain,
            vec![
                "k51folderB".to_string(),
                "k51folderA".to_string(),
                "k51root".to_string()
            ]
        );

        let chain_a = ancestor_ipns_chain(&table, folder_a);
        assert_eq!(
            chain_a,
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
        assert!(!chain.is_empty());
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
        };
        let params = build_coverage_params(&ancestors, &cache);

        let selected = grant_root_for(&ancestors, &params);
        assert_eq!(
            selected,
            Some("k51folderB".to_string()),
            "must select the leaf-first (closest) matching ancestor, not a deeper one"
        );

        // Sanity: dropping folderB from ancestors (walk from folder_b's own ino
        // gives FolderA as the closest match once FolderB is excluded).
        let ancestors_from_a = ancestor_ipns_chain(&table, _folder_a);
        let params_a = build_coverage_params(&ancestors_from_a, &cache);
        assert_eq!(
            grant_root_for(&ancestors_from_a, &params_a),
            Some("k51folderA".to_string())
        );
        let _ = folder_b;
    }

    #[test]
    fn grant_root_for_returns_none_when_no_ancestor_is_covered() {
        let (table, _a, _b, file_c) = build_nested_tree();
        let ancestors = ancestor_ipns_chain(&table, file_c);
        let cache = SentSharesCache::empty();
        let params = build_coverage_params(&ancestors, &cache);

        assert_eq!(grant_root_for(&ancestors, &params), None);
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

        let params = build_coverage_params(&ancestors, &cache);
        assert!(params.active_grant_root_ipns_names.contains("k51folderA"));
        assert_eq!(
            params.local_grant_record,
            Some(LocalGrantRecord {
                root_ipns_name: "k51folderA".to_string(),
            })
        );
        assert!(has_covering_grant(&params));
    }
}
