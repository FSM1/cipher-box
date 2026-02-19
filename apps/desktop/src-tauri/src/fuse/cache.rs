//! Memory caches for file content and folder metadata with TTL/LRU eviction.
//!
//! - MetadataCache: Folder metadata keyed by IPNS name with 30s TTL
//! - ContentCache: Decrypted file content keyed by CID with 256 MiB LRU budget

use std::collections::HashMap;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::crypto::folder::FolderMetadata;

/// Time-to-live for cached folder metadata (matches 30s sync polling interval).
pub const METADATA_TTL: Duration = Duration::from_secs(30);

/// Maximum memory budget for content cache (256 MiB).
pub const MAX_CACHE_SIZE: usize = 256 * 1024 * 1024;

// ── Metadata Cache ────────────────────────────────────────────────────────────

/// Cached folder metadata entry with timestamp.
pub struct CachedMetadata {
    pub metadata: FolderMetadata,
    pub cid: String,
    fetched_at: Instant,
}

/// In-memory cache for decrypted folder metadata, keyed by IPNS name.
///
/// Entries expire after `METADATA_TTL` (30 seconds). Stale entries return
/// `None` from `get()` but remain in the map until overwritten or invalidated.
pub struct MetadataCache {
    entries: HashMap<String, CachedMetadata>,
}

impl MetadataCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Get cached metadata if it exists and is still fresh (within TTL).
    ///
    /// Returns `None` if the entry doesn't exist or has expired.
    pub fn get(&self, ipns_name: &str) -> Option<&CachedMetadata> {
        self.entries.get(ipns_name).filter(|entry| {
            entry.fetched_at.elapsed() < METADATA_TTL
        })
    }

    /// Store folder metadata in the cache.
    pub fn set(&mut self, ipns_name: &str, metadata: FolderMetadata, cid: String) {
        self.entries.insert(
            ipns_name.to_string(),
            CachedMetadata {
                metadata,
                cid,
                fetched_at: Instant::now(),
            },
        );
    }

    /// Remove a specific cache entry (used when metadata is known to have changed).
    pub fn invalidate(&mut self, ipns_name: &str) {
        self.entries.remove(ipns_name);
    }

    /// Clear all cached metadata entries. Used during FUSE destroy().
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ── Content Cache ─────────────────────────────────────────────────────────────

/// Cached decrypted file content entry with LRU tracking.
struct CachedContent {
    data: Vec<u8>,
    accessed_at: Instant,
    size: usize,
}

impl Drop for CachedContent {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// In-memory LRU cache for decrypted file content, keyed by CID.
///
/// Evicts least-recently-accessed entries when total size exceeds `MAX_CACHE_SIZE`.
/// Content is decrypted plaintext -- never persisted to disk.
pub struct ContentCache {
    entries: HashMap<String, CachedContent>,
    current_size: usize,
}

impl ContentCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            current_size: 0,
        }
    }

    /// Get cached content, updating the access time for LRU tracking.
    ///
    /// Returns `None` if the CID is not in cache.
    pub fn get(&mut self, cid: &str) -> Option<&[u8]> {
        // Two-phase to satisfy borrow checker: check then update
        if self.entries.contains_key(cid) {
            let entry = self.entries.get_mut(cid).unwrap();
            entry.accessed_at = Instant::now();
            Some(&entry.data)
        } else {
            None
        }
    }

    /// Store decrypted content in the cache, evicting LRU entries if over budget.
    pub fn set(&mut self, cid: &str, data: Vec<u8>) {
        let size = data.len();

        // Remove existing entry for this CID if present (to update size tracking)
        if let Some(old) = self.entries.remove(cid) {
            self.current_size = self.current_size.saturating_sub(old.size);
        }

        // Evict LRU entries until we have room
        while self.current_size + size > MAX_CACHE_SIZE && !self.entries.is_empty() {
            self.evict_lru();
        }

        // If a single item exceeds the budget, still cache it (will be evicted next insertion)
        self.current_size += size;
        self.entries.insert(
            cid.to_string(),
            CachedContent {
                data,
                accessed_at: Instant::now(),
                size,
            },
        );
    }

    /// Evict the least recently accessed entry from the cache.
    fn evict_lru(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, v)| v.accessed_at)
            .map(|(k, _)| k.clone())
        {
            if let Some(evicted) = self.entries.remove(&oldest_key) {
                self.current_size = self.current_size.saturating_sub(evicted.size);
            }
        }
    }

    /// Current total size of cached content in bytes.
    #[allow(dead_code)]
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Clear all cached content entries, zeroizing each one via Drop.
    /// Used during FUSE destroy() for defense-in-depth cleanup.
    pub fn clear(&mut self) {
        self.entries.clear(); // Each CachedContent::drop() zeroizes data
        self.current_size = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MetadataCache tests ───────────────────────────────────────────────

    #[test]
    fn test_metadata_cache_set_and_get() {
        let mut cache = MetadataCache::new();
        let metadata = FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        };
        cache.set("k51test", metadata, "bafytest".to_string());

        let entry = cache.get("k51test");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().cid, "bafytest");
    }

    #[test]
    fn test_metadata_cache_miss() {
        let cache = MetadataCache::new();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_metadata_cache_invalidate() {
        let mut cache = MetadataCache::new();
        let metadata = FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        };
        cache.set("k51test", metadata, "bafytest".to_string());
        cache.invalidate("k51test");
        assert!(cache.get("k51test").is_none());
    }

    // TTL test: we can't easily test time expiry in a unit test without
    // injecting time, but we verify the check exists by ensuring fresh entries work.

    // ── ContentCache tests ────────────────────────────────────────────────

    #[test]
    fn test_content_cache_set_and_get() {
        let mut cache = ContentCache::new();
        cache.set("bafyfile1", vec![1, 2, 3, 4]);

        let data = cache.get("bafyfile1");
        assert!(data.is_some());
        assert_eq!(data.unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_content_cache_miss() {
        let mut cache = ContentCache::new();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_content_cache_evicts_when_over_budget() {
        // Create a small cache with a custom max -- we'll test with the actual
        // struct but use large entries to trigger eviction.
        let mut cache = ContentCache::new();

        // Insert entries totalling > MAX_CACHE_SIZE
        // Each entry is MAX_CACHE_SIZE / 2 + 1 bytes, so two entries exceed budget
        let half_plus = MAX_CACHE_SIZE / 2 + 1;
        let data1 = vec![0u8; half_plus];
        let data2 = vec![1u8; half_plus];

        cache.set("cid1", data1);
        assert_eq!(cache.current_size(), half_plus);

        cache.set("cid2", data2);
        // cid1 should have been evicted to make room for cid2
        assert!(cache.get("cid1").is_none());
        assert!(cache.get("cid2").is_some());
        assert_eq!(cache.current_size(), half_plus);
    }

    #[test]
    fn test_content_cache_lru_eviction_order() {
        let mut cache = ContentCache::new();
        // Use slightly more than 1/3 so three items exceed the budget
        let chunk = MAX_CACHE_SIZE / 3 + 1;

        cache.set("a", vec![0u8; chunk]);
        cache.set("b", vec![1u8; chunk]);
        // Access "a" to make it more recently used
        let _ = cache.get("a");

        // Insert "c" which should evict "b" (least recently accessed)
        cache.set("c", vec![2u8; chunk]);

        assert!(cache.get("a").is_some(), "a should still be cached (recently accessed)");
        assert!(cache.get("b").is_none(), "b should be evicted (LRU)");
        assert!(cache.get("c").is_some(), "c should be cached (just inserted)");
    }

    #[test]
    fn test_content_cache_update_existing() {
        let mut cache = ContentCache::new();
        cache.set("cid1", vec![1, 2, 3]);
        assert_eq!(cache.current_size(), 3);

        // Update with larger data
        cache.set("cid1", vec![1, 2, 3, 4, 5]);
        assert_eq!(cache.current_size(), 5);
        assert_eq!(cache.get("cid1").unwrap(), &[1, 2, 3, 4, 5]);
    }
}
