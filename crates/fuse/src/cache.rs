//! The mount's bounded plaintext chunk cache — the one place plaintext is
//! cached, memory-only (blueprint/desktop.md "Reads, writes, and the
//! never-block law").
//!
//! Blocks are keyed by the engine [`StreamHandle`] that produced them. A stream
//! pins one head version for its whole life, so a block cached under its handle
//! can never be served as a slice of a different version.
//!
//! Every block is owned here and nowhere else, so this cache is the terminal
//! owner that zeroizes it (security rule 7). Zeroization rides `Drop`, not an
//! unmount callback: a mount torn down without one still leaves no plaintext.

use std::collections::BTreeMap;

use cipherbox_engine::{ContentProfile, StreamHandle};
use zeroize::Zeroizing;

/// One cached block: the stream that pinned it, and its index at
/// [`CacheBudget::block_bytes`] granularity.
type BlockKey = (StreamHandle, u64);

/// How much plaintext one mount may hold, and at what granularity.
///
/// `block_bytes` matches the content plane's chunk framing so a cache block
/// maps onto exactly one sealed chunk: a smaller block would make every miss
/// fetch a whole leaf and keep a fraction of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheBudget {
    max_bytes: usize,
    block_bytes: u64,
}

impl CacheBudget {
    /// Blocks a mount may hold at once under either profile.
    const BLOCKS: usize = 64;

    /// The production budget: 64 chunks of hot plaintext per mount.
    pub const PRODUCTION: Self = Self::of(ContentProfile::PRODUCTION);
    /// The CI budget, at the CI profile's framing.
    pub const CI: Self = Self::of(ContentProfile::CI);

    const fn of(profile: ContentProfile) -> Self {
        Self {
            max_bytes: profile.chunk_size() * Self::BLOCKS,
            block_bytes: profile.chunk_size() as u64,
        }
    }

    /// A budget of `blocks` chunks at `profile`'s framing. At least one block,
    /// so a miss the cache can never hold is not representable.
    pub const fn for_profile(profile: ContentProfile, blocks: usize) -> Option<Self> {
        if blocks == 0 {
            return None;
        }
        Some(Self {
            max_bytes: profile.chunk_size() * blocks,
            block_bytes: profile.chunk_size() as u64,
        })
    }

    /// The plaintext ceiling, in bytes.
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// The window one miss reads and stores.
    pub const fn block_bytes(&self) -> u64 {
        self.block_bytes
    }
}

struct Entry {
    /// The tick this block was last served at; its key in `recency`.
    used: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

/// The mount's plaintext blocks, bounded in bytes and evicted least-recently-
/// used first.
pub struct ChunkCache {
    budget: CacheBudget,
    blocks: BTreeMap<BlockKey, Entry>,
    recency: BTreeMap<u64, BlockKey>,
    next_tick: u64,
    retained: usize,
}

impl ChunkCache {
    /// An empty cache under `budget`.
    pub fn new(budget: CacheBudget) -> Self {
        Self {
            budget,
            blocks: BTreeMap::new(),
            recency: BTreeMap::new(),
            next_tick: 0,
            retained: 0,
        }
    }

    /// The window one miss reads and stores.
    pub fn block_bytes(&self) -> u64 {
        self.budget.block_bytes
    }

    /// Plaintext bytes currently held. Never above the budget's ceiling.
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }

    /// Serve a block, making it the most recently used.
    pub fn get(&mut self, key: BlockKey) -> Option<&[u8]> {
        let tick = self.next_tick;
        let entry = self.blocks.get_mut(&key)?;
        self.recency.remove(&entry.used);
        entry.used = tick;
        self.next_tick += 1;
        self.recency.insert(tick, key);
        self.blocks
            .get(&key)
            .map(|entry| entry.plaintext.as_slice())
    }

    /// Retain `plaintext` under `key`, evicting until it fits. A block larger
    /// than the whole budget is dropped rather than cached: the ceiling is the
    /// mount's promise, not a target to overshoot.
    pub fn insert(&mut self, key: BlockKey, plaintext: Vec<u8>) {
        // Wrapped before any early return: a block this cache refuses is still
        // plaintext it took ownership of, and must leave memory zeroed.
        let plaintext = Zeroizing::new(plaintext);
        let len = plaintext.len();
        if len > self.budget.max_bytes {
            return;
        }
        self.drop_block(key);
        while self.retained + len > self.budget.max_bytes {
            let Some((_, oldest)) = self.recency.first_key_value().map(|(t, k)| (*t, *k)) else {
                break;
            };
            self.drop_block(oldest);
        }
        let tick = self.next_tick;
        self.next_tick += 1;
        self.retained += len;
        self.recency.insert(tick, key);
        self.blocks.insert(
            key,
            Entry {
                used: tick,
                plaintext,
            },
        );
    }

    /// Release everything a closed stream cached.
    pub fn forget_stream(&mut self, stream: StreamHandle) {
        let doomed: Vec<BlockKey> = self
            .blocks
            .keys()
            .copied()
            .filter(|(owner, _)| *owner == stream)
            .collect();
        for key in doomed {
            self.drop_block(key);
        }
    }

    /// Release every block.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.recency.clear();
        self.retained = 0;
    }

    fn drop_block(&mut self, key: BlockKey) {
        if let Some(entry) = self.blocks.remove(&key) {
            self.recency.remove(&entry.used);
            self.retained -= entry.plaintext.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: StreamHandle = StreamHandle(1);

    fn tiny() -> CacheBudget {
        CacheBudget::for_profile(ContentProfile::CI, 3).expect("three blocks")
    }

    fn block(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    #[test]
    fn every_shipped_budget_admits_at_least_one_block() {
        for budget in [CacheBudget::PRODUCTION, CacheBudget::CI] {
            assert!(budget.block_bytes() > 0);
            assert!(
                budget.max_bytes() >= budget.block_bytes() as usize,
                "a budget too small for one block could never serve a miss"
            );
        }
    }

    #[test]
    fn a_zero_block_budget_is_not_representable() {
        assert_eq!(CacheBudget::for_profile(ContentProfile::CI, 0), None);
    }

    #[test]
    fn a_stored_block_is_served_back() {
        let mut cache = ChunkCache::new(tiny());
        cache.insert((STREAM, 0), block(7, 16));
        assert_eq!(cache.get((STREAM, 0)), Some(block(7, 16).as_slice()));
        assert_eq!(cache.get((STREAM, 1)), None);
    }

    #[test]
    fn two_streams_never_share_a_block() {
        let mut cache = ChunkCache::new(tiny());
        cache.insert((StreamHandle(1), 0), block(1, 16));
        cache.insert((StreamHandle(2), 0), block(2, 16));
        assert_eq!(
            cache.get((StreamHandle(1), 0)),
            Some(block(1, 16).as_slice())
        );
        assert_eq!(
            cache.get((StreamHandle(2), 0)),
            Some(block(2, 16).as_slice())
        );
    }

    #[test]
    fn the_ceiling_holds_and_the_least_recently_used_block_goes_first() {
        let mut cache = ChunkCache::new(tiny());
        for index in 0..3 {
            cache.insert((STREAM, index), block(index as u8, 16));
        }
        assert_eq!(cache.retained_bytes(), 48);

        // Touch 0 and 2, leaving 1 the oldest, then overflow by one block.
        cache.get((STREAM, 0)).expect("still held");
        cache.get((STREAM, 2)).expect("still held");
        cache.insert((STREAM, 3), block(3, 16));

        assert!(cache.retained_bytes() <= cache.budget.max_bytes());
        assert_eq!(cache.get((STREAM, 1)), None, "the oldest block was evicted");
        assert!(cache.get((STREAM, 0)).is_some());
        assert!(cache.get((STREAM, 2)).is_some());
        assert!(cache.get((STREAM, 3)).is_some());
    }

    #[test]
    fn a_block_larger_than_the_whole_budget_is_never_retained() {
        let mut cache = ChunkCache::new(tiny());
        cache.insert((STREAM, 0), block(9, 49));
        assert_eq!(cache.retained_bytes(), 0);
        assert_eq!(cache.get((STREAM, 0)), None);
    }

    #[test]
    fn re_inserting_a_key_does_not_double_count_its_bytes() {
        let mut cache = ChunkCache::new(tiny());
        cache.insert((STREAM, 0), block(1, 16));
        cache.insert((STREAM, 0), block(2, 16));
        assert_eq!(cache.retained_bytes(), 16);
        assert_eq!(cache.get((STREAM, 0)), Some(block(2, 16).as_slice()));
    }

    #[test]
    fn forgetting_one_stream_leaves_the_others_intact() {
        let mut cache = ChunkCache::new(tiny());
        cache.insert((StreamHandle(1), 0), block(1, 16));
        cache.insert((StreamHandle(2), 0), block(2, 16));

        cache.forget_stream(StreamHandle(1));

        assert_eq!(cache.get((StreamHandle(1), 0)), None);
        assert!(cache.get((StreamHandle(2), 0)).is_some());
        assert_eq!(cache.retained_bytes(), 16);
    }

    #[test]
    fn clearing_releases_every_block() {
        let mut cache = ChunkCache::new(tiny());
        cache.insert((StreamHandle(1), 0), block(1, 16));
        cache.insert((StreamHandle(2), 5), block(2, 16));

        cache.clear();

        assert_eq!(cache.retained_bytes(), 0);
        assert_eq!(cache.get((StreamHandle(1), 0)), None);
        assert_eq!(cache.get((StreamHandle(2), 5)), None);
    }
}
