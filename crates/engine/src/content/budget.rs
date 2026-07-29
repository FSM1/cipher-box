//! Staging admission: the exact sealed total a version will occupy, reserved
//! whole before its first chunk is pushed (#828, #829).
//!
//! A write handle stages for as long as it takes the client to feed the file and
//! the drain to upload it, so two handles opened moments apart would both read
//! the same `staged_bytes_total` and both be admitted against room only one of
//! them can have. The ledger closes that: a reservation is the version's **whole
//! sealed total**, held from `beginWrite` to release, so concurrent handles
//! contend for the budget rather than over-admit against it. `pushChunk`
//! therefore enforces only the declared shape and never re-checks the budget.
//!
//! The reservation is exact, not an estimate: leaf count and per-leaf overhead
//! are both determined by the declared size and the frozen framing, and the root
//! block is sized by assembling one over placeholder links of the fixed CID
//! width.

use std::collections::BTreeMap;

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};

use super::chunk::SEALED_LEAF_OVERHEAD;
use super::dag::{DagError, assemble, expected_leaf_count};
use super::profile::ContentProfile;
use crate::storage_policy::{Headroom, StoragePolicy};

/// The exact staged byte total a version of `size` plaintext bytes occupies:
/// every leaf's sealed length (`size + 40n`) plus the assembled root block's.
///
/// Fails closed with the same [`DagError`] the real assembly would raise, so a
/// file past the flat-DAG ceiling is refused before a single byte is staged.
pub fn sealed_total_bytes(size: u64, profile: &ContentProfile) -> Result<u64, DagError> {
    let leaves = expected_leaf_count(size, profile.chunk_size() as u64);
    // Placeholder links: every content CID is the same fixed width, so a root
    // over `leaves` of them encodes to exactly the length the real one will.
    let placeholder = compute_cid(CONTENT_CID_CODEC, b"");
    let links = vec![placeholder; usize::try_from(leaves).map_err(|_| DagError::RootTooLarge {
        size: usize::MAX,
        limit: super::limits::MAX_RESOLVED_RECORD_BYTES,
    })?];
    let root = assemble(&links, size, profile)?;
    Ok(size
        .saturating_add(leaves.saturating_mul(SEALED_LEAF_OVERHEAD))
        .saturating_add(root.root_block.len() as u64))
}

/// A handle's live staging reservation. Held by the ledger until the write
/// commits, fails, or its bytes leave the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReservationId(pub u64);

/// The verdict on one admission request. The three refusals are separate
/// because they call for different user actions: nothing helps on this device,
/// wait for the queue to drain, or free disk space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Admitted; the reservation is held until it is released.
    Reserved(ReservationId),
    /// The version exceeds this platform's hard staging cap, so no amount of
    /// free space or drain progress admits it.
    OverLimit {
        /// The version's exact sealed total.
        requested: u64,
        /// The room the budget would have with nothing staged or reserved.
        available: u64,
    },
    /// It would fit an empty store, but staged and reserved bytes leave too
    /// little right now — the drain frees room as blocks upload.
    Backlog {
        /// The version's exact sealed total.
        requested: u64,
        /// `budget - (staged + reserved)`, the room a caller may quote.
        available: u64,
    },
    /// The budget is below the platform cap because this device's measured
    /// headroom cut it there.
    DeviceFull {
        /// The version's exact sealed total.
        requested: u64,
        /// The whole budget this device's headroom allows.
        available: u64,
    },
    /// The host could not measure storage headroom, so nothing is admissible —
    /// distinct from a measured zero, which is a device known to be full.
    Unmeasured {
        /// The version's exact sealed total.
        requested: u64,
    },
}

/// The in-memory reservation ledger of live write handles. Session-scoped: a
/// restart drops every reservation, and the staged bytes it held are either
/// referenced by a queued op or collected as orphans.
#[derive(Debug, Default)]
pub struct StagingLedger {
    live: BTreeMap<ReservationId, u64>,
    next: u64,
}

impl StagingLedger {
    /// Reserve `requested` bytes against `policy`, given the store's current
    /// `staged` total. The reservation counts from here, so a second handle
    /// opened before the first stages anything still sees the room taken.
    pub fn admit(&mut self, requested: u64, staged: u64, policy: &StoragePolicy) -> Admission {
        if policy.headroom == Headroom::Unmeasured {
            return Admission::Unmeasured { requested };
        }
        if requested > policy.staging_cap_bytes {
            return Admission::OverLimit {
                requested,
                available: policy.staging_cap_bytes,
            };
        }
        if requested > policy.staging_budget_bytes {
            return Admission::DeviceFull {
                requested,
                available: policy.staging_budget_bytes,
            };
        }
        // Saturating: an overflowing sum is unreachable under any real budget,
        // and must still read as "no room", never wrap to a spurious surplus.
        let committed = staged.saturating_add(self.reserved());
        let available = policy.staging_budget_bytes.saturating_sub(committed);
        if requested > available {
            return Admission::Backlog {
                requested,
                available,
            };
        }
        self.next += 1;
        let id = ReservationId(self.next);
        self.live.insert(id, requested);
        Admission::Reserved(id)
    }

    /// Drop a reservation — the write committed, failed, or was abandoned. Its
    /// bytes are accounted by the store from here on.
    pub fn release(&mut self, id: ReservationId) {
        self.live.remove(&id);
    }

    /// Bytes reserved by live handles and not yet staged-and-accounted.
    pub fn reserved(&self) -> u64 {
        self.live.values().copied().fold(0, u64::saturating_add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::chunk::ContentKey;
    use crate::content::write::ContentWriter;
    use crate::storage_policy::{StoragePlatform, StoragePolicy};
    use crate::testkit::SeededEntropy;
    use cipherbox_core::suite::aead::KEY_LEN;

    fn budget(bytes: u64) -> StoragePolicy {
        StoragePolicy {
            staging_budget_bytes: bytes,
            staging_cap_bytes: bytes,
            ..StoragePolicy::CI
        }
    }

    /// The reservation must be the byte count staging actually holds — an
    /// under-estimate over-admits and an over-estimate refuses writable files.
    #[test]
    fn the_reservation_is_the_exact_staged_total() {
        let profile = ContentProfile::CI;
        for size in [0usize, 1, 15, 16, 17, 32, 100] {
            let plaintext = vec![7u8; size];
            let mut entropy = SeededEntropy::new(1);
            let mut writer =
                ContentWriter::new(ContentKey::from_bytes([3u8; KEY_LEN]), profile);
            let mut staged = 0u64;
            let mut rest = &plaintext[..];
            while !rest.is_empty() {
                let (remaining, leaf) = writer.push(rest, &mut entropy).unwrap();
                if let Some(leaf) = leaf {
                    staged += leaf.sealed.len() as u64;
                }
                rest = remaining;
            }
            let finished = writer.finish(&mut entropy).unwrap();
            if let Some(tail) = &finished.tail {
                staged += tail.sealed.len() as u64;
            }
            staged += finished.root_block.len() as u64;

            assert_eq!(
                sealed_total_bytes(size as u64, &profile).unwrap(),
                staged,
                "size {size}: reservation must equal what staging holds"
            );
        }
    }

    #[test]
    fn a_file_past_the_flat_dag_ceiling_is_refused_before_a_byte_is_staged() {
        // 120k links at the production chunk size push the root past the block
        // cap, which `assemble` refuses — the sizing pass sees the same verdict.
        let profile = ContentProfile::PRODUCTION;
        let size = 120_000u64 * profile.chunk_size() as u64;
        assert!(matches!(
            sealed_total_bytes(size, &profile),
            Err(DagError::RootTooLarge { .. })
        ));
    }

    #[test]
    fn concurrent_handles_cannot_over_admit_against_one_budget() {
        let mut ledger = StagingLedger::default();
        let policy = budget(1000);
        // Nothing is staged yet, so a naive check would admit both.
        let Admission::Reserved(first) = ledger.admit(600, 0, &policy) else {
            panic!("the first handle fits");
        };
        assert!(
            matches!(ledger.admit(600, 0, &policy), Admission::Backlog { available, .. } if available == 400),
            "the second handle contends with the first's reservation"
        );
        ledger.release(first);
        assert!(matches!(
            ledger.admit(600, 0, &policy),
            Admission::Reserved(_)
        ));
    }

    #[test]
    fn a_refusal_quotes_the_room_left_never_the_whole_budget() {
        let mut ledger = StagingLedger::default();
        let policy = budget(1000);
        assert_eq!(
            ledger.admit(500, 700, &policy),
            Admission::Backlog {
                requested: 500,
                available: 300
            },
            "the figure a caller may act on is budget - staged"
        );
    }

    #[test]
    fn the_three_staging_refusals_are_distinguishable() {
        let mut ledger = StagingLedger::default();
        // Headroom cut the budget below the platform cap: freeing space helps.
        let constrained = StoragePolicy {
            staging_budget_bytes: 100,
            staging_cap_bytes: 1000,
            ..StoragePolicy::CI
        };
        assert!(matches!(
            ledger.admit(500, 0, &constrained),
            Admission::DeviceFull { available: 100, .. }
        ));
        // Past the platform cap: nothing on this device ever admits it.
        assert!(matches!(
            ledger.admit(5000, 0, &constrained),
            Admission::OverLimit { available: 1000, .. }
        ));
        // Room in principle, taken right now: the drain frees it.
        assert!(matches!(
            ledger.admit(60, 50, &constrained),
            Admission::Backlog { available: 50, .. }
        ));
    }

    #[test]
    fn an_unmeasurable_host_is_never_reported_as_a_full_one() {
        let mut ledger = StagingLedger::default();
        assert_eq!(
            ledger.admit(1, 0, &StoragePolicy::UNMEASURED),
            Admission::Unmeasured { requested: 1 }
        );
    }

    #[test]
    fn a_released_reservation_stops_counting() {
        let mut ledger = StagingLedger::default();
        let policy = budget(1000);
        let Admission::Reserved(id) = ledger.admit(400, 0, &policy) else {
            panic!("admitted");
        };
        assert_eq!(ledger.reserved(), 400);
        ledger.release(id);
        assert_eq!(ledger.reserved(), 0);
    }

    #[test]
    fn a_production_split_sizes_a_realistic_file() {
        // A 10 MiB file at the shipped framing fits the web platform budget.
        let policy = StoragePolicy::measured(StoragePlatform::WEB, 64 * (1 << 30));
        let total = sealed_total_bytes(10 * (1 << 20), &ContentProfile::PRODUCTION).unwrap();
        assert!(total > 10 * (1 << 20), "sealing adds overhead");
        assert!(matches!(
            StagingLedger::default().admit(total, 0, &policy),
            Admission::Reserved(_)
        ));
    }
}
