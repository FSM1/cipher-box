//! Staging admission: the exact sealed total a version will occupy, reserved
//! whole before its first chunk is pushed (#828, #829).
//!
//! A write handle stages for as long as it takes the client to feed the file and
//! the drain to upload it, so two handles opened moments apart would both read
//! the same `staged_bytes_total` and both be admitted against room only one of
//! them can have. The ledger closes that: a reservation is the version's **whole
//! sealed total**, held from `beginWrite` to release, so concurrent handles
//! contend for the budget rather than over-admit against it.

use std::collections::BTreeMap;

use super::chunk::SEALED_LEAF_OVERHEAD;
use super::dag::{DagError, expected_leaf_count, root_block_len};
use super::profile::ContentProfile;
use crate::storage_policy::{Headroom, StoragePolicy};

/// The exact staged byte total a version of `size` plaintext bytes occupies:
/// every leaf's sealed length (`size + 40n`) plus the root block's.
///
/// Fails closed on the flat-DAG ceiling, so a file whose root could never be
/// read back is refused before a single byte is staged.
pub(crate) fn sealed_total_bytes(size: u64, profile: &ContentProfile) -> Result<u64, DagError> {
    let leaves = expected_leaf_count(size, profile.chunk_size() as u64);
    Ok(size
        .saturating_add(leaves.saturating_mul(SEALED_LEAF_OVERHEAD))
        .saturating_add(root_block_len(size, profile)?))
}

/// A handle's live staging reservation. Held by the ledger until the write
/// commits, fails, or its bytes leave the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ReservationId(pub u64);

/// How many write handles may be open at once.
///
/// The ledger bounds *staged* bytes, which a handle only spends as the client
/// feeds it — so a caller that opens handles and never pushes reserves almost
/// nothing while costing a live buffer and a map entry each. This is the bound
/// on that: a host driving more than a few uploads at once is already past any
/// useful concurrency, and a caller opening thousands is a bug or an attack.
pub(crate) const MAX_OPEN_WRITES: usize = 64;

/// Why an admission was refused. The variants are separate because they call for
/// different user actions: nothing helps on this device, free disk space, wait
/// for the queue to drain, close some uploads, or the host cannot say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Too many write handles are already open ([`MAX_OPEN_WRITES`]).
    TooManyWrites,
    /// The version exceeds this platform's hard staging cap, so no amount of
    /// free space or drain progress admits it.
    OverLimit,
    /// The budget is below the platform cap because this device's measured
    /// headroom cut it there.
    DeviceFull,
    /// It would fit an empty store, but staged and reserved bytes leave too
    /// little right now — the drain frees room as blocks upload.
    Backlog,
    /// The host could not measure storage headroom, so nothing is admissible —
    /// distinct from a measured zero, which is a device known to be full.
    Unmeasured,
}

/// A refused admission: why, what it asked for, and the room a caller may quote
/// — never the whole budget, which a caller cannot act on when other writes
/// already hold most of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refused {
    /// Which ceiling refused it, and so which action helps.
    pub(crate) refusal: Refusal,
    /// The version's exact sealed total.
    pub(crate) requested: u64,
    /// The applicable room: `budget - (staged + reserved)` for a backlog, the
    /// relevant ceiling otherwise.
    pub(crate) available: u64,
}

/// The in-memory reservation ledger of live write handles. Session-scoped: a
/// restart drops every reservation, and the staged bytes it held are either
/// referenced by a queued op or collected as orphans.
#[derive(Debug, Default)]
pub(crate) struct StagingLedger {
    live: BTreeMap<ReservationId, u64>,
    next: u64,
}

impl StagingLedger {
    /// Reserve `requested` bytes against `policy`, given the store's current
    /// `staged` total. The reservation counts from here, so a second handle
    /// opened before the first stages anything still sees the room taken.
    pub(crate) fn admit(
        &mut self,
        requested: u64,
        staged: u64,
        policy: &StoragePolicy,
    ) -> Result<ReservationId, Refused> {
        let refuse = |refusal, available| {
            Err(Refused {
                refusal,
                requested,
                available,
            })
        };
        if policy.headroom == Headroom::Unmeasured {
            return refuse(Refusal::Unmeasured, 0);
        }
        if self.live.len() >= MAX_OPEN_WRITES {
            return refuse(Refusal::TooManyWrites, 0);
        }
        if requested > policy.staging_cap_bytes {
            return refuse(Refusal::OverLimit, policy.staging_cap_bytes);
        }
        if requested > policy.staging_budget_bytes {
            return refuse(Refusal::DeviceFull, policy.staging_budget_bytes);
        }
        // Saturating: an overflowing sum is unreachable under any real budget,
        // and must still read as "no room", never wrap to a spurious surplus.
        let committed = staged.saturating_add(self.reserved());
        let available = policy.staging_budget_bytes.saturating_sub(committed);
        if requested > available {
            return refuse(Refusal::Backlog, available);
        }
        self.next += 1;
        let id = ReservationId(self.next);
        self.live.insert(id, requested);
        Ok(id)
    }

    /// Drop a reservation — the write committed, failed, or was abandoned. Its
    /// bytes are accounted by the store from here on.
    pub(crate) fn release(&mut self, id: ReservationId) {
        self.live.remove(&id);
    }

    /// Bytes reserved by live handles and not yet staged-and-accounted.
    pub(crate) fn reserved(&self) -> u64 {
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
                ContentWriter::new(ContentKey::from_bytes([3u8; KEY_LEN]), profile, size as u64);
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
        let first = ledger
            .admit(600, 0, &policy)
            .expect("the first handle fits");
        assert_eq!(
            ledger.admit(600, 0, &policy),
            Err(Refused {
                refusal: Refusal::Backlog,
                requested: 600,
                available: 400
            }),
            "the second handle contends with the first's reservation"
        );
        ledger.release(first);
        assert!(ledger.admit(600, 0, &policy).is_ok());
    }

    #[test]
    fn a_refusal_quotes_the_room_left_never_the_whole_budget() {
        let mut ledger = StagingLedger::default();
        let policy = budget(1000);
        assert_eq!(
            ledger.admit(500, 700, &policy),
            Err(Refused {
                refusal: Refusal::Backlog,
                requested: 500,
                available: 300
            }),
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
        let mut refusal = |requested, staged| {
            ledger
                .admit(requested, staged, &constrained)
                .expect_err("refused")
                .refusal
        };
        assert_eq!(refusal(500, 0), Refusal::DeviceFull);
        // Past the platform cap: nothing on this device ever admits it.
        assert_eq!(refusal(5000, 0), Refusal::OverLimit);
        // Room in principle, taken right now: the drain frees it.
        assert_eq!(refusal(60, 50), Refusal::Backlog);
    }

    #[test]
    fn an_unmeasurable_host_is_never_reported_as_a_full_one() {
        let mut ledger = StagingLedger::default();
        assert_eq!(
            ledger
                .admit(1, 0, &StoragePolicy::UNMEASURED)
                .expect_err("refused")
                .refusal,
            Refusal::Unmeasured
        );
    }

    /// A handle costs a buffer and a map entry before it stages anything, so the
    /// byte ledger alone does not bound them: opening thousands of near-empty
    /// writes must be refused, not absorbed.
    #[test]
    fn open_handles_are_capped_independently_of_the_byte_budget() {
        let mut ledger = StagingLedger::default();
        let policy = budget(u64::MAX);
        let mut ids = Vec::new();
        for _ in 0..MAX_OPEN_WRITES {
            ids.push(ledger.admit(1, 0, &policy).expect("under the cap"));
        }
        assert_eq!(
            ledger.admit(1, 0, &policy).expect_err("at the cap").refusal,
            Refusal::TooManyWrites
        );
        ledger.release(ids[0]);
        assert!(
            ledger.admit(1, 0, &policy).is_ok(),
            "closing one makes room for the next"
        );
    }

    /// A caller-declared size is a `u64` from JS: sizing it must fail closed on
    /// the flat-DAG ceiling, never try to allocate its leaf set first.
    #[test]
    fn an_absurd_declared_size_is_refused_without_allocating() {
        for profile in [ContentProfile::CI, ContentProfile::PRODUCTION] {
            assert!(matches!(
                sealed_total_bytes(u64::MAX, &profile),
                Err(DagError::RootTooLarge { .. })
            ));
        }
    }

    #[test]
    fn a_released_reservation_stops_counting() {
        let mut ledger = StagingLedger::default();
        let policy = budget(1000);
        let id = ledger.admit(400, 0, &policy).expect("admitted");
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
        assert!(StagingLedger::default().admit(total, 0, &policy).is_ok());
    }
}
