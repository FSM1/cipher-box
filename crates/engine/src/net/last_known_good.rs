//! The one write path for a name's last-known-good record in the snapshot
//! cache.

use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Poll, Waker};
use std::collections::BTreeMap;

use cipherbox_core::ipns::{IpnsName, IpnsRecord};

use super::eol::ranks_above;
use crate::seams::{SeamError, SnapshotCache};

/// Leave `record_bytes`, a gate pass for `name`, as last-known-good unless the
/// cached copy already sits above its sequence, or at it and does not rank
/// below it ([`ranks_above`]).
///
/// Every path that caches a name's record calls this **before** it moves that
/// name's floor: a read that finds no source opens the cached copy at the
/// floor, so a floor raised past the cached copy leaves that read nothing it
/// can open. The two still drift apart the other way — a pass that cached but
/// failed its floor commit leaves a newer copy — so the put compares sequences
/// rather than trusting the order of passes, and holds the name's [`NameLock`]
/// across the read and the put so two passes cannot interleave them.
///
/// Answers the copy it found, read under the same lock, so a caller holds the
/// evidence of a same-sequence fork that this write can replace.
pub(crate) async fn keep_newest_last_known_good<S: SnapshotCache>(
    snapshot_cache: &S,
    name: &IpnsName,
    record_bytes: &[u8],
) -> Result<Option<Vec<u8>>, SeamError> {
    let key = name.as_str().as_bytes();
    let _writing = NameLock::acquire(key).await;
    let cached = snapshot_cache.get(key).await?;
    let keep = cached.as_deref().is_some_and(|cached| {
        cached == record_bytes
            || verified_rank(name, cached).is_some_and(|(held_sequence, _)| {
                verified_rank(name, record_bytes).is_none_or(|(sequence, _)| {
                    held_sequence > sequence
                        || (held_sequence == sequence && !outranks(name, record_bytes, cached))
                })
            })
    });
    if !keep {
        snapshot_cache.put(key, record_bytes).await?;
    }
    Ok(cached)
}

/// `cached`, a copy of `name` the cache held, when it is another verified
/// record at the sequence of `record_bytes`: evidence of a same-sequence fork
/// (ADR 0066 D1).
pub(crate) fn cached_fork(
    name: &IpnsName,
    cached: Option<Vec<u8>>,
    record_bytes: &[u8],
) -> Option<Vec<u8>> {
    let sequence = |bytes: &[u8]| verified_rank(name, bytes).map(|(sequence, _)| sequence);
    cached.filter(|cached| {
        cached != record_bytes
            && sequence(cached).is_some()
            && sequence(cached) == sequence(record_bytes)
    })
}

/// Whether `candidate` ranks above `held` ([`ranks_above`]), two records of
/// `name` at one sequence. A record that does not verify ranks below.
pub(crate) fn outranks(name: &IpnsName, candidate: &[u8], held: &[u8]) -> bool {
    match (verified_rank(name, candidate), verified_rank(name, held)) {
        (Some((_, candidate_eol)), Some((_, held_eol))) => {
            ranks_above((&candidate_eol, candidate), (&held_eol, held))
        }
        (candidate, _) => candidate.is_some(),
    }
}

/// Leave `record_bytes` as `name`'s last-known-good, then run `commit`, the
/// floor advance the gate pass that admitted it owes — the order
/// [`keep_newest_last_known_good`] requires, stated once.
pub(crate) async fn keep_then_commit<S: SnapshotCache, T>(
    snapshot_cache: &S,
    name: &IpnsName,
    record_bytes: &[u8],
    commit: impl Future<Output = Result<T, SeamError>>,
) -> Result<T, SeamError> {
    keep_newest_last_known_good(snapshot_cache, name, record_bytes).await?;
    commit.await
}

/// A verified record's sequence and signed EOL, the two keys it ranks by.
fn verified_rank(name: &IpnsName, record_bytes: &[u8]) -> Option<(u64, Vec<u8>)> {
    IpnsRecord::unmarshal(record_bytes)
        .and_then(|record| record.verify(name))
        .ok()
        .map(|verified| (verified.sequence, verified.validity))
}

std::thread_local! {
    /// The names a last-known-good write holds, each with the tasks parked on
    /// it. Per thread: the engine is `!Send`, so every pass of one engine runs
    /// on the thread that owns it. Engines that share a thread share the map,
    /// which only serializes more.
    static WRITING: RefCell<BTreeMap<Vec<u8>, Vec<Waker>>> = const { RefCell::new(BTreeMap::new()) };
}

/// An async per-name mutex over [`WRITING`], released on drop.
struct NameLock(Vec<u8>);

impl NameLock {
    async fn acquire(key: &[u8]) -> Self {
        poll_fn(|cx| {
            WRITING.with_borrow_mut(|writing| match writing.get_mut(key) {
                None => {
                    writing.insert(key.to_vec(), Vec::new());
                    Poll::Ready(())
                }
                Some(parked) => {
                    if !parked.iter().any(|waker| waker.will_wake(cx.waker())) {
                        parked.push(cx.waker().clone());
                    }
                    Poll::Pending
                }
            })
        })
        .await;
        Self(key.to_vec())
    }
}

impl Drop for NameLock {
    fn drop(&mut self) {
        let parked = WRITING
            .try_with(|writing| writing.borrow_mut().remove(&self.0))
            .ok()
            .flatten();
        parked.into_iter().flatten().for_each(Waker::wake);
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::pin::pin;
    use core::task::{Context, Waker};

    use super::*;
    use crate::net::eol;
    use crate::seams::UnixMillis;
    use crate::session::SessionIdentity;
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemorySnapshotCache;

    /// A cache whose next `get` reads, then parks until [`Self::release`].
    #[derive(Default)]
    struct ParkingCache {
        inner: InMemorySnapshotCache,
        park_next_get: Cell<bool>,
        parked: Cell<bool>,
    }

    impl ParkingCache {
        fn release(&self) {
            self.parked.set(false);
        }
    }

    impl SnapshotCache for ParkingCache {
        async fn put(&self, cache_key: &[u8], ciphertext: &[u8]) -> Result<(), SeamError> {
            self.inner.put(cache_key, ciphertext).await
        }

        async fn get(&self, cache_key: &[u8]) -> Result<Option<Vec<u8>>, SeamError> {
            let value = self.inner.get(cache_key).await;
            if self.park_next_get.replace(false) {
                self.parked.set(true);
                poll_fn(|_| {
                    if self.parked.get() {
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
            }
            value
        }

        async fn remove(&self, cache_key: &[u8]) -> Result<(), SeamError> {
            self.inner.remove(cache_key).await
        }

        async fn clear(&self) -> Result<(), SeamError> {
            self.inner.clear().await
        }
    }

    /// A device that cached a renewal takes the real write at the same
    /// sequence, which carries the later EOL, and never goes back (ADR 0061 D3
    /// step 7).
    #[test]
    fn at_one_sequence_the_keeper_takes_the_later_eol() {
        let signer = SessionIdentity::write_name_signer(&[5u8; 32], &[7u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let now = UnixMillis(9_000_000);
        let renewal =
            IpnsRecord::create_v2(&signer, b"/ipfs/renewed", 3, 1, &eol::renewal_eol_from(now))
                .marshal();
        let write =
            IpnsRecord::create_v2(&signer, b"/ipfs/written", 3, 1, &eol::eol_from(now)).marshal();
        let cache = InMemorySnapshotCache::default();
        let key = name.as_str().as_bytes();

        block_on(keep_newest_last_known_good(&cache, &name, &renewal)).unwrap();
        block_on(keep_newest_last_known_good(&cache, &name, &write)).unwrap();
        assert_eq!(
            cache.peek(key),
            Some(write.clone()),
            "the real write replaces the renewal"
        );

        block_on(keep_newest_last_known_good(&cache, &name, &renewal)).unwrap();
        assert_eq!(
            cache.peek(key),
            Some(write),
            "and the renewal never replaces it"
        );
    }

    /// At one sequence and one EOL, the keeper holds the lower record bytes,
    /// in whichever order the two records arrive (ADR 0066 D2).
    #[test]
    fn at_one_sequence_and_one_eol_the_keeper_takes_the_lower_bytes() {
        let signer = SessionIdentity::write_name_signer(&[5u8; 32], &[7u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let eol = eol::eol_from(UnixMillis(9_000_000));
        let mut records = [
            IpnsRecord::create_v2(&signer, b"/ipfs/one", 3, 1, &eol).marshal(),
            IpnsRecord::create_v2(&signer, b"/ipfs/two", 3, 1, &eol).marshal(),
        ];
        records.sort();
        let [lower, higher] = records;
        let key = name.as_str().as_bytes();

        for order in [[&lower, &higher], [&higher, &lower]] {
            let cache = InMemorySnapshotCache::default();
            for record in order {
                block_on(keep_newest_last_known_good(&cache, &name, record)).unwrap();
            }
            assert_eq!(cache.peek(key).as_ref(), Some(&lower));
        }
    }

    /// Two gate passes for one name interleave: the pass that read sequence 6
    /// reads the cache first, and the pass that read 7 runs while that read is
    /// parked. The older pass then finishes last, and the newer copy stays.
    #[test]
    fn an_older_pass_that_finishes_last_keeps_the_newer_copy() {
        let signer = SessionIdentity::write_name_signer(&[5u8; 32], &[6u8; 16]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let record = |sequence| {
            let validity = eol::eol_from(UnixMillis(0));
            IpnsRecord::create_v2(&signer, b"/ipfs/value", sequence, 1, &validity).marshal()
        };
        let (older, newer) = (record(6), record(7));
        let cache = ParkingCache::default();
        cache.park_next_get.set(true);
        let mut cx = Context::from_waker(Waker::noop());

        let mut older_pass = pin!(keep_newest_last_known_good(&cache, &name, &older));
        assert!(older_pass.as_mut().poll(&mut cx).is_pending());
        let mut newer_pass = pin!(keep_newest_last_known_good(&cache, &name, &newer));
        let mut newer_done = newer_pass.as_mut().poll(&mut cx);
        cache.release();
        assert!(matches!(
            older_pass.as_mut().poll(&mut cx),
            Poll::Ready(Ok(_))
        ));
        if newer_done.is_pending() {
            newer_done = newer_pass.as_mut().poll(&mut cx);
        }
        assert!(matches!(newer_done, Poll::Ready(Ok(_))));

        let cached = cache.inner.peek(name.as_str().as_bytes());
        assert_eq!(
            cached.and_then(|cached| verified_rank(&name, &cached).map(|(sequence, _)| sequence)),
            Some(7)
        );
    }
}
