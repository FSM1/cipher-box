//! The one write path for a name's last-known-good record in the snapshot
//! cache.

use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Poll, Waker};
use std::collections::BTreeMap;

use cipherbox_core::ipns::{IpnsName, IpnsRecord};

use crate::seams::{SeamError, SnapshotCache};

/// Leave `record_bytes`, a gate pass for `name`, as last-known-good unless the
/// cached copy already sits at or above its sequence.
///
/// Every path that caches a name's record calls this **before** it moves that
/// name's floor: a read that finds no source opens the cached copy at the
/// floor, so a floor raised past the cached copy leaves that read nothing it
/// can open. The two still drift apart the other way — a pass that cached but
/// failed its floor commit leaves a newer copy — so the put compares sequences
/// rather than trusting the order of passes, and holds the name's [`NameLock`]
/// across the read and the put so two passes cannot interleave them.
pub(crate) async fn keep_newest_last_known_good<S: SnapshotCache>(
    snapshot_cache: &S,
    name: &IpnsName,
    record_bytes: &[u8],
) -> Result<(), SeamError> {
    let key = name.as_str().as_bytes();
    let _writing = NameLock::acquire(key).await;
    let cached = snapshot_cache.get(key).await?;
    if cached.as_deref() == Some(record_bytes) {
        return Ok(());
    }
    let cached_sequence = cached.and_then(|cached| verified_sequence(name, &cached));
    if cached_sequence.is_some_and(|cached| Some(cached) >= verified_sequence(name, record_bytes)) {
        return Ok(());
    }
    snapshot_cache.put(key, record_bytes).await
}

fn verified_sequence(name: &IpnsName, record_bytes: &[u8]) -> Option<u64> {
    IpnsRecord::unmarshal(record_bytes)
        .and_then(|record| record.verify(name))
        .ok()
        .map(|verified| verified.sequence)
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
            Poll::Ready(Ok(()))
        ));
        if newer_done.is_pending() {
            newer_done = newer_pass.as_mut().poll(&mut cx);
        }
        assert!(matches!(newer_done, Poll::Ready(Ok(()))));

        let cached = cache.inner.peek(name.as_str().as_bytes());
        assert_eq!(
            cached.and_then(|cached| verified_sequence(&name, &cached)),
            Some(7)
        );
    }
}
