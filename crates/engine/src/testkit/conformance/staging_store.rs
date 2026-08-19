//! Conformance kit: [`StagingStore`] FIFO ordering, durability, orphan-GC
//! support, and `put_staged_bytes` failure atomicity.

use crate::seams::StagingStore;

/// The staging key the failure-atomicity phases write, so a host whose fault
/// injector is scoped to one key can arm exactly the put the kit makes fail.
pub const FAILED_PUT_KEY: &[u8] = b"failed-put-key";

/// Which of the kit's backings the host is being asked for.
///
/// Each names a **distinct** durable backing that starts empty; repeat `open`
/// calls for the same one must reopen it (new handle, same durable state), which
/// is how the kit asserts durability without a process restart. The failure
/// phases cannot share a backing with the ordering phase or with each other:
/// one needs an established record to defend, the next needs a key that has
/// never been written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backing {
    /// FIFO ordering, durability, and orphan-GC support.
    Ordering,
    /// Failure atomicity of a put that replaces an existing record.
    FailedReplacement,
    /// Failure atomicity of a put at a key that held nothing.
    FailedFirstPut,
}

impl Backing {
    /// A stable label a host can key a directory, database name, or map entry
    /// off to keep its backings apart.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ordering => "ordering",
            Self::FailedReplacement => "failed-replacement",
            Self::FailedFirstPut => "failed-first-put",
        }
    }
}

/// Runs the whole `StagingStore` contract against an implementation.
///
/// `arm_failed_put` is the fault lever the failure-atomicity phases need and the
/// kit cannot supply: it must make the named backing's next `put_staged_bytes`
/// at [`FAILED_PUT_KEY`] fail (exhausted quota, a short write, a denied
/// directory; the host picks its own). It is a parameter rather than a second
/// entry point so a host cannot be held to only the half of the contract it
/// remembered to ask for.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<S, F, G>(mut open: F, mut arm_failed_put: G)
where
    S: StagingStore,
    F: AsyncFnMut(Backing) -> S,
    G: AsyncFnMut(Backing),
{
    ordering_and_durability(&mut open).await;
    failed_replacement_put(&mut open, &mut arm_failed_put).await;
    failed_first_put(&mut open, &mut arm_failed_put).await;
}

/// FIFO ordering, id progression, staged-byte accounting, orphan-GC support,
/// and the durability of all four across reopen.
async fn ordering_and_durability<S, F>(open: &mut F)
where
    S: StagingStore,
    F: AsyncFnMut(Backing) -> S,
{
    let store = open(Backing::Ordering).await;

    // Fresh backing.
    assert!(store.queued_ops().await.unwrap().is_empty());
    assert!(store.staged_keys().await.unwrap().is_empty());
    assert_eq!(store.staged_bytes_total().await.unwrap(), 0);

    // FIFO with strictly increasing ids.
    let id_a = store.enqueue_op(b"op-a").await.unwrap();
    let id_b = store.enqueue_op(b"op-b").await.unwrap();
    let id_c = store.enqueue_op(b"op-c").await.unwrap();
    assert!(
        id_a < id_b && id_b < id_c,
        "op ids must be strictly increasing"
    );

    let ops = store.queued_ops().await.unwrap();
    assert_eq!(
        ops,
        vec![
            (id_a, b"op-a".to_vec()),
            (id_b, b"op-b".to_vec()),
            (id_c, b"op-c".to_vec()),
        ],
        "queued ops must come back FIFO with payloads verbatim"
    );

    // Removal preserves the order of survivors; removing again is
    // idempotent.
    store.remove_op(id_b).await.unwrap();
    store.remove_op(id_b).await.unwrap();
    assert_eq!(
        store.queued_ops().await.unwrap(),
        vec![(id_a, b"op-a".to_vec()), (id_c, b"op-c".to_vec())],
        "removing one op must not disturb FIFO order"
    );

    // Staged bytes: verbatim round-trip, replacement, exact accounting.
    store.put_staged_bytes(b"key-1", b"12345").await.unwrap();
    store.put_staged_bytes(b"key-2", b"1234567").await.unwrap();
    assert_eq!(
        store.staged_bytes(b"key-1").await.unwrap(),
        Some(b"12345".to_vec())
    );
    assert_eq!(store.staged_bytes_total().await.unwrap(), 12);

    store.put_staged_bytes(b"key-1", b"123").await.unwrap();
    assert_eq!(
        store.staged_bytes_total().await.unwrap(),
        10,
        "replacing staged bytes must not double-count"
    );

    // Orphan-GC support: enumeration and removal are exact.
    let mut keys = store.staged_keys().await.unwrap();
    keys.sort();
    assert_eq!(keys, vec![b"key-1".to_vec(), b"key-2".to_vec()]);

    store.remove_staged_bytes(b"key-1").await.unwrap();
    store.remove_staged_bytes(b"key-1").await.unwrap(); // idempotent
    assert_eq!(store.staged_bytes(b"key-1").await.unwrap(), None);
    assert_eq!(store.staged_keys().await.unwrap(), vec![b"key-2".to_vec()]);
    assert_eq!(store.staged_bytes_total().await.unwrap(), 7);

    // Durability: queue order, staged bytes, and id progression survive
    // reopen.
    let reopened = open(Backing::Ordering).await;
    assert_eq!(
        reopened.queued_ops().await.unwrap(),
        vec![(id_a, b"op-a".to_vec()), (id_c, b"op-c".to_vec())],
        "the op queue must survive reopen in order"
    );
    assert_eq!(
        reopened.staged_bytes(b"key-2").await.unwrap(),
        Some(b"1234567".to_vec()),
        "staged bytes must survive reopen"
    );
    let id_d = reopened.enqueue_op(b"op-d").await.unwrap();
    assert!(
        id_d > id_c,
        "op ids must never be reused, even across reopen"
    );

    // Removing the highest id must not release it while lower ids are still
    // queued. The engine's queue-scan memo reads an unchanged high-water id plus
    // an unchanged length as proof that nothing was enqueued or removed,
    // so a store allocating `max(queued) + 1` would hand the next op the id it
    // just freed and rebuild that exact pair over different records.
    reopened.remove_op(id_d).await.unwrap();
    let id_e = reopened.enqueue_op(b"op-e").await.unwrap();
    assert!(
        id_e > id_d,
        "a removed high-water op id must never be handed out again"
    );

    // Nor may draining the queue empty restart the progression.
    for id in [id_a, id_c, id_e] {
        reopened.remove_op(id).await.unwrap();
    }
    assert!(reopened.queued_ops().await.unwrap().is_empty());

    let drained = open(Backing::Ordering).await;
    let id_f = drained.enqueue_op(b"op-f").await.unwrap();
    assert!(
        id_f > id_e,
        "an op id must never be reused, not even after the queue drains empty"
    );
}

/// A put that returns `Err` over an existing record must leave the previous
/// bytes exactly as it found them.
async fn failed_replacement_put<S, F, G>(open: &mut F, arm_failed_put: &mut G)
where
    S: StagingStore,
    F: AsyncFnMut(Backing) -> S,
    G: AsyncFnMut(Backing),
{
    let backing = Backing::FailedReplacement;
    let store = open(backing).await;
    assert!(
        store.staged_keys().await.unwrap().is_empty(),
        "every kit backing is its own, and starts empty"
    );

    let previous = b"the-previously-staged-record";
    store
        .put_staged_bytes(FAILED_PUT_KEY, previous)
        .await
        .unwrap();
    let total = store.staged_bytes_total().await.unwrap();

    arm_failed_put(backing).await;
    assert!(
        store
            .put_staged_bytes(FAILED_PUT_KEY, b"a-longer-replacement-that-must-not-land")
            .await
            .is_err(),
        "an armed put must report the failure rather than succeed"
    );

    // Read back through a fresh handle: what must survive is the durable
    // record, not what the handle that failed still remembers.
    let reopened = open(backing).await;
    assert_eq!(
        reopened
            .staged_bytes(FAILED_PUT_KEY)
            .await
            .unwrap()
            .as_deref(),
        Some(previous.as_slice()),
        "a failed put must leave the previous bytes readable and unchanged"
    );
    assert!(
        reopened
            .staged_keys()
            .await
            .unwrap()
            .contains(&FAILED_PUT_KEY.to_vec()),
        "a failed put must not unpublish the key it failed to replace"
    );
    assert_eq!(
        reopened.staged_bytes_total().await.unwrap(),
        total,
        "a failed put must leave the staging budget on the surviving bytes"
    );
}

/// A put that returns `Err` for a key that held nothing must leave that key
/// absent — never an empty or half-written record.
async fn failed_first_put<S, F, G>(open: &mut F, arm_failed_put: &mut G)
where
    S: StagingStore,
    F: AsyncFnMut(Backing) -> S,
    G: AsyncFnMut(Backing),
{
    let backing = Backing::FailedFirstPut;
    let store = open(backing).await;
    assert!(
        store.staged_keys().await.unwrap().is_empty(),
        "this phase reads the key's absence as the result, so the backing must start empty"
    );

    arm_failed_put(backing).await;
    assert!(
        store
            .put_staged_bytes(FAILED_PUT_KEY, b"a-first-record-that-must-not-land")
            .await
            .is_err(),
        "an armed put must report the failure rather than succeed"
    );

    // Read back through a fresh handle: what must be absent is the durable
    // record, not what the handle that failed still remembers.
    let reopened = open(backing).await;
    assert_eq!(
        reopened.staged_bytes(FAILED_PUT_KEY).await.unwrap(),
        None,
        "a failed first put must leave no record at the key"
    );
    assert!(
        !reopened
            .staged_keys()
            .await
            .unwrap()
            .contains(&FAILED_PUT_KEY.to_vec()),
        "a failed first put must not publish a key the caller never staged"
    );
    assert_eq!(
        reopened.staged_bytes_total().await.unwrap(),
        0,
        "a failed first put must charge the staging budget nothing"
    );
}
