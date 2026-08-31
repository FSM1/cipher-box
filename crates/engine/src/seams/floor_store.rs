//! `FloorStore` — durable monotonic-max floors (blueprint/engine.md).

use core::cell::Cell;
use std::borrow::Cow;
use std::rc::Rc;

use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::x25519::X25519Secret;

use super::{SeamError, SeamResult};
use crate::sync::owner_tag;

/// Durable monotonic-max per-scope epoch floors and per-name sequence
/// floors; regression rejects fail-closed.
///
/// The floor law (blueprint/engine.md, #39 D4) lives in the engine — this
/// seam only stores. Its contract, enforced by the conformance kit
/// (`testkit::conformance::floor_store` under the `test-kit` feature):
///
/// - **Monotonic-max**: a `raise_*` call never lowers a floor. Raising to a
///   value at or below the stored floor is a no-op that reports the stored
///   floor — the store is structurally incapable of regression.
/// - **Durable**: raised floors survive reopening the store (new session,
///   new handle over the same backing).
/// - **Namespaced**: epoch floors and sequence floors are independent maps;
///   identical key bytes in the two namespaces never collide.
///
/// Keys are opaque bytes chosen by the engine (scope identifiers for epoch
/// floors, `ipnsName` bytes for sequence floors); the store never interprets
/// them. Hosts: IndexedDB (web), local journal (desktop).
pub trait FloorStore {
    /// The durable epoch floor for a scope, if one was ever raised.
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>>;

    /// Raises the scope's epoch floor to `max(stored, epoch)`, durably, and
    /// returns the resulting stored floor.
    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64>;

    /// The durable sequence floor for a name, if one was ever raised.
    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>>;

    /// Raises the name's sequence floor to `max(stored, sequence)`, durably,
    /// and returns the resulting stored floor.
    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64>;

    /// Commits a batch of monotonic-max floor raises across both namespaces.
    ///
    /// A single floor advance raises several distinctly-keyed floors at once
    /// (read-epoch, write-epoch, per-name sequence). An implementation closes the
    /// partial-advance hazard one of two ways: **transactionally** (a
    /// cross-key transaction leaves no entry durably changed on error) or by
    /// **roll-forward** (the desktop store fsyncs a batch intent record before any
    /// per-key write and replays it on reopen — it heals forward, never rewinds).
    ///
    /// The default fallback applies the raises one key at a time in the given
    /// order — not atomic. **Callers MUST order entries revocation-before-
    /// liveness**: an interrupted fallback then fails toward *more* restriction
    /// and re-converges idempotently on retry. The web IndexedDB seam rides this
    /// fallback — its JS boundary exposes only the per-key methods — and
    /// web-atomic commit is deferred as a durability/liveness concern, not a
    /// trust hole.
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        for raise in raises {
            match raise.namespace {
                FloorNamespace::Epoch => self.raise_epoch_floor(&raise.key, raise.value).await?,
                FloorNamespace::Sequence => {
                    self.raise_sequence_floor(&raise.key, raise.value).await?
                }
            };
        }
        Ok(())
    }

    /// Drops every floor in both namespaces, durably ("forget this device") —
    /// the one exit from the monotonic ratchet. Floors survive logout by
    /// design; a cleared store re-seeds from the record plane on the next cold
    /// start, so a partial clear would leave the device pinned above records it
    /// can no longer explain — every leg runs even when one refuses, and the
    /// first refusal is what the caller sees.
    async fn clear(&self) -> SeamResult<()>;
}

/// Which of the two independent floor maps a [`FloorRaise`] targets. Identical
/// key bytes in the two namespaces never collide (the single-key methods keep
/// the same separation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorNamespace {
    /// Per-scope epoch floors ([`FloorStore::raise_epoch_floor`]).
    Epoch,
    /// Per-name sequence floors ([`FloorStore::raise_sequence_floor`]).
    Sequence,
}

/// One monotonic-max floor raise inside a [`FloorStore::commit_floors`] batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorRaise {
    /// The map this raise targets.
    pub namespace: FloorNamespace,
    /// Opaque engine-chosen key bytes (scope id or `ipnsName`).
    pub key: Vec<u8>,
    /// The floor value to raise to (`max(stored, value)`).
    pub value: u64,
}

/// `key` behind a fixed-width namespace `prefix`. Fixed width is the whole
/// property: it keeps the prefixed keyspace prefix-free, so no (prefix, key)
/// pair can spell another pair's stored key.
fn prefixed(prefix: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + key.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(key);
    out
}

impl FloorRaise {
    /// An epoch-namespace raise.
    pub fn epoch(key: impl Into<Vec<u8>>, value: u64) -> Self {
        Self {
            namespace: FloorNamespace::Epoch,
            key: key.into(),
            value,
        }
    }

    /// A sequence-namespace raise.
    pub fn sequence(key: impl Into<Vec<u8>>, value: u64) -> Self {
        Self {
            namespace: FloorNamespace::Sequence,
            key: key.into(),
            value,
        }
    }
}

/// One identity's view of a [`FloorStore`]: every key is prefixed with that
/// identity's [`owner_tag`], the way `sync::owner_scoped_key` namespaces the
/// staging stores.
///
/// Which floors a session may reach is decided in-core, from the authenticated
/// secret, and not by the container name the host passed in. Both hosts do open
/// one floor container per account today (`<prefix>-<accountId>-floors` on web,
/// `<accountDir>/floors` on desktop), but that name is a host argument: a host
/// that opened one account's container and started a session under another's
/// secret would corrupt a ratchet nothing can lower again. A vault's own root
/// scope id is the anchored all-zero id16 for **every** account, so the root
/// scope's floors are exactly where two identities would land on one key.
///
/// The tag is bound once, from the session the engine derives at
/// [`start`](crate::facade::Engine::start). Every read and every raise before
/// that refuses — a key read out of the wrong namespace answers "no floor",
/// which is fail-open on the gate's epoch stage.
///
/// The prefix changes the durable key shape with no migration, under the
/// greenfield rule: a device holding pre-cutover floors reads none of them back
/// and re-seeds from the record plane, so it must be forgotten rather than
/// upgraded.
#[derive(Clone)]
pub struct OwnerScopedFloorStore<F> {
    inner: F,
    /// Shared across clones so the handles the spawned loops hold see the bind,
    /// whichever side of it they were cloned on.
    tag: Rc<Cell<Option<[u8; OWNER_TAG_LEN]>>>,
}

/// The fixed-width prefix [`OwnerScopedFloorStore`] puts on every key. Exposed
/// because a reader that strips it back off must strip exactly this many bytes.
pub const OWNER_TAG_LEN: usize = 32;

impl<F> OwnerScopedFloorStore<F> {
    /// An unbound view over `inner` — [`bind`](Self::bind) before any floor.
    pub fn new(inner: F) -> Self {
        Self {
            inner,
            tag: Rc::new(Cell::new(None)),
        }
    }

    /// Binds this view to the identity `enc_secret` belongs to. Called from
    /// [`Engine::start`](crate::facade::Engine::start) and nowhere else: a
    /// start that bound and then failed its login rebinds on the retry, which
    /// is why this rebinds silently rather than refusing.
    pub(crate) fn bind(&self, enc_secret: &X25519Secret) {
        self.tag.set(Some(owner_tag(enc_secret)));
    }

    /// `key` under the bound identity, or a refusal when none is bound.
    fn scoped(&self, key: &[u8]) -> SeamResult<Vec<u8>> {
        let Some(tag) = self.tag.get() else {
            return Err(SeamError::new("floor_store: no identity is bound"));
        };
        Ok(prefixed(&tag, key))
    }
}

impl<F: FloorStore> FloorStore for OwnerScopedFloorStore<F> {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        self.inner.epoch_floor(&self.scoped(scope_id)?).await
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        self.inner
            .raise_epoch_floor(&self.scoped(scope_id)?, epoch)
            .await
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        self.inner.sequence_floor(&self.scoped(ipns_name)?).await
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        self.inner
            .raise_sequence_floor(&self.scoped(ipns_name)?, sequence)
            .await
    }

    /// Scopes each key and hands the batch on whole, so the backing's own
    /// atomicity (or roll-forward) still covers the raises as one commit.
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        let scoped = raises
            .iter()
            .map(|raise| {
                Ok(FloorRaise {
                    namespace: raise.namespace,
                    key: self.scoped(&raise.key)?,
                    value: raise.value,
                })
            })
            .collect::<SeamResult<Vec<_>>>()?;
        self.inner.commit_floors(&scoped).await
    }

    /// The one method that does not scope, matching the device-scoped
    /// [`Command::ForgetDevice`] it serves: the seams never interpret their
    /// contents, so no per-identity filter could make the erase complete. Safe
    /// because both hosts open a per-account backing — a host that ever shares
    /// one across identities owes this seam a prefix-ranged erase before it
    /// does.
    ///
    /// [`Command::ForgetDevice`]: crate::facade::Command::ForgetDevice
    async fn clear(&self) -> SeamResult<()> {
        self.inner.clear().await
    }
}

/// A [`FloorStore`] view for a scope this device reads under **another party's**
/// authority: every epoch-namespace key carries that party's identity key, so
/// the ratchet is per-granting-authority.
///
/// A scope root's `scopeId` is authored by its owner and bound to nothing
/// outside its own record, so two unrelated grants may carry one id — and a
/// vault's own root scope id is the anchored all-zero id16 every account shares.
/// Epoch floors are a durable monotonic ratchet nothing can lower, so one shared
/// key lets any imported contact raise the floor of a scope it has no authority
/// over and pin every later record of that scope below it. Binding the key to
/// the granting identity means a raise can only restrict the scopes that
/// identity actually granted.
///
/// Sequence floors pass through unprefixed: an `ipnsName` is an Ed25519 public
/// key, so no second authority can name one it holds no signing key for.
///
/// The prefix changes the durable key shape with no migration, exactly as
/// [`OwnerScopedFloorStore`]'s does: a device holding pre-cutover floors for an
/// accepted share reads none of them back and must be forgotten, not upgraded.
#[derive(Clone, Copy)]
pub struct SharerScopedFloorStore<'a, F> {
    inner: &'a F,
    /// The granting owner's compressed SEC1 identity key, or `None` for a scope
    /// this vault owns.
    sharer: Option<[u8; IDENTITY_PUBLIC_LEN]>,
}

impl<'a, F> SharerScopedFloorStore<'a, F> {
    /// The view for a scope this vault owns — the plain scope-id key every other
    /// owner-side floor caller reads.
    pub fn own(inner: &'a F) -> Self {
        Self {
            inner,
            sharer: None,
        }
    }

    /// The view for a scope `sharer` granted this device.
    pub fn granted_by(inner: &'a F, sharer: [u8; IDENTITY_PUBLIC_LEN]) -> Self {
        Self {
            inner,
            sharer: Some(sharer),
        }
    }

    /// `scope_id` under the granting identity, borrowed unchanged on the owner
    /// arm. The prefix is fixed-width, so no (identity, scope) pair can spell
    /// another pair's stored key.
    fn scoped<'k>(&self, scope_id: &'k [u8]) -> Cow<'k, [u8]> {
        let Some(sharer) = &self.sharer else {
            return Cow::Borrowed(scope_id);
        };
        Cow::Owned(prefixed(sharer, scope_id))
    }
}

impl<F: FloorStore> FloorStore for SharerScopedFloorStore<'_, F> {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        self.inner.epoch_floor(&self.scoped(scope_id)).await
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        self.inner
            .raise_epoch_floor(&self.scoped(scope_id), epoch)
            .await
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        self.inner.sequence_floor(ipns_name).await
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        self.inner.raise_sequence_floor(ipns_name, sequence).await
    }

    /// Prefixes the epoch entries and hands the batch on whole, so the backing's
    /// own atomicity still covers the raises as one commit.
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        if self.sharer.is_none() {
            return self.inner.commit_floors(raises).await;
        }
        let scoped: Vec<FloorRaise> = raises
            .iter()
            .map(|raise| match raise.namespace {
                FloorNamespace::Epoch => FloorRaise {
                    namespace: raise.namespace,
                    key: self.scoped(&raise.key).into_owned(),
                    value: raise.value,
                },
                FloorNamespace::Sequence => raise.clone(),
            })
            .collect();
        self.inner.commit_floors(&scoped).await
    }

    async fn clear(&self) -> SeamResult<()> {
        self.inner.clear().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryFloorStore;

    use cipherbox_core::kdf;

    /// The vault's own root scope id — the same anchored value for every
    /// account, which is why the two views below collide without the tag.
    const ROOT_SCOPE: [u8; 16] = [0u8; 16];
    const NAME: &[u8] = b"k51-scope-root-name";

    fn view(
        shared: &InMemoryFloorStore,
        secret: &[u8],
    ) -> OwnerScopedFloorStore<InMemoryFloorStore> {
        let view = OwnerScopedFloorStore::new(shared.clone());
        view.bind(&kdf::enc_subkey(secret));
        view
    }

    #[test]
    fn two_identities_on_one_store_share_no_floor() {
        let shared = InMemoryFloorStore::default();
        let alice = view(&shared, &[7u8; 32]);
        let bob = view(&shared, &[9u8; 32]);

        block_on(alice.raise_epoch_floor(&ROOT_SCOPE, 9)).expect("the floor raises");
        block_on(alice.raise_sequence_floor(NAME, 4)).expect("the floor raises");
        block_on(alice.commit_floors(&[FloorRaise::epoch(ROOT_SCOPE.as_slice(), 11)]))
            .expect("the batch commits");

        assert_eq!(
            block_on(bob.epoch_floor(&ROOT_SCOPE)).expect("floor read"),
            None,
            "a second identity provisioning here must not inherit the first's floor"
        );
        assert_eq!(
            block_on(bob.sequence_floor(NAME)).expect("floor read"),
            None
        );
        block_on(bob.raise_epoch_floor(&ROOT_SCOPE, 1)).expect("the floor raises");
        assert_eq!(
            block_on(alice.epoch_floor(&ROOT_SCOPE)).expect("floor read"),
            Some(11),
            "and the first identity's ratchet is untouched by the second's"
        );
    }

    /// The tag is fixed-width, so no (identity, key) pair can spell another
    /// pair's stored key — the property a variable-length prefix would lose.
    #[test]
    fn a_key_cannot_spell_another_identitys_key() {
        let shared = InMemoryFloorStore::default();
        let alice = view(&shared, &[7u8; 32]);
        let bob = view(&shared, &[9u8; 32]);

        block_on(alice.raise_sequence_floor(b"xy", 3)).expect("the floor raises");
        assert_eq!(
            block_on(bob.sequence_floor(b"y")).expect("floor read"),
            None
        );
    }

    /// The attack the sharer prefix exists for: a contact grants a scope whose
    /// `scopeId` collides with one this vault holds elsewhere — the anchored
    /// all-zero root id included — at an epoch far past anything the real scope
    /// will publish at. Under one shared key that raise is a permanent,
    /// unrecoverable lockout, because the ratchet has no descent.
    #[test]
    fn a_sharer_cannot_raise_a_scope_it_did_not_grant() {
        let store = InMemoryFloorStore::default();
        let hostile = SharerScopedFloorStore::granted_by(&store, [0x03; IDENTITY_PUBLIC_LEN]);
        let honest = SharerScopedFloorStore::granted_by(&store, [0x02; IDENTITY_PUBLIC_LEN]);
        let mine = SharerScopedFloorStore::own(&store);

        block_on(hostile.raise_epoch_floor(&ROOT_SCOPE, u64::MAX)).expect("the floor raises");
        block_on(hostile.commit_floors(&[FloorRaise::epoch(ROOT_SCOPE.as_slice(), u64::MAX)]))
            .expect("the batch commits");

        assert_eq!(
            block_on(honest.epoch_floor(&ROOT_SCOPE)).expect("floor read"),
            None,
            "another sharer's grant of the same scope id keeps its own floor"
        );
        assert_eq!(
            block_on(mine.epoch_floor(&ROOT_SCOPE)).expect("floor read"),
            None,
            "and this vault's own scope is out of every contact's reach"
        );
    }

    #[test]
    fn sequence_floors_stay_shared_across_sharers() {
        let store = InMemoryFloorStore::default();
        let sharer = SharerScopedFloorStore::granted_by(&store, [0x02; IDENTITY_PUBLIC_LEN]);

        block_on(sharer.raise_sequence_floor(NAME, 7)).expect("the floor raises");
        block_on(sharer.commit_floors(&[FloorRaise::sequence(NAME, 9)]))
            .expect("the batch commits");

        assert_eq!(
            block_on(SharerScopedFloorStore::own(&store).sequence_floor(NAME)).expect("floor read"),
            Some(9),
            "one name has one sequence ratchet, whoever reads it"
        );
    }

    /// Fail-closed at the consumer, not only at the seam: the gate must refuse,
    /// never read an unbound store as a scope with no floor to enforce.
    #[test]
    fn an_unbound_store_makes_the_gate_refuse() {
        let unbound = OwnerScopedFloorStore::new(InMemoryFloorStore::default());

        let refused = block_on(crate::gate::floor::check(
            &unbound,
            NAME,
            &ROOT_SCOPE,
            9,
            9,
            crate::gate::floor::Strictness::StrictlyNewer,
        ));
        assert!(matches!(refused, Err(crate::gate::GateError::Seam(_))));
    }

    /// Fail-closed, not fail-open: an unscoped read would answer "no floor",
    /// which the gate's epoch stage reads as nothing to enforce.
    #[test]
    fn an_unbound_view_refuses_every_floor() {
        let unbound = OwnerScopedFloorStore::new(InMemoryFloorStore::default());

        assert!(block_on(unbound.epoch_floor(&ROOT_SCOPE)).is_err());
        assert!(block_on(unbound.raise_epoch_floor(&ROOT_SCOPE, 1)).is_err());
        assert!(block_on(unbound.sequence_floor(NAME)).is_err());
        assert!(block_on(unbound.raise_sequence_floor(NAME, 1)).is_err());
        assert!(block_on(unbound.commit_floors(&[FloorRaise::sequence(NAME, 1)])).is_err());
        // The erase is device-scoped, and a device that never started is
        // exactly the one that needs forgetting.
        assert!(block_on(unbound.clear()).is_ok());
    }
}
