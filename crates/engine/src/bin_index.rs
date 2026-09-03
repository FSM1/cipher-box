//! The bin index plane: publish and resolve the owner's record of every
//! soft-deleted node (CONTEXT.md "Bin index", blueprint/engine.md "Bin index
//! record").
//!
//! The record plane is [`crate::settings`]'s, so the floor law, the degradation
//! ladder and the mint-versus-adopt revision pair carry over unchanged. The
//! properties that do not are stated where they bite: the nonce rule at
//! [`publish_bin_index`], the rewrite guard at [`BinIndexLoad::writable`], and
//! the renewal enrolment at [`BinIndexRead::renewable`], which stands in for the
//! settings resolve's lapsed-EOL refusal (blueprint/engine.md "Bin index
//! record").

use core::cell::RefCell;

use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    BinIndex, NodeKind, is_bin_index_over_rung, open_bin_index, seal_bin_index,
};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::api::ApiClient;
use crate::content::Gateway;
use crate::entropy::{Entropy, EntropyError, fresh_nonce};
use crate::gate::floor;
use crate::gate::floor::RevisionMintError;
use crate::net::fanout_get_verify;
use crate::net::fetch_head_block;
use crate::net::liveness::{HeldRecord, HeldValue};
use crate::net::publish::{PublishOutcome, head_cid_from_value};
use crate::net::record_publish::{
    PreflightError, RecordPublishError, RecordPublishRequest, preflight_bin_index, publish_record,
};
use crate::net::retire::{OrphanHeads, orphaned_head};
use crate::profile::SyncTimingProfile;
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SeamError, SnapshotCache,
};
use crate::settings::{DefaultsReason, prefixed_key, unresolved_reason, within};

/// What a bin index load produced.
///
/// The three rungs the settings record's load has, named for this plane: an
/// empty bin is what a vault with nothing soft-deleted holds, so it is the
/// bottom rung rather than an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinIndexLoad {
    /// The published record opened and cleared the floor law.
    Resolved(BinIndex),
    /// No usable published record, but this device's last-known-good copy
    /// opened: the entries it names were binned, but a newer publish from
    /// another device may not be here.
    Stale {
        /// The index this device last adopted.
        index: BinIndex,
        /// Why the published record was not used.
        reason: DefaultsReason,
    },
    /// Neither a published record nor a cached one.
    Empty(DefaultsReason),
}

impl BinIndexLoad {
    /// The index a publish may build on, or the reason it may not.
    ///
    /// The bin index is rewritten whole, so a publish over anything but the
    /// current index silently drops entries. Only a resolved record establishes
    /// the current index, and only a first run this device can find no durable
    /// mark for establishes that there is none yet. Every other outcome refuses:
    /// the caller retries on a later tick rather than publishing over a copy it
    /// cannot show is current.
    pub fn writable(self) -> Result<BinIndex, DefaultsReason> {
        match self {
            Self::Resolved(index) => Ok(index),
            Self::Empty(DefaultsReason::UnprovenFirstRun) => Ok(BinIndex::new(0)),
            Self::Stale { reason, .. } | Self::Empty(reason) => Err(reason),
        }
    }
}

/// What one bin entry says, copied out of the index for a caller that acts on
/// it — a restore, a purge, or the expiry that queues one.
///
/// A copy, so it is a terminal owner in its own right: `ipnsName` and
/// `originName` are sealed-record plaintext, and the entry they came from wipes
/// its own buffers while this one outlives the index it was read from.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct BinnedNode {
    /// The name the node's own record publishes under.
    pub(crate) ipns_name: Vec<u8>,
    /// The node's immutable kind.
    #[zeroize(skip)]
    pub(crate) kind: NodeKind,
    /// The scope the node was sealed under at the delete.
    #[zeroize(skip)]
    pub(crate) scope_id: [u8; 16],
    /// The folder the node was unlinked from — a restore's default destination.
    #[zeroize(skip)]
    pub(crate) origin_parent: [u8; 16],
    /// The name the node carried in that folder.
    pub(crate) origin_name: String,
    /// The injected deletion time. Also the per-delete half of the bin-held key.
    #[zeroize(skip)]
    pub(crate) deleted_at: u64,
}

impl BinnedNode {
    /// The standing entry for `node`, or `None` when the index holds none.
    pub(crate) fn of(index: &BinIndex, node: &[u8; 16]) -> Option<Self> {
        index
            .entries
            .iter()
            .find(|entry| entry.node_id == *node)
            .map(|entry| Self {
                ipns_name: entry.ipns_name().to_vec(),
                kind: entry.kind,
                scope_id: entry.scope_id,
                origin_parent: entry.origin_parent,
                origin_name: entry.origin_name().to_owned(),
                deleted_at: entry.deleted_at,
            })
    }
}

/// Why a bin index publish did not reach the network. Every variant is
/// fail-closed: nothing is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinIndexPublishError {
    /// Core refused to encode or seal the body — a duplicate `nodeId` or an
    /// over-bound field.
    Codec(CodecError),
    /// The body is past the top rung, so the bin holds all the entries one
    /// record can carry. Distinct from [`Self::Codec`] because no re-author
    /// shrinks it: only the expiry sweep frees space.
    Full,
    /// The host could not supply the per-seal nonce.
    Entropy(EntropyError),
    /// The sealed record failed its pre-publish dry run.
    Preflight(PreflightError),
    /// The shared publish port failed.
    Publish(RecordPublishError),
    /// The record reached the network but the confirm re-resolve did not return
    /// our own bytes at our own sequence, so the update is not known to have
    /// landed and the floor must not advance behind it.
    Unconfirmed,
    /// The confirmed publish could not be recorded durably.
    Floor(SeamError),
    /// The durable revision counter did not advance, so this publish would mint
    /// a body revision the reader refuses (AGENTS.md rule 8).
    Revision,
}

/// Tell a bin the top rung no longer admits from every other encode refusal,
/// so the host reads a full bin rather than a codec defect.
fn publish_refusal(error: CodecError) -> BinIndexPublishError {
    if is_bin_index_over_rung(&error) {
        return BinIndexPublishError::Full;
    }
    BinIndexPublishError::Codec(error)
}

/// The bin's own key material, derived once from the login secret.
///
/// The publish, load and re-key paths take this rather than the login secret, so
/// the spawned task that bins a node holds only what the bin needs (AGENTS.md
/// security rule 1). The held-key edge factors into a per-account half and a
/// per-delete half, so the whole edge is reachable from the account half alone.
pub struct BinIndexKeys {
    signer: Ed25519Signer,
    seal_key: SecretBytes,
    held_root: SecretBytes,
    name: IpnsName,
}

impl BinIndexKeys {
    /// Derive the `bin-index-ipns-keypair`, `bin-index-seal-key` and
    /// `bin-held-key` edges.
    #[must_use]
    pub fn derive(login_secret: &[u8]) -> Self {
        let signer = kdf::bin_index_ipns_keypair(login_secret);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        Self {
            signer,
            seal_key: kdf::bin_index_seal_key(login_secret),
            held_root: kdf::bin_held_root(login_secret),
            name,
        }
    }

    /// The IPNS name the bin index record is published under.
    #[must_use]
    pub fn name(&self) -> &IpnsName {
        &self.name
    }

    /// The seed the doomed subtree rooted at `node_id` re-seals under, which is
    /// the whole of the access cut: no scope seed of any epoch is an input, so
    /// key regression cannot reach it (ADR 0010 item 3).
    #[must_use]
    pub fn held_key(&self, node_id: &[u8; 16], deleted_at: u64) -> Zeroizing<[u8; SECRET_LEN]> {
        Zeroizing::new(
            *kdf::bin_held_key(self.held_root.as_bytes(), node_id, deleted_at).as_bytes(),
        )
    }
}

/// The reader's body-revision bar, kept apart from the writer's counter at
/// [`revision_mint_key`] ([`floor::mint_revision`]).
fn revision_adopted_key(name: &IpnsName) -> Vec<u8> {
    prefixed_key(b"bin-index-revision/", name)
}

fn revision_mint_key(name: &IpnsName) -> Vec<u8> {
    prefixed_key(b"bin-index-revision-mint/", name)
}

/// The bin index head block's own snapshot-cache key, kept apart from the
/// record-plane keys [`crate::net::resolve()`] writes.
fn bin_index_cache_key(name: &IpnsName) -> Vec<u8> {
    prefixed_key(b"bin-index-head/", name)
}

/// This device's last-known-good bin index, off the snapshot cache alone.
///
/// For the reader that only needs to know an entry is *due* something, and whose
/// action re-reads the resolved index before it acts: the expiry sweep runs on
/// every poll tick, and a record resolve per tick buys a decision that retention
/// measures in days. Every write path refreshes this cache, so a device that has
/// ever loaded the bin has a copy.
pub(crate) async fn cached_bin_index<Sn: SnapshotCache>(
    snapshots: &Sn,
    keys: &BinIndexKeys,
) -> Option<BinIndex> {
    let block = snapshots
        .get(&bin_index_cache_key(&keys.name))
        .await
        .ok()
        .flatten()?;
    open_bin_index(keys.seal_key.as_bytes(), &block).ok()
}

/// Whether this device holds any durable mark for the bin index name.
///
/// The genesis publish's cheap gate: the mint arm it runs for is the one a load
/// reaches only with no record *and* no mark, so a marked device already knows
/// the answer without the fanout resolve and head fetch that would repeat it. A
/// floor the host cannot read answers `true`, which is where the load's own
/// `FloorUnreadable` rung leaves the publish.
pub(crate) async fn holds_a_bin_index_mark<F: FloorStore>(floors: &F, keys: &BinIndexKeys) -> bool {
    let name = &keys.name;
    let minted = revision_mint_key(name);
    let adopted = revision_adopted_key(name);
    for key in [name.as_str().as_bytes(), &minted, &adopted] {
        if !matches!(floor::sequence_floor(floors, key).await, Ok(None)) {
            return true;
        }
    }
    false
}

/// The next body revision for this account's bin index record.
async fn next_revision<F: FloorStore>(
    floors: &F,
    name: &IpnsName,
) -> Result<u64, BinIndexPublishError> {
    floor::mint_revision(
        floors,
        &revision_mint_key(name),
        &revision_adopted_key(name),
    )
    .await
    .map_err(|error| match error {
        RevisionMintError::Store(error) => BinIndexPublishError::Floor(error),
        RevisionMintError::Stalled => BinIndexPublishError::Revision,
    })
}

/// Seal `index` and publish it at [`BinIndexKeys::name`] through the shared
/// publish port, so the record inherits register-first, seq-CAS, and confirm.
///
/// **The nonce is drawn fresh from the entropy seam on every publish.**
/// `bin-index-seal-key` takes no epoch input, so it never rotates: one key seals
/// every publish this account makes, on every device. A counter, or a nonce
/// derived from the revision or the sequence, is unique on one device and
/// collides across two — and two devices publish this record concurrently under
/// one CAS guard. Nonce reuse under one XChaCha20-Poly1305 key discloses every
/// `heldKey` the two bodies carry.
///
/// The body revision is minted here, from the durable counter; `index.revision`
/// is not read. The entries and the preserved unknown fields are the caller's,
/// so a rewrite re-emits a field a later build added.
///
/// Returns the confirmed record as a [`HeldRecord`] for the session's renewal
/// set: the record carries a client-signed 90-day EOL and the API republisher is
/// keyless, so a name nobody renews lapses and the owner's bin goes unreachable.
#[allow(clippy::too_many_arguments)]
pub async fn publish_bin_index<T, H, C, F, Sn, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    snapshots: &Sn,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    entropy: &mut dyn Entropy,
    orphans: &OrphanHeads,
    keys: &BinIndexKeys,
    index: &BinIndex,
) -> Result<HeldRecord, BinIndexPublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sn: SnapshotCache,
    Sch: Scheduler + Clone + 'static,
{
    let name = &keys.name;
    let revision = next_revision(floors, name).await?;
    let nonce = fresh_nonce(entropy).map_err(BinIndexPublishError::Entropy)?;
    let seal_key = &keys.seal_key;
    let minted = BinIndex {
        revision,
        entries: index.entries.clone(),
        unknown: index.unknown.clone(),
    };
    let block = seal_bin_index(seal_key.as_bytes(), &nonce, &minted).map_err(publish_refusal)?;
    let head = preflight_bin_index(seal_key.as_bytes(), block.clone())
        .map_err(BinIndexPublishError::Preflight)?;

    let receipt = match publish_record(
        transport,
        api,
        floors,
        scheduler,
        profile,
        &RecordPublishRequest {
            name,
            signer: &keys.signer,
            head: &head,
            content_cids: Vec::new(),
            min_current_sequence: None,
        },
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            // This publish runs outside a drain pass, so it clears its own
            // orphan set rather than deferring to a pass boundary.
            if orphaned_head(&error) {
                orphans.record(head.cid());
                orphans.retire_pending(api).await;
            }
            return Err(BinIndexPublishError::Publish(error));
        }
    };

    let PublishOutcome::Published { sequence } = receipt.outcome else {
        return Err(BinIndexPublishError::Unconfirmed);
    };
    let _ = snapshots.put(&bin_index_cache_key(name), &block).await;
    floor::advance_sequence_on_unseal(floors, name.as_str().as_bytes(), sequence)
        .await
        .map_err(BinIndexPublishError::Floor)?;
    floor::advance_sequence_on_unseal(floors, &revision_adopted_key(name), revision)
        .await
        .map_err(BinIndexPublishError::Floor)?;
    Ok(HeldRecord {
        routing_key: name.as_str().to_owned(),
        record_bytes: receipt.record_bytes,
        signer: keys.signer.clone(),
        value: HeldValue::Head(head.cid().to_owned()),
        // The bin index record anchors its sealed body and nothing else.
        content_cids: Vec::new(),
    })
}

/// A bin index load, with the record the plane served at the bin index name.
pub struct BinIndexRead {
    /// What the degradation ladder produced.
    pub load: BinIndexLoad,
    /// The record standing at the name, for the session's renewal set.
    ///
    /// A read alone enrols the record, which is what keeps the EOL alive on a
    /// session that publishes nothing, and so what keeps a live account away
    /// from the lapse this plane does not refuse.
    ///
    /// Two bars, because the renewal re-signs at `floor + 1` and so promotes
    /// whatever it is given. The record must have cleared the whole floor law,
    /// or a replay or a fork would be re-signed into winning record selection.
    /// And this device must already hold a sequence floor for the name, or it
    /// has nothing of its own against which to judge the age of what the plane
    /// served — the bar the lapsed-EOL refusal used to carry
    /// (blueprint/engine.md "Bin index record").
    pub renewable: Option<HeldRecord>,
}

impl BinIndexRead {
    /// Put the renewable record in the session's slot and hand back the load.
    ///
    /// Every caller enrols: a load that reads and does not enrol is what lets
    /// the record's EOL lapse under a session that publishes nothing.
    ///
    /// `observed` is the record bytes the slot held when the load began, and the
    /// write happens only while the slot still holds them. A command load and
    /// the drain interleave on one executor, so a publish that landed across
    /// this load has already put its own confirmed record here; the renewal
    /// re-signs at `floor + 1`, so re-signing this pass's older read would win
    /// record selection and bring back the entries that publish removed. The
    /// bar [`SettingsRead::enrol`](crate::settings::SettingsRead::enrol) holds
    /// its own slot to.
    pub fn enrol(
        self,
        slot: &RefCell<Option<HeldRecord>>,
        observed: Option<Vec<u8>>,
    ) -> BinIndexLoad {
        if let Some(renewable) = self.renewable {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().map(|held| held.record_bytes.as_slice()) == observed.as_deref() {
                *slot = Some(renewable);
            }
        }
        self.load
    }
}

/// Resolve the bin index record, bounded by
/// [`SyncTimingProfile::settings_load_budget`] — the same bound the vault
/// settings load runs under, because this is the same class of owner record read
/// off the login secret alone, and neither may block its caller.
///
/// Never fails: a record that will not resolve, will not open, or will not clear
/// the floor law degrades to this device's last-known-good copy and only then to
/// an empty bin. [`BinIndexLoad::writable`] is what stops a degraded outcome
/// reaching a publish.
#[allow(clippy::too_many_arguments)]
pub async fn load_bin_index<T, H, F, Sn, Sch>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    snapshots: &Sn,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    keys: &BinIndexKeys,
) -> BinIndexRead
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
    Sch: Scheduler,
{
    let seal_key = &keys.seal_key;
    // Held outside the budget so a load that runs out of it mid-resolve still
    // has the cached ciphertext the resolve read on its way in.
    let mut cached = None;
    let load = resolve_bin_index(
        transport,
        gateway,
        http,
        floors,
        snapshots,
        &mut cached,
        keys,
    );
    let reason = match within(scheduler, profile.settings_load_budget, load).await {
        Some(Ok((index, renewable))) => {
            return BinIndexRead {
                load: BinIndexLoad::Resolved(index),
                renewable,
            };
        }
        Some(Err(reason)) => reason,
        None => DefaultsReason::TimedOut,
    };
    // The cached copy clears the same seal open the fetched one does; being
    // cached buys bytes nothing.
    let load = match cached.and_then(|block| open_bin_index(seal_key.as_bytes(), &block).ok()) {
        Some(index) => BinIndexLoad::Stale { index, reason },
        None => BinIndexLoad::Empty(reason),
    };
    BinIndexRead {
        load,
        renewable: None,
    }
}

/// The resolved index and the record to enrol for renewal
/// ([`BinIndexRead::renewable`]), or the reason the ladder degrades.
#[allow(clippy::too_many_arguments)]
async fn resolve_bin_index<T, H, F, Sn>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    snapshots: &Sn,
    cached: &mut Option<Vec<u8>>,
    keys: &BinIndexKeys,
) -> Result<(BinIndex, Option<HeldRecord>), DefaultsReason>
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
{
    let name = &keys.name;
    let seal_key = &keys.seal_key;
    let key = name.as_str().as_bytes();
    let cache_key = bin_index_cache_key(name);
    // Read ahead of the resolve so a degraded outcome has last-known-good to
    // fall back on; the cache never short-circuits the fetch.
    *cached = snapshots.get(&cache_key).await.ok().flatten();
    // No scope and no epoch, so the per-name sequence floor and the adopted body
    // revision are this record's whole floor law.
    let Ok(durable) = floor::sequence_floor(floors, key).await else {
        return Err(DefaultsReason::FloorUnreadable);
    };
    let Some((verified, record_bytes)) = fanout_get_verify(transport, name).await else {
        // All three marks answer here, because only here does their absence
        // still let a publish mint a first index. Each is raised where the
        // sequence floor is not.
        let (Ok(minted), Ok(adopted)) = (
            floor::sequence_floor(floors, &revision_mint_key(name)).await,
            floor::sequence_floor(floors, &revision_adopted_key(name)).await,
        ) else {
            return Err(DefaultsReason::FloorUnreadable);
        };
        return Err(unresolved_reason(durable, minted, adopted));
    };
    let sequence = verified.sequence;
    let floor = durable.unwrap_or(0);
    if sequence < floor {
        return Err(DefaultsReason::RolledBack { floor, sequence });
    }

    // The name only this account can sign for, so an absent head block is a
    // withheld bin index.
    let Ok((_, block)) = fetch_head_block(gateway, http, name, &record_bytes, None).await else {
        return Err(DefaultsReason::Suppressed);
    };
    let index =
        open_bin_index(seal_key.as_bytes(), &block).map_err(|_| DefaultsReason::Unreadable)?;
    let adopted_key = revision_adopted_key(name);
    let Ok(adopted) = floor::sequence_floor(floors, &adopted_key).await else {
        return Err(DefaultsReason::FloorUnreadable);
    };
    let adopted = adopted.unwrap_or(0);
    // The revision arbitrates only what the sequence cannot: a fork *at* the
    // adopted sequence.
    if sequence == floor && index.revision < adopted {
        return Err(DefaultsReason::RevisionRolledBack {
            floor: adopted,
            revision: index.revision,
        });
    }
    // Both bars are behind this point ([`BinIndexRead::renewable`]).
    let renewable = durable
        .and_then(|_| head_cid_from_value(&verified.value))
        .map(|head_cid| HeldRecord {
            routing_key: name.as_str().to_owned(),
            record_bytes,
            signer: keys.signer.clone(),
            value: HeldValue::Head(head_cid),
            content_cids: Vec::new(),
        });
    // Ciphertext at rest: the sealed block, never the opened index.
    let _ = snapshots.put(&cache_key, &block).await;
    let _ = floor::advance_sequence_on_unseal(floors, key, sequence).await;
    let _ = floor::advance_sequence_on_unseal(floors, &adopted_key, index.revision).await;
    Ok((index, renewable))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bin index is rewritten whole, so only a load that establishes the
    /// current index may be published over. v1's whole-list rewrite over an
    /// unestablished copy is the named data-loss bug this refuses.
    #[test]
    fn only_an_established_index_is_writable() {
        let index = BinIndex::new(9);
        assert_eq!(
            BinIndexLoad::Resolved(index.clone()).writable(),
            Ok(index.clone()),
        );
        assert_eq!(
            BinIndexLoad::Empty(DefaultsReason::UnprovenFirstRun).writable(),
            Ok(BinIndex::new(0)),
            "a device with no durable mark may mint the first index",
        );
        for reason in [
            DefaultsReason::Suppressed,
            DefaultsReason::RolledBack {
                floor: 4,
                sequence: 2,
            },
            DefaultsReason::RevisionRolledBack {
                floor: 4,
                revision: 2,
            },
            DefaultsReason::TimedOut,
            DefaultsReason::Unreadable,
            DefaultsReason::FloorUnreadable,
        ] {
            assert_eq!(
                BinIndexLoad::Empty(reason).writable(),
                Err(reason),
                "{reason:?} must never be published over",
            );
            assert_eq!(
                BinIndexLoad::Stale {
                    index: index.clone(),
                    reason,
                }
                .writable(),
                Err(reason),
                "{reason:?}: a cached copy may be behind another device's publish",
            );
        }
    }

    /// The durable marks are keyed apart from each other and from the bare name
    /// the per-name sequence floor uses, or one would raise another's bar.
    #[test]
    fn every_durable_mark_takes_its_own_key() {
        let name = BinIndexKeys::derive(&[3u8; 32]).name().clone();
        let keys = [
            name.as_str().as_bytes().to_vec(),
            revision_adopted_key(&name),
            revision_mint_key(&name),
            bin_index_cache_key(&name),
        ];
        for (i, key) in keys.iter().enumerate() {
            for other in &keys[i + 1..] {
                assert_ne!(key, other);
            }
        }
    }

    /// The bin and the settings record are two records of one owner, so their
    /// names must not collide.
    #[test]
    fn the_bin_publishes_at_a_name_the_settings_record_never_takes() {
        let secret = [3u8; 32];
        assert_ne!(
            BinIndexKeys::derive(&secret).name(),
            &crate::settings::settings_name(&secret),
        );
    }
}
