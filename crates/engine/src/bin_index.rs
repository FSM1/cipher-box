//! The bin index plane: publish and resolve the owner's record of every
//! soft-deleted node (CONTEXT.md "Bin index", blueprint/engine.md "Bin index
//! record").
//!
//! The record plane is [`crate::settings`]'s, so the floor law, the degradation
//! ladder and the mint-versus-adopt revision pair carry over unchanged. The two
//! properties that do not are stated where they bite: the nonce rule at
//! [`publish_bin_index`], and the rewrite guard at [`BinIndexLoad::writable`].

use core::fmt;

use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{BinIndex, open_bin_index, seal_bin_index};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;

use crate::api::ApiClient;
use crate::content::Gateway;
use crate::entropy::{Entropy, EntropyError, fresh_nonce};
use crate::gate::floor;
use crate::gate::floor::RevisionMintError;
use crate::net::eol::is_expired;
use crate::net::fanout_get_verify;
use crate::net::fetch_head_block;
use crate::net::liveness::{HeldRecord, HeldValue};
use crate::net::publish::PublishOutcome;
use crate::net::record_publish::{
    PreflightError, RecordPublishError, RecordPublishRequest, preflight_bin_index, publish_record,
};
use crate::net::retire::{OrphanHeads, orphaned_head};
use crate::profile::SyncTimingProfile;
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SeamError, SnapshotCache,
    UnixMillis,
};
use crate::settings::{DefaultsReason, prefixed_key, within};

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

/// Why a bin index publish did not reach the network. Every variant is
/// fail-closed: nothing is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinIndexPublishError {
    /// Core refused to encode or seal the body — a duplicate `nodeId`, an
    /// over-bound field, or a body no rung admits.
    Codec(CodecError),
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

/// The bin index's own key material, derived once from the login secret.
///
/// The publish and load paths take this rather than the login secret, so the
/// spawned task that writes a bin entry holds only what the bin index needs
/// (AGENTS.md security rule 1).
#[derive(Clone)]
pub struct BinIndexKeys {
    signer: Ed25519Signer,
    seal_key: SecretBytes,
    name: IpnsName,
}

impl BinIndexKeys {
    /// Derive the `bin-index-ipns-keypair` and `bin-index-seal-key` edges.
    #[must_use]
    pub fn derive(login_secret: &[u8]) -> Self {
        let signer = kdf::bin_index_ipns_keypair(login_secret);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        Self {
            signer,
            seal_key: kdf::bin_index_seal_key(login_secret),
            name,
        }
    }

    /// The IPNS name the bin index record is published under.
    #[must_use]
    pub fn name(&self) -> &IpnsName {
        &self.name
    }
}

impl fmt::Debug for BinIndexKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinIndexKeys")
            .field("name", &self.name)
            .finish_non_exhaustive()
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
    let block = seal_bin_index(seal_key.as_bytes(), &nonce, &minted)
        .map_err(BinIndexPublishError::Codec)?;
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
) -> BinIndexLoad
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
    Sch: Scheduler,
{
    let name = &keys.name;
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
        seal_key,
        name,
        scheduler.now(),
    );
    let reason = match within(scheduler, profile.settings_load_budget, load).await {
        Some(Ok(index)) => return BinIndexLoad::Resolved(index),
        Some(Err(reason)) => reason,
        None => DefaultsReason::TimedOut,
    };
    // The cached copy clears the same seal open the fetched one does; being
    // cached buys bytes nothing.
    match cached.and_then(|block| open_bin_index(seal_key.as_bytes(), &block).ok()) {
        Some(index) => BinIndexLoad::Stale { index, reason },
        None => BinIndexLoad::Empty(reason),
    }
}

#[allow(clippy::too_many_arguments)]
async fn resolve_bin_index<T, H, F, Sn>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    snapshots: &Sn,
    cached: &mut Option<Vec<u8>>,
    seal_key: &SecretBytes,
    name: &IpnsName,
    now: UnixMillis,
) -> Result<BinIndex, DefaultsReason>
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
{
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
        return Err(match durable.or(minted).or(adopted) {
            Some(_) => DefaultsReason::Suppressed,
            None => DefaultsReason::UnprovenFirstRun,
        });
    };
    // The reader is always the signer, so a lapse is refused here rather than
    // recovered by revival (blueprint/engine.md "Vault settings load").
    if is_expired(now, &verified.validity) {
        return Err(DefaultsReason::Expired);
    }
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
    // Ciphertext at rest: the sealed block, never the opened index.
    let _ = snapshots.put(&cache_key, &block).await;
    let _ = floor::advance_sequence_on_unseal(floors, key, sequence).await;
    let _ = floor::advance_sequence_on_unseal(floors, &adopted_key, index.revision).await;
    Ok(index)
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
            DefaultsReason::Expired,
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
