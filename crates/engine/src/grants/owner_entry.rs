//! Durable owner entry over the owner-local sealed store.

use core::cell::RefCell;
use futures_util::future::LocalBoxFuture;

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    OwnerLocalKind, OwnerSeedRecord, decode_envelope, decode_grant_section,
    decode_owner_seed_record, encode_owner_seed_record, grant_section_bytes, open_owner_local,
    seal_owner_local,
};
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::entropy::{Entropy, fresh_ephemeral};
use crate::net::last_known_good::NameLock;
use crate::seams::{SeamError, StagingStore};

/// Reserved staging namespace for confirmed owner recovery records.
pub const OWNER_SEED_CACHE_PREFIX: &[u8] = b"cbx/os/";

// StagingStore has async methods; these three boxed calls erase only the host seam.
trait CacheBytes {
    fn read<'s>(&'s self, key: &'s [u8]) -> LocalBoxFuture<'s, Result<Option<Vec<u8>>, SeamError>>;
    fn write<'s>(
        &'s self,
        key: &'s [u8],
        blob: &'s [u8],
    ) -> LocalBoxFuture<'s, Result<(), SeamError>>;
    fn remove<'s>(&'s self, key: &'s [u8]) -> LocalBoxFuture<'s, Result<(), SeamError>>;
}
impl<St: StagingStore> CacheBytes for St {
    fn read<'s>(&'s self, key: &'s [u8]) -> LocalBoxFuture<'s, Result<Option<Vec<u8>>, SeamError>> {
        Box::pin(self.staged_bytes(key))
    }
    fn write<'s>(
        &'s self,
        key: &'s [u8],
        blob: &'s [u8],
    ) -> LocalBoxFuture<'s, Result<(), SeamError>> {
        Box::pin(self.put_staged_bytes(key, blob))
    }
    fn remove<'s>(&'s self, key: &'s [u8]) -> LocalBoxFuture<'s, Result<(), SeamError>> {
        Box::pin(self.remove_staged_bytes(key))
    }
}

trait Ephemeral {
    fn draw(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, SeamError>;
}
impl<E: Entropy> Ephemeral for RefCell<E> {
    fn draw(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, SeamError> {
        fresh_ephemeral(&mut *self.borrow_mut()).map_err(local_error)
    }
}

/// One device's confirmed owner reads, with one sealed entry per scope.
#[derive(Clone)]
pub struct OwnerSeedCache<'a> {
    owner: &'a X25519Secret,
    labels: &'a SecretBytes,
    staging: &'a dyn CacheBytes,
    entropy: &'a dyn Ephemeral,
}

fn local_error(_: impl core::fmt::Display) -> SeamError {
    SeamError::new("owner seed cache entry unavailable")
}

impl<'a> OwnerSeedCache<'a> {
    pub(crate) fn new<St: StagingStore, E: Entropy>(
        staging: &'a St,
        owner: &'a X25519Secret,
        entropy: &'a RefCell<E>,
        labels: &'a SecretBytes,
    ) -> Self {
        Self {
            owner,
            labels,
            staging,
            entropy,
        }
    }

    fn key(&self, scope: &[u8; 16]) -> Vec<u8> {
        let label = kdf::name_label(
            self.labels.as_bytes(),
            &[OWNER_SEED_CACHE_PREFIX, scope.as_slice()].concat(),
        );
        [OWNER_SEED_CACHE_PREFIX, label.as_slice()].concat()
    }

    async fn read_scope(
        &self,
        key: &[u8],
        scope: &[u8; 16],
    ) -> Result<Option<OwnerSeedRecord>, SeamError> {
        let Some(blob) = self.staging.read(key).await? else {
            return Ok(None);
        };
        let record = open_owner_local(self.owner, OwnerLocalKind::OwnerSeedCache, &blob)
            .and_then(|body| decode_owner_seed_record(&body));
        Ok(record.ok().filter(|record| record.scope_id == *scope))
    }

    pub(crate) async fn load(
        &self,
        scope: &[u8; 16],
        name: &IpnsName,
    ) -> Result<Option<OwnerSeedRecord>, SeamError> {
        Ok(self
            .read_scope(&self.key(scope), scope)
            .await?
            .filter(|record| record.ipns_name == name.as_str().as_bytes()))
    }

    pub(crate) async fn remove(&self, scope: &[u8; 16]) -> Result<(), SeamError> {
        let key = self.key(scope);
        let _writing = NameLock::acquire(&key).await;
        self.staging.remove(&key).await
    }

    pub(crate) async fn save(&self, record: &OwnerSeedRecord) -> Result<(), SeamError> {
        let name = IpnsName::parse(std::str::from_utf8(&record.ipns_name).map_err(local_error)?)
            .map_err(local_error)?;
        let key = self.key(&record.scope_id);
        let _writing = NameLock::acquire(&key).await;
        let next_sequence = IpnsRecord::unmarshal(&record.record_bytes)
            .and_then(|r| r.verify(&name))
            .map_err(local_error)?
            .sequence;
        // At one name the gate already holds every epoch floor, and a keyless
        // root must still move the entry up to the sequence floor.
        if let Some(held) = self.read_scope(&key, &record.scope_id).await? {
            let stale = if held.ipns_name == record.ipns_name {
                IpnsRecord::unmarshal(&held.record_bytes)
                    .and_then(|r| r.verify(&name))
                    .is_ok_and(|previous| previous.sequence >= next_sequence)
            } else {
                // A keyless read knows no write epoch. The owner-signed cut
                // epoch never falls across a root move, and a copy at a name the
                // owner did not choose cannot pass the gate.
                match (cut_epoch(&held), cut_epoch(record)) {
                    (Some(old), Some(new)) => new < old,
                    (Some(_), None) => true,
                    (None, _) => false,
                }
            };
            if stale {
                return Ok(());
            }
        }
        let body = encode_owner_seed_record(record).map_err(local_error)?;
        let ephemeral = self.entropy.draw()?;
        let blob = seal_owner_local(
            self.owner,
            OwnerLocalKind::OwnerSeedCache,
            &ephemeral,
            &body,
        )
        .map_err(local_error)?;
        self.staging.write(&key, &blob).await
    }
}

fn cut_epoch(record: &OwnerSeedRecord) -> Option<u64> {
    let envelope = decode_envelope(&record.head_block).ok()?;
    let section = decode_grant_section(grant_section_bytes(&envelope)?).ok()?;
    Some(section.commitment.cut_epoch)
}

/// Recovery records do not reserve upload space.
pub(crate) async fn upload_staged_bytes<St: StagingStore>(staging: &St) -> Result<u64, SeamError> {
    let mut total = staging.staged_bytes_total().await?;
    for key in staging.staged_keys().await? {
        if key.starts_with(OWNER_SEED_CACHE_PREFIX) {
            let held = staging.staged_bytes(&key).await?;
            total = total.saturating_sub(held.map_or(0, |b| b.len() as u64));
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{SeededEntropy, block_on, fakes::InMemoryStagingStore};
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    #[test]
    fn the_sealed_cache_refuses_account_and_lookup_transplants() {
        let staging = InMemoryStagingStore::default();
        let owner = X25519Secret::from_scalar([0x11; 32]);
        let entropy = RefCell::new(SeededEntropy::new(17));
        let labels = kdf::contact_label_seed(&[0x22; 32]);
        let store = OwnerSeedCache::new(&staging, &owner, &entropy, &labels);
        let signer = Ed25519Signer::from_seed([0x33; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let record = record(&signer, 1, b"/ipfs/test");
        block_on(store.save(&record)).unwrap();
        let body = block_on(store.load(&record.scope_id, &name))
            .unwrap()
            .unwrap();
        assert_eq!(body.epoch, 1);
        let key = store.key(&record.scope_id);
        let blob = block_on(staging.staged_bytes(&key)).unwrap().unwrap();
        let other_scope = [0x66; 16];
        block_on(staging.put_staged_bytes(&store.key(&other_scope), &blob)).unwrap();
        assert!(matches!(
            block_on(store.load(&other_scope, &name)),
            Ok(None)
        ));
        let foreign_owner = X25519Secret::from_scalar([0x77; 32]);
        let foreign = OwnerSeedCache::new(&staging, &foreign_owner, &entropy, &labels);
        assert!(matches!(
            block_on(foreign.load(&record.scope_id, &name)),
            Ok(None)
        ));
    }

    fn record(signer: &Ed25519Signer, sequence: u64, value: &[u8]) -> OwnerSeedRecord {
        OwnerSeedRecord {
            scope_id: [0x44; 16],
            epoch: 1,
            write_epoch: 1,
            parent_node_seed: None,
            ipns_name: IpnsName::from_public_key(&signer.verifying_key())
                .as_str()
                .as_bytes()
                .to_vec(),
            record_bytes: IpnsRecord::create_v2(
                signer,
                value,
                sequence,
                2_000_000_000,
                "2099-01-01T00:00:00Z",
            )
            .marshal(),
            head_block: Vec::new(),
        }
    }

    #[test]
    fn one_scope_keeps_one_name_and_only_a_greater_sequence_replaces_it() {
        let staging = InMemoryStagingStore::default();
        let owner = X25519Secret::from_scalar([0x11; 32]);
        let entropy = RefCell::new(SeededEntropy::new(17));
        let labels = kdf::contact_label_seed(&[0x22; 32]);
        let cache = OwnerSeedCache::new(&staging, &owner, &entropy, &labels);
        let first = Ed25519Signer::from_seed([0x33; 32]);
        let next = Ed25519Signer::from_seed([0x34; 32]);
        let old_name = IpnsName::from_public_key(&first.verifying_key());
        let next_name = IpnsName::from_public_key(&next.verifying_key());
        let confirmed = record(&first, 4, b"/ipfs/confirmed");
        block_on(cache.save(&confirmed)).unwrap();
        for sequence in [3, 4] {
            block_on(cache.save(&record(&first, sequence, b"/ipfs/fork"))).unwrap();
            assert_eq!(
                block_on(cache.load(&confirmed.scope_id, &old_name))
                    .unwrap()
                    .unwrap()
                    .record_bytes,
                confirmed.record_bytes
            );
        }
        let advanced = record(&first, 5, b"/ipfs/advanced");
        block_on(cache.save(&advanced)).unwrap();
        assert_eq!(
            block_on(cache.load(&confirmed.scope_id, &old_name))
                .unwrap()
                .unwrap()
                .record_bytes,
            advanced.record_bytes
        );
        let moved = record(&next, 1, b"/ipfs/moved");
        block_on(cache.save(&moved)).unwrap();
        assert!(
            block_on(cache.load(&confirmed.scope_id, &old_name))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            block_on(cache.load(&confirmed.scope_id, &next_name))
                .unwrap()
                .unwrap()
                .record_bytes,
            moved.record_bytes
        );
        assert_eq!(block_on(staging.staged_keys()).unwrap().len(), 1);
        block_on(cache.remove(&confirmed.scope_id)).unwrap();
        assert!(block_on(staging.staged_keys()).unwrap().is_empty());
    }

    #[test]
    fn the_cache_does_not_spend_the_upload_budget() {
        let staging = InMemoryStagingStore::default();
        block_on(staging.put_staged_bytes(b"cbx/os/recovery", &[0; 4096])).unwrap();
        block_on(staging.put_staged_bytes(b"upload", &[0; 12])).unwrap();
        assert_eq!(block_on(upload_staged_bytes(&staging)).unwrap(), 12);
    }

    #[test]
    fn the_lookup_key_matches_the_core_kat() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../core/kat/manifest.json")).unwrap();
        let lookup = &manifest["ownerSeedCache"]["lookup"];
        let labels = SecretBytes::new(
            hex::decode(lookup["labelSeed"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let scope = hex::decode(lookup["scope"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let staging = InMemoryStagingStore::default();
        let owner = X25519Secret::from_scalar([0x11; 32]);
        let entropy = RefCell::new(SeededEntropy::new(17));
        let cache = OwnerSeedCache::new(&staging, &owner, &entropy, &labels);
        assert_eq!(
            hex::encode(cache.key(&scope)),
            lookup["key"].as_str().unwrap()
        );
    }
}
