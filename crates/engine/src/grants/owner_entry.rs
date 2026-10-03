//! Durable owner entry over the owner-local sealed store.

use core::cell::RefCell;
use futures_util::future::LocalBoxFuture;
use std::rc::Rc;

use cipherbox_core::error::{CodecError, TrustViolation};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    OwnerLocalKind, OwnerSeedRecord, decode_owner_seed_record, encode_owner_seed_record,
    open_owner_local, seal_owner_local,
};
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::entropy::{Entropy, fresh_ephemeral};
use crate::gate::{GateError, GateRejection, GateStage, RejectionReason};
use crate::net::last_known_good::NameLock;
use crate::seams::{SeamError, StagingStore};

/// Reserved staging namespace for confirmed owner recovery records.
pub const OWNER_SEED_CACHE_PREFIX: &[u8] = b"cbx/os/";

trait Store {
    fn load<'a>(
        &'a self,
        scope: &'a [u8; 16],
        name: &'a IpnsName,
    ) -> LocalBoxFuture<'a, Result<Option<OwnerSeedRecord>, GateError>>;
    fn save<'a>(&'a self, record: &'a OwnerSeedRecord)
    -> LocalBoxFuture<'a, Result<(), GateError>>;
}

/// One device's confirmed owner reads. The lookup label reveals no scope or name.
#[derive(Clone)]
pub struct OwnerSeedCache<'a>(Rc<dyn Store + 'a>);

impl<'a> OwnerSeedCache<'a> {
    pub(crate) fn new<St: StagingStore, E: Entropy>(
        staging: &'a St,
        owner: &'a X25519Secret,
        entropy: &'a RefCell<E>,
        labels: &SecretBytes,
    ) -> Self {
        Self(Rc::new(StagingCache {
            staging,
            owner,
            entropy,
            labels: labels.clone(),
        }))
    }

    pub(crate) async fn load(
        &self,
        scope: &[u8; 16],
        name: &IpnsName,
    ) -> Result<Option<OwnerSeedRecord>, GateError> {
        self.0.load(scope, name).await
    }

    pub(crate) async fn save(&self, record: &OwnerSeedRecord) -> Result<(), GateError> {
        self.0.save(record).await
    }
}

struct StagingCache<'a, St, E> {
    staging: &'a St,
    owner: &'a X25519Secret,
    entropy: &'a RefCell<E>,
    labels: SecretBytes,
}

fn malformed(error: CodecError) -> GateError {
    GateError::Rejected(GateRejection {
        stage: GateStage::Unseal,
        reason: RejectionReason::Trust(error),
    })
}

impl<St: StagingStore, E: Entropy> StagingCache<'_, St, E> {
    fn key(&self, scope: &[u8; 16], name: &IpnsName) -> Vec<u8> {
        let label = kdf::name_label(
            self.labels.as_bytes(),
            &[scope.as_slice(), name.as_str().as_bytes()].concat(),
        );
        [OWNER_SEED_CACHE_PREFIX, label.as_slice()].concat()
    }

    async fn read(
        &self,
        scope: &[u8; 16],
        name: &IpnsName,
    ) -> Result<Option<OwnerSeedRecord>, GateError> {
        let Some(blob) = self
            .staging
            .staged_bytes(&self.key(scope, name))
            .await
            .map_err(GateError::Seam)?
        else {
            return Ok(None);
        };
        let body = open_owner_local(self.owner, OwnerLocalKind::OwnerSeedCache, &blob)
            .map_err(malformed)?;
        let record = decode_owner_seed_record(&body).map_err(malformed)?;
        if record.scope_id != *scope || record.ipns_name != name.as_str().as_bytes() {
            return Err(malformed(TrustViolation::SealOpenFailed.into()));
        }
        Ok(Some(record))
    }
}

impl<St: StagingStore, E: Entropy> Store for StagingCache<'_, St, E> {
    fn load<'a>(
        &'a self,
        scope: &'a [u8; 16],
        name: &'a IpnsName,
    ) -> LocalBoxFuture<'a, Result<Option<OwnerSeedRecord>, GateError>> {
        Box::pin(self.read(scope, name))
    }

    fn save<'a>(
        &'a self,
        record: &'a OwnerSeedRecord,
    ) -> LocalBoxFuture<'a, Result<(), GateError>> {
        Box::pin(async move {
            let name = IpnsName::parse(
                std::str::from_utf8(&record.ipns_name)
                    .map_err(|_| malformed(TrustViolation::SealOpenFailed.into()))?,
            )
            .map_err(malformed)?;
            let key = self.key(&record.scope_id, &name);
            let _writing = NameLock::acquire(&key).await;
            let sequence = |record: &OwnerSeedRecord| {
                IpnsRecord::unmarshal(&record.record_bytes)
                    .and_then(|r| r.verify(&name))
                    .map(|r| r.sequence)
                    .map_err(malformed)
            };
            let next_sequence = sequence(record)?;
            if let Some(held) = self.read(&record.scope_id, &name).await? {
                if held.epoch > record.epoch
                    || sequence(&held)? > next_sequence
                    || held.record_bytes == record.record_bytes
                {
                    return Ok(());
                }
            }
            let body = encode_owner_seed_record(record).map_err(malformed)?;
            let ephemeral = fresh_ephemeral(&mut *self.entropy.borrow_mut()).map_err(|_| {
                GateError::Seam(SeamError::new("owner seed cache entropy unavailable"))
            })?;
            let blob = seal_owner_local(
                self.owner,
                OwnerLocalKind::OwnerSeedCache,
                &ephemeral,
                &body,
            )
            .map_err(malformed)?;
            self.staging
                .put_staged_bytes(&key, &blob)
                .await
                .map_err(GateError::Seam)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{SeededEntropy, block_on, fakes::InMemoryStagingStore};
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use zeroize::Zeroizing;

    #[test]
    fn the_sealed_cache_refuses_account_and_lookup_transplants() {
        let staging = InMemoryStagingStore::default();
        let owner = X25519Secret::from_scalar([0x11; 32]);
        let entropy = RefCell::new(SeededEntropy::new(17));
        let store = StagingCache {
            staging: &staging,
            owner: &owner,
            entropy: &entropy,
            labels: kdf::contact_label_seed(&[0x22; 32]),
        };
        let signer = Ed25519Signer::from_seed([0x33; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let record = OwnerSeedRecord {
            scope_id: [0x44; 16],
            epoch: 1,
            seed: Zeroizing::new([0x55; 32]),
            parent_node_seed: None,
            ipns_name: name.as_str().as_bytes().to_vec(),
            record_bytes: IpnsRecord::create_v2(
                &signer,
                b"/ipfs/test",
                1,
                2_000_000_000,
                "2099-01-01T00:00:00Z",
            )
            .marshal(),
            head_block: Vec::new(),
        };
        block_on(store.save(&record)).unwrap();
        let body = block_on(store.read(&record.scope_id, &name))
            .unwrap()
            .unwrap();
        assert_eq!(body.epoch, 1);
        let key = store.key(&record.scope_id, &name);
        let blob = block_on(staging.staged_bytes(&key)).unwrap().unwrap();
        let other_scope = [0x66; 16];
        block_on(staging.put_staged_bytes(&store.key(&other_scope, &name), &blob)).unwrap();
        assert!(matches!(
            block_on(store.read(&other_scope, &name)),
            Err(GateError::Rejected(_))
        ));
        let foreign_owner = X25519Secret::from_scalar([0x77; 32]);
        let foreign = StagingCache {
            owner: &foreign_owner,
            ..store
        };
        assert!(matches!(
            block_on(foreign.read(&record.scope_id, &name)),
            Err(GateError::Rejected(_))
        ));
    }
}
