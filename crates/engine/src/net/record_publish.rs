//! The one shared publish port: move an authored record to the network and
//! hand back the signed bytes (blueprint/engine.md "Resolve/publish pipeline").
//!
//! Custody-free by design — it holds no read-key material, seals nothing, and
//! runs no gate; the name and its signer are injected, mirroring the layer
//! below ([`publish`]). What custody would have bought is recovered
//! structurally: a [`PreflightedHead`] is reachable only through a per-family
//! dry run, each of which reopens the block under the key its reader will
//! re-derive, so a head no reader could open cannot reach the network.

use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{decode_envelope, open_read_body, open_settings_record};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;

use super::author::AuthoredHead;
use super::publish::{PublishError, PublishReceipt, PublishRequest, publish};
use crate::api::{ApiClient, ApiError};
use crate::content::limits::MAX_RESOLVED_RECORD_BYTES;
use crate::content::root_block_cid;
use crate::profile::SyncTimingProfile;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};

/// The identity an authored envelope must claim, as the caller believes it —
/// carried alongside the envelope rather than read out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadBinding {
    /// The node the record is for.
    pub node_id: [u8; 16],
    /// The scope it belongs to.
    pub scope_id: [u8; 16],
    /// The scope read epoch it is sealed at.
    pub epoch: u64,
}

/// A pre-publish dry-run failure. The op fails locally and **nothing** is
/// published — a signed record cannot be unpublished, so a post-publish
/// rejection would have diagnostic value and no preventive value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightError {
    /// The head block is not the encoding of the envelope beside it, so the
    /// bytes checked here are not the bytes that would ship.
    BlockEnvelopeMismatch,
    /// The authored envelope does not claim the identity the caller expects.
    BindingMismatch,
    /// The head does not reopen under the key its reader will re-derive — an
    /// encoder bug caught before it reaches the network.
    Unseal(CodecError),
    /// The head block exceeds the ceiling every block read enforces
    /// ([`MAX_RESOLVED_RECORD_BYTES`]). Publishing it would sign a pointer to a
    /// block this build's own reader always refuses.
    TooLarge {
        /// The encoded block's size.
        size: usize,
        /// The enforced ceiling.
        limit: usize,
    },
}

impl core::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BlockEnvelopeMismatch => f.write_str("head block is not the envelope beside it"),
            Self::BindingMismatch => f.write_str("authored envelope binding mismatch"),
            Self::Unseal(e) => write!(f, "authored head does not reopen: {}", e.check()),
            Self::TooLarge { size, limit } => {
                write!(f, "head block exceeds the content cap ({size} > {limit})")
            }
        }
    }
}

impl std::error::Error for PreflightError {}

/// A head block that passed a dry run. Private fields and no public
/// constructor: this type *is* the guarantee that every published head was
/// dry-run first, and that its CID is its own content address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightedHead {
    block: Vec<u8>,
    cid: String,
}

impl PreflightedHead {
    /// Address `block` and cap it. Private: reachable only past a family's
    /// reopen proof.
    fn new(block: Vec<u8>) -> Result<Self, PreflightError> {
        if block.len() > MAX_RESOLVED_RECORD_BYTES {
            return Err(PreflightError::TooLarge {
                size: block.len(),
                limit: MAX_RESOLVED_RECORD_BYTES,
            });
        }
        let cid = root_block_cid(&block);
        Ok(Self { block, cid })
    }

    /// The head block's content CID, as the record `Value` spells it.
    pub fn cid(&self) -> &str {
        &self.cid
    }

    /// The head block itself — the bytes a publish uploads at [`Self::cid`].
    pub fn block(&self) -> &[u8] {
        &self.block
    }
}

/// Envelope-level dry run: check the head block really is the envelope beside
/// it, that the envelope claims the expected `(id, scope, epoch)`, and that it
/// reopens under the read key the adoption gate will re-derive. No network, no
/// record, no floor advance — the full six-stage gate still runs post-publish
/// on the returned bytes.
pub fn preflight(
    binding: &HeadBinding,
    read_key: &[u8; 32],
    head: &AuthoredHead,
) -> Result<PreflightedHead, PreflightError> {
    let envelope = &head.envelope;
    // The block ships; the envelope is what the rest of this dry run inspects.
    // A head that pairs one with the other's bytes would publish unchecked.
    if decode_envelope(&head.block).ok().as_ref() != Some(envelope) {
        return Err(PreflightError::BlockEnvelopeMismatch);
    }
    if envelope.id != binding.node_id
        || envelope.scope != binding.scope_id
        || envelope.epoch != binding.epoch
    {
        return Err(PreflightError::BindingMismatch);
    }
    open_read_body(envelope, read_key).map_err(PreflightError::Unseal)?;
    PreflightedHead::new(head.block.clone())
}

/// Settings-record dry run: the vault settings head is a self-sealed blob
/// rather than an envelope, so the reopen is the whole check — the block must
/// open under the same `enc-subkey` its reader will use.
pub fn preflight_settings(
    enc_secret: &X25519Secret,
    block: Vec<u8>,
) -> Result<PreflightedHead, PreflightError> {
    open_settings_record(enc_secret, &block).map_err(PreflightError::Unseal)?;
    PreflightedHead::new(block)
}

/// One record publish: the name and its narrow per-name signer, the
/// preflighted head, and the content CIDs to register alongside it.
pub struct RecordPublishRequest<'a> {
    /// The IPNS name being published.
    pub name: &'a IpnsName,
    /// The narrow per-name Ed25519 signer for [`Self::name`].
    pub signer: &'a Ed25519Signer,
    /// The dry-run head block to upload and point the record at.
    pub head: &'a PreflightedHead,
    /// The content CIDs to register/pin under this name.
    pub content_cids: Vec<String>,
    /// Raises the CAS expected-current sequence (revival only; see
    /// [`PublishRequest::min_current_sequence`]).
    pub min_current_sequence: Option<u64>,
}

/// A fail-closed record-publish failure: what the publish *pipeline* reports
/// about one attempt, which the rotation seams fold into their own
/// [`RotationPublishError`](crate::rotation::RotationPublishError).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordPublishError {
    /// The head block upload failed; nothing was published.
    Upload(ApiError),
    /// The API did not echo the address we declared, so it is not answering
    /// about the block we uploaded. Publishing our CID on that answer would
    /// sign a pointer to a block nothing confirmed — refused fail-closed. The
    /// bytes/CID binding itself is enforced at the ingress, which refuses bytes
    /// that do not hash to the declared address (blueprint/api.md).
    HeadCidMismatch {
        /// The head block's own content address, as declared.
        expected: String,
        /// What the API echoed back.
        returned: String,
    },
    /// The publish pipeline failed.
    Publish(PublishError),
}

/// Publish one authored record: upload its head block, then run the
/// register-first CAS publish and hand back the signed bytes. Only
/// [`PublishOutcome::Published`] bytes may be self-adopted — adopting an
/// unconfirmed publish would advance the sequence floor and destroy the
/// idempotent-in-sequence retry.
pub async fn publish_record<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    request: &RecordPublishRequest<'_>,
) -> Result<PublishReceipt, RecordPublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    let uploaded = api
        .upload(&request.head.cid, &request.head.block)
        .await
        .map_err(RecordPublishError::Upload)?;
    if uploaded.cid != request.head.cid {
        return Err(RecordPublishError::HeadCidMismatch {
            expected: request.head.cid.clone(),
            returned: uploaded.cid,
        });
    }

    publish(
        transport,
        api,
        floors,
        scheduler,
        profile,
        &PublishRequest {
            name: request.name,
            signer: request.signer,
            head_cid: request.head.cid.clone(),
            content_cids: request.content_cids.clone(),
            min_current_sequence: request.min_current_sequence,
        },
    )
    .await
    .map_err(RecordPublishError::Publish)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::author::{EnvelopeAuthoring, author_child_envelope};
    use crate::seams::{HttpResponse, RecordTransport};
    use crate::testkit::{FakeWorld, block_on};
    use cipherbox_core::seal::{PreservedFields, ReadBody};

    const READ_KEY: [u8; 32] = [8u8; 32];
    const NONCE: [u8; 24] = [6u8; 24];

    fn binding() -> HeadBinding {
        HeadBinding {
            node_id: [1u8; 16],
            scope_id: [2u8; 16],
            epoch: 3,
        }
    }

    fn head(binding: &HeadBinding) -> AuthoredHead {
        let body = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        };
        author_child_envelope(EnvelopeAuthoring {
            node_id: binding.node_id,
            scope_id: binding.scope_id,
            epoch: binding.epoch,
            read_key: &READ_KEY,
            nonce: &NONCE,
            body: &body,
            carried_unknown: PreservedFields::new(),
            carried_epoch_tag_unknown: PreservedFields::new(),
        })
        .unwrap()
    }

    /// A pin store that answers with an address other than the block's own is
    /// not holding the bytes we authored, so signing a record at our CID would
    /// point at a block nothing pinned.
    #[test]
    fn a_pin_store_that_reports_another_address_publishes_nothing() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let binding = binding();
        let authored = head(&binding);
        let preflighted = preflight(&binding, &READ_KEY, &authored).expect("dry run");
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        device.http.enqueue_response(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: br#"{"cid":"bafkreisomeotherblock","size":1}"#.to_vec(),
        });
        let signer = Ed25519Signer::from_seed([9u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());

        let outcome = block_on(publish_record(
            &device.record_store,
            &api,
            &device.floor_store,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &RecordPublishRequest {
                name: &name,
                signer: &signer,
                head: &preflighted,
                content_cids: Vec::new(),
                min_current_sequence: None,
            },
        ));

        assert_eq!(
            outcome.unwrap_err(),
            RecordPublishError::HeadCidMismatch {
                expected: authored.cid,
                returned: "bafkreisomeotherblock".to_owned(),
            }
        );
        assert!(
            device
                .record_store
                .record_at(&device.record_store.endpoints()[0], name.as_str())
                .is_none(),
            "nothing reached the record plane"
        );
    }

    /// The block is what ships and the envelope is what the rest of the dry run
    /// inspects, so a head pairing one with the other's bytes would publish a
    /// block nothing checked.
    #[test]
    fn a_head_whose_block_is_not_its_envelope_never_gets_a_witness() {
        let binding = binding();
        let mut authored = head(&binding);
        authored.block.push(0);

        assert_eq!(
            preflight(&binding, &READ_KEY, &authored).unwrap_err(),
            PreflightError::BlockEnvelopeMismatch,
        );
    }

    #[test]
    fn an_envelope_claiming_another_identity_never_gets_a_witness() {
        let authored = head(&binding());
        for wrong in [
            HeadBinding {
                node_id: [9u8; 16],
                ..binding()
            },
            HeadBinding {
                scope_id: [9u8; 16],
                ..binding()
            },
            HeadBinding {
                epoch: 4,
                ..binding()
            },
        ] {
            assert_eq!(
                preflight(&wrong, &READ_KEY, &authored).unwrap_err(),
                PreflightError::BindingMismatch,
            );
        }
    }

    #[test]
    fn an_envelope_the_gates_key_cannot_reopen_never_gets_a_witness() {
        let binding = binding();
        assert!(matches!(
            preflight(&binding, &[0u8; 32], &head(&binding)).unwrap_err(),
            PreflightError::Unseal(_)
        ));
    }
}
