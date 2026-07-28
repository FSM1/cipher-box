//! The one shared publish port: move an authored record to the network and
//! hand back the signed bytes (blueprint/engine.md "Resolve/publish pipeline").
//!
//! Custody-free by design — it holds no read-key material, seals nothing, and
//! runs no gate; the name and its signer are injected, mirroring the layer
//! below ([`publish`]). What custody would have bought is recovered
//! structurally: [`PreflightedHead`]'s only constructor is [`preflight`], so an
//! envelope that has not been dry-run against the key the gate will re-derive
//! cannot reach the network.

use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::open_read_body;
use cipherbox_core::suite::ed25519::Ed25519Signer;

use super::author::AuthoredHead;
use super::publish::{PublishError, PublishReceipt, PublishRequest, publish};
use crate::api::{ApiClient, ApiError};
use crate::profile::SyncTimingProfile;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};

/// The identity an authored envelope must claim, supplied independently of the
/// envelope so the preflight compares rather than echoes.
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
    /// The authored envelope does not claim the identity the caller expects.
    BindingMismatch,
    /// The authored envelope does not reopen under the key the gate will
    /// re-derive — an encoder bug caught before it reaches the network.
    Unseal(CodecError),
}

impl core::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BindingMismatch => f.write_str("authored envelope binding mismatch"),
            Self::Unseal(e) => write!(f, "authored envelope does not reopen: {}", e.check()),
        }
    }
}

impl std::error::Error for PreflightError {}

/// A head block that passed [`preflight`]. Private fields and no other
/// constructor: this type *is* the guarantee that every published head was
/// dry-run first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightedHead {
    block: Vec<u8>,
    cid: String,
}

impl PreflightedHead {
    /// The head block's content CID, as a record `Value` spells it.
    pub fn cid(&self) -> &str {
        &self.cid
    }
}

/// Envelope-level dry run: check the authored envelope claims the expected
/// `(id, scope, epoch)` and reopens under the read key the adoption gate will
/// re-derive. No network, no record, no floor advance — the full six-stage gate
/// still runs post-publish on the returned bytes.
pub fn preflight(
    binding: &HeadBinding,
    read_key: &[u8; 32],
    head: &AuthoredHead,
) -> Result<PreflightedHead, PreflightError> {
    let envelope = &head.envelope;
    if envelope.id != binding.node_id
        || envelope.scope != binding.scope_id
        || envelope.epoch != binding.epoch
    {
        return Err(PreflightError::BindingMismatch);
    }
    open_read_body(envelope, read_key).map_err(PreflightError::Unseal)?;
    Ok(PreflightedHead {
        block: head.block.clone(),
        cid: head.cid.clone(),
    })
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

/// A fail-closed record-publish failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordPublishError {
    /// The head block upload failed; nothing was published.
    Upload(ApiError),
    /// The pin store reported a CID other than the block's own address, so the
    /// bytes it holds are not the bytes we authored. Publishing our CID anyway
    /// would sign a pointer to a block nothing pinned — refused fail-closed.
    HeadCidMismatch {
        /// The head block's own content address.
        expected: String,
        /// What the pin store reported.
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
        .upload(&request.head.block)
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
    use cipherbox_core::seal::ReadBody;

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
            unknown: Vec::new(),
        };
        author_child_envelope(EnvelopeAuthoring {
            node_id: binding.node_id,
            scope_id: binding.scope_id,
            epoch: binding.epoch,
            read_key: &READ_KEY,
            nonce: &NONCE,
            body: &body,
            carried_unknown: Vec::new(),
            carried_epoch_tag_unknown: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn a_dry_run_head_carries_its_own_block_address() {
        let binding = binding();
        let authored = head(&binding);
        let flighted = preflight(&binding, &READ_KEY, &authored).unwrap();
        assert_eq!(flighted.cid(), authored.cid);
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
