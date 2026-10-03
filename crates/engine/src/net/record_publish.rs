//! The one shared publish port: move an authored record to the network and
//! hand back the signed bytes (blueprint/engine.md "Resolve/publish pipeline").
//!
//! Custody-free by design — it holds no read-key material, seals nothing, and
//! runs no gate; the name and its signer are injected, mirroring the layer
//! below ([`publish`]). What custody would have bought is recovered
//! structurally: a [`PreflightedHead`] is reachable only through a per-family
//! dry run, each of which reopens the block under the key its reader will
//! re-derive, so a head no reader could open cannot reach the network.

use cipherbox_core::content::decode_content_cid_str;
use cipherbox_core::error::CodecError;
use cipherbox_core::seal::{
    decode_envelope, decode_grant_section, grant_section_bytes, open_bin_index, open_read_body,
    open_settings_record,
};
use cipherbox_core::suite::aead::KEY_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;

use super::author::AuthoredHead;
use super::publish::{
    Observed, PublishBar, PublishError, PublishReceipt, PublishRequest, PutMark, publish_marked,
};
use crate::api::{ApiClient, ApiError};
use crate::content::limits::MAX_RESOLVED_RECORD_BYTES;
use crate::content::provider::place_block;
use crate::content::{ByoIpfsConfig, ProviderError, root_block_cid};
use crate::profile::SyncTimingProfile;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};
use crate::settings::Placement;

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
    /// For a scope root, the write epoch its owner-write-blob binds
    /// ([`PublishBar::write_epoch`]).
    pub write_epoch: Option<u64>,
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
    /// The floors this head must clear at its signature, for the families that
    /// bind a scope epoch. Set from the dry run's own [`HeadBinding`] and the
    /// head's own grant section, so no caller can publish an envelope under a
    /// bar other than the one it was proven against.
    bar: Option<PublishBar>,
}

impl PreflightedHead {
    /// Address `block` and cap it. Private: reachable only past a family's
    /// reopen proof.
    fn new(block: Vec<u8>, bar: Option<PublishBar>) -> Result<Self, PreflightError> {
        if block.len() > MAX_RESOLVED_RECORD_BYTES {
            return Err(PreflightError::TooLarge {
                size: block.len(),
                limit: MAX_RESOLVED_RECORD_BYTES,
            });
        }
        let cid = root_block_cid(&block);
        Ok(Self { block, cid, bar })
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
    let cut_epoch = grant_section_bytes(envelope)
        .map(|bytes| decode_grant_section(bytes).map(|section| section.commitment.cut_epoch))
        .transpose()
        .map_err(PreflightError::Unseal)?;
    PreflightedHead::new(
        head.block.clone(),
        Some(PublishBar {
            scope_id: binding.scope_id,
            read_epoch: binding.epoch,
            write_epoch: binding.write_epoch,
            cut_epoch,
        }),
    )
}

/// Settings-record dry run: the vault settings head is a self-sealed blob
/// rather than an envelope, so the reopen is the whole check — the block must
/// open under the same `enc-subkey` its reader will use.
pub fn preflight_settings(
    enc_secret: &X25519Secret,
    block: Vec<u8>,
) -> Result<PreflightedHead, PreflightError> {
    open_settings_record(enc_secret, &block).map_err(PreflightError::Unseal)?;
    // The vault settings record binds no scope read epoch.
    PreflightedHead::new(block, None)
}

/// Bin-index dry run: the record is a self-sealed blob under the owner's
/// `bin-index-seal-key`, so the reopen is the whole check.
pub fn preflight_bin_index(
    seal_key: &[u8; KEY_LEN],
    block: Vec<u8>,
) -> Result<PreflightedHead, PreflightError> {
    open_bin_index(seal_key, &block).map_err(PreflightError::Unseal)?;
    // The bin index binds no scope read epoch.
    PreflightedHead::new(block, None)
}

/// One record publish: the observed name and its narrow per-name signer, the
/// preflighted head, and the content CIDs to register alongside it.
pub struct RecordPublishRequest<'a> {
    /// The record the publish builds on, and the name it publishes under.
    pub observed: &'a Observed,
    /// The narrow per-name Ed25519 signer for the observed name.
    pub signer: &'a Ed25519Signer,
    /// The dry-run head block to upload and point the record at.
    pub head: &'a PreflightedHead,
    /// The content CIDs to register/pin under this name.
    pub content_cids: Vec<String>,
}

/// A fail-closed record-publish failure: what the publish *pipeline* reports
/// about one attempt, which the rotation seams fold into their own
/// [`RotationPublishError`](crate::rotation::RotationPublishError).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordPublishError {
    /// The head block upload failed; nothing was published.
    Upload(ApiError),
    /// The member's own provider did not take the head block under its own
    /// address; nothing was published.
    Placement(ProviderError),
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

/// Publish one authored record: place its head block where the session's
/// placement puts bytes (hosted when it decided none), then run the
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
    let placement = api.placement().unwrap_or(Placement::Hosted);
    publish_record_placed(
        transport,
        api,
        floors,
        scheduler,
        profile,
        request,
        &placement,
        &mut MirrorLeg::once(),
        None,
    )
    .await
}

/// Attempts one op may spend on the member's own provider before its mirror is
/// abandoned for that version. A dual write completes when hosted succeeds and
/// external has either succeeded or exhausted its attempts (#34 D1), so the leg
/// needs attempts to spend — one refusal is a blip, not a verdict.
const MIRROR_ATTEMPTS: u32 = 3;

/// A dual write's best-effort mirror leg, carried across one op's blocks and
/// record heads.
///
/// The budget is per op rather than per block because a provider that is down
/// refuses every block alike: spending a fresh budget on each would stall the
/// whole pass behind one dead endpoint, and a version the mirror has already
/// missed a block of is not one it can serve whatever the rest do.
pub(crate) struct MirrorLeg {
    /// Attempts left to spend. Reaching zero is what abandons the mirror: the
    /// block that spent the last one never landed on it.
    attempts: u32,
    /// The first refusal, reported once the leg is abandoned.
    refusal: Option<ProviderError>,
}

impl Default for MirrorLeg {
    fn default() -> Self {
        Self {
            attempts: MIRROR_ATTEMPTS,
            refusal: None,
        }
    }
}

impl MirrorLeg {
    /// A leg for one publish outside an op, which no later block retries.
    pub(crate) fn once() -> Self {
        Self {
            attempts: 1,
            refusal: None,
        }
    }

    /// Whether the mirror is short of this version. Refusals a later attempt
    /// recovered from are not: the block reached the provider.
    pub(crate) fn missed(&self) -> bool {
        self.attempts == 0
    }

    pub(crate) fn refused(&mut self, error: ProviderError) {
        self.attempts = self.attempts.saturating_sub(1);
        self.refusal.get_or_insert(error);
    }

    /// The refusal to report, which is one only where the mirror stayed short.
    pub(crate) fn failure(&self) -> Option<ProviderError> {
        self.missed().then_some(self.refusal).flatten()
    }
}

/// [`publish_record`], raising `mark` just before the PUT ([`PutMark`]), with
/// the head block placed on the legs of
/// `placement` rather than the session's, and a dual write's mirror attempts
/// spent from `mirror`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_record_placed<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    request: &RecordPublishRequest<'_>,
    placement: &Placement,
    mirror: &mut MirrorLeg,
    mark: Option<PutMark<'_>>,
) -> Result<PublishReceipt, RecordPublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    place_head(api, placement, mirror, request.head).await?;

    publish_marked(
        transport,
        api,
        floors,
        scheduler,
        profile,
        &PublishRequest {
            observed: request.observed,
            signer: request.signer,
            head_cid: request.head.cid.clone(),
            content_cids: request.content_cids.clone(),
            bar: request.head.bar,
        },
        mark,
    )
    .await
    .map_err(RecordPublishError::Publish)
}

/// Put a head block on every leg `placement` names, the same as a content
/// version (ADR 0029 D1). Only the hosted leg can fail a dual write (D3).
async fn place_head<H: Http, C: CredentialStore>(
    api: &ApiClient<H, C>,
    placement: &Placement,
    mirror: &mut MirrorLeg,
    head: &PreflightedHead,
) -> Result<(), RecordPublishError> {
    match placement {
        Placement::Hosted => hosted_head(api, head).await,
        Placement::External(config) => member_head(api, config, head)
            .await
            .map_err(RecordPublishError::Placement),
        Placement::Dual(config) => {
            hosted_head(api, head).await?;
            while !mirror.missed() {
                match member_head(api, config, head).await {
                    Ok(()) => break,
                    Err(error) => mirror.refused(error),
                }
            }
            Ok(())
        }
    }
}

async fn hosted_head<H: Http, C: CredentialStore>(
    api: &ApiClient<H, C>,
    head: &PreflightedHead,
) -> Result<(), RecordPublishError> {
    let uploaded = api
        .upload(&head.cid, &head.block)
        .await
        .map_err(RecordPublishError::Upload)?;
    if uploaded.cid != head.cid {
        return Err(RecordPublishError::HeadCidMismatch {
            expected: head.cid.clone(),
            returned: uploaded.cid,
        });
    }
    Ok(())
}

/// [`place_block`] holds the member's node to the head block's own address.
async fn member_head<H: Http, C: CredentialStore>(
    api: &ApiClient<H, C>,
    config: &ByoIpfsConfig,
    head: &PreflightedHead,
) -> Result<(), ProviderError> {
    let cid =
        decode_content_cid_str(&head.cid).map_err(|_| ProviderError::MalformedBlockAddress)?;
    place_block(config, &cid, &head.block, api.http(), api.deadlines()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::author::{EnvelopeAuthoring, author_child_envelope};
    use crate::seams::{HttpResponse, RecordTransport};
    use crate::testkit::account::MEMBER_NODE;
    use crate::testkit::{FakeWorld, block_on};
    use cipherbox_core::ipns::IpnsName;
    use cipherbox_core::seal::{PreservedFields, ReadBody};

    const READ_KEY: [u8; 32] = [8u8; 32];
    const NONCE: [u8; 24] = [6u8; 24];

    fn binding() -> HeadBinding {
        HeadBinding {
            node_id: [1u8; 16],
            scope_id: [2u8; 16],
            epoch: 3,
            write_epoch: None,
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
            body: br#"{"cid":"bafkreisomeotherblock","size":1}"#.to_vec().into(),
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
                observed: &Observed::unread(&name),
                signer: &signer,
                head: &preflighted,
                content_cids: Vec::new(),
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

    /// Under `External` the member's node is the head's only leg, so it is held
    /// to the same address check as the hosted store, and the hosted ingress is
    /// never asked.
    #[test]
    fn a_member_node_that_reports_another_address_publishes_nothing() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let binding = binding();
        let authored = head(&binding);
        let preflighted = preflight(&binding, &READ_KEY, &authored).expect("dry run");
        let config = ByoIpfsConfig {
            endpoint: MEMBER_NODE.to_owned(),
            kind: crate::content::ByoKind::Kubo,
            access_token: crate::content::ByoBearer::None,
        };
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        )
        .with_placement(std::rc::Rc::new(core::cell::RefCell::new(Some(
            crate::settings::SessionPlacement::member(Ok(Placement::External(config))),
        ))));
        let other = root_block_cid(b"another block");
        device.http.enqueue_response(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: format!("{{\"Key\":\"{other}\",\"Size\":0}}\n")
                .into_bytes()
                .into(),
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
                observed: &Observed::unread(&name),
                signer: &signer,
                head: &preflighted,
                content_cids: Vec::new(),
            },
        ));

        assert_eq!(
            outcome.unwrap_err(),
            RecordPublishError::Placement(ProviderError::AddressMismatch)
        );
        let requests = device.http.requests();
        assert!(
            requests
                .iter()
                .all(|request| request.url.starts_with(MEMBER_NODE)),
            "only the member's node was asked"
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
