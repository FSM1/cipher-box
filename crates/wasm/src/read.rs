//! Every read a host asks the worker for, and what each answers. A read
//! crosses as one generated `Read` value and answers with one generated
//! `ReadAnswer` whose `kind` names the read, so the host derives the answer
//! type of each kind from these two types alone (blueprint/web-client.md "WASM
//! packaging and the type boundary").

use cipherbox_engine::facade::{
    BinView, InvitePreview, NodeId, ReceivedShareRow, SharingView, SiweIntent, SnapshotView,
    VaultStorageView, VersionEntry,
};
use cipherbox_engine::{AuthMethod, PendingApprovalView, RegisteredDevice};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::Zeroizing;

use crate::rendezvous::{DeviceRendezvousResult, DeviceRendezvousStep};

/// One read intent. `folder` and `scope` name the engine's own root when null.
#[derive(Deserialize, tsify::Tsify)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Read {
    /// A key-free snapshot of one folder.
    Snapshot {
        /// The folder to read.
        #[serde(deserialize_with = "cipherbox_engine::wire::opt_node_id::deserialize")]
        #[tsify(type = "Uint8Array | null")]
        folder: Option<NodeId>,
    },
    /// The contact book and the grants one scope root's record commits.
    Sharing {
        /// The scope root to read.
        #[serde(deserialize_with = "cipherbox_engine::wire::opt_node_id::deserialize")]
        #[tsify(type = "Uint8Array | null")]
        scope: Option<NodeId>,
    },
    /// This vault's accepted shares.
    #[serde(deserialize_with = "cipherbox_engine::wire::no_fields")]
    ReceivedShares,
    /// The invite link a URL fragment names, before the join.
    InvitePreview {
        /// The fragment: the whole bearer capability.
        #[serde(with = "cipherbox_engine::wire::secret_placeholder")]
        #[tsify(type = "string")]
        fragment: Zeroizing<String>,
    },
    /// The owner's bin.
    #[serde(deserialize_with = "cipherbox_engine::wire::no_fields")]
    Bin,
    /// The storage pane's whole read.
    #[serde(deserialize_with = "cipherbox_engine::wire::no_fields")]
    VaultStorage,
    /// The login methods on the account.
    #[serde(deserialize_with = "cipherbox_engine::wire::no_fields")]
    AuthMethods,
    /// The device identity keys on the account registry.
    #[serde(deserialize_with = "cipherbox_engine::wire::no_fields")]
    Devices,
    /// The bytes a device signs to join the account registry.
    DeviceRegistrationChallenge {
        /// The joining device's key.
        device_public_key: String,
    },
    /// The rendezvous this account is asked to approve.
    #[serde(deserialize_with = "cipherbox_engine::wire::no_fields")]
    PendingApprovals,
    /// One step of the device-approval rendezvous (ADR 0009). Needs no
    /// session.
    DeviceRendezvous {
        /// The step.
        #[serde(deserialize_with = "step_outside")]
        step: DeviceRendezvousStep,
    },
    /// The fingerprint shown beside a grantee name (ADR 0027 D7). Needs no
    /// session.
    IdentityFingerprint {
        /// The 33-byte compressed identity key.
        #[serde(deserialize_with = "cipherbox_engine::wire::bytes::deserialize")]
        #[tsify(type = "Uint8Array")]
        identity_public_key: Vec<u8>,
    },
    /// The nonce an EIP-4361 message must embed.
    SiweChallenge {
        /// The surface the nonce is for.
        intent: SiweIntent,
    },
    /// One file's current plaintext.
    Download {
        /// The file.
        #[serde(deserialize_with = "cipherbox_engine::wire::node_id::deserialize")]
        #[tsify(type = "Uint8Array")]
        node: NodeId,
    },
    /// One file's prior versions, newest first.
    FileVersions {
        /// The file.
        #[serde(deserialize_with = "cipherbox_engine::wire::node_id::deserialize")]
        #[tsify(type = "Uint8Array")]
        node: NodeId,
    },
    /// One prior version's plaintext.
    DownloadVersion {
        /// The file.
        #[serde(deserialize_with = "cipherbox_engine::wire::node_id::deserialize")]
        #[tsify(type = "Uint8Array")]
        node: NodeId,
        /// The version's content root CID.
        #[serde(deserialize_with = "cipherbox_engine::wire::bytes::deserialize")]
        #[tsify(type = "Uint8Array")]
        content_cid: Vec<u8>,
    },
}

/// A rendezvous step carries secrets that serde would buffer unwiped, so the
/// read decode takes it through its own decode ([`crate::boundary::decode_read`]).
fn step_outside<'de, D: Deserializer<'de>>(_: D) -> Result<DeviceRendezvousStep, D::Error> {
    Err(de::Error::custom(
        "a rendezvous step is decoded outside the read decode",
    ))
}

fn as_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}

/// What one read answered, under the `kind` of the read.
#[derive(Serialize, tsify::Tsify)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum ReadAnswer {
    /// The folder snapshot.
    Snapshot(SnapshotView),
    /// The scope's sharing state.
    Sharing(SharingView),
    /// The accepted shares.
    ReceivedShares(Vec<ReceivedShareRow>),
    /// The invite preview.
    InvitePreview(InvitePreview),
    /// The bin.
    Bin(BinView),
    /// The storage pane.
    VaultStorage(VaultStorageView),
    /// The login methods.
    AuthMethods(Vec<AuthMethod>),
    /// The registered devices.
    Devices(Vec<RegisteredDevice>),
    /// The bytes to sign.
    DeviceRegistrationChallenge(
        #[serde(serialize_with = "as_bytes")]
        #[tsify(type = "Uint8Array")]
        Vec<u8>,
    ),
    /// The rendezvous to approve.
    PendingApprovals(Vec<PendingApprovalView>),
    /// What the rendezvous step produced.
    DeviceRendezvous(DeviceRendezvousResult),
    /// The fingerprint.
    IdentityFingerprint(String),
    /// The nonce.
    SiweChallenge(String),
    /// The plaintext. The encode copies it into JS from this zeroizing owner.
    Download(
        #[serde(serialize_with = "as_bytes")]
        #[tsify(type = "Uint8Array")]
        Zeroizing<Vec<u8>>,
    ),
    /// The prior versions.
    FileVersions(Vec<VersionEntry>),
    /// The version's plaintext, as for `download`.
    DownloadVersion(
        #[serde(serialize_with = "as_bytes")]
        #[tsify(type = "Uint8Array")]
        Zeroizing<Vec<u8>>,
    ),
}
