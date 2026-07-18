//! `node/v3` write-emit API — `create_folder_node`/`create_file_node` +
//! the D-07 dual-keyed `build_child_refs`.
//!
//! This is the callable emit half of the P1a-sdk glue (the read half lives
//! in `crate::adapter`). Today `crates/fuse` cannot emit a node/v3 node at
//! all; these functions mint per-node keys, seal BOTH the read-body and
//! write-body (`cipherbox_core::node::seal::seal_published_node`, 69-15),
//! and publish the FIRST IPNS record at sequence 1 (mirroring the
//! `registry.rs`/legacy `createSubfolder`/`mkdir.rs` direct-publish idiom —
//! no new publish abstraction, D-07/T-69-16-04).
//!
//! Terminal-owner zeroization (D-09): every function here returns the
//! minted `read_key`/`write_key`/`ipns_private_key` RAW — the caller (FUSE,
//! P1b) is the terminal owner of that key material's lifecycle. This module
//! zeros ONLY its own scratch intermediates (e.g. the `Zeroizing` wrapper
//! `generate_ed25519_keypair` returns for the signing seed, once its bytes
//! have been copied out into the raw `Vec<u8>` this module returns) and
//! NEVER zeros a caller-supplied borrowed key — `build_child_refs` takes
//! `parent_read_key`/`parent_write_key`/`child_read_key`/`child_write_key`
//! by borrow and never mutates or zeros them (reproducing the 48/89
//! sdk-e2e terminal-owner incident is forbidden here, project memory).
//!
//! No new Cargo dependency: `crates/sdk` already depends on
//! `cipherbox-api-client` (used by `registry.rs`) and `cipherbox-crypto`/
//! `cipherbox-core` (used throughout this crate).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use cipherbox_api_client::ipfs::upload_content;
use cipherbox_api_client::ipns::publish_ipns;
use cipherbox_api_client::{ApiClient, IpnsPublishRequest, PublishResult};
use cipherbox_core::ipns::{create_ipns_record, marshal_ipns_record};
use cipherbox_core::node::seal;
use cipherbox_core::node::{
    encode_published_node, Node, NodeContent, NodeKind, NodeWriteBody, SealedChildRef,
    WriteChildRef,
};

use crate::error::SdkError;

/// IPNS record lifetime for a fresh publish (24h; matches the convention
/// used throughout `crates/sdk`/`crates/fuse` -- `registry.rs`, `mkdir.rs`,
/// `content_ops.rs`, `replay.rs`).
const IPNS_RECORD_LIFETIME_MS: u64 = 86_400_000;

// ---------------------------------------------------------------------------
// TEE enrollment input
// ---------------------------------------------------------------------------

/// TEE enrollment parameters for a fresh node's `ipnsPrivateKey` wrap
/// (CLAUDE.md rule #7 -- the ONLY ECIES on this emit path; everything else
/// composes the AES-256-GCM AAD primitive via `seal_published_node`).
#[derive(Debug, Clone)]
pub struct TeeEnrollment {
    /// Uncompressed secp256k1 TEE public key (65 bytes, 0x04-prefixed).
    pub tee_public_key: Vec<u8>,
    /// TEE key epoch (rotates on a 4-week grace period, per CLAUDE.md).
    pub key_epoch: u32,
}

// ---------------------------------------------------------------------------
// Emission results
// ---------------------------------------------------------------------------

/// The result of minting + sealing a fresh folder/root node/v3 node.
///
/// `read_key`/`write_key`/`ipns_private_key` are returned RAW (D-09 -- the
/// caller is the terminal owner). `Debug` redacts key material so it can
/// never leak into a log line by accident (T-69-16-02).
#[derive(Clone)]
pub struct FolderEmission {
    /// `encode_published_node` bytes of the fresh, sealed `PublishedNode`.
    pub published_node: Vec<u8>,
    /// The freshly derived k51 IPNS name for this node.
    pub ipns_name: String,
    /// The freshly minted hyphenated UUID node id.
    pub id: String,
    /// Raw 32-byte readKey (D-09 -- caller-owned from here).
    pub read_key: Vec<u8>,
    /// Raw 32-byte writeKey (D-09 -- caller-owned from here).
    pub write_key: Vec<u8>,
    /// Raw 32-byte Ed25519 signing seed (D-09 -- caller-owned from here).
    pub ipns_private_key: Vec<u8>,
}

impl std::fmt::Debug for FolderEmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderEmission")
            .field("published_node_len", &self.published_node.len())
            .field("ipns_name", &self.ipns_name)
            .field("id", &self.id)
            .field("read_key", &"[REDACTED]")
            .field("write_key", &"[REDACTED]")
            .field("ipns_private_key", &"[REDACTED]")
            .finish()
    }
}

/// The result of minting + sealing a fresh file node/v3 node. Same shape
/// and redaction discipline as [`FolderEmission`].
#[derive(Clone)]
pub struct FileEmission {
    pub published_node: Vec<u8>,
    pub ipns_name: String,
    pub id: String,
    pub read_key: Vec<u8>,
    pub write_key: Vec<u8>,
    pub ipns_private_key: Vec<u8>,
}

impl std::fmt::Debug for FileEmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileEmission")
            .field("published_node_len", &self.published_node.len())
            .field("ipns_name", &self.ipns_name)
            .field("id", &self.id)
            .field("read_key", &"[REDACTED]")
            .field("write_key", &"[REDACTED]")
            .field("ipns_private_key", &"[REDACTED]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Pure emission builders (no network IO)
// ---------------------------------------------------------------------------

/// Mints a fresh Ed25519 ipns keypair + readKey + writeKey, derives the k51
/// ipns_name, builds a folder/root `Node` (generation 0), and seals BOTH
/// bodies via `seal_published_node` (69-15). No network IO -- pure and
/// synchronous, so it is directly testable without a live API/IPFS
/// round-trip.
///
/// `children`/`write_children` are passed straight through into the fresh
/// node -- callers that need to link a newly-minted child into this SAME
/// node must first learn this emission's `read_key`/`write_key`/`id` (e.g.
/// via a `children=vec![]` mint), then call [`build_child_refs`] with those
/// keys, then re-seal at this node's identity for the update (the "add a
/// child to an existing/just-minted folder" path already used by
/// `crate::rotation::engine::rotate_one`'s re-seal-on-mutation idiom) --
/// this function itself only mints+seals a NODE'S OWN fresh identity.
pub fn build_folder_emission(
    children: Vec<SealedChildRef>,
    write_children: Vec<WriteChildRef>,
    is_root: bool,
) -> Result<FolderEmission, SdkError> {
    let (ipns_public_key, ipns_private_key_zeroizing) =
        cipherbox_crypto::generate_ed25519_keypair();
    // D-09: copy the minted signing seed out into the raw Vec<u8> we return;
    // the Zeroizing wrapper then zeros ITS OWN copy on drop -- the returned
    // clone stays raw for the caller (terminal owner).
    let ipns_private_key: Vec<u8> = ipns_private_key_zeroizing.to_vec();

    let ipns_public_key_arr: [u8; 32] = ipns_public_key
        .as_slice()
        .try_into()
        .map_err(|_| SdkError::Emit("minted ed25519 public key is not 32 bytes".to_string()))?;
    let ipns_name = cipherbox_crypto::derive_ipns_name(&ipns_public_key_arr)?;

    let read_key = cipherbox_crypto::generate_random_bytes(32);
    let write_key = cipherbox_crypto::generate_random_bytes(32);
    let read_key_arr: [u8; 32] = read_key
        .as_slice()
        .try_into()
        .map_err(|_| SdkError::Emit("minted readKey is not 32 bytes".to_string()))?;
    let write_key_arr: [u8; 32] = write_key
        .as_slice()
        .try_into()
        .map_err(|_| SdkError::Emit("minted writeKey is not 32 bytes".to_string()))?;

    let id = cipherbox_crypto::utils::generate_uuid_v4();
    let now = now_ms();

    let node = if is_root {
        Node::Root {
            id: id.clone(),
            generation: 0,
            created_at: now,
            modified_at: now,
            children,
        }
    } else {
        Node::Folder {
            id: id.clone(),
            generation: 0,
            created_at: now,
            modified_at: now,
            children,
        }
    };

    let write_body = NodeWriteBody {
        ipns_private_key: ipns_private_key.clone(),
        write_children,
        recipient_pins: Vec::new(),
    };

    let published =
        seal::seal_published_node(&node, &read_key_arr, &write_key_arr, Some(&write_body))?;
    let published_node = encode_published_node(&published)?;

    Ok(FolderEmission {
        published_node,
        ipns_name,
        id,
        read_key,
        write_key,
        ipns_private_key,
    })
}

/// Mints a fresh Ed25519 ipns keypair + readKey + writeKey, derives the k51
/// ipns_name, builds a file `Node` (generation 0) wrapping `content`, and
/// seals BOTH bodies. No network IO. Mirrors [`build_folder_emission`]'s
/// mint/seal discipline exactly; `write_children` is always empty (a file
/// node has no children).
pub fn build_file_emission(content: NodeContent) -> Result<FileEmission, SdkError> {
    let (ipns_public_key, ipns_private_key_zeroizing) =
        cipherbox_crypto::generate_ed25519_keypair();
    let ipns_private_key: Vec<u8> = ipns_private_key_zeroizing.to_vec();

    let ipns_public_key_arr: [u8; 32] = ipns_public_key
        .as_slice()
        .try_into()
        .map_err(|_| SdkError::Emit("minted ed25519 public key is not 32 bytes".to_string()))?;
    let ipns_name = cipherbox_crypto::derive_ipns_name(&ipns_public_key_arr)?;

    let read_key = cipherbox_crypto::generate_random_bytes(32);
    let write_key = cipherbox_crypto::generate_random_bytes(32);
    let read_key_arr: [u8; 32] = read_key
        .as_slice()
        .try_into()
        .map_err(|_| SdkError::Emit("minted readKey is not 32 bytes".to_string()))?;
    let write_key_arr: [u8; 32] = write_key
        .as_slice()
        .try_into()
        .map_err(|_| SdkError::Emit("minted writeKey is not 32 bytes".to_string()))?;

    let id = cipherbox_crypto::utils::generate_uuid_v4();
    let now = now_ms();

    let node = Node::File {
        id: id.clone(),
        generation: 0,
        created_at: now,
        modified_at: now,
        content,
    };

    let write_body = NodeWriteBody {
        ipns_private_key: ipns_private_key.clone(),
        write_children: Vec::new(),
        recipient_pins: Vec::new(),
    };

    let published =
        seal::seal_published_node(&node, &read_key_arr, &write_key_arr, Some(&write_body))?;
    let published_node = encode_published_node(&published)?;

    Ok(FileEmission {
        published_node,
        ipns_name,
        id,
        read_key,
        write_key,
        ipns_private_key,
    })
}

// ---------------------------------------------------------------------------
// create_folder_node / create_file_node -- mint + seal + FIRST publish
// ---------------------------------------------------------------------------

/// Builds a fresh folder/root emission and publishes it as the FIRST IPNS
/// record for this node (sequence 1, T-69-16-04). Mirrors the exact
/// `registry.rs`/legacy `mkdir.rs` idiom: `upload_content` ->
/// `create_ipns_record(seq=1)` -> `publish_ipns`, no new publish
/// abstraction, no CAS/conflict-detection (first publish never needs it).
///
/// When `tee` is `Some`, the `ipnsPrivateKey` is TEE-wrapped (ECIES, the
/// ONLY ECIES on this path, CLAUDE.md rule #7) and computed BEFORE the
/// upload -- fail-closed on a malformed TEE public key rather than
/// publishing an un-enrollable folder.
pub async fn create_folder_node(
    api: &ApiClient,
    children: Vec<SealedChildRef>,
    write_children: Vec<WriteChildRef>,
    is_root: bool,
    tee: Option<TeeEnrollment>,
) -> Result<FolderEmission, SdkError> {
    let emission = build_folder_emission(children, write_children, is_root)?;
    publish_first(
        api,
        &emission.published_node,
        &emission.ipns_name,
        &emission.ipns_private_key,
        tee,
    )
    .await?;
    Ok(emission)
}

/// Builds a fresh file emission and publishes it as the FIRST IPNS record
/// for this node (sequence 1). A1: publishes inline by default AND returns
/// the ready emission so a P1b batching caller (e.g. `journal_helpers.rs`'s
/// analog) can reuse the already-minted keys/bytes without re-minting.
pub async fn create_file_node(
    api: &ApiClient,
    content: NodeContent,
    tee: Option<TeeEnrollment>,
) -> Result<FileEmission, SdkError> {
    let emission = build_file_emission(content)?;
    publish_first(
        api,
        &emission.published_node,
        &emission.ipns_name,
        &emission.ipns_private_key,
        tee,
    )
    .await?;
    Ok(emission)
}

/// Shared FIRST-publish primitive (sequence 1, no CAS): upload the sealed
/// envelope, TEE-wrap the ipnsPrivateKey when enrolled (fail-closed BEFORE
/// upload), create+marshal the IPNS record, and publish. A conflict on a
/// brand-new k51 name is unexpected (fresh keys never collide) -- logged
/// and treated as non-fatal, mirroring `registry.rs`/`mkdir.rs`.
async fn publish_first(
    api: &ApiClient,
    published_node: &[u8],
    ipns_name: &str,
    ipns_private_key: &[u8],
    tee: Option<TeeEnrollment>,
) -> Result<(), SdkError> {
    // TEE fields computed FIRST, fail-closed BEFORE any upload/publish IO
    // (T-69-16-04): a malformed TEE public key must never let an
    // un-enrollable folder get published anyway.
    let (encrypted_ipns_private_key, key_epoch) = match tee {
        Some(enrollment) => {
            let wrapped =
                cipherbox_crypto::ecies::wrap_key(ipns_private_key, &enrollment.tee_public_key)?;
            (Some(hex::encode(wrapped)), Some(enrollment.key_epoch))
        }
        None => (None, None),
    };

    let cid = upload_content(api, published_node)
        .await
        .map_err(SdkError::Api)?;

    let ipns_priv_arr: [u8; 32] = ipns_private_key
        .try_into()
        .map_err(|_| SdkError::Emit("ipnsPrivateKey is not 32 bytes".to_string()))?;
    let value = format!("/ipfs/{}", cid);
    let record = create_ipns_record(&ipns_priv_arr, &value, 1, IPNS_RECORD_LIFETIME_MS)?;
    let marshaled = marshal_ipns_record(&record)?;
    let record_b64 = STANDARD.encode(&marshaled);

    let publish_req = IpnsPublishRequest {
        ipns_name: ipns_name.to_string(),
        record: record_b64,
        metadata_cid: cid,
        encrypted_ipns_private_key,
        key_epoch,
        expected_sequence_number: None,
    };

    match publish_ipns(api, &publish_req)
        .await
        .map_err(SdkError::Api)?
    {
        PublishResult::Success => {}
        PublishResult::Conflict { .. } => {
            log::warn!(
                "Unexpected conflict on first publish (sequence 1) for {}",
                ipns_name
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// build_child_refs -- the D-07 dual read/write link
// ---------------------------------------------------------------------------

/// Produces the D-07 dual link for one child: a read-plane `SealedChildRef`
/// keyed by `ipns_name` (`read_key_sealed = seal_child_read_key(..)`) AND a
/// write-plane `WriteChildRef` keyed by `child_id` (a UUID,
/// `write_key_sealed = seal_child_write_key(..)`) -- the two keys are NEVER
/// conflated (`child_id` a UUID, `ipns_name` a k51, structurally distinct
/// formats; project memory "write plane keyed by UUID, read plane by
/// ipnsName").
///
/// Terminal-owner (D-09): all four key parameters are taken by BORROW and
/// are NEVER zeroed here -- the caller retains ownership of their
/// lifecycle. `generation`/`version_floor` are the values this ref will
/// present to the ROT-07 gate on the next resolve of this child (parent
/// mirror semantics, Pitfall 4 / M1 -- see `crate::listing`).
pub fn build_child_refs(
    child_read_key: &[u8; 32],
    child_write_key: &[u8; 32],
    parent_read_key: &[u8; 32],
    parent_write_key: &[u8; 32],
    child_id: &str,
    ipns_name: &str,
    name: &str,
    kind: NodeKind,
    generation: u32,
    version_floor: u64,
) -> Result<(SealedChildRef, WriteChildRef), SdkError> {
    let read_key_sealed_bytes =
        seal::seal_child_read_key(child_read_key, parent_read_key, child_id, kind, generation)?;
    let read_key_sealed = STANDARD.encode(read_key_sealed_bytes);

    let write_key_sealed_bytes = seal::seal_child_write_key(
        child_write_key,
        parent_write_key,
        child_id,
        kind,
        generation,
    )?;
    let write_key_sealed = STANDARD.encode(write_key_sealed_bytes);

    let sealed_child_ref = SealedChildRef {
        name: name.to_string(),
        ipns_name: ipns_name.to_string(),
        generation,
        version_floor,
        read_key_sealed,
    };

    let write_child_ref = WriteChildRef {
        child_id: child_id.to_string(),
        write_key_sealed,
    };

    Ok((sealed_child_ref, write_child_ref))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{list_folder, FetchedRecord, ListingError, NodeFetcher};
    use crate::rotation::{HighWaterStore, RotationError, RotationHighWater};
    use cipherbox_core::node::seal as core_seal;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory HighWaterStore fixture (mirrors listing.rs's own MemStore).
    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, u64>>);

    impl HighWaterStore for MemStore {
        async fn get(&self, node_id: &str) -> Option<u64> {
            self.0.lock().unwrap().get(node_id).copied()
        }

        async fn put(&self, node_id: &str, value: u64) -> Result<(), RotationError> {
            self.0.lock().unwrap().insert(node_id.to_string(), value);
            Ok(())
        }
    }

    fn rhw() -> RotationHighWater<MemStore> {
        RotationHighWater::new(MemStore::default(), MemStore::default())
    }

    /// In-memory fetcher fixture (mirrors listing.rs's own FakeFetcher).
    #[derive(Default)]
    struct FakeFetcher(HashMap<String, FetchedRecord>);

    impl NodeFetcher for FakeFetcher {
        async fn fetch(&self, ipns_name: &str) -> Result<FetchedRecord, ListingError> {
            self.0
                .get(ipns_name)
                .cloned()
                .ok_or_else(|| ListingError::FetchFailed {
                    ipns_name: ipns_name.to_string(),
                    message: "not found in fixture".to_string(),
                })
        }
    }

    fn sample_content(size: u64) -> NodeContent {
        NodeContent {
            cid: "cid-1".to_string(),
            file_iv: "iv-1".to_string(),
            size,
            mime_type: "text/plain".to_string(),
            encryption_mode: "GCM".to_string(),
            file_key: vec![9u8; 32],
            versions: Vec::new(),
        }
    }

    // -----------------------------------------------------------------
    // build_folder_emission / build_file_emission: pure mint+seal.
    // -----------------------------------------------------------------

    #[test]
    fn build_folder_emission_mints_and_seals_an_empty_folder() {
        let emission = build_folder_emission(vec![], vec![], false).expect("build ok");
        assert!(!emission.published_node.is_empty());
        assert!(emission.ipns_name.starts_with('k'));
        assert_eq!(emission.read_key.len(), 32);
        assert_eq!(emission.write_key.len(), 32);
        assert_eq!(emission.ipns_private_key.len(), 32);
    }

    #[test]
    fn build_file_emission_mints_and_seals_a_file_node() {
        let emission = build_file_emission(sample_content(1234)).expect("build ok");
        assert!(!emission.published_node.is_empty());
        assert!(emission.ipns_name.starts_with('k'));
        assert_eq!(emission.read_key.len(), 32);
        assert_eq!(emission.write_key.len(), 32);
    }

    #[test]
    fn each_emission_mints_distinct_keys_and_ipns_names() {
        let a = build_folder_emission(vec![], vec![], false).unwrap();
        let b = build_folder_emission(vec![], vec![], false).unwrap();
        assert_ne!(a.ipns_name, b.ipns_name);
        assert_ne!(a.id, b.id);
        assert_ne!(a.read_key, b.read_key);
    }

    // -----------------------------------------------------------------
    // (a) emit->list round-trip: a folder emission whose children contain
    // a build_child_refs SealedChildRef, fed through FakeFetcher +
    // list_folder, yields exactly that child as a ResolvedChild.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn emit_children_round_trip_through_list_folder() {
        // Mint the two children independently (own keys/ids/ipns_names).
        let file_emission = build_file_emission(sample_content(777)).expect("file emission");
        let subfolder_emission =
            build_folder_emission(vec![], vec![], false).expect("subfolder emission");

        // Mint the PARENT's own identity via an empty-children stub -- its
        // read_key/write_key/id are what the children's SealedChildRef/
        // WriteChildRef must be sealed under (the enclosing folder's OWN
        // read/write key, per crate::listing's parent_read_key convention).
        let parent_stub = build_folder_emission(vec![], vec![], false).expect("parent stub");
        let parent_read_key: [u8; 32] = parent_stub.read_key.clone().try_into().unwrap();
        let parent_write_key: [u8; 32] = parent_stub.write_key.clone().try_into().unwrap();

        let file_read_key: [u8; 32] = file_emission.read_key.clone().try_into().unwrap();
        let file_write_key: [u8; 32] = file_emission.write_key.clone().try_into().unwrap();
        let folder_read_key: [u8; 32] = subfolder_emission.read_key.clone().try_into().unwrap();
        let folder_write_key: [u8; 32] = subfolder_emission.write_key.clone().try_into().unwrap();

        let (file_sealed_ref, file_write_ref) = build_child_refs(
            &file_read_key,
            &file_write_key,
            &parent_read_key,
            &parent_write_key,
            &file_emission.id,
            &file_emission.ipns_name,
            "hello.txt",
            NodeKind::File,
            0,
            0,
        )
        .expect("build_child_refs (file) ok");

        let (folder_sealed_ref, folder_write_ref) = build_child_refs(
            &folder_read_key,
            &folder_write_key,
            &parent_read_key,
            &parent_write_key,
            &subfolder_emission.id,
            &subfolder_emission.ipns_name,
            "subdir",
            NodeKind::Folder,
            0,
            0,
        )
        .expect("build_child_refs (folder) ok");

        // Re-seal the SAME parent identity (same id/keys minted by
        // parent_stub) now WITH both children -- this is the "add children
        // to a just-minted/existing folder" step (mirrors how
        // rotate_one re-seals an existing node on mutation); build_folder_emission
        // itself only mints+seals a node's OWN fresh identity in one shot.
        let parent_node = Node::Folder {
            id: parent_stub.id.clone(),
            generation: 0,
            created_at: 1_000,
            modified_at: 5_000,
            children: vec![file_sealed_ref, folder_sealed_ref],
        };
        let parent_write_body = NodeWriteBody {
            ipns_private_key: parent_stub.ipns_private_key.clone(),
            write_children: vec![file_write_ref.clone(), folder_write_ref.clone()],
            recipient_pins: Vec::new(),
        };
        let parent_published = core_seal::seal_published_node(
            &parent_node,
            &parent_read_key,
            &parent_write_key,
            Some(&parent_write_body),
        )
        .expect("re-seal parent ok");
        let parent_published_bytes = encode_published_node(&parent_published).expect("encode ok");

        // D-07: the write-plane key (child_id, a UUID) is never the
        // read-plane key (ipns_name, a k51) -- assembled here so the fixture
        // itself demonstrates the dual link is addressable by both keys.
        assert_ne!(file_write_ref.child_id, file_emission.ipns_name);
        assert_ne!(folder_write_ref.child_id, subfolder_emission.ipns_name);

        let fetcher = FakeFetcher(HashMap::from([
            (
                parent_stub.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: parent_published_bytes,
                },
            ),
            (
                file_emission.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: file_emission.published_node.clone(),
                },
            ),
            (
                subfolder_emission.ipns_name.clone(),
                FetchedRecord {
                    sequence_number: 1,
                    bytes: subfolder_emission.published_node.clone(),
                },
            ),
        ]));

        let high_water = rhw();
        let children = list_folder(
            &fetcher,
            &high_water,
            &parent_stub.ipns_name,
            &parent_read_key,
            None,
        )
        .await
        .expect("list_folder should succeed");

        assert_eq!(children.len(), 2);

        let file_child = children
            .iter()
            .find(|c| c.ipns_name == file_emission.ipns_name)
            .expect("file child resolved");
        assert_eq!(file_child.name, "hello.txt");
        assert_eq!(file_child.kind, NodeKind::File);
        assert_eq!(file_child.size, Some(777));

        let folder_child = children
            .iter()
            .find(|c| c.ipns_name == subfolder_emission.ipns_name)
            .expect("folder child resolved");
        assert_eq!(folder_child.name, "subdir");
        assert_eq!(folder_child.kind, NodeKind::Folder);
        assert_eq!(folder_child.size, None);
    }

    // -----------------------------------------------------------------
    // (b) D-07: WriteChildRef.child_id (a UUID) is never equal to
    // SealedChildRef.ipns_name (a k51) -- the two key spaces are distinct.
    // -----------------------------------------------------------------

    #[test]
    fn write_child_ref_id_is_never_the_sealed_child_ref_ipns_name() {
        let file_emission = build_file_emission(sample_content(1)).expect("file emission");
        let parent_read_key = [7u8; 32];
        let parent_write_key = [8u8; 32];
        let child_read_key: [u8; 32] = file_emission.read_key.clone().try_into().unwrap();
        let child_write_key: [u8; 32] = file_emission.write_key.clone().try_into().unwrap();

        let (sealed_child_ref, write_child_ref) = build_child_refs(
            &child_read_key,
            &child_write_key,
            &parent_read_key,
            &parent_write_key,
            &file_emission.id,
            &file_emission.ipns_name,
            "file.bin",
            NodeKind::File,
            0,
            0,
        )
        .expect("build_child_refs ok");

        assert_eq!(sealed_child_ref.ipns_name, file_emission.ipns_name);
        assert_eq!(write_child_ref.child_id, file_emission.id);
        assert_ne!(
            write_child_ref.child_id, sealed_child_ref.ipns_name,
            "write-plane child_id (UUID) must never equal read-plane ipns_name (k51)"
        );
    }

    // -----------------------------------------------------------------
    // (c) Terminal-owner: a caller-supplied parent key buffer is unchanged
    // after build_child_refs (borrow-only, never zeroed here).
    // -----------------------------------------------------------------

    #[test]
    fn caller_supplied_parent_key_buffers_are_unchanged_after_build_child_refs() {
        let file_emission = build_file_emission(sample_content(1)).expect("file emission");
        let child_read_key: [u8; 32] = file_emission.read_key.clone().try_into().unwrap();
        let child_write_key: [u8; 32] = file_emission.write_key.clone().try_into().unwrap();

        let parent_read_key = [11u8; 32];
        let parent_write_key = [22u8; 32];
        let parent_read_key_before = parent_read_key;
        let parent_write_key_before = parent_write_key;

        let _ = build_child_refs(
            &child_read_key,
            &child_write_key,
            &parent_read_key,
            &parent_write_key,
            &file_emission.id,
            &file_emission.ipns_name,
            "file.bin",
            NodeKind::File,
            0,
            0,
        )
        .expect("build_child_refs ok");

        assert_eq!(
            parent_read_key, parent_read_key_before,
            "build_child_refs must never mutate/zero the caller's parent_read_key buffer"
        );
        assert_eq!(
            parent_write_key, parent_write_key_before,
            "build_child_refs must never mutate/zero the caller's parent_write_key buffer"
        );
    }
}
