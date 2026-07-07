//! Vault initialization and decryption commands.

use crate::state::AppState;
use zeroize::Zeroizing;

/// Build an empty node/v3 ROOT node (no children) sealed under the given root
/// read/write keys, returning the `encode_published_node` envelope bytes.
///
/// Pure / no-IO. Mirrors the `crates/sdk::build_folder_emission` seal path
/// (`seal_published_node(.., Some(&write_body))` → `encode_published_node`) but
/// with the vault's REAL root keys — the two independent random root read/write
/// keys minted at `initialize_vault` and the HKDF-derived root IPNS signing seed
/// — instead of the fresh random IPNS keypair `build_folder_emission` mints, so
/// create and recovery agree on the root keys.
///
/// Terminal-owner (D-09): the caller owns the key buffers; this helper only
/// borrows them into the seal and never zeroes caller-owned material.
fn build_empty_root_published_node(
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
    root_ipns_private_key: &[u8],
) -> Result<Vec<u8>, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let root_node = cipherbox_core::node::Node::Root {
        id: cipherbox_crypto::utils::generate_uuid_v4(),
        generation: 0,
        created_at: now,
        modified_at: now,
        children: Vec::new(),
    };
    let write_body = cipherbox_core::node::NodeWriteBody {
        ipns_private_key: root_ipns_private_key.to_vec(),
        write_children: Vec::new(),
    };
    let published = cipherbox_core::node::seal::seal_published_node(
        &root_node,
        root_read_key,
        root_write_key,
        Some(&write_body),
    )
    .map_err(|e| format!("root node seal failed: {}", e))?;
    cipherbox_core::node::encode_published_node(&published)
        .map_err(|e| format!("root node encode failed: {}", e))
}

/// Load user-configurable vault settings from encrypted IPNS entry.
///
/// Pattern: derive IPNS keypair -> resolve IPNS -> fetch IPFS -> ECIES unwrap -> parse JSON -> validate.
/// Returns default settings on any failure (IPNS not found, decrypt error, parse error).
/// Per D-03 and D-05: graceful fallback, desktop is read-only for settings.
pub(crate) async fn load_vault_settings(
    api: &std::sync::Arc<cipherbox_api_client::ApiClient>,
    private_key: &[u8; 32],
) -> cipherbox_core::VaultSettings {
    let result: Result<cipherbox_core::VaultSettings, String> =
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (_priv_key, _pub_key, ipns_name) =
                cipherbox_crypto::hkdf::derive_vault_settings_ipns_keypair(private_key)
                    .map_err(|e| format!("HKDF derivation failed: {:?}", e))?;

            // D-09: route through verified chokepoint — fail-closed on tampered settings.
            let resolved =
                match cipherbox_api_client::ipns::resolve_ipns_verified(api, &ipns_name).await {
                    Ok(v) => v,
                    Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
                        return Err(format!("IPNS resolve failed: {}", e));
                    }
                    Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
                        log::error!(
                            "Vault settings IPNS {} verify failed (D-09): {}",
                            ipns_name,
                            msg
                        );
                        return Err(format!("IPNS verification failed: {}", msg));
                    }
                };

            let encrypted = cipherbox_api_client::ipfs::fetch_content(api, &resolved.cid)
                .await
                .map_err(|e| format!("IPFS fetch failed: {}", e))?;

            // NOT AES-GCM — vault settings use ECIES wrapKey
            let plaintext = cipherbox_crypto::ecies::unwrap_key(&encrypted, private_key)
                .map_err(|e| format!("ECIES unwrap failed: {:?}", e))?;

            let parsed: serde_json::Value = serde_json::from_slice(&plaintext)
                .map_err(|e| format!("JSON parse failed: {}", e))?;

            Ok(cipherbox_core::validate_vault_settings(&parsed))
        })
        .await
        .unwrap_or_else(|_| Err("vault settings load timed out after 10s".to_string()));

    match result {
        Ok(settings) => {
            log::info!(
                "Vault settings loaded: maxVersions={}, cooldown={}min, retention={}d, delete={:?}",
                settings.max_versions_per_file,
                settings.version_cooldown_minutes,
                settings.recycle_bin_retention_days,
                settings.delete_behavior
            );
            settings
        }
        Err(e) => {
            log::warn!("Vault settings load failed (using defaults): {}", e);
            cipherbox_core::default_vault_settings()
        }
    }
}

/// Initialize a new vault for a first-time user (node/v3).
///
/// Mints TWO independent random 32-byte root keys (`root_read_key`,
/// `root_write_key`) — never derived from one another — and a deterministic
/// Ed25519 IPNS keypair via HKDF from the user's private key. ECIES-wraps both
/// root keys with the user's secp256k1 public key into a vault-blob-v3, seals
/// the empty root Node under those same two keys, publishes both to IPNS, and
/// POSTs only `{ owner_public_key, root_ipns_name }` to `/vault/init`.
pub(crate) async fn initialize_vault(state: &AppState, public_key: &[u8]) -> Result<(), String> {
    // Mint two INDEPENDENT random 32-byte root keys (node/v3): read-plane and
    // write-plane seal keys. Two separate calls — never derived from each other
    // (research §Q1); a web-created v3 vault must be cross-openable.
    let root_read_key: Zeroizing<[u8; 32]> =
        Zeroizing::new(cipherbox_crypto::utils::generate_file_key());
    let root_write_key: Zeroizing<[u8; 32]> =
        Zeroizing::new(cipherbox_crypto::utils::generate_file_key());

    // Derive IPNS keypairs from user's private key
    let private_key = state
        .sdk
        .private_key
        .read()
        .await
        .as_ref()
        .ok_or("Private key not available for vault IPNS derivation")?
        .clone();
    let private_key_arr: [u8; 32] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid private key length")?;

    // Root folder IPNS keypair (for folder metadata)
    let (root_ipns_private_key, _root_ipns_public_key, root_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault IPNS derivation failed: {:?}", e))?;

    // Vault key IPNS keypair (for rootFolderKey blob — separate IPNS name)
    let (vault_key_ipns_private, _vault_key_ipns_public, vault_key_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_key_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault key IPNS derivation failed: {:?}", e))?;

    // ECIES-wrap BOTH root keys under the user's secp256k1 pubkey (CLAUDE.md #4 /
    // NODE-06 — the ONLY ECIES on this path). Order: read then write, mirroring
    // the web oracle (packages/core init.ts + sdk-core publishVaultKeyBlob).
    let encrypted_root_read_key = cipherbox_crypto::ecies::wrap_key(&*root_read_key, public_key)
        .map_err(|e| format!("Failed to wrap root read key: {}", e))?;
    let encrypted_root_write_key = cipherbox_crypto::ecies::wrap_key(&*root_write_key, public_key)
        .map_err(|e| format!("Failed to wrap root write key: {}", e))?;

    log::info!("Publishing vault key blob and root folder metadata");

    use base64::Engine;

    // 1. Publish v3 key blob to vault key IPNS (both ECIES-wrapped keys, no metadata)
    let blob_bytes = cipherbox_core::vault_blob::serialize_vault_blob_v3(
        &encrypted_root_read_key,
        &encrypted_root_write_key,
    )?;
    let key_blob_cid = cipherbox_api_client::ipfs::upload_content(&state.sdk.api, &blob_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let vault_key_ipns_arr: [u8; 32] = vault_key_ipns_private
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid vault key IPNS private key length".to_string())?;
    let key_value = format!("/ipfs/{}", key_blob_cid);
    let key_record =
        cipherbox_core::ipns::create_ipns_record(&vault_key_ipns_arr, &key_value, 1, 86_400_000)
            .map_err(|e| format!("IPNS record creation failed: {}", e))?;
    let key_marshaled = cipherbox_core::ipns::marshal_ipns_record(&key_record)
        .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
    let key_record_base64 = base64::engine::general_purpose::STANDARD.encode(&key_marshaled);

    let key_publish_req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: vault_key_ipns_name,
        record: key_record_base64,
        metadata_cid: key_blob_cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(&state.sdk.api, &key_publish_req)
        .await
        .map_err(|e| e.to_string())?
    {
        cipherbox_api_client::PublishResult::Success => {}
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on vault key blob publish (sequence 1); aborting vault initialization to avoid mismatched root_folder_key");
            return Err(
                "Vault initialization aborted due to existing vault key IPNS record".to_string(),
            );
        }
    }

    // 2. Publish the root folder as an empty node/v3 ROOT node (seq 1), sealed
    //    under the SAME two random root keys wrapped into the v3 blob above so a
    //    fresh vault opens on recovery. The root IPNS keypair stays HKDF-derived
    //    (recomputable, not in the blob) so create and recovery agree. This
    //    replaces the legacy placeholder bridge removed in 69-23.
    let root_node_bytes = build_empty_root_published_node(
        &root_read_key,
        &root_write_key,
        root_ipns_private_key.as_slice(),
    )?;
    let folder_cid = cipherbox_api_client::ipfs::upload_content(&state.sdk.api, &root_node_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let root_ipns_arr: [u8; 32] = root_ipns_private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid root IPNS private key length".to_string())?;
    let folder_value = format!("/ipfs/{}", folder_cid);
    let folder_record =
        cipherbox_core::ipns::create_ipns_record(&root_ipns_arr, &folder_value, 1, 86_400_000)
            .map_err(|e| format!("IPNS record creation failed: {}", e))?;
    let folder_marshaled = cipherbox_core::ipns::marshal_ipns_record(&folder_record)
        .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
    let folder_record_base64 = base64::engine::general_purpose::STANDARD.encode(&folder_marshaled);

    let folder_publish_req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: root_ipns_name.clone(),
        record: folder_record_base64,
        metadata_cid: folder_cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(&state.sdk.api, &folder_publish_req)
        .await
        .map_err(|e| e.to_string())?
    {
        cipherbox_api_client::PublishResult::Success => {}
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on root folder publish (sequence 1); aborting vault initialization to avoid inconsistent state");
            return Err(
                "Vault initialization aborted due to existing root folder IPNS record".to_string(),
            );
        }
    }

    // 3. Register vault with backend AFTER both IPNS records are durable
    let init_req = cipherbox_api_client::InitVaultRequest {
        owner_public_key: hex::encode(public_key),
        root_ipns_name: root_ipns_name.clone(),
    };

    let resp = state
        .sdk
        .api
        .authenticated_post("/vault/init", &init_req)
        .await
        .map_err(|e| format!("Vault init request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vault init failed ({}): {}", status, body));
    }

    log::info!("Vault initialized: key blob + root metadata published for new user");
    Ok(())
}

/// Fetch vault from backend and recover the node/v3 root keys from the IPFS v3 blob.
///
/// Deserializes the vault-blob-v3 and ECIES-unwraps BOTH `root_read_key` and
/// `root_write_key` under the user's private key. The root Ed25519 IPNS keypair
/// is always HKDF-derived from the user's private key (recomputable, not in the
/// blob). Stores all keys in AppState (memory only).
pub(crate) async fn fetch_and_decrypt_vault(state: &AppState) -> Result<(), String> {
    log::info!("Fetching and decrypting vault keys");

    // GET /vault
    let resp = state
        .sdk
        .api
        .authenticated_get("/vault")
        .await
        .map_err(|e| format!("Vault fetch failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vault fetch failed ({}): {}", status, body));
    }

    let vault: cipherbox_api_client::VaultResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse vault response: {}", e))?;

    // Get private key
    let private_key = state
        .sdk
        .private_key
        .read()
        .await
        .as_ref()
        .ok_or("Private key not available for vault decryption")?
        .clone();
    let private_key_arr: [u8; 32] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid private key length")?;

    // Derive root folder IPNS keypair (for folder operations)
    let (root_ipns_priv, _root_ipns_pub, _root_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("HKDF derivation failed: {:?}", e))?;

    // Derive vault key IPNS keypair (for rootFolderKey blob)
    let (_vault_key_priv, _vault_key_pub, vault_key_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_key_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault key HKDF derivation failed: {:?}", e))?;

    // D-09: route vault key IPNS through verified chokepoint — tampered blob rejected.
    let resolved = match cipherbox_api_client::ipns::resolve_ipns_verified(
        &state.sdk.api,
        &vault_key_ipns_name,
    )
    .await
    {
        Ok(v) => v,
        Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
            return Err(format!("Vault key IPNS resolve failed: {}", e));
        }
        Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
            log::error!(
                "Vault key IPNS {} verify failed (D-09): {}",
                vault_key_ipns_name,
                msg
            );
            return Err(format!("Vault key IPNS verification failed: {}", msg));
        }
    };
    let blob_bytes = cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resolved.cid)
        .await
        .map_err(|e| format!("IPFS fetch failed for vault key blob: {}", e))?;

    // node/v3: deserialize the two ECIES-wrapped root keys (read then write) and
    // unwrap each under the user's private key. A v2/malformed blob is rejected
    // fail-closed by deserialize_vault_blob_v3's Err (the old v2-only gate is gone).
    let (enc_read, enc_write) = cipherbox_core::vault_blob::deserialize_vault_blob_v3(&blob_bytes)
        .map_err(|e| format!("v3 blob parse failed: {}", e))?;
    let root_read_key = cipherbox_crypto::ecies::unwrap_key(&enc_read, &private_key)
        .map_err(|e| format!("Failed to decrypt root read key from v3 blob: {}", e))?;
    let root_write_key = cipherbox_crypto::ecies::unwrap_key(&enc_write, &private_key)
        .map_err(|e| format!("Failed to decrypt root write key from v3 blob: {}", e))?;

    // `unwrap_key` returns `Zeroizing<Vec<u8>>` and the SDK-state fields are also
    // `Zeroizing<Vec<u8>>`, so store directly and keep the keys wiped on drop.
    // Transitional (until 69-24): `root_folder_key` mirrors `root_read_key` so the
    // still-bridged mount (fuse/mod.rs) + post_auth_finalize `root_folder_key`
    // read stay workspace-green; 69-24 removes this coupling.
    *state.sdk.root_folder_key.write().await = Some(Zeroizing::new(root_read_key.to_vec()));
    *state.sdk.root_read_key.write().await = Some(root_read_key);
    *state.sdk.root_write_key.write().await = Some(root_write_key);

    // Root folder IPNS key is HKDF-derived (recomputable, NOT in the blob)
    *state.sdk.root_ipns_private_key.write().await = Some(root_ipns_priv.to_vec());

    // Store IPNS name and TEE keys
    *state.sdk.root_ipns_name.write().await = Some(vault.root_ipns_name);
    *state.sdk.tee_keys.write().await = vault.tee_keys;

    log::info!("Vault keys decrypted and stored in memory");
    Ok(())
}

#[cfg(test)]
mod root_emit_tests {
    use super::*;
    use base64::Engine as _;

    /// KAT-consistent round-trip for the empty node/v3 root emit helper:
    /// seal+encode → decode envelope → unseal both bodies under two INDEPENDENT
    /// random-style root keys, asserting AAD key separation (read key cannot
    /// open the write body).
    #[test]
    fn build_empty_root_published_node_round_trips() {
        // Two independent distinct root keys (node/v3) — never derived from each other.
        let read_key = [0x42u8; 32];
        let write_key = [0x7Eu8; 32];
        let root_ipns_seed = [0x11u8; 32];

        let bytes = build_empty_root_published_node(&read_key, &write_key, &root_ipns_seed)
            .expect("build empty root published node");

        // Envelope shape: schema node/v3, kind root, generation 0, both bodies sealed.
        let published =
            cipherbox_core::node::decode_published_node(&bytes).expect("decode published node");
        assert_eq!(published.schema, "node/v3");
        assert_eq!(published.kind, "root");
        assert_eq!(published.generation, 0);
        assert!(
            published.write_sealed.is_some(),
            "write body must be sealed"
        );

        // Read-body unseals under the root read key → empty-children Root.
        let read_sealed = base64::engine::general_purpose::STANDARD
            .decode(&published.read_sealed)
            .expect("valid base64 read_sealed");
        let read_body = cipherbox_core::node::seal::unseal_node(
            &read_sealed,
            &read_key,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            0,
        )
        .expect("unseal read body under read key");
        match cipherbox_core::node::decode_node(&read_body).expect("decode read-body node") {
            cipherbox_core::node::Node::Root {
                children,
                generation,
                ..
            } => {
                assert!(children.is_empty(), "root has no children");
                assert_eq!(generation, 0);
            }
            other => panic!("expected Node::Root, got {:?}", other),
        }

        // Write-body unseals under the root write key → empty write_children + the ipns seed.
        let write_sealed = base64::engine::general_purpose::STANDARD
            .decode(published.write_sealed.as_ref().unwrap())
            .expect("valid base64 write_sealed");
        let write_body_bytes = cipherbox_core::node::seal::unseal_node(
            &write_sealed,
            &write_key,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            0,
        )
        .expect("unseal write body under write key");
        let write_body =
            cipherbox_core::node::decode_write_body(&write_body_bytes).expect("decode write body");
        assert!(write_body.write_children.is_empty(), "no write children");
        assert_eq!(write_body.ipns_private_key, root_ipns_seed.to_vec());

        // AAD key separation: the read key must NOT open the write-body seal.
        let opened_with_read = cipherbox_core::node::seal::unseal_node(
            &write_sealed,
            &read_key,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            0,
        );
        assert!(
            opened_with_read.is_err(),
            "the write-body must not open under the read key (AAD/key separation)"
        );
    }

    /// End-to-end init->recover round-trip (pure, no live IO): mirror
    /// `initialize_vault`'s wrap+serialize with two INDEPENDENT random-style root
    /// keys, then mirror `fetch_and_decrypt_vault`'s deserialize+unwrap and assert
    /// both keys come back byte-identical (and stay distinct). Finally seal the
    /// empty root under the recovered keys and assert the read-body opens under
    /// root_read_key but the write-body does NOT (AAD/key separation).
    #[test]
    fn init_recover_v3_round_trips() {
        // Fixed secp256k1 keypair: private key = 1, public key = generator point G
        // (uncompressed, 0x04 prefix). Avoids adding a keygen dependency.
        let private_key = {
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        };
        let public_key = hex::decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179\
8483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        )
        .expect("valid uncompressed secp256k1 pubkey hex");

        // Two INDEPENDENT distinct root keys (never derived from each other).
        let root_read_key = [0x11u8; 32];
        let root_write_key = [0x22u8; 32];
        assert_ne!(root_read_key, root_write_key);

        // INIT twin: ECIES-wrap both (read then write), serialize the v3 blob.
        let enc_read = cipherbox_crypto::ecies::wrap_key(&root_read_key, &public_key)
            .expect("wrap root read key");
        let enc_write = cipherbox_crypto::ecies::wrap_key(&root_write_key, &public_key)
            .expect("wrap root write key");
        let blob = cipherbox_core::vault_blob::serialize_vault_blob_v3(&enc_read, &enc_write)
            .expect("serialize v3 blob");

        // RECOVER twin: deserialize the v3 blob, unwrap both under the private key.
        let (dec_enc_read, dec_enc_write) =
            cipherbox_core::vault_blob::deserialize_vault_blob_v3(&blob)
                .expect("deserialize v3 blob");
        let rec_read = cipherbox_crypto::ecies::unwrap_key(&dec_enc_read, &private_key)
            .expect("unwrap root read key");
        let rec_write = cipherbox_crypto::ecies::unwrap_key(&dec_enc_write, &private_key)
            .expect("unwrap root write key");

        // Both keys recovered byte-identical and remain distinct.
        assert_eq!(rec_read.as_slice(), &root_read_key);
        assert_eq!(rec_write.as_slice(), &root_write_key);
        assert_ne!(rec_read.as_slice(), rec_write.as_slice());

        // Seal the empty root under the RECOVERED keys; read-body opens under the
        // read key, write-body must NOT open under the read key (AAD separation).
        let root_ipns_seed = [0x33u8; 32];
        let read_arr: [u8; 32] = rec_read
            .as_slice()
            .try_into()
            .expect("read key is 32 bytes");
        let write_arr: [u8; 32] = rec_write
            .as_slice()
            .try_into()
            .expect("write key is 32 bytes");
        let bytes = build_empty_root_published_node(&read_arr, &write_arr, &root_ipns_seed)
            .expect("build empty root node under recovered keys");
        let published =
            cipherbox_core::node::decode_published_node(&bytes).expect("decode published node");

        let read_sealed = base64::engine::general_purpose::STANDARD
            .decode(&published.read_sealed)
            .expect("valid base64 read_sealed");
        let read_body = cipherbox_core::node::seal::unseal_node(
            &read_sealed,
            &read_arr,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            0,
        )
        .expect("unseal read body under recovered read key");
        match cipherbox_core::node::decode_node(&read_body).expect("decode read-body node") {
            cipherbox_core::node::Node::Root { children, .. } => {
                assert!(children.is_empty(), "recovered root has no children");
            }
            other => panic!("expected Node::Root, got {:?}", other),
        }

        let write_sealed = base64::engine::general_purpose::STANDARD
            .decode(published.write_sealed.as_ref().expect("write body sealed"))
            .expect("valid base64 write_sealed");
        let opened_with_read = cipherbox_core::node::seal::unseal_node(
            &write_sealed,
            &read_arr,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            0,
        );
        assert!(
            opened_with_read.is_err(),
            "the write-body must not open under the recovered read key (AAD/key separation)"
        );
    }
}
