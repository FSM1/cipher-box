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
        // Fresh empty root at vault init — no shares yet (D-03).
        recipient_pins: Vec::new(),
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

/// Classify a raw IPNS resolve outcome into a fail-closed preflight verdict.
///
/// Pure / no-IO decision seam for vault-init preflight. The network resolve call
/// is performed by `preflight_ipns_absent`; this helper only maps its `Result`,
/// so the mapping is unit-testable without a live API — mirroring the
/// closure/seam testability pattern of `crates/fuse/src/metadata.rs`'s
/// `run_publish_retry_seam`.
///
/// - `Ok(true)`  — confirmed ABSENT (`ApiError::IpnsNotFound`, a real 404): safe
///   to mint fresh keys and publish.
/// - `Ok(false)` — confirmed PRESENT (`Ok(_)`): route to the recovery branch.
/// - `Err(_)`    — any OTHER `ApiError` (transient / 5xx / auth / timeout): the
///   caller MUST abort. A resolve that cannot confirm absence is NEVER coerced to
///   absent (fail closed). This arm can never return `Ok(true)`.
fn classify_preflight_outcome(
    outcome: Result<cipherbox_api_client::IpnsResolveResponse, cipherbox_api_client::ApiError>,
    ipns_name: &str,
) -> Result<bool, String> {
    match outcome {
        Ok(_) => Ok(false),
        Err(cipherbox_api_client::ApiError::IpnsNotFound(_)) => Ok(true),
        Err(e) => Err(format!("preflight resolve failed for {}: {}", ipns_name, e)),
    }
}

/// Fail-closed preflight: is `ipns_name` confirmed absent?
///
/// Resolves `ipns_name` via `cipherbox_api_client::ipns::resolve_ipns` and
/// classifies the outcome through `classify_preflight_outcome`. Returns
/// `Ok(true)` ONLY on a confirmed 404, `Ok(false)` when a record already exists,
/// and `Err` on any other outcome — in which case the caller MUST abort and
/// never publish.
async fn preflight_ipns_absent(
    api: &cipherbox_api_client::ApiClient,
    ipns_name: &str,
) -> Result<bool, String> {
    classify_preflight_outcome(
        cipherbox_api_client::ipns::resolve_ipns(api, ipns_name).await,
        ipns_name,
    )
}

/// The vault-init route selected by the fail-closed preflight of both IPNS names.
#[derive(Debug, PartialEq, Eq)]
enum VaultInitRoute {
    /// Both names absent (fresh user): mint keys, publish blob + root, register.
    FreshInit,
    /// Key blob present, root absent (publish failed after a clean preflight):
    /// decrypt-and-resume from the existing key blob WITHOUT re-minting keys.
    RecoverResume,
}

/// Route a vault init from the two `preflight_ipns_absent` verdicts, failing closed.
///
/// Consumes the raw preflight `Result`s so a transient `Err` on EITHER name aborts
/// (via `?`) BEFORE a route is chosen — i.e. before any publish is attempted. The
/// four (key_blob_absent, root_absent) presence states map as:
///
/// - (true, true)   -> `FreshInit`
/// - (false, true)  -> `RecoverResume` (decrypt-and-resume; key-blob-first order)
/// - (false, false) -> `Err`: a fully-published vault is not an init — route
///   through the normal load path (`fetch_and_decrypt_vault`) instead.
/// - (true, false)  -> `Err`: unrecoverable/unexpected under key-blob-first
///   publish order (root present but key blob absent).
///
/// This is the unit-testable decision seam for `initialize_vault` (mirrors the
/// `run_publish_retry_seam` testability pattern in `crates/fuse/src/metadata.rs`).
fn route_vault_init(
    key_blob_absent: Result<bool, String>,
    root_absent: Result<bool, String>,
) -> Result<VaultInitRoute, String> {
    let key_blob_absent = key_blob_absent?;
    let root_absent = root_absent?;
    match (key_blob_absent, root_absent) {
        (true, true) => Ok(VaultInitRoute::FreshInit),
        (false, true) => Ok(VaultInitRoute::RecoverResume),
        (false, false) => Err(
            "vault already fully initialized (both IPNS records present) — route \
             through the vault load path, not initialize_vault"
                .to_string(),
        ),
        (true, false) => Err(
            "unrecoverable vault state: root folder IPNS record present but vault \
             key blob absent (unexpected under key-blob-first publish order)"
                .to_string(),
        ),
    }
}

/// Recover the ORIGINAL root read/write keys from an already-published vault key
/// blob (decrypt-and-resume). Mirrors `fetch_and_decrypt_vault`'s ECIES unwrap:
/// resolve the vault key IPNS name through the verified chokepoint (D-09), fetch
/// the blob, deserialize the two ECIES-wrapped keys, and unwrap each under the
/// user's private key. NEVER mints new keys — a second random pair could never
/// match the already-published blob (research §Critical Finding). Returned buffers
/// zero on drop.
async fn recover_root_keys_from_key_blob(
    api: &cipherbox_api_client::ApiClient,
    vault_key_ipns_name: &str,
    private_key: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), String> {
    let resolved =
        match cipherbox_api_client::ipns::resolve_ipns_verified(api, vault_key_ipns_name).await {
            Ok(v) => v,
            Err(cipherbox_api_client::ipns::VerifyError::Api(e)) => {
                return Err(format!("recovery: vault key IPNS resolve failed: {}", e));
            }
            Err(cipherbox_api_client::ipns::VerifyError::Invalid(msg)) => {
                return Err(format!(
                    "recovery: vault key IPNS verification failed: {}",
                    msg
                ));
            }
        };
    let blob_bytes = cipherbox_api_client::ipfs::fetch_content(api, &resolved.cid)
        .await
        .map_err(|e| format!("recovery: IPFS fetch failed for vault key blob: {}", e))?;

    // node/v3: two ECIES-wrapped root keys (read then write), unwrapped under the
    // user's private key — identical to fetch_and_decrypt_vault, never re-minted.
    let (enc_read, enc_write) = cipherbox_core::vault_blob::deserialize_vault_blob_v3(&blob_bytes)
        .map_err(|e| format!("recovery: v3 blob parse failed: {}", e))?;
    let root_read_key = cipherbox_crypto::ecies::unwrap_key(&enc_read, private_key)
        .map_err(|e| format!("recovery: failed to decrypt root read key from v3 blob: {}", e))?;
    let root_write_key = cipherbox_crypto::ecies::unwrap_key(&enc_write, private_key)
        .map_err(|e| format!("recovery: failed to decrypt root write key from v3 blob: {}", e))?;
    Ok((root_read_key, root_write_key))
}

/// Coherency gate (Open Question 1 recommendation): fetch the published root node
/// back and confirm its read body unseals under the recovered `root_read_key`
/// before completing `/vault/init`. Binds the recovered keys to the root record so
/// a decrypt-and-resume never registers a vault whose root cannot be opened.
async fn coherency_check_root_unseal(
    api: &cipherbox_api_client::ApiClient,
    folder_cid: &str,
    root_read_key: &[u8; 32],
) -> Result<(), String> {
    use base64::Engine as _;
    let node_bytes = cipherbox_api_client::ipfs::fetch_content(api, folder_cid)
        .await
        .map_err(|e| format!("recovery coherency: root fetch failed: {}", e))?;
    let published = cipherbox_core::node::decode_published_node(&node_bytes)
        .map_err(|e| format!("recovery coherency: decode published root failed: {}", e))?;
    let read_sealed = base64::engine::general_purpose::STANDARD
        .decode(&published.read_sealed)
        .map_err(|e| format!("recovery coherency: read_sealed base64 decode failed: {}", e))?;
    cipherbox_core::node::seal::unseal_node(
        &read_sealed,
        root_read_key,
        &published.id,
        cipherbox_core::node::NodeKind::Root,
        published.generation,
    )
    .map_err(|e| {
        format!(
            "recovery coherency: root read body did not unseal under recovered root_read_key: {}",
            e
        )
    })?;
    Ok(())
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

/// Publish the vault-key blob (both ECIES-wrapped root keys) to the vault key
/// IPNS name at sequence 1. An unexpected CAS conflict aborts with a
/// distinguishable error so a subsequent attempt's preflight routes correctly.
async fn publish_vault_key_blob(
    api: &cipherbox_api_client::ApiClient,
    vault_key_ipns_private: &[u8],
    vault_key_ipns_name: &str,
    encrypted_root_read_key: &[u8],
    encrypted_root_write_key: &[u8],
) -> Result<(), String> {
    use base64::Engine as _;
    let blob_bytes = cipherbox_core::vault_blob::serialize_vault_blob_v3(
        encrypted_root_read_key,
        encrypted_root_write_key,
    )?;
    let key_blob_cid = cipherbox_api_client::ipfs::upload_content(api, &blob_bytes)
        .await
        .map_err(|e| format!("vault key blob upload failed: {}", e))?;

    let vault_key_ipns_arr: [u8; 32] = vault_key_ipns_private
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
        ipns_name: vault_key_ipns_name.to_string(),
        record: key_record_base64,
        metadata_cid: key_blob_cid,
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(api, &key_publish_req)
        .await
        .map_err(|e| format!("vault key blob publish failed after clean preflight: {}", e))?
    {
        cipherbox_api_client::PublishResult::Success => Ok(()),
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on vault key blob publish (sequence 1); aborting vault initialization to avoid mismatched root keys");
            Err("Vault initialization aborted due to existing vault key IPNS record".to_string())
        }
    }
}

/// Seal an empty root node/v3 under the given root keys and publish it to the
/// root folder IPNS name at sequence 1, returning the published node's CID.
/// Shared by the fresh-init and decrypt-and-resume recovery branches.
async fn publish_root_folder(
    api: &cipherbox_api_client::ApiClient,
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
    root_ipns_private_key: &[u8],
    root_ipns_name: &str,
) -> Result<String, String> {
    use base64::Engine as _;
    let root_node_bytes =
        build_empty_root_published_node(root_read_key, root_write_key, root_ipns_private_key)?;
    let folder_cid = cipherbox_api_client::ipfs::upload_content(api, &root_node_bytes)
        .await
        .map_err(|e| format!("root folder upload failed: {}", e))?;

    let root_ipns_arr: [u8; 32] = root_ipns_private_key
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
        ipns_name: root_ipns_name.to_string(),
        record: folder_record_base64,
        metadata_cid: folder_cid.clone(),
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: None,
    };
    match cipherbox_api_client::ipns::publish_ipns(api, &folder_publish_req)
        .await
        .map_err(|e| format!("root folder publish failed after clean preflight: {}", e))?
    {
        cipherbox_api_client::PublishResult::Success => Ok(folder_cid),
        cipherbox_api_client::PublishResult::Conflict { .. } => {
            log::warn!("Unexpected conflict on root folder publish (sequence 1); aborting vault initialization to avoid inconsistent state");
            Err("Vault initialization aborted due to existing root folder IPNS record".to_string())
        }
    }
}

/// POST `{ owner_public_key, root_ipns_name }` to `/vault/init` to register the
/// vault after its IPNS records are durable. Idempotent completion shared by both
/// init routes.
async fn register_vault(
    state: &AppState,
    public_key: &[u8],
    root_ipns_name: &str,
) -> Result<(), String> {
    let init_req = cipherbox_api_client::InitVaultRequest {
        owner_public_key: hex::encode(public_key),
        root_ipns_name: root_ipns_name.to_string(),
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
    Ok(())
}

/// Initialize a new vault for a first-time user (node/v3).
///
/// Fail-closed preflight of BOTH IPNS names precedes any write. On a fresh user
/// (both absent) this mints TWO independent random 32-byte root keys
/// (`root_read_key`, `root_write_key`) — never derived from one another — plus a
/// deterministic Ed25519 IPNS keypair via HKDF, ECIES-wraps both root keys into a
/// vault-blob-v3, seals the empty root Node under those keys, publishes both to
/// IPNS, and POSTs `/vault/init`.
///
/// If a prior attempt already published the key blob but not the root folder
/// (`RecoverResume`), it decrypt-and-resumes: the ORIGINAL root keys are recovered
/// via ECIES-unwrap of the existing key blob (NEVER re-minted — a second random
/// pair could never match the published blob), the missing root folder is sealed
/// and published under the recovered keys, a coherency unseal binds the recovered
/// keys to the published root, and `/vault/init` completes. Any transient resolve
/// error or unexpected presence state aborts before any write (fail closed).
pub(crate) async fn initialize_vault(state: &AppState, public_key: &[u8]) -> Result<(), String> {
    // Derive the user's private key + BOTH IPNS keypairs first (needed for the
    // preflight, before any key mint or publish).
    let private_key = state
        .sdk
        .private_key
        .read()
        .await
        .as_ref()
        .ok_or("Private key not available for vault IPNS derivation")?
        .clone();
    // Hold the user's master private key in `Zeroizing` so this transient [u8;32]
    // copy is scrubbed on drop — it lives across the preflights, uploads, and
    // publishes below. Deref coercion keeps the derive_*_ipns_keypair(&..) sites
    // unchanged. (CodeRabbit PR #610; mirrors the Zeroizing wrap on every sibling key.)
    let private_key_arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        private_key
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid private key length")?,
    );

    // Root folder IPNS keypair (for folder metadata)
    let (root_ipns_private_key, _root_ipns_public_key, root_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault IPNS derivation failed: {:?}", e))?;

    // Vault key IPNS keypair (for rootFolderKey blob — separate IPNS name)
    let (vault_key_ipns_private, _vault_key_ipns_public, vault_key_ipns_name) =
        cipherbox_crypto::hkdf::derive_vault_key_ipns_keypair(&private_key_arr)
            .map_err(|e| format!("Vault key IPNS derivation failed: {:?}", e))?;

    // Fail-closed preflight of BOTH names BEFORE any write. A transient error on
    // either name aborts here (via `?`) with no publish attempted.
    let key_blob_absent = preflight_ipns_absent(&state.sdk.api, &vault_key_ipns_name).await;
    let root_absent = preflight_ipns_absent(&state.sdk.api, &root_ipns_name).await;

    match route_vault_init(key_blob_absent, root_absent)? {
        VaultInitRoute::FreshInit => {
            // Mint two INDEPENDENT random 32-byte root keys (node/v3): read-plane
            // and write-plane seal keys. Two separate calls — never derived from
            // each other (research §Q1); a web-created v3 vault must be cross-openable.
            let root_read_key: Zeroizing<[u8; 32]> =
                Zeroizing::new(cipherbox_crypto::utils::generate_file_key());
            let root_write_key: Zeroizing<[u8; 32]> =
                Zeroizing::new(cipherbox_crypto::utils::generate_file_key());

            // ECIES-wrap BOTH root keys under the user's secp256k1 pubkey (CLAUDE.md
            // #4 / NODE-06 — the ONLY ECIES on this path). Order: read then write,
            // mirroring the web oracle (packages/core init.ts + publishVaultKeyBlob).
            let encrypted_root_read_key =
                cipherbox_crypto::ecies::wrap_key(&*root_read_key, public_key)
                    .map_err(|e| format!("Failed to wrap root read key: {}", e))?;
            let encrypted_root_write_key =
                cipherbox_crypto::ecies::wrap_key(&*root_write_key, public_key)
                    .map_err(|e| format!("Failed to wrap root write key: {}", e))?;

            log::info!("Publishing vault key blob and root folder metadata (fresh init)");

            // 1. Publish v3 key blob to the vault key IPNS name (key-blob-first order).
            publish_vault_key_blob(
                &state.sdk.api,
                vault_key_ipns_private.as_slice(),
                &vault_key_ipns_name,
                &encrypted_root_read_key,
                &encrypted_root_write_key,
            )
            .await?;

            // 2. Publish the empty root node/v3 under the SAME two random root keys.
            //    A publish failure here aborts with a distinguishable error; because
            //    the key blob is already durable, the NEXT attempt's preflight routes
            //    to the RecoverResume branch.
            publish_root_folder(
                &state.sdk.api,
                &root_read_key,
                &root_write_key,
                root_ipns_private_key.as_slice(),
                &root_ipns_name,
            )
            .await?;
        }
        VaultInitRoute::RecoverResume => {
            // Decrypt-and-resume: the key blob is already published but the root
            // folder is not. Recover the ORIGINAL root keys from the blob — NEVER
            // re-mint — then publish the missing root under them.
            log::info!(
                "Resuming partial vault init: recovering root keys from existing key blob"
            );
            let (root_read_vec, root_write_vec) = recover_root_keys_from_key_blob(
                &state.sdk.api,
                &vault_key_ipns_name,
                private_key.as_slice(),
            )
            .await?;
            // Hold the recovered root keys in `Zeroizing` (mirroring the FreshInit
            // arm above) so these transient copies are scrubbed on drop — never
            // left as bare, un-zeroized key material on the stack.
            let root_read_key: Zeroizing<[u8; 32]> = Zeroizing::new(
                root_read_vec
                    .as_slice()
                    .try_into()
                    .map_err(|_| "recovery: recovered root read key wrong length".to_string())?,
            );
            let root_write_key: Zeroizing<[u8; 32]> = Zeroizing::new(
                root_write_vec
                    .as_slice()
                    .try_into()
                    .map_err(|_| "recovery: recovered root write key wrong length".to_string())?,
            );

            let folder_cid = publish_root_folder(
                &state.sdk.api,
                &root_read_key,
                &root_write_key,
                root_ipns_private_key.as_slice(),
                &root_ipns_name,
            )
            .await?;

            // Coherency gate: confirm the published root unseals under the recovered
            // read key before registering (Open Question 1 recommendation).
            coherency_check_root_unseal(&state.sdk.api, &folder_cid, &root_read_key).await?;
        }
    }

    // Register vault with backend AFTER both IPNS records are durable.
    register_vault(state, public_key, &root_ipns_name).await?;

    log::info!("Vault initialized: key blob + root metadata published and registered");
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
    // Hold the user's master private key in `Zeroizing` so this transient [u8;32]
    // copy is scrubbed on drop — it lives across the preflights, uploads, and
    // publishes below. Deref coercion keeps the derive_*_ipns_keypair(&..) sites
    // unchanged. (CodeRabbit PR #610; mirrors the Zeroizing wrap on every sibling key.)
    let private_key_arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        private_key
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid private key length")?,
    );

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

#[cfg(test)]
mod preflight_tests {
    use super::*;

    /// A present-record resolve response (fields irrelevant to the preflight
    /// existence check — only Ok-vs-Err matters).
    fn present_response() -> cipherbox_api_client::IpnsResolveResponse {
        cipherbox_api_client::IpnsResolveResponse {
            success: true,
            cid: "bafyfakecidforpreflighttest".to_string(),
            sequence_number: "1".to_string(),
            signature_v2: None,
            data: None,
            pub_key: None,
        }
    }

    // A confirmed 404 (IpnsNotFound) is the ONLY outcome that reports "absent".
    #[test]
    fn preflight_ipns_absent_maps_not_found_to_absent() {
        let out = classify_preflight_outcome(
            Err(cipherbox_api_client::ApiError::IpnsNotFound("k51-name".to_string())),
            "k51-name",
        );
        assert_eq!(out, Ok(true), "IpnsNotFound must map to confirmed-absent");
    }

    // A successful resolve means the record exists -> recovery path (Ok(false)).
    #[test]
    fn preflight_ipns_absent_maps_ok_to_present() {
        let out = classify_preflight_outcome(Ok(present_response()), "k51-name");
        assert_eq!(out, Ok(false), "an existing record must map to present");
    }

    // A non-404 API error (5xx) must fail closed: Err, and NEVER Ok(true).
    #[test]
    fn preflight_ipns_absent_fails_closed_on_transient_error() {
        let out = classify_preflight_outcome(
            Err(cipherbox_api_client::ApiError::ApiResponse {
                status: 503,
                message: "upstream unavailable".to_string(),
            }),
            "k51-name",
        );
        assert!(out.is_err(), "a non-404 resolve must abort, not proceed");
        assert_ne!(
            out,
            Ok(true),
            "a transient error must NEVER be coerced to confirmed-absent (fail closed)"
        );
    }

    // An auth error is likewise transient/unknown -> abort, never absent.
    #[test]
    fn preflight_ipns_absent_fails_closed_on_auth_error() {
        let out = classify_preflight_outcome(
            Err(cipherbox_api_client::ApiError::AuthFailed("token expired".to_string())),
            "k51-name",
        );
        assert!(out.is_err(), "an auth error must abort the preflight");
        assert_ne!(out, Ok(true));
    }
}

#[cfg(test)]
mod vault_init_route_tests {
    use super::*;

    // Both names absent (fresh user) -> mint+publish+register (FreshInit).
    #[test]
    fn vault_init_route_both_absent_is_fresh_init() {
        let route = route_vault_init(Ok(true), Ok(true));
        assert_eq!(route, Ok(VaultInitRoute::FreshInit));
    }

    // Key blob present, root absent (publish failed after clean preflight) ->
    // decrypt-and-resume recovery.
    #[test]
    fn vault_init_route_key_blob_present_root_absent_is_recover_resume() {
        let route = route_vault_init(Ok(false), Ok(true));
        assert_eq!(route, Ok(VaultInitRoute::RecoverResume));
    }

    // Both present -> not an init; abort and route through the load path.
    #[test]
    fn vault_init_route_both_present_aborts() {
        let route = route_vault_init(Ok(false), Ok(false));
        assert!(route.is_err(), "a fully-published vault is not an init");
        assert!(route.unwrap_err().contains("already fully initialized"));
    }

    // Root present but key blob absent -> unrecoverable/unexpected; abort.
    #[test]
    fn vault_init_route_root_present_key_blob_absent_aborts() {
        let route = route_vault_init(Ok(true), Ok(false));
        assert!(route.is_err(), "root-present/key-blob-absent is unrecoverable");
        assert!(route.unwrap_err().contains("unrecoverable"));
    }

    // Transient error on the key-blob preflight -> abort BEFORE routing (no publish).
    #[test]
    fn vault_init_route_transient_key_blob_error_aborts_before_publish() {
        let route = route_vault_init(
            Err("preflight resolve failed for vault-key: 503".to_string()),
            Ok(true),
        );
        assert!(
            route.is_err(),
            "a transient preflight error must abort before any route/publish"
        );
    }

    // Transient error on the root preflight -> abort BEFORE routing (no publish).
    #[test]
    fn vault_init_route_transient_root_error_aborts_before_publish() {
        let route = route_vault_init(
            Ok(true),
            Err("preflight resolve failed for root: timeout".to_string()),
        );
        assert!(
            route.is_err(),
            "a transient preflight error must abort before any route/publish"
        );
    }
}

#[cfg(test)]
mod vault_init_recovery_tests {
    use super::*;
    use base64::Engine as _;

    /// A present-record resolve response (only Ok-vs-Err matters for preflight).
    fn present_response() -> cipherbox_api_client::IpnsResolveResponse {
        cipherbox_api_client::IpnsResolveResponse {
            success: true,
            cid: "bafyfakecidrecoverytest".to_string(),
            sequence_number: "1".to_string(),
            signature_v2: None,
            data: None,
            pub_key: None,
        }
    }

    // End-to-end fail-closed chain: a transient (non-404) resolve outcome on the
    // key-blob name flows classify -> route -> Err, aborting BEFORE any publish is
    // reached (route returns before the publish branch in initialize_vault).
    #[test]
    fn vault_init_transient_resolve_aborts_before_publish() {
        let key_blob = classify_preflight_outcome(
            Err(cipherbox_api_client::ApiError::ApiResponse {
                status: 500,
                message: "backend on fire".to_string(),
            }),
            "vault-key-name",
        );
        let root = classify_preflight_outcome(Ok(present_response()), "root-name");

        let route = route_vault_init(key_blob, root);
        assert!(
            route.is_err(),
            "a transient resolve must abort before any publishable route is chosen"
        );
        assert_ne!(route, Ok(VaultInitRoute::FreshInit));
        assert_ne!(route, Ok(VaultInitRoute::RecoverResume));
    }

    // Unrecoverable state (root present, key blob absent) surfaced through the full
    // classify -> route chain -> Err.
    #[test]
    fn vault_init_unrecoverable_state_aborts() {
        let key_blob = classify_preflight_outcome(
            Err(cipherbox_api_client::ApiError::IpnsNotFound("vault-key".to_string())),
            "vault-key",
        );
        let root = classify_preflight_outcome(Ok(present_response()), "root");
        let route = route_vault_init(key_blob, root);
        assert!(route.is_err(), "root-present/key-blob-absent must abort");
        assert!(route.unwrap_err().contains("unrecoverable"));
    }

    // Decrypt-and-resume recovery round-trip (pure, no live IO): mirror the
    // FIRST attempt's mint+wrap+serialize, then the RecoverResume branch's
    // deserialize+unwrap (recover_root_keys_from_key_blob), asserting the recovered
    // root keys equal the first attempt's minted keys BYTE-FOR-BYTE (proving no
    // re-mint). Then mirror publish_root_folder + coherency_check_root_unseal under
    // the recovered keys and assert the coherency unseal succeeds.
    #[test]
    fn vault_init_recovery_recovers_original_keys_and_coherency_unseals() {
        // Fixed secp256k1 keypair: private key = 1, public key = generator point G.
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

        // FIRST ATTEMPT twin (FreshInit): two INDEPENDENT minted root keys wrapped
        // into the v3 blob (as publish_vault_key_blob would persist).
        let minted_read = [0xA1u8; 32];
        let minted_write = [0xB2u8; 32];
        assert_ne!(minted_read, minted_write);
        let enc_read = cipherbox_crypto::ecies::wrap_key(&minted_read, &public_key)
            .expect("wrap minted root read key");
        let enc_write = cipherbox_crypto::ecies::wrap_key(&minted_write, &public_key)
            .expect("wrap minted root write key");
        let blob = cipherbox_core::vault_blob::serialize_vault_blob_v3(&enc_read, &enc_write)
            .expect("serialize v3 blob");

        // RECOVERY twin (recover_root_keys_from_key_blob): deserialize + unwrap.
        let (denc_read, denc_write) =
            cipherbox_core::vault_blob::deserialize_vault_blob_v3(&blob)
                .expect("deserialize v3 blob");
        let rec_read = cipherbox_crypto::ecies::unwrap_key(&denc_read, &private_key)
            .expect("recover root read key");
        let rec_write = cipherbox_crypto::ecies::unwrap_key(&denc_write, &private_key)
            .expect("recover root write key");

        // Recovered keys equal the first attempt's MINTED keys byte-for-byte — the
        // core no-re-mint guarantee.
        assert_eq!(
            rec_read.as_slice(),
            &minted_read,
            "recovered root_read_key must equal the originally minted key"
        );
        assert_eq!(
            rec_write.as_slice(),
            &minted_write,
            "recovered root_write_key must equal the originally minted key"
        );

        // publish_root_folder twin: seal an empty root under the RECOVERED keys.
        let rec_read_arr: [u8; 32] = rec_read.as_slice().try_into().expect("32-byte read key");
        let rec_write_arr: [u8; 32] = rec_write.as_slice().try_into().expect("32-byte write key");
        let root_ipns_seed = [0x33u8; 32];
        let node_bytes =
            build_empty_root_published_node(&rec_read_arr, &rec_write_arr, &root_ipns_seed)
                .expect("build empty root under recovered keys");

        // coherency_check_root_unseal twin: decode + unseal read body under the
        // recovered read key must succeed (the coherency gate).
        let published =
            cipherbox_core::node::decode_published_node(&node_bytes).expect("decode published root");
        let read_sealed = base64::engine::general_purpose::STANDARD
            .decode(&published.read_sealed)
            .expect("valid base64 read_sealed");
        let read_body = cipherbox_core::node::seal::unseal_node(
            &read_sealed,
            &rec_read_arr,
            &published.id,
            cipherbox_core::node::NodeKind::Root,
            published.generation,
        )
        .expect("coherency unseal under recovered root_read_key must succeed");
        match cipherbox_core::node::decode_node(&read_body).expect("decode read-body node") {
            cipherbox_core::node::Node::Root { children, .. } => {
                assert!(children.is_empty(), "recovered root has no children");
            }
            other => panic!("expected Node::Root, got {:?}", other),
        }
    }
}
