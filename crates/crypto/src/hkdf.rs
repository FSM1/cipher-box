//! HKDF-SHA256 deterministic IPNS keypair derivation.
//!
//! Derives deterministic Ed25519 IPNS keypairs from a secp256k1 private key
//! using HKDF-SHA256 with domain-separated info strings. Matches the TypeScript
//! implementations in `@cipherbox/crypto` (vault/derive-ipns.ts, file/derive-ipns.ts,
//! registry/derive-ipns.ts).
//!
//! Derivation path:
//!   secp256k1 privateKey (32 bytes)
//!     -> HKDF-SHA256(salt="CipherBox-v1", info=<domain-specific>)
//!     -> 32-byte Ed25519 seed
//!     -> Ed25519 keypair
//!     -> IPNS name (k51...)

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;
use crate::ipns_name;

/// Common HKDF salt for all CipherBox derivations.
const HKDF_SALT: &[u8] = b"CipherBox-v1";

/// HKDF info for vault IPNS keypair derivation (root folder metadata).
const VAULT_HKDF_INFO: &[u8] = b"cipherbox-vault-ipns-v1";

/// HKDF info for vault key blob IPNS keypair derivation (rootFolderKey storage).
const VAULT_KEY_HKDF_INFO: &[u8] = b"cipherbox-vault-key-ipns-v1";

/// HKDF info for device registry IPNS keypair derivation.
const REGISTRY_HKDF_INFO: &[u8] = b"cipherbox-device-registry-ipns-v1";

/// HKDF info for recycle bin IPNS keypair derivation.
const BIN_HKDF_INFO: &[u8] = b"cipherbox-recycle-bin-ipns-v1";

/// HKDF info prefix for per-file IPNS keypair derivation.
const FILE_HKDF_INFO_PREFIX: &str = "cipherbox-file-ipns-v1:";

/// Minimum file ID length (matches TypeScript validation).
const MIN_FILE_ID_LENGTH: usize = 10;

/// Internal helper: derive an Ed25519 keypair and IPNS name from HKDF output.
///
/// All three public functions follow the same pattern and delegate here.
fn derive_ipns_keypair(
    user_private_key: &[u8; 32],
    info: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, String), CryptoError> {
    // 1. HKDF-SHA256: extract + expand
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), user_private_key);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::HkdfDerivationFailed)?;

    // 2. Ed25519 keypair from 32-byte seed
    let signing_key = SigningKey::from_bytes(&okm);
    okm.zeroize();
    let verifying_key = signing_key.verifying_key();

    let private_key = Zeroizing::new(signing_key.to_bytes().to_vec());
    let public_key = verifying_key.to_bytes().to_vec();

    // 3. Derive IPNS name from public key
    let pk_array: [u8; 32] = verifying_key.to_bytes();
    let ipns_name = ipns_name::derive_ipns_name(&pk_array)
        .map_err(|_| CryptoError::IpnsNameDerivationFailed)?;

    Ok((private_key, public_key, ipns_name))
}

/// Derive the deterministic Ed25519 IPNS keypair for the user's vault.
///
/// Uses HKDF info "cipherbox-vault-ipns-v1" for domain separation.
///
/// Given the same secp256k1 privateKey, this always produces the same
/// IPNS name, enabling vault discovery from any device with the user's key.
///
/// Returns (ed25519_private_key, ed25519_public_key, ipns_name).
pub fn derive_vault_ipns_keypair(
    user_private_key: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, String), CryptoError> {
    derive_ipns_keypair(user_private_key, VAULT_HKDF_INFO)
}

/// Derive a dedicated Ed25519 IPNS keypair for the vault key blob.
///
/// This IPNS name stores the v2 blob containing the ECIES-wrapped rootFolderKey.
/// Separate from the root folder IPNS name to avoid folder publishes overwriting the key blob.
///
/// Uses HKDF info "cipherbox-vault-key-ipns-v1" for domain separation.
pub fn derive_vault_key_ipns_keypair(
    user_private_key: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, String), CryptoError> {
    derive_ipns_keypair(user_private_key, VAULT_KEY_HKDF_INFO)
}

/// Derive a deterministic Ed25519 IPNS keypair for a specific file.
///
/// Uses HKDF info "cipherbox-file-ipns-v1:{fileId}" for per-file domain separation.
///
/// Returns (ed25519_private_key, ed25519_public_key, ipns_name).
pub fn derive_file_ipns_keypair(
    user_private_key: &[u8; 32],
    file_id: &str,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, String), CryptoError> {
    if file_id.len() < MIN_FILE_ID_LENGTH {
        return Err(CryptoError::InvalidFileId);
    }

    let info = format!("{}{}", FILE_HKDF_INFO_PREFIX, file_id);
    derive_ipns_keypair(user_private_key, info.as_bytes())
}

/// Derive the deterministic Ed25519 IPNS keypair for the device registry.
///
/// Uses HKDF info "cipherbox-device-registry-ipns-v1" for domain separation.
///
/// Returns (ed25519_private_key, ed25519_public_key, ipns_name).
pub fn derive_registry_ipns_keypair(
    user_private_key: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, String), CryptoError> {
    derive_ipns_keypair(user_private_key, REGISTRY_HKDF_INFO)
}

/// Derive the deterministic Ed25519 IPNS keypair for the recycle bin.
///
/// Uses HKDF info "cipherbox-recycle-bin-ipns-v1" for domain separation.
///
/// Returns (ed25519_private_key, ed25519_public_key, ipns_name).
pub fn derive_bin_ipns_keypair(
    user_private_key: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, String), CryptoError> {
    derive_ipns_keypair(user_private_key, BIN_HKDF_INFO)
}
