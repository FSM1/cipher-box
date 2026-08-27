//! The Web3Auth Core Kit store, sealed at rest under a keyring-held wrapping
//! key.
//!
//! What the SDK keeps here is a secp256k1 scalar that both addresses and
//! decrypts the Web3Auth record holding the login secret, so it may not sit in
//! the clear. The keyring holds a 256-bit wrapping key; only sealed bytes reach
//! the filesystem, which is this crate's ciphertext-only-at-rest law.
//!
//! The web host seals the same store under a non-extractable WebCrypto key
//! (`apps/web/src/auth/sealedStore.ts`); this is the desktop leg of that
//! custody, and what lets a recovered factor survive a restart.
//!
//! The store is per device rather than per account: it is read before a login
//! secret exists, so no account directory can name it yet — so a forget on one
//! account drops what every account on this device held.
//!
//! What the custody buys is narrow, and worth stating so nothing is relaxed on
//! the strength of it. It defeats a reader of the disk alone — a stolen drive,
//! a partial backup, a grep over an image. It does not defeat local code: only
//! the Apple Keychain binds an entry to the reading app, so on the Secret
//! Service and the Windows Credential Manager any process of the same user can
//! read the wrapping key. Nor does the envelope bind freshness: an earlier
//! sealed slot restored onto the disk opens as current.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cipherbox_core::suite::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use cipherbox_engine::entropy::{fresh_nonce, fresh_seed};
use cipherbox_engine::seams::{SeamError, SeamResult};
use cipherbox_engine::{Entropy, EntropyError};
use zeroize::Zeroizing;

use crate::credential_store::CoreKitWrappingKey;
use crate::fs_util::{
    atomic_write, empty_dir, ensure_dir, keep_first, list_file_names, read_file_opt,
    remove_file_durable, seam_err, to_hex,
};

/// The envelope version, bound into the AAD. A blob a later build cannot open
/// is dropped and re-minted, never migrated.
const ENVELOPE_V: u64 = 1;

/// The largest value this store seals. The login SDK's own record is a few
/// kilobytes; the webview reaches this store over IPC, so the bound is what
/// keeps a slot directory from being a place to put arbitrary bytes.
const MAX_SLOT_BYTES: usize = 64 * 1024;

/// The longest storage key a slot is named for. The name is the key in hex, so
/// every platform's filename limit sits well above twice this.
const MAX_SLOT_KEY_BYTES: usize = 96;

/// The most slots this store holds. The login SDK keeps one; the bound is what
/// stops the webview from growing the directory a name at a time.
const MAX_SLOTS: usize = 8;

/// The Core Kit store's slots, sealed under a wrapping key `C` holds.
pub struct SealedCoreKitStore<C> {
    dir: PathBuf,
    keys: C,
    entropy: Mutex<Box<dyn Entropy + Send>>,
    /// The wrapping key once this process has loaded it, so a burst of SDK
    /// reads costs one keyring call rather than one each.
    wrapping: tokio::sync::Mutex<Option<Zeroizing<[u8; KEY_LEN]>>>,
}

impl<C: CoreKitWrappingKey> SealedCoreKitStore<C> {
    /// Opens (creating if absent) the store's slot directory.
    pub fn open(
        dir: impl AsRef<Path>,
        keys: C,
        entropy: Box<dyn Entropy + Send>,
    ) -> SeamResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        ensure_dir(&dir).map_err(|err| seam_err("core_kit_store open", &err))?;
        Ok(Self {
            dir,
            keys,
            entropy: Mutex::new(entropy),
            wrapping: tokio::sync::Mutex::new(None),
        })
    }

    /// One slot's value, or `None` when this device holds nothing openable for
    /// it.
    ///
    /// A slot the wrapping key does not authenticate is dropped rather than
    /// surfaced: it costs one sign-in, where a refusal would wedge the shell.
    pub async fn get_item(&self, key: &str) -> SeamResult<Option<String>> {
        let path = self.slot(key)?;
        let Some(sealed) =
            read_file_opt(&path).map_err(|err| seam_err("core_kit_store get", &err))?
        else {
            return Ok(None);
        };
        // Resolved before the open, so a keyring that merely refused to answer
        // fails the read rather than discarding a session it could still open.
        let Some(wrapping) = self.wrapping_key(Mint::Never).await? else {
            // The slot stays: a device that holds no key today opens it once the
            // keyring entry is back.
            return Ok(None);
        };
        let opened = match open_envelope(&wrapping, &aad(key), &sealed) {
            Some(opened) => Some(opened),
            None => {
                // Another instance can have re-keyed the store since this one
                // resolved its key, so a memo is not evidence the slot is
                // unopenable.
                *self.wrapping.lock().await = None;
                match self.wrapping_key(Mint::Never).await? {
                    Some(fresh) => open_envelope(&fresh, &aad(key), &sealed),
                    None => return Ok(None),
                }
            }
        };
        let Some(opened) = opened else {
            remove_file_durable(&path).map_err(|err| seam_err("core_kit_store drop", &err))?;
            return Ok(None);
        };
        core::str::from_utf8(&opened)
            .map(|text| Some(text.to_owned()))
            .map_err(|_| SeamError::new("core_kit_store: the sealed value is not text"))
    }

    /// Seals `value` into one slot, replacing whatever it held. Refused for a
    /// value past [`MAX_SLOT_BYTES`] — the caller is a webview.
    pub async fn set_item(&self, key: &str, value: &str) -> SeamResult<()> {
        let path = self.slot(key)?;
        if value.len() > MAX_SLOT_BYTES {
            return Err(SeamError::new("core_kit_store: the value is too large"));
        }
        self.room_for(&path)?;
        // The lock spans the mint and the write, so a purge cannot sweep the
        // directory between them and leave the slot that mint was for standing.
        let mut held = self.wrapping.lock().await;
        let wrapping = self
            .resolve(&mut held, Mint::WhenAbsent)
            .await?
            .ok_or_else(|| SeamError::new("core_kit_store: no wrapping key was minted"))?;
        let nonce = self.draw(fresh_nonce)?;
        let mut envelope = Vec::with_capacity(NONCE_LEN + value.len() + TAG_LEN);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&aead::encrypt(
            &wrapping,
            &nonce,
            &aad(key),
            value.as_bytes(),
        ));
        atomic_write(&path, &envelope).map_err(|err| seam_err("core_kit_store set", &err))
    }

    /// Drops every slot and the key that opens them — the forget-this-device
    /// leg. The slots go first: once they are gone the key opens nothing, so a
    /// keyring that refuses still leaves this device with no session to take.
    pub async fn purge(&self) -> SeamResult<()> {
        // The lock spans both legs: it is the gate every mint passes, so a write
        // cannot slip between them and re-key a store that reported itself
        // purged.
        let mut held = self.wrapping.lock().await;
        let emptied = empty_dir(&self.dir).map_err(|err| seam_err("core_kit_store purge", &err));
        *held = None;
        keep_first(emptied, self.keys.clear_core_kit_wrapping_key().await)
    }

    /// The wrapping key this device holds, minting and persisting one per
    /// `mint`.
    async fn wrapping_key(&self, mint: Mint) -> SeamResult<Option<Zeroizing<[u8; KEY_LEN]>>> {
        let mut held = self.wrapping.lock().await;
        self.resolve(&mut held, mint).await
    }

    /// The same, against a lock the caller already holds — which is what lets a
    /// write span the mint and the slot it seals.
    async fn resolve(
        &self,
        held: &mut Option<Zeroizing<[u8; KEY_LEN]>>,
        mint: Mint,
    ) -> SeamResult<Option<Zeroizing<[u8; KEY_LEN]>>> {
        if held.is_none()
            && let Some(stored) = self.keys.load_core_kit_wrapping_key().await?
        {
            // A held entry of the wrong length is custody this build does not
            // understand; minting over it would destroy what it opens.
            *held = Some(fixed(&stored).ok_or_else(|| {
                SeamError::new("core_kit_store: the held wrapping key is the wrong length")
            })?);
        }
        if held.is_none() && mint == Mint::WhenAbsent {
            let minted = self.draw(fresh_seed)?;
            self.keys
                .store_core_kit_wrapping_key(minted.as_slice())
                .await?;
            *held = Some(minted);
        }
        Ok(held.clone())
    }

    /// Refuses a slot this store has no room for. An existing name always has
    /// room: a replacement adds nothing.
    fn room_for(&self, path: &Path) -> SeamResult<()> {
        if path.exists() {
            return Ok(());
        }
        let held = list_file_names(&self.dir)
            .map_err(|err| seam_err("core_kit_store count", &err))?
            .len();
        if held >= MAX_SLOTS {
            return Err(SeamError::new("core_kit_store: the store is full"));
        }
        Ok(())
    }

    /// Where one storage key's sealed bytes live. Hex, so the name is always a
    /// single path component whatever the key holds.
    fn slot(&self, key: &str) -> SeamResult<PathBuf> {
        // An empty name would compose the store directory itself, which is not
        // a file this store may read or replace.
        if key.is_empty() || key.len() > MAX_SLOT_KEY_BYTES {
            return Err(SeamError::new("core_kit_store: the slot name is not one"));
        }
        Ok(self.dir.join(to_hex(key.as_bytes())))
    }

    /// One fail-closed draw off the injected source. `fresh` is the engine's
    /// helper for the value being drawn, which refuses a seam that reports
    /// success having written nothing.
    fn draw<T>(
        &self,
        fresh: impl FnOnce(&mut Box<dyn Entropy + Send>) -> Result<T, EntropyError>,
    ) -> SeamResult<T> {
        let mut source = self
            .entropy
            .lock()
            .map_err(|_| SeamError::new("core_kit_store: the entropy source is unusable"))?;
        fresh(&mut source).map_err(|err| SeamError::new(format!("core_kit_store: {err}")))
    }
}

/// Whether a read of the wrapping key may create one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mint {
    /// A read: a device with no key holds nothing this key could open.
    Never,
    /// A write: the first one on this device is what mints the key.
    WhenAbsent,
}

/// What a slot's ciphertext is authenticated against. The storage key is bound
/// so one slot's bytes cannot be transplanted into another, and the version so
/// an envelope never opens under a later build's semantics.
fn aad(key: &str) -> Vec<u8> {
    format!("cipherbox/v2/core-kit-store/v{ENVELOPE_V}/{key}").into_bytes()
}

/// The stored bytes as a wrapping key, or `None` for an entry of the wrong
/// length.
fn fixed(bytes: &[u8]) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    bytes.try_into().ok().map(Zeroizing::new)
}

/// `None` for anything `wrapping` does not authenticate under `aad`.
fn open_envelope(
    wrapping: &[u8; KEY_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().ok()?;
    aead::decrypt(wrapping, nonce, aad, ciphertext).map(Zeroizing::new)
}
