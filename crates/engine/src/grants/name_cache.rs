//! The owner device's grantee name cache, the part of the contact book that
//! pre-fills a name
//! ([ADR 0027](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0027-a-grantee-name-is-not-an-identity.md)
//! D4).
//!
//! It holds the last grantee name this device saw for each identity, so that
//! when the owner names the same person on another folder the host can offer
//! it. It is never synced and it is no authority: the owner-signed ledger row
//! is the only grantee name any owner act reads.
//!
//! Sealed HPKE-to-self under its own owner-local kind, at a staging key inside
//! the book's prefix.

use core::cell::RefCell;

use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::seal::{
    GranteeName, NameSource, OwnerLocalKind, open_owner_local, seal_owner_local,
};
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::entropy::{Entropy, fresh_ephemeral};
use crate::seams::StagingStore;
use crate::sync::owner_scoped_key;

use super::accept::{TooLong, reject_unknown, req, within};
use super::contact_store::{BookCodecError, ContactStoreError, MAX_CONTACTS};

/// The staging-key prefix the cache is stored under. It sits inside the
/// contact book's prefix, so the orphan sweep treats it as the book's.
pub const GRANTEE_NAMES_PREFIX: &[u8] = b"cbx/cb/n/";

/// The bound on cached names. The oldest name leaves first.
pub const MAX_CACHED_NAMES: usize = MAX_CONTACTS;

/// The stored-body grammar version this build writes and can read.
const NAME_CACHE_V: u64 = 1;

/// The last grantee name this device saw for each identity (ADR 0027 D4).
pub trait GranteeNameCache {
    /// Record `name` as the last name seen for `identity_pk`.
    async fn remember(
        &self,
        identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
        name: &str,
    ) -> Result<(), ContactStoreError>;

    /// Every cached name, oldest first.
    async fn names(&self) -> Result<Vec<([u8; IDENTITY_PUBLIC_LEN], String)>, ContactStoreError>;
}

/// The name cache over a host's [`StagingStore`], under one staging key.
pub struct StagingGranteeNameCache<'a, St, E> {
    staging: &'a St,
    enc_secret: &'a X25519Secret,
    entropy: &'a RefCell<E>,
    staging_key: Vec<u8>,
}

impl<'a, St: StagingStore, E: Entropy> StagingGranteeNameCache<'a, St, E> {
    /// Wraps a staging store as the name cache for one session.
    pub fn new(staging: &'a St, enc_secret: &'a X25519Secret, entropy: &'a RefCell<E>) -> Self {
        Self {
            staging,
            enc_secret,
            entropy,
            staging_key: owner_scoped_key(GRANTEE_NAMES_PREFIX, enc_secret),
        }
    }

    /// The staging key this identity's cache occupies.
    pub fn staging_key(&self) -> &[u8] {
        &self.staging_key
    }

    async fn load(&self) -> Result<Vec<([u8; IDENTITY_PUBLIC_LEN], String)>, ContactStoreError> {
        let Some(blob) = self.staging.staged_bytes(&self.staging_key).await? else {
            return Ok(Vec::new());
        };
        let body = open_owner_local(self.enc_secret, OwnerLocalKind::GranteeNames, &blob)
            .map_err(|e| ContactStoreError::Unreadable(BookCodecError::DidNotOpen(e)))?;
        decode_names(&body).map_err(ContactStoreError::Unreadable)
    }
}

impl<St: StagingStore, E: Entropy> GranteeNameCache for StagingGranteeNameCache<'_, St, E> {
    async fn remember(
        &self,
        identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
        name: &str,
    ) -> Result<(), ContactStoreError> {
        let mut names = self.load().await?;
        names.retain(|(held, _)| held != identity_pk);
        names.push((*identity_pk, name.to_owned()));
        let over = names.len().saturating_sub(MAX_CACHED_NAMES);
        names.drain(..over);
        let body = encode_names(&names).map_err(ContactStoreError::Encode)?;
        let ephemeral =
            fresh_ephemeral(&mut *self.entropy.borrow_mut()).map_err(ContactStoreError::Entropy)?;
        let blob = seal_owner_local(
            self.enc_secret,
            OwnerLocalKind::GranteeNames,
            &ephemeral,
            &body,
        )
        .map_err(ContactStoreError::Seal)?;
        self.staging
            .put_staged_bytes(&self.staging_key, &blob)
            .await?;
        Ok(())
    }

    async fn names(&self) -> Result<Vec<([u8; IDENTITY_PUBLIC_LEN], String)>, ContactStoreError> {
        self.load().await
    }
}

/// A cached name, checked as a grantee name is: the cache never holds a name
/// the owner could not sign into a row.
fn checked(name: &str) -> Result<(), BookCodecError> {
    GranteeName::new(name.to_owned(), NameSource::Owner)
        .map(|_| ())
        .map_err(BookCodecError::Codec)
}

/// Encode the cache, oldest first. Refuses what [`decode_names`] refuses,
/// release-active (AGENTS.md rule 8).
fn encode_names(names: &[([u8; IDENTITY_PUBLIC_LEN], String)]) -> Result<Vec<u8>, BookCodecError> {
    within("names", names.len(), MAX_CACHED_NAMES)?;
    let mut items = Vec::with_capacity(names.len());
    for (at, (identity_pk, name)) in names.iter().enumerate() {
        checked(name)?;
        if names[..at].iter().any(|(held, _)| held == identity_pk) {
            return Err(BookCodecError::DuplicateIdentity);
        }
        let mut entry = Map::new();
        entry.insert("id", Value::Bytes(identity_pk.to_vec()));
        entry.insert("name", Value::Text(name.clone()));
        items.push(Value::Map(entry));
    }
    let mut body = Map::new();
    body.insert("names", Value::Array(items));
    body.insert("v", Value::Unsigned(NAME_CACHE_V));
    Ok(encode_fixed_depth(&Value::Map(body)))
}

/// Decode a stored cache (strict det-CBOR). A missing or unknown field, an
/// unreadable version, a bound breach, a malformed name or one identity twice
/// is an error, never a partial cache.
fn decode_names(bytes: &[u8]) -> Result<Vec<([u8; IDENTITY_PUBLIC_LEN], String)>, BookCodecError> {
    let tree = decode(bytes)?;
    let map = tree.as_map()?;
    reject_unknown(map, &["names", "v"])?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != NAME_CACHE_V {
        return Err(BookCodecError::UnsupportedVersion { version });
    }
    let items = req(map, "names")?.as_array()?;
    within("names", items.len(), MAX_CACHED_NAMES)?;
    let mut names: Vec<([u8; IDENTITY_PUBLIC_LEN], String)> = Vec::with_capacity(items.len());
    for item in items {
        let entry = item.as_map()?;
        reject_unknown(entry, &["id", "name"])?;
        let raw = req(entry, "id")?.as_bytes()?;
        let identity_pk = <[u8; IDENTITY_PUBLIC_LEN]>::try_from(raw).map_err(|_| {
            BookCodecError::from(TooLong {
                field: "id",
                len: raw.len(),
                limit: IDENTITY_PUBLIC_LEN,
            })
        })?;
        let name = req(entry, "name")?.as_text()?.to_owned();
        checked(&name)?;
        if names.iter().any(|(held, _)| *held == identity_pk) {
            return Err(BookCodecError::DuplicateIdentity);
        }
        names.push((identity_pk, name));
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::contact_store::CONTACTS_PREFIX;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on};

    fn cache<'a>(
        staging: &'a InMemoryStagingStore,
        secret: &'a X25519Secret,
        entropy: &'a RefCell<SeededEntropy>,
    ) -> StagingGranteeNameCache<'a, InMemoryStagingStore, SeededEntropy> {
        StagingGranteeNameCache::new(staging, secret, entropy)
    }

    #[test]
    fn a_remembered_name_reads_back_and_the_last_one_wins() {
        let staging = InMemoryStagingStore::default();
        let secret = X25519Secret::from_scalar([0x21; 32]);
        let entropy = RefCell::new(SeededEntropy::new(3));
        let store = cache(&staging, &secret, &entropy);
        block_on(store.remember(&[2; 33], "Alice")).expect("remember");
        block_on(store.remember(&[3; 33], "Bob")).expect("remember");
        block_on(store.remember(&[2; 33], "Alice B")).expect("remember");

        assert_eq!(
            block_on(cache(&staging, &secret, &entropy).names()).expect("names"),
            vec![([3; 33], "Bob".to_owned()), ([2; 33], "Alice B".to_owned())],
        );
    }

    #[test]
    fn the_oldest_name_leaves_first_at_the_bound() {
        let staging = InMemoryStagingStore::default();
        let secret = X25519Secret::from_scalar([0x22; 32]);
        let entropy = RefCell::new(SeededEntropy::new(4));
        let store = cache(&staging, &secret, &entropy);
        for at in 0..=MAX_CACHED_NAMES {
            let mut id = [0u8; 33];
            id[..8].copy_from_slice(&(at as u64).to_be_bytes());
            block_on(store.remember(&id, "n")).expect("remember");
        }
        let names = block_on(store.names()).expect("names");
        assert_eq!(names.len(), MAX_CACHED_NAMES);
        assert_eq!(names[0].0[..8], 1u64.to_be_bytes());
    }

    #[test]
    fn a_name_no_row_could_carry_is_refused_and_writes_nothing() {
        let staging = InMemoryStagingStore::default();
        let secret = X25519Secret::from_scalar([0x23; 32]);
        let entropy = RefCell::new(SeededEntropy::new(5));
        let store = cache(&staging, &secret, &entropy);
        for name in ["", "tab\there", &"a".repeat(256)] {
            assert!(matches!(
                block_on(store.remember(&[2; 33], name)),
                Err(ContactStoreError::Encode(_))
            ));
        }
        assert!(
            block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .is_none()
        );
    }

    #[test]
    fn the_cache_key_is_the_books_bookkeeping_and_not_the_book() {
        let staging = InMemoryStagingStore::default();
        let secret = X25519Secret::from_scalar([0x24; 32]);
        let entropy = RefCell::new(SeededEntropy::new(6));
        let key = cache(&staging, &secret, &entropy).staging_key().to_vec();
        assert!(key.starts_with(CONTACTS_PREFIX));
        assert_ne!(key, owner_scoped_key(CONTACTS_PREFIX, &secret));
    }

    #[test]
    fn a_book_body_under_the_cache_key_is_refused() {
        let staging = InMemoryStagingStore::default();
        let secret = X25519Secret::from_scalar([0x25; 32]);
        let entropy = RefCell::new(SeededEntropy::new(7));
        let store = cache(&staging, &secret, &entropy);
        let mut book = Map::new();
        book.insert("contacts", Value::Array(Vec::new()));
        book.insert("linkContacts", Value::Array(Vec::new()));
        book.insert("v", Value::Unsigned(1));
        let ephemeral = fresh_ephemeral(&mut SeededEntropy::new(8)).expect("ephemeral");
        let blob = seal_owner_local(
            &secret,
            OwnerLocalKind::ContactBook,
            &ephemeral,
            &encode_fixed_depth(&Value::Map(book)),
        )
        .expect("seal");
        block_on(staging.put_staged_bytes(store.staging_key(), &blob)).expect("put");

        assert!(matches!(
            block_on(store.names()),
            Err(ContactStoreError::Unreadable(BookCodecError::DidNotOpen(_)))
        ));
    }

    /// Release-active (AGENTS.md rule 8): the encoder refuses the duplicate
    /// the decoder refuses.
    #[test]
    fn the_encoder_refuses_one_identity_twice() {
        let names = [([2; 33], "Alice".to_owned()), ([2; 33], "Bob".to_owned())];
        assert!(matches!(
            encode_names(&names),
            Err(BookCodecError::DuplicateIdentity)
        ));
    }
}
