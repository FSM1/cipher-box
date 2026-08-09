//! The owner's durable contact book — what gives a grant command a verified
//! [`Contact`] to resolve a recipient from.
//!
//! A grant command names its recipient by identity key alone, but the grant
//! blob and the blinded tag both need that recipient's X25519 encryption
//! subkey. Pairing an identity key from one source with a subkey from another
//! is the key-substitution attack contact import exists to close, so the subkey
//! may only ever come from a passing binding verify.
//!
//! This store therefore persists the self-authenticating **contact code**, not
//! the imported pair: [`ContactStore::record`] is itself the fail-closed
//! import, and every load re-runs that same verify. Host bytes never produce a
//! [`Contact`], so a tampered backing can never re-point an identity key at a
//! subkey its holder did not sign.
//!
//! The book is sealed HPKE-to-self under the session's `enc-subkey` before it
//! reaches the host (`owner-local`, kind `contact-book`), so the contact graph
//! is ciphertext at rest and only the owner can author an entry.
//!
//! What that does *not* cover, because a contact code carries no counter and
//! the structure carries no generation: a host replaying an earlier sealed book
//! rolls an identity back to a subkey its holder signed **once** but has since
//! rotated away from, and dropping the stored key entirely reads as an empty
//! book, turning a later revoke into
//! [`ContactStoreError::RecipientNotImported`]. Both need a monotone counter
//! held where the host cannot roll it back.

use core::cell::RefCell;

use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::error::CodecError;
use cipherbox_core::seal::{OwnerLocalKind, open_owner_local, seal_owner_local};
use cipherbox_core::suite::contact::import_contact_code;
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::x25519::X25519Secret;
use core::fmt;

use crate::entropy::{Entropy, EntropyError, fresh_ephemeral};
use crate::seams::{SeamError, StagingStore};
use crate::sync::owner_scoped_key;

use super::accept::{TooLong, reject_unknown, req, within};
use super::contact::{Contact, MAX_CONTACT_CODE_BYTES};

/// The staging-key prefix the contact book is stored under, scoped per identity
/// by [`owner_scoped_key`]. `is_bookkeeping` treats the whole prefix as
/// referenced.
pub const CONTACTS_PREFIX: &[u8] = b"cbx/cb/";

/// The stored-body grammar version this build writes and can read.
const CONTACT_BOOK_V: u64 = 1;

/// The frozen bound on recorded contacts, enforced release-active in both codec
/// directions (AGENTS.md rule 8).
///
/// It bounds reader CPU as well as the staging budget
/// ([`MAX_RECEIVED_SHARES`](super::accept::MAX_RECEIVED_SHARES)'s rationale):
/// every load re-verifies one binding signature per stored code.
pub const MAX_CONTACTS: usize = 1024;

/// Why a contact-book operation failed.
#[derive(Debug)]
pub enum ContactStoreError {
    /// The offered contact code is malformed, or its subkey binding does not
    /// verify — a hard trust rejection, never a degraded import.
    Import(CodecError),
    /// The grant names an identity key no import ever verified. There is no
    /// directory to re-fetch a subkey from, so this is terminal rather than a
    /// prompt to source one elsewhere.
    RecipientNotImported,
    /// Stored bytes this build cannot read as a contact book. Never reported as
    /// an empty book: a recipient resolved against one would look un-imported
    /// while the owner's real book sits unread.
    Unreadable(BookCodecError),
    /// The book already holds [`MAX_CONTACTS`]. The stored bytes are fine — the
    /// set this import would make is the one past the bound — so a host can
    /// offer [`ContactStore::forget`] rather than report corruption.
    Full,
    /// Entropy acquisition failed, so no book is sealed and none is written.
    Entropy(EntropyError),
    /// Sealing the book for storage failed. A write-path failure, so never
    /// [`Unreadable`](Self::Unreadable) — nothing was read and nothing stored
    /// is in doubt.
    Seal(CodecError),
    /// The durable backing failed.
    Seam(SeamError),
}

impl fmt::Display for ContactStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContactStoreError::Import(e) => write!(f, "contact code rejected: {}", e.check()),
            ContactStoreError::RecipientNotImported => {
                f.write_str("no imported contact holds that identity key")
            }
            ContactStoreError::Unreadable(e) => write!(f, "the stored contact book {e}"),
            ContactStoreError::Full => {
                write!(f, "the contact book already holds {MAX_CONTACTS} contacts")
            }
            ContactStoreError::Entropy(e) => write!(f, "contact book: {e}"),
            ContactStoreError::Seal(e) => write!(f, "contact book seal failed: {}", e.check()),
            ContactStoreError::Seam(e) => write!(f, "contact book: {e}"),
        }
    }
}

impl std::error::Error for ContactStoreError {}

impl From<SeamError> for ContactStoreError {
    fn from(e: SeamError) -> Self {
        ContactStoreError::Seam(e)
    }
}

impl From<BookCodecError> for ContactStoreError {
    fn from(e: BookCodecError) -> Self {
        ContactStoreError::Unreadable(e)
    }
}

/// Why encoding or decoding a stored contact book failed.
///
/// Engine-owned rather than a bare [`CodecError`] so a check this format needs
/// does not extend core's frozen `Malformed` registry, whose names the KAT
/// manifest pins.
#[derive(Debug)]
pub enum BookCodecError {
    /// The det-CBOR framing was malformed.
    Codec(CodecError),
    /// The stored blob did not open under this session's `enc-subkey` as a
    /// `contact-book` blob — tampered, another identity's, another store's, or
    /// written at a format version this build refuses. Never an empty book: the
    /// contacts are there and this build cannot reach them.
    DidNotOpen(CodecError),
    /// A stored code no longer imports — a tampered or truncated book, never a
    /// contact to skip past.
    UnverifiableCode(CodecError),
    /// Two codes named one identity: no defined authority for that recipient's
    /// subkey, refused in both directions (AGENTS.md rule 8).
    DuplicateIdentity,
    /// A stored code that is not its own canonical re-encoding. This build only
    /// ever writes canonical codes, so anything else is bytes it did not author
    /// — refused rather than silently normalised.
    NonCanonicalCode,
    /// A book written at a grammar version this build does not read. Never
    /// treated as empty: the contacts are there, this build cannot read them.
    UnsupportedVersion {
        /// The version the stored body declared.
        version: u64,
    },
    /// A collection or field past its frozen bound.
    TooLong(TooLong),
}

impl fmt::Display for BookCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BookCodecError::Codec(e) => write!(f, "codec: {e}"),
            BookCodecError::DidNotOpen(e) => write!(f, "did not open: {}", e.check()),
            BookCodecError::UnverifiableCode(e) => {
                write!(f, "holds a code that no longer imports: {}", e.check())
            }
            BookCodecError::DuplicateIdentity => f.write_str("names one identity twice"),
            BookCodecError::NonCanonicalCode => {
                f.write_str("holds a code that is not its canonical encoding")
            }
            BookCodecError::UnsupportedVersion { version } => {
                write!(f, "is at version {version}, which is not readable")
            }
            BookCodecError::TooLong(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BookCodecError {}

impl From<TooLong> for BookCodecError {
    fn from(e: TooLong) -> Self {
        BookCodecError::TooLong(e)
    }
}

impl<E: Into<CodecError>> From<E> for BookCodecError {
    fn from(e: E) -> Self {
        BookCodecError::Codec(e.into())
    }
}

/// Durable persistence for the owner's imported contacts.
///
/// [`record`](Self::record) takes the code rather than a [`Contact`] on
/// purpose: the import *is* the write path, so no caller can persist a pair
/// whose binding was never checked.
pub trait ContactStore {
    /// Import a contact code and durably record it, returning the verified
    /// contact. A code already recorded for that identity key replaces it —
    /// both codes carry that identity's own signature, so a re-imported code is
    /// the contact rotating their own subkey.
    async fn record(&self, contact_code: &[u8]) -> Result<Contact, ContactStoreError>;

    /// Drop the entry for `identity_pk`. Idempotent: an identity the book does
    /// not hold succeeds. Without it a book at [`MAX_CONTACTS`] would refuse
    /// every further import with no way back.
    async fn forget(
        &self,
        identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
    ) -> Result<(), ContactStoreError>;

    /// Every recorded contact, each re-verified from its stored code.
    async fn contacts(&self) -> Result<Vec<Contact>, ContactStoreError>;
}

/// Resolve the recipient a grant names by identity key.
///
/// The lookup key is the compressed SEC1 identity key the grant ledger entry
/// and the mailbox address both use, so a revoke or downgrade resolves the
/// recipient its grant was minted for.
pub async fn resolve_recipient<S: ContactStore>(
    store: &S,
    identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
) -> Result<Contact, ContactStoreError> {
    store
        .contacts()
        .await?
        .into_iter()
        .find(|contact| contact.identity_pk().to_sec1() == *identity_pk)
        .ok_or(ContactStoreError::RecipientNotImported)
}

/// One recorded contact: the verified pair and the canonical self-authenticating
/// code the book stores it as. Only [`import_recorded`] builds one, so the pair
/// and the code can never disagree.
struct Recorded {
    contact: Contact,
    code: Vec<u8>,
}

/// Verify a contact code and return it alongside its canonical re-encoding.
fn import_recorded(bytes: &[u8]) -> Result<(Contact, Vec<u8>), CodecError> {
    let code = import_contact_code(bytes)?;
    Ok((Contact::from(&code), code.encode()))
}

/// The contact book the engine ships over a host's [`StagingStore`], under one
/// staging key.
///
/// The book is sealed HPKE-to-self under the session's `enc-subkey` before it
/// reaches the host, so no contact's identity key or encryption subkey sits in
/// host storage in the clear.
pub struct StagingContactStore<'a, St, E> {
    staging: &'a St,
    enc_secret: &'a X25519Secret,
    entropy: &'a RefCell<E>,
    staging_key: Vec<u8>,
}

impl<'a, St: StagingStore, E: Entropy> StagingContactStore<'a, St, E> {
    /// Wraps a staging store as the contact book for one session.
    pub fn new(staging: &'a St, enc_secret: &'a X25519Secret, entropy: &'a RefCell<E>) -> Self {
        Self {
            staging,
            enc_secret,
            entropy,
            staging_key: owner_scoped_key(CONTACTS_PREFIX, enc_secret),
        }
    }

    /// The staging key this identity's book occupies.
    pub fn staging_key(&self) -> &[u8] {
        &self.staging_key
    }

    async fn recorded(&self) -> Result<Vec<Recorded>, ContactStoreError> {
        let Some(blob) = self.staging.staged_bytes(self.staging_key()).await? else {
            return Ok(Vec::new());
        };
        // A stored book this session cannot open is state, never an empty book:
        // the next import would overwrite contacts it never saw.
        let body = open_owner_local(self.enc_secret, OwnerLocalKind::ContactBook, &blob)
            .map_err(BookCodecError::DidNotOpen)?;
        Ok(decode_book(&body)?)
    }

    /// Replace the whole book.
    async fn put(&self, book: &[Recorded]) -> Result<(), ContactStoreError> {
        let body = encode_book(book)?;
        let ephemeral =
            fresh_ephemeral(&mut *self.entropy.borrow_mut()).map_err(ContactStoreError::Entropy)?;
        let blob = seal_owner_local(
            self.enc_secret,
            OwnerLocalKind::ContactBook,
            &ephemeral,
            &body,
        )
        .map_err(ContactStoreError::Seal)?;
        self.staging
            .put_staged_bytes(self.staging_key(), &blob)
            .await?;
        Ok(())
    }
}

impl<St: StagingStore, E: Entropy> ContactStore for StagingContactStore<'_, St, E> {
    async fn record(&self, contact_code: &[u8]) -> Result<Contact, ContactStoreError> {
        // Import re-encodes canonically, so what lands is the ~130 frozen bytes
        // of the three keys — never the caller's spelling, which tolerates
        // unknown fields and would otherwise be an attacker-chosen byte channel
        // into the owner's durable store.
        let (contact, code) = import_recorded(contact_code).map_err(ContactStoreError::Import)?;
        let mut book = self.recorded().await?;
        book.retain(|held| held.contact.identity_pk() != contact.identity_pk());
        if book.len() >= MAX_CONTACTS {
            return Err(ContactStoreError::Full);
        }
        book.push(Recorded { contact, code });
        self.put(&book).await?;
        Ok(contact)
    }

    async fn forget(
        &self,
        identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
    ) -> Result<(), ContactStoreError> {
        let mut book = self.recorded().await?;
        let before = book.len();
        book.retain(|held| held.contact.identity_pk().to_sec1() != *identity_pk);
        if book.len() == before {
            return Ok(());
        }
        self.put(&book).await
    }

    async fn contacts(&self) -> Result<Vec<Contact>, ContactStoreError> {
        Ok(self
            .recorded()
            .await?
            .into_iter()
            .map(|held| held.contact)
            .collect())
    }
}

/// Encode the durable book to det-CBOR, codes in byte order so one book has one
/// spelling.
///
/// Rejects the bounds and the two-codes-for-one-identity shape [`decode_book`]
/// hard-rejects, release-active (AGENTS.md rule 8).
fn encode_book(book: &[Recorded]) -> Result<Vec<u8>, BookCodecError> {
    within("contacts", book.len(), MAX_CONTACTS)?;
    let mut sorted: Vec<&Recorded> = book.iter().collect();
    sorted.sort_by_key(|held| held.contact.identity_pk().to_sec1());
    if sorted
        .windows(2)
        .any(|pair| pair[0].contact.identity_pk() == pair[1].contact.identity_pk())
    {
        return Err(BookCodecError::DuplicateIdentity);
    }
    for held in &sorted {
        within("contactCode", held.code.len(), MAX_CONTACT_CODE_BYTES)?;
    }
    let mut body = Map::new();
    body.insert(
        "contacts",
        Value::Array(
            sorted
                .into_iter()
                .map(|held| Value::Bytes(held.code.clone()))
                .collect(),
        ),
    );
    body.insert("v", Value::Unsigned(CONTACT_BOOK_V));
    Ok(encode_fixed_depth(&Value::Map(body)))
}

/// Decode a stored book (strict det-CBOR), re-importing every code so the
/// binding verify runs again on bytes the host handed back.
///
/// A missing or mistyped field, an unknown key, an unreadable version, a bound
/// breach, a code that no longer imports, or two codes for one identity is an
/// error — never a partial book.
fn decode_book(bytes: &[u8]) -> Result<Vec<Recorded>, BookCodecError> {
    let tree = decode(bytes)?;
    let map = tree.as_map()?;
    reject_unknown(map, &["contacts", "v"])?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != CONTACT_BOOK_V {
        return Err(BookCodecError::UnsupportedVersion { version });
    }
    let raw = req(map, "contacts")?.as_array()?;
    within("contacts", raw.len(), MAX_CONTACTS)?;
    let mut book: Vec<Recorded> = Vec::with_capacity(raw.len());
    for item in raw {
        let code = item.as_bytes()?;
        within("contactCode", code.len(), MAX_CONTACT_CODE_BYTES)?;
        let (contact, canonical) =
            import_recorded(code).map_err(BookCodecError::UnverifiableCode)?;
        if canonical != code {
            return Err(BookCodecError::NonCanonicalCode);
        }
        if book
            .iter()
            .any(|held| held.contact.identity_pk() == contact.identity_pk())
        {
            return Err(BookCodecError::DuplicateIdentity);
        }
        book.push(Recorded {
            contact,
            code: canonical,
        });
    }
    Ok(book)
}

#[cfg(test)]
mod tests {
    use cipherbox_core::kdf;
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use super::super::contact::import_contact;
    use super::*;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on, conformance};

    fn enc(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    fn seeded(seed: u64) -> RefCell<SeededEntropy> {
        RefCell::new(SeededEntropy::new(seed))
    }

    /// Reports success while writing nothing, so the caller's ephemeral stays
    /// all-zero — a seam that would silently reuse one HPKE ephemeral forever.
    struct SilentEntropy;

    impl Entropy for SilentEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Ok(())
        }
    }

    struct FailingEntropy;

    impl Entropy for FailingEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::new("no entropy"))
        }
    }

    /// A book body sealed as this build seals one, so a test can put bytes the
    /// loader will actually open back under the store's key.
    fn sealed(secret: &X25519Secret, seed: u64, body: &[u8]) -> Vec<u8> {
        sealed_as(secret, OwnerLocalKind::ContactBook, seed, body)
    }

    fn sealed_as(secret: &X25519Secret, kind: OwnerLocalKind, seed: u64, body: &[u8]) -> Vec<u8> {
        let ephemeral = fresh_ephemeral(&mut SeededEntropy::new(seed)).expect("ephemeral");
        seal_owner_local(secret, kind, &ephemeral, body).expect("seal")
    }

    /// A contact code the peer signed itself, as one arrives out of band.
    fn code(scalar: u8) -> Vec<u8> {
        bound_code(scalar, scalar)
    }

    /// A code binding `scalar`'s identity to `subkey_scalar`'s encryption
    /// subkey, signed by that same identity — a legitimate rotation.
    fn bound_code(scalar: u8, subkey_scalar: u8) -> Vec<u8> {
        let identity = EcdsaSigner::from_scalar(&[scalar; 32]).expect("valid identity scalar");
        ContactCode::create(&identity, kdf::enc_subkey(&[subkey_scalar; 32]).public()).encode()
    }

    fn identity_of(scalar: u8) -> [u8; IDENTITY_PUBLIC_LEN] {
        EcdsaSigner::from_scalar(&[scalar; 32])
            .expect("valid identity scalar")
            .verifying_key()
            .to_sec1()
    }

    /// A code carrying a subkey the binding signature does not cover — the
    /// key-substitution shape import exists to refuse.
    fn substituted_code(scalar: u8, substitute: u8) -> Vec<u8> {
        let mut bytes = code(scalar);
        let honest = kdf::enc_subkey(&[scalar; 32]).public().to_bytes();
        let forged = kdf::enc_subkey(&[substitute; 32]).public().to_bytes();
        let at = bytes
            .windows(honest.len())
            .position(|w| w == honest)
            .expect("the encoded code carries the subkey it bound");
        bytes[at..at + forged.len()].copy_from_slice(&forged);
        bytes
    }

    /// A book holding exactly `codes`, framed as this build frames one — the
    /// bytes a hostile host could put back under the key.
    fn framed(codes: &[Vec<u8>]) -> Vec<u8> {
        let mut m = Map::new();
        m.insert(
            "contacts",
            Value::Array(codes.iter().cloned().map(Value::Bytes).collect()),
        );
        m.insert("v", Value::Unsigned(CONTACT_BOOK_V));
        encode_fixed_depth(&Value::Map(m))
    }

    #[test]
    fn the_staging_store_passes_the_contact_store_kit() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x11);
        let entropy = seeded(17);
        block_on(conformance::contact_store::check(async || {
            StagingContactStore::new(&staging, &secret, &entropy)
        }));
    }

    /// The gap this store closes: a grant names only the identity key, and the
    /// subkey it must seal to has to come back from the durable book.
    #[test]
    fn a_recorded_contact_resolves_by_identity_key_after_a_restart() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x21);
        let entropy = seeded(33);
        let imported =
            block_on(StagingContactStore::new(&staging, &secret, &entropy).record(&code(0x33)))
                .expect("import");

        let restarted = StagingContactStore::new(&staging, &secret, &entropy);
        let resolved =
            block_on(resolve_recipient(&restarted, &identity_of(0x33))).expect("resolves");
        assert_eq!(resolved.identity_pk(), imported.identity_pk());
        assert_eq!(
            resolved.enc_subkey(),
            imported.enc_subkey(),
            "the resolved subkey is the one the import verified"
        );
    }

    #[test]
    fn an_identity_key_no_import_verified_fails_closed() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x31);
        let entropy = seeded(49);
        block_on(StagingContactStore::new(&staging, &secret, &entropy).record(&code(0x33)))
            .expect("import");

        let store = StagingContactStore::new(&staging, &secret, &entropy);
        assert!(
            matches!(
                block_on(resolve_recipient(&store, &identity_of(0x44))),
                Err(ContactStoreError::RecipientNotImported)
            ),
            "an un-imported recipient is refused, never resolved from elsewhere"
        );
    }

    /// The store's only writer is the import, so a code whose binding does not
    /// verify persists nothing at all.
    #[test]
    fn a_code_whose_binding_fails_is_never_recorded() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x41);
        let entropy = seeded(65);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        assert!(matches!(
            block_on(store.record(&substituted_code(0x33, 0x44))),
            Err(ContactStoreError::Import(_))
        ));
        assert!(
            block_on(store.contacts()).expect("load").is_empty(),
            "a refused import leaves the book empty"
        );
        assert!(
            block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .is_none(),
            "a refused import writes nothing"
        );
    }

    /// Why the code is stored rather than the pair: the seal is not the only
    /// check, so even a body that opens is re-verified before it reaches a
    /// grant. Sealed under the store's own key so the tamper reaches the
    /// decoder rather than stopping at the AEAD.
    #[test]
    fn a_tampered_book_never_yields_a_contact() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x51);
        let entropy = seeded(81);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record(&code(0x33))).expect("import");
        block_on(staging.put_staged_bytes(
            store.staging_key(),
            &sealed(&secret, 51, &framed(&[substituted_code(0x33, 0x44)])),
        ))
        .expect("clobber");

        assert!(matches!(
            block_on(resolve_recipient(&store, &identity_of(0x33))),
            Err(ContactStoreError::Unreadable(
                BookCodecError::UnverifiableCode(_)
            ))
        ));
    }

    #[test]
    fn a_book_this_build_cannot_read_fails_closed_rather_than_reading_empty() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x61);
        let entropy = seeded(97);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record(&code(0x33))).expect("import");
        block_on(staging.put_staged_bytes(store.staging_key(), b"not a contact book"))
            .expect("clobber");

        assert!(matches!(
            block_on(store.contacts()),
            Err(ContactStoreError::Unreadable(BookCodecError::DidNotOpen(_)))
        ));
    }

    /// The other arm of the same rule: bytes that open under this session's key
    /// but carry a body this build does not read are still state, not an empty
    /// book.
    #[test]
    fn a_body_this_build_cannot_decode_fails_closed_rather_than_reading_empty() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x62);
        let entropy = seeded(98);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record(&code(0x33))).expect("import");
        block_on(staging.put_staged_bytes(
            store.staging_key(),
            &sealed(&secret, 62, b"opens, but is not a contact book"),
        ))
        .expect("clobber");

        assert!(matches!(
            block_on(store.contacts()),
            Err(ContactStoreError::Unreadable(BookCodecError::Codec(_)))
        ));
    }

    /// The store names its owner-local kind, so a sibling store's blob is
    /// unreadable state even when its body is a book this build decodes
    /// perfectly — separation is the kind, not the body grammar.
    #[test]
    fn a_blob_from_another_owner_local_store_fails_closed() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x63);
        let entropy = seeded(99);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(staging.put_staged_bytes(
            store.staging_key(),
            &sealed_as(
                &secret,
                OwnerLocalKind::ReceivedShares,
                63,
                &framed(&[code(0x33)]),
            ),
        ))
        .expect("stage");

        assert!(
            matches!(
                block_on(store.contacts()),
                Err(ContactStoreError::Unreadable(BookCodecError::DidNotOpen(_)))
            ),
            "another store's blob is an error, never a book to adopt"
        );
    }

    /// The disclosure this store's seal closes: a local reader of host storage
    /// must not learn who the owner has imported.
    #[test]
    fn the_persisted_book_never_holds_a_contact_key_in_the_clear() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x64);
        let entropy = seeded(100);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        let imported = block_on(store.record(&code(0x33))).expect("import");

        let stored = block_on(staging.staged_bytes(store.staging_key()))
            .expect("staged")
            .expect("the book is stored");
        let identity = imported.identity_pk().to_sec1();
        let subkey = imported.enc_subkey().to_bytes();
        assert!(
            !stored.windows(identity.len()).any(|w| w == identity),
            "a contact's identity key must never sit in host storage in the clear"
        );
        assert!(
            !stored.windows(subkey.len()).any(|w| w == subkey),
            "a contact's encryption subkey is sealed too"
        );
    }

    #[test]
    fn an_all_zero_ephemeral_fails_closed_before_the_seal() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x65);
        let entropy = RefCell::new(SilentEntropy);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        assert!(matches!(
            block_on(store.record(&code(0x33))),
            Err(ContactStoreError::Entropy(_))
        ));
        assert!(
            block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .is_none(),
            "a refused seal writes nothing"
        );
    }

    #[test]
    fn an_entropy_failure_leaves_the_recorded_book_untouched() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x66);
        let good = seeded(102);
        block_on(StagingContactStore::new(&staging, &secret, &good).record(&code(0x33)))
            .expect("import");

        let broken = RefCell::new(FailingEntropy);
        let store = StagingContactStore::new(&staging, &secret, &broken);
        assert!(block_on(store.record(&code(0x44))).is_err());
        assert_eq!(
            block_on(store.contacts()).expect("load").len(),
            1,
            "a failed import never clears the book it could not replace"
        );
    }

    #[test]
    fn another_identitys_book_is_not_this_sessions_book() {
        let staging = InMemoryStagingStore::default();
        let alice = enc(0x71);
        let bob = enc(0x72);
        let entropy = seeded(0x71);
        block_on(StagingContactStore::new(&staging, &alice, &entropy).record(&code(0x33)))
            .expect("import");

        assert!(
            block_on(StagingContactStore::new(&staging, &bob, &entropy).contacts())
                .expect("load")
                .is_empty(),
            "one store is shared across accounts; a contact must not cross identities"
        );
    }

    /// Rule 8: the decoder refuses two codes for one identity — no defined
    /// authority for that recipient's subkey — so the encoder must too.
    #[test]
    fn two_codes_for_one_identity_are_refused_in_both_directions() {
        let codes = [code(0x33), bound_code(0x33, 0x99)];
        let book: Vec<Recorded> = codes
            .iter()
            .map(|code| Recorded {
                contact: import_contact(code).expect("valid code"),
                code: code.clone(),
            })
            .collect();
        assert!(matches!(
            encode_book(&book),
            Err(BookCodecError::DuplicateIdentity)
        ));
        assert!(matches!(
            decode_book(&framed(&codes)),
            Err(BookCodecError::DuplicateIdentity)
        ));
    }

    #[test]
    fn a_book_at_an_unreadable_version_is_refused() {
        let mut m = Map::new();
        m.insert("contacts", Value::Array(vec![]));
        m.insert("v", Value::Unsigned(CONTACT_BOOK_V + 1));
        assert!(matches!(
            decode_book(&encode_fixed_depth(&Value::Map(m))),
            Err(BookCodecError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn a_book_with_an_unknown_key_is_refused() {
        let mut m = Map::new();
        m.insert("contacts", Value::Array(vec![]));
        m.insert("extra", Value::Unsigned(1));
        m.insert("v", Value::Unsigned(CONTACT_BOOK_V));
        assert!(decode_book(&encode_fixed_depth(&Value::Map(m))).is_err());
    }

    /// A contact rotating their own subkey re-signs the binding, so the newer
    /// code replaces the older one instead of sitting beside it.
    #[test]
    fn re_importing_an_identity_replaces_the_subkey_it_resolves_to() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x81);
        let entropy = seeded(129);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record(&code(0x33))).expect("first import");
        block_on(store.record(&bound_code(0x33, 0x99))).expect("rotated import");

        assert_eq!(block_on(store.contacts()).expect("load").len(), 1);
        let resolved = block_on(resolve_recipient(&store, &identity_of(0x33))).expect("resolves");
        assert_eq!(
            resolved.enc_subkey(),
            kdf::enc_subkey(&[0x99; 32]).public(),
            "the rotated subkey is what a later grant seals to"
        );
    }

    /// The book is the only durable home for a recipient's subkey, so a full
    /// book must name its own remedy rather than read as corruption.
    #[test]
    fn a_full_book_reports_as_full_and_a_forget_makes_room() {
        /// A distinct identity per index, since the bound is past a byte.
        fn nth_code(i: u16) -> Vec<u8> {
            let mut seed = [0x11; 32];
            seed[..2].copy_from_slice(&i.to_be_bytes());
            let identity = EcdsaSigner::from_scalar(&seed).expect("valid identity scalar");
            ContactCode::create(&identity, kdf::enc_subkey(&seed).public()).encode()
        }

        let staging = InMemoryStagingStore::default();
        let secret = enc(0xB1);
        let entropy = seeded(177);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        let book: Vec<Recorded> = (0..MAX_CONTACTS)
            .map(|i| {
                let (contact, code) =
                    import_recorded(&nth_code(u16::try_from(i).expect("in range")))
                        .expect("valid code");
                Recorded { contact, code }
            })
            .collect();
        let first = book[0].contact.identity_pk().to_sec1();
        block_on(store.put(&book)).expect("seed a full book");

        let fresh = nth_code(u16::try_from(MAX_CONTACTS).expect("in range"));
        assert!(
            matches!(block_on(store.record(&fresh)), Err(ContactStoreError::Full)),
            "a full book is refused as full, never as unreadable bytes"
        );

        block_on(store.forget(&first)).expect("forget");
        block_on(store.record(&fresh)).expect("a forget makes room");
    }

    /// A code with an unknown field imports, but only its canonical re-encoding
    /// is stored — the offered spelling is never an attacker-chosen byte channel
    /// into the owner's durable store.
    #[test]
    fn only_the_canonical_code_reaches_the_book() {
        use cipherbox_core::codec::{decode as cbor_decode, encode as cbor_encode};

        let staging = InMemoryStagingStore::default();
        let secret = enc(0xC1);
        let entropy = seeded(193);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        let padded = {
            let mut map = cbor_decode(&code(0x33)).unwrap().as_map().unwrap().clone();
            map.insert("padding", Value::Bytes(vec![0x5A; 512]));
            cbor_encode(&Value::Map(map)).unwrap()
        };
        block_on(store.record(&padded)).expect("a padded code still imports");

        let stored = block_on(staging.staged_bytes(store.staging_key()))
            .expect("staged")
            .expect("the book is stored");
        // Read past the seal: the claim is about the body this store authored,
        // and asserting on ciphertext would hold however the code was spelled.
        let body = open_owner_local(&secret, OwnerLocalKind::ContactBook, &stored).expect("opens");
        assert!(
            !body.windows(16).any(|w| w == [0x5A; 16]),
            "the offered padding never reached the durable book"
        );
        assert_eq!(block_on(store.contacts()).expect("load").len(), 1);
    }

    #[test]
    fn a_lost_write_never_destroys_the_recorded_book() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x91);
        let entropy = seeded(145);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record(&code(0x33))).expect("import");

        staging.interrupt_staged_write_after(store.staging_key(), 0);
        assert!(block_on(store.record(&code(0x44))).is_err());
        assert_eq!(
            block_on(store.contacts()).expect("load").len(),
            1,
            "the lost replacement left the recorded book intact"
        );
    }

    /// The book's real staging key — not just its prefix — is what orphan GC
    /// must spare, so this pins the key the sweep's prefix table is fed.
    #[test]
    fn the_books_staging_key_sits_under_the_swept_prefix() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0xA1);
        let entropy = seeded(161);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record(&code(0x33))).expect("import");

        assert!(
            block_on(staging.staged_keys())
                .expect("keys")
                .iter()
                .all(|key| key.starts_with(CONTACTS_PREFIX)),
            "the book writes nothing outside the prefix orphan GC spares"
        );
    }

    /// The freshness invariant the seal rests on: two persists must not share an
    /// HPKE ephemeral. `fresh_ephemeral` only rejects an all-zero draw, so a seam
    /// stuck on any other constant is caught here or nowhere.
    #[test]
    fn two_persists_never_share_an_hpke_ephemeral() {
        fn enc_of(blob: &[u8]) -> Vec<u8> {
            decode(blob)
                .expect("frame")
                .as_map()
                .expect("map")
                .get("enc")
                .expect("enc")
                .as_bytes()
                .expect("bytes")
                .to_vec()
        }

        let staging = InMemoryStagingStore::default();
        let secret = enc(0xD1);
        let entropy = seeded(209);
        let store = StagingContactStore::new(&staging, &secret, &entropy);

        block_on(store.record(&code(0x33))).expect("first import");
        let first = enc_of(
            &block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .expect("stored"),
        );
        block_on(store.record(&code(0x44))).expect("second import");
        let second = enc_of(
            &block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .expect("stored"),
        );

        assert_ne!(
            first, second,
            "an ephemeral reused across two seals under one key and info is a confidentiality break"
        );
    }
}
