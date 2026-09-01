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

/// The frozen bound on the share of the book claim conversions may take.
///
/// An invite link is bearer and multi-claim, and a link holder mints a fresh
/// identity per claim, so one leaked link would otherwise fill the whole
/// per-vault book and deny contact import across the account.
///
/// An admission charge rather than a stored bound, and charged **per link**
/// ([`link_budget_full`]): one leaked link takes only its own share, so it
/// denies no other link's claims and no hand import. [`MAX_CONTACTS`] is what
/// bounds the stored set.
///
/// The owner clears a link that reached the bound by revoking it and minting a
/// fresh one, which carries its own share. No contact is dropped on that path,
/// so every converted grant stays cuttable.
pub const MAX_LINK_CONTACTS: usize = 128;

/// The frozen bound on the scopes one link-sourced contact holds a converted
/// grant on. Enforced release-active in both codec directions
/// (AGENTS.md rule 8).
pub const MAX_LINK_CONTACT_SCOPES: usize = 64;

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
    /// This link's own claim conversions already hold [`MAX_LINK_CONTACTS`].
    /// Named, because the remedy is to revoke that link, and a bearer link's
    /// claimants are strangers the owner cannot pick out of the book by hand.
    LinkBookFull {
        /// The committed tag of the link the refused claim came in on.
        link_tag: [u8; 32],
    },
    /// One link-sourced contact already holds a converted grant on
    /// [`MAX_LINK_CONTACT_SCOPES`] scopes. Distinct from
    /// [`Encode`](Self::Encode), which says the whole book is unwritable: here
    /// the book is fine and one contact reached a frozen bound.
    LinkContactScopesFull,
    /// The book to store is not one this build may write: two codes for one
    /// identity, or a field past its bound. A write-path refusal, so never
    /// [`Unreadable`](Self::Unreadable) — nothing was read.
    Encode(BookCodecError),
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
            ContactStoreError::LinkBookFull { .. } => write!(
                f,
                "that invite link's claims already hold {MAX_LINK_CONTACTS} contacts"
            ),
            ContactStoreError::LinkContactScopesFull => write!(
                f,
                "that contact already holds a granted scope on {MAX_LINK_CONTACT_SCOPES} scopes"
            ),
            ContactStoreError::Encode(e) => write!(f, "the contact book to store {e}"),
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
    /// One link-sourced entry named a scope twice, so the count of grants it
    /// holds would outlive the cuts that removed them.
    DuplicateScope,
    /// A link-sourced entry holding no grant. It charges the link bound for a
    /// contact no cut needs, so it is refused rather than carried.
    LinkContactHoldsNothing,
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
            BookCodecError::DuplicateScope => {
                f.write_str("names one scope twice for a link-sourced contact")
            }
            BookCodecError::LinkContactHoldsNothing => {
                f.write_str("holds a link-sourced contact with no grant")
            }
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

    /// Record a contact a claim conversion anchored, charged to that link's own
    /// share of the book and holding the grant the conversion just minted at
    /// `scope_id`.
    ///
    /// A contact the owner imported by hand keeps that standing and owes the
    /// link bound nothing.
    async fn record_from_link(
        &self,
        contact_code: &[u8],
        link_tag: &[u8; 32],
        scope_id: &[u8; 16],
    ) -> Result<Contact, ContactStoreError>;

    /// Take `identity_pk` off the link budget for good: the owner granted it
    /// directly, which is a stronger vouch than a hand import.
    ///
    /// The entry then holds grants no claim conversion recorded, so no cut may
    /// collect it — dropping it would leave a live grant the owner cannot
    /// resolve a recipient for. Idempotent, and a no-op on an identity the book
    /// does not hold or already holds by hand.
    async fn vouch(&self, identity_pk: &[u8; IDENTITY_PUBLIC_LEN])
    -> Result<(), ContactStoreError>;

    /// Drop the grant a link-sourced contact holds at `scope_id`, and the entry
    /// itself once it holds none.
    ///
    /// Idempotent, and a no-op on a hand-imported or vouched contact: no cut
    /// takes one of those out.
    async fn forget_link_grant(
        &self,
        identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
        scope_id: &[u8; 16],
    ) -> Result<(), ContactStoreError>;

    /// Every recorded contact with the link that sourced it, `None` for one the
    /// owner imported or granted directly. One decode for a caller that needs
    /// both the book and [`link_budget_full`]'s input.
    async fn contacts_with_sources(
        &self,
    ) -> Result<Vec<(Contact, Option<[u8; 32]>)>, ContactStoreError>;

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

/// Why a claim-sourced contact is in the book: the link that produced it, and
/// the scopes its conversions took a grant on.
///
/// The scopes are what makes the entry collectable. A link-sourced contact is
/// held only so a later revoke or downgrade can resolve the recipient the
/// conversion granted, so an entry whose last grant a cut removed has no reason
/// left to occupy the book ([`ContactStore::forget_link_grant`]).
#[derive(Clone)]
struct LinkOrigin {
    link_tag: [u8; 32],
    scopes: Vec<[u8; 16]>,
}

impl LinkOrigin {
    fn hold(&mut self, scope_id: &[u8; 16]) -> Result<(), ContactStoreError> {
        if self.scopes.contains(scope_id) {
            return Ok(());
        }
        if self.scopes.len() >= MAX_LINK_CONTACT_SCOPES {
            return Err(ContactStoreError::LinkContactScopesFull);
        }
        self.scopes.push(*scope_id);
        Ok(())
    }
}

/// One recorded contact: the verified pair, the canonical self-authenticating
/// code the book stores it as, and where it came from — `None` for a hand
/// import. Only [`import_recorded`] builds one, so the pair and the code can
/// never disagree.
struct Recorded {
    contact: Contact,
    code: Vec<u8>,
    origin: Option<LinkOrigin>,
}

/// Whether `link_tag`'s own claim conversions already hold its whole
/// [`MAX_LINK_CONTACTS`] share of the book.
///
/// `sourcing` is the link each recorded contact came from, `None` for a hand
/// import ([`ContactStore::contacts_with_sources`]). The charge is per link, so
/// one leaked link takes only its own share and denies no other link's claims.
pub fn link_budget_full(sourcing: &[Option<[u8; 32]>], link_tag: &[u8; 32]) -> bool {
    sourcing
        .iter()
        .filter(|held| held.as_ref() == Some(link_tag))
        .count()
        >= MAX_LINK_CONTACTS
}

/// The link each entry of `book` came from, `None` for one the owner imported
/// or granted directly.
fn sources(book: &[Recorded]) -> Vec<Option<[u8; 32]>> {
    book.iter()
        .map(|held| held.origin.as_ref().map(|origin| origin.link_tag))
        .collect()
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
        let body = open_owner_local(self.enc_secret, OwnerLocalKind::ContactBook, &blob)
            .map_err(|e| ContactStoreError::Unreadable(BookCodecError::DidNotOpen(e)))?;
        decode_book(&body).map_err(ContactStoreError::Unreadable)
    }

    /// Replace the whole book.
    async fn put(&self, book: &[Recorded]) -> Result<(), ContactStoreError> {
        let body = encode_book(book).map_err(ContactStoreError::Encode)?;
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
        // A hand import outranks a claim: the owner vouched for this identity,
        // so the entry stops charging the link bound and stops being collectable
        // by a cut.
        book.retain(|held| held.contact.identity_pk() != contact.identity_pk());
        if book.len() >= MAX_CONTACTS {
            return Err(ContactStoreError::Full);
        }
        book.push(Recorded {
            contact,
            code,
            origin: None,
        });
        self.put(&book).await?;
        Ok(contact)
    }

    async fn record_from_link(
        &self,
        contact_code: &[u8],
        link_tag: &[u8; 32],
        scope_id: &[u8; 16],
    ) -> Result<Contact, ContactStoreError> {
        let (contact, code) = import_recorded(contact_code).map_err(ContactStoreError::Import)?;
        let mut book = self.recorded().await?;
        let held = book
            .iter()
            .position(|held| held.contact.identity_pk() == contact.identity_pk())
            .map(|at| book.remove(at));
        let origin = match held {
            Some(Recorded { origin: None, .. }) => None,
            Some(Recorded {
                origin: Some(mut origin),
                ..
            }) => {
                // A claim moves the entry onto the link it came in on, so the
                // move is a charge on that link. Without it a holder of two
                // links empties one by re-claiming its entries on the other,
                // then refills it, past the per-link share.
                if origin.link_tag != *link_tag && link_budget_full(&sources(&book), link_tag) {
                    return Err(ContactStoreError::LinkBookFull {
                        link_tag: *link_tag,
                    });
                }
                origin.link_tag = *link_tag;
                origin.hold(scope_id)?;
                Some(origin)
            }
            None => {
                if link_budget_full(&sources(&book), link_tag) {
                    return Err(ContactStoreError::LinkBookFull {
                        link_tag: *link_tag,
                    });
                }
                Some(LinkOrigin {
                    link_tag: *link_tag,
                    scopes: vec![*scope_id],
                })
            }
        };
        if book.len() >= MAX_CONTACTS {
            return Err(ContactStoreError::Full);
        }
        book.push(Recorded {
            contact,
            code,
            origin,
        });
        self.put(&book).await?;
        Ok(contact)
    }

    async fn vouch(
        &self,
        identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
    ) -> Result<(), ContactStoreError> {
        let mut book = self.recorded().await?;
        let Some(held) = book
            .iter_mut()
            .find(|held| held.contact.identity_pk().to_sec1() == *identity_pk)
        else {
            return Ok(());
        };
        if held.origin.take().is_none() {
            return Ok(());
        }
        self.put(&book).await
    }

    async fn forget_link_grant(
        &self,
        identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
        scope_id: &[u8; 16],
    ) -> Result<(), ContactStoreError> {
        let mut book = self.recorded().await?;
        let Some(at) = book
            .iter()
            .position(|held| held.contact.identity_pk().to_sec1() == *identity_pk)
        else {
            return Ok(());
        };
        let Some(origin) = book[at].origin.as_mut() else {
            return Ok(());
        };
        let before = origin.scopes.len();
        origin.scopes.retain(|held| held != scope_id);
        if origin.scopes.len() == before {
            return Ok(());
        }
        if origin.scopes.is_empty() {
            book.remove(at);
        }
        self.put(&book).await
    }

    async fn contacts_with_sources(
        &self,
    ) -> Result<Vec<(Contact, Option<[u8; 32]>)>, ContactStoreError> {
        Ok(self
            .recorded()
            .await?
            .into_iter()
            .map(|held| (held.contact, held.origin.map(|origin| origin.link_tag)))
            .collect())
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
    let mut imported = Vec::new();
    let mut from_links = Vec::new();
    for held in sorted {
        within("contactCode", held.code.len(), MAX_CONTACT_CODE_BYTES)?;
        match &held.origin {
            None => imported.push(Value::Bytes(held.code.clone())),
            Some(origin) => {
                within(
                    "linkContactScopes",
                    origin.scopes.len(),
                    MAX_LINK_CONTACT_SCOPES,
                )?;
                if origin.scopes.is_empty() {
                    return Err(BookCodecError::LinkContactHoldsNothing);
                }
                let mut entry = Map::new();
                entry.insert("code", Value::Bytes(held.code.clone()));
                entry.insert("linkTag", Value::Bytes(origin.link_tag.to_vec()));
                let mut scopes = origin.scopes.clone();
                scopes.sort_unstable();
                scopes.dedup();
                if scopes.len() != origin.scopes.len() {
                    return Err(BookCodecError::DuplicateScope);
                }
                entry.insert(
                    "scopes",
                    Value::Array(
                        scopes
                            .into_iter()
                            .map(|scope| Value::Bytes(scope.to_vec()))
                            .collect(),
                    ),
                );
                from_links.push(Value::Map(entry));
            }
        }
    }
    let mut body = Map::new();
    body.insert("contacts", Value::Array(imported));
    body.insert("linkContacts", Value::Array(from_links));
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
    reject_unknown(map, &["contacts", "linkContacts", "v"])?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != CONTACT_BOOK_V {
        return Err(BookCodecError::UnsupportedVersion { version });
    }
    let imported = req(map, "contacts")?.as_array()?;
    let from_links = req(map, "linkContacts")?.as_array()?;
    within(
        "contacts",
        imported.len().saturating_add(from_links.len()),
        MAX_CONTACTS,
    )?;
    let mut book: Vec<Recorded> = Vec::with_capacity(imported.len() + from_links.len());
    for item in imported {
        let (contact, code) = decode_code(item.as_bytes()?)?;
        push_unique(&mut book, contact, code, None)?;
    }
    for item in from_links {
        let entry = item.as_map()?;
        reject_unknown(entry, &["code", "linkTag", "scopes"])?;
        let (contact, code) = decode_code(req(entry, "code")?.as_bytes()?)?;
        let link_tag = fixed(req(entry, "linkTag")?.as_bytes()?)?;
        let raw = req(entry, "scopes")?.as_array()?;
        within("linkContactScopes", raw.len(), MAX_LINK_CONTACT_SCOPES)?;
        let mut scopes: Vec<[u8; 16]> = Vec::with_capacity(raw.len());
        for scope in raw {
            let scope = fixed(scope.as_bytes()?)?;
            if scopes.contains(&scope) {
                return Err(BookCodecError::DuplicateScope);
            }
            scopes.push(scope);
        }
        // An entry that holds nothing is one a cut should already have taken
        // out: keeping it would charge the link bound for a contact no revoke
        // needs. Refused in both directions (AGENTS.md rule 8).
        if scopes.is_empty() {
            return Err(BookCodecError::LinkContactHoldsNothing);
        }
        push_unique(
            &mut book,
            contact,
            code,
            Some(LinkOrigin { link_tag, scopes }),
        )?;
    }
    Ok(book)
}

/// Re-verify one stored code and prove it is the canonical spelling this build
/// writes.
fn decode_code(code: &[u8]) -> Result<(Contact, Vec<u8>), BookCodecError> {
    within("contactCode", code.len(), MAX_CONTACT_CODE_BYTES)?;
    let (contact, canonical) = import_recorded(code).map_err(BookCodecError::UnverifiableCode)?;
    if canonical != code {
        return Err(BookCodecError::NonCanonicalCode);
    }
    Ok((contact, canonical))
}

/// A stored fixed-width field, or [`BookCodecError::TooLong`] naming its width.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], BookCodecError> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        BookCodecError::from(TooLong {
            field: "linkContactField",
            len: bytes.len(),
            limit: N,
        })
    })
}

/// Append one entry, refusing a second code for one identity across both lists.
fn push_unique(
    book: &mut Vec<Recorded>,
    contact: Contact,
    code: Vec<u8>,
    origin: Option<LinkOrigin>,
) -> Result<(), BookCodecError> {
    if book
        .iter()
        .any(|held| held.contact.identity_pk() == contact.identity_pk())
    {
        return Err(BookCodecError::DuplicateIdentity);
    }
    book.push(Recorded {
        contact,
        code,
        origin,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use cipherbox_core::kdf;
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use super::super::contact::import_contact;
    use super::*;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{FailingEntropy, SeededEntropy, SilentEntropy, block_on, conformance};

    fn enc(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    fn seeded(seed: u64) -> RefCell<SeededEntropy> {
        RefCell::new(SeededEntropy::new(seed))
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
        m.insert("linkContacts", Value::Array(Vec::new()));
        m.insert("v", Value::Unsigned(CONTACT_BOOK_V));
        encode_fixed_depth(&Value::Map(m))
    }

    /// One link-sourced entry as the book stores it.
    fn framed_link_entry(code: &[u8], link_tag: [u8; 32], scopes: &[[u8; 16]]) -> Value {
        let mut m = Map::new();
        m.insert("code", Value::Bytes(code.to_vec()));
        m.insert("linkTag", Value::Bytes(link_tag.to_vec()));
        m.insert(
            "scopes",
            Value::Array(
                scopes
                    .iter()
                    .map(|scope| Value::Bytes(scope.to_vec()))
                    .collect(),
            ),
        );
        Value::Map(m)
    }

    /// A stored book carrying `link_entries` beside the hand-imported `codes`.
    fn framed_with_links(codes: &[Vec<u8>], link_entries: Vec<Value>) -> Vec<u8> {
        let mut m = Map::new();
        m.insert(
            "contacts",
            Value::Array(codes.iter().cloned().map(Value::Bytes).collect()),
        );
        m.insert("linkContacts", Value::Array(link_entries));
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

    /// The write path's own refusals are not a verdict on stored bytes: a book
    /// this build declines to encode leaves the stored book unimpeached, so a
    /// host must not be told the owner's contacts are corrupt.
    #[test]
    fn a_book_this_build_refuses_to_encode_is_not_reported_as_unreadable() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x62);
        let entropy = seeded(62);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        let (contact, encoded) = import_recorded(&code(0x33)).expect("import");
        let clash = [
            Recorded {
                contact,
                code: encoded.clone(),
                origin: None,
            },
            Recorded {
                contact,
                code: encoded,
                origin: None,
            },
        ];

        assert!(matches!(
            block_on(store.put(&clash)),
            Err(ContactStoreError::Encode(BookCodecError::DuplicateIdentity))
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
                origin: None,
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
                Recorded {
                    contact,
                    code,
                    origin: None,
                }
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

    /// A contact code minted for the `i`-th claimant of a bearer link.
    fn claimant_code(i: u16) -> Vec<u8> {
        let mut scalar = [0x77; 32];
        scalar[..2].copy_from_slice(&i.to_be_bytes());
        let identity = EcdsaSigner::from_scalar(&scalar).expect("valid identity scalar");
        ContactCode::create(&identity, kdf::enc_subkey(&scalar).public()).encode()
    }

    fn claimant_identity(i: u16) -> [u8; IDENTITY_PUBLIC_LEN] {
        import_contact(&claimant_code(i))
            .expect("valid code")
            .identity_pk()
            .to_sec1()
    }

    const LINK: [u8; 32] = [0xAB; 32];
    const OTHER_LINK: [u8; 32] = [0xCD; 32];
    const SCOPE_A: [u8; 16] = [0x0A; 16];
    const SCOPE_B: [u8; 16] = [0x0B; 16];

    /// A bearer link is multi-claim and its holder mints a fresh identity per
    /// claim, so without a share of its own it fills the whole per-vault book.
    /// The bound stops it short of the room hand imports need, and it names the
    /// link so the owner knows which one to revoke.
    #[test]
    fn claims_past_the_link_bound_are_refused_and_hand_imports_still_land() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x71);
        let entropy = seeded(113);
        let store = StagingContactStore::new(&staging, &secret, &entropy);

        for i in 0..MAX_LINK_CONTACTS {
            block_on(store.record_from_link(
                &claimant_code(u16::try_from(i).expect("in range")),
                &LINK,
                &SCOPE_A,
            ))
            .expect("a claim under the bound records");
        }

        let over = u16::try_from(MAX_LINK_CONTACTS).expect("in range");
        assert!(
            matches!(
                block_on(store.record_from_link(&claimant_code(over), &LINK, &SCOPE_A)),
                Err(ContactStoreError::LinkBookFull { link_tag }) if link_tag == LINK
            ),
            "the refusal names the link the claim came in on"
        );
        block_on(store.record(&code(0x33))).expect("a hand import still has room");
    }

    /// The bound is charged per link, so one leaked link takes only its own
    /// share. A second link's claims still convert, and a fresh link the owner
    /// mints after a revoke carries a share of its own.
    #[test]
    fn one_full_link_denies_no_other_links_claims() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x72);
        let entropy = seeded(114);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        for i in 0..MAX_LINK_CONTACTS {
            block_on(store.record_from_link(
                &claimant_code(u16::try_from(i).expect("in range")),
                &LINK,
                &SCOPE_A,
            ))
            .expect("a claim under the bound records");
        }

        let sources = block_on(store.contacts_with_sources())
            .expect("book")
            .into_iter()
            .map(|(_, source)| source)
            .collect::<Vec<_>>();
        assert!(link_budget_full(&sources, &LINK));
        assert!(
            !link_budget_full(&sources, &OTHER_LINK),
            "another link's own share is untouched"
        );

        let over = u16::try_from(MAX_LINK_CONTACTS).expect("in range");
        block_on(store.record_from_link(&claimant_code(over), &OTHER_LINK, &SCOPE_A))
            .expect("a claim on another link converts");
        assert_eq!(
            block_on(store.contacts()).expect("load").len(),
            MAX_LINK_CONTACTS + 1,
            "and every earlier claimant stays resolvable for a cut"
        );
    }

    /// A move between links is charged to the link the entry lands on. Without
    /// that charge a holder of two links empties one by re-claiming its entries
    /// on the other, then refills it, past the share either link may take.
    #[test]
    fn a_claim_that_moves_an_entry_onto_a_full_link_is_refused() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x7A);
        let entropy = seeded(122);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        let moved = u16::try_from(MAX_LINK_CONTACTS).expect("in range");
        block_on(store.record_from_link(&claimant_code(moved), &LINK, &SCOPE_A))
            .expect("a claim on the first link converts");
        for i in 0..MAX_LINK_CONTACTS {
            block_on(store.record_from_link(
                &claimant_code(u16::try_from(i).expect("in range")),
                &OTHER_LINK,
                &SCOPE_A,
            ))
            .expect("a claim under the second link's bound records");
        }

        assert!(
            matches!(
                block_on(store.record_from_link(&claimant_code(moved), &OTHER_LINK, &SCOPE_B)),
                Err(ContactStoreError::LinkBookFull { link_tag }) if link_tag == OTHER_LINK
            ),
            "the refusal names the link the entry would move onto"
        );
        let sources = block_on(store.contacts_with_sources())
            .expect("book")
            .into_iter()
            .map(|(_, source)| source)
            .collect::<Vec<_>>();
        assert_eq!(
            sources.iter().filter(|s| **s == Some(LINK)).count(),
            1,
            "the refused move left the entry charged to the link it came from"
        );
        assert_eq!(
            sources.iter().filter(|s| **s == Some(OTHER_LINK)).count(),
            MAX_LINK_CONTACTS,
            "and the full link took no further share"
        );
    }

    /// A repeat claim on the link that already sources the entry adds a scope,
    /// not an entry, so a link at its own bound must still convert it.
    #[test]
    fn a_repeat_claim_on_the_sourcing_link_converts_at_the_bound() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x7B);
        let entropy = seeded(123);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        for i in 0..MAX_LINK_CONTACTS {
            block_on(store.record_from_link(
                &claimant_code(u16::try_from(i).expect("in range")),
                &LINK,
                &SCOPE_A,
            ))
            .expect("a claim under the bound records");
        }

        block_on(store.record_from_link(&claimant_code(0), &LINK, &SCOPE_B))
            .expect("the same link's repeat claim takes a scope, not a share");
        assert_eq!(
            block_on(store.contacts()).expect("load").len(),
            MAX_LINK_CONTACTS,
            "and the book grew by no entry"
        );
    }

    /// A link-sourced contact is held only so a cut can resolve the recipient
    /// its conversion granted. The entry goes when the last of those grants
    /// does, and not before.
    #[test]
    fn a_link_sourced_contact_goes_when_its_last_grant_is_cut() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x73);
        let entropy = seeded(115);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record_from_link(&claimant_code(0), &LINK, &SCOPE_A)).expect("claim");
        block_on(store.record_from_link(&claimant_code(0), &LINK, &SCOPE_B))
            .expect("a second scope's claim");

        block_on(store.forget_link_grant(&claimant_identity(0), &SCOPE_A)).expect("cut one");
        assert_eq!(
            block_on(store.contacts()).expect("load").len(),
            1,
            "a contact that still holds a grant elsewhere stays cuttable"
        );
        block_on(store.forget_link_grant(&claimant_identity(0), &SCOPE_B)).expect("cut the last");
        assert!(
            block_on(store.contacts()).expect("load").is_empty(),
            "the last cut returns the room the link took"
        );
    }

    /// An owner-driven grant records no scope on the entry, so a cut must not
    /// collect it: the claimant would keep a live grant no revoke could resolve
    /// a recipient for. The vouch is what takes it off both the bound and the
    /// collector.
    #[test]
    fn a_vouched_claimant_is_never_collected_by_a_cut() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x74);
        let entropy = seeded(116);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record_from_link(&claimant_code(0), &LINK, &SCOPE_A)).expect("claim");
        block_on(store.vouch(&claimant_identity(0))).expect("the owner grants them directly");

        let sources = block_on(store.contacts_with_sources())
            .expect("book")
            .into_iter()
            .map(|(_, source)| source)
            .collect::<Vec<_>>();
        assert_eq!(sources, vec![None], "the entry no longer charges the link");
        block_on(store.forget_link_grant(&claimant_identity(0), &SCOPE_A)).expect("cut");
        assert_eq!(
            block_on(store.contacts()).expect("load").len(),
            1,
            "and the cut leaves the recipient of every other grant resolvable"
        );
    }

    /// A hand import outranks a claim the same way: the owner vouched for that
    /// identity, so no cut takes it out.
    #[test]
    fn a_hand_import_takes_a_claimant_off_the_link_budget() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x75);
        let entropy = seeded(117);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        block_on(store.record_from_link(&claimant_code(0), &LINK, &SCOPE_A)).expect("claim");
        block_on(store.record(&claimant_code(0))).expect("the owner imports the same identity");

        block_on(store.forget_link_grant(&claimant_identity(0), &SCOPE_A)).expect("cut");
        assert_eq!(
            block_on(store.contacts()).expect("load").len(),
            1,
            "a cut never drops a contact the owner imported"
        );
    }

    /// Rule 8: a link-sourced entry holding no grant charges the link bound for
    /// a contact no cut needs, so both codec directions refuse it.
    #[test]
    fn a_link_sourced_contact_holding_nothing_is_refused_in_both_directions() {
        let (contact, code) = import_recorded(&claimant_code(0)).expect("import");
        let book = [Recorded {
            contact,
            code: code.clone(),
            origin: Some(LinkOrigin {
                link_tag: LINK,
                scopes: Vec::new(),
            }),
        }];
        assert!(matches!(
            encode_book(&book),
            Err(BookCodecError::LinkContactHoldsNothing)
        ));
        assert!(matches!(
            decode_book(&framed_with_links(
                &[],
                vec![framed_link_entry(&code, LINK, &[])]
            )),
            Err(BookCodecError::LinkContactHoldsNothing)
        ));
    }

    /// Rule 8: one scope named twice would outlive the cut that removed it, so
    /// both directions refuse it.
    #[test]
    fn a_repeated_scope_on_a_link_sourced_contact_is_refused_in_both_directions() {
        let (contact, code) = import_recorded(&claimant_code(0)).expect("import");
        let book = [Recorded {
            contact,
            code: code.clone(),
            origin: Some(LinkOrigin {
                link_tag: LINK,
                scopes: vec![SCOPE_A, SCOPE_A],
            }),
        }];
        assert!(matches!(
            encode_book(&book),
            Err(BookCodecError::DuplicateScope)
        ));
        assert!(matches!(
            decode_book(&framed_with_links(
                &[],
                vec![framed_link_entry(&code, LINK, &[SCOPE_A, SCOPE_A])]
            )),
            Err(BookCodecError::DuplicateScope)
        ));
    }

    /// One contact at the scope bound reports itself, never as a book this
    /// build cannot write: the stored book is fine and one entry is full.
    #[test]
    fn a_claimant_past_the_scope_bound_reports_its_own_refusal() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x76);
        let entropy = seeded(118);
        let store = StagingContactStore::new(&staging, &secret, &entropy);
        for i in 0..MAX_LINK_CONTACT_SCOPES {
            let mut scope = [0u8; 16];
            scope[..2].copy_from_slice(&u16::try_from(i).expect("in range").to_be_bytes());
            block_on(store.record_from_link(&claimant_code(0), &LINK, &scope))
                .expect("a claim under the scope bound records");
        }
        assert!(matches!(
            block_on(store.record_from_link(&claimant_code(0), &LINK, &SCOPE_B)),
            Err(ContactStoreError::LinkContactScopesFull)
        ));
    }
}
