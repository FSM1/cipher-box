//! The sealing rule for per-owner durable bookkeeping in the staging store.
//!
//! **A per-owner staging surface seals its value**, as an [`OwnerLocalKind`]
//! blob under the session's `enc-subkey`; a new surface takes a new kind rather
//! than a cleartext encoding. The store is a host's unencrypted IndexedDB or
//! on-disk directory, and an entry outlives the operation that wrote it, so
//! what it *associates* — this node with this content CID, this node with the
//! `ipnsName`s its deleted subtree published under — stays readable long after
//! the state it describes is gone. Against an attacker who can *write* the
//! store it also buys forgery resistance: an entry that will not open is
//! refused rather than spent.
//!
//! Two shapes stay clear, and must:
//!
//! - **Every key.** [`orphan_staging_keys`](crate::sync::orphan_staging_keys)
//!   enumerates keys and a scoped removal addresses them, so a key cannot be
//!   sealed. It leaks that this owner owes a retirement on this CID, or that
//!   this node has a delete pending; the seal removes the rest of each
//!   association, and the figures.
//! - **The op-id high-water marks**
//!   ([`owner_scoped_key`](crate::sync::owner_scoped_key)), the per-op attempt
//!   counts, and the notices of versionless dead letters
//!   (`crate::sync::staging`'s `DEAD_LETTER_NOTICES_PREFIX`).
//!   Their values associate no two identifiers and name nothing outside this
//!   store: an op id, a count, an enumerated reason, a timestamp. The preserved
//!   set beside them already carries the same op id and reason in the clear,
//!   and a writer who could forge a notice could rewrite that set instead — a
//!   notice holds no key, no block reference and no name.

use core::cell::RefCell;

use cipherbox_core::seal::{OwnerLocalKind, open_owner_local, seal_owner_local};
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::entropy::{Entropy, fresh_ephemeral};
use crate::seams::{SeamError, SeamResult};

/// One session's custody of its per-owner staging bookkeeping: the `enc-subkey`
/// every entry seals to, and the injected entropy each seal draws its ephemeral
/// from.
///
/// Erased to `dyn Entropy` so the surfaces holding one stay non-generic — the
/// drain's boxed source and a test's seeded one both coerce here. `'static`
/// behind the borrow keeps the handle covariant, so one seal can be handed to
/// callees holding shorter borrows of the same session.
#[derive(Clone, Copy)]
pub struct BookkeepingSeal<'a> {
    enc_secret: &'a X25519Secret,
    entropy: &'a RefCell<dyn Entropy + 'static>,
}

impl<'a> BookkeepingSeal<'a> {
    /// Adopt the session's `enc-subkey` and entropy as bookkeeping custody.
    pub fn new(enc_secret: &'a X25519Secret, entropy: &'a RefCell<dyn Entropy + 'static>) -> Self {
        Self {
            enc_secret,
            entropy,
        }
    }

    /// Seal one entry's encoded body. A fresh ephemeral per call: HPKE
    /// ephemeral reuse under one recipient key and `info` is a confidentiality
    /// break ([`seal_owner_local`]).
    pub fn seal(&self, kind: OwnerLocalKind, body: &[u8]) -> SeamResult<Vec<u8>> {
        let ephemeral = fresh_ephemeral(&mut *self.entropy.borrow_mut())
            .map_err(|e| SeamError::new(e.message().to_owned()))?;
        seal_owner_local(self.enc_secret, kind, &ephemeral, body)
            .map_err(|e| SeamError::new(e.to_string()))
    }

    /// Open one entry, or `None` for bytes this identity's key does not open —
    /// which every caller reads as *unwritten* rather than as state of its own,
    /// the same verdict a foreign or truncated encoding already earned.
    pub fn open(&self, kind: OwnerLocalKind, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        open_owner_local(self.enc_secret, kind, blob).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::SeededEntropy;

    fn secret(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    #[test]
    fn an_entry_round_trips_under_the_owners_own_key() {
        let entropy = RefCell::new(SeededEntropy::new(1));
        let mine = secret(9);
        let seal = BookkeepingSeal::new(&mine, &entropy);

        let blob = seal
            .seal(OwnerLocalKind::RetireLedger, b"debt")
            .expect("seal");
        let opened = seal
            .open(OwnerLocalKind::RetireLedger, &blob)
            .expect("opens");
        assert_eq!(&opened[..], b"debt");
    }

    /// The store is shared across identities and across kinds, so an entry only
    /// its own owner and its own kind open is what keeps one surface's bytes
    /// from reading as another's state.
    #[test]
    fn a_stranger_and_a_sibling_kind_both_read_it_as_unwritten() {
        let entropy = RefCell::new(SeededEntropy::new(2));
        let mine = secret(9);
        let theirs = secret(10);
        let blob = BookkeepingSeal::new(&mine, &entropy)
            .seal(OwnerLocalKind::DoomedJournal, b"names")
            .expect("seal");

        assert_eq!(
            BookkeepingSeal::new(&theirs, &entropy).open(OwnerLocalKind::DoomedJournal, &blob),
            None,
            "another identity's key"
        );
        assert_eq!(
            BookkeepingSeal::new(&mine, &entropy).open(OwnerLocalKind::RetireLedger, &blob),
            None,
            "the sibling bookkeeping kind"
        );
    }

    #[test]
    fn two_seals_of_one_body_never_share_an_ephemeral() {
        let entropy = RefCell::new(SeededEntropy::new(3));
        let mine = secret(9);
        let seal = BookkeepingSeal::new(&mine, &entropy);

        let first = seal.seal(OwnerLocalKind::RetireLedger, b"debt").expect("a");
        let second = seal.seal(OwnerLocalKind::RetireLedger, b"debt").expect("b");
        assert_ne!(first, second);
    }
}
