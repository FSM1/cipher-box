//! BLAKE3 tree-KDF primitives (blueprint/core.md "Crypto suite").
//!
//! The two BLAKE3 modes the whole KDF edge catalog is built from: keyed
//! context derivation ([`derive_key`]) and keyed hashing ([`keyed_hash`]).
//! Both are thin, total wrappers over the `blake3` crate; [`crate::kdf`] is the
//! only caller and composes them per the frozen per-node shape
//! `keyed_hash(derive_key(context, seed), message)`.

use super::secret::{SECRET_LEN, SecretBytes};

/// BLAKE3 `derive_key`: a context-separated 32-byte key from input key
/// material. `context` is a fixed, program-unique domain string (the KDF
/// catalog's `cipherbox/v2/<edge>` constants) — never attacker-influenced and
/// never variable-length caller input; variable data enters through
/// [`keyed_hash`]'s message instead (blueprint/core.md "KDF edge catalog":
/// ids are fixed-length message input, never variable context).
pub fn derive_key(context: &str, key_material: &[u8]) -> SecretBytes {
    SecretBytes::new(blake3::derive_key(context, key_material))
}

/// BLAKE3 `keyed_hash`: a 32-byte MAC of `message` under a 32-byte `key`. The
/// catalog feeds fixed-length ids/tags/indices as the message so variable data
/// never lands in a derivation context.
pub fn keyed_hash(key: &[u8; SECRET_LEN], message: &[u8]) -> SecretBytes {
    SecretBytes::new(*blake3::keyed_hash(key, message).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_deterministic_and_context_separated() {
        let ikm = [1u8; 32];
        let a = derive_key("cipherbox/v2/test-a", &ikm);
        let a2 = derive_key("cipherbox/v2/test-a", &ikm);
        let b = derive_key("cipherbox/v2/test-b", &ikm);
        assert_eq!(a.as_bytes(), a2.as_bytes(), "same ctx+ikm must match");
        assert_ne!(
            a.as_bytes(),
            b.as_bytes(),
            "distinct contexts must separate"
        );
    }

    #[test]
    fn keyed_hash_matches_blake3_reference() {
        // Pin against a direct blake3 call so a dependency swap that changed
        // the mapping would be caught here as well as in the KAT.
        let key = [2u8; 32];
        let msg = b"cipherbox";
        assert_eq!(
            keyed_hash(&key, msg).as_bytes(),
            blake3::keyed_hash(&key, msg).as_bytes()
        );
    }
}
