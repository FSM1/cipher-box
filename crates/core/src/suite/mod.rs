//! The crypto suite: primitive bindings (blueprint/core.md "Crypto suite").
//!
//! Pure RustCrypto / dalek-family primitives, constant-time where the primitive
//! is, with all key material in zeroizing owning types ([`secret::SecretBytes`]
//! and the key wrappers here) — type-enforced, never comment-enforced. Entropy
//! is injected (HPKE's ephemeral scalar, every keypair seed), never sampled;
//! this layer holds no state and reads no clock.
//!
//! Primitives only: XChaCha20-Poly1305 ([`aead`]), BLAKE3 ([`hash`]), X25519
//! ([`x25519`]) and RFC 9180 HPKE ([`hpke`]), secp256k1 ECDSA ([`ecdsa`]) and
//! ECIES ([`ecies`]),
//! Ed25519 ([`ed25519`]), and the encryption-subkey binding + contact code
//! codec ([`contact`]). The CipherBox seal/unseal layer — structured AAD,
//! envelope framing, structure signatures — is [`crate::seal`].

pub mod aead;
pub mod contact;
pub mod ecdsa;
pub mod ecies;
pub mod ed25519;
pub mod hash;
pub mod hpke;
pub mod secret;
pub mod x25519;
