//! RFC 9180 HPKE, single-shot, in base mode (blueprint/core.md "Crypto suite":
//! sealing to a person — grant blobs, owner blob, ascent links, mailbox
//! payloads) and auth mode (the durable op record, sealed to self).
//!
//! Base mode authenticates the *ciphertext*, not the *sender*: the recipient key
//! is public, so anyone can produce a ciphertext that opens. Auth mode (§5.1.1)
//! folds a static sender DH into the KEM, so opening proves the holder of that
//! sender secret produced the bytes. Sealing to self makes that static DH
//! `[a²]G`, so an outsider forging one solves square-CDH rather than the RFC's
//! independent-key-pair CDH; the two are equivalent (Maurer-Wolf).
//!
//! Ciphersuite: KEM = DHKEM(X25519, HKDF-SHA256), KDF = HKDF-SHA256, AEAD =
//! XChaCha20-Poly1305. XChaCha is not an IANA-registered HPKE AEAD, so this
//! crate assigns it the private-use id [`AEAD_ID_XCHACHA`], frozen in the KAT
//! manifest (the eciesjs lesson: a full-envelope KAT under a fixed ephemeral
//! key must pin the wire format so a dependency bump can never silently orphan
//! stored ciphertexts).
//!
//! Determinism (blueprint/core.md "Doctrine"): the sender's ephemeral secret is
//! an injected parameter, never sampled here — so seal is a pure function and
//! every path is KAT-able. The KEM and key schedule are validated against
//! RFC 9180 Appendix A.1.1 (base) and A.1.3 (auth) vectors in the tests below
//! (byte-for-byte on `enc`, `shared_secret`, `key`, `base_nonce`,
//! `exporter_secret`); the XChaCha substitution is a change of AEAD id and
//! nonce width over that same validated pipeline.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::aead;
use super::secret::SecretBytes;
use super::x25519::{X25519Public, X25519Secret};
use crate::error::TrustViolation;

/// KEM id: DHKEM(X25519, HKDF-SHA256).
const KEM_ID: u16 = 0x0020;
/// KDF id: HKDF-SHA256.
const KDF_ID: u16 = 0x0001;
/// CipherBox's private-use AEAD id for XChaCha20-Poly1305 in HPKE. Frozen in
/// the KAT manifest; RFC 9180 registers no id for XChaCha.
pub const AEAD_ID_XCHACHA: u16 = 0x8000;

/// RFC 9180 §5.1 mode ids.
const MODE_BASE: u8 = 0x00;
/// Frozen in the KAT manifest as the op record's mode.
pub const MODE_AUTH: u8 = 0x02;

/// DHKEM(X25519) shared-secret length (`Nsecret`).
const NSECRET: usize = 32;
/// HKDF-SHA256 output length (`Nh`).
const NH: usize = 32;
/// Length of an encapsulated key (X25519 public key).
pub const ENC_LEN: usize = 32;

/// The output of a single-shot seal: the encapsulated key and the AEAD
/// ciphertext (`ciphertext || tag`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeCiphertext {
    /// The encapsulated ephemeral public key.
    pub enc: [u8; ENC_LEN],
    /// The XChaCha20-Poly1305 ciphertext with its appended tag.
    pub ciphertext: Vec<u8>,
}

/// Seal `plaintext` to `recipient_pub` under HPKE base mode. `ephemeral_scalar`
/// is the injected 32-byte ephemeral secret (X25519 clamps it), making the
/// whole operation deterministic.
///
/// # Security — ephemeral scalar uniqueness (caller invariant)
///
/// `ephemeral_scalar` **must be fresh, uniformly-random 32 bytes on every
/// call.** Reusing it across two different plaintexts for the same
/// `recipient_pub`/`info` re-derives the identical AEAD key **and** base nonce,
/// and XChaCha20-Poly1305 under a repeated (key, nonce) is a catastrophic
/// break. Core cannot sample entropy or enforce this (determinism
/// doctrine), so the engine seam that calls `hpke_seal` owns the invariant: the
/// ephemeral is in the same *random-per-use* class as content keys, **not** a
/// KDF-catalog edge. KATs reuse a fixed scalar only because they seal one fixed
/// plaintext per scalar.
pub fn hpke_seal(
    recipient_pub: &X25519Public,
    ephemeral_scalar: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> HpkeCiphertext {
    let (shared, enc) = dhkem_encap(recipient_pub, ephemeral_scalar);
    HpkeCiphertext {
        enc,
        ciphertext: seal_under(&shared, MODE_BASE, info, aad, plaintext),
    }
}

/// Open an HPKE ciphertext with the recipient's secret. Fails closed with
/// [`TrustViolation::HpkeOpenFailed`] when the AEAD tag does not verify (a tag
/// mismatch means tampering or an `enc`/AAD transplant, never staleness).
pub fn hpke_open(
    recipient_secret: &X25519Secret,
    enc: &[u8; ENC_LEN],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TrustViolation> {
    let shared = dhkem_decap(recipient_secret, enc)?;
    open_under(&shared, MODE_BASE, info, aad, ciphertext)
}

/// Seal `plaintext` to `recipient_pub` under HPKE **auth mode** (RFC 9180
/// §5.1.1), naming `sender_secret` as the static sender. The recipient recovers
/// the plaintext only by re-deriving the sender's static DH, so opening proves
/// the holder of `sender_secret` produced these bytes.
///
/// [`hpke_seal`]'s `ephemeral_scalar` freshness invariant applies unchanged —
/// the static DH is a constant for a fixed key pair.
pub(crate) fn hpke_seal_auth(
    sender_secret: &X25519Secret,
    recipient_pub: &X25519Public,
    ephemeral_scalar: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> HpkeCiphertext {
    let (shared, enc) = dhkem_auth_encap(recipient_pub, ephemeral_scalar, sender_secret);
    HpkeCiphertext {
        enc,
        ciphertext: seal_under(&shared, MODE_AUTH, info, aad, plaintext),
    }
}

/// Open an auth-mode ciphertext, requiring `sender_pub` to be the static sender.
///
/// A wrong sender is cryptographically indistinguishable from tampering — both
/// derive a different shared secret and fail the AEAD tag — so both fail closed
/// with [`TrustViolation::HpkeOpenFailed`]. A failure here is a forged or
/// tampered ciphertext, never staleness.
///
/// # Security — sender key provenance (caller invariant)
///
/// `sender_pub` must be a key the caller **already trusts**: its own, or one
/// pinned by a grant or contact code. Reading it out of the framing around the
/// ciphertext reduces auth mode to base mode — an attacker seals under their
/// own key, stamps their own `pkS`, and the open succeeds.
pub(crate) fn hpke_open_auth(
    recipient_secret: &X25519Secret,
    sender_pub: &X25519Public,
    enc: &[u8; ENC_LEN],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TrustViolation> {
    let shared = dhkem_auth_decap(recipient_secret, enc, sender_pub)?;
    open_under(&shared, MODE_AUTH, info, aad, ciphertext)
}

/// The AEAD half of a single-shot seal at seq 0, shared by both modes.
fn seal_under(
    shared: &SecretBytes,
    mode: u8,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let (key, nonce) = seq0_key_and_nonce(shared, mode, info);
    aead::encrypt(&key, &nonce, aad, plaintext)
}

fn open_under(
    shared: &SecretBytes,
    mode: u8,
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TrustViolation> {
    let (key, nonce) = seq0_key_and_nonce(shared, mode, info);
    aead::decrypt(&key, &nonce, aad, ciphertext)
        .map(Zeroizing::new)
        .ok_or(TrustViolation::HpkeOpenFailed)
}

fn seq0_key_and_nonce(
    shared: &SecretBytes,
    mode: u8,
    info: &[u8],
) -> (Zeroizing<[u8; aead::KEY_LEN]>, [u8; aead::NONCE_LEN]) {
    let ks = key_schedule(
        mode,
        shared.as_bytes(),
        info,
        AEAD_ID_XCHACHA,
        aead::KEY_LEN,
        aead::NONCE_LEN,
    );
    (
        Zeroizing::new(ks.key[..].try_into().expect("Nk == KEY_LEN")),
        ks.base_nonce[..].try_into().expect("Nn == NONCE_LEN"),
    )
}

// ---------------------------------------------------------------------------
// RFC 9180 §4-5 internals. pub(crate) so the conformance tests can drive the
// KEM and key schedule directly with the published intermediate values.
// ---------------------------------------------------------------------------

/// `KEM` suite id: `"KEM" || I2OSP(kem_id, 2)`.
fn kem_suite_id() -> [u8; 5] {
    let mut id = [0u8; 5];
    id[..3].copy_from_slice(b"KEM");
    id[3..].copy_from_slice(&KEM_ID.to_be_bytes());
    id
}

/// Key-schedule suite id: `"HPKE" || kem_id || kdf_id || aead_id`.
fn ks_suite_id(aead_id: u16) -> [u8; 10] {
    let mut id = [0u8; 10];
    id[..4].copy_from_slice(b"HPKE");
    id[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    id[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    id[8..].copy_from_slice(&aead_id.to_be_bytes());
    id
}

/// RFC 9180 `LabeledExtract(salt, label, ikm)` with HKDF-SHA256.
fn labeled_extract(salt: &[u8], suite_id: &[u8], label: &[u8], ikm: &[u8]) -> [u8; NH] {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    // The scratch buffer copies `ikm` verbatim — in the KEM path that is the DH
    // shared secret — so wipe it before it drops.
    labeled_ikm.zeroize();
    prk.into()
}

/// RFC 9180 `LabeledExpand(prk, label, info, L)` with HKDF-SHA256.
fn labeled_expand(
    prk: &[u8; NH],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Vec<u8> {
    let mut labeled_info = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("Nh-length prk is a valid HKDF prk");
    let mut okm = vec![0u8; length];
    hk.expand(&labeled_info, &mut okm)
        .expect("length is far below HKDF's 255*Nh ceiling");
    okm
}

/// DHKEM `ExtractAndExpand(dh, kem_context)`.
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> SecretBytes {
    let suite = kem_suite_id();
    // The PRK recovers the DH shared secret, so keep it in a zeroizing binding.
    let eae_prk = Zeroizing::new(labeled_extract(b"", &suite, b"eae_prk", dh));
    let shared = Zeroizing::new(labeled_expand(
        &eae_prk,
        &suite,
        b"shared_secret",
        kem_context,
        NSECRET,
    ));
    SecretBytes::new(shared[..].try_into().expect("Nsecret == SECRET_LEN"))
}

/// DHKEM `Encap(pkR)` with an injected ephemeral scalar. Infallible: `pk_r` is a
/// validated [`X25519Public`] (never low-order), so the exchange is always
/// contributory.
pub(crate) fn dhkem_encap(
    pk_r: &X25519Public,
    ephemeral_scalar: &[u8; 32],
) -> (SecretBytes, [u8; ENC_LEN]) {
    let sk_e = X25519Secret::from_scalar(*ephemeral_scalar);
    let enc = sk_e.public().to_bytes();
    // Sound only while every `X25519Public` is built through the low-order-
    // rejecting `from_bytes`; a constructor that bypasses it needs a re-audit.
    let dh = sk_e
        .diffie_hellman(pk_r)
        .expect("recipient key is validated non-low-order, so ECDH is contributory");
    (
        extract_and_expand(dh.as_bytes(), &kem_context(&enc, pk_r, None)),
        enc,
    )
}

/// DHKEM `AuthEncap(pkR, skS)` (RFC 9180 §4.1) with an injected ephemeral
/// scalar: the ephemeral DH concatenated with the static sender DH, and `pkS`
/// appended to the KEM context. Infallible for the same reason as
/// [`dhkem_encap`] — both peers are validated [`X25519Public`]s.
pub(crate) fn dhkem_auth_encap(
    pk_r: &X25519Public,
    ephemeral_scalar: &[u8; 32],
    sk_s: &X25519Secret,
) -> (SecretBytes, [u8; ENC_LEN]) {
    let sk_e = X25519Secret::from_scalar(*ephemeral_scalar);
    let enc = sk_e.public().to_bytes();
    let contributory = "recipient key is validated non-low-order, so ECDH is contributory";
    let dh_e = sk_e.diffie_hellman(pk_r).expect(contributory);
    let dh_s = sk_s.diffie_hellman(pk_r).expect(contributory);
    let mut dh = Zeroizing::new(Vec::with_capacity(2 * NSECRET));
    dh.extend_from_slice(dh_e.as_bytes());
    dh.extend_from_slice(dh_s.as_bytes());
    let pk_s = sk_s.public();
    (
        extract_and_expand(&dh, &kem_context(&enc, pk_r, Some(&pk_s))),
        enc,
    )
}

/// `kem_context = enc || pkRm [|| pkSm]` — the sender key is appended in auth
/// mode only (RFC 9180 §4.1).
fn kem_context(enc: &[u8; ENC_LEN], pk_r: &X25519Public, pk_s: Option<&X25519Public>) -> Vec<u8> {
    let mut ctx = Vec::with_capacity((2 + usize::from(pk_s.is_some())) * ENC_LEN);
    ctx.extend_from_slice(enc);
    ctx.extend_from_slice(&pk_r.to_bytes());
    if let Some(pk_s) = pk_s {
        ctx.extend_from_slice(&pk_s.to_bytes());
    }
    ctx
}

/// DHKEM `Decap(enc, skR)`. Fails closed with
/// [`TrustViolation::HpkeNonContributory`] when the peer `enc` is a low-order
/// point (rejected at the constructor) or otherwise yields a non-contributory
/// shared secret (RFC 9180 §7.1.4) — a forced-known-secret / key-substitution
/// attack, not staleness.
pub(crate) fn dhkem_decap(
    sk_r: &X25519Secret,
    enc: &[u8; ENC_LEN],
) -> Result<SecretBytes, TrustViolation> {
    let pk_e = X25519Public::from_bytes(*enc).ok_or(TrustViolation::HpkeNonContributory)?;
    let dh = sk_r
        .diffie_hellman(&pk_e)
        .ok_or(TrustViolation::HpkeNonContributory)?;
    Ok(extract_and_expand(
        dh.as_bytes(),
        &kem_context(enc, &sk_r.public(), None),
    ))
}

/// DHKEM `AuthDecap(enc, skR, pkS)` (RFC 9180 §4.1). Fails closed with
/// [`TrustViolation::HpkeNonContributory`] when either DH is non-contributory.
pub(crate) fn dhkem_auth_decap(
    sk_r: &X25519Secret,
    enc: &[u8; ENC_LEN],
    pk_s: &X25519Public,
) -> Result<SecretBytes, TrustViolation> {
    let pk_e = X25519Public::from_bytes(*enc).ok_or(TrustViolation::HpkeNonContributory)?;
    let dh_e = sk_r
        .diffie_hellman(&pk_e)
        .ok_or(TrustViolation::HpkeNonContributory)?;
    let dh_s = sk_r
        .diffie_hellman(pk_s)
        .ok_or(TrustViolation::HpkeNonContributory)?;
    let mut dh = Zeroizing::new(Vec::with_capacity(2 * NSECRET));
    dh.extend_from_slice(dh_e.as_bytes());
    dh.extend_from_slice(dh_s.as_bytes());
    Ok(extract_and_expand(
        &dh,
        &kem_context(enc, &sk_r.public(), Some(pk_s)),
    ))
}

/// The key schedule outputs (seq 0). `key`/`base_nonce` seal; the
/// exporter secret is derived only so the RFC 9180 A.1 conformance test can
/// pin it.
pub(crate) struct KeySchedule {
    pub key: Zeroizing<Vec<u8>>,
    // Not secret — the AEAD authenticates it, so no zeroizing owner.
    pub base_nonce: Vec<u8>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub exporter_secret: Zeroizing<Vec<u8>>,
}

/// RFC 9180 `KeySchedule(mode, shared_secret, info, "", "")` — the mode byte is
/// the first thing bound into the key-schedule context, so a base-mode and an
/// auth-mode ciphertext under one shared secret never share an AEAD key.
pub(crate) fn key_schedule(
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    aead_id: u16,
    nk: usize,
    nn: usize,
) -> KeySchedule {
    let suite = ks_suite_id(aead_id);
    // psk_id = "" and psk = "" — no PSK mode.
    let psk_id_hash = labeled_extract(b"", &suite, b"psk_id_hash", b"");
    let info_hash = labeled_extract(b"", &suite, b"info_hash", info);
    let mut ksc = Vec::with_capacity(1 + 2 * NH);
    ksc.push(mode);
    ksc.extend_from_slice(&psk_id_hash);
    ksc.extend_from_slice(&info_hash);

    // `secret` is the parent of the AEAD key and the exporter secret, so it is
    // as sensitive as they are — keep it zeroized for its whole lifetime.
    let secret = Zeroizing::new(labeled_extract(shared_secret, &suite, b"secret", b""));
    KeySchedule {
        key: Zeroizing::new(labeled_expand(&secret, &suite, b"key", &ksc, nk)),
        base_nonce: labeled_expand(&secret, &suite, b"base_nonce", &ksc, nn),
        exporter_secret: Zeroizing::new(labeled_expand(&secret, &suite, b"exp", &ksc, NH)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn arr32(s: &str) -> [u8; 32] {
        unhex(s).try_into().expect("32 bytes")
    }

    /// RFC 9180 Appendix A.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    /// AES-128-GCM), base setup. AES is not implemented here, but the KEM and
    /// the entire labeled KDF / key schedule are AEAD-independent byte outputs,
    /// so `enc`, `shared_secret`, `key`, `base_nonce`, and `exporter_secret`
    /// are validated directly — pinning the hand-written RFC 9180 pipeline to
    /// the official vectors.
    #[test]
    fn rfc9180_a1_kem_and_key_schedule() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let sk_em = arr32("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        let pk_rm = arr32("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let sk_rm = arr32("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        let expected_enc =
            arr32("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        let expected_shared =
            arr32("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");

        // KEM: Encap under the fixed ephemeral scalar.
        let pk_r = X25519Public::from_bytes(pk_rm).expect("A.1 recipient key");
        let (shared, enc) = dhkem_encap(&pk_r, &sk_em);
        assert_eq!(enc, expected_enc, "A.1 enc");
        assert_eq!(shared.as_bytes(), &expected_shared, "A.1 shared_secret");

        // KEM: Decap recovers the same shared secret.
        let sk_r = X25519Secret::from_scalar(sk_rm);
        assert_eq!(
            dhkem_decap(&sk_r, &enc).expect("A.1 decap").as_bytes(),
            &expected_shared,
            "A.1 decap shared_secret"
        );

        // Key schedule with aead_id = 0x0001 (AES-128-GCM): Nk = 16, Nn = 12.
        let ks = key_schedule(MODE_BASE, shared.as_bytes(), &info, 0x0001, 16, 12);
        assert_eq!(
            *ks.key,
            unhex("4531685d41d65f03dc48f6b8302c05b0"),
            "A.1 key"
        );
        assert_eq!(
            ks.base_nonce,
            unhex("56d890e5accaaf011cff4b7d"),
            "A.1 base_nonce"
        );
        assert_eq!(
            *ks.exporter_secret,
            unhex("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"),
            "A.1 exporter_secret"
        );
    }

    /// RFC 9180 Appendix A.1.3, the same suite in **mode_auth**. Pins
    /// `AuthEncap`/`AuthDecap` — the two-DH concatenation and the `enc || pkRm
    /// || pkSm` KEM context — and the `0x02` mode byte in the key schedule.
    #[test]
    fn rfc9180_a13_auth_kem_and_key_schedule() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let sk_em = arr32("ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518");
        let pk_rm = arr32("1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e");
        let sk_rm = arr32("fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e");
        let pk_sm = arr32("8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b");
        let sk_sm = arr32("dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd");
        let expected_enc =
            arr32("23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76");
        let expected_shared =
            arr32("2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7");

        let pk_r = X25519Public::from_bytes(pk_rm).expect("A.1.3 recipient key");
        let sk_s = X25519Secret::from_scalar(sk_sm);
        assert_eq!(sk_s.public().to_bytes(), pk_sm, "A.1.3 pkSm");

        let (shared, enc) = dhkem_auth_encap(&pk_r, &sk_em, &sk_s);
        assert_eq!(enc, expected_enc, "A.1.3 enc");
        assert_eq!(shared.as_bytes(), &expected_shared, "A.1.3 shared_secret");

        let sk_r = X25519Secret::from_scalar(sk_rm);
        assert_eq!(
            dhkem_auth_decap(&sk_r, &enc, &sk_s.public())
                .expect("A.1.3 auth decap")
                .as_bytes(),
            &expected_shared,
            "A.1.3 auth decap shared_secret"
        );

        let ks = key_schedule(MODE_AUTH, shared.as_bytes(), &info, 0x0001, 16, 12);
        assert_eq!(
            *ks.key,
            unhex("b062cb2c4dd4bca0ad7c7a12bbc341e6"),
            "A.1.3 key"
        );
        assert_eq!(
            ks.base_nonce,
            unhex("a1bc314c1942ade7051ffed0"),
            "A.1.3 base_nonce"
        );
        assert_eq!(
            *ks.exporter_secret,
            unhex("ee1a093e6e1c393c162ea98fdf20560c75909653550540a2700511b65c88c6f1"),
            "A.1.3 exporter_secret"
        );
    }

    #[test]
    fn seal_open_round_trip_and_determinism() {
        let recipient = X25519Secret::from_scalar([7u8; 32]);
        let eph = [9u8; 32];
        let sealed = hpke_seal(&recipient.public(), &eph, b"info", b"aad", b"grant blob");
        // Deterministic under a fixed ephemeral scalar.
        assert_eq!(
            hpke_seal(&recipient.public(), &eph, b"info", b"aad", b"grant blob"),
            sealed
        );
        let opened = hpke_open(&recipient, &sealed.enc, b"info", b"aad", &sealed.ciphertext)
            .expect("round trip opens");
        assert_eq!(&opened[..], b"grant blob");
    }

    #[test]
    fn open_fails_closed_on_tamper_and_context_mismatch() {
        let recipient = X25519Secret::from_scalar([7u8; 32]);
        let sealed = hpke_seal(&recipient.public(), &[9u8; 32], b"info", b"aad", b"secret");

        // Tampered ciphertext.
        let mut ct = sealed.ciphertext.clone();
        ct[0] ^= 0x01;
        assert_eq!(
            hpke_open(&recipient, &sealed.enc, b"info", b"aad", &ct).unwrap_err(),
            TrustViolation::HpkeOpenFailed
        );
        // Wrong AAD.
        assert!(
            hpke_open(
                &recipient,
                &sealed.enc,
                b"info",
                b"other",
                &sealed.ciphertext
            )
            .is_err()
        );
        // Wrong info.
        assert!(
            hpke_open(
                &recipient,
                &sealed.enc,
                b"other",
                b"aad",
                &sealed.ciphertext
            )
            .is_err()
        );
        // Wrong recipient.
        let other = X25519Secret::from_scalar([8u8; 32]);
        assert!(hpke_open(&other, &sealed.enc, b"info", b"aad", &sealed.ciphertext).is_err());
    }

    #[test]
    fn low_order_enc_rejects_as_non_contributory() {
        // A low-order `enc` forces an all-zero DH; decap must fail closed before
        // the AEAD open (RFC 9180 §7.1.4), distinct from a tag mismatch.
        let recipient = X25519Secret::from_scalar([7u8; 32]);
        let low_order = arr32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        assert_eq!(
            dhkem_decap(&recipient, &low_order).unwrap_err(),
            TrustViolation::HpkeNonContributory
        );
        assert_eq!(
            hpke_open(&recipient, &low_order, b"info", b"aad", b"whatever").unwrap_err(),
            TrustViolation::HpkeNonContributory
        );
    }

    #[test]
    fn auth_seal_open_round_trips_and_is_deterministic() {
        let sender = X25519Secret::from_scalar([3u8; 32]);
        let recipient = X25519Secret::from_scalar([7u8; 32]);
        let eph = [9u8; 32];
        let sealed = hpke_seal_auth(
            &sender,
            &recipient.public(),
            &eph,
            b"info",
            b"aad",
            b"op intent",
        );
        assert_eq!(
            hpke_seal_auth(
                &sender,
                &recipient.public(),
                &eph,
                b"info",
                b"aad",
                b"op intent"
            ),
            sealed
        );
        let opened = hpke_open_auth(
            &recipient,
            &sender.public(),
            &sealed.enc,
            b"info",
            b"aad",
            &sealed.ciphertext,
        )
        .expect("auth round trip opens");
        assert_eq!(&opened[..], b"op intent");
    }

    #[test]
    fn auth_open_fails_closed_on_a_wrong_sender() {
        let sender = X25519Secret::from_scalar([3u8; 32]);
        let recipient = X25519Secret::from_scalar([7u8; 32]);
        let sealed = hpke_seal_auth(
            &sender,
            &recipient.public(),
            &[9u8; 32],
            b"info",
            b"aad",
            b"op intent",
        );
        let impostor = X25519Secret::from_scalar([4u8; 32]);
        assert_eq!(
            hpke_open_auth(
                &recipient,
                &impostor.public(),
                &sealed.enc,
                b"info",
                b"aad",
                &sealed.ciphertext
            )
            .unwrap_err(),
            TrustViolation::HpkeOpenFailed
        );
    }

    #[test]
    fn a_base_mode_ciphertext_never_opens_as_auth_mode() {
        let recipient = X25519Secret::from_scalar([7u8; 32]);
        let forged = hpke_seal(&recipient.public(), &[9u8; 32], b"info", b"aad", b"forged");
        assert_eq!(
            hpke_open_auth(
                &recipient,
                &recipient.public(),
                &forged.enc,
                b"info",
                b"aad",
                &forged.ciphertext
            )
            .unwrap_err(),
            TrustViolation::HpkeOpenFailed
        );
    }

    #[test]
    fn a_low_order_enc_rejects_in_auth_mode_too() {
        let recipient = X25519Secret::from_scalar([7u8; 32]);
        let sealed = hpke_seal_auth(
            &recipient,
            &recipient.public(),
            &[9u8; 32],
            b"info",
            b"aad",
            b"op intent",
        );
        let low_order = arr32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        assert_eq!(
            dhkem_auth_decap(&recipient, &low_order, &recipient.public()).unwrap_err(),
            TrustViolation::HpkeNonContributory
        );
        assert_eq!(
            hpke_open_auth(
                &recipient,
                &recipient.public(),
                &low_order,
                b"info",
                b"aad",
                &sealed.ciphertext
            )
            .unwrap_err(),
            TrustViolation::HpkeNonContributory
        );

        // The sender half has its own contributory backstop. `from_bytes`
        // guards the encoding, so drive the peer through dalek's total type.
        let low_order_sender = crate::suite::x25519::testonly_public_from_bytes(low_order);
        assert_eq!(
            dhkem_auth_decap(&recipient, &sealed.enc, &low_order_sender).unwrap_err(),
            TrustViolation::HpkeNonContributory
        );
    }

    #[test]
    fn an_auth_mode_ciphertext_never_opens_as_base_mode() {
        let owner = X25519Secret::from_scalar([7u8; 32]);
        let sealed = hpke_seal_auth(
            &owner,
            &owner.public(),
            &[9u8; 32],
            b"info",
            b"aad",
            b"op intent",
        );
        assert_eq!(
            hpke_open(&owner, &sealed.enc, b"info", b"aad", &sealed.ciphertext).unwrap_err(),
            TrustViolation::HpkeOpenFailed
        );
    }
}
