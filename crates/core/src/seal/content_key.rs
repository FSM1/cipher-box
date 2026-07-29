//! The staged content-key blob: one version's random content key, sealed to the
//! owner's own enc subkey while the version waits in the op queue
//! (blueprint/engine.md "Content plane"; CONTEXT.md "Content key").
//!
//! A content key is a KDF **non-edge** — random per version, never derivable —
//! so between sealing the blocks and publishing the version something durable
//! must carry it, or the staged bytes become permanently unopenable. It rides
//! the op sealed under the enc subkey, which comes from the login secret and is
//! therefore epoch-independent: available on exactly the sessions that can run a
//! drain.
//!
//! What makes a blob non-transplantable: HPKE **auth mode to self** closes it
//! across accounts; the version's **`contentCid`** rides the sealed payload and
//! is re-checked against the caller's expectation on open, closing it across
//! versions; and the **scope and epoch** ride the AAD as values rather than key
//! inputs, closing it across scopes and epochs while leaving a rotation unable
//! to strand a queued version — content bytes are never re-encrypted by any
//! rotation path. Its own structure tag keeps it distinct from every other
//! structure sealed under the same key.

use zeroize::Zeroizing;

use crate::codec::{Map, Value, decode, encode, encode_fixed_depth};
use crate::content::is_wellformed_content_cid;
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::seal::aad::{AAD_DOMAIN, STRUCT_TAG_CONTENT_KEY};
use crate::seal::body::{ScrubOnDrop, ScrubOwned, bytes_fixed, req};
use crate::suite::hpke::{self, ENC_LEN};
use crate::suite::secret::SECRET_LEN;
use crate::suite::x25519::X25519Secret;

/// The content-key blob format version this build writes and can open. Bound
/// into the AAD, so a rewritten declaration fails the tag.
pub const CONTENT_KEY_V: u64 = 1;

/// The HPKE `info` string — the key-schedule domain separator, distinct from the
/// op-record's and the grant family's so structures sealed to one enc subkey are
/// never mutually transplantable. Frozen in the KAT manifest.
pub const CONTENT_KEY_HPKE_INFO: &[u8] = b"cipherbox/v2/content-key";

/// The three frame keys, exhaustive at [`CONTENT_KEY_V`].
const FRAME_KEYS: [&str; 3] = ["ciphertext", "enc", "v"];

/// The AAD of a content-key blob: the `cipherbox/v2` domain separator, the
/// format version, the structure tag, and the `{scope, epoch}` the version is
/// authored at. A five-element array whose third element is a tag no other
/// structure carries.
pub fn content_key_aad(scope: &[u8; 16], epoch: u64) -> Vec<u8> {
    encode_fixed_depth(&Value::Array(vec![
        Value::Text(AAD_DOMAIN.to_string()),
        Value::Unsigned(CONTENT_KEY_V),
        Value::Unsigned(u64::from(STRUCT_TAG_CONTENT_KEY)),
        Value::Bytes(scope.to_vec()),
        Value::Unsigned(epoch),
    ]))
}

/// The invariant both directions enforce (AGENTS.md rule 8): a content-key blob
/// only ever names a well-formed content CID. Release-active on the seal path —
/// a blob whose CID the open path refuses is a version whose key is gone.
fn check_content_cid(content_cid: &[u8]) -> Result<(), CodecError> {
    if is_wellformed_content_cid(content_cid) {
        Ok(())
    } else {
        Err(TrustViolation::ContentCidMismatch.into())
    }
}

/// Seal `content_key` for the version addressed by `content_cid`, to the owner's
/// own enc subkey with that same key as the HPKE static sender — so only the
/// secret's holder can author one.
///
/// `ephemeral_scalar` must be **fresh per blob**: HPKE ephemeral reuse across
/// two seals under one recipient key is a confidentiality break
/// ([`hpke::hpke_seal_auth`]).
pub fn seal_content_key(
    owner_enc_secret: &X25519Secret,
    ephemeral_scalar: &[u8; 32],
    scope: &[u8; 16],
    epoch: u64,
    content_cid: &[u8],
    content_key: &[u8; SECRET_LEN],
) -> Result<Vec<u8>, CodecError> {
    check_content_cid(content_cid)?;
    let mut payload = Value::Map({
        let mut m = Map::new();
        m.insert("contentCid", Value::Bytes(content_cid.to_vec()));
        m.insert("key", Value::Bytes(content_key.to_vec()));
        m
    });
    // The transient tree holds a verbatim copy of the key; scrub it on every
    // return path and on unwind (terminal-owner rule).
    let plaintext = {
        let guard = ScrubOnDrop(&mut payload);
        Zeroizing::new(encode(guard.0)?)
    };
    let sealed = hpke::hpke_seal_auth(
        owner_enc_secret,
        &owner_enc_secret.public(),
        ephemeral_scalar,
        CONTENT_KEY_HPKE_INFO,
        &content_key_aad(scope, epoch),
        &plaintext,
    );
    let mut m = Map::new();
    m.insert("ciphertext", Value::Bytes(sealed.ciphertext));
    m.insert("enc", Value::Bytes(sealed.enc.to_vec()));
    m.insert("v", Value::Unsigned(CONTENT_KEY_V));
    encode(&Value::Map(m))
}

/// Open a content-key blob authored at `epoch` for the version addressed by
/// `content_cid`.
///
/// Fails closed with [`Malformed::UnsupportedRecordVersion`] on a version this
/// build does not implement, and with [`TrustViolation::HpkeOpenFailed`] when
/// the blob is another identity's, tampered, or authored at another epoch. A
/// blob that opens but names a different version fails with
/// [`TrustViolation::ContentCidMismatch`] — the sealed CID is the binding that
/// stops a key being moved onto another version's blocks.
pub fn open_content_key(
    owner_enc_secret: &X25519Secret,
    scope: &[u8; 16],
    epoch: u64,
    content_cid: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<[u8; SECRET_LEN]>, CodecError> {
    check_content_cid(content_cid)?;
    let value = decode(sealed)?;
    let map = value.as_map()?;
    // Version first, like the op record's: a blob a newer build wrote must be
    // classified as unimplemented, never as any value-level grammar failure —
    // the caller retains it on the former and destroys it on the latter.
    let version = req(map, "v")?.as_unsigned()?;
    if version != CONTENT_KEY_V {
        return Err(Malformed::UnsupportedRecordVersion { version }.into());
    }
    if let Some((key, _)) = map
        .entries()
        .iter()
        .find(|(key, _)| !FRAME_KEYS.contains(&key.as_str()))
    {
        return Err(Malformed::UnknownRecordField { key: key.clone() }.into());
    }
    let enc = bytes_fixed::<ENC_LEN>(req(map, "enc")?, "enc")?;
    let ciphertext = req(map, "ciphertext")?.as_bytes()?;
    // Sender = recipient: the caller's own key.
    let plaintext = hpke::hpke_open_auth(
        owner_enc_secret,
        &owner_enc_secret.public(),
        &enc,
        CONTENT_KEY_HPKE_INFO,
        &content_key_aad(scope, epoch),
        ciphertext,
    )?;

    let payload = ScrubOwned(decode(&plaintext)?);
    let payload = payload.value().as_map()?;
    if req(payload, "contentCid")?.as_bytes()? != content_cid {
        return Err(TrustViolation::ContentCidMismatch.into());
    }
    Ok(Zeroizing::new(bytes_fixed::<SECRET_LEN>(
        req(payload, "key")?,
        "key",
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{CONTENT_CID_CODEC, compute_cid};

    fn secret(b: u8) -> X25519Secret {
        X25519Secret::from_scalar([b; 32])
    }

    fn cid(seed: &[u8]) -> Vec<u8> {
        compute_cid(CONTENT_CID_CODEC, seed)
    }

    const KEY: [u8; SECRET_LEN] = [0x5a; SECRET_LEN];
    const SCOPE: [u8; 16] = [0xC0; 16];

    #[test]
    fn a_blob_round_trips_under_its_own_epoch_and_version() {
        let owner = secret(1);
        let root = cid(b"root block");
        let sealed = seal_content_key(&owner, &[2; 32], &SCOPE, 7, &root, &KEY).unwrap();
        assert_eq!(
            *open_content_key(&owner, &SCOPE, 7, &root, &sealed).unwrap(),
            KEY,
            "the sealed key comes back verbatim"
        );
    }

    #[test]
    fn another_identity_never_opens_it() {
        let owner = secret(3);
        let root = cid(b"root block");
        let sealed = seal_content_key(&owner, &[4; 32], &SCOPE, 1, &root, &KEY).unwrap();
        assert_eq!(
            open_content_key(&secret(5), &SCOPE, 1, &root, &sealed)
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn a_blob_replayed_at_another_epoch_fails_closed() {
        let owner = secret(6);
        let root = cid(b"root block");
        let sealed = seal_content_key(&owner, &[7; 32], &SCOPE, 2, &root, &KEY).unwrap();
        assert_eq!(
            open_content_key(&owner, &SCOPE, 3, &root, &sealed)
                .unwrap_err()
                .check(),
            "hpke-open-failed",
            "the epoch is AAD-bound, so it cannot be re-dated"
        );
    }

    #[test]
    fn a_blob_replayed_in_another_scope_fails_closed() {
        let owner = secret(24);
        let root = cid(b"root block");
        let sealed = seal_content_key(&owner, &[25; 32], &SCOPE, 1, &root, &KEY).unwrap();
        assert_eq!(
            open_content_key(&owner, &[0xD0; 16], 1, &root, &sealed)
                .unwrap_err()
                .check(),
            "hpke-open-failed",
            "the scope is AAD-bound, so a blob cannot cross scopes"
        );
    }

    #[test]
    fn a_blob_moved_onto_another_version_fails_closed() {
        let owner = secret(8);
        let sealed = seal_content_key(&owner, &[9; 32], &SCOPE, 1, &cid(b"mine"), &KEY).unwrap();
        assert_eq!(
            open_content_key(&owner, &SCOPE, 1, &cid(b"theirs"), &sealed)
                .unwrap_err()
                .check(),
            "content-cid-mismatch",
            "the sealed contentCid binds the key to the blocks it opens"
        );
    }

    #[test]
    fn a_malformed_content_cid_is_refused_at_seal_in_every_build() {
        // The encode-side half of the open path's own reject (rule 8): a blob
        // naming a CID the reader refuses would strand the version's key.
        assert_eq!(
            seal_content_key(&secret(10), &[11; 32], &SCOPE, 1, b"not a cid", &KEY)
                .unwrap_err()
                .check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn a_tampered_blob_fails_closed() {
        let owner = secret(12);
        let root = cid(b"root block");
        let sealed = seal_content_key(&owner, &[13; 32], &SCOPE, 1, &root, &KEY).unwrap();
        let value = decode(&sealed).unwrap();
        let mut map = value.as_map().unwrap().clone();
        let mut ct = map.get("ciphertext").unwrap().as_bytes().unwrap().to_vec();
        ct[0] ^= 1;
        map.insert("ciphertext", Value::Bytes(ct));
        assert_eq!(
            open_content_key(&owner, &SCOPE, 1, &root, &encode(&Value::Map(map)).unwrap())
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn a_forward_version_blob_never_reaches_the_aead() {
        let owner = secret(14);
        let root = cid(b"root block");
        let sealed = seal_content_key(&owner, &[15; 32], &SCOPE, 1, &root, &KEY).unwrap();
        let value = decode(&sealed).unwrap();
        let mut map = value.as_map().unwrap().clone();
        map.insert("v", Value::Unsigned(CONTENT_KEY_V + 1));
        assert_eq!(
            open_content_key(&owner, &SCOPE, 1, &root, &encode(&Value::Map(map)).unwrap())
                .unwrap_err()
                .check(),
            "unsupported-record-version"
        );
    }

    #[test]
    fn an_unknown_frame_field_is_malformed() {
        let owner = secret(16);
        let root = cid(b"root block");
        let sealed = seal_content_key(&owner, &[17; 32], &SCOPE, 1, &root, &KEY).unwrap();
        let value = decode(&sealed).unwrap();
        let mut map = value.as_map().unwrap().clone();
        map.insert("extra", Value::Unsigned(1));
        assert_eq!(
            open_content_key(&owner, &SCOPE, 1, &root, &encode(&Value::Map(map)).unwrap())
                .unwrap_err()
                .check(),
            "unknown-record-field"
        );
    }

    #[test]
    fn a_truncated_blob_is_malformed_not_a_panic() {
        let owner = secret(18);
        let root = cid(b"root block");
        let sealed = seal_content_key(&owner, &[19; 32], &SCOPE, 1, &root, &KEY).unwrap();
        assert!(open_content_key(&owner, &SCOPE, 1, &root, &sealed[..sealed.len() / 2]).is_err());
        assert!(open_content_key(&owner, &SCOPE, 1, &root, b"").is_err());
    }

    #[test]
    fn a_blob_forged_from_the_public_enc_key_never_opens() {
        // Auth mode: the enc subkey is both static sender and recipient, so a
        // writer holding only the public half cannot author a blob.
        let owner = secret(20);
        let root = cid(b"root block");
        let forged = hpke::hpke_seal(
            &owner.public(),
            &[21; 32],
            CONTENT_KEY_HPKE_INFO,
            &content_key_aad(&SCOPE, 1),
            b"whatever",
        );
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(forged.ciphertext));
        m.insert("enc", Value::Bytes(forged.enc.to_vec()));
        m.insert("v", Value::Unsigned(CONTENT_KEY_V));
        assert_eq!(
            open_content_key(&owner, &SCOPE, 1, &root, &encode(&Value::Map(m)).unwrap())
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }
}
