//! The device registry and the device-approval rendezvous (FSM1/cipher-box-next ADR 0009).
//!
//! Everything two hosts and the API must agree on byte for byte: the three
//! signed payloads, the out-of-band comparison value D3 rests on, and the
//! sealed-factor envelope D5's fresh factor travels in.
//!
//! The Ed25519 signature itself is made outside — the device identity key is
//! held in browser custody (AGENTS.md rule 4) — so this module produces the
//! bytes to sign and never the signature.
//!
//! Every payload is newline-joined, and every builder refuses a field whose
//! alphabet is not newline-free. A field that could carry a newline would let a
//! caller move the separator and have the API verify a different statement than
//! the one a member authorised.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cipherbox_core::error::TrustViolation;
use cipherbox_core::hex::lower as hex_lower;
use cipherbox_core::suite::aead;
use cipherbox_core::suite::ecies::{
    ENC_LEN, ecies_open, ecies_public_key, ecies_recipient_is_a_point, ecies_seal,
};
use cipherbox_core::suite::ed25519::{
    Ed25519Signature, Ed25519Verifier, PUBLIC_LEN as ED25519_PUBLIC_LEN,
    SIGNATURE_LEN as ED25519_SIGNATURE_LEN,
};
use cipherbox_core::suite::secret::SECRET_LEN;
use core::fmt;
use zeroize::Zeroizing;

/// How an approver answered. The wire spelling is what the API's DTO fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Seal a fresh factor to the requester.
    Approve,
    /// Refuse, sealing nothing.
    Deny,
}

impl ApprovalDecision {
    /// The wire spelling the API's `RespondApprovalDto` accepts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// A field the device surface would not put in a signed payload or an
/// envelope. Carries the check that fired, never the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedDeviceField {
    check: &'static str,
}

impl MalformedDeviceField {
    /// The check that refused; safe to surface and to log.
    pub fn check(self) -> &'static str {
        self.check
    }
}

impl fmt::Display for MalformedDeviceField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.check)
    }
}

fn refuse(check: &'static str) -> MalformedDeviceField {
    MalformedDeviceField { check }
}

/// A field the API constrains to lowercase hex of one fixed byte width.
fn lower_hex<'a>(
    value: &'a str,
    bytes: usize,
    check: &'static str,
) -> Result<&'a str, MalformedDeviceField> {
    if value.len() == bytes * 2 && value.bytes().all(is_lower_hex) {
        Ok(value)
    } else {
        Err(refuse(check))
    }
}

/// A raw Ed25519 device identity public key: 32 bytes, lowercase hex.
fn device_public_key(value: &str) -> Result<&str, MalformedDeviceField> {
    lower_hex(
        value,
        ED25519_PUBLIC_LEN,
        "device-public-key-not-lowercase-hex",
    )
}

/// The requester's compressed secp256k1 ephemeral key. On the curve, not merely
/// well-prefixed: this is the produce side of what `ecies_seal` hard-rejects, so
/// a key that could never be sealed to is refused before a member compares it.
fn ephemeral_public_key(value: &str) -> Result<[u8; ENC_LEN], MalformedDeviceField> {
    let refusal = refuse("ephemeral-key-not-a-point");
    let mut bytes = [0u8; ENC_LEN];
    decode_hex(value, &mut bytes).ok_or(refusal)?;
    if !ecies_recipient_is_a_point(&bytes) {
        return Err(refusal);
    }
    Ok(bytes)
}

/// An identifier the API minted — a request id or an account id. Only its
/// newline-freedom is this side's business; the API is authoritative on the
/// rest, and a wrong value there is refused rather than believed.
fn identifier<'a>(value: &'a str, check: &'static str) -> Result<&'a str, MalformedDeviceField> {
    if value.is_empty() || value.contains('\n') {
        Err(refuse(check))
    } else {
        Ok(value)
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// What a device signs to prove possession of its identity key when it joins
/// the account registry.
pub fn registration_payload(
    account_id: &str,
    device_public_key_hex: &str,
) -> Result<Vec<u8>, MalformedDeviceField> {
    let account = identifier(account_id, "account-id-not-newline-free")?;
    let device = device_public_key(device_public_key_hex)?;
    Ok(join(&["cipherbox/device-registration/v1", account, device]))
}

/// Everything the registry bounds on a signed registration, checked on the
/// produce side: a registration the API would refuse never leaves this device
/// (AGENTS.md rule 8).
pub fn check_registration(
    account_id: &str,
    device_public_key_hex: &str,
    signature_hex: &str,
    identity_token: &str,
    label: Option<&str>,
) -> Result<(), MalformedDeviceField> {
    registration_payload(account_id, device_public_key_hex)?;
    check_signature(signature_hex)?;
    if identity_token.is_empty() || identity_token.chars().count() > MAX_IDENTITY_TOKEN_CHARS {
        return Err(refuse("identity-token-out-of-bounds"));
    }
    match label {
        Some(label) if label.chars().count() > MAX_LABEL_CHARS => {
            Err(refuse("device-label-too-long"))
        }
        _ => Ok(()),
    }
}

/// The same, for one answer to a rendezvous.
pub fn check_response(
    device_public_key_hex: &str,
    request_id: &str,
    decision: ApprovalDecision,
    ephemeral_public_key_hex: &str,
    signature_hex: &str,
    sealed_factor: Option<&str>,
) -> Result<(), MalformedDeviceField> {
    check_registry_id(request_id)?;
    approval_response_payload(
        device_public_key_hex,
        request_id,
        decision,
        ephemeral_public_key_hex,
        sealed_factor.unwrap_or_default(),
    )?;
    check_signature(signature_hex)
}

/// An id the engine puts in a request path. The alphabet is the one every
/// authenticated path segment takes, so a host-supplied id is refused with its
/// own verdict rather than as a failed request.
pub fn check_registry_id(value: &str) -> Result<(), MalformedDeviceField> {
    if crate::seams::item_id_is_legal(value) {
        Ok(())
    } else {
        Err(refuse("device-id-not-path-safe"))
    }
}

/// An Ed25519 signature the API verifies: 64 bytes, lowercase hex.
fn check_signature(signature_hex: &str) -> Result<(), MalformedDeviceField> {
    lower_hex(
        signature_hex,
        ED25519_SIGNATURE_LEN,
        "device-signature-not-lowercase-hex",
    )
    .map(drop)
}

/// The API's own ceilings on the two free-text fields a registration carries.
const MAX_IDENTITY_TOKEN_CHARS: usize = 4096;
const MAX_LABEL_CHARS: usize = 64;

/// How many rendezvous a host is ever offered at once. The list is relayed, so
/// a server that answered with thousands would otherwise drive the screen.
pub const MAX_PENDING_APPROVALS: usize = 8;

/// What the requesting device signs: the ephemeral key it asks to have a factor
/// sealed to, bound to its own identity key.
pub fn approval_request_payload(
    device_public_key_hex: &str,
    ephemeral_public_key_hex: &str,
) -> Result<Vec<u8>, MalformedDeviceField> {
    let device = device_public_key(device_public_key_hex)?;
    ephemeral_public_key(ephemeral_public_key_hex)?;
    Ok(join(&[
        "cipherbox/device-approval/request/v1",
        device,
        ephemeral_public_key_hex,
    ]))
}

/// What the approving device signs: its decision, bound to the request, the
/// ephemeral key and the sealed bytes.
pub fn approval_response_payload(
    device_public_key_hex: &str,
    request_id: &str,
    decision: ApprovalDecision,
    ephemeral_public_key_hex: &str,
    sealed_factor: &str,
) -> Result<Vec<u8>, MalformedDeviceField> {
    let device = device_public_key(device_public_key_hex)?;
    let request = identifier(request_id, "request-id-not-newline-free")?;
    ephemeral_public_key(ephemeral_public_key_hex)?;
    sealed_factor_bytes(decision, sealed_factor)?;
    Ok(join(&[
        "cipherbox/device-approval/response/v1",
        device,
        request,
        decision.as_str(),
        ephemeral_public_key_hex,
        sealed_factor,
    ]))
}

/// One rendezvous an approver may answer, as the engine hands it to a host.
///
/// The relayed fields survive to here only after the request binding verifies,
/// so a host renders a rendezvous the requester really opened or none at all.
/// The comparison value travels with them because deriving it is the engine's
/// job, not the screen's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApprovalView {
    /// The rendezvous id.
    pub request_id: String,
    /// The requesting device identity public key, lowercase hex.
    pub requester_device_public_key: String,
    /// The compressed secp256k1 key a factor must be sealed to.
    pub ephemeral_public_key: String,
    /// The digits both screens must show before an approval is possible.
    pub comparison_value: String,
    /// When the rendezvous opened, ISO 8601.
    pub created_at: String,
    /// When the row is gone, ISO 8601.
    pub expires_at: String,
}

/// Whether a relayed rendezvous still carries the requester's own signature
/// over the pair it offers (D4).
///
/// The bulletin board relays the device key, the ephemeral key and this
/// signature together, so an approver checks the binding here rather than
/// trusting the echo. One boolean, no reason: a caller must not learn which
/// part failed.
pub fn request_binding_holds(
    device_public_key_hex: &str,
    ephemeral_public_key_hex: &str,
    signature_hex: &str,
) -> bool {
    let Ok(payload) = approval_request_payload(device_public_key_hex, ephemeral_public_key_hex)
    else {
        return false;
    };
    let (Some(verifier), Some(signature)) = (
        ed25519_verifier(device_public_key_hex),
        ed25519_signature(signature_hex),
    ) else {
        return false;
    };
    verifier.verify(&payload, &signature)
}

fn ed25519_verifier(public_key_hex: &str) -> Option<Ed25519Verifier> {
    let mut bytes = [0u8; ED25519_PUBLIC_LEN];
    decode_hex(public_key_hex, &mut bytes)?;
    Ed25519Verifier::from_bytes(bytes)
}

fn ed25519_signature(signature_hex: &str) -> Option<Ed25519Signature> {
    let mut bytes = [0u8; ED25519_SIGNATURE_LEN];
    decode_hex(signature_hex, &mut bytes)?;
    Some(Ed25519Signature::from_bytes(bytes))
}

/// Fill `out` from lowercase hex of exactly its width. `None` otherwise.
fn decode_hex(value: &str, out: &mut [u8]) -> Option<()> {
    if value.len() != out.len() * 2 || !value.bytes().all(is_lower_hex) {
        return None;
    }
    for (byte, pair) in out.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(())
}

/// The comparison value both screens show, so the member — not the relay —
/// decides that the key being sealed to is the key that was offered (D3).
///
/// It covers only the two fields the requester fixed before it spoke to the
/// relay. A server-chosen field would let the relay move the value on the
/// honest screen as well as on its own, which turns a targeted second-preimage
/// search into a birthday search and costs about 2^30 instead of 2^60. So the
/// requester's digits are a constant of its own state, and the relay must hit
/// them with a key it can decrypt under.
pub fn comparison_value(
    device_public_key_hex: &str,
    ephemeral_public_key_hex: &str,
) -> Result<String, MalformedDeviceField> {
    let device = device_public_key(device_public_key_hex)?;
    ephemeral_public_key(ephemeral_public_key_hex)?;
    let transcript = join(&[
        "cipherbox/device-approval/comparison/v2",
        device,
        ephemeral_public_key_hex,
    ]);
    let digest = cipherbox_core::suite::hash::hash(&transcript);
    let mut wide = [0u8; 16];
    wide.copy_from_slice(&digest[..16]);
    let value = u128::from_be_bytes(wide) % 1_000_000_000_000_000_000;
    let digits = format!("{value:018}");
    Ok(format!(
        "{} {} {}",
        &digits[..6],
        &digits[6..12],
        &digits[12..]
    ))
}

/// Seal a fresh factor to the requester's rendezvous key, bound to the request
/// it answers.
///
/// # Security — seal scalar uniqueness (caller invariant)
///
/// `seal_scalar` **must be fresh, uniformly-random 32 bytes on every call**.
/// The ECIES key schedule derives both the AEAD key and the nonce from it, so a
/// repeat against one recipient repeats the pair, which is a total break. This
/// layer is the last one that sees the value and it cannot sample entropy
/// (blueprint/engine.md determinism doctrine), so the host owns it.
pub fn seal_factor(
    rendezvous_public_key_hex: &str,
    request_id: &str,
    requester_device_public_key_hex: &str,
    seal_scalar: &[u8; SECRET_LEN],
    factor_key: &[u8],
) -> Result<String, MalformedDeviceField> {
    let recipient = ephemeral_public_key(rendezvous_public_key_hex)?;
    let aad = factor_aad(request_id, requester_device_public_key_hex)?;
    let sealed = ecies_seal(&recipient, seal_scalar, &aad, factor_key)
        .ok_or_else(|| refuse("factor-seal-scalar-outside-group"))?;
    let mut envelope = Vec::with_capacity(ENC_LEN + sealed.ciphertext.len());
    envelope.extend_from_slice(&sealed.enc);
    envelope.extend_from_slice(&sealed.ciphertext);
    Ok(BASE64.encode(&envelope))
}

/// Open a sealed factor with the scalar that opened the rendezvous.
///
/// Every failure answers with the one [`TrustViolation::EciesOpenFailed`]: the
/// envelope came off a relay, so a tag mismatch is tampering rather than a
/// mistyped field, and no caller may learn which part was wrong.
///
/// Private: [`adopt_factor`] is the one door, so no host can open an envelope
/// the approving device never signed for.
fn open_factor(
    sealed_factor: &str,
    request_id: &str,
    requester_device_public_key_hex: &str,
    rendezvous_scalar: &[u8; SECRET_LEN],
) -> Result<Zeroizing<Vec<u8>>, TrustViolation> {
    const REFUSED: TrustViolation = TrustViolation::EciesOpenFailed;
    let aad = factor_aad(request_id, requester_device_public_key_hex).map_err(|_| REFUSED)?;
    let envelope = BASE64.decode(sealed_factor).map_err(|_| REFUSED)?;
    if envelope.len() < ENC_LEN + aead::TAG_LEN {
        return Err(REFUSED);
    }
    let mut enc = [0u8; ENC_LEN];
    enc.copy_from_slice(&envelope[..ENC_LEN]);
    ecies_open(rendezvous_scalar, &enc, &aad, &envelope[ENC_LEN..])
}

/// Why a requester refused the answer a relay carried back to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayedAnswerRefused {
    /// The approving device's signature did not cover this answer (D4).
    Unsigned,
    /// The envelope itself did not open ([`open_factor`]).
    Sealed(TrustViolation),
}

impl RelayedAnswerRefused {
    /// The stable name of the check that fired; safe to surface and to log.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Unsigned => "device-response-binding-refused",
            Self::Sealed(violation) => violation.check(),
        }
    }
}

impl fmt::Display for RelayedAnswerRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.check())
    }
}

impl std::error::Error for RelayedAnswerRefused {}

/// Whether a relayed answer still carries the approving device's own signature
/// over every field it answered with (D4). The requester-side mirror of
/// [`request_binding_holds`]. One boolean, no reason: a caller must not learn
/// which part failed.
fn response_binding_holds(
    device_public_key_hex: &str,
    request_id: &str,
    decision: ApprovalDecision,
    ephemeral_public_key_hex: &str,
    sealed_factor: &str,
    signature_hex: &str,
) -> bool {
    let Ok(payload) = approval_response_payload(
        device_public_key_hex,
        request_id,
        decision,
        ephemeral_public_key_hex,
        sealed_factor,
    ) else {
        return false;
    };
    let (Some(verifier), Some(signature)) = (
        ed25519_verifier(device_public_key_hex),
        ed25519_signature(signature_hex),
    ) else {
        return false;
    };
    verifier.verify(&payload, &signature)
}

/// Adopt the factor a relayed approval carries, while the approving device's
/// signature still covers the whole of that answer (D4).
///
/// The signature is checked before the envelope, so bytes a relay sealed to
/// this rendezvous key itself are refused rather than opened. The ephemeral key
/// the signature binds is re-derived from this device's own scalar, never taken
/// from the relayed echo.
pub fn adopt_factor(
    sealed_factor: &str,
    request_id: &str,
    requester_device_public_key_hex: &str,
    responder_device_public_key_hex: &str,
    response_signature_hex: &str,
    rendezvous_scalar: &[u8; SECRET_LEN],
) -> Result<Zeroizing<Vec<u8>>, RelayedAnswerRefused> {
    // A scalar outside the group opens nothing, which is the verdict
    // `open_factor` answers the same call with.
    let ephemeral_public_key = rendezvous_public_key(rendezvous_scalar)
        .map_err(|_| RelayedAnswerRefused::Sealed(TrustViolation::EciesOpenFailed))?;
    if !response_binding_holds(
        responder_device_public_key_hex,
        request_id,
        ApprovalDecision::Approve,
        &ephemeral_public_key,
        sealed_factor,
        response_signature_hex,
    ) {
        return Err(RelayedAnswerRefused::Unsigned);
    }
    open_factor(
        sealed_factor,
        request_id,
        requester_device_public_key_hex,
        rendezvous_scalar,
    )
    .map_err(RelayedAnswerRefused::Sealed)
}

/// The compressed public key a requester offers, in the lowercase hex the
/// rendezvous takes. The produce side of the API's own field constraint.
pub fn rendezvous_public_key(
    rendezvous_scalar: &[u8; SECRET_LEN],
) -> Result<String, MalformedDeviceField> {
    ecies_public_key(rendezvous_scalar)
        .map(|key| hex_lower(&key))
        .ok_or_else(|| refuse("rendezvous-scalar-outside-group"))
}

/// The factor envelope's additional authenticated data: the request it answers
/// and the device that opened it, so an envelope lifted onto another rendezvous
/// opens nothing (the binding FSM1/cipher-box-next ADR 0009 D4 puts on the signatures, applied to the
/// ciphertext as well).
fn factor_aad(
    request_id: &str,
    requester_device_public_key_hex: &str,
) -> Result<Vec<u8>, MalformedDeviceField> {
    let request = identifier(request_id, "request-id-not-newline-free")?;
    let device = device_public_key(requester_device_public_key_hex)?;
    Ok(join(&[
        "cipherbox/device-approval/factor/v1",
        request,
        device,
    ]))
}

/// What an approval may carry: canonical base64 that decodes to a whole
/// envelope inside the API's 1 KiB ceiling, and nothing at all on a denial.
///
/// The floor is the one [`open_factor`] refuses below, so this side cannot sign
/// an approval the requester's own opener always rejects (AGENTS.md 8).
fn sealed_factor_bytes(
    decision: ApprovalDecision,
    sealed_factor: &str,
) -> Result<(), MalformedDeviceField> {
    match decision {
        ApprovalDecision::Deny if sealed_factor.is_empty() => Ok(()),
        ApprovalDecision::Deny => Err(refuse("denial-seals-nothing")),
        ApprovalDecision::Approve => {
            let bytes = BASE64
                .decode(sealed_factor)
                .map_err(|_| refuse("sealed-factor-not-canonical-base64"))?;
            if bytes.len() < ENC_LEN + aead::TAG_LEN {
                return Err(refuse("sealed-factor-under-envelope-floor"));
            }
            if bytes.len() > MAX_SEALED_FACTOR_BYTES {
                return Err(refuse("sealed-factor-over-ceiling"));
            }
            Ok(())
        }
    }
}

/// The API's own decoded-byte ceiling on a sealed factor.
const MAX_SEALED_FACTOR_BYTES: usize = 1024;

fn join(parts: &[&str]) -> Vec<u8> {
    parts.join("\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    const DEVICE: &str = "cd11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    const REQUEST: &str = "1b3d4c1a-0000-4000-8000-000000000001";

    fn ephemeral(scalar: &[u8; SECRET_LEN]) -> String {
        rendezvous_public_key(scalar).expect("a valid scalar")
    }

    #[test]
    fn the_three_payloads_are_newline_joined_as_the_api_verifies_them() {
        let eph = ephemeral(&[3u8; SECRET_LEN]);
        assert_eq!(
            registration_payload("account-1", DEVICE).expect("payload"),
            format!("cipherbox/device-registration/v1\naccount-1\n{DEVICE}").into_bytes()
        );
        assert_eq!(
            approval_request_payload(DEVICE, &eph).expect("payload"),
            format!("cipherbox/device-approval/request/v1\n{DEVICE}\n{eph}").into_bytes()
        );
        assert_eq!(
            approval_response_payload(DEVICE, REQUEST, ApprovalDecision::Deny, &eph, "")
                .expect("payload"),
            format!("cipherbox/device-approval/response/v1\n{DEVICE}\n{REQUEST}\ndeny\n{eph}\n")
                .into_bytes()
        );
    }

    #[test]
    fn a_field_that_could_move_the_separator_is_refused() {
        let eph = ephemeral(&[3u8; SECRET_LEN]);
        assert!(registration_payload("account\n1", DEVICE).is_err());
        assert!(registration_payload("", DEVICE).is_err());
        assert!(approval_request_payload("not hex", &eph).is_err());
        assert!(approval_request_payload(DEVICE, "04").is_err());
        assert!(
            approval_response_payload(DEVICE, "id\n2", ApprovalDecision::Deny, &eph, "").is_err()
        );
    }

    #[test]
    fn an_uppercase_or_short_device_key_never_reaches_a_payload() {
        let upper = DEVICE.to_uppercase();
        assert!(registration_payload("account-1", &upper).is_err());
        assert!(registration_payload("account-1", &DEVICE[..62]).is_err());
    }

    #[test]
    fn a_denial_carrying_a_sealed_factor_is_refused_and_so_is_an_empty_approval() {
        let eph = ephemeral(&[3u8; SECRET_LEN]);
        assert!(
            approval_response_payload(DEVICE, REQUEST, ApprovalDecision::Deny, &eph, "AAAA")
                .is_err()
        );
        assert!(
            approval_response_payload(DEVICE, REQUEST, ApprovalDecision::Approve, &eph, "!!")
                .is_err()
        );
        // An empty factor decodes cleanly and is under the ceiling, so only the
        // envelope floor refuses it.
        assert!(
            approval_response_payload(DEVICE, REQUEST, ApprovalDecision::Approve, &eph, "")
                .is_err()
        );
    }

    /// The floor `open_factor` refuses below has to refuse on this side too, or
    /// a release build signs an approval no requester can ever open.
    #[test]
    fn an_approval_sealing_less_than_a_whole_envelope_is_refused() {
        let eph = ephemeral(&[3u8; SECRET_LEN]);
        let short = BASE64.encode(vec![0u8; ENC_LEN + aead::TAG_LEN - 1]);
        assert!(
            approval_response_payload(DEVICE, REQUEST, ApprovalDecision::Approve, &eph, &short)
                .is_err()
        );
        let whole = BASE64.encode(vec![0u8; ENC_LEN + aead::TAG_LEN]);
        assert!(
            approval_response_payload(DEVICE, REQUEST, ApprovalDecision::Approve, &eph, &whole)
                .is_ok()
        );
    }

    #[test]
    fn a_sealed_factor_over_the_ceiling_is_refused() {
        let eph = ephemeral(&[3u8; SECRET_LEN]);
        let oversized = BASE64.encode(vec![0u8; MAX_SEALED_FACTOR_BYTES + 1]);
        assert!(
            approval_response_payload(DEVICE, REQUEST, ApprovalDecision::Approve, &eph, &oversized)
                .is_err()
        );
    }

    /// A relayed rendezvous is only shown when the requester's own signature
    /// still covers the pair the board echoed.
    #[test]
    fn a_relayed_pair_the_requester_did_not_sign_is_refused() {
        let signer = Ed25519Signer::from_seed([13u8; SECRET_LEN]);
        let device = hex_lower(&signer.verifying_key().to_bytes());
        let eph = rendezvous_public_key(&[3u8; SECRET_LEN]).expect("a valid scalar");
        let other_eph = rendezvous_public_key(&[5u8; SECRET_LEN]).expect("a valid scalar");
        let payload = approval_request_payload(&device, &eph).expect("payload");
        let signature = hex_lower(&signer.sign(&payload).to_bytes());

        assert!(request_binding_holds(&device, &eph, &signature));
        assert!(!request_binding_holds(&device, &other_eph, &signature));
        assert!(!request_binding_holds(DEVICE, &eph, &signature));
        assert!(!request_binding_holds(&device, &eph, &"00".repeat(64)));
        assert!(!request_binding_holds(&device, &eph, "not hex"));
    }

    #[test]
    fn a_device_key_that_is_not_a_point_never_verifies() {
        let eph = rendezvous_public_key(&[3u8; SECRET_LEN]).expect("a valid scalar");
        assert!(!request_binding_holds(
            &"ff".repeat(32),
            &eph,
            &"00".repeat(64)
        ));
    }

    #[test]
    fn the_comparison_value_is_eighteen_grouped_digits() {
        let value = comparison_value(DEVICE, &ephemeral(&[3u8; SECRET_LEN])).expect("value");
        assert_eq!(value.len(), 20);
        let digits: String = value.chars().filter(|c| *c != ' ').collect();
        assert_eq!(digits.len(), 18);
        assert!(digits.chars().all(|c| c.is_ascii_digit()));
    }

    /// The property D3 rests on: alter either offered field and the two screens
    /// disagree.
    #[test]
    fn every_offered_field_changes_the_comparison_value() {
        let eph = ephemeral(&[3u8; SECRET_LEN]);
        let other_eph = ephemeral(&[5u8; SECRET_LEN]);
        let other_device = format!("ab{}", &DEVICE[2..]);
        let base = comparison_value(DEVICE, &eph).expect("value");
        assert_ne!(base, comparison_value(DEVICE, &other_eph).expect("value"));
        assert_ne!(base, comparison_value(&other_device, &eph).expect("value"));
    }

    /// The relay picks the rendezvous id, so a value that covered it would move
    /// on the honest screen too and the search would be a birthday search.
    #[test]
    fn the_comparison_value_covers_only_fields_the_requester_itself_fixed() {
        let eph = ephemeral(&[3u8; SECRET_LEN]);
        let payload = approval_request_payload(DEVICE, &eph).expect("payload");
        let value = comparison_value(DEVICE, &eph).expect("value");
        // Everything the value covers is inside what the requester signed, so
        // nothing the relay chose can reach it.
        let signed = String::from_utf8(payload).expect("the payload is text");
        assert!(signed.contains(DEVICE) && signed.contains(&eph));
        assert!(!signed.contains(REQUEST));
        assert_eq!(value, comparison_value(DEVICE, &eph).expect("value"));
    }

    #[test]
    fn the_comparison_value_is_pinned_so_two_hosts_cannot_drift() {
        assert_eq!(
            comparison_value(DEVICE, &ephemeral(&[3u8; SECRET_LEN])).expect("value"),
            "157910 307840 438338"
        );
    }

    /// An off-curve key passes the length and prefix checks but can never be
    /// sealed to, so it is refused before a member is asked to compare it.
    #[test]
    fn an_ephemeral_key_that_is_not_a_point_never_reaches_a_comparison_value() {
        let off_curve = format!("02{}05", "00".repeat(31));
        assert!(comparison_value(DEVICE, &off_curve).is_err());
        assert!(approval_request_payload(DEVICE, &off_curve).is_err());
        let at_prime = "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        assert!(comparison_value(DEVICE, at_prime).is_err());
    }

    #[test]
    fn a_sealed_factor_round_trips_under_the_ephemeral_scalar() {
        let requester = [4u8; SECRET_LEN];
        let eph = ephemeral(&requester);
        let sealed = seal_factor(&eph, REQUEST, DEVICE, &[9u8; SECRET_LEN], b"a fresh factor")
            .expect("seal");
        assert_eq!(
            open_factor(&sealed, REQUEST, DEVICE, &requester)
                .expect("open")
                .as_slice(),
            b"a fresh factor"
        );
    }

    #[test]
    fn a_sealed_factor_lifted_onto_another_rendezvous_opens_nothing() {
        let requester = [4u8; SECRET_LEN];
        let eph = ephemeral(&requester);
        let sealed = seal_factor(&eph, REQUEST, DEVICE, &[9u8; SECRET_LEN], b"a fresh factor")
            .expect("seal");
        assert!(
            open_factor(
                &sealed,
                "1b3d4c1a-0000-4000-8000-000000000002",
                DEVICE,
                &requester
            )
            .is_err()
        );
        let other_device = format!("ab{}", &DEVICE[2..]);
        assert!(open_factor(&sealed, REQUEST, &other_device, &requester).is_err());
    }

    /// One approver, one sealed factor, and the answer that approver signed
    /// over it.
    fn answered(
        approver_seed: [u8; SECRET_LEN],
        requester_scalar: &[u8; SECRET_LEN],
    ) -> (String, String, String) {
        let signer = Ed25519Signer::from_seed(approver_seed);
        let approver = hex_lower(&signer.verifying_key().to_bytes());
        let eph = ephemeral(requester_scalar);
        let sealed = seal_factor(&eph, REQUEST, DEVICE, &[9u8; SECRET_LEN], b"a fresh factor")
            .expect("seal");
        let payload =
            approval_response_payload(&approver, REQUEST, ApprovalDecision::Approve, &eph, &sealed)
                .expect("payload");
        let signature = hex_lower(&signer.sign(&payload).to_bytes());
        (approver, sealed, signature)
    }

    #[test]
    fn an_answer_the_approver_signed_hands_over_its_factor() {
        let scalar = [4u8; SECRET_LEN];
        let (approver, sealed, signature) = answered([21u8; SECRET_LEN], &scalar);
        assert_eq!(
            adopt_factor(&sealed, REQUEST, DEVICE, &approver, &signature, &scalar)
                .expect("adopt")
                .as_slice(),
            b"a fresh factor"
        );
    }

    /// The envelope here opens under this scalar, so the signature check is all
    /// that stands between a relay's own bytes and the factor the requester
    /// adopts. Every field the answer binds is varied one at a time.
    #[test]
    fn an_answer_the_approver_did_not_sign_never_reaches_the_envelope() {
        let scalar = [4u8; SECRET_LEN];
        let (approver, sealed, signature) = answered([21u8; SECRET_LEN], &scalar);
        let other = hex_lower(
            &Ed25519Signer::from_seed([22u8; SECRET_LEN])
                .verifying_key()
                .to_bytes(),
        );
        let refused = |responder: &str, sig: &str| {
            adopt_factor(&sealed, REQUEST, DEVICE, responder, sig, &scalar).unwrap_err()
        };
        // A relay that answers under a key of its own, and a signature that
        // covers nothing this answer says.
        assert_eq!(refused(&other, &signature), RelayedAnswerRefused::Unsigned);
        assert_eq!(
            refused(&approver, &"00".repeat(ED25519_SIGNATURE_LEN)),
            RelayedAnswerRefused::Unsigned
        );
        assert_eq!(
            refused(&approver, "not hex"),
            RelayedAnswerRefused::Unsigned
        );
        assert_eq!(refused(&approver, ""), RelayedAnswerRefused::Unsigned);
        assert_eq!(
            refused(&"ff".repeat(ED25519_PUBLIC_LEN), &signature),
            RelayedAnswerRefused::Unsigned
        );
        // The refusal names its own check rather than the envelope's.
        assert_eq!(
            refused(&other, &signature).check(),
            "device-response-binding-refused"
        );
    }

    /// The answer is bound to the request it answers, to the bytes it carries,
    /// and to the rendezvous key this device itself cut.
    #[test]
    fn an_answer_lifted_off_its_own_transcript_is_refused() {
        let scalar = [4u8; SECRET_LEN];
        let (approver, sealed, signature) = answered([21u8; SECRET_LEN], &scalar);
        for lifted in [
            adopt_factor(
                &sealed,
                "1b3d4c1a-0000-4000-8000-000000000002",
                DEVICE,
                &approver,
                &signature,
                &scalar,
            ),
            // Another envelope, which the same signature does not cover.
            adopt_factor(
                &seal_factor(
                    &ephemeral(&scalar),
                    REQUEST,
                    DEVICE,
                    &[10u8; SECRET_LEN],
                    b"a fresh factor",
                )
                .expect("seal"),
                REQUEST,
                DEVICE,
                &approver,
                &signature,
                &scalar,
            ),
            // Another rendezvous scalar: the signed ephemeral key is derived
            // here, so it moves with the scalar rather than with the relay.
            adopt_factor(
                &sealed,
                REQUEST,
                DEVICE,
                &approver,
                &signature,
                &[5u8; SECRET_LEN],
            ),
        ] {
            assert_eq!(lifted.unwrap_err(), RelayedAnswerRefused::Unsigned);
        }
    }

    /// A signed answer whose envelope was swapped still refuses, and that
    /// refusal keeps the envelope's own verdict.
    #[test]
    fn a_signed_answer_over_an_envelope_for_another_device_keeps_the_seal_verdict() {
        let scalar = [4u8; SECRET_LEN];
        let signer = Ed25519Signer::from_seed([21u8; SECRET_LEN]);
        let approver = hex_lower(&signer.verifying_key().to_bytes());
        let eph = ephemeral(&scalar);
        let other_device = format!("ab{}", &DEVICE[2..]);
        let sealed = seal_factor(
            &eph,
            REQUEST,
            &other_device,
            &[9u8; SECRET_LEN],
            b"a fresh factor",
        )
        .expect("seal");
        let payload =
            approval_response_payload(&approver, REQUEST, ApprovalDecision::Approve, &eph, &sealed)
                .expect("payload");
        let signature = hex_lower(&signer.sign(&payload).to_bytes());
        assert_eq!(
            adopt_factor(&sealed, REQUEST, DEVICE, &approver, &signature, &scalar)
                .unwrap_err()
                .check(),
            TrustViolation::EciesOpenFailed.check()
        );
    }

    #[test]
    fn a_rendezvous_scalar_outside_the_group_opens_nothing() {
        let outside = [0xffu8; SECRET_LEN];
        assert!(rendezvous_public_key(&outside).is_err());
        assert_eq!(
            adopt_factor("", REQUEST, DEVICE, DEVICE, &"00".repeat(64), &outside)
                .unwrap_err()
                .check(),
            TrustViolation::EciesOpenFailed.check()
        );
    }

    #[test]
    fn an_envelope_shorter_than_its_encapsulated_key_is_refused() {
        let requester = [4u8; SECRET_LEN];
        assert!(open_factor(&BASE64.encode([0u8; ENC_LEN]), REQUEST, DEVICE, &requester).is_err());
        assert!(open_factor("not base64!", REQUEST, DEVICE, &requester).is_err());
    }

    #[test]
    fn a_sealed_factor_fits_the_wire_ceiling() {
        let eph = ephemeral(&[4u8; SECRET_LEN]);
        let sealed = seal_factor(
            &eph,
            REQUEST,
            DEVICE,
            &[9u8; SECRET_LEN],
            &[0u8; SECRET_LEN],
        )
        .expect("seal");
        assert!(BASE64.decode(&sealed).expect("base64").len() <= MAX_SEALED_FACTOR_BYTES);
        assert!(
            approval_response_payload(DEVICE, REQUEST, ApprovalDecision::Approve, &eph, &sealed)
                .is_ok()
        );
    }
}
