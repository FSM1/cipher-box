//! Pointer and mailbox payloads (blueprint/core.md "Envelope and structures —
//! Pointer payloads").
//!
//! Two owner/sender-authenticated transports core owns end to end:
//!
//! - **Pointer payload** ([`pointer`]) — the owner-identity-signed re-point
//!   object, sealed under the scope's stable `pointerReadKey` via the symmetric
//!   [`seal`](crate::seal) path. The vault pointer carries the same object for
//!   the root scope (#39 D5).
//! - **Mailbox payload** ([`mailbox`]) — an [`hpke`](crate::suite::hpke)-sealed
//!   item with the sender's identity signature **inside the seal** (#39 D9),
//!   verified against the contact-code-anchored key after opening.
//! - **Invite names** ([`invite`]) — the owner signature over the names an
//!   invite-link fragment carries (ADR 0027 D5).
//!
//! The structure-tag registry (`pointer-payload = 0x07`,
//! `mailbox-payload = 0x08`) is frozen — consumed here, never redefined.

pub mod invite;
pub mod mailbox;
pub mod pointer;

pub use invite::{
    INVITE_NAMES_SIG_DOMAIN, InviteNames, invite_names_preimage, sign_invite_names,
    verify_invite_names,
};

pub use mailbox::{
    MAILBOX_SIG_DOMAIN, MailboxItem, mailbox_sig_preimage, open_mailbox_payload,
    seal_mailbox_payload,
};
pub use pointer::{RepointObject, open_pointer_payload, repoint_preimage, seal_pointer_payload};

use crate::codec::{Map, Value};
use crate::error::{CodecError, Malformed};

/// A required map field, or [`Malformed::MissingField`]. (A payload-local twin
/// of the seal slice's `pub(super)` helper — the two modules are disjoint.)
pub(crate) fn req<'a>(map: &'a Map, field: &'static str) -> Result<&'a Value, CodecError> {
    map.get(field)
        .ok_or_else(|| Malformed::MissingField { field }.into())
}

/// A fixed-length byte field as `[u8; N]`, or [`Malformed::InvalidFieldLength`].
pub(crate) fn bytes_fixed<const N: usize>(
    v: &Value,
    field: &'static str,
) -> Result<[u8; N], CodecError> {
    let b = v.as_bytes()?;
    b.try_into().map_err(|_| {
        Malformed::InvalidFieldLength {
            field,
            expected: N,
            found: b.len(),
        }
        .into()
    })
}
