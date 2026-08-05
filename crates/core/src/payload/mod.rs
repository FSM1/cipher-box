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
//!
//! The structure-tag registry (`pointer-payload = 0x07`,
//! `mailbox-payload = 0x08`) is frozen — consumed here, never redefined.

pub mod mailbox;
pub mod pointer;

pub use mailbox::{MailboxItem, open_mailbox_payload, seal_mailbox_payload};
pub use pointer::{RepointObject, open_pointer_payload, seal_pointer_payload};

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
