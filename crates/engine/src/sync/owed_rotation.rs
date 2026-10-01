//! The durable record of the owner rotation work this device still owes
//! (CONTEXT.md "Owed rotation work"; ADR 0063).

/// The staging-key prefix the owed rotation record is journaled under.
/// [`orphan_staging_keys`](crate::sync::orphan_staging_keys) treats the whole
/// prefix as referenced, every owner's entry included.
///
/// Kept short: the desktop store spells a key as a hex filename, at twice its
/// byte length.
pub const OWED_ROTATION_PREFIX: &[u8] = b"cbx/or/";
