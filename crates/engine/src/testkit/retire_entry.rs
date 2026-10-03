//! The retire-ledger entry codec, for the engine KAT generator and suite.

use cipherbox_core::content::decode_content_cid_str;

use crate::net::retire::{decode_entry, encode_entry};
use crate::seams::{OwedRetire, SeamError, SeamResult};

/// The bytes the ledger seals for `entry`, bound to the key of its target.
///
/// # Errors
///
/// What the ledger's own encode refuses.
pub fn encode(entry: &OwedRetire) -> SeamResult<Vec<u8>> {
    let cid = decode_content_cid_str(&entry.target)
        .map_err(|_| SeamError::new("retire-ledger target is not a content CID"))?;
    Ok(encode_entry(entry, &cid)?.to_vec())
}

/// The entry `stored` holds under the key of `target`, or `None` for bytes the
/// ledger reads as unwritten.
#[must_use]
pub fn decode(stored: &[u8], target: &str) -> Option<OwedRetire> {
    let cid = decode_content_cid_str(target).ok()?;
    decode_entry(stored, &cid).map(|entry| OwedRetire {
        target: target.to_owned(),
        ..entry
    })
}
