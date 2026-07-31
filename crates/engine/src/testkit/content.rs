//! Version framing for fixtures: one definition of the write handle's
//! push/finish loop, so a change to the [`ContentWriter`] contract lands in one
//! place rather than in every suite that hand-rolls it.

use cipherbox_core::suite::aead::KEY_LEN;

use super::SeededEntropy;
use crate::content::{ContentKey, ContentProfile, ContentWriter, SealedChunk, SealedContent};

/// Frame `plaintext` the way a write handle does, without the facade: every
/// sealed block in file order, the root block, and the version's own identity.
///
/// `key` and `seed` are the fixture's, so two versions in one test can be told
/// apart by their bytes.
pub fn frame_version(
    plaintext: &[u8],
    key: [u8; KEY_LEN],
    seed: u64,
) -> (Vec<SealedChunk>, Vec<u8>, SealedContent) {
    let mut entropy = SeededEntropy::new(seed);
    let mut writer = ContentWriter::new(
        ContentKey::from_bytes(key),
        ContentProfile::CI,
        plaintext.len() as u64,
    );
    let mut blocks = Vec::new();
    let mut rest = plaintext;
    while !rest.is_empty() {
        let (remaining, leaf) = writer.push(rest, &mut entropy).expect("seeded entropy");
        if let Some(leaf) = leaf {
            blocks.push(leaf);
        }
        rest = remaining;
    }
    let finished = writer.finish(&mut entropy).expect("seeded entropy");
    if let Some(tail) = finished.tail {
        blocks.push(tail);
    }
    (blocks, finished.root_block, finished.content)
}
