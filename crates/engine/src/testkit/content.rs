//! Content-plane fixtures: one definition of the write handle's push/finish
//! loop and of the block store a verified read is served from, so a change to
//! the [`ContentWriter`] or gateway contract lands in one place rather than in
//! every suite that hand-rolls it.

use std::collections::BTreeMap;
use std::sync::Arc;

use cipherbox_core::content::encode_content_cid_str;
use cipherbox_core::suite::aead::KEY_LEN;

use super::SeededEntropy;
use super::fakes::ScriptedHttp;
use crate::content::{
    ContentKey, ContentProfile, ContentVersion, ContentWriter, Gateway, GatewaySource, SealedChunk,
    SealedContent,
};
use crate::seams::{HttpResponse, SeamError};

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
    frame_version_with(plaintext, key, seed, ContentProfile::CI)
}

/// [`frame_version`] under a caller-chosen framing profile, for a suite whose
/// property only shows up at a chunk size the CI profile cannot reach.
pub fn frame_version_with(
    plaintext: &[u8],
    key: [u8; KEY_LEN],
    seed: u64,
    profile: ContentProfile,
) -> (Vec<SealedChunk>, Vec<u8>, SealedContent) {
    let mut entropy = SeededEntropy::new(seed);
    let mut writer =
        ContentWriter::new(ContentKey::from_bytes(key), profile, plaintext.len() as u64);
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

/// One sealed version as a prune sees it: the doomed [`ContentVersion`], the
/// root block a retire expands it from, and its leaf CIDs as the registry spells
/// them.
pub fn doomed_version(plaintext: &[u8]) -> (ContentVersion, Vec<u8>, Vec<String>) {
    let (_, root_block, content) = frame_version(plaintext, [9u8; KEY_LEN], 11);
    let doomed = ContentVersion::from_plaintext_size(
        encode_content_cid_str(content.content_cid()),
        plaintext.len() as u64,
        &ContentProfile::CI,
    )
    .expect("under the ceiling");
    let leaf_cids = content
        .leaf_cids()
        .iter()
        .map(|cid| encode_content_cid_str(cid))
        .collect();
    (doomed, root_block, leaf_cids)
}

/// A gateway with no accelerator: every block is fetched from one public
/// trustless-gateway source.
pub fn gateway() -> Gateway {
    Gateway {
        accelerator: None,
        public_fallbacks: vec![GatewaySource::public("https://public.gw.test")],
    }
}

/// The CID a trustless-gateway raw-block URL addresses.
pub fn requested_cid(url: &str) -> String {
    url.rsplit('/')
        .next()
        .and_then(|tail| tail.split('?').next())
        .unwrap_or_default()
        .to_owned()
}

/// Index sealed leaves by the gateway address that serves them.
pub fn block_store<'a>(
    leaves: impl IntoIterator<Item = &'a SealedChunk>,
) -> BTreeMap<String, Vec<u8>> {
    leaves
        .into_iter()
        .map(|leaf| (encode_content_cid_str(&leaf.cid), leaf.sealed.clone()))
        .collect()
}

/// Serve `blocks` for more requests than a single read makes; anything unstored
/// is an availability failure, never a trust verdict.
pub fn serve(blocks: &BTreeMap<String, Vec<u8>>) -> ScriptedHttp {
    let http = ScriptedHttp::default();
    // Shared, not copied per reply: a multi-MiB block store costs one copy.
    let blocks = Arc::new(blocks.clone());
    for _ in 0..32 {
        let blocks = Arc::clone(&blocks);
        http.enqueue_derived(
            move |request| match blocks.get(&requested_cid(&request.url)) {
                Some(block) => Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: block.clone(),
                }),
                None => Err(SeamError::new("no such block")),
            },
        );
    }
    http
}
