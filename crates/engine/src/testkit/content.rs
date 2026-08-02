//! Content-plane fixtures: one definition of the write handle's push/finish
//! loop and of the block store a verified read is served from, so a change to
//! the [`ContentWriter`] or gateway contract lands in one place rather than in
//! every suite that hand-rolls it.

use std::collections::BTreeMap;

use cipherbox_core::content::encode_content_cid_str;
use cipherbox_core::suite::aead::KEY_LEN;

use super::SeededEntropy;
use super::fakes::ScriptedHttp;
use crate::content::{
    ContentKey, ContentProfile, ContentWriter, Gateway, GatewaySource, SealedChunk, SealedContent,
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

/// A gateway with no accelerator: every block is fetched from one public
/// trustless-gateway source.
pub fn gateway() -> Gateway {
    Gateway {
        accelerator: None,
        public_fallbacks: vec![GatewaySource {
            base_url: "https://public.gw.test".into(),
            bearer: None,
        }],
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
    for _ in 0..32 {
        let blocks = blocks.clone();
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
