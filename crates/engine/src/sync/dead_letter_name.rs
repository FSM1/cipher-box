//! The name a preserved dead letter records: the `ipnsName` of the record its
//! version would have joined, so a discard and a trim journal the dropped
//! version under that name (ADR 0075). One sealed `dead-letter-names` value per
//! op, beside the preserved set.

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::OwnerLocalKind;
use zeroize::Zeroizing;

use crate::seams::{OpId, SeamError, SeamResult, StagingStore};
use crate::sync::BookkeepingSeal;

/// The staging-key prefix of the recorded names:
/// `prefix | ownerTagLen(1) | ownerTag | opId(8, big-endian)`.
pub const DEAD_LETTER_NAME_PREFIX: &[u8] = b"cbx/dn/";

/// The body format tag inside the seal.
const NAME_FORMAT_V1: u8 = 1;

/// The key of the name `op_id` records.
pub fn dead_letter_name_key(owner_tag: &[u8], op_id: OpId) -> SeamResult<Vec<u8>> {
    let len = u8::try_from(owner_tag.len())
        .map_err(|_| SeamError::new("dead-letter name owner tag is over 255 bytes"))?;
    let mut key = DEAD_LETTER_NAME_PREFIX.to_vec();
    key.push(len);
    key.extend_from_slice(owner_tag);
    key.extend_from_slice(&op_id.0.to_be_bytes());
    Ok(key)
}

/// The op id a name key ends with, when `key` is one.
pub(crate) fn dead_letter_name_op(key: &[u8]) -> Option<OpId> {
    let rest = key.strip_prefix(DEAD_LETTER_NAME_PREFIX)?;
    rest.last_chunk::<{ size_of::<u64>() }>()
        .map(|op_id| OpId(u64::from_be_bytes(*op_id)))
}

/// `NAME_FORMAT_V1 | opId(8) | rootCid | nameLen(1) | name`. `rootCid` is the
/// binary content CID of the parked version.
///
/// Refuses a name [`decode_dead_letter_name`] would read as no name (AGENTS.md
/// rule 8).
pub fn encode_dead_letter_name(
    op_id: OpId,
    root_cid: &[u8],
    name: &str,
) -> SeamResult<Zeroizing<Vec<u8>>> {
    if IpnsName::parse(name).is_err() {
        return Err(SeamError::new("dead-letter name is not an IPNS name"));
    }
    let len = u8::try_from(name.len())
        .map_err(|_| SeamError::new("dead-letter name is over 255 bytes"))?;
    let mut body = Zeroizing::new(Vec::with_capacity(
        2 + size_of::<u64>() + root_cid.len() + name.len(),
    ));
    body.push(NAME_FORMAT_V1);
    body.extend_from_slice(&op_id.0.to_be_bytes());
    body.extend_from_slice(root_cid);
    body.push(len);
    body.extend_from_slice(name.as_bytes());
    Ok(body)
}

/// The name a body records for `op_id` at `root_cid`, or `None` for a body that
/// binds another op or another version, or that this build did not write.
pub fn decode_dead_letter_name(body: &[u8], op_id: OpId, root_cid: &[u8]) -> Option<String> {
    let rest = body.strip_prefix(&[NAME_FORMAT_V1])?;
    let (stored_op, rest) = rest.split_first_chunk::<{ size_of::<u64>() }>()?;
    if u64::from_be_bytes(*stored_op) != op_id.0 {
        return None;
    }
    let (&len, rest) = rest.strip_prefix(root_cid)?.split_first()?;
    let (name, tail) = rest.split_at_checked(usize::from(len))?;
    let name = core::str::from_utf8(name).ok()?;
    (tail.is_empty() && IpnsName::parse(name).is_ok()).then(|| name.to_owned())
}

/// One owner's recorded names in the staging store.
pub(crate) struct DeadLetterNames<'a, S> {
    store: &'a S,
    seal: BookkeepingSeal<'a>,
    owner_tag: [u8; 32],
}

impl<'a, S: StagingStore> DeadLetterNames<'a, S> {
    pub(crate) fn new(store: &'a S, seal: BookkeepingSeal<'a>, owner_tag: [u8; 32]) -> Self {
        Self {
            store,
            seal,
            owner_tag,
        }
    }

    /// Record `name` for the version `op_id` parks at `root_cid`.
    pub(crate) async fn record(
        &self,
        op_id: OpId,
        root_cid: &[u8],
        name: &IpnsName,
    ) -> SeamResult<()> {
        let body = encode_dead_letter_name(op_id, root_cid, name.as_str())?;
        let blob = self.seal.seal(OwnerLocalKind::DeadLetterNames, &body)?;
        self.store
            .put_staged_bytes(&dead_letter_name_key(&self.owner_tag, op_id)?, &blob)
            .await
    }

    /// The name `op_id` recorded for `root_cid`. A value that does not open or
    /// does not decode is no name.
    pub(crate) async fn read(&self, op_id: OpId, root_cid: &[u8]) -> SeamResult<Option<String>> {
        let key = dead_letter_name_key(&self.owner_tag, op_id)?;
        let Some(blob) = self.store.staged_bytes(&key).await? else {
            return Ok(None);
        };
        Ok(self
            .seal
            .open(OwnerLocalKind::DeadLetterNames, &blob)
            .and_then(|body| decode_dead_letter_name(&body, op_id, root_cid)))
    }

    /// Remove the name `op_id` recorded.
    pub(crate) async fn remove(&self, op_id: OpId) -> SeamResult<()> {
        self.store
            .remove_staged_bytes(&dead_letter_name_key(&self.owner_tag, op_id)?)
            .await
    }

    /// [`Self::remove`], best-effort: orphan GC collects a key that stays.
    pub(crate) async fn forget(&self, op_id: OpId) {
        let _ = self.remove(op_id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    const ROOT: &[u8] = b"a binary root cid";

    fn name() -> IpnsName {
        IpnsName::from_public_key(&Ed25519Signer::from_seed([0x5a; 32]).verifying_key())
    }

    fn body() -> Zeroizing<Vec<u8>> {
        encode_dead_letter_name(OpId(7), ROOT, name().as_str()).expect("encodes")
    }

    #[test]
    fn a_name_round_trips_for_its_own_op_and_version() {
        assert_eq!(
            decode_dead_letter_name(&body(), OpId(7), ROOT).as_deref(),
            Some(name().as_str())
        );
    }

    #[test]
    fn a_body_of_another_op_or_version_reads_as_no_name() {
        assert_eq!(decode_dead_letter_name(&body(), OpId(8), ROOT), None);
        assert_eq!(
            decode_dead_letter_name(&body(), OpId(7), b"another root cid!"),
            None
        );
    }

    #[test]
    fn a_damaged_body_reads_as_no_name() {
        let mut trailing = body().to_vec();
        trailing.push(0);
        let mut unknown = body().to_vec();
        unknown[0] = 2;
        let mut bad_name = body().to_vec();
        let last = bad_name.len() - 1;
        bad_name[last] = b'!';
        let mut short = body().to_vec();
        short.pop();
        for damaged in [trailing, unknown, bad_name, short, Vec::new()] {
            assert_eq!(decode_dead_letter_name(&damaged, OpId(7), ROOT), None);
        }
    }

    /// The `dead-letter-names` body the core KAT pins decodes to the name it
    /// spells, so a layout change on one side fails here.
    #[test]
    fn the_kat_dead_letter_names_body_decodes() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../core/kat/vectors/owner_local/owner_local_accept.json"
        ))
        .expect("the KAT file parses");
        let body = vectors
            .iter()
            .find(|vector| vector["name"] == "dead-letter-names-body")
            .and_then(|vector| vector["body"].as_str())
            .map(|hex| hex::decode(hex).expect("the KAT body is hex"))
            .expect("the KAT pins the body");
        let root = compute_cid(CONTENT_CID_CODEC, b"a parked version root");
        let name = IpnsName::from_public_key(&Ed25519Signer::from_seed([0xd1; 32]).verifying_key());

        assert_eq!(
            decode_dead_letter_name(&body, OpId(7), &root).as_deref(),
            Some(name.as_str())
        );
    }

    #[test]
    fn a_name_key_ends_with_its_op_id() {
        let key = dead_letter_name_key(&[3; 32], OpId(0x0102)).expect("a key");
        assert_eq!(dead_letter_name_op(&key), Some(OpId(0x0102)));
        assert_eq!(dead_letter_name_op(b"cbx/dj/0123456789"), None);
    }
}
