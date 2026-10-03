//! The owner's confirmed root copy. Recovery opens the seed from its owner blob.

use zeroize::Zeroizing;

use super::MAX_BLOCK_BYTES;
use crate::codec::scrub::ScrubOwned;
use crate::codec::{Map, Value, decode, encode};
use crate::error::{CodecError, Malformed};
use crate::ipns::MAX_IPNS_NAME_BYTES;
use crate::seal::body::{assert_within_bound, bytes_fixed, req};

/// Maximum payload bytes of one cached IPNS record.
pub const MAX_OWNER_SEED_RECORD_BYTES: usize = 10 * 1024;
/// Maximum encoded cache body, including the encrypted head and CBOR framing.
pub const MAX_OWNER_SEED_CACHE_BYTES: usize =
    MAX_BLOCK_BYTES + MAX_OWNER_SEED_RECORD_BYTES + MAX_IPNS_NAME_BYTES + 151;

/// A confirmed read and its recovery inputs. The parent seed zeroizes here.
pub struct OwnerSeedRecord {
    pub scope_id: [u8; 16],
    pub epoch: u64,
    pub write_epoch: u64,
    pub parent_node_seed: Option<Zeroizing<[u8; 32]>>,
    pub ipns_name: Vec<u8>,
    pub record_bytes: Vec<u8>,
    pub head_block: Vec<u8>,
}

impl OwnerSeedRecord {
    fn validate(&self) -> Result<(), CodecError> {
        assert_within_bound("ipnsName", self.ipns_name.len(), MAX_IPNS_NAME_BYTES)?;
        assert_within_bound(
            "ipnsRecord",
            self.record_bytes.len(),
            MAX_OWNER_SEED_RECORD_BYTES,
        )?;
        assert_within_bound("headBlock", self.head_block.len(), MAX_BLOCK_BYTES)
    }
}

/// Encode only a body the matching decoder can read (AGENTS.md rule 8).
pub fn encode_owner_seed_record(
    record: &OwnerSeedRecord,
) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    record.validate()?;
    let mut map = Map::new();
    map.insert("v", Value::Unsigned(1));
    map.insert("scope", Value::Bytes(record.scope_id.to_vec()));
    map.insert("epoch", Value::Unsigned(record.epoch));
    map.insert("writeEpoch", Value::Unsigned(record.write_epoch));
    if let Some(seed) = &record.parent_node_seed {
        map.insert("parentNodeSeed", Value::Bytes(seed.to_vec()));
    }
    map.insert("ipnsName", Value::Bytes(record.ipns_name.clone()));
    map.insert("ipnsRecord", Value::Bytes(record.record_bytes.clone()));
    map.insert("headBlock", Value::Bytes(record.head_block.clone()));
    let value = ScrubOwned(Value::Map(map));
    let bytes = Zeroizing::new(encode(value.value())?);
    assert_within_bound("ownerSeedCache", bytes.len(), MAX_OWNER_SEED_CACHE_BYTES)?;
    Ok(bytes)
}

/// Decode a bounded body. The caller must authenticate its owner-local seal first.
pub fn decode_owner_seed_record(bytes: &[u8]) -> Result<OwnerSeedRecord, CodecError> {
    assert_within_bound("ownerSeedCache", bytes.len(), MAX_OWNER_SEED_CACHE_BYTES)?;
    let value = ScrubOwned(decode(bytes)?);
    let map = value.value().as_map()?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != 1 {
        return Err(Malformed::UnsupportedRecordVersion { version }.into());
    }
    const KEYS: &[&str] = &[
        "v",
        "scope",
        "epoch",
        "writeEpoch",
        "parentNodeSeed",
        "ipnsName",
        "ipnsRecord",
        "headBlock",
    ];
    if let Some((key, _)) = map
        .entries()
        .iter()
        .find(|(key, _)| !KEYS.contains(&key.as_str()))
    {
        return Err(Malformed::UnknownRecordField { key: key.clone() }.into());
    }
    let record = OwnerSeedRecord {
        scope_id: bytes_fixed(req(map, "scope")?, "scope")?,
        epoch: req(map, "epoch")?.as_unsigned()?,
        write_epoch: req(map, "writeEpoch")?.as_unsigned()?,
        parent_node_seed: map
            .get("parentNodeSeed")
            .map(|v| bytes_fixed(v, "parentNodeSeed").map(Zeroizing::new))
            .transpose()?,
        ipns_name: req(map, "ipnsName")?.as_bytes()?.to_vec(),
        record_bytes: req(map, "ipnsRecord")?.as_bytes()?.to_vec(),
        head_block: req(map, "headBlock")?.as_bytes()?.to_vec(),
    };
    record.validate()?;
    Ok(record)
}
