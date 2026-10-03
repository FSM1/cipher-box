//! The owner's confirmed scope seed and the encrypted root copy it can recover.

use zeroize::Zeroizing;

use super::MAX_BLOCK_BYTES;
use crate::codec::scrub::ScrubOwned;
use crate::codec::{Map, Value, decode, encode};
use crate::error::{CodecError, Malformed};
use crate::ipns::MAX_IPNS_NAME_BYTES;

/// Maximum payload bytes of one cached IPNS record.
pub const MAX_OWNER_SEED_RECORD_BYTES: usize = 10 * 1024;
/// Maximum encoded cache body, including the encrypted head and CBOR framing.
pub const MAX_OWNER_SEED_CACHE_BYTES: usize =
    MAX_BLOCK_BYTES + MAX_OWNER_SEED_RECORD_BYTES + MAX_IPNS_NAME_BYTES + 170;

/// A confirmed read and its recovery inputs. Seeds zeroize at this owner.
pub struct OwnerSeedRecord {
    pub scope_id: [u8; 16],
    pub epoch: u64,
    pub seed: Zeroizing<[u8; 32]>,
    pub parent_node_seed: Option<Zeroizing<[u8; 32]>>,
    pub ipns_name: Vec<u8>,
    pub record_bytes: Vec<u8>,
    pub head_block: Vec<u8>,
}

fn bounded(field: &'static str, size: usize, limit: usize) -> Result<(), CodecError> {
    if size > limit {
        return Err(Malformed::TooManyStructures {
            collection: field,
            count: size,
            limit,
        }
        .into());
    }
    Ok(())
}

impl OwnerSeedRecord {
    fn validate(&self) -> Result<(), CodecError> {
        bounded("ipnsName", self.ipns_name.len(), MAX_IPNS_NAME_BYTES)?;
        bounded(
            "ipnsRecord",
            self.record_bytes.len(),
            MAX_OWNER_SEED_RECORD_BYTES,
        )?;
        bounded("headBlock", self.head_block.len(), MAX_BLOCK_BYTES)
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
    map.insert("seed", Value::Bytes(record.seed.to_vec()));
    if let Some(seed) = &record.parent_node_seed {
        map.insert("parentNodeSeed", Value::Bytes(seed.to_vec()));
    }
    map.insert("ipnsName", Value::Bytes(record.ipns_name.clone()));
    map.insert("ipnsRecord", Value::Bytes(record.record_bytes.clone()));
    map.insert("headBlock", Value::Bytes(record.head_block.clone()));
    let value = ScrubOwned(Value::Map(map));
    let bytes = Zeroizing::new(encode(value.value())?);
    bounded("ownerSeedCache", bytes.len(), MAX_OWNER_SEED_CACHE_BYTES)?;
    Ok(bytes)
}

fn req<'a>(map: &'a Map, key: &'static str) -> Result<&'a Value, CodecError> {
    map.get(key)
        .ok_or_else(|| Malformed::MissingField { field: key }.into())
}

fn fixed<const N: usize>(value: &Value, field: &'static str) -> Result<[u8; N], CodecError> {
    let bytes = value.as_bytes()?;
    bytes.try_into().map_err(|_| {
        Malformed::InvalidFieldLength {
            field,
            expected: N,
            found: bytes.len(),
        }
        .into()
    })
}

/// Decode a bounded body. The caller must authenticate its owner-local seal first.
pub fn decode_owner_seed_record(bytes: &[u8]) -> Result<OwnerSeedRecord, CodecError> {
    bounded("ownerSeedCache", bytes.len(), MAX_OWNER_SEED_CACHE_BYTES)?;
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
        "seed",
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
        scope_id: fixed(req(map, "scope")?, "scope")?,
        epoch: req(map, "epoch")?.as_unsigned()?,
        seed: Zeroizing::new(fixed(req(map, "seed")?, "seed")?),
        parent_node_seed: map
            .get("parentNodeSeed")
            .map(|v| fixed(v, "parentNodeSeed").map(Zeroizing::new))
            .transpose()?,
        ipns_name: req(map, "ipnsName")?.as_bytes()?.to_vec(),
        record_bytes: req(map, "ipnsRecord")?.as_bytes()?.to_vec(),
        head_block: req(map, "headBlock")?.as_bytes()?.to_vec(),
    };
    record.validate()?;
    Ok(record)
}
