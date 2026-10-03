//! The serde shape of the facade commands, events and views at the WASM
//! boundary: the adapters for the field types whose durable serde form is not
//! the boundary form (blueprint/web-client.md "WASM packaging and the type
//! boundary").
//!
//! [`NodeId`] and [`facade::NodeKind`] already derive serde for the op queue,
//! which must still read what the previous release wrote, so the boundary
//! spells them through these adapters rather than through a changed derive.

use core::fmt;

use cipherbox_core::seal::NameSource;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::content::ByoBearer;
use crate::facade::{self, NodeId, QueueHoldReason};
use crate::record_plane::BinIndexHoldCheck;
use crate::seams::{OpId, UnixMillis};
use crate::settings::SettingsHoldCheck;
use crate::settings::{DEFAULT_BIN_RETENTION_DAYS, MAX_BIN_RETENTION_DAYS};
use crate::{Contact, MintedInviteLink, RetentionPolicy};

/// The `accessToken` value that keeps the bearer the session already holds.
pub const KEEP_STORED_BEARER: &str = "keep";

/// Bytes as a `Uint8Array` or `ArrayBuffer` only. `serde_bytes` would also take
/// a string's UTF-8 or an array of numbers, and a sixteen-character name would
/// then pass for a node id.
pub mod bytes {
    use super::*;

    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a Uint8Array")
        }

        fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(bytes)
        }

        fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
            Ok(bytes.to_vec())
        }
    }

    /// Refuses every value that is not bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}

/// Optional bytes; `null` and `undefined` are both absent.
pub mod opt_bytes {
    use super::*;

    #[derive(Deserialize)]
    struct Wire(#[serde(with = "bytes")] Vec<u8>);

    /// Refuses a present value that is not bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Ok(Option::<Wire>::deserialize(deserializer)?.map(|Wire(bytes)| bytes))
    }
}

/// A node id as the raw 16 bytes of a `Uint8Array`.
pub mod node_id {
    use super::*;

    /// Refuses any length but 16.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<NodeId, D::Error> {
        let raw = bytes::deserialize(deserializer)?;
        <[u8; 16]>::try_from(raw.as_slice())
            .map(NodeId)
            .map_err(|_| de::Error::invalid_length(raw.len(), &"16 node id bytes"))
    }

    /// Writes the 16 bytes as a `Uint8Array`.
    pub fn serialize<S: Serializer>(id: &NodeId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&id.0)
    }
}

/// An optional node id; `null` and `undefined` are both absent.
pub mod opt_node_id {
    use super::*;

    /// Writes a known id as bytes, or null when the op could not be decoded.
    pub fn serialize<S: Serializer>(id: &Option<NodeId>, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(
            &id.as_ref().map(|id| serde_bytes::Bytes::new(&id.0)),
            serializer,
        )
    }

    #[derive(Deserialize)]
    struct Wire(#[serde(with = "node_id")] NodeId);

    /// Refuses a present id of any length but 16.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<NodeId>, D::Error> {
        Ok(Option::<Wire>::deserialize(deserializer)?.map(|Wire(id)| id))
    }
}

/// A command that carries no field. Serde reads an internally tagged unit
/// variant with any fields beside the tag, so each one refuses them here.
pub fn no_fields<'de, D: Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    struct Empty;

    impl<'de> Visitor<'de> for Empty {
        type Value = ();

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("no field beside `kind`")
        }

        fn visit_unit<E: de::Error>(self) -> Result<(), E> {
            Ok(())
        }

        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            match map.next_key::<de::IgnoredAny>()? {
                None => Ok(()),
                Some(_) => Err(de::Error::custom("unknown field")),
            }
        }
    }

    deserializer.deserialize_any(Empty)
}

/// A node kind as `"file"` or `"folder"`.
pub mod node_kind {
    use super::*;

    /// The boundary spelling of a [`facade::NodeKind`].
    #[derive(Serialize, Deserialize, tsify::Tsify)]
    #[serde(rename_all = "camelCase")]
    pub enum NodeKind {
        /// `"file"`.
        File,
        /// `"folder"`.
        Folder,
    }

    /// Refuses any other spelling.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<facade::NodeKind, D::Error> {
        Ok(match NodeKind::deserialize(deserializer)? {
            NodeKind::File => facade::NodeKind::File,
            NodeKind::Folder => facade::NodeKind::Folder,
        })
    }

    /// Writes the kind as the decode reads it.
    pub fn serialize<S: Serializer>(
        kind: &facade::NodeKind,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match kind {
            facade::NodeKind::File => NodeKind::File,
            facade::NodeKind::Folder => NodeKind::Folder,
        }
        .serialize(serializer)
    }
}

/// A secret text field — an invite fragment, an identity token — which the
/// boundary takes into a zeroizing buffer itself, outside the serde decode that
/// buffers the whole command. This decode takes only the empty placeholder the
/// boundary puts in its place, and wipes and refuses anything else.
pub mod secret_placeholder {
    use super::*;

    /// Takes `""` alone.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        if text.is_empty() {
            Ok(text)
        } else {
            Err(de::Error::custom(
                "a secret is taken outside the command decode",
            ))
        }
    }
}

/// The key of the object the boundary puts in place of each JS `bigint` before
/// the decode. Serde buffers a tagged command before it picks the variant, and
/// the buffer holds a safe-integer `number` and a `bigint` as the same integer;
/// the tag keeps them apart, so a `u64` field takes a `bigint` alone and a
/// `number` field refuses one.
pub const BIGINT_TAG: &str = "$bigint";

/// A `u64` from a tagged `bigint`.
pub mod big_u64 {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Tagged {
        // Serde takes a literal here: this is `BIGINT_TAG`.
        #[serde(rename = "$bigint")]
        decimal: String,
    }

    /// Refuses a `number`, a negative value, one past `u64::MAX`, and any text
    /// but ASCII digits, which is all `BigInt.prototype.toString` writes.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let Tagged { decimal } = Tagged::deserialize(deserializer)?;
        let refused = || de::Error::custom("a u64 is a bigint in 0..=2^64-1");
        if decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit()) {
            return Err(refused());
        }
        decimal.parse().map_err(|_| refused())
    }
}

/// An optional `u64` from a tagged `bigint`; `null` and `undefined` are absent.
pub mod opt_big_u64 {
    use super::*;

    #[derive(Deserialize)]
    struct Wire(#[serde(with = "big_u64")] u64);

    /// Refuses a present value that is no tagged `bigint` in range.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Ok(Option::<Wire>::deserialize(deserializer)?.map(|Wire(n)| n))
    }
}

/// An op id from a tagged `bigint`.
pub mod op_id {
    use super::*;

    /// Refuses what [`big_u64`] refuses.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OpId, D::Error> {
        big_u64::deserialize(deserializer).map(OpId)
    }
}

/// An optional Unix-millis instant from a tagged `bigint`.
pub mod opt_unix_millis {
    use super::*;

    /// Refuses what [`opt_big_u64`] refuses.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<UnixMillis>, D::Error> {
        opt_big_u64::deserialize(deserializer).map(|at| at.map(UnixMillis))
    }
}

/// The retention policy as `keepLatestVersions`: a count of versions, or `null`
/// to keep every one.
pub mod keep_latest_versions {
    use super::*;
    use core::num::NonZeroU64;

    /// Refuses `0`, which would retire the live version of every file.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<RetentionPolicy, D::Error> {
        match Option::<u32>::deserialize(deserializer)? {
            None => Ok(RetentionPolicy::KeepAll),
            Some(n) => NonZeroU64::new(u64::from(n))
                .map(RetentionPolicy::KeepLatest)
                .ok_or_else(|| de::Error::custom("keepLatestVersions must be > 0")),
        }
    }

    /// Saturates a count past `u32::MAX`: a bound never reads as no bound.
    pub fn serialize<S: Serializer>(
        policy: &RetentionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match policy {
            RetentionPolicy::KeepAll => serializer.serialize_none(),
            RetentionPolicy::KeepLatest(n) => {
                serializer.serialize_some(&u32::try_from(n.get()).unwrap_or(u32::MAX))
            }
        }
    }
}

/// Days a soft-deleted node stays in the bin; absent or `null` takes
/// [`DEFAULT_BIN_RETENTION_DAYS`].
pub mod bin_retention_days {
    use super::*;

    /// Refuses a value past [`MAX_BIN_RETENTION_DAYS`], as the encode path does.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let days = Option::<u32>::deserialize(deserializer)?.unwrap_or(DEFAULT_BIN_RETENTION_DAYS);
        if days > MAX_BIN_RETENTION_DAYS {
            return Err(de::Error::custom(format_args!(
                "binRetentionDays must be <= {MAX_BIN_RETENTION_DAYS}"
            )));
        }
        Ok(days)
    }

    /// The default for an absent field.
    pub fn absent() -> u32 {
        DEFAULT_BIN_RETENTION_DAYS
    }
}

/// `null` stores no bearer and [`KEEP_STORED_BEARER`] keeps the stored one.
/// A bearer's bytes are refused and wiped here: the boundary takes them into a
/// zeroizing buffer itself, outside the serde decode
/// that buffers the whole command.
impl<'de> Deserialize<'de> for ByoBearer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BearerVisitor;

        impl<'de> Visitor<'de> for BearerVisitor {
            type Value = ByoBearer;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "\"{KEEP_STORED_BEARER}\" or null")
            }

            fn visit_unit<E: de::Error>(self) -> Result<ByoBearer, E> {
                Ok(ByoBearer::None)
            }

            fn visit_none<E: de::Error>(self) -> Result<ByoBearer, E> {
                Ok(ByoBearer::None)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<ByoBearer, E> {
                if value == KEEP_STORED_BEARER {
                    Ok(ByoBearer::Keep)
                } else {
                    Err(E::custom("a bearer crosses as bytes, never as text"))
                }
            }

            fn visit_byte_buf<E: de::Error>(self, mut bytes: Vec<u8>) -> Result<ByoBearer, E> {
                bytes.zeroize();
                Err(E::custom("a bearer is taken outside the command decode"))
            }
        }

        deserializer.deserialize_any(BearerVisitor)
    }
}

/// An imported contact as its two public keys.
pub fn contact<S: Serializer>(contact: &Contact, serializer: S) -> Result<S::Ok, S::Error> {
    let mut out = serializer.serialize_struct("Contact", 2)?;
    out.serialize_field(
        "identityPublicKey",
        serde_bytes::Bytes::new(&contact.identity_pk().to_sec1()),
    )?;
    out.serialize_field(
        "encPublicKey",
        serde_bytes::Bytes::new(&contact.enc_subkey().to_bytes()),
    )?;
    out.end()
}

/// A minted link as its URL fragment, serialized from the zeroizing buffer
/// without an intermediate copy.
pub fn minted_link<S: Serializer>(
    link: &MintedInviteLink,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut out = serializer.serialize_struct("MintedInviteLink", 1)?;
    out.serialize_field("fragment", link.fragment.as_str())?;
    out.end()
}

/// A grantee name and who chose it, as one value, so neither crosses without
/// the other.
#[derive(Serialize, tsify::Tsify)]
pub struct GranteeName<'a> {
    /// The name.
    pub name: &'a str,
    /// Who chose it.
    pub source: GranteeNameSource,
}

/// Who chose a grantee name ([`NameSource`]).
#[derive(Serialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
pub enum GranteeNameSource {
    /// The owner gave or edited the name.
    Owner,
    /// The claimant asked for the name.
    Claimant,
}

/// An optional grantee name as a [`GranteeName`].
pub fn grantee_name<S: Serializer>(
    named: &Option<(String, NameSource)>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    named
        .as_ref()
        .map(|(name, source)| GranteeName {
            name,
            source: match source {
                NameSource::Owner => GranteeNameSource::Owner,
                NameSource::Claimant => GranteeNameSource::Claimant,
            },
        })
        .serialize(serializer)
}

/// The held queue head, one variant per reason, each with only the figure its
/// own notice renders. A check names the rule that refused, never the endpoint
/// or the bearer the settings carry.
#[derive(Serialize, tsify::Tsify)]
#[serde(
    tag = "reason",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[tsify(large_number_types_as_bigints)]
pub enum QueueHold {
    /// Held over the account quota.
    Quota {
        /// The held op.
        op_id: OpId,
        /// The node the held op targets.
        #[serde(serialize_with = "node_id::serialize")]
        #[tsify(type = "Uint8Array")]
        node: NodeId,
        /// The byte count the resume probe must find room for.
        needed_bytes: u64,
    },
    /// Held over the member's own settings.
    Settings {
        /// The held op.
        op_id: OpId,
        /// The node the held op targets.
        #[serde(serialize_with = "node_id::serialize")]
        #[tsify(type = "Uint8Array")]
        node: NodeId,
        /// The rule that refused.
        check: SettingsHoldCheck,
    },
    /// Held over the owner's bin index.
    BinIndex {
        /// The held op.
        op_id: OpId,
        /// The node the held op targets.
        #[serde(serialize_with = "node_id::serialize")]
        #[tsify(type = "Uint8Array")]
        node: NodeId,
        /// The load outcome.
        check: BinIndexHoldCheck,
    },
}

impl From<facade::QueueHold> for QueueHold {
    fn from(hold: facade::QueueHold) -> Self {
        let (op_id, node) = (hold.op_id, hold.node);
        match hold.reason {
            QueueHoldReason::Quota { needed_bytes } => Self::Quota {
                op_id,
                node,
                needed_bytes,
            },
            QueueHoldReason::Settings(settings) => Self::Settings {
                op_id,
                node,
                check: settings.check(),
            },
            QueueHoldReason::BinIndex(check) => Self::BinIndex { op_id, node, check },
        }
    }
}

/// An optional held queue head as a [`QueueHold`].
pub fn queue_hold<S: Serializer>(
    hold: &Option<facade::QueueHold>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    hold.map(QueueHold::from).serialize(serializer)
}
