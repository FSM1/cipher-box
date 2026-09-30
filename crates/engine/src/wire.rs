//! The serde shape of the facade commands at the WASM boundary: the adapters
//! for the field types whose durable serde form is not the boundary form
//! (blueprint/web-client.md "WASM packaging and the type boundary").
//!
//! [`NodeId`] and [`NodeKind`] already derive serde for the op queue, which must
//! still read what the previous release wrote, so the boundary spells them
//! through these adapters rather than through a changed derive.

use core::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::{SerializeStruct, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::content::ByoBearer;
use crate::facade::{NodeId, NodeKind};
use crate::seams::check_bearer;
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
}

/// An optional node id; `null` and `undefined` are both absent.
pub mod opt_node_id {
    use super::*;

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

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    enum Wire {
        File,
        Folder,
    }

    /// Refuses any other spelling.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<NodeKind, D::Error> {
        Ok(match Wire::deserialize(deserializer)? {
            Wire::File => NodeKind::File,
            Wire::Folder => NodeKind::Folder,
        })
    }
}

/// A text value the boundary holds in a zeroizing buffer. The decoded string
/// moves into the buffer, so no second copy is made.
pub mod zeroizing_string {
    use super::*;

    /// Takes a JS string.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        String::deserialize(deserializer).map(Zeroizing::new)
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

/// A bearer a host sent as bytes, as the zeroizing text a request splices.
/// `String::from_utf8` reuses the allocation, so the credential is never
/// copied, and the refused bytes are wiped before the refusal returns. The
/// refusal carries no part of the value.
pub fn bearer_from_bytes(bytes: Vec<u8>) -> Result<Zeroizing<String>, InvalidBearerBytes> {
    let token = Zeroizing::new(String::from_utf8(bytes).map_err(|error| {
        error.into_bytes().zeroize();
        InvalidBearerBytes
    })?);
    check_bearer(&token).map_err(|_| InvalidBearerBytes)?;
    Ok(token)
}

/// The bytes are not a sendable bearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBearerBytes;

impl fmt::Display for InvalidBearerBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("accessToken must be a sendable bearer")
    }
}

impl std::error::Error for InvalidBearerBytes {}

/// `null` stores no bearer and [`KEEP_STORED_BEARER`] keeps the stored one.
/// A bearer's bytes are refused and wiped here: the boundary takes them into a
/// zeroizing buffer itself ([`bearer_from_bytes`]), outside the serde decode
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
