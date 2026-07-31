//! Structured AAD construction and the structure-tag registry
//! (blueprint/core.md "Envelope and structures", "Structure-tag registry").
//!
//! The AAD is the authenticated-but-not-encrypted context every sealed body is
//! bound to: `(v, id, scope, epoch, structTag)` under the `cipherbox/v2` domain
//! separator (#27 D3/D4). It is a det-CBOR array, byte-frozen by the KAT, and is
//! never decoded — only fed to the AEAD — so it carries no unknown-field
//! tolerance.
//!
//! What each bound element buys: **`v`** is the downgrade defence (a rolled-back
//! `v` recomputes a different AAD and fails the tag); **`id` + `scope` + `epoch`**
//! close transplant of a body across nodes, scopes, and epochs; **`structTag`**
//! stops a read-body ciphertext being reinterpreted as a write-body, grant blob,
//! or pointer payload.
//!
//! **`ipnsName` is deliberately excluded** (#39 D7): the name wave republishes
//! epoch-lagged bodies under fresh names, so binding the name would break the
//! wave. Name transplant is closed by duplicate-`ipnsName` rejection at decode
//! ([`super::body`]) instead of by the tag.

use crate::codec::{Value, encode_fixed_depth};

/// The fresh `cipherbox/v2` AAD domain separator. Its presence as the first
/// AAD element keeps CipherBox v2 seals from ever colliding with another
/// protocol's (or a future v-line's) authenticated data. Frozen in the KAT
/// manifest; changing it is a breaking re-seal.
pub const AAD_DOMAIN: &str = "cipherbox/v2/aad";

// ---------------------------------------------------------------------------
// Structure-tag registry: the domain-separation byte-space, frozen here and in
// the KAT manifest. Every sealed/signed structure has exactly one tag; the tag
// is bound into the AAD and the structure-signature preimage. Bytes are assigned
// once and never reused — a fresh v2 space (the v1 content self-seal role `0x03`
// has no v2 analog and is not carried).
// ---------------------------------------------------------------------------

/// `read-body` — the sealed node body (folder children / file versions).
pub const STRUCT_TAG_READ_BODY: u8 = 0x01;
/// `write-body` — the scope-root write-plane payload.
pub const STRUCT_TAG_WRITE_BODY: u8 = 0x02;
/// `grant-blob` — a scope seed sealed to one recipient.
pub const STRUCT_TAG_GRANT_BLOB: u8 = 0x03;
/// `owner-blob` — the override seed wrapped to the owner.
pub const STRUCT_TAG_OWNER_BLOB: u8 = 0x04;
/// `ascent-link` — the override seed sealed to the parent keypair.
pub const STRUCT_TAG_ASCENT_LINK: u8 = 0x05;
/// `history-link` — the previous epoch's seed under the current one.
pub const STRUCT_TAG_HISTORY_LINK: u8 = 0x06;
/// `pointer-payload` — the re-point object at a scope/vault pointer.
pub const STRUCT_TAG_POINTER_PAYLOAD: u8 = 0x07;
/// `mailbox-payload` — the HPKE-sealed mailbox item.
pub const STRUCT_TAG_MAILBOX_PAYLOAD: u8 = 0x08;
/// `owner-write-blob` — the write-scope seed HPKE-sealed to the owner's enc
/// subkey, the write-plane mirror of the owner blob (owner cold-start write-seed
/// recovery; blueprint/core.md "Grant section").
pub const STRUCT_TAG_OWNER_WRITE_BLOB: u8 = 0x09;
/// `op-record` — the durable op-queue entry HPKE-sealed to the owner's enc
/// subkey ([`super::op_record`]). Local durable state rather than a published
/// body, so it binds its own clear header instead of an [`AadContext`].
pub const STRUCT_TAG_OP_RECORD: u8 = 0x0a;
/// `settings-record` — the published vault settings record HPKE-sealed to the
/// owner's enc subkey ([`super::settings_record`]). Like `op-record`, it binds
/// its own clear header instead of an [`AadContext`].
pub const STRUCT_TAG_SETTINGS_RECORD: u8 = 0x0b;
/// `content-key` — the per-version content key HPKE-sealed to the owner's enc
/// subkey while its version waits in the op queue ([`super::content_key`]).
/// Local durable state like `op-record`, and bound to its own epoch rather than
/// an [`AadContext`].
pub const STRUCT_TAG_CONTENT_KEY: u8 = 0x0c;

/// One registry entry's frozen, machine-checkable metadata: the structure's
/// stable name and its domain-separation byte. The KAT manifest freezes this
/// table; [`STRUCT_TAGS`] is its single source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructTagSpec {
    pub name: &'static str,
    pub tag: u8,
}

/// The twelve structure tags, in registry (byte) order. Every new tag extends
/// this table and its manifest vectors before merge (blueprint/core.md).
pub const STRUCT_TAGS: &[StructTagSpec] = &[
    StructTagSpec {
        name: "read-body",
        tag: STRUCT_TAG_READ_BODY,
    },
    StructTagSpec {
        name: "write-body",
        tag: STRUCT_TAG_WRITE_BODY,
    },
    StructTagSpec {
        name: "grant-blob",
        tag: STRUCT_TAG_GRANT_BLOB,
    },
    StructTagSpec {
        name: "owner-blob",
        tag: STRUCT_TAG_OWNER_BLOB,
    },
    StructTagSpec {
        name: "ascent-link",
        tag: STRUCT_TAG_ASCENT_LINK,
    },
    StructTagSpec {
        name: "history-link",
        tag: STRUCT_TAG_HISTORY_LINK,
    },
    StructTagSpec {
        name: "pointer-payload",
        tag: STRUCT_TAG_POINTER_PAYLOAD,
    },
    StructTagSpec {
        name: "mailbox-payload",
        tag: STRUCT_TAG_MAILBOX_PAYLOAD,
    },
    StructTagSpec {
        name: "owner-write-blob",
        tag: STRUCT_TAG_OWNER_WRITE_BLOB,
    },
    StructTagSpec {
        name: "op-record",
        tag: STRUCT_TAG_OP_RECORD,
    },
    StructTagSpec {
        name: "settings-record",
        tag: STRUCT_TAG_SETTINGS_RECORD,
    },
    StructTagSpec {
        name: "content-key",
        tag: STRUCT_TAG_CONTENT_KEY,
    },
];

/// The AAD context of a seal: everything the ciphertext is bound to except the
/// key/nonce. `id` and `scope` are the 16-byte node and scope-root UUIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AadContext {
    /// The envelope format+suite version.
    pub v: u64,
    /// The node id (16-byte UUID).
    pub id: [u8; 16],
    /// The scope-root node id (16-byte UUID) — the epoch tag's scope.
    pub scope: [u8; 16],
    /// The epoch-tag epoch (scope-relative rotation counter).
    pub epoch: u64,
    /// The structure tag (a [`STRUCT_TAGS`] byte).
    pub struct_tag: u8,
}

/// Build the AAD bytes for a seal: the det-CBOR encoding of
/// `[AAD_DOMAIN, v, id, scope, epoch, structTag]`. Deterministic and
/// unambiguous; the array positions are frozen by the KAT.
pub fn build_aad(ctx: &AadContext) -> Vec<u8> {
    encode_fixed_depth(&Value::Array(vec![
        Value::Text(AAD_DOMAIN.to_string()),
        Value::Unsigned(ctx.v),
        Value::Bytes(ctx.id.to_vec()),
        Value::Bytes(ctx.scope.to_vec()),
        Value::Unsigned(ctx.epoch),
        Value::Unsigned(u64::from(ctx.struct_tag)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn ctx() -> AadContext {
        AadContext {
            v: 2,
            id: [1; 16],
            scope: [2; 16],
            epoch: 7,
            struct_tag: STRUCT_TAG_READ_BODY,
        }
    }

    #[test]
    fn struct_tags_are_unique_named_and_byte_ordered() {
        let mut names = BTreeSet::new();
        let mut tags = BTreeSet::new();
        for (i, s) in STRUCT_TAGS.iter().enumerate() {
            assert!(names.insert(s.name), "duplicate tag name {}", s.name);
            assert!(tags.insert(s.tag), "duplicate tag byte {:#x}", s.tag);
            // Registry order is byte order, and bytes are 1-based dense.
            assert_eq!(s.tag as usize, i + 1, "tag {} out of byte order", s.name);
        }
        assert_eq!(
            STRUCT_TAGS.len(),
            12,
            "the frozen byte-space is twelve tags"
        );
    }

    #[test]
    fn aad_is_deterministic_and_decodes_as_the_frozen_array() {
        let a = build_aad(&ctx());
        assert_eq!(a, build_aad(&ctx()), "AAD must be deterministic");
        // It is valid det-CBOR (never decoded in production, but the layout is
        // frozen): a 6-element array with the domain separator first.
        let v = crate::codec::decode(&a).expect("AAD is valid det-CBOR");
        let arr = v.as_array().expect("AAD is an array");
        assert_eq!(arr.len(), 6);
        assert_eq!(arr[0].as_text().unwrap(), AAD_DOMAIN);
    }

    #[test]
    fn every_bound_field_changes_the_aad() {
        let base = build_aad(&ctx());
        let mutate = |f: &dyn Fn(&mut AadContext)| {
            let mut c = ctx();
            f(&mut c);
            build_aad(&c)
        };
        assert_ne!(base, mutate(&|c| c.v += 1), "v must be bound (downgrade)");
        assert_ne!(base, mutate(&|c| c.id[0] ^= 1), "id must be bound");
        assert_ne!(base, mutate(&|c| c.scope[0] ^= 1), "scope must be bound");
        assert_ne!(base, mutate(&|c| c.epoch += 1), "epoch must be bound");
        assert_ne!(
            base,
            mutate(&|c| c.struct_tag = STRUCT_TAG_WRITE_BODY),
            "structTag must be bound"
        );
    }
}
