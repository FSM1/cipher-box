//! Encode-side refusals of the link-first fields (AGENTS.md rule 8). CI also
//! runs this file under `--release`, where `debug_assert!` is compiled out, so
//! a refusal that leans on one fails there.

use core::num::NonZeroU64;

use cipherbox_core::codec::Value;
use cipherbox_core::seal::{
    EntryKind, GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, GranteeName,
    MAX_GRANTEE_NAME_BYTES, NameSource, Permission, PreservedFields, WriteBody,
    encode_grant_set_commitment, encode_write_body, sign_grant_set,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;

const PRK: [u8; 32] = [0x66; 32];

fn commitment(entry: GrantSetEntry) -> GrantSetCommitment {
    GrantSetCommitment {
        ipns_name: b"scope-root".to_vec(),
        owner_pseudonym_pk: [0x88; 32],
        cut_epoch: 0,
        entries: vec![entry],
        unknown: PreservedFields::new(),
    }
}

fn entry(permission: Permission) -> GrantSetEntry {
    GrantSetEntry::new(&PRK, [0x01; 32], [0x41; 32], permission, [0x02; 32])
}

fn refused(c: &GrantSetCommitment) -> (&'static str, &'static str) {
    let owner = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
    (
        encode_grant_set_commitment(c).unwrap_err().check(),
        sign_grant_set(&owner, c).unwrap_err().check(),
    )
}

#[test]
fn a_deadline_on_a_personal_entry_is_refused_at_encode_and_sign() {
    let mut e = entry(Permission::Read);
    e.deadline = NonZeroU64::new(1_800_000_000_000);
    assert_eq!(
        refused(&commitment(e)),
        (
            "link-field-on-personal-entry",
            "link-field-on-personal-entry"
        )
    );
}

#[test]
fn a_link_committed_at_write_is_refused_at_encode_and_sign() {
    let mut e = entry(Permission::Write);
    e.kind = EntryKind::Link;
    assert_eq!(
        refused(&commitment(e)),
        ("link-permission-not-read", "link-permission-not-read")
    );
}

#[test]
fn a_link_field_smuggled_through_preserved_fields_is_refused() {
    let mut e = entry(Permission::Read);
    e.unknown = PreservedFields::from_iter([("kind".to_owned(), Value::Text("link".into()))]);
    assert_eq!(
        refused(&commitment(e)),
        ("unknown-field-collision", "unknown-field-collision")
    );
}

#[test]
fn a_malformed_grantee_name_cannot_be_built() {
    for name in [
        String::new(),
        "n".repeat(MAX_GRANTEE_NAME_BYTES + 1),
        "Alice\u{7}".to_owned(),
    ] {
        assert_eq!(
            GranteeName::new(name, NameSource::Owner)
                .unwrap_err()
                .check(),
            "invalid-grantee-name"
        );
    }
}

#[test]
fn a_signed_row_field_smuggled_through_preserved_fields_is_refused() {
    let mut row = GrantLedgerEntry::new(
        [0x02; 33],
        [0x11; 32],
        Permission::Read,
        [0x21; 32],
        [0x77; 64],
    );
    row.unknown =
        PreservedFields::from_iter([("granteeName".to_owned(), Value::Text(String::new()))]);
    let body = WriteBody {
        grant_ledger: vec![row],
        write_history_link: Vec::new(),
        direct_child_scope_index: Vec::new(),
        unknown: PreservedFields::new(),
    };
    assert_eq!(
        encode_write_body(&body).unwrap_err().check(),
        "unknown-field-collision"
    );
}
