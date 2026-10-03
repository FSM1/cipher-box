use core::num::NonZeroU64;

use cipherbox_core::codec::Value;
use cipherbox_core::seal::{
    GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, GrantSetEntryKind, GranteeName,
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
    e.kind = GrantSetEntryKind::Link;
    assert_eq!(
        refused(&commitment(e)),
        ("link-permission-not-read", "link-permission-not-read")
    );
}

#[test]
fn a_link_without_each_required_field_is_refused_at_encode_and_sign() {
    let full = || {
        let mut e = entry(Permission::Read);
        e.kind = GrantSetEntryKind::Link;
        e.deadline = NonZeroU64::new(1_800_000_000_000);
        e.conversion_permission = Some(Permission::Read);
        e.admission_cap = Some(0);
        e
    };
    let owner = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
    assert!(sign_grant_set(&owner, &commitment(full())).is_ok());
    let strips: [fn(&mut GrantSetEntry); 3] = [
        |e| e.deadline = None,
        |e| e.conversion_permission = None,
        |e| e.admission_cap = None,
    ];
    for strip in strips {
        let mut e = full();
        strip(&mut e);
        assert_eq!(refused(&commitment(e)), ("missing-field", "missing-field"));
    }
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
        "Alice\u{202E}".to_owned(),
        "Alice\u{2066}".to_owned(),
        "Alice\u{200B}".to_owned(),
        "Alice\u{FEFF}".to_owned(),
        "Alice\u{2028}".to_owned(),
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

#[test]
fn malformed_content_cids_are_refused_at_body_encode_and_decode() {
    use cipherbox_core::codec::{Map, encode};
    use cipherbox_core::content::compute_cid;
    use cipherbox_core::seal::{ReadBody, Version, decode_read_body, encode_read_body};

    let mut bad_framing = compute_cid(cipherbox_core::content::CONTENT_CID_CODEC, b"content");
    bad_framing[0] = 0;
    for cid in [Vec::new(), vec![1; 35], bad_framing] {
        let body = ReadBody::File {
            created_at: 1,
            modified_at: 2,
            versions: vec![Version::new(cid.clone(), [3; 32], 4, 2)],
            unknown: PreservedFields::new(),
        };
        assert_eq!(
            encode_read_body(&body).unwrap_err().check(),
            "content-cid-malformed"
        );
        let mut version = Map::new();
        version.insert("contentCid", Value::Bytes(cid));
        version.insert("contentKey", Value::Bytes(vec![3; 32]));
        version.insert("size", Value::Unsigned(4));
        version.insert("modifiedAt", Value::Unsigned(2));
        let mut wire = Map::new();
        wire.insert("kind", Value::Text("file".into()));
        wire.insert("createdAt", Value::Unsigned(1));
        wire.insert("modifiedAt", Value::Unsigned(2));
        wire.insert("versions", Value::Array(vec![Value::Map(version)]));
        assert_eq!(
            decode_read_body(&encode(&Value::Map(wire)).unwrap())
                .unwrap_err()
                .check(),
            "content-cid-malformed"
        );
    }
}

#[test]
fn an_owner_seed_cache_refuses_oversized_fields_in_both_directions() {
    use cipherbox_core::codec::{decode, encode};
    use cipherbox_core::seal::{
        MAX_BLOCK_BYTES, MAX_OWNER_SEED_RECORD_BYTES, OwnerSeedRecord, decode_owner_seed_record,
        encode_owner_seed_record,
    };
    use zeroize::Zeroizing;
    let mut record = OwnerSeedRecord {
        scope_id: [0x21; 16],
        epoch: 1,
        write_epoch: 1,
        seed: Zeroizing::new([0x32; 32]),
        parent_node_seed: None,
        ipns_name: b"name".to_vec(),
        record_bytes: vec![1],
        head_block: vec![2],
    };
    for (field, limit) in [
        ("ipnsName", cipherbox_core::ipns::MAX_IPNS_NAME_BYTES),
        ("ipnsRecord", MAX_OWNER_SEED_RECORD_BYTES),
        ("headBlock", MAX_BLOCK_BYTES),
    ] {
        let body = encode_owner_seed_record(&record).expect("valid body");
        let mut value = decode(&body).expect("det-CBOR");
        let Value::Map(map) = &mut value else {
            panic!("map");
        };
        map.insert(field, Value::Bytes(vec![0; limit + 1]));
        let rejected = decode_owner_seed_record(&encode(&value).expect("det-CBOR"));
        assert!(rejected.is_err(), "the decoder enforces the bound");
        value.zeroize_bytes();
        let bytes = match field {
            "ipnsName" => &mut record.ipns_name,
            "ipnsRecord" => &mut record.record_bytes,
            _ => &mut record.head_block,
        };
        let old = std::mem::replace(bytes, vec![0; limit + 1]);
        assert!(
            encode_owner_seed_record(&record).is_err(),
            "the producer enforces the same bound in release"
        );
        let bytes = match field {
            "ipnsName" => &mut record.ipns_name,
            "ipnsRecord" => &mut record.record_bytes,
            _ => &mut record.head_block,
        };
        *bytes = old;
    }
}
