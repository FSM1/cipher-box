use cipherbox_core::seal::{OwnerSeedRecord, decode_owner_seed_record, encode_owner_seed_record};
use cipherbox_core::suite::secret::ct_eq;
use zeroize::Zeroizing;

#[test]
fn a_confirmed_owner_seed_and_its_recovery_copy_round_trip() {
    let record = OwnerSeedRecord {
        scope_id: [0x21; 16],
        epoch: 7,
        write_epoch: 1,
        parent_node_seed: Some(Zeroizing::new([0x43; 32])),
        ipns_name: b"scope-name".to_vec(),
        record_bytes: vec![1, 2, 3],
        head_block: vec![4, 5, 6],
    };
    let bytes = encode_owner_seed_record(&record).expect("encode");
    let restored = decode_owner_seed_record(&bytes).expect("decode");
    assert_eq!(restored.scope_id, [0x21; 16]);
    assert_eq!(restored.epoch, 7);
    assert!(
        ct_eq(
            restored.parent_node_seed.as_ref().unwrap(),
            record.parent_node_seed.as_ref().unwrap()
        ),
        "the parent seed survives"
    );
    assert_eq!(restored.ipns_name, b"scope-name");
    assert_eq!(restored.record_bytes, [1, 2, 3]);
    assert_eq!(restored.head_block, [4, 5, 6]);
}
