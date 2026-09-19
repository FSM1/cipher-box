use super::*;
use crate::grants::mint_grant_row;
use crate::testkit::{SeededEntropy, padding};
use cipherbox_core::seal::{
    ChildScopeRef, GrantSetEntry, MAX_DIRECT_CHILD_SCOPES, MAX_WRITE_BODY_BYTES,
    encode_grant_section, open_ascent_link, open_grant_blob, open_history_link, open_owner_blob,
    open_owner_history_link, open_owner_write_blob, sign_grant_set, sign_recipient_binding,
    verify_structure,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Verifier};
use cipherbox_core::suite::secret::ct_eq;
use cipherbox_core::suite::x25519::X25519Secret;

const V: u64 = 2;
const SCOPE: [u8; 16] = [0x5c; 16];
/// The name every honestly minted fixture set binds.
const MINTED_NAME: &[u8] = b"minted-scope-root-name";

/// An entropy seam that panics the moment it is drawn — the probe that turns
/// "eventually refused" into "refused before the first seal", since every
/// seal `reseal_scope_root` performs draws a nonce or an HPKE scalar first.
struct UndrawnEntropy;
impl Entropy for UndrawnEntropy {
    fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
        panic!("the guard must reject before any seal draws entropy");
    }
}

/// The oversize refusal reaches a caller under its own name, and no other
/// encode fault is laundered into it — the operator signal the bound exists
/// to give.
#[test]
fn an_over_bound_write_body_is_named_apart_from_every_other_encode_fault() {
    let row = |tag: [u8; 32]| {
        GrantLedgerEntry::new([0x02; 33], [0x11; 32], Permission::Read, tag, [0x77; 64])
    };
    let oversize = WriteBody {
        grant_ledger: vec![row([0x21; 32])],
        write_history_link: Vec::new(),
        direct_child_scope_index: Vec::new(),
        unknown: PreservedFields::from_iter([(
            "zzPad".to_string(),
            cipherbox_core::codec::Value::Bytes(vec![0xab; MAX_WRITE_BODY_BYTES]),
        )]),
    };
    assert_eq!(
        write_body_encode_error(encode_write_body(&oversize).unwrap_err()),
        ResealError::WriteBodyTooLarge
    );

    let duplicate_tag = WriteBody {
        grant_ledger: vec![row([0x21; 32]), row([0x21; 32])],
        write_history_link: Vec::new(),
        direct_child_scope_index: Vec::new(),
        unknown: PreservedFields::new(),
    };
    assert!(matches!(
        write_body_encode_error(encode_write_body(&duplicate_tag).unwrap_err()),
        ResealError::Encode(_)
    ));
}

struct Fixture {
    owner_enc: X25519Secret,
    pseudonym: Ed25519Signer,
    owner_ecdsa: EcdsaSigner,
    parent_node_seed: [u8; 32],
    write_scope_seed: [u8; 32],
    pointer_read_key: [u8; 32],
    read_grantee: X25519Secret,
    write_grantee: X25519Secret,
}

impl Fixture {
    fn new() -> Self {
        let owner_ecdsa = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
        Self {
            owner_enc: X25519Secret::from_scalar([0x11; 32]),
            pseudonym: Ed25519Signer::from_seed([0x22; 32]),
            owner_ecdsa,
            parent_node_seed: [0x44; 32],
            write_scope_seed: [0x55; 32],
            pointer_read_key: [0x66; 32],
            read_grantee: Self::read_recipient(),
            write_grantee: Self::write_recipient(),
        }
    }

    fn read_tag() -> [u8; 32] {
        [0xa1; 32]
    }
    fn write_tag() -> [u8; 32] {
        [0xb2; 32]
    }
    /// The i-th distinct fixture recipient, for the bound fixtures that need
    /// a commitment entry per grant.
    fn nth_recipient(i: usize) -> X25519Secret {
        let mut scalar = [0x11u8; 32];
        scalar[..8].copy_from_slice(&(i as u64).to_be_bytes());
        X25519Secret::from_scalar(scalar)
    }
    fn read_recipient() -> X25519Secret {
        X25519Secret::from_scalar([0x77; 32])
    }
    fn write_recipient() -> X25519Secret {
        X25519Secret::from_scalar([0x88; 32])
    }

    /// One ledger row the owner attests at `ipns_name` — the shape a re-seal
    /// admits, however the tag was arrived at. Signing is what a re-mint does
    /// too, so a fixture row and a minted one are indistinguishable to a
    /// re-sealer.
    fn attested_row(
        &self,
        recipient_identity_pk: [u8; 33],
        recipient_enc_pk: [u8; 32],
        permission: Permission,
        tag: [u8; 32],
        ipns_name: &[u8],
    ) -> GrantLedgerEntry {
        let mut row = GrantLedgerEntry::new(
            recipient_identity_pk,
            recipient_enc_pk,
            permission,
            tag,
            [0u8; ECDSA_SIG_LEN],
        );
        row.owner_sig = sign_recipient_binding(&self.owner_ecdsa, ipns_name, &row).to_compact();
        row
    }

    /// A commitment + matching ledger for a read grantee and a write grantee,
    /// both attested at `ipns_name`.
    fn committed(
        &self,
        ipns_name: &[u8],
    ) -> (
        GrantSetCommitment,
        [u8; ECDSA_SIG_LEN],
        Vec<GrantLedgerEntry>,
    ) {
        let entries = vec![
            GrantSetEntry::new(
                &self.pointer_read_key,
                Self::read_tag(),
                Self::read_recipient().public().to_bytes(),
                Permission::Read,
                [0x02; 32],
            ),
            GrantSetEntry::new(
                &self.pointer_read_key,
                Self::write_tag(),
                Self::write_recipient().public().to_bytes(),
                Permission::Write,
                [0x03; 32],
            ),
        ];
        let commitment = GrantSetCommitment {
            ipns_name: ipns_name.to_vec(),
            owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries,
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&self.owner_ecdsa, &commitment)
            .unwrap()
            .to_compact();
        let ledger = vec![
            self.attested_row(
                [0x02; 33],
                self.read_grantee.public().to_bytes(),
                Permission::Read,
                Self::read_tag(),
                ipns_name,
            ),
            self.attested_row(
                [0x03; 33],
                self.write_grantee.public().to_bytes(),
                Permission::Write,
                Self::write_tag(),
                ipns_name,
            ),
        ];
        (commitment, sig, ledger)
    }

    /// The same pair, but with every tag **honestly minted** at
    /// [`MINTED_NAME`] from the owner–recipient ECDH — what an owner-held
    /// re-sealer re-derives.
    fn minted(
        &self,
    ) -> (
        GrantSetCommitment,
        [u8; ECDSA_SIG_LEN],
        Vec<GrantLedgerEntry>,
    ) {
        let mint = |grantee: &X25519Secret, identity_scalar: [u8; 32], permission| {
            let identity = EcdsaSigner::from_scalar(&identity_scalar).unwrap();
            mint_grant_row(
                &self.owner_ecdsa,
                &self.owner_enc,
                &self.pointer_read_key,
                identity.verifying_key().to_sec1(),
                &grantee.public(),
                &SCOPE,
                MINTED_NAME,
                permission,
            )
            .expect("a contributory recipient key")
        };
        let rows = [
            mint(&self.read_grantee, [0x51; 32], Permission::Read),
            mint(&self.write_grantee, [0x52; 32], Permission::Write),
        ];
        let commitment = GrantSetCommitment {
            ipns_name: MINTED_NAME.to_vec(),
            owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&self.owner_ecdsa, &commitment)
            .unwrap()
            .to_compact();
        let ledger = rows.iter().map(|r| r.ledger_entry.clone()).collect();
        (commitment, sig, ledger)
    }
}

// `owner_enc_pub` needs a `&X25519Public`; hold it in a local so the borrow
// outlives the call.
fn identity<'a>(
    fx: &'a Fixture,
    owner_pub: &'a X25519Public,
    ipns_name: &'a [u8],
    parent: Option<&'a [u8; 32]>,
) -> ScopeRootIdentity<'a> {
    ScopeRootIdentity {
        v: V,
        scope_id: SCOPE,
        ipns_name,
        owner_enc_pub: owner_pub,
        owner_enc_secret: None,
        ascent: parent.map(AscentAuthority::ParentSeed),
        owes_ascent_link: parent.is_some(),
        pseudonym_signer: &fx.pseudonym,
    }
}

fn seeds<'a>(
    override_seed: &'a [u8; 32],
    read_epoch: u64,
    prev: Option<PrevEpochSeed<'a>>,
    write_scope_seed: &'a [u8; 32],
    pointer_read_key: &'a [u8; 32],
) -> ResealSeeds<'a> {
    ResealSeeds {
        override_seed,
        read_epoch,
        prev,
        write_scope_seed,
        write_epoch: 1,
        write_history: WriteHistory::Genesis,
        pointer_read_key,
    }
}

fn committed_set<'a>(
    commitment: &'a GrantSetCommitment,
    sig: &'a [u8; ECDSA_SIG_LEN],
    ledger: &'a [GrantLedgerEntry],
) -> CommittedSet<'a> {
    CommittedSet {
        commitment,
        commitment_sig: sig,
        grant_ledger: ledger,
        direct_child_scope_index: &[],
        revoked_recipients: &[],
    }
}

fn verifier(fx: &Fixture) -> Ed25519Verifier {
    fx.pseudonym.verifying_key()
}

fn blob_sig(sig: &[u8; 64]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(*sig)
}

#[test]
fn a_re_seal_to_a_carried_public_half_still_opens_by_the_ancestors_descent() {
    // A grantee holds no ancestor seed, so it seals to the public half the
    // record it is replacing publishes; the ancestor must still descend.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
    let carried = kdf::ascent_keypair(&fx.parent_node_seed)
        .public()
        .to_bytes();
    let mut id = identity(&fx, &owner_pub, b"scope-root-name", None);
    id.ascent = Some(AscentAuthority::CarriedPublic(&carried));
    id.owes_ascent_link = true;
    let override_seed = [0x9d; 32];

    let section = reseal_scope_root(
        &mut SeededEntropy::new(5),
        &id,
        &seeds(
            &override_seed,
            4,
            None,
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        ),
        &committed_set(&commitment, &sig, &ledger),
        &[],
    )
    .expect("the re-seal completes without an ancestor seed");

    let link = section.ascent_link.expect("a link is owed and minted");
    let ctx = ctx_for(V, SCOPE, 4, STRUCT_TAG_ASCENT_LINK);
    let opened = open_ascent_link(
        &fx.parent_node_seed,
        &ctx,
        &cipherbox_core::seal::AscentLink {
            ascent_public: link.ascent_public,
            enc: link.enc,
            ciphertext: link.ciphertext,
            unknown: PreservedFields::new(),
        },
    )
    .expect("the ancestor's own descent opens it");
    assert!(ct_eq(opened.override_seed(), &override_seed));
}

#[test]
fn an_ascent_public_half_no_key_can_open_is_refused_before_any_seal() {
    // Release-active: a link sealed to bytes that are not an X25519 point
    // could never serve the descent it exists for.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
    // Not the canonical encoding of a prime-order point, so
    // `X25519Public::from_bytes` refuses to address it.
    let unusable = [0xff; 32];
    let mut id = identity(&fx, &owner_pub, b"scope-root-name", None);
    id.ascent = Some(AscentAuthority::CarriedPublic(&unusable));
    id.owes_ascent_link = true;

    assert_eq!(
        reseal_scope_root(
            &mut UndrawnEntropy,
            &id,
            &seeds(
                &[0x9d; 32],
                4,
                None,
                &fx.write_scope_seed,
                &fx.pointer_read_key
            ),
            &committed_set(&commitment, &sig, &ledger),
            &[],
        )
        .unwrap_err(),
        ResealError::UnusableAscentPublic,
    );
}

#[test]
fn reseal_round_trips_and_every_structure_is_pseudonym_signed() {
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let ipns = b"scope-root-name";
    let (commitment, sig, ledger) = fx.committed(ipns);
    let id = identity(&fx, &owner_pub, ipns, Some(&fx.parent_node_seed));

    let override_seed = [0x99; 32];
    let prev_seed = [0x9a; 32];
    let s = seeds(
        &override_seed,
        5,
        Some(PrevEpochSeed {
            seed: &prev_seed,
            epoch: 4,
        }),
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let cs = committed_set(&commitment, &sig, &ledger);

    let mut e = SeededEntropy::new(1);
    let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");

    let ver = verifier(&fx);

    // Grant blobs: sorted by tag; read grantee opens read seed only, write
    // grantee opens both — all at the new epoch, all pseudonym-signed.
    assert_eq!(section.grant_blobs.len(), 2);
    for gb in &section.grant_blobs {
        let input = StructureSigInput::over_ciphertext(
            SCOPE,
            5,
            STRUCT_TAG_GRANT_BLOB,
            Some(gb.tag),
            &gb.ciphertext,
        );
        verify_structure(&ver, &input, &blob_sig(&gb.signature)).expect("grant blob signed");
    }

    let read_gb = section
        .grant_blobs
        .iter()
        .find(|b| b.tag == Fixture::read_tag())
        .unwrap();
    let ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_GRANT_BLOB);
    let read_payload =
        open_grant_blob(&fx.read_grantee, &read_gb.enc, &ctx, &read_gb.ciphertext).unwrap();
    assert!(ct_eq(read_payload.read_scope_seed(), &override_seed));
    assert!(
        read_payload.write_scope_seed().is_none(),
        "read grant, no write seed"
    );
    assert_eq!(read_payload.epoch, 5);
    assert!(ct_eq(read_payload.pointer_read_key(), &fx.pointer_read_key));

    let write_gb = section
        .grant_blobs
        .iter()
        .find(|b| b.tag == Fixture::write_tag())
        .unwrap();
    let write_payload =
        open_grant_blob(&fx.write_grantee, &write_gb.enc, &ctx, &write_gb.ciphertext).unwrap();
    assert!(ct_eq(write_payload.read_scope_seed(), &override_seed));
    assert!(
        ct_eq(
            write_payload.write_scope_seed().unwrap(),
            &fx.write_scope_seed
        ),
        "write grant carries the write scope seed"
    );

    // Owner blob → override seed.
    let owner_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_OWNER_BLOB);
    let owner_payload = open_owner_blob(
        &fx.owner_enc,
        &section.owner_blob.enc,
        &owner_ctx,
        &section.owner_blob.ciphertext,
    )
    .unwrap();
    assert!(ct_eq(owner_payload.override_seed(), &override_seed));

    // Owner-write-blob → write scope seed, AAD bound to the WRITE epoch (1),
    // structure signature bound to the READ epoch (5, the envelope's).
    let owb = section
        .owner_write_blob
        .as_ref()
        .expect("owner-write-blob authored beside the write-body");
    let owb_ctx = ctx_for(V, SCOPE, 1, STRUCT_TAG_OWNER_WRITE_BLOB);
    let owb_payload =
        open_owner_write_blob(&fx.owner_enc, &owb.enc, &owb_ctx, &owb.ciphertext).unwrap();
    assert!(ct_eq(owb_payload.write_scope_seed(), &fx.write_scope_seed));
    assert_eq!(owb_payload.write_epoch, 1);
    let owb_sig_input = StructureSigInput::over_ciphertext(
        SCOPE,
        5,
        STRUCT_TAG_OWNER_WRITE_BLOB,
        None,
        &owb.ciphertext,
    );
    verify_structure(&ver, &owb_sig_input, &blob_sig(&owb.signature))
        .expect("owner-write-blob signed at the read epoch");

    // Ascent link → override seed, opened with the parent seed.
    let ascent = section
        .ascent_link
        .as_ref()
        .expect("interior root has ascent");
    let ascent_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_ASCENT_LINK);
    let ascent_link = cipherbox_core::seal::AscentLink {
        ascent_public: ascent.ascent_public,
        enc: ascent.enc,
        ciphertext: ascent.ciphertext.clone(),
        unknown: PreservedFields::new(),
    };
    let ascent_payload = open_ascent_link(&fx.parent_node_seed, &ascent_ctx, &ascent_link).unwrap();
    assert!(ct_eq(ascent_payload.override_seed(), &override_seed));

    // History link → prev seed under the new epoch's structure key.
    assert_eq!(section.history_links.len(), 1);
    let hl_key = kdf::structure_key(&override_seed, STRUCT_TAG_HISTORY_LINK);
    let hl_ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_HISTORY_LINK);
    let hl =
        open_history_link(hl_key.as_bytes(), &hl_ctx, &section.history_links[0].sealed).unwrap();
    assert!(ct_eq(hl.prev_seed(), &prev_seed));
    assert_eq!(hl.prev_epoch, 4);

    // The whole section encodes (the release-active dup-tag guard passes).
    encode_grant_section(&section).expect("section encodes");
}

/// Release-active (rule 8): the guard returns `Err`, so a `--release` build
/// refuses exactly the links a debug build does. Every reject row is a link
/// an ancestor reader rejects whole-record.
#[test]
fn an_ascent_link_the_gate_would_reject_is_never_signed() {
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
    let parent_node_seed = fx.parent_node_seed;
    let override_seed = [0x99; 32];
    let ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_ASCENT_LINK);

    // The link a real re-seal mints passes its own guard.
    let id = identity(&fx, &owner_pub, b"scope-root-name", Some(&parent_node_seed));
    let s = seeds(
        &override_seed,
        ctx.epoch,
        None,
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let cs = committed_set(&commitment, &sig, &ledger);
    let minted = reseal_scope_root(&mut SeededEntropy::new(13), &id, &s, &cs, &[])
        .expect("reseal")
        .ascent_link
        .expect("interior root has ascent");
    verify_ascent_link(
        &parent_node_seed,
        &ctx,
        &override_seed,
        &AscentLink {
            ascent_public: minted.ascent_public,
            enc: minted.enc,
            ciphertext: minted.ciphertext,
            unknown: PreservedFields::new(),
        },
    )
    .expect("a minted link is the one an ancestor reader opens");

    let sealed = |seed: &[u8; 32], carried: [u8; 32], epoch: u64, c: &AadContext| {
        seal_ascent_link_to(
            &kdf::ascent_keypair(seed).public(),
            &[0x07; 32],
            c,
            &OverrideSeedPayload::new(carried, epoch),
        )
        .expect("seals")
    };
    // A valid foreign public half with this link's own `enc`/ciphertext: the
    // reader re-derives the public half, never trusts the carried one.
    let mut foreign_public = sealed(&parent_node_seed, override_seed, ctx.epoch, &ctx);
    foreign_public.ascent_public = X25519Secret::from_scalar([0x31; 32]).public().to_bytes();
    for link in [
        // Sealed to a keypair no ancestor of this node derives.
        sealed(&[0x45; 32], override_seed, ctx.epoch, &ctx),
        // Carries a seed that does not derive this node's read key.
        sealed(&parent_node_seed, [0x9a; 32], ctx.epoch, &ctx),
        // Carries an epoch the record does not publish at.
        sealed(&parent_node_seed, override_seed, ctx.epoch + 1, &ctx),
        // AAD transplants: the context is load-bearing, not decoration.
        sealed(
            &parent_node_seed,
            override_seed,
            ctx.epoch,
            &ctx_for(V, [0xee; 16], ctx.epoch, STRUCT_TAG_ASCENT_LINK),
        ),
        sealed(
            &parent_node_seed,
            override_seed,
            ctx.epoch,
            &ctx_for(V, SCOPE, ctx.epoch, STRUCT_TAG_OWNER_BLOB),
        ),
        sealed(
            &parent_node_seed,
            override_seed,
            ctx.epoch,
            &ctx_for(V + 1, SCOPE, ctx.epoch, STRUCT_TAG_ASCENT_LINK),
        ),
        foreign_public,
    ] {
        assert_eq!(
            verify_ascent_link(&parent_node_seed, &ctx, &override_seed, &link),
            Err(ResealError::AscentLinkMismatch),
        );
    }
    assert_eq!(
        ResealError::AscentLinkMismatch.check(),
        "rot-reseal-ascent-link-mismatch"
    );
}

/// The publish arm keys the record's read body off the seed it recovers from
/// the **owner blob** (`net/rotation.rs`), while an ancestor reader derives
/// its expected read key from the **ascent link**. A section whose two
/// structures disagreed would publish a root its own ancestors reject, so the
/// agreement is asserted on `reseal_scope_root`'s output, not assumed.
#[test]
fn the_ascent_link_and_the_owner_blob_carry_one_seed() {
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
    let override_seed = [0x99; 32];
    let id = identity(
        &fx,
        &owner_pub,
        b"scope-root-name",
        Some(&fx.parent_node_seed),
    );
    let s = seeds(
        &override_seed,
        5,
        None,
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let cs = committed_set(&commitment, &sig, &ledger);
    let section =
        reseal_scope_root(&mut SeededEntropy::new(17), &id, &s, &cs, &[]).expect("reseal");

    let owner = open_owner_blob(
        &fx.owner_enc,
        &section.owner_blob.enc,
        &ctx_for(V, SCOPE, 5, STRUCT_TAG_OWNER_BLOB),
        &section.owner_blob.ciphertext,
    )
    .expect("owner opens its blob");
    let ascent = section.ascent_link.expect("interior root has ascent");
    let recovered = open_ascent_link(
        &fx.parent_node_seed,
        &ctx_for(V, SCOPE, 5, STRUCT_TAG_ASCENT_LINK),
        &AscentLink {
            ascent_public: ascent.ascent_public,
            enc: ascent.enc,
            ciphertext: ascent.ciphertext,
            unknown: PreservedFields::new(),
        },
    )
    .expect("an ancestor opens the link");
    assert!(ct_eq(recovered.override_seed(), owner.override_seed()));
    assert_eq!(recovered.epoch, owner.epoch);
}

#[test]
fn vault_root_omits_ascent_link() {
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"root");
    let id = identity(&fx, &owner_pub, b"root", None);
    let seed = [0x01; 32];
    let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let mut e = SeededEntropy::new(2);
    let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");
    assert!(
        section.ascent_link.is_none(),
        "vault root has no ascent link"
    );
    assert!(section.history_links.is_empty(), "no prev, no history link");
}

#[test]
fn sweep_seed_source_mints_no_new_history_link() {
    // prev = None (sweep catch-up): no fresh link, carried sealed bytes kept
    // and re-signed at this read epoch.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"n");
    let id = identity(&fx, &owner_pub, b"n", Some(&fx.parent_node_seed));
    let seed = [0x0e; 32];
    let s = seeds(&seed, 7, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let carried = vec![SignedSealed {
        sealed: b"prior-epoch-link".to_vec(),
        signature: [0x01; 64],
        unknown: PreservedFields::new(),
    }];
    let mut e = SeededEntropy::new(3);
    let section = reseal_scope_root(&mut e, &id, &s, &cs, &carried).expect("reseal");
    assert_eq!(section.history_links.len(), 1, "no fresh link minted");
    assert_eq!(
        section.history_links[0].sealed, carried[0].sealed,
        "the sealed link stays openable under the epoch key that minted it"
    );
    let input = StructureSigInput::over_ciphertext(
        SCOPE,
        7,
        STRUCT_TAG_HISTORY_LINK,
        None,
        &carried[0].sealed,
    );
    verify_structure(
        &verifier(&fx),
        &input,
        &blob_sig(&section.history_links[0].signature),
    )
    .expect("the carried link is re-signed at the epoch the gate recomputes at");
}

/// The synthetic chain's override seed for epoch `e`.
fn chain_seed(e: u64) -> [u8; 32] {
    let mut seed = [0x40; 32];
    seed[..8].copy_from_slice(&e.to_be_bytes());
    seed
}

/// A real ratchet: links for epochs `2..=newest`, oldest first, each sealed
/// under its own epoch's structure key and naming the epoch before it —
/// exactly what `reseal_scope_root` mints, so the walk accepts it.
fn real_chain(newest: u64) -> Vec<SignedSealed> {
    (2..=newest)
        .map(|e| {
            let key = kdf::structure_key(&chain_seed(e), STRUCT_TAG_HISTORY_LINK);
            let ctx = ctx_for(V, SCOPE, e, STRUCT_TAG_HISTORY_LINK);
            let payload = HistoryLinkPayload::new(chain_seed(e - 1), e - 1);
            SignedSealed {
                sealed: seal_history_link(key.as_bytes(), &[0x5a; 24], &ctx, &payload).unwrap(),
                signature: [0x01; 64],
                unknown: PreservedFields::new(),
            }
        })
        .collect()
}

/// Re-seal at `newest + 1`, carrying `carried`.
fn reseal_over_chain(
    fx: &Fixture,
    newest: u64,
    carried: &[SignedSealed],
) -> Result<GrantSection, ResealError> {
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"n");
    let id = identity(fx, &owner_pub, b"n", None);
    let head = chain_seed(newest);
    let fresh = chain_seed(newest + 1);
    let s = seeds(
        &fresh,
        newest + 1,
        Some(PrevEpochSeed {
            seed: &head,
            epoch: newest,
        }),
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let cs = committed_set(&commitment, &sig, &ledger);
    reseal_scope_root(&mut SeededEntropy::new(11), &id, &s, &cs, carried)
}

#[test]
fn retention_keeps_the_newest_window_and_drops_the_oldest() {
    // The ratchet is a contiguous chain, so only the oldest end may be
    // dropped — a hole would strand every epoch beyond it.
    let fx = Fixture::new();
    let newest = MAX_RETAINED_HISTORY_LINKS as u64 + 8;
    let carried = real_chain(newest);
    let section = reseal_over_chain(&fx, newest, &carried).expect("reseal");

    assert_eq!(
        section.history_links.len(),
        MAX_RETAINED_HISTORY_LINKS,
        "the fresh link rides inside the retained window, never past it"
    );
    let kept: Vec<&Vec<u8>> = section.history_links[..MAX_RETAINED_HISTORY_LINKS - 1]
        .iter()
        .map(|l| &l.sealed)
        .collect();
    let newest_carried: Vec<&Vec<u8>> = carried[carried.len() - (MAX_RETAINED_HISTORY_LINKS - 1)..]
        .iter()
        .map(|l| &l.sealed)
        .collect();
    assert_eq!(kept, newest_carried, "newest carried links kept, in order");
    let fresh = &section.history_links[MAX_RETAINED_HISTORY_LINKS - 1].sealed;
    assert!(
        !carried.iter().any(|l| &l.sealed == fresh),
        "the freshly minted link is appended last, keeping the wire order oldest-first"
    );
    // Retention is what holds a re-seal inside the codec's frozen bound.
    encode_grant_section(&section).expect("a retained section always encodes");
}

/// A mutation that breaks the carried chain inside the retained window, so
/// the damage is not merely pruned away.
type ChainBreak = fn(&mut Vec<SignedSealed>);

#[test]
fn a_chain_that_does_not_walk_is_truncated_never_refused() {
    // The carried set is attacker-influenced: the gate authenticates each
    // link's signature and nothing about their order. Refusing would let a
    // committed write-grantee block the rotation that revokes them, so the
    // unwalkable remainder is dropped and the cut still lands.
    let cases: [(&str, ChainBreak); 4] = [
        ("reversed", |c| c.reverse()),
        ("gapped", |c| {
            c.remove(c.len() - 3);
        }),
        ("tampered", |c| c.last_mut().unwrap().sealed[30] ^= 0xFF),
        ("interior swap", |c| {
            let n = c.len();
            c.swap(n - 2, n - 3);
        }),
    ];
    let fx = Fixture::new();
    for (name, break_chain) in cases {
        let mut carried = real_chain(12);
        break_chain(&mut carried);
        let section = reseal_over_chain(&fx, 12, &carried)
            .unwrap_or_else(|e| panic!("{name}: a broken chain must not block the cut: {e}"));
        assert!(
            section.history_links.len() < carried.len() + 1,
            "{name}: the unwalkable remainder must be dropped, not carried"
        );
        encode_grant_section(&section).unwrap_or_else(|e| panic!("{name}: encodes: {e}"));
    }
}

#[test]
fn a_link_minted_for_another_scope_is_never_re_signed() {
    // The AAD binds the scope, so a genuine link lifted from another scope
    // opens under no seed this walk reaches — transplant, not tamper.
    let fx = Fixture::new();
    let mut carried = real_chain(12);
    let key = kdf::structure_key(&chain_seed(12), STRUCT_TAG_HISTORY_LINK);
    let ctx = ctx_for(V, [0xee; 16], 12, STRUCT_TAG_HISTORY_LINK);
    let payload = HistoryLinkPayload::new(chain_seed(11), 11);
    carried.last_mut().unwrap().sealed =
        seal_history_link(key.as_bytes(), &[0x5a; 24], &ctx, &payload).unwrap();

    let section = reseal_over_chain(&fx, 12, &carried).expect("the cut still lands");
    assert_eq!(
        section.history_links.len(),
        1,
        "nothing older than the transplant survives; only the fresh link remains"
    );
}

#[test]
fn a_carried_set_past_the_codec_bound_fails_closed_before_any_seal() {
    // Release-active mirror of the codec's own bound: a set this big could
    // only ever produce a section this build's own encoder rejects.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"n");
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = chain_seed(9);
    let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let carried = real_chain(MAX_HISTORY_LINKS as u64 + 3);
    let err = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &carried)
        .expect_err("past the bound");
    assert_eq!(err.check(), "rot-reseal-too-many-history-links");
}

#[test]
fn a_full_committed_set_re_seals_inside_the_budget_the_author_reserved() {
    // The other half of the coordination `net/author.rs` enforces: the
    // author holds a scope root's other bytes under the complement of this
    // budget, so a section that fits it always fits beside them. Measured on
    // real bytes at the frozen ceiling of committed rows, since the budget
    // is sized from per-row wire estimates.
    //
    // Every row and every child ref carries a padded unknown map here. The
    // counts are frozen and the per-item sizes are not, so the budget is a
    // bound only because the re-seal drops the carry.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (mut commitment, _, _) = fx.committed(b"n");
    let rows: Vec<(_, _)> = (0..MAX_GRANT_BLOBS)
        .map(|i| {
            let mut tag = [0u8; SECRET_LEN];
            tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let recipient = Fixture::nth_recipient(i).public().to_bytes();
            (
                GrantSetEntry::new(
                    &fx.pointer_read_key,
                    tag,
                    recipient,
                    Permission::Read,
                    [0x02; 32],
                ),
                fx.attested_row([0x02; 33], recipient, Permission::Read, tag, b"n"),
            )
        })
        .collect();
    commitment.entries = rows.iter().map(|(entry, _)| entry.clone()).collect();
    let sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
        .expect("the owner signs the maximal set")
        .to_compact();
    let ledger: Vec<GrantLedgerEntry> = rows
        .into_iter()
        .map(|(_, row)| GrantLedgerEntry {
            unknown: padding(1024),
            ..row
        })
        .collect();

    // Every count axis at its ceiling at once, since only the joint maximum
    // can exhaust the budget.
    let children: Vec<ChildScopeRef> = (0..MAX_DIRECT_CHILD_SCOPES)
        .map(|i| {
            let mut scope_id = [0u8; 16];
            scope_id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            ChildScopeRef {
                scope_id,
                ipns_name: crate::rotation::derive_write_name(&[0x5b; SECRET_LEN], &scope_id)
                    .as_str()
                    .as_bytes()
                    .to_vec(),
                unknown: padding(1024),
            }
        })
        .collect();
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = chain_seed(MAX_HISTORY_LINKS as u64 + 1);
    let s = seeds(
        &seed,
        MAX_HISTORY_LINKS as u64 + 1,
        None,
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let mut cs = committed_set(&commitment, &sig, &ledger);
    cs.direct_child_scope_index = &children;
    let carried = real_chain(MAX_HISTORY_LINKS as u64);
    let section = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &carried)
        .expect("a maximal committed set re-seals");
    assert_eq!(section.grant_blobs.len(), MAX_GRANT_BLOBS);
    let size = encode_grant_section(&section).expect("encodes").len();
    let budget = resealable_section_bytes(MAX_GRANT_BLOBS);
    // Headroom, so a wire-shape edit fails here rather than at the cliff.
    assert!(
        size + 64 * 1024 <= budget,
        "a maximal re-seal is {size} bytes against a {budget}-byte budget"
    );
}

#[test]
fn a_re_seal_carries_no_preserved_field_a_write_grantee_authored() {
    // A rotation is not a republish and owes no byte stability
    // (FSM1/cipher-box-next#27 D10), and no owner signature covers either
    // map, so carrying one forward hands a committed write grantee a run
    // no count bound can size.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"n");
    let ledger: Vec<GrantLedgerEntry> = ledger
        .into_iter()
        .map(|row| GrantLedgerEntry {
            unknown: padding(64),
            ..row
        })
        .collect();
    let children = vec![ChildScopeRef {
        scope_id: [0x21; 16],
        ipns_name: b"child".to_vec(),
        unknown: padding(64),
    }];
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = chain_seed(1);
    let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let mut cs = committed_set(&commitment, &sig, &ledger);
    cs.direct_child_scope_index = &children;

    let section = reseal_scope_root(&mut SeededEntropy::new(11), &id, &s, &cs, &[])
        .expect("a padded set re-seals");
    let body = opened_write_body(&section, &fx.write_scope_seed, 1);
    for row in &body.grant_ledger {
        assert!(
            row.unknown.is_empty(),
            "a re-sealed ledger row carries a padded map"
        );
    }
    for child in &body.direct_child_scope_index {
        assert!(
            child.unknown.is_empty(),
            "a re-sealed child scope ref carries a padded map"
        );
    }
}

#[test]
fn every_history_link_this_engine_mints_fits_the_retained_bound() {
    // The bound is only safe to enforce because an honest link never
    // approaches it. Measured on a real minted link, not on the layout the
    // constant was derived from.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"n");
    let id = identity(&fx, &owner_pub, b"n", None);
    let head = chain_seed(4);
    let fresh = chain_seed(5);
    let s = seeds(
        &fresh,
        5,
        Some(PrevEpochSeed {
            seed: &head,
            epoch: 4,
        }),
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let cs = committed_set(&commitment, &sig, &ledger);
    let section = reseal_scope_root(&mut SeededEntropy::new(21), &id, &s, &cs, &[])
        .expect("the rotation mints one fresh link");

    let minted = &section.history_links[0].sealed;
    assert!(
        minted.len() <= MAX_RETAINED_HISTORY_LINK_BYTES,
        "a {}-byte minted link does not survive a {MAX_RETAINED_HISTORY_LINK_BYTES}-byte bound",
        minted.len()
    );

    // The widest honest case: the epoch is the one variable-width field.
    let widest = mint_history_link(
        &mut SeededEntropy::new(22),
        V,
        SCOPE,
        &fresh,
        u64::MAX,
        &PrevEpochSeed {
            seed: &head,
            epoch: u64::MAX - 1,
        },
    )
    .expect("the link mints");
    assert!(
        widest.len() * 2 <= MAX_RETAINED_HISTORY_LINK_BYTES,
        "a {}-byte link leaves too little headroom under {MAX_RETAINED_HISTORY_LINK_BYTES}",
        widest.len()
    );
}

#[test]
fn a_carried_history_link_past_the_retained_bound_is_dropped_with_everything_older() {
    // The sweep path keeps its carried links verbatim (`prev` is `None`),
    // so without this bound one inflated link rides forward for ever and
    // the section budget is an estimate rather than a bound. Dropped, never
    // refused, or whoever inflated it blocks the scope's own re-seal.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"n");
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = chain_seed(3);
    let s = seeds(&seed, 3, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);

    let honest = |byte: u8| SignedSealed {
        sealed: vec![byte; MAX_RETAINED_HISTORY_LINK_BYTES],
        signature: [0u8; 64],
        unknown: padding(32),
    };
    let inflated = SignedSealed {
        sealed: vec![0x22; MAX_RETAINED_HISTORY_LINK_BYTES + 1],
        signature: [0u8; 64],
        unknown: PreservedFields::new(),
    };
    let carried = vec![honest(0x11), inflated, honest(0x33)];

    let section = reseal_scope_root(&mut SeededEntropy::new(12), &id, &s, &cs, &carried)
        .expect("the sweep still re-seals");
    assert_eq!(
        section.history_links.len(),
        1,
        "the inflated link and everything older than it must go"
    );
    assert!(
        section.history_links[0].unknown.is_empty(),
        "and the retained link carries no padded map either"
    );
}

#[test]
fn a_commitment_past_the_codec_bound_fails_closed_before_any_seal() {
    // The owner learns the ceiling here, before one HPKE wrap per committed
    // grant is spent on a section `encode_grant_section` would refuse.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (mut commitment, sig, ledger) = fx.committed(b"n");
    commitment.entries = (0..=MAX_GRANT_BLOBS)
        .map(|i| {
            let mut tag = [0u8; SECRET_LEN];
            tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
            GrantSetEntry::new(
                &fx.pointer_read_key,
                tag,
                Fixture::nth_recipient(i).public().to_bytes(),
                Permission::Read,
                [0x02; 32],
            )
        })
        .collect();
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = chain_seed(9);
    let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let err = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &[])
        .expect_err("past the bound");
    assert_eq!(err.check(), "rot-reseal-too-many-committed-grants");
}

#[test]
fn a_committed_ledger_past_the_codec_bound_fails_closed_before_any_seal() {
    // The commitment stays inside the bound, so only the ledger — the side the
    // wrap loop walks — trips the guard.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, _) = fx.committed(b"n");
    let ledger: Vec<GrantLedgerEntry> = (0..=MAX_GRANT_BLOBS)
        .map(|i| {
            let mut tag = [0u8; SECRET_LEN];
            tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
            fx.attested_row(
                [0x02; 33],
                fx.read_grantee.public().to_bytes(),
                Permission::Read,
                tag,
                b"n",
            )
        })
        .collect();
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = chain_seed(9);
    let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let err =
        reseal_scope_root(&mut UndrawnEntropy, &id, &s, &cs, &[]).expect_err("past the bound");
    assert_eq!(err.check(), "rot-reseal-too-many-committed-grants");
}

#[test]
fn a_sweep_carries_its_chain_through_unpruned() {
    // A sweep mints no link, so the record's epoch label can outrun the
    // newest link's minting epoch — the AAD a walk needs. It neither walks
    // nor prunes; appending nothing, it cannot grow the set either.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"n");
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = chain_seed(9);
    let s = seeds(&seed, 9, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    // Past the retained window, so a reinstated sweep prune would show up.
    let carried = real_chain(MAX_RETAINED_HISTORY_LINKS as u64 + 8);
    let section = reseal_scope_root(&mut SeededEntropy::new(3), &id, &s, &cs, &carried)
        .expect("a sweep re-seals whatever it carries");
    let sealed: Vec<&Vec<u8>> = section.history_links.iter().map(|l| &l.sealed).collect();
    let carried_sealed: Vec<&Vec<u8>> = carried.iter().map(|l| &l.sealed).collect();
    assert_eq!(
        sealed, carried_sealed,
        "carried through, in order, unpruned"
    );
}

#[test]
fn revoked_grantee_is_absent_survivors_present_at_new_epoch() {
    // The revocation crown jewel: three grantees, revoke the middle one by
    // removing it from BOTH the commitment and the ledger, re-seal, and prove
    // the revokee has no blob while survivors decrypt to the fresh seed.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let revoked = X25519Secret::from_scalar([0xcc; 32]);

    // A real name: the cut binds the commitment to the scope it names.
    let scope_name = super::super::rotate_write::derive_write_name(&[0x5a; 32], &SCOPE);
    let scope_name_bytes = scope_name.as_str().as_bytes();
    // The cut names the revokee by re-deriving this tag from the owner's own
    // ECDH, so the fixture files the row under the tag that key really binds.
    let revoked_tag =
        crate::grants::recipient_blinded_tag(&fx.owner_enc, &revoked.public(), scope_name_bytes)
            .expect("a contributory recipient key");

    let entries = vec![
        GrantSetEntry::new(
            &fx.pointer_read_key,
            Fixture::read_tag(),
            Fixture::read_recipient().public().to_bytes(),
            Permission::Read,
            [0x02; 32],
        ),
        GrantSetEntry::new(
            &fx.pointer_read_key,
            revoked_tag,
            revoked.public().to_bytes(),
            Permission::Read,
            [0x04; 32],
        ),
        GrantSetEntry::new(
            &fx.pointer_read_key,
            Fixture::write_tag(),
            Fixture::write_recipient().public().to_bytes(),
            Permission::Write,
            [0x03; 32],
        ),
    ];
    let commitment = GrantSetCommitment {
        ipns_name: scope_name_bytes.to_vec(),
        owner_pseudonym_pk: fx.pseudonym.verifying_key().to_bytes(),
        cut_epoch: 0,
        entries,
        unknown: PreservedFields::new(),
    };
    let ledger = vec![
        fx.attested_row(
            [0x02; 33],
            fx.read_grantee.public().to_bytes(),
            Permission::Read,
            Fixture::read_tag(),
            scope_name_bytes,
        ),
        fx.attested_row(
            [0x04; 33],
            revoked.public().to_bytes(),
            Permission::Read,
            revoked_tag,
            scope_name_bytes,
        ),
        fx.attested_row(
            [0x03; 33],
            fx.write_grantee.public().to_bytes(),
            Permission::Write,
            Fixture::write_tag(),
            scope_name_bytes,
        ),
    ];

    // Revoke: the read-revoke trigger's committed-set cut.
    let commitment_sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
        .unwrap()
        .to_compact();
    let cut = super::super::trigger::revoke_read_grant(
        &super::super::trigger::GrantCutPlan {
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &ledger,
            scope_root_name: &scope_name,
            owner_signer: &fx.owner_ecdsa,
            pointer_read_key: &fx.pointer_read_key,
        },
        &revoked_tag,
    )
    .expect("revoke");
    assert!(
        !cut.grant_ledger.iter().any(|e| e.tag == revoked_tag),
        "revokee gone from ledger"
    );
    assert!(
        !cut.commitment.entries.iter().any(|e| e.tag == revoked_tag),
        "revokee gone from commitment"
    );

    let id = identity(&fx, &owner_pub, scope_name_bytes, None);
    let new_seed = [0xef; 32];
    let s = seeds(
        &new_seed,
        2,
        None,
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let cs = CommittedSet {
        commitment: &cut.commitment,
        commitment_sig: &cut.commitment_sig,
        grant_ledger: &cut.grant_ledger,
        direct_child_scope_index: &[],
        revoked_recipients: &[],
    };
    let mut e = SeededEntropy::new(4);
    let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");

    // The revokee has NO grant blob.
    assert!(
        !section.grant_blobs.iter().any(|b| b.tag == revoked_tag),
        "revoked party's blob is absent — this is the revocation"
    );
    assert_eq!(
        section.grant_blobs.len(),
        2,
        "only survivors are re-wrapped"
    );
    // And the revokee cannot open any survivor's blob (fresh seed).
    let ctx = ctx_for(V, SCOPE, 2, STRUCT_TAG_GRANT_BLOB);
    for b in &section.grant_blobs {
        assert!(
            open_grant_blob(&revoked, &b.enc, &ctx, &b.ciphertext).is_err(),
            "revokee cannot open a survivor's blob"
        );
    }
    // Survivor opens the fresh seed.
    let read_gb = section
        .grant_blobs
        .iter()
        .find(|b| b.tag == Fixture::read_tag())
        .unwrap();
    let payload =
        open_grant_blob(&fx.read_grantee, &read_gb.enc, &ctx, &read_gb.ciphertext).unwrap();
    assert!(ct_eq(payload.read_scope_seed(), &new_seed));
}

#[test]
fn diverging_ledger_fails_closed_release_active() {
    // A write-grantee adds a ledger row the owner never committed. The re-seal
    // rejects it with a runtime `Err` (not a debug_assert) — so a release
    // build never seals a section the gate would reject. This test is active
    // in release.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, mut ledger) = fx.committed(b"n");
    ledger.push(fx.attested_row(
        [0x09; 33],
        X25519Secret::from_scalar([0x0f; 32]).public().to_bytes(),
        Permission::Write,
        [0xff; 32], // uncommitted tag
        b"n",
    ));
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = [0x01; 32];
    let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let mut e = SeededEntropy::new(5);
    let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("diverging ledger");
    assert_eq!(err.check(), "rot-reseal-ledger-diverges-from-commitment");
}

#[test]
fn signer_not_committed_fails_closed_release_active() {
    // The rotator's pseudonym signer differs from the owner-committed pseudonym
    // key. The re-seal rejects it with a runtime `Err` (not a debug_assert) — so
    // a release build never signs a scope root the gate would reject as
    // signer-mismatched (an unopenable root). This test is active in release.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
    let wrong_signer = Ed25519Signer::from_seed([0x99; 32]);
    let id = ScopeRootIdentity {
        v: V,
        scope_id: SCOPE,
        ipns_name: b"scope-root-name",
        owner_enc_pub: &owner_pub,
        owner_enc_secret: None,
        ascent: None,
        owes_ascent_link: false,
        pseudonym_signer: &wrong_signer,
    };
    let seed = [0x01; 32];
    let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let mut e = SeededEntropy::new(7);
    let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("signer mismatch");
    assert_eq!(err.check(), "rot-reseal-signer-not-committed");
}

#[test]
fn a_descendant_re_sealed_with_no_parent_seed_fails_closed_release_active() {
    // Only `parent_node_seed` mints an ascent link, so a descendant re-sealed
    // without one would publish a record `gate_root_pass` permanently
    // rejects — signed, live, and unopenable as anyone's child. The re-seal
    // refuses with a runtime `Err` (not a debug_assert), so a release build
    // cannot mint it. This test is active in release.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
    let id = ScopeRootIdentity {
        owes_ascent_link: true,
        ..identity(&fx, &owner_pub, b"scope-root-name", None)
    };
    let seed = [0x01; 32];
    let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let mut e = SeededEntropy::new(11);
    let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("no link to bind it");
    assert_eq!(err.check(), "rot-reseal-ascent-link-dropped");

    // The same identity handed the seed mints the link and seals.
    let ok = ScopeRootIdentity {
        owes_ascent_link: true,
        ..identity(
            &fx,
            &owner_pub,
            b"scope-root-name",
            Some(&fx.parent_node_seed),
        )
    };
    let mut e = SeededEntropy::new(11);
    assert!(
        reseal_scope_root(&mut e, &ok, &s, &cs, &[])
            .expect("the descendant seals")
            .ascent_link
            .is_some()
    );
}

#[test]
fn a_root_that_owes_no_ascent_link_is_never_re_sealed_with_one() {
    // A vault root's readers derive no parent seed, so a minted link is one
    // no descent reproduces: every read is rejected at the gate's ascent
    // stage while the name's sequence floor has already moved past the last
    // good record. Permanent lockout, so the refusal is a runtime `Err` and
    // this test is active in release.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"scope-root-name");
    let id = ScopeRootIdentity {
        owes_ascent_link: false,
        ..identity(
            &fx,
            &owner_pub,
            b"scope-root-name",
            Some(&fx.parent_node_seed),
        )
    };
    let seed = [0x01; 32];
    let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let mut e = SeededEntropy::new(11);
    let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("a link it does not owe");
    assert_eq!(err.check(), "rot-reseal-ascent-link-not-owed");

    // The same identity handed no seed seals, link-less.
    let ok = identity(&fx, &owner_pub, b"scope-root-name", None);
    let mut e = SeededEntropy::new(11);
    assert!(
        reseal_scope_root(&mut e, &ok, &s, &cs, &[])
            .expect("the vault root seals")
            .ascent_link
            .is_none()
    );
}

/// The re-seal a holder of the owner encryption subkey runs.
fn owner_held<'a>(fx: &'a Fixture, owner_pub: &'a X25519Public) -> ScopeRootIdentity<'a> {
    ScopeRootIdentity {
        owner_enc_secret: Some(&fx.owner_enc),
        ..identity(fx, owner_pub, MINTED_NAME, None)
    }
}

#[test]
fn an_owner_held_reseal_wraps_every_honestly_minted_row() {
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.minted();
    let seed = [0x01; 32];
    let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);

    let section = reseal_scope_root(
        &mut SeededEntropy::new(21),
        &owner_held(&fx, &owner_pub),
        &s,
        &cs,
        &[],
    )
    .expect("every row derives the tag it is filed under");
    assert_eq!(section.grant_blobs.len(), 2);
}

/// The same-epoch helper reads a resolved target onto the very fields the
/// explicit form spells out — the property that lets a call site drop its own
/// `ScopeRootIdentity`/`ResealSeeds` literal.
#[test]
fn the_same_epoch_helper_seals_the_bytes_the_explicit_form_seals() {
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.minted();
    let seed = [0x01; 32];
    let target = CascadeTarget {
        v: V,
        current_read_epoch: 4,
        owner_enc_pub: owner_pub,
        pseudonym_signer: Ed25519Signer::from_seed([0x22; 32]),
        write_body_signer: None,
        override_seed: Zeroizing::new(seed),
        write_scope_seed: Zeroizing::new(fx.write_scope_seed),
        pointer_read_key: Zeroizing::new(fx.pointer_read_key),
        write_epoch: 1,
        commitment: commitment.clone(),
        commitment_sig: sig,
        grant_ledger: ledger.clone(),
        write_history_link: Vec::new(),
        direct_child_scope_index: Vec::new(),
        carried_history_links: Vec::new(),
        carried_ascent_link: false,
    };
    let committed = committed_set(&commitment, &sig, &ledger);

    let explicit = reseal_scope_root(
        &mut SeededEntropy::new(7),
        &ScopeRootIdentity {
            v: V,
            scope_id: SCOPE,
            ipns_name: MINTED_NAME,
            owner_enc_pub: &owner_pub,
            owner_enc_secret: Some(&fx.owner_enc),
            ascent: None,
            owes_ascent_link: false,
            pseudonym_signer: &target.pseudonym_signer,
        },
        &ResealSeeds {
            override_seed: &seed,
            read_epoch: 4,
            prev: None,
            write_scope_seed: &fx.write_scope_seed,
            write_epoch: 1,
            write_history: WriteHistory::Carried(&[]),
            pointer_read_key: &fx.pointer_read_key,
        },
        &committed,
        &[],
    )
    .expect("the explicit same-epoch form seals");

    let through_helper = reseal_at_current_epoch(
        &mut SeededEntropy::new(7),
        &target,
        &ResealSite {
            scope_id: SCOPE,
            ipns_name: MINTED_NAME,
            owner_enc_secret: &fx.owner_enc,
            ascent: None,
            owes_ascent_link: false,
        },
        &committed,
    )
    .expect("the helper seals the same inputs");

    assert_eq!(
        encode_grant_section(&through_helper).unwrap(),
        encode_grant_section(&explicit).unwrap()
    );
}

#[test]
fn a_relabelled_ledger_row_cannot_redirect_the_blob() {
    // A committed write-grantee re-authors the write body with a victim's
    // `recipientEncPk` replaced by a key of its own. The re-seal wraps to the
    // key the owner signed into the commitment entry, so the relabelling is
    // inert: it neither redirects the blob nor drops it.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let attacker = X25519Secret::from_scalar([0x5f; 32]);
    let (commitment, sig, mut ledger) = fx.minted();
    let victim_tag = ledger[0].tag;
    ledger[0].recipient_enc_pk = attacker.public().to_bytes();
    let seed = [0x01; 32];
    let read_epoch = 1;
    let s = seeds(
        &seed,
        read_epoch,
        None,
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let cs = committed_set(&commitment, &sig, &ledger);
    let ctx = ctx_for(V, SCOPE, read_epoch, STRUCT_TAG_GRANT_BLOB);

    // Both legs agree, which is the point: the write-grantee re-sealer holds
    // no owner secret and still reaches the owner-committed key.
    for id in [
        owner_held(&fx, &owner_pub),
        identity(&fx, &owner_pub, MINTED_NAME, None),
    ] {
        let section = reseal_scope_root(&mut SeededEntropy::new(23), &id, &s, &cs, &[])
            .expect("the rotation the relabelling was meant to disturb still publishes");
        assert_eq!(
            section.grant_blobs.len(),
            commitment.entries.len(),
            "every committed entry keeps its blob"
        );
        let victim_blob = section
            .grant_blobs
            .iter()
            .find(|b| b.tag == victim_tag)
            .expect("the victim's committed tag still carries a blob");
        let payload = open_grant_blob(
            &fx.read_grantee,
            &victim_blob.enc,
            &ctx,
            &victim_blob.ciphertext,
        )
        .expect("the owner-committed recipient opens its own blob");
        assert!(ct_eq(payload.read_scope_seed(), &seed));
        assert!(
            open_grant_blob(&attacker, &victim_blob.enc, &ctx, &victim_blob.ciphertext).is_err(),
            "the key the row was relabelled to opens nothing"
        );
    }
}

#[test]
fn a_corrupted_row_signature_costs_the_committed_blob_nothing() {
    // Corrupting the 64 signature bytes needs no key material, so it is the
    // cheapest attack a committed writer has on a co-grantee. The blob is
    // wrapped to the commitment entry, which the owner signs as one set, so
    // the row's own attestation is not what the victim's delivery rests on.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, mut ledger) = fx.minted();
    let victim_tag = ledger[0].tag;
    ledger[0].owner_sig[0] ^= 0xff;
    let seed = [0x01; 32];
    let read_epoch = 1;
    let s = seeds(
        &seed,
        read_epoch,
        None,
        &fx.write_scope_seed,
        &fx.pointer_read_key,
    );
    let cs = committed_set(&commitment, &sig, &ledger);
    let ctx = ctx_for(V, SCOPE, read_epoch, STRUCT_TAG_GRANT_BLOB);

    for id in [
        owner_held(&fx, &owner_pub),
        identity(&fx, &owner_pub, MINTED_NAME, None),
    ] {
        let section = reseal_scope_root(&mut SeededEntropy::new(31), &id, &s, &cs, &[])
            .expect("the re-seal publishes");
        let victim_blob = section
            .grant_blobs
            .iter()
            .find(|b| b.tag == victim_tag)
            .expect("the victim keeps its blob");
        let payload = open_grant_blob(
            &fx.read_grantee,
            &victim_blob.enc,
            &ctx,
            &victim_blob.ciphertext,
        )
        .expect("the owner-committed recipient opens its own blob");
        assert!(ct_eq(payload.read_scope_seed(), &seed));
    }
}

#[test]
fn a_committed_recipient_key_core_will_not_adopt_fails_closed_release_active() {
    // A cofactor twin and the key with bit 255 set both blind to the honest
    // key's tag, so nothing but core's adoption gate separates them from it.
    // The owner signs the commitment, so such an entry is the owner attesting
    // a grant nothing can be sealed to: the whole re-seal fails with a runtime
    // `Err`, never a debug_assert, and `UndrawnEntropy` proves the refusal
    // lands before the first seal. Active in release.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let victim = fx.read_grantee.public();
    let mut high_bit = victim.to_bytes();
    high_bit[31] |= 0x80;

    let unadoptable = cipherbox_core::suite::x25519::cofactor_twins(&victim)
        .into_iter()
        .chain([high_bit]);
    for enc_pk in unadoptable {
        let (mut commitment, _, ledger) = fx.minted();
        commitment.entries[0].set_recipient_enc_pk(&fx.pointer_read_key, enc_pk);
        let sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
            .expect("the owner signs the set it attests")
            .to_compact();
        let seed = [0x01; 32];
        let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
        let cs = committed_set(&commitment, &sig, &ledger);

        // Both legs agree: holding the owner secret buys no way to wrap a
        // grant to a key core will not adopt.
        for id in [
            owner_held(&fx, &owner_pub),
            identity(&fx, &owner_pub, MINTED_NAME, None),
        ] {
            let err = reseal_scope_root(&mut UndrawnEntropy, &id, &s, &cs, &[])
                .expect_err("a grant can never be wrapped to a key core will not adopt");
            assert_eq!(err.check(), "rot-reseal-unusable-recipient-key");
        }
    }
}

#[test]
fn unusable_recipient_key_fails_closed() {
    // A low-order (all-zero) committed recipient key cannot receive a grant,
    // so the whole re-seal fails rather than publish a set one entry short.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let commitment = GrantSetCommitment {
        ipns_name: b"n".to_vec(),
        owner_pseudonym_pk: fx.pseudonym.verifying_key().to_bytes(),
        cut_epoch: 0,
        entries: vec![GrantSetEntry::new(
            &fx.pointer_read_key,
            Fixture::read_tag(),
            [0u8; 32], // low-order X25519 → from_bytes rejects
            Permission::Read,
            [0x02; 32],
        )],
        unknown: PreservedFields::new(),
    };
    let sig = sign_grant_set(&fx.owner_ecdsa, &commitment)
        .unwrap()
        .to_compact();
    let ledger = vec![fx.attested_row(
        [0x02; 33],
        Fixture::read_recipient().public().to_bytes(),
        Permission::Read,
        Fixture::read_tag(),
        b"n",
    )];
    let id = identity(&fx, &owner_pub, b"n", None);
    let seed = [0x01; 32];
    let s = seeds(&seed, 1, None, &fx.write_scope_seed, &fx.pointer_read_key);
    let cs = committed_set(&commitment, &sig, &ledger);
    let mut e = SeededEntropy::new(6);
    let err = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect_err("bad key");
    assert_eq!(err.check(), "rot-reseal-unusable-recipient-key");
}

#[test]
fn determinism_same_entropy_same_bytes() {
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed(b"n");
    let id = identity(&fx, &owner_pub, b"n", Some(&fx.parent_node_seed));
    let seed = [0x01; 32];
    let prev = [0x02; 32];
    let build = || {
        let s = seeds(
            &seed,
            3,
            Some(PrevEpochSeed {
                seed: &prev,
                epoch: 2,
            }),
            &fx.write_scope_seed,
            &fx.pointer_read_key,
        );
        let cs = committed_set(&commitment, &sig, &ledger);
        let mut e = SeededEntropy::new(42);
        encode_grant_section(&reseal_scope_root(&mut e, &id, &s, &cs, &[]).unwrap()).unwrap()
    };
    assert_eq!(
        build(),
        build(),
        "same entropy seed → byte-identical section"
    );
}

/// The write scope seed a cut moves TO, and the one it retires.
const FRESH_WRITE_SCOPE_SEED: [u8; 32] = [0xc1; 32];
const RETIRING_WRITE_SCOPE_SEED: [u8; 32] = [0xc2; 32];

/// A cut's seeds: the read plane stands still, the write plane advances from
/// `prev_write_epoch` to `write_epoch` over a fresh write scope seed.
fn cut_seeds<'a>(
    override_seed: &'a [u8; 32],
    pointer_read_key: &'a [u8; 32],
    prev: PrevEpochSeed<'a>,
    write_epoch: u64,
) -> ResealSeeds<'a> {
    ResealSeeds {
        override_seed,
        read_epoch: 5,
        prev: None,
        write_scope_seed: &FRESH_WRITE_SCOPE_SEED,
        write_epoch,
        write_history: WriteHistory::Cut(prev),
        pointer_read_key,
    }
}

/// The write-body a section publishes, opened as any write-key holder does.
fn opened_write_body(
    section: &GrantSection,
    write_scope_seed: &[u8; 32],
    write_epoch: u64,
) -> cipherbox_core::seal::WriteBody {
    let write_seed = kdf::write_seed(write_scope_seed, &SCOPE);
    let write_key = kdf::write_key(write_seed.as_bytes());
    let ctx = ctx_for(V, SCOPE, write_epoch, STRUCT_TAG_WRITE_BODY);
    let plaintext =
        cipherbox_core::seal::unseal(write_key.as_bytes(), &ctx, &section.write_body.sealed)
            .expect("the write body opens under the fresh write key");
    cipherbox_core::seal::decode_write_body(&plaintext).expect("decodes")
}

#[test]
fn a_write_cut_mints_its_history_link_to_the_owner_alone() {
    let fx = Fixture::new();
    let (commitment, sig, ledger) = fx.minted();
    let owner_pub = fx.owner_enc.public();
    let id = ScopeRootIdentity {
        owner_enc_secret: Some(&fx.owner_enc),
        ..identity(&fx, &owner_pub, MINTED_NAME, None)
    };
    let override_seed = [0x0e; 32];
    let s = cut_seeds(
        &override_seed,
        &fx.pointer_read_key,
        PrevEpochSeed {
            seed: &RETIRING_WRITE_SCOPE_SEED,
            epoch: 4,
        },
        5,
    );
    let cs = committed_set(&commitment, &sig, &ledger);
    let mut e = SeededEntropy::new(70);
    let section = reseal_scope_root(&mut e, &id, &s, &cs, &[]).expect("reseal");

    let body = opened_write_body(&section, &FRESH_WRITE_SCOPE_SEED, 5);
    let ctx = ctx_for(V, SCOPE, 5, STRUCT_TAG_WRITE_HISTORY_LINK);
    let payload = open_owner_history_link(&fx.owner_enc, &ctx, &body.write_history_link)
        .expect("the link opens for the owner at the new write epoch");
    assert!(ct_eq(payload.prev_seed(), &RETIRING_WRITE_SCOPE_SEED));
    assert_eq!(payload.prev_epoch, 4);

    for seed in [&FRESH_WRITE_SCOPE_SEED, &RETIRING_WRITE_SCOPE_SEED] {
        let key = kdf::structure_key(seed, STRUCT_TAG_HISTORY_LINK);
        assert!(
            open_history_link(key.as_bytes(), &ctx, &body.write_history_link).is_err(),
            "a write-plane seed opens nothing"
        );
    }
}

#[test]
fn a_write_cut_without_the_owner_key_is_refused_before_any_seal() {
    let fx = Fixture::new();
    let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
    let owner_pub = fx.owner_enc.public();
    let id = identity(&fx, &owner_pub, MINTED_NAME, Some(&fx.parent_node_seed));
    let override_seed = [0x0e; 32];
    let s = cut_seeds(
        &override_seed,
        &fx.pointer_read_key,
        PrevEpochSeed {
            seed: &RETIRING_WRITE_SCOPE_SEED,
            epoch: 4,
        },
        5,
    );
    assert_eq!(
        reseal_scope_root(
            &mut UndrawnEntropy,
            &id,
            &s,
            &committed_set(&commitment, &sig, &ledger),
            &[]
        )
        .expect_err("a keyless cut seals nothing")
        .check(),
        "rot-reseal-owner-key-required-for-write-cut"
    );
}

/// `UndrawnEntropy` is the release-active proof: the refusal returns before
/// any seal draws a byte, in a build that strips `debug_assert!`. Dropping
/// the blob instead would publish an empty link above write epoch 1, which
/// truncates the write-plane regression chain from that epoch onward.
#[test]
fn a_carried_write_history_link_past_the_codec_bound_is_refused_before_any_seal() {
    let fx = Fixture::new();
    let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
    let owner_pub = fx.owner_enc.public();
    let id = identity(&fx, &owner_pub, MINTED_NAME, None);
    let override_seed = [0x0e; 32];
    let cs = committed_set(&commitment, &sig, &ledger);
    let at_len = |link: &'static [u8]| ResealSeeds {
        write_history: WriteHistory::Carried(link),
        write_epoch: 3,
        ..seeds(
            &override_seed,
            5,
            None,
            &FRESH_WRITE_SCOPE_SEED,
            &fx.pointer_read_key,
        )
    };
    const BLOATED: &[u8] = &[0x7c; MAX_WRITE_HISTORY_LINK_BYTES + 1];
    const AT_BOUND: &[u8] = &[0x7c; MAX_WRITE_HISTORY_LINK_BYTES];

    assert_eq!(
        reseal_scope_root(&mut UndrawnEntropy, &id, &at_len(BLOATED), &cs, &[])
            .expect_err("an over-length carried link seals nothing")
            .check(),
        "rot-reseal-carried-write-history-link-too-large"
    );

    // The bound itself still carries, so the refusal is the codec's own and
    // not one byte narrower.
    let mut e = SeededEntropy::new(71);
    let section = reseal_scope_root(&mut e, &id, &at_len(AT_BOUND), &cs, &[])
        .expect("a link at the bound re-seals");
    assert_eq!(
        opened_write_body(&section, &FRESH_WRITE_SCOPE_SEED, 3).write_history_link,
        AT_BOUND,
    );
}

#[test]
fn a_minted_empty_write_history_above_write_epoch_1_is_refused_before_any_seal() {
    // `UndrawnEntropy` is the release-active proof: the refusal returns
    // before any seal draws a byte, in a build that strips `debug_assert!`.
    let fx = Fixture::new();
    let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
    let owner_pub = fx.owner_enc.public();
    let id = identity(&fx, &owner_pub, MINTED_NAME, Some(&fx.parent_node_seed));
    let override_seed = [0x0e; 32];
    let cs = committed_set(&commitment, &sig, &ledger);
    let at_epoch = |write_epoch| ResealSeeds {
        write_epoch,
        ..seeds(
            &override_seed,
            1,
            None,
            &FRESH_WRITE_SCOPE_SEED,
            &fx.pointer_read_key,
        )
    };

    assert_eq!(
        reseal_scope_root(&mut UndrawnEntropy, &id, &at_epoch(2), &cs, &[])
            .expect_err("an empty link above write epoch 1 seals nothing")
            .check(),
        "rot-reseal-empty-write-history-above-first-epoch"
    );

    let mut e = SeededEntropy::new(83);
    reseal_scope_root(&mut e, &id, &at_epoch(1), &cs, &[])
        .expect("the same mint at write epoch 1 re-seals");
}

/// The refusal covers what this build mints, never what it carries. The
/// carried value is a committed writer's, so refusing an empty one would let
/// that writer make the scope un-re-keyable — the wedge the budget work
/// elsewhere in this file exists to close.
#[test]
fn a_carried_empty_write_history_above_write_epoch_1_still_re_seals() {
    let fx = Fixture::new();
    let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
    let owner_pub = fx.owner_enc.public();
    let id = identity(&fx, &owner_pub, MINTED_NAME, Some(&fx.parent_node_seed));
    let override_seed = [0x0e; 32];
    let cs = committed_set(&commitment, &sig, &ledger);
    let s = ResealSeeds {
        write_epoch: 3,
        write_history: WriteHistory::Carried(&[]),
        ..seeds(
            &override_seed,
            1,
            None,
            &FRESH_WRITE_SCOPE_SEED,
            &fx.pointer_read_key,
        )
    };

    let mut e = SeededEntropy::new(91);
    reseal_scope_root(&mut e, &id, &s, &cs, &[])
        .expect("a foreign empty link must not refuse the owner's re-seal");
}

#[test]
fn a_history_link_that_does_not_descend_is_refused_before_any_seal() {
    // An interior scope root, so `UndrawnEntropy` pins the refusal ahead of
    // every seal the section carries, the ascent link included.
    let fx = Fixture::new();
    let (commitment, sig, ledger) = fx.committed(MINTED_NAME);
    let owner_pub = fx.owner_enc.public();
    let id = identity(&fx, &owner_pub, MINTED_NAME, Some(&fx.parent_node_seed));
    let override_seed = [0x0e; 32];
    let cs = committed_set(&commitment, &sig, &ledger);
    for prev_epoch in [5, 6] {
        let write_cut = cut_seeds(
            &override_seed,
            &fx.pointer_read_key,
            PrevEpochSeed {
                seed: &RETIRING_WRITE_SCOPE_SEED,
                epoch: prev_epoch,
            },
            5,
        );
        let read_cut = seeds(
            &override_seed,
            5,
            Some(PrevEpochSeed {
                seed: &RETIRING_WRITE_SCOPE_SEED,
                epoch: prev_epoch,
            }),
            &FRESH_WRITE_SCOPE_SEED,
            &fx.pointer_read_key,
        );
        for s in [write_cut, read_cut] {
            assert_eq!(
                reseal_scope_root(&mut UndrawnEntropy, &id, &s, &cs, &[])
                    .expect_err("a non-descending link seals nothing")
                    .check(),
                "rot-reseal-history-link-not-descending"
            );
        }
    }
}

#[test]
fn a_gapped_read_history_link_is_refused_but_a_gapped_write_cut_is_not() {
    // A gapped write cut is legitimate: the name wave sources the cut's
    // `epoch` from the rotation plan and its `prev.epoch` from the durable
    // write floor (`net/rotation.rs`), so a device whose floor lags the plan
    // mints a gap that must still seal. Plane asymmetry:
    // [`ResealSeeds::check_history_descends`].
    let fx = Fixture::new();
    let (commitment, sig, ledger) = fx.minted();
    let owner_pub = fx.owner_enc.public();
    let id = ScopeRootIdentity {
        owner_enc_secret: Some(&fx.owner_enc),
        ..identity(&fx, &owner_pub, MINTED_NAME, None)
    };
    let override_seed = [0x0e; 32];
    let cs = committed_set(&commitment, &sig, &ledger);

    let read_cut = seeds(
        &override_seed,
        5,
        Some(PrevEpochSeed {
            seed: &RETIRING_WRITE_SCOPE_SEED,
            epoch: 3,
        }),
        &FRESH_WRITE_SCOPE_SEED,
        &fx.pointer_read_key,
    );
    assert_eq!(
        reseal_scope_root(&mut UndrawnEntropy, &id, &read_cut, &cs, &[])
            .expect_err("a gapped read link seals nothing")
            .check(),
        "rot-reseal-history-link-not-contiguous"
    );

    let write_cut = cut_seeds(
        &override_seed,
        &fx.pointer_read_key,
        PrevEpochSeed {
            seed: &RETIRING_WRITE_SCOPE_SEED,
            epoch: 3,
        },
        5,
    );
    let section = reseal_scope_root(&mut SeededEntropy::new(70), &id, &write_cut, &cs, &[])
        .expect("a gapped write cut still seals");
    let payload = open_owner_history_link(
        &fx.owner_enc,
        &ctx_for(V, SCOPE, 5, STRUCT_TAG_WRITE_HISTORY_LINK),
        &opened_write_body(&section, &FRESH_WRITE_SCOPE_SEED, 5).write_history_link,
    )
    .expect("the gapped link opens for the owner");
    assert_eq!(payload.prev_epoch, 3);
}

// --- The key-regression ratchet walked backward ---

#[test]
fn the_ratchet_reaches_every_epoch_its_links_span() {
    // A published record at epoch 5 carrying the links for 2..=5: the seed
    // for any epoch in that span is recoverable, and each one is the epoch's
    // own.
    let links = real_chain(5);
    for target in 1..=5u64 {
        let seed = seed_at_epoch(V, SCOPE, &chain_seed(5), 5, &links, target)
            .unwrap_or_else(|| panic!("epoch {target} is inside the retained window"));
        assert!(ct_eq(&seed, &chain_seed(target)), "epoch {target}");
    }
}

#[test]
fn the_ratchet_never_steps_forward() {
    assert!(seed_at_epoch(V, SCOPE, &chain_seed(5), 5, &real_chain(5), 6).is_none());
}

#[test]
fn an_epoch_older_than_the_retained_window_is_unreachable() {
    // The links only span 4..=5, so epoch 2 is behind the ratchet's reach —
    // unreadable to every reader, not just this one.
    let links = real_chain(5)[3..].to_vec();
    assert!(seed_at_epoch(V, SCOPE, &chain_seed(5), 5, &links, 2).is_none());
}

#[test]
fn a_link_from_another_scope_breaks_the_walk() {
    let links = real_chain(5);
    assert!(seed_at_epoch(V, [0x9e; 16], &chain_seed(5), 5, &links, 4).is_none());
    assert!(
        seed_at_epoch(V, SCOPE, &chain_seed(4), 5, &links, 4).is_none(),
        "nor does a walk started from the wrong seed open the newest link",
    );
}

#[test]
fn a_scope_at_epoch_one_resolves_its_own_seed_with_no_links() {
    let seed = seed_at_epoch(V, SCOPE, &chain_seed(1), 1, &[], 1).expect("the current seed");
    assert!(ct_eq(&seed, &chain_seed(1)));
}

/// A new variant that inherits another variant's check name, or is appended out
/// of order, fails here rather than reaching a reject vector unnamed.
#[test]
fn the_check_surface_matches_the_variants_in_order() {
    let named: Vec<&str> = [
        ResealError::LedgerDivergesFromCommitment,
        ResealError::SignerNotCommitted,
        ResealError::UnusableRecipientKey,
        ResealError::TagNotBoundToRecipient,
        ResealError::AscentLinkMismatch,
        ResealError::AscentLinkDropped,
        ResealError::AscentLinkNotOwed,
        ResealError::UnusableAscentPublic,
        ResealError::Entropy(EntropyError::new("no entropy")),
        ResealError::TooManyHistoryLinks,
        ResealError::TooManyCommittedGrants,
        ResealError::HistoryLinkNotDescending,
        ResealError::HistoryLinkNotContiguous,
        ResealError::EmptyWriteHistoryAboveFirstEpoch,
        ResealError::OwnerKeyRequiredForWriteCut,
        ResealError::WriteBodyTooLarge,
        ResealError::HistoryLinkTooLarge { size: 1, limit: 0 },
        ResealError::CarriedWriteHistoryLinkTooLarge { size: 1, limit: 0 },
        ResealError::SectionNotResealable { size: 1, limit: 0 },
        ResealError::Encode(cipherbox_core::error::TrustViolation::DuplicateGrantTag.into()),
    ]
    .iter()
    .map(ResealError::check)
    .collect();
    assert_eq!(named, ResealError::CHECKS);
}
