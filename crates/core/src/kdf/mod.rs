//! The frozen KDF edge catalog (blueprint/core.md "KDF edge catalog", #39 D8).
//!
//! Nothing in CipherBox derives a key outside these twenty-five edges, save the
//! primitive-internal schedules named below. Every edge is domain-separated by
//! a fixed `cipherbox/v2/<edge>` context string fed to
//! BLAKE3 `derive_key`; per-node/per-id material takes the frozen shape
//! `keyed_hash(derive_key(context, seed), id)` — ids, tags, and indices are
//! **fixed-length message input**, never variable context, which would admit
//! cross-edge collisions. Composite-material edges hash a fixed-prefix
//! concatenation as the `derive_key` ikm instead.
//!
//! Pure and deterministic: seeds and login secrets enter as parameters, and
//! outputs are the zeroizing owning types from [`crate::suite`]. The KAT
//! manifest freezes the context strings, input layouts, and per-edge outputs;
//! [`edge_probe_outputs`] backs the mechanical separation KAT.
//!
//! Non-edges, stated to stay non-edges (blueprint/core.md): content keys, and
//! every scope seed a rotation or a grant cut mints — all random, none derived
//! here; and a key schedule internal to one primitive, whose output never
//! leaves it for other code to hold and name — HPKE's and the ECIES
//! device-factor seal's (FSM1/cipher-box-next ADR 0015 D2). The genesis pair
//! below is the one exception, and only because genesis has no predecessor to
//! be idempotent against (ADR 0007).

use zeroize::Zeroize;

use crate::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use crate::suite::ed25519::Ed25519Signer;
use crate::suite::hash::{derive_key, keyed_hash};
use crate::suite::secret::{SECRET_LEN, SecretBytes};
use crate::suite::x25519::X25519Secret;

// ---------------------------------------------------------------------------
// The frozen context-string table. `cipherbox/v2/<edge>`; changing any string
// is a breaking KDF change and re-derives every affected key.
// ---------------------------------------------------------------------------

const CTX_NODE_SEED: &str = "cipherbox/v2/node-seed";
const CTX_READ_KEY: &str = "cipherbox/v2/read-key";
const CTX_STRUCTURE_KEY: &str = "cipherbox/v2/structure-key";
const CTX_WRITE_SEED: &str = "cipherbox/v2/write-seed";
const CTX_WRITE_KEY: &str = "cipherbox/v2/write-key";
const CTX_IPNS_KEYPAIR: &str = "cipherbox/v2/ipns-keypair";
const CTX_ASCENT_KEYPAIR: &str = "cipherbox/v2/ascent-keypair";
const CTX_ENC_SUBKEY: &str = "cipherbox/v2/enc-subkey";
const CTX_BLINDED_TAG: &str = "cipherbox/v2/blinded-tag";
const CTX_OWNER_PSEUDONYM_SEED: &str = "cipherbox/v2/owner-pseudonym-seed";
const CTX_PSEUDONYM_SIGN: &str = "cipherbox/v2/pseudonym-sign";
const CTX_OWNER_POINTER_SEED: &str = "cipherbox/v2/owner-pointer-seed";
const CTX_SCOPE_POINTER: &str = "cipherbox/v2/scope-pointer";
const CTX_POINTER_READ_KEY: &str = "cipherbox/v2/pointer-read-key";
const CTX_VAULT_POINTER_INDEX: &str = "cipherbox/v2/vault-pointer-index";
const CTX_SETTINGS_IPNS_KEYPAIR: &str = "cipherbox/v2/settings-ipns-keypair";
const CTX_BIN_INDEX_IPNS_KEYPAIR: &str = "cipherbox/v2/bin-index-ipns-keypair";
const CTX_BIN_INDEX_SEAL_KEY: &str = "cipherbox/v2/bin-index-seal-key";
const CTX_BIN_HELD_KEY: &str = "cipherbox/v2/bin-held-key";
const CTX_GENESIS_READ_SCOPE_SEED: &str = "cipherbox/v2/genesis-read-scope-seed";
const CTX_GENESIS_WRITE_SCOPE_SEED: &str = "cipherbox/v2/genesis-write-scope-seed";
const CTX_CONTACT_LABEL_SEED: &str = "cipherbox/v2/contact-label-seed";
const CTX_CONTACT_LABEL: &str = "cipherbox/v2/contact-label";
const CTX_NAME_LABEL: &str = "cipherbox/v2/name-label";
const CTX_COMMITTED_RECIPIENT_MASK: &str = "cipherbox/v2/committed-recipient-mask";

/// One catalog edge's frozen, machine-checkable metadata: its stable name, its
/// `cipherbox/v2/...` context string, and an input-layout descriptor. The KAT
/// manifest freezes this table; [`EDGES`] is its single source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeSpec {
    pub name: &'static str,
    pub context: &'static str,
    pub input_layout: &'static str,
}

/// The twenty-five edges, in catalog order. [`edge_probe_outputs`] returns one
/// output per row in this same order.
pub const EDGES: &[EdgeSpec] = &[
    EdgeSpec {
        name: "node-seed",
        context: CTX_NODE_SEED,
        input_layout: "keyed_hash(derive_key(ctx, scopeSeed[32]), nodeId[16])",
    },
    EdgeSpec {
        name: "read-key",
        context: CTX_READ_KEY,
        input_layout: "derive_key(ctx, nodeSeed[32])",
    },
    EdgeSpec {
        name: "structure-key",
        context: CTX_STRUCTURE_KEY,
        input_layout: "keyed_hash(derive_key(ctx, seed[32]), structTag[1])",
    },
    EdgeSpec {
        name: "write-seed",
        context: CTX_WRITE_SEED,
        input_layout: "keyed_hash(derive_key(ctx, writeScopeSeed[32]), nodeId[16])",
    },
    EdgeSpec {
        name: "write-key",
        context: CTX_WRITE_KEY,
        input_layout: "derive_key(ctx, writeSeed[32])",
    },
    EdgeSpec {
        name: "ipns-keypair",
        context: CTX_IPNS_KEYPAIR,
        input_layout: "ed25519_from_seed(derive_key(ctx, writeSeed[32]))",
    },
    EdgeSpec {
        name: "ascent-keypair",
        context: CTX_ASCENT_KEYPAIR,
        input_layout: "x25519_from_scalar(derive_key(ctx, parentNodeSeed[32]))",
    },
    EdgeSpec {
        name: "enc-subkey",
        context: CTX_ENC_SUBKEY,
        input_layout: "x25519_from_scalar(derive_key(ctx, loginSecret[var]))",
    },
    EdgeSpec {
        name: "blinded-tag",
        context: CTX_BLINDED_TAG,
        input_layout: "derive_key(ctx, ecdh[32] || scopeRootIpnsName[var])",
    },
    EdgeSpec {
        name: "owner-pseudonym-seed",
        context: CTX_OWNER_PSEUDONYM_SEED,
        input_layout: "derive_key(ctx, loginSecret[var])",
    },
    EdgeSpec {
        name: "pseudonym-sign",
        context: CTX_PSEUDONYM_SIGN,
        input_layout: "ed25519_from_seed(derive_key(ctx, pairwiseMaterial[32] || scopeId[16]))",
    },
    EdgeSpec {
        name: "owner-pointer-seed",
        context: CTX_OWNER_POINTER_SEED,
        input_layout: "derive_key(ctx, loginSecret[var])",
    },
    EdgeSpec {
        name: "scope-pointer",
        context: CTX_SCOPE_POINTER,
        input_layout: "ed25519_from_seed(keyed_hash(derive_key(ctx, ownerPointerSeed[32]), scopeId[16]))",
    },
    EdgeSpec {
        name: "pointer-read-key",
        context: CTX_POINTER_READ_KEY,
        input_layout: "keyed_hash(derive_key(ctx, ownerPointerSeed[32]), scopeId[16])",
    },
    EdgeSpec {
        name: "vault-pointer-index",
        context: CTX_VAULT_POINTER_INDEX,
        input_layout: "ed25519_from_seed(keyed_hash(derive_key(ctx, loginSecret[var]), index[8 BE]))",
    },
    EdgeSpec {
        name: "settings-ipns-keypair",
        context: CTX_SETTINGS_IPNS_KEYPAIR,
        input_layout: "ed25519_from_seed(derive_key(ctx, loginSecret[var]))",
    },
    EdgeSpec {
        name: "bin-index-ipns-keypair",
        context: CTX_BIN_INDEX_IPNS_KEYPAIR,
        input_layout: "ed25519_from_seed(derive_key(ctx, loginSecret[var]))",
    },
    EdgeSpec {
        name: "bin-index-seal-key",
        context: CTX_BIN_INDEX_SEAL_KEY,
        input_layout: "derive_key(ctx, loginSecret[var])",
    },
    EdgeSpec {
        name: "bin-held-key",
        context: CTX_BIN_HELD_KEY,
        input_layout: "keyed_hash(derive_key(ctx, loginSecret[var]), nodeId[16] || deletedAt[8 BE])",
    },
    EdgeSpec {
        name: "genesis-read-scope-seed",
        context: CTX_GENESIS_READ_SCOPE_SEED,
        input_layout: "derive_key(ctx, loginSecret[var])",
    },
    EdgeSpec {
        name: "genesis-write-scope-seed",
        context: CTX_GENESIS_WRITE_SCOPE_SEED,
        input_layout: "derive_key(ctx, loginSecret[var])",
    },
    EdgeSpec {
        name: "contact-label-seed",
        context: CTX_CONTACT_LABEL_SEED,
        input_layout: "derive_key(ctx, loginSecret[var])",
    },
    EdgeSpec {
        name: "contact-label",
        context: CTX_CONTACT_LABEL,
        input_layout: "keyed_hash(derive_key(ctx, contactLabelSeed[32]), identityPk[33])",
    },
    EdgeSpec {
        name: "name-label",
        context: CTX_NAME_LABEL,
        input_layout: "keyed_hash(derive_key(ctx, contactLabelSeed[32]), sequenceKey[var])",
    },
    EdgeSpec {
        name: "committed-recipient-mask",
        context: CTX_COMMITTED_RECIPIENT_MASK,
        input_layout: "keyed_hash(derive_key(ctx, pointerReadKey[32]), tag[32])",
    },
];

// ---------------------------------------------------------------------------
// Core derivations: each edge's raw 32-byte material, in the zeroizing owning
// type. The public edge functions below wrap it into the purpose type; the
// probe reads its bytes.
// ---------------------------------------------------------------------------

fn node_seed_bytes(scope_seed: &[u8; SECRET_LEN], node_id: &[u8; 16]) -> SecretBytes {
    keyed_hash(derive_key(CTX_NODE_SEED, scope_seed).as_bytes(), node_id)
}

fn read_key_bytes(node_seed: &[u8; SECRET_LEN]) -> SecretBytes {
    derive_key(CTX_READ_KEY, node_seed)
}

fn structure_key_bytes(seed: &[u8; SECRET_LEN], struct_tag: u8) -> SecretBytes {
    keyed_hash(
        derive_key(CTX_STRUCTURE_KEY, seed).as_bytes(),
        &[struct_tag],
    )
}

fn write_seed_bytes(write_scope_seed: &[u8; SECRET_LEN], node_id: &[u8; 16]) -> SecretBytes {
    keyed_hash(
        derive_key(CTX_WRITE_SEED, write_scope_seed).as_bytes(),
        node_id,
    )
}

fn write_key_bytes(write_seed: &[u8; SECRET_LEN]) -> SecretBytes {
    derive_key(CTX_WRITE_KEY, write_seed)
}

fn ipns_keypair_bytes(write_seed: &[u8; SECRET_LEN]) -> SecretBytes {
    derive_key(CTX_IPNS_KEYPAIR, write_seed)
}

fn ascent_keypair_bytes(parent_node_seed: &[u8; SECRET_LEN]) -> SecretBytes {
    derive_key(CTX_ASCENT_KEYPAIR, parent_node_seed)
}

fn enc_subkey_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_ENC_SUBKEY, login_secret)
}

fn blinded_tag_bytes(ecdh_shared: &[u8; SECRET_LEN], scope_root_ipns_name: &[u8]) -> SecretBytes {
    let mut ikm = Vec::with_capacity(SECRET_LEN + scope_root_ipns_name.len());
    ikm.extend_from_slice(ecdh_shared);
    ikm.extend_from_slice(scope_root_ipns_name);
    let out = derive_key(CTX_BLINDED_TAG, &ikm);
    ikm.zeroize();
    out
}

fn owner_pseudonym_seed_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_OWNER_PSEUDONYM_SEED, login_secret)
}

fn pseudonym_sign_bytes(pairwise_material: &[u8; SECRET_LEN], scope_id: &[u8; 16]) -> SecretBytes {
    let mut ikm = Vec::with_capacity(SECRET_LEN + 16);
    ikm.extend_from_slice(pairwise_material);
    ikm.extend_from_slice(scope_id);
    let out = derive_key(CTX_PSEUDONYM_SIGN, &ikm);
    ikm.zeroize();
    out
}

fn owner_pointer_seed_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_OWNER_POINTER_SEED, login_secret)
}

fn scope_pointer_bytes(owner_pointer_seed: &[u8; SECRET_LEN], scope_id: &[u8; 16]) -> SecretBytes {
    keyed_hash(
        derive_key(CTX_SCOPE_POINTER, owner_pointer_seed).as_bytes(),
        scope_id,
    )
}

fn pointer_read_key_bytes(
    owner_pointer_seed: &[u8; SECRET_LEN],
    scope_id: &[u8; 16],
) -> SecretBytes {
    keyed_hash(
        derive_key(CTX_POINTER_READ_KEY, owner_pointer_seed).as_bytes(),
        scope_id,
    )
}

fn vault_pointer_index_bytes(login_secret: &[u8], index: u64) -> SecretBytes {
    keyed_hash(
        derive_key(CTX_VAULT_POINTER_INDEX, login_secret).as_bytes(),
        &index.to_be_bytes(),
    )
}

fn settings_ipns_keypair_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_SETTINGS_IPNS_KEYPAIR, login_secret)
}

fn bin_index_ipns_keypair_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_BIN_INDEX_IPNS_KEYPAIR, login_secret)
}

fn bin_index_seal_key_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_BIN_INDEX_SEAL_KEY, login_secret)
}

fn bin_held_root_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_BIN_HELD_KEY, login_secret)
}

fn bin_held_key_bytes(
    bin_held_root: &[u8; SECRET_LEN],
    node_id: &[u8; 16],
    deleted_at: u64,
) -> SecretBytes {
    let mut message = [0u8; 24];
    message[..16].copy_from_slice(node_id);
    message[16..].copy_from_slice(&deleted_at.to_be_bytes());
    keyed_hash(bin_held_root, &message)
}

fn genesis_read_scope_seed_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_GENESIS_READ_SCOPE_SEED, login_secret)
}

fn genesis_write_scope_seed_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_GENESIS_WRITE_SCOPE_SEED, login_secret)
}

fn contact_label_seed_bytes(login_secret: &[u8]) -> SecretBytes {
    derive_key(CTX_CONTACT_LABEL_SEED, login_secret)
}

fn committed_recipient_mask_bytes(
    pointer_read_key: &[u8; SECRET_LEN],
    tag: &[u8; SECRET_LEN],
) -> SecretBytes {
    keyed_hash(
        derive_key(CTX_COMMITTED_RECIPIENT_MASK, pointer_read_key).as_bytes(),
        tag,
    )
}

fn contact_label_bytes(
    contact_label_seed: &[u8; SECRET_LEN],
    identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
) -> SecretBytes {
    keyed_hash(
        derive_key(CTX_CONTACT_LABEL, contact_label_seed).as_bytes(),
        identity_pk,
    )
}

fn name_label_bytes(contact_label_seed: &[u8; SECRET_LEN], key: &[u8]) -> SecretBytes {
    keyed_hash(
        derive_key(CTX_NAME_LABEL, contact_label_seed).as_bytes(),
        key,
    )
}

// ---------------------------------------------------------------------------
// Public edge API. The engine derives every key through exactly these.
// ---------------------------------------------------------------------------

/// `node-seed`: a node's flat-within-scope seed from the scope seed and node id.
pub fn node_seed(scope_seed: &[u8; SECRET_LEN], node_id: &[u8; 16]) -> SecretBytes {
    node_seed_bytes(scope_seed, node_id)
}

/// `read-key`: a node's read (sealing) key from its node seed.
pub fn read_key(node_seed: &[u8; SECRET_LEN]) -> SecretBytes {
    read_key_bytes(node_seed)
}

/// `structure-key`: a per-structure sealing key from a node/scope seed and a
/// 1-byte structure tag.
pub fn structure_key(seed: &[u8; SECRET_LEN], struct_tag: u8) -> SecretBytes {
    structure_key_bytes(seed, struct_tag)
}

/// `write-seed`: a node's flat write seed from the write scope seed and node id.
pub fn write_seed(write_scope_seed: &[u8; SECRET_LEN], node_id: &[u8; 16]) -> SecretBytes {
    write_seed_bytes(write_scope_seed, node_id)
}

/// `write-key`: a node's write (sealing) key from its write seed.
pub fn write_key(write_seed: &[u8; SECRET_LEN]) -> SecretBytes {
    write_key_bytes(write_seed)
}

/// `ipns-keypair`: the Ed25519 keypair (→ `ipnsName`) from a write seed.
pub fn ipns_keypair(write_seed: &[u8; SECRET_LEN]) -> Ed25519Signer {
    Ed25519Signer::from_seed(*ipns_keypair_bytes(write_seed).as_bytes())
}

/// `ascent-keypair`: the X25519 keypair for the ascent link, from the parent
/// node seed.
pub fn ascent_keypair(parent_node_seed: &[u8; SECRET_LEN]) -> X25519Secret {
    X25519Secret::from_scalar(*ascent_keypair_bytes(parent_node_seed).as_bytes())
}

/// `enc-subkey`: the X25519 encryption subkey from the login secret.
pub fn enc_subkey(login_secret: &[u8]) -> X25519Secret {
    X25519Secret::from_scalar(*enc_subkey_bytes(login_secret).as_bytes())
}

/// `blinded-tag`: the public grant-blob tag from an ECDH secret and the scope
/// root's `ipnsName`.
///
/// `ecdh_shared` must be a **contributory** X25519 result: an all-zero shared
/// secret yields a tag depending only on the `ipnsName` — degenerate, not a
/// secrecy break (the tag is public). Callers get that check for free from
/// [`X25519Secret::diffie_hellman`](crate::suite::x25519::X25519Secret::diffie_hellman).
pub fn blinded_tag(
    ecdh_shared: &[u8; SECRET_LEN],
    scope_root_ipns_name: &[u8],
) -> [u8; SECRET_LEN] {
    *blinded_tag_bytes(ecdh_shared, scope_root_ipns_name).as_bytes()
}

/// `owner-pseudonym-seed`: the owner's `pseudonym-sign` input, from the login
/// secret. A dedicated edge keeps structure-signing authority off the
/// encryption and pointer planes (FSM1/cipher-box-next ADR 0005).
pub fn owner_pseudonym_seed(login_secret: &[u8]) -> SecretBytes {
    owner_pseudonym_seed_bytes(login_secret)
}

/// `pseudonym-sign`: the Ed25519 writer-pseudonym keypair from the pairwise
/// material (a grantee's ECDH secret, or the owner's `ownerPseudonymSeed`) and
/// the scope id.
pub fn pseudonym_sign(pairwise_material: &[u8; SECRET_LEN], scope_id: &[u8; 16]) -> Ed25519Signer {
    Ed25519Signer::from_seed(*pseudonym_sign_bytes(pairwise_material, scope_id).as_bytes())
}

/// `owner-pointer-seed`: the owner's pointer seed from the login secret.
pub fn owner_pointer_seed(login_secret: &[u8]) -> SecretBytes {
    owner_pointer_seed_bytes(login_secret)
}

/// `scope-pointer`: a per-scope pointer Ed25519 keypair from the owner pointer
/// seed and the scope id.
pub fn scope_pointer(owner_pointer_seed: &[u8; SECRET_LEN], scope_id: &[u8; 16]) -> Ed25519Signer {
    Ed25519Signer::from_seed(*scope_pointer_bytes(owner_pointer_seed, scope_id).as_bytes())
}

/// `pointer-read-key`: the stable per-scope pointer read key from the owner
/// pointer seed and the scope id.
pub fn pointer_read_key(owner_pointer_seed: &[u8; SECRET_LEN], scope_id: &[u8; 16]) -> SecretBytes {
    pointer_read_key_bytes(owner_pointer_seed, scope_id)
}

/// `vault-pointer-index`: the i-th vault pointer Ed25519 keypair from the login
/// secret (index 0 is the default).
pub fn vault_pointer_index(login_secret: &[u8], index: u64) -> Ed25519Signer {
    Ed25519Signer::from_seed(*vault_pointer_index_bytes(login_secret, index).as_bytes())
}

/// `settings-ipns-keypair`: the vault settings record's Ed25519 keypair
/// (→ `ipnsName`), derived from the login secret so the name resolves at cold
/// start without CipherBox infrastructure.
pub fn settings_ipns_keypair(login_secret: &[u8]) -> Ed25519Signer {
    Ed25519Signer::from_seed(*settings_ipns_keypair_bytes(login_secret).as_bytes())
}

/// `bin-index-ipns-keypair`: the bin index record's Ed25519 keypair
/// (→ `ipnsName`), derived from the login secret so the owner's bin resolves at
/// cold start without CipherBox infrastructure (ADR 0010).
pub fn bin_index_ipns_keypair(login_secret: &[u8]) -> Ed25519Signer {
    Ed25519Signer::from_seed(*bin_index_ipns_keypair_bytes(login_secret).as_bytes())
}

/// `bin-index-seal-key`: the symmetric key that seals the bin index body. The
/// index is owner-sealed, so it derives from the login secret and no grant
/// carries it.
///
/// This key takes no epoch input, so it never rotates: every publish of the bin
/// index, on every device, seals under it. A caller must therefore draw each
/// seal's nonce from a CSPRNG. A counter or a `revision`-derived nonce is unique
/// on one device and collides across two, and two devices publish this record
/// concurrently under one CAS guard.
pub fn bin_index_seal_key(login_secret: &[u8]) -> SecretBytes {
    bin_index_seal_key_bytes(login_secret)
}

/// The account half of the `bin-held-key` edge — an intermediate, never a key.
/// It seals nothing and seeds no scope; the only thing it may do is feed
/// [`bin_held_key`].
///
/// A session derives it once and carries it in place of the login secret, so the
/// pass that re-keys a doomed subtree holds the bin's capability and nothing
/// wider. That capability is every held key of every node and every generation,
/// so it never enters a bin entry, an export, or a log.
pub fn bin_held_root(login_secret: &[u8]) -> SecretBytes {
    bin_held_root_bytes(login_secret)
}

/// `bin-held-key`: the seed one soft delete re-keys a doomed subtree under
/// (ADR 0010 item 3). It sits outside every scope's derivation, which is what
/// cuts a grantee's access — key regression cannot reach it, because no scope
/// seed of any epoch is an input.
///
/// The key is scope-seed shaped: every node of the doomed subtree keys at
/// `read_key(node_seed(held, nodeId))`, so one held key opens the whole subtree
/// and `node_id` here is the subtree root's — the node the bin entry names.
///
/// `deleted_at` makes the key per-delete rather than per-node: a node that is
/// binned, restored, and binned again re-keys under fresh bytes, so a disclosed
/// held key opens one bin generation and not every later one.
pub fn bin_held_key(
    bin_held_root: &[u8; SECRET_LEN],
    node_id: &[u8; 16],
    deleted_at: u64,
) -> SecretBytes {
    bin_held_key_bytes(bin_held_root, node_id, deleted_at)
}

/// `genesis-read-scope-seed`: the vault root scope's read (override) seed at the
/// genesis epoch, from the login secret.
///
/// Genesis alone derives — it has no predecessor to be idempotent against, and
/// deriving is what makes two mint attempts by one account reproduce one vault
/// (ADR 0007 D1). Every later read seed is drawn at its rotation.
pub fn genesis_read_scope_seed(login_secret: &[u8]) -> SecretBytes {
    genesis_read_scope_seed_bytes(login_secret)
}

/// `genesis-write-scope-seed`: the vault root scope's `writeScopeSeed` at the
/// genesis epoch, from the login secret. See [`genesis_read_scope_seed`] for why
/// genesis is the one derived pair.
pub fn genesis_write_scope_seed(login_secret: &[u8]) -> SecretBytes {
    genesis_write_scope_seed_bytes(login_secret)
}

/// `contact-label-seed`: the device-only seed [`contact_label`] labels under,
/// from the login secret. A dedicated edge, so the label derives from no key
/// that leaves the device.
pub fn contact_label_seed(login_secret: &[u8]) -> SecretBytes {
    contact_label_seed_bytes(login_secret)
}

/// `committed-recipient-mask`: the per-(scope, tag) keystream a grant-set
/// commitment entry hides its recipient encryption subkey under.
///
/// Keyed on the scope's `pointerReadKey`, which the owner derives and every
/// grant blob carries, so the owner and every grantee of the scope recover the
/// recipient and no observer does. The blinded tag is the message, so one
/// recipient masks to unrelated bytes at every scope root — the unlinkability
/// the tag itself exists for, extended to the recipient the owner must commit.
pub fn committed_recipient_mask(
    pointer_read_key: &[u8; SECRET_LEN],
    tag: &[u8; SECRET_LEN],
) -> SecretBytes {
    committed_recipient_mask_bytes(pointer_read_key, tag)
}

/// `contact-label`: a fixed-width local label for a contact identity key, for
/// keying durable device-local state that would otherwise name that contact in
/// the clear.
///
/// Deterministic across sessions on one device, and unlinkable off it: the seed
/// is the account's alone, so no observer who holds the identity key can
/// recompute the label. Local state only — a label MUST never be published, or
/// it becomes exactly the cross-scope correlator the blinded tag exists to deny.
/// The identity key enters as fixed-length `keyed_hash` message, never as
/// context and never as a concatenation tail.
pub fn contact_label(
    contact_label_seed: &[u8; SECRET_LEN],
    identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
) -> [u8; SECRET_LEN] {
    *contact_label_bytes(contact_label_seed, identity_pk).as_bytes()
}

/// `name-label`: a fixed-width local label for a durable sequence-namespace
/// floor key, so a floor store that a reader of local storage can open names no
/// record it bars replay on (FSM1/cipher-box-next ADR 0016).
///
/// The message is the whole store key, not only an `ipnsName`, so two keys that
/// share a name but not a purpose label to unrelated bytes. It is the catalog's
/// one variable-length message: the context stays fixed, and `keyed_hash` is a
/// pseudorandom function over a message of any length.
///
/// The seed is the account's alone, so an observer who collects published names
/// inverts nothing, and every reader in the account labels one name the same
/// way — one name keeps one sequence ratchet. Local state only, on the same
/// terms as [`contact_label`]: a published label is a cross-scope correlator.
pub fn name_label(contact_label_seed: &[u8; SECRET_LEN], key: &[u8]) -> [u8; SECRET_LEN] {
    *name_label_bytes(contact_label_seed, key).as_bytes()
}

// ---------------------------------------------------------------------------
// Separation surface: the whole edge table under one set of probe inputs.
// ---------------------------------------------------------------------------

/// Fixed inputs driving every edge through [`edge_probe_outputs`]. One probe
/// fills every seed-shaped and id-shaped slot, so any two outputs differing is
/// attributable to the context string alone — what the separation KAT asserts.
///
/// `#[doc(hidden)]`: `pub` only for the cross-crate KAT tests and the `kat_gen`
/// example, not supported API. `seed` is key material, so `Debug` is redacted.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct EdgeProbe<'a> {
    /// Fills every 32-byte seed / ECDH / material / login-secret slot.
    pub seed: &'a [u8; SECRET_LEN],
    /// Fills every 16-byte node-id / scope-id slot.
    pub id: &'a [u8; 16],
    /// The structure tag for `structure-key`.
    pub struct_tag: u8,
    /// The index for `vault-pointer-index`.
    pub index: u64,
    /// The variable-length message of `blinded-tag` and `name-label`.
    pub ipns_name: &'a [u8],
    /// The 33-byte compressed SEC1 identity key for `contact-label`.
    pub identity_pk: &'a [u8; IDENTITY_PUBLIC_LEN],
}

impl core::fmt::Debug for EdgeProbe<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EdgeProbe")
            .field("seed", &"<redacted>")
            .field("id", &self.id)
            .field("struct_tag", &self.struct_tag)
            .field("index", &self.index)
            .field("ipns_name", &self.ipns_name)
            .field("identity_pk", &self.identity_pk)
            .finish()
    }
}

/// One edge's raw 32-byte derived output under a probe. The output is key
/// material, so `Debug` is redacted; `PartialEq` compares the frozen KAT
/// outputs (test inputs, not attacker-controlled secrets) so it needs no
/// constant-time guarantee.
///
/// `#[doc(hidden)]`: see [`EdgeProbe`] — a test/KAT surface, not supported API.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EdgeProbeOutput {
    pub name: &'static str,
    pub output: [u8; SECRET_LEN],
}

impl core::fmt::Debug for EdgeProbeOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EdgeProbeOutput")
            .field("name", &self.name)
            .field("output", &"<redacted>")
            .finish()
    }
}

/// Run every edge under one probe, in [`EDGES`] order. Backs the separation KAT
/// (the outputs must be pairwise distinct), its property test, and the frozen
/// vectors the KAT generator writes.
///
/// The **catalog-freezing / separation surface**, not the production derivation
/// path: it returns each edge's raw derived bytes in the clear. Never feed
/// production seeds through it — derive through the typed edge functions above
/// ([`node_seed`], [`read_key`], …), which return zeroizing owning types.
/// `#[doc(hidden)]`: see [`EdgeProbe`].
#[doc(hidden)]
pub fn edge_probe_outputs(probe: &EdgeProbe) -> Vec<EdgeProbeOutput> {
    let b = |s: SecretBytes| *s.as_bytes();
    vec![
        EdgeProbeOutput {
            name: "node-seed",
            output: b(node_seed_bytes(probe.seed, probe.id)),
        },
        EdgeProbeOutput {
            name: "read-key",
            output: b(read_key_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "structure-key",
            output: b(structure_key_bytes(probe.seed, probe.struct_tag)),
        },
        EdgeProbeOutput {
            name: "write-seed",
            output: b(write_seed_bytes(probe.seed, probe.id)),
        },
        EdgeProbeOutput {
            name: "write-key",
            output: b(write_key_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "ipns-keypair",
            output: b(ipns_keypair_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "ascent-keypair",
            output: b(ascent_keypair_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "enc-subkey",
            output: b(enc_subkey_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "blinded-tag",
            output: b(blinded_tag_bytes(probe.seed, probe.ipns_name)),
        },
        EdgeProbeOutput {
            name: "owner-pseudonym-seed",
            output: b(owner_pseudonym_seed_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "pseudonym-sign",
            output: b(pseudonym_sign_bytes(probe.seed, probe.id)),
        },
        EdgeProbeOutput {
            name: "owner-pointer-seed",
            output: b(owner_pointer_seed_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "scope-pointer",
            output: b(scope_pointer_bytes(probe.seed, probe.id)),
        },
        EdgeProbeOutput {
            name: "pointer-read-key",
            output: b(pointer_read_key_bytes(probe.seed, probe.id)),
        },
        EdgeProbeOutput {
            name: "vault-pointer-index",
            output: b(vault_pointer_index_bytes(probe.seed, probe.index)),
        },
        EdgeProbeOutput {
            name: "settings-ipns-keypair",
            output: b(settings_ipns_keypair_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "bin-index-ipns-keypair",
            output: b(bin_index_ipns_keypair_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "bin-index-seal-key",
            output: b(bin_index_seal_key_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "bin-held-key",
            output: b(bin_held_key_bytes(
                bin_held_root_bytes(probe.seed).as_bytes(),
                probe.id,
                probe.index,
            )),
        },
        EdgeProbeOutput {
            name: "genesis-read-scope-seed",
            output: b(genesis_read_scope_seed_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "genesis-write-scope-seed",
            output: b(genesis_write_scope_seed_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "contact-label-seed",
            output: b(contact_label_seed_bytes(probe.seed)),
        },
        EdgeProbeOutput {
            name: "contact-label",
            output: b(contact_label_bytes(probe.seed, probe.identity_pk)),
        },
        EdgeProbeOutput {
            name: "name-label",
            output: b(name_label_bytes(probe.seed, probe.ipns_name)),
        },
        EdgeProbeOutput {
            name: "committed-recipient-mask",
            output: b(committed_recipient_mask_bytes(probe.seed, probe.seed)),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const PROBE_IDENTITY_PK: [u8; IDENTITY_PUBLIC_LEN] = [0x02; IDENTITY_PUBLIC_LEN];

    fn probe<'a>(seed: &'a [u8; 32], id: &'a [u8; 16], name: &'a [u8]) -> EdgeProbe<'a> {
        EdgeProbe {
            seed,
            id,
            struct_tag: 1,
            index: 0,
            ipns_name: name,
            identity_pk: &PROBE_IDENTITY_PK,
        }
    }

    #[test]
    fn edge_probe_matches_edges_table_order() {
        let out = edge_probe_outputs(&probe(&[1; 32], &[2; 16], b"name"));
        assert_eq!(out.len(), EDGES.len());
        for (o, e) in out.iter().zip(EDGES) {
            assert_eq!(o.name, e.name, "probe order must track EDGES order");
        }
    }

    #[test]
    fn edges_are_pairwise_separated() {
        // Uniform inputs across every slot: any collision would be a context
        // failure, not an input coincidence.
        let out = edge_probe_outputs(&probe(&[9; 32], &[9; 16], b"scope-root-ipns"));
        let distinct: BTreeSet<[u8; 32]> = out.iter().map(|o| o.output).collect();
        assert_eq!(
            distinct.len(),
            EDGES.len(),
            "two edges produced equal output"
        );
    }

    #[test]
    fn edge_contexts_are_unique_and_v2_prefixed() {
        let mut seen = BTreeSet::new();
        for e in EDGES {
            assert!(seen.insert(e.context), "duplicate context {}", e.context);
            assert_eq!(e.context, format!("cipherbox/v2/{}", e.name));
        }
    }

    #[test]
    fn public_edges_agree_with_probe_material() {
        // The typed public API must derive from the same bytes the probe/KAT
        // freeze, so freezing the probe freezes the real keys.
        let seed = [3u8; 32];
        let id = [4u8; 16];
        let out = edge_probe_outputs(&probe(&seed, &id, b"n"));
        let by = |name: &str| out.iter().find(|o| o.name == name).unwrap().output;

        assert_eq!(read_key(&seed).as_bytes(), &by("read-key"));
        assert_eq!(node_seed(&seed, &id).as_bytes(), &by("node-seed"));
        assert_eq!(
            owner_pseudonym_seed(&seed).as_bytes(),
            &by("owner-pseudonym-seed")
        );
        // Keypair edges: the public key must match a keypair built from the
        // frozen seed bytes.
        assert_eq!(
            ipns_keypair(&seed).verifying_key().to_bytes(),
            Ed25519Signer::from_seed(by("ipns-keypair"))
                .verifying_key()
                .to_bytes()
        );
        assert_eq!(
            enc_subkey(&seed).public().to_bytes(),
            X25519Secret::from_scalar(by("enc-subkey"))
                .public()
                .to_bytes()
        );
        assert_eq!(
            settings_ipns_keypair(&seed).verifying_key().to_bytes(),
            Ed25519Signer::from_seed(by("settings-ipns-keypair"))
                .verifying_key()
                .to_bytes()
        );
        assert_eq!(
            bin_index_ipns_keypair(&seed).verifying_key().to_bytes(),
            Ed25519Signer::from_seed(by("bin-index-ipns-keypair"))
                .verifying_key()
                .to_bytes()
        );
        assert_eq!(
            bin_index_seal_key(&seed).as_bytes(),
            &by("bin-index-seal-key")
        );
        assert_eq!(
            bin_held_key(bin_held_root(&seed).as_bytes(), &id, 0).as_bytes(),
            &by("bin-held-key")
        );
        assert_eq!(
            genesis_read_scope_seed(&seed).as_bytes(),
            &by("genesis-read-scope-seed")
        );
        assert_eq!(
            genesis_write_scope_seed(&seed).as_bytes(),
            &by("genesis-write-scope-seed")
        );
        assert_eq!(
            contact_label_seed(&seed).as_bytes(),
            &by("contact-label-seed")
        );
        assert_eq!(
            contact_label(&seed, &PROBE_IDENTITY_PK),
            by("contact-label")
        );
        assert_eq!(name_label(&seed, b"n"), by("name-label"));
    }

    /// The label must separate two contacts on one device and one contact
    /// across two devices, which is the whole of what it buys the floor store.
    #[test]
    fn a_contact_label_separates_contacts_and_accounts() {
        let seed = contact_label_seed(b"login-secret");
        let other_seed = contact_label_seed(b"another-secret");
        let a = [0x02u8; IDENTITY_PUBLIC_LEN];
        let mut b = a;
        b[IDENTITY_PUBLIC_LEN - 1] ^= 1;

        assert_eq!(
            contact_label(seed.as_bytes(), &a),
            contact_label(contact_label_seed(b"login-secret").as_bytes(), &a),
            "one account labels one contact the same way on every session",
        );
        assert_ne!(
            contact_label(seed.as_bytes(), &a),
            contact_label(seed.as_bytes(), &b)
        );
        assert_ne!(
            contact_label(seed.as_bytes(), &a),
            contact_label(other_seed.as_bytes(), &a),
            "and no other account can recompute it from the identity key alone",
        );
    }

    /// The label must separate two names under one account and one name across
    /// two accounts, and it must carry no run of the name it labels — the whole
    /// of what it buys the durable floor store (ADR 0016).
    #[test]
    fn a_name_label_separates_names_and_accounts_and_hides_the_name() {
        let seed = contact_label_seed(b"login-secret");
        let other_seed = contact_label_seed(b"another-secret");
        let name = b"k51qzi5uqu5-scope-root".as_slice();

        assert_eq!(
            name_label(seed.as_bytes(), name),
            name_label(contact_label_seed(b"login-secret").as_bytes(), name),
            "one account labels one name the same way on every session",
        );
        assert_ne!(
            name_label(seed.as_bytes(), name),
            name_label(seed.as_bytes(), b"k51qzi5uqu5-other-root"),
        );
        assert_ne!(
            name_label(seed.as_bytes(), name),
            name_label(other_seed.as_bytes(), name),
            "and no other account can recompute it from the public name alone",
        );
        // A variable-length message: a name and a prefix of it must not label
        // alike, which a length-blind construction would allow.
        assert_ne!(
            name_label(seed.as_bytes(), name),
            name_label(seed.as_bytes(), &name[..name.len() - 1]),
        );
        for run in name.windows(8) {
            assert!(
                !name_label(seed.as_bytes(), name)
                    .windows(run.len())
                    .any(|w| w == run),
                "a label carries part of the name it hides",
            );
        }
    }

    /// The bin edges are the owner's alone, and the held key is per-delete: the
    /// access cut ADR 0010 item 3 rests on is that nothing a grantee holds is an
    /// input, and that a second binning of one node draws fresh bytes.
    #[test]
    fn the_bin_edges_separate_by_secret_node_and_delete_time() {
        let secret = b"login-secret".as_slice();
        let other = b"another-secret".as_slice();
        let node = [7u8; 16];

        assert_ne!(
            bin_index_ipns_keypair(secret).verifying_key().to_bytes(),
            bin_index_ipns_keypair(other).verifying_key().to_bytes(),
        );
        assert_ne!(
            bin_index_seal_key(secret).as_bytes(),
            bin_index_seal_key(other).as_bytes(),
        );
        let root = bin_held_root(secret);
        let other_root = bin_held_root(other);
        assert_ne!(root.as_bytes(), other_root.as_bytes());
        assert_ne!(
            bin_held_key(root.as_bytes(), &node, 10).as_bytes(),
            bin_held_key(other_root.as_bytes(), &node, 10).as_bytes(),
        );
        assert_ne!(
            bin_held_key(root.as_bytes(), &node, 10).as_bytes(),
            bin_held_key(root.as_bytes(), &[8u8; 16], 10).as_bytes(),
        );
        assert_ne!(
            bin_held_key(root.as_bytes(), &node, 10).as_bytes(),
            bin_held_key(root.as_bytes(), &node, 11).as_bytes(),
            "a re-bin of one node must not reuse the first binning's key",
        );
        assert_eq!(
            bin_held_key(root.as_bytes(), &node, 10).as_bytes(),
            bin_held_key(root.as_bytes(), &node, 10).as_bytes(),
        );
    }

    /// The genesis pair is the whole of ADR 0007's derived-mint property: the two
    /// seeds must be a pure function of the login secret and must not be each
    /// other. Separation from the rest of the catalog is
    /// [`edges_are_pairwise_separated`]'s job.
    #[test]
    fn the_genesis_pair_is_derived_and_separated() {
        let secret = b"login-secret".as_slice();
        assert_eq!(
            genesis_read_scope_seed(secret).as_bytes(),
            genesis_read_scope_seed(secret).as_bytes(),
            "a second attempt by one account derives the same read seed",
        );
        assert_eq!(
            genesis_write_scope_seed(secret).as_bytes(),
            genesis_write_scope_seed(secret).as_bytes(),
            "and the same write seed, which is what makes the mint idempotent",
        );
        assert_ne!(
            genesis_read_scope_seed(secret).as_bytes(),
            genesis_write_scope_seed(secret).as_bytes(),
        );
        for edge in [
            genesis_read_scope_seed as fn(&[u8]) -> SecretBytes,
            genesis_write_scope_seed,
        ] {
            assert_ne!(edge(secret).as_bytes(), &[0u8; 32]);
            assert_ne!(edge(secret).as_bytes(), edge(b"another-secret").as_bytes());
        }
    }
}
