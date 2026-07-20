//! The frozen KDF edge catalog (blueprint/core.md "KDF edge catalog", #39 D8).
//!
//! Nothing in CipherBox derives a key outside these fourteen edges. Every edge
//! is domain-separated by a fixed `cipherbox/v2/<edge>` context string fed to
//! BLAKE3 `derive_key`; per-node/per-id material then takes the frozen shape
//! `keyed_hash(derive_key(context, seed), id)` — ids, tags, and indices are
//! **fixed-length message input**, never variable context (a variable context
//! would admit cross-edge collisions). Composite-material edges hash a
//! fixed-prefix concatenation as the `derive_key` ikm instead.
//!
//! The catalog is `pure` and deterministic: seeds and login secrets enter as
//! parameters, and outputs are the zeroizing owning types from [`crate::suite`].
//! The context-string table, input layouts, and per-edge outputs are frozen in
//! the KAT manifest, and [`edge_probe_outputs`] backs both the mechanical
//! separation KAT (no two edges share an output for equal inputs) and its
//! property test.
//!
//! Non-edges, stated to stay non-edges (blueprint/core.md): content keys
//! (random per version), scope override seeds (random at rotation), and scope
//! seeds at grant cuts (random) — none derive through here.

use zeroize::Zeroize;

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
const CTX_PSEUDONYM_SIGN: &str = "cipherbox/v2/pseudonym-sign";
const CTX_OWNER_POINTER_SEED: &str = "cipherbox/v2/owner-pointer-seed";
const CTX_SCOPE_POINTER: &str = "cipherbox/v2/scope-pointer";
const CTX_POINTER_READ_KEY: &str = "cipherbox/v2/pointer-read-key";
const CTX_VAULT_POINTER_INDEX: &str = "cipherbox/v2/vault-pointer-index";

/// One catalog edge's frozen, machine-checkable metadata: its stable name, its
/// `cipherbox/v2/...` context string, and an input-layout descriptor. The KAT
/// manifest freezes this table; [`EDGES`] is its single source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeSpec {
    pub name: &'static str,
    pub context: &'static str,
    pub input_layout: &'static str,
}

/// The fourteen edges, in catalog order. [`edge_probe_outputs`] returns one
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
];

// ---------------------------------------------------------------------------
// Core derivations. Each returns the 32-byte material its edge is built on,
// in the zeroizing owning type; the public edge functions below wrap it into
// the purpose type, and the probe reads its bytes.
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
/// `ecdh_shared` is expected to be a **contributory** X25519 result. A
/// low-order peer public key forces an all-zero shared secret and thus a tag
/// that depends only on the `ipnsName` — degenerate, not a secrecy break (the
/// tag is public), but callers computing the ECDH should use the contributory
/// check on the [`x25519`](crate::suite::x25519) seam if they later attach any
/// secrecy requirement to the tag.
pub fn blinded_tag(
    ecdh_shared: &[u8; SECRET_LEN],
    scope_root_ipns_name: &[u8],
) -> [u8; SECRET_LEN] {
    *blinded_tag_bytes(ecdh_shared, scope_root_ipns_name).as_bytes()
}

/// `pseudonym-sign`: the Ed25519 writer-pseudonym keypair from the pairwise
/// material (ECDH, or the owner's root secret) and the scope id.
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

// ---------------------------------------------------------------------------
// Separation surface: the whole edge table under one set of probe inputs.
// ---------------------------------------------------------------------------

/// Fixed inputs driving every edge through [`edge_probe_outputs`]. The same
/// probe fills each edge's seed-shaped and id-shaped slots, so a difference in
/// any two outputs is attributable to the context string alone — exactly what
/// the mechanical separation KAT asserts.
///
/// `seed` is caller key material, so `Debug` is redacted.
///
/// `#[doc(hidden)]`: `pub` only so the KAT integration tests and the `kat_gen`
/// example (separate crates) can drive the separation surface. Not part of the
/// supported API — production derives keys through the typed edge functions.
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
    /// The scope-root `ipnsName` for `blinded-tag`.
    pub ipns_name: &'a [u8],
}

impl core::fmt::Debug for EdgeProbe<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EdgeProbe")
            .field("seed", &"<redacted>")
            .field("id", &self.id)
            .field("struct_tag", &self.struct_tag)
            .field("index", &self.index)
            .field("ipns_name", &self.ipns_name)
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
/// (the fourteen outputs must be pairwise distinct) and its property test, and
/// is the frozen-vector surface the KAT generator writes.
///
/// This is the **catalog-freezing / separation surface**, not the production
/// derivation path: it returns each edge's raw derived bytes in the clear
/// (redacted `Debug` notwithstanding). Production code derives keys through the
/// typed edge functions above ([`node_seed`], [`read_key`], …), which return
/// zeroizing owning types. Do not feed production seeds through this function.
///
/// `#[doc(hidden)]`: `pub` exists only for the cross-crate KAT tests and the
/// `kat_gen` example; it is not part of the crate's supported surface and the
/// engine must never call it.
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn probe<'a>(seed: &'a [u8; 32], id: &'a [u8; 16], name: &'a [u8]) -> EdgeProbe<'a> {
        EdgeProbe {
            seed,
            id,
            struct_tag: 1,
            index: 0,
            ipns_name: name,
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
    }
}
