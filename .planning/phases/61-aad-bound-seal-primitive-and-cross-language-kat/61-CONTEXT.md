# Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT - Context

**Gathered:** 2026-06-27
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 61 delivers the canonical **AAD-bound AES-256-GCM seal primitive** and its **frozen byte encoding**, in both TypeScript (`@cipherbox/crypto`) and Rust (`cipherbox-crypto`), proven byte-identical by a committed cross-language Known-Answer Test (KAT).

New, additive surface (no consumer breaks this phase):

- `sealAesGcmAad(plaintext, key, aad)` / `unsealAesGcmAad(sealed, key, aad)`
- `buildNodeAad(nodeId, kind, generation, role)` — the canonical AAD builder with a frozen byte encoding
- A Rust twin of all three in `cipherbox-crypto`
- One committed cross-language KAT fixture covering all four role bytes, asserted by both `packages/crypto/__tests__/build-node-aad.test.ts` and a Rust `#[test]` in `crates/crypto/tests/cross_language.rs`
- An AAD transplant-resistance negative suite (CRYPTO-03)
- **Documentation:** ADR 0003 freezing the encoding + aligned pointers in the metadata/encryption docs (user-directed scope addition — see D-05)

The frozen encoding must be committed and KAT-green **before** any consumer seals a `Node` — a retroactive encoding change would require rotating every sealed body.

**In scope:** the seal/unseal/AAD-builder primitives, the frozen encoding, the KAT, the transplant suite, and the ADR + doc pointers for the crypto/encoding layer.

**Out of scope (hard boundary):**

- The `FolderMetadata`/`FileMetadata`/`FilePointer` → unified `Node` schema and its documentation → **phase 62** (ROADMAP SC#6 already assigns `METADATA_SCHEMAS.md` schema rewrite to 62). Phase 61 docs touch the encryption/encoding layer only.
- Any consumer rewiring (FUSE symmetric unwrap, sdk-core sealing, web) → phases 62–69.
- AES-CTR content streaming — `encryptAesCtr` already exists and is a content concern, not part of the GCM+AAD seal primitive.

</domain>

<decisions>
## Implementation Decisions

### Frozen AAD encoding (locked by milestone research — NOT re-litigated)

The byte encoding is already frozen in `.planning/research/ARCHITECTURE.md` §4.3 (line 114) and `PITFALLS.md` Pitfall 1. Carried forward verbatim — downstream agents implement strictly from this, not from the other language's source:

```
buildNodeAad =
  "cipherbox/node-seal/v1"           (UTF-8 domain string)
  ‖ 0x00                              (null separator before nodeId)
  ‖ nodeId        (16 bytes, raw UUID bytes, RFC-4122 field order)
  ‖ kind          (1 byte: 0x01 folder / 0x02 file / 0x03 root)
  ‖ generation    (4 bytes, big-endian u32)
  ‖ role          (1 byte: 0x01 body / 0x02 child-readkey / 0x03 content / 0x04 child-writekey)
```

- **D-00a:** Seal blob layout is the already-frozen `[IV(12 bytes)][ciphertext + 16-byte GCM tag]` (matches existing `sealAesGcm`/`seal_aes_gcm`). Each seal mints a **fresh random 12-byte IV**.
- **D-00b:** `sealAesGcm`/`seal_aes_gcm` (non-AAD) **stay** for non-node uses; the AAD variants are additive in `packages/crypto/src/aes/seal.ts` and `crates/crypto/src/aes.rs`.

### KAT vector rigor (D-01)

- **D-01:** Commit **both** vector kinds (recommended default; user did not override):
  - (a) An **AAD-bytes vector** — `buildNodeAad(...) → exact aad_bytes`, covering **all four role bytes** (`0x01..0x04`). This is the literal research deliverable and the first thing to land.
  - (b) A **fixed-key / fixed-IV full-seal vector** — `sealAesGcmAad(plaintext, key, iv, aad) → exact [IV][ct+tag]`, mirroring the existing `tests/vectors/crypto/aes-gcm.json` precedent. Proves the **entire** AEAD-with-AAD path is byte-identical across TS↔Rust, not just AAD construction.
  - Rationale: TEST-02 — "a byte mismatch is silent total decryption failure." The AAD-only vector pins the builder; the full-seal vector pins that AAD actually flows into the AEAD identically on both sides. The KAT infra already supports fixed-IV vectors, so the marginal cost is one JSON entry.

### Transplant-resistance / negative suite (CRYPTO-03) (D-02)

- **D-02:** **Extended** negative matrix (recommended default). A sealed blob must fail to unseal when replayed under a different:
  - `childId` (nodeId), `role`, `generation` — the CRYPTO-03 minimum
  - plus `kind`
  - plus `domain` version (e.g. forging `node-seal/v2`)
  - plus a **tamper case** — flipped auth-tag bit and a truncated blob (below `IV+tag` minimum) must error, not silently succeed.

### `buildNodeAad` input validation (D-03)

- **D-03:** **Fail-closed** (recommended default). `buildNodeAad` rejects (throws / returns `Err`):
  - a `nodeId` that does not parse to exactly 16 bytes / malformed UUID
  - `kind` ∉ {`0x01`,`0x02`,`0x03`}
  - `role` ∉ {`0x01`,`0x02`,`0x03`,`0x04`}
  - `generation` outside `[0, 2^32-1]` (cannot encode as 4-byte BE u32)
  - Rationale: a wrong-length AAD must never be silently produced — that is exactly the silent-failure surface PITFALLS Pitfall 1 warns about.

### UUID → 16-byte parity (D-04)

- **D-04:** Use a canonical, library-backed UUID→bytes path on both sides, cross-checked by the KAT (recommended default). This is the **#1 silent-mismatch landmine** (PITFALLS Pitfall 1: `uuid.as_bytes()` raw 16 bytes vs `uuid.to_string()` UTF-8 are trivially confusable).
  - **Rust:** add the `uuid` crate (workspace dep) and use `Uuid::parse_str(s)?.as_bytes()` → canonical RFC-4122 16-byte field order. (`crates/crypto` has **no** `uuid` dep today; the existing `generate_uuid_v4()` produces a hex *string*, not raw bytes.)
  - **TS:** a canonical parser that converts the hyphenated UUID string → 16 raw bytes (parse hex by RFC-4122 field order — **never** `TextEncoder` the string). (`@cipherbox/crypto` has no UUID→16B helper today.)
  - The KAT's hardcoded `nodeId` (string) → `aad_bytes` (with the embedded raw 16 bytes) is the cross-language proof that both parsers agree.

### Documentation alignment — ADR 0003 + doc pointers (D-05, user-directed scope addition)

- **D-05:** Phase 61 also updates the metadata/encryption docs to align with the seal primitive. Scoped to the crypto/encoding layer only (Node schema → phase 62):
  - **NEW** `docs/adr/0003-aad-bound-node-seal-encoding.md` — the **authoritative freeze**: the byte-encoding table, role-byte table, AEAD parameters (AES-256-GCM, 12-byte IV, 16-byte tag, `[IV][ct+tag]` layout), and the standing rule **"every new `role` byte must extend the KAT."** Status: accepted. Follows the existing `0001`/`0002` ADR frontmatter pattern.
  - `docs/METADATA_SCHEMAS.md` §2 (Encryption Hierarchy) + §3 (Wire Format) — add an AAD-bound seal-primitive subsection that **links** ADR 0003. Do **not** add `Node` schema text.
  - `docs/METADATA_EVOLUTION_PROTOCOL.md` §5 (Version Field Convention) + §6 (Testing Requirements) — record the `"…/v1"` domain-separator version lever (a future encoding change bumps to `node-seal/v2`) and the mandatory cross-language KAT discipline.
  - `docs/FILESYSTEM_SPECIFICATION.md` (Encryption Modes) — one-line note that node metadata bodies use the AAD-bound seal.

### Implementation constraints carried into planning

- **C-01:** KAT is the **merge gate** and the **first deliverable** — committed and green before any other phase begins (PITFALLS Pitfall 1 / checklist line 427).
- **C-02:** Do **not** place `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad` in an `index.ts` barrel — vitest coverage excludes `src/**/index.ts`, which would silently hide the most security-critical code from the 80% gate (PITFALLS line 268). Put them in named files (`src/aes/seal.ts` is fine; the barrel only re-exports).
- **C-03:** Native AAD support exists on both stacks — Web Crypto `AesGcmParams.additionalData` (TS) and `aes-gcm` 0.10 `Payload { aad, msg }` (Rust). No new crypto dependency beyond the Rust `uuid` crate.
- **C-04:** The cross-language test currently runs on **Linux CI only** (`cargo test -p cipherbox-crypto --test cross_language`). `cipherbox-crypto` has no feature gates and builds on all platforms — no macOS/winfsp build risk for this phase.

### Claude's Discretion

- Exact KAT input values (the chosen `nodeId`/`key`/`iv`/`plaintext` for the fixtures), the JSON file name(s) under `tests/vectors/crypto/` (e.g. `node-aad.json`), whether vectors are generated by extending `scripts/generate-test-vectors.ts` or hand-frozen (either is fine provided the committed bytes are asserted on **both** sides), error type names, and helper factoring are left to research/planning.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Frozen encoding — source of truth (read first)

- `.planning/research/ARCHITECTURE.md` §2.5 (envelope, lines 100-130), §4.3 "AAD Byte Encoding — Cross-Language Parity Surface" (lines 133-150, esp. line 114 — the frozen encoding), §6.1 "TS↔Rust Parity Surface" (lines 290-301) — the authoritative frozen byte encoding.
- `.planning/research/PITFALLS.md` Pitfall 1 "AAD Byte-Encoding Drift … = Silent Total Decryption Failure" (lines 11-26), coverage-barrel pitfall (line 268), checklist (lines 427, 450).

### Docs to update this phase (D-05)

- `docs/adr/0003-aad-bound-node-seal-encoding.md` — **NEW**, the freeze artifact.
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md`, `docs/adr/0002-read-revocation-protects-future-content-only.md` — ADR frontmatter/format pattern to follow.
- `docs/METADATA_SCHEMAS.md` §1 Overview, §2 Encryption Hierarchy, §3 Wire Format — add seal-primitive subsection (no Node schema).
- `docs/METADATA_EVOLUTION_PROTOCOL.md` §4.3/§4.4 (Rust impl + cross-platform verification), §5 Version Convention, §6 Testing — add `/v1` lever + KAT discipline.
- `docs/FILESYSTEM_SPECIFICATION.md` Encryption Modes / Metadata Storage — one-line note.

### Implementation sites — TypeScript (`@cipherbox/crypto`)

- `packages/crypto/src/aes/seal.ts` — existing `sealAesGcm`/`unsealAesGcm`; add the AAD variants + `buildNodeAad` here (named file, not the barrel).
- `packages/crypto/src/aes/encrypt.ts`, `packages/crypto/src/aes/decrypt.ts` — Web Crypto `encryptAesGcm`/`decryptAesGcm`; AAD goes via `AesGcmParams.additionalData`.
- `packages/crypto/src/constants.ts` — `AES_KEY_SIZE`=32, `AES_IV_SIZE`=12, `AES_TAG_SIZE`=16.
- `packages/crypto/src/utils/encoding.ts` — `concatBytes`/`hexToBytes`/`bytesToHex`; add the canonical UUID→16B parser near here.
- `packages/crypto/__tests__/build-node-aad.test.ts` — **NEW**, TS side of the KAT.

### Implementation sites — Rust (`cipherbox-crypto`)

- `crates/crypto/src/aes.rs` — existing `seal_aes_gcm`/`unseal_aes_gcm` (`[IV][ct+tag]`, "matches the TypeScript … exactly"); add `seal_aes_gcm_aad`/`unseal_aes_gcm_aad`/`build_node_aad`.
- `crates/crypto/Cargo.toml` + root `Cargo.toml` — add the `uuid` workspace dependency (D-04).
- `crates/crypto/tests/cross_language.rs` — existing cross-language KAT harness (loads `../../tests/vectors/` via `serde_json`); add the node-AAD `#[test]`.
- `crates/crypto/src/hkdf.rs`, `crates/crypto/src/ipns_name.rs` — domain-separation + TS↔Rust parity precedent (frozen `b"cipherbox-…-v1"` info strings); the pattern the new domain separator follows.

### Cross-language vector infrastructure

- `tests/vectors/crypto/aes-gcm.json` — existing full-seal vector format precedent (`key`/`iv`/`plaintext`/`ciphertext` hex). New AAD vectors slot in alongside (e.g. `tests/vectors/crypto/node-aad.json`).
- `scripts/generate-test-vectors.ts` — generates official vectors from `@cipherbox/crypto`; extend or hand-freeze (Claude's discretion, D-decisions).

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **TS AES-GCM (Web Crypto):** `encryptAesGcm(plaintext, key, iv)` / `decryptAesGcm(ciphertext, key, iv)` and `sealAesGcm`/`unsealAesGcm` in `packages/crypto/src/aes/`. Web Crypto's `AesGcmParams` natively accepts `additionalData` — AAD is a parameter, not a custom construction.
- **Rust AES-GCM:** `encrypt_aes_gcm`/`decrypt_aes_gcm` + `seal_aes_gcm`/`unseal_aes_gcm` in `crates/crypto/src/aes.rs`, backed by `aes-gcm = "0.10"` (`Aes256Gcm`). AAD via `Payload { aad: Some(..), msg: .. }` or the in-place detached API.
- **Encoding utils:** TS `concatBytes`/`hexToBytes`/`bytesToHex` (`src/utils/encoding.ts`); Rust `hex` crate. Both have what `buildNodeAad`/the KAT need.
- **Cross-language KAT harness:** `crates/crypto/tests/cross_language.rs` already loads shared JSON vectors from `tests/vectors/crypto/` and asserts byte parity (used today for `aes-gcm`, `ed25519`, `ecies`, `hkdf`, `ipns-name`). The new KAT is a strict extension of this proven harness.

### Established Patterns

- **Frozen domain separation precedent:** `crates/crypto/src/hkdf.rs` uses frozen `b"cipherbox-…-v1"` info strings + salt `b"CipherBox-v1"`, asserted byte-identical across TS↔Rust via the same KAT harness. The new `"cipherbox/node-seal/v1"` domain separator is the same discipline applied to AAD.
- **Seal blob framing is already cross-language-frozen:** `[IV(12)][ct+tag(16)]`, with Rust commenting "matches the TypeScript `sealAesGcm` output exactly." The AAD variants inherit this framing unchanged.
- **Vitest coverage excludes `index.ts` barrels** — security-critical primitives must live in named files (C-02).

### Integration Points

- **Net-new, zero consumers this phase.** No current AES-GCM call passes AAD (grep for `additionalData`/`aad`/`associated_data` returns nothing in either package). The AAD variants are parallel APIs, not refactors of the existing seal funcs.
- **Gap to close:** neither language has a raw-16-byte UUID helper today (Rust has no `uuid` dep; `generate_uuid_v4()` returns a hex string). This helper is new work and is the parity-critical surface (D-04).

</code_context>

<specifics>
## Specific Ideas

- The user explicitly asked that this phase **also update the docs around metadata and encryption** to align with what's implemented — captured as D-05 (ADR 0003 + scoped doc pointers), with the Node-schema rewrite deliberately deferred to phase 62 to avoid documenting a schema that doesn't exist yet.
- The user took the recommended defaults on all four technical gray areas (KAT rigor, transplant breadth, validation strictness, UUID parity) — recorded as D-01..D-04.

</specifics>

<deferred>
## Deferred Ideas

- **`FolderMetadata`/`FileMetadata`/`FilePointer` → `Node` schema documentation** — belongs to **phase 62** (ROADMAP SC#6 assigns the `METADATA_SCHEMAS.md` schema rewrite there). Phase 61 docs are encryption/encoding-layer only.
- **Consumer rewiring** (FUSE symmetric unwrap, sdk-core sealing, web/desktop) — phases 62–69.

### Reviewed Todos (not folded)

- `2026-06-24-harden-validity-type-and-vector-expiry-lockstep.md` — "keep cross-language vectors in expiry lockstep" (area `tests/vectors`). Reviewed; **not folded** — it concerns IPNS *Validity* vectors, not the crypto-AAD KAT. Noted only as the precedent discipline ("cross-language vectors stay in lockstep") the new node-AAD KAT should respect.
- The remaining 13 `todo.match-phase` hits (scores ≤ 0.6) are generic keyword matches (`phase`/`tests`/`packages`/`crates`) with no genuine scope overlap with the seal primitive — not folded.

</deferred>

---

_Phase: 61-aad-bound-seal-primitive-and-cross-language-kat_
_Context gathered: 2026-06-27_
