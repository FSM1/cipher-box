# Phase 62: Unified Node Codec (Core Keystone) - Context

**Gathered:** 2026-06-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 62 delivers the unified **`Node` / `SealedChildRef` / `PublishedNode`** types and their **codecs** in `packages/core`, replacing all legacy metadata types (`FolderMetadata` / `FileMetadata` / `FilePointer` / `FolderEntry`) and redesigning the vault recovery blob to carry two keys. It is the **keystone** of the v2.0 milestone: nothing downstream typechecks until it lands.

This phase **fully owns and tests the codec** (encode/decode/seal/unseal of all three node kinds, the published envelope, and the v3 vault blob) and brings the rest of the monorepo to **compile** against the new types. It does **not** implement the read-chain navigation, rotation, write-chain, or share fan-out behavior — those are deliberately deferred to their owning phases (63–69).

**In scope:**

- `Node` (discriminated by `kind`: folder/file/root) with two independently sealed bodies — `readSealed` under `readKey`, `writeSealed` under `writeKey` — and the plaintext `PublishedNode` envelope exposing `generation` as the AAD epoch / anti-rollback witness.
- File node `content` self-seals under the file's **own** `readKey` (including `content.fileKey` and each `VersionEntry`'s inline `fileKey` + mandatory `encryptionMode`).
- `SealedChildRef` read-only chain link (`name`, `ipnsName`, `generation` mirror, `versionFloor`, `readKeySealed` only).
- Structured recursive write-body / write-chain types (write link in parent write-body, role `0x04`).
- Vault recovery blob redesign → two ECIES keys (`ECIES(rootReadKey)` + `ECIES(rootWriteKey)`); `encryptedRootFolderKey` removed.
- Frozen Node wire-format golden vectors (body bytes + full envelope + vault v3 blob).
- `METADATA_SCHEMAS.md` rewrite for the static node/v3 schema + the two named invariants (SC#6), plus the FILESYSTEM_SPEC / METADATA_EVOLUTION_PROTOCOL pointers Phase 61 left.
- Monorepo (`packages/sdk-core`, `packages/sdk`, `apps/web`) typechecks cleanly after `packages/core` `dist/` rebuild — zero references to retired types.

**Out of scope (hard boundary):**

- Behavioral rewiring of consumers — read-chain navigation, `rotateReadFromNode`, write-revocation, share fan-out removal, bin re-link, invite claim → **phases 63–69** (any path needing this is stubbed, see D-01).
- The Rust `Node` enum and FUSE/WinFsp symmetric unwrap → **phase 69** (this phase is the TS codec only).
- The seal primitive and frozen AAD encoding → **already shipped in phase 61** (carried forward, not re-litigated).
- API schema cutover (`share_keys` delete, `folder_ipns` → `ipns_records`, publish CAS, tombstone) → **phase 66**.

</domain>

<decisions>
## Implementation Decisions

### Phase boundary — codec full, consumers stubbed (D-01, D-02)

- **D-01:** Phase 62 **fully implements and unit-tests the core codec**; consumers (`sdk-core`/`sdk`/`web`) are brought to **compile only**. Trivial renames are ported, but any consumer path requiring real new logic (navigation walk, rotation, write-chain sealing, share fan-out) gets an explicit `throw new Error('not implemented — phase NN')` naming the owning phase. The app is **intentionally non-runnable mid-milestone** — acceptable under greenfield (no prod instance, staging wiped). This keeps the keystone bounded and pulls **zero** phase-63–69 behavior forward.
- **D-02 (CI gate):** Phase 62's gate = **monorepo typechecks + lint + the NEW core codec unit/golden tests pass**. Broken consumer suites that exercise retired/stubbed behavior are **quarantined** with `describe.skip` + a `// TODO(phase NN)` pointer (NOT deleted — they are the spec the owning phase revives). The vitest **coverage floor is relaxed/exempted** on packages whose behavior is stubbed, and restored when the phase that fills the stub lands.

### Sealed-body wire format (D-03) — not discussed, defaulted

- **D-03:** The plaintext inside `readSealed` / `writeSealed` (and `content`) is **JSON** — `JSON.stringify` → `TextEncoder`, matching today's `encryptFolderMetadata` codec (`packages/core/src/folder/metadata.ts`). Rationale: the AAD already provides integrity/binding; JSON is serde-friendly for the Phase-69 Rust twin; deterministic re-serialization is not required (a fresh random IV is minted per seal, and decryption is decrypt-then-`JSON.parse`, not byte-compare). CBOR/canonical-JSON rejected as unneeded complexity.

### Node golden-vector freeze (D-04)

- **D-04:** **Freeze the Node wire format in THIS phase** (freeze-first discipline — Phase 62 is the first Node-sealing consumer). Commit a frozen fixture under `tests/vectors/` covering **all three kinds** (folder; file with `content` + at least one `VersionEntry`, exercising both `GCM` and `CTR` `encryptionMode`; root):
  - **Primary lock:** decoded-`Node` → plaintext **body bytes** (IV-independent — the true wire-format freeze).
  - **Full-seal lock:** a fixed-key / fixed-IV **full-envelope** vector (decoded `Node` → exact `PublishedNode` with deterministic `readSealed`/`writeSealed`), mirroring Phase 61 D-01b, proving AAD flows into the AEAD identically.
  - Include the **vault v3 blob** (D-05) in the same fixture set.
  - **TS-asserts now**; structured so the Phase-69 Rust `#[test]` slots in against the **same bytes** (Phase 61 KAT pattern). Keep cross-language vectors in lockstep discipline.

### Vault recovery blob v3 — two keys, hard-cut (D-05)

- **D-05:** New binary envelope:

  ```text
  0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)
  ```

  (symmetric, length-prefixed; mirrors the v2 `0x02 | u16(keyLen) | ecies(key)` style; each ECIES output ≈ 129 bytes.) **Greenfield hard-cut:** DELETE `detectBlobVersion` / `serializeVaultBlobV2` / `deserializeVaultBlobV2` / `BLOB_V2_VERSION` and the v1 JSON path; ship **v3-only** serialize/deserialize. The `encryptedRootFolderKey` field is removed from vault types (NODE-06). Refresh `vault-blob-vectors.test.ts` to the v3 two-key layout (folds into the D-04 golden fixture set). `vault/init.ts` recovery path adapts to wrap/unwrap two keys.

### packages/core module layout (D-06)

- **D-06:** New `src/node/` directory with codecs in **named files** (coverage excludes `index.ts` barrels — Phase 61 C-02):
  - `node/types.ts` — `Node`, `SealedChildRef`, `PublishedNode`, `content` / `VersionEntry` / write-body types.
  - `node/encode.ts` — `Node` → plaintext body bytes (read-body, write-body).
  - `node/decode.ts` — bytes → `Node` + runtime validation.
  - `node/seal.ts` — encode + `sealAesGcmAad` → `PublishedNode`; unseal + decode.
  - `node/index.ts` — re-export only.
  - **Retire `folder/` + `file/` entirely.** Adapt the legacy-type references in `registry/` (`registry/schema.ts`) and `bin/types.ts` so they compile against `Node`/`SealedChildRef` (behavior stubbed per D-01). Keep `ipns/` unchanged this phase; `vault/` keeps the v3 blob (D-05).

### METADATA_SCHEMAS.md rewrite scope (D-07)

- **D-07:** Document the **full static node/v3 schema** (`Node` / `SealedChildRef` / `PublishedNode` / `content` / write-body / vault-v3-blob) plus the **two SC#6-required invariants**:
  1. `generation`-as-convergence-witness (per-node authoritative only on the child's own envelope; every other appearance — `SealedChildRef.generation` mirror, `shares.rootGeneration` — is a staleness witness, never independent).
  2. `fileKey`-inside-sealed-read-body as a **semantic type change** (ECIES hex string → raw 32-byte key inside the sealed body), applied to `content` and every `VersionEntry`.
  - **DEFER** flow docs (navigation walk, rotation, write-revocation) to their owning phases 63–69 — documenting behavior that doesn't exist yet risks drift.
  - Update the FILESYSTEM_SPECIFICATION.md + METADATA_EVOLUTION_PROTOCOL.md pointers Phase 61 left (it added the seal-primitive subsection; this phase adds the Node schema it pointed forward to).

### Numeric types (D-08)

- **D-08:** `generation` is a **`number`** (u32-safe, < 2^53; matches Phase 61's `[0, 2^32-1]` AAD validation and the plaintext-JSON envelope). `versionFloor` and the seq high-water are **`bigint`**, matching the existing IPNS `sequenceNumber` bigint convention. The codec validates the `generation` range on encode/decode (fail-closed, mirroring Phase 61 D-03).

### Codec API & key-material zeroization (D-09) — not discussed, defaulted

- **D-09:** `decode`/`unseal` return raw key material (`readKey`, `writeKey`, `content.fileKey`, the Ed25519 write seed) as `Uint8Array` that the **caller owns and must zero** (terminal-owner principle). The codec **never** zeros a caller-supplied or returned buffer it does not exclusively own, and retains no references to key material after returning. This sets the ownership contract every later phase consumes; flagged for the security-reviewer in the phases that wire real behavior. See the zeroization landmine carried forward in `<code_context>`.

### Claude's Discretion

- Exact golden-vector input values (chosen `nodeId`/keys/IV/plaintext), fixture JSON file name(s) under `tests/vectors/`, and whether vectors are generated by extending `scripts/generate-test-vectors.ts` or hand-frozen (either is fine provided the committed bytes are asserted).
- Error type names and codec helper factoring.
- How stub call sites are typed to satisfy the compiler (e.g. `throw` after a typed cast, `never`-returning helper) — provided the stub is explicit and names the owning phase.
- Exact `encryptionMode` representation as a string-literal union (`'GCM' | 'CTR'`) per the project TS convention (string literals over enums) — locked in spirit, mechanics at discretion.
- The precise `registry/` and `bin/types.ts` adaptation needed to compile.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Design source of truth (read first)

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — the single source of truth for the whole v2.0 milestone. **§2 (the reorganized metadata schema)** is the Phase-62 spec: §2.1 unified Node + Rust-enum boundary, §2.2 two sealed bodies, §2.3 Node schema (decrypted), §2.4 published envelope, §2.5 AAD primitive (frozen), §2.6 `SealedChildRef`, §2.7 `generation` single-source-of-truth, §2.8 grant row, §2.9 content self-seal. Also **§7.1 blast radius** (core = highest/keystone), **§7.2 cutover order** (step 2 = `packages/core`), **§7.3 test strategy** (tests 6, 7, 8 touch the codec/AAD).
- `.planning/design/2026-06-26-sharing-flows-walkthrough.md` — FS-permutation walkthrough behind the open questions (context only; flows are phases 63–69).

### ADRs (authoritative freezes)

- `docs/adr/0003-aad-bound-node-seal-encoding.md` — the frozen seal/AAD byte encoding (Phase 61). The standing rule: every new `role` byte must extend the KAT.
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — the honest threat-model stance the schema's `generation`/`fileKey` semantics serve.
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — why the write-body is a structured recursive chain (role `0x04`).

### Requirements & roadmap

- `.planning/REQUIREMENTS.md` — **NODE-01 … NODE-06** (the phase's requirements) + the `## Out of Scope` table (no migration / no dual-codec).
- `.planning/ROADMAP.md` — Phase 62 goal + 6 success criteria; the v2.0 phase sequence (62 keystone → 63–69 consumers).
- `.planning/phases/61-aad-bound-seal-primitive-and-cross-language-kat/61-CONTEXT.md` — carried-forward seal/AAD decisions (D-00a/b layout, KAT discipline, coverage-barrel C-02, UUID→16B parity D-04).

### Docs to rewrite/update this phase (D-07)

- `docs/METADATA_SCHEMAS.md` — rewrite for the static node/v3 schema + the two invariants (Phase 61 added the seal-primitive subsection here pointing forward to this).
- `docs/METADATA_EVOLUTION_PROTOCOL.md` — extend with the node/v3 schema-version lever + cross-language vector discipline for Node.
- `docs/FILESYSTEM_SPECIFICATION.md` — expand the one-line node-metadata note into the node/v3 storage description.
- Root `CONTEXT.md` glossary — the pinned terminology (`readKey`/`writeKey`, the three counters `generation`/`keyEpoch`/`sequenceNumber`, descriptor refs). Do not redefine terms; cite it.

### Frozen-encoding / pitfalls (parity surface)

- `.planning/research/ARCHITECTURE.md` §2.5 (envelope) + §4.3 (AAD byte encoding) + §6.1 (TS↔Rust parity surface).
- `.planning/research/PITFALLS.md` — Pitfall 1 (AAD byte-encoding drift = silent total decryption failure) + the coverage-barrel pitfall.

### Implementation sites — TypeScript

- `packages/core/src/node/` — **NEW** (D-06); the Node types + codecs in named files.
- `packages/core/src/folder/` + `packages/core/src/file/` — **RETIRE** (legacy `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry`/codecs); `folder/metadata.ts` is the JSON-codec pattern to mirror (D-03).
- `packages/core/src/vault/blob.ts` + `vault/types.ts` + `vault/init.ts` — v3 two-key blob (D-05); remove `encryptedRootFolderKey`.
- `packages/core/src/registry/schema.ts`, `packages/core/src/bin/types.ts` — adapt legacy-type refs to compile (D-06).
- `packages/core/src/index.ts` — barrel export surface (re-export `node/`, drop `folder/`+`file/`).
- `packages/crypto/src/aes/seal.ts` — Phase 61 `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad` (the seal primitive this codec calls; do NOT reimplement).
- `tests/vectors/crypto/node-aad.json` (Phase 61) — precedent; new Node golden vectors slot alongside under `tests/vectors/`.
- `packages/core/src/__tests__/vault-blob-vectors.test.ts` — refresh to v3 (D-05).
- `scripts/generate-test-vectors.ts` — extend or hand-freeze the Node vectors (discretion).

### Implementation sites — Rust (Phase 69 consumers of this phase's frozen format — do NOT implement now)

- `crates/crypto/tests/cross_language.rs` — where the Phase-69 Rust Node `#[test]` will assert the same golden bytes frozen here.
- `crates/core/src/` — future `enum Node { Folder { children }, File { content }, Root { children } }` (Phase 69, NODE-05).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **Seal primitive (Phase 61):** `sealAesGcmAad(plaintext, key, aad)` / `unsealAesGcmAad(sealed, key, aad)` / `buildNodeAad(nodeId, kind, generation, role)` in `@cipherbox/crypto` — the codec composes these, never reimplements them. Roles `0x01 body / 0x02 child-readkey / 0x03 content / 0x04 child-writekey` are reserved and KAT-frozen.
- **JSON codec pattern:** `encryptFolderMetadata` (`packages/core/src/folder/metadata.ts`) — `JSON.stringify` → `TextEncoder` → AES-GCM, with chunked base64 for large blobs (MEDIUM-08). The node codec mirrors this (D-03), swapping `encryptAesGcm` for the AAD-bound seal.
- **Vault blob v2 envelope:** `serializeVaultBlobV2`/`deserializeVaultBlobV2` (`packages/core/src/vault/blob.ts`) — the `0x02 | u16_BE(len) | bytes` pattern the v3 two-key layout extends (D-05); pure byte manipulation, zero deps, Rust-portable.
- **Cross-language vector harness:** `crates/crypto/tests/cross_language.rs` loads shared JSON from `tests/vectors/` and asserts byte parity — the Phase-69 Rust Node test extends this against the vectors frozen here.

### Established Patterns

- **Vitest coverage excludes `src/**/index.ts` barrels** — security/codec-critical code must live in named files (Phase 61 C-02); drives the `src/node/` layout (D-06).
- **Greenfield delete-outright** — no production data, staging wiped; `node/v3` is the sole codec, no dual-codec/`version`-discriminator bridge (design §1.6). Justifies the v3 hard-cut (D-05) and retiring `folder/`+`file/`.
- **String literals over TS enums** (project convention) — `encryptionMode: 'GCM' | 'CTR'`.
- **IPNS `sequenceNumber` is `bigint`** across the codebase — `versionFloor`/seq high-water follow it (D-08).
- **Zeroization — terminal-owner only** ([[project-zeroization-callee-must-not-zero-reused-buffer]]): a callee must NOT zero a caller-owned/reused buffer; zero only at the terminal owner (`client.destroy`/`clearBytes`/fresh-keypair funcs). Drives the codec ownership contract (D-09).

### Integration Points

- **Keystone fan-out:** consumers currently importing the retired types — `packages/core/src/index.ts`, `packages/sdk-core/src/{index,file/index,folder/index,folder/metadata-ops,folder/load,folder/registration}.ts`, `packages/sdk/src/...`, `apps/web/...`. Each must compile against `Node`/`SealedChildRef`; real behavior is stubbed (D-01). Nothing below `packages/core` typechecks until the codec lands.
- **`packages/core` `dist/` rebuild is required** before consumer typecheck — sdk/web check the built dist, not source ([[project-cross-package-dist-staleness]]). Build core dist before judging the SC#5 typecheck.

</code_context>

<specifics>
## Specific Ideas

- The user took the **recommended default on every decision** (terse/decisive) — D-01..D-08 are all the recommended options; D-03 (JSON wire format) and D-09 (zeroization contract) were not selected for discussion and defaulted.
- Strong intent: **keep the keystone bounded** — the app being non-runnable between phases 62 and ~68 is explicitly acceptable; do not pull phase-63–69 behavior forward to keep things runnable.
- **Freeze-first discipline** (carried from Phase 61): the Node wire format must be committed + vector-green before later phases seal Nodes against it — a retroactive encoding change would require re-sealing every body.

</specifics>

<deferred>
## Deferred Ideas

- **Consumer behavioral rewiring** — read-chain navigation + `rotateReadFromNode` (63), rotation soundness (64), write-chain/bin re-link/invite claim (65), API schema cutover (66), TEE lease-renewer (67), web rotation UX + durable client state (68), FUSE/WinFsp symmetric unwrap + Rust `Node` enum (69). Phase 62 stubs these (D-01).
- **Rust `Node` enum** (NODE-05) and the cross-language Node `#[test]` — Phase 69; this phase only freezes the bytes the Rust side will later assert.
- **Flow documentation** (navigation/rotation/write-revocation) in `METADATA_SCHEMAS.md` — deferred to owning phases (D-07).
- **Open questions Q1/Q2/Q3** (co-writer offline, rotation host, write-recipient deletions vs owner sub-shares) — not Phase-62 questions; assigned to phases 68 / 63 / 65–69 respectively (design §9.2, ROADMAP).

### Reviewed Todos (not folded)

- `2026-06-24-harden-validity-type-and-vector-expiry-lockstep.md` — "keep cross-language vectors in expiry lockstep" (area `tests/vectors`). Reviewed; **not folded** — it concerns IPNS *Validity* vectors (phases 66/67), not the Node codec. Noted only as the precedent discipline the new Node golden vectors should respect (D-04).
- `2026-06-24-ts-resolve-strict-rfc3339-validity-parity.md`, `2026-06-28-harden-uuid-acceptance-parity-aad-builder.md`, `2026-06-28-zeroize-local-key-plaintext-copies-in-aes-helpers.md`, `2026-06-20-e2e-helper-scripts-zeroize-userprivatekey.md` — Reviewed; **not folded** — crypto/IPNS-layer follow-ups to phases 61/66/67, not the `packages/core` Node codec. The zeroization todos inform the D-09 ownership contract but are their own work.
- The remaining ~15 `todo.match-phase` hits (scores ≤ 0.6) are generic keyword matches (`phase`/`packages`/`sdk`/`web`/`apps`) with no genuine Node-codec scope overlap — not folded.

</deferred>

---

*Phase: 62-unified-node-codec-core-keystone*
*Context gathered: 2026-06-28*
