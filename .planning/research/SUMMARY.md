# Research Summary: v2.0 Metadata and Sharing Refactor

**Synthesized:** 2026-06-27
**Dimensions researched:** Architecture + Pitfalls only (Stack + Features intentionally skipped — design is implementation-ready)
**Confidence:** HIGH — all cited symbols verified against live codebase (zero material drift)

## Executive Summary

CipherBox v2.0 replaces a database-driven per-item key fan-out model (`share_keys` table, `O(items × recipients)` rows) with metadata-driven read key-chaining, and closes two confirmed revocation gaps: lazy/unsound read-revocation and un-rotatable write delegation. Scope is locked to **Tier 1** (unified `Node` schema, read key-chain navigation, resumable read-rotation engine) and **Tier 2** (write-revocation via full Ed25519 rotation — ADR 0001, and the resolve/republish/TEE contract rewrite). **Tier 3** (capability-layer TTL/op-caps) is explicitly out of scope.

The design is implementation-ready — three adversarial reviews, two grilling sessions, and two ratified ADRs; no design decisions remain open except the three §9.2 questions flagged below. Stack and Features research were deliberately skipped because the design already pins them.

The build order is strictly dependency-constrained across 8 layers: crypto primitive → core keystone → sdk-core rotation engine → sdk write/bin/invite → api schema+publish-gate → tee-worker contract → web → fuse/winfsp. The **AAD-bound seal primitive must land first** because a byte-encoding mismatch between TS and Rust is a **silent total decryption failure** — no error, just broken unseals across every node. **`packages/core` is the keystone**: nothing below it typechecks until `Node`/`SealedChildRef`/`PublishedNode` exist and `dist/` is rebuilt.

## The Three Silent-Failure Risks (must be test-gated before their phase closes)

These fail with NO runtime error — the worst class for this refactor:

1. **CRIT-1 — content-key rotation.** Rotating a file node without minting a new `fileKey'` leaves the revoked reader able to decrypt the next content version. Gate: §7.3 test 2.
2. **M1 — generation downgrade defense persistence.** The `{nodeId → highestGeneration}` high-water must be **durable** (IndexedDB/sqlite); stored in memory it evaporates on restart and a colluding relay replays the pre-rotation record. Gate: §7.3 test 5 (must survive restart).
3. **Republisher sequence increment.** The TEE republisher must STOP incrementing `sequenceNumber` (`apps/tee-worker/src/routes/republish.ts:79` `+ 1n` confirmed) — a re-signed stale pre-rotation CID at a forward sequence dominates the rotation publish. Gate: §7.3 test 12.

Plus the top silent-**data-loss** risk:

4. **HIGH-4 — add-during-rotation.** The 409-retry path must re-fetch and re-merge `SealedChildRef`s, not re-seal from stale in-memory `children[]`; otherwise a concurrent upload is silently dropped. Gate: §7.3 test 4.

## Suggested Phase Decomposition (8 phases, dependency-ordered)

1. **Crypto Primitive** — `sealAesGcmAad`/`unsealAesGcmAad` + `buildNodeAad` (TS) + byte-identical Rust twin + committed cross-language KAT (all 4 role bytes; frozen byte encoding). Self-contained, no consumers break. Gate: tests 6 (AAD transplant) + 7 (TS↔Rust KAT).
2. **Core Keystone** — unified `Node`/`SealedChildRef`/`PublishedNode` + codecs (two sealed bodies, content self-seal, structured write chain, `versionFloor`). Gate: all consumers typecheck after `dist/` rebuild. Critical-path bottleneck — nothing below typechecks until this lands.
3. **sdk-core Rotation Engine** — read-chain navigation + `rotateReadFromNode`/`rotateOne`/`verifySubtreeClean` in **named files (not a fat `index.ts` barrel** — coverage excludes barrels). Must include CRIT-1, M1, HIGH-3, HIGH-4 as success criteria. Gate: tests 1–5, 9; SDK E2E pass.
4. **sdk Write/Bin/Invite** — `shared-write.ts` rewrite (structured write-body, (c) full rotation, role `0x04`); delete `addShareKeys`/`reWrapForRecipients`; `bin/*` re-link (delete `originalFolderKeyEncrypted` re-encrypt path); invite claim re-wrap (delete `encryptedChildKeys[]` JSONB fan-out). Gate: tests 10 (bin restore), 11 (invite claim).
5. **API Schema + Publish Gate** — delete `share_keys`; slim `shares` (`readDescriptorRef`/`writeDescriptorRef`); rename `folder_ipns` → `ipns_records`; **drop `folder_ipns.public_key`** (null-row footgun behind two Phase-60 regressions); collapse `ipns_republish_schedule` duplicated columns; **atomic conditional-UPDATE publish CAS**; tombstone state + publish-gate rejection + resolve fail-closed fall-through (case-split: expected-null shared-folder rows apply seq floor, CID-mismatch fails closed); server-side generation gate. Run `pnpm api:generate`, commit regenerated client (`check-api-client.sh` pre-commit gate). Gate: tests 13, 15, 16, 20.
6. **TEE Worker Contract** — lease-renewer rewrite: receive marshaled record, verify signature, extend EOL only, **no CID origination, no sequence increment**; internal epoch derivation; name↔key binding; migration durability. Round-trip the TEE/republish E2E. Gate: tests 12, 17, 18, 19.
7. **Web** — replace `executeLazyRotation` with `rotateReadFromNode`; drop per-mutation fan-out; reconcile `folderTree` against `sequenceNumber` before publishes; durable IndexedDB generation + seq high-water. Note: web vitest only runs `*.test.ts` (not `.spec.ts`). Gate: test 5 (durable survives restart), test 13.
8. **FUSE + WinFsp** — symmetric child-key unwrap; delete `spawn_file_meta_reencrypt` from **both callers** (`write_ops/.../rename.rs` AND `platform/windows/write_ops.rs`); add `rotateReadFromNode`; unify scope-exit; **grant-root awareness** in `delete`/`rename`/`move` (net-new); durable client floors; strict-verify each republish (recover Ed25519 pubkey from k51 name via `publicKeyFromIpnsName`, never the dropped column); `Node` as a real Rust enum. Budget a Windows CI round-trip (winfsp can't compile on macOS; watch the `super::` vs `super::super::` nesting trap). Gate: test 21 (`Cargo Check & Test (Windows)` authoritative); desktop E2E is dispatch-gated — trigger explicitly.

## Test Strategy Thread (§7.3 — must-pass-before-merge)

The design's 21-item test list maps onto the phases above. The crash-safety/resume suite (test 1) and the three silent-revocation-bypass tests (2, 5, 12) plus the silent-data-loss test (4) are the non-negotiable merge gates. `tests/sdk-e2e` is the only real client→API IPNS publish/resolve round-trip — extend it with abort-and-resume cases. Keep checker subagents to static analysis only (no concurrent vitest — RAM starvation).

## Drift Report (design citations vs live code)

- `decryptFileMetadata` is ~line 231 in `packages/core/src/file/metadata.ts` (design cites 232) — immaterial.
- All other 17 cited symbols verified present: TEE `+ 1n` (`republish.ts:79`), `unenrollIpns` schedule-only delete (`republish.service.ts:257`), `folder_ipns.public_key` nullable (`Buffer | null`, entity ~line 63), `encryptedChildKeys` JSONB on `share_invites`, `originalFolderKeyEncrypted` re-encrypt path (`packages/sdk/src/bin/index.ts:688`), `parseCachedRecord`-null fall-through (`ipns.service.ts:504`, case-dependent two-branch fix).

## Sub-phase Research Flags

- **Phase 5 (API):** TypeORM FK constraint map for the `folder_ipns` → `ipns_records` rename — the FK references must be inspected (against staging DB schema) before writing the migration; all referencing tables migrate atomically.
- **Phase 8 (FUSE):** grant-root scope computation algorithm is net-new and under-specified in the design — needs a plan-time design pass.
- Skip research: Phase 1 (additive AES primitive), Phase 2 (schema fully specified), Phase 6 (surgical TEE rewrite, fully specified in design §6.2–6.7).

## Open Questions for Owning Phases (design §9.2)

- **Q1 — Co-writer offline handling** under (c): a co-writer offline during write-key rotation can't write until re-fetch. Accept as explicit, or add grace/notification? → owning phase: Web (Phase 7).
- **Q2 — Rotation host for pure-web users:** eager million-node rotation is owner-online and resumable; desktop (FUSE) is the natural host. Is a long, chunked, multi-session web rotation acceptable for a large revoke? → document in sdk-core (Phase 3).
- **Q3 — Write-recipient-vs-owner sub-share authority:** when a write-recipient deletes/moves a node the owner independently sub-shared, the unlink and the revocation split across two principals. Decide the authority model + acceptable exposure window. → owning phases: Web (Phase 7) + FUSE delete path (Phase 8).

## Watch Out For (top execution traps from project history)

- AAD byte-encoding drift TS↔Rust = silent total decryption failure → KAT is Phase 1's merge gate.
- `folder_ipns.public_key` null-row footgun → drop the column; recover pubkey from k51 name.
- folderTree/Zustand vs SDK desync ("Folder not loaded" class) → reconcile before rotation publishes.
- Zeroization of caller-owned/reused buffers breaks SDK E2E → zero only at terminal owner.
- winfsp can't compile on macOS; desktop E2E is dispatch-gated → explicit CI round-trips as phase completion criteria, not post-merge.
