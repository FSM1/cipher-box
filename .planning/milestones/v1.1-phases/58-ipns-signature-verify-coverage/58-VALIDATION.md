---
phase: 58
slug: ipns-signature-verify-coverage
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-22
---

# Phase 58 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------- |
| **Framework**          | cargo test (Rust) · vitest (sdk-core/web) · jest (apps/api specs) · SDK E2E (tests/sdk-e2e) |
| **Config file**        | per-crate `Cargo.toml` · `vitest.config.ts` · `jest` config in apps/api                    |
| **Quick run command**  | `cargo test -p cipherbox-core` / `pnpm --filter @cipherbox/sdk-core test`                  |
| **Full suite command** | `cargo test` + apps/api specs + full SDK E2E (local; redis 6380)                            |
| **Estimated runtime**  | ~minutes (full SDK E2E dominates)                                                           |

---

## Sampling Rate

- **After every task commit:** Run the relevant quick command (cargo test for Rust tasks, vitest for TS tasks)
- **After every plan wave:** Run the full suite command
- **Before `/gsd-verify-work`:** Full suite must be green (cargo test + apps/api specs + full SDK E2E)
- **Max feedback latency:** quick unit tests < ~60s

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Threat Ref        | Secure Behavior                                                                        | Test Type   | Automated Command                                       | File Exists | Status   |
| -------- | ---- | ---- | ----------- | ----------------- | -------------------------------------------------------------------------------------- | ----------- | ------------------------------------------------------- | ----------- | -------- |
| 58-01-01 | 01   | 1    | HARD-09     | D-07/D-08         | `decode_ipns_cbor_data` round-trips CBOR built by `build_cbor_data`                   | unit        | `cargo test -p cipherbox-core decode_ipns_cbor`         | ✅          | ✅ green |
| 58-01-02 | 01   | 1    | HARD-09     | D-07/D-08         | `decode_ipns_cbor_data` rejects non-map CBOR                                           | unit        | `cargo test -p cipherbox-core decode_ipns_cbor`         | ✅          | ✅ green |
| 58-01-03 | 01   | 1    | HARD-09     | D-07/D-08         | `decode_ipns_cbor_data` rejects CBOR missing `Value` key                               | unit        | `cargo test -p cipherbox-core decode_ipns_cbor`         | ✅          | ✅ green |
| 58-01-04 | 01   | 1    | HARD-09     | D-07/D-08         | `decode_ipns_cbor_data` rejects CBOR missing `Sequence` key                            | unit        | `cargo test -p cipherbox-core decode_ipns_cbor`         | ✅          | ✅ green |
| 58-01-05 | 01   | 1    | HARD-09     | D-07/D-08         | `decode_ipns_cbor_data` rejects negative sequence values                               | unit        | `cargo test -p cipherbox-core decode_ipns_cbor`         | ✅          | ✅ green |
| 58-01-06 | 01   | 1    | HARD-09     | D-07/D-08         | JS `resolveIpnsRecord` throws on cid binding mismatch (D-08)                          | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-01-07 | 01   | 1    | HARD-09     | D-07/D-08         | JS `resolveIpnsRecord` throws on sequence binding mismatch (D-07)                     | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-01-08 | 01   | 1    | HARD-09     | D-07/D-08         | JS `resolveIpnsRecord` resolves with matching cid and sequence (positive case)         | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-01-09 | 01   | 1    | HARD-09     | D-04              | Legacy record (all sig fields absent) is not subjected to CBOR binding (D-04)         | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-01-10 | 01   | 1    | HARD-09     | D-02              | CBOR binding mismatch is NOT swallowed as 404 — propagates to caller                  | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-02-01 | 02   | 1    | HARD-09     | D-09/D-10         | First publish with embedded sequence > 1 is rejected (wedge-poison prevention)        | unit        | `pnpm --filter @cipherbox/api test ipns.service`        | ✅          | ✅ green |
| 58-02-02 | 02   | 1    | HARD-09     | D-09              | First publish with embedded sequence = 0 is accepted                                  | unit        | `pnpm --filter @cipherbox/api test ipns.service`        | ✅          | ✅ green |
| 58-02-03 | 02   | 1    | HARD-09     | D-09              | First publish with embedded sequence = 1 is accepted                                  | unit        | `pnpm --filter @cipherbox/api test ipns.service`        | ✅          | ✅ green |
| 58-02-04 | 02   | 1    | HARD-09     | D-09              | Idempotent republish (embedded = DB seq) updates `latestCid` but does NOT increment DB sequence | unit | `pnpm --filter @cipherbox/api test ipns.service`   | ✅          | ✅ green |
| 58-02-05 | 02   | 1    | HARD-09     | D-09              | Forward publish (embedded = DB seq + 1) is accepted and increments DB sequence        | unit        | `pnpm --filter @cipherbox/api test ipns.service`        | ✅          | ✅ green |
| 58-02-06 | 02   | 1    | HARD-09     | D-09              | Rollback (embedded < DB seq) is rejected                                               | unit        | `pnpm --filter @cipherbox/api test ipns.service`        | ✅          | ✅ green |
| 58-02-07 | 02   | 1    | HARD-09     | D-09              | Wild jump (embedded > DB seq + 1) is rejected                                         | unit        | `pnpm --filter @cipherbox/api test ipns.service`        | ✅          | ✅ green |
| 58-02-08 | 02   | 1    | HARD-09     | D-09/D-10         | D-09 gate runs even when `expectedSequenceNumber` is undefined (unconditional)         | unit        | `pnpm --filter @cipherbox/api test ipns.service`        | ✅          | ✅ green |
| 58-02-09 | 02   | 1    | HARD-09     | D-09              | CAS 409 conflict check takes precedence over D-09 400 check                            | unit        | `pnpm --filter @cipherbox/api test ipns.service`        | ✅          | ✅ green |
| 58-03-01 | 03   | 2    | HARD-09     | D-13              | `apps/web` resolveIpnsRecord delegates to `@cipherbox/sdk-core` (no local dup)        | integration | `pnpm --filter @cipherbox/web typecheck`                | ✅          | ✅ green |
| 58-04-01 | 04   | 2    | HARD-09     | D-11/D-12         | Shared fixture `tests/vectors/ipns/verify.json` has exactly 7 cases                   | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-04-02 | 04   | 2    | HARD-09     | D-11/D-12         | Rust `ipns_verify_cross_language` — valid vector resolves Ok                           | integration | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | ✅        | ✅ green |
| 58-04-03 | 04   | 2    | HARD-09     | D-11/D-12         | Rust: tampered-sig vector → verify failure                                             | integration | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | ✅        | ✅ green |
| 58-04-04 | 04   | 2    | HARD-09     | D-11/D-12         | Rust: name-mismatch vector → verify failure                                            | integration | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | ✅        | ✅ green |
| 58-04-05 | 04   | 2    | HARD-09     | D-07/D-08/D-11    | Rust: cid-swapped vector → CBOR binding failure                                        | integration | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | ✅        | ✅ green |
| 58-04-06 | 04   | 2    | HARD-09     | D-07/D-11         | Rust: seq-mismatch vector → CBOR binding failure                                       | integration | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | ✅        | ✅ green |
| 58-04-07 | 04   | 2    | HARD-09     | D-05/D-11         | Rust: partial-fields (downgrade) vector → failure                                      | integration | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | ✅        | ✅ green |
| 58-04-08 | 04   | 2    | HARD-09     | D-04/D-11         | Rust: legacy-absent vector → allowed, signatureVerified=false                          | integration | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | ✅        | ✅ green |
| 58-04-09 | 04   | 2    | HARD-09     | D-11/D-12         | JS: tampered-sig vector → throws                                                       | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-04-10 | 04   | 2    | HARD-09     | D-11/D-12         | JS: name-mismatch vector → throws                                                      | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-04-11 | 04   | 2    | HARD-09     | D-07/D-08/D-11    | JS: cid-swapped vector → throws on cid binding mismatch (real data bytes)             | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-04-12 | 04   | 2    | HARD-09     | D-07/D-11         | JS: seq-mismatch vector → throws on sequence binding mismatch (real data bytes)       | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-04-13 | 04   | 2    | HARD-09     | D-05/D-11         | JS: partial-fields (downgrade) vector → throws                                         | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-04-14 | 04   | 2    | HARD-09     | D-04/D-11         | JS: legacy-absent vector → resolves with signatureVerified=false                       | unit        | `pnpm --filter @cipherbox/sdk-core test`                | ✅          | ✅ green |
| 58-E2E   | all  | —    | HARD-09     | D-09/D-10/D-02    | Full SDK E2E 89/89 green — no non-CAS publish path regressed by D-09 gate              | e2e         | `pnpm --filter tests/sdk-e2e test` (local; redis 6380)  | ✅          | ✅ green |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Test Name → File Reference

| Test Name (exact)                                                                        | File                                                              |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `decode_ipns_cbor_data_round_trips_build`                                                | `crates/core/src/ipns.rs`                                         |
| `decode_ipns_cbor_data_round_trips_sequences`                                            | `crates/core/src/ipns.rs`                                         |
| `decode_ipns_cbor_data_rejects_non_map`                                                  | `crates/core/src/ipns.rs`                                         |
| `decode_ipns_cbor_data_rejects_missing_value_key`                                        | `crates/core/src/ipns.rs`                                         |
| `decode_ipns_cbor_data_rejects_missing_sequence_key`                                     | `crates/core/src/ipns.rs`                                         |
| `decode_ipns_cbor_data_rejects_negative_sequence`                                        | `crates/core/src/ipns.rs`                                         |
| `throws on cid binding mismatch (D-08)`                                                  | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `throws on sequence binding mismatch (D-07)`                                             | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `resolves with matching cid and sequence (D-07/D-08 positive)`                           | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `legacy record is NOT subjected to CBOR binding (D-04)`                                  | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `binding mismatch error is NOT swallowed as 404 — propagates`                            | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `rejects first publish with embedded sequence > 1 (wedge-poison prevention)`             | `apps/api/src/ipns/ipns.service.spec.ts`                          |
| `allows first publish with embedded sequence 0n`                                         | `apps/api/src/ipns/ipns.service.spec.ts`                          |
| `allows first publish with embedded sequence 1n`                                         | `apps/api/src/ipns/ipns.service.spec.ts`                          |
| `allows idempotent republish (embedded = DB seq) without incrementing DB sequenceNumber` | `apps/api/src/ipns/ipns.service.spec.ts`                          |
| `rejects rollback (embedded < DB seq)`                                                   | `apps/api/src/ipns/ipns.service.spec.ts`                          |
| `rejects wild jump (embedded > DB seq + 1)`                                              | `apps/api/src/ipns/ipns.service.spec.ts`                          |
| `rejects first publish with embedded=2n even when expectedSequenceNumber is undefined`   | `apps/api/src/ipns/ipns.service.spec.ts`                          |
| `CAS-409 takes precedence over D-09 when expectedSequenceNumber is stale`                | `apps/api/src/ipns/ipns.service.spec.ts`                          |
| `ipns_verify_cross_language` (7 sub-cases via loop)                                      | `crates/fuse/tests/ipns_verify_vectors.rs`                        |
| `fixture has exactly 7 cases`                                                            | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `valid — resolves with signatureVerified=true`                                           | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `tampered-sig — throws on invalid signature`                                             | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `name-mismatch — throws on pubKey-to-name binding failure`                               | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `cid-swapped — throws on cid binding mismatch (real data bytes)`                         | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `seq-mismatch — throws on sequence binding mismatch (real data bytes)`                   | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `partial-fields — throws on incomplete signature data (downgrade vector)`                | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |
| `legacy-absent — resolves with signatureVerified=false (D-04)`                           | `packages/sdk-core/src/__tests__/ipns.test.ts`                    |

---

## Wave 0 Requirements

- [x] Shared cross-language verify vectors fixture (valid / tampered-sig / name-mismatch / cid-swapped / seq-mismatch / partial-fields / legacy-absent) — D-11/D-12 (Plan 58-04) — **exists at `tests/vectors/ipns/verify.json`**
- [x] CBOR-decode probe (Rust `ciborium`; JS `parseCborData` import path) — `decode_ipns_cbor_data` in `crates/core/src/ipns.rs`; `parseCborData` bound in `packages/sdk-core/src/ipns/index.ts`

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |

_All phase behaviors have automated verification._

---

## Validation Sign-Off

- [x] All tasks have automated verify
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all previously missing references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** Nyquist compliant — 0 gaps. All 35 rows map to named, passing tests across cargo test (75 passed incl. decode_ipns_cbor_data suite), cipherbox-fuse integration (87 + ipns_verify_cross_language 7 cases), apps/api jest (913/913 incl. 9 D-09 cases in `upsertFolderIpns D-09 embedded-sequence gate` describe block), sdk-core vitest (243 incl. D-07/D-08 CBOR binding + 7 shared-vector consumer tests), and full SDK E2E (89/89).
