---
phase: 51
slug: crypto-signature-secret-leak-hardening
status: ready
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-19
---

# Phase 51 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                                                   |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Framework**          | Jest (api), Vitest (sdk-core, web — `.test.ts` only), `cargo test` (Rust)                                              |
| **Config file**        | per-package (api jest config, sdk-core/web vitest config, Cargo workspace) — none installed in Wave 0                  |
| **Quick run command**  | `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec && pnpm --filter @cipherbox/sdk-core test -- ipns` |
| **Full suite command** | `pnpm --filter @cipherbox/api test && pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/web test && cargo test -p cipherbox-api-client -p cipherbox-fuse` |
| **Estimated runtime**  | ~30s quick / ~3-5 min full (incl. Rust build)                                                                          |

---

## Sampling Rate

- **After every task commit:** Run quick run command (API ipns spec + sdk-core ipns)
- **After every plan wave:** Run full suite command
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** ~30 seconds (quick)

---

## Per-Task Verification Map

> Planner fills exact task IDs. Behaviors below are derived from RESEARCH.md "Phase Requirements → Test Map".

| Task ID | Plan | Wave | Requirement | Threat Ref       | Secure Behavior                                                       | Test Type   | Automated Command                                                            | File Exists | Status     |
| ------- | ---- | ---- | ----------- | ---------------- | -------------------------------------------------------------------- | ----------- | --------------------------------------------------------------------------- | ----------- | ---------- |
| TBD     | TBD  | 1    | HARD-02     | S1 / T-tampering | S1: 400 on embedded-CID vs metadataCid mismatch                      | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec`  | ✅          | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S1 / T-tampering | S1: 400 on embedded-seq vs expectedSeq mismatch (non-first publish)  | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec`  | ✅ extend   | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S1               | S1: first-publish seq tolerance (0n or 1n accepted), valid passes    | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec`  | ✅ extend   | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S2 / T-tampering | S2: web resolve throws on present-but-invalid signature             | unit        | `pnpm --filter @cipherbox/web test`                                          | ❌ W0       | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S2 / D-03        | S2: web resolve returns signatureVerified=false on absent fields    | unit        | `pnpm --filter @cipherbox/web test`                                          | ❌ W0       | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S2               | S2: sdk-core resolve already throws (regression)                    | unit        | `pnpm --filter @cipherbox/sdk-core test -- ipns`                             | ✅          | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S2 / D-04        | S2: Rust IpnsResolveResponse deserializes sig fields; verify_* cases | unit (Rust) | `cargo test -p cipherbox-api-client`                                         | ❌ W0       | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S3 / Info-Disc   | S3: sdk-core ipns/vault/folder zero key after return                | unit        | `pnpm --filter @cipherbox/sdk-core test -- ipns vault folder`               | ✅ extend   | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S3 / Info-Disc   | S3: Rust BFS queue + get_folder_key are Zeroizing (compile-time)    | compile     | `cargo build -p cipherbox-fuse`                                             | ✅          | ⬜ pending |
| TBD     | TBD  | 1    | HARD-02     | S3 / D-05        | S3: enforcement guard (regression test/lint) asserts caller-owns-key | unit/lint   | `pnpm --filter @cipherbox/sdk-core test` / lint                             | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

> Resolved inline via TDD Task 1 (RED step) in the owning Wave 1 plans — test-first within each plan satisfies the Wave 0 dependency.

- [x] `apps/web/src/services/__tests__/ipns.service.test.ts` — new file covering S2 web fail-closed (present-but-invalid throws; absent fields → signatureVerified=false) — owned by plan 51-02
- [x] `crates/api-client/src/ipns.rs` `#[cfg(test)]` module (or `ipns_tests.rs`) — Rust sig-field deserialization + `verify_ipns_resolve_signature` cases (absent → None, invalid → Some(false), valid → Some(true)) — owned by plan 51-03
- [x] S3 enforcement guard — regression test and/or lint asserting caller-owns-key on the touched sdk-core paths (D-05) — owned by plan 51-04

_Existing `ipns.service.spec.ts` (api) covers S1 after extension. Existing `sdk-core/__tests__/ipns.test.ts` covers sdk-core S2/S3 after extension._

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |
| —        | —           | —          | —                 |

_All phase behaviors have automated verification (unit + compile-time)._

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (web ipns test, Rust verify test, S3 guard)
- [x] No watch-mode flags
- [x] Feedback latency < 30s (quick)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-19
