---
phase: 77
slug: crypto-hygiene-and-terminology-canonicalization
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-11
---

# Phase 77 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| caller → AES helper | caller passes a raw symmetric key it still owns; `importAesKey` borrows, copies internally, and never mutates the caller's buffer | 32-byte AES key (highly sensitive) |
| caller → `wrapIpnsKeyForTee` | caller supplies the raw `ipnsPrivateKey` (borrowed) and the TEE public key; helper reads only, does not zero the argument | IPNS Ed25519 private key (highly sensitive) |
| API relay → tee-worker | private HTTP contract carrying the ECIES-wrapped IPNS private key for republish (not exposed via OpenAPI) | `encryptedIpnsPrivateKey` (ciphertext) |
| authenticated caller → shares/invite API | caller asserts a `shareRootIpnsName`; server verifies caller registered that node before issuing a share/invite | ownership claim (auth-relevant) |
| in-process base64 codec | encode/decode of already-in-memory sealed-node / grant / rotation bytes; no untrusted external input crosses here | binary node/grant payloads |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-77-01a | Tampering | hoisted base64 codec diverging from copied impls | high | mitigate | Verbatim copy of encode loop; `encoding.test.ts` golden vectors + `node-codec-vectors.test.ts` parity gate — 35/35 pass, byte-identical | closed |
| T-77-01b | Tampering | supply-chain (package install) | n/a | accept | No package installs occur in this phase | closed |
| T-77-02a | Information Disclosure | un-zeroed local AES key copy in heap after importKey | medium | mitigate | `importAesKey` zeroes its owned `keyView` in a `finally` block after `importKey` consumes it | closed |
| T-77-02b | Tampering | accidental zeroization of caller-owned key (D-09, prior 48/89 regression class) | high | mitigate | Helper `.fill(0)`s only the local copy; caller-key-unchanged unit assertion; verified by direct read of `import-key.ts` | closed |
| T-77-02c | Tampering | refactor silently alters AES encrypt/decrypt output | high | mitigate | `aes.test.ts` + `aes-ctr.test.ts` round-trip suites re-run green (207/207) | closed |
| T-77-03a | Tampering | TEE field-name skew (rename lands one side only) leaving wrapped key undecryptable | high | mitigate | Atomic rename across relay + worker; `grep encryptedIpnsKey\b` → 0 stale refs; republish specs green | closed |
| T-77-03b | Information Disclosure | stale negative assertion silently stops proving schedule row omits the wrapped key | medium | mitigate | Negative assertions updated to canonical property name (Plan 77-03 Task 2) | closed |
| T-77-03c | Tampering | supply-chain (package install) | n/a | accept | No package installs in this phase | closed |
| T-77-04a | Elevation of Privilege / Spoofing | confused-deputy share/invite for a node the caller does not own | high | mitigate | `assertRootOwnership` preserves the exact same-repo ownership query + `ForbiddenException`; defense-in-depth atop the cryptographic boundary; both callers verified | closed |
| T-77-04b | Tampering | extraction changes the query predicate or drops the throw | high | mitigate | Single throw site confirmed; shares/invite specs re-run green (57/57); behavior-preserving `findOne({ ipnsName, userId })` | closed |
| T-77-04c | Tampering | supply-chain (package install) | n/a | accept | No package installs in this phase | closed |
| T-77-05a | Tampering | hex/bytes boundary confusion lets malformed TEE pubkey reach `wrapKey` | medium | mitigate | `hexToBytes` throws on odd-length/non-hex; hex-decode kept at call site before `wrapKey` (fail-fast preserved) | closed |
| T-77-05b | Tampering | signature change without updating all 3 callers | high | mitigate | Signature + 3 callers land atomically; sdk-core typecheck + suite + round-trip unwrap-parity test green | closed |
| T-77-05c | Information Disclosure | mistakenly zeroing the borrowed `ipnsPrivateKey` in the helper (D-09) | high | mitigate | Helper only reads the borrowed key; verified no `.fill(0)` touches the argument in `wrap.ts` | closed |
| T-77-05d | Tampering | supply-chain (package install) | n/a | accept | No package installs in this phase | closed |
| T-77-06a | Tampering | removing a required type field breaks tsc across sdk → web before sites update | high | mitigate | Field + all construction sites removed in one task; sdk dist rebuilt before web typecheck; both green | closed |
| T-77-06b | Tampering | deleting a callback with a live caller silently drops behavior | medium | mitigate | grep-confirmed zero live callers before deletion of `ShareCallbacks`/`addShareKeysFn`/`updateSharePermission` | closed |
| T-77-06c | Information Disclosure | a `.not.toHaveBeenCalled()` invariant becomes a false pass after field removal | low | mitigate | Now-meaningless assertions deleted (not renamed) | closed |
| T-77-06d | Tampering | supply-chain (package install) | n/a | accept | No package installs in this phase | closed |
| T-77-07a | Tampering | consolidating onto shared codec changes sealed-node byte output | high | mitigate | Shared codec is a verbatim copy; `node-codec-vectors.test.ts` FULL-SEAL golden vectors re-run green | closed |
| T-77-07b | Tampering | dropping `decode.ts` `expectedLength` assertion weakens malformed-input validation | medium | mitigate | Length-check kept as a thin local wrapper over the shared bytes-only helper | closed |
| T-77-07c | Tampering | supply-chain (package install) | n/a | accept | No package installs in this phase | closed |
| T-77-08a | Tampering | swapping local codec for shared one changes grant/rotation bytes | high | mitigate | Byte-identical shared codec; rotation/share round-trip tests re-run green | closed |
| T-77-08b | Tampering | supply-chain (package install) | n/a | accept | No package installs in this phase | closed |
| T-77-09a | Tampering | string-keyed fixtures/`toHaveProperty` stop testing after the field rename (false pass) | medium | mitigate | Loose mocks + cross-name assertion updated; scoped negative grep confirms no stray old token | closed |
| T-77-09b | Tampering | base64 dedup changes file-node byte output | high | mitigate | `file-node.test.ts` round-trip parity gate green | closed |
| T-77-09c | Tampering | stale sdk-core dist makes the sdk run a false pass/fail | medium | mitigate | sdk-core dist rebuilt before sdk tests (Pitfall 5) | closed |
| T-77-09d | Tampering | supply-chain (package install) | n/a | accept | No package installs in this phase | closed |
| T-77-10a | Information Disclosure | minted subfolder keys leak on a seal/upload/publish throw (never zeroed) | medium | mitigate | `createSubfolder` steps 4-8 wrapped in try/catch, three minted keys `.fill(0)`'d on error path; forced-throw test proves it | closed |
| T-77-10b | Tampering | mistakenly zeroing the success-path return (D-09, prior 48/89 regression class) | high | mitigate | Error-path-only zeroization; success-path "does NOT zero" test stays green; D-09 comment retained | closed |
| T-77-10c | Information Disclosure | `verify-filepointer.mts` leaves `userPrivateKey`/read keys in memory until exit | low | mitigate | `clearBytes` added in a `finally` block mirroring sibling scripts | closed |
| T-77-10d | Tampering | supply-chain (package install) | n/a | accept | No package installs in this phase | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above workflow.security_block_on (high) count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-77-supply | T-77-{01b,03c,04c,05d,06d,07c,08b,09d,10d} | This phase is refactor/dedup/rename hygiene — no npm/pip/cargo install occurs, so the supply-chain vector is not applicable (RESEARCH Package Legitimacy Audit) | ship-phase audit | 2026-07-11 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-11 | 30 | 30 | 0 | ship-phase (L1 short-circuit + orchestrator spot-checks + parallel crypto-privacy review) |

L1 short-circuit applied (`threats_open: 0`, register authored at plan time, ASVS L1). All 30 register entries carried planned mitigations, each independently confirmed by `77-VERIFICATION.md` direct test runs and re-spot-checked by the orchestrator: `importAesKey` zeroes only its local `keyView` (D-09 clean); `wrapIpnsKeyForTee` borrows and never mutates `ipnsPrivateKey`; `grep encryptedIpnsKey\b` → 0 stale refs; `assertRootOwnership` is behavior-preserving with a single throw site and two verified callers. A dedicated `crypto-privacy-reviewer` and general-security sweep ran in parallel over the phase diff as deeper L2/L3 coverage.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-11
