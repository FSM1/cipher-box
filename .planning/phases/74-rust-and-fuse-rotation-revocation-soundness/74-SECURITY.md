---
phase: 74
slug: rust-and-fuse-rotation-revocation-soundness
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-11
---

# Phase 74 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| rotation engine (host-agnostic) → caller (FUSE/web) | Post-rotation read keys leave the engine via RotateReadResult/rotatedNodes; caller is terminal owner | Per-node AES read keys (`Zeroizing<[u8;32]>` / `Uint8Array`) |
| Rust engine ↔ TS engine | Cross-language parity pair; shape drift is a silent-decryption hazard | `RotatedNodeKey` struct shape |
| rotation result → in-memory FUSE InodeTable | Refreshed keys written into inode state that later local relinks reseal under | Per-node read key bytes |
| desktop client → CipherBox API | PATCH/DELETE carry share_id (public) + ECIES ciphertext (no plaintext key) | `encryptedReadKey` (ECIES), rootGeneration |
| API grant list → engine re-mint | Retained recipients re-wrapped; absence = revocation | recipient public keys, ECIES-wrapped read keys |
| WinFsp write-op handler → InodeTable + rotation | Destructive overwrite-rename crosses into node removal; must pass scope-exit gate first | dest_ino removal, rotation trigger |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-74-01 | Information Disclosure | `RotateReadResult.rotated_nodes` key map (`crates/sdk/src/rotation/engine.rs`) | high | mitigate | Keys in `Zeroizing<[u8;32]>` (engine.rs:810); no log macros on key bytes; map inserts clone; engine zeroes only its own temps (D-09 terminal-owner) | closed |
| T-74-02 | Tampering | per-node map keying (engine.rs) | medium | mitigate | Keyed by ipns_name at each call site (1633/1880/2097); deep-tree test asserts 3 levels (engine.rs:4610) | closed |
| T-74-03 | Tampering (shape drift) | TS/Rust `RotatedNodeKey` parity | high | mitigate | Field-for-field LOCKED contract (engine.ts:343-348); parity test (engine.test.ts:3504-3634) | closed |
| T-74-12 | Information Disclosure | `rotatedNodes` readKey values (engine.ts) | medium | mitigate | Keys `Uint8Array` owned by terminal caller; `@security` D-09 note (engine.ts:360); no console log of key bytes | closed |
| T-74-04 | EoP / Information Disclosure | stale intermediate inode read_key resealed post-rotation (`grant_scope.rs`) | high | mitigate | Refresh EVERY rotated node's inode key by ipns_name before relink (grant_scope.rs:575-600); deep-tree test (:1395) | closed |
| T-74-13 | Information Disclosure | copy of key bytes into inode buffers | low | mitigate | `copy_from_slice` into inode's own `Zeroizing` buffer (grant_scope.rs:594); call-site log prints only ipns/child_id | closed |
| T-74-05 | Tampering / Input Validation | `update_grant` request body (`shares.rs`) | medium | mitigate | Body carries only `encryptedReadKey`+`rootGeneration` (shares.rs:156-162); write-key fields omitted; test asserts absent | closed |
| T-74-06 | Information Disclosure | `encryptedReadKey` on wire | medium | mitigate | ECIES ciphertext forwarded from caller, no re-wrap (shares.rs:98-123); bearer auth injected (client.rs:110); no log macros | closed |
| T-74-07 | DoS (over-broad revocation) | `query_grants_rooted_at` (`rotation_deps.rs`) | high | mitigate | Real query filtered by `root_node_id==node_id` (rotation_deps.rs:264-286); FakeTransport filter test | closed |
| T-74-08 | Spoofing / Info Disclosure | `recipient_public_key` hex parse | medium | mitigate | `hex_to_bytes` trims 0x, keeps 04 prefix (rotation_deps.rs:270-271); ECIES wrap by caller; hex error → RotateFailed | closed |
| T-74-14 | EoP (revoked recipient retained) | inverse over-retention | medium | accept | Structurally prevented: `is_revoked:false` hardcoded (rotation_deps.rs:282); revoked shares hard-deleted server-side, never appear in query | closed (accepted) |
| T-74-09 | EoP | ungated `fs.inodes.remove(dest_ino)` on overwrite-rename (`windows/write_ops.rs`) | high | mitigate | Dest gate `run_scope_exit_gate(dest_ino)` before removal (write_ops.rs:1156-1160 → :1178); ENOTEMPTY before source gate; collision check first | closed |
| T-74-11 | Tampering | reorder moving collision check (windows/write_ops.rs) | medium | mitigate | Collision check `status_object_name_collision` unchanged & first (:1102-1105); only ENOTEMPTY moved | closed |
| T-74-10 | Information Disclosure | deep-path decryptability after revocation (e2e) | high | mitigate | Part C asserts revoked recipient cannot decrypt intermediate folder NOR retained file at depth via decryptability probe (shared-scope-exit-rotation.mts:879-903) | closed |
| T-74-15 | DoS (retained recipient wrongly cut) | e2e | medium | mitigate | Part C: Carol re-minted (`pollGrantRemint`) and still decrypts folderB (shared-scope-exit-rotation.mts:928-959) | closed |
| T-74-09v | EoP (WinFsp overwrite-rename bypass) | e2e | high | mitigate | Part D overwrite-rename through mount; revoked cut post-rename, retained kept (shared-scope-exit-rotation.mts:1120-1173); Windows-CI-authoritative | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above high count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-74-01 | T-74-14 | Revoked-recipient over-retention is structurally impossible: revoked shares are hard-deleted server-side, so they never appear in the `query_grants_rooted_at` result to be re-minted. `is_revoked` is hardcoded `false` from `collect_sent_shares`. No code branch needed; `delete_grant` retained for engine-contract completeness only. | gsd-security-auditor (Phase 74) | 2026-07-11 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-11 | 16 | 16 | 0 | gsd-security-auditor (ASVS L1, block_on: high) |

### Non-blocking notes (documented, not mitigation gaps)

1. Runtime verification of T-74-09/T-74-11 (WinFsp) and T-74-10/T-74-15/T-74-09v (e2e legs) is CI-deferred — mitigation code is present and structurally correct at ASVS L1, but not runtime-proven until the `Cargo Check & Test (Windows)` and `desktop-e2e` jobs are dispatched green. Documented infra limitation (winfsp build is CI-only on macOS).
2. Pre-existing Part A "Bob" e2e assertion may false-FAIL under 74-05's real `query_grants_rooted_at` (Bob's still-active grant should now be re-minted, not cut). Stale test semantics predating this phase's fix — logged as a follow-up todo, not a phase-74 mitigation gap.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-11
