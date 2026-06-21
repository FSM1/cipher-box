# Phase 51 Security Audit — Crypto-Signature & Secret-Leak Hardening (HARD-02)

Branch: `feat/crypto-signature-secret-leak-hardening`
ASVS Level: 2 | Block-on: high
Audit date: 2026-06-19

Result: SECURED — all 12 `mitigate` threats verified present in implementation; all 4 `accept` dispositions reasonable and documented.

## Threat Verification

| Threat ID | Category        | Disposition | Status | Evidence (file:line)                                                                                 |
| --------- | --------------- | ----------- | ------ | --------------------------------------------------------------------------------------------------- |
| T-51-01   | Tampering       | mitigate    | CLOSED | `apps/api/src/ipns/ipns.service.ts:266-270` — `BadRequestException` on embedded CID != metadataCid    |
| T-51-02   | Tampering       | mitigate    | CLOSED | `apps/api/src/ipns/ipns.service.ts:274-294` — offset-aware seq gate, first-publish 0n/1n tolerance    |
| T-51-03   | Tampering       | accept      | CLOSED | `apps/api/src/ipns/ipns.service.ts:230-236` — embedded-vs-embedded anti-rollback 409 preserved        |
| T-51-04   | Tampering       | mitigate    | CLOSED | `apps/web/src/services/ipns.service.ts:180-182` — throw on present-but-invalid signature              |
| T-51-05   | Spoofing        | mitigate    | CLOSED | `apps/web/src/services/ipns.service.ts:186-191` — throw on derived-name mismatch (key substitution)   |
| T-51-06   | Repudiation     | accept      | CLOSED | `apps/web/src/services/ipns.service.ts:194-197` — absent fields allow + warn; outer 404 catch narrow @207 |
| T-51-07   | Tampering       | mitigate    | CLOSED | `crates/api-client/src/ipns.rs:64-120` verify fn; `crates/fuse/src/lib.rs:1643-1666` 4-arm gate, error on Some(false)/Err |
| T-51-08   | Repudiation     | accept      | CLOSED | `crates/fuse/src/lib.rs:1644-1650` — `Ok(None)` → warn + continue (DB CID authoritative)              |
| T-51-09   | Info Disclosure | mitigate    | CLOSED | `crates/fuse/src/lib.rs:1617` BFS queue `VecDeque<(String, Zeroizing<Vec<u8>>)>`; :933-942 get_folder_key returns Zeroizing; :1681 child keys stay Zeroizing |
| T-51-10   | Info Disclosure | mitigate    | CLOSED | `crates/crypto/src/ecies.rs:38,49-51` — `unwrap_key` returns `Zeroizing<Vec<u8>>` (`.map(Zeroizing::new)`) |
| T-51-SC   | Tampering       | accept      | CLOSED | `crates/api-client/Cargo.toml` — `cipherbox-crypto = { workspace = true }`, first-party workspace crate, no registry gate needed |
| T-51-11   | Info Disclosure | mitigate    | CLOSED | `packages/sdk-core/src/ipns/index.ts` — `params.ipnsPrivateKey.fill(0)` in `finally` within withPerf  |
| T-51-12   | Info Disclosure | mitigate    | CLOSED | `packages/sdk-core/src/vault/index.ts` — `vaultKeyKeypair.privateKey.fill(0)` in `finally`            |
| T-51-13   | Info Disclosure | mitigate    | CLOSED | `packages/sdk-core/src/folder/index.ts` — documented caller-owns-key SKIP + `folder.test.ts` unchanged-buffer guard (client.ts audit: all 9 sites pass live session keys) |
| T-51-14   | Tampering       | mitigate    | CLOSED | `packages/sdk-core/src/__tests__/ipns.test.ts` Test D — regression guard asserts resolveIpnsRecord throws on invalid sig |

12/12 `mitigate` verified present. 4/4 `accept` documented and reasonable. Register total: 14 IDs (T-51-01..14) + T-51-SC.

## Accept-Disposition Justification

- T-51-03 (anti-rollback 409): pre-shipped embedded-vs-embedded sequence-regression 409 left unchanged; S1 (400) was correctly placed AFTER the 409/CAS checks so concurrency/rollback signals stay authoritative.
- T-51-06 / T-51-08 (absent sig fields, web + Rust): allow + flag (`signatureVerified=false` / `Ok(None)` → warn) is intentional backward-compat for legacy records; DB CID is authoritative. Consistent across web, Rust, and sdk-core.
- T-51-SC (cargo dep add): only first-party `cipherbox-crypto` workspace crate added; no crates.io legitimacy checkpoint applies.

## Desktop unwrap_key Hotfix Review (T-51-10)

`apps/desktop/src-tauri/src/commands/vault.rs:207-215` (commit `11c1b5516`) consumes the new `Zeroizing<Vec<u8>>` from `unwrap_key` and copies it via `.to_vec()` into the long-lived `state.sdk.root_folder_key` SDK-state field, which is typed `Option<Vec<u8>>` (`apps/desktop/src-tauri/src/fuse/mod.rs:81`).

Verdict: does NOT undermine T-51-10. The declared mitigation — `unwrap_key` returns `Zeroizing<Vec<u8>>` so its decrypted copy zeroes on drop — is intact: the `Zeroizing` temporary in `load_vault_key` is dropped (and wiped) at function exit. The long-lived plain-`Vec` SDK-state field is PRE-EXISTING (the field type was already `Option<Vec<u8>>` before this phase; only the +3/-1 line `.to_vec()` compile-fix was added on the branch) and is OUTSIDE the Phase-51 threat register. The hotfix is the minimal change to keep the desktop building against the new return type and introduces no new plaintext-key persistence that did not already exist.

## Informational — Pre-existing residual (NOT a Phase-51 gap)

The desktop SDK-state retains the root folder key and root IPNS private key as non-zeroizing long-lived `Vec<u8>` (`fuse/mod.rs:81`, plus `root_folder_key`/`root_ipns_private_key` state). This is unchanged by Phase 51 and not enumerated in this phase's register (the Rust S3/D-05 scope was ecies + the FUSE key-descent path). Candidate for a future hardening item: migrate the desktop SDK-state key fields to `Zeroizing<Vec<u8>>` for parity with the FUSE descent path. Logged here for traceability only — does not block this phase.

## Unregistered Flags

None. All four plan SUMMARYs report no new network endpoints, auth paths, trust boundaries, or schema changes (51-01 "Threat Surface Scan: No new..."; 51-02/03/04 "Threat Flags: None"). No new attack surface appeared during implementation that lacks a register mapping.
