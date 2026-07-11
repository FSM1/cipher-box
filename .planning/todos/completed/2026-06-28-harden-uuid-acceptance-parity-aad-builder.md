---
created: 2026-06-28
title: Harden UUID acceptance-domain parity in the AAD builder (Phase 61 security follow-up)
area: crypto
files:
  - packages/crypto/src/utils/encoding.ts
  - crates/crypto/src/aes.rs
resolves_phase: 75
---

## Problem

Phase 61 security review (verdict SHIP, 0 BLOCKER/HIGH/MEDIUM) surfaced two LOW fail-closed hardening items in the `buildNodeAad` / `uuidToBytes` UUID-parsing boundary. Neither is exploitable and neither is a silent-decryption path — every divergent input is rejected by the stricter side, and the canonical pipeline (`crypto.randomUUID()` / `generate_uuid_v4`, always lowercase-hyphenated) never produces a divergent form. Captured for a deliberate fix because the phase's whole premise is "a byte mismatch is silent total decryption failure," so the TS↔Rust acceptance domains should match exactly.

### LOW-1 — TS/Rust UUID acceptance-domain divergence

`packages/crypto/src/utils/encoding.ts` (`uuidToBytes`) and `crates/crypto/src/aes.rs:~172` (`Uuid::parse_str`) accept different sets of UUID string forms:

| Input form | TS `uuidToBytes` | Rust `parse_str` |
| --- | --- | --- |
| canonical hyphenated / simple 32-hex / uppercase | accept | accept |
| arbitrary hyphen placement (strips to 32 hex) | accept | reject |
| braced `{…}` / `urn:uuid:…` | reject | accept |

Both sides are fail-closed (the stricter side rejects), so this is not exploitable today. It only matters if a non-canonical `node_id` ever reaches one side.

### LOW-2 — RESOLVED (commit `f1a81344f`)

`uuidToBytes` now validates `/^[0-9a-fA-F]{32}$/` on the hyphen-stripped value and throws `CryptoError('INVALID_AAD_INPUT')` for 32-char non-hex input (with a regression test in `build-node-aad.test.ts`). Fixed during the Phase 61 ship loop via the CodeRabbit review. No further action. The remaining open work below is LOW-1 only.

## Decision needed

Pick ONE canonicalization policy and enforce it identically on both sides:

- **Option A (strictest):** accept only canonical lowercase-hyphenated `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`; reject simple-32-hex, braced, urn, loose-hyphen on both sides. (NOTE: TS currently accepts simple-32-hex — confirm no caller/test relies on it before tightening.)
- **Option B:** canonicalize `node_id` to lowercase-hyphenated at the boundary before `buildNodeAad`/`build_node_aad`.

## Proposed fix

1. Add a shared strict UUID-format validator used by both `uuidToBytes` (TS) and `build_node_aad` (Rust) per the chosen policy.
2. Make `uuidToBytes` throw `CryptoError('…','INVALID_AAD_INPUT')` for all malformed input (covers LOW-2), and add a unit test for the 32-char non-hex case.
3. Extend the cross-language KAT / unit tests with the divergent forms to lock the agreed acceptance domain on both sides.

## Info-level notes (no action required, captured for context)

- `encryptAesGcmAad`/`encryptAesGcm` are exported and take a caller-supplied IV — by design for the deterministic KAT/low-level path. Production seals must route through `sealAesGcmAad`/`seal_aes_gcm_aad` (fresh IV). Documented in `encrypt.ts`.
- `sealAesGcmAad`/`unsealAesGcmAad` do not assert `aad.length === 45`; `buildNodeAad` always returns 45 bytes so the intended path is safe. Consider an assertion only if these are ever called outside `buildNodeAad`.

## Source

Phase 61 (`61-aad-bound-seal-primitive-and-cross-language-kat`) adversarial security review, 2026-06-28. Verdict: SHIP. The cross-language KAT (independently re-derived via OpenSSL) and the 8-case transplant suite are green; these items are forward hardening, not regressions.
