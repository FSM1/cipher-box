# Crypto/Privacy Review — Phase 76 (FUSE durability + TEE write-path hardening)

Date: 2026-07-12
Scope: crypto/privacy-adjacent files in `git diff origin/main...HEAD`
Verdict: **SHIP-SAFE** — no Critical or High crypto/privacy defect introduced.

## Files reviewed

- `apps/tee-worker/src/services/ipns-signer.ts` (strictly-later-EOL guard, `EolRollbackError`)
- `apps/tee-worker/src/services/key-manager.ts` (`decryptWithFallback`, typed-error rethrow)
- `apps/tee-worker/src/services/tee-keys.ts` (`TeeKeyUnavailableError`)
- `apps/tee-worker/src/routes/republish.ts` (per-entry null guard, key zeroization)
- `packages/crypto/src/ipns/parse-record.ts` (additive `ParsedIpnsRecord.validity: Date`)
- `apps/desktop/src-tauri/src/commands/vault.rs` (fail-closed preflight, decrypt-and-resume recovery, coherency unseal, zeroization)
- `crates/fuse/src/{metadata,fs,content_ops}.rs` (publish CAS retry, transient-key zeroization)

## Threat-lens results

1. **IPNS rollback/replay** — Sound. `ipns-signer.ts:77` compares `newValidity.getTime() <= existingValidity.getTime()`, both sourced from `parseIpnsRecord` (never `Date.now()`); equality is rejected (`<=`), no off-by-one. `value`/`sequence` come from the parsed existing record; `republish.ts` verifies the record signature on the same bytes before decryption — no TOCTOU.
2. **Key material handling** — `republish.ts` zeroes `ipnsPrivateKey` on every path (binding-fail, success, catch); `decryptIpnsKey` zeroes the TEE private key in `finally`. `decryptWithFallback` leaks neither plaintext nor which trial matched. FUSE zeroization changes are net improvements.
3. **Recovery path (`vault.rs`)** — Correct. `recover_root_keys_from_key_blob` ECIES-unwraps the existing blob and never mints (test asserts byte-identical recovery). `coherency_check_root_unseal` runs before registration. `classify_preflight_outcome` maps only `IpnsNotFound` to absent; every other error aborts before any write (fail-closed).
4. **Error typing** — `TeeKeyUnavailableError` rethrow preserves only config/infra context (no key material), thrown/caught per-entry. Un-masking a misconfig is a posture improvement.
5. **`parse-record.ts` Date mapping** — `new Date(record.validity)` is consistent on both sides of the comparison; RFC3339 carries explicit offset (no timezone ambiguity); sub-ms truncation can at worst raise a false-positive `EolRollbackError` (availability), never a rollback bypass.

## Findings and dispositions

- **LOW — un-zeroized recovered root keys (FIXED).** `vault.rs` `RecoverResume` arm materialized recovered root keys as bare `[u8;32]` via `try_into()`, inconsistent with the `FreshInit` arm's `Zeroizing<[u8;32]>`. Fixed on this branch: recovered keys are now wrapped in `Zeroizing` (use sites unchanged via deref coercion). Also independently flagged by the threat-model audit (`76-SECURITY.md`).
- **INFO — EOL guard no-ops on `Invalid Date`.** If either validity is `NaN`, `NaN <= x` is `false`, so the guard would not throw. Not exploitable (record signature is verified upstream and the fresh record is trusted-minted with a future EOL). Defense-in-depth only — **discarded** (below materiality bar).
- **INFO — config posture leak to relay.** `republish.ts` returns `TeeKeyUnavailableError.message` verbatim in `result.error`, exposing deployment state (no key material). Trusted-relay boundary — **discarded**.
- **PRE-EXISTING — un-zeroized `private_key_arr` copies** in `initialize_vault`/`fetch_and_decrypt_vault`. Not introduced by this phase — **out of scope**.

## Test coverage

Strong: `ipns-signer.test.ts` covers equal/earlier/longer-existing EOL rejection under a frozen clock; `key-manager.test.ts` covers stale-guard, mid-rotation fallback, genuine-corruption vs `TeeKeyUnavailableError`, and no-key-in-message; `vault.rs` unit tests cover fail-closed routing, no-re-mint byte-identity, and coherency unseal.
