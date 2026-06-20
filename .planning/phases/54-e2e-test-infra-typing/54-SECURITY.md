---
phase: 54
slug: e2e-test-infra-typing
verdict: SECURED
audited: 2026-06-20
auditor: gsd-security-auditor
scope: test-infrastructure-only
---

# Phase 54 — Security Audit (E2E Test-Infra Typing)

## Verdict: SECURED

Phase 54 is a pure test-infrastructure TypeScript migration (`.mjs` → `.ts`) of
7 dev/test E2E helper scripts plus 8 runner-script invocation swaps. It touches
no application runtime, no crypto primitives, no API endpoint/DTO/controller, and
no IPNS publish/resolve runtime. The migrated scripts are dev/test tooling not
shipped to users.

The single trust boundary is the test credential `TEST_SECRET`, which flows
`runner → tsx → migrated .ts helper` via environment variable — **unchanged**
from the prior `node *.mjs` invocation. The migration is behavior-preserving:
no new logging of secrets/tokens/keys, no new third-party package, no new
network/auth surface, and existing key-zeroization is retained verbatim. No new
attack surface is introduced.

`TEST_SECRET` is a non-production CI/test shared secret for `/auth/test-login`;
it is not a user or production secret (54-RESEARCH §ASVS note).

---

## Trust Boundary

```text
runner (.sh/.ps1)  --TEST_SECRET env-->  tsx  -->  migrated .ts helper
                                                        |
                                          POST /auth/test-login { email, secret }
                                                        |
                                          { accessToken, privateKeyHex, publicKeyHex? }
```

Pre-migration the interpreter was `node` on a `.mjs`; post-migration it is
`tsx` on a `.ts`. The credential channel (env var) and the wire contract are
identical.

---

## Evidence

### (a) No secret / token / privateKey newly logged

Grep across all 7 migrated `.ts` files + `tests/e2e-helpers/{auth,types}.ts` for
`console.*` referencing `secret`/`accessToken`/`privateKey`/`TEST_SECRET`:

- **No `console.*` call prints `TEST_SECRET`, `accessToken`, or any user
  `privateKey`.** `TEST_SECRET` appears only as: doc-comment usage strings, a
  `process.env.TEST_SECRET` read, error-message "requires TEST_SECRET env var"
  text, and forwarding into a child-spawn env (`test-move-content.ts:103`,
  `{ ...process.env, TEST_SECRET: secret }`) — never logged.
- `auth.ts` never logs `accessToken`/`privateKeyHex`; on auth failure it throws
  with status + response body text (not the secret).
- The 3 `console.log(...PRIVATE_KEY...)` lines in `generate-test-vectors.ts`
  print **hardcoded, well-known cross-language test-vector constants** (RFC 8032
  Ed25519 / standard secp256k1 fixtures), not user or runtime keys. Verified
  pre-existing: `git show origin/main:…generate-test-vectors.mjs | grep -c PRIVATE_KEY` = 3,
  and the migration diff added **0** new `PRIVATE_KEY` console lines. Behavior
  preserved (the Rust parity tests require these exact fixtures).
- `staging-perf-wallet.ts` uses the canonical public Hardhat/Anvil test private
  key (`0xac09…ff80`) — a publicly-documented test key, not a secret; unchanged
  from the `.mjs`.

The `--secret` CLI guard is intact (`auth.ts:89-91`,
`"Do not pass --secret on CLI. Set TEST_SECRET in environment."`), preserving the
env-only secret-handling pattern (54-RESEARCH §Security note).

Key-zeroization preserved verbatim across the migration:
`clearBytes(fileKey)` / `fileIpnsPrivateKey.fill(0)` / `rootIpnsKeypair.privateKey.fill(0)`
in `edit-filepointer.ts`; `.fill(0)` + `clearBytes(userPrivateKey)` in
`rename-folder.ts` and `bump-ipns-sequence.ts`.

### (b) No new package install of note (supply-chain)

- Lockfile importer-level additions: **only** `@cipherbox/core: workspace:*` →
  `version: link:../../packages/core` (a first-party workspace link required by
  the D-02 IPNS-symbol import fix in `generate-test-vectors.ts`).
- **Zero** new versioned/third-party `packages:` entries added to
  `pnpm-lock.yaml` (`git diff | grep "^+  '<pkg>@<ver>'"` → none). The remaining
  lockfile diff is `libc: [...]` metadata normalization on pre-existing
  `@napi-rs`/`@rollup`/`@tauri-apps` linux entries — not new dependencies.
- `tsx` (`^4.21.0`) and `@noble/secp256k1` (`^3.0.0`) were **already** declared;
  no new download. No untrusted third-party package introduced.

### (c) Behavior-preserving → no new attack surface

CLI/env/stdout/exit contracts, network calls (`/auth/test-login`, `/vault`, SDK
publish paths), and key handling are unchanged. The only code deltas are
TypeScript type-narrowing guards (unreachable in practice, reuse existing error
messages) and a type-safe `'signatureV1' in ipnsRecord` narrowing that does not
alter any computed value. No server-side auth/session/crypto logic is touched.

---

## STRIDE Disposition

| Category | Threat (test-infra context) | Disposition | Evidence |
| -------- | --------------------------- | ----------- | -------- |
| **Spoofing** | Helper authenticates to API as the test identity via `/auth/test-login` | UNCHANGED — same endpoint/payload/credential channel as `.mjs`; `TEST_SECRET` env-only, `--secret` CLI rejected | `auth.ts:28-32,89-91` |
| **Tampering** | Migration alters the flows the scripts drive (e.g. emitted crypto vectors, IPNS sequence bumps) | MITIGATED — behavior-preserving (D-07); test vectors byte-identical (0 new prints, drop-in `deriveEd25519PublicKey`); republish flow unchanged | `generate-test-vectors.ts`, 54-03-SUMMARY §Emitted Test-Vector Integrity |
| **Repudiation** | N/A — dev/test tooling, no audit-log surface | N/A | — |
| **Information Disclosure** | `TEST_SECRET` / `accessToken` / user `privateKey` leaked via logs or new outputs | MITIGATED — no secret/token/user-key in any `console.*`; secret forwarded only via child-spawn env; key-zeroization retained | grep (section a); `test-move-content.ts:103` |
| **Denial of Service** | N/A for a typing migration; child-spawn already bounded | UNCHANGED — `verify` child spawn retains 60s `timeout` + `maxBuffer` | `test-move-content.ts:108-109` |
| **Elevation of Privilege** | New/untrusted dependency or transitive supply-chain risk via the toolchain swap | MITIGATED — only a first-party `workspace:*` link added; `tsx`/`@noble/secp256k1` pre-existing; no third-party install | lockfile diff (section b) |

---

## Residual Risk

None of security note. The standard cross-package dist-staleness operational
gotcha (D-02) is a correctness concern, not a security one, and is already
mitigated by build-ordering in the root `typecheck` script.

The desktop `run-all.sh` + web-e2e behavioral suites (live stack) are the
runtime confirmation of behavior preservation and are deferred to manual/CI per
54-VALIDATION.md — they are not security gates for this static migration.
