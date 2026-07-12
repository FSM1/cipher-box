---
phase: 78
slug: recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-12
---

# Phase 78 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

Register origin: authored at plan time (`register_authored_at_plan_time: true` — all 8 PLAN files carry a `<threat_model>` block). Verification depth: ASVS L1 (grep/static-analysis). Block threshold: `high`.

Design anchor (not a gap): the recovery tool is deliberately SDK/API/Web3Auth-free — it uses only `@cipherbox/crypto` + `@cipherbox/core` over a caller-configured HTTP gateway, driven by the user's `privateKey`, shipped as a single self-contained esbuild bundle. IPNS records are fetched over untrusted HTTP and then Ed25519-signature-verified locally (verify-after-fetch trust model). This is a LOCKED architectural decision, not a threat.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| recovery tool → external IPFS/IPNS gateway (HTTP) | Untrusted gateway responses (IPNS records, IPFS bytes) cross into the browser tool; verified after fetch | IPNS records, sealed IPFS bytes (untrusted until verified) |
| user → recovery tool | The pasted `privateKey` is the sole credential; stays client-side | `privateKey` (secret) |
| sealed envelope → plaintext | AEAD unseal is the integrity boundary for all recovered content | Sealed nodes / file ciphertext → plaintext |
| async poll / descent result → shared folder store | In-flight results cross into shared folder / active write-depth state that navigation may have already advanced | Folder metadata, active writeKey/depth (integrity-sensitive) |
| apps/web/src → @cipherbox/sdk-core / @cipherbox/core (compile-time) | Import boundary keeping the web app on the SDK facade, off raw read-chain/IPFS internals | Module import graph (compile-time) |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-78-01 | Tampering | gateway.ts IPNS resolve | high | mitigate | `verifyIpnsRecordSignature(ipnsName, marshalledRecord)` on the primary rung; a failure is a hard security stop (throws, no fallthrough) — `apps/web/recovery-src/gateway.ts:90-100`. | closed |
| T-78-02 | Tampering | supply chain (bundled crypto/core, esbuild/fflate) | medium | mitigate | Self-contained esbuild bundle of low-level `@cipherbox/crypto` + `@cipherbox/core` + `fflate`; no CDN/`jsdelivr` runtime fetch — depends only on the user-configured gateway — `apps/web/recovery-src/build.ts`. | closed |
| T-78-03 | Info Disclosure | private key in browser | medium | accept | Key stays client-side; no localStorage/sessionStorage persistence (CLAUDE.md Rule 1). See Accepted Risks Log. | closed |
| T-78-04 | Tampering | walk.ts content decrypt | high | mitigate | `unsealNode` + `decryptAesGcm` AEAD auth-tag verification fails closed on tampered IPFS content — `apps/web/recovery-src/walk.ts:100,141` (reuse of shipped codec). | closed |
| T-78-05 | Tampering | walk.ts child unseal | high | mitigate | Parent-mirror generation (`childRef.generation`, NEVER `published.generation`, §2.6 rule) preserves the exact published AAD binding; deviation fails closed — `apps/web/recovery-src/walk.ts:127-141`. | closed |
| T-78-06 | Info Disclosure | privateKey in DOM | medium | accept | `autocomplete="off"`, no localStorage/sessionStorage, post-recovery clear-history note (CLAUDE.md Rule 1). See Accepted Risks Log. | closed |
| T-78-07 | Repudiation | SC1 exit gate | low | mitigate | `tests/web-e2e/tests/recovery.spec.ts` un-fixme'd, active, and GREEN; phase exit grep for `test.fixme`/`test.skip` is clean — durable regression guard against v3 recovery-path rot. | closed |
| T-78-08 | Info Disclosure | download store status text | low | accept | Store holds only filenames + status enums; no key/credential material; pure UI state over the existing SDK facade. See Accepted Risks Log. | closed |
| T-78-09 | Tampering | web/SDK boundary erosion | medium | mitigate | ESLint `@typescript-eslint/no-restricted-imports` (error) blocks runtime `@cipherbox/sdk-core`/`@cipherbox/core` imports in `apps/web/src` (`allowTypeImports: true`), CI-enforced via `pnpm lint` — `eslint.config.js:40-53`. | closed |
| T-78-10 | Elevation of Privilege | mixed-import bypass | low | mitigate | Gate B `no-restricted-syntax` (error) forbids raw IPFS calls (`fetchFromIpfs`/`addToIpfs`/`unpinFromIpfs`) that a freshly-inlined mixed import could reintroduce — `eslint.config.js:55-63`. | closed |
| T-78-11 | Repudiation | undocumented test policy | low | mitigate | The `apps/web` Vitest-exclusion / web-e2e split is documented as a deliberate decision (D-06) in `docs/DEVELOPMENT.md:125-131`, making the exclusion auditable rather than an accidental gap. | closed |
| T-78-12 | Tampering | invalidateOpenFolder stale write | high | mitigate | Sequence-number monotonicity guard drops any poll result whose captured/resolved clock is no longer current (`store.folders[...].sequenceNumber > resolvedSequence` → return) — `apps/web/src/hooks/useSyncPolling.ts:33-58`; e2e regression spec locks it. | closed |
| T-78-13 | Tampering | active writeKey misrouting | high | mitigate | Monotonic descent token checked at BOTH the web hook (`useSharedNavigationActions.ts:380-503`) and the SDK active-depth state (`shared-folder-tree.ts:54-62` `seedGeneration`; `client.ts` guard) — a superseded descent's late result is discarded. | closed |
| T-78-14 | Elevation of Privilege | cross-depth write in a shared folder | medium | mitigate | The same dual-checked descent token prevents wrong-depth active-writeKey repointing, so shared-folder writes commit only at the depth the user is authorized-and-viewing. | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above workflow.security_block_on count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-78-01 | T-78-03 | `privateKey` is necessarily present client-side in the browser recovery tool to drive ECIES unwrap; it is never persisted to localStorage/sessionStorage and never leaves the client (CLAUDE.md Rule 1). Residual risk is browser-process memory only — inherent to a client-side zero-knowledge recovery tool. | Phase 78 plan (78-01) | 2026-07-12 |
| AR-78-02 | T-78-06 | The `privateKey` input field is in the DOM during recovery; mitigated by `autocomplete="off"`, no storage persistence, and a post-recovery clear-history note. Carried forward from the v2 tool unchanged. | Phase 78 plan (78-02) | 2026-07-12 |
| AR-78-03 | T-78-08 | The download-progress store holds only filenames + status enums (no key or credential material) and crosses no new trust boundary — pure UI state over the existing SDK facade. | Phase 78 plan (78-04) | 2026-07-12 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-12 | 14 | 14 | 0 | gsd-secure-phase (L1 static verification) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-12
