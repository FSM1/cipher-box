# Phase 78: Recovery Tool v3, Vault-Load Guards, Web UX and CI Guards - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-12
**Phase:** 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
**Areas discussed:** Web vitest CI decision, Download-progress dead code, Offline recovery tool crypto (+ IPFS access mechanism)

---

## Web vitest CI decision (SC3)

| Option | Description | Selected |
|--------|-------------|----------|
| Keep out of CI + document | No web-unit CI job; document logic→SDK / UI→web-e2e split; ensure residual apps/web tests pass or relocate | ✓ |
| Wire apps/web vitest into CI | Add apps/web vitest (*.test.ts) as a blocking CI gate | |
| Wire as main-only / non-blocking | Run in CI but gated to main-push or non-blocking | |

**User's choice:** Keep out of CI + document.
**Notes:** Preserves the standing architecture (reusable logic in `packages/sdk` Vitest, UI via Playwright web-e2e). A green 67-test apps/web suite exists today, but gating CI on it is intentionally declined to avoid inviting UI-coupled unit tests.

---

## Download-progress dead code (SC2)

| Option | Description | Selected |
|--------|-------------|----------|
| Delete the dead code | Remove useFileDownload + download.store | |
| Wire it to real spinners | Connect to real download + restore progress spinners | ✓ |

**User's choice:** Wire it to real spinners.
**Notes:** Deliver the progress UX the code was scaffolded for rather than removing it.

---

## Offline recovery tool crypto (SC1)

| Option | Description | Selected |
|--------|-------------|----------|
| Bundle the SDK v3 read path | Inline compiled SDK read/decrypt chain | |
| Standalone reimplementation | Hand-reimplement v3 read/decrypt in recovery.html | |
| Reuse low-level libs + standalone walk | Bundle packages/crypto + packages/core; tool implements its own IPNS/IPFS walk; no SDK/API/Web3Auth | ✓ (clarified) |

**User's choice:** Reuse the low-level libraries (`packages/crypto`, `packages/core`); do NOT use the SDK.
**Notes:** The user corrected the framing — the SDK routes IPNS resolve + IPFS fetch through the CipherBox API, which defeats the recovery tool's entire purpose. The tool must recover a vault even if all CipherBox API infra disappears: given only the `privateKey` and content pinned on *some* reachable server, walk the IPNS/IPFS links and decrypt the whole tree with zero Web3Auth/API dependency. Low-level libs are reused for crypto/codec parity; the walk is standalone.

### IPFS access mechanism (sub-decision)

| Option | Description | Selected |
|--------|-------------|----------|
| Configurable gateway URL | User-supplied gateway/pinning URL (default public); resolve `/ipns/<name>`, fetch `/ipfs/<cid>` over HTTP | ✓ |
| Gateway + delegated routing | Separate content gateway + delegated-routing/IPNS-resolve endpoint | |
| Paste CIDs manually | User resolves IPNS out-of-band, pastes CIDs | |

**User's choice:** Configurable gateway URL (default a public gateway).
**Notes:** Browser tool cannot run a libp2p node; all fetches are HTTP against a configurable gateway. Key derivation, IPNS verification, and decryption happen locally from the pasted private key.

---

## 68.2/73 hardening backlog scope (SC3) — not selected for deep discussion

**Default applied (per ROADMAP):** Fix only item 3 (poll-monotonicity) + item 11 (descent-vs-restore race), each with e2e coverage; defer the remaining 68.2/73 backlog items.

## Claude's Discretion

- Single-file bundler choice (esbuild vs vite single-file) for recovery.html, provided no SDK/API/Web3Auth dependency is introduced.
- Default gateway value / optional curated gateway list.

## Deferred Ideas

- Remaining open items of the 68.2/73 CodeRabbit hardening backlog beyond items 3 + 11.
- 22 lower-confidence todo matches (score ≤ 0.6) that were keyword-collisions from other phases/backlog — reviewed, not folded.
