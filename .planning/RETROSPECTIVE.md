# Project Retrospective

_A living document updated after each milestone. Lessons feed forward into future planning._

## Milestone: v1.1 — IPFS Infrastructure

**Shipped:** 2026-06-27
**Phases:** 45 | **Plans:** 198 | **Tasks:** 342

### What Was Built

- Self-hosted Someguy IPNS routing replacing delegated-ipfs.dev, with a DB-first resolve path (sub-2s normal case) that degrades gracefully to DB-only when the DHT is slow.
- Vault blob v2 migration moving rootFolderKey into the IPFS vault header — DB crypto columns dropped entirely, achieving a true zero-knowledge server.
- BYO-IPFS node support with a user-selectable pinning mode (cipherbox-only / external-only / dual-pin), Settings STORAGE tab, and a TEE-routed connection test; IPNS publishes still route through the CipherBox API in every mode.
- Performance baselines and instrumentation — server Prometheus histograms, Kubo scrape, client-side SDK timing, journey timing tests, load-test thresholds, and a documented capacity model.
- A layered TypeScript SDK extraction (`@cipherbox/crypto`, `core`, `api-client`, `sdk-core`, `sdk`) plus a mirrored five-crate Rust SDK workspace, reducing the desktop app to a thin Tauri shell backed by cross-language test vectors.
- Writable shares — read/write permission levels, ECIES-wrapped IPNS key delivery, owner permission management, and multi-writer CAS conflict retry; later productionized through SDK folder-state and shared-folder consolidation.
- FUSE write durability — an fsync'd ciphertext write journal with crash-recovery replay closing silent `release()` data loss, plus three-way IPNS conflict handling (loser-becomes-version).
- The HARD-01..11 hardening block, culminating in a strict fail-closed cross-layer IPNS verified-resolver chokepoint: relocated to api-client, Legacy/first-publish skew acceptance removed, resolve-side expiry added, and all 17 Rust call sites plus the web and API paths routed through it.

### What Worked

- Goal-backward verification (observable truths traced to file:line evidence) made phase VERIFICATION reports concrete and auditable rather than vibes-based.
- Cross-language test vectors in `tests/vectors/` gave a real Rust/TS parity gate — the same IPNS verify cases classify identically in both languages, catching drift before it shipped.
- Reopening the milestone into a hardening block (Phases 50–60) to absorb audit and verification findings — rather than declaring v1.1 done and deferring to a v1.2 — kept the integrity work attached to the milestone that introduced it.
- Adversarial spot-checking during the close-out audit (retroactively-authored Phase 38/39 VERIFICATION each came back with 0 refutations) raised confidence that the gaps were genuinely the only gaps.
- Establishing performance baselines (Phase 18) before any architectural change gave before/after evidence for the Someguy migration and the upload pin parallelization.

### What Was Inefficient

- Scope ballooned from 5 originally-planned phases (18–22) to 45. The milestone became the de-facto home for the SDK extraction, writable shares, FUSE durability, the Phala migration, release engineering, and an 11-item hardening block.
- Two phases (38, 39) shipped with no VERIFICATION.md until the milestone close-out audit had to retro-author them — a 3-month verification lag.
- STATE.md velocity counts drifted during the long tail; the milestone close required reconciling REQUIREMENTS.md traceability (HARD statuses Planned→Complete, formal count corrected 69→66).
- A long hardening long-tail (Phases 50–60) was rework on IPNS verification — the strict fail-closed chokepoint took multiple phases to land because each pass surfaced another producer/consumer (e.g. the 10th first-publish producer, StorageTab BYO config, found only during Phase 60 adversarial closeout).

### Patterns Established

- Embed-sequence-1 first-publish invariant — every first IPNS publish must embed sequence 1, enforced by a strict API gate (`embeddedSeq !== 1n` → 400) across all producers (sdk-core, FUSE, vault-settings, BYO storage-config).
- Verified-resolver chokepoint — a single fail-closed `resolve_ipns_verified` / `resolveIpnsRecord` entry point per layer; raw resolve is not re-exported, so no caller can skip verification.
- Per-package release-please automation — independent semver per app/package/crate driven by PR-time conventional-commit analysis, with the load-bearing `chore(release)` bot commit and date-based staging tags.
- `.mts` typechecked helper scripts — E2E/SDK helper scripts moved off untyped `.mjs` into TypeScript wired into typecheck and lint, catching SDK contract drift in CI.

### Key Lessons

1. Retro-author VERIFICATION at phase close, not milestone close — Phases 38/39 went unverified for ~3 months; a missing VERIFICATION.md is a process gap that compounds into milestone-audit debt.
2. Treat IPNS `sequenceNumber` as the version clock — folder state lives in both the Zustand store and the SDK `folderTree`; reconciling them against the IPNS sequence is the canonical way to avoid stale-sequence 409s and resurrected-delete merges.
3. Strict fail-closed verification needs ALL producers and consumers enumerated up front — the chokepoint took the entire 50–60 tail because each phase found another path (resolve sites, first-publish producers) that the prior "all N covered" claim had missed.

### Cost Observations

- 45 phases / 198 plans / 342 tasks over the milestone (Mar–Jun 2026), the largest milestone to date by a wide margin.
- Model mix not tracked for this milestone — unknown opus/sonnet/haiku split.
- Notable: roughly a quarter of the phases (50–60, the hardening block) were rework/integrity hardening rather than net-new features, concentrated in IPNS verification.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Sessions | Phases | Key Change                                                        |
| --------- | -------- | ------ | ---------------------------------------------------------------- |
| v1.1      | n/a      | 45     | Goal-backward verification + reopened hardening block (50–60)    |

### Cumulative Quality

| Milestone | Tests | Coverage | Zero-Dep Additions |
| --------- | ----- | -------- | ------------------ |
| v1.1      | n/a   | n/a      | n/a                |

### Top Lessons (Verified Across Milestones)

1. (Pending a second milestone to cross-validate.)
