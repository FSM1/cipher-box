# Phase 19: IPNS Resolution Improvement - Scoping Rationale

**Date:** 2026-03-07
**Purpose:** Trace decision-making and tradeoffs for Phase 19 scoping discussions.

---

## 1. Resolution Strategy: Network-First vs DB-First

**STATE.md said:** "DB-first with async Kubo DHT verification adopted as IPNS resolution strategy"

**Decision:** Keep network-first (current logic). STATE.md needs correction.

**Rationale:** The original DB-first decision assumed delegated-ipfs.dev would remain unreliable. With self-hosted Someguy, the network path becomes reliable and fast. Network-first is preferred because:

1. **Reduces DB dependence** — aligns with the long-term vision of making CipherBox more IPFS-native
2. **Simpler change** — swapping a URL is less risky than rewriting resolution logic
3. **Measurable** — Phase 18 baselines with delegated-ipfs.dev can be directly compared to Someguy metrics using the same code path
4. **DB fallback remains** — safety net for when Someguy is unavailable

**Tradeoff:** If Someguy is slow, worst-case is 10s before DB fallback kicks in. Accepted because:
- Timeout tuning can happen after baseline data exists
- The 10s timeout ensures comparable metrics with Phase 18 baselines
- User explicitly stated: "I actually want to reduce reliance on the db"

---

## 2. TEE Worker Routing: Someguy vs delegated-ipfs.dev

**Options considered:**
- A) Route TEE through Someguy (same Docker network, fast)
- B) Keep TEE on delegated-ipfs.dev (async, latency-tolerant)

**Decision:** Option B — TEE stays on delegated-ipfs.dev.

**Rationale:**
1. **TEE will move to Phala infra** — eventually it won't be in the same Docker network. Routing through CipherBox Someguy would require exposing Someguy publicly, adding attack surface.
2. **Async tolerance** — TEE republishes happen every 6 hours in background batches. Latency doesn't affect user experience.
3. **Scope reduction** — fewer moving parts in Phase 19.
4. **Revisit trigger** — if Phase 18 metrics show delegated-ipfs.dev flakiness causes TEE republish failures at scale, reconsider.

**Tradeoff:** TEE continues depending on an external service (delegated-ipfs.dev). Accepted because:
- TEE publishes are best-effort with retries
- Failed TEE publishes don't affect user operations (client publishes are the primary path)
- CipherBox API's own Someguy handles all user-facing resolution

---

## 3. IPNS-03: Recovery Tool and Self-Sovereignty

**Original requirement:** "Recovery tool resolves IPNS records via self-hosted Someguy without depending on the CipherBox API or delegated-ipfs.dev"

**Problem:** This contradicts self-sovereignty. If recovery depends on self-hosted Someguy (CipherBox infrastructure), recovery fails when CipherBox is down — the exact scenario recovery is designed for.

**Decision:** Rewrite IPNS-03. Recovery defaults to public routing (delegated-ipfs.dev or any public IPFS gateway). Self-hosted Someguy is available as an optional configurable endpoint.

**Rationale:**
1. **Self-sovereignty principle** — vault export format spec (docs/VAULT_EXPORT_FORMAT.md) explicitly states: "No CipherBox servers, accounts, or APIs are required" for recovery
2. **Public DHT is the right default** — IPNS records published via Someguy propagate to the public DHT (Kubo is connected to it). Any public resolver can find them.
3. **Optional Someguy** — power users running their own Someguy/Kubo can point recovery at it. This is a config option, not a dependency.

**Tradeoff:** Recovery still depends on public infrastructure (IPFS DHT). Accepted because:
- This is inherent to IPFS — if the entire public network is down, IPFS-based storage doesn't work regardless
- CipherBox DB fallback covers the CipherBox-is-running scenario
- Recovery is the CipherBox-is-gone scenario, where only public infrastructure matters

**Deferred:** Building an actual standalone CLI recovery tool — captured for a future phase.

---

## 4. Degradation Strategy: Sequential vs Parallel

**Options considered:**
- A) Sequential: Someguy first, DB fallback on failure (current pattern)
- B) Parallel race: Fire both, return faster result
- C) DB-first with async Someguy verification

**Decision:** Option A — sequential with timeout.

**Rationale:** User stated: "longer term I feel that IPNS resolution should not be a responsibility of the core CipherBox solution." This architectural direction means:

1. **Clean separation** — the API asks one source (Someguy/IPFS network), falls back to DB cache. Not racing two sources.
2. **DB is a temporary crutch** — as IPNS resolution becomes more reliable, DB's role diminishes. A parallel race would entrench DB dependency.
3. **Simpler code path** — no race condition complexity, no "which result wins" logic changes.

**Tradeoff:** If Someguy is slow (not erroring), user waits up to 10s before seeing data. Accepted because:
- Self-hosted Someguy should be fast (local network)
- Timeout tuning deferred until baseline data exists
- DB fallback rate metrics will reveal if this is a problem in practice

---

## 5. Metrics: Dedicated vs Reuse Existing

**Decision:** Add dedicated Prometheus metrics for Someguy resolution.

**Rationale:**
- Phase 18 establishes baselines with delegated-ipfs.dev
- Phase 19 needs comparable metrics with Someguy to measure improvement
- Existing `ipnsResolves` counter is too coarse — need latency histograms and timeout/fallback counts
- No alerting thresholds yet — establish baselines first, configure alerts with real data

---

_Rationale documented: 2026-03-07_
