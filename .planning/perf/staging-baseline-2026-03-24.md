# Staging Vault Login Path — Performance Baseline

**Date:** 2026-03-24 07:05 UTC
**Staging code:** Pre-IPNS-separation (current `main`)
**Purpose:** Baseline before PR #349 (vault key IPNS separation) deploys to staging
**Script:** `tests/web-e2e/staging-perf-wallet.mjs` (Playwright + `@johanneskares/wallet-mock`)

## Flow Change (PR #349)

|                      | Before (current staging)                        | After (PR #349)                                |
| -------------------- | ----------------------------------------------- | ---------------------------------------------- |
| Login IPNS resolve   | 1 name (root folder) → v2 blob (key + metadata) | 1 name (vault key) → v2 blob (key only)        |
| Root folder metadata | Bundled in blob, available at login             | Separate IPNS resolve, deferred to folder load |
| Net effect           | All-in-one but couples key + metadata           | Smaller login blob, decoupled publishes        |

---

## Scenario 1: Fresh Vault Login (First-Time User)

Measured on first run (no existing vault). Vault init + IPNS publish included.

| Phase                                  | Duration     | Notes                           |
| -------------------------------------- | ------------ | ------------------------------- |
| Page load + Core Kit init              | 1,498ms      | Sapphire Devnet connection      |
| SIWE nonce + verify                    | 316ms        | Wallet sign + backend verify    |
| Core Kit DKG                           | ~45,000ms    | Sapphire tBFT — dominates total |
| CipherBox auth (`POST /auth/login`)    | 273ms        | JWT from Core Kit identity      |
| Vault load (`GET /vault` → 404 → init) | ~722ms       | New vault init path             |
| **Total login → vault ready**          | **47,844ms** | ~45s is Web3Auth, not our code  |

---

## Scenario 2: Existing Vault Login (Returning User)

Measured on second run (vault exists, Core Kit has cached DKG state).

### Full Waterfall

| T (ms) | Method | Endpoint                      | Duration | Status | Notes                    |
| ------ | ------ | ----------------------------- | -------- | ------ | ------------------------ |
| 1,224  | GET    | `/health`                     | 117ms    | 200    | Healthcheck              |
| 2,204  | GET    | `/auth/identity/wallet/nonce` | 62ms     | 200    | SIWE nonce               |
| 2,277  | POST   | `/auth/identity/wallet`       | 293ms    | 200    | SIWE verify              |
| 11,453 | POST   | `/auth/login`                 | 213ms    | 200    | Core Kit → CipherBox JWT |
| 13,891 | GET    | `/vault`                      | 187ms    | 200    | Fetch vault record       |
| 14,165 | GET    | `/vault/config`               | 136ms    | 200    | Parallel                 |
| 14,193 | GET    | `/vault/quota`                | 115ms    | 200    | Parallel                 |
| 14,193 | GET    | `/ipns/resolve`               | 359ms    | 404    | IPNS resolve #1          |
| 14,165 | GET    | `/ipns/resolve`               | 620ms    | 404    | IPNS resolve #2          |

### Phase Breakdown

| Phase                         | Duration                  | Notes                           |
| ----------------------------- | ------------------------- | ------------------------------- |
| Page load + Core Kit init     | 2,029ms                   | Faster with cached state        |
| SIWE nonce + verify           | 355ms                     |                                 |
| Core Kit re-auth              | ~9,000ms                  | Much faster (cached DKG shares) |
| CipherBox auth                | 213ms                     |                                 |
| Vault load (serial)           | 187ms + 620ms = **807ms** | vault + IPNS resolve            |
| **Total login → vault ready** | **12,959ms**              | ~9s is Core Kit                 |

### Vault-Critical Path (Our Code Only)

```text
POST /auth/login      █████████ 213ms
GET /vault            ████████ 187ms
GET /vault/config     ██████ 136ms  ←── parallel
GET /vault/quota      █████ 115ms  ←── parallel
IPNS resolve #1       ██████████████ 359ms
IPNS resolve #2       █████████████████████████ 620ms
                      ─────────────────────────────
Serial critical:      ~1,379ms (auth + vault + IPNS resolves)
```

**Note:** Two IPNS resolves both returned 404 — old staging code doesn't publish vault blob to IPNS during wallet login. After PR #349, there will be one IPNS resolve for the vault key blob (should return 200 with real data).

---

## Scenario 3: Session Restore (Page Reload)

Core Kit doesn't persist tKey shares in headless Playwright, so reload requires full re-auth.

### Waterfall

| T (ms) | Method | Endpoint        | Duration | Status | Notes             |
| ------ | ------ | --------------- | -------- | ------ | ----------------- |
| 229    | GET    | `/health`       | 49ms     | 200    |                   |
| 1,143  | POST   | `/auth/refresh` | 536ms    | 401    | Race: stale token |
| 1,143  | POST   | `/auth/refresh` | 543ms    | 401    | Race: stale token |
| 1,143  | POST   | `/auth/refresh` | 827ms    | 200    | Succeeded         |
| 1,143  | POST   | `/auth/refresh` | 845ms    | 200    | Duplicate         |
| 1,143  | POST   | `/auth/refresh` | 849ms    | 200    | Duplicate         |
| 1,143  | POST   | `/auth/refresh` | 853ms    | 200    | Duplicate         |
| 31,143 | GET    | `/health`       | 154ms    | 200    |                   |

### Key Observations

- **6 concurrent `auth/refresh` calls** — race condition; 2 fail (401), 4 succeed
- After token refresh, app routes to `/#/` but **does not load vault** — Core Kit session lost
- In real browser (non-headless), Core Kit persists session → reload would skip DKG entirely
- The auth/refresh race is a pre-existing bug (deduplication needed), not introduced by PR #349

---

## API Endpoint Latencies (curl, 3 runs each, median)

| Endpoint           | Method | Median | Min   | Max   |
| ------------------ | ------ | ------ | ----- | ----- |
| `/auth/test-login` | POST   | 251ms  | 237ms | 263ms |
| `/vault`           | GET    | 137ms  | 124ms | 264ms |
| `/ipfs`            | POST   | 133ms  | 123ms | 195ms |
| `/ipns/publish`    | POST   | 127ms  | 122ms | 215ms |
| `/vault/init`      | POST   | 126ms  | 122ms | 199ms |
| `/ipns/resolve`    | POST   | 128ms  | 120ms | 162ms |

---

## Summary Table

| Scenario                   | Total Time    | Our Code (vault path) | Web3Auth                |
| -------------------------- | ------------- | --------------------- | ----------------------- |
| Fresh vault (new user)     | 47.8s         | ~722ms                | ~45s DKG                |
| Existing vault (returning) | 13.0s         | ~1,379ms              | ~9s cached DKG          |
| Session restore (reload)   | N/A (stalled) | auth/refresh 827ms    | Core Kit re-init needed |

**Bottom line:** Web3Auth Core Kit DKG dominates all login paths (9-45s). Our vault-critical serial path is 0.7-1.4s. The IPNS separation in PR #349 won't measurably change total login time — the change is architectural (decoupling key blob from folder metadata publishes).

## Re-measurement Checklist (Post-Deploy)

1. Run `tests/web-e2e/staging-perf-wallet.mjs` with fresh random wallet key
2. Verify vault key IPNS resolve returns 200 (not 404)
3. Compare IPNS resolve + IPFS fetch latency vs this baseline
4. Confirm root folder IPNS resolve is deferred to folder-load
5. Confirm auth/refresh race resolved — single refresh call observed on reload
