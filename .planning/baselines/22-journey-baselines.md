# Performance Baselines - Phase 22 (Journey Timing)

> End-to-end user journey timing captured via Playwright with real browser rendering.
> Timings include network, crypto, IPFS operations, and browser paint.

## Capture Information

| Field            | Value                                                      |
| ---------------- | ---------------------------------------------------------- |
| **Capture Date** | [PENDING - fill after test run]                            |
| **Environment**  | Local (localhost:3000 API, localhost:5173 frontend)        |
| **Browser**      | Chromium (Playwright managed)                              |
| **Auth Method**  | Mock wallet (instant auth, no Web3Auth latency)            |
| **Test File**    | `tests/web-e2e/tests/journey-timing.spec.ts`               |
| **Note**         | Real-world login adds 5-15s (Web3Auth network round-trips) |

## Journey 1: Login-to-Vault

Measures wall-clock time from clicking the wallet login button through vault metadata loading and file list rendering.

| Phase           | Duration    |
| --------------- | ----------- |
| **Wallet Auth** | [PENDING]ms |
| **Vault Load**  | [PENDING]ms |
| **Total**       | [PENDING]ms |

Includes: Core Kit initialization wait, mock wallet connect, SIWE signature, backend JWT exchange, vault metadata IPNS resolve, file list React render.

**Note:** Mock wallet eliminates real Web3Auth latency (5-15s). Actual user-facing login will be significantly slower.

## Journey 2: Upload-to-Visible

Measures wall-clock time from file input selection through the file appearing in the file list UI.

| Metric             | Value       |
| ------------------ | ----------- |
| **File Size**      | 100KB       |
| **Total Duration** | [PENDING]ms |

Includes: AES-256-GCM encryption, IPFS ciphertext upload (pin), IPFS metadata upload (pin), IPNS file publish, folder metadata update, IPNS folder publish, React state update, file list re-render.

## Journey 3: Share-to-Accessible

Measures wall-clock time from Alice initiating a share through Bob seeing the shared item in the Shared section.

| Phase                      | Duration    |
| -------------------------- | ----------- |
| **Share Create (Alice)**   | [PENDING]ms |
| **Recipient Access (Bob)** | [PENDING]ms |
| **Total**                  | [PENDING]ms |

Includes: ECIES key wrapping for recipient, share key API call, share dialog UI interaction, Bob's navigation to Shared section, share list API fetch, shared item rendering.

**Note:** If multi-account sharing fails (flaky in E2E due to IPNS propagation), partial results are recorded with an explanatory note.

## Comparison with SDK-Level Timings

Journey timings will be higher than SDK-level timings (from Plan 01) because they include:

- Browser rendering and paint
- React state updates and re-renders
- Navigation and URL changes
- Network proxy overhead (Playwright -> browser -> API)
- UI interaction latency (click handlers, modal transitions)

The delta between journey timing and SDK timing represents the "UI tax" -- overhead from the web application layer.

## How to Capture

Run the journey timing tests with API + frontend running:

```bash
# Start API and frontend first (if not already running)
pnpm --filter @cipherbox/api dev &
pnpm --filter @cipherbox/web dev &

# Run journey timing tests
cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts

# Capture output lines starting with JOURNEY_TIMING:
cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts 2>&1 | grep "JOURNEY_TIMING:"
```

The test outputs structured JSON on each line prefixed with `JOURNEY_TIMING:`. The final summary line contains all journey results in a single JSON object.

Example output:

```json
JOURNEY_TIMING: {"journey":"login-to-vault","totalMs":4523,"phases":{"walletAuthMs":3100,"vaultLoadMs":1423}}
JOURNEY_TIMING: {"journey":"upload-to-visible","totalMs":2847,"fileSizeBytes":102400}
JOURNEY_TIMING: {"journey":"share-to-accessible","totalMs":8921,"phases":{"shareCreateMs":3456,"recipientAccessMs":5465}}
JOURNEY_TIMING: {"summary":true,"capturedAt":"2026-03-25T...","journeys":[...]}
```

## Historical Comparison

Once captured, compare with SDK-level baselines from Plan 01 to quantify the UI overhead:

| Journey        | SDK Timing (Plan 01) | E2E Timing (this) | UI Overhead |
| -------------- | -------------------- | ----------------- | ----------- |
| Upload (100KB) | [PENDING]            | [PENDING]         | [PENDING]   |
