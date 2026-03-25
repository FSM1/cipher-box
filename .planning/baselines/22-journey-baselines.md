# Performance Baselines - Phase 22 (Journey Timing)

> End-to-end user journey timing captured via Playwright with real browser rendering.
> Timings include network, crypto, IPFS operations, and browser paint.

## Capture Information

| Field            | Value                                                        |
| ---------------- | ------------------------------------------------------------ |
| **Capture Date** | 2026-03-25                                                   |
| **Environment**  | Staging (api-staging.cipherbox.cc, app-staging.cipherbox.cc) |
| **Browser**      | Chromium (Playwright managed, headless)                      |
| **Auth Method**  | Mock wallet (EIP-1193 via @johanneskares/wallet-mock)        |
| **Test File**    | `tests/web-e2e/tests/journey-timing.spec.ts`                 |
| **API Version**  | v0.27.0 (staging-cipher-box-v0.27.0-rc-1)                    |
| **VPS**          | 4 vCPU, 8GB RAM (Hostinger)                                  |

## Journey 1: Login-to-Vault

Measures wall-clock time from clicking the wallet login button through vault metadata loading and file list rendering.

| Phase           | Duration |
| --------------- | -------- |
| **Wallet Auth** | 23,483ms |
| **Vault Load**  | 86ms     |
| **Total**       | 23,569ms |

Includes: Core Kit initialization wait, mock wallet connect, SIWE signature, backend JWT exchange, vault metadata IPNS resolve, file list React render.

**Note:** Wallet auth dominates at 99.6% of total time. This is Web3Auth Core Kit MPC initialization + Sapphire Devnet DKG key generation for a brand-new identity. Repeat logins (existing identity) are expected to be significantly faster (5-10s).

## Journey 2: Upload-to-Visible

Measures wall-clock time from file input selection through the file appearing in the file list UI.

| Metric             | Value   |
| ------------------ | ------- |
| **File Size**      | 100KB   |
| **Total Duration** | 1,355ms |

Includes: AES-256-GCM encryption, IPFS ciphertext upload (pin), IPFS metadata upload (pin), IPNS file publish, folder metadata update, IPNS folder publish, React state update, file list re-render.

## Journey 3: Share-to-Accessible

Measures wall-clock time from Alice initiating a share through Bob seeing the shared item in the Shared section.

| Phase                      | Duration |
| -------------------------- | -------- |
| **Share Create (Alice)**   | 2,236ms  |
| **Recipient Access (Bob)** | 803ms    |
| **Total**                  | 3,039ms  |

Includes: ECIES key wrapping for recipient, share key API call, share dialog UI interaction, Bob's navigation to Shared section, share list API fetch, shared item rendering.

## Raw Data

```text
JOURNEY_TIMING: {"journey":"login-to-vault","totalMs":23569,"phases":{"walletAuthMs":23483,"vaultLoadMs":86}}
JOURNEY_TIMING: {"journey":"upload-to-visible","totalMs":1355,"fileSizeBytes":102400}
JOURNEY_TIMING: {"journey":"share-to-accessible","totalMs":3039,"phases":{"shareCreateMs":2236,"recipientAccessMs":803}}
JOURNEY_TIMING: {"summary":true,"capturedAt":"2026-03-25T02:58:23.753Z","journeys":[{"journey":"login-to-vault","totalMs":23569,"phases":{"walletAuthMs":23483,"vaultLoadMs":86}},{"journey":"upload-to-visible","totalMs":1355,"fileSizeBytes":102400},{"journey":"share-to-accessible","totalMs":3039,"phases":{"shareCreateMs":2236,"recipientAccessMs":803}}]}
```

## How to Recapture

Run the journey timing tests against staging:

```bash
cd tests/web-e2e && npx playwright test journey-timing.spec.ts --config /tmp/pw-staging.config.ts
```

Or against localhost with API + frontend running:

```bash
cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts
```

The test outputs structured JSON on each line prefixed with `JOURNEY_TIMING:`. The final summary line contains all journey results in a single JSON object.
