<!-- generated-by: gsd-doc-writer -->

# CipherBox E2E Tests

End-to-end tests for CipherBox using Playwright.

## Setup

1. Install dependencies:

   ```bash
   pnpm install
   ```

2. Install Playwright browsers:

   ```bash
   pnpm exec playwright install
   ```

3. Configure environment (optional):

   ```bash
   cp .env.example .env
   # Edit .env with your test configuration
   ```

## Running Tests

### All tests

```bash
pnpm test
```

### Specific test file

```bash
pnpm test tests/wallet-login.spec.ts
```

### Single browser

```bash
pnpm test --project=chromium
```

### Headed mode (visible browser)

```bash
pnpm test:headed
```

### Debug mode

```bash
pnpm test:debug
```

### View last report

```bash
pnpm test:report
```

## Test Structure

```text
tests/web-e2e/
├── fixtures/              # Static test assets
│   └── files/             # Sample files for upload tests (images, PDFs, video, audio)
├── page-objects/          # Page Object Model classes
│   ├── login.page.ts      # Login page interactions
│   ├── base.page.ts       # Base page helpers
│   ├── dialogs/           # Dialog page objects
│   ├── file-browser/      # File browser page objects
│   └── pages/             # Other page objects
├── tests/                 # Test specs (flat, no subdirectories)
│   ├── wallet-login.spec.ts
│   ├── full-workflow.spec.ts
│   ├── sharing-workflow.spec.ts
│   ├── mfa-flows.spec.ts
│   ├── recovery.spec.ts
│   ├── search-workflow.spec.ts
│   ├── recycle-bin.spec.ts
│   ├── conflict-detection.spec.ts
│   ├── batch-download.spec.ts
│   ├── writable-shares.spec.ts
│   ├── invite-link-workflow.spec.ts
│   ├── media-preview.spec.ts
│   ├── streaming-playback.spec.ts
│   └── journey-timing.spec.ts
├── utils/                 # Test utilities
│   ├── wallet-login-helpers.ts  # Mock wallet setup and login helpers
│   ├── api-helpers.ts           # API-level helpers
│   ├── cleanup-helpers.ts       # Account/data cleanup helpers
│   ├── conflict-helpers.ts      # Conflict scenario helpers
│   ├── mfa-helpers.ts           # MFA flow helpers
│   ├── multi-account-wallet.ts  # Multi-account wallet setup
│   └── test-files.ts            # Test file references
└── playwright.config.ts   # Playwright configuration
```

## Authentication in Tests

### Mock Wallet Pattern

Tests authenticate using `@johanneskares/wallet-mock`, which installs an EIP-6963 mock
provider in the browser. This avoids any real Web3Auth modal interaction and works fully
headless in CI.

Each test suite that requires authentication calls `setupMockWallet()` before navigating:

```typescript
import { setupMockWallet, createTestAccount } from '../utils/wallet-login-helpers';

const account = createTestAccount(); // generates a random private key

test.beforeAll(async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await setupMockWallet(page, account); // must be called before navigation
  await page.goto('/');
});
```

For deterministic tests (e.g., wallet login flow), a well-known Hardhat account key is
used instead of a random key.

### No Storage State

There is no global setup or stored `.auth/user.json` state. Each test suite sets up its
own wallet-authenticated session from scratch using the mock wallet.

## CI Integration

E2E tests run automatically on GitHub Actions for every push and pull request to `main`.

### CI Workflow

The E2E workflow (`.github/workflows/web-e2e.yml`):

1. Starts PostgreSQL and IPFS services
2. Installs dependencies and Playwright browsers
3. Builds all packages
4. Runs E2E tests in headless Chromium
5. Uploads test artifacts (reports, videos, screenshots) on failure

### CI Environment

- **Authentication**: All tests use the mock wallet — no manual Web3Auth interaction required
- **Services**: PostgreSQL and IPFS run as Docker containers
- **Parallelism**: Tests run sequentially (`workers: 1`) to share a single browser session

### Running Tests Locally Like CI

```bash
# Set CI environment variable
CI=true pnpm test
```

This will:

- Use HTML reporter (instead of interactive list)
- Fail if any tests are marked `.only`
- Always start a fresh dev server (never reuses an existing one)

## Notes

- **Chromium only**: Tests target Desktop Chrome; other browsers are not configured
- **Sequential execution**: `fullyParallel: false`, `workers: 1` — tests run one at a time
- **No retries**: Flakiness is fixed at the source, not masked with retries
- **External target**: Set `BASE_URL` to a staging/production URL to skip local server startup
- **Protected Routes**: Dashboard and file browser routes require wallet authentication

## Troubleshooting

### Mock Wallet Not Detected

`setupMockWallet()` must be called before any `page.goto()`. If the wallet is not detected,
ensure the call order in `beforeAll`/`beforeEach` is correct.

### Web App Not Starting

- Verify `pnpm install` has been run at the monorepo root
- Check that ports 3000 (API), 3001 (mock IPNS routing), and 5173 (web) are free
- The mock IPNS routing service must be built first: `pnpm build` from the workspace root

### Tests Timing Out

- Increase timeout in `playwright.config.ts`
- Check that the backend API is running and accessible at `http://localhost:3000`
- For CI, verify the `web-e2e.yml` workflow services started successfully
