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
pnpm test tests/auth/login.spec.ts
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

### UI mode (interactive)

```bash
pnpm test:ui
```

## Test Structure

```
tests/e2e/
├── fixtures/          # Test fixtures
│   └── auth.fixture.ts    # Authenticated session fixture
├── tests/             # Test specs
│   └── auth/
│       ├── login.spec.ts   # Login flow tests
│       ├── logout.spec.ts  # Logout flow tests
│       └── session.spec.ts # Session persistence tests
├── utils/             # Test utilities
│   └── web3auth-helpers.ts # Web3Auth interaction helpers
└── playwright.config.ts    # Playwright configuration
```

## Authentication in Tests

### Storage State Pattern

Most tests use the **storage state pattern** for fast, reliable authentication:

1. **First run**: Perform manual login once to generate auth state
2. **Subsequent runs**: Tests load saved auth state (fast, no Web3Auth interaction)

### Setting up Auth State

#### Option 1: Manual Login (Interactive)

Run a test that requires authentication and complete the Web3Auth flow manually:

```bash
pnpm test:headed tests/auth/login.spec.ts
```

This will generate `.auth/user.json` with your authenticated session.

#### Option 2: CI Setup

For CI environments, auth state should be pre-generated and made available to tests. This can be done via:

- Storing auth state as a CI secret
- Using API-based test authentication endpoint
- Programmatic Web3Auth authentication

### Using Authenticated Tests

```typescript
import { authenticatedTest } from '../fixtures/auth.fixture';

authenticatedTest('my test', async ({ authenticatedPage }) => {
  // Page is already authenticated and on dashboard
  await authenticatedPage.click('button');
});
```

## CI Integration

E2E tests run automatically on GitHub Actions for every push and pull request to `main`.

### CI Workflow

The E2E workflow (`.github/workflows/e2e.yml`):

1. Starts PostgreSQL and IPFS services
2. Installs dependencies and Playwright browsers
3. Builds all packages
4. Runs E2E tests in headless Chromium
5. Uploads test artifacts (reports, videos, screenshots) on failure

### CI Environment

- **Authentication**: Global setup creates placeholder auth state for CI
- **Authenticated tests**: Skipped in CI (require manual Web3Auth interaction)
- **Unauthenticated tests**: Run fully automated (login page, redirects, etc.)
- **Services**: PostgreSQL and IPFS run as Docker containers

### Running Tests Locally Like CI

```bash
# Set CI environment variable
CI=true pnpm test
```

This will:

- Use HTML reporter (instead of interactive list)
- Fail if any tests are marked `.only`
- Never reuse existing dev server (always starts fresh)

## Notes

- **Web3Auth Modal Tests**: Tests that interact with the Web3Auth modal may be flaky and are skipped in CI
- **Protected Routes**: Dashboard and Settings routes require authentication
- **Logout**: Clears all session data and redirects to login page
- **Session Persistence**: Auth state persists across page reloads via cookies and localStorage

## Troubleshooting

### "Authentication state not found" Error

This means you need to set up auth state first. Run an interactive test or generate auth state using the setup process.

### Web3Auth Modal Not Appearing

- Check that the web app is running (`pnpm dev` in workspace root)
- Verify Web3Auth client ID is configured
- Try running in headed mode to see what's happening

### Tests Timing Out

- Increase timeout in `playwright.config.ts`
- Check that backend API is running and accessible
- Verify network connectivity to Web3Auth services
