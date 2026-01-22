import { FullConfig } from '@playwright/test';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

// ESM compatibility - __dirname is not available in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Playwright global setup.
 * Runs once before all tests to prepare the test environment.
 *
 * For E2E tests, this ensures authentication state placeholder exists
 * so tests don't fail immediately. In CI, actual authenticated tests
 * are skipped since they require manual Web3Auth interaction.
 */
async function globalSetup(_config: FullConfig): Promise<void> {
  console.log('Running global setup...');

  const authStateFile = resolve(__dirname, '.auth/user.json');
  const authDir = dirname(authStateFile);

  // Ensure .auth directory exists
  if (!existsSync(authDir)) {
    mkdirSync(authDir, { recursive: true });
    console.log('Created .auth directory');
  }

  // If auth state doesn't exist, create a placeholder
  // This prevents fixture errors while still allowing unauthenticated tests to run
  if (!existsSync(authStateFile)) {
    console.log('Auth state not found, creating placeholder...');

    // Create minimal storage state placeholder
    const placeholderState = {
      cookies: [],
      origins: [],
    };

    writeFileSync(authStateFile, JSON.stringify(placeholderState, null, 2));
    console.log(`Placeholder auth state created at ${authStateFile}`);
    console.log(
      'NOTE: Authenticated tests will be skipped. To run them, perform manual login once.'
    );
  } else {
    console.log('Auth state found, authenticated tests will use existing state');
  }

  console.log('Global setup complete');
}

export default globalSetup;
