import { FullConfig, chromium } from '@playwright/test';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';

// ESM compatibility - __dirname is not available in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
config({ path: resolve(__dirname, '.env') });

/**
 * Playwright global setup.
 * Runs once before all tests to prepare the test environment.
 *
 * If Web3Auth test credentials are available, performs automated login
 * and saves the authentication state for use by all tests.
 */
async function globalSetup(config: FullConfig): Promise<void> {
  console.log('Running global setup...');

  const authStateFile = resolve(__dirname, '.auth/user.json');
  const authDir = dirname(authStateFile);

  // Ensure .auth directory exists
  if (!existsSync(authDir)) {
    mkdirSync(authDir, { recursive: true });
    console.log('Created .auth directory');
  }

  const testEmail = process.env.WEB3AUTH_TEST_EMAIL;
  const testOtp = process.env.WEB3AUTH_TEST_OTP;

  // If test credentials are available, perform automated login
  if (testEmail && testOtp) {
    console.log('Test credentials found, performing automated login...');
    console.log(`Using test email: ${testEmail}`);

    try {
      await performAutomatedLogin(config, authStateFile, testEmail, testOtp);
      console.log('Automated login successful, auth state saved');
    } catch (error) {
      console.error('Automated login failed:', error);
      console.log('Creating placeholder auth state, some tests may be skipped');
      createPlaceholderAuthState(authStateFile);
    }
  } else {
    console.log('No test credentials found (WEB3AUTH_TEST_EMAIL, WEB3AUTH_TEST_OTP)');

    if (!existsSync(authStateFile)) {
      console.log('Creating placeholder auth state...');
      createPlaceholderAuthState(authStateFile);
      console.log('NOTE: Authenticated tests will be skipped without valid credentials');
    } else {
      console.log('Using existing auth state');
    }
  }

  console.log('Global setup complete');
}

/**
 * Performs automated login using Web3Auth test credentials.
 */
async function performAutomatedLogin(
  config: FullConfig,
  authStateFile: string,
  email: string,
  otp: string
): Promise<void> {
  const baseURL = config.projects[0]?.use?.baseURL || 'http://localhost:5173';

  // Launch browser for login
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Navigate to login page
    await page.goto(baseURL);
    console.log('Navigated to login page');

    // Click Sign In button
    await page.click('button:has-text("Sign In")');
    console.log('Clicked Sign In button');

    // Wait for Web3Auth modal (can be iframe-based or direct DOM)
    await Promise.race([
      page.waitForSelector('iframe[id*="w3a"]', { timeout: 15000 }).catch(() => null),
      page
        .waitForSelector('button:has-text("Continue with Email")', { timeout: 15000 })
        .catch(() => null),
      page
        .waitForSelector(':text("Continue with Email/Phone")', { timeout: 15000 })
        .catch(() => null),
    ]);
    console.log('Web3Auth modal appeared');

    // Click the "Continue with Email/Phone" button to reveal the email input
    const emailPhoneButton = page.locator(
      'button:has-text("Continue with Email"), :text("Continue with Email/Phone")'
    );
    await emailPhoneButton.first().waitFor({ state: 'visible', timeout: 10000 });
    await emailPhoneButton.first().click();
    console.log('Clicked Continue with Email/Phone button');

    // Wait for email input to appear after clicking the button
    const emailInput = page.locator(
      'input[placeholder*="@example.com"], input[placeholder*="email" i], input[type="email"], input[type="text"]'
    );
    await emailInput.first().waitFor({ state: 'visible', timeout: 10000 });

    // Fill the email input
    await emailInput.first().fill(email);
    console.log('Entered email');

    // Press Enter to submit
    await page.keyboard.press('Enter');
    console.log('Submitted email, waiting for OTP screen...');

    // Wait a moment for the form to process
    await page.waitForTimeout(2000);

    // Wait for OTP input and enter code
    const otpInput = page.locator(
      'input[type="tel"], input[inputmode="numeric"], input[autocomplete="one-time-code"], input[maxlength="1"]'
    );
    await otpInput.first().waitFor({ state: 'visible', timeout: 15000 });
    console.log('OTP input appeared');

    // Check for multiple inputs (one per digit) or single input
    const multipleInputs = page.locator('input[maxlength="1"]');
    const multipleCount = await multipleInputs.count();

    if (multipleCount >= 4) {
      // Multiple input fields
      for (let i = 0; i < otp.length && i < multipleCount; i++) {
        await multipleInputs.nth(i).fill(otp[i]);
      }
    } else {
      // Single input
      const singleInput = page.locator(
        'input[type="tel"], input[inputmode="numeric"], input[autocomplete="one-time-code"]'
      );
      await singleInput.first().fill(otp);
    }
    console.log('Entered OTP code');

    // Click verify if button exists
    const verifyButton = page.locator(
      'button:has-text("Verify"), button:has-text("Submit"), button:has-text("Confirm"), button[type="submit"]'
    );
    if ((await verifyButton.count()) > 0) {
      await verifyButton.first().click();
      console.log('Clicked verify button');
    }

    // Wait for redirect to dashboard
    await page.waitForURL('**/dashboard', { timeout: 60000 });
    console.log('Login successful, redirected to dashboard');

    // Wait a moment for any additional state to settle
    await page.waitForTimeout(2000);

    // Save storage state
    const storageState = await context.storageState();
    writeFileSync(authStateFile, JSON.stringify(storageState, null, 2));
    console.log(`Auth state saved to ${authStateFile}`);
  } finally {
    await browser.close();
  }
}

/**
 * Creates a placeholder auth state file.
 */
function createPlaceholderAuthState(authStateFile: string): void {
  const placeholderState = {
    cookies: [],
    origins: [],
  };
  writeFileSync(authStateFile, JSON.stringify(placeholderState, null, 2));
}

export default globalSetup;
