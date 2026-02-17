/**
 * CipherBox Desktop - Webview Entry Point
 *
 * On app start:
 * 1. Check for --dev-key mode (debug builds skip Core Kit entirely)
 * 2. Try silent refresh from Keychain-stored refresh token
 * 3. Initialize Core Kit and show CipherBox-branded login UI
 * 4. After auth completes, the Rust side has all keys -- app transitions to
 *    headless menu bar mode (webview window hides)
 *
 * The webview is only used for the auth flow. Once authenticated,
 * the app runs as a menu bar utility with FUSE mount.
 */

import './polyfills';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { initCoreKit, loginWithGoogle, requestEmailOtp, loginWithEmailOtp, logout } from './auth';

// CipherBox API base URL for dev-key test-login flow
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3000';

/**
 * Application initialization sequence.
 */
async function init(): Promise<void> {
  console.log('CipherBox Desktop initializing...');

  const appDiv = document.getElementById('app');

  // Show loading state
  if (appDiv) {
    appDiv.innerHTML = loadingHtml('Initializing CipherBox...');
  }

  // Step 1: Check for dev-key mode (debug builds)
  const devKey: string | null = await invoke('get_dev_key');
  if (devKey) {
    if (appDiv) {
      appDiv.innerHTML = loadingHtml('Dev mode: authenticating with provided key...');
    }
    try {
      await handleDevKeyAuth(devKey);
      handleAuthSuccess(appDiv);
      return;
    } catch (err) {
      console.error('Dev-key auth failed:', err);
      if (appDiv) {
        appDiv.innerHTML = errorHtml(
          err instanceof Error ? err.message : 'Dev-key authentication failed'
        );
      }
      return;
    }
  }

  // Step 2: Try silent refresh from Keychain
  try {
    const refreshed: boolean = await invoke('try_silent_refresh');
    if (refreshed) {
      console.log('API session refreshed from Keychain');
      // NOTE: Even with a refreshed API session, the private key is NOT
      // available on cold start. We still need Core Kit login to get
      // the private key for vault decryption.
    }
  } catch (err) {
    console.warn('Silent refresh failed:', err);
    // Not an error -- just means we need full login
  }

  // Step 3: Initialize Core Kit
  if (appDiv) {
    appDiv.innerHTML = loadingHtml('Connecting to CipherBox...');
  }

  try {
    await initCoreKit();
  } catch (err) {
    console.error('Core Kit initialization failed:', err);
    if (appDiv) {
      appDiv.innerHTML = errorHtml(
        err instanceof Error ? err.message : 'Failed to initialize authentication'
      );
    }
    return;
  }

  // Step 4: Show login form
  if (appDiv) {
    renderLoginForm(appDiv);
  }
}

/**
 * Render the CipherBox-branded login form with Google OAuth and Email OTP.
 */
function renderLoginForm(appDiv: HTMLElement): void {
  appDiv.innerHTML = `
    <div style="color: #d1d5db; font-family: 'Courier New', Courier, monospace; padding: 2rem; text-align: center; max-width: 340px; margin: 0 auto;">
      <div style="font-size: 1.25rem; margin-bottom: 0.25rem; color: #e5e7eb; letter-spacing: 0.1em;">CIPHERBOX</div>
      <div style="font-size: 0.75rem; color: #6b7280; margin-bottom: 1.5rem;">zero-knowledge encrypted storage</div>

      <div id="google-section" style="margin-bottom: 1rem;">
        <button id="google-btn" style="width: 100%; padding: 0.625rem 1rem; background: #1f2937; border: 1px solid #374151; color: #d1d5db; font-family: 'Courier New', Courier, monospace; font-size: 0.875rem; cursor: pointer; transition: border-color 0.15s;">
          [ sign in with Google ]
        </button>
      </div>

      <div style="color: #4b5563; margin: 0.75rem 0; font-size: 0.75rem;">// or</div>

      <div id="email-section">
        <input id="email-input" type="email" placeholder="email address"
          style="width: 100%; padding: 0.5rem; background: #111827; border: 1px solid #374151; color: #d1d5db; font-family: 'Courier New', Courier, monospace; font-size: 0.875rem; margin-bottom: 0.5rem; box-sizing: border-box; outline: none;" />
        <button id="email-btn" style="width: 100%; padding: 0.625rem 1rem; background: #1f2937; border: 1px solid #374151; color: #d1d5db; font-family: 'Courier New', Courier, monospace; font-size: 0.875rem; cursor: pointer; transition: border-color 0.15s;">
          [ send code ]
        </button>
      </div>

      <div id="otp-section" style="display: none;">
        <input id="otp-input" type="text" placeholder="enter 6-digit code" maxlength="6"
          style="width: 100%; padding: 0.5rem; background: #111827; border: 1px solid #374151; color: #d1d5db; font-family: 'Courier New', Courier, monospace; font-size: 0.875rem; margin-bottom: 0.5rem; box-sizing: border-box; outline: none; text-align: center; letter-spacing: 0.3em;" />
        <button id="otp-btn" style="width: 100%; padding: 0.625rem 1rem; background: #1f2937; border: 1px solid #374151; color: #d1d5db; font-family: 'Courier New', Courier, monospace; font-size: 0.875rem; cursor: pointer; transition: border-color 0.15s;">
          [ verify ]
        </button>
        <button id="back-btn" style="width: 100%; padding: 0.375rem 1rem; background: transparent; border: none; color: #6b7280; font-family: 'Courier New', Courier, monospace; font-size: 0.75rem; cursor: pointer; margin-top: 0.25rem;">
          back
        </button>
      </div>

      <div id="auth-status" style="margin-top: 1rem; font-size: 0.75rem; min-height: 1.25rem;"></div>
    </div>
  `;

  // Hover effects
  for (const btnId of ['google-btn', 'email-btn', 'otp-btn']) {
    const btn = document.getElementById(btnId);
    if (btn) {
      btn.addEventListener('mouseenter', () => {
        btn.style.borderColor = '#10b981';
      });
      btn.addEventListener('mouseleave', () => {
        btn.style.borderColor = '#374151';
      });
    }
  }

  // Focus effects for inputs
  for (const inputId of ['email-input', 'otp-input']) {
    const input = document.getElementById(inputId);
    if (input) {
      input.addEventListener('focus', () => {
        (input as HTMLInputElement).style.borderColor = '#10b981';
      });
      input.addEventListener('blur', () => {
        (input as HTMLInputElement).style.borderColor = '#374151';
      });
    }
  }

  // State for email flow
  let currentEmail = '';

  // Wire Google button
  const googleBtn = document.getElementById('google-btn');
  googleBtn?.addEventListener('click', async () => {
    setStatus('Connecting to Google...', '#9ca3af');
    disableButtons(true);
    try {
      const result = await loginWithGoogle();
      if (result.status === 'required_share') {
        renderRequiredShareUI(appDiv);
        return;
      }
      handleAuthSuccess(appDiv);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Google login failed', '#ef4444');
      disableButtons(false);
    }
  });

  // Wire Email OTP - send code
  const emailBtn = document.getElementById('email-btn');
  emailBtn?.addEventListener('click', async () => {
    const emailInput = document.getElementById('email-input') as HTMLInputElement;
    const email = emailInput?.value?.trim();
    if (!email || !email.includes('@')) {
      setStatus('Please enter a valid email address', '#ef4444');
      return;
    }
    currentEmail = email;
    setStatus('Sending code...', '#9ca3af');
    disableButtons(true);
    try {
      await requestEmailOtp(email);
      // Show OTP input section
      const emailSection = document.getElementById('email-section');
      const otpSection = document.getElementById('otp-section');
      if (emailSection) emailSection.style.display = 'none';
      if (otpSection) otpSection.style.display = 'block';
      setStatus('Code sent to ' + email, '#9ca3af');
      disableButtons(false);
      // Focus OTP input
      document.getElementById('otp-input')?.focus();
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to send code', '#ef4444');
      disableButtons(false);
    }
  });

  // Wire OTP verify
  const otpBtn = document.getElementById('otp-btn');
  otpBtn?.addEventListener('click', async () => {
    const otpInput = document.getElementById('otp-input') as HTMLInputElement;
    const otp = otpInput?.value?.trim();
    if (!otp || otp.length < 4) {
      setStatus('Please enter the verification code', '#ef4444');
      return;
    }
    setStatus('Verifying...', '#9ca3af');
    disableButtons(true);
    try {
      const result = await loginWithEmailOtp(currentEmail, otp);
      if (result.status === 'required_share') {
        renderRequiredShareUI(appDiv);
        return;
      }
      handleAuthSuccess(appDiv);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Verification failed', '#ef4444');
      disableButtons(false);
    }
  });

  // Wire back button
  const backBtn = document.getElementById('back-btn');
  backBtn?.addEventListener('click', () => {
    const emailSection = document.getElementById('email-section');
    const otpSection = document.getElementById('otp-section');
    if (emailSection) emailSection.style.display = 'block';
    if (otpSection) otpSection.style.display = 'none';
    setStatus('', '#9ca3af');
  });

  // Allow Enter key submission on inputs
  document.getElementById('email-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') emailBtn?.click();
  });
  document.getElementById('otp-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') otpBtn?.click();
  });
}

/**
 * Show stub UI for MFA REQUIRED_SHARE status.
 * Users with MFA enabled on a new device see this. Full MFA UI in Plan 05.
 */
function renderRequiredShareUI(appDiv: HTMLElement): void {
  appDiv.innerHTML = `
    <div style="color: #d1d5db; font-family: 'Courier New', Courier, monospace; padding: 2rem; text-align: center; max-width: 340px; margin: 0 auto;">
      <div style="font-size: 1.25rem; margin-bottom: 0.25rem; color: #e5e7eb; letter-spacing: 0.1em;">CIPHERBOX</div>
      <div style="font-size: 0.75rem; color: #6b7280; margin-bottom: 1.5rem;">device verification required</div>

      <div style="background: #1f2937; border: 1px solid #374151; padding: 1.25rem; text-align: left; font-size: 0.8rem; line-height: 1.6;">
        <div style="color: #f59e0b; margin-bottom: 0.75rem;">MFA is enabled on your account.</div>
        <div style="color: #9ca3af;">This device needs to be verified before you can access your vault.</div>
        <div style="color: #9ca3af; margin-top: 0.75rem;">Options:</div>
        <div style="color: #d1d5db; margin-top: 0.25rem; padding-left: 1rem;">
          1. Approve from an existing device<br/>
          2. Enter your recovery phrase
        </div>
        <div style="color: #6b7280; margin-top: 0.75rem; font-size: 0.7rem;">
          (Full MFA verification coming in a future update)
        </div>
      </div>

      <button id="mfa-logout-btn" style="margin-top: 1rem; padding: 0.5rem 1rem; background: transparent; border: 1px solid #374151; color: #6b7280; font-family: 'Courier New', Courier, monospace; font-size: 0.75rem; cursor: pointer;">
        [ back to login ]
      </button>
    </div>
  `;

  document.getElementById('mfa-logout-btn')?.addEventListener('click', async () => {
    try {
      await logout();
    } catch (err) {
      console.warn('Logout during MFA failed:', err);
    }
    location.reload();
  });
}

/**
 * Handle successful authentication -- show success message and hide window.
 */
function handleAuthSuccess(appDiv: HTMLElement | null): void {
  if (appDiv) {
    appDiv.innerHTML = `
      <div style="color: #10b981; font-family: 'Courier New', Courier, monospace; padding: 2rem; text-align: center;">
        <div style="font-size: 1rem; margin-bottom: 0.5rem;">authenticated</div>
        <div style="font-size: 0.75rem; color: #6b7280;">CipherBox is running in the menu bar.</div>
      </div>
    `;
  }

  // Give user a moment to see the success message, then hide window
  setTimeout(async () => {
    try {
      const window = getCurrentWindow();
      await window.hide();
    } catch (err) {
      console.warn('Failed to hide window:', err);
    }
  }, 1500);
}

/**
 * Handle dev-key authentication (debug builds only).
 *
 * Uses the backend's test-login endpoint to get a JWT and then calls
 * handle_auth_complete directly with the dev key, bypassing Core Kit entirely.
 */
async function handleDevKeyAuth(devKeyHex: string): Promise<void> {
  // Use the test-login endpoint to get a JWT and keypair
  const testLoginSecret = import.meta.env.VITE_TEST_LOGIN_SECRET || '';
  if (!testLoginSecret) {
    // Fall back to direct invoke with a synthetic approach
    console.warn('No TEST_LOGIN_SECRET configured, attempting direct dev-key auth');
  }

  const resp = await fetch(`${API_BASE}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'dev-key@cipherbox.local',
      secret: testLoginSecret,
    }),
  });

  if (!resp.ok) {
    throw new Error(`Test-login failed (${resp.status}). Is TEST_LOGIN_SECRET configured?`);
  }

  const data = await resp.json();

  // Call handle_auth_complete with the test JWT and dev key
  await invoke('handle_auth_complete', {
    idToken: data.idToken,
    privateKey: devKeyHex,
  });
}

// --- Helper functions ---

function setStatus(message: string, color: string): void {
  const el = document.getElementById('auth-status');
  if (el) {
    el.textContent = message;
    el.style.color = color;
  }
}

function disableButtons(disabled: boolean): void {
  for (const id of ['google-btn', 'email-btn', 'otp-btn']) {
    const btn = document.getElementById(id) as HTMLButtonElement | null;
    if (btn) {
      btn.disabled = disabled;
      btn.style.opacity = disabled ? '0.5' : '1';
      btn.style.cursor = disabled ? 'default' : 'pointer';
    }
  }
}

function loadingHtml(message: string): string {
  return `<div style="color: #9ca3af; font-family: 'Courier New', Courier, monospace; padding: 2rem; text-align: center;">${message}</div>`;
}

function errorHtml(message: string): string {
  return `<div style="color: #ef4444; font-family: 'Courier New', Courier, monospace; padding: 2rem; text-align: center;">
    Failed to initialize authentication.<br/>
    <small style="color: #9ca3af;">${message}</small><br/><br/>
    <button onclick="location.reload()" style="color: #9ca3af; background: #1f2937; border: 1px solid #374151; padding: 0.5rem 1rem; cursor: pointer; font-family: 'Courier New', Courier, monospace;">
      [ retry ]
    </button>
  </div>`;
}

// Start the app
init().catch((err) => {
  console.error('CipherBox Desktop initialization error:', err);
});
