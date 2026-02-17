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
import {
  initCoreKit,
  loginWithGoogle,
  loginWithWallet,
  requestEmailOtp,
  loginWithEmailOtp,
  logout,
  inputRecoveryPhrase,
  requestDeviceApproval,
  pollApprovalStatus,
  cancelApprovalRequest,
} from './auth';

// TODO (Phase 11.2): Add approval listener after auth success to poll for
// pending approval requests and show native notification when approval needed.

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
  const font = "'JetBrains Mono', 'Courier New', monospace";
  const btnStyle = `width: 100%; padding: 0.625rem 1rem; background: #001108; border: 1px solid #003322; color: #00D084; font-family: ${font}; font-size: 0.875rem; cursor: pointer; transition: border-color 0.15s;`;
  const inputStyle = `width: 100%; padding: 0.5rem; background: #000000; border: 1px solid #003322; color: #00D084; font-family: ${font}; font-size: 0.875rem; margin-bottom: 0.5rem; box-sizing: border-box; outline: none;`;

  appDiv.innerHTML = `
    <div style="color: #00D084; font-family: ${font}; padding: 2rem; text-align: center; max-width: 340px; margin: 0 auto;">
      <div style="font-size: 1.25rem; margin-bottom: 0.25rem; letter-spacing: 0.1em;"><span style="color: #006644;">&gt; </span><span style="color: #00D084;">CIPHERBOX</span></div>
      <div style="font-size: 0.75rem; color: #006644; margin-bottom: 1.5rem;">zero-knowledge encrypted storage</div>

      <div id="google-section" style="margin-bottom: 0.5rem;">
        <button id="google-btn" style="${btnStyle}">
          [ sign in with Google ]
        </button>
      </div>

      <div id="wallet-section" style="margin-bottom: 1rem;">
        <button id="wallet-btn" style="${btnStyle}">
          [ connect wallet ]
        </button>
      </div>

      <div style="color: #006644; margin: 0.75rem 0; font-size: 0.75rem;">// or</div>

      <div id="email-section">
        <input id="email-input" type="email" placeholder="email address"
          style="${inputStyle}" />
        <button id="email-btn" style="${btnStyle}">
          [ send code ]
        </button>
      </div>

      <div id="otp-section" style="display: none;">
        <input id="otp-input" type="text" placeholder="enter 6-digit code" maxlength="6"
          style="${inputStyle} text-align: center; letter-spacing: 0.3em;" />
        <button id="otp-btn" style="${btnStyle}">
          [ verify ]
        </button>
        <button id="back-btn" style="width: 100%; padding: 0.375rem 1rem; background: transparent; border: none; color: #006644; font-family: ${font}; font-size: 0.75rem; cursor: pointer; margin-top: 0.25rem;">
          back
        </button>
      </div>

      <div id="auth-status" style="margin-top: 1rem; font-size: 0.75rem; min-height: 1.25rem;"></div>
    </div>
  `;

  // Hover effects
  for (const btnId of ['google-btn', 'wallet-btn', 'email-btn', 'otp-btn']) {
    const btn = document.getElementById(btnId);
    if (btn) {
      btn.addEventListener('mouseenter', () => {
        btn.style.borderColor = '#00D084';
      });
      btn.addEventListener('mouseleave', () => {
        btn.style.borderColor = '#003322';
      });
    }
  }

  // Focus effects for inputs
  for (const inputId of ['email-input', 'otp-input']) {
    const input = document.getElementById(inputId);
    if (input) {
      input.addEventListener('focus', () => {
        (input as HTMLInputElement).style.borderColor = '#00D084';
      });
      input.addEventListener('blur', () => {
        (input as HTMLInputElement).style.borderColor = '#003322';
      });
    }
  }

  // State for email flow
  let currentEmail = '';

  // Wire Google button
  const googleBtn = document.getElementById('google-btn');
  googleBtn?.addEventListener('click', async () => {
    setStatus('Connecting to Google...', '#006644');
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

  // Wire Wallet button
  const walletBtn = document.getElementById('wallet-btn');
  walletBtn?.addEventListener('click', async () => {
    setStatus('Connecting wallet...', '#006644');
    disableButtons(true);
    try {
      const result = await loginWithWallet();
      if (result.status === 'required_share') {
        renderRequiredShareUI(appDiv);
        return;
      }
      handleAuthSuccess(appDiv);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Wallet login failed', '#ef4444');
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
    setStatus('Sending code...', '#006644');
    disableButtons(true);
    try {
      await requestEmailOtp(email);
      // Show OTP input section
      const emailSection = document.getElementById('email-section');
      const otpSection = document.getElementById('otp-section');
      if (emailSection) emailSection.style.display = 'none';
      if (otpSection) otpSection.style.display = 'block';
      setStatus('Code sent to ' + email, '#006644');
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
    setStatus('Verifying...', '#006644');
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
    setStatus('', '#006644');
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
 * MFA REQUIRED_SHARE UI with two recovery paths:
 * 1. Enter Recovery Phrase -- textarea for 24-word mnemonic
 * 2. Request Device Approval -- creates bulletin board request and polls
 *
 * After either path succeeds, auth completes normally (TSS key export +
 * Rust handoff happens inside the auth.ts MFA functions).
 */
function renderRequiredShareUI(appDiv: HTMLElement): void {
  const font = "'JetBrains Mono', 'Courier New', monospace";
  const btnStyle = [
    'width: 100%',
    'padding: 0.625rem 1rem',
    'background: #001108',
    'border: 1px solid #003322',
    'color: #00D084',
    `font-family: ${font}`,
    'font-size: 0.875rem',
    'cursor: pointer',
    'transition: border-color 0.15s',
  ].join('; ');

  appDiv.innerHTML = `
    <div style="color: #00D084; font-family: ${font}; padding: 2rem; text-align: center; max-width: 380px; margin: 0 auto;">
      <div style="font-size: 1.25rem; margin-bottom: 0.25rem; letter-spacing: 0.1em;"><span style="color: #006644;">&gt; </span><span style="color: #00D084;">CIPHERBOX</span></div>
      <div style="font-size: 0.75rem; color: #006644; margin-bottom: 1rem;">device verification required</div>

      <div style="color: #f59e0b; font-size: 0.8rem; margin-bottom: 1rem;">
        MFA is enabled. This device needs a second factor.
      </div>

      <div style="margin-bottom: 0.5rem;">
        <button id="recovery-btn" style="${btnStyle}">
          [ enter recovery phrase ]
        </button>
      </div>

      <div style="margin-bottom: 1rem;">
        <button id="approval-btn" style="${btnStyle}">
          [ request device approval ]
        </button>
      </div>

      <div id="recovery-form" style="display: none; text-align: left; margin-top: 1rem;">
        <div style="font-size: 0.75rem; color: #006644; margin-bottom: 0.5rem;">
          Enter your 24-word recovery phrase:
        </div>
        <textarea id="mnemonic-input" rows="3"
          placeholder="word1 word2 word3 ..."
          style="width: 100%; background: #000000; border: 1px solid #003322; color: #00D084; font-family: ${font}; font-size: 0.8rem; padding: 0.5rem; box-sizing: border-box; outline: none; resize: vertical;"></textarea>
        <button id="submit-recovery" style="${btnStyle}; margin-top: 0.5rem;">
          [ recover ]
        </button>
      </div>

      <div id="approval-waiting" style="display: none; text-align: left; margin-top: 1rem;">
        <div style="font-size: 0.8rem; color: #006644;">
          Waiting for approval from another device...
        </div>
        <div style="font-size: 0.7rem; color: #006644; margin-top: 0.5rem;">
          Approve this device from your web app or another authorized device.
        </div>
        <div id="approval-status" style="margin-top: 0.5rem; font-size: 0.8rem;"></div>
        <button id="cancel-approval-btn" style="margin-top: 0.75rem; padding: 0.375rem 1rem; background: transparent; border: 1px solid #003322; color: #006644; font-family: ${font}; font-size: 0.75rem; cursor: pointer;">
          [ cancel ]
        </button>
      </div>

      <div id="mfa-status" style="margin-top: 1rem; font-size: 0.8rem; min-height: 1.25rem;"></div>

      <button id="mfa-logout-btn" style="margin-top: 1rem; padding: 0.375rem 1rem; background: transparent; border: none; color: #006644; font-family: ${font}; font-size: 0.75rem; cursor: pointer;">
        back to login
      </button>
    </div>
  `;

  // Hover effects for buttons
  for (const id of ['recovery-btn', 'approval-btn', 'submit-recovery']) {
    const btn = document.getElementById(id);
    if (btn) {
      btn.addEventListener('mouseenter', () => {
        btn.style.borderColor = '#00D084';
      });
      btn.addEventListener('mouseleave', () => {
        btn.style.borderColor = '#003322';
      });
    }
  }

  // Focus effect for textarea
  const textarea = document.getElementById('mnemonic-input');
  if (textarea) {
    textarea.addEventListener('focus', () => {
      (textarea as HTMLTextAreaElement).style.borderColor = '#00D084';
    });
    textarea.addEventListener('blur', () => {
      (textarea as HTMLTextAreaElement).style.borderColor = '#003322';
    });
  }

  // Track active approval request for cleanup
  let activeRequestId: string | null = null;
  let pollInterval: ReturnType<typeof setInterval> | null = null;

  const mfaStatus = document.getElementById('mfa-status')!;

  // --- Recovery phrase path ---
  document.getElementById('recovery-btn')?.addEventListener('click', () => {
    document.getElementById('recovery-form')!.style.display = 'block';
    document.getElementById('approval-waiting')!.style.display = 'none';
    mfaStatus.textContent = '';
    // Cancel any active approval request
    if (activeRequestId) {
      void cancelApprovalRequest(activeRequestId);
      activeRequestId = null;
    }
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  });

  document.getElementById('submit-recovery')?.addEventListener('click', async () => {
    const mnemonicEl = document.getElementById('mnemonic-input') as HTMLTextAreaElement;
    const mnemonic = mnemonicEl.value.trim();
    if (!mnemonic) {
      mfaStatus.style.color = '#ef4444';
      mfaStatus.textContent = 'Please enter your recovery phrase';
      return;
    }
    // Basic word count validation
    const wordCount = mnemonic.split(/\s+/).length;
    if (wordCount !== 24) {
      mfaStatus.style.color = '#ef4444';
      mfaStatus.textContent = `Expected 24 words, got ${wordCount}`;
      return;
    }
    mfaStatus.style.color = '#006644';
    mfaStatus.textContent = 'Recovering...';
    try {
      await inputRecoveryPhrase(mnemonic);
      handleAuthSuccess(appDiv);
    } catch (err) {
      mfaStatus.style.color = '#ef4444';
      mfaStatus.textContent = err instanceof Error ? err.message : 'Recovery failed';
    }
  });

  // --- Device approval path ---
  document.getElementById('approval-btn')?.addEventListener('click', async () => {
    document.getElementById('recovery-form')!.style.display = 'none';
    document.getElementById('approval-waiting')!.style.display = 'block';
    mfaStatus.textContent = '';

    const statusEl = document.getElementById('approval-status')!;

    try {
      statusEl.style.color = '#006644';
      statusEl.textContent = 'Creating approval request...';

      activeRequestId = await requestDeviceApproval();
      statusEl.textContent = 'Approval request sent. Waiting...';

      // Poll every 3 seconds
      pollInterval = setInterval(async () => {
        if (!activeRequestId) return;
        try {
          const status = await pollApprovalStatus(activeRequestId);
          if (status === 'approved') {
            if (pollInterval) clearInterval(pollInterval);
            pollInterval = null;
            activeRequestId = null;
            handleAuthSuccess(appDiv);
          } else if (status === 'denied') {
            if (pollInterval) clearInterval(pollInterval);
            pollInterval = null;
            activeRequestId = null;
            statusEl.style.color = '#ef4444';
            statusEl.textContent = 'Approval was rejected.';
          } else if (status === 'expired') {
            if (pollInterval) clearInterval(pollInterval);
            pollInterval = null;
            activeRequestId = null;
            statusEl.style.color = '#ef4444';
            statusEl.textContent = 'Approval request expired.';
          }
        } catch {
          // Continue polling on transient errors
        }
      }, 3000);
    } catch (err) {
      statusEl.style.color = '#ef4444';
      statusEl.textContent = 'Failed to request approval';
      console.error('[MFA] Approval request error:', err);
    }
  });

  // Cancel approval button
  document.getElementById('cancel-approval-btn')?.addEventListener('click', async () => {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    if (activeRequestId) {
      await cancelApprovalRequest(activeRequestId);
      activeRequestId = null;
    }
    document.getElementById('approval-waiting')!.style.display = 'none';
    mfaStatus.textContent = '';
  });

  // Back to login button
  document.getElementById('mfa-logout-btn')?.addEventListener('click', async () => {
    // Clean up any active approval
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    if (activeRequestId) {
      await cancelApprovalRequest(activeRequestId);
      activeRequestId = null;
    }
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
      <div style="color: #00D084; font-family: 'JetBrains Mono', 'Courier New', monospace; padding: 2rem; text-align: center;">
        <div style="font-size: 1rem; margin-bottom: 0.5rem;">authenticated</div>
        <div style="font-size: 0.75rem; color: #006644;">CipherBox is running in the menu bar.</div>
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
  for (const id of ['google-btn', 'wallet-btn', 'email-btn', 'otp-btn']) {
    const btn = document.getElementById(id) as HTMLButtonElement | null;
    if (btn) {
      btn.disabled = disabled;
      btn.style.opacity = disabled ? '0.5' : '1';
      btn.style.cursor = disabled ? 'default' : 'pointer';
    }
  }
}

function loadingHtml(message: string): string {
  return `<div style="color: #006644; font-family: 'JetBrains Mono', 'Courier New', monospace; padding: 2rem; text-align: center;">${message}</div>`;
}

function errorHtml(message: string): string {
  return `<div style="color: #ef4444; font-family: 'JetBrains Mono', 'Courier New', monospace; padding: 2rem; text-align: center;">
    Failed to initialize authentication.<br/>
    <small style="color: #006644;">${message}</small><br/><br/>
    <button onclick="location.reload()" style="color: #00D084; background: #001108; border: 1px solid #003322; padding: 0.5rem 1rem; cursor: pointer; font-family: 'JetBrains Mono', 'Courier New', monospace;">
      [ retry ]
    </button>
  </div>`;
}

// Start the app
init().catch((err) => {
  console.error('CipherBox Desktop initialization error:', err);
});
