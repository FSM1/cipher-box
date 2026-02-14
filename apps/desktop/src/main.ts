/**
 * CipherBox Desktop - Webview Entry Point
 *
 * On app start:
 * 1. Try silent refresh from Keychain-stored refresh token
 * 2. If silent refresh succeeds but private key is not in memory (cold start),
 *    still need Web3Auth login to get the private key for vault decryption
 * 3. Initialize Web3Auth and show login modal
 * 4. After auth completes, the Rust side has all keys -- app transitions to
 *    headless menu bar mode (webview window hides)
 *
 * The webview is only used for the Web3Auth login flow. Once authenticated,
 * the app runs as a menu bar utility with FUSE mount (plan 09-05).
 */

import './polyfills';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { initWeb3Auth, login } from './auth';

/**
 * Application initialization sequence.
 */
async function init(): Promise<void> {
  console.log('CipherBox Desktop initializing...');

  const appDiv = document.getElementById('app');

  // Show loading state
  if (appDiv) {
    appDiv.innerHTML =
      '<div style="color: #9ca3af; font-family: monospace; padding: 2rem; text-align: center;">Initializing CipherBox...</div>';
  }

  // Step 1: Try silent refresh from Keychain
  try {
    const refreshed: boolean = await invoke('try_silent_refresh');
    if (refreshed) {
      console.log('API session refreshed from Keychain');
      // NOTE: Even with a refreshed API session, the private key is NOT
      // available on cold start. We still need Web3Auth login to get
      // the private key for vault decryption. The silent refresh only
      // refreshes the API tokens, not the crypto keys.
    }
  } catch (err) {
    console.warn('Silent refresh failed:', err);
    // Not an error -- just means we need full login
  }

  // Step 2: Initialize Web3Auth and show login
  if (appDiv) {
    appDiv.innerHTML =
      '<div style="color: #9ca3af; font-family: monospace; padding: 2rem; text-align: center;">Connecting to Web3Auth...</div>';
  }

  try {
    await initWeb3Auth();
  } catch (err) {
    console.error('Web3Auth initialization failed:', err);
    if (appDiv) {
      appDiv.innerHTML = `<div style="color: #ef4444; font-family: monospace; padding: 2rem; text-align: center;">
        Failed to initialize authentication.<br/>
        <small>${err instanceof Error ? err.message : String(err)}</small><br/><br/>
        <button onclick="location.reload()" style="color: #9ca3af; background: #1f2937; border: 1px solid #374151; padding: 0.5rem 1rem; cursor: pointer; font-family: monospace;">
          Retry
        </button>
      </div>`;
    }
    return;
  }

  // Step 3: Show login button
  if (appDiv) {
    appDiv.innerHTML = `<div style="color: #9ca3af; font-family: monospace; padding: 2rem; text-align: center;">
      <div style="margin-bottom: 1rem;">CipherBox Desktop</div>
      <button id="login-btn" style="color: #d1d5db; background: #1f2937; border: 1px solid #374151; padding: 0.75rem 1.5rem; cursor: pointer; font-family: monospace; font-size: 1rem;">
        [CONNECT]
      </button>
      <div id="auth-status" style="margin-top: 1rem; font-size: 0.875rem;"></div>
    </div>`;

    const loginBtn = document.getElementById('login-btn');
    const statusEl = document.getElementById('auth-status');

    if (loginBtn) {
      loginBtn.addEventListener('click', async () => {
        loginBtn.setAttribute('disabled', 'true');
        loginBtn.textContent = 'Authenticating...';
        if (statusEl) statusEl.textContent = '';

        try {
          await login();

          // Auth complete -- hide webview window
          // App continues as menu bar utility with FUSE mount
          if (statusEl) {
            statusEl.style.color = '#10b981';
            statusEl.textContent = 'Authenticated. CipherBox is running in the menu bar.';
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
        } catch (err) {
          console.error('Login failed:', err);
          loginBtn.removeAttribute('disabled');
          loginBtn.textContent = '[CONNECT]';
          if (statusEl) {
            statusEl.style.color = '#ef4444';
            statusEl.textContent = err instanceof Error ? err.message : 'Login failed';
          }
        }
      });
    }
  }
}

// Start the app
init().catch((err) => {
  console.error('CipherBox Desktop initialization error:', err);
});
