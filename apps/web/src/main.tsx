import './polyfills';

// Initialize @cipherbox/api-client config at module load time.
// MUST come before any code that calls authApi.* or generated API functions.
import './lib/api-config';

import { initFaro } from './lib/faro';

// Initialize Faro observability (no-op when VITE_FARO_URL is absent)
initFaro();

// DEBUG: Error capture for UAT - captures first 20 errors to window.__errorLog
if (import.meta.env.DEV) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = window as any;
  w.__errorLog = [];
  w.__errorCount = 0;
  const origError = console.error;
  console.error = function (...args: unknown[]) {
    w.__errorCount++;
    if (w.__errorLog.length < 20) {
      w.__errorLog.push({
        type: 'console.error',
        count: w.__errorCount,
        msg: args
          .map((a) => (typeof a === 'string' ? a.substring(0, 300) : String(a).substring(0, 300)))
          .join(' '),
        time: Date.now(),
      });
    }
    // After 100 errors, stop logging to prevent browser crash
    if (w.__errorCount <= 100) {
      origError.apply(console, args);
    }
  };
}

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { WagmiSetup } from './lib/wagmi/provider';
import { CoreKitProvider } from './lib/web3auth/core-kit-provider';
import { registerDecryptSW, setSwApiBase, updateSwToken } from './lib/sw-registration';
import { useAuthStore } from './stores/auth.store';
import App from './App';
import './index.css';

// Register Service Worker for streaming media decryption (non-blocking)
registerDecryptSW().then((reg) => {
  if (!reg) return;
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:3000';
  setSwApiBase(apiUrl);

  // Send current token if already available
  const { accessToken } = useAuthStore.getState();
  if (accessToken) updateSwToken(accessToken);
});

// Keep SW auth token in sync whenever it changes (clear on logout)
useAuthStore.subscribe((state, prevState) => {
  if (state.accessToken !== prevState.accessToken) {
    updateSwToken(state.accessToken ?? '');
  }
});

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
});

const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Root element not found');

createRoot(rootElement).render(
  <StrictMode>
    <WagmiSetup>
      <CoreKitProvider>
        <QueryClientProvider client={queryClient}>
          <App />
        </QueryClientProvider>
      </CoreKitProvider>
    </WagmiSetup>
  </StrictMode>
);
